//! Low-level ACME protocol client (RFC 8555).
//!
//! This module implements the core ACME protocol interactions: directory
//! discovery, account registration, order creation, authorization handling,
//! challenge acceptance, order finalization, certificate download, and
//! certificate revocation.
//!
//! All requests use the JWS (JSON Web Signature) POST-as-GET convention
//! required by RFC 8555. ECDSA P-256 (ES256) is used for signing.

use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use reqwest::header::HeaderValue;
use ring::rand::SystemRandom;
use ring::signature::{self, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::crypto::PrivateKey;
use crate::error::{AcmeError, Result};

// ---------------------------------------------------------------------------
// Configurable User-Agent
// ---------------------------------------------------------------------------

/// Global user-agent string for ACME HTTP requests.
static USER_AGENT: OnceLock<String> = OnceLock::new();

/// Set the global user-agent string used by [`AcmeClient`] for all HTTP
/// requests.
///
/// This must be called before creating an [`AcmeClient`] to take effect.
/// If not called, the default `"certon/0.1"` is used.
pub fn set_user_agent(ua: impl Into<String>) {
    USER_AGENT.set(ua.into()).ok();
}

/// Return the configured user-agent string, or the default.
fn get_user_agent() -> &'static str {
    USER_AGENT.get().map(|s| s.as_str()).unwrap_or("certon/0.1")
}

// ---------------------------------------------------------------------------
// Well-known CA directory URLs
// ---------------------------------------------------------------------------

/// Let's Encrypt production ACME directory.
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Let's Encrypt staging ACME directory (for testing).
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ZeroSSL production ACME directory.
pub const ZEROSSL_PRODUCTION: &str = "https://acme.zerossl.com/v2/DV90";

/// Google Trust Services staging ACME directory.
pub const GOOGLE_TRUST_STAGING: &str = "https://dv.acme-v02.test-api.pki.goog/directory";

/// Google Trust Services production ACME directory.
pub const GOOGLE_TRUST_PRODUCTION: &str = "https://dv.acme-v02.api.pki.goog/directory";

// ---------------------------------------------------------------------------
// ACME Directory
// ---------------------------------------------------------------------------

/// The ACME directory resource (RFC 8555 Section 7.1.1).
///
/// Contains the URLs for all ACME operations. This is fetched once from
/// the CA's directory URL and cached for the lifetime of the [`AcmeClient`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDirectory {
    /// URL to obtain a new replay nonce.
    #[serde(rename = "newNonce")]
    pub new_nonce: String,

    /// URL to create a new account.
    #[serde(rename = "newAccount")]
    pub new_account: String,

    /// URL to create a new order.
    #[serde(rename = "newOrder")]
    pub new_order: String,

    /// URL to create a new pre-authorization (optional, not all CAs support
    /// this).
    #[serde(rename = "newAuthz")]
    pub new_authz: Option<String>,

    /// URL to revoke a certificate.
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,

    /// URL for key change operations.
    #[serde(rename = "keyChange")]
    pub key_change: String,

    /// URL for ACME Renewal Information (ARI) per RFC 9773.
    ///
    /// Not all CAs support ARI; this field is `None` when the directory
    /// does not advertise the endpoint.
    #[serde(rename = "renewalInfo")]
    pub renewal_info: Option<String>,

    /// Optional metadata about the ACME server.
    pub meta: Option<DirectoryMeta>,
}

/// Optional metadata returned by an ACME directory (RFC 8555 Section 7.1.1).
///
/// Contains information about the CA such as terms of service, website,
/// CAA identities, and whether external account binding is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryMeta {
    /// URL of the CA's terms of service.
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,

    /// URL of the CA's website.
    pub website: Option<String>,

    /// Hostnames that the CA recognizes as referring to itself for the
    /// purposes of CAA record validation.
    #[serde(rename = "caaIdentities")]
    pub caa_identities: Option<Vec<String>>,

    /// Whether an external account binding is required.
    #[serde(rename = "externalAccountRequired")]
    pub external_account_required: Option<bool>,
}

// ---------------------------------------------------------------------------
// ACME Renewal Information (ARI) types — RFC 9773
// ---------------------------------------------------------------------------

/// ACME Renewal Information per RFC 9773 (draft-ietf-acme-ari).
///
/// Contains the server's suggested renewal window and an optional
/// explanation URL. The `selected_time` field is computed locally by
/// picking a random instant within the suggested window.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RenewalInfo {
    /// Suggested renewal window (start and end timestamps).
    #[serde(rename = "suggestedWindow")]
    pub suggested_window: Option<RenewalWindow>,

    /// An explanation from the server (e.g. why early renewal is suggested).
    #[serde(rename = "explanationURL")]
    pub explanation_url: Option<String>,

    /// Retry-After value in seconds, if the server wants us to check again
    /// later.
    #[serde(rename = "retryAfter")]
    pub retry_after: Option<u64>,

    /// The selected renewal time (computed locally within the suggested
    /// window). This is not serialized to/from JSON because it is a local
    /// decision.
    #[serde(skip)]
    pub selected_time: Option<DateTime<Utc>>,
}

/// A time window within which the server suggests the certificate should be
/// renewed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalWindow {
    /// RFC 3339 timestamp for the start of the renewal window.
    pub start: String,
    /// RFC 3339 timestamp for the end of the renewal window.
    pub end: String,
}

// ---------------------------------------------------------------------------
// ACME data types
// ---------------------------------------------------------------------------

/// An ACME order (RFC 8555 Section 7.1.3), representing a request for
/// certificate issuance.
///
/// An order progresses through statuses: `pending` -> `ready` -> `processing`
/// -> `valid` (with `invalid` possible at any stage). Once `valid`, the
/// `certificate` field contains the URL to download the issued certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrder {
    /// The status of the order (e.g. `"pending"`, `"ready"`, `"valid"`,
    /// `"invalid"`).
    #[serde(default)]
    pub status: String,

    /// The identifiers (domains) this order covers.
    #[serde(default)]
    pub identifiers: Vec<AcmeIdentifier>,

    /// URLs to the authorization resources for each identifier.
    #[serde(default)]
    pub authorizations: Vec<String>,

    /// URL to POST the CSR to when the order is ready.
    #[serde(default)]
    pub finalize: String,

    /// URL to download the certificate from once the order is valid.
    #[serde(default)]
    pub certificate: Option<String>,

    /// When the order expires.
    #[serde(default)]
    pub expires: Option<String>,

    /// An error associated with this order, if any.
    #[serde(default)]
    pub error: Option<AcmeProblem>,
}

/// An ACME authorization resource (RFC 8555 Section 7.1.4).
///
/// An authorization associates a set of challenges with a specific
/// identifier (domain). The client must successfully complete one of the
/// challenges to prove control of the identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAuthorization {
    /// The status of the authorization (e.g. `"pending"`, `"valid"`,
    /// `"invalid"`, `"deactivated"`, `"expired"`, `"revoked"`).
    #[serde(default)]
    pub status: String,

    /// The identifier this authorization is for.
    pub identifier: AcmeIdentifier,

    /// The available challenges.
    #[serde(default)]
    pub challenges: Vec<AcmeChallenge>,

    /// When this authorization expires.
    #[serde(default)]
    pub expires: Option<String>,

    /// Whether this is a wildcard authorization.
    #[serde(default)]
    pub wildcard: Option<bool>,
}

/// A single ACME challenge (RFC 8555 Section 7.1.5).
///
/// The server offers one or more challenges for each authorization.
/// The client selects one, presents the appropriate response (e.g. an
/// HTTP resource, a DNS TXT record, or a TLS-ALPN certificate), and
/// then notifies the server that the challenge is ready for validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallenge {
    /// The challenge type (e.g. `"http-01"`, `"dns-01"`, `"tls-alpn-01"`).
    #[serde(rename = "type")]
    pub challenge_type: String,

    /// The URL to POST to in order to respond to this challenge.
    pub url: String,

    /// The challenge token.
    #[serde(default)]
    pub token: String,

    /// The current status of the challenge.
    #[serde(default)]
    pub status: String,

    /// When this challenge was validated.
    #[serde(default)]
    pub validated: Option<String>,

    /// An error associated with this challenge, if any.
    #[serde(default)]
    pub error: Option<AcmeProblem>,
}

/// An ACME identifier (RFC 8555 Section 7.1.4).
///
/// Typically a DNS name (`type: "dns"`), but can also be an IP address
/// (`type: "ip"`) per RFC 8738.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    /// The identifier type (e.g. `"dns"`).
    #[serde(rename = "type")]
    pub id_type: String,

    /// The identifier value (e.g. `"example.com"`).
    pub value: String,
}

/// An ACME problem document (RFC 7807 / RFC 8555 Section 6.7).
///
/// Returned by the CA when an error occurs. Contains a machine-readable
/// problem type URI, a human-readable detail string, and optionally
/// sub-problems for compound errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeProblem {
    /// A URI identifying the problem type.
    #[serde(rename = "type", default)]
    pub problem_type: String,

    /// A human-readable description of the problem.
    #[serde(default)]
    pub detail: String,

    /// The HTTP status code.
    #[serde(default)]
    pub status: Option<u16>,

    /// Sub-problems (for compound errors).
    #[serde(default)]
    pub subproblems: Option<Vec<AcmeProblem>>,
}

impl std::fmt::Display for AcmeProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)?;
        if !self.problem_type.is_empty() {
            write!(f, " ({})", self.problem_type)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Account response
// ---------------------------------------------------------------------------

/// The response from an ACME account registration or lookup
/// (RFC 8555 Section 7.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    /// The account status (e.g. `"valid"`, `"deactivated"`, `"revoked"`).
    #[serde(default)]
    pub status: String,

    /// Contact URIs associated with the account.
    #[serde(default)]
    pub contact: Vec<String>,

    /// Whether the account has agreed to the CA's terms of service.
    #[serde(rename = "termsOfServiceAgreed", default)]
    pub terms_of_service_agreed: bool,

    /// Orders URL for this account (if any).
    #[serde(default)]
    pub orders: Option<String>,
}

// ---------------------------------------------------------------------------
// External Account Binding
// ---------------------------------------------------------------------------

/// External Account Binding (EAB) credentials (RFC 8555 Section 7.3.4).
///
/// Some CAs (such as ZeroSSL) require an external account binding during
/// ACME account registration. The binding ties the ACME account to an
/// existing account on the CA's system using a key identifier and an
/// HMAC key provided out-of-band by the CA.
#[derive(Debug, Clone)]
pub struct ExternalAccountBinding {
    /// The key ID provided by the CA.
    pub kid: String,
    /// The HMAC key (raw bytes) provided by the CA.
    pub hmac_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// JWS types (internal)
// ---------------------------------------------------------------------------

/// JWS protected header.
#[derive(Serialize)]
struct JwsProtected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

/// JSON Web Key (JWK) for ECDSA P-256 public keys.
#[derive(Clone, Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

/// JWS body sent as `application/jose+json`.
#[derive(Serialize)]
struct JwsBody {
    protected: String,
    payload: String,
    signature: String,
}

// ---------------------------------------------------------------------------
// JWK helpers
// ---------------------------------------------------------------------------

/// Build a [`Jwk`] from a P-256 private key.
///
/// The public key is extracted from the PKCS#8 DER. The uncompressed point
/// format is 65 bytes: `0x04 || x (32 bytes) || y (32 bytes)`.
fn jwk_from_key(key: &PrivateKey) -> Result<Jwk> {
    let rng = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.pkcs8_der(), &rng)
            .map_err(|e| AcmeError::Account(format!("failed to load ECDSA key pair: {e}")))?;

    let public_key = signature::KeyPair::public_key(&key_pair).as_ref();
    // Uncompressed point: 0x04 || x || y
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(AcmeError::Account("unexpected ECDSA P-256 public key format".into()).into());
    }
    let (x, y) = public_key[1..].split_at(32);

    Ok(Jwk {
        alg: "ES256",
        crv: "P-256",
        kty: "EC",
        u: "sig",
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
    })
}

/// Compute the JWK thumbprint (SHA-256) of a key, as defined in RFC 7638.
///
/// The thumbprint is computed from the lexicographically-sorted JSON
/// representation of the required JWK members for EC keys: `crv`, `kty`,
/// `x`, `y`.
fn jwk_thumbprint(jwk: &Jwk) -> String {
    #[derive(Serialize)]
    struct JwkThumb<'a> {
        crv: &'a str,
        kty: &'a str,
        x: &'a str,
        y: &'a str,
    }

    let thumb = JwkThumb {
        crv: jwk.crv,
        kty: jwk.kty,
        x: &jwk.x,
        y: &jwk.y,
    };
    let json = serde_json::to_vec(&thumb).expect("JWK thumbprint serialization should not fail");
    let digest = Sha256::digest(&json);
    URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------------
// Key Authorization (public)
// ---------------------------------------------------------------------------

/// Compute the ACME key authorization string: `{token}.{jwk_thumbprint}`
/// (RFC 8555 Section 8.1).
///
/// This value is needed by HTTP-01 and TLS-ALPN-01 challenge solvers. For
/// DNS-01 challenges, the base64url-encoded SHA-256 digest of this value
/// is used instead (see [`key_authorization_sha256`]).
pub fn key_authorization(token: &str, account_key: &PrivateKey) -> Result<String> {
    let jwk = jwk_from_key(account_key)?;
    let thumbprint = jwk_thumbprint(&jwk);
    Ok(format!("{token}.{thumbprint}"))
}

/// Compute the SHA-256 digest of the key authorization, returned as raw
/// bytes. This is needed by DNS-01 challenge solvers (the base64url encoding
/// of this digest is the DNS TXT record value).
pub fn key_authorization_sha256(token: &str, account_key: &PrivateKey) -> Result<Vec<u8>> {
    let ka = key_authorization(token, account_key)?;
    Ok(Sha256::digest(ka.as_bytes()).to_vec())
}

// ---------------------------------------------------------------------------
// JWS signing
// ---------------------------------------------------------------------------

/// Sign `data` with the ECDSA P-256 key, returning the fixed-size (r || s)
/// signature.
fn sign_with_key(key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.pkcs8_der(), &rng).map_err(
            |e| AcmeError::Account(format!("failed to load ECDSA key pair for signing: {e}")),
        )?;

    let sig = key_pair
        .sign(&rng, data)
        .map_err(|e| AcmeError::Account(format!("ECDSA signing failed: {e}")))?;

    Ok(sig.as_ref().to_vec())
}

/// Build a JWS body for an ACME request.
///
/// If `kid` is `Some`, the JWS header uses `kid` (for authenticated
/// requests). Otherwise, the JWS header includes the full `jwk` (for
/// account creation / lookup).
///
/// If `payload` is `None`, an empty payload is used (POST-as-GET).
fn build_jws_body(
    key: &PrivateKey,
    kid: Option<&str>,
    nonce: &str,
    url: &str,
    payload: Option<&str>,
) -> Result<Vec<u8>> {
    let jwk = match kid {
        None => Some(jwk_from_key(key)?),
        Some(_) => None,
    };

    let protected = JwsProtected {
        alg: "ES256",
        jwk,
        kid,
        nonce,
        url,
    };
    let protected_json = serde_json::to_vec(&protected)
        .map_err(|e| AcmeError::Account(format!("failed to encode JWS protected header: {e}")))?;
    let protected_b64 = URL_SAFE_NO_PAD.encode(&protected_json);

    let payload_b64 = match payload {
        Some(p) => URL_SAFE_NO_PAD.encode(p.as_bytes()),
        None => String::new(),
    };

    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = sign_with_key(key, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let body = JwsBody {
        protected: protected_b64,
        payload: payload_b64,
        signature: signature_b64,
    };

    serde_json::to_vec(&body)
        .map_err(|e| AcmeError::Account(format!("failed to serialize JWS body: {e}")).into())
}

// ---------------------------------------------------------------------------
// AcmeClient
// ---------------------------------------------------------------------------

/// A low-level ACME protocol client.
///
/// Manages the ACME directory, nonce caching, and provides async methods for
/// every major ACME operation: account registration, order creation,
/// authorization handling, challenge acceptance, order finalization,
/// certificate download, and certificate revocation.
///
/// All requests are signed using JWS (JSON Web Signature) with the
/// POST-as-GET convention required by RFC 8555. ECDSA P-256 (ES256)
/// is used for signing.
///
/// Nonce management is handled automatically: every response's
/// `Replay-Nonce` header is cached and reused for the next request.
/// If no cached nonce is available, a fresh one is obtained via a HEAD
/// request to the `newNonce` URL.
pub struct AcmeClient {
    /// The HTTP client used for all requests.
    http: reqwest::Client,
    /// The ACME directory (cached after initial fetch).
    directory: AcmeDirectory,
    /// A cached replay nonce. The ACME server provides a new nonce with every
    /// response; we cache it here so we don't have to do a HEAD request
    /// before every POST.
    nonce: Mutex<Option<String>>,
}

impl std::fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeClient")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

impl AcmeClient {
    /// Create a new [`AcmeClient`] by fetching the ACME directory from the
    /// given URL and obtaining an initial replay nonce.
    ///
    /// The CA URL must use HTTPS. HTTP is only allowed for localhost,
    /// `127.0.0.1`, `[::1]`, and `.internal` hosts (for testing/development).
    pub async fn new(directory_url: &str) -> Result<Self> {
        // Validate that the directory URL uses HTTPS, unless it is a local
        // or internal address.
        if let Ok(parsed) = url::Url::parse(directory_url)
            && parsed.scheme() == "http" {
                let host = parsed.host_str().unwrap_or("");
                let is_local = host == "localhost"
                    || host == "127.0.0.1"
                    || host == "[::1]"
                    || host == "::1"
                    || host.ends_with(".internal")
                    || host.ends_with(".localhost");
                if !is_local {
                    return Err(AcmeError::Directory(format!(
                        "ACME directory URL must use HTTPS (got {directory_url}); \
                         HTTP is only allowed for localhost/internal hosts"
                    ))
                    .into());
                }
            }

        debug!(directory_url, "fetching ACME directory");

        let http = reqwest::Client::builder()
            .user_agent(get_user_agent())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AcmeError::Directory(format!("failed to build HTTP client: {e}")))?;

        // Fetch directory.
        let resp = http
            .get(directory_url)
            .send()
            .await
            .map_err(|e| AcmeError::Directory(format!("failed to fetch directory: {e}")))?;

        if !resp.status().is_success() {
            return Err(
                AcmeError::Directory(format!("directory returned HTTP {}", resp.status())).into(),
            );
        }

        let directory: AcmeDirectory = resp
            .json()
            .await
            .map_err(|e| AcmeError::Directory(format!("failed to parse directory JSON: {e}")))?;

        debug!(
            new_nonce = %directory.new_nonce,
            new_account = %directory.new_account,
            new_order = %directory.new_order,
            "ACME directory loaded"
        );

        // Get initial nonce.
        let nonce = Self::fetch_nonce_from(&http, &directory.new_nonce).await?;

        Ok(Self {
            http,
            directory,
            nonce: Mutex::new(Some(nonce)),
        })
    }

    /// Returns a reference to the cached ACME directory.
    pub fn directory(&self) -> &AcmeDirectory {
        &self.directory
    }

    // -----------------------------------------------------------------------
    // Nonce management
    // -----------------------------------------------------------------------

    /// Obtain a fresh replay nonce. If a cached nonce is available, it is
    /// returned (and the cache is cleared). Otherwise, a HEAD request is
    /// made to the `newNonce` URL.
    async fn get_nonce(&self) -> Result<String> {
        {
            let mut guard = self.nonce.lock().await;
            if let Some(nonce) = guard.take() {
                return Ok(nonce);
            }
        }
        Self::fetch_nonce_from(&self.http, &self.directory.new_nonce).await
    }

    /// Fetch a nonce via HEAD request to the `new_nonce_url`.
    async fn fetch_nonce_from(http: &reqwest::Client, new_nonce_url: &str) -> Result<String> {
        debug!("fetching new nonce via HEAD");
        let resp = http
            .head(new_nonce_url)
            .send()
            .await
            .map_err(|e| AcmeError::Nonce(format!("HEAD newNonce failed: {e}")))?;

        extract_nonce(&resp).ok_or_else(|| {
            AcmeError::Nonce("no Replay-Nonce header in HEAD response".into()).into()
        })
    }

    /// Store a nonce from a response for later reuse.
    async fn cache_nonce(&self, resp: &reqwest::Response) {
        if let Some(nonce) = extract_nonce(resp) {
            let mut guard = self.nonce.lock().await;
            *guard = Some(nonce);
        }
    }

    // -----------------------------------------------------------------------
    // Generic ACME POST helper
    // -----------------------------------------------------------------------

    /// Send a signed ACME POST request. Returns the response.
    ///
    /// - If `kid` is `Some`, the JWS uses `kid` in the protected header.
    /// - If `kid` is `None`, the JWS includes the full JWK (used for newAccount).
    /// - If `payload` is `None`, an empty payload is sent (POST-as-GET).
    async fn acme_post(
        &self,
        account_key: &PrivateKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&str>,
    ) -> Result<reqwest::Response> {
        // We try once; on a badNonce error we retry with a fresh nonce.
        for attempt in 0..2 {
            let nonce = self.get_nonce().await?;
            let body = build_jws_body(account_key, kid, &nonce, url, payload)?;

            let resp = self
                .http
                .post(url)
                .header("Content-Type", "application/jose+json")
                .body(body)
                .send()
                .await
                .map_err(|e| AcmeError::Order(format!("ACME POST to {url} failed: {e}")))?;

            // Always cache the nonce from the response.
            self.cache_nonce(&resp).await;

            // Check for badNonce and retry once.
            if resp.status().as_u16() == 400 && attempt == 0 {
                // Peek at the body to see if it's a badNonce error.
                let resp_bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| AcmeError::Nonce(format!("failed to read response body: {e}")))?;

                if let Ok(problem) = serde_json::from_slice::<AcmeProblem>(&resp_bytes)
                    && problem.problem_type.contains("badNonce") {
                        warn!("bad nonce, retrying with fresh nonce");
                        continue;
                    }

                // Not a badNonce error; return an error with the body we already read.
                let problem: std::result::Result<AcmeProblem, _> =
                    serde_json::from_slice(&resp_bytes);
                let detail = match problem {
                    Ok(p) => format!("{p}"),
                    Err(_) => String::from_utf8_lossy(&resp_bytes).into_owned(),
                };
                return Err(AcmeError::Order(format!(
                    "ACME request to {url} failed (HTTP 400): {detail}"
                ))
                .into());
            }

            return Ok(resp);
        }

        Err(AcmeError::Nonce("failed after badNonce retry".into()).into())
    }

    /// Send a signed ACME POST and parse the JSON response. Also returns
    /// the `Location` header if present.
    async fn acme_post_json<T: serde::de::DeserializeOwned>(
        &self,
        account_key: &PrivateKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&str>,
    ) -> Result<(T, Option<String>)> {
        let resp = self.acme_post(account_key, kid, url, payload).await?;

        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            let detail = match serde_json::from_slice::<AcmeProblem>(&body) {
                Ok(p) => format!("{p}"),
                Err(_) => String::from_utf8_lossy(&body).into_owned(),
            };
            return Err(
                AcmeError::Order(format!("ACME {url} returned HTTP {status}: {detail}")).into(),
            );
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| AcmeError::Order(format!("failed to read response body: {e}")))?;

        let parsed: T = serde_json::from_slice(&body)
            .map_err(|e| AcmeError::Order(format!("failed to parse response JSON: {e}")))?;

        Ok((parsed, location))
    }

    // -----------------------------------------------------------------------
    // Account operations
    // -----------------------------------------------------------------------

    /// Register a new ACME account with the CA.
    ///
    /// Returns the account response and the account URL (from the `Location`
    /// header).
    pub async fn new_account(
        &self,
        account_key: &PrivateKey,
        contact: &[String],
        tos_agreed: bool,
        eab: Option<ExternalAccountBinding>,
    ) -> Result<(AccountResponse, String)> {
        debug!("registering new ACME account");

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct NewAccountRequest {
            terms_of_service_agreed: bool,
            contact: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            external_account_binding: Option<serde_json::Value>,
        }

        let eab_value = match eab {
            Some(eab_creds) => Some(build_eab_jws(
                account_key,
                &eab_creds,
                &self.directory.new_account,
            )?),
            None => None,
        };

        let req = NewAccountRequest {
            terms_of_service_agreed: tos_agreed,
            contact: contact.to_vec(),
            external_account_binding: eab_value,
        };

        let payload = serde_json::to_string(&req)
            .map_err(|e| AcmeError::Account(format!("failed to serialize account request: {e}")))?;

        let (acct_resp, location): (AccountResponse, _) = self
            .acme_post_json(
                account_key,
                None,
                &self.directory.new_account,
                Some(&payload),
            )
            .await?;

        let account_url = location.ok_or_else(|| {
            AcmeError::Account("no Location header in account creation response".into())
        })?;

        debug!(
            status = %acct_resp.status,
            account_url = %account_url,
            "ACME account registered"
        );

        Ok((acct_resp, account_url))
    }

    /// Look up an existing ACME account by key.
    ///
    /// Returns `Ok(Some((response, account_url)))` if found, or `Ok(None)` if
    /// no account exists for this key.
    pub async fn find_account(
        &self,
        account_key: &PrivateKey,
    ) -> Result<Option<(AccountResponse, String)>> {
        debug!("looking up existing ACME account");

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct FindAccountRequest {
            only_return_existing: bool,
        }

        let req = FindAccountRequest {
            only_return_existing: true,
        };

        let payload = serde_json::to_string(&req)
            .map_err(|e| AcmeError::Account(format!("failed to serialize find request: {e}")))?;

        let nonce = self.get_nonce().await?;
        let body = build_jws_body(
            account_key,
            None,
            &nonce,
            &self.directory.new_account,
            Some(&payload),
        )?;

        let resp = self
            .http
            .post(&self.directory.new_account)
            .header("Content-Type", "application/jose+json")
            .body(body)
            .send()
            .await
            .map_err(|e| AcmeError::Account(format!("account lookup failed: {e}")))?;

        self.cache_nonce(&resp).await;

        // 400 with accountDoesNotExist means no account for this key.
        if resp.status().as_u16() == 400 {
            let body_bytes = resp.bytes().await.unwrap_or_default();
            if let Ok(problem) = serde_json::from_slice::<AcmeProblem>(&body_bytes)
                && problem.problem_type.contains("accountDoesNotExist") {
                    return Ok(None);
                }
            return Err(AcmeError::Account(format!(
                "account lookup returned HTTP 400: {}",
                String::from_utf8_lossy(&body_bytes)
            ))
            .into());
        }

        if !resp.status().is_success() {
            return Err(AcmeError::Account(format!(
                "account lookup returned HTTP {}",
                resp.status()
            ))
            .into());
        }

        let account_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| AcmeError::Account(format!("failed to read response: {e}")))?;

        let acct_resp: AccountResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| AcmeError::Account(format!("failed to parse account response: {e}")))?;

        match account_url {
            Some(url) => Ok(Some((acct_resp, url))),
            None => Err(
                AcmeError::Account("no Location header in account lookup response".into()).into(),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Order operations
    // -----------------------------------------------------------------------

    /// Create a new ACME order for the specified domains.
    ///
    /// Returns the order object and the order URL (from `Location` header).
    pub async fn new_order(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        domains: &[String],
    ) -> Result<(AcmeOrder, String)> {
        debug!(?domains, "creating new ACME order");

        #[derive(Serialize)]
        struct NewOrderRequest {
            identifiers: Vec<AcmeIdentifier>,
        }

        let identifiers: Vec<AcmeIdentifier> = domains
            .iter()
            .map(|d| AcmeIdentifier {
                id_type: "dns".to_owned(),
                value: d.clone(),
            })
            .collect();

        let req = NewOrderRequest { identifiers };
        let payload = serde_json::to_string(&req)
            .map_err(|e| AcmeError::Order(format!("failed to serialize order request: {e}")))?;

        let (order, location): (AcmeOrder, _) = self
            .acme_post_json(
                account_key,
                Some(account_url),
                &self.directory.new_order,
                Some(&payload),
            )
            .await?;

        let order_url = location.ok_or_else(|| {
            AcmeError::Order("no Location header in order creation response".into())
        })?;

        debug!(
            status = %order.status,
            order_url = %order_url,
            "ACME order created"
        );

        Ok((order, order_url))
    }

    // -----------------------------------------------------------------------
    // Authorization operations
    // -----------------------------------------------------------------------

    /// Fetch the authorization details for an authorization URL.
    pub async fn get_authorization(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        authz_url: &str,
    ) -> Result<AcmeAuthorization> {
        debug!(authz_url, "fetching authorization");

        // POST-as-GET (empty payload).
        let (authz, _): (AcmeAuthorization, _) = self
            .acme_post_json(account_key, Some(account_url), authz_url, None)
            .await?;

        debug!(
            status = %authz.status,
            identifier = %authz.identifier.value,
            "authorization fetched"
        );

        Ok(authz)
    }

    /// Tell the CA that we are ready for it to validate a challenge.
    ///
    /// The `challenge_url` is the `url` field from an [`AcmeChallenge`].
    pub async fn accept_challenge(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        challenge_url: &str,
    ) -> Result<AcmeChallenge> {
        debug!(challenge_url, "accepting challenge");

        // POST an empty JSON object `{}` to signal readiness.
        let payload = "{}";
        let (challenge, _): (AcmeChallenge, _) = self
            .acme_post_json(account_key, Some(account_url), challenge_url, Some(payload))
            .await?;

        debug!(
            status = %challenge.status,
            challenge_type = %challenge.challenge_type,
            "challenge accepted"
        );

        Ok(challenge)
    }

    /// Poll an authorization URL until its status is `valid`, `invalid`, or
    /// the timeout expires.
    pub async fn poll_authorization(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        authz_url: &str,
        timeout: Duration,
    ) -> Result<AcmeAuthorization> {
        debug!(authz_url, ?timeout, "polling authorization");

        let deadline = tokio::time::Instant::now() + timeout;
        let mut interval = Duration::from_secs(2);
        let max_interval = Duration::from_secs(30);

        loop {
            let authz = self
                .get_authorization(account_key, account_url, authz_url)
                .await?;

            match authz.status.as_str() {
                "valid" => {
                    debug!(authz_url, "authorization is valid");
                    return Ok(authz);
                }
                "invalid" => {
                    let detail = authz
                        .challenges
                        .iter()
                        .find_map(|c| c.error.as_ref())
                        .map(|p| format!("{p}"))
                        .unwrap_or_else(|| "unknown".into());
                    return Err(AcmeError::Authorization(format!(
                        "authorization for {} failed: {detail}",
                        authz.identifier.value
                    ))
                    .into());
                }
                "deactivated" | "expired" | "revoked" => {
                    return Err(AcmeError::Authorization(format!(
                        "authorization for {} has status: {}",
                        authz.identifier.value, authz.status
                    ))
                    .into());
                }
                _ => {
                    // "pending" or "processing" — keep polling.
                }
            }

            if tokio::time::Instant::now() + interval > deadline {
                return Err(crate::error::Error::Timeout(format!(
                    "authorization polling timed out after {timeout:?} (last status: {})",
                    authz.status
                )));
            }

            tokio::time::sleep(interval).await;
            interval = std::cmp::min(interval * 2, max_interval);
        }
    }

    // -----------------------------------------------------------------------
    // Finalization
    // -----------------------------------------------------------------------

    /// Submit a CSR to finalize an order.
    ///
    /// `csr_der` is the DER-encoded PKCS#10 Certificate Signing Request.
    pub async fn finalize_order(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        finalize_url: &str,
        csr_der: &[u8],
    ) -> Result<AcmeOrder> {
        debug!(finalize_url, "finalizing order");

        #[derive(Serialize)]
        struct FinalizeRequest {
            csr: String,
        }

        let req = FinalizeRequest {
            csr: URL_SAFE_NO_PAD.encode(csr_der),
        };
        let payload = serde_json::to_string(&req)
            .map_err(|e| AcmeError::Order(format!("failed to serialize finalize request: {e}")))?;

        let (order, _): (AcmeOrder, _) = self
            .acme_post_json(account_key, Some(account_url), finalize_url, Some(&payload))
            .await?;

        debug!(status = %order.status, "order finalized");

        Ok(order)
    }

    /// Poll an order URL until its status is `valid`, `invalid`, or the
    /// timeout expires.
    pub async fn poll_order(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        order_url: &str,
        timeout: Duration,
    ) -> Result<AcmeOrder> {
        debug!(order_url, ?timeout, "polling order");

        let deadline = tokio::time::Instant::now() + timeout;
        let mut interval = Duration::from_secs(2);
        let max_interval = Duration::from_secs(30);

        loop {
            // POST-as-GET to the order URL.
            let (order, _): (AcmeOrder, _) = self
                .acme_post_json(account_key, Some(account_url), order_url, None)
                .await?;

            match order.status.as_str() {
                "valid" => {
                    debug!(order_url, "order is valid");
                    return Ok(order);
                }
                "invalid" => {
                    let detail = order
                        .error
                        .as_ref()
                        .map(|p| format!("{p}"))
                        .unwrap_or_else(|| "unknown".into());
                    return Err(AcmeError::Order(format!("order failed: {detail}")).into());
                }
                _ => {
                    // "pending", "ready", "processing" — keep polling.
                }
            }

            if tokio::time::Instant::now() + interval > deadline {
                return Err(crate::error::Error::Timeout(format!(
                    "order polling timed out after {timeout:?} (last status: {})",
                    order.status
                )));
            }

            tokio::time::sleep(interval).await;
            interval = std::cmp::min(interval * 2, max_interval);
        }
    }

    // -----------------------------------------------------------------------
    // Certificate download
    // -----------------------------------------------------------------------

    /// Download the certificate chain (PEM) from the given certificate URL.
    pub async fn download_certificate(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_url: &str,
    ) -> Result<String> {
        debug!(cert_url, "downloading certificate");

        let resp = self
            .acme_post(account_key, Some(account_url), cert_url, None)
            .await?;

        if !resp.status().is_success() {
            return Err(AcmeError::Certificate(format!(
                "certificate download returned HTTP {}",
                resp.status()
            ))
            .into());
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AcmeError::Certificate(format!("failed to read certificate body: {e}")))?;

        debug!(cert_url, len = body.len(), "certificate downloaded");

        Ok(body)
    }

    // -----------------------------------------------------------------------
    // Certificate revocation
    // -----------------------------------------------------------------------

    /// Revoke a certificate.
    ///
    /// `cert_der` is the DER-encoded certificate to revoke.
    /// `reason` is the optional RFC 5280 revocation reason code (0-10).
    pub async fn revoke_certificate(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_der: &[u8],
        reason: Option<u8>,
    ) -> Result<()> {
        debug!("revoking certificate");

        #[derive(Serialize)]
        struct RevokeRequest {
            certificate: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<u8>,
        }

        let req = RevokeRequest {
            certificate: URL_SAFE_NO_PAD.encode(cert_der),
            reason,
        };
        let payload = serde_json::to_string(&req).map_err(|e| {
            AcmeError::Certificate(format!("failed to serialize revoke request: {e}"))
        })?;

        let resp = self
            .acme_post(
                account_key,
                Some(account_url),
                &self.directory.revoke_cert,
                Some(&payload),
            )
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            let detail = match serde_json::from_slice::<AcmeProblem>(&body) {
                Ok(p) => format!("{p}"),
                Err(_) => String::from_utf8_lossy(&body).into_owned(),
            };
            return Err(AcmeError::Certificate(format!(
                "certificate revocation failed (HTTP {status}): {detail}",
            ))
            .into());
        }

        debug!("certificate revoked");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // ACME Renewal Information (ARI) — RFC 9773
    // -----------------------------------------------------------------------

    /// Fetch ACME Renewal Information (ARI) for a certificate.
    ///
    /// The `cert_id` is computed from the certificate's AKI and serial number
    /// as a base64url-encoded string: `base64url(AKI).base64url(serial)`.
    /// See [`ari_cert_id`] for computing this value.
    ///
    /// Performs a POST-as-GET to `{directory.renewalInfo}/{cert_id}`. If the
    /// directory does not advertise a `renewalInfo` endpoint, returns a
    /// default (empty) [`RenewalInfo`].
    pub async fn get_renewal_info(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_id: &str,
    ) -> Result<RenewalInfo> {
        let renewal_info_base = match &self.directory.renewal_info {
            Some(url) => url.clone(),
            None => {
                debug!("ACME directory does not advertise renewalInfo endpoint");
                return Ok(RenewalInfo::default());
            }
        };

        let url = format!("{}/{}", renewal_info_base.trim_end_matches('/'), cert_id);
        debug!(url = %url, "fetching ACME Renewal Information (ARI)");

        let resp = self
            .acme_post(account_key, Some(account_url), &url, None)
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            let detail = String::from_utf8_lossy(&body);
            warn!(
                status = %status,
                detail = %detail,
                "ARI request returned non-success status; returning default"
            );
            return Ok(RenewalInfo::default());
        }

        let body = resp.bytes().await.map_err(|e| {
            AcmeError::Certificate(format!("failed to read ARI response body: {e}"))
        })?;

        let info: RenewalInfo = serde_json::from_slice(&body).map_err(|e| {
            AcmeError::Certificate(format!("failed to parse ARI response JSON: {e}"))
        })?;

        debug!(?info, "ACME Renewal Information fetched");

        Ok(info)
    }
}

// ---------------------------------------------------------------------------
// ARI certificate ID computation
// ---------------------------------------------------------------------------

/// Compute the ACME Renewal Information (ARI) certificate identifier from a
/// DER-encoded certificate.
///
/// Per RFC 9773, the certificate identifier is formed as:
///
/// ```text
/// base64url(AKI) "." base64url(serial)
/// ```
///
/// where AKI is the Authority Key Identifier extension's `keyIdentifier`
/// value and serial is the certificate's serial number (DER integer bytes,
/// with leading zero-padding stripped per the spec — the raw big-endian
/// unsigned representation).
///
/// # Errors
///
/// Returns an error if the certificate cannot be parsed or does not have an
/// Authority Key Identifier extension.
pub fn ari_cert_id(cert_der: &[u8]) -> Result<String> {
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        AcmeError::Certificate(format!("failed to parse certificate for ARI ID: {e}"))
    })?;

    // Extract the Authority Key Identifier (AKI) extension by walking
    // all extensions.
    let mut aki_bytes: Option<Vec<u8>> = None;
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension()
            && let Some(key_id) = &aki.key_identifier {
                aki_bytes = Some(key_id.0.to_vec());
                break;
            }
    }

    let aki_bytes = aki_bytes.ok_or_else(|| {
        AcmeError::Certificate(
            "certificate has no Authority Key Identifier extension with keyIdentifier".into(),
        )
    })?;

    // Extract serial number bytes. `x509_parser` gives us the serial as a
    // BigUint; we want the raw unsigned big-endian bytes.
    let serial_bytes = cert.raw_serial();

    // Strip leading zero byte(s) that serve as sign padding in the DER
    // INTEGER encoding. RFC 9773 requires the unsigned representation.
    let serial_bytes = strip_leading_zeros(serial_bytes);

    let aki_b64 = URL_SAFE_NO_PAD.encode(&aki_bytes);
    let serial_b64 = URL_SAFE_NO_PAD.encode(serial_bytes);

    Ok(format!("{aki_b64}.{serial_b64}"))
}

/// Strip leading zero bytes from a byte slice (used for DER INTEGER
/// sign-padding removal).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    b
}

// ---------------------------------------------------------------------------
// EAB helper
// ---------------------------------------------------------------------------

/// Build an External Account Binding JWS object.
///
/// This is a JWS that wraps the account's public JWK, signed with the EAB
/// HMAC key, as required by CAs that mandate external account binding (e.g.
/// ZeroSSL).
fn build_eab_jws(
    account_key: &PrivateKey,
    eab: &ExternalAccountBinding,
    new_account_url: &str,
) -> Result<serde_json::Value> {
    use ring::hmac;

    let jwk = jwk_from_key(account_key)?;
    let jwk_json = serde_json::to_vec(&jwk)
        .map_err(|e| AcmeError::Account(format!("failed to serialize JWK for EAB: {e}")))?;

    #[derive(Serialize)]
    struct EabProtected<'a> {
        alg: &'static str,
        kid: &'a str,
        url: &'a str,
    }

    let protected = EabProtected {
        alg: "HS256",
        kid: &eab.kid,
        url: new_account_url,
    };
    let protected_json = serde_json::to_vec(&protected)
        .map_err(|e| AcmeError::Account(format!("failed to serialize EAB protected: {e}")))?;
    let protected_b64 = URL_SAFE_NO_PAD.encode(&protected_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&jwk_json);

    let signing_input = format!("{protected_b64}.{payload_b64}");
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &eab.hmac_key);
    let signature = hmac::sign(&hmac_key, signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

    Ok(serde_json::json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }))
}

// ---------------------------------------------------------------------------
// Nonce extraction helper
// ---------------------------------------------------------------------------

/// Extract the `Replay-Nonce` header value from an HTTP response.
fn extract_nonce(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("replay-nonce")
        .and_then(|v: &HeaderValue| v.to_str().ok())
        .map(|s| s.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyType, generate_private_key};

    #[test]
    fn test_jwk_from_key() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let jwk = jwk_from_key(&key).unwrap();
        assert_eq!(jwk.alg, "ES256");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.u, "sig");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
    }

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let jwk = jwk_from_key(&key).unwrap();
        let t1 = jwk_thumbprint(&jwk);
        let t2 = jwk_thumbprint(&jwk);
        assert_eq!(t1, t2);
        // SHA-256 => 32 bytes => ~43 base64url chars
        assert!(!t1.is_empty());
        assert!(!t1.contains('+'));
        assert!(!t1.contains('/'));
    }

    #[test]
    fn test_key_authorization_format() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let token = "test_token_12345";
        let ka = key_authorization(token, &key).unwrap();
        assert!(ka.starts_with(token));
        assert!(ka.contains('.'));
        // The part after the dot is the thumbprint.
        let parts: Vec<&str> = ka.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], token);
        assert!(!parts[1].is_empty());
    }

    #[test]
    fn test_key_authorization_deterministic() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let ka1 = key_authorization("tok", &key).unwrap();
        let ka2 = key_authorization("tok", &key).unwrap();
        assert_eq!(ka1, ka2);
    }

    #[test]
    fn test_key_authorization_sha256() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let hash = key_authorization_sha256("tok", &key).unwrap();
        assert_eq!(hash.len(), 32); // SHA-256 is 32 bytes
    }

    #[test]
    fn test_sign_with_key() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let data = b"hello world";
        let sig = sign_with_key(&key, data).unwrap();
        // P-256 fixed-size signature is 64 bytes (32 for r, 32 for s).
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_build_jws_body_with_jwk() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let body = build_jws_body(
            &key,
            None,
            "nonce123",
            "https://example.com/new-acct",
            Some("{}"),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.get("protected").is_some());
        assert!(parsed.get("payload").is_some());
        assert!(parsed.get("signature").is_some());
    }

    #[test]
    fn test_build_jws_body_with_kid() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let body = build_jws_body(
            &key,
            Some("https://example.com/acme/acct/1"),
            "nonce456",
            "https://example.com/new-order",
            Some(r#"{"identifiers":[]}"#),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.get("protected").is_some());
    }

    #[test]
    fn test_build_jws_body_post_as_get() {
        let key = generate_private_key(KeyType::EcdsaP256).unwrap();
        let body = build_jws_body(
            &key,
            Some("https://example.com/acme/acct/1"),
            "nonce789",
            "https://example.com/some-resource",
            None,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Empty payload for POST-as-GET.
        let payload = parsed.get("payload").unwrap().as_str().unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_acme_problem_display() {
        let problem = AcmeProblem {
            problem_type: "urn:ietf:params:acme:error:malformed".into(),
            detail: "something went wrong".into(),
            status: Some(400),
            subproblems: None,
        };
        let display = format!("{problem}");
        assert!(display.contains("something went wrong"));
        assert!(display.contains("malformed"));
    }

    #[test]
    fn test_acme_problem_display_no_type() {
        let problem = AcmeProblem {
            problem_type: String::new(),
            detail: "just a message".into(),
            status: None,
            subproblems: None,
        };
        let display = format!("{problem}");
        assert_eq!(display, "just a message");
    }

    #[test]
    fn test_directory_constants() {
        assert!(LETS_ENCRYPT_PRODUCTION.starts_with("https://"));
        assert!(LETS_ENCRYPT_STAGING.starts_with("https://"));
        assert!(ZEROSSL_PRODUCTION.starts_with("https://"));
        assert!(GOOGLE_TRUST_STAGING.starts_with("https://"));
        assert!(GOOGLE_TRUST_PRODUCTION.starts_with("https://"));
    }
}
