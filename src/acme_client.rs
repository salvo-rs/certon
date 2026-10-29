//! Low-level ACME protocol client (RFC 8555).
//!
//! This module implements the core ACME protocol interactions: directory
//! discovery, account registration, order creation, authorization handling,
//! challenge acceptance, order finalization, certificate download, and
//! certificate revocation.
//!
//! All requests use the JWS (JSON Web Signature) POST-as-GET convention
//! required by RFC 8555. ECDSA P-256 (ES256) is used for signing.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as crypto_provider;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use crypto_provider::rand::SystemRandom;
use crypto_provider::signature::{self, ECDSA_P256_SHA256_FIXED_SIGNING};
use reqwest::header::HeaderValue;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring as crypto_provider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::crypto::PrivateKey;
use crate::error::{AcmeError, Result};
// ---------------------------------------------------------------------------
// Configurable User-Agent
// ---------------------------------------------------------------------------
/// Set the user agent shared by all certon HTTP requests.
pub use crate::http::set_user_agent;
use crate::http::{MAX_ERROR_BODY_BYTES, MAX_JSON_BODY_BYTES, read_body_limited};

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

/// Maximum alternate-chain requests made by one download operation.
pub const MAX_ALTERNATE_CHAINS: usize = 8;
const MAX_CERTIFICATE_CHAIN_BYTES: usize = 1024 * 1024;
const MAX_ALTERNATE_DISCOVERY_TIME: Duration = Duration::from_secs(5);

fn certificate_chain_leaf(pem: &str) -> Result<Vec<u8>> {
    let certificates = crate::crypto::parse_certs_from_pem_bundle(pem)?;
    for der in &certificates {
        let (remainder, _) = x509_parser::parse_x509_certificate(der).map_err(|error| {
            AcmeError::Certificate(format!("invalid certificate in downloaded chain: {error}"))
        })?;
        if !remainder.is_empty() {
            return Err(
                AcmeError::Certificate("trailing data in downloaded certificate".into()).into(),
            );
        }
    }
    Ok(certificates
        .into_iter()
        .next()
        .expect("PEM parser requires a certificate"))
}

fn enqueue_alternate_chains(
    links: Vec<String>,
    seen: &mut HashSet<String>,
    pending: &mut VecDeque<String>,
    limit: usize,
) {
    for link in links {
        if seen.len() > limit {
            break;
        }
        if seen.insert(link.clone()) {
            pending.push_back(link);
        }
    }
}

// Split RFC 8288 lists/parameters only outside URI references and quoted
// strings. In particular commas inside <URI> or title="a,b" are not separators.
fn split_link_parts(value: &str, separator: char) -> Vec<&str> {
    let (mut quoted, mut escaped, mut target, mut start) = (false, false, false, 0);
    let mut parts = Vec::new();
    for (index, character) in value.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
        } else if target {
            if character == '>' {
                target = false;
            }
        } else {
            match character {
                '"' => quoted = true,
                '<' => target = true,
                c if c == separator => {
                    parts.push(value[start..index].trim());
                    start = index + c.len_utf8();
                }
                _ => {}
            }
        }
    }
    parts.push(value[start..].trim());
    parts
}

fn link_parameter(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.starts_with('"') {
        return Some(value.to_owned());
    }
    let quoted = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut decoded = String::new();
    let mut characters = quoted.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            decoded.push(characters.next()?);
        } else if character == '"' {
            return None;
        } else {
            decoded.push(character);
        }
    }
    Some(decoded)
}

fn alternate_certificate_links(
    headers: &reqwest::header::HeaderMap,
    base: &url::Url,
) -> Vec<String> {
    let mut links = Vec::new();
    for header in headers.get_all(reqwest::header::LINK) {
        let Ok(value) = header.to_str() else {
            continue;
        };
        for link in split_link_parts(value, ',') {
            let parts = split_link_parts(link, ';');
            let Some(target) = parts
                .first()
                .and_then(|part| part.strip_prefix('<'))
                .and_then(|part| part.strip_suffix('>'))
            else {
                continue;
            };
            let mut alternate = false;
            let mut anchored = false;
            for parameter in parts.iter().skip(1) {
                let Some((name, value)) = parameter.split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("anchor") {
                    anchored = true;
                }
                if name.trim().eq_ignore_ascii_case("rel") {
                    alternate = link_parameter(value).is_some_and(|relations| {
                        relations
                            .split_ascii_whitespace()
                            .any(|relation| relation.eq_ignore_ascii_case("alternate"))
                    });
                }
            }
            if !alternate || anchored {
                continue;
            }
            let Ok(mut target) = base.join(target) else {
                continue;
            };
            if !matches!(target.scheme(), "http" | "https")
                || !target.username().is_empty()
                || target.password().is_some()
            {
                continue;
            }
            target.set_fragment(None);
            links.push(target.to_string());
            if links.len() == MAX_ALTERNATE_CHAINS {
                return links;
            }
        }
    }
    links
}

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

/// ACME Renewal Information per RFC 9773.
///
/// Contains the server's suggested renewal window and an optional
/// explanation URL. The `selected_time` field is computed locally by
/// deriving a stable, distributed instant from the leaf and suggested window.
/// Managed certificates persist that local choice separately from wire JSON.
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

    /// The locally selected renewal time within the suggested window.
    /// This field is excluded from ACME wire JSON. Managed lifecycle state
    /// persists it explicitly in an issuer/leaf sidecar; an unchanged window
    /// keeps the same choice across refreshes and restarts.
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

const ACCOUNT_DOES_NOT_EXIST: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

/// Issuer-only classification; public order APIs keep returning the existing
/// error type even for an account-missing response.
pub(crate) enum NewOrderOutcome {
    Created(Box<AcmeOrder>, String),
    AccountDoesNotExist,
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
#[derive(Clone)]
pub struct ExternalAccountBinding {
    /// The key ID provided by the CA.
    pub kid: String,
    /// The HMAC key (raw bytes) provided by the CA.
    pub hmac_key: Vec<u8>,
}

impl std::fmt::Debug for ExternalAccountBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalAccountBinding")
            .field("kid", &self.kid)
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

/// Optional parameters sent to the CA when creating an order.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OrderOptions {
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
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
    let key_pair =
        crate::crypto::ecdsa_from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.pkcs8_der())
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
        crate::crypto::ecdsa_from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.pkcs8_der())
            .map_err(|e| {
                AcmeError::Account(format!("failed to load ECDSA key pair for signing: {e}"))
            })?;

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

#[derive(Clone, Copy)]
struct AcmeTransportPolicy {
    allow_local_http: bool,
}

impl AcmeTransportPolicy {
    fn for_directory(directory_url: &str) -> Result<Self> {
        let url = url::Url::parse(directory_url)
            .map_err(|_| AcmeError::Directory("invalid ACME directory URL".into()))?;
        let policy = Self {
            allow_local_http: url.scheme() == "http",
        };
        policy
            .validate_url(directory_url)
            .map_err(|error| AcmeError::Directory(error.to_string()))?;
        Ok(policy)
    }

    fn allows(&self, url: &url::Url) -> bool {
        url.scheme() == "https"
            || (self.allow_local_http
                && url.scheme() == "http"
                && url.host_str().is_some_and(|host| {
                    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
                        || host.ends_with(".internal")
                        || host.ends_with(".localhost")
                }))
    }

    fn validate_url(&self, endpoint: &str) -> Result<()> {
        let url = url::Url::parse(endpoint)
            .map_err(|_| crate::Error::Config("invalid ACME endpoint URL".into()))?;
        if !self.allows(&url) {
            return Err(crate::Error::Config(
                "ACME endpoints require HTTPS; HTTP is allowed only for a local HTTP directory"
                    .into(),
            ));
        }
        Ok(())
    }

    fn redirects(self) -> reqwest::redirect::Policy {
        reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > 10 {
                return attempt.error("ACME redirect limit exceeded");
            }
            if attempt.url().scheme() == "http"
                && attempt.previous().iter().any(|url| url.scheme() == "https")
            {
                return attempt.error("ACME HTTPS-to-HTTP redirect is forbidden");
            }
            if !self.allows(attempt.url()) {
                return attempt.error("ACME redirect target requires HTTPS");
            }
            attempt.follow()
        })
    }
}

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
    transport: AcmeTransportPolicy,
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
    /// `127.0.0.1`, `[::1]`, `.localhost`, and `.internal` hosts (for testing/development).
    pub async fn new(directory_url: &str) -> Result<Self> {
        Self::with_http_client_builder(directory_url, crate::http::client_builder()).await
    }

    /// Create a client using a caller-configured builder, including custom CA
    /// roots, proxy settings and timeouts. Certon overrides the redirect policy
    /// before building: every hop must obey the ACME transport policy.
    ///
    /// Already-built clients cannot be accepted because reqwest provides no
    /// way to replace or inspect their automatic redirect policy. An HTTPS
    /// directory requires HTTPS endpoints, including on localhost. A directory
    /// explicitly served over local HTTP retains the development exception.
    pub async fn with_http_client_builder(
        directory_url: &str,
        http: reqwest::ClientBuilder,
    ) -> Result<Self> {
        let mut transport = AcmeTransportPolicy::for_directory(directory_url)?;
        crate::http::install_crypto_provider();
        let http = http
            .redirect(transport.redirects())
            .build()
            .map_err(|error| {
                AcmeError::Directory(format!(
                    "failed to build ACME transport: {}",
                    error.without_url()
                ))
            })?;

        debug!(directory_url, "fetching ACME directory");

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

        // A local HTTP directory may upgrade to HTTPS, but its authenticated
        // directory contents must not send later operations back to HTTP.
        if resp.url().scheme() == "https" {
            transport.allow_local_http = false;
        }
        let body = read_body_limited(resp, MAX_JSON_BODY_BYTES, "ACME directory")
            .await
            .map_err(|e| AcmeError::Directory(e.to_string()))?;
        let directory: AcmeDirectory = serde_json::from_slice(&body)
            .map_err(|e| AcmeError::Directory(format!("failed to parse directory JSON: {e}")))?;

        for endpoint in [
            directory.new_nonce.as_str(),
            directory.new_account.as_str(),
            directory.new_order.as_str(),
            directory.revoke_cert.as_str(),
            directory.key_change.as_str(),
        ]
        .into_iter()
        .chain(directory.new_authz.as_deref())
        .chain(directory.renewal_info.as_deref())
        {
            transport
                .validate_url(endpoint)
                .map_err(|error| AcmeError::Directory(error.to_string()))?;
        }

        debug!(
            new_nonce = %directory.new_nonce,
            new_account = %directory.new_account,
            new_order = %directory.new_order,
            "ACME directory loaded"
        );

        // Get initial nonce.
        let nonce = Self::fetch_nonce_from(&http, transport, &directory.new_nonce).await?;

        Ok(Self {
            http,
            transport,
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
        Self::fetch_nonce_from(&self.http, self.transport, &self.directory.new_nonce).await
    }

    /// Fetch a nonce via HEAD request to the `new_nonce_url`.
    async fn fetch_nonce_from(
        http: &reqwest::Client,
        transport: AcmeTransportPolicy,
        new_nonce_url: &str,
    ) -> Result<String> {
        transport
            .validate_url(new_nonce_url)
            .map_err(|error| AcmeError::Nonce(error.to_string()))?;
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
        self.acme_post_accepting_problem(account_key, kid, url, payload, None)
            .await?
            .ok_or_else(|| AcmeError::Order("unexpected accepted ACME problem".into()).into())
    }

    /// Only an explicit caller may recognize a problem with its actual HTTP
    /// status and complete type URI. Other POSTs retain their original errors.
    async fn acme_post_accepting_problem(
        &self,
        account_key: &PrivateKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&str>,
        accepted_problem: Option<(u16, &str)>,
    ) -> Result<Option<reqwest::Response>> {
        self.transport
            .validate_url(url)
            .map_err(|error| AcmeError::Order(error.to_string()))?;
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

            // The actual response status, never the problem JSON's status,
            // controls recognition. Keep the original first-400 nonce retry.
            let status = resp.status();
            if (status.as_u16() == 400 && (attempt == 0 || accepted_problem.is_some()))
                || accepted_problem.is_some_and(|(code, _)| status.as_u16() == code)
            {
                // Peek at the body to see if it's a badNonce error.
                let resp_bytes = read_body_limited(resp, MAX_ERROR_BODY_BYTES, "ACME error")
                    .await
                    .map_err(|e| {
                        if status.as_u16() == 400 {
                            AcmeError::Nonce(e.to_string())
                        } else {
                            AcmeError::Order(e.to_string())
                        }
                    })?;

                if let Ok(problem) = serde_json::from_slice::<AcmeProblem>(&resp_bytes)
                    && status.as_u16() == 400
                    && problem.problem_type.contains("badNonce")
                    && attempt == 0
                {
                    warn!("bad nonce, retrying with fresh nonce");
                    continue;
                }

                // Not a badNonce error; return an error with the body we already read.
                let problem: std::result::Result<AcmeProblem, _> =
                    serde_json::from_slice(&resp_bytes);
                let detail = match problem {
                    Ok(p)
                        if accepted_problem == Some((status.as_u16(), p.problem_type.as_str())) =>
                    {
                        return Ok(None);
                    }
                    Ok(p) => format!("{p}"),
                    Err(_) => String::from_utf8_lossy(&resp_bytes).into_owned(),
                };
                let message = if status.as_u16() == 400 {
                    format!("ACME request to {url} failed (HTTP 400): {detail}")
                } else {
                    format!("ACME {url} returned HTTP {status}: {detail}")
                };
                return Err(AcmeError::Order(message).into());
            }

            return Ok(Some(resp));
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
        self.acme_post_json_accepting_problem(account_key, kid, url, payload, None)
            .await?
            .ok_or_else(|| AcmeError::Order("unexpected accepted ACME problem".into()).into())
    }

    /// Preserve an explicitly accepted status/type problem before its body is
    /// consumed, including the response after the single badNonce retry.
    async fn acme_post_json_accepting_problem<T: serde::de::DeserializeOwned>(
        &self,
        account_key: &PrivateKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&str>,
        accepted_problem: Option<(u16, &str)>,
    ) -> Result<Option<(T, Option<String>)>> {
        let Some(resp) = self
            .acme_post_accepting_problem(account_key, kid, url, payload, accepted_problem)
            .await?
        else {
            return Ok(None);
        };

        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        if !status.is_success() {
            let body = read_body_limited(resp, MAX_ERROR_BODY_BYTES, "ACME error")
                .await
                .map_err(|e| AcmeError::Order(e.to_string()))?;
            let detail = match serde_json::from_slice::<AcmeProblem>(&body) {
                Ok(p) => format!("{p}"),
                Err(_) => String::from_utf8_lossy(&body).into_owned(),
            };
            return Err(
                AcmeError::Order(format!("ACME {url} returned HTTP {status}: {detail}")).into(),
            );
        }

        let body = read_body_limited(resp, MAX_JSON_BODY_BYTES, "ACME JSON")
            .await
            .map_err(|e| AcmeError::Order(e.to_string()))?;

        let parsed: T = serde_json::from_slice(&body)
            .map_err(|e| AcmeError::Order(format!("failed to parse response JSON: {e}")))?;

        Ok(Some((parsed, location)))
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

        self.transport
            .validate_url(&self.directory.new_account)
            .map_err(|error| AcmeError::Account(error.to_string()))?;
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
            let body_bytes = read_body_limited(resp, MAX_ERROR_BODY_BYTES, "ACME account error")
                .await
                .map_err(|e| AcmeError::Account(e.to_string()))?;
            if let Ok(problem) = serde_json::from_slice::<AcmeProblem>(&body_bytes)
                && problem.problem_type == ACCOUNT_DOES_NOT_EXIST
            {
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

        let body_bytes = read_body_limited(resp, MAX_JSON_BODY_BYTES, "ACME account")
            .await
            .map_err(|e| AcmeError::Account(e.to_string()))?;

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

    /// Create a new ACME order for the specified DNS names or IP addresses.
    ///
    /// IP addresses use RFC 8738's `ip` identifier and canonical address text;
    /// DNS values are passed through unchanged. The CA must support issuance
    /// for the requested identifier types and any selected ACME profile.
    ///
    /// Returns the order object and the order URL (from `Location` header).
    pub async fn new_order(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        domains: &[String],
    ) -> Result<(AcmeOrder, String)> {
        self.new_order_with_options(account_key, account_url, domains, &OrderOptions::default())
            .await
    }

    /// Create an order including a profile and requested validity bounds.
    /// DNS names and IP addresses are encoded as in [`Self::new_order`].
    pub async fn new_order_with_options(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        domains: &[String],
        options: &OrderOptions,
    ) -> Result<(AcmeOrder, String)> {
        match self
            .new_order_inner(account_key, account_url, domains, options, false)
            .await?
        {
            NewOrderOutcome::Created(order, url) => Ok((*order, url)),
            NewOrderOutcome::AccountDoesNotExist => {
                Err(AcmeError::Order("unexpected accepted ACME problem".into()).into())
            }
        }
    }

    /// Only the issuer's initial order attempt may interpret this exact
    /// protocol response as permission to enter account recovery.
    pub(crate) async fn new_order_for_issuer(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        domains: &[String],
        options: &OrderOptions,
    ) -> Result<NewOrderOutcome> {
        self.new_order_inner(account_key, account_url, domains, options, true)
            .await
    }

    async fn new_order_inner(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        domains: &[String],
        options: &OrderOptions,
        recognize_missing_account: bool,
    ) -> Result<NewOrderOutcome> {
        debug!(?domains, "creating new ACME order");

        #[derive(Serialize)]
        struct NewOrderRequest {
            identifiers: Vec<AcmeIdentifier>,
            #[serde(flatten)]
            options: OrderOptions,
        }

        let identifiers: Vec<AcmeIdentifier> = domains
            .iter()
            .map(|domain| match domain.parse::<IpAddr>() {
                Ok(address) => AcmeIdentifier {
                    id_type: "ip".to_owned(),
                    value: address.to_string(),
                },
                Err(_) => AcmeIdentifier {
                    id_type: "dns".to_owned(),
                    value: domain.clone(),
                },
            })
            .collect();

        let req = NewOrderRequest {
            identifiers,
            options: options.clone(),
        };
        let payload = serde_json::to_string(&req)
            .map_err(|e| AcmeError::Order(format!("failed to serialize order request: {e}")))?;

        let response: Option<(AcmeOrder, _)> = self
            .acme_post_json_accepting_problem(
                account_key,
                Some(account_url),
                &self.directory.new_order,
                Some(&payload),
                recognize_missing_account.then_some((400, ACCOUNT_DOES_NOT_EXIST)),
            )
            .await?;
        let Some((order, location)) = response else {
            return Ok(NewOrderOutcome::AccountDoesNotExist);
        };

        let order_url = location.ok_or_else(|| {
            AcmeError::Order("no Location header in order creation response".into())
        })?;

        debug!(
            status = %order.status,
            order_url = %order_url,
            "ACME order created"
        );

        Ok(NewOrderOutcome::Created(Box::new(order), order_url))
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
    /// the timeout expires. The total budget includes HTTP requests, nonce
    /// retries, response bodies and backoff waits.
    pub async fn poll_authorization(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        authz_url: &str,
        timeout: Duration,
    ) -> Result<AcmeAuthorization> {
        tokio::time::timeout(
            timeout,
            self.poll_authorization_until_terminal(account_key, account_url, authz_url, timeout),
        )
        .await
        .map_err(|_| {
            crate::error::Error::Timeout(format!(
                "authorization polling timed out after {timeout:?}"
            ))
        })?
    }

    async fn poll_authorization_until_terminal(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        authz_url: &str,
        timeout: Duration,
    ) -> Result<AcmeAuthorization> {
        debug!(authz_url, ?timeout, "polling authorization");

        let started = tokio::time::Instant::now();
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

            if started.elapsed().saturating_add(interval) > timeout {
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
        self.finalize_order_inner(account_key, account_url, finalize_url, csr_der, false)
            .await?
            .ok_or_else(|| AcmeError::Order("unexpected accepted ACME problem".into()).into())
    }

    async fn finalize_order_inner(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        finalize_url: &str,
        csr_der: &[u8],
        recognize_not_ready: bool,
    ) -> Result<Option<AcmeOrder>> {
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

        let response: Option<(AcmeOrder, _)> = self
            .acme_post_json_accepting_problem(
                account_key,
                Some(account_url),
                finalize_url,
                Some(&payload),
                recognize_not_ready.then_some((403, "urn:ietf:params:acme:error:orderNotReady")),
            )
            .await?;
        Ok(response.map(|(order, _)| order))
    }

    /// Continue one issuer order without registering again or replaying its
    /// authorizations. Public finalize/poll methods keep their original behavior.
    pub(crate) async fn complete_order_for_issuer(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        order_url: &str,
        finalize_url: &str,
        csr_der: &[u8],
        deadline: Instant,
    ) -> Result<AcmeOrder> {
        tokio::time::timeout_at(deadline, async {
            let mut order = self
                .finalize_order_inner(account_key, account_url, finalize_url, csr_der, true)
                .await?;
            let mut interval = Duration::from_secs(1);
            let mut polled = false;
            loop {
                match order.as_ref().map(|order| order.status.as_str()) {
                    Some("valid") => return Ok(order.expect("valid order")),
                    Some("invalid") => {
                        let detail = order
                            .as_ref()
                            .and_then(|order| order.error.as_ref())
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".into());
                        return Err(AcmeError::Order(format!("order failed: {detail}")).into());
                    }
                    Some("ready") => {
                        // Even an advertised-ready order may reject finalization
                        // again. Back off before every repeated CSR submission.
                        tokio::time::sleep(interval).await;
                        interval = (interval * 2).min(Duration::from_secs(30));
                        order = self
                            .finalize_order_inner(
                                account_key,
                                account_url,
                                finalize_url,
                                csr_der,
                                true,
                            )
                            .await?;
                        continue;
                    }
                    Some("pending" | "processing") => {
                        if polled {
                            tokio::time::sleep(interval).await;
                            interval = (interval * 2).min(Duration::from_secs(30));
                        }
                    }
                    None => {} // Exact 403/orderNotReady: inspect the same order now.
                    Some(status) => {
                        let detail = order
                            .as_ref()
                            .and_then(|order| order.error.as_ref())
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".into());
                        return Err(AcmeError::Order(format!(
                            "unexpected order status: {status}: {detail}"
                        ))
                        .into());
                    }
                }
                let (current, _): (AcmeOrder, _) = self
                    .acme_post_json(account_key, Some(account_url), order_url, None)
                    .await?;
                order = Some(current);
                polled = true;
            }
        })
        .await
        .map_err(|_| {
            crate::error::Error::Timeout(
                "order finalization and polling exceeded the issuance deadline".into(),
            )
        })?
    }

    /// Poll an order URL until its status is `valid`, `invalid`, or the
    /// timeout expires. The total budget includes HTTP requests, nonce
    /// retries, response bodies and backoff waits.
    pub async fn poll_order(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        order_url: &str,
        timeout: Duration,
    ) -> Result<AcmeOrder> {
        tokio::time::timeout(
            timeout,
            self.poll_order_until_terminal(account_key, account_url, order_url, timeout),
        )
        .await
        .map_err(|_| {
            crate::error::Error::Timeout(format!("order polling timed out after {timeout:?}"))
        })?
    }

    async fn poll_order_until_terminal(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        order_url: &str,
        timeout: Duration,
    ) -> Result<AcmeOrder> {
        debug!(order_url, ?timeout, "polling order");

        let started = tokio::time::Instant::now();
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

            if started.elapsed().saturating_add(interval) > timeout {
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

    /// Download only the CA's default certificate chain (PEM).
    /// The response body is limited to 1 MiB. Alternate links are not followed.
    pub async fn download_certificate(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_url: &str,
    ) -> Result<String> {
        self.download_certificate_response(account_key, account_url, cert_url)
            .await
            .map(|(pem, _)| pem)
    }

    /// Download the default PEM chain and up to `max_alternates` alternatives
    /// advertised with `Link: ...; rel="alternate"`. The request count is capped
    /// at eight alternates even if a larger limit is supplied. Each response is
    /// limited to 1 MiB, duplicate/cyclic URLs are fetched at most once, and
    /// failed or malformed alternatives are ignored. Alternatives must contain
    /// the same leaf certificate as the default chain. Chain order is preserved.
    /// All alternate requests share a five-second budget after the default has
    /// arrived; expiration returns the chains already downloaded.
    pub async fn download_certificate_chains(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_url: &str,
        max_alternates: usize,
    ) -> Result<Vec<String>> {
        self.download_certificate_chains_with_deadline(
            account_key,
            account_url,
            cert_url,
            max_alternates,
            None,
        )
        .await
    }

    /// Reserve time to return an already-issued certificate before the caller's
    /// overall issuance deadline. The deadline spans all prior work and retries.
    pub(crate) async fn download_certificate_chains_with_deadline(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_url: &str,
        max_alternates: usize,
        issuance_deadline: Option<Instant>,
    ) -> Result<Vec<String>> {
        let limit = max_alternates.min(MAX_ALTERNATE_CHAINS);
        let (default, links) = self
            .download_certificate_response(account_key, account_url, cert_url)
            .await?;
        let now = Instant::now();
        // Discovery is optional: spend at most half of the caller's remaining
        // time, leaving the other half for chain selection and returning the
        // valid default. This also handles time already spent before download.
        let discovery_budget = issuance_deadline.map_or(MAX_ALTERNATE_DISCOVERY_TIME, |deadline| {
            MAX_ALTERNATE_DISCOVERY_TIME.min(deadline.saturating_duration_since(now) / 2)
        });
        let discovery_deadline = now + discovery_budget;
        let leaf = certificate_chain_leaf(&default)?;
        let mut chains = vec![default];
        let mut seen = HashSet::new();
        if let Ok(mut primary) = url::Url::parse(cert_url) {
            primary.set_fragment(None);
            seen.insert(primary.to_string());
        }
        let mut pending = VecDeque::new();
        enqueue_alternate_chains(links, &mut seen, &mut pending, limit);
        while let Some(url) = pending.pop_front() {
            if Instant::now() >= discovery_deadline {
                break;
            }
            let download = tokio::time::timeout_at(
                discovery_deadline,
                self.download_certificate_response(account_key, account_url, &url),
            )
            .await;
            match download {
                Ok(Ok((pem, links))) => match certificate_chain_leaf(&pem) {
                    Ok(alternate_leaf) if alternate_leaf == leaf => {
                        if !chains.contains(&pem) {
                            chains.push(pem);
                        }
                        enqueue_alternate_chains(links, &mut seen, &mut pending, limit);
                    }
                    _ => warn!(
                        url,
                        "ignoring alternate chain with an invalid or different leaf certificate"
                    ),
                },
                Ok(Err(error)) => {
                    warn!(url, %error, "ignoring unavailable alternate certificate chain")
                }
                Err(_) => {
                    debug!(
                        chain_count = chains.len(),
                        "alternate discovery budget exhausted; keeping downloaded chains"
                    );
                    break;
                }
            }
        }
        Ok(chains)
    }

    async fn download_certificate_response(
        &self,
        account_key: &PrivateKey,
        account_url: &str,
        cert_url: &str,
    ) -> Result<(String, Vec<String>)> {
        debug!(cert_url, "downloading certificate");
        let mut response = self
            .acme_post(account_key, Some(account_url), cert_url, None)
            .await?;
        if !response.status().is_success() {
            return Err(AcmeError::Certificate(format!(
                "certificate download returned HTTP {}",
                response.status()
            ))
            .into());
        }
        let links = alternate_certificate_links(response.headers(), response.url());
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CERTIFICATE_CHAIN_BYTES as u64)
        {
            return Err(
                AcmeError::Certificate("certificate response exceeds 1 MiB limit".into()).into(),
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            AcmeError::Certificate(format!("failed to read certificate body: {error}"))
        })? {
            if chunk.len() > MAX_CERTIFICATE_CHAIN_BYTES - body.len() {
                return Err(AcmeError::Certificate(
                    "certificate response exceeds 1 MiB limit".into(),
                )
                .into());
            }
            body.extend_from_slice(&chunk);
        }
        let pem = String::from_utf8(body).map_err(|error| {
            AcmeError::Certificate(format!("certificate response is not UTF-8 PEM: {error}"))
        })?;
        debug!(cert_url, len = pem.len(), "certificate downloaded");
        Ok((pem, links))
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

        let Some(resp) = self
            .acme_post_accepting_problem(
                account_key,
                Some(account_url),
                &self.directory.revoke_cert,
                Some(&payload),
                Some((400, "urn:ietf:params:acme:error:alreadyRevoked")),
            )
            .await?
        else {
            // RFC 8555 section 7.6: this exact problem confirms that the
            // requested certificate has already been revoked.
            debug!("certificate was already revoked");
            return Ok(());
        };

        let status = resp.status();
        if !status.is_success() {
            let body = read_body_limited(resp, MAX_ERROR_BODY_BYTES, "ACME revocation error")
                .await
                .map_err(|e| AcmeError::Certificate(e.to_string()))?;
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
    /// Performs an unauthenticated GET to `{directory.renewalInfo}/{cert_id}`. If the
    /// directory does not advertise a `renewalInfo` endpoint, returns a
    /// default (empty) [`RenewalInfo`].
    pub async fn get_renewal_info(
        &self,
        _account_key: &PrivateKey,
        _account_url: &str,
        cert_id: &str,
    ) -> Result<RenewalInfo> {
        self.fetch_renewal_info(cert_id)
            .await
            .map(|info| info.unwrap_or_default())
    }

    pub(crate) async fn fetch_renewal_info(&self, cert_id: &str) -> Result<Option<RenewalInfo>> {
        let renewal_info_base = match &self.directory.renewal_info {
            Some(url) => url.clone(),
            None => {
                debug!("ACME directory does not advertise renewalInfo endpoint");
                return Ok(None);
            }
        };

        let url = format!("{}/{}", renewal_info_base.trim_end_matches('/'), cert_id);
        self.transport
            .validate_url(&url)
            .map_err(|error| AcmeError::Certificate(error.to_string()))?;
        debug!(url = %url, "fetching ACME Renewal Information (ARI)");

        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_timeout() {
                crate::Error::Timeout("ARI request timed out".into())
            } else {
                AcmeError::Certificate(format!("ARI request failed: {}", e.without_url())).into()
            }
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body = read_body_limited(resp, MAX_ERROR_BODY_BYTES, "ACME ARI error")
                .await
                .map_err(|e| AcmeError::Certificate(e.to_string()))?;
            let detail = String::from_utf8_lossy(&body);
            warn!(
                status = %status,
                detail = %detail,
                "ARI request returned non-success status"
            );
            if status.is_server_error() {
                return Err(
                    AcmeError::RenewalInfoTemporary(format!("server returned {status}")).into(),
                );
            }
            return Ok(None);
        }

        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .and_then(|value| {
                value.parse::<u64>().ok().or_else(|| {
                    chrono::DateTime::parse_from_rfc2822(value)
                        .ok()
                        .map(|date| {
                            (date.with_timezone(&Utc) - Utc::now()).num_seconds().max(0) as u64
                        })
                })
            });
        let body = read_body_limited(resp, MAX_JSON_BODY_BYTES, "ACME ARI")
            .await
            .map_err(|e| AcmeError::Certificate(e.to_string()))?;

        let mut info: RenewalInfo = serde_json::from_slice(&body).map_err(|e| {
            AcmeError::Certificate(format!("failed to parse ARI response JSON: {e}"))
        })?;
        info.retry_after = retry_after;
        if let Some(window) = &info.suggested_window {
            let start = DateTime::parse_from_rfc3339(&window.start).ok();
            let end = DateTime::parse_from_rfc3339(&window.end).ok();
            if !matches!((start, end), (Some(start), Some(end)) if start < end) {
                return Err(AcmeError::Certificate("ARI renewal window is invalid".into()).into());
            }
        }

        debug!(?info, "ACME Renewal Information fetched");

        Ok(Some(info))
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
/// value and serial is the certificate's DER INTEGER content, including any
/// leading zero byte required to keep the integer positive.
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
            && let Some(key_id) = &aki.key_identifier
        {
            aki_bytes = Some(key_id.0.to_vec());
            break;
        }
    }

    let aki_bytes = aki_bytes.ok_or_else(|| {
        AcmeError::Certificate(
            "certificate has no Authority Key Identifier extension with keyIdentifier".into(),
        )
    })?;

    // RFC 9773 encodes the DER INTEGER content, including its sign padding.
    let serial_bytes = cert.raw_serial();

    let aki_b64 = URL_SAFE_NO_PAD.encode(&aki_bytes);
    let serial_b64 = URL_SAFE_NO_PAD.encode(serial_bytes);

    Ok(format!("{aki_b64}.{serial_b64}"))
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
    use crypto_provider::hmac;

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
    fn ari_identifier_keeps_der_serial_sign_padding() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::new(params, key);
        let mut leaf = rcgen::CertificateParams::new(vec!["ari.example.com".into()]).unwrap();
        leaf.use_authority_key_identifier_extension = true;
        leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x87, 0x65, 0x43, 0x21]));
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        let id = ari_cert_id(cert.der()).unwrap();
        assert_eq!(id.split_once('.').unwrap().1, "AIdlQyE");
    }

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
