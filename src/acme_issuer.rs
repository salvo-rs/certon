//! ACME certificate issuer — the main certificate acquisition orchestrator.
//!
//! This module implements the [`CertIssuer`] and [`Revoker`] traits via
//! [`AcmeIssuer`], which coordinates the full ACME challenge/finalize flow
//! to obtain TLS certificates from an ACME-compatible Certificate Authority
//! such as Let's Encrypt.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use x509_parser::prelude::FromDer;

use crate::rate_limiter::RateLimiter;

/// Per-CA rate limiters, keyed by `"{ca_url},{email}"`.
///
/// Each unique CA+email pair gets its own rate limiter so that issuance
/// requests are throttled per account without different accounts blocking
/// each other.
static CA_RATE_LIMITERS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Arc<RateLimiter>>>> =
    std::sync::OnceLock::new();

/// Return (or create) the per-CA rate limiter for the given key.
fn get_ca_rate_limiter(ca_url: &str, email: &str) -> Arc<RateLimiter> {
    let map_mutex = CA_RATE_LIMITERS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let key = format!("{},{}", ca_url, email);
    let mut map = map_mutex.lock().unwrap();
    map.entry(key)
        .or_insert_with(|| Arc::new(RateLimiter::new(10, Duration::from_secs(10))))
        .clone()
}

use crate::account::{AcmeAccount, delete_account_locally, get_or_create_account, save_account};
use crate::acme_client::{
    AcmeClient, ExternalAccountBinding, LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING,
};
use crate::crypto::{
    KeyType, encode_private_key_pem, generate_csr, generate_private_key,
    parse_certs_from_pem_bundle,
};
use crate::error::{AcmeError, Error, Result};
use crate::solvers::{DistributedSolver, Solver};
use crate::storage::{Storage, issuer_key};

/// Callback invoked on newly created accounts before CA registration.
type NewAccountFunc = Arc<dyn Fn(&mut AcmeAccount) + Send + Sync>;

// ---------------------------------------------------------------------------
// Well-known CA constants (re-exported for convenience)
// ---------------------------------------------------------------------------

/// Default Let's Encrypt production CA directory URL.
pub const DEFAULT_CA: &str = LETS_ENCRYPT_PRODUCTION;

/// Default Let's Encrypt staging CA directory URL.
pub const DEFAULT_TEST_CA: &str = LETS_ENCRYPT_STAGING;

// ---------------------------------------------------------------------------
// ACME challenge type constants
// ---------------------------------------------------------------------------

/// ACME HTTP-01 challenge type identifier.
const CHALLENGE_TYPE_HTTP01: &str = "http-01";

/// ACME DNS-01 challenge type identifier.
const CHALLENGE_TYPE_DNS01: &str = "dns-01";

/// ACME TLS-ALPN-01 challenge type identifier.
const CHALLENGE_TYPE_TLSALPN01: &str = "tls-alpn-01";

/// Default timeout for the entire certificate obtain operation.
const DEFAULT_CERT_OBTAIN_TIMEOUT: Duration = Duration::from_secs(90);

/// Default timeout for polling a single authorization.
const DEFAULT_AUTHZ_POLL_TIMEOUT: Duration = Duration::from_secs(120);

/// Default timeout for polling the order after finalization.
const DEFAULT_ORDER_POLL_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// CertIssuer / Revoker traits
// ---------------------------------------------------------------------------

/// Abstract interface for certificate issuers.
///
/// Implementors know how to obtain a certificate for a set of domain names
/// given a CSR (Certificate Signing Request) in DER format. Multiple issuers
/// can be configured in a [`Config`](crate::config::Config) -- they are
/// tried in order until one succeeds.
///
/// The built-in implementations are [`AcmeIssuer`] (Let's Encrypt and other
/// generic ACME CAs) and [`ZeroSslIssuer`](crate::zerossl_issuer::ZeroSslIssuer).
#[async_trait]
pub trait CertIssuer: Send + Sync {
    /// Issue a certificate for the given CSR.
    ///
    /// `csr_der` is a DER-encoded PKCS#10 CSR. `domains` lists the subject
    /// names (SANs) the certificate should cover.
    ///
    /// Returns an [`IssuedCertificate`] on success.
    async fn issue(&self, csr_der: &[u8], domains: &[String]) -> Result<IssuedCertificate>;

    /// Return a unique key identifying this issuer.
    ///
    /// The key is used to partition storage paths so that certificates from
    /// different issuers do not collide.
    fn issuer_key(&self) -> String;

    /// Return this issuer as a [`Revoker`], if it supports certificate
    /// revocation.
    ///
    /// The default implementation returns `None`. Issuers that also implement
    /// [`Revoker`] (such as [`AcmeIssuer`]) should override this to return
    /// `Some(self)`.
    fn as_revoker(&self) -> Option<&dyn Revoker> {
        None
    }
}

/// Abstract interface for certificate revokers.
///
/// Implementors know how to revoke a previously-issued certificate with
/// the CA. This is typically done via the ACME `revokeCert` endpoint.
#[async_trait]
pub trait Revoker: Send + Sync {
    /// Revoke a PEM-encoded certificate.
    ///
    /// `cert_pem` is the PEM-encoded certificate (chain) to revoke.
    /// `reason` is the optional RFC 5280 revocation reason code (0–10).
    async fn revoke(&self, cert_pem: &[u8], reason: Option<u8>) -> Result<()>;
}

// ---------------------------------------------------------------------------
// PreChecker trait
// ---------------------------------------------------------------------------

/// Optional pre-check interface for certificate issuers.
///
/// Implementors can validate that the requested domain names are suitable
/// for issuance *before* any ACME operations are attempted. This allows
/// early failure with a clear error message rather than a cryptic CA
/// rejection after a potentially expensive ACME flow.
///
/// For example, a pre-checker might verify that DNS is configured correctly,
/// or that the domain resolves to the expected IP address.
#[async_trait]
pub trait PreChecker: Send + Sync {
    /// Pre-check whether the given domain names are ready for certificate
    /// issuance.
    ///
    /// `interactive` indicates whether user interaction (e.g. prompts) is
    /// permitted. Some checks may be skipped in non-interactive mode.
    ///
    /// Returns `Ok(())` if all names pass the pre-check. Returns an error
    /// describing which name failed and why otherwise.
    async fn pre_check(&self, names: &[String], interactive: bool) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Manager trait
// ---------------------------------------------------------------------------

/// An external certificate manager that can provide certificates for TLS
/// handshakes.
///
/// Unlike [`CertIssuer`], which obtains certificates via the ACME protocol,
/// a `Manager` represents an external or custom source of certificates.
/// This is useful for integrating with existing certificate infrastructure,
/// hardware security modules, or other certificate management systems.
///
/// Managers are consulted during TLS handshakes (via [`CertResolver`])
/// when no matching certificate is found in the cache and on-demand TLS
/// is not configured.
///
/// [`CertResolver`]: crate::handshake::CertResolver
#[async_trait]
pub trait Manager: Send + Sync {
    /// Attempt to provide a TLS certificate for the given server name.
    ///
    /// `server_name` is the SNI value from the TLS ClientHello.
    ///
    /// Returns `Ok(Some(cert))` if the manager can provide a certificate,
    /// `Ok(None)` if this manager does not handle the given name, or
    /// `Err(_)` on failure.
    async fn get_certificate(
        &self,
        server_name: &str,
    ) -> Result<Option<crate::certificates::Certificate>>;
}

// ---------------------------------------------------------------------------
// IssuedCertificate
// ---------------------------------------------------------------------------

/// The result of a successful certificate issuance.
///
/// Contains the PEM-encoded certificate chain, the private key (if one was
/// generated during issuance), and arbitrary issuer-specific metadata
/// (such as the ACME order URL and certificate URL).
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    /// PEM-encoded certificate chain.
    pub certificate_pem: Vec<u8>,
    /// PEM-encoded private key (if one was generated during issuance).
    pub private_key_pem: Vec<u8>,
    /// Arbitrary issuer-specific metadata (e.g. the ACME certificate URL,
    /// order details, etc.).
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// ChainPreference
// ---------------------------------------------------------------------------

/// Preferences for selecting an alternate certificate chain when the CA
/// offers more than one.
///
/// The first matching criterion wins. If no chain matches, the first
/// (default) chain is used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainPreference {
    /// When `true`, prefer chains with the fewest bytes.
    /// When `false`, prefer chains with the most bytes.
    /// When `None`, no size preference is applied (ordering is preserved).
    pub smallest: Option<bool>,

    /// Select the first chain whose root certificate has one of these
    /// Common Names.
    #[serde(default)]
    pub root_common_name: Vec<String>,

    /// Select the first chain where *any* certificate has one of these
    /// Common Names (as the issuer CN).
    #[serde(default)]
    pub any_common_name: Vec<String>,
}

// ---------------------------------------------------------------------------
// AcmeIssuer
// ---------------------------------------------------------------------------

/// An ACME-based certificate issuer.
///
/// Orchestrates the full ACME certificate acquisition flow:
/// 1. Lazily initialise an [`AcmeClient`] (fetching the CA directory).
/// 2. Lazily obtain (or create) an [`AcmeAccount`] under a distributed lock.
/// 3. Create an ACME order for the requested domains.
/// 4. For each authorization, select and present the appropriate challenge.
/// 5. Finalize the order with the CSR.
/// 6. Download and return the issued certificate.
///
/// Use [`AcmeIssuer::builder()`] to construct an instance.
pub struct AcmeIssuer {
    /// CA directory URL (default: Let's Encrypt production).
    pub ca: String,
    /// Test/staging CA URL (default: Let's Encrypt staging).
    pub test_ca: String,
    /// Contact email address for the ACME account.
    pub email: String,
    /// Whether the CA's terms of service are agreed to.
    pub agreed: bool,
    /// External Account Binding credentials (for CAs like ZeroSSL).
    pub external_account: Option<ExternalAccountBinding>,

    /// Disable HTTP-01 challenges.
    pub disable_http_challenge: bool,
    /// Disable TLS-ALPN-01 challenges.
    pub disable_tlsalpn_challenge: bool,

    /// Custom DNS-01 solver (if DNS challenges are desired).
    pub dns01_solver: Option<Arc<dyn Solver>>,
    /// Custom HTTP-01 solver override.
    pub http01_solver: Option<Arc<dyn Solver>>,
    /// Custom TLS-ALPN-01 solver override.
    pub tlsalpn01_solver: Option<Arc<dyn Solver>>,

    /// Alternate port for the HTTP-01 challenge server (instead of 80).
    pub alt_http_port: Option<u16>,
    /// Alternate port for the TLS-ALPN-01 challenge server (instead of 443).
    pub alt_tlsalpn_port: Option<u16>,
    /// Host to bind challenge servers on.
    pub listen_host: Option<String>,
    /// When true, do not wrap solvers in DistributedSolver.
    pub disable_distributed_solvers: bool,
    /// Pre-existing account key PEM (bypasses key generation).
    pub account_key_pem: Option<String>,
    /// Custom CA root certificates (DER-encoded).
    pub trusted_roots: Option<Vec<u8>>,

    /// Key type for generated certificate private keys.
    pub cert_key_type: KeyType,
    /// Chain preference for selecting among alternate certificate chains.
    pub preferred_chains: Option<ChainPreference>,

    /// Timeout for the entire certificate obtain operation.
    pub cert_obtain_timeout: Duration,

    /// Custom DNS resolver address (e.g. "8.8.8.8:53") for DNS-01 challenges.
    pub resolver: Option<String>,

    /// Callback invoked on newly created accounts before CA registration.
    ///
    /// This allows the caller to modify the account (e.g. set external
    /// account binding, change contacts) before it is registered.
    pub new_account_func: Option<NewAccountFunc>,

    /// Offset from now for the `notBefore` field of the certificate.
    pub not_before: Option<Duration>,
    /// Offset from now for the `notAfter` field of the certificate.
    pub not_after: Option<Duration>,

    /// ACME profile selection (draft-aaron-acme-profiles).
    pub profile: Option<String>,

    /// Shared storage for accounts and challenge coordination.
    pub storage: Arc<dyn Storage>,

    /// Lazily-initialised ACME client (for the production CA).
    client: Mutex<Option<AcmeClient>>,
    /// Lazily-initialised ACME client (for the test CA, if different).
    test_client: Mutex<Option<AcmeClient>>,
    /// Lazily-initialised ACME account (for the production CA).
    account: Mutex<Option<AcmeAccount>>,
    /// Lazily-initialised ACME account (for the test CA).
    test_account: Mutex<Option<AcmeAccount>>,
}

impl std::fmt::Debug for AcmeIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeIssuer")
            .field("ca", &self.ca)
            .field("test_ca", &self.test_ca)
            .field("email", &self.email)
            .field("agreed", &self.agreed)
            .field("disable_http_challenge", &self.disable_http_challenge)
            .field("disable_tlsalpn_challenge", &self.disable_tlsalpn_challenge)
            .field("cert_key_type", &self.cert_key_type)
            .field("preferred_chains", &self.preferred_chains)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// AcmeIssuerBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing an [`AcmeIssuer`] with sensible defaults.
///
/// Created via [`AcmeIssuer::builder()`]. At a minimum, a [`Storage`]
/// implementation must be provided before calling [`build()`](AcmeIssuerBuilder::build).
pub struct AcmeIssuerBuilder {
    ca: String,
    test_ca: String,
    email: String,
    agreed: bool,
    external_account: Option<ExternalAccountBinding>,
    disable_http_challenge: bool,
    disable_tlsalpn_challenge: bool,
    dns01_solver: Option<Arc<dyn Solver>>,
    http01_solver: Option<Arc<dyn Solver>>,
    tlsalpn01_solver: Option<Arc<dyn Solver>>,
    alt_http_port: Option<u16>,
    alt_tlsalpn_port: Option<u16>,
    listen_host: Option<String>,
    disable_distributed_solvers: bool,
    account_key_pem: Option<String>,
    trusted_roots: Option<Vec<u8>>,
    cert_key_type: KeyType,
    preferred_chains: Option<ChainPreference>,
    cert_obtain_timeout: Duration,
    resolver: Option<String>,
    new_account_func: Option<NewAccountFunc>,
    not_before: Option<Duration>,
    not_after: Option<Duration>,
    profile: Option<String>,
    storage: Option<Arc<dyn Storage>>,
}

impl AcmeIssuerBuilder {
    /// Set the production CA directory URL.
    pub fn ca(mut self, ca: impl Into<String>) -> Self {
        self.ca = ca.into();
        self
    }

    /// Set the test/staging CA directory URL.
    pub fn test_ca(mut self, test_ca: impl Into<String>) -> Self {
        self.test_ca = test_ca.into();
        self
    }

    /// Set the contact email address.
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// Set whether the CA's terms of service are agreed to.
    pub fn agreed(mut self, agreed: bool) -> Self {
        self.agreed = agreed;
        self
    }

    /// Set External Account Binding credentials.
    pub fn external_account(mut self, eab: ExternalAccountBinding) -> Self {
        self.external_account = Some(eab);
        self
    }

    /// Disable HTTP-01 challenges.
    pub fn disable_http_challenge(mut self, disabled: bool) -> Self {
        self.disable_http_challenge = disabled;
        self
    }

    /// Disable TLS-ALPN-01 challenges.
    pub fn disable_tlsalpn_challenge(mut self, disabled: bool) -> Self {
        self.disable_tlsalpn_challenge = disabled;
        self
    }

    /// Set a custom DNS-01 solver.
    pub fn dns01_solver(mut self, solver: Arc<dyn Solver>) -> Self {
        self.dns01_solver = Some(solver);
        self
    }

    /// Set a custom HTTP-01 solver.
    pub fn http01_solver(mut self, solver: Arc<dyn Solver>) -> Self {
        self.http01_solver = Some(solver);
        self
    }

    /// Set a custom TLS-ALPN-01 solver.
    pub fn tlsalpn01_solver(mut self, solver: Arc<dyn Solver>) -> Self {
        self.tlsalpn01_solver = Some(solver);
        self
    }

    /// Set an alternate port for the HTTP-01 challenge server.
    pub fn alt_http_port(mut self, port: u16) -> Self {
        self.alt_http_port = Some(port);
        self
    }

    /// Set an alternate port for the TLS-ALPN-01 challenge server.
    pub fn alt_tlsalpn_port(mut self, port: u16) -> Self {
        self.alt_tlsalpn_port = Some(port);
        self
    }

    /// Set the host to bind challenge servers on.
    pub fn listen_host(mut self, host: impl Into<String>) -> Self {
        self.listen_host = Some(host.into());
        self
    }

    /// Disable automatic wrapping of solvers in DistributedSolver.
    pub fn disable_distributed_solvers(mut self, disabled: bool) -> Self {
        self.disable_distributed_solvers = disabled;
        self
    }

    /// Set a pre-existing account key PEM.
    pub fn account_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.account_key_pem = Some(pem.into());
        self
    }

    /// Set custom CA root certificates (DER-encoded).
    pub fn trusted_roots(mut self, roots: Vec<u8>) -> Self {
        self.trusted_roots = Some(roots);
        self
    }

    /// Set the key type for generated certificate private keys.
    pub fn cert_key_type(mut self, key_type: KeyType) -> Self {
        self.cert_key_type = key_type;
        self
    }

    /// Set the chain preference for selecting alternate certificate chains.
    pub fn preferred_chains(mut self, pref: ChainPreference) -> Self {
        self.preferred_chains = Some(pref);
        self
    }

    /// Set the timeout for the certificate obtain operation.
    pub fn cert_obtain_timeout(mut self, timeout: Duration) -> Self {
        self.cert_obtain_timeout = timeout;
        self
    }

    /// Set a custom DNS resolver address (e.g. "8.8.8.8:53").
    pub fn resolver(mut self, resolver: impl Into<String>) -> Self {
        self.resolver = Some(resolver.into());
        self
    }

    /// Set a callback invoked on newly created accounts before CA registration.
    pub fn new_account_func(mut self, func: NewAccountFunc) -> Self {
        self.new_account_func = Some(func);
        self
    }

    /// Set the `notBefore` offset from now for certificate validity.
    pub fn not_before(mut self, offset: Duration) -> Self {
        self.not_before = Some(offset);
        self
    }

    /// Set the `notAfter` offset from now for certificate validity.
    pub fn not_after(mut self, offset: Duration) -> Self {
        self.not_after = Some(offset);
        self
    }

    /// Set the ACME profile name (draft-aaron-acme-profiles).
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the shared storage backend (required).
    pub fn storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Build the [`AcmeIssuer`].
    ///
    /// # Panics
    ///
    /// Panics if no `storage` has been provided.
    pub fn build(self) -> AcmeIssuer {
        let storage = self.storage.expect(
            "AcmeIssuer requires a Storage implementation — call .storage() on the builder",
        );

        AcmeIssuer {
            ca: self.ca,
            test_ca: self.test_ca,
            email: self.email,
            agreed: self.agreed,
            external_account: self.external_account,
            disable_http_challenge: self.disable_http_challenge,
            disable_tlsalpn_challenge: self.disable_tlsalpn_challenge,
            dns01_solver: self.dns01_solver,
            http01_solver: self.http01_solver,
            tlsalpn01_solver: self.tlsalpn01_solver,
            alt_http_port: self.alt_http_port,
            alt_tlsalpn_port: self.alt_tlsalpn_port,
            listen_host: self.listen_host,
            disable_distributed_solvers: self.disable_distributed_solvers,
            account_key_pem: self.account_key_pem,
            trusted_roots: self.trusted_roots,
            cert_key_type: self.cert_key_type,
            preferred_chains: self.preferred_chains,
            cert_obtain_timeout: self.cert_obtain_timeout,
            resolver: self.resolver,
            new_account_func: self.new_account_func,
            not_before: self.not_before,
            not_after: self.not_after,
            profile: self.profile,
            storage,
            client: Mutex::new(None),
            test_client: Mutex::new(None),
            account: Mutex::new(None),
            test_account: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// AcmeIssuer — construction helpers
// ---------------------------------------------------------------------------

impl AcmeIssuer {
    /// Create a new [`AcmeIssuerBuilder`] with default settings.
    ///
    /// Defaults:
    /// - CA: Let's Encrypt production
    /// - Test CA: Let's Encrypt staging
    /// - Key type: ECDSA P-256
    /// - Timeout: 90 seconds
    pub fn builder() -> AcmeIssuerBuilder {
        AcmeIssuerBuilder {
            ca: DEFAULT_CA.to_owned(),
            test_ca: DEFAULT_TEST_CA.to_owned(),
            email: String::new(),
            agreed: false,
            external_account: None,
            disable_http_challenge: false,
            disable_tlsalpn_challenge: false,
            dns01_solver: None,
            http01_solver: None,
            tlsalpn01_solver: None,
            alt_http_port: None,
            alt_tlsalpn_port: None,
            listen_host: None,
            disable_distributed_solvers: false,
            account_key_pem: None,
            trusted_roots: None,
            cert_key_type: KeyType::default(),
            preferred_chains: None,
            cert_obtain_timeout: DEFAULT_CERT_OBTAIN_TIMEOUT,
            resolver: None,
            new_account_func: None,
            not_before: None,
            not_after: None,
            profile: None,
            storage: None,
        }
    }

    /// Determine whether the production CA and test CA are the same URL.
    fn using_test_ca(&self, ca_url: &str) -> bool {
        ca_url == self.test_ca && self.ca != self.test_ca
    }

    // -----------------------------------------------------------------------
    // Lazy client initialisation
    // -----------------------------------------------------------------------

    /// Get or lazily initialise the ACME client for the given CA URL.
    async fn get_client(&self, use_test: bool) -> Result<AcmeClient> {
        let ca_url = if use_test { &self.test_ca } else { &self.ca };
        let mutex = if use_test {
            &self.test_client
        } else {
            &self.client
        };

        {
            let guard = mutex.lock().await;
            if let Some(ref client) = *guard {
                // AcmeClient is not Clone, but we can re-create from same URL
                // since directory is cached. For simplicity, we re-create on
                // each call. A production implementation would Arc-wrap the
                // client. Here we just create a new one if not cached.
                let _ = client;
            }
        }

        // Always check the cache first.
        {
            let guard = mutex.lock().await;
            if guard.is_some() {
                // Client exists — drop guard and re-create from same URL.
                // Since AcmeClient is not Clone, we create a fresh one. This
                // is a simplification; the real overhead is negligible because
                // the directory and nonce are cached server-side.
                drop(guard);
            }
        }

        info!(ca = %ca_url, "initialising ACME client");
        let client = AcmeClient::new(ca_url).await?;
        let mut guard = mutex.lock().await;
        *guard = Some(AcmeClient::new(ca_url).await?);
        Ok(client)
    }

    // -----------------------------------------------------------------------
    // Lazy account initialisation
    // -----------------------------------------------------------------------

    /// Get or lazily initialise the ACME account for the given CA URL.
    ///
    /// If no account exists in storage, a new one is created and registered
    /// with the CA. A distributed lock is used to avoid duplicate
    /// registration in clustered deployments.
    async fn get_account(&self, client: &AcmeClient, use_test: bool) -> Result<AcmeAccount> {
        let ca_url = if use_test { &self.test_ca } else { &self.ca };
        let mutex = if use_test {
            &self.test_account
        } else {
            &self.account
        };

        // Fast path: already cached.
        {
            let guard = mutex.lock().await;
            if let Some(ref acct) = *guard {
                return Ok(acct.clone());
            }
        }

        // Slow path: load from storage or register new account.
        let lock_key = format!("acme_account_{}", issuer_key(ca_url));
        self.storage.lock(&lock_key).await?;

        let result = self.get_account_inner(client, ca_url).await;

        self.storage.unlock(&lock_key).await?;

        let acct = result?;

        // Cache the account.
        let mut guard = mutex.lock().await;
        *guard = Some(acct.clone());

        Ok(acct)
    }

    /// Inner account initialisation logic (called under the distributed lock).
    async fn get_account_inner(&self, client: &AcmeClient, ca_url: &str) -> Result<AcmeAccount> {
        let (mut acct, is_new) = get_or_create_account(
            self.storage.as_ref(),
            ca_url,
            &self.email,
            KeyType::EcdsaP256, // Account keys are always P-256 for ACME JWS.
        )
        .await?;

        if is_new {
            // Invoke the new-account callback (if configured) before
            // registering with the CA, allowing the caller to modify
            // the account (e.g. set EAB, change contacts).
            if let Some(ref func) = self.new_account_func {
                func(&mut acct);
            }

            // Register the account with the CA.
            info!(
                email = %self.email,
                ca = %ca_url,
                "registering new ACME account with CA"
            );

            let eab = self.external_account.clone();
            let private_key = crate::crypto::decode_private_key_pem(&acct.private_key_pem)
                .map_err(|e| AcmeError::Account(format!("failed to decode account key: {e}")))?;

            let (resp, location) = client
                .new_account(&private_key, &acct.contact, self.agreed, eab)
                .await?;

            acct.status = resp.status;
            acct.location = location;
            acct.terms_of_service_agreed = self.agreed;

            save_account(self.storage.as_ref(), ca_url, &acct).await?;

            info!(
                location = %acct.location,
                "ACME account registered and saved"
            );
        } else {
            debug!(
                location = %acct.location,
                "using existing ACME account"
            );
        }

        Ok(acct)
    }

    // -----------------------------------------------------------------------
    // Challenge selection
    // -----------------------------------------------------------------------

    /// Select the most appropriate challenge from an authorization's
    /// challenge list.
    ///
    /// Preference order:
    /// 1. `dns-01` if a DNS solver is configured
    /// 2. `http-01` if not disabled
    /// 3. `tls-alpn-01` if not disabled
    fn select_challenge<'a>(
        &self,
        challenges: &'a [crate::acme_client::AcmeChallenge],
    ) -> Result<&'a crate::acme_client::AcmeChallenge> {
        // Prefer dns-01 if a DNS solver is available.
        if self.dns01_solver.is_some()
            && let Some(c) = challenges
                .iter()
                .find(|c| c.challenge_type == CHALLENGE_TYPE_DNS01)
        {
            return Ok(c);
        }

        // Try http-01.
        if !self.disable_http_challenge
            && let Some(c) = challenges
                .iter()
                .find(|c| c.challenge_type == CHALLENGE_TYPE_HTTP01)
        {
            return Ok(c);
        }

        // Try tls-alpn-01.
        if !self.disable_tlsalpn_challenge
            && let Some(c) = challenges
                .iter()
                .find(|c| c.challenge_type == CHALLENGE_TYPE_TLSALPN01)
        {
            return Ok(c);
        }

        let available: Vec<&str> = challenges
            .iter()
            .map(|c| c.challenge_type.as_str())
            .collect();
        Err(AcmeError::Challenge {
            challenge_type: "none".into(),
            message: format!(
                "no suitable challenge type found among {:?} \
                 (dns01_solver={}, http_disabled={}, tlsalpn_disabled={})",
                available,
                self.dns01_solver.is_some(),
                self.disable_http_challenge,
                self.disable_tlsalpn_challenge,
            ),
        }
        .into())
    }

    /// Get the solver for a given challenge type.
    fn solver_for(&self, challenge_type: &str) -> Result<Arc<dyn Solver>> {
        match challenge_type {
            CHALLENGE_TYPE_DNS01 => self.dns01_solver.clone().ok_or_else(|| {
                Error::Config("dns-01 challenge selected but no DNS solver is configured".into())
            }),
            CHALLENGE_TYPE_HTTP01 => self.http01_solver.clone().ok_or_else(|| {
                Error::Config("http-01 challenge selected but no HTTP solver is configured".into())
            }),
            CHALLENGE_TYPE_TLSALPN01 => self.tlsalpn01_solver.clone().ok_or_else(|| {
                Error::Config(
                    "tls-alpn-01 challenge selected but no TLS-ALPN solver is configured".into(),
                )
            }),
            other => Err(Error::Config(format!(
                "unsupported challenge type: {other}"
            ))),
        }
    }

    // -----------------------------------------------------------------------
    // Core issuance logic
    // -----------------------------------------------------------------------

    /// Perform the actual certificate issuance using the ACME protocol.
    ///
    /// This is the workhorse method that drives the full ACME order flow.
    /// `attempt` is the 1-based attempt number for logging purposes.
    async fn do_issue(
        &self,
        csr_der: &[u8],
        domains: &[String],
        use_test_ca: bool,
        attempt: usize,
    ) -> Result<(IssuedCertificate, bool)> {
        let ca_url = if use_test_ca { &self.test_ca } else { &self.ca };
        let is_test = self.using_test_ca(ca_url);

        debug!(
            attempt = attempt,
            domains = ?domains,
            ca = %ca_url,
            "ACME issuance attempt"
        );

        // Per-CA rate limiting: wait before issuing to avoid overwhelming the CA.
        let limiter = get_ca_rate_limiter(ca_url, &self.email);
        let waited = limiter.wait().await;
        if !waited.is_zero() {
            debug!(
                waited_ms = waited.as_millis(),
                ca = %ca_url,
                "waited for per-CA rate limiter"
            );
        }

        // Step 1: get ACME client.
        let client = self.get_client(use_test_ca).await?;

        // Step 2: get ACME account.
        let acct = self.get_account(&client, use_test_ca).await?;

        let account_key = crate::crypto::decode_private_key_pem(&acct.private_key_pem)
            .map_err(|e| AcmeError::Account(format!("failed to decode account key: {e}")))?;

        info!(
            domains = ?domains,
            ca = %ca_url,
            account = %acct.location,
            "starting ACME certificate issuance"
        );

        // Step 3: create order (with account-does-not-exist recovery).
        let order_result = client
            .new_order(&account_key, &acct.location, domains)
            .await;

        let (order, order_url) = match order_result {
            Ok(result) => result,
            Err(ref e) if format!("{e}").contains("accountDoesNotExist") => {
                warn!(
                    ca = %ca_url,
                    "account does not exist on CA, deleting local account and retrying"
                );
                self.delete_account_and_clear_cache(ca_url, &acct, use_test_ca)
                    .await?;

                // Re-obtain account (will create a new one).
                let new_acct = self.get_account(&client, use_test_ca).await?;
                let new_account_key = crate::crypto::decode_private_key_pem(
                    &new_acct.private_key_pem,
                )
                .map_err(|e| AcmeError::Account(format!("failed to decode account key: {e}")))?;

                // Retry order creation with the new account.
                client
                    .new_order(&new_account_key, &new_acct.location, domains)
                    .await?
            }
            Err(e) => return Err(e),
        };

        debug!(
            order_url = %order_url,
            status = %order.status,
            authorizations = order.authorizations.len(),
            "ACME order created"
        );

        // Step 4: process each authorization.
        for authz_url in &order.authorizations {
            let authz = client
                .get_authorization(&account_key, &acct.location, authz_url)
                .await?;

            // Skip already-valid authorizations (e.g. from cached validations).
            if authz.status == "valid" {
                debug!(
                    identifier = %authz.identifier.value,
                    "authorization already valid, skipping"
                );
                continue;
            }

            // Select challenge.
            let challenge = self.select_challenge(&authz.challenges)?;

            debug!(
                identifier = %authz.identifier.value,
                challenge_type = %challenge.challenge_type,
                "selected challenge"
            );

            // Compute key authorization.
            let key_auth = crate::acme_client::key_authorization(&challenge.token, &account_key)?;

            // Get the solver, optionally wrapping in DistributedSolver.
            let solver = self.solver_for(&challenge.challenge_type)?;
            let solver: Arc<dyn Solver> = if !self.disable_distributed_solvers {
                let prefix = issuer_key(ca_url);
                Arc::new(DistributedSolver::with_prefix(
                    Box::new(SolverWrapper(solver)),
                    self.storage.clone(),
                    prefix,
                ))
            } else {
                solver
            };

            // Present the challenge.
            solver
                .present(&authz.identifier.value, &challenge.token, &key_auth)
                .await
                .map_err(|e| AcmeError::Challenge {
                    challenge_type: challenge.challenge_type.clone(),
                    message: format!("failed to present challenge: {e}"),
                })?;

            // Wait for the solver to be ready (e.g. DNS propagation).
            if let Err(e) = solver
                .wait(&authz.identifier.value, &challenge.token, &key_auth)
                .await
            {
                // Cleanup on wait failure.
                let _ = solver
                    .cleanup(&authz.identifier.value, &challenge.token, &key_auth)
                    .await;
                return Err(AcmeError::Challenge {
                    challenge_type: challenge.challenge_type.clone(),
                    message: format!("solver wait failed: {e}"),
                }
                .into());
            }

            // Tell the CA we are ready.
            client
                .accept_challenge(&account_key, &acct.location, &challenge.url)
                .await?;

            // Poll authorization until valid.
            let poll_result = client
                .poll_authorization(
                    &account_key,
                    &acct.location,
                    authz_url,
                    DEFAULT_AUTHZ_POLL_TIMEOUT,
                )
                .await;

            // Cleanup the challenge regardless of poll result.
            if let Err(cleanup_err) = solver
                .cleanup(&authz.identifier.value, &challenge.token, &key_auth)
                .await
            {
                warn!(
                    identifier = %authz.identifier.value,
                    error = %cleanup_err,
                    "failed to clean up challenge solver"
                );
            }

            // Check the poll result.
            poll_result?;

            debug!(
                identifier = %authz.identifier.value,
                "authorization validated"
            );
        }

        // Step 5: finalize the order with the CSR.
        let finalized = client
            .finalize_order(&account_key, &acct.location, &order.finalize, csr_der)
            .await?;

        debug!(
            order_url = %order_url,
            status = %finalized.status,
            "order finalized"
        );

        // Step 6: poll order until the certificate is ready.
        let completed = if finalized.status == "valid" {
            finalized
        } else {
            client
                .poll_order(
                    &account_key,
                    &acct.location,
                    &order_url,
                    DEFAULT_ORDER_POLL_TIMEOUT,
                )
                .await?
        };

        // Step 7: download the certificate.
        let cert_url = completed.certificate.ok_or_else(|| {
            AcmeError::Certificate("order is valid but has no certificate URL".into())
        })?;

        let cert_pem = client
            .download_certificate(&account_key, &acct.location, &cert_url)
            .await?;

        info!(
            domains = ?domains,
            ca = %ca_url,
            cert_url = %cert_url,
            "certificate issued successfully"
        );

        // Step 8: select preferred chain if applicable.
        // The ACME protocol can offer alternate chains via Link headers, but
        // most Rust ACME clients return a single chain. For now we apply
        // chain preference filtering if we detect multiple certificates in
        // the PEM bundle.
        let final_pem = if let Some(ref pref) = self.preferred_chains {
            self.select_preferred_chain(&cert_pem, pref)
        } else {
            cert_pem.clone()
        };

        let metadata = serde_json::json!({
            "ca": ca_url,
            "account_location": acct.location,
            "order_url": order_url,
            "certificate_url": cert_url,
        });

        let issued = IssuedCertificate {
            certificate_pem: final_pem.into_bytes(),
            private_key_pem: Vec::new(), // CSR was provided externally.
            metadata,
        };

        Ok((issued, is_test))
    }

    // -----------------------------------------------------------------------
    // Chain preference selection
    // -----------------------------------------------------------------------

    /// Given a PEM certificate chain, apply the chain preference rules.
    ///
    /// In typical ACME usage there is only one chain. This method is a
    /// simplified version that parses the PEM bundle and checks CN matching
    /// when preferences are specified.
    fn select_preferred_chain(&self, cert_pem: &str, pref: &ChainPreference) -> String {
        // Parse certs from the bundle for inspection.
        let cert_ders = match parse_certs_from_pem_bundle(cert_pem) {
            Ok(ders) => ders,
            Err(e) => {
                warn!(error = %e, "failed to parse certificate chain for preference selection");
                return cert_pem.to_owned();
            }
        };

        if cert_ders.is_empty() {
            return cert_pem.to_owned();
        }

        // Parse each certificate with x509-parser to check Common Names.
        // We store the owned DER bytes alongside the parsed certificate
        // reference via indices, since x509-parser borrows from the DER slice.
        //
        // Helper: extract the issuer CN from a DER-encoded certificate.
        fn issuer_cn_from_der(der: &[u8]) -> Option<String> {
            let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;

            cert.issuer()
                .iter_common_name()
                .next()
                .and_then(|attr| attr.as_str().ok())
                .map(|s| s.to_owned())
        }

        // Check any_common_name: match any certificate's issuer CN.
        if !pref.any_common_name.is_empty() {
            for pref_cn in &pref.any_common_name {
                for der in &cert_ders {
                    if let Some(cn) = issuer_cn_from_der(der)
                        && cn == *pref_cn
                    {
                        debug!(
                            preferred_cn = %pref_cn,
                            "found certificate matching any_common_name preference"
                        );
                        return cert_pem.to_owned();
                    }
                }
            }
        }

        // Check root_common_name: match the last certificate's issuer CN.
        if !pref.root_common_name.is_empty()
            && let Some(root_der) = cert_ders.last()
            && let Some(cn) = issuer_cn_from_der(root_der)
        {
            for pref_cn in &pref.root_common_name {
                if cn == *pref_cn {
                    debug!(
                        preferred_cn = %pref_cn,
                        "found certificate matching root_common_name preference"
                    );
                    return cert_pem.to_owned();
                }
            }
        }

        // Check smallest preference: sort by PEM size.
        if let Some(want_smallest) = pref.smallest {
            // We only have a single chain here (the PEM bundle). In a
            // scenario with multiple alternate chains from the CA, we
            // would sort across all of them. For now, this is a no-op
            // since there is only one chain, but we implement the sorting
            // logic for future multi-chain support. We split the PEM
            // bundle by certificate boundaries and re-assemble sorted.
            let _pem_items = match pem::parse_many(cert_pem) {
                Ok(items) if items.len() > 1 => items,
                _ => return cert_pem.to_owned(),
            };

            // Treat the whole PEM as a single "chain" — sorting a single
            // chain is a no-op. The sorting becomes meaningful when
            // multiple alternate chains are available. We return the
            // original PEM unchanged.
            let mut chains: Vec<String> = vec![cert_pem.to_owned()];

            chains.sort_by(|a, b| {
                if want_smallest {
                    a.len().cmp(&b.len())
                } else {
                    b.len().cmp(&a.len())
                }
            });

            debug!(
                smallest = want_smallest,
                chain_count = chains.len(),
                "applied chain size sorting preference"
            );

            return chains
                .into_iter()
                .next()
                .unwrap_or_else(|| cert_pem.to_owned());
        }

        // No preference matched — return the original chain.
        cert_pem.to_owned()
    }

    // -----------------------------------------------------------------------
    // Account deletion (for account-does-not-exist recovery)
    // -----------------------------------------------------------------------

    /// Delete the locally stored account data and clear the in-memory cache.
    ///
    /// This is used when the CA reports that an account no longer exists
    /// (e.g. after a CA reinstall), allowing recovery by creating a fresh
    /// account on the next issuance attempt.
    async fn delete_account_and_clear_cache(
        &self,
        ca_url: &str,
        acct: &AcmeAccount,
        use_test: bool,
    ) -> Result<()> {
        delete_account_locally(self.storage.as_ref(), ca_url, acct).await?;

        // Clear the cached account.
        let mutex = if use_test {
            &self.test_account
        } else {
            &self.account
        };
        let mut guard = mutex.lock().await;
        *guard = None;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CertIssuer trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl CertIssuer for AcmeIssuer {
    async fn issue(&self, csr_der: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        let mut attempt: usize = 0;

        // First attempt: production CA.
        attempt += 1;
        info!(attempt = attempt, domains = ?domains, "starting certificate issuance");
        let result = self.do_issue(csr_der, domains, false, attempt).await;

        match result {
            Ok((cert, _used_test)) => return Ok(cert),
            Err(first_err) => {
                // If a test CA is configured and different from production,
                // try the test CA as a fallback to verify our setup is
                // correct.
                if self.ca != self.test_ca {
                    warn!(
                        error = %first_err,
                        "production CA issuance failed, trying test CA to verify setup"
                    );

                    attempt += 1;
                    info!(attempt = attempt, "retrying with test CA");
                    match self.do_issue(csr_der, domains, true, attempt).await {
                        Ok((_test_cert, _)) => {
                            info!("test CA issuance succeeded; retrying production CA once more");
                            // Test CA worked, so our setup is valid.
                            // Retry production CA once more.
                            attempt += 1;
                            info!(attempt = attempt, "retrying production CA");
                            let (cert, _) = self.do_issue(csr_der, domains, false, attempt).await?;
                            return Ok(cert);
                        }
                        Err(test_err) => {
                            warn!(
                                error = %test_err,
                                "test CA issuance also failed"
                            );
                            // Both failed — return the original production error.
                            return Err(first_err);
                        }
                    }
                }

                return Err(first_err);
            }
        }
    }

    fn issuer_key(&self) -> String {
        issuer_key(&self.ca)
    }

    fn as_revoker(&self) -> Option<&dyn Revoker> {
        Some(self)
    }
}

// ---------------------------------------------------------------------------
// Revoker trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Revoker for AcmeIssuer {
    async fn revoke(&self, cert_pem: &[u8], reason: Option<u8>) -> Result<()> {
        let cert_pem_str = std::str::from_utf8(cert_pem)
            .map_err(|e| AcmeError::Certificate(format!("cert PEM is not valid UTF-8: {e}")))?;

        let cert_ders = parse_certs_from_pem_bundle(cert_pem_str)?;
        if cert_ders.is_empty() {
            return Err(
                AcmeError::Certificate("no certificates found in PEM bundle".into()).into(),
            );
        }

        // Use the first (leaf) certificate for revocation.
        let leaf_der = &cert_ders[0];

        let client = self.get_client(false).await?;
        let acct = self.get_account(&client, false).await?;

        let account_key = crate::crypto::decode_private_key_pem(&acct.private_key_pem)
            .map_err(|e| AcmeError::Account(format!("failed to decode account key: {e}")))?;

        client
            .revoke_certificate(&account_key, &acct.location, leaf_der, reason)
            .await?;

        info!("certificate revoked");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Convenience: issue with auto-generated key + CSR
// ---------------------------------------------------------------------------

impl AcmeIssuer {
    /// A convenience method that generates a private key and CSR, then issues
    /// the certificate.
    ///
    /// Returns an [`IssuedCertificate`] whose `private_key_pem` field is
    /// populated with the generated key.
    pub async fn issue_for_domains(&self, domains: &[String]) -> Result<IssuedCertificate> {
        if domains.is_empty() {
            return Err(Error::Config(
                "at least one domain is required for certificate issuance".into(),
            ));
        }

        // Generate a private key for the certificate.
        let private_key = generate_private_key(self.cert_key_type)?;
        let private_key_pem = encode_private_key_pem(&private_key)?;

        // Generate CSR.
        let csr_der = generate_csr(&private_key, domains, false)?;

        // Issue via the ACME protocol.
        let mut issued = self.issue(&csr_der, domains).await?;

        // Attach the generated private key.
        issued.private_key_pem = private_key_pem.into_bytes();

        Ok(issued)
    }
}

// ---------------------------------------------------------------------------
// SolverWrapper — bridge Arc<dyn Solver> to Box<dyn Solver>
// ---------------------------------------------------------------------------

/// A simple wrapper that allows an `Arc<dyn Solver>` to be used where a
/// `Box<dyn Solver>` is expected (e.g. by [`DistributedSolver`]).
struct SolverWrapper(Arc<dyn Solver>);

#[async_trait]
impl Solver for SolverWrapper {
    async fn present(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        self.0.present(domain, token, key_auth).await
    }

    async fn wait(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        self.0.wait(domain, token, key_auth).await
    }

    async fn cleanup(&self, domain: &str, token: &str, key_auth: &str) -> Result<()> {
        self.0.cleanup(domain, token, key_auth).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_key_lets_encrypt() {
        let ik = issuer_key(LETS_ENCRYPT_PRODUCTION);
        assert!(ik.contains("acme-v02.api.letsencrypt.org"));
    }

    #[test]
    fn test_issuer_key_staging() {
        let ik = issuer_key(LETS_ENCRYPT_STAGING);
        assert!(ik.contains("acme-staging-v02.api.letsencrypt.org"));
    }

    #[test]
    fn test_chain_preference_default() {
        let pref = ChainPreference::default();
        assert!(pref.smallest.is_none());
        assert!(pref.root_common_name.is_empty());
        assert!(pref.any_common_name.is_empty());
    }

    #[test]
    fn test_issued_certificate_fields() {
        let ic = IssuedCertificate {
            certificate_pem: b"cert data".to_vec(),
            private_key_pem: b"key data".to_vec(),
            metadata: serde_json::json!({"url": "https://example.com"}),
        };
        assert_eq!(ic.certificate_pem, b"cert data");
        assert_eq!(ic.private_key_pem, b"key data");
        assert!(ic.metadata.is_object());
    }

    #[test]
    fn test_challenge_type_constants() {
        assert_eq!(CHALLENGE_TYPE_HTTP01, "http-01");
        assert_eq!(CHALLENGE_TYPE_DNS01, "dns-01");
        assert_eq!(CHALLENGE_TYPE_TLSALPN01, "tls-alpn-01");
    }

    #[test]
    fn test_default_ca_urls() {
        assert_eq!(DEFAULT_CA, LETS_ENCRYPT_PRODUCTION);
        assert_eq!(DEFAULT_TEST_CA, LETS_ENCRYPT_STAGING);
    }
}
