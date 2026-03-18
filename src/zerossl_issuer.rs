//! ZeroSSL certificate issuers.
//!
//! This module provides two issuer implementations for ZeroSSL:
//!
//! - [`ZeroSslIssuer`] — uses ZeroSSL's ACME endpoint with automatic EAB provisioning (recommended
//!   for most use cases).
//! - [`ZeroSslApiIssuer`] — uses ZeroSSL's REST API directly (not ACME). This is useful when ACME
//!   challenges are not practical, as it supports email-based domain validation. Note that REST API
//!   access may be restricted by payment tier.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::acme_client::{ExternalAccountBinding, ZEROSSL_PRODUCTION};
use crate::acme_issuer::{AcmeIssuer, CertIssuer, ChainPreference, IssuedCertificate, Revoker};
use crate::crypto::{KeyType, encode_private_key_pem, generate_csr, generate_private_key};
use crate::error::{Error, Result};
use crate::solvers::Solver;
use crate::storage::Storage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ZeroSSL EAB credentials API endpoint.
const ZEROSSL_EAB_ENDPOINT: &str = "https://api.zerossl.com/acme/eab-credentials";

/// The issuer key prefix used for storage partitioning.
const ZEROSSL_ISSUER_KEY: &str = "zerossl";

// ---------------------------------------------------------------------------
// EAB API response
// ---------------------------------------------------------------------------

/// Response from the ZeroSSL EAB credentials API.
#[derive(Debug, Deserialize)]
struct EabCredentialsResponse {
    /// Whether the request succeeded.
    #[serde(default)]
    success: bool,
    /// The EAB key identifier.
    eab_kid: Option<String>,
    /// The EAB HMAC key (Base64URL-encoded).
    eab_hmac_key: Option<String>,
    /// Error details, if the request failed.
    error: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// ZeroSslIssuer
// ---------------------------------------------------------------------------

/// A certificate issuer that obtains certificates from ZeroSSL via ACME.
///
/// ZeroSSL requires External Account Binding (EAB) for ACME. This issuer
/// automatically provisions EAB credentials using the ZeroSSL API and an
/// API key, then delegates all ACME operations to an inner [`AcmeIssuer`].
///
/// ZeroSSL offers free 90-day DV certificates through their ACME endpoint.
/// Unlike Let's Encrypt, ZeroSSL does not have a separate staging
/// environment.
///
/// Use [`ZeroSslIssuer::builder()`] to construct an instance.
pub struct ZeroSslIssuer {
    /// ZeroSSL API key (used to obtain EAB credentials).
    /// Retained for potential future use (e.g. re-fetching EAB on rotation).
    #[allow(dead_code)]
    api_key: String,
    /// The underlying ACME issuer, pre-configured for ZeroSSL.
    inner: AcmeIssuer,
}

impl std::fmt::Debug for ZeroSslIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroSslIssuer")
            .field("api_key", &"[REDACTED]")
            .field("inner", &self.inner)
            .finish()
    }
}

impl ZeroSslIssuer {
    /// Create a new [`ZeroSslIssuerBuilder`].
    pub fn builder() -> ZeroSslIssuerBuilder {
        ZeroSslIssuerBuilder {
            api_key: String::new(),
            email: None,
            storage: None,
            cert_key_type: None,
            preferred_chains: None,
            cert_obtain_timeout: None,
            disable_http_challenge: false,
            disable_tlsalpn_challenge: false,
            dns01_solver: None,
            http01_solver: None,
            tlsalpn01_solver: None,
        }
    }

    /// Return a reference to the inner [`AcmeIssuer`].
    pub fn inner(&self) -> &AcmeIssuer {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// CertIssuer trait
// ---------------------------------------------------------------------------

#[async_trait]
impl CertIssuer for ZeroSslIssuer {
    async fn issue(&self, csr_der: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.inner.issue(csr_der, domains).await
    }

    fn issuer_key(&self) -> String {
        ZEROSSL_ISSUER_KEY.to_owned()
    }

    fn as_revoker(&self) -> Option<&dyn Revoker> {
        Some(self)
    }
}

// ---------------------------------------------------------------------------
// Revoker trait
// ---------------------------------------------------------------------------

#[async_trait]
impl Revoker for ZeroSslIssuer {
    async fn revoke(&self, cert_pem: &[u8], reason: Option<u8>) -> Result<()> {
        self.inner.revoke(cert_pem, reason).await
    }
}

// ---------------------------------------------------------------------------
// EAB credential fetching
// ---------------------------------------------------------------------------

/// Fetch EAB credentials from ZeroSSL's API using the given API key.
///
/// This makes a POST request to ZeroSSL's EAB endpoint and returns the
/// [`ExternalAccountBinding`] that can be used with ACME registration.
async fn fetch_eab_credentials(api_key: &str) -> Result<ExternalAccountBinding> {
    let url = format!("{ZEROSSL_EAB_ENDPOINT}?access_key={api_key}");

    debug!("fetching EAB credentials from ZeroSSL API");

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .send()
        .await
        .map_err(|e| Error::Other(format!("failed to request ZeroSSL EAB credentials: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_owned());
        return Err(Error::Other(format!(
            "ZeroSSL EAB endpoint returned HTTP {status}: {body}"
        )));
    }

    let eab_resp: EabCredentialsResponse = resp
        .json()
        .await
        .map_err(|e| Error::Other(format!("failed to parse ZeroSSL EAB response: {e}")))?;

    if !eab_resp.success {
        let detail = eab_resp
            .error
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown error".to_owned());
        return Err(Error::Other(format!(
            "ZeroSSL EAB request failed: {detail}"
        )));
    }

    let kid = eab_resp
        .eab_kid
        .ok_or_else(|| Error::Other("ZeroSSL EAB response missing eab_kid".to_owned()))?;
    let hmac_key_b64 = eab_resp
        .eab_hmac_key
        .ok_or_else(|| Error::Other("ZeroSSL EAB response missing eab_hmac_key".to_owned()))?;

    // The HMAC key from ZeroSSL is Base64URL-encoded.
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hmac_key = URL_SAFE_NO_PAD
        .decode(&hmac_key_b64)
        .map_err(|e| Error::Other(format!("failed to decode ZeroSSL HMAC key: {e}")))?;

    info!(kid = %kid, "obtained EAB credentials from ZeroSSL");

    Ok(ExternalAccountBinding { kid, hmac_key })
}

// ---------------------------------------------------------------------------
// ZeroSslIssuerBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`ZeroSslIssuer`].
///
/// At a minimum, the `api_key` and `storage` must be provided. The `build()`
/// method is async because it fetches EAB credentials from the ZeroSSL API.
pub struct ZeroSslIssuerBuilder {
    api_key: String,
    email: Option<String>,
    storage: Option<Arc<dyn Storage>>,
    cert_key_type: Option<KeyType>,
    preferred_chains: Option<ChainPreference>,
    cert_obtain_timeout: Option<Duration>,
    disable_http_challenge: bool,
    disable_tlsalpn_challenge: bool,
    dns01_solver: Option<Arc<dyn Solver>>,
    http01_solver: Option<Arc<dyn Solver>>,
    tlsalpn01_solver: Option<Arc<dyn Solver>>,
}

impl ZeroSslIssuerBuilder {
    /// Set the ZeroSSL API key (required).
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = api_key.into();
        self
    }

    /// Set the contact email address for the ACME account.
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the shared storage backend (required).
    pub fn storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the key type for generated certificate private keys.
    pub fn cert_key_type(mut self, key_type: KeyType) -> Self {
        self.cert_key_type = Some(key_type);
        self
    }

    /// Set the chain preference for selecting alternate certificate chains.
    pub fn preferred_chains(mut self, pref: ChainPreference) -> Self {
        self.preferred_chains = Some(pref);
        self
    }

    /// Set the timeout for the certificate obtain operation.
    pub fn cert_obtain_timeout(mut self, timeout: Duration) -> Self {
        self.cert_obtain_timeout = Some(timeout);
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

    /// Build the [`ZeroSslIssuer`].
    ///
    /// This method is `async` because it fetches EAB credentials from the
    /// ZeroSSL API using the provided API key.
    ///
    /// # Panics
    ///
    /// Panics if `api_key` is empty or `storage` has not been provided.
    ///
    /// # Errors
    ///
    /// Returns an error if EAB credentials cannot be obtained from ZeroSSL.
    pub async fn build(self) -> Result<ZeroSslIssuer> {
        assert!(
            !self.api_key.is_empty(),
            "ZeroSslIssuer requires an API key — call .api_key() on the builder"
        );
        let storage = self.storage.expect(
            "ZeroSslIssuer requires a Storage implementation — call .storage() on the builder",
        );

        // Fetch EAB credentials from ZeroSSL.
        let eab = fetch_eab_credentials(&self.api_key).await?;

        // Build the inner AcmeIssuer with ZeroSSL's ACME directory and EAB.
        let mut acme_builder = AcmeIssuer::builder()
            .ca(ZEROSSL_PRODUCTION)
            .test_ca(ZEROSSL_PRODUCTION) // ZeroSSL has no separate staging environment.
            .agreed(true)
            .external_account(eab)
            .storage(storage)
            .disable_http_challenge(self.disable_http_challenge)
            .disable_tlsalpn_challenge(self.disable_tlsalpn_challenge);

        if let Some(email) = self.email {
            acme_builder = acme_builder.email(email);
        }
        if let Some(key_type) = self.cert_key_type {
            acme_builder = acme_builder.cert_key_type(key_type);
        }
        if let Some(pref) = self.preferred_chains {
            acme_builder = acme_builder.preferred_chains(pref);
        }
        if let Some(timeout) = self.cert_obtain_timeout {
            acme_builder = acme_builder.cert_obtain_timeout(timeout);
        }
        if let Some(solver) = self.dns01_solver {
            acme_builder = acme_builder.dns01_solver(solver);
        }
        if let Some(solver) = self.http01_solver {
            acme_builder = acme_builder.http01_solver(solver);
        }
        if let Some(solver) = self.tlsalpn01_solver {
            acme_builder = acme_builder.tlsalpn01_solver(solver);
        }

        let inner = acme_builder.build();

        Ok(ZeroSslIssuer {
            api_key: self.api_key,
            inner,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zerossl_issuer_key() {
        // The issuer key is a static string, not derived from the CA URL.
        assert_eq!(ZEROSSL_ISSUER_KEY, "zerossl");
    }

    #[test]
    fn test_eab_endpoint_constant() {
        assert_eq!(
            ZEROSSL_EAB_ENDPOINT,
            "https://api.zerossl.com/acme/eab-credentials"
        );
    }

    #[test]
    fn test_eab_response_deserialization_success() {
        let json = r#"{
            "success": true,
            "eab_kid": "kid123",
            "eab_hmac_key": "aG1hY2tleQ"
        }"#;
        let resp: EabCredentialsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.eab_kid.as_deref(), Some("kid123"));
        assert_eq!(resp.eab_hmac_key.as_deref(), Some("aG1hY2tleQ"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_eab_response_deserialization_error() {
        let json = r#"{
            "success": false,
            "error": {"code": 123, "type": "invalid_access_key"}
        }"#;
        let resp: EabCredentialsResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert!(resp.eab_kid.is_none());
        assert!(resp.eab_hmac_key.is_none());
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_builder_creation() {
        let builder = ZeroSslIssuer::builder().api_key("test_key");
        assert_eq!(builder.api_key, "test_key");
        assert!(builder.storage.is_none());
        assert!(builder.email.is_none());
    }

    // -- ZeroSslApiIssuer --------------------------------------------------

    #[test]
    fn test_api_issuer_key() {
        assert_eq!(ZEROSSL_API_ISSUER_KEY, "zerossl_api");
    }

    #[test]
    fn test_api_issuer_defaults() {
        let storage: Arc<dyn Storage> = Arc::new(crate::file_storage::FileStorage::default());
        let issuer = ZeroSslApiIssuer::new("test_key", storage);
        assert_eq!(issuer.validity_days, 90);
        assert_eq!(issuer.key_type, KeyType::EcdsaP256);
        assert_eq!(issuer.poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_api_issuer_with_options() {
        let storage: Arc<dyn Storage> = Arc::new(crate::file_storage::FileStorage::default());
        let issuer = ZeroSslApiIssuer::new("test_key", storage)
            .with_validity_days(365)
            .with_key_type(KeyType::Rsa2048)
            .with_poll_interval(Duration::from_secs(10));
        assert_eq!(issuer.validity_days, 365);
        assert_eq!(issuer.key_type, KeyType::Rsa2048);
        assert_eq!(issuer.poll_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_api_issuer_issuer_key_trait() {
        let storage: Arc<dyn Storage> = Arc::new(crate::file_storage::FileStorage::default());
        let issuer = ZeroSslApiIssuer::new("test_key", storage);
        assert_eq!(issuer.issuer_key(), "zerossl_api");
    }

    #[test]
    fn test_api_issuer_debug_redacts_key() {
        let storage: Arc<dyn Storage> = Arc::new(crate::file_storage::FileStorage::default());
        let issuer = ZeroSslApiIssuer::new("super_secret_key", storage);
        let debug_str = format!("{:?}", issuer);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super_secret_key"));
    }

    #[test]
    fn test_api_cert_response_deserialization() {
        let json = r#"{
            "id": "abc123",
            "status": "issued"
        }"#;
        let resp: ZeroSslCertResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "abc123");
        assert_eq!(resp.status, "issued");
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_api_cert_response_with_error() {
        let json = r#"{
            "id": "",
            "status": "",
            "error": {"code": 400, "type": "invalid_csr"}
        }"#;
        let resp: ZeroSslCertResponse = serde_json::from_str(json).unwrap();
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_api_download_response_deserialization() {
        let json = r#"{
            "certificate.crt": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            "ca_bundle.crt": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n"
        }"#;
        let resp: ZeroSslDownloadResponse = serde_json::from_str(json).unwrap();
        assert!(resp.certificate_crt.contains("BEGIN CERTIFICATE"));
        assert!(resp.ca_bundle_crt.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_encode_csr_pem() {
        let fake_der = b"fake-csr-data";
        let pem = ZeroSslApiIssuer::encode_csr_pem(fake_der);
        assert!(pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(pem.contains("END CERTIFICATE REQUEST"));
    }
}

// ===========================================================================
// ZeroSslApiIssuer — REST API mode (non-ACME)
// ===========================================================================

/// Base URL for the ZeroSSL REST API (v1).
const ZEROSSL_API_BASE: &str = "https://api.zerossl.com";

/// The issuer key used for storage partitioning by the REST API issuer.
const ZEROSSL_API_ISSUER_KEY: &str = "zerossl_api";

/// Default certificate validity in days.
const DEFAULT_VALIDITY_DAYS: u32 = 90;

/// Default interval between status polls.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum number of poll attempts before giving up.
const MAX_POLL_ATTEMPTS: u32 = 120;

// ---------------------------------------------------------------------------
// ZeroSSL REST API response types
// ---------------------------------------------------------------------------

/// Response from the ZeroSSL certificate creation and status endpoints.
#[derive(Debug, Deserialize)]
struct ZeroSslCertResponse {
    /// Certificate ID assigned by ZeroSSL.
    #[serde(default)]
    id: String,
    /// Certificate status (e.g. `"draft"`, `"pending_validation"`, `"issued"`).
    #[serde(default)]
    status: String,
    /// Error information, if any.
    #[serde(default)]
    error: Option<serde_json::Value>,
}

/// Response from the ZeroSSL certificate download endpoint.
#[derive(Debug, Deserialize)]
struct ZeroSslDownloadResponse {
    /// The issued certificate (leaf + intermediates).
    #[serde(rename = "certificate.crt")]
    certificate_crt: String,
    /// The CA bundle (root chain).
    #[serde(rename = "ca_bundle.crt")]
    ca_bundle_crt: String,
}

// ---------------------------------------------------------------------------
// ZeroSslApiIssuer
// ---------------------------------------------------------------------------

/// A certificate issuer that uses ZeroSSL's REST API directly, bypassing ACME.
///
/// This issuer communicates with ZeroSSL's REST API to create, validate, and
/// download certificates. It uses **email-based domain validation** by default,
/// which means ZeroSSL will send a validation email to the domain's
/// administrative contacts (e.g. `admin@example.com`).
///
/// # Limitations
///
/// - REST API access may be restricted by ZeroSSL payment tier.
/// - Only email-based validation is implemented. For HTTP or CNAME validation, use
///   [`ZeroSslIssuer`] (the ACME-based issuer) instead.
/// - Revocation requires the certificate ID from ZeroSSL. This issuer stores the certificate ID in
///   the [`IssuedCertificate::metadata`] field so it can be retrieved later for revocation.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use certon::zerossl_issuer::ZeroSslApiIssuer;
/// # use certon::{FileStorage, Storage, KeyType};
/// let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
/// let issuer = ZeroSslApiIssuer::new("your-api-key", storage)
///     .with_validity_days(90)
///     .with_key_type(KeyType::EcdsaP256);
/// ```
pub struct ZeroSslApiIssuer {
    /// ZeroSSL API key.
    api_key: String,
    /// Certificate validity in days (default 90).
    validity_days: u32,
    /// Storage for certs/keys.
    storage: Arc<dyn Storage>,
    /// Key type for generated certificate private keys.
    key_type: KeyType,
    /// Interval between status polls.
    poll_interval: Duration,
}

impl std::fmt::Debug for ZeroSslApiIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroSslApiIssuer")
            .field("api_key", &"[REDACTED]")
            .field("validity_days", &self.validity_days)
            .field("key_type", &self.key_type)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

impl ZeroSslApiIssuer {
    /// Create a new `ZeroSslApiIssuer` with the given API key and storage.
    pub fn new(api_key: impl Into<String>, storage: Arc<dyn Storage>) -> Self {
        Self {
            api_key: api_key.into(),
            validity_days: DEFAULT_VALIDITY_DAYS,
            storage,
            key_type: KeyType::EcdsaP256,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Set the certificate validity period in days (default 90).
    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set the key type for generated certificate private keys.
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set the poll interval for checking certificate status (default 5s).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Return the configured storage backend.
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }

    /// Encode a DER CSR as PEM.
    fn encode_csr_pem(csr_der: &[u8]) -> String {
        let pem_obj = ::pem::Pem::new("CERTIFICATE REQUEST", csr_der.to_vec());
        ::pem::encode(&pem_obj)
    }

    /// Create a certificate via the ZeroSSL REST API.
    ///
    /// Posts the CSR and domain list to ZeroSSL and returns the certificate
    /// response (which includes the certificate ID needed for subsequent
    /// operations).
    async fn create_certificate(
        &self,
        csr_pem: &str,
        domains: &[String],
    ) -> Result<ZeroSslCertResponse> {
        let url = format!(
            "{ZEROSSL_API_BASE}/certificates?access_key={}",
            self.api_key
        );
        let domains_csv = domains.join(",");

        debug!(domains = %domains_csv, "creating ZeroSSL certificate via REST API");

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .form(&[
                ("certificate_domains", domains_csv.as_str()),
                ("certificate_csr", csr_pem),
                ("certificate_validity_days", &self.validity_days.to_string()),
            ])
            .send()
            .await
            .map_err(|e| Error::Other(format!("failed to create ZeroSSL certificate: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_owned());
            return Err(Error::Other(format!(
                "ZeroSSL create certificate returned HTTP {status}: {body}"
            )));
        }

        let cert_resp: ZeroSslCertResponse = resp.json().await.map_err(|e| {
            Error::Other(format!(
                "failed to parse ZeroSSL create certificate response: {e}"
            ))
        })?;

        if let Some(ref err) = cert_resp.error {
            return Err(Error::Other(format!(
                "ZeroSSL create certificate error: {err}"
            )));
        }

        if cert_resp.id.is_empty() {
            return Err(Error::Other(
                "ZeroSSL create certificate response missing certificate ID".to_owned(),
            ));
        }

        info!(cert_id = %cert_resp.id, "created ZeroSSL certificate");
        Ok(cert_resp)
    }

    /// Initiate email-based validation for a certificate.
    ///
    /// This tells ZeroSSL to send validation emails to the domain's
    /// administrative contacts.
    async fn verify_by_email(&self, cert_id: &str) -> Result<()> {
        let url = format!(
            "{ZEROSSL_API_BASE}/certificates/{cert_id}/challenges?access_key={}",
            self.api_key
        );

        debug!(
            cert_id = cert_id,
            "initiating email validation for ZeroSSL certificate"
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .form(&[("validation_method", "EMAIL")])
            .send()
            .await
            .map_err(|e| {
                Error::Other(format!("failed to initiate ZeroSSL email validation: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_owned());
            return Err(Error::Other(format!(
                "ZeroSSL email validation returned HTTP {status}: {body}"
            )));
        }

        info!(
            cert_id = cert_id,
            "initiated email validation for ZeroSSL certificate"
        );
        Ok(())
    }

    /// Poll the ZeroSSL API until the certificate status becomes `"issued"`.
    ///
    /// Returns the certificate response with updated status. Returns an error
    /// if the maximum number of poll attempts is exceeded or an unexpected
    /// status is encountered.
    async fn wait_for_issued(&self, cert_id: &str) -> Result<ZeroSslCertResponse> {
        let url = format!(
            "{ZEROSSL_API_BASE}/certificates/{cert_id}?access_key={}",
            self.api_key
        );
        let client = reqwest::Client::new();

        for attempt in 1..=MAX_POLL_ATTEMPTS {
            tokio::time::sleep(self.poll_interval).await;

            debug!(
                cert_id = cert_id,
                attempt = attempt,
                "polling ZeroSSL certificate status"
            );

            let resp = client.get(&url).send().await.map_err(|e| {
                Error::Other(format!("failed to poll ZeroSSL certificate status: {e}"))
            })?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "<failed to read body>".to_owned());
                warn!(
                    cert_id = cert_id,
                    http_status = %status,
                    "ZeroSSL status poll returned non-success; retrying"
                );
                debug!(body = body, "ZeroSSL status poll response body");
                continue;
            }

            let cert_resp: ZeroSslCertResponse = resp.json().await.map_err(|e| {
                Error::Other(format!("failed to parse ZeroSSL status response: {e}"))
            })?;

            match cert_resp.status.as_str() {
                "issued" => {
                    info!(cert_id = cert_id, "ZeroSSL certificate has been issued");
                    return Ok(cert_resp);
                }
                "pending_validation" | "draft" => {
                    debug!(
                        cert_id = cert_id,
                        status = %cert_resp.status,
                        "certificate not yet issued, will poll again"
                    );
                }
                other => {
                    return Err(Error::Other(format!(
                        "unexpected ZeroSSL certificate status: {other}"
                    )));
                }
            }
        }

        Err(Error::Other(format!(
            "timed out waiting for ZeroSSL certificate {cert_id} to be issued \
             after {MAX_POLL_ATTEMPTS} attempts"
        )))
    }

    /// Download the issued certificate from ZeroSSL.
    ///
    /// Returns the PEM-encoded certificate chain (leaf + CA bundle
    /// concatenated).
    async fn download_certificate(&self, cert_id: &str) -> Result<String> {
        let url = format!(
            "{ZEROSSL_API_BASE}/certificates/{cert_id}/download/return?access_key={}",
            self.api_key
        );

        debug!(cert_id = cert_id, "downloading ZeroSSL certificate");

        let client = reqwest::Client::new();
        let resp =
            client.get(&url).send().await.map_err(|e| {
                Error::Other(format!("failed to download ZeroSSL certificate: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_owned());
            return Err(Error::Other(format!(
                "ZeroSSL download returned HTTP {status}: {body}"
            )));
        }

        let download: ZeroSslDownloadResponse = resp
            .json()
            .await
            .map_err(|e| Error::Other(format!("failed to parse ZeroSSL download response: {e}")))?;

        // Concatenate the leaf certificate and CA bundle into a single PEM chain.
        let full_chain = format!("{}{}", download.certificate_crt, download.ca_bundle_crt);

        info!(cert_id = cert_id, "downloaded ZeroSSL certificate");
        Ok(full_chain)
    }
}

// ---------------------------------------------------------------------------
// CertIssuer trait for ZeroSslApiIssuer
// ---------------------------------------------------------------------------

#[async_trait]
impl CertIssuer for ZeroSslApiIssuer {
    /// Issue a certificate using ZeroSSL's REST API.
    ///
    /// The flow is:
    /// 1. Generate a private key and CSR (if `csr_der` is empty) or use the provided CSR.
    /// 2. Create the certificate via the ZeroSSL API.
    /// 3. Initiate email-based domain validation.
    /// 4. Poll until the certificate is issued.
    /// 5. Download and return the certificate chain.
    async fn issue(&self, csr_der: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        if domains.is_empty() {
            return Err(Error::Other("at least one domain is required".to_owned()));
        }

        // Generate a key + CSR if none was provided.
        let (private_key_pem, csr_der_owned) = if csr_der.is_empty() {
            let key = generate_private_key(self.key_type)?;
            let pem = encode_private_key_pem(&key)?;
            let csr = generate_csr(&key, domains, false)?;
            (pem.into_bytes(), csr)
        } else {
            (Vec::new(), csr_der.to_vec())
        };

        let csr_pem = Self::encode_csr_pem(&csr_der_owned);

        // Step 1: Create the certificate.
        let cert_resp = self.create_certificate(&csr_pem, domains).await?;
        let cert_id = cert_resp.id;

        // Step 2: Initiate email validation.
        self.verify_by_email(&cert_id).await?;

        // Step 3: Poll until issued.
        let _issued = self.wait_for_issued(&cert_id).await?;

        // Step 4: Download the certificate.
        let cert_chain_pem = self.download_certificate(&cert_id).await?;

        // Store the certificate ID in metadata for later revocation.
        let metadata = serde_json::json!({
            "issuer": ZEROSSL_API_ISSUER_KEY,
            "certificate_id": cert_id,
        });

        Ok(IssuedCertificate {
            certificate_pem: cert_chain_pem.into_bytes(),
            private_key_pem,
            metadata,
        })
    }

    fn issuer_key(&self) -> String {
        ZEROSSL_API_ISSUER_KEY.to_owned()
    }

    fn as_revoker(&self) -> Option<&dyn Revoker> {
        Some(self)
    }
}

// ---------------------------------------------------------------------------
// Revoker trait for ZeroSslApiIssuer
// ---------------------------------------------------------------------------

#[async_trait]
impl Revoker for ZeroSslApiIssuer {
    /// Revoke a certificate using ZeroSSL's REST API.
    ///
    /// The `cert_pem` parameter is currently unused. Revocation requires the
    /// certificate ID, which must be stored in the certificate resource's
    /// metadata (set during issuance). This implementation attempts to extract
    /// the certificate ID from the metadata stored alongside the PEM.
    ///
    /// **Note**: For this to work, the caller must pass the certificate
    /// resource metadata (containing the `certificate_id` field) as
    /// JSON-encoded bytes in `cert_pem`. If the metadata cannot be parsed,
    /// an error is returned describing the limitation.
    async fn revoke(&self, cert_pem: &[u8], reason: Option<u8>) -> Result<()> {
        // Try to extract the certificate ID from the provided data.
        // The caller may pass the metadata JSON instead of raw PEM.
        let cert_id = if let Ok(text) = std::str::from_utf8(cert_pem) {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(text) {
                meta.get("certificate_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned())
            } else {
                None
            }
        } else {
            None
        };

        let cert_id = cert_id.ok_or_else(|| {
            Error::Other(
                "cannot revoke ZeroSSL REST API certificate: no certificate_id found. \
                 Pass the metadata JSON (containing \"certificate_id\") as the cert_pem argument."
                    .to_owned(),
            )
        })?;

        let reason_str = reason.unwrap_or(0).to_string();
        let url = format!(
            "{ZEROSSL_API_BASE}/certificates/{cert_id}/revoke?access_key={}",
            self.api_key
        );

        debug!(cert_id = %cert_id, reason = %reason_str, "revoking ZeroSSL certificate via REST API");

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .form(&[("reason", reason_str.as_str())])
            .send()
            .await
            .map_err(|e| Error::Other(format!("failed to revoke ZeroSSL certificate: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_owned());
            return Err(Error::Other(format!(
                "ZeroSSL revoke returned HTTP {status}: {body}"
            )));
        }

        info!(cert_id = %cert_id, "revoked ZeroSSL certificate via REST API");
        Ok(())
    }
}
