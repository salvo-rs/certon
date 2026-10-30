//! ZeroSSL certificate issuers.
//!
//! This module provides two issuer implementations for ZeroSSL:
//!
//! - [`ZeroSslIssuer`] — uses ZeroSSL's ACME endpoint with automatic EAB provisioning (recommended
//!   for most use cases).
//! - [`ZeroSslApiIssuer`] — uses ZeroSSL's REST API directly (not ACME). This is useful when ACME
//!   challenges are not practical, as it supports email-based domain validation. Note that REST API
//!   access may be restricted by payment tier.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, info, warn};
use url::Url;

use crate::acme_client::{ExternalAccountBinding, ZEROSSL_PRODUCTION};
use crate::acme_issuer::{AcmeIssuer, CertIssuer, ChainPreference, IssuedCertificate, Revoker};
use crate::crypto::{KeyType, encode_private_key_pem, generate_csr, generate_private_key_async};
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

fn zerossl_client() -> Result<&'static reqwest::Client> {
    crate::http::client()
}

async fn zerossl_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    action: &'static str,
) -> Result<T> {
    let body =
        crate::http::read_body_limited(response, crate::http::MAX_JSON_BODY_BYTES, action).await?;
    serde_json::from_slice(&body)
        .map_err(|e| Error::Other(format!("failed to parse {action} JSON response: {e}")))
}

async fn zerossl_error_body(response: reqwest::Response, action: &'static str) -> Result<String> {
    let body =
        crate::http::read_body_limited(response, crate::http::MAX_ERROR_BODY_BYTES, action).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn zerossl_url(base: &str, api_key: &str) -> Result<Url> {
    let mut url = Url::parse(base)
        .map_err(|e| Error::Other(format!("failed to build ZeroSSL API URL: {e}")))?;
    url.query_pairs_mut().append_pair("access_key", api_key);
    Ok(url)
}

fn zerossl_api_url<'a>(segments: impl IntoIterator<Item = &'a str>, api_key: &str) -> Result<Url> {
    let mut url = Url::parse(ZEROSSL_API_BASE)
        .map_err(|e| Error::Other(format!("failed to build ZeroSSL API URL: {e}")))?;
    {
        let mut path_segments = url
            .path_segments_mut()
            .map_err(|_| Error::Other("ZeroSSL API base URL cannot be a base".to_owned()))?;
        path_segments.clear();
        for segment in segments {
            path_segments.push(segment);
        }
    }
    url.query_pairs_mut().append_pair("access_key", api_key);
    Ok(url)
}

fn zerossl_request_error(action: &str, e: reqwest::Error) -> Error {
    let timeout = e.is_timeout();
    let e = e.without_url();
    if timeout {
        Error::Timeout(format!(
            "ZeroSSL {action} timed out after {:?}",
            crate::http::REQUEST_TIMEOUT
        ))
    } else {
        Error::Other(format!("failed to {action}: {e}"))
    }
}

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

#[cfg(test)]
mod ari_tests;

#[async_trait]
impl CertIssuer for ZeroSslIssuer {
    async fn issue(&self, csr_der: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.inner.issue(csr_der, domains).await
    }

    async fn renewal_info(&self, leaf_der: &[u8]) -> Result<Option<crate::RenewalInfo>> {
        self.inner.renewal_info(leaf_der).await
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
    let url = zerossl_url(ZEROSSL_EAB_ENDPOINT, api_key)?;

    debug!("fetching EAB credentials from ZeroSSL API");

    let client = zerossl_client()?;
    let resp = client
        .post(url)
        .send()
        .await
        .map_err(|e| zerossl_request_error("request EAB credentials", e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = zerossl_error_body(resp, "ZeroSSL EAB error").await?;
        return Err(Error::Other(format!(
            "ZeroSSL EAB endpoint returned HTTP {status}: {body}"
        )));
    }

    let eab_resp: EabCredentialsResponse = zerossl_json(resp, "ZeroSSL EAB").await?;

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

    async fn body_response(
        body: &str,
        chunked: bool,
    ) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let body = body.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let encoding = if chunked {
                "Transfer-Encoding: chunked\r\n".to_owned()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let header = format!("HTTP/1.1 200 OK\r\n{encoding}Connection: close\r\n\r\n");
            if stream.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            if chunked {
                for part in body.as_bytes().chunks(4096) {
                    if stream
                        .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                        .await
                        .is_err()
                        || stream.write_all(part).await.is_err()
                        || stream.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
            } else {
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });
        (
            zerossl_client().unwrap().get(url).send().await.unwrap(),
            task,
        )
    }

    #[tokio::test]
    async fn zerossl_json_readers_bound_known_and_chunked_bodies() {
        for chunked in [false, true] {
            let (response, task) = body_response("{\"success\":true}", chunked).await;
            let value: serde_json::Value = zerossl_json(response, "ZeroSSL test").await.unwrap();
            assert_eq!(value["success"], true);
            task.await.unwrap();
            let oversized =
                serde_json::json!({"padding": "x".repeat(crate::http::MAX_JSON_BODY_BYTES)})
                    .to_string();
            let (response, task) = body_response(&oversized, chunked).await;
            let error = zerossl_json::<serde_json::Value>(response, "ZeroSSL test")
                .await
                .unwrap_err();
            assert!(error.to_string().contains("exceeds"));
            assert!(error.to_string().len() < 1024);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn zerossl_error_readers_use_the_smaller_log_budget() {
        for chunked in [false, true] {
            let (response, task) = body_response("diagnostic", chunked).await;
            assert_eq!(
                zerossl_error_body(response, "ZeroSSL test error")
                    .await
                    .unwrap(),
                "diagnostic"
            );
            task.await.unwrap();
            let (response, task) =
                body_response(&"x".repeat(crate::http::MAX_ERROR_BODY_BYTES + 1), chunked).await;
            let error = zerossl_error_body(response, "ZeroSSL test error")
                .await
                .unwrap_err();
            assert!(error.to_string().contains("exceeds 65536 bytes"));
            task.await.unwrap();
        }
    }

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
            .with_key_type(KeyType::EcdsaP384)
            .with_poll_interval(Duration::from_secs(10));
        assert_eq!(issuer.validity_days, 365);
        assert_eq!(issuer.key_type, KeyType::EcdsaP384);
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

    #[tokio::test]
    async fn rest_manager_revocation_uses_resource_id_and_checks_success_envelope() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::{
            CertManager, CertStore, CertificateResource, FileStorage, KeyValueCertStore, OcspConfig,
        };
        for (body, succeeds) in [
            (r#"{"success":1}"#, true),
            (r#"{"success":true}"#, true),
            (
                r#"{"success":false,"error":{"code":2906,"type":"revocation_failed"}}"#,
                false,
            ),
            (r#"{}"#, false),
            ("invalid JSON", false),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
            let store = Arc::new(KeyValueCertStore::new(storage.clone()));
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["example.com".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let resource = CertificateResource {
                sans: vec!["example.com".into()],
                certificate_pem: cert.pem().into_bytes(),
                private_key_pem: key.serialize_pem().into_bytes(),
                issuer_key: ZEROSSL_API_ISSUER_KEY.into(),
                issuer_data: Some(serde_json::json!({"certificate_id":"cert-123"})),
            };
            store.save(ZEROSSL_API_ISSUER_KEY, &resource).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut issuer = ZeroSslApiIssuer::new("test-access-key", storage.clone());
            issuer.revocation_origin =
                Some(Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 2048];
                    let count = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let header = std::str::from_utf8(&request[..end]).unwrap();
                        let length: usize = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request.starts_with(
                        "POST /certificates/cert-123/revoke?access_key=test-access-key HTTP/1.1\r\n"
                    ),
                    "{request}"
                );
                assert!(request.ends_with("reason=1"), "{request}");
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
            });
            let manager = CertManager::builder()
                .storage(storage)
                .certificates(store.clone())
                .issuers(vec![Arc::new(issuer)])
                .ocsp(OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                })
                .build();
            manager.manage(&["example.com".into()]).await.unwrap();
            assert_eq!(
                manager.revoke("example.com", Some(1)).await.is_ok(),
                succeeds,
                "body={body}"
            );
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
            assert!(manager.cache.get_all().await.is_empty());
            assert_eq!(
                store
                    .load(ZEROSSL_API_ISSUER_KEY, "example.com")
                    .await
                    .unwrap()
                    .is_none(),
                succeeds
            );
            if !succeeds {
                assert!(manager.load_certificate("example.com").await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn rest_revoker_keeps_pem_contract_and_requires_resource_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let issuer = ZeroSslApiIssuer::new(
            "secret",
            Arc::new(crate::FileStorage::new(directory.path())),
        );
        for bytes in [
            b"-----BEGIN CERTIFICATE-----".as_slice(),
            br#"{"certificate_id":"not-pem"}"#.as_slice(),
        ] {
            let error = issuer.revoke(bytes, None).await.unwrap_err().to_string();
            assert!(error.contains("revoke_resource"));
        }
        let resource = crate::CertificateResource {
            sans: vec!["example.com".into()],
            certificate_pem: vec![],
            private_key_pem: vec![],
            issuer_key: ZEROSSL_API_ISSUER_KEY.into(),
            issuer_data: None,
        };
        assert!(
            issuer
                .revoke_resource(&resource, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("no certificate_id")
        );
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
    #[serde(default)]
    success: Option<serde_json::Value>,
    #[serde(default)]
    validation: Option<ZeroSslValidationOptions>,
}

#[derive(Debug, Deserialize)]
struct ZeroSslValidationOptions {
    #[serde(default)]
    email_validation: BTreeMap<String, Vec<String>>,
}

// Preserve explicit null separately from a missing field. Besides avoiding
// accidental confirmation, this lets derived deserialization reject duplicate
// confirmation/identity fields even when their first value is null.
#[derive(Default)]
struct ZeroSslPresentValue(Option<serde_json::Value>);

impl<'de> Deserialize<'de> for ZeroSslPresentValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        serde_json::Value::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

#[derive(Deserialize)]
struct ZeroSslEmailResponse {
    #[serde(default)]
    success: ZeroSslPresentValue,
    #[serde(default)]
    error: ZeroSslPresentValue,
    #[serde(default)]
    id: ZeroSslPresentValue,
    #[serde(default)]
    status: ZeroSslPresentValue,
    #[serde(default)]
    validation_type: ZeroSslPresentValue,
    #[serde(default)]
    validation_emails: ZeroSslPresentValue,
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
/// download certificates. It uses **email-based domain validation**. Configure
/// one address for each requested domain with [`Self::with_validation_email`];
/// the address must appear in ZeroSSL's eligible validation emails for that
/// domain. A recipient must approve the email before issuance can finish.
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
///     .with_key_type(KeyType::EcdsaP256)
///     .with_validation_email("example.com", "admin@example.com")?;
/// # Ok::<(), certon::Error>(())
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
    /// Explicit per-domain recipients; never inferred from administrative names.
    validation_emails: BTreeMap<String, String>,
    #[cfg(test)]
    revocation_origin: Option<Url>,
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
    /// Configure recipients with [`Self::with_validation_email`] before issuance.
    pub fn new(api_key: impl Into<String>, storage: Arc<dyn Storage>) -> Self {
        Self {
            api_key: api_key.into(),
            validity_days: DEFAULT_VALIDITY_DAYS,
            storage,
            key_type: KeyType::EcdsaP256,
            poll_interval: DEFAULT_POLL_INTERVAL,
            validation_emails: BTreeMap::new(),
            #[cfg(test)]
            revocation_origin: None,
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

    /// Select an email validation recipient for one domain.
    ///
    /// Call once per requested domain. DNS names are compared without ASCII
    /// case or a trailing dot; wildcard prefixes remain significant. Duplicate
    /// domains and email list delimiters are rejected. Addresses are matched
    /// exactly against the CA's `validation.email_validation` candidates.
    /// The selected addresses are sent in requested-domain order using the
    /// REST API's `validation_email` comma-separated form field. Extra configured
    /// domains may be retained for later requests using the same issuer.
    pub fn with_validation_email(
        mut self,
        domain: impl AsRef<str>,
        email: impl AsRef<str>,
    ) -> Result<Self> {
        let domain = Self::validation_domain(domain.as_ref())?;
        let email = email.as_ref();
        if email.len() > 254
            || email
                .bytes()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control() || c == b',')
            || !email.split_once('@').is_some_and(|(local, host)| {
                !local.is_empty() && !host.is_empty() && !host.contains('@')
            })
        {
            return Err(Error::Config(
                "invalid ZeroSSL validation email address".into(),
            ));
        }
        if self.validation_emails.contains_key(&domain) {
            return Err(Error::Config(
                "duplicate ZeroSSL email validation domain".into(),
            ));
        }
        self.validation_emails.insert(domain, email.to_owned());
        Ok(self)
    }

    fn validation_domain(domain: &str) -> Result<String> {
        if !crate::dns_util::is_valid_domain(domain) {
            return Err(Error::Config(
                "invalid ZeroSSL email validation domain".into(),
            ));
        }
        Ok(domain
            .strip_suffix('.')
            .unwrap_or(domain)
            .to_ascii_lowercase())
    }

    fn selected_validation_emails(&self, domains: &[String]) -> Result<Vec<String>> {
        let mut seen = HashSet::new();
        domains
            .iter()
            .map(|domain| {
                let domain = Self::validation_domain(domain)?;
                if !seen.insert(domain.clone()) {
                    return Err(Error::Config(
                        "duplicate ZeroSSL email validation domain".into(),
                    ));
                }
                self.validation_emails.get(&domain).cloned().ok_or_else(|| {
                    Error::Config(
                        "configure a ZeroSSL validation email for every requested domain".into(),
                    )
                })
            })
            .collect()
    }

    fn check_validation_candidates(
        response: &ZeroSslCertResponse,
        domains: &[String],
        emails: &[String],
    ) -> Result<()> {
        let options = response.validation.as_ref().ok_or_else(|| {
            Error::Other("ZeroSSL create response missing eligible validation emails".into())
        })?;
        for (domain, email) in domains.iter().zip(emails) {
            let canonical = Self::validation_domain(domain)?;
            let mut matches = options.email_validation.iter().filter(|(name, _)| {
                Self::validation_domain(name).is_ok_and(|name| name == canonical)
            });
            let Some((_, candidates)) = matches.next() else {
                return Err(Error::Other(
                    "ZeroSSL create response missing domain's eligible validation emails".into(),
                ));
            };
            if matches.next().is_some() || !candidates.contains(email) {
                return Err(Error::Config(
                    "selected ZeroSSL validation email is not an unambiguous eligible address"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn api_url<'a>(&self, segments: impl IntoIterator<Item = &'a str>) -> Result<Url> {
        let url = zerossl_api_url(segments, &self.api_key)?;
        #[cfg(test)]
        let url = if let Some(origin) = &self.revocation_origin {
            let mut url = url;
            url.set_scheme(origin.scheme()).unwrap();
            url.set_host(origin.host_str()).unwrap();
            url.set_port(origin.port()).unwrap();
            url
        } else {
            url
        };
        Ok(url)
    }

    fn validation_error(&self, status: reqwest::StatusCode, error: &serde_json::Value) -> Error {
        // Only retain structured diagnostic identifiers, never a provider body
        // or URL that could echo access_key (including its encoded form).
        let code = error.get("code").and_then(serde_json::Value::as_u64);
        let kind = error
            .get("type")
            .and_then(serde_json::Value::as_str)
            .filter(|kind| {
                !kind.is_empty()
                    && kind.len() <= 80
                    && kind
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                    && (self.api_key.is_empty() || !kind.contains(&self.api_key))
            });
        Error::Other(format!(
            "ZeroSSL email validation was not confirmed (HTTP {status}, code {code:?}, type {})",
            kind.unwrap_or("[REDACTED]")
        ))
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
        let url = self.api_url(["certificates"])?;
        let domains_csv = domains.join(",");

        debug!(domains = %domains_csv, "creating ZeroSSL certificate via REST API");

        let client = zerossl_client()?;
        let resp = client
            .post(url)
            .form(&[
                ("certificate_domains", domains_csv.as_str()),
                ("certificate_csr", csr_pem),
                ("certificate_validity_days", &self.validity_days.to_string()),
            ])
            .send()
            .await
            .map_err(|e| zerossl_request_error("create ZeroSSL certificate", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = crate::http::read_body_limited(
                resp,
                crate::http::MAX_ERROR_BODY_BYTES,
                "ZeroSSL create error",
            )
            .await?;
            let body: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            return Err(self.validation_error(
                status,
                body.get("error").unwrap_or(&serde_json::Value::Null),
            ));
        }

        let body = crate::http::read_body_limited(
            resp,
            crate::http::MAX_JSON_BODY_BYTES,
            "ZeroSSL create",
        )
        .await?;
        let cert_resp: ZeroSslCertResponse = serde_json::from_slice(&body)
            .map_err(|_| Error::Other("invalid ZeroSSL create JSON response".into()))?;

        if let Some(ref err) = cert_resp.error {
            return Err(self.validation_error(status, err));
        }
        if cert_resp
            .success
            .as_ref()
            .is_some_and(|success| success.as_bool() != Some(true) && success.as_u64() != Some(1))
        {
            return Err(self.validation_error(status, &serde_json::Value::Null));
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
    /// This tells ZeroSSL to send validation emails to the explicitly selected
    /// eligible recipients and requires confirmation before polling.
    async fn verify_by_email(&self, cert_id: &str, emails: &[String]) -> Result<()> {
        let url = self.api_url(["certificates", cert_id, "challenges"])?;
        let emails_csv = emails.join(",");

        debug!(
            cert_id = cert_id,
            "initiating email validation for ZeroSSL certificate"
        );

        let client = zerossl_client()?;
        let resp = client
            .post(url)
            .form(&[
                ("validation_method", "EMAIL"),
                ("validation_email", emails_csv.as_str()),
            ])
            .send()
            .await
            .map_err(|e| zerossl_request_error("initiate ZeroSSL email validation", e))?;

        let status = resp.status();
        let limit = if status.is_success() {
            crate::http::MAX_JSON_BODY_BYTES
        } else {
            crate::http::MAX_ERROR_BODY_BYTES
        };
        let body = crate::http::read_body_limited(resp, limit, "ZeroSSL email validation").await?;
        let response: ZeroSslEmailResponse = serde_json::from_slice(&body)
            .map_err(|_| Error::Other("invalid ZeroSSL email validation JSON response".into()))?;
        let error = response
            .error
            .0
            .as_ref()
            .unwrap_or(&serde_json::Value::Null);
        let explicit_success = response
            .success
            .0
            .as_ref()
            .is_some_and(|value| value.as_bool() == Some(true) || value.as_u64() == Some(1));
        if !status.is_success()
            || !error.is_null()
            || (response.success.0.is_some() && !explicit_success)
        {
            return Err(self.validation_error(status, error));
        }
        let has_object = response.id.0.is_some() || response.status.0.is_some();
        let valid_object = response.id.0.as_ref().and_then(serde_json::Value::as_str)
            == Some(cert_id)
            && matches!(
                response
                    .status
                    .0
                    .as_ref()
                    .and_then(serde_json::Value::as_str),
                Some("pending_validation" | "issued")
            );
        // VerifyIdentifiers returns a certificate object in the original SDK.
        // Also tolerate an explicit success envelope, but never let it mask a
        // contradictory or partially supplied certificate identity.
        if (has_object && !valid_object) || (!has_object && !explicit_success) {
            return Err(self.validation_error(status, error));
        }
        if response
            .validation_type
            .0
            .as_ref()
            .filter(|value| !value.is_null())
            .is_some_and(|value| {
                !value
                    .as_str()
                    .is_some_and(|method| method.eq_ignore_ascii_case("EMAIL"))
            })
            || response
                .validation_emails
                .0
                .as_ref()
                .filter(|value| !value.is_null())
                .is_some_and(|value| {
                    let Some(csv) = value.as_str() else {
                        return true;
                    };
                    let mut actual: Vec<_> = csv.split(',').map(str::trim).collect();
                    let mut expected: Vec<_> = emails.iter().map(String::as_str).collect();
                    actual.sort_unstable();
                    expected.sort_unstable();
                    actual != expected
                })
        {
            return Err(self.validation_error(status, error));
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
        let url = self.api_url(["certificates", cert_id])?;
        let client = zerossl_client()?;

        for attempt in 1..=MAX_POLL_ATTEMPTS {
            tokio::time::sleep(self.poll_interval).await;

            debug!(
                cert_id = cert_id,
                attempt = attempt,
                "polling ZeroSSL certificate status"
            );

            let resp = client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| zerossl_request_error("poll ZeroSSL certificate status", e))?;

            let status = resp.status();
            if !status.is_success() {
                let body = zerossl_error_body(resp, "ZeroSSL status error").await?;
                warn!(
                    cert_id = cert_id,
                    http_status = %status,
                    "ZeroSSL status poll returned non-success; retrying"
                );
                debug!(body = body, "ZeroSSL status poll response body");
                continue;
            }

            let cert_resp: ZeroSslCertResponse = zerossl_json(resp, "ZeroSSL status").await?;

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
        let url = self.api_url(["certificates", cert_id, "download", "return"])?;

        debug!(cert_id = cert_id, "downloading ZeroSSL certificate");

        let client = zerossl_client()?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| zerossl_request_error("download ZeroSSL certificate", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = zerossl_error_body(resp, "ZeroSSL download error").await?;
            return Err(Error::Other(format!(
                "ZeroSSL download returned HTTP {status}: {body}"
            )));
        }

        let download: ZeroSslDownloadResponse = zerossl_json(resp, "ZeroSSL download").await?;

        // Concatenate the leaf certificate and CA bundle into a single PEM chain.
        let full_chain = format!("{}{}", download.certificate_crt, download.ca_bundle_crt);

        info!(cert_id = cert_id, "downloaded ZeroSSL certificate");
        Ok(full_chain)
    }
}

// ---------------------------------------------------------------------------
// CertIssuer trait for ZeroSslApiIssuer
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "zerossl_issuer/email_validation_tests.rs"]
mod email_validation_tests;

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
        let validation_emails = self.selected_validation_emails(domains)?;

        // Generate a key + CSR if none was provided.
        let (private_key_pem, csr_der_owned) = if csr_der.is_empty() {
            let key = generate_private_key_async(self.key_type).await?;
            let pem = encode_private_key_pem(&key)?;
            let csr = generate_csr(&key, domains, false)?;
            (pem.into_bytes(), csr)
        } else {
            (Vec::new(), csr_der.to_vec())
        };

        let csr_pem = Self::encode_csr_pem(&csr_der_owned);

        // Step 1: Create the certificate.
        let cert_resp = self.create_certificate(&csr_pem, domains).await?;
        Self::check_validation_candidates(&cert_resp, domains, &validation_emails)?;
        let cert_id = cert_resp.id;

        // Step 2: Initiate email validation.
        self.verify_by_email(&cert_id, &validation_emails).await?;

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
    /// REST revocation needs the ID saved during issuance. PEM bytes alone
    /// cannot identify a ZeroSSL REST resource; use `revoke_resource` instead.
    async fn revoke(&self, _cert_pem: &[u8], _reason: Option<u8>) -> Result<()> {
        Err(Error::Config(
            "ZeroSSL REST revocation requires CertificateResource.issuer_data.certificate_id; use revoke_resource".into(),
        ))
    }

    async fn revoke_resource(
        &self,
        resource: &crate::CertificateResource,
        reason: Option<u8>,
    ) -> Result<()> {
        let cert_id = resource
            .issuer_data
            .as_ref()
            .and_then(|metadata| metadata.get("certificate_id"))
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                Error::Config(
                    "ZeroSSL REST certificate has no certificate_id in issuer_data".into(),
                )
            })?;

        let reason_str = reason.unwrap_or(0).to_string();
        let url = zerossl_api_url(["certificates", cert_id, "revoke"], &self.api_key)?;
        #[cfg(test)]
        let url = if let Some(origin) = &self.revocation_origin {
            let mut url = url;
            url.set_scheme(origin.scheme()).unwrap();
            url.set_host(origin.host_str()).unwrap();
            url.set_port(origin.port()).unwrap();
            url
        } else {
            url
        };

        debug!(cert_id = %cert_id, reason = %reason_str, "revoking ZeroSSL certificate via REST API");

        let client = zerossl_client()?;
        let resp = client
            .post(url)
            .form(&[("reason", reason_str.as_str())])
            .send()
            .await
            .map_err(|e| zerossl_request_error("revoke ZeroSSL certificate", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = zerossl_error_body(resp, "ZeroSSL revoke error").await?;
            return Err(Error::Other(format!(
                "ZeroSSL revoke returned HTTP {status}: {body}"
            )));
        }

        let body: serde_json::Value = zerossl_json(resp, "ZeroSSL revoke").await?;
        // The revoke endpoint documents success: 1. Also accept true, while
        // never treating an HTTP 200 error envelope as confirmation.
        let success = body
            .get("success")
            .is_some_and(|value| value.as_u64() == Some(1) || value.as_bool() == Some(true));
        if !success || body.get("error").is_some_and(|error| !error.is_null()) {
            return Err(Error::Other(format!(
                "ZeroSSL revocation was not confirmed: {body}"
            )));
        }
        info!(cert_id = %cert_id, "revoked ZeroSSL certificate via REST API");
        Ok(())
    }
}
