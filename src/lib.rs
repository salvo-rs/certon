//! # Certon
//!
//! Automatic HTTPS/TLS certificate management using the ACME protocol.
//!
//! Certon provides production-grade automatic certificate management.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use certon::CertManager;
//!
//! #[tokio::main]
//! async fn main() -> certon::Result<()> {
//!     let domains = vec!["example.com".into()];
//!     let tls_config = certon::manage(&domains).await?;
//!     // Use tls_config with your server...
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! - [`CertManager`] runs the certificate lifecycle: obtain, renew, revoke, cache, serve.
//! - [`Policy`] holds certificate management settings.
//! - [`AcmeIssuer`] and `ZeroSslIssuer` (with `zerossl`) implement [`CertIssuer`].
//! - [`CertCache`] provides an in-memory certificate store indexed by domain name for fast TLS
//!   handshake lookups.
//! - [`CertResolver`] implements [`rustls::server::ResolvesServerCert`] and plugs directly into a
//!   `rustls::ServerConfig`.
//! - [`CertStore`] holds certificates; [`KeyValueCertStore`] adapts a [`Storage`].
//! - [`Storage`] provides key-value persistence and cluster locks.
//! - [`http`] owns the shared outbound HTTP client.
//! - [`start_maintenance`] runs background loops that renew certificates and refresh OCSP staples.
//! - [`Manager`] is an external certificate provider trait for custom sources.
//! - [`PreChecker`] validates domains before ACME issuance is attempted.
//! - [`HttpsRedirectHandler`] redirects HTTP traffic to HTTPS.

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("Either the `aws-lc-rs` (default) or `ring` feature must be enabled");

use std::sync::Arc;

/// Install a default rustls provider while preserving an embedder's choice.
///
/// Useful when building rustls configurations with both provider features enabled.
pub fn install_default_crypto_provider() {
    http::install_crypto_provider();
}

pub mod account;
pub mod acme_client;
pub mod acme_issuer;
pub mod async_jobs;
pub mod cache;
pub mod cert_store;
pub mod certificates;
pub mod crypto;
#[cfg(feature = "dns-01")]
pub mod dns_util;
pub mod error;
pub mod file_storage;
pub mod handshake;
pub mod http;
pub mod http_handler;
pub mod maintain;
pub mod manager;
pub mod ocsp;
pub mod policy;
pub mod rate_limiter;
pub mod redirect;
pub mod solvers;
pub mod storage;
#[cfg(feature = "zerossl")]
pub mod zerossl_issuer;

// ---------------------------------------------------------------------------
// Re-exports of key public types
// ---------------------------------------------------------------------------

pub use account::{prompt_user_agreement, prompt_user_for_email};
pub use acme_client::{
    LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING, RenewalInfo, RenewalWindow, ZEROSSL_PRODUCTION,
    ari_cert_id,
};
pub use acme_issuer::{
    AcmeIssuer, AcmeIssuerBuilder, CertIssuer, IssuedCertificate, Manager, PreChecker, Revoker,
};
pub use cache::{CacheOptions, CertCache};
pub use cert_store::{CertStore, KeyValueCertStore};
pub use certificates::Certificate;
pub use crypto::{KeyType, PrivateKey};
pub use error::{Error, Result};
pub use file_storage::FileStorage;
pub use handshake::{CertResolver, OnDemandConfig};
pub use http::set_user_agent;
pub use maintain::MaintenanceConfig;
pub use manager::{CertManager, CertManagerBuilder};
pub use ocsp::OcspConfig;
pub use policy::{CertificateSelector, IssuerPolicy, Policy};
pub use redirect::{HttpsRedirectHandler, start_https_redirect, start_https_redirect_to_host};
pub use solvers::{DistributedSolver, Http01Solver, Solver, TlsAlpn01Solver};
#[cfg(feature = "dns-01")]
pub use solvers::{Dns01Solver, DnsProvider};
pub use storage::{
    CertificateResource, KeyInfo, LockGuard, Storage, StorageKeys, acquire, try_acquire,
};
#[cfg(feature = "zerossl")]
pub use zerossl_issuer::{ZeroSslApiIssuer, ZeroSslIssuer};

// ---------------------------------------------------------------------------
// High-level convenience functions
// ---------------------------------------------------------------------------

/// Manage certificates for the given domains using a default configuration.
///
/// This is the highest-level entry point. It:
///
/// 1. Creates a [`CertManager`] backed by the default [`FileStorage`].
/// 2. Calls [`CertManager::manage`] to obtain (or load from storage) and cache certificates for
///    every domain.
/// 3. Returns a [`rustls::ServerConfig`] wired up with a [`CertResolver`] that serves the managed
///    certificates.
///
/// # Errors
///
/// Returns an error if certificate management fails (e.g. no ACME issuers
/// configured, network errors during issuance, storage errors).
///
/// # Example
///
/// ```rust,no_run
/// #[tokio::main]
/// async fn main() -> certon::Result<()> {
///     let domains = vec!["example.com".into()];
///     let tls_config = certon::manage(&domains).await?;
///     // Use tls_config with a tokio-rustls TlsAcceptor, hyper, axum, etc.
///     Ok(())
/// }
/// ```
pub async fn manage(domains: &[String]) -> Result<rustls::ServerConfig> {
    install_default_crypto_provider();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
    let config = CertManager::builder().storage(storage).build();
    config.manage(domains).await?;

    // Build a rustls ServerConfig with the CertResolver backed by the
    // config's in-memory certificate cache.
    let resolver = CertResolver::new(config.cache.clone());
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    Ok(tls_config)
}

/// Obtain/load certificates for `domains` and bind a TLS listener on `addr`.
///
/// Returns a [`tokio_rustls::TlsAcceptor`] that is ready to accept TLS
/// connections. This is a convenience function that combines certificate
/// management with listener setup.
///
/// # Errors
///
/// Returns an error if certificate management or address binding fails.
pub async fn listen(domains: &[String], addr: &str) -> Result<tokio_rustls::TlsAcceptor> {
    let tls_cfg = manage(domains).await?;
    let _listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Other(format!("failed to bind listener on {addr}: {e}")))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg)))
}

/// Obtain or load certificates for `domains`, and wait for it.
///
/// Use this when you already have a `rustls::ServerConfig` and only need the
/// certificates to exist; [`manage`] is the one that hands you a server
/// configuration as well.
///
/// # Errors
///
/// Returns an error if certificate management fails.
pub async fn obtain(domains: &[String]) -> Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
    let config = CertManager::builder().storage(storage).build();
    config.manage(domains).await
}

/// Obtain or load certificates for `domains` without waiting.
///
/// The returned handle can be awaited if you later decide you do want to
/// know how it went.
pub fn obtain_in_background(domains: &[String]) -> tokio::task::JoinHandle<Result<()>> {
    let domains = domains.to_vec();
    tokio::spawn(async move { obtain(&domains).await })
}

/// Start background certificate maintenance for a [`CertManager`].
///
/// Spawns a tokio task that periodically:
/// - Checks all managed certificates in the config's cache for renewal.
/// - Refreshes OCSP staples for cached certificates.
///
/// The returned [`tokio::task::JoinHandle`] can be used to monitor the
/// maintenance task. To stop maintenance, call [`CertCache::stop`] on
/// the config's cache, which signals the task to exit gracefully.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use certon::{CertManager, FileStorage, Storage};
/// # fn example() {
/// let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
/// let config = CertManager::builder().storage(storage).build();
/// let handle = certon::start_maintenance(&config);
/// // ... later, to stop:
/// // config.cache.stop();
/// # }
/// ```
pub fn start_maintenance(config: &CertManager) -> tokio::task::JoinHandle<()> {
    let cache = config.cache.clone();
    let maint_config = MaintenanceConfig {
        renew_check_interval: maintain::DEFAULT_RENEW_CHECK_INTERVAL,
        ocsp_check_interval: maintain::DEFAULT_OCSP_CHECK_INTERVAL,
        ocsp: config.policy.ocsp.clone(),
        storage: config.storage.clone(),
    };

    let renew_func = maintenance_renewal(config);

    maintain::start_maintenance(cache, maint_config, renew_func)
}

fn maintenance_renewal(config: &CertManager) -> Arc<maintain::RenewFn> {
    let manager = Arc::new(config.detached("maintenance"));
    Arc::new(move |domain: String| {
        let manager = Arc::clone(&manager);
        Box::pin(async move { manager.renew(&domain, false).await })
    })
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;

    struct Issuer;
    #[async_trait::async_trait]
    impl CertIssuer for Issuer {
        async fn issue(&self, _: &[u8], _: &[String]) -> Result<IssuedCertificate> {
            Err(Error::Other("configured issuer reached".into()))
        }
        fn issuer_key(&self) -> String {
            "test".into()
        }
    }

    #[tokio::test]
    async fn maintenance_keeps_the_issuer_and_renewal_policy() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        storage::store_certificate(
            storage.as_ref(),
            "test",
            &CertificateResource {
                sans: vec!["example.com".into()],
                certificate_pem: cert.cert.pem().into_bytes(),
                private_key_pem: cert.signing_key.serialize_pem().into_bytes(),
                issuer_key: "test".into(),
                issuer_data: None,
            },
        )
        .await
        .unwrap();
        let config = CertManager::builder()
            .storage(storage)
            .issuers(vec![Arc::new(Issuer)])
            .interactive(true)
            .renewal_window_ratio(1.0)
            .build();
        let error = maintenance_renewal(&config)("example.com".into())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("configured issuer reached"),
            "{error}"
        );
    }
}
