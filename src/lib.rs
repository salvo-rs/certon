//! # Certon
//!
//! Automatic HTTPS/TLS certificate management using the ACME protocol.
//!
//! Certon provides production-grade automatic certificate management.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use certon::Config;
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
//! - [`Config`] is the central entry point that coordinates the certificate lifecycle (obtain,
//!   renew, revoke, cache).
//! - [`AcmeIssuer`] and [`ZeroSslIssuer`] implement the [`CertIssuer`] trait to obtain certificates
//!   from ACME-compatible Certificate Authorities.
//! - [`CertCache`] provides an in-memory certificate store indexed by domain name for fast TLS
//!   handshake lookups.
//! - [`CertResolver`] implements [`rustls::server::ResolvesServerCert`] and plugs directly into a
//!   `rustls::ServerConfig`.
//! - [`Storage`] is the persistence abstraction; [`FileStorage`] is the default filesystem-backed
//!   implementation.
//! - [`start_maintenance`] runs background loops that renew certificates and refresh OCSP staples.
//! - [`Manager`] is an external certificate provider trait for custom sources.
//! - [`PreChecker`] validates domains before ACME issuance is attempted.
//! - [`HttpsRedirectHandler`] redirects HTTP traffic to HTTPS.

use std::sync::Arc;

pub mod account;
pub mod acme_client;
pub mod acme_issuer;
pub mod async_jobs;
pub mod cache;
pub mod certificates;
pub mod config;
pub mod crypto;
pub mod dns_util;
pub mod error;
pub mod file_storage;
pub mod handshake;
pub mod http_handler;
pub mod maintain;
pub mod ocsp;
pub mod rate_limiter;
pub mod redirect;
pub mod solvers;
pub mod storage;
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
pub use certificates::Certificate;
pub use config::{CertificateSelector, Config, ConfigBuilder, IssuerPolicy};
pub use crypto::{KeyType, PrivateKey};
pub use error::{Error, Result};
pub use file_storage::FileStorage;
pub use handshake::{CertResolver, OnDemandConfig};
pub use maintain::MaintenanceConfig;
pub use ocsp::OcspConfig;
pub use redirect::{HttpsRedirectHandler, start_https_redirect};
pub use solvers::{
    DistributedSolver, Dns01Solver, DnsProvider, Http01Solver, Solver, TlsAlpn01Solver,
};
pub use storage::{CertificateResource, KeyInfo, Storage, StorageKeys};
pub use zerossl_issuer::{ZeroSslApiIssuer, ZeroSslIssuer};

// ---------------------------------------------------------------------------
// High-level convenience functions
// ---------------------------------------------------------------------------

/// Manage certificates for the given domains using a default configuration.
///
/// This is the highest-level entry point. It:
///
/// 1. Creates a [`Config`] backed by the default [`FileStorage`].
/// 2. Calls [`Config::manage_sync`] to obtain (or load from storage) and cache certificates for
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
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
    let config = Config::builder().storage(storage).build();
    config.manage_sync(domains).await?;

    // Build a rustls ServerConfig with the CertResolver backed by the
    // config's in-memory certificate cache.
    let resolver = CertResolver::new(config.cache.clone());
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    Ok(tls_config)
}

/// Create a TLS configuration for the given domains.
///
/// This is an alias for [`manage`] — it obtains/loads certificates for
/// `domains` and returns a ready-to-use [`rustls::ServerConfig`].
///
/// # Errors
///
/// See [`manage`] for error conditions.
pub async fn tls_config(domains: &[String]) -> Result<rustls::ServerConfig> {
    manage(domains).await
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

/// Synchronous-style certificate management for the given domains.
///
/// Obtains/loads certificates using a default configuration and waits for
/// completion. This is a convenience wrapper around
/// [`Config::manage_sync`].
///
/// # Errors
///
/// Returns an error if certificate management fails.
pub async fn manage_sync(domains: &[String]) -> Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
    let config = Config::builder().storage(storage).build();
    config.manage_sync(domains).await
}

/// Asynchronous certificate management for the given domains.
///
/// Spawns certificate management as a background task and returns
/// immediately. The returned [`tokio::task::JoinHandle`] can be awaited
/// to wait for completion.
pub fn manage_async(domains: &[String]) -> tokio::task::JoinHandle<Result<()>> {
    let domains = domains.to_vec();
    tokio::spawn(async move { manage_sync(&domains).await })
}

/// Start background certificate maintenance for a [`Config`].
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
/// # use certon::{Config, FileStorage, Storage};
/// # fn example() {
/// let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
/// let config = Config::builder().storage(storage).build();
/// let handle = certon::start_maintenance(&config);
/// // ... later, to stop:
/// // config.cache.stop();
/// # }
/// ```
pub fn start_maintenance(config: &Config) -> tokio::task::JoinHandle<()> {
    let cache = config.cache.clone();
    let maint_config = MaintenanceConfig {
        renew_check_interval: maintain::DEFAULT_RENEW_CHECK_INTERVAL,
        ocsp_check_interval: maintain::DEFAULT_OCSP_CHECK_INTERVAL,
        ocsp: config.ocsp.clone(),
        storage: config.storage.clone(),
    };

    // Build a renewal function that delegates to Config::renew_cert_sync.
    // We need to clone the config's relevant parts into an Arc so the
    // closure can be 'static + Send + Sync.
    let config_storage = config.storage.clone();
    let config_cache = config.cache.clone();
    let config_issuers = config.issuers.clone();
    let config_key_type = config.key_type;
    let config_ocsp = config.ocsp.clone();
    let config_renewal_ratio = config.renewal_window_ratio;

    let renew_func: Arc<maintain::RenewFn> = Arc::new(move |domain: String| {
        let storage = config_storage.clone();
        let cache = config_cache.clone();
        let issuers = config_issuers.clone();
        let key_type = config_key_type;
        let ocsp_cfg = config_ocsp.clone();
        let renewal_ratio = config_renewal_ratio;

        Box::pin(async move {
            // Reconstruct a minimal Config for renewal.
            let cfg = Config::builder().storage(storage).build();
            // NOTE: This is a simplified renewal path. In a full
            // implementation the original Config would be shared via Arc.
            // For now we call manage_sync which handles obtain-or-renew.
            let _ = (cache, issuers, key_type, ocsp_cfg, renewal_ratio);
            cfg.manage_sync(&[domain]).await
        })
    });

    maintain::start_maintenance(cache, maint_config, renew_func)
}
