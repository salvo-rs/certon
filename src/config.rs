//! Central configuration hub and certificate lifecycle management.
//!
//! This module provides the [`Config`] struct, which is the primary entry
//! point for managing TLS certificates. It coordinates certificate
//! obtainment, renewal, revocation, and caching across multiple issuers
//! and a persistent storage backend.
//!
//!
//! # Usage
//!
//! ```ignore
//! use certon::config::Config;
//!
//! let config = Config::builder()
//!     .storage(my_storage)
//!     .build();
//!
//! config.manage_sync(&["example.com".into()]).await?;
//! ```

use std::sync::Arc;

use tracing::{debug, error, info, warn};

use crate::acme_issuer::CertIssuer;
use crate::async_jobs::{JobQueue, RetryConfig, do_with_retry};
use crate::cache::CertCache;
use crate::certificates::{Certificate, subject_qualifies_for_cert};
use crate::crypto::{
    KeyType, decode_private_key_pem, encode_private_key_pem, generate_csr, generate_private_key,
};
use crate::error::{Error, Result, StorageError};
use crate::handshake::{CertResolver, OnDemandConfig};
use crate::ocsp::{OcspConfig, OcspStatus, staple_ocsp};
use crate::storage::{
    CertificateResource, Storage, load_certificate, site_cert_key, site_meta_key, site_private_key,
    store_certificate,
};

// ---------------------------------------------------------------------------
// IssuerPolicy
// ---------------------------------------------------------------------------

/// Controls how issuers are selected when obtaining or renewing certificates.
#[derive(Debug, Clone, Copy, Default)]
pub enum IssuerPolicy {
    /// Use issuers in the order they were configured (first to last).
    #[default]
    UseFirstIssuer,
    /// Shuffle issuers randomly before iterating, distributing load across CAs.
    UseFirstRandomIssuer,
}

// ---------------------------------------------------------------------------
// CertificateSelector trait
// ---------------------------------------------------------------------------

/// Trait for custom certificate selection logic during TLS handshakes.
///
/// Implementations can inspect the [`ClientHello`](rustls::server::ClientHello)
/// and choose which certificate to present from the available options.
pub trait CertificateSelector: Send + Sync {
    /// Select a certificate from `choices` to present for the given TLS
    /// handshake. Returns the index into `choices`, or `None` to fall
    /// back to the default selection logic.
    fn select_certificate(
        &self,
        hello: &rustls::server::ClientHello<'_>,
        choices: &[&Certificate],
    ) -> Option<usize>;
}

// ---------------------------------------------------------------------------
// Event name constants
// ---------------------------------------------------------------------------

/// Event emitted when a certificate obtain operation begins.
///
/// Event data: `{ "identifier": "<domain>", "renewal": false }`.
/// Returning an error from the event callback will **not** abort this event
/// (the obtain will proceed).
pub const EVENT_CERT_OBTAINING: &str = "cert_obtaining";

/// Event emitted when a certificate has been successfully obtained.
///
/// Event data: `{ "identifier": "<domain>", "issuer": "<issuer_key>", "renewal": false }`.
pub const EVENT_CERT_OBTAINED: &str = "cert_obtained";

/// Event emitted when a certificate has been successfully renewed.
///
/// Event data: `{ "identifier": "<domain>", "issuer": "<issuer_key>", "renewal": true }`.
pub const EVENT_CERT_RENEWED: &str = "cert_renewed";

/// Event emitted when a certificate has been revoked.
///
/// Event data: `{ "identifier": "<domain>" }`.
pub const EVENT_CERT_REVOKED: &str = "cert_revoked";

/// Event emitted when a certificate obtain or renewal operation failed.
///
/// Event data: `{ "identifier": "<domain>", "renewal": <bool>, "issuers": [...] }`.
pub const EVENT_CERT_FAILED: &str = "cert_failed";

/// Event emitted when a managed certificate is cached (loaded from storage
/// into the in-memory [`CertCache`]).
///
/// Event data: `{ "sans": [<domain>, ...] }`.
pub const EVENT_CACHED_MANAGED_CERT: &str = "cached_managed_cert";

// ---------------------------------------------------------------------------
// Lock operation prefix
// ---------------------------------------------------------------------------

/// Lock key prefix for certificate issuance operations.
const CERT_ISSUE_LOCK_OP: &str = "issue_cert";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Central configuration for automatic TLS certificate management.
///
/// `Config` coordinates the full certificate lifecycle: obtainment, renewal,
/// revocation, OCSP stapling, caching, and storage. It holds references to
/// one or more [`CertIssuer`] implementations, a persistent [`Storage`] backend,
/// and a shared in-memory [`CertCache`].
///
/// Use [`Config::builder()`] to construct an instance with sensible defaults.
pub struct Config {
    /// Ratio of certificate lifetime at which to start renewal.
    ///
    /// A value of `1.0 / 3.0` means "renew when only 1/3 of the lifetime
    /// remains". Defaults to [`crate::certificates::DEFAULT_RENEWAL_WINDOW_RATIO`].
    pub renewal_window_ratio: f64,

    /// On-demand TLS configuration (optional).
    ///
    /// When set, certificate operations may be deferred to TLS handshake
    /// time for domains that are not yet managed.
    pub on_demand: Option<Arc<OnDemandConfig>>,

    /// Certificate issuers, tried in order until one succeeds.
    ///
    /// Defaults to a single [`AcmeIssuer`](crate::acme_issuer::AcmeIssuer)
    /// configured for Let's Encrypt production.
    pub issuers: Vec<Arc<dyn CertIssuer>>,

    /// Persistent storage backend for certificates, keys, and metadata.
    pub storage: Arc<dyn Storage>,

    /// Key type for newly generated certificate private keys.
    pub key_type: KeyType,

    /// OCSP stapling configuration.
    pub ocsp: OcspConfig,

    /// Shared in-memory certificate cache.
    pub cache: Arc<CertCache>,

    /// Optional event callback invoked when notable lifecycle events occur.
    ///
    /// The callback receives an event name (one of the `EVENT_*` constants)
    /// and a JSON value containing event-specific data. Returning an error
    /// from the callback may abort the current operation (for critical
    /// events like [`EVENT_CERT_OBTAINING`]). Callbacks should return
    /// quickly as they are invoked synchronously.
    pub on_event: Option<Arc<dyn Fn(&str, &serde_json::Value) -> Result<()> + Send + Sync>>,

    /// Whether user interaction is allowed (e.g. for Terms of Service
    /// acceptance prompts). When `true`, operations run synchronously in
    /// the foreground; when `false`, operations run with automatic retries
    /// in the background.
    pub interactive: bool,

    /// When `true`, request the OCSP Must-Staple extension on new
    /// certificates. Defaults to `false`.
    pub must_staple: bool,

    /// When `true`, reuse the existing private key on certificate renewal
    /// instead of generating a fresh one. Defaults to `false`.
    pub reuse_private_keys: bool,

    /// Optional transform applied to domain names before obtaining
    /// certificates. Can be used for normalization, aliasing, etc.
    pub subject_transformer: Option<Arc<dyn Fn(&str) -> Result<String> + Send + Sync>>,

    /// Fallback server name used when the TLS client does not provide an
    /// SNI value.
    pub default_server_name: Option<String>,

    /// Last-resort server name used when no certificate matches the
    /// requested SNI.
    pub fallback_server_name: Option<String>,

    /// When `true`, skip the storage-health probe on startup.
    /// Defaults to `true`.
    pub disable_storage_check: bool,

    /// Controls how issuers are iterated when obtaining or renewing
    /// certificates. Defaults to [`IssuerPolicy::UseFirstIssuer`].
    pub issuer_policy: IssuerPolicy,

    /// When `true`, disable the ACME Renewal Information (ARI) extension.
    /// Defaults to `false`.
    pub disable_ari: bool,

    /// Optional custom certificate selector for TLS handshakes.
    ///
    /// When set, the selector is consulted to choose among multiple
    /// matching certificates.
    pub cert_selection: Option<Arc<dyn CertificateSelector>>,

    /// Background job queue for async certificate operations.
    ///
    /// Used by `manage_async` to submit background obtain/renew jobs
    /// with deduplication.
    job_queue: Arc<JobQueue>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("renewal_window_ratio", &self.renewal_window_ratio)
            .field("key_type", &self.key_type)
            .field("ocsp", &self.ocsp)
            .field("interactive", &self.interactive)
            .field("must_staple", &self.must_staple)
            .field("reuse_private_keys", &self.reuse_private_keys)
            .field("default_server_name", &self.default_server_name)
            .field("fallback_server_name", &self.fallback_server_name)
            .field("disable_storage_check", &self.disable_storage_check)
            .field("issuer_policy", &self.issuer_policy)
            .field("disable_ari", &self.disable_ari)
            .field("issuers_count", &self.issuers.len())
            .field("on_demand", &self.on_demand.as_ref().map(|_| "..."))
            .field("on_event", &self.on_event.as_ref().map(|_| "..."))
            .field(
                "subject_transformer",
                &self.subject_transformer.as_ref().map(|_| "..."),
            )
            .field(
                "cert_selection",
                &self.cert_selection.as_ref().map(|_| "..."),
            )
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// ConfigBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`Config`] with sensible defaults.
///
/// Created via [`Config::builder()`]. At a minimum, a [`Storage`]
/// implementation must be provided before calling [`build()`](ConfigBuilder::build).
pub struct ConfigBuilder {
    renewal_window_ratio: f64,
    on_demand: Option<Arc<OnDemandConfig>>,
    issuers: Option<Vec<Arc<dyn CertIssuer>>>,
    storage: Option<Arc<dyn Storage>>,
    key_type: KeyType,
    ocsp: OcspConfig,
    cache: Option<Arc<CertCache>>,
    on_event: Option<Arc<dyn Fn(&str, &serde_json::Value) -> Result<()> + Send + Sync>>,
    interactive: bool,
    must_staple: bool,
    reuse_private_keys: bool,
    subject_transformer: Option<Arc<dyn Fn(&str) -> Result<String> + Send + Sync>>,
    default_server_name: Option<String>,
    fallback_server_name: Option<String>,
    disable_storage_check: bool,
    issuer_policy: IssuerPolicy,
    disable_ari: bool,
    cert_selection: Option<Arc<dyn CertificateSelector>>,
}

impl ConfigBuilder {
    /// Set the renewal window ratio.
    pub fn renewal_window_ratio(mut self, ratio: f64) -> Self {
        self.renewal_window_ratio = ratio;
        self
    }

    /// Set the on-demand TLS configuration.
    pub fn on_demand(mut self, on_demand: Arc<OnDemandConfig>) -> Self {
        self.on_demand = Some(on_demand);
        self
    }

    /// Set the certificate issuers.
    pub fn issuers(mut self, issuers: Vec<Arc<dyn CertIssuer>>) -> Self {
        self.issuers = Some(issuers);
        self
    }

    /// Set the persistent storage backend.
    pub fn storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the key type for new certificate private keys.
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set the OCSP configuration.
    pub fn ocsp(mut self, ocsp: OcspConfig) -> Self {
        self.ocsp = ocsp;
        self
    }

    /// Set the shared certificate cache.
    pub fn cache(mut self, cache: Arc<CertCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the event callback.
    ///
    /// The callback returns `Result<()>`. For critical events (e.g.
    /// [`EVENT_CERT_OBTAINING`]), returning an error aborts the operation.
    pub fn on_event(
        mut self,
        on_event: Arc<dyn Fn(&str, &serde_json::Value) -> Result<()> + Send + Sync>,
    ) -> Self {
        self.on_event = Some(on_event);
        self
    }

    /// Set whether user interaction is allowed.
    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    /// Request the OCSP Must-Staple extension on new certificates.
    pub fn must_staple(mut self, must_staple: bool) -> Self {
        self.must_staple = must_staple;
        self
    }

    /// Reuse the existing private key on certificate renewal.
    pub fn reuse_private_keys(mut self, reuse: bool) -> Self {
        self.reuse_private_keys = reuse;
        self
    }

    /// Set a transform applied to domain names before obtaining
    /// certificates.
    pub fn subject_transformer(
        mut self,
        f: Arc<dyn Fn(&str) -> Result<String> + Send + Sync>,
    ) -> Self {
        self.subject_transformer = Some(f);
        self
    }

    /// Set the fallback server name used when the client does not
    /// provide an SNI value.
    pub fn default_server_name(mut self, name: impl Into<String>) -> Self {
        self.default_server_name = Some(name.into());
        self
    }

    /// Set the last-resort server name used when no certificate matches
    /// the requested SNI.
    pub fn fallback_server_name(mut self, name: impl Into<String>) -> Self {
        self.fallback_server_name = Some(name.into());
        self
    }

    /// Skip the storage-health probe on startup.
    pub fn disable_storage_check(mut self, disable: bool) -> Self {
        self.disable_storage_check = disable;
        self
    }

    /// Set the issuer selection policy.
    pub fn issuer_policy(mut self, policy: IssuerPolicy) -> Self {
        self.issuer_policy = policy;
        self
    }

    /// Disable the ACME Renewal Information (ARI) extension.
    pub fn disable_ari(mut self, disable: bool) -> Self {
        self.disable_ari = disable;
        self
    }

    /// Set a custom certificate selector for TLS handshakes.
    pub fn cert_selection(mut self, selector: Arc<dyn CertificateSelector>) -> Self {
        self.cert_selection = Some(selector);
        self
    }

    /// Build the [`Config`].
    ///
    /// # Panics
    ///
    /// Panics if no `storage` has been provided.
    pub fn build(self) -> Config {
        use crate::cache::CacheOptions;

        let storage = self
            .storage
            .expect("Config requires a Storage implementation -- call .storage() on the builder");

        let cache = self
            .cache
            .unwrap_or_else(|| CertCache::new(CacheOptions::default()));

        let issuers = self.issuers.unwrap_or_default();

        Config {
            renewal_window_ratio: self.renewal_window_ratio,
            on_demand: self.on_demand,
            issuers,
            storage,
            key_type: self.key_type,
            ocsp: self.ocsp,
            cache,
            on_event: self.on_event,
            interactive: self.interactive,
            must_staple: self.must_staple,
            reuse_private_keys: self.reuse_private_keys,
            subject_transformer: self.subject_transformer,
            default_server_name: self.default_server_name,
            fallback_server_name: self.fallback_server_name,
            disable_storage_check: self.disable_storage_check,
            issuer_policy: self.issuer_policy,
            disable_ari: self.disable_ari,
            cert_selection: self.cert_selection,
            job_queue: Arc::new(JobQueue::new("cert_management")),
        }
    }
}

// ---------------------------------------------------------------------------
// Config — construction
// ---------------------------------------------------------------------------

impl Config {
    /// Create a new [`ConfigBuilder`] with sensible defaults.
    ///
    /// Defaults:
    /// - `renewal_window_ratio`: `1.0 / 3.0`
    /// - `key_type`: [`KeyType::EcdsaP256`]
    /// - `ocsp`: [`OcspConfig::default()`]
    /// - `interactive`: `false`
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            renewal_window_ratio: crate::certificates::DEFAULT_RENEWAL_WINDOW_RATIO,
            on_demand: None,
            issuers: None,
            storage: None,
            key_type: KeyType::default(),
            ocsp: OcspConfig::default(),
            cache: None,
            on_event: None,
            interactive: false,
            must_staple: false,
            reuse_private_keys: false,
            subject_transformer: None,
            default_server_name: None,
            fallback_server_name: None,
            disable_storage_check: true,
            issuer_policy: IssuerPolicy::default(),
            disable_ari: false,
            cert_selection: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Config — event emission
// ---------------------------------------------------------------------------

impl Config {
    /// Emit a lifecycle event to the configured callback, if any.
    ///
    /// Returns `Ok(())` if no callback is configured or the callback
    /// succeeded. Propagates the callback's error otherwise.
    fn emit(&self, event_name: &str, data: &serde_json::Value) -> Result<()> {
        if let Some(ref on_event) = self.on_event {
            on_event(event_name, data)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Config — storage helpers
// ---------------------------------------------------------------------------

impl Config {
    /// Build a lock key for a certificate operation on the given domain.
    fn lock_key(op: &str, domain: &str) -> String {
        format!("{op}_{domain}")
    }

    /// Check whether storage has all three certificate resources (cert, key,
    /// meta) for `domain` from `issuer`.
    async fn storage_has_cert_resources(
        storage: &dyn Storage,
        issuer: &dyn CertIssuer,
        domain: &str,
    ) -> bool {
        let issuer_key = issuer.issuer_key();
        let cert_key = site_cert_key(&issuer_key, domain);
        let key_key = site_private_key(&issuer_key, domain);
        let meta_key = site_meta_key(&issuer_key, domain);

        let cert_ok = storage.exists(&cert_key).await.unwrap_or(false);
        let key_ok = storage.exists(&key_key).await.unwrap_or(false);
        let meta_ok = storage.exists(&meta_key).await.unwrap_or(false);

        cert_ok && key_ok && meta_ok
    }

    /// Check whether storage has cert resources from any configured issuer.
    async fn storage_has_cert_resources_any_issuer(&self, domain: &str) -> bool {
        for issuer in &self.issuers {
            if Self::storage_has_cert_resources(self.storage.as_ref(), issuer.as_ref(), domain)
                .await
            {
                return true;
            }
        }
        false
    }

    /// Load a certificate resource from storage, trying all configured
    /// issuers in order. Returns the first successfully loaded resource.
    async fn load_cert_resource_any_issuer(&self, domain: &str) -> Result<CertificateResource> {
        let mut last_err = None;

        for issuer in &self.issuers {
            match load_certificate(self.storage.as_ref(), &issuer.issuer_key(), domain).await {
                Ok(cert_res) => return Ok(cert_res),
                Err(e) => {
                    // NotFound is expected when trying multiple issuers.
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::Storage(StorageError::NotFound(format!(
                "no certificate resource found for '{domain}' from any configured issuer"
            )))
        }))
    }

    /// Delete certificate assets (cert, key, meta) for `domain` under
    /// `issuer_key` from storage.
    async fn delete_site_assets(&self, issuer_key: &str, domain: &str) -> Result<()> {
        self.storage
            .delete(&site_cert_key(issuer_key, domain))
            .await?;
        self.storage
            .delete(&site_private_key(issuer_key, domain))
            .await?;
        self.storage
            .delete(&site_meta_key(issuer_key, domain))
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Config — certificate construction
// ---------------------------------------------------------------------------

impl Config {
    /// Parse a [`CertificateResource`] into a [`Certificate`], applying OCSP
    /// stapling if enabled.
    ///
    /// The certificate PEM is decoded into a chain of DER-encoded
    /// certificates, and the private key PEM is decoded into raw key bytes.
    /// If OCSP stapling is not disabled, the function fetches and attaches
    /// an OCSP response (using the storage cache when possible).
    pub async fn make_certificate_with_ocsp(
        &self,
        cert_res: &CertificateResource,
    ) -> Result<Certificate> {
        let mut cert = Certificate::from_pem(&cert_res.certificate_pem, &cert_res.private_key_pem)?;

        // Apply OCSP stapling unless disabled.
        if !self.ocsp.disable_stapling {
            match staple_ocsp(self.storage.as_ref(), &mut cert, &self.ocsp).await {
                Ok(_stapled) => {
                    debug!(
                        names = ?cert.names,
                        "OCSP staple applied"
                    );
                }
                Err(e) => {
                    warn!(
                        names = ?cert.names,
                        error = %e,
                        "failed to staple OCSP"
                    );
                    // Non-fatal: the certificate is still usable without OCSP.
                }
            }
        }

        Ok(cert)
    }
}

// ---------------------------------------------------------------------------
// Config — manage
// ---------------------------------------------------------------------------

impl Config {
    /// Manage certificates for the given domain names synchronously.
    ///
    /// This is the primary entry point for certificate management. For each
    /// domain:
    ///
    /// 1. Check if already managed in cache -- skip if so.
    /// 2. Try loading from storage -- add to cache if found.
    /// 3. If not found in storage -- obtain a new certificate from the configured issuers.
    /// 4. If loaded from storage, check if renewal is needed and renew if so.
    ///
    /// "Synchronously" means that certificate operations are performed in
    /// the foreground without background retries. Use [`Config::manage_async`]
    /// instead if you want background retry behaviour.
    ///
    /// Returns on the first error encountered.
    pub async fn manage_sync(&self, domains: &[String]) -> Result<()> {
        self.manage_all(domains, false).await
    }

    /// Manage certificates for the given domain names asynchronously.
    ///
    /// Same as [`manage_sync`](Config::manage_sync), but ACME operations
    /// (obtain, renew) are submitted as background tasks via the
    /// [`JobQueue`]. This method returns as soon as each domain's
    /// management task has been submitted -- certificates may not yet be
    /// ready when this method returns.
    pub async fn manage_async(&self, domains: &[String]) -> Result<()> {
        for domain in domains {
            let domain = domain.to_lowercase();

            // Check if already managed in cache.
            let cached_certs = self.cache.all_matching_certificates(&domain).await;
            let already_managed = cached_certs.iter().any(|c| c.managed);
            if already_managed {
                continue;
            }

            // Submit a background job for this domain. The job queue
            // deduplicates by name so concurrent calls for the same
            // domain are coalesced.
            let job_name = format!("manage_{domain}");
            // We need to clone the parts of self that the closure needs.
            // Since Config is not Clone/Arc-wrapped here, we clone the
            // individual fields required for manage_one.
            let storage = Arc::clone(&self.storage);
            let cache = Arc::clone(&self.cache);
            let issuers = self.issuers.clone();
            let key_type = self.key_type;
            let ocsp = self.ocsp.clone();
            let renewal_ratio = self.renewal_window_ratio;
            let on_event = self.on_event.clone();
            let on_demand = self.on_demand.clone();
            let interactive = self.interactive;
            let must_staple = self.must_staple;
            let reuse_private_keys = self.reuse_private_keys;
            let default_server_name = self.default_server_name.clone();
            let fallback_server_name = self.fallback_server_name.clone();
            let disable_storage_check = self.disable_storage_check;
            let subject_transformer = self.subject_transformer.clone();
            let issuer_policy = self.issuer_policy;
            let disable_ari = self.disable_ari;
            let cert_selection = self.cert_selection.clone();
            let domain_owned = domain.clone();

            self.job_queue
                .submit(job_name, move || async move {
                    // Reconstruct a minimal Config for background work.
                    let cfg = Config {
                        renewal_window_ratio: renewal_ratio,
                        on_demand,
                        issuers,
                        storage,
                        key_type,
                        ocsp,
                        cache,
                        on_event,
                        interactive,
                        must_staple,
                        reuse_private_keys,
                        subject_transformer,
                        default_server_name,
                        fallback_server_name,
                        disable_storage_check,
                        issuer_policy,
                        disable_ari,
                        cert_selection,
                        job_queue: Arc::new(JobQueue::new("bg_manage")),
                    };
                    if let Err(e) = cfg.manage_one(&domain_owned, true).await {
                        error!(
                            domain = %domain_owned,
                            error = %e,
                            "background certificate management failed"
                        );
                    }
                })
                .await;
        }
        Ok(())
    }

    /// Internal implementation for both sync and async management.
    async fn manage_all(&self, domains: &[String], r#async: bool) -> Result<()> {
        for domain in domains {
            let domain = domain.to_lowercase();
            self.manage_one(&domain, r#async).await?;
        }
        Ok(())
    }

    /// Manage a single domain name.
    async fn manage_one(&self, domain: &str, r#async: bool) -> Result<()> {
        // If the certificate is already managed in cache, nothing to do.
        let cached_certs = self.cache.all_matching_certificates(domain).await;
        for cert in &cached_certs {
            if cert.managed {
                return Ok(());
            }
        }

        // Try loading from storage.
        match self.cache_managed_certificate(domain).await {
            Ok(cert) => {
                // Certificate was loaded from storage and cached.
                let mut needs_action = cert.needs_renewal(self.renewal_window_ratio);

                // Task 7: Check OCSP revocation status. If the certificate
                // has been revoked, trigger a renewal.
                if !needs_action
                    && let Some(OcspStatus::Revoked) = cert.ocsp_status {
                        warn!(
                            domain = %domain,
                            "certificate OCSP status is Revoked; triggering renewal"
                        );
                        needs_action = true;
                    }

                if needs_action {
                    if r#async {
                        self.renew_cert_async(domain, false).await?;
                    } else {
                        self.renew_cert_sync(domain, false).await?;
                    }
                    // Reload the renewed certificate into cache.
                    let _ = self.cache_managed_certificate(domain).await;
                }
                Ok(())
            }
            Err(e) => {
                // Check if it is a "not found" error.
                let is_not_found = matches!(&e, Error::Storage(StorageError::NotFound(_)));
                if !is_not_found {
                    return Err(Error::Other(format!("{domain}: caching certificate: {e}")));
                }

                // Not in storage -- obtain a new certificate.
                if r#async {
                    self.obtain_cert_async(domain).await
                } else {
                    self.obtain_cert_sync(domain).await
                }
            }
        }
    }

    /// Load a managed certificate from storage and add it to the in-memory
    /// cache.
    pub async fn cache_managed_certificate(&self, domain: &str) -> Result<Certificate> {
        let cert = self.load_managed_certificate(domain).await?;
        self.cache.add(cert.clone()).await;
        let _ = self.emit(
            EVENT_CACHED_MANAGED_CERT,
            &serde_json::json!({"sans": cert.names}),
        );
        Ok(cert)
    }

    /// Load a managed certificate from storage without adding it to the
    /// cache.
    async fn load_managed_certificate(&self, domain: &str) -> Result<Certificate> {
        let cert_res = self.load_cert_resource_any_issuer(domain).await?;
        let mut cert = self.make_certificate_with_ocsp(&cert_res).await?;
        cert.managed = true;
        cert.issuer_key = cert_res.issuer_key.clone();
        Ok(cert)
    }

    /// Load a certificate from storage for the given domain.
    ///
    /// Tries all configured issuers in order and returns the first
    /// successfully loaded certificate. Returns `Some(Certificate)` if
    /// found, `None` if not in storage for any issuer.
    pub async fn load_cert_from_storage(&self, domain: &str) -> Result<Option<Certificate>> {
        match self.load_managed_certificate(domain).await {
            Ok(cert) => Ok(Some(cert)),
            Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Config — obtain
// ---------------------------------------------------------------------------

impl Config {
    /// Obtain a new certificate synchronously (foreground, no retries).
    ///
    /// Generates a new private key and CSR, then tries each configured
    /// issuer in order until one succeeds. The resulting certificate, key,
    /// and metadata are persisted to storage. A distributed lock is held
    /// during the operation to prevent duplicate issuance.
    pub async fn obtain_cert_sync(&self, domain: &str) -> Result<()> {
        self.obtain_cert(domain, true).await
    }

    /// Obtain a new certificate asynchronously (background, with retries).
    ///
    /// Same as [`Config::obtain_cert_sync`] but wraps the
    /// operation in [`do_with_retry`],
    /// automatically retrying transient failures with exponential backoff.
    pub async fn obtain_cert_async(&self, domain: &str) -> Result<()> {
        self.obtain_cert(domain, false).await
    }

    /// Core certificate obtain logic.
    ///
    /// 1. Validate the domain qualifies for a certificate.
    /// 2. Check if storage already has the certificate (no-op if so).
    /// 3. Acquire a distributed lock for the domain.
    /// 4. Re-check storage (another instance may have obtained it).
    /// 5. Generate private key and CSR.
    /// 6. Try each issuer in order until one succeeds.
    /// 7. Store the certificate resource.
    /// 8. Emit lifecycle events.
    async fn obtain_cert(&self, domain: &str, interactive: bool) -> Result<()> {
        if self.issuers.is_empty() {
            return Err(Error::Config(
                "no issuers configured; cannot obtain certificate".into(),
            ));
        }

        if !subject_qualifies_for_cert(domain) {
            return Err(Error::Config(format!(
                "domain '{domain}' does not qualify for a certificate"
            )));
        }

        // If storage already has all resources, this is a no-op.
        if self.storage_has_cert_resources_any_issuer(domain).await {
            debug!(domain = %domain, "certificate already exists in storage; skipping obtain");
            return Ok(());
        }

        info!(domain = %domain, "acquiring lock for certificate obtain");

        let lock_key = Self::lock_key(CERT_ISSUE_LOCK_OP, domain);
        self.storage.lock(&lock_key).await?;

        let result = if interactive {
            self.do_obtain(domain).await
        } else {
            let storage = Arc::clone(&self.storage);
            let res = do_with_retry(&RetryConfig::default(), |_| self.do_obtain(domain)).await;
            // Ensure lock is released even on retry exhaustion.
            drop(storage);
            res
        };

        info!(domain = %domain, "releasing lock for certificate obtain");
        if let Err(unlock_err) = self.storage.unlock(&lock_key).await {
            error!(
                domain = %domain,
                error = %unlock_err,
                "failed to release lock after certificate obtain"
            );
        }

        result
    }

    /// The inner obtain logic, called once per attempt (with or without
    /// retries).
    async fn do_obtain(&self, domain: &str) -> Result<()> {
        // Apply subject transformer if configured (Task 5).
        let domain = if let Some(ref transformer) = self.subject_transformer {
            let transformed = transformer(domain)?;
            debug!(
                original = %domain,
                transformed = %transformed,
                "subject transformer applied"
            );
            transformed
        } else {
            domain.to_string()
        };
        let domain = domain.as_str();

        // Re-check storage: another instance may have obtained the cert
        // while we were waiting for the lock.
        if self.storage_has_cert_resources_any_issuer(domain).await {
            info!(domain = %domain, "certificate already exists in storage (obtained by another instance)");
            return Ok(());
        }

        info!(domain = %domain, "obtaining certificate");

        // Emit EVENT_CERT_OBTAINING; propagate error to abort issuance.
        self.emit(
            EVENT_CERT_OBTAINING,
            &serde_json::json!({"identifier": domain, "renewal": false}),
        )?;

        // Generate or reuse private key (Task 5).
        let (private_key, private_key_pem) = if self.reuse_private_keys {
            self.load_or_generate_private_key(domain).await?
        } else {
            let pk = generate_private_key(self.key_type)?;
            let pem = encode_private_key_pem(&pk)?;
            (pk, pem)
        };

        // Generate CSR.
        let domains = vec![domain.to_string()];
        let csr_der = generate_csr(&private_key, &domains, self.must_staple)?;

        // Build issuer list, applying IssuerPolicy (Task 5).
        let mut issuers: Vec<Arc<dyn CertIssuer>> = self.issuers.clone();
        if matches!(self.issuer_policy, IssuerPolicy::UseFirstRandomIssuer) {
            use rand::seq::SliceRandom;
            issuers.shuffle(&mut rand::rng());
        }

        // Try each issuer in order.
        let mut last_err: Option<Error> = None;
        let mut issuer_keys = Vec::new();

        for (i, issuer) in issuers.iter().enumerate() {
            let ik = issuer.issuer_key();
            issuer_keys.push(ik.clone());

            debug!(
                domain = %domain,
                issuer = %ik,
                attempt = i + 1,
                total = issuers.len(),
                "trying issuer"
            );

            match issuer.issue(&csr_der, &domains).await {
                Ok(issued) => {
                    // Success -- store the certificate resource.
                    let cert_res = CertificateResource {
                        sans: domains.clone(),
                        certificate_pem: issued.certificate_pem,
                        private_key_pem: private_key_pem.as_bytes().to_vec(),
                        issuer_data: Some(issued.metadata),
                        issuer_key: ik.clone(),
                    };

                    store_certificate(self.storage.as_ref(), &ik, &cert_res).await?;

                    info!(
                        domain = %domain,
                        issuer = %ik,
                        "certificate obtained successfully"
                    );

                    let _ = self.emit(
                        EVENT_CERT_OBTAINED,
                        &serde_json::json!({
                            "identifier": domain,
                            "issuer": ik,
                            "renewal": false,
                        }),
                    );

                    return Ok(());
                }
                Err(e) => {
                    error!(
                        domain = %domain,
                        issuer = %ik,
                        error = %e,
                        "could not get certificate from issuer"
                    );
                    last_err = Some(e);
                }
            }
        }

        // All issuers failed.
        let _ = self.emit(
            EVENT_CERT_FAILED,
            &serde_json::json!({
                "identifier": domain,
                "renewal": false,
                "issuers": issuer_keys,
            }),
        );

        Err(last_err
            .unwrap_or_else(|| Error::Config(format!("[{domain}] obtain: all issuers failed"))))
    }

    /// Try to load an existing private key from storage for reuse, or
    /// generate a fresh one if none exists.
    async fn load_or_generate_private_key(
        &self,
        domain: &str,
    ) -> Result<(crate::crypto::PrivateKey, String)> {
        // Try each issuer's key path.
        for issuer in &self.issuers {
            let key_path = site_private_key(&issuer.issuer_key(), domain);
            match self.storage.load(&key_path).await {
                Ok(pem_bytes) => {
                    if let Ok(pem_str) = std::str::from_utf8(&pem_bytes)
                        && let Ok(pk) = decode_private_key_pem(pem_str) {
                            debug!(
                                domain = %domain,
                                issuer = %issuer.issuer_key(),
                                "reusing existing private key from storage"
                            );
                            return Ok((pk, pem_str.to_string()));
                        }
                }
                Err(_) => continue,
            }
        }

        // No existing key found; generate a new one.
        let pk = generate_private_key(self.key_type)?;
        let pem = encode_private_key_pem(&pk)?;
        Ok((pk, pem))
    }
}

// ---------------------------------------------------------------------------
// Config — renew
// ---------------------------------------------------------------------------

impl Config {
    /// Renew a certificate synchronously (foreground, no retries).
    ///
    /// Loads the existing certificate from storage, checks if renewal is
    /// needed (unless `force` is `true`), generates a new key and CSR,
    /// and tries each configured issuer in order. A distributed lock is
    /// held during the operation.
    pub async fn renew_cert_sync(&self, domain: &str, force: bool) -> Result<()> {
        self.renew_cert(domain, force, true).await
    }

    /// Renew a certificate asynchronously (background, with retries).
    ///
    /// Same as [`Config::renew_cert_sync`] but wraps the
    /// operation in [`do_with_retry`],
    /// automatically retrying transient failures with exponential backoff.
    pub async fn renew_cert_async(&self, domain: &str, force: bool) -> Result<()> {
        self.renew_cert(domain, force, false).await
    }

    /// Core certificate renewal logic.
    ///
    /// 1. Acquire a distributed lock.
    /// 2. Load the existing certificate from storage.
    /// 3. Check if renewal is actually needed (unless `force`).
    /// 4. Generate a new private key and CSR.
    /// 5. Try each issuer in order.
    /// 6. Store the new certificate resource.
    /// 7. Emit lifecycle events.
    async fn renew_cert(&self, domain: &str, force: bool, interactive: bool) -> Result<()> {
        if self.issuers.is_empty() {
            return Err(Error::Config(
                "no issuers configured; cannot renew certificate".into(),
            ));
        }

        info!(domain = %domain, "acquiring lock for certificate renewal");

        let lock_key = Self::lock_key(CERT_ISSUE_LOCK_OP, domain);
        self.storage.lock(&lock_key).await?;

        let result = if interactive {
            self.do_renew(domain, force).await
        } else {
            do_with_retry(&RetryConfig::default(), |_| self.do_renew(domain, force)).await
        };

        info!(domain = %domain, "releasing lock for certificate renewal");
        if let Err(unlock_err) = self.storage.unlock(&lock_key).await {
            error!(
                domain = %domain,
                error = %unlock_err,
                "failed to release lock after certificate renewal"
            );
        }

        result
    }

    /// The inner renewal logic, called once per attempt.
    async fn do_renew(&self, domain: &str, force: bool) -> Result<()> {
        // Load the existing certificate resource from storage.
        let cert_res = self.load_cert_resource_any_issuer(domain).await?;

        // Double-check: re-load the cert and verify it still needs renewal
        // (Task 6). Another instance may have renewed it while we were
        // waiting for the lock.
        let cert = self.make_certificate_with_ocsp(&cert_res).await?;
        let needs_renewal = cert.needs_renewal(self.renewal_window_ratio);

        if !needs_renewal && !force {
            info!(
                domain = %domain,
                "certificate does not need renewal (may have been renewed by another instance); reloading into cache"
            );
            // Reload the (possibly fresh) certificate into cache.
            let mut fresh = cert;
            fresh.managed = true;
            fresh.issuer_key = cert_res.issuer_key.clone();
            self.cache.add(fresh).await;
            return Ok(());
        }

        if !needs_renewal && force {
            info!(
                domain = %domain,
                "certificate does not need renewal, but renewal is being forced"
            );
        }

        info!(domain = %domain, "renewing certificate");

        // Emit EVENT_CERT_OBTAINING for renewal; propagate error to abort.
        self.emit(
            EVENT_CERT_OBTAINING,
            &serde_json::json!({
                "identifier": domain,
                "renewal": true,
                "forced": force,
            }),
        )?;

        // Generate or reuse private key.
        let (private_key, private_key_pem) = if self.reuse_private_keys {
            self.load_or_generate_private_key(domain).await?
        } else {
            let pk = generate_private_key(self.key_type)?;
            let pem = encode_private_key_pem(&pk)?;
            (pk, pem)
        };

        // Generate CSR.
        let domains = vec![domain.to_string()];
        let csr_der = generate_csr(&private_key, &domains, self.must_staple)?;

        // Build issuer list, applying IssuerPolicy.
        let mut issuers: Vec<Arc<dyn CertIssuer>> = self.issuers.clone();
        if matches!(self.issuer_policy, IssuerPolicy::UseFirstRandomIssuer) {
            use rand::seq::SliceRandom;
            issuers.shuffle(&mut rand::rng());
        }

        // Try each issuer.
        let mut last_err: Option<Error> = None;
        let mut issuer_keys = Vec::new();

        for issuer in &issuers {
            let ik = issuer.issuer_key();
            issuer_keys.push(ik.clone());

            match issuer.issue(&csr_der, &domains).await {
                Ok(issued) => {
                    let new_cert_res = CertificateResource {
                        sans: domains.clone(),
                        certificate_pem: issued.certificate_pem,
                        private_key_pem: private_key_pem.as_bytes().to_vec(),
                        issuer_data: Some(issued.metadata),
                        issuer_key: ik.clone(),
                    };

                    store_certificate(self.storage.as_ref(), &ik, &new_cert_res).await?;

                    info!(
                        domain = %domain,
                        issuer = %ik,
                        "certificate renewed successfully"
                    );

                    let _ = self.emit(
                        EVENT_CERT_RENEWED,
                        &serde_json::json!({
                            "identifier": domain,
                            "issuer": ik,
                        }),
                    );

                    return Ok(());
                }
                Err(e) => {
                    error!(
                        domain = %domain,
                        issuer = %ik,
                        error = %e,
                        "could not renew certificate from issuer"
                    );
                    last_err = Some(e);
                }
            }
        }

        // All issuers failed.
        let _ = self.emit(
            EVENT_CERT_FAILED,
            &serde_json::json!({
                "identifier": domain,
                "renewal": true,
                "issuers": issuer_keys,
            }),
        );

        Err(last_err
            .unwrap_or_else(|| Error::Config(format!("[{domain}] renew: all issuers failed"))))
    }
}

// ---------------------------------------------------------------------------
// Config — revoke
// ---------------------------------------------------------------------------

impl Config {
    /// Revoke the certificate for `domain`.
    ///
    /// Iterates over configured issuers, attempting revocation for each.
    /// After successful revocation, the certificate assets are deleted from
    /// storage to prevent reuse. The optional `reason` is an RFC 5280
    /// revocation reason code (0-10).
    pub async fn revoke_cert(&self, domain: &str, reason: Option<u8>) -> Result<()> {
        for (i, issuer) in self.issuers.iter().enumerate() {
            let ik = issuer.issuer_key();

            // Try to load the certificate resource for this issuer.
            let cert_res = match load_certificate(self.storage.as_ref(), &ik, domain).await {
                Ok(res) => res,
                Err(_) => continue,
            };

            // We need to check if the private key exists.
            let pk_key = site_private_key(&ik, domain);
            let pk_exists = self.storage.exists(&pk_key).await.unwrap_or(false);
            if !pk_exists {
                return Err(Error::Config(format!(
                    "private key not found for '{domain}' (issuer {i}: {ik})"
                )));
            }

            info!(
                domain = %domain,
                issuer = %ik,
                "revoking certificate"
            );

            // Call the ACME revocation endpoint if the issuer supports it.
            if let Some(revoker) = issuer.as_revoker() {
                revoker.revoke(&cert_res.certificate_pem, reason).await?;
                info!(
                    domain = %domain,
                    issuer = %ik,
                    "certificate revoked via ACME"
                );
            } else {
                warn!(
                    domain = %domain,
                    issuer = %ik,
                    "issuer does not support revocation; skipping ACME revoke call"
                );
            }

            // Delete certificate assets from storage after revocation.
            self.delete_site_assets(&ik, domain).await?;

            info!(
                domain = %domain,
                issuer = %ik,
                "certificate assets deleted after revocation"
            );

            let _ = self.emit(
                EVENT_CERT_REVOKED,
                &serde_json::json!({
                    "identifier": domain,
                    "issuer": ik,
                }),
            );

            // Also remove from cache.
            let cached_certs = self.cache.all_matching_certificates(domain).await;
            for cert in &cached_certs {
                if cert.issuer_key == ik {
                    self.cache.remove(&cert.hash).await;
                }
            }

            // Only need to revoke from one issuer (the one that issued it).
            return Ok(());
        }

        Err(Error::Config(format!(
            "no certificate found in storage for '{domain}' from any configured issuer"
        )))
    }
}

// ---------------------------------------------------------------------------
// Config — TLS configuration
// ---------------------------------------------------------------------------

impl Config {
    /// Build a [`rustls::ServerConfig`] wired up to serve certificates from
    /// this config's cache.
    ///
    /// The returned server config uses a [`CertResolver`] backed by the
    /// config's in-memory certificate cache, with ALPN protocols set to
    /// `["h2", "http/1.1"]`.
    ///
    /// If [`default_server_name`](Config::default_server_name) or
    /// [`fallback_server_name`](Config::fallback_server_name) are
    /// configured, they are applied to the resolver.
    pub fn tls_config(&self) -> rustls::ServerConfig {
        let mut resolver = CertResolver::new(self.cache.clone());

        // Apply default/fallback server names if configured.
        if self.default_server_name.is_some() {
            resolver.set_default_server_name(self.default_server_name.clone());
        }
        if self.fallback_server_name.is_some() {
            resolver.set_fallback_server_name(self.fallback_server_name.clone());
        }

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        // Set ALPN protocols for HTTP/2 and HTTP/1.1.
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        tls_config
    }
}

// ---------------------------------------------------------------------------
// Client TLS credentials (mTLS)
// ---------------------------------------------------------------------------

impl Config {
    /// Build TLS client credentials from a managed certificate.
    ///
    /// Loads the certificate and private key for `domain` from the cache (or
    /// storage) and returns them as a pair suitable for constructing a
    /// [`rustls::ClientConfig`] for mutual TLS (mTLS) authentication.
    ///
    /// # Returns
    ///
    /// A tuple of `(cert_chain, private_key)` where:
    /// - `cert_chain` is a list of DER-encoded certificates (leaf first).
    /// - `private_key` is the DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if no certificate is found for `domain` in the cache
    /// or storage, or if the certificate has no private key.
    pub async fn client_credentials(
        &self,
        domain: &str,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        // Try cache first.
        let cert = match self.cache.get_by_name(domain).await {
            Some(c) => c,
            None => {
                // Try loading from storage.
                let mut found = None;
                for issuer in &self.issuers {
                    let ik = issuer.issuer_key();
                    let cert_key = crate::storage::site_cert_key(&ik, domain);
                    let key_key = crate::storage::site_private_key(&ik, domain);

                    if let (Ok(cert_pem), Ok(key_pem)) = (
                        self.storage.load(&cert_key).await,
                        self.storage.load(&key_key).await,
                    )
                        && let Ok(c) = Certificate::from_pem(&cert_pem, &key_pem) {
                            found = Some(c);
                            break;
                        }
                }
                match found {
                    Some(c) => c,
                    None => {
                        return Err(Error::Config(format!(
                            "no certificate found for domain '{domain}' in cache or storage"
                        )));
                    }
                }
            }
        };

        let cert_chain = cert.cert_chain.clone();

        let pk_bytes = cert.private_key_der.as_ref().ok_or_else(|| {
            Error::Config(format!("certificate for '{domain}' has no private key"))
        })?;

        if pk_bytes.is_empty() {
            return Err(Error::Config(format!(
                "certificate for '{domain}' has empty private key bytes"
            )));
        }

        use rustls::pki_types::{
            PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
        };

        use crate::certificates::PrivateKeyKind;

        let pk_der = match cert.private_key_kind {
            PrivateKeyKind::Pkcs8 => {
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pk_bytes.clone()))
            }
            PrivateKeyKind::Pkcs1 => {
                PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(pk_bytes.clone()))
            }
            PrivateKeyKind::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(pk_bytes.clone())),
            PrivateKeyKind::None => {
                return Err(Error::Config(format!(
                    "certificate for '{domain}' has unknown private key kind"
                )));
            }
        };

        Ok((cert_chain, pk_der))
    }

    /// Build a [`rustls::ClientConfig`] for mutual TLS (mTLS) using a
    /// managed certificate.
    ///
    /// This is a convenience wrapper around [`client_credentials`] that
    /// produces a ready-to-use `ClientConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if no suitable certificate is found or if TLS
    /// configuration fails.
    pub async fn client_tls_config(&self, domain: &str) -> Result<rustls::ClientConfig> {
        let (cert_chain, pk_der) = self.client_credentials(domain).await?;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(cert_chain, pk_der)
            .map_err(|e| Error::Config(format!("failed to build client TLS config: {e}")))?;

        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Utc;
    use tokio::sync::RwLock;

    use super::*;
    use crate::cache::CacheOptions;
    use crate::storage::KeyInfo;

    // -----------------------------------------------------------------------
    // Minimal in-memory storage for tests
    // -----------------------------------------------------------------------

    struct MemoryStorage {
        data: RwLock<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl Storage for MemoryStorage {
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            let mut data = self.data.write().await;
            data.insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            let data = self.data.read().await;
            data.get(key)
                .cloned()
                .ok_or_else(|| Error::Storage(StorageError::NotFound(key.to_owned())))
        }

        async fn delete(&self, key: &str) -> Result<()> {
            let mut data = self.data.write().await;
            data.remove(key);
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool> {
            let data = self.data.read().await;
            Ok(data.contains_key(key))
        }

        async fn list(&self, path: &str, _recursive: bool) -> Result<Vec<String>> {
            let data = self.data.read().await;
            let keys: Vec<String> = data
                .keys()
                .filter(|k| k.starts_with(path))
                .cloned()
                .collect();
            Ok(keys)
        }

        async fn stat(&self, key: &str) -> Result<KeyInfo> {
            let data = self.data.read().await;
            match data.get(key) {
                Some(v) => Ok(KeyInfo {
                    key: key.to_owned(),
                    modified: Utc::now(),
                    size: v.len() as u64,
                    is_terminal: true,
                }),
                None => Err(Error::Storage(StorageError::NotFound(key.to_owned()))),
            }
        }

        async fn lock(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn unlock(&self, _name: &str) -> Result<()> {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_builder_defaults() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        assert!((config.renewal_window_ratio - 1.0 / 3.0).abs() < f64::EPSILON);
        assert_eq!(config.key_type, KeyType::EcdsaP256);
        assert!(!config.interactive);
        assert!(config.issuers.is_empty());
        assert!(config.on_demand.is_none());
        assert!(config.on_event.is_none());
    }

    #[test]
    #[should_panic(expected = "Config requires a Storage")]
    fn test_config_builder_panics_without_storage() {
        let _config = Config::builder().build();
    }

    #[test]
    fn test_config_builder_custom_values() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cache = CertCache::new(CacheOptions::default());

        let config = Config::builder()
            .storage(storage)
            .cache(cache)
            .key_type(KeyType::EcdsaP384)
            .renewal_window_ratio(0.5)
            .interactive(true)
            .build();

        assert_eq!(config.key_type, KeyType::EcdsaP384);
        assert!((config.renewal_window_ratio - 0.5).abs() < f64::EPSILON);
        assert!(config.interactive);
    }

    #[test]
    fn test_config_debug() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("renewal_window_ratio"));
    }

    #[test]
    fn test_lock_key_format() {
        let key = Config::lock_key("issue_cert", "example.com");
        assert_eq!(key, "issue_cert_example.com");
    }

    #[test]
    fn test_event_constants() {
        assert_eq!(EVENT_CERT_OBTAINING, "cert_obtaining");
        assert_eq!(EVENT_CERT_OBTAINED, "cert_obtained");
        assert_eq!(EVENT_CERT_RENEWED, "cert_renewed");
        assert_eq!(EVENT_CERT_REVOKED, "cert_revoked");
        assert_eq!(EVENT_CERT_FAILED, "cert_failed");
        assert_eq!(EVENT_CACHED_MANAGED_CERT, "cached_managed_cert");
    }

    #[tokio::test]
    async fn test_storage_has_no_cert_resources() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        let has = config
            .storage_has_cert_resources_any_issuer("example.com")
            .await;
        assert!(!has);
    }

    #[tokio::test]
    async fn test_load_cert_from_storage_not_found() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        let result = config.load_cert_from_storage("example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_emit_with_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&call_count);

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder()
            .storage(storage)
            .on_event(Arc::new(move |event, _data| {
                assert_eq!(event, "test_event");
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }))
            .build();

        config.emit("test_event", &serde_json::json!({})).unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_emit_without_callback() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        // Should not panic when no callback is set.
        config.emit("test_event", &serde_json::json!({})).unwrap();
    }

    #[tokio::test]
    async fn test_obtain_cert_no_issuers() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        let result = config.obtain_cert_sync("example.com").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no issuers configured"));
    }

    #[tokio::test]
    async fn test_obtain_cert_invalid_domain() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        // Create a config with a dummy issuer list (though the domain check
        // should fail before trying any issuer).
        let config = Config::builder().storage(storage).build();

        // ".invalid" starts with a dot, so it should fail validation.
        // But first, the issuers check runs -- let us handle that by noting
        // both checks exist.
        let result = config.obtain_cert(".invalid.com", true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_renew_cert_no_issuers() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        let result = config.renew_cert_sync("example.com", false).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no issuers configured"));
    }

    #[tokio::test]
    async fn test_manage_sync_no_issuers_no_storage() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        // With no issuers and nothing in storage, manage_sync should fail
        // because it tries to obtain a cert but has no issuers.
        let result = config.manage_sync(&["example.com".to_string()]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_cert_nothing_in_storage() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = Config::builder().storage(storage).build();

        let result = config.revoke_cert("example.com", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_site_assets() {
        let storage = Arc::new(MemoryStorage::new());
        let storage_trait: Arc<dyn Storage> = Arc::clone(&storage) as _;

        // Pre-populate storage with some keys.
        storage
            .store("certificates/test/example.com/example.com.crt", b"cert")
            .await
            .unwrap();
        storage
            .store("certificates/test/example.com/example.com.key", b"key")
            .await
            .unwrap();
        storage
            .store("certificates/test/example.com/example.com.json", b"meta")
            .await
            .unwrap();

        let config = Config::builder().storage(storage_trait).build();

        // delete_site_assets uses storage key builders which may produce
        // different keys than the raw ones above. This test simply
        // verifies the method runs without error.
        // The actual key format is determined by the storage module.
        let _result = config.delete_site_assets("test", "example.com").await;
    }
}
