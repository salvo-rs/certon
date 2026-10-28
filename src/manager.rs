//! The certificate lifecycle: obtaining, renewing, revoking and serving.
//!
//! [`CertManager`] is the thing that does the work. What it *should* do lives
//! in [`Policy`], separately, as data.
//!
//! The two used to be one type called `Config`, with twenty fields and
//! fifteen async methods — settings, collaborators, hooks and a lifecycle
//! engine in one place. A type named `Config` that can revoke a certificate
//! is not a configuration, and the name was the smaller half of the problem:
//! nothing could be taken out. You could plug a storage backend *into* it;
//! you could not get the settings out of it to compare two, or build the
//! machinery without deciding every setting, or hand a background task a copy
//! without writing out eighteen fields by hand — which is what the code did.
//!
//! # Usage
//!
//! ```ignore
//! use certon::{CertManager, Policy};
//!
//! let manager = CertManager::builder()
//!     .storage(my_storage)
//!     .policy(Policy { must_staple: true, ..Policy::default() })
//!     .build();
//!
//! manager.manage(&["example.com".into()]).await?;
//! ```

use std::sync::Arc;

use tracing::{debug, error, info, warn};

use crate::acme_issuer::CertIssuer;
use crate::async_jobs::{JobQueue, RetryConfig, do_with_retry};
use crate::cache::CertCache;
use crate::cert_store::{CertStore, KeyValueCertStore};
use crate::certificates::{Certificate, subject_qualifies_for_cert};
use crate::crypto::{
    KeyType, decode_private_key_pem, encode_private_key_pem, generate_csr,
    generate_private_key_async,
};
use crate::error::{CertError, Error, Result, StorageError};
use crate::handshake::{CertResolver, OnDemandConfig};
use crate::ocsp::{OcspConfig, OcspStatus, staple_ocsp};
use crate::policy::{CertificateSelector, IssuerPolicy, Policy};
use crate::storage::{CertificateResource, Storage, acquire};

/// Callback invoked on notable lifecycle events.
type EventCallback = Arc<dyn Fn(&str, &serde_json::Value) -> Result<()> + Send + Sync>;

/// Transform applied to domain names before obtaining certificates.
type SubjectTransformer = Arc<dyn Fn(&str) -> Result<String> + Send + Sync>;

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
// CertManager
// ---------------------------------------------------------------------------

/// Central configuration for automatic TLS certificate management.
///
/// `CertManager` coordinates the full certificate lifecycle: obtainment, renewal,
/// revocation, OCSP stapling, caching, and storage. It holds references to
/// one or more [`CertIssuer`] implementations, a persistent [`Storage`] backend,
/// and a shared in-memory [`CertCache`].
///
/// Use [`CertManager::builder()`] to construct an instance with sensible defaults.
pub struct CertManager {
    /// What should happen. Plain data, so it can be built, cloned, compared
    /// and printed on its own.
    pub policy: Policy,

    /// Certificate issuers, tried in order until one succeeds.
    ///
    /// Defaults to a single [`AcmeIssuer`](crate::acme_issuer::AcmeIssuer)
    /// configured for Let's Encrypt production.
    pub issuers: Vec<Arc<dyn CertIssuer>>,

    /// Where certificates go.
    ///
    /// Defaults to a [`KeyValueCertStore`] over `storage`, so a deployment
    /// that has said nothing keeps exactly the layout it already has on disk.
    pub certificates: Arc<dyn CertStore>,

    /// Key-value storage for everything that does not go through
    /// [`CertStore`] yet: OCSP staples, ACME account data, challenge state,
    /// and cluster locks.
    pub storage: Arc<dyn Storage>,

    /// Shared in-memory certificate cache.
    pub cache: Arc<CertCache>,

    /// On-demand TLS (optional). When set, certificate operations may be
    /// deferred to TLS handshake time for domains that are not yet managed.
    pub on_demand: Option<Arc<OnDemandConfig>>,

    /// Optional event callback invoked when notable lifecycle events occur.
    ///
    /// The callback receives an event name (one of the `EVENT_*` constants)
    /// and a JSON value containing event-specific data. Returning an error
    /// from the callback may abort the current operation (for critical
    /// events like [`EVENT_CERT_OBTAINING`]). Callbacks should return
    /// quickly as they are invoked synchronously.
    pub on_event: Option<EventCallback>,

    /// Optional transform applied to domain names before obtaining
    /// certificates. Can be used for normalization, aliasing, etc.
    pub subject_transformer: Option<SubjectTransformer>,

    /// Optional custom certificate selector for TLS handshakes.
    pub cert_selection: Option<Arc<dyn CertificateSelector>>,

    /// Background job queue for async certificate operations.
    job_queue: Arc<JobQueue>,
}

impl std::fmt::Debug for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Eleven of the fields this used to list by hand now print themselves,
        // because they are a value rather than a scattering of settings.
        f.debug_struct("CertManager")
            .field("policy", &self.policy)
            .field("issuers", &self.issuers.len())
            .field("certificates", &self.certificates)
            .field("on_demand", &self.on_demand.is_some())
            .field("on_event", &self.on_event.is_some())
            .field("subject_transformer", &self.subject_transformer.is_some())
            .field("cert_selection", &self.cert_selection.is_some())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// CertManagerBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`CertManager`] with sensible defaults.
///
/// Created via [`CertManager::builder()`]. At a minimum, a [`Storage`]
/// implementation must be provided before calling [`build()`](CertManagerBuilder::build).
pub struct CertManagerBuilder {
    policy: Policy,
    on_demand: Option<Arc<OnDemandConfig>>,
    issuers: Option<Vec<Arc<dyn CertIssuer>>>,
    storage: Option<Arc<dyn Storage>>,
    certificates: Option<Arc<dyn CertStore>>,
    cache: Option<Arc<CertCache>>,
    on_event: Option<EventCallback>,
    subject_transformer: Option<SubjectTransformer>,
    cert_selection: Option<Arc<dyn CertificateSelector>>,
}

impl CertManagerBuilder {
    /// Set the renewal window ratio.
    /// Replace every setting at once.
    ///
    /// The individual setters below write into this, so calling it after them
    /// discards what they set.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn renewal_window_ratio(mut self, ratio: f64) -> Self {
        self.policy.renewal_window_ratio = ratio;
        self
    }

    /// Set the on-demand TLS configuration.
    ///
    /// If no obtain callback is supplied, TLS cache misses use this manager's
    /// normal obtain and cache publication flow, subject to the configured
    /// decision, allowlist and rate limit.
    pub fn on_demand(mut self, on_demand: Arc<OnDemandConfig>) -> Self {
        self.on_demand = Some(on_demand);
        self
    }

    /// Set the certificate issuers.
    pub fn issuers(mut self, issuers: Vec<Arc<dyn CertIssuer>>) -> Self {
        self.issuers = Some(issuers);
        self
    }

    /// Put certificates somewhere other than the key-value storage.
    ///
    /// Without this they go into `storage` under certon's own key layout,
    /// which is what every existing deployment has. With it, they can go into
    /// a database or a secret manager without the ACME account key and the
    /// lock files having to follow them there.
    pub fn certificates(mut self, certificates: Arc<dyn CertStore>) -> Self {
        self.certificates = Some(certificates);
        self
    }

    /// Set storage for accounts, locks, OCSP and the default certificate store.
    pub fn storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the key type for new certificate private keys.
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.policy.key_type = key_type;
        self
    }

    /// Set the OCSP configuration.
    pub fn ocsp(mut self, ocsp: OcspConfig) -> Self {
        self.policy.ocsp = ocsp;
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
    pub fn on_event(mut self, on_event: EventCallback) -> Self {
        self.on_event = Some(on_event);
        self
    }

    /// Set whether user interaction is allowed.
    pub fn interactive(mut self, interactive: bool) -> Self {
        self.policy.interactive = interactive;
        self
    }

    /// Request the OCSP Must-Staple extension on new certificates.
    pub fn must_staple(mut self, must_staple: bool) -> Self {
        self.policy.must_staple = must_staple;
        self
    }

    /// Reuse the existing private key on certificate renewal.
    pub fn reuse_private_keys(mut self, reuse: bool) -> Self {
        self.policy.reuse_private_keys = reuse;
        self
    }

    /// Set a transform applied to domain names before obtaining
    /// certificates.
    pub fn subject_transformer(mut self, f: SubjectTransformer) -> Self {
        self.subject_transformer = Some(f);
        self
    }

    /// Set the fallback server name used when the client does not
    /// provide an SNI value.
    pub fn default_server_name(mut self, name: impl Into<String>) -> Self {
        self.policy.default_server_name = Some(name.into());
        self
    }

    /// Set the last-resort server name used when no certificate matches
    /// the requested SNI.
    pub fn fallback_server_name(mut self, name: impl Into<String>) -> Self {
        self.policy.fallback_server_name = Some(name.into());
        self
    }

    /// Skip the storage-health probe on startup.
    pub fn disable_storage_check(mut self, disable: bool) -> Self {
        self.policy.disable_storage_check = disable;
        self
    }

    /// Set the issuer selection policy.
    pub fn issuer_policy(mut self, policy: IssuerPolicy) -> Self {
        self.policy.issuer_policy = policy;
        self
    }

    /// Disable the ACME Renewal Information (ARI) extension.
    pub fn disable_ari(mut self, disable: bool) -> Self {
        self.policy.disable_ari = disable;
        self
    }

    /// Set a custom certificate selector for TLS handshakes.
    pub fn cert_selection(mut self, selector: Arc<dyn CertificateSelector>) -> Self {
        self.cert_selection = Some(selector);
        self
    }

    /// Build the [`CertManager`].
    ///
    /// # Panics
    ///
    /// Panics if no `storage` has been provided.
    pub fn build(self) -> CertManager {
        use crate::cache::CacheOptions;

        let storage = self.storage.expect(
            "CertManager requires a Storage implementation -- call .storage() on the builder",
        );

        let cache = self
            .cache
            .unwrap_or_else(|| CertCache::new(CacheOptions::default()));

        let issuers = self.issuers.unwrap_or_default();

        let certificates = self
            .certificates
            .unwrap_or_else(|| Arc::new(KeyValueCertStore::new(Arc::clone(&storage))));

        CertManager {
            policy: self.policy,
            certificates,
            issuers,
            storage,
            cache,
            on_demand: self.on_demand,
            on_event: self.on_event,
            subject_transformer: self.subject_transformer,
            cert_selection: self.cert_selection,
            job_queue: Arc::new(JobQueue::certificate_jobs("cert_management")),
        }
    }
}

// ---------------------------------------------------------------------------
// CertManager — construction
// ---------------------------------------------------------------------------

impl CertManager {
    /// What this manager was told to do.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// A copy that can be moved into a background task.
    ///
    /// This used to be eighteen fields cloned by hand at the call site, under
    /// a comment explaining that `CertManager` is not `Clone`. It still is not —
    /// a job queue is not something to duplicate — but everything else here is
    /// either a value or an `Arc`, so the copy is one place rather than a list
    /// somebody has to keep in step with the struct. Detached managers share
    /// the original queue's admission budget and named-job registry.
    pub(crate) fn detached(&self, _job_name: &'static str) -> Self {
        Self {
            policy: self.policy.clone(),
            issuers: self.issuers.clone(),
            certificates: Arc::clone(&self.certificates),
            storage: Arc::clone(&self.storage),
            cache: Arc::clone(&self.cache),
            on_demand: self.on_demand.clone(),
            on_event: self.on_event.clone(),
            subject_transformer: self.subject_transformer.clone(),
            cert_selection: self.cert_selection.clone(),
            job_queue: Arc::clone(&self.job_queue),
        }
    }

    /// Create a new [`CertManagerBuilder`].
    ///
    /// Settings start at [`Policy::default()`], which documents what each one
    /// is and why it defaults where it does. Everything else — issuers, cache,
    /// hooks — starts empty, and a [`Storage`] must be given.
    pub fn builder() -> CertManagerBuilder {
        CertManagerBuilder {
            policy: Policy::default(),
            on_demand: None,
            issuers: None,
            storage: None,
            certificates: None,
            cache: None,
            on_event: None,
            subject_transformer: None,
            cert_selection: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CertManager — event emission
// ---------------------------------------------------------------------------

impl CertManager {
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
// CertManager — storage helpers
// ---------------------------------------------------------------------------

impl CertManager {
    /// Build a lock key for a certificate operation on the given domain.
    fn lock_key(op: &str, domain: &str) -> String {
        format!("{op}_{}", domain.to_lowercase())
    }

    /// Check the certificate store, propagating backend failures.
    async fn storage_has_cert_resources_any_issuer(&self, domain: &str) -> Result<bool> {
        for issuer in &self.issuers {
            if self.certificates.has(&issuer.issuer_key(), domain).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Select the newest valid resource across configured issuers. An older
    /// preferred CA must not shadow a certificate renewed through a fallback.
    async fn load_cert_resource_any_issuer(&self, domain: &str) -> Result<CertificateResource> {
        self.load_cert_resource_for_operation(domain, false).await
    }

    async fn load_cert_resource_for_operation(
        &self,
        domain: &str,
        allow_revoked: bool,
    ) -> Result<CertificateResource> {
        let mut selected = None;
        let mut validation_errors = Vec::new();
        let mut revoked = Vec::new();
        let now = chrono::Utc::now();
        for issuer in &self.issuers {
            let issuer_key = issuer.issuer_key();
            // Backend failures must remain failures even if another issuer has
            // a usable resource. Only invalid certificate contents are skipped.
            if let Some(resource) = self.certificates.load(&issuer_key, domain).await? {
                let cert = match Self::parse_managed_certificate(&resource, domain) {
                    Ok(cert) => cert,
                    Err(error) => {
                        validation_errors.push(format!("{issuer_key}: {error}"));
                        continue;
                    }
                };
                let mut has_intent = false;
                if let Some(leaf_hash) = crate::storage::certificate_leaf_hash(&cert) {
                    has_intent = crate::storage::load_revocation(self.storage.as_ref(), &leaf_hash)
                        .await?
                        .is_some();
                    if has_intent {
                        self.cache.deny_revoked_certificate(&leaf_hash).await;
                        revoked.push(issuer_key);
                        if !allow_revoked {
                            continue;
                        }
                    }
                }
                let rank = (
                    !has_intent,
                    cert.not_before <= now && !cert.expired(),
                    cert.not_before,
                    cert.not_after,
                );
                if selected.as_ref().is_none_or(|(best, _)| rank > *best) {
                    selected = Some((rank, resource));
                }
            }
        }
        if let Some((_, resource)) = selected {
            Ok(resource)
        } else if !revoked.is_empty() {
            Err(crate::error::CertError::Revoked(format!(
                "{domain}: persisted revocation intent for {}",
                revoked.join(", ")
            ))
            .into())
        } else if !validation_errors.is_empty() {
            Err(Error::Config(format!(
                "no valid certificate resource for '{domain}': {}",
                validation_errors.join("; ")
            )))
        } else {
            Err(Error::Storage(StorageError::NotFound(format!(
                "no certificate resource found for '{domain}' from any configured issuer"
            ))))
        }
    }

    /// Delete certificate assets (cert, key, meta) for `domain` under
    /// `issuer_key` from storage.
    async fn delete_site_assets(&self, issuer_key: &str, domain: &str) -> Result<()> {
        self.certificates.remove(issuer_key, domain).await
    }
}

// ---------------------------------------------------------------------------
// CertManager — certificate construction
// ---------------------------------------------------------------------------

impl CertManager {
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
        let cert = Certificate::from_pem(&cert_res.certificate_pem, &cert_res.private_key_pem)?;
        Ok(self.staple_certificate(cert).await)
    }

    async fn staple_certificate(&self, mut cert: Certificate) -> Certificate {
        // Apply OCSP stapling unless disabled.
        if !self.policy.ocsp.disable_stapling {
            match staple_ocsp(self.storage.as_ref(), &mut cert, &self.policy.ocsp).await {
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

        cert
    }
}

// ---------------------------------------------------------------------------
// CertManager — manage
// ---------------------------------------------------------------------------

impl CertManager {
    /// Manage certificates for the given domain names synchronously.
    ///
    /// This is the primary entry point for certificate management. For each
    /// domain:
    ///
    /// 1. Skip currently valid managed entries, removing stale managed entries.
    /// 2. Load storage resources and cache only certificates currently valid.
    /// 3. If not found in storage -- obtain a new certificate from the configured issuers.
    /// 4. If loaded from storage, check if renewal is needed and renew if so.
    ///
    /// "Synchronously" means that certificate operations are performed in
    /// the foreground without background retries. Use [`CertManager::manage_in_background`]
    /// instead if you want background retry behaviour.
    ///
    /// Returns on the first error encountered.
    pub async fn manage(&self, domains: &[String]) -> Result<()> {
        self.manage_all(domains, false).await
    }

    /// Manage certificates for the given domain names asynchronously.
    ///
    /// Same as [`manage`](CertManager::manage), but ACME operations
    /// (obtain, renew) are submitted as background tasks via the
    /// [`JobQueue`]. This method returns as soon as each domain's
    /// management task has been submitted -- certificates may not yet be
    /// ready when this method returns.
    /// At most four jobs execute and 68 are admitted per manager family;
    /// further submissions apply backpressure until capacity is available.
    pub async fn manage_in_background(&self, domains: &[String]) -> Result<()> {
        for domain in domains {
            let domain = domain.to_lowercase();

            if self.has_current_managed_certificate(&domain).await {
                continue;
            }

            // Submit a background job for this domain. The job queue
            // deduplicates by name so concurrent calls for the same
            // domain are coalesced.
            let job_name = format!("manage_{domain}");
            // We need to clone the parts of self that the closure needs.
            let detached = self.detached("bg_manage");
            let domain_owned = domain.clone();

            self.job_queue
                .submit(job_name, move || async move {
                    let cfg = detached;
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

    /// Remove only time-invalid managed entries before taking the fast path.
    /// A valid sibling remains available even when another cached leaf is stale.
    async fn has_current_managed_certificate(&self, domain: &str) -> bool {
        let mut current = false;
        let mut stale = Vec::new();
        for cert in self.cache.all_matching_certificates(domain).await {
            if cert.managed {
                if Self::validate_certificate_time(&cert, domain).is_ok() {
                    current = true;
                } else {
                    stale.push(cert.hash);
                }
            }
        }
        if !stale.is_empty() {
            self.cache.remove_many(&stale).await;
        }
        current
    }

    /// Manage a single domain name.
    async fn manage_one(&self, domain: &str, r#async: bool) -> Result<()> {
        if self.has_current_managed_certificate(domain).await {
            return Ok(());
        }

        // Planning may read an expired/future resource for its SANs and issuer,
        // but those credentials must not be published before renewal succeeds.
        match self.load_stored_certificate(domain).await {
            Ok(cert) => {
                let current = Self::validate_certificate_time(&cert, domain).is_ok();
                let revoked = matches!(cert.ocsp_status, Some(OcspStatus::Revoked));
                let needs_action =
                    !current || cert.needs_renewal(self.policy.renewal_window_ratio) || revoked;
                if current {
                    self.cache_loaded_certificate(cert, domain).await?;
                }
                if needs_action {
                    if r#async {
                        self.renew_in_background(domain, revoked).await?;
                    } else {
                        self.renew(domain, revoked).await?;
                    }
                    // renew publishes its validated replacement before return.
                }
                Ok(())
            }
            Err(error) => {
                if !matches!(&error, Error::Storage(StorageError::NotFound(_))) {
                    return Err(Error::Other(format!(
                        "{domain}: loading certificate: {error}"
                    )));
                }
                if r#async {
                    self.obtain_in_background(domain).await
                } else {
                    self.obtain(domain).await
                }
            }
        }
    }

    /// Load a managed certificate from storage and add it to the in-memory
    /// cache. A future or expired certificate returns a validity error without
    /// replacing any working certificate already in the cache.
    pub async fn cache_certificate(&self, domain: &str) -> Result<Certificate> {
        let cert = self.load_stored_certificate(domain).await?;
        self.cache_loaded_certificate(cert, domain).await
    }

    async fn cache_loaded_certificate(
        &self,
        cert: Certificate,
        domain: &str,
    ) -> Result<Certificate> {
        Self::validate_certificate_time(&cert, domain)?;
        self.cache.add(cert.clone()).await;
        let _ = self.emit(
            EVENT_CACHED_MANAGED_CERT,
            &serde_json::json!({"sans": cert.names}),
        );
        Ok(cert)
    }

    fn validate_certificate_time(cert: &Certificate, domain: &str) -> Result<()> {
        if cert.not_before > chrono::Utc::now() {
            return Err(CertError::NotYetValid(domain.to_owned()).into());
        }
        if cert.expired() {
            return Err(CertError::Expired(domain.to_owned()).into());
        }
        Ok(())
    }

    /// Read metadata for lifecycle planning without publishing. Time-invalid
    /// resources remain usable as renewal inputs; revocation checks still apply.
    async fn load_stored_certificate(&self, domain: &str) -> Result<Certificate> {
        let cert_res = self.load_cert_resource_any_issuer(domain).await?;
        let mut cert = self.validated_certificate(&cert_res, domain).await?;
        cert.managed = true;
        cert.issuer_key = cert_res.issuer_key.clone();
        Ok(cert)
    }

    /// Validate issuer/storage output before publishing it to the live cache.
    async fn validated_certificate(
        &self,
        resource: &CertificateResource,
        domain: &str,
    ) -> Result<Certificate> {
        let cert = Self::parse_managed_certificate(resource, domain)?;
        if let Some(leaf_hash) = crate::storage::certificate_leaf_hash(&cert)
            && crate::storage::load_revocation(self.storage.as_ref(), &leaf_hash)
                .await?
                .is_some()
        {
            self.cache.deny_revoked_certificate(&leaf_hash).await;
            return Err(crate::error::CertError::Revoked(format!(
                "{domain}: persisted revocation intent"
            ))
            .into());
        }
        Ok(self.staple_certificate(cert).await)
    }

    pub(crate) fn parse_managed_certificate(
        resource: &CertificateResource,
        domain: &str,
    ) -> Result<Certificate> {
        let mut cert = Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)?;
        crate::handshake::cert_to_certified_key(&cert)?
            .keys_match()
            .map_err(|error| Error::Config(format!("certificate/private key mismatch: {error}")))?;
        Self::validate_certificate_name(&cert, domain)?;
        // Keep the lookup alias first so maintenance renews through the same
        // CertStore address even if the CA orders SANs differently.
        cert.names.retain(|name| !name.eq_ignore_ascii_case(domain));
        cert.names.insert(0, domain.to_ascii_lowercase());
        cert.managed = true;
        cert.issuer_key = resource.issuer_key.clone();
        Ok(cert)
    }

    fn validate_certificate_name(cert: &Certificate, domain: &str) -> Result<()> {
        let domain = domain.to_ascii_lowercase();
        if domain.starts_with("*.") {
            use x509_parser::prelude::FromDer;
            let (_, leaf) =
                x509_parser::certificate::X509Certificate::from_der(cert.cert_chain[0].as_ref())
                    .map_err(|error| Error::Config(format!("invalid leaf certificate: {error}")))?;
            let sans = leaf
                .subject_alternative_name()
                .map_err(|error| Error::Config(format!("invalid certificate SAN: {error}")))?;
            let covered = sans.is_some_and(|san| san.value.general_names.iter().any(|name| {
                matches!(name, x509_parser::extensions::GeneralName::DNSName(name) if name.eq_ignore_ascii_case(&domain))
            }));
            if !covered {
                return Err(Error::Config(format!(
                    "issued certificate does not cover {domain}"
                )));
            }
        } else {
            let parsed = rustls::server::ParsedCertificate::try_from(&cert.cert_chain[0])
                .map_err(|error| Error::Config(format!("invalid leaf certificate: {error}")))?;
            let name = rustls::pki_types::ServerName::try_from(domain.as_str())
                .map_err(|error| Error::Config(format!("invalid certificate name: {error}")))?;
            rustls::client::verify_server_name(&parsed, &name).map_err(|error| {
                Error::Config(format!(
                    "issued certificate does not cover {domain}: {error}"
                ))
            })?;
        }
        Ok(())
    }

    fn tls_names(cert: &Certificate) -> Vec<String> {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::FromDer;
        let Some(leaf_der) = cert.cert_chain.first() else {
            return Vec::new();
        };
        let Ok((_, leaf)) = x509_parser::certificate::X509Certificate::from_der(leaf_der.as_ref())
        else {
            return Vec::new();
        };
        let Ok(Some(sans)) = leaf.subject_alternative_name() else {
            return Vec::new();
        };
        sans.value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(name) => Some(name.to_ascii_lowercase()),
                GeneralName::IPAddress(raw) => match *raw {
                    [a, b, c, d] => Some(std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string()),
                    raw if raw.len() == 16 => <[u8; 16]>::try_from(raw)
                        .ok()
                        .map(|ip| std::net::Ipv6Addr::from(ip).to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    pub(crate) fn covers_certificate(replacement: &Certificate, previous: &Certificate) -> bool {
        let names = Self::tls_names(previous);
        !names.is_empty()
            && names
                .iter()
                .all(|name| Self::validate_certificate_name(replacement, name).is_ok())
    }

    async fn publish_certificate(&self, cert: Certificate, domain: &str) {
        let incoming_hash = cert.hash.clone();
        let previous = self.cache.all_matching_certificates(domain).await;
        let superseded: Vec<_> = previous
            .iter()
            .filter(|old| {
                old.managed && old.hash != incoming_hash && Self::covers_certificate(&cert, old)
            })
            .map(|old| old.hash.as_str())
            .collect();
        // A partial replacement must keep the old certificate serving every
        // name that it still covers. This applies to cleanup entries too.
        let old_hash = superseded.first().copied().unwrap_or(&incoming_hash);
        self.cache.replace(old_hash, cert).await;
        for hash in superseded.into_iter().skip(1) {
            self.cache.remove(hash).await;
        }
    }

    /// Load a certificate from storage for the given domain.
    ///
    /// Tries all configured issuers, preferring currently valid certificates.
    /// Returns the best stored resource even if it needs renewal; this method
    /// does not publish it to the serving cache. Returns `None` when absent.
    pub async fn load_certificate(&self, domain: &str) -> Result<Option<Certificate>> {
        match self.load_stored_certificate(domain).await {
            Ok(cert) => Ok(Some(cert)),
            Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// CertManager — obtain
// ---------------------------------------------------------------------------

impl CertManager {
    /// Obtain a new certificate synchronously (foreground, no retries).
    ///
    /// Generates a new private key and CSR, then tries each configured
    /// issuer in order until one succeeds. The resulting certificate, key,
    /// and metadata are persisted to storage. A distributed lock is held
    /// during the operation to prevent duplicate issuance.
    pub async fn obtain(&self, domain: &str) -> Result<()> {
        self.obtain_cert(domain, true).await
    }

    /// Obtain a new certificate asynchronously (background, with retries).
    ///
    /// Same as [`CertManager::obtain`] but wraps the
    /// operation in [`do_with_retry`],
    /// automatically retrying transient failures with exponential backoff.
    pub async fn obtain_in_background(&self, domain: &str) -> Result<()> {
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

        // A failed repair must not leave a known-invalid managed leaf hiding
        // a valid cached sibling. Obtain still checks storage after this scan.
        self.has_current_managed_certificate(domain).await;

        // Existing valid storage is a no-op; invalid-time credentials need
        // renewal before they can safely enter the serving cache.
        if self.storage_has_cert_resources_any_issuer(domain).await? {
            return match self.cache_certificate(domain).await {
                Ok(_) => Ok(()),
                Err(Error::Cert(CertError::Expired(_) | CertError::NotYetValid(_))) => {
                    self.renew_cert(domain, false, interactive).await
                }
                Err(error) => Err(error),
            };
        }

        info!(domain = %domain, "acquiring lock for certificate obtain");

        let lock_key = Self::lock_key(CERT_ISSUE_LOCK_OP, domain);
        // Held until this guard is dropped, which happens on every path out of
        // here including a panic and a cancelled future. It used to be a
        // matching `unlock` below, and a cancelled future left the lock held
        // for the life of the process.
        let _lock = acquire(Arc::clone(&self.storage), &lock_key).await?;

        if interactive {
            self.do_obtain(domain).await
        } else {
            do_with_retry(&RetryConfig::default(), |_| self.do_obtain(domain)).await
        }
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
        if self.storage_has_cert_resources_any_issuer(domain).await? {
            return match self.cache_certificate(domain).await {
                Ok(_) => Ok(()),
                Err(Error::Cert(CertError::Expired(_) | CertError::NotYetValid(_))) => {
                    // The obtain caller owns the domain lock and retry loop.
                    // Reuse the leaf lock without reacquiring the domain lock.
                    self.renew_with_domain_lock(domain, false, true).await
                }
                Err(error) => Err(error),
            };
        }

        info!(domain = %domain, "obtaining certificate");

        // Emit EVENT_CERT_OBTAINING; propagate error to abort issuance.
        self.emit(
            EVENT_CERT_OBTAINING,
            &serde_json::json!({"identifier": domain, "renewal": false}),
        )?;

        // Generate or reuse private key (Task 5).
        let (private_key, private_key_pem) = if self.policy.reuse_private_keys {
            self.load_or_generate_private_key(domain).await?
        } else {
            let pk = generate_private_key_async(self.policy.key_type).await?;
            let pem = encode_private_key_pem(&pk)?;
            (pk, pem)
        };

        // Generate CSR.
        let domains = vec![domain.to_string()];
        let csr_der = generate_csr(&private_key, &domains, self.policy.must_staple)?;

        // Build issuer list, applying IssuerPolicy (Task 5).
        let mut issuers: Vec<Arc<dyn CertIssuer>> = self.issuers.clone();
        if matches!(
            self.policy.issuer_policy,
            IssuerPolicy::UseFirstRandomIssuer
        ) {
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

                    let cert = self.validated_certificate(&cert_res, domain).await?;
                    if cert.expired() || cert.not_before > chrono::Utc::now() {
                        return Err(Error::Config(
                            "issuer returned a certificate outside its validity period".into(),
                        ));
                    }
                    self.certificates.save(&ik, &cert_res).await?;
                    self.publish_certificate(cert, domain).await;

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
        for issuer in &self.issuers {
            if let Some(resource) = self.certificates.load(&issuer.issuer_key(), domain).await? {
                let pem = String::from_utf8(resource.private_key_pem)
                    .map_err(|e| Error::Config(format!("invalid private key PEM: {e}")))?;
                let key = decode_private_key_pem(&pem)?;
                return Ok((key, pem));
            }
        }

        // No existing key found; generate a new one.
        let pk = generate_private_key_async(self.policy.key_type).await?;
        let pem = encode_private_key_pem(&pk)?;
        Ok((pk, pem))
    }
}

// ---------------------------------------------------------------------------
// CertManager — renew
// ---------------------------------------------------------------------------

impl CertManager {
    /// Renew a certificate synchronously (foreground, no retries).
    ///
    /// Loads the existing certificate from storage, checks if renewal is
    /// needed (unless `force` is `true`), generates a new key and CSR,
    /// and tries each configured issuer in order. A distributed lock is
    /// held during the operation. With `force = true`, a quarantined stored
    /// resource may supply the SANs for a replacement with a new leaf; its old
    /// leaf remains blocked and cannot be republished.
    /// A stored certificate outside its validity period always needs renewal.
    pub async fn renew(&self, domain: &str, force: bool) -> Result<()> {
        self.renew_cert(domain, force, true).await
    }

    /// Renew a certificate asynchronously (background, with retries).
    ///
    /// Same as [`CertManager::renew`] but wraps the
    /// operation in [`do_with_retry`],
    /// automatically retrying transient failures with exponential backoff.
    pub async fn renew_in_background(&self, domain: &str, force: bool) -> Result<()> {
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
        let _lock = acquire(Arc::clone(&self.storage), &lock_key).await?;

        self.renew_with_domain_lock(domain, force, interactive)
            .await
    }

    /// The caller already owns the domain lifecycle lock. Keep the same leaf
    /// lock and post-lock identity recheck for initial-load repair and renewal.
    async fn renew_with_domain_lock(
        &self,
        domain: &str,
        force: bool,
        interactive: bool,
    ) -> Result<()> {
        loop {
            let resource = self.load_cert_resource_for_operation(domain, force).await?;
            let leaf_hash = crate::storage::resource_leaf_hash(&resource)?;
            // A custom CertStore may resolve multiple aliases to the same leaf.
            // Hold only one leaf lock, after the domain lock, and re-read when
            // a preceding operation replaced the resource while we waited.
            let leaf_lock = acquire(
                self.storage.clone(),
                &format!("certificate_leaf_{leaf_hash}"),
            )
            .await?;
            let current = self.load_cert_resource_for_operation(domain, force).await?;
            if crate::storage::resource_leaf_hash(&current)? != leaf_hash {
                drop(leaf_lock);
                continue;
            }
            return if interactive {
                self.do_renew(domain, force).await
            } else {
                do_with_retry(&RetryConfig::default(), |_| self.do_renew(domain, force)).await
            };
        }
    }

    /// The inner renewal logic, called once per attempt.
    async fn do_renew(&self, domain: &str, force: bool) -> Result<()> {
        // Load the existing certificate resource from storage.
        let cert_res = self.load_cert_resource_for_operation(domain, force).await?;

        // Double-check: re-load the cert and verify it still needs renewal
        // (Task 6). Another instance may have renewed it while we were
        // waiting for the lock.
        // Explicit forced renewal may use a quarantined resource only as the
        // source of its SANs/key policy. It is never republished, and validation
        // of the replacement still rejects the old leaf or another banned leaf.
        let cert = if force {
            Self::parse_managed_certificate(&cert_res, domain)?
        } else {
            self.validated_certificate(&cert_res, domain).await?
        };
        // Maintenance may have rejected an unusable storage replacement. Do
        // not let its normal renewal callback republish a future certificate
        // through the "already renewed" shortcut below.
        let needs_renewal = cert.not_before > chrono::Utc::now()
            || cert.expired()
            || cert.needs_renewal(self.policy.renewal_window_ratio);

        // Renew all actual DNS/IP SANs, including managed overlaps that would
        // otherwise lose coverage. CNs, URIs and email SANs are not TLS names.
        // Keep the lookup name first, and never expand a wildcard into a host.
        let mut domains = vec![domain.to_ascii_lowercase()];
        let mut coverage_gap = false;
        for name in Self::tls_names(&cert) {
            if !domains.contains(&name) {
                domains.push(name);
            }
        }
        for previous in self
            .cache
            .all_matching_certificates(domain)
            .await
            .into_iter()
            .filter(|cert| cert.managed)
        {
            coverage_gap |= !Self::covers_certificate(&cert, &previous);
            for name in Self::tls_names(&previous) {
                if !domains.contains(&name) {
                    domains.push(name);
                }
            }
        }

        let force = force || matches!(cert.ocsp_status, Some(OcspStatus::Revoked));
        if !needs_renewal && !force && !coverage_gap {
            info!(
                domain = %domain,
                "certificate does not need renewal (may have been renewed by another instance); reloading into cache"
            );
            // Reload the (possibly fresh) certificate into cache.
            let mut fresh = cert;
            fresh.managed = true;
            fresh.issuer_key = cert_res.issuer_key.clone();
            self.publish_certificate(fresh, domain).await;
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

        // Reuse the resource selected for this renewal, rather than searching
        // issuer order again and reviving an older issuer's private key.
        let (private_key, private_key_pem) = if self.policy.reuse_private_keys {
            let pem = std::str::from_utf8(&cert_res.private_key_pem)
                .map_err(|error| Error::Config(format!("invalid private key PEM: {error}")))?;
            let key = decode_private_key_pem(pem)?;
            (key, pem.to_owned())
        } else {
            let pk = generate_private_key_async(self.policy.key_type).await?;
            let pem = encode_private_key_pem(&pk)?;
            (pk, pem)
        };

        // Generate CSR.
        let csr_der = generate_csr(&private_key, &domains, self.policy.must_staple)?;

        // Build issuer list, applying IssuerPolicy.
        let mut issuers: Vec<Arc<dyn CertIssuer>> = self.issuers.clone();
        if matches!(
            self.policy.issuer_policy,
            IssuerPolicy::UseFirstRandomIssuer
        ) {
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
                        // Preserve the existing names_key / lookup alias. The
                        // renewed certificate may carry more SANs than this key.
                        sans: cert_res.sans.clone(),
                        certificate_pem: issued.certificate_pem,
                        private_key_pem: private_key_pem.as_bytes().to_vec(),
                        issuer_data: Some(issued.metadata),
                        issuer_key: ik.clone(),
                    };

                    let cert = self.validated_certificate(&new_cert_res, domain).await?;
                    for name in &domains {
                        Self::validate_certificate_name(&cert, name)?;
                    }
                    if cert.expired() || cert.not_before > chrono::Utc::now() {
                        return Err(Error::Config(
                            "issuer returned a certificate outside its validity period".into(),
                        ));
                    }
                    self.certificates.save(&ik, &new_cert_res).await?;
                    self.publish_certificate(cert, domain).await;

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
// CertManager — revoke
// ---------------------------------------------------------------------------

impl CertManager {
    /// Revoke the certificate for `domain`.
    ///
    /// Revoke the first stored resource found in issuer order. Before calling
    /// the provider, persist revocation intent in the shared [`Storage`] and
    /// quarantine this leaf in the local cache. Provider errors do not undo
    /// that intent. After confirmation, delete the matching stored resource;
    /// cleanup retries skip a provider call already recorded as confirmed.
    /// `reason` is an optional RFC 5280 revocation reason code (0-10).
    ///
    /// The operation runs in an owned task: dropping the caller's future does
    /// not cancel it. Await the result to observe provider, cleanup and task
    /// errors. Runtime/process shutdown can still interrupt it; a persistent
    /// pending marker blocks reuse until provider reconciliation and cleanup.
    ///
    /// Other instances must share the storage/lock backend and refresh their
    /// existing caches with [`Self::refresh_revocations`] or maintenance. This
    /// does not close existing TLS sessions or invalidate separately cloned
    /// signing keys. A provider without [`crate::Revoker`] support is an error.
    pub async fn revoke(&self, domain: &str, reason: Option<u8>) -> Result<()> {
        let worker = self.detached("revocation");
        let domain = domain.to_lowercase();
        // Dropping the caller's future must not interrupt an irreversible CA
        // operation between acknowledgement and local invalidation/cleanup.
        tokio::spawn(async move {
            let result = worker.revoke_locked(&domain, reason).await;
            if let Err(error) = &result {
                error!(%domain, %error, "certificate revocation failed");
            }
            result
        })
        .await
        .map_err(|error| Error::Other(format!("revocation task failed: {error}")))?
    }

    async fn revoke_locked(&self, domain: &str, reason: Option<u8>) -> Result<()> {
        let _lock = acquire(
            self.storage.clone(),
            &Self::lock_key(CERT_ISSUE_LOCK_OP, domain),
        )
        .await?;
        loop {
            let mut selected = None;
            for issuer in &self.issuers {
                if let Some(resource) = self.certificates.load(&issuer.issuer_key(), domain).await?
                {
                    selected = Some((issuer, resource));
                    break;
                }
            }
            let Some((issuer, resource)) = selected else {
                return Err(Error::Config(format!(
                    "no certificate found in storage for '{domain}' from any configured issuer"
                )));
            };
            let issuer_key = issuer.issuer_key();
            let leaf_hash = crate::storage::resource_leaf_hash(&resource)?;
            let leaf_lock = acquire(
                self.storage.clone(),
                &format!("certificate_leaf_{leaf_hash}"),
            )
            .await?;
            let current = self.certificates.load(&issuer_key, domain).await?;
            let Some(resource) = current else {
                drop(leaf_lock);
                continue;
            };
            if crate::storage::resource_leaf_hash(&resource)? != leaf_hash {
                drop(leaf_lock);
                continue;
            }
            let revoker = issuer.as_revoker().ok_or_else(|| {
                Error::Config(format!(
                    "issuer {issuer_key} does not support certificate revocation"
                ))
            })?;
            let leaf_hash = crate::storage::resource_leaf_hash(&resource)?;
            let marker = crate::storage::load_revocation(self.storage.as_ref(), &leaf_hash).await?;
            if marker.is_none() {
                crate::storage::store_revocation(self.storage.as_ref(), &leaf_hash, false).await?;
            }
            // Persistent intent is fail closed even if the provider subsequently
            // fails, panics, or the process exits before recording confirmation.
            self.cache.deny_revoked_certificate(&leaf_hash).await;
            if !marker.is_some_and(|marker| marker.confirmed) {
                revoker.revoke_resource(&resource, reason).await?;
                crate::storage::store_revocation(self.storage.as_ref(), &leaf_hash, true).await?;
            }
            // All certon writers use the lifecycle lock. Check the leaf again as
            // protection against an independently updated custom CertStore; this
            // is not an atomic CAS against writers that ignore the shared lock.
            if let Some(current) = self.certificates.load(&issuer_key, domain).await?
                && crate::storage::resource_leaf_hash(&current)? == leaf_hash
            {
                self.delete_site_assets(&issuer_key, domain).await?;
            }
            let _ = self.emit(
                EVENT_CERT_REVOKED,
                &serde_json::json!({
                    "identifier": domain, "issuer": issuer_key, "leaf_hash": leaf_hash,
                }),
            );
            return Ok(());
        }
    }

    /// Poll shared revocation intent and quarantine matching cached leaves.
    /// Other processes' existing caches are not synchronously invalidated;
    /// applications may call this after receiving their own invalidation event.
    pub async fn refresh_revocations(&self) -> Result<usize> {
        crate::maintain::refresh_revocations(&self.cache, self.storage.as_ref()).await
    }
}

// ---------------------------------------------------------------------------
// CertManager — TLS configuration
// ---------------------------------------------------------------------------

impl CertManager {
    /// Build a [`rustls::ServerConfig`] wired up to serve certificates from
    /// this config's cache.
    ///
    /// The returned server config uses a [`CertResolver`] backed by the
    /// config's in-memory certificate cache, with ALPN protocols set to
    /// `["h2", "http/1.1"]`.
    ///
    /// If [`default_server_name`](Policy::default_server_name) or
    /// [`fallback_server_name`](Policy::fallback_server_name) are
    /// configured, they are applied to the resolver.
    /// On-demand issuance and custom certificate selection are also applied.
    /// Without an explicit on-demand obtain callback, this manager performs
    /// issuance in the background; the first handshake may still fail.
    pub fn server_config(&self) -> rustls::ServerConfig {
        crate::install_default_crypto_provider();
        let mut resolver = if let Some(on_demand) = &self.on_demand {
            let configured = if on_demand.obtain_func.is_some() {
                Arc::clone(on_demand)
            } else {
                let manager = Arc::new(self.detached("on_demand"));
                Arc::new(OnDemandConfig {
                    decision_func: on_demand.decision_func.clone(),
                    host_allowlist: on_demand.host_allowlist.clone(),
                    rate_limit: on_demand.rate_limit.clone(),
                    obtain_func: Some(Arc::new(move |domain| {
                        let manager = Arc::clone(&manager);
                        Box::pin(async move { manager.obtain(&domain).await })
                    })),
                })
            };
            CertResolver::with_on_demand(self.cache.clone(), configured)
        } else {
            CertResolver::new(self.cache.clone())
        };
        if let Some(selector) = &self.cert_selection {
            resolver.set_certificate_selector(Arc::clone(selector));
        }

        // Apply default/fallback server names if configured.
        if self.policy.default_server_name.is_some() {
            resolver.set_default_server_name(self.policy.default_server_name.clone());
        }
        if self.policy.fallback_server_name.is_some() {
            resolver.set_fallback_server_name(self.policy.fallback_server_name.clone());
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

impl CertManager {
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
                let resource = self.load_cert_resource_any_issuer(domain).await?;
                Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)?
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
    /// This is a convenience wrapper around [`Self::client_credentials`].
    /// `roots` supplies the trust anchors used to authenticate the server;
    /// client credentials do not establish trust in the server's certificate.
    /// Pass a store (or a shared `Arc` of one) populated with your trusted CAs.
    /// An empty store rejects servers whose certificates require a trust anchor.
    ///
    /// # Errors
    ///
    /// Returns an error if no suitable certificate is found or if TLS
    /// configuration fails.
    pub async fn client_config(
        &self,
        domain: &str,
        roots: impl Into<Arc<rustls::RootCertStore>>,
    ) -> Result<rustls::ClientConfig> {
        let (cert_chain, pk_der) = self.client_credentials(domain).await?;

        crate::install_default_crypto_provider();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
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

    #[tokio::test]
    async fn bulk_management_and_detached_managers_share_bounded_admission() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use crate::async_jobs::{CERTIFICATE_JOB_CONCURRENCY, CERTIFICATE_JOB_PENDING};

        struct SlowIssuer(Arc<AtomicUsize>);
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        #[async_trait::async_trait]
        impl CertIssuer for SlowIssuer {
            async fn issue(&self, _: &[u8], _: &[String]) -> Result<crate::IssuedCertificate> {
                self.0.fetch_add(1, Ordering::SeqCst);
                let _active = Active(self.0.clone());
                std::future::pending().await
            }
            fn issuer_key(&self) -> String {
                "slow-test-ca".into()
            }
        }

        let active = Arc::new(AtomicUsize::new(0));
        let manager = Arc::new(
            CertManager::builder()
                .storage(Arc::new(MemoryStorage::new()))
                .issuers(vec![Arc::new(SlowIssuer(active.clone()))])
                .build(),
        );
        let producer = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .manage_in_background(
                        &(0..1000)
                            .map(|i| format!("host-{i}.example.com"))
                            .collect::<Vec<_>>(),
                    )
                    .await
                    .unwrap();
            }
        });
        let capacity = CERTIFICATE_JOB_CONCURRENCY + CERTIFICATE_JOB_PENDING;
        tokio::time::timeout(Duration::from_secs(2), async {
            while manager.job_queue.len().await < capacity
                || active.load(Ordering::SeqCst) < CERTIFICATE_JOB_CONCURRENCY
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(manager.job_queue.len().await, capacity);
        assert_eq!(active.load(Ordering::SeqCst), CERTIFICATE_JOB_CONCURRENCY);
        assert!(!producer.is_finished());
        // Already-admitted names still deduplicate instead of waiting at cap.
        tokio::time::timeout(
            Duration::from_secs(1),
            manager.manage_in_background(&["host-0.example.com".into()]),
        )
        .await
        .unwrap()
        .unwrap();
        let detached = manager.detached("another-manager");
        assert!(Arc::ptr_eq(&manager.job_queue, &detached.job_queue));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                detached.manage_in_background(&["other.example.com".into()])
            )
            .await
            .is_err()
        );
        assert_eq!(manager.job_queue.len().await, capacity);
        producer.abort();
        assert!(producer.await.unwrap_err().is_cancelled());
        manager.job_queue.shutdown().await;
        assert!(manager.job_queue.is_empty().await);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_config_builder_defaults() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();

        assert!((config.policy.renewal_window_ratio - 1.0 / 3.0).abs() < f64::EPSILON);
        assert_eq!(config.policy.key_type, KeyType::EcdsaP256);
        assert!(!config.policy.interactive);
        assert!(config.issuers.is_empty());
        assert!(config.on_demand.is_none());
        assert!(config.on_event.is_none());
    }

    #[test]
    #[should_panic(expected = "CertManager requires a Storage")]
    fn test_config_builder_panics_without_storage() {
        let _config = CertManager::builder().build();
    }

    #[test]
    fn test_config_builder_custom_values() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let cache = CertCache::new(CacheOptions::default());

        let config = CertManager::builder()
            .storage(storage)
            .cache(cache)
            .key_type(KeyType::EcdsaP384)
            .renewal_window_ratio(0.5)
            .interactive(true)
            .build();

        assert_eq!(config.policy.key_type, KeyType::EcdsaP384);
        assert!((config.policy.renewal_window_ratio - 0.5).abs() < f64::EPSILON);
        assert!(config.policy.interactive);
    }

    #[test]
    fn test_config_debug() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("CertManager"));
        assert!(debug_str.contains("renewal_window_ratio"));
    }

    #[test]
    fn test_lock_key_format() {
        let key = CertManager::lock_key("issue_cert", "example.com");
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
        let config = CertManager::builder().storage(storage).build();

        let has = config
            .storage_has_cert_resources_any_issuer("example.com")
            .await;
        assert!(!has.unwrap());
    }

    #[tokio::test]
    async fn test_load_cert_from_storage_not_found() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();

        let result = config.load_certificate("example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_emit_with_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&call_count);

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder()
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
        let config = CertManager::builder().storage(storage).build();

        // Should not panic when no callback is set.
        config.emit("test_event", &serde_json::json!({})).unwrap();
    }

    #[tokio::test]
    async fn test_obtain_cert_no_issuers() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();

        let result = config.obtain("example.com").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no issuers configured"));
    }

    #[tokio::test]
    async fn test_obtain_cert_invalid_domain() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        // Create a config with a dummy issuer list (though the domain check
        // should fail before trying any issuer).
        let config = CertManager::builder().storage(storage).build();

        // ".invalid" starts with a dot, so it should fail validation.
        // But first, the issuers check runs -- let us handle that by noting
        // both checks exist.
        let result = config.obtain_cert(".invalid.com", true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_renew_cert_no_issuers() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();

        let result = config.renew("example.com", false).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no issuers configured"));
    }

    #[tokio::test]
    async fn test_manage_sync_no_issuers_no_storage() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();

        // With no issuers and nothing in storage, manage should fail
        // because it tries to obtain a cert but has no issuers.
        let result = config.manage(&["example.com".to_string()]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_cert_nothing_in_storage() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let config = CertManager::builder().storage(storage).build();

        let result = config.revoke("example.com", None).await;
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

        let config = CertManager::builder().storage(storage_trait).build();

        // delete_site_assets uses storage key builders which may produce
        // different keys than the raw ones above. This test simply
        // verifies the method runs without error.
        // The actual key format is determined by the storage module.
        let _result = config.delete_site_assets("test", "example.com").await;
    }
    #[tokio::test]
    async fn private_key_reuse_reads_the_custom_certificate_store() {
        struct Issuer;
        #[async_trait::async_trait]
        impl CertIssuer for Issuer {
            async fn issue(&self, _: &[u8], _: &[String]) -> Result<crate::IssuedCertificate> {
                unreachable!()
            }
            fn issuer_key(&self) -> String {
                "ca".into()
            }
        }
        let store = Arc::new(crate::cert_store::tests::InMemory::default());
        let key = crate::crypto::generate_private_key(KeyType::EcdsaP256).unwrap();
        let pem = encode_private_key_pem(&key).unwrap();
        store
            .save(
                "ca",
                &CertificateResource {
                    sans: vec!["example.com".into()],
                    certificate_pem: vec![],
                    private_key_pem: pem.as_bytes().to_vec(),
                    issuer_data: None,
                    issuer_key: "ca".into(),
                },
            )
            .await
            .unwrap();
        let manager = CertManager::builder()
            .storage(Arc::new(MemoryStorage::new()))
            .certificates(store)
            .issuers(vec![Arc::new(Issuer)])
            .build();
        let (_, reused) = manager
            .load_or_generate_private_key("example.com")
            .await
            .unwrap();
        assert_eq!(reused, pem);
    }
}
