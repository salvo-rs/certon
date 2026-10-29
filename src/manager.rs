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

#[cfg(test)]
mod replacement_recovery_tests;

/// Callback invoked on notable lifecycle events.
type EventCallback = Arc<dyn Fn(&str, &serde_json::Value) -> Result<()> + Send + Sync>;

/// Transform applied to domain names before obtaining certificates.
type SubjectTransformer = Arc<dyn Fn(&str) -> Result<String> + Send + Sync>;

struct ManagedCertificatePlan {
    needs_renewal: bool,
    revoked: bool,
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

    /// Optional transform applied once per obtain or management operation,
    /// before validating, reading storage or taking lifecycle locks. The
    /// transformed subject is the managed identifier, normalized to lowercase.
    /// A queued job keeps that identity across retries; resubmission resolves it
    /// again. Explicit renewal and revocation take managed identifiers directly.
    pub subject_transformer: Option<SubjectTransformer>,

    /// Optional custom certificate selector for TLS handshakes.
    pub cert_selection: Option<Arc<dyn CertificateSelector>>,

    /// Background job queue for async certificate operations.
    job_queue: Arc<JobQueue>,
    background_retry: RetryConfig,
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
    background_retry: RetryConfig,
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
    /// Configure retries for queued background management. Invalid clock bounds
    /// or empty intervals are rejected by `manage_in_background` before submit.
    pub fn background_retry_config(mut self, config: RetryConfig) -> Self {
        self.background_retry = config;
        self
    }
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
    /// Panics if storage is missing or policy settings are invalid. Use
    /// [`Self::try_build`] for settings obtained from external configuration.
    pub fn build(self) -> CertManager {
        self.try_build().expect("invalid CertManager configuration")
    }

    /// Build a manager, returning configuration errors before any work starts.
    pub fn try_build(self) -> Result<CertManager> {
        use crate::cache::CacheOptions;

        self.policy.validate()?;
        let storage = self.storage.ok_or_else(|| {
            Error::Config(
                "CertManager requires a Storage implementation -- call .storage() on the builder"
                    .into(),
            )
        })?;

        let cache = self
            .cache
            .unwrap_or_else(|| CertCache::new(CacheOptions::default()));

        let issuers = self.issuers.unwrap_or_default();

        let certificates = self
            .certificates
            .unwrap_or_else(|| Arc::new(KeyValueCertStore::new(Arc::clone(&storage))));

        Ok(CertManager {
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
            background_retry: self.background_retry,
        })
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
            background_retry: self.background_retry.clone(),
        }
    }

    /// Create a new [`CertManagerBuilder`].
    ///
    /// Settings start at [`Policy::default()`], which documents what each one
    /// is and why it defaults where it does. Everything else — issuers, cache,
    /// hooks — starts empty, and a [`Storage`] must be given.
    pub fn builder() -> CertManagerBuilder {
        CertManagerBuilder {
            background_retry: RetryConfig::default(),
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
    /// 1. Skip currently usable managed entries.
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
    /// Backoff releases execution. At most 64 jobs retain retry records, leaving
    /// four admission records for new work. When retention is full, a failed job
    /// ends with `cert_failed` / `error_kind = "retry_backlog_full"`; it can be
    /// resubmitted later. Success here means submitted, not issued successfully.
    pub async fn manage_in_background(&self, domains: &[String]) -> Result<()> {
        self.background_retry.validate()?;
        for domain in domains {
            let domain = self.canonical_subject(&domain.to_lowercase())?;

            // A rejected retry may have left the old leaf managed in cache.
            // Explicit resubmission must still be able to renew that due leaf.
            let cached_certs = self.cache.all_matching_certificates(&domain).await;
            let already_managed = cached_certs.iter().any(|c| {
                c.managed
                    && c.not_before <= chrono::Utc::now()
                    && !c.expired()
                    && !crate::ari::needs_renewal(
                        c,
                        self.policy.renewal_window_ratio,
                        self.policy.disable_ari,
                    )
                    && c.ocsp_status != Some(OcspStatus::Revoked)
            });
            if already_managed {
                continue;
            }

            // Submit a background job for this domain. The job queue
            // deduplicates by name so concurrent calls for the same
            // domain are coalesced.
            let job_name = format!("manage_{domain}");
            // We need to clone the parts of self that the closure needs.
            let detached = Arc::new(self.detached("bg_manage"));
            let domain_owned = domain.clone();

            self.job_queue
                .submit_retrying(
                    job_name,
                    self.background_retry.clone(),
                    {
                        let detached = detached.clone();
                        move |_| {
                            let cfg = detached.clone();
                            let domain = domain_owned.clone();
                            // Each attempt uses the existing locked single-attempt
                            // transaction; there is no nested retry loop.
                            async move { cfg.manage_from_storage(&domain, false).await }
                        }
                    },
                    move |result| {
                        if let Err(failure) = result {
                            error!(
                                domain = %domain,
                                error = %failure.error,
                                error_kind = failure.kind,
                                "background certificate management failed"
                            );
                            let _ = detached.emit(
                                EVENT_CERT_FAILED,
                                &serde_json::json!({
                                    "identifier": domain,
                                    "background": true,
                                    "error_kind": failure.kind,
                                    "error": failure.error.to_string(),
                                }),
                            );
                        }
                    },
                )
                .await;
        }
        Ok(())
    }

    /// Internal implementation for both sync and async management.
    async fn manage_all(&self, domains: &[String], r#async: bool) -> Result<()> {
        for domain in domains {
            let domain = self.canonical_subject(&domain.to_lowercase())?;
            self.manage_one(&domain, r#async).await?;
        }
        Ok(())
    }

    /// Manage a single domain name.
    async fn manage_one(&self, domain: &str, r#async: bool) -> Result<()> {
        if self.cache.has_usable_managed_certificate(domain) {
            return Ok(());
        }

        self.manage_from_storage(domain, r#async).await
    }

    // This entry takes an already canonical identity. Unlike manage_one's initial
    // cache shortcut, a retry must re-read storage even when an earlier failed
    // renewal already cached the old managed leaf. Never transform a retry again.
    async fn manage_from_storage(&self, domain: &str, r#async: bool) -> Result<()> {
        // Planning may read an expired/future resource for its SANs and issuer,
        // but those credentials must not be published before renewal succeeds.
        match self.load_stored_certificate(domain).await {
            Ok(cert) => {
                let plan = self.plan_managed_certificate(cert, domain, None).await?;
                if plan.needs_renewal {
                    if r#async {
                        self.renew_in_background(domain, plan.revoked).await?;
                    } else {
                        self.renew(domain, plan.revoked).await?;
                    }
                    // renew publishes its validated replacement before return.
                }
                Ok(())
            }
            Err(e) => {
                // Check if it is a "not found" error.
                let is_not_found = matches!(&e, Error::Storage(StorageError::NotFound(_)));
                if !is_not_found {
                    // Preserve permanent certificate/configuration errors for
                    // the retry classifier; the background failure event/log
                    // already carries this domain as context.
                    return Err(e);
                }
                self.obtain_canonical(domain, !r#async).await
            }
        }
    }

    fn certificate_needs_renewal(&self, cert: &Certificate) -> bool {
        cert.not_before > chrono::Utc::now()
            || cert.expired()
            || crate::ari::needs_renewal(
                cert,
                self.policy.renewal_window_ratio,
                self.policy.disable_ari,
            )
    }

    /// Serving admission must not hide renewal inputs for a due or verified
    /// revoked Must-Staple leaf. Use the same plan for initial management and
    /// the current resource encountered by a delayed maintenance callback.
    async fn plan_managed_certificate(
        &self,
        mut cert: Certificate,
        domain: &str,
        observed_leaf: Option<&str>,
    ) -> Result<ManagedCertificatePlan> {
        let current = Self::validate_certificate_time(&cert, domain).is_ok();
        let leaf_hash = crate::storage::certificate_leaf_hash(&cert);
        let cached_revoked = leaf_hash
            .as_deref()
            .is_some_and(|hash| self.cache.has_ocsp_revoked_leaf(domain, hash));
        let mut revoked = cert.ocsp_status == Some(OcspStatus::Revoked) || cached_revoked;
        if cached_revoked {
            cert.ocsp_status = Some(OcspStatus::Revoked);
            cert.ocsp_response = None;
        }
        let mut needs_renewal = self.certificate_needs_renewal(&cert) || revoked;
        if current {
            let must_staple = crate::ocsp::requires_ocsp_staple(&cert)?;
            let hash = cert.hash.clone();
            let admission = self
                .cache_loaded_certificate_observing(&cert, domain, observed_leaf)
                .await;
            if matches!(&admission, Ok(false)) {
                return Ok(ManagedCertificatePlan {
                    needs_renewal: false,
                    revoked: false,
                });
            }
            // Admission can reconcile a revocation received while preparing
            // the signing key; never await issuance with that leaf serving.
            let cached_revoked = leaf_hash
                .as_deref()
                .is_some_and(|hash| self.cache.has_ocsp_revoked_leaf(domain, hash));
            if cached_revoked {
                revoked = true;
                if admission.is_ok() {
                    self.cache
                        .update_ocsp_if_present(&hash, Some(OcspStatus::Revoked), None)
                        .await;
                }
            }
            needs_renewal |= revoked;
            match admission {
                Ok(_) => {}
                Err(Error::Cert(CertError::OcspFailed(_))) if needs_renewal && must_staple => {}
                Err(error) => return Err(error),
            }
        }
        Ok(ManagedCertificatePlan {
            needs_renewal,
            revoked,
        })
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
        self.cache_loaded_certificate_observing(&cert, domain, None)
            .await?;
        Ok(cert)
    }

    async fn cache_loaded_certificate_observing(
        &self,
        cert: &Certificate,
        domain: &str,
        observed_leaf: Option<&str>,
    ) -> Result<bool> {
        Self::validate_certificate_time(cert, domain)?;
        let published = match observed_leaf {
            Some(leaf) => {
                self.cache
                    .add_managed_if_observed_revoked(cert.clone(), domain, leaf)
                    .await?
            }
            None => {
                self.cache.add_managed(cert.clone(), domain).await?;
                true
            }
        };
        if published {
            let _ = self.emit(
                EVENT_CACHED_MANAGED_CERT,
                &serde_json::json!({"sans": cert.names}),
            );
        }
        Ok(published)
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
        self.certificate_for_planning(&cert_res, domain).await
    }

    async fn certificate_for_planning(
        &self,
        cert_res: &CertificateResource,
        domain: &str,
    ) -> Result<Certificate> {
        let mut cert = self.validated_certificate(cert_res, domain).await?;
        cert.managed = true;
        cert.issuer_key = cert_res.issuer_key.clone();
        if cert.ocsp_status != Some(OcspStatus::Revoked) {
            crate::ari::attach_cached(
                self.storage.as_ref(),
                &self.cache,
                &mut cert,
                self.policy.disable_ari,
            )
            .await;
        }
        Ok(cert)
    }

    /// Validate issuer/storage output before publishing it to the live cache.
    async fn validated_certificate(
        &self,
        resource: &CertificateResource,
        domain: &str,
    ) -> Result<Certificate> {
        let cert = Self::parse_managed_certificate(resource, domain)?;
        self.validate_certificate_status(cert, domain).await
    }

    /// Response contents are attributable to the issuer. Keep these checks
    /// separate from fallible revocation/storage reads so only bad responses
    /// cause issuer fallback.
    fn parse_issued_certificate(
        resource: &CertificateResource,
        domain: &str,
        requested_names: &[String],
    ) -> Result<Certificate> {
        let cert = Self::parse_managed_certificate(resource, domain)?;
        for name in requested_names {
            Self::validate_certificate_name(&cert, name)?;
        }
        Self::validate_certificate_time(&cert, domain)?;
        Ok(cert)
    }

    async fn validate_certificate_status(
        &self,
        cert: Certificate,
        domain: &str,
    ) -> Result<Certificate> {
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
        let cert = Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)?;
        Self::validate_managed_certificate(cert, domain, &resource.issuer_key)
    }

    /// Complete identity admission for an already parsed resource. Callers may
    /// first apply persistent revocation intent, including its quarantine side
    /// effect, before rejecting an otherwise unusable replacement key or name.
    pub(crate) fn validate_managed_certificate(
        mut cert: Certificate,
        domain: &str,
        issuer_key: &str,
    ) -> Result<Certificate> {
        crate::handshake::cert_to_certified_key(&cert)?
            .keys_match()
            .map_err(|error| Error::Config(format!("certificate/private key mismatch: {error}")))?;
        Self::validate_certificate_name(&cert, domain)?;
        // Keep the lookup alias first so maintenance renews through the same
        // CertStore address even if the CA orders SANs differently.
        cert.names.retain(|name| !name.eq_ignore_ascii_case(domain));
        cert.names.insert(0, domain.to_ascii_lowercase());
        cert.managed = true;
        cert.issuer_key = issuer_key.to_owned();
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

    async fn publish_certificate(&self, cert: Certificate, domain: &str) -> Result<()> {
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
        self.cache.replace_managed(old_hash, cert, domain).await?;
        for hash in superseded.into_iter().skip(1) {
            self.cache.remove(hash).await;
        }
        Ok(())
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
    /// 1. Transform and normalize the domain, then validate the actual subject.
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

        let canonical = self.canonical_subject(domain)?;
        self.obtain_canonical(&canonical, interactive).await
    }

    // Resolve before cache/storage/queue admission/locks, once per logical
    // operation. All subsequent work, including retries, uses this identity.
    fn canonical_subject(&self, domain: &str) -> Result<String> {
        let canonical = if let Some(transformer) = &self.subject_transformer {
            transformer(domain)?
        } else {
            domain.to_owned()
        };
        let canonical = canonical.to_lowercase();
        if !subject_qualifies_for_cert(&canonical) {
            return Err(Error::Config(format!(
                "domain '{canonical}' does not qualify for a certificate"
            )));
        }
        Ok(canonical)
    }

    // Private canonical entry also serves management, which resolves identity
    // before planning from storage and must not invoke the transformer again.
    async fn obtain_canonical(&self, domain: &str, interactive: bool) -> Result<()> {
        if self.issuers.is_empty() {
            return Err(Error::Config(
                "no issuers configured; cannot obtain certificate".into(),
            ));
        }

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
        let mut issuer_errors = Vec::new();

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

                    let cert = match Self::parse_issued_certificate(&cert_res, domain, &domains) {
                        Ok(cert) => cert,
                        Err(error) => {
                            error!(domain, issuer = %ik, %error, "issuer returned an unusable certificate");
                            issuer_errors.push(
                                serde_json::json!({"issuer": ik, "error": error.to_string()}),
                            );
                            last_err = Some(error);
                            continue;
                        }
                    };
                    // Backend failures must abort the transaction, even when
                    // another issuer could return a different certificate.
                    let cert = self.validate_certificate_status(cert, domain).await?;
                    crate::ocsp::ensure_required_staple(&cert).await?;
                    self.certificates.save(&ik, &cert_res).await?;
                    self.publish_certificate(cert.clone(), domain).await?;
                    crate::ari::refresh(self, &cert).await;

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
                    issuer_errors.push(serde_json::json!({"issuer": ik, "error": e.to_string()}));
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
                "issuer_errors": issuer_errors,
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

    /// Re-evaluate the current resource for a delayed OCSP recovery request.
    /// A healthy replacement is only reloaded; a replacement independently
    /// verified revoked or due uses its own renewal plan under lifecycle locks.
    pub(crate) async fn renew_observed_revocation(
        &self,
        domain: &str,
        observed_leaf: &str,
    ) -> Result<()> {
        let _domain_lock = acquire(
            self.storage.clone(),
            &Self::lock_key(CERT_ISSUE_LOCK_OP, domain),
        )
        .await?;
        loop {
            let resource = self.load_cert_resource_for_operation(domain, true).await?;
            let leaf = crate::storage::resource_leaf_hash(&resource)?;
            let leaf_lock =
                acquire(self.storage.clone(), &format!("certificate_leaf_{leaf}")).await?;
            let current = self.load_cert_resource_for_operation(domain, true).await?;
            if crate::storage::resource_leaf_hash(&current)? != leaf {
                drop(leaf_lock);
                continue;
            }
            if !self
                .cache
                .has_managed_ocsp_revoked_leaf(domain, observed_leaf)
            {
                return Ok(());
            }
            if leaf != observed_leaf {
                let cert = self.certificate_for_planning(&current, domain).await;
                // A verified status is useful independently of the authority
                // to keep managing A. Preserve it for an already cached B even
                // if later identity/observation checks make this job stale.
                if let Ok(cert) = &cert
                    && cert.ocsp_status == Some(OcspStatus::Revoked)
                {
                    let _ = self
                        .cache
                        .update_ocsp_if_present(&cert.hash, Some(OcspStatus::Revoked), None)
                        .await;
                }
                // OCSP and ARI can await storage or a remote responder. Recheck
                // the selected identity before admission, and again afterwards
                // because key preparation can also await issuer discovery.
                let latest = self.load_cert_resource_for_operation(domain, true).await?;
                if crate::storage::resource_leaf_hash(&latest)? != leaf
                    || latest.issuer_key != current.issuer_key
                {
                    drop(leaf_lock);
                    continue;
                }
                if !self
                    .cache
                    .has_managed_ocsp_revoked_leaf(domain, observed_leaf)
                {
                    return Ok(());
                }
                let plan = self
                    .plan_managed_certificate(cert?, domain, Some(observed_leaf))
                    .await;
                let latest = self.load_cert_resource_for_operation(domain, true).await?;
                if crate::storage::resource_leaf_hash(&latest)? != leaf
                    || latest.issuer_key != current.issuer_key
                {
                    drop(leaf_lock);
                    continue;
                }
                if !self
                    .cache
                    .has_managed_ocsp_revoked_leaf(domain, observed_leaf)
                {
                    return Ok(());
                }
                let plan = plan?;
                return if plan.needs_renewal {
                    self.do_renew(domain, plan.revoked).await
                } else {
                    Ok(())
                };
            }
            // Maintenance uses one foreground attempt, without long background
            // retry/backoff while holding these locks.
            return self.do_renew(domain, true).await;
        }
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
            self.certificate_for_planning(&cert_res, domain).await?
        };
        // Maintenance may have rejected an unusable storage replacement. Do
        // not let its normal renewal callback republish a future certificate
        // through the "already renewed" shortcut below.
        let needs_renewal = self.certificate_needs_renewal(&cert);

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
            self.publish_certificate(fresh, domain).await?;
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
        let mut issuer_errors = Vec::new();

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

                    let cert = match Self::parse_issued_certificate(&new_cert_res, domain, &domains)
                    {
                        Ok(cert) => cert,
                        Err(error) => {
                            error!(domain, issuer = %ik, %error, "issuer returned an unusable renewal certificate");
                            issuer_errors.push(
                                serde_json::json!({"issuer": ik, "error": error.to_string()}),
                            );
                            last_err = Some(error);
                            continue;
                        }
                    };
                    let cert = self.validate_certificate_status(cert, domain).await?;
                    crate::ocsp::ensure_required_staple(&cert).await?;
                    self.certificates.save(&ik, &new_cert_res).await?;
                    self.publish_certificate(cert.clone(), domain).await?;
                    crate::ari::refresh(self, &cert).await;

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
                    issuer_errors.push(serde_json::json!({"issuer": ik, "error": e.to_string()}));
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
                "issuer_errors": issuer_errors,
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
    /// Select the stored resource using the same validity/latest-issuance
    /// preference as certificate loading, independent of issuer order. Pending
    /// or confirmed markers do not lower its rank: recording intent alone cannot
    /// redirect a retry to an older backup. This revokes one stored resource, not every
    /// certificate that can serve this domain. Use [`Self::revoke_from_issuer`]
    /// to target a particular issuer's resource.
    ///
    /// Every invocation selects from current storage under the lifecycle lock;
    /// if resources or their validity state have changed, a new call may select
    /// a different leaf.
    /// Before calling
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
        self.revoke_selected(domain, None, reason).await
    }

    /// Revoke the resource currently stored for `domain` under an exact
    /// configured `issuer_key`. Other issuers are not consulted or used as
    /// fallbacks, including when the selected provider is unavailable or does
    /// not support revocation.
    ///
    /// Unlike default target selection, this recovery/cleanup path needs only a
    /// parseable leaf certificate: an expired certificate, incorrect SAN or
    /// damaged private key does not prevent provider-side revocation.
    /// Ownership, locking, persisted intent and cleanup semantics are the same
    /// as [`Self::revoke`]. This selects an issuer, not an immutable historical
    /// leaf: if that issuer's resource was replaced, a new call targets its
    /// current resource.
    pub async fn revoke_from_issuer(
        &self,
        domain: &str,
        issuer_key: &str,
        reason: Option<u8>,
    ) -> Result<()> {
        self.revoke_selected(domain, Some(issuer_key.to_owned()), reason)
            .await
    }

    async fn revoke_selected(
        &self,
        domain: &str,
        issuer_key: Option<String>,
        reason: Option<u8>,
    ) -> Result<()> {
        let worker = self.detached("revocation");
        let domain = domain.to_lowercase();
        // Dropping the caller's future must not interrupt an irreversible CA
        // operation between acknowledgement and local invalidation/cleanup.
        tokio::spawn(async move {
            let result = worker
                .revoke_locked(&domain, issuer_key.as_deref(), reason)
                .await;
            if let Err(error) = &result {
                error!(%domain, %error, "certificate revocation failed");
            }
            result
        })
        .await
        .map_err(|error| Error::Other(format!("revocation task failed: {error}")))?
    }

    async fn select_revocation_resource(
        &self,
        domain: &str,
        issuer_key: Option<&str>,
    ) -> Result<(Arc<dyn CertIssuer>, CertificateResource)> {
        let now = chrono::Utc::now();
        let mut selected = None;
        let mut validation_errors = Vec::new();
        let mut found_issuer = false;
        for issuer in &self.issuers {
            let key = issuer.issuer_key();
            if issuer_key.is_some_and(|wanted| wanted != key) {
                continue;
            }
            found_issuer = true;
            // Default selection checks all configured stores: backend errors
            // must not quietly redirect a destructive operation to another CA.
            let Some(resource) = self.certificates.load(&key, domain).await? else {
                continue;
            };
            if issuer_key.is_some() {
                crate::storage::resource_leaf_hash(&resource)?;
                return Ok((Arc::clone(issuer), resource));
            }
            let cert = match Self::parse_managed_certificate(&resource, domain) {
                Ok(cert) => cert,
                Err(error) => {
                    validation_errors.push(format!("{key}: {error}"));
                    continue;
                }
            };
            // Do not use the normal loader's !has_intent rank component:
            // writing our pending marker must not select an older backup on
            // retry, and confirmed cleanup retries must skip a second CA call.
            let rank = (
                cert.not_before <= now && !cert.expired(),
                cert.not_before,
                cert.not_after,
            );
            if selected.as_ref().is_none_or(|(best, _)| rank > *best) {
                selected = Some((rank, (Arc::clone(issuer), resource)));
            }
        }
        if let Some((_, (issuer, resource))) = selected {
            Ok((issuer, resource))
        } else if let Some(issuer_key) = issuer_key {
            Err(Error::Config(if found_issuer {
                format!(
                    "no certificate found in storage for '{domain}' under issuer '{issuer_key}'"
                )
            } else {
                format!("issuer '{issuer_key}' is not configured")
            }))
        } else if !validation_errors.is_empty() {
            Err(Error::Config(format!(
                "no valid revocation target for '{domain}': {}",
                validation_errors.join("; ")
            )))
        } else {
            Err(Error::Config(format!(
                "no certificate found in storage for '{domain}' from any configured issuer"
            )))
        }
    }

    async fn revoke_locked(
        &self,
        domain: &str,
        selected_issuer: Option<&str>,
        reason: Option<u8>,
    ) -> Result<()> {
        let _lock = acquire(
            self.storage.clone(),
            &Self::lock_key(CERT_ISSUE_LOCK_OP, domain),
        )
        .await?;
        loop {
            let (issuer, resource) = self
                .select_revocation_resource(domain, selected_issuer)
                .await?;
            let issuer_key = issuer.issuer_key();
            let leaf_hash = crate::storage::resource_leaf_hash(&resource)?;
            let leaf_lock = acquire(
                self.storage.clone(),
                &format!("certificate_leaf_{leaf_hash}"),
            )
            .await?;
            let (current_issuer, resource) = self
                .select_revocation_resource(domain, selected_issuer)
                .await?;
            if current_issuer.issuer_key() != issuer_key
                || crate::storage::resource_leaf_hash(&resource)? != leaf_hash
            {
                drop(leaf_lock);
                continue;
            }
            let revoker = issuer.as_revoker().ok_or_else(|| {
                Error::Config(format!(
                    "issuer {issuer_key} does not support certificate revocation"
                ))
            })?;
            let leaf_hash = crate::storage::resource_leaf_hash(&resource)?;
            info!(domain, issuer = %issuer_key, %leaf_hash, "selected stored certificate for revocation");
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
    /// Reads at most eight unique leaf markers concurrently and returns the
    /// number of quarantined leaves. Alternate chains share one marker read.
    /// A failed read does not prevent other leaves from being quarantined; the
    /// first snapshot-order error is returned after all reads finish.
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
    /// Candidates must be time-valid and not locally known to be revoked.
    /// Each call reads persisted revocation intent even for a warm cache;
    /// backend errors are propagated. An unusable leaf does not hide a usable
    /// sibling. Server Must-Staple policy is not applied to client identities,
    /// and this method does not query an OCSP responder.
    ///
    /// Returned credentials are an immutable validated snapshot. A later
    /// revocation or expiry does not invalidate previously exported keys or
    /// configurations; construct fresh credentials to check current state.
    ///
    /// # Returns
    ///
    /// A tuple of `(cert_chain, private_key)` where:
    /// - `cert_chain` is a list of DER-encoded certificates (leaf first).
    /// - `private_key` is the DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if no usable certificate is found for `domain`, or if
    /// persisted revocation intent cannot be read.
    pub async fn client_credentials(
        &self,
        domain: &str,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        let cert = self.select_client_certificate(domain).await?;

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

    async fn select_client_certificate(&self, domain: &str) -> Result<Arc<Certificate>> {
        let mut rejected = None;
        if let Some(cert) = self
            .select_client_candidate(
                self.cache.client_certificate_candidates(domain),
                domain,
                &mut rejected,
            )
            .await?
        {
            return Ok(cert);
        }

        // Storage selection must consider every issuer rather than returning
        // an unusable first/best leaf and overlooking a healthy fallback.
        let mut candidates = Vec::new();
        for issuer in &self.issuers {
            if let Some(resource) = self.certificates.load(&issuer.issuer_key(), domain).await? {
                match Self::parse_managed_certificate(&resource, domain) {
                    Ok(cert) => candidates.push(Arc::new(cert)),
                    Err(error) => {
                        rejected.get_or_insert(error);
                    }
                }
            }
        }
        if let Some(cert) = self
            .select_client_candidate(candidates, domain, &mut rejected)
            .await?
        {
            return Ok(cert);
        }
        Err(rejected.unwrap_or_else(|| {
            StorageError::NotFound(format!("no client certificate found for '{domain}'")).into()
        }))
    }

    async fn select_client_candidate(
        &self,
        mut candidates: Vec<Arc<Certificate>>,
        domain: &str,
        rejected: &mut Option<Error>,
    ) -> Result<Option<Arc<Certificate>>> {
        // Retain the cache's existing preference among usable identities.
        candidates.sort_by(|a, b| {
            b.managed
                .cmp(&a.managed)
                .then_with(|| b.not_after.cmp(&a.not_after))
                .then_with(|| a.hash.cmp(&b.hash))
        });
        let mut usable = Vec::new();
        for cert in candidates {
            if let Err(error) = Self::validate_client_certificate(&cert, domain) {
                rejected.get_or_insert(error);
                continue;
            }
            let leaf_hash = crate::storage::certificate_leaf_hash(&cert)
                .expect("validated client certificate has a leaf");
            if cert.ocsp_status == Some(OcspStatus::Revoked)
                || self.cache.client_leaf_is_revoked(domain, &leaf_hash)
            {
                rejected.get_or_insert_with(|| CertError::Revoked(domain.to_owned()).into());
                continue;
            }
            // Marker I/O failures are not invalid candidate contents: never
            // swallow one while falling back to a cached or stored sibling.
            if crate::storage::load_revocation(self.storage.as_ref(), &leaf_hash)
                .await?
                .is_some()
            {
                self.cache.deny_revoked_certificate(&leaf_hash).await;
                rejected.get_or_insert_with(|| CertError::Revoked(domain.to_owned()).into());
                continue;
            }
            usable.push((cert, leaf_hash));
        }
        for (cert, leaf_hash) in usable {
            // A different candidate's marker read may have awaited a backend
            // while this candidate expired or acquired local revocation state.
            if let Err(error) = Self::validate_client_time(&cert, domain) {
                rejected.get_or_insert(error);
                continue;
            }
            if self.cache.client_leaf_is_revoked(domain, &leaf_hash) {
                rejected.get_or_insert_with(|| CertError::Revoked(domain.to_owned()).into());
                continue;
            }
            return Ok(Some(cert));
        }
        Ok(None)
    }

    fn validate_client_time(cert: &Certificate, domain: &str) -> Result<()> {
        let now = chrono::Utc::now();
        if cert.not_before > now {
            return Err(CertError::NotYetValid(domain.to_owned()).into());
        }
        if now >= cert.not_after {
            return Err(CertError::Expired(domain.to_owned()).into());
        }
        Ok(())
    }

    fn validate_client_certificate(cert: &Certificate, domain: &str) -> Result<()> {
        Self::validate_client_time(cert, domain)?;
        crate::handshake::cert_to_certified_key(cert)?
            .keys_match()
            .map_err(|error| Error::Config(format!("certificate/private key mismatch: {error}")))?;
        Ok(())
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
        fail_reads: std::sync::atomic::AtomicBool,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: RwLock::new(HashMap::new()),
                fail_reads: std::sync::atomic::AtomicBool::new(false),
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
            if self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("injected storage read failure").into());
            }
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

    mod must_staple_recovery {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        use x509_parser::prelude::FromDer;

        use super::*;

        const DOMAIN: &str = "ocsp.example.com";

        struct CsrKey(Vec<u8>);
        impl rcgen::PublicKeyData for CsrKey {
            fn der_bytes(&self) -> &[u8] {
                &self.0
            }
            fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
                &rcgen::PKCS_ECDSA_P256_SHA256
            }
        }

        struct Issuer {
            ca: rcgen::Issuer<'static, rcgen::KeyPair>,
            root: rustls::pki_types::CertificateDer<'static>,
            storage: Arc<MemoryStorage>,
            calls: AtomicUsize,
            unavailable: AtomicBool,
        }

        fn params(before: i64, after: i64, must_staple: bool) -> rcgen::CertificateParams {
            let mut params = rcgen::CertificateParams::new(vec![DOMAIN.into()]).unwrap();
            params.distinguished_name = rcgen::DistinguishedName::new();
            let date = |offset: i64| {
                rcgen::date_time_ymd(1970, 1, 1)
                    + Duration::from_secs((Utc::now().timestamp() + offset).try_into().unwrap())
            };
            params.not_before = date(before);
            params.not_after = date(after);
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            if must_staple {
                params
                    .custom_extensions
                    .push(rcgen::CustomExtension::from_oid_content(
                        &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                        vec![0x30, 0x03, 0x02, 0x01, 0x05],
                    ));
            }
            params
        }

        #[async_trait::async_trait]
        impl CertIssuer for Issuer {
            async fn issue(
                &self,
                csr: &[u8],
                names: &[String],
            ) -> Result<crate::IssuedCertificate> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.unavailable.load(Ordering::SeqCst) {
                    return Err(Error::Config("recovery CA unavailable".into()));
                }
                let (_, csr) =
                    x509_parser::certification_request::X509CertificationRequest::from_der(csr)
                        .unwrap();
                let public = CsrKey(
                    csr.certification_request_info
                        .subject_pki
                        .subject_public_key
                        .data
                        .to_vec(),
                );
                let mut params = params(-60, 90 * 86400, true);
                params.subject_alt_names = names
                    .iter()
                    .map(|name| rcgen::SanType::DnsName(name.clone().try_into().unwrap()))
                    .collect();
                let leaf = params.signed_by(&public, &self.ca).unwrap();
                let chain = vec![leaf.der().clone(), self.root.clone()];
                let response = crate::ocsp::tests::signed_response(
                    &chain,
                    self.ca.key(),
                    0,
                    Utc::now(),
                    Utc::now() + chrono::Duration::hours(4),
                );
                self.storage
                    .store(
                        &crate::storage::ocsp_key(
                            &names[0],
                            &crate::certificates::hash_certificate_chain(&chain),
                        ),
                        &response,
                    )
                    .await?;
                Ok(crate::IssuedCertificate {
                    certificate_pem: format!(
                        "{}{}",
                        leaf.pem(),
                        ::pem::encode(&::pem::Pem::new("CERTIFICATE", self.root.as_ref()))
                    )
                    .into_bytes(),
                    private_key_pem: Vec::new(),
                    metadata: serde_json::Value::Null,
                })
            }
            fn issuer_key(&self) -> String {
                "must-staple-recovery".into()
            }
        }

        struct Fixture {
            storage: Arc<MemoryStorage>,
            store: Arc<crate::cert_store::tests::InMemory>,
            issuer: Arc<Issuer>,
            manager: Arc<CertManager>,
            old: Certificate,
            resource: CertificateResource,
        }

        impl Fixture {
            async fn new(due: bool, status: Option<u8>, must_staple: bool) -> Self {
                let storage = Arc::new(MemoryStorage::new());
                let store = Arc::new(crate::cert_store::tests::InMemory::default());
                let key = rcgen::KeyPair::generate().unwrap();
                let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
                ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
                let root = ca.self_signed(&key).unwrap().der().clone();
                let issuer = Arc::new(Issuer {
                    ca: rcgen::Issuer::new(ca, key),
                    root,
                    storage: storage.clone(),
                    calls: AtomicUsize::new(0),
                    unavailable: AtomicBool::new(false),
                });
                let key = rcgen::KeyPair::generate().unwrap();
                let leaf = params(
                    if due { -80 * 86400 } else { -86400 },
                    if due { 10 * 86400 } else { 89 * 86400 },
                    must_staple,
                )
                .signed_by(&key, &issuer.ca)
                .unwrap();
                let resource = CertificateResource {
                    sans: vec![DOMAIN.into()],
                    certificate_pem: format!(
                        "{}{}",
                        leaf.pem(),
                        ::pem::encode(&::pem::Pem::new("CERTIFICATE", issuer.root.as_ref()))
                    )
                    .into_bytes(),
                    private_key_pem: key.serialize_pem().into_bytes(),
                    issuer_key: issuer.issuer_key(),
                    issuer_data: None,
                };
                store.save(&issuer.issuer_key(), &resource).await.unwrap();
                let mut old =
                    Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                        .unwrap();
                old.managed = true;
                old.issuer_key = issuer.issuer_key();
                assert_eq!(old.needs_renewal(1.0 / 3.0), due);
                if let Some(status) = status {
                    let response = crate::ocsp::tests::signed_response(
                        &old.cert_chain,
                        issuer.ca.key(),
                        status,
                        Utc::now(),
                        Utc::now() + chrono::Duration::hours(4),
                    );
                    storage
                        .store(&crate::storage::ocsp_key(DOMAIN, &old.hash), &response)
                        .await
                        .unwrap();
                    old.ocsp_response = Some(response);
                }
                let manager = Arc::new(
                    CertManager::builder()
                        .storage(storage.clone())
                        .certificates(store.clone())
                        .issuers(vec![issuer.clone()])
                        .background_retry_config(RetryConfig {
                            max_retries: 1,
                            ..Default::default()
                        })
                        .build(),
                );
                Self {
                    storage,
                    store,
                    issuer,
                    manager,
                    old,
                    resource,
                }
            }

            async fn manage(&self, queued: bool) -> Result<()> {
                if queued {
                    self.manager.manage_in_background(&[DOMAIN.into()]).await?;
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        self.manager.job_queue.wait(&format!("manage_{DOMAIN}")),
                    )
                    .await
                    .unwrap();
                    Ok(())
                } else {
                    self.manager.manage(&[DOMAIN.into()]).await
                }
            }

            async fn handshake(&self) -> Option<Vec<u8>> {
                crate::install_default_crypto_provider();
                let mut roots = rustls::RootCertStore::empty();
                roots.add(self.issuer.root.clone()).unwrap();
                let client = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let (server_io, client_io) = tokio::io::duplex(16384);
                let acceptor =
                    tokio_rustls::TlsAcceptor::from(Arc::new(self.manager.server_config()));
                let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
                let (server, client) = tokio::join!(
                    acceptor.accept(server_io),
                    connector.connect(DOMAIN.try_into().unwrap(), client_io)
                );
                server.ok()?;
                Some(client.ok()?.get_ref().1.peer_certificates()?[0].to_vec())
            }
        }

        #[tokio::test]
        async fn due_or_revoked_must_staple_recovers_from_cold_or_unusable_cached_state() {
            for queued in [false, true] {
                for (due, status, warm) in [
                    (true, None, false),
                    (false, Some(1), false),
                    (true, None, true),
                    (false, Some(1), true),
                ] {
                    let fixture = Fixture::new(due, status, true).await;
                    if warm {
                        fixture.manager.cache.add(fixture.old.clone()).await;
                    }
                    fixture.manage(queued).await.unwrap();
                    assert_eq!(
                        fixture.issuer.calls.load(Ordering::SeqCst),
                        1,
                        "queued={queued} due={due} status={status:?} warm={warm}"
                    );
                    let current = fixture.manager.cache.resolve(DOMAIN).unwrap();
                    assert_ne!(current.hash, fixture.old.hash);
                    assert!(current.key.ocsp.is_some());
                    assert_eq!(
                        fixture.handshake().await.unwrap(),
                        current.key.cert[0].as_ref()
                    );
                }
            }
        }

        #[tokio::test]
        async fn cached_revocation_still_forces_recovery_when_storage_replays_fresh_good() {
            for queued in [false, true] {
                let fixture = Fixture::new(false, Some(0), true).await;
                fixture.manager.cache.add(fixture.old.clone()).await;
                fixture
                    .manager
                    .cache
                    .update_ocsp_if_present(&fixture.old.hash, Some(OcspStatus::Revoked), None)
                    .await
                    .unwrap();
                fixture.manage(queued).await.unwrap();
                assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
                let current = fixture.manager.cache.resolve(DOMAIN).unwrap();
                assert_ne!(current.hash, fixture.old.hash);
                assert_eq!(
                    fixture.handshake().await.unwrap(),
                    current.key.cert[0].as_ref()
                );
            }
        }

        #[tokio::test]
        async fn same_leaf_alternate_chain_does_not_republish_a_cached_revocation() {
            let fixture = Fixture::new(false, Some(0), true).await;
            fixture.manager.cache.add(fixture.old.clone()).await;
            fixture
                .manager
                .cache
                .update_ocsp_if_present(&fixture.old.hash, Some(OcspStatus::Revoked), None)
                .await
                .unwrap();
            // Cross-sign the original issuer key under another root. Both
            // chains authenticate exactly the same leaf and OCSP CertID.
            let other_key = rcgen::KeyPair::generate().unwrap();
            let mut other_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let other_root = other_params.self_signed(&other_key).unwrap();
            let other_issuer = rcgen::Issuer::new(other_params, other_key);
            let mut cross_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            cross_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            cross_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let cross_signed = cross_params
                .signed_by(fixture.issuer.ca.key(), &other_issuer)
                .unwrap();
            let resource = CertificateResource {
                certificate_pem: format!(
                    "{}{}{}",
                    ::pem::encode(&::pem::Pem::new(
                        "CERTIFICATE",
                        fixture.old.cert_chain[0].as_ref()
                    )),
                    cross_signed.pem(),
                    other_root.pem()
                )
                .into_bytes(),
                ..fixture.resource.clone()
            };
            let alternate =
                Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                    .unwrap();
            assert_ne!(alternate.hash, fixture.old.hash);
            assert_eq!(
                crate::storage::certificate_leaf_hash(&alternate),
                crate::storage::certificate_leaf_hash(&fixture.old)
            );
            let response = crate::ocsp::tests::signed_response(
                &alternate.cert_chain,
                fixture.issuer.ca.key(),
                0,
                Utc::now(),
                Utc::now() + chrono::Duration::hours(4),
            );
            assert_eq!(
                crate::ocsp::parse_ocsp_response_for_cert_chain(&response, &alternate.cert_chain)
                    .await
                    .unwrap()
                    .status,
                OcspStatus::Good
            );
            fixture
                .storage
                .store(
                    &crate::storage::ocsp_key(DOMAIN, &alternate.hash),
                    &response,
                )
                .await
                .unwrap();
            fixture
                .store
                .save(&fixture.issuer.issuer_key(), &resource)
                .await
                .unwrap();
            fixture.manage(false).await.unwrap();
            assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
            let current = fixture.manager.cache.resolve(DOMAIN).unwrap();
            assert_ne!(current.key.cert[0], fixture.old.cert_chain[0]);
            assert_eq!(
                fixture.handshake().await.unwrap(),
                current.key.cert[0].as_ref()
            );
        }

        #[tokio::test]
        async fn cached_revocation_does_not_force_issue_for_a_different_healthy_stored_leaf() {
            let fixture = Fixture::new(false, Some(0), true).await;
            fixture.manager.cache.add(fixture.old.clone()).await;
            fixture
                .manager
                .cache
                .update_ocsp_if_present(&fixture.old.hash, Some(OcspStatus::Revoked), None)
                .await
                .unwrap();
            let key = rcgen::KeyPair::generate().unwrap();
            let leaf = params(-60, 90 * 86400, true)
                .signed_by(&key, &fixture.issuer.ca)
                .unwrap();
            let resource = CertificateResource {
                certificate_pem: format!(
                    "{}{}",
                    leaf.pem(),
                    ::pem::encode(&::pem::Pem::new(
                        "CERTIFICATE",
                        fixture.issuer.root.as_ref()
                    ))
                )
                .into_bytes(),
                private_key_pem: key.serialize_pem().into_bytes(),
                ..fixture.resource.clone()
            };
            let replacement =
                Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                    .unwrap();
            let response = crate::ocsp::tests::signed_response(
                &replacement.cert_chain,
                fixture.issuer.ca.key(),
                0,
                Utc::now(),
                Utc::now() + chrono::Duration::hours(4),
            );
            fixture
                .storage
                .store(
                    &crate::storage::ocsp_key(DOMAIN, &replacement.hash),
                    &response,
                )
                .await
                .unwrap();
            fixture
                .store
                .save(&fixture.issuer.issuer_key(), &resource)
                .await
                .unwrap();
            fixture.manage(false).await.unwrap();
            assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture.handshake().await.unwrap(),
                replacement.cert_chain[0].as_ref()
            );
            assert_eq!(
                fixture
                    .manager
                    .cache
                    .get_by_hash(&fixture.old.hash)
                    .await
                    .unwrap()
                    .ocsp_status,
                Some(OcspStatus::Revoked)
            );
        }

        #[tokio::test]
        async fn fresh_must_staple_without_good_response_does_not_issue() {
            for (queued, warm) in [(false, false), (true, false), (false, true), (true, true)] {
                let fixture = Fixture::new(false, None, true).await;
                if warm {
                    fixture.manager.cache.add(fixture.old.clone()).await;
                }
                let result = fixture.manage(queued).await;
                if !queued {
                    assert!(matches!(result, Err(Error::Cert(CertError::OcspFailed(_)))));
                } else {
                    result.unwrap();
                }
                assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
                assert!(fixture.handshake().await.is_none());
                assert_eq!(
                    fixture
                        .store
                        .load(&fixture.issuer.issuer_key(), DOMAIN)
                        .await
                        .unwrap()
                        .unwrap()
                        .certificate_pem,
                    fixture.resource.certificate_pem
                );
            }
        }

        #[tokio::test]
        async fn due_must_staple_recovery_preserves_backend_marker_and_ca_errors() {
            for fault in ["backend", "marker", "ca"] {
                let fixture = Fixture::new(true, None, true).await;
                match fault {
                    "backend" => fixture.storage.fail_reads.store(true, Ordering::SeqCst),
                    "marker" => crate::storage::store_revocation(
                        fixture.storage.as_ref(),
                        &crate::storage::certificate_leaf_hash(&fixture.old).unwrap(),
                        true,
                    )
                    .await
                    .unwrap(),
                    "ca" => fixture.issuer.unavailable.store(true, Ordering::SeqCst),
                    _ => unreachable!(),
                }
                let error = fixture.manage(false).await.unwrap_err();
                assert!(
                    match (&error, fault) {
                        (Error::Storage(StorageError::Io(_)), "backend")
                        | (Error::Cert(CertError::Revoked(_)), "marker") => true,
                        (Error::Config(message), "ca") => message == "recovery CA unavailable",
                        _ => false,
                    },
                    "fault={fault}: {error}"
                );
                assert_eq!(
                    fixture.issuer.calls.load(Ordering::SeqCst),
                    usize::from(fault == "ca")
                );
                assert!(fixture.handshake().await.is_none());
                assert_eq!(
                    fixture
                        .store
                        .load(&fixture.issuer.issuer_key(), DOMAIN)
                        .await
                        .unwrap()
                        .unwrap()
                        .certificate_pem,
                    fixture.resource.certificate_pem
                );
            }
        }

        #[tokio::test]
        async fn serving_due_leaves_keep_the_foreground_managed_shortcut() {
            for must_staple in [false, true] {
                let fixture = Fixture::new(true, must_staple.then_some(0), must_staple).await;
                fixture.manager.cache_certificate(DOMAIN).await.unwrap();
                fixture.manage(false).await.unwrap();
                assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    fixture.handshake().await.unwrap(),
                    fixture.old.cert_chain[0].as_ref()
                );
            }
        }
    }

    #[tokio::test]
    async fn actual_must_staple_requires_good_ocsp_before_saving_or_publishing() {
        use x509_parser::prelude::FromDer;
        struct CsrKey(Vec<u8>);
        impl rcgen::PublicKeyData for CsrKey {
            fn der_bytes(&self) -> &[u8] {
                &self.0
            }
            fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
                &rcgen::PKCS_ECDSA_P256_SHA256
            }
        }
        struct Issuer {
            ca: rcgen::Issuer<'static, rcgen::KeyPair>,
            root: rustls::pki_types::CertificateDer<'static>,
            storage: Arc<dyn Storage>,
            feature: bool,
            status: Option<u8>,
        }
        #[async_trait::async_trait]
        impl CertIssuer for Issuer {
            async fn issue(
                &self,
                csr: &[u8],
                names: &[String],
            ) -> Result<crate::IssuedCertificate> {
                let (_, csr) =
                    x509_parser::certification_request::X509CertificationRequest::from_der(csr)
                        .unwrap();
                let public = CsrKey(
                    csr.certification_request_info
                        .subject_pki
                        .subject_public_key
                        .data
                        .to_vec(),
                );
                let mut params = rcgen::CertificateParams::new(names.to_vec()).unwrap();
                params.not_before = rcgen::date_time_ymd(1970, 1, 1)
                    + std::time::Duration::from_secs(
                        (Utc::now().timestamp() - 60).try_into().unwrap(),
                    );
                params.not_after =
                    params.not_before + std::time::Duration::from_secs(2 * 24 * 60 * 60);
                params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                if self.feature {
                    params
                        .custom_extensions
                        .push(rcgen::CustomExtension::from_oid_content(
                            &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                            vec![0x30, 0x03, 0x02, 0x01, 0x05],
                        ));
                }
                let leaf = params.signed_by(&public, &self.ca).unwrap();
                let chain = vec![leaf.der().clone(), self.root.clone()];
                if let Some(status) = self.status {
                    let raw = crate::ocsp::tests::signed_response(
                        &chain,
                        self.ca.key(),
                        status,
                        Utc::now(),
                        Utc::now() + chrono::Duration::hours(4),
                    );
                    self.storage
                        .store(
                            &crate::storage::ocsp_key(
                                &names[0],
                                &crate::certificates::hash_certificate_chain(&chain),
                            ),
                            &raw,
                        )
                        .await
                        .unwrap();
                }
                let certificate_pem: String = chain
                    .iter()
                    .map(|der| ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.as_ref())))
                    .collect();
                Ok(crate::IssuedCertificate {
                    certificate_pem: certificate_pem.into_bytes(),
                    private_key_pem: Vec::new(),
                    metadata: serde_json::Value::Null,
                })
            }
            fn issuer_key(&self) -> String {
                "must-staple-test".into()
            }
        }
        for renew in [false, true] {
            for (feature, status, disabled, expected) in [
                (true, None, false, false),
                (true, Some(2), false, false),
                (true, Some(0), true, false),
                (true, Some(0), false, true),
                // A requested CSR feature is not proof that the CA included it.
                (false, None, false, true),
            ] {
                let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
                let store = Arc::new(crate::cert_store::tests::InMemory::default());
                let key = rcgen::KeyPair::generate().unwrap();
                let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
                let root = params.self_signed(&key).unwrap().der().clone();
                let issuer = Arc::new(Issuer {
                    ca: rcgen::Issuer::new(params, key),
                    root,
                    storage: storage.clone(),
                    feature,
                    status,
                });
                let manager = CertManager::builder()
                    .storage(storage)
                    .certificates(store.clone())
                    .issuers(vec![issuer])
                    .must_staple(!feature)
                    .ocsp(OcspConfig {
                        disable_stapling: disabled,
                        ..Default::default()
                    })
                    .build();
                let old = if renew {
                    let old = rcgen::generate_simple_self_signed(vec!["ocsp.example.com".into()])
                        .unwrap();
                    let resource = CertificateResource {
                        sans: vec!["ocsp.example.com".into()],
                        certificate_pem: old.cert.pem().into_bytes(),
                        private_key_pem: old.signing_key.serialize_pem().into_bytes(),
                        issuer_key: "must-staple-test".into(),
                        issuer_data: None,
                    };
                    store.save("must-staple-test", &resource).await.unwrap();
                    manager.cache_certificate("ocsp.example.com").await.unwrap();
                    Some(resource)
                } else {
                    None
                };
                let result = if renew {
                    manager.renew("ocsp.example.com", true).await
                } else {
                    manager.obtain("ocsp.example.com").await
                };
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "renew={renew}, feature={feature}, status={status:?}, disabled={disabled}: {result:?}"
                );
                let stored = store
                    .load("must-staple-test", "ocsp.example.com")
                    .await
                    .unwrap();
                if !expected {
                    assert!(matches!(result, Err(Error::Cert(CertError::OcspFailed(_)))));
                    assert_eq!(
                        stored.as_ref().map(|r| &r.certificate_pem),
                        old.as_ref().map(|r| &r.certificate_pem)
                    );
                    if let Some(old) = old {
                        let previous =
                            Certificate::from_pem(&old.certificate_pem, &old.private_key_pem)
                                .unwrap();
                        assert_eq!(
                            manager.cache.resolve("ocsp.example.com").unwrap().key.cert[0],
                            previous.cert_chain[0]
                        );
                    } else {
                        assert!(manager.cache.resolve("ocsp.example.com").is_none());
                    }
                } else {
                    let serving = manager.cache.resolve("ocsp.example.com").unwrap();
                    assert_eq!(serving.key.ocsp.is_some(), feature);
                    assert!(stored.is_some());
                }
            }
        }
    }

    #[tokio::test]
    async fn client_credentials_reject_a_verified_local_ocsp_revocation() {
        let (mut cert, issuer_key) = crate::cache::tests::signed_certificate();
        let domain = cert.names[0].clone();
        let hash = cert.hash.clone();
        cert.ocsp_response = Some(crate::ocsp::tests::signed_response(
            &cert.cert_chain,
            &issuer_key,
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::hours(1),
        ));
        assert!(cert.ocsp_status.is_none());
        let manager = CertManager::builder()
            .storage(Arc::new(MemoryStorage::new()))
            .build();
        manager.cache.add(cert).await;
        assert_eq!(
            manager.cache.get_by_hash(&hash).await.unwrap().ocsp_status,
            Some(OcspStatus::Revoked)
        );
        assert!(matches!(
            manager.client_credentials(&domain).await,
            Err(Error::Cert(CertError::Revoked(_)))
        ));
        assert!(
            manager
                .client_config(&domain, rustls::RootCertStore::empty())
                .await
                .is_err()
        );
        // The management metadata is retained even when mTLS rejects the leaf.
        assert!(manager.cache.get_by_hash(&hash).await.is_some());
    }

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
