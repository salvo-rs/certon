//! In-memory certificate cache with domain name indexing.
//!
//! This module implements a concurrent, in-memory cache for TLS certificates.
//! Certificates are stored by their content hash and indexed by subject name
//! (SAN) for fast lookup during TLS handshakes.
//!
//! Generally there should be only one cache per process. Having more than one
//! is a code smell that may indicate an over-engineered design.
//!
//! # Lifecycle
//!
//! 1. Create a cache with [`CertCache::new`].
//! 2. Add certificates with [`CertCache::add`].
//! 3. Look up certificates during TLS handshakes with [`CertCache::get_by_name`].
//! 4. When shutting down, call [`CertCache::stop`] to signal any background maintenance tasks.
//!
//! # Certificate selection
//!
//! When multiple certificates match a lookup name, the best one is selected
//! automatically:
//! - Non-expired certificates are preferred over expired ones.
//! - Managed certificates are preferred over unmanaged ones.
//! - Among otherwise-equal certs, the one with the longest remaining lifetime (latest `not_after`)
//!   wins.
//!
//! # Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use certon::cache::{CertCache, CacheOptions};
//!
//! let cache = CertCache::new(CacheOptions::default());
//! // cache.add(cert).await;
//! // let cert = cache.get_by_name("example.com").await;
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::Utc;
use rand::RngExt;
use rustls::sign::CertifiedKey;
use tokio::sync::watch;
use tracing::info;

use crate::certificates::Certificate;
use crate::error::Result;
use crate::handshake::cert_to_certified_key;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default interval for checking whether certificates need renewal (10 minutes).
///
/// This controls how frequently the maintenance loop scans cached certificates
/// to determine if any need to be renewed.
pub const DEFAULT_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Default interval for checking whether OCSP staples need updating (1 hour).
///
/// This controls how frequently the maintenance loop refreshes OCSP responses
/// for cached certificates.
pub const DEFAULT_OCSP_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Callback that returns per-certificate configuration data.
type CertConfigFunc =
    Arc<dyn Fn(&Certificate) -> Arc<dyn std::any::Any + Send + Sync> + Send + Sync>;

// ---------------------------------------------------------------------------
// CacheEvent
// ---------------------------------------------------------------------------

/// Events emitted by the certificate cache when its contents change.
///
/// These events are delivered via the optional [`CacheOptions::on_event`]
/// callback. They can be used to trigger external actions such as logging,
/// metrics, or cache invalidation in a reverse proxy.
#[derive(Debug, Clone)]
pub enum CacheEvent {
    /// A new certificate was added to the cache.
    Added {
        /// Subject names on the certificate.
        names: Vec<String>,
        /// The certificate's content hash.
        hash: String,
    },
    /// An existing certificate was updated (e.g. tags merged).
    Updated {
        /// Subject names on the certificate.
        names: Vec<String>,
        /// The certificate's content hash.
        hash: String,
    },
    /// A certificate was removed from the cache.
    Removed {
        /// Subject names on the removed certificate.
        names: Vec<String>,
        /// The certificate's content hash.
        hash: String,
    },
}

// ---------------------------------------------------------------------------
// SubjectIssuer
// ---------------------------------------------------------------------------

/// Pairs a subject name with an optional issuer key, used when removing
/// managed certificates from the cache via [`CertCache::remove_managed`].
///
/// If [`SubjectIssuer::issuer_key`] is empty, all managed certificates
/// matching the subject are removed regardless of which issuer created them.
#[derive(Debug, Clone)]
pub struct SubjectIssuer {
    /// The certificate subject (SAN) to match.
    pub subject: String,
    /// If non-empty, only remove certificates issued by this particular
    /// issuer. An empty string matches all issuers.
    pub issuer_key: String,
}

// ---------------------------------------------------------------------------
// CacheOptions
// ---------------------------------------------------------------------------

/// Configuration options for [`CertCache`].
///
/// Once a cache has been created with certain options, they can be updated
/// at runtime via [`CertCache::set_options`]. Interval values of zero are
/// automatically replaced with their defaults.
#[derive(Clone)]
pub struct CacheOptions {
    /// How often to check certificates for renewal.
    ///
    /// Defaults to [`DEFAULT_RENEW_CHECK_INTERVAL`] (10 minutes).
    pub renew_check_interval: Duration,

    /// How often to check OCSP staple freshness.
    ///
    /// Defaults to [`DEFAULT_OCSP_CHECK_INTERVAL`] (1 hour).
    pub ocsp_check_interval: Duration,

    /// Maximum number of certificates allowed in the cache. When the cache
    /// reaches capacity, a random managed certificate is evicted to make room.
    /// A value of `0` means unlimited.
    pub capacity: usize,

    /// Optional callback invoked when a cache event occurs (add, remove,
    /// update). This can be used for logging, metrics, or triggering
    /// external cache invalidation.
    pub on_event: Option<Arc<dyn Fn(CacheEvent) + Send + Sync>>,

    /// Optional callback that returns configuration data associated with
    /// a certificate.
    ///
    /// This is a flexible extension point: callers can attach arbitrary
    /// per-certificate configuration by returning an
    /// `Arc<dyn Any + Send + Sync>`. The returned value can later be
    /// downcast to the expected concrete type.
    pub get_config_for_cert: Option<CertConfigFunc>,
}

impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            renew_check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
            ocsp_check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
            capacity: 0,
            on_event: None,
            get_config_for_cert: None,
        }
    }
}

impl std::fmt::Debug for CacheOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheOptions")
            .field("renew_check_interval", &self.renew_check_interval)
            .field("ocsp_check_interval", &self.ocsp_check_interval)
            .field("capacity", &self.capacity)
            .field("on_event", &self.on_event.as_ref().map(|_| "..."))
            .field(
                "get_config_for_cert",
                &self.get_config_for_cert.as_ref().map(|_| "..."),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// CertCache
// ---------------------------------------------------------------------------

/// An in-memory certificate cache that indexes certificates by subject name
/// for efficient TLS handshake lookups.
///
/// The cache is safe for concurrent use via interior `RwLock`s. [`CertCache::new`]
/// returns an `Arc<CertCache>` ready for shared ownership across tasks.
///
/// Certificates are keyed by their SHA-256 content hash and indexed by
/// lowercase subject name (SAN) for O(1) lookups during TLS handshakes.
/// Wildcard matching replaces only the leftmost label of the queried
/// domain with `*`, and matches exactly one label.
///
/// Call [`CertCache::stop`] to signal background maintenance to stop.
/// Maintenance tasks retain the cache until they exit.
///
/// **Do not construct this struct directly** -- use [`CertCache::new`].
pub struct CertCache {
    // Certificate metadata and the serving index share one short, synchronous
    // critical section. No user callback or cryptographic operation runs here.
    state: RwLock<CacheState>,
    options: RwLock<CacheOptions>,
    stop_tx: watch::Sender<bool>,
    done_tx: watch::Sender<bool>,
    maintenance_count: Mutex<usize>,
}

#[derive(Default)]
struct CacheState {
    certificates: HashMap<String, CachedCertificate>,
    index: HashMap<String, Vec<String>>,
    revoked_leaf_hashes: HashSet<String>,
    /// Dense managed-only sampling pool; each entry stores its back-reference.
    managed_hashes: Vec<String>,
}

struct CachedCertificate {
    leaf_hash: Option<String>,
    certificate: Arc<Certificate>,
    key: Option<Arc<CertifiedKey>>,
    managed_index: Option<usize>,
}

/// Renewal policy at the OCSP update's cache linearization point.
pub(crate) struct OcspUpdateState {
    pub managed: bool,
    pub first_name: String,
    pub ocsp_status: Option<crate::ocsp::OcspStatus>,
}

impl From<&Certificate> for OcspUpdateState {
    fn from(cert: &Certificate) -> Self {
        Self {
            managed: cert.managed,
            first_name: cert.names.first().cloned().unwrap_or_default(),
            ocsp_status: cert.ocsp_status,
        }
    }
}

/// A serving lookup contains no raw private-key copy.
pub(crate) struct CachedKey {
    pub key: Arc<CertifiedKey>,
    pub hash: String,
    pub needs_ocsp: bool,
}

/// Registered before spawning maintenance, so immediate shutdown cannot race
/// task startup. Dropping an unpolled or aborted task releases its registration.
pub(crate) struct MaintenanceGuard {
    cache: Arc<CertCache>,
}

impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        let mut count = self
            .cache
            .maintenance_count
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *count -= 1;
        if *count == 0 {
            self.cache.done_tx.send_replace(true);
        }
    }
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertCache").finish_non_exhaustive()
    }
}

impl CacheState {
    fn remove(&mut self, hash: &str) -> Option<CacheEvent> {
        let entry = self.certificates.remove(hash)?;
        if let Some(index) = entry.managed_index {
            self.managed_hashes.swap_remove(index);
            if let Some(moved_hash) = self.managed_hashes.get(index) {
                self.certificates
                    .get_mut(moved_hash)
                    .expect("managed sampling pool references a cached certificate")
                    .managed_index = Some(index);
            }
        }
        for name in &entry.certificate.names {
            let lower = name.to_lowercase();
            if let Some(hashes) = self.index.get_mut(&lower) {
                hashes.retain(|h| h != hash);
                if hashes.is_empty() {
                    self.index.remove(&lower);
                }
            }
        }
        Some(CacheEvent::Removed {
            names: entry.certificate.names.clone(),
            hash: hash.to_owned(),
        })
    }

    fn matching(&self, name: &str) -> Vec<&CachedCertificate> {
        let lower = name.to_lowercase();
        let wildcard = if !lower.contains('*') && !lower.split('.').any(str::is_empty) {
            lower
                .split_once('.')
                .filter(|(label, rest)| !label.is_empty() && !rest.is_empty())
                .map(|(_, suffix)| format!("*.{suffix}"))
        } else {
            None
        };
        let mut seen = HashSet::new();
        std::iter::once(lower.as_str())
            .chain(wildcard.as_deref())
            .filter_map(|subject| self.index.get(subject))
            .flatten()
            .filter(|hash| seen.insert(hash.as_str()))
            .filter_map(|hash| self.certificates.get(hash))
            .collect()
    }

    fn add(
        &mut self,
        cert: Certificate,
        key: Option<Arc<CertifiedKey>>,
        leaf_hash: Option<String>,
        options: &CacheOptions,
        events: &mut Vec<CacheEvent>,
    ) {
        if leaf_hash
            .as_ref()
            .is_some_and(|hash| self.revoked_leaf_hashes.contains(hash))
        {
            return;
        }
        let hash = cert.hash.clone();
        if let Some(existing) = self.certificates.get_mut(&hash) {
            for tag in &cert.tags {
                if !existing.certificate.tags.contains(tag) {
                    Arc::make_mut(&mut existing.certificate)
                        .tags
                        .push(tag.clone());
                }
            }
            events.push(CacheEvent::Updated {
                names: cert.names,
                hash,
            });
            return;
        }
        if options.capacity > 0
            && self.certificates.len() >= options.capacity
            && !self.managed_hashes.is_empty()
        {
            let index = rand::rng().random_range(0..self.managed_hashes.len());
            let hash = self.managed_hashes[index].clone();
            if let Some(event) = self.remove(&hash) {
                events.push(event);
            }
        }
        for name in &cert.names {
            self.index
                .entry(name.to_lowercase())
                .or_default()
                .push(hash.clone());
        }
        events.push(CacheEvent::Added {
            names: cert.names.clone(),
            hash: hash.clone(),
        });
        let managed_index = cert.managed.then(|| {
            let index = self.managed_hashes.len();
            self.managed_hashes.push(hash.clone());
            index
        });
        self.certificates.insert(
            hash,
            CachedCertificate {
                leaf_hash,
                certificate: Arc::new(cert),
                key,
                managed_index,
            },
        );
    }
}

fn dispatch_events(options: &CacheOptions, events: Vec<CacheEvent>) {
    for event in events {
        if let CacheEvent::Added { names, hash } = &event {
            info!(subjects = ?names, hash = %hash, "added certificate to cache");
        }
        if let Some(callback) = &options.on_event {
            callback(event);
        }
    }
}

impl CertCache {
    /// Create an empty cache. Maintenance must be started separately.
    pub fn new(options: CacheOptions) -> Arc<Self> {
        let (stop_tx, _) = watch::channel(false);
        let (done_tx, _) = watch::channel(true);
        Arc::new(Self {
            state: RwLock::new(CacheState::default()),
            options: RwLock::new(normalize_options(options)),
            stop_tx,
            done_tx,
            maintenance_count: Mutex::new(0),
        })
    }

    /// Update cache options; zero intervals are replaced with their defaults.
    pub async fn set_options(&self, options: CacheOptions) {
        *self.options.write().unwrap_or_else(|e| e.into_inner()) = normalize_options(options);
    }

    /// Persist a stop request, including when maintenance has not subscribed yet.
    pub fn stop(&self) {
        self.stop_tx.send_replace(true);
    }

    /// Subscribe to shutdown. Check the current value before waiting for changes.
    pub fn subscribe_stop(&self) -> watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    /// Stop all registered maintenance loops and wait for their guards to drop.
    /// Returns immediately if no maintenance loop is registered.
    pub async fn stop_and_wait(&self) {
        self.stop();
        let mut done = self.done_tx.subscribe();
        while !*done.borrow_and_update() {
            if done.changed().await.is_err() {
                break;
            }
        }
    }

    pub(crate) fn maintenance_guard(self: &Arc<Self>) -> MaintenanceGuard {
        let mut count = self
            .maintenance_count
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *count += 1;
        self.done_tx.send_replace(false);
        MaintenanceGuard {
            cache: Arc::clone(self),
        }
    }

    /// Signal completion for legacy callers. Registered maintenance is tracked
    /// by guards, so a single loop cannot mark other active loops as complete.
    pub fn signal_done(&self) {
        let count = self
            .maintenance_count
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if *count == 0 {
            self.done_tx.send_replace(true);
        }
    }

    /// Add a certificate, merging tags if the hash is already present.
    /// Signing keys are prepared once, outside the cache lock. Quarantined
    /// leaves are ignored; Result-returning unmanaged helpers report rejection.
    pub async fn add(&self, cert: Certificate) {
        let key = cert_to_certified_key(&cert).ok();
        let leaf_hash = crate::storage::certificate_leaf_hash(&cert);
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut events = Vec::new();
        self.state.write().unwrap_or_else(|e| e.into_inner()).add(
            cert,
            key,
            leaf_hash,
            &options,
            &mut events,
        );
        dispatch_events(&options, events);
    }

    /// Remove a certificate by hash.
    pub async fn remove(&self, hash: &str) {
        self.remove_many(&[hash.to_owned()]).await;
    }

    /// Remove a batch atomically. Callbacks run after releasing the cache lock.
    pub async fn remove_many(&self, hashes: &[String]) {
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let events = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            hashes
                .iter()
                .filter_map(|hash| state.remove(hash))
                .collect()
        };
        dispatch_events(&options, events);
    }

    /// Remove managed certificates matching a subject and optional issuer key.
    pub async fn remove_managed(&self, subjects: &[SubjectIssuer]) {
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let events = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let mut hashes = HashSet::new();
            for subject in subjects {
                if let Some(candidates) = state.index.get(&subject.subject.to_lowercase()) {
                    for hash in candidates {
                        if state.certificates.get(hash).is_some_and(|entry| {
                            entry.certificate.managed
                                && (subject.issuer_key.is_empty()
                                    || subject.issuer_key == entry.certificate.issuer_key)
                                && entry
                                    .certificate
                                    .names
                                    .iter()
                                    .any(|name| name.eq_ignore_ascii_case(&subject.subject))
                        }) {
                            hashes.insert(hash.clone());
                        }
                    }
                }
            }
            hashes
                .iter()
                .filter_map(|hash| state.remove(hash))
                .collect()
        };
        dispatch_events(&options, events);
    }

    /// Replace metadata and the prebuilt serving key in one critical section.
    pub async fn replace(&self, old_hash: &str, new_cert: Certificate) {
        let key = cert_to_certified_key(&new_cert).ok();
        let leaf_hash = crate::storage::certificate_leaf_hash(&new_cert);
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut events = Vec::new();
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            if leaf_hash
                .as_ref()
                .is_some_and(|hash| state.revoked_leaf_hashes.contains(hash))
            {
                return;
            }
            if let Some(event) = state.remove(old_hash) {
                events.push(event);
            }
            state.add(new_cert, key, leaf_hash, &options, &mut events);
        }
        dispatch_events(&options, events);
    }

    /// Irreversibly quarantine this leaf for the lifetime of this cache. A
    /// stale loader or alternate chain cannot put it back after revocation.
    pub(crate) async fn deny_revoked_certificate(&self, leaf_hash: &str) {
        let options = self
            .options
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let events = {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|error| error.into_inner());
            state.revoked_leaf_hashes.insert(leaf_hash.to_owned());
            let hashes: Vec<_> = state
                .certificates
                .iter()
                .filter(|(_, entry)| entry.leaf_hash.as_deref() == Some(leaf_hash))
                .map(|(hash, _)| hash.clone())
                .collect();
            hashes
                .iter()
                .filter_map(|hash| state.remove(hash))
                .collect()
        };
        dispatch_events(&options, events);
    }

    /// Publish only OCSP fields, preserving the current certificate metadata.
    /// Membership and revocation checks share the same write lock as the update:
    /// stale refreshes cannot resurrect removed certificates or undo revocation.
    /// A new certificate hash is installed through the ordinary `replace` API.
    /// Returns the current policy/status at that same linearization point,
    /// including when an older response cannot replace sticky revocation.
    /// Later metadata changes are not serialized with the renewal callback.
    pub(crate) async fn update_ocsp_if_present(
        &self,
        hash: &str,
        status: Option<crate::ocsp::OcspStatus>,
        response: Option<Vec<u8>>,
    ) -> Option<OcspUpdateState> {
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (event, published) = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let current = state.certificates.get_mut(hash)?;
            if current.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                && status != Some(crate::ocsp::OcspStatus::Revoked)
            {
                return Some(OcspUpdateState::from(current.certificate.as_ref()));
            }
            let certificate = Arc::make_mut(&mut current.certificate);
            certificate.ocsp_status = status;
            certificate.ocsp_response = response.clone();
            if let Some(key) = &mut current.key {
                // Clone just the rustls container when an in-flight handshake
                // shares it; retain the prepared signing key without crypto work.
                Arc::make_mut(key).ocsp = response;
            }
            (
                CacheEvent::Updated {
                    names: current.certificate.names.clone(),
                    hash: hash.to_owned(),
                },
                OcspUpdateState::from(current.certificate.as_ref()),
            )
        };
        dispatch_events(&options, vec![event]);
        Some(published)
    }

    /// Get the best exact or single leftmost-label wildcard match.
    pub async fn get_by_name(&self, name: &str) -> Option<Certificate> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        state
            .matching(name)
            .into_iter()
            .min_by(|a, b| compare_certificates(&a.certificate, &b.certificate, now))
            .map(|entry| entry.certificate.as_ref().clone())
    }

    /// Synchronous hot path for rustls, independent of any async runtime.
    pub(crate) fn resolve(&self, name: &str) -> Option<CachedKey> {
        self.resolve_with_filter(name, |_| true)
    }

    /// Filter client-incompatible keys before applying certificate preferences.
    pub(crate) fn resolve_with_filter(
        &self,
        name: &str,
        accepts: impl Fn(&CertifiedKey) -> bool,
    ) -> Option<CachedKey> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        let entry = state
            .matching(name)
            .into_iter()
            .filter(|e| e.key.as_ref().is_some_and(|key| accepts(key)))
            .min_by(|a, b| compare_certificates(&a.certificate, &b.certificate, now))?;
        Some(CachedKey {
            key: Arc::clone(entry.key.as_ref()?),
            hash: entry.certificate.hash.clone(),
            needs_ocsp: entry.certificate.ocsp_status.is_none()
                || entry.certificate.ocsp_response.is_none(),
        })
    }

    /// Look up metadata by content hash.
    pub async fn get_by_hash(&self, hash: &str) -> Option<Certificate> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .certificates
            .get(hash)
            .map(|e| e.certificate.as_ref().clone())
    }

    /// All exact and valid single leftmost-label wildcard matches.
    pub async fn all_matching_certificates(&self, name: &str) -> Vec<Certificate> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .matching(name)
            .into_iter()
            .map(|e| e.certificate.as_ref().clone())
            .collect()
    }

    /// Number of cached certificates.
    pub async fn count(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .certificates
            .len()
    }

    /// Snapshot all certificate metadata.
    pub async fn get_all(&self) -> Vec<Certificate> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .certificates
            .values()
            .map(|e| e.certificate.as_ref().clone())
            .collect()
    }

    /// Snapshot all managed certificate metadata.
    pub async fn get_managed_certificates(&self) -> Vec<Certificate> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .certificates
            .values()
            .filter(|e| e.certificate.managed)
            .map(|e| e.certificate.as_ref().clone())
            .collect()
    }

    /// Immutable internal snapshots share certificate bytes. Updates use copy
    /// on write, so a scan observes one version without cloning every key/chain.
    pub(crate) fn maintenance_snapshot(&self, managed_only: bool) -> Vec<Arc<Certificate>> {
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        if managed_only {
            state
                .managed_hashes
                .iter()
                .filter_map(|hash| state.certificates.get(hash))
                .map(|entry| Arc::clone(&entry.certificate))
                .collect()
        } else {
            state
                .certificates
                .values()
                .map(|entry| Arc::clone(&entry.certificate))
                .collect()
        }
    }

    // -----------------------------------------------------------------------
    // Unmanaged certificate helpers
    // -----------------------------------------------------------------------

    /// Cache an unmanaged (user-provided) certificate from PEM data.
    ///
    /// The certificate is parsed from `cert_pem` and `key_pem`, marked as
    /// unmanaged (`managed = false`), tagged with the provided `tags`, and
    /// added to the cache.
    ///
    /// If a certificate with the same hash already exists, its tags are
    /// merged.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM data is malformed or contains no
    /// certificates, or if the leaf has been quarantined by revocation intent.
    pub async fn cache_unmanaged_pem(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
        tags: Vec<String>,
    ) -> Result<()> {
        let mut cert = Certificate::from_pem(cert_pem, key_pem)?;
        cert.managed = false;
        cert.tags = tags;
        self.admit_unmanaged(cert, false)
    }

    /// Cache an unmanaged certificate from raw rustls types (DER-encoded
    /// certificate chain and private key).
    ///
    /// Builds a [`Certificate`] from the provided `cert_chain` and
    /// `private_key`, marks it as unmanaged, applies the given `tags`, and
    /// adds it to the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate chain is empty or the leaf
    /// certificate cannot be parsed, or if the leaf is quarantined.
    pub async fn cache_unmanaged_certified_key(
        &self,
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        private_key: rustls::pki_types::PrivateKeyDer<'static>,
        tags: Vec<String>,
    ) -> Result<()> {
        let mut cert = Certificate::from_der(cert_chain, Some(private_key))?;
        cert.managed = false;
        cert.tags = tags;
        info!(
            subjects = ?cert.names,
            expires = %cert.not_after,
            "caching unmanaged certified key"
        );
        self.admit_unmanaged(cert, false)
    }

    /// Cache an unmanaged certificate, replacing all existing certificates
    /// for the same SANs.
    ///
    /// This method first removes any existing certificates (managed or
    /// unmanaged) whose SANs overlap with the new certificate's SANs, then
    /// adds the new certificate. This ensures a clean replacement rather
    /// than accumulating stale entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM data is malformed or contains no
    /// certificates, or if the leaf has been quarantined by revocation intent.
    pub async fn cache_unmanaged_replacing(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
        tags: Vec<String>,
    ) -> Result<()> {
        let mut cert = Certificate::from_pem(cert_pem, key_pem)?;
        cert.managed = false;
        cert.tags = tags;

        self.admit_unmanaged(cert, true)
    }

    /// Admission and optional replacement share the deny-list linearization
    /// point. A stale publisher cannot delete a working certificate before
    /// discovering that the incoming leaf has been quarantined.
    fn admit_unmanaged(&self, cert: Certificate, replacing: bool) -> Result<()> {
        let key = cert_to_certified_key(&cert).ok();
        let leaf_hash = crate::storage::certificate_leaf_hash(&cert);
        let options = self
            .options
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let mut events = Vec::new();
        {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|error| error.into_inner());
            if leaf_hash
                .as_ref()
                .is_some_and(|hash| state.revoked_leaf_hashes.contains(hash))
            {
                return Err(crate::error::CertError::Revoked(
                    "certificate leaf is quarantined in this cache".into(),
                )
                .into());
            }
            if replacing {
                let hashes: HashSet<_> = cert
                    .names
                    .iter()
                    .flat_map(|name| state.matching(name))
                    .map(|entry| entry.certificate.hash.clone())
                    .collect();
                for hash in hashes {
                    if let Some(event) = state.remove(&hash) {
                        events.push(event);
                    }
                }
            }
            state.add(cert, key, leaf_hash, &options, &mut events);
        }
        dispatch_events(&options, events);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Certificate selection
// ---------------------------------------------------------------------------

/// Select the best certificate from a list of candidates.
///
/// Selection criteria (in order of priority):
/// 1. Non-expired certificates are preferred over expired ones.
/// 2. Managed certificates are preferred over unmanaged ones.
/// 3. Among otherwise-equal certs, the one with the longest remaining lifetime (latest `not_after`)
///    wins.
#[cfg(test)]
fn select_best_certificate(candidates: Vec<Certificate>) -> Option<Certificate> {
    let now = Utc::now();
    candidates
        .into_iter()
        .min_by(|a, b| compare_certificates(a, b, now))
}

fn compare_certificates(
    a: &Certificate,
    b: &Certificate,
    now: chrono::DateTime<Utc>,
) -> std::cmp::Ordering {
    (a.not_after < now)
        .cmp(&(b.not_after < now))
        .then_with(|| b.managed.cmp(&a.managed))
        .then_with(|| b.not_after.cmp(&a.not_after))
        .then_with(|| a.hash.cmp(&b.hash))
}

// ---------------------------------------------------------------------------
// Option normalization
// ---------------------------------------------------------------------------

/// Ensure option intervals have sensible default values.
fn normalize_options(mut opts: CacheOptions) -> CacheOptions {
    if opts.renew_check_interval.is_zero() {
        opts.renew_check_interval = DEFAULT_RENEW_CHECK_INTERVAL;
    }
    if opts.ocsp_check_interval.is_zero() {
        opts.ocsp_check_interval = DEFAULT_OCSP_CHECK_INTERVAL;
    }
    opts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;

    /// Helper: build a minimal test certificate.
    fn make_cert(names: &[&str], hash: &str, managed: bool) -> Certificate {
        let now = Utc::now();
        Certificate {
            cert_chain: Vec::new(),
            private_key_der: None,
            private_key_kind: crate::certificates::PrivateKeyKind::None,
            names: names.iter().map(|n| n.to_string()).collect(),
            tags: Vec::new(),
            managed,
            issuer_key: String::new(),
            hash: hash.to_string(),
            ocsp_response: None,
            ocsp_status: None,
            not_after: now + ChronoDuration::days(90),
            not_before: now - ChronoDuration::days(1),
            ari: None,
        }
    }

    fn make_expired_cert(names: &[&str], hash: &str, managed: bool) -> Certificate {
        let now = Utc::now();
        Certificate {
            cert_chain: Vec::new(),
            private_key_der: None,
            private_key_kind: crate::certificates::PrivateKeyKind::None,
            names: names.iter().map(|n| n.to_string()).collect(),
            tags: Vec::new(),
            managed,
            issuer_key: String::new(),
            hash: hash.to_string(),
            ocsp_response: None,
            ocsp_status: None,
            not_after: now - ChronoDuration::days(1),
            not_before: now - ChronoDuration::days(91),
            ari: None,
        }
    }

    #[tokio::test]
    async fn test_add_and_get_by_hash() {
        let cache = CertCache::new(CacheOptions::default());
        let cert = make_cert(&["example.com"], "hash1", true);
        cache.add(cert.clone()).await;

        let found = cache.get_by_hash("hash1").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().names, vec!["example.com".to_string()]);
    }

    #[tokio::test]
    async fn test_add_and_get_by_name() {
        let cache = CertCache::new(CacheOptions::default());
        let cert = make_cert(&["example.com", "www.example.com"], "hash1", true);
        cache.add(cert).await;

        let found = cache.get_by_name("example.com").await;
        assert!(found.is_some());

        let found = cache.get_by_name("www.example.com").await;
        assert!(found.is_some());

        let found = cache.get_by_name("other.com").await;
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_case_insensitive_lookup() {
        let cache = CertCache::new(CacheOptions::default());
        let cert = make_cert(&["Example.COM"], "hash1", true);
        cache.add(cert).await;

        let found = cache.get_by_name("example.com").await;
        assert!(found.is_some());

        let found = cache.get_by_name("EXAMPLE.COM").await;
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_wildcard_lookup() {
        let cache = CertCache::new(CacheOptions::default());
        let cert = make_cert(&["*.example.com"], "hash1", true);
        cache.add(cert).await;

        // Direct lookup by the wildcard name itself.
        let found = cache.get_by_name("*.example.com").await;
        assert!(found.is_some());

        // Lookup by a subdomain should match the wildcard.
        let found = cache.get_by_name("sub.example.com").await;
        assert!(found.is_some());

        // A sub-subdomain should not match a single-level wildcard via
        // label replacement at each position.
        // We replace each label individually, so
        // "a.b.example.com" tries "*.b.example.com", "a.*.example.com", etc.
        // Our wildcard cert is "*.example.com" so it won't match.
        let found = cache.get_by_name("a.b.example.com").await;
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_remove_by_hash() {
        let cache = CertCache::new(CacheOptions::default());
        let cert = make_cert(&["example.com"], "hash1", true);
        cache.add(cert).await;

        assert_eq!(cache.count().await, 1);

        cache.remove("hash1").await;

        assert_eq!(cache.count().await, 0);
        assert!(cache.get_by_hash("hash1").await.is_none());
        assert!(cache.get_by_name("example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_remove_many() {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(make_cert(&["a.com"], "h1", true)).await;
        cache.add(make_cert(&["b.com"], "h2", true)).await;
        cache.add(make_cert(&["c.com"], "h3", true)).await;

        assert_eq!(cache.count().await, 3);

        cache
            .remove_many(&["h1".to_string(), "h3".to_string()])
            .await;

        assert_eq!(cache.count().await, 1);
        assert!(cache.get_by_hash("h2").await.is_some());
    }

    #[tokio::test]
    async fn test_remove_managed() {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(make_cert(&["a.com"], "h1", true)).await;
        cache.add(make_cert(&["a.com"], "h2", false)).await;
        cache.add(make_cert(&["b.com"], "h3", true)).await;

        cache
            .remove_managed(&[SubjectIssuer {
                subject: "a.com".to_string(),
                issuer_key: String::new(),
            }])
            .await;

        // Only the managed cert for "a.com" should be removed.
        assert!(cache.get_by_hash("h1").await.is_none());
        assert!(cache.get_by_hash("h2").await.is_some()); // unmanaged, kept
        assert!(cache.get_by_hash("h3").await.is_some()); // different subject
    }

    #[tokio::test]
    async fn test_replace() {
        let cache = CertCache::new(CacheOptions::default());
        let old = make_cert(&["example.com"], "old_hash", true);
        cache.add(old).await;

        let new = make_cert(&["example.com", "www.example.com"], "new_hash", true);
        cache.replace("old_hash", new).await;

        assert!(cache.get_by_hash("old_hash").await.is_none());
        assert!(cache.get_by_hash("new_hash").await.is_some());
        assert!(cache.get_by_name("www.example.com").await.is_some());
    }

    #[tokio::test]
    async fn test_duplicate_add_merges_tags() {
        let cache = CertCache::new(CacheOptions::default());

        let mut cert1 = make_cert(&["example.com"], "hash1", true);
        cert1.tags = vec!["tag-a".to_string()];
        cache.add(cert1).await;

        let mut cert2 = make_cert(&["example.com"], "hash1", true);
        cert2.tags = vec!["tag-a".to_string(), "tag-b".to_string()];
        cache.add(cert2).await;

        // Should still be one certificate.
        assert_eq!(cache.count().await, 1);

        let found = cache.get_by_hash("hash1").await.unwrap();
        assert!(found.tags.contains(&"tag-a".to_string()));
        assert!(found.tags.contains(&"tag-b".to_string()));
    }

    #[tokio::test]
    async fn test_prefer_non_expired() {
        let cache = CertCache::new(CacheOptions::default());

        let expired = make_expired_cert(&["example.com"], "expired", true);
        let valid = make_cert(&["example.com"], "valid", true);

        cache.add(expired).await;
        cache.add(valid).await;

        let found = cache.get_by_name("example.com").await.unwrap();
        assert_eq!(found.hash, "valid");
    }

    #[tokio::test]
    async fn test_prefer_managed() {
        let cache = CertCache::new(CacheOptions::default());

        let unmanaged = make_cert(&["example.com"], "unmanaged", false);
        let managed = make_cert(&["example.com"], "managed", true);

        cache.add(unmanaged).await;
        cache.add(managed).await;

        let found = cache.get_by_name("example.com").await.unwrap();
        assert_eq!(found.hash, "managed");
    }

    #[tokio::test]
    async fn test_prefer_longer_lifetime() {
        let cache = CertCache::new(CacheOptions::default());
        let now = Utc::now();

        let mut short = make_cert(&["example.com"], "short", true);
        short.not_after = now + ChronoDuration::days(30);

        let mut long = make_cert(&["example.com"], "long", true);
        long.not_after = now + ChronoDuration::days(90);

        cache.add(short).await;
        cache.add(long).await;

        let found = cache.get_by_name("example.com").await.unwrap();
        assert_eq!(found.hash, "long");
    }

    #[tokio::test]
    async fn test_capacity_eviction() {
        let opts = CacheOptions {
            capacity: 2,
            ..Default::default()
        };
        let cache = CertCache::new(opts);

        cache.add(make_cert(&["a.com"], "h1", true)).await;
        cache.add(make_cert(&["b.com"], "h2", true)).await;

        // Cache is at capacity (2). Adding a third should evict one.
        cache.add(make_cert(&["c.com"], "h3", true)).await;

        assert_eq!(cache.count().await, 2);
        // h3 must exist since it was just added.
        assert!(cache.get_by_hash("h3").await.is_some());
    }

    #[tokio::test]
    async fn test_capacity_no_evict_unmanaged() {
        let opts = CacheOptions {
            capacity: 2,
            ..Default::default()
        };
        let cache = CertCache::new(opts);

        // Fill with unmanaged certs.
        cache.add(make_cert(&["a.com"], "h1", false)).await;
        cache.add(make_cert(&["b.com"], "h2", false)).await;

        // Adding a third: no managed cert to evict, so cache may grow beyond
        // capacity (eviction only targets managed certs).
        cache.add(make_cert(&["c.com"], "h3", true)).await;

        // All three should be present because eviction only targets managed
        // certs and there were none to evict.
        assert_eq!(cache.count().await, 3);
    }

    #[tokio::test]
    async fn test_get_managed_certificates() {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(make_cert(&["a.com"], "h1", true)).await;
        cache.add(make_cert(&["b.com"], "h2", false)).await;
        cache.add(make_cert(&["c.com"], "h3", true)).await;

        let managed = cache.get_managed_certificates().await;
        assert_eq!(managed.len(), 2);
    }

    #[tokio::test]
    async fn test_get_all() {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(make_cert(&["a.com"], "h1", true)).await;
        cache.add(make_cert(&["b.com"], "h2", false)).await;

        let all = cache.get_all().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_count_empty() {
        let cache = CertCache::new(CacheOptions::default());
        assert_eq!(cache.count().await, 0);
    }

    #[tokio::test]
    async fn test_stop_signal() {
        let cache = CertCache::new(CacheOptions::default());
        let mut rx = cache.subscribe_stop();

        assert!(!*rx.borrow());
        cache.stop();
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn test_all_matching_certificates() {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(make_cert(&["example.com"], "h1", true)).await;
        cache.add(make_cert(&["*.example.com"], "h2", true)).await;

        // "sub.example.com" should match the wildcard cert.
        let certs = cache.all_matching_certificates("sub.example.com").await;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hash, "h2");

        // "example.com" should match exact only.
        let certs = cache.all_matching_certificates("example.com").await;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].hash, "h1");
    }

    #[tokio::test]
    async fn test_event_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let add_count = Arc::new(AtomicUsize::new(0));
        let remove_count = Arc::new(AtomicUsize::new(0));

        let add_clone = Arc::clone(&add_count);
        let remove_clone = Arc::clone(&remove_count);

        let opts = CacheOptions {
            on_event: Some(Arc::new(move |event| match event {
                CacheEvent::Added { .. } => {
                    add_clone.fetch_add(1, Ordering::SeqCst);
                }
                CacheEvent::Removed { .. } => {
                    remove_clone.fetch_add(1, Ordering::SeqCst);
                }
                CacheEvent::Updated { .. } => {}
            })),
            ..Default::default()
        };

        let cache = CertCache::new(opts);
        cache.add(make_cert(&["a.com"], "h1", true)).await;
        cache.add(make_cert(&["b.com"], "h2", true)).await;
        cache.remove("h1").await;

        assert_eq!(add_count.load(Ordering::SeqCst), 2);
        assert_eq!(remove_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_normalize_options_defaults() {
        let opts = CacheOptions {
            renew_check_interval: Duration::ZERO,
            ocsp_check_interval: Duration::ZERO,
            ..Default::default()
        };
        let normalized = normalize_options(opts);
        assert_eq!(
            normalized.renew_check_interval,
            DEFAULT_RENEW_CHECK_INTERVAL
        );
        assert_eq!(normalized.ocsp_check_interval, DEFAULT_OCSP_CHECK_INTERVAL);
    }

    #[test]
    fn test_normalize_options_preserves_custom() {
        let custom = Duration::from_secs(42);
        let opts = CacheOptions {
            renew_check_interval: custom,
            ocsp_check_interval: custom,
            ..Default::default()
        };
        let normalized = normalize_options(opts);
        assert_eq!(normalized.renew_check_interval, custom);
        assert_eq!(normalized.ocsp_check_interval, custom);
    }

    #[test]
    fn test_select_best_empty() {
        assert!(select_best_certificate(vec![]).is_none());
    }

    #[test]
    fn test_select_best_single() {
        let cert = make_cert(&["example.com"], "h1", true);
        let selected = select_best_certificate(vec![cert.clone()]).unwrap();
        assert_eq!(selected.hash, "h1");
    }

    #[test]
    fn test_cache_options_debug() {
        let opts = CacheOptions::default();
        let debug_str = format!("{:?}", opts);
        assert!(debug_str.contains("CacheOptions"));
    }

    #[tokio::test]
    async fn shutdown_without_maintenance_returns_and_preserves_stop() {
        let cache = CertCache::new(CacheOptions::default());
        tokio::time::timeout(Duration::from_secs(1), cache.stop_and_wait())
            .await
            .unwrap();
        assert!(*cache.subscribe_stop().borrow());
        let guard = cache.maintenance_guard();
        assert!(*cache.subscribe_stop().borrow());
        drop(guard);
        cache.stop_and_wait().await;
    }

    #[tokio::test]
    async fn shutdown_waits_for_all_maintenance_guards() {
        let cache = CertCache::new(CacheOptions::default());
        let first = cache.maintenance_guard();
        let second = cache.maintenance_guard();
        let waiter = tokio::spawn({
            let cache = Arc::clone(&cache);
            async move {
                cache.stop_and_wait().await;
            }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(first);
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(second);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_wildcards_do_not_match_other_labels() {
        let cache = CertCache::new(CacheOptions::default());
        cache
            .add(make_cert(
                &["sub.*.com", "sub.example.*", "*.*.com", "*..example.com"],
                "invalid",
                true,
            ))
            .await;
        assert!(cache.get_by_name("sub.example.com").await.is_none());
        assert!(cache.get_by_name("sub..example.com").await.is_none());
        assert!(
            cache
                .all_matching_certificates("sub.example.com")
                .await
                .is_empty()
        );
        cache
            .add(make_cert(&["*.example.com"], "valid", true))
            .await;
        assert_eq!(
            cache.get_by_name("sub.example.com").await.unwrap().hash,
            "valid"
        );
        assert!(cache.get_by_name("deep.sub.example.com").await.is_none());
    }

    #[tokio::test]
    async fn event_callback_can_read_the_serving_cache() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = CertCache::new(CacheOptions::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let weak = Arc::downgrade(&cache);
        cache
            .set_options(CacheOptions {
                on_event: Some(Arc::new({
                    let calls = Arc::clone(&calls);
                    move |_| {
                        let cache = weak.upgrade().unwrap();
                        let _ = cache.resolve("example.com");
                        calls.fetch_add(1, Ordering::SeqCst);
                    }
                })),
                ..Default::default()
            })
            .await;
        cache.add(make_cert(&["example.com"], "old", true)).await;
        cache
            .replace("old", make_cert(&["example.com"], "new", true))
            .await;
        cache.remove("new").await;
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    fn assert_cache_indices(cache: &CertCache) {
        let state = cache.state.read().unwrap();
        let expected: HashSet<_> = state
            .certificates
            .iter()
            .filter(|(_, entry)| entry.certificate.managed)
            .map(|(hash, _)| hash)
            .collect();
        let actual: HashSet<_> = state.managed_hashes.iter().collect();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), state.managed_hashes.len());
        for (index, hash) in state.managed_hashes.iter().enumerate() {
            assert_eq!(state.certificates[hash].managed_index, Some(index));
        }
        for (hash, entry) in &state.certificates {
            assert_eq!(entry.managed_index.is_some(), entry.certificate.managed);
            for name in &entry.certificate.names {
                assert!(state.index[&name.to_lowercase()].contains(hash));
            }
        }
    }

    #[tokio::test]
    async fn indexed_removal_preserves_issuer_wildcard_and_unmanaged_semantics() {
        let cache = CertCache::new(CacheOptions::default());
        for (hash, names, managed, issuer) in [
            ("a", vec!["Example.com", "www.example.com"], true, "ca-a"),
            ("b", vec!["example.com"], true, "ca-b"),
            ("wildcard", vec!["*.example.com"], true, "ca-a"),
            ("unmanaged", vec!["example.com"], false, "ca-a"),
        ] {
            let mut cert = make_cert(&names, hash, managed);
            cert.issuer_key = issuer.into();
            cache.add(cert).await;
        }
        cache
            .remove_managed(&[
                SubjectIssuer {
                    subject: "EXAMPLE.COM".into(),
                    issuer_key: "ca-a".into(),
                },
                SubjectIssuer {
                    subject: "WWW.EXAMPLE.COM".into(),
                    issuer_key: "ca-a".into(),
                },
            ])
            .await;
        assert!(cache.get_by_hash("a").await.is_none());
        assert!(cache.get_by_hash("b").await.is_some());
        assert!(cache.get_by_hash("unmanaged").await.is_some());
        cache
            .remove_managed(&[SubjectIssuer {
                subject: "sub.example.com".into(),
                issuer_key: String::new(),
            }])
            .await;
        assert!(
            cache.get_by_hash("wildcard").await.is_some(),
            "removal is exact, not wildcard-expanded"
        );
        cache
            .remove_managed(&[SubjectIssuer {
                subject: "*.EXAMPLE.COM".into(),
                issuer_key: "ca-a".into(),
            }])
            .await;
        assert!(cache.get_by_hash("wildcard").await.is_none());
        cache
            .remove_managed(&[SubjectIssuer {
                subject: "example.com".into(),
                issuer_key: String::new(),
            }])
            .await;
        assert_eq!(cache.count().await, 1);
        assert!(cache.get_by_hash("unmanaged").await.is_some());
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn sampling_pool_tracks_swap_removal_and_managed_flag_replacement() {
        let cache = CertCache::new(CacheOptions {
            capacity: 3,
            ..Default::default()
        });
        for hash in ["a", "b", "c"] {
            cache
                .add(make_cert(&[&format!("{hash}.example.com")], hash, true))
                .await;
        }
        cache.remove("b").await; // Move the final pool member into the middle slot.
        assert_cache_indices(&cache);
        cache.remove("c").await; // Its new back-reference must now remove slot 1.
        assert_cache_indices(&cache);
        cache
            .replace("a", make_cert(&["a.example.com"], "a", false))
            .await;
        assert!(cache.maintenance_snapshot(true).is_empty());
        assert_cache_indices(&cache);
        for hash in ["d", "e"] {
            cache
                .add(make_cert(&[&format!("{hash}.example.com")], hash, false))
                .await;
        }
        cache.add(make_cert(&["f.example.com"], "f", true)).await;
        assert_eq!(
            cache.count().await,
            4,
            "unmanaged entries retain their documented protection from eviction"
        );
        cache
            .replace("a", make_cert(&["a.example.com"], "a", true))
            .await;
        assert!(
            cache.get_by_hash("f").await.is_none(),
            "only managed f can be evicted during promotion"
        );
        cache.add(make_cert(&["g.example.com"], "g", true)).await;
        assert!(cache.get_by_hash("a").await.is_none());
        assert!(cache.get_by_hash("d").await.is_some());
        assert!(cache.get_by_hash("e").await.is_some());
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn shared_snapshots_only_copy_changed_metadata() {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(make_cert(&["a.example.com"], "a", true)).await;
        cache.add(make_cert(&["b.example.com"], "b", false)).await;
        let old = cache.maintenance_snapshot(false);
        let managed = cache.maintenance_snapshot(true);
        assert_eq!(managed.len(), 1);
        let previous_a = old.iter().find(|cert| cert.hash == "a").unwrap();
        assert!(Arc::ptr_eq(previous_a, &managed[0]));
        let mut update = make_cert(&["a.example.com"], "a", true);
        update.tags = vec!["new-tag".into()];
        cache.add(update).await;
        let new = cache.maintenance_snapshot(false);
        let current_a = new.iter().find(|cert| cert.hash == "a").unwrap();
        assert!(!Arc::ptr_eq(previous_a, current_a));
        assert!(previous_a.tags.is_empty());
        assert_eq!(current_a.tags, vec!["new-tag"]);
        let previous_b = old.iter().find(|cert| cert.hash == "b").unwrap();
        let current_b = new.iter().find(|cert| cert.hash == "b").unwrap();
        assert!(Arc::ptr_eq(previous_b, current_b));
        let mut owned = cache.get_all().await;
        owned
            .iter_mut()
            .find(|cert| cert.hash == "a")
            .unwrap()
            .tags
            .clear();
        assert_eq!(cache.get_by_hash("a").await.unwrap().tags, vec!["new-tag"]);
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn shared_snapshot_ocsp_updates_preserve_signing_key_and_old_view() {
        let generated = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let cert = Certificate::from_pem(
            generated.cert.pem().as_bytes(),
            generated.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let cache = CertCache::new(CacheOptions::default());
        let hash = cert.hash.clone();
        cache.add(cert).await;
        let snapshot = cache.maintenance_snapshot(false);
        let before = cache.resolve("example.com").unwrap().key;
        cache
            .update_ocsp_if_present(
                &hash,
                Some(crate::ocsp::OcspStatus::Good),
                Some(vec![1, 2, 3]),
            )
            .await
            .unwrap();
        let after = cache.resolve("example.com").unwrap().key;
        assert!(snapshot[0].ocsp_response.is_none());
        assert!(before.ocsp.is_none());
        assert_eq!(after.ocsp, Some(vec![1, 2, 3]));
        assert!(
            Arc::ptr_eq(&before.key, &after.key),
            "OCSP mutation must not re-import the signing key"
        );
        assert_cache_indices(&cache);
    }

    /// Reproducible, in-memory debug-profile scaling probe. No network, disk,
    /// signing-key parsing, or unrelated tests are included in timed regions.
    /// Run with --ignored --exact --nocapture --test-threads=1. Each operation
    /// has one warm-up and seven recorded rounds; population/restoration is not
    /// timed. These synthetic certificates have a 6 KiB chain, 256-byte private
    /// key and 1 KiB staple, with no supported signing-key kind. The snapshot
    /// case calls the same shared snapshot path as maintenance; the baseline
    /// used its former owned `get_all()` path with identical fixtures/rounds.
    #[tokio::test]
    #[ignore = "manual cache scaling benchmark"]
    async fn cache_maintenance_benchmark() {
        use std::hint::black_box;
        use std::time::Instant;

        fn payload(index: usize) -> Certificate {
            let mut cert = make_cert(
                &[
                    &format!("host-{index}.example.com"),
                    &format!("alt-{index}.example.com"),
                ],
                &format!("{index:064x}"),
                true,
            );
            cert.issuer_key = "benchmark-ca".into();
            cert.cert_chain = vec![
                rustls::pki_types::CertificateDer::from(vec![0; 4096]),
                rustls::pki_types::CertificateDer::from(vec![0; 2048]),
            ];
            cert.private_key_der = Some(vec![1; 256]);
            cert.ocsp_response = Some(vec![2; 1024]);
            cert
        }

        async fn populated(size: usize, capacity: usize) -> Arc<CertCache> {
            let cache = CertCache::new(CacheOptions {
                capacity,
                ..Default::default()
            });
            for index in 0..size {
                cache.add(payload(index)).await;
            }
            cache
        }

        fn report(size: usize, operation: &str, mut samples: Vec<u128>) {
            samples.sort_unstable();
            println!(
                "CACHE_BENCH size={size} operation={operation} median_ns={} min_ns={} max_ns={} rounds={}",
                samples[samples.len() / 2],
                samples[0],
                samples[samples.len() - 1],
                samples.len()
            );
        }

        println!(
            "CACHE_BENCH profile=debug warmup=1 rounds=7 synthetic_payload_bytes=7424 timing_includes_result_drop=true"
        );
        for size in [1_000, 10_000] {
            let cache = populated(size, 0).await;
            let indices: Vec<_> = (0..128).map(|i| i * (size / 128)).collect();
            let subjects: Vec<_> = indices
                .iter()
                .map(|i| SubjectIssuer {
                    subject: format!("host-{i}.example.com"),
                    issuer_key: "benchmark-ca".into(),
                })
                .collect();
            let mut samples = Vec::new();
            for round in 0..8 {
                let start = Instant::now();
                cache.remove_managed(black_box(&subjects)).await;
                let elapsed = start.elapsed().as_nanos();
                assert_eq!(cache.count().await, size - indices.len());
                if round > 0 {
                    samples.push(elapsed);
                }
                for index in &indices {
                    cache.add(payload(*index)).await;
                }
            }
            report(size, "remove_128", samples);
            drop(cache);

            let cache = populated(size, size).await;
            let mut samples = Vec::new();
            for round in 0..8 {
                // Prepare inputs outside the timed critical sections.
                let incoming: Vec<_> = (0..64).map(|i| payload(size + round * 64 + i)).collect();
                let start = Instant::now();
                for cert in incoming {
                    cache.add(black_box(cert)).await;
                }
                let elapsed = start.elapsed().as_nanos();
                assert_eq!(cache.count().await, size);
                if round > 0 {
                    samples.push(elapsed);
                }
            }
            report(size, "evict_insert_64", samples);
            drop(cache);

            let cache = populated(size, 0).await;
            let mut samples = Vec::new();
            for round in 0..8 {
                let start = Instant::now();
                for _ in 0..4 {
                    let snapshot = cache.maintenance_snapshot(false);
                    assert_eq!(snapshot.len(), size);
                    black_box(snapshot);
                }
                let elapsed = start.elapsed().as_nanos();
                if round > 0 {
                    samples.push(elapsed);
                }
            }
            report(size, "maintenance_snapshot_4", samples);
        }
    }
}
