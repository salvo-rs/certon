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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
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
    ocsp_changed: watch::Sender<Option<DateTime<Utc>>>,
}

#[derive(Default)]
struct CacheState {
    certificates: HashMap<String, CachedCertificate>,
    index: HashMap<String, Vec<String>>,
    revoked_leaf_hashes: HashSet<String>,
    /// Dense managed-only sampling pool; each entry stores its back-reference.
    managed_hashes: Vec<String>,
    /// One indexed effective deadline per scheduled certificate.
    ocsp_deadlines: BTreeMap<DateTime<Utc>, HashSet<String>>,
}

struct CachedCertificate {
    leaf_hash: Option<String>,
    certificate: Arc<Certificate>,
    key: Option<Arc<CertifiedKey>>,
    unstapled_key: Option<Arc<CertifiedKey>>,
    ocsp_validity: Option<OcspValidity>,
    ocsp_retry_after: Option<DateTime<Utc>>,
    managed_index: Option<usize>,
}

#[derive(Clone, Copy)]
struct OcspValidity {
    expires_at: DateTime<Utc>,
    refresh_at: DateTime<Utc>,
}

impl OcspValidity {
    async fn for_response(raw: &[u8], cert: &Certificate) -> Option<Self> {
        let response = crate::ocsp::parse_ocsp_response_for_cert_chain(raw, &cert.cert_chain)
            .await
            .ok()?;
        if response.status != crate::ocsp::OcspStatus::Good {
            return None;
        }
        let expires_at = response.next_update.unwrap_or_else(|| {
            response.this_update + chrono::Duration::hours(crate::ocsp::DEFAULT_OCSP_LIFETIME_HOURS)
        });
        Some(Self {
            expires_at,
            refresh_at: response.this_update + (expires_at - response.this_update) / 2,
        })
    }
}

struct PreparedKey {
    key: Option<Arc<CertifiedKey>>,
    unstapled: Option<Arc<CertifiedKey>>,
    validity: Option<OcspValidity>,
    retry_after: Option<DateTime<Utc>>,
}

impl PreparedKey {
    async fn for_certificate(cert: &Certificate) -> Self {
        let validity = match &cert.ocsp_response {
            Some(raw) => OcspValidity::for_response(raw, cert).await,
            None => None,
        };
        Self::new(cert_to_certified_key(cert).ok(), validity)
    }

    fn new(mut key: Option<Arc<CertifiedKey>>, validity: Option<OcspValidity>) -> Self {
        let unstapled = key.as_ref().map(|key| {
            if key.ocsp.is_none() {
                return Arc::clone(key);
            }
            let mut container = key.as_ref().clone();
            container.ocsp = None;
            Arc::new(container)
        });
        if validity.is_none() {
            key = unstapled.clone();
        }
        Self {
            key,
            unstapled,
            validity,
            retry_after: None,
        }
    }
}

impl CachedCertificate {
    fn serving_key(&self, now: DateTime<Utc>) -> Option<&Arc<CertifiedKey>> {
        if self.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked) {
            return None;
        }
        if self
            .ocsp_validity
            .is_some_and(|validity| now < validity.expires_at)
        {
            self.key.as_ref()
        } else {
            self.unstapled_key.as_ref()
        }
    }

    fn needs_ocsp(&self, now: DateTime<Utc>) -> bool {
        self.ocsp_validity
            .is_none_or(|validity| now >= validity.refresh_at)
    }

    fn ocsp_deadline(&self) -> Option<DateTime<Utc>> {
        match (self.ocsp_validity, self.ocsp_retry_after) {
            (Some(validity), Some(retry)) => Some(validity.refresh_at.max(retry)),
            (Some(validity), None) => Some(validity.refresh_at),
            (None, retry) => retry,
        }
    }
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

/// Keep a true cache miss distinct from cached, client-incompatible keys.
pub(crate) struct CachedKeyLookup {
    pub matched: bool,
    pub selected: Option<CachedKey>,
}

pub(crate) struct CachedKeyCandidate {
    pub certificate: Arc<Certificate>,
    pub key: CachedKey,
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
    fn next_ocsp_deadline(&self) -> Option<DateTime<Utc>> {
        self.ocsp_deadlines
            .first_key_value()
            .map(|(deadline, _)| *deadline)
    }

    fn change_ocsp_deadline(
        &mut self,
        hash: &str,
        old: Option<DateTime<Utc>>,
        new: Option<DateTime<Utc>>,
    ) {
        if old == new {
            return;
        }
        if let Some(old) = old
            && let Some(hashes) = self.ocsp_deadlines.get_mut(&old)
        {
            hashes.remove(hash);
            if hashes.is_empty() {
                self.ocsp_deadlines.remove(&old);
            }
        }
        if let Some(new) = new {
            self.ocsp_deadlines
                .entry(new)
                .or_default()
                .insert(hash.to_owned());
        }
    }

    fn remove(&mut self, hash: &str) -> Option<CacheEvent> {
        let entry = self.certificates.remove(hash)?;
        self.change_ocsp_deadline(hash, entry.ocsp_deadline(), None);
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
        key: PreparedKey,
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
            if cert.managed && !existing.certificate.managed {
                let old_names = existing.certificate.names.clone();
                let current = Arc::make_mut(&mut existing.certificate);
                current.managed = true;
                current.issuer_key = cert.issuer_key.clone();
                // A manager puts its canonical store alias first. Preserve
                // that order for maintenance while retaining the existing
                // signing key, tags and OCSP state (including sticky Revoked).
                current.names = cert.names.clone();
                existing.managed_index = Some(self.managed_hashes.len());
                self.managed_hashes.push(hash.clone());
                for name in old_names {
                    let name = name.to_lowercase();
                    if let Some(hashes) = self.index.get_mut(&name) {
                        hashes.retain(|candidate| candidate != &hash);
                        if hashes.is_empty() {
                            self.index.remove(&name);
                        }
                    }
                }
                for name in &current.names {
                    let hashes = self.index.entry(name.to_lowercase()).or_default();
                    if !hashes.contains(&hash) {
                        hashes.push(hash.clone());
                    }
                }
            }
            for tag in &cert.tags {
                if !existing.certificate.tags.contains(tag) {
                    Arc::make_mut(&mut existing.certificate)
                        .tags
                        .push(tag.clone());
                }
            }
            events.push(CacheEvent::Updated {
                names: existing.certificate.names.clone(),
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
        self.change_ocsp_deadline(
            &hash,
            None,
            key.validity
                .map(|validity| validity.refresh_at)
                .into_iter()
                .chain(key.retry_after)
                .max(),
        );
        self.certificates.insert(
            hash,
            CachedCertificate {
                leaf_hash,
                certificate: Arc::new(cert),
                key: key.key,
                unstapled_key: key.unstapled,
                ocsp_validity: key.validity,
                ocsp_retry_after: key.retry_after,
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
            ocsp_changed: watch::channel(None).0,
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

    pub(crate) fn subscribe_ocsp(&self) -> watch::Receiver<Option<DateTime<Utc>>> {
        self.ocsp_changed.subscribe()
    }

    fn notify_ocsp_schedule(&self) {
        // Keep the snapshot and notification ordered with mutations. The watch
        // wakes tasks without polling their futures under this read lock.
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let deadline = state.next_ocsp_deadline();
        self.ocsp_changed.send_if_modified(|current| {
            if *current == deadline {
                false
            } else {
                *current = deadline;
                true
            }
        });
    }

    pub(crate) fn next_ocsp_deadline(&self) -> Option<DateTime<Utc>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .next_ocsp_deadline()
    }

    pub(crate) fn ocsp_refresh_due(&self, hash: &str) -> bool {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state.certificates.get(hash).is_some_and(|entry| {
            entry
                .ocsp_deadline()
                .is_none_or(|deadline| Utc::now() >= deadline)
        })
    }

    pub(crate) fn ocsp_snapshot(&self, periodic: bool) -> Vec<Arc<Certificate>> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        if periodic {
            state
                .certificates
                .values()
                .map(|entry| Arc::clone(&entry.certificate))
                .collect()
        } else {
            state
                .ocsp_deadlines
                .range(..=Utc::now())
                .flat_map(|(_, hashes)| hashes)
                .filter_map(|hash| state.certificates.get(hash))
                .map(|entry| Arc::clone(&entry.certificate))
                .collect()
        }
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
    /// A managed input takes over an unmanaged entry's management metadata and
    /// name order atomically, retaining its signing key and OCSP state. Repeated
    /// imports cannot downgrade an entry that is already managed.
    /// Signing keys and signed OCSP deadlines are prepared outside the cache
    /// lock. Invalid or expired raw staples are omitted from serving keys.
    /// Leaf-only chains may require fetching the issuer through AIA to verify
    /// a supplied staple. Quarantined
    /// leaves are ignored; Result-returning unmanaged helpers report rejection.
    /// Time-invalid entries remain available as lifecycle metadata, but are
    /// excluded from TLS selection until their validity period begins.
    pub async fn add(&self, cert: Certificate) {
        let _ = self.publish_prepared(None, cert, None).await;
    }

    /// Managed publication rechecks time at the write-lock linearization point,
    /// after any asynchronous OCSP/AIA preparation has finished.
    pub(crate) async fn add_managed(&self, cert: Certificate, domain: &str) -> Result<()> {
        self.publish_prepared(None, cert, Some(domain)).await
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
        self.notify_ocsp_schedule();
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
        self.notify_ocsp_schedule();
        dispatch_events(&options, events);
    }

    /// Replace metadata and the prebuilt serving key in one critical section.
    pub async fn replace(&self, old_hash: &str, new_cert: Certificate) {
        let _ = self.publish_prepared(Some(old_hash), new_cert, None).await;
    }

    pub(crate) async fn replace_managed(
        &self,
        old_hash: &str,
        cert: Certificate,
        domain: &str,
    ) -> Result<()> {
        self.publish_prepared(Some(old_hash), cert, Some(domain))
            .await
    }

    async fn publish_prepared(
        &self,
        old_hash: Option<&str>,
        mut cert: Certificate,
        domain: Option<&str>,
    ) -> Result<()> {
        // Keep a version token while preparation awaits. Holding this Arc makes
        // any concurrent OCSP metadata write use copy-on-write, so pointer
        // identity detects intervening updates without a separate generation.
        let original = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .certificates
            .get(&cert.hash)
            .map(|entry| Arc::clone(&entry.certificate));
        let mut key = PreparedKey::for_certificate(&cert).await;
        let leaf_hash = crate::storage::certificate_leaf_hash(&cert);
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut events = Vec::new();
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            if let Some(domain) = domain {
                let now = Utc::now();
                if cert.not_before > now {
                    return Err(crate::error::CertError::NotYetValid(domain.to_owned()).into());
                }
                if now >= cert.not_after {
                    return Err(crate::error::CertError::Expired(domain.to_owned()).into());
                }
            }
            if leaf_hash
                .as_ref()
                .is_some_and(|hash| state.revoked_leaf_hashes.contains(hash))
            {
                return Err(crate::error::CertError::Revoked(
                    "certificate leaf is quarantined in this cache".into(),
                )
                .into());
            }
            // Reject invalid managed input before removing the old working leaf.
            if old_hash == Some(cert.hash.as_str())
                && let Some(current) = state.certificates.get(&cert.hash)
                && (current.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                    || original
                        .as_ref()
                        .is_none_or(|original| !Arc::ptr_eq(original, &current.certificate)))
            {
                // Preparation may await AIA while a newer OCSP update arrives.
                // Replacing the same leaf changes management metadata, not its
                // current status, serving containers or refresh schedule.
                cert.ocsp_status = current.certificate.ocsp_status;
                cert.ocsp_response = current.certificate.ocsp_response.clone();
                key = PreparedKey {
                    key: current.key.clone(),
                    unstapled: current.unstapled_key.clone(),
                    validity: current.ocsp_validity,
                    retry_after: current.ocsp_retry_after,
                };
            }
            if let Some(old_hash) = old_hash
                && let Some(event) = state.remove(old_hash)
            {
                events.push(event);
            }
            state.add(cert, key, leaf_hash, &options, &mut events);
        }
        self.notify_ocsp_schedule();
        dispatch_events(&options, events);
        Ok(())
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
        self.notify_ocsp_schedule();
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
        let certificate = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            Arc::clone(&state.certificates.get(hash)?.certificate)
        };
        let validity = match &response {
            Some(raw) => OcspValidity::for_response(raw, &certificate).await,
            None => None,
        };
        drop(certificate);
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (event, published) = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let current = state.certificates.get_mut(hash)?;
            let old_deadline = current.ocsp_deadline();
            let was_scheduled = old_deadline.is_some();
            let keep_revoked = current.certificate.ocsp_status
                == Some(crate::ocsp::OcspStatus::Revoked)
                && status != Some(crate::ocsp::OcspStatus::Revoked);
            if !keep_revoked {
                let certificate = Arc::make_mut(&mut current.certificate);
                certificate.ocsp_status = status;
                certificate.ocsp_response = response.clone();
                current.key = current.unstapled_key.as_ref().map(|key| {
                    if validity.is_none() {
                        return Arc::clone(key);
                    }
                    let mut container = key.as_ref().clone();
                    container.ocsp = response;
                    Arc::new(container)
                });
                current.ocsp_validity = validity;
            }
            // Even a rejected stale response consumed a refresh attempt. Keep
            // sticky revocation, but move its due timer forward to avoid an
            // immediate retry loop when the responder fails or returns Good.
            let validity = current.ocsp_validity;
            current.ocsp_retry_after = if validity.is_some() || was_scheduled {
                let now = Utc::now();
                let delay = validity.map_or(chrono::Duration::seconds(30), |validity| {
                    ((validity.expires_at - now) / 2)
                        .clamp(chrono::Duration::seconds(1), chrono::Duration::seconds(30))
                });
                Some(now + delay)
            } else {
                None
            };
            let new_deadline = current.ocsp_deadline();
            let result = (
                CacheEvent::Updated {
                    names: current.certificate.names.clone(),
                    hash: hash.to_owned(),
                },
                OcspUpdateState::from(current.certificate.as_ref()),
            );
            state.change_ocsp_deadline(hash, old_deadline, new_deadline);
            result
        };
        self.notify_ocsp_schedule();
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
    /// Expiry checks use validated metadata and a prebuilt unstapled container;
    /// they do not parse DER, verify signatures, or copy the signing key.
    pub(crate) fn resolve(&self, name: &str) -> Option<CachedKey> {
        self.resolve_with_filter(name, |_| true).selected
    }

    /// Filter time-invalid and client-incompatible keys before preferences.
    pub(crate) fn resolve_with_filter(
        &self,
        name: &str,
        accepts: impl Fn(&CertifiedKey) -> bool,
    ) -> CachedKeyLookup {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        let candidates = state.matching(name);
        let matched = !candidates.is_empty();
        let selected = candidates
            .into_iter()
            .filter(|e| e.certificate.not_before <= now && now < e.certificate.not_after)
            .filter(|e| e.serving_key(now).is_some_and(|key| accepts(key)))
            .min_by(|a, b| compare_certificates(&a.certificate, &b.certificate, now))
            .and_then(|entry| {
                Some(CachedKey {
                    key: Arc::clone(entry.serving_key(now)?),
                    hash: entry.certificate.hash.clone(),
                    needs_ocsp: entry.needs_ocsp(now),
                })
            });
        CachedKeyLookup { matched, selected }
    }

    /// An immutable selection snapshot. User hooks must run after this returns,
    /// without the cache lock, and need no private-key or certificate byte copy.
    pub(crate) fn selection_candidates(
        &self,
        name: &str,
        accepts: impl Fn(&CertifiedKey) -> bool,
    ) -> (bool, Vec<CachedKeyCandidate>) {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let matches = state.matching(name);
        let matched = !matches.is_empty();
        let now = Utc::now();
        let mut candidates: Vec<_> = matches
            .into_iter()
            .filter(|entry| {
                entry.certificate.not_before <= now && now < entry.certificate.not_after
            })
            .filter(|entry| entry.serving_key(now).is_some_and(|key| accepts(key)))
            .filter_map(|entry| {
                Some(CachedKeyCandidate {
                    certificate: Arc::clone(&entry.certificate),
                    key: CachedKey {
                        key: Arc::clone(entry.serving_key(now)?),
                        hash: entry.certificate.hash.clone(),
                        needs_ocsp: entry.needs_ocsp(now),
                    },
                })
            })
            .collect();
        drop(state);
        candidates.sort_by(|a, b| compare_certificates(&a.certificate, &b.certificate, now));
        (matched, candidates)
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
        let key = PreparedKey::new(cert_to_certified_key(&cert).ok(), None);
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
        self.notify_ocsp_schedule();
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
pub(crate) mod tests {
    pub(crate) fn signed_certificate() -> (Certificate, rcgen::KeyPair) {
        let (chain, issuer, key) = crate::ocsp::tests::signed_chain();
        let pem: String = chain
            .iter()
            .map(|der| ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.as_ref())))
            .collect();
        (
            Certificate::from_pem(pem.as_bytes(), key.as_bytes()).unwrap(),
            issuer,
        )
    }

    pub(crate) fn signed_staple(
        cert: &Certificate,
        issuer: &rcgen::KeyPair,
        seconds: i64,
    ) -> Vec<u8> {
        crate::ocsp::tests::signed_response(
            &cert.cert_chain,
            issuer,
            0,
            Utc::now(),
            Utc::now() + chrono::Duration::seconds(seconds),
        )
    }

    #[tokio::test]
    async fn ocsp_index_is_bounded_and_untracked_imports_do_not_wake_maintenance() {
        let cache = CertCache::new(CacheOptions::default());
        let mut changes = cache.subscribe_ocsp();
        for index in 0..1000 {
            cache
                .add(make_cert(
                    &[&format!("host-{index}.example.com")],
                    &index.to_string(),
                    false,
                ))
                .await;
        }
        assert!(!changes.has_changed().unwrap());
        assert!(cache.next_ocsp_deadline().is_none());
        let (mut cert, issuer) = signed_certificate();
        cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(signed_staple(&cert, &issuer, 3600));
        let hash = cert.hash.clone();
        cache.add(cert.clone()).await;
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        for index in 0..20 {
            let response = signed_staple(&cert, &issuer, 4000 + index);
            cache
                .update_ocsp_if_present(&hash, Some(crate::ocsp::OcspStatus::Good), Some(response))
                .await
                .unwrap();
            let state = cache.state.read().unwrap();
            let records: usize = state.ocsp_deadlines.values().map(HashSet::len).sum();
            assert_eq!(records, 1, "an old deadline survived an OCSP update");
            assert_eq!(
                state.next_ocsp_deadline(),
                state.certificates[&hash].ocsp_deadline()
            );
        }
        changes.borrow_and_update();
        cache
            .add(make_cert(&["untracked.example.com"], "untracked", false))
            .await;
        assert!(!changes.has_changed().unwrap());
        cache.remove(&hash).await;
        assert!(cache.next_ocsp_deadline().is_none());
        assert!(cache.state.read().unwrap().ocsp_deadlines.is_empty());
        cache.add(cert).await;
        let leaf_hash = cache.state.read().unwrap().certificates[&hash]
            .leaf_hash
            .clone()
            .unwrap();
        cache.deny_revoked_certificate(&leaf_hash).await;
        assert!(cache.state.read().unwrap().ocsp_deadlines.is_empty());
        assert!(cache.ocsp_snapshot(false).is_empty());
    }

    #[tokio::test]
    async fn verified_revoked_leaves_are_metadata_only_and_a_normal_sibling_can_serve() {
        async fn handshake(
            cache: Arc<CertCache>,
            trusted_root: rustls::pki_types::CertificateDer<'static>,
        ) -> Option<Vec<u8>> {
            crate::install_default_crypto_provider();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(trusted_root).unwrap();
            let client = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(crate::handshake::CertResolver::new(cache)));
            let (server_io, client_io) = tokio::io::duplex(16384);
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
            let (server, client) = tokio::join!(
                acceptor.accept(server_io),
                connector.connect("ocsp.example.com".try_into().unwrap(), client_io)
            );
            server.ok()?;
            Some(client.ok()?.get_ref().1.peer_certificates()?[0].to_vec())
        }
        for sibling in [false, true] {
            let (mut cert, issuer) = signed_certificate();
            cert.managed = true;
            let hash = cert.hash.clone();
            let cache = CertCache::new(CacheOptions::default());
            cache.add(cert.clone()).await;
            // Use a genuinely signed revoked response to exercise the same
            // validation that feeds maintenance's cache update.
            let response = crate::ocsp::tests::signed_response(
                &cert.cert_chain,
                &issuer,
                1,
                Utc::now(),
                Utc::now() + chrono::Duration::hours(1),
            );
            let parsed =
                crate::ocsp::parse_ocsp_response_for_cert_chain(&response, &cert.cert_chain)
                    .await
                    .unwrap();
            assert_eq!(parsed.status, crate::ocsp::OcspStatus::Revoked);
            cache
                .update_ocsp_if_present(&hash, Some(parsed.status), None)
                .await
                .unwrap();
            let (mut normal, _) = signed_certificate();
            // Prefer the revoked entry by expiry if filtering happens too late.
            normal.not_after = cert.not_after - chrono::Duration::hours(1);
            if sibling {
                cache.add(normal.clone()).await;
            }
            assert_eq!(
                cache.get_by_hash(&hash).await.unwrap().ocsp_status,
                Some(crate::ocsp::OcspStatus::Revoked)
            );
            assert!(
                cache
                    .maintenance_snapshot(true)
                    .iter()
                    .any(|entry| entry.hash == hash)
            );
            let lookup = cache.resolve_with_filter("ocsp.example.com", |_| true);
            assert!(lookup.matched);
            let (matched, candidates) = cache.selection_candidates("ocsp.example.com", |_| true);
            assert!(matched);
            if sibling {
                assert_eq!(lookup.selected.unwrap().hash, normal.hash);
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].key.hash, normal.hash);
                assert_eq!(
                    handshake(cache, normal.cert_chain[1].clone())
                        .await
                        .unwrap(),
                    normal.cert_chain[0].as_ref()
                );
            } else {
                assert!(
                    lookup.selected.is_none(),
                    "known revoked leaf remained available for TLS"
                );
                assert!(candidates.is_empty());
                assert!(handshake(cache, cert.cert_chain[1].clone()).await.is_none());
            }
        }
    }

    #[tokio::test]
    async fn prepared_publication_preserves_current_status_and_leaf_quarantine_during_aia_wait() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for scenario in 0..4 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/issuer", listener.local_addr().unwrap());
            let issuer_key = rcgen::KeyPair::generate().unwrap();
            let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let ca_cert = ca.self_signed(&issuer_key).unwrap();
            let issuer = rcgen::Issuer::new(ca, &issuer_key);
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["ocsp.example.com".into()]).unwrap();
            let wrap =
                |tag: u8, value: &[u8]| [vec![tag, value.len() as u8], value.to_vec()].concat();
            let access = wrap(
                0x30,
                &[
                    vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02],
                    wrap(0x86, url.as_bytes()),
                ]
                .concat(),
            );
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    wrap(0x30, &access),
                ));
            let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
            let mut cert =
                Certificate::from_pem(leaf.pem().as_bytes(), leaf_key.serialize_pem().as_bytes())
                    .unwrap();
            cert.managed = true;
            let hash = cert.hash.clone();
            let cache = CertCache::new(CacheOptions::default());
            let incoming_leaf = crate::storage::certificate_leaf_hash(&cert).unwrap();
            let old = if scenario == 0 || scenario == 3 {
                cert.clone()
            } else {
                signed_certificate().0
            };
            let old_hash = old.hash.clone();
            let old_leaf = crate::storage::certificate_leaf_hash(&old).unwrap();
            cache.add(old).await;
            cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
            cert.ocsp_response = Some(crate::ocsp::tests::signed_response(
                &[leaf.der().clone(), ca_cert.der().clone()],
                &issuer_key,
                0,
                Utc::now(),
                Utc::now() + chrono::Duration::hours(1),
            ));
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let server = tokio::spawn({
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = [0; 4096];
                    assert!(socket.read(&mut request).await.unwrap() > 0);
                    entered.notify_one();
                    release.notified().await;
                    socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            ca_cert.der().len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                    socket.write_all(ca_cert.der()).await.unwrap();
                }
            });
            let worker = tokio::spawn({
                let cache = cache.clone();
                let hash = old_hash.clone();
                async move { cache.replace_managed(&hash, cert, "ocsp.example.com").await }
            });
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            let expected_status = if scenario == 3 {
                crate::ocsp::OcspStatus::Unknown
            } else {
                crate::ocsp::OcspStatus::Revoked
            };
            match scenario {
                0 | 3 => {
                    cache
                        .update_ocsp_if_present(&hash, Some(expected_status), None)
                        .await
                        .unwrap();
                }
                1 => cache.deny_revoked_certificate(&incoming_leaf).await,
                2 => cache.deny_revoked_certificate(&old_leaf).await,
                _ => unreachable!(),
            }
            let current_key = cache
                .state
                .read()
                .unwrap()
                .certificates
                .get(&old_hash)
                .and_then(|entry| entry.key.clone());
            release.notify_one();
            let result = worker.await.unwrap();
            server.await.unwrap();
            if scenario == 1 {
                assert!(matches!(
                    result,
                    Err(crate::Error::Cert(crate::error::CertError::Revoked(_)))
                ));
                assert!(cache.get_by_hash(&hash).await.is_none());
                assert!(cache.get_by_hash(&old_hash).await.is_some());
                assert!(Arc::ptr_eq(
                    current_key.as_ref().unwrap(),
                    &cache.resolve("ocsp.example.com").unwrap().key
                ));
                continue;
            }
            result.unwrap();
            let current = cache.get_by_hash(&hash).await.unwrap();
            if scenario == 2 {
                assert!(cache.get_by_hash(&old_hash).await.is_none());
                assert_eq!(current.ocsp_status, Some(crate::ocsp::OcspStatus::Good));
                assert!(
                    cache
                        .resolve("ocsp.example.com")
                        .unwrap()
                        .key
                        .ocsp
                        .is_some()
                );
                continue;
            }
            assert_eq!(current.ocsp_status, Some(expected_status));
            assert!(current.ocsp_response.is_none());
            assert!(Arc::ptr_eq(
                current_key.as_ref().unwrap(),
                cache.state.read().unwrap().certificates[&hash]
                    .key
                    .as_ref()
                    .unwrap()
            ));
            if scenario == 0 {
                assert!(cache.resolve("ocsp.example.com").is_none());
            }
            assert!(cache.next_ocsp_deadline().is_none());
        }
    }

    #[tokio::test]
    async fn rejected_stale_ocsp_updates_advance_the_sticky_revocation_retry_deadline() {
        let cache = CertCache::new(CacheOptions::default());
        let (mut cert, issuer) = signed_certificate();
        cert.ocsp_response = Some(signed_staple(&cert, &issuer, 120));
        cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
        let hash = cert.hash.clone();
        cache.add(cert).await;
        cache
            .update_ocsp_if_present(&hash, Some(crate::ocsp::OcspStatus::Revoked), None)
            .await
            .unwrap();
        for status in [None, Some(crate::ocsp::OcspStatus::Good)] {
            {
                let mut state = cache.state.write().unwrap();
                let entry = state.certificates.get_mut(&hash).unwrap();
                let old = entry.ocsp_deadline();
                entry.ocsp_retry_after = Some(Utc::now() - chrono::Duration::seconds(1));
                let new = entry.ocsp_deadline();
                state.change_ocsp_deadline(&hash, old, new);
            }
            cache.notify_ocsp_schedule();
            let mut changed = cache.subscribe_ocsp();
            changed.borrow_and_update();
            let current = cache
                .update_ocsp_if_present(&hash, status, None)
                .await
                .unwrap();
            assert_eq!(current.ocsp_status, Some(crate::ocsp::OcspStatus::Revoked));
            assert!(
                cache.next_ocsp_deadline().unwrap() > Utc::now(),
                "rejected response left an already-due deadline and will spin"
            );
            assert!(!cache.ocsp_refresh_due(&hash));
            assert!(changed.has_changed().unwrap());
            assert!(cache.resolve("ocsp.example.com").is_none());
        }
    }

    #[tokio::test]
    async fn managed_publication_rechecks_time_after_real_aia_wait_before_replacing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for replacing in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/issuer", listener.local_addr().unwrap());
            let issuer_key = rcgen::KeyPair::generate().unwrap();
            let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let ca_cert = ca.self_signed(&issuer_key).unwrap();
            let issuer = rcgen::Issuer::new(ca, &issuer_key);
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["ocsp.example.com".into()]).unwrap();
            params.not_before = rcgen::date_time_ymd(1970, 1, 1);
            params.not_after = params.not_before
                + Duration::from_secs((Utc::now().timestamp() + 2).try_into().unwrap());
            let wrap = |tag: u8, value: &[u8]| {
                assert!(value.len() < 128);
                [vec![tag, value.len() as u8], value.to_vec()].concat()
            };
            let access = wrap(
                0x30,
                &[
                    vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02],
                    wrap(0x86, url.as_bytes()),
                ]
                .concat(),
            );
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    wrap(0x30, &access),
                ));
            let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
            let mut incoming =
                Certificate::from_pem(leaf.pem().as_bytes(), leaf_key.serialize_pem().as_bytes())
                    .unwrap();
            incoming.managed = true;
            incoming.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
            incoming.ocsp_response = Some(crate::ocsp::tests::signed_response(
                &[leaf.der().clone(), ca_cert.der().clone()],
                &issuer_key,
                0,
                Utc::now(),
                Utc::now() + chrono::Duration::hours(1),
            ));
            assert!(!incoming.expired());
            let expires = incoming.not_after + chrono::Duration::seconds(1);
            let hash = incoming.hash.clone();
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let server = tokio::spawn({
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = [0; 4096];
                    assert!(socket.read(&mut request).await.unwrap() > 0);
                    entered.notify_one();
                    release.notified().await;
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", ca_cert.der().len()).as_bytes()).await.unwrap();
                    socket.write_all(ca_cert.der()).await.unwrap();
                }
            });
            let cache = CertCache::new(CacheOptions::default());
            let (old, _) = signed_certificate();
            let root = old.cert_chain[1].clone();
            let old_leaf = old.cert_chain[0].clone();
            let old_hash = old.hash.clone();
            cache.add(old).await;
            let before = cache.resolve("ocsp.example.com").unwrap().key;
            let worker = tokio::spawn({
                let cache = cache.clone();
                let old_hash = old_hash.clone();
                let incoming = incoming.clone();
                async move {
                    if replacing {
                        cache
                            .replace_managed(&old_hash, incoming, "ocsp.example.com")
                            .await
                    } else {
                        cache.add_managed(incoming, "ocsp.example.com").await
                    }
                }
            });
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            assert!(cache.get_by_hash(&hash).await.is_none());
            assert!(Arc::ptr_eq(
                &before,
                &cache.resolve("ocsp.example.com").unwrap().key
            ));
            tokio::time::sleep(
                (expires - Utc::now()).to_std().unwrap_or_default() + Duration::from_millis(20),
            )
            .await;
            release.notify_one();
            let error = worker.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                crate::Error::Cert(crate::error::CertError::Expired(_))
            ));
            server.await.unwrap();
            assert!(cache.get_by_hash(&hash).await.is_none());
            assert!(cache.get_by_hash(&old_hash).await.is_some());
            assert!(Arc::ptr_eq(
                &before,
                &cache.resolve("ocsp.example.com").unwrap().key
            ));
            crate::install_default_crypto_provider();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(root).unwrap();
            let client = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(crate::handshake::CertResolver::new(cache.clone())));
            let (server_io, client_io) = tokio::io::duplex(16384);
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
            let (server_tls, client_tls) = tokio::join!(
                acceptor.accept(server_io),
                connector.connect("ocsp.example.com".try_into().unwrap(), client_io)
            );
            server_tls.unwrap();
            assert_eq!(
                client_tls.unwrap().get_ref().1.peer_certificates().unwrap()[0],
                old_leaf
            );
            // The public low-level API intentionally retains historical-import
            // semantics, independent of guarded managed publication.
            incoming.ocsp_response = None;
            cache.add(incoming).await;
            assert!(cache.get_by_hash(&hash).await.is_some());
        }
    }

    #[tokio::test]
    async fn live_ocsp_expiry_omits_staple_without_reimporting_the_signing_key() {
        let (mut cert, issuer) = signed_certificate();
        let raw = signed_staple(&cert, &issuer, 4);
        cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(raw.clone());
        let name = cert.names[0].clone();
        let hash = cert.hash.clone();
        let cache = CertCache::new(CacheOptions::default());
        cache.add(cert).await;
        let before = cache.resolve(&name).unwrap().key;
        assert_eq!(before.ocsp.as_ref(), Some(&raw));
        for _ in 0..50 {
            assert!(Arc::ptr_eq(&before, &cache.resolve(&name).unwrap().key));
        }
        let expires = cache.state.read().unwrap().certificates[&hash]
            .ocsp_validity
            .unwrap()
            .expires_at;
        tokio::time::sleep(
            (expires - Utc::now()).to_std().unwrap_or_default() + Duration::from_millis(20),
        )
        .await;
        let after = cache.resolve(&name).unwrap();
        assert!(after.key.ocsp.is_none());
        assert!(after.needs_ocsp);
        assert!(Arc::ptr_eq(&before.key, &after.key.key));
        assert_eq!(
            cache.get_by_hash(&hash).await.unwrap().ocsp_response,
            Some(raw)
        );
        // An already captured handshake has an immutable snapshot, just as it
        // does across renewal/removal. New lookups must use the unstapled key.
        assert!(before.ocsp.is_some());
    }

    #[tokio::test]
    async fn verified_staple_without_next_update_uses_the_existing_24_hour_limit() {
        use chrono::Timelike;
        let (mut cert, issuer) = signed_certificate();
        let this_update = (Utc::now() - chrono::Duration::hours(1))
            .with_nanosecond(0)
            .unwrap();
        let raw = crate::ocsp::tests::signed_response_with_next_update(
            &cert.cert_chain,
            &issuer,
            0,
            this_update,
            None,
        );
        cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(raw);
        let validity = PreparedKey::for_certificate(&cert).await.validity.unwrap();
        assert_eq!(
            validity.expires_at,
            this_update + chrono::Duration::hours(24)
        );
        assert_eq!(
            validity.refresh_at,
            this_update + chrono::Duration::hours(12)
        );
        cert.ocsp_response = Some(crate::ocsp::tests::signed_response_with_next_update(
            &cert.cert_chain,
            &issuer,
            0,
            this_update - chrono::Duration::hours(24),
            None,
        ));
        assert!(PreparedKey::for_certificate(&cert).await.validity.is_none());
    }
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
    async fn time_invalid_entries_remain_metadata_but_never_become_tls_candidates() {
        crate::install_default_crypto_provider();
        for managed in [false, true] {
            for future in [false, true] {
                let cache = CertCache::new(CacheOptions::default());
                let generated =
                    rcgen::generate_simple_self_signed(vec!["*.example.com".into()]).unwrap();
                let mut invalid = Certificate::from_pem(
                    generated.cert.pem().as_bytes(),
                    generated.signing_key.serialize_pem().as_bytes(),
                )
                .unwrap();
                invalid.managed = managed;
                let now = Utc::now();
                if future {
                    invalid.not_before = now + ChronoDuration::days(1);
                } else {
                    invalid.not_after = now - ChronoDuration::days(1);
                }
                cache.add(invalid.clone()).await;
                assert!(cache.get_by_hash(&invalid.hash).await.is_some());
                assert!(cache.get_by_name("a.example.com").await.is_some());
                assert_eq!(
                    cache.get_managed_certificates().await.len(),
                    usize::from(managed)
                );
                let lookup = cache.resolve_with_filter("a.example.com", |_| {
                    panic!("invalid-time candidate reached key filter")
                });
                assert!(lookup.matched);
                assert!(lookup.selected.is_none());
                let (matched, candidates) = cache.selection_candidates("a.example.com", |_| {
                    panic!("invalid-time candidate reached selector filter")
                });
                assert!(matched);
                assert!(candidates.is_empty());

                let generated =
                    rcgen::generate_simple_self_signed(vec!["*.example.com".into()]).unwrap();
                let valid = Certificate::from_pem(
                    generated.cert.pem().as_bytes(),
                    generated.signing_key.serialize_pem().as_bytes(),
                )
                .unwrap();
                cache.add(valid.clone()).await;
                assert_eq!(cache.resolve("a.example.com").unwrap().hash, valid.hash);
                let (_, candidates) = cache.selection_candidates("a.example.com", |_| true);
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].key.hash, valid.hash);
                assert!(cache.get_by_hash(&invalid.hash).await.is_some());
            }
        }
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
    async fn same_hash_management_promotion_updates_indices_without_downgrading() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = CertCache::new(CacheOptions::default());
        cache
            .add(make_cert(&["other.example.com"], "other", true))
            .await;
        let mut original = make_cert(&["old-alias.example.com", "example.com"], "promoted", false);
        original.tags = vec!["operator".into()];
        cache.add(original).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let weak = Arc::downgrade(&cache);
        let observed = calls.clone();
        cache
            .set_options(CacheOptions {
                on_event: Some(Arc::new(move |event| {
                    if let CacheEvent::Updated { hash, names } = event {
                        let cache = weak.upgrade().unwrap();
                        // A callback must be able to re-enter both reads and writes,
                        // and observe metadata and the pool already in agreement.
                        let state = cache
                            .state
                            .try_write()
                            .expect("promotion callback ran under cache lock");
                        let entry = &state.certificates[&hash];
                        assert!(entry.certificate.managed);
                        assert_eq!(entry.certificate.issuer_key, "managed-ca");
                        assert_eq!(entry.certificate.names, names);
                        assert_eq!(state.managed_hashes.len(), 2);
                        assert_eq!(state.managed_hashes[entry.managed_index.unwrap()], hash);
                        assert!(!state.index.contains_key("old-alias.example.com"));
                        drop(state);
                        let _ = cache.resolve("example.com");
                        observed.fetch_add(1, Ordering::SeqCst);
                    }
                })),
                ..Default::default()
            })
            .await;
        let mut managed = make_cert(&["example.com", "www.example.com"], "promoted", true);
        managed.issuer_key = "managed-ca".into();
        managed.tags = vec!["managed".into()];
        cache.add(managed.clone()).await;
        cache.add(managed).await;
        let mut stale = make_cert(&["wrong.example.com"], "promoted", false);
        stale.issuer_key = "unmanaged-import".into();
        stale.tags = vec!["reimport".into()];
        cache.add(stale).await;
        let cert = cache.get_by_hash("promoted").await.unwrap();
        assert!(cert.managed);
        assert_eq!(cert.issuer_key, "managed-ca");
        assert_eq!(cert.names, vec!["example.com", "www.example.com"]);
        assert_eq!(cert.tags, vec!["operator", "managed", "reimport"]);
        assert!(cache.get_by_name("old-alias.example.com").await.is_none());
        assert!(cache.get_by_name("wrong.example.com").await.is_none());
        assert_eq!(
            cache.get_by_name("www.example.com").await.unwrap().hash,
            "promoted"
        );
        assert_eq!(
            cache.state.read().unwrap().index["example.com"],
            vec!["promoted"]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_cache_indices(&cache);
        cache.remove("other").await; // Exercise the promoted entry's moved back-reference.
        assert_cache_indices(&cache);
        cache.remove("promoted").await;
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn same_hash_management_promotion_preserves_ocsp_and_quarantine() {
        use crate::ocsp::OcspStatus;
        for status in [OcspStatus::Good, OcspStatus::Revoked] {
            let (cert, issuer) = signed_certificate();
            let leaf_hash = crate::storage::certificate_leaf_hash(&cert).unwrap();
            let hash = cert.hash.clone();
            let cache = CertCache::new(CacheOptions::default());
            cache.add(cert.clone()).await;
            let response = (status == OcspStatus::Good).then(|| signed_staple(&cert, &issuer, 120));
            cache
                .update_ocsp_if_present(&hash, Some(status), response.clone())
                .await
                .unwrap();
            let before = cache.state.read().unwrap().certificates[&hash]
                .key
                .clone()
                .unwrap();
            let mut incoming = cert;
            incoming.managed = true;
            incoming.issuer_key = "managed-ca".into();
            incoming.ocsp_status = Some(OcspStatus::Good);
            incoming.ocsp_response = Some(vec![9, 9, 9]);
            cache.add(incoming.clone()).await;
            let current = cache.get_by_hash(&hash).await.unwrap();
            assert!(current.managed);
            assert_eq!(current.ocsp_status, Some(status));
            assert_eq!(current.ocsp_response, response);
            let after = cache.state.read().unwrap().certificates[&hash]
                .key
                .clone()
                .unwrap();
            assert!(
                Arc::ptr_eq(&before, &after),
                "metadata promotion replaced the existing serving key/staple"
            );
            assert_eq!(after.ocsp, response);
            if status == OcspStatus::Revoked {
                assert!(cache.resolve("ocsp.example.com").is_none());
            }
            assert_eq!(cache.maintenance_snapshot(true).len(), 1);
            assert_cache_indices(&cache);
            cache.deny_revoked_certificate(&leaf_hash).await;
            cache.add(incoming).await;
            assert!(cache.get_by_hash(&hash).await.is_none());
            assert!(cache.resolve("ocsp.example.com").is_none());
            assert!(cache.maintenance_snapshot(true).is_empty());
            assert_cache_indices(&cache);
        }
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
        let (cert, issuer) = signed_certificate();
        let cache = CertCache::new(CacheOptions::default());
        let hash = cert.hash.clone();
        let response = signed_staple(&cert, &issuer, 120);
        cache.add(cert).await;
        let snapshot = cache.maintenance_snapshot(false);
        let before = cache.resolve("ocsp.example.com").unwrap().key;
        cache
            .update_ocsp_if_present(
                &hash,
                Some(crate::ocsp::OcspStatus::Good),
                Some(response.clone()),
            )
            .await
            .unwrap();
        let after = cache.resolve("ocsp.example.com").unwrap().key;
        assert!(snapshot[0].ocsp_response.is_none());
        assert!(before.ocsp.is_none());
        assert_eq!(after.ocsp, Some(response.clone()));
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
