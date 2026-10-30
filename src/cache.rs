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
/// at runtime via [`CertCache::set_options`]. Zero intervals and durations
/// outside the monotonic clock range are replaced with their defaults.
/// [`crate::start_maintenance`] follows these intervals; explicit
/// [`crate::maintain::MaintenanceConfig`] values take precedence at lower-level
/// maintenance entry points.
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
    /// Reducing this limit immediately evicts managed entries until the cache
    /// fits or only unmanaged entries remain. Unmanaged entries are protected:
    /// they can exceed the limit, and a subsequent insertion can still add one
    /// entry while evicting an older managed entry if available.
    /// A value of `0` means unlimited and does not evict existing entries.
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

#[derive(Clone)]
pub(crate) struct AriChange {
    pub hash: String,
    pub reload: bool,
}

enum ManagedObservation<'a> {
    RevokedLeaf(&'a str),
    ManagedHash { hash: &'a str, issuer: &'a str },
}

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
    maintenance_intervals: watch::Sender<crate::maintain::MaintenanceIntervals>,
    stop_tx: watch::Sender<bool>,
    done_tx: watch::Sender<bool>,
    maintenance_count: Mutex<usize>,
    ocsp_changed: watch::Sender<u64>,
    ari_changed: watch::Sender<u64>,
    ari_schedule_changed: tokio::sync::broadcast::Sender<AriChange>,
}

#[derive(Default)]
struct CacheState {
    // Authoritative at publication, including after asynchronous preparation
    // or an earlier clone of the event/configuration options.
    capacity: usize,
    certificates: HashMap<String, CachedCertificate>,
    index: HashMap<String, Vec<String>>,
    /// Live chain hashes grouped by leaf, independent of SAN or managed state.
    /// Lifetime quarantine below outlives membership in this reverse index.
    chains_by_leaf: HashMap<String, HashSet<String>>,
    revoked_leaf_hashes: HashSet<String>,
    /// Dense managed-only sampling pool; each entry stores its back-reference.
    managed_hashes: Vec<String>,
    /// One indexed effective deadline per scheduled certificate.
    ocsp_deadlines: BTreeMap<DateTime<Utc>, HashSet<String>>,
    ocsp_revision: u64,
}

struct CachedCertificate {
    leaf_hash: Option<String>,
    certificate: Arc<Certificate>,
    key: Option<Arc<CertifiedKey>>,
    unstapled_key: Option<Arc<CertifiedKey>>,
    ocsp_validity: Option<OcspValidity>,
    ocsp_retry_after: Option<DateTime<Utc>>,
    // Confirmed, unchanged responder successes, separate from public metadata.
    ocsp_unchanged_refreshes: u8,
    must_staple: bool,
    managed_index: Option<usize>,
    ari_unpersisted: Option<Option<String>>,
}

#[derive(Clone, Copy)]
struct OcspValidity {
    expires_at: DateTime<Utc>,
    refresh_at: DateTime<Utc>,
}

struct VerifiedOcsp {
    status: crate::ocsp::OcspStatus,
    validity: Option<OcspValidity>,
}

impl VerifiedOcsp {
    async fn for_response(raw: &[u8], cert: &Certificate) -> Option<Self> {
        let response = crate::ocsp::parse_ocsp_response_for_cert_chain(raw, &cert.cert_chain)
            .await
            .ok()?;
        let expires_at = response.next_update.unwrap_or_else(|| {
            response.this_update + chrono::Duration::hours(crate::ocsp::DEFAULT_OCSP_LIFETIME_HOURS)
        });
        Some(Self {
            status: response.status,
            validity: (response.status == crate::ocsp::OcspStatus::Good).then_some(OcspValidity {
                expires_at,
                refresh_at: response.this_update + (expires_at - response.this_update) / 2,
            }),
        })
    }
}

struct PreparedKey {
    key: Option<Arc<CertifiedKey>>,
    unstapled: Option<Arc<CertifiedKey>>,
    validity: Option<OcspValidity>,
    retry_after: Option<DateTime<Utc>>,
    verified_status: Option<crate::ocsp::OcspStatus>,
    must_staple: bool,
}

impl PreparedKey {
    async fn for_certificate(cert: &Certificate) -> Self {
        let verified = match &cert.ocsp_response {
            Some(raw) => VerifiedOcsp::for_response(raw, cert).await,
            None => None,
        };
        let mut key = Self::new(
            cert_to_certified_key(cert).ok(),
            verified.as_ref().and_then(|response| response.validity),
            crate::ocsp::requires_ocsp_staple(cert).unwrap_or(true),
        );
        key.verified_status = verified.map(|response| response.status);
        key
    }

    fn new(
        mut key: Option<Arc<CertifiedKey>>,
        validity: Option<OcspValidity>,
        must_staple: bool,
    ) -> Self {
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
            verified_status: None,
            must_staple,
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
        } else if self.must_staple {
            None
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

// Only confirmed, unchanged Good responses far from expiry use the longer
// retry. Errors/cached fallbacks/changed responses retain the short deadline.
fn ocsp_retry_delay(
    now: DateTime<Utc>,
    validity: Option<OcspValidity>,
    unchanged_refreshes: u8,
    jitter_percent: u32,
) -> chrono::Duration {
    if let Some(validity) = validity
        && unchanged_refreshes > 0
        && validity.expires_at - now > chrono::Duration::hours(1)
    {
        let seconds = (30_i64 << unchanged_refreshes.min(4)).min(300);
        let remaining = validity.expires_at - now;
        return (chrono::Duration::seconds(seconds) * jitter_percent.clamp(80, 100) as i32 / 100)
            .min(remaining / 8)
            .min((remaining - chrono::Duration::hours(1)).max(chrono::Duration::seconds(1)));
    }
    validity.map_or(chrono::Duration::seconds(30), |validity| {
        ((validity.expires_at - now) / 2)
            .clamp(chrono::Duration::seconds(1), chrono::Duration::seconds(30))
    })
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
    fn has_managed_ocsp_revoked_leaf(&self, name: &str, leaf_hash: &str) -> bool {
        self.matching(name).into_iter().any(|entry| {
            entry.certificate.managed
                && entry.leaf_hash.as_deref() == Some(leaf_hash)
                && entry.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
        })
    }

    fn has_ocsp_revoked_leaf(&self, leaf_hash: &str) -> bool {
        self.chains_by_leaf.get(leaf_hash).is_some_and(|hashes| {
            hashes.iter().any(|hash| {
                self.certificates.get(hash).is_some_and(|entry| {
                    entry.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                })
            })
        })
    }

    /// A verified response authenticates the leaf even when duplicate admission
    /// will retain this entry's existing signing key and management metadata.
    fn record_verified_revocation(
        &mut self,
        hash: &str,
        incoming_leaf: Option<&str>,
    ) -> Vec<CacheEvent> {
        // A CertID authenticates the leaf, not one encoding of its chain or
        // its current store alias. Keep all live chains consistent under the
        // same publication lock, including unmanaged siblings.
        let leaf = incoming_leaf.or_else(|| {
            self.certificates
                .get(hash)
                .and_then(|entry| entry.leaf_hash.as_deref())
        });
        let mut hashes = leaf
            .and_then(|leaf| self.chains_by_leaf.get(leaf))
            .cloned()
            .unwrap_or_default();
        if self
            .certificates
            .get(hash)
            .is_some_and(|entry| leaf.is_none() || entry.leaf_hash.as_deref() == leaf)
        {
            hashes.insert(hash.to_owned());
        }
        hashes
            .into_iter()
            .filter_map(|hash| self.record_chain_revocation(&hash))
            .collect()
    }

    fn record_chain_revocation(&mut self, hash: &str) -> Option<CacheEvent> {
        let current = self.certificates.get_mut(hash)?;
        if current.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked) {
            return None;
        }
        let old_deadline = current.ocsp_deadline();
        let cert = Arc::make_mut(&mut current.certificate);
        cert.ocsp_status = Some(crate::ocsp::OcspStatus::Revoked);
        cert.ocsp_response = None;
        current.key = current.unstapled_key.clone();
        current.ocsp_validity = None;
        current.ocsp_unchanged_refreshes = 0;
        current.ocsp_retry_after = (cert.managed || old_deadline.is_some())
            .then(|| Utc::now() + chrono::Duration::seconds(30));
        let new_deadline = current.ocsp_deadline();
        let event = CacheEvent::Updated {
            names: current.certificate.names.clone(),
            hash: hash.to_owned(),
        };
        self.change_ocsp_deadline(hash, old_deadline, new_deadline);
        Some(event)
    }

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
        self.ocsp_revision = self.ocsp_revision.wrapping_add(1);
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
        if let Some(leaf_hash) = &entry.leaf_hash
            && let Some(chains) = self.chains_by_leaf.get_mut(leaf_hash)
        {
            chains.remove(hash);
            if chains.is_empty() {
                self.chains_by_leaf.remove(leaf_hash);
            }
        }
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

    fn evict_managed(&mut self) -> Option<CacheEvent> {
        self.evict_managed_excluding(None)
    }

    fn evict_managed_excluding(&mut self, protected: Option<&str>) -> Option<CacheEvent> {
        let protected = protected.and_then(|hash| {
            self.certificates
                .get(hash)
                .and_then(|entry| entry.managed_index)
        });
        let eligible = self.managed_hashes.len() - usize::from(protected.is_some());
        if eligible == 0 {
            return None;
        }
        let mut index = rand::rng().random_range(0..eligible);
        if protected.is_some_and(|protected| index >= protected) {
            index += 1;
        }
        let hash = self.managed_hashes[index].clone();
        self.remove(&hash)
    }

    fn add(
        &mut self,
        cert: Certificate,
        key: PreparedKey,
        leaf_hash: Option<String>,
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
            // A duplicate merges metadata but retains the cached chain/leaf;
            // its reverse membership must not follow the incoming metadata.
            let old_deadline = existing.ocsp_deadline();
            let promoted = cert.managed && !existing.certificate.managed;
            if promoted {
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
            // Promotion retains the imported OCSP state and key. A verified
            // revoked import may never have had a timer; taking responsibility
            // for it must also make recovery schedulable.
            if existing.certificate.managed
                && existing.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                && old_deadline.is_none()
            {
                existing.ocsp_retry_after = Some(Utc::now() + chrono::Duration::seconds(30));
            }
            let new_deadline = existing.ocsp_deadline();
            events.push(CacheEvent::Updated {
                names: existing.certificate.names.clone(),
                hash: hash.clone(),
            });
            self.change_ocsp_deadline(&hash, old_deadline, new_deadline);
            if promoted {
                // Taking responsibility for a protected import makes it count
                // towards eviction again. Preserve this incoming entry just
                // like fresh admission, reclaiming older managed entries first.
                // Re-read its pool index after every swap removal.
                while self.capacity > 0 && self.certificates.len() > self.capacity {
                    let Some(event) = self.evict_managed_excluding(Some(&hash)) else {
                        break;
                    };
                    events.push(event);
                }
            }
            return;
        }
        if self.capacity > 0
            && self.certificates.len() >= self.capacity
            && let Some(event) = self.evict_managed()
        {
            events.push(event);
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
        // A reload can discover revocation before this hash has ever had an
        // OCSP index entry. Keep it eligible for bounded maintenance recovery
        // even if replacing the old leaf removes that leaf's retry deadline.
        let retry_after = key.retry_after.or_else(|| {
            (cert.managed && cert.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked))
                .then(|| Utc::now() + chrono::Duration::seconds(30))
        });
        self.change_ocsp_deadline(
            &hash,
            None,
            key.validity
                .map(|validity| validity.refresh_at)
                .into_iter()
                .chain(retry_after)
                .max(),
        );
        if let Some(leaf_hash) = &leaf_hash {
            self.chains_by_leaf
                .entry(leaf_hash.clone())
                .or_default()
                .insert(hash.clone());
        }
        self.certificates.insert(
            hash,
            CachedCertificate {
                leaf_hash,
                certificate: Arc::new(cert),
                key: key.key,
                unstapled_key: key.unstapled,
                ocsp_validity: key.validity,
                ocsp_retry_after: retry_after,
                ocsp_unchanged_refreshes: 0,
                must_staple: key.must_staple,
                managed_index,
                ari_unpersisted: None,
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
        let options = normalize_options(options);
        let intervals = crate::maintain::MaintenanceIntervals::new(
            options.renew_check_interval,
            options.ocsp_check_interval,
        );
        Arc::new(Self {
            state: RwLock::new(CacheState {
                capacity: options.capacity,
                ..Default::default()
            }),
            options: RwLock::new(options),
            maintenance_intervals: watch::channel(intervals).0,
            stop_tx,
            done_tx,
            maintenance_count: Mutex::new(0),
            ocsp_changed: watch::channel(0).0,
            ari_changed: watch::channel(0).0,
            ari_schedule_changed: tokio::sync::broadcast::channel(64).0,
        })
    }

    /// Update cache options; zero or unrepresentable intervals use defaults.
    /// High-level maintenance adopts the latest interval pair asynchronously.
    /// Only a changed timer restarts, waiting one full new period from adoption;
    /// unchanged intervals and capacity/callback updates preserve its phase.
    /// A finite capacity immediately evicts managed entries until the cache
    /// fits or only protected unmanaged entries remain. Removal callbacks run
    /// after releasing the configuration and certificate locks.
    pub async fn set_options(&self, options: CacheOptions) {
        let options = normalize_options(options);
        let mut events = Vec::new();
        let previous = {
            // The only combined lock order is options -> state. Publishers
            // release their options snapshot before taking the state lock.
            let mut configured = self.options.write().unwrap_or_else(|e| e.into_inner());
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.capacity = options.capacity;
            while state.capacity > 0 && state.certificates.len() > state.capacity {
                let Some(event) = state.evict_managed() else {
                    break;
                };
                events.push(event);
            }
            let previous = std::mem::replace(&mut *configured, options.clone());
            let intervals = crate::maintain::MaintenanceIntervals::new(
                options.renew_check_interval,
                options.ocsp_check_interval,
            );
            // Publish Copy data in the same order as authoritative options.
            // Dropping the old callback below can block or re-enter set_options.
            self.maintenance_intervals.send_if_modified(|current| {
                if *current == intervals {
                    false
                } else {
                    *current = intervals;
                    true
                }
            });
            previous
        };
        // Dropping the previous callback/configuration can run user-owned
        // destructors, so it must not retain either cache lock either.
        drop(previous);
        self.notify_ocsp_schedule();
        dispatch_events(&options, events);
    }

    /// Persist a stop request, including when maintenance has not subscribed yet.
    pub fn stop(&self) {
        self.stop_tx.send_replace(true);
    }

    /// Subscribe to shutdown. Check the current value before waiting for changes.
    pub fn subscribe_stop(&self) -> watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    pub(crate) fn subscribe_maintenance_intervals(
        &self,
    ) -> watch::Receiver<crate::maintain::MaintenanceIntervals> {
        self.maintenance_intervals.subscribe()
    }

    pub(crate) fn subscribe_ari_schedule(&self) -> tokio::sync::broadcast::Receiver<AriChange> {
        self.ari_schedule_changed.subscribe()
    }

    pub(crate) fn has_unpersisted_ari(&self, hash: &str, issuer: &str) -> bool {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .certificates
            .get(hash)
            .is_some_and(|entry| {
                entry.certificate.managed
                    && entry.certificate.issuer_key == issuer
                    && entry.ari_unpersisted.is_some()
            })
    }

    /// A failed write may override only the record observed before that write.
    /// A different successfully persisted record wins over the local fallback.
    pub(crate) fn reconcile_ari(
        &self,
        hash: &str,
        issuer: &str,
        loaded: Option<(Option<String>, Option<crate::RenewalInfo>)>,
    ) -> Option<crate::RenewalInfo> {
        let mut changed = false;
        let result = {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|error| error.into_inner());
            let current = state.certificates.get_mut(hash).filter(|entry| {
                entry.certificate.managed && entry.certificate.issuer_key == issuer
            });
            match (current, loaded) {
                (Some(current), Some((fingerprint, info))) if current.ari_unpersisted.is_some() => {
                    if fingerprint.is_none()
                        || current.ari_unpersisted.as_ref() == Some(&fingerprint)
                    {
                        current.certificate.ari.clone()
                    } else {
                        current.ari_unpersisted = None;
                        Arc::make_mut(&mut current.certificate).ari = info.clone();
                        changed = true;
                        info
                    }
                }
                (Some(current), None) if current.ari_unpersisted.is_some() => {
                    current.certificate.ari.clone()
                }
                (_, Some((_, info))) => info,
                _ => None,
            }
        };
        if changed {
            let _ = self.ari_schedule_changed.send(AriChange {
                hash: hash.to_owned(),
                reload: true,
            });
            self.notify_ari();
        }
        result
    }

    pub(crate) fn ari_certificate(&self, hash: &str) -> Option<Arc<Certificate>> {
        self.managed_certificate(hash)
    }

    pub(crate) fn managed_certificate(&self, hash: &str) -> Option<Arc<Certificate>> {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .certificates
            .get(hash)
            .filter(|entry| entry.certificate.managed)
            .map(|entry| entry.certificate.clone())
    }

    pub(crate) fn has_managed_leaf(&self, issuer: &str, leaf: &str) -> bool {
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        state.chains_by_leaf.get(leaf).is_some_and(|hashes| {
            hashes.iter().any(|hash| {
                state.certificates.get(hash).is_some_and(|entry| {
                    entry.certificate.managed && entry.certificate.issuer_key == issuer
                })
            })
        })
    }

    /// Renewal retry identities reuse hashes prepared during publication.
    pub(crate) fn renewal_snapshot(&self) -> Vec<(Arc<Certificate>, Option<String>)> {
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        state
            .managed_hashes
            .iter()
            .filter_map(|hash| state.certificates.get(hash))
            .map(|entry| (entry.certificate.clone(), entry.leaf_hash.clone()))
            .collect()
    }

    pub(crate) fn subscribe_ari(&self) -> watch::Receiver<u64> {
        self.ari_changed.subscribe()
    }

    pub(crate) fn notify_ari(&self) {
        self.ari_changed
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    /// Apply only advisory metadata to live managed chains of the same leaf.
    /// This never republishes a key or changes OCSP/quarantine state.
    pub(crate) fn update_ari(
        &self,
        issuer: &str,
        leaf: &str,
        info: Option<crate::RenewalInfo>,
        unpersisted: Option<Option<String>>,
    ) {
        let mut scheduled = None;
        let changed = {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|error| error.into_inner());
            let hashes = state.chains_by_leaf.get(leaf).cloned().unwrap_or_default();
            let mut changed = false;
            for hash in hashes {
                if let Some(entry) = state.certificates.get_mut(&hash)
                    && entry.certificate.managed
                    && entry.certificate.issuer_key == issuer
                    && !entry.certificate.expired()
                {
                    let old = entry
                        .certificate
                        .ari
                        .as_ref()
                        .and_then(|info| crate::ari::selected_time(&entry.certificate, info));
                    let new = info
                        .as_ref()
                        .and_then(|info| crate::ari::selected_time(&entry.certificate, info));
                    Arc::make_mut(&mut entry.certificate).ari = info.clone();
                    entry.ari_unpersisted = unpersisted.clone();
                    if old != new {
                        scheduled.get_or_insert_with(|| hash.clone());
                    }
                    changed |= old != new && new.is_none_or(|time| time <= Utc::now());
                }
            }
            changed
        };
        if let Some(hash) = scheduled {
            let _ = self.ari_schedule_changed.send(AriChange {
                hash,
                reload: false,
            });
        }
        if changed {
            self.notify_ari();
        }
    }

    pub(crate) fn subscribe_ocsp(&self) -> watch::Receiver<u64> {
        self.ocsp_changed.subscribe()
    }

    fn notify_ocsp_schedule(&self) {
        // Keep the snapshot and notification ordered with mutations. The watch
        // wakes tasks without polling their futures under this read lock.
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        self.ocsp_changed.send_if_modified(|current| {
            if *current == state.ocsp_revision {
                false
            } else {
                *current = state.ocsp_revision;
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

    /// A maintenance loop owns its own refresh pool; another loop may still
    /// refresh these hashes independently. Skip only this loop's work without
    /// removing global deadlines or hiding another certificate's later timer.
    pub(crate) fn next_ocsp_deadline_excluding(
        &self,
        excluded: &HashSet<String>,
    ) -> Option<DateTime<Utc>> {
        if excluded.is_empty() {
            return self.next_ocsp_deadline();
        }
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ocsp_deadlines
            .iter()
            .find_map(|(deadline, hashes)| {
                hashes
                    .iter()
                    .any(|hash| !excluded.contains(hash))
                    .then_some(*deadline)
            })
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

    pub(crate) fn due_ocsp_snapshot(
        &self,
        excluded: &HashSet<String>,
        limit: usize,
    ) -> Vec<Arc<Certificate>> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state
            .ocsp_deadlines
            .range(..=Utc::now())
            .flat_map(|(_, hashes)| hashes)
            .filter(|hash| !excluded.contains(*hash))
            .filter_map(|hash| state.certificates.get(hash))
            .take(limit)
            .map(|entry| Arc::clone(&entry.certificate))
            .collect()
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
        let _ = self.publish_prepared(None, cert, None, None).await;
    }

    /// Managed publication rechecks time at the write-lock linearization point,
    /// after any asynchronous OCSP/AIA preparation has finished.
    pub(crate) async fn add_managed(&self, cert: Certificate, domain: &str) -> Result<()> {
        self.publish_prepared(None, cert, Some(domain), None)
            .await
            .map(|_| ())
    }

    /// Publish management only while the queued revocation observation still
    /// belongs to a managed entry. Verified revocation of an existing incoming
    /// leaf is retained even if this observation has been withdrawn.
    pub(crate) async fn add_managed_if_observed_revoked(
        &self,
        cert: Certificate,
        domain: &str,
        observed_leaf: &str,
    ) -> Result<bool> {
        self.publish_prepared(
            None,
            cert,
            Some(domain),
            Some(ManagedObservation::RevokedLeaf(observed_leaf)),
        )
        .await
    }

    pub(crate) async fn replace_managed_if_current(
        &self,
        old_hash: &str,
        cert: Certificate,
        domain: &str,
        issuer: &str,
    ) -> Result<bool> {
        self.publish_prepared(
            Some(old_hash),
            cert,
            Some(domain),
            Some(ManagedObservation::ManagedHash {
                hash: old_hash,
                issuer,
            }),
        )
        .await
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
        let _ = self
            .publish_prepared(Some(old_hash), new_cert, None, None)
            .await;
    }

    pub(crate) async fn replace_managed(
        &self,
        old_hash: &str,
        cert: Certificate,
        domain: &str,
    ) -> Result<()> {
        self.publish_prepared(Some(old_hash), cert, Some(domain), None)
            .await
            .map(|_| ())
    }

    async fn publish_prepared(
        &self,
        old_hash: Option<&str>,
        mut cert: Certificate,
        domain: Option<&str>,
        observation: Option<ManagedObservation<'_>>,
    ) -> Result<bool> {
        let requires_staple = domain.is_some() && crate::ocsp::requires_ocsp_staple(&cert)?;
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
        let published_hash = cert.hash.clone();
        let published_issuer = cert.issuer_key.clone();
        let mut key = PreparedKey::for_certificate(&cert).await;
        if let Some(status) = key.verified_status {
            if cert.ocsp_status != Some(crate::ocsp::OcspStatus::Revoked) {
                cert.ocsp_status = Some(status);
            }
            if status != crate::ocsp::OcspStatus::Good {
                cert.ocsp_response = None;
            }
        }
        let leaf_hash = crate::storage::certificate_leaf_hash(&cert);
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut events = Vec::new();
        let mut quarantine_events = Vec::new();
        let publication: Result<bool> = (|| {
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
            // A manager that ignores ARI must not erase another manager's
            // advisory state when reloading the same live identity.
            let ari_unpersisted = state
                .certificates
                .get(&cert.hash)
                .filter(|entry| entry.certificate.issuer_key == cert.issuer_key)
                .and_then(|entry| entry.ari_unpersisted.clone());
            if domain.is_some()
                && let Some(current) = state
                    .certificates
                    .get(&cert.hash)
                    .filter(|entry| entry.certificate.issuer_key == cert.issuer_key)
                && (cert.ari.is_none()
                    || current.ari_unpersisted.is_some()
                    || original
                        .as_ref()
                        .is_some_and(|original| !Arc::ptr_eq(original, &current.certificate)))
            {
                cert.ari = current.certificate.ari.clone();
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
            // A different chain can authenticate the same revoked leaf. Check
            // every admission at its write-lock linearization point, including
            // revocation received while preparation awaited AIA. This uses live
            // leaf membership, without a new lifetime deny-list policy.
            if let Some(leaf_hash) = leaf_hash.as_deref()
                && state.has_ocsp_revoked_leaf(leaf_hash)
            {
                cert.ocsp_status = Some(crate::ocsp::OcspStatus::Revoked);
                cert.ocsp_response = None;
                key.key = key.unstapled.clone();
                key.validity = None;
            }
            // `staple_ocsp` already clears raw bytes after verifying Revoked;
            // preserve that trusted status as well as evidence parsed here.
            if cert.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked) {
                quarantine_events =
                    state.record_verified_revocation(&cert.hash, leaf_hash.as_deref());
            }
            if let (Some(domain), Some(observation)) = (domain, observation) {
                let still_managed = match observation {
                    ManagedObservation::RevokedLeaf(leaf) => {
                        state.has_managed_ocsp_revoked_leaf(domain, leaf)
                    }
                    ManagedObservation::ManagedHash { hash, issuer } => {
                        state.certificates.get(hash).is_some_and(|entry| {
                            entry.certificate.managed
                                && entry.certificate.issuer_key == issuer
                                && entry
                                    .certificate
                                    .names
                                    .first()
                                    .is_some_and(|name| name == domain)
                        })
                    }
                };
                if !still_managed {
                    return Ok(false);
                }
            }
            // An explicit managed reload can recover a stable, unusable
            // Must-Staple entry. Keep its signing key and all other metadata;
            // only an authenticated Good for the same leaf may update OCSP.
            // Any intervening metadata/status publication changes the held
            // Arc version, so a delayed preparation must retain that update.
            let recovered_deadline = state.certificates.get_mut(&cert.hash).and_then(|current| {
                let now = Utc::now();
                if !requires_staple
                    || old_hash == Some(cert.hash.as_str())
                    || key.verified_status != Some(crate::ocsp::OcspStatus::Good)
                    || cert.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                    || leaf_hash.is_none()
                    || leaf_hash != current.leaf_hash
                    || current.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                    || current.serving_key(now).is_some()
                    || original
                        .as_ref()
                        .is_none_or(|original| !Arc::ptr_eq(original, &current.certificate))
                {
                    return None;
                }
                let validity = key.validity.filter(|validity| now < validity.expires_at)?;
                let response = cert.ocsp_response.as_ref()?;
                let mut container = current.unstapled_key.as_ref()?.as_ref().clone();
                container.ocsp = Some(response.clone());
                let old_deadline = current.ocsp_deadline();
                let certificate = Arc::make_mut(&mut current.certificate);
                certificate.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
                certificate.ocsp_response = Some(response.clone());
                current.key = Some(Arc::new(container));
                current.ocsp_validity = Some(validity);
                current.ocsp_retry_after = None;
                current.ocsp_unchanged_refreshes = 0;
                Some((old_deadline, current.ocsp_deadline()))
            });
            if let Some((old, new)) = recovered_deadline {
                state.change_ocsp_deadline(&cert.hash, old, new);
            }
            if let Some(current) = state.certificates.get(&cert.hash)
                && ((requires_staple && old_hash != Some(cert.hash.as_str()))
                    || (old_hash == Some(cert.hash.as_str())
                        && (current.certificate.ocsp_status
                            == Some(crate::ocsp::OcspStatus::Revoked)
                            || original.as_ref().is_none_or(|original| {
                                !Arc::ptr_eq(original, &current.certificate)
                            }))))
            {
                // Preparation may await AIA while a newer OCSP update arrives.
                // Replacing the same leaf changes management metadata, not its
                // current status, serving containers or refresh schedule.
                // Adding an existing hash (including replacement of another
                // hash) merges metadata only, so readiness must also use the
                // current containers that CacheState::add will retain.
                cert.ocsp_status = current.certificate.ocsp_status;
                cert.ocsp_response = current.certificate.ocsp_response.clone();
                key = PreparedKey {
                    key: current.key.clone(),
                    unstapled: current.unstapled_key.clone(),
                    validity: current.ocsp_validity,
                    retry_after: current.ocsp_retry_after,
                    verified_status: None,
                    must_staple: current.must_staple,
                };
            }
            // Evaluate readiness after reconciling a newer same-hash update.
            // A prepared Good response must not authorize publication over a
            // newer Unknown/Revoked state or its now-missing required staple.
            if let Some(domain) = domain.filter(|_| requires_staple)
                && (key
                    .validity
                    .is_none_or(|validity| Utc::now() >= validity.expires_at)
                    || key.key.as_ref().is_none_or(|key| key.ocsp.is_none())
                    || cert.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked))
            {
                return Err(crate::error::CertError::OcspFailed(format!(
                    "{domain}: Must-Staple certificate requires a current signed Good OCSP response"
                ))
                .into());
            }
            if let Some(old_hash) = old_hash
                && let Some(event) = state.remove(old_hash)
            {
                events.push(event);
            }
            state.add(cert, key, leaf_hash, &mut events);
            if domain.is_some()
                && let Some(entry) = state
                    .certificates
                    .get_mut(&published_hash)
                    .filter(|entry| entry.certificate.issuer_key == published_issuer)
            {
                entry.ari_unpersisted = ari_unpersisted;
            }
            Ok(true)
        })();
        // A later managed-readiness guard may reject publication after an
        // authenticated revocation has quarantined the existing entry. Still
        // publish that status/deadline change. Successful add/replace already
        // emits its normal events, without an extra duplicate Updated event.
        let quarantine_events: Vec<_> = quarantine_events
            .into_iter()
            .filter(|event| {
                let CacheEvent::Updated { hash, .. } = event else {
                    return true;
                };
                // The ordinary publication already reports the target, and a
                // removed/evicted sibling needs only its removal notification.
                let published = matches!(&publication, Ok(true)) && hash == &published_hash;
                let removed = events.iter().any(|event| {
                    matches!(event, CacheEvent::Removed { hash: removed, .. } if removed == hash)
                });
                !(published || removed)
            })
            .collect();
        events.extend(quarantine_events);
        self.notify_ocsp_schedule();
        dispatch_events(&options, events);
        if matches!(&publication, Ok(true)) && domain.is_some() {
            let _ = self.ari_schedule_changed.send(AriChange {
                hash: published_hash,
                reload: true,
            });
        }
        publication
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
            // Taking the bucket avoids scanning unrelated certificates and
            // transfers its chain hashes without cloning them. All removals
            // still use the common SAN/managed/OCSP bookkeeping under this lock.
            let hashes = state.chains_by_leaf.remove(leaf_hash).unwrap_or_default();
            hashes
                .into_iter()
                .filter_map(|hash| state.remove(&hash))
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
    /// A verified revocation still updates live sibling chains if the original
    /// hash was removed while issuer verification awaited I/O; it is not readded.
    /// Later metadata changes are not serialized with the renewal callback.
    pub(crate) async fn update_ocsp_if_present(
        &self,
        hash: &str,
        status: Option<crate::ocsp::OcspStatus>,
        response: Option<Vec<u8>>,
    ) -> Option<OcspUpdateState> {
        self.update_ocsp_after_refresh(hash, status, response, None)
            .await
    }

    pub(crate) async fn update_ocsp_after_refresh(
        &self,
        hash: &str,
        status: Option<crate::ocsp::OcspStatus>,
        response: Option<Vec<u8>>,
        refresh: Option<(&Arc<Certificate>, &crate::ocsp::OcspRefreshOutcome)>,
    ) -> Option<OcspUpdateState> {
        let (certificate, observed_leaf) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            let entry = state.certificates.get(hash)?;
            (Arc::clone(&entry.certificate), entry.leaf_hash.clone())
        };
        let verified = match &response {
            Some(raw) => VerifiedOcsp::for_response(raw, &certificate).await,
            None => None,
        };
        let status = if status == Some(crate::ocsp::OcspStatus::Revoked) {
            status
        } else {
            verified.as_ref().map(|response| response.status).or(status)
        };
        let validity = verified
            .as_ref()
            .and_then(|response| response.validity)
            .filter(|_| status == Some(crate::ocsp::OcspStatus::Good));
        let response = if verified
            .as_ref()
            .is_some_and(|response| response.status != crate::ocsp::OcspStatus::Good)
            || status == Some(crate::ocsp::OcspStatus::Revoked)
        {
            None
        } else {
            response
        };
        let options = self
            .options
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (events, published) = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let mut events = if status == Some(crate::ocsp::OcspStatus::Revoked) {
                state.record_verified_revocation(hash, observed_leaf.as_deref())
            } else {
                Vec::new()
            };
            events.retain(|event| !matches!(event, CacheEvent::Updated { hash: changed, .. } if changed == hash));
            let update = state
                .certificates
                .get_mut(hash)
                .filter(|entry| entry.leaf_hash == observed_leaf)
                .map(|current| {
                    let now = Utc::now();
                    let old_deadline = current.ocsp_deadline();
                    let was_scheduled = old_deadline.is_some();
                    let keep_revoked = current.certificate.ocsp_status
                        == Some(crate::ocsp::OcspStatus::Revoked)
                        && status != Some(crate::ocsp::OcspStatus::Revoked);
                    let unchanged = !keep_revoked
                        && Arc::ptr_eq(&current.certificate, &certificate)
                        && current.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Good)
                        && status == Some(crate::ocsp::OcspStatus::Good)
                        && current
                            .ocsp_validity
                            .is_some_and(|old| now < old.expires_at)
                        && validity
                            .is_some_and(|new| new.expires_at - now > chrono::Duration::hours(1))
                        && response.as_ref().is_some_and(|raw| {
                            current.certificate.ocsp_response.as_ref() == Some(raw)
                                && refresh.is_some_and(|(expected, proof)| {
                                    Arc::ptr_eq(expected, &current.certificate)
                                        && proof.confirms_good(raw)
                                })
                        });
                    current.ocsp_unchanged_refreshes = if unchanged {
                        current.ocsp_unchanged_refreshes.saturating_add(1).min(4)
                    } else {
                        0
                    };
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
                    current.ocsp_retry_after = if validity.is_some()
                        || was_scheduled
                        || current.certificate.ocsp_status == Some(crate::ocsp::OcspStatus::Revoked)
                    {
                        let delay = ocsp_retry_delay(
                            now,
                            validity,
                            current.ocsp_unchanged_refreshes,
                            rand::rng().random_range(80..=100),
                        );
                        Some(now + delay)
                    } else {
                        None
                    };
                    let new_deadline = current.ocsp_deadline();
                    let event = CacheEvent::Updated {
                        names: current.certificate.names.clone(),
                        hash: hash.to_owned(),
                    };
                    (
                        old_deadline,
                        new_deadline,
                        event,
                        OcspUpdateState::from(current.certificate.as_ref()),
                    )
                });
            if let Some((old_deadline, new_deadline, event, published)) = update {
                state.change_ocsp_deadline(hash, old_deadline, new_deadline);
                events.push(event);
                (events, Some(published))
            } else {
                (events, None)
            }
        };
        self.notify_ocsp_schedule();
        dispatch_events(&options, events);
        published
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

    /// Read local OCSP evidence for this managed identity across alternate
    /// chains. A different replacement leaf remains independent.
    pub(crate) fn has_ocsp_revoked_leaf(&self, _name: &str, leaf_hash: &str) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .has_ocsp_revoked_leaf(leaf_hash)
    }

    pub(crate) fn has_managed_ocsp_revoked_leaf(&self, name: &str, leaf_hash: &str) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .has_managed_ocsp_revoked_leaf(name, leaf_hash)
    }

    /// Client authentication uses the certificate metadata, independently of
    /// the server's Must-Staple serving policy. Share bytes while callers check
    /// persisted revocation intent without holding the cache lock.
    pub(crate) fn client_certificate_candidates(&self, name: &str) -> Vec<Arc<Certificate>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .matching(name)
            .into_iter()
            .map(|entry| Arc::clone(&entry.certificate))
            .collect()
    }

    /// Recheck after asynchronous marker reads, including a quarantine that
    /// already removed its metadata and OCSP evidence on an alternate chain.
    pub(crate) fn client_leaf_is_revoked(&self, _name: &str, leaf_hash: &str) -> bool {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state.revoked_leaf_hashes.contains(leaf_hash) || state.has_ocsp_revoked_leaf(leaf_hash)
    }

    /// Lifecycle shortcuts must not treat an unusable Must-Staple or revoked
    /// entry as already managed successfully. Keep the same serving boundary
    /// without parsing DER or cloning private keys.
    pub(crate) fn has_usable_managed_certificate(&self, name: &str) -> bool {
        self.has_usable_managed_certificate_where(name, |_| true)
    }

    /// Apply lifecycle eligibility to the same candidate whose serving key is
    /// usable, rather than combining independent matches from sibling chains.
    pub(crate) fn has_usable_managed_certificate_where(
        &self,
        name: &str,
        eligible: impl Fn(&Certificate) -> bool,
    ) -> bool {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        state.matching(name).into_iter().any(|entry| {
            entry.certificate.managed
                && entry.certificate.not_before <= now
                && now < entry.certificate.not_after
                && entry.serving_key(now).is_some()
                && eligible(&entry.certificate)
        })
    }

    /// An unusable Must-Staple key can request recovery without being offered
    /// as a TLS candidate. Only identifiers are copied on the handshake path.
    pub(crate) fn ocsp_refresh_candidate(
        &self,
        name: &str,
        accepts: impl Fn(&CertifiedKey) -> bool,
    ) -> Option<String> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        state
            .matching(name)
            .into_iter()
            .find(|entry| {
                entry.must_staple
                    && entry.certificate.ocsp_status != Some(crate::ocsp::OcspStatus::Revoked)
                    && entry.certificate.not_before <= now
                    && now < entry.certificate.not_after
                    && entry.needs_ocsp(now)
                    && entry.key.as_ref().is_some_and(|key| accepts(key))
            })
            .map(|entry| entry.certificate.hash.clone())
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
        let key = PreparedKey::new(
            cert_to_certified_key(&cert).ok(),
            None,
            crate::ocsp::requires_ocsp_staple(&cert).unwrap_or(true),
        );
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
            if leaf_hash.as_ref().is_some_and(|hash| {
                state.revoked_leaf_hashes.contains(hash) || state.has_ocsp_revoked_leaf(hash)
            }) {
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
            state.add(cert, key, leaf_hash, &mut events);
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
    let intervals = crate::maintain::MaintenanceIntervals::new(
        opts.renew_check_interval,
        opts.ocsp_check_interval,
    );
    opts.renew_check_interval = intervals.renew;
    opts.ocsp_check_interval = intervals.ocsp;
    opts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod leaf_revocation_tests;

#[cfg(test)]
mod ocsp_backoff_tests;

#[cfg(test)]
pub(crate) mod tests {
    // Simulate crossing the indexed deadline without confusing Tokio's paused
    // monotonic clock with the wall clock used by signed OCSP validity checks.
    pub(crate) fn force_ocsp_due(cache: &CertCache, hash: &str) {
        let mut state = cache.state.write().unwrap();
        let entry = state.certificates.get_mut(hash).unwrap();
        let old = entry.ocsp_deadline();
        entry.ocsp_retry_after = Some(Utc::now() - chrono::Duration::seconds(1));
        let new = entry.ocsp_deadline();
        state.change_ocsp_deadline(hash, old, new);
    }

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

    async fn signed_cache_handshake(
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
    #[tokio::test]
    async fn verified_revoked_leaves_are_metadata_only_and_a_normal_sibling_can_serve() {
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
                    signed_cache_handshake(cache, normal.cert_chain[1].clone())
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
                assert!(
                    signed_cache_handshake(cache, cert.cert_chain[1].clone())
                        .await
                        .is_none()
                );
            }
        }
    }

    #[tokio::test]
    async fn with_ocsp_signed_revocation_is_not_lost_on_initial_or_duplicate_publication() {
        for mode in [
            "insert",
            "duplicate",
            "replace_same",
            "replace_existing",
            "duplicate_stapled",
        ] {
            let cache = CertCache::new(CacheOptions::default());
            let (mut cert, issuer) = signed_certificate();
            cert.managed = true;
            cert.issuer_key = "original-ca".into();
            cert.tags = vec!["operator".into()];
            let hash = cert.hash.clone();
            if mode != "insert" {
                let mut good = cert.clone().with_ocsp(signed_staple(&cert, &issuer, 120));
                good.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
                cache.add(good).await;
            }
            let raw = crate::ocsp::tests::signed_response(
                &cert.cert_chain,
                &issuer,
                1,
                Utc::now(),
                Utc::now() + chrono::Duration::hours(1),
            );
            let mut incoming = cert.clone().with_ocsp(raw.clone());
            if mode == "duplicate_stapled" {
                let directory = tempfile::tempdir().unwrap();
                let storage = crate::FileStorage::new(directory.path());
                crate::storage::Storage::store(
                    &storage,
                    &crate::storage::ocsp_key(&cert.names[0], &hash),
                    &raw,
                )
                .await
                .unwrap();
                crate::ocsp::staple_ocsp(
                    &storage,
                    &mut incoming,
                    &crate::ocsp::OcspConfig::default(),
                )
                .await
                .unwrap();
                assert_eq!(incoming.ocsp_status, Some(crate::ocsp::OcspStatus::Revoked));
                assert!(incoming.ocsp_response.is_none());
            } else {
                assert!(
                    incoming.ocsp_status.is_none(),
                    "the public builder deliberately leaves verification to publication"
                );
            }
            match mode {
                "replace_same" => cache.replace(&hash, incoming).await,
                "replace_existing" => {
                    let (other, _) = signed_certificate();
                    let other_hash = other.hash.clone();
                    cache.add(other).await;
                    cache.replace(&other_hash, incoming).await;
                }
                _ => cache.add(incoming).await,
            }
            let current = cache.get_by_hash(&hash).await.unwrap();
            assert_eq!(
                current.ocsp_status,
                Some(crate::ocsp::OcspStatus::Revoked),
                "mode={mode}"
            );
            assert!(current.ocsp_response.is_none());
            assert!(current.managed);
            assert_eq!(current.issuer_key, "original-ca");
            assert_eq!(current.tags, vec!["operator"]);
            assert!(cache.resolve("ocsp.example.com").is_none());
            assert!(
                cache
                    .selection_candidates("ocsp.example.com", |_| true)
                    .1
                    .is_empty()
            );
            assert!(
                signed_cache_handshake(cache.clone(), cert.cert_chain[1].clone())
                    .await
                    .is_none()
            );
            cache
                .replace(
                    &hash,
                    cert.clone().with_ocsp(signed_staple(&cert, &issuer, 120)),
                )
                .await;
            assert_eq!(
                cache.get_by_hash(&hash).await.unwrap().ocsp_status,
                Some(crate::ocsp::OcspStatus::Revoked)
            );
            assert_cache_indices(&cache);
        }
    }

    #[tokio::test]
    async fn raw_ocsp_update_derives_verified_status_and_does_not_trust_bad_responses() {
        for status in [0, 1, 2, 3] {
            let cache = CertCache::new(CacheOptions::default());
            let (cert, issuer) = signed_certificate();
            let hash = cert.hash.clone();
            cache.add(cert.clone()).await;
            let mut raw = crate::ocsp::tests::signed_response(
                &cert.cert_chain,
                &issuer,
                if status == 3 { 1 } else { status },
                Utc::now(),
                Utc::now() + chrono::Duration::hours(1),
            );
            if status == 3 {
                *raw.last_mut().unwrap() ^= 1;
            }
            let imported = CertCache::new(CacheOptions::default());
            imported.add(cert.clone().with_ocsp(raw.clone())).await;
            let result = cache
                .update_ocsp_if_present(&hash, None, Some(raw))
                .await
                .unwrap();
            let expected = match status {
                0 => Some(crate::ocsp::OcspStatus::Good),
                1 => Some(crate::ocsp::OcspStatus::Revoked),
                2 => Some(crate::ocsp::OcspStatus::Unknown),
                _ => None,
            };
            assert_eq!(result.ocsp_status, expected, "response status={status}");
            assert_eq!(
                imported.get_by_hash(&hash).await.unwrap().ocsp_status,
                expected
            );
            assert_eq!(
                signed_cache_handshake(imported, cert.cert_chain[1].clone())
                    .await
                    .is_none(),
                status == 1
            );
            assert_eq!(
                cache.get_by_hash(&hash).await.unwrap().ocsp_status,
                expected
            );
            assert_eq!(cache.resolve("ocsp.example.com").is_none(), status == 1);
            assert_eq!(
                signed_cache_handshake(cache.clone(), cert.cert_chain[1].clone())
                    .await
                    .is_none(),
                status == 1
            );
        }
    }

    #[tokio::test]
    async fn prepared_publication_preserves_current_status_and_leaf_quarantine_during_aia_wait() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // 0..3: existing OCSP/leaf quarantine races; 4..5: incoming verified
        // Revoked versus a concurrent Good update (replace/add); 6..9:
        // Must-Staple readiness versus Unknown/Revoked or duplicate admission;
        // 10: a different chain for the same leaf becomes revoked during AIA;
        // 11..12: a same-hash Unknown entry is inserted/reinserted during AIA.
        for scenario in 0..13 {
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
            if scenario >= 6 {
                params
                    .custom_extensions
                    .push(rcgen::CustomExtension::from_oid_content(
                        &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                        vec![0x30, 0x03, 0x02, 0x01, 0x05],
                    ));
            }
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
            let old = if matches!(scenario, 0 | 3 | 4 | 5 | 6 | 7 | 8 | 12) {
                cert.clone()
            } else if scenario == 10 {
                // Omitting the trusted root is a valid alternate TLS chain.
                let mut full_chain = cert.clone();
                full_chain.cert_chain.push(ca_cert.der().clone());
                full_chain.hash =
                    crate::certificates::hash_certificate_chain(&full_chain.cert_chain);
                full_chain
            } else {
                signed_certificate().0
            };
            let old_hash = old.hash.clone();
            let old_leaf = crate::storage::certificate_leaf_hash(&old).unwrap();
            cache.add(old).await;
            if scenario == 9 {
                cache.add(cert.clone()).await;
            }
            cert.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
            cert.ocsp_response = Some(crate::ocsp::tests::signed_response(
                &[leaf.der().clone(), ca_cert.der().clone()],
                &issuer_key,
                if matches!(scenario, 4 | 5) { 1 } else { 0 },
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
            let mut concurrent_entry = cert.clone();
            concurrent_entry.ocsp_status = Some(crate::ocsp::OcspStatus::Unknown);
            concurrent_entry.ocsp_response = None;
            let worker = tokio::spawn({
                let cache = cache.clone();
                let hash = old_hash.clone();
                async move {
                    if matches!(scenario, 5 | 8 | 11 | 12) {
                        cache.add_managed(cert, "ocsp.example.com").await
                    } else {
                        cache.replace_managed(&hash, cert, "ocsp.example.com").await
                    }
                }
            });
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            let expected_status = if matches!(scenario, 3 | 6 | 8 | 9 | 11 | 12) {
                crate::ocsp::OcspStatus::Unknown
            } else {
                crate::ocsp::OcspStatus::Revoked
            };
            match scenario {
                0 | 3 | 4 | 5 | 6 | 7 | 8 | 9 => {
                    cache
                        .update_ocsp_if_present(
                            &hash,
                            Some(if matches!(scenario, 4 | 5) {
                                crate::ocsp::OcspStatus::Good
                            } else {
                                expected_status
                            }),
                            None,
                        )
                        .await
                        .unwrap();
                }
                1 => cache.deny_revoked_certificate(&incoming_leaf).await,
                2 => cache.deny_revoked_certificate(&old_leaf).await,
                10 => {
                    cache
                        .update_ocsp_if_present(&old_hash, Some(expected_status), None)
                        .await
                        .unwrap();
                }
                11 | 12 => {
                    if scenario == 12 {
                        cache.remove(&hash).await;
                    }
                    cache.add(concurrent_entry).await;
                }
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
            if scenario == 10 {
                assert!(matches!(
                    result,
                    Err(crate::Error::Cert(crate::error::CertError::OcspFailed(_)))
                ));
                assert!(cache.get_by_hash(&hash).await.is_none());
                assert_eq!(
                    cache.get_by_hash(&old_hash).await.unwrap().ocsp_status,
                    Some(crate::ocsp::OcspStatus::Revoked)
                );
                assert!(cache.resolve("ocsp.example.com").is_none());
                continue;
            }
            if matches!(scenario, 4 | 5) {
                result.unwrap();
                let current = cache.get_by_hash(&hash).await.unwrap();
                assert_eq!(current.ocsp_status, Some(crate::ocsp::OcspStatus::Revoked));
                assert!(cache.resolve("ocsp.example.com").is_none());
                assert!(current.ocsp_response.is_none());
                continue;
            }
            if scenario >= 6 {
                assert!(
                    matches!(
                        result,
                        Err(crate::Error::Cert(crate::error::CertError::OcspFailed(_)))
                    ),
                    "scenario {scenario}: {result:?}"
                );
                let current = cache.get_by_hash(&hash).await.unwrap();
                assert_eq!(current.ocsp_status, Some(expected_status));
                assert!(current.ocsp_response.is_none());
                assert!(cache.get_by_hash(&old_hash).await.is_some());
                if scenario == 9 {
                    assert!(Arc::ptr_eq(
                        current_key.as_ref().unwrap(),
                        &cache.resolve("ocsp.example.com").unwrap().key,
                    ));
                }
                continue;
            }
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
            if expected_status == crate::ocsp::OcspStatus::Revoked {
                assert!(cache.next_ocsp_deadline().unwrap() > Utc::now());
            } else {
                assert!(cache.next_ocsp_deadline().is_none());
            }
        }
    }

    #[tokio::test]
    async fn stable_managed_duplicate_recovers_ocsp_without_replacing_the_signing_key() {
        let cache = CertCache::new(CacheOptions::default());
        let (mut imported, issuer) = crate::ocsp::tests::short_lived_certificate(Some(5));
        imported.tags = vec!["operator".into()];
        let hash = imported.hash.clone();
        cache.add(imported.clone()).await;
        let original = cache.state.read().unwrap().certificates[&hash]
            .certificate
            .clone();
        let signing = cache.state.read().unwrap().certificates[&hash]
            .unstapled_key
            .as_ref()
            .unwrap()
            .key
            .clone();
        assert!(cache.resolve("ocsp.example.com").is_none());
        imported.managed = true;
        imported.issuer_key = "managed-ca".into();
        imported.tags = vec!["application".into()];
        imported.ocsp_response = Some(signed_staple(&imported, &issuer, 120));
        let response = imported.ocsp_response.clone();
        cache
            .add_managed(imported, "ocsp.example.com")
            .await
            .unwrap();
        let current = cache.get_by_hash(&hash).await.unwrap();
        assert!(current.managed);
        assert_eq!(current.issuer_key, "managed-ca");
        assert_eq!(current.tags, vec!["operator", "application"]);
        assert_eq!(current.ocsp_response, response);
        assert_eq!(current.ocsp_status, Some(crate::ocsp::OcspStatus::Good));
        let selected = cache.resolve("ocsp.example.com").unwrap();
        assert!(Arc::ptr_eq(&signing, &selected.key.key));
        assert_eq!(selected.key.ocsp, response);
        assert!(cache.next_ocsp_deadline().is_some());
        assert!(!original.managed);
        assert!(original.ocsp_response.is_none());
        assert_eq!(original.tags, vec!["operator"]);
        assert!(!Arc::ptr_eq(
            &original,
            &cache.state.read().unwrap().certificates[&hash].certificate
        ));
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn duplicate_recovery_requires_the_existing_leaf_identity() {
        let cache = CertCache::new(CacheOptions::default());
        let (existing, _) = crate::ocsp::tests::short_lived_certificate(Some(5));
        let hash = existing.hash.clone();
        let original_leaf = crate::storage::certificate_leaf_hash(&existing);
        cache.add(existing).await;
        let (mut incoming, issuer) = crate::ocsp::tests::short_lived_certificate(Some(5));
        assert_ne!(
            crate::storage::certificate_leaf_hash(&incoming),
            original_leaf
        );
        incoming.hash = hash.clone();
        incoming.managed = true;
        incoming.ocsp_response = Some(signed_staple(&incoming, &issuer, 120));
        assert!(
            cache
                .add_managed(incoming, "ocsp.example.com")
                .await
                .is_err()
        );
        let retained = cache.get_by_hash(&hash).await.unwrap();
        assert_eq!(
            crate::storage::certificate_leaf_hash(&retained),
            original_leaf
        );
        assert!(retained.ocsp_response.is_none());
        assert!(cache.resolve("ocsp.example.com").is_none());
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn lifecycle_readiness_and_eligibility_must_match_the_same_certificate() {
        let cache = CertCache::new(CacheOptions::default());
        let (mut unusable, _) = crate::ocsp::tests::short_lived_certificate(Some(5));
        unusable.managed = true;
        unusable.issuer_key = "not-due".into();
        cache.add(unusable).await;
        let (mut usable, _) = signed_certificate();
        usable.managed = true;
        usable.issuer_key = "due".into();
        cache.add(usable).await;
        assert!(cache.has_usable_managed_certificate("ocsp.example.com"));
        assert!(
            !cache.has_usable_managed_certificate_where("ocsp.example.com", |cert| cert.issuer_key
                == "not-due")
        );
        assert!(
            cache.has_usable_managed_certificate_where("ocsp.example.com", |cert| cert.issuer_key
                == "due")
        );
    }

    #[tokio::test]
    async fn managed_must_staple_readiness_uses_the_containers_actually_published() {
        for replace_other in [false, true] {
            let cache = CertCache::new(CacheOptions::default());
            let (mut required, issuer) = crate::ocsp::tests::short_lived_certificate(Some(5));
            required.managed = true;
            required.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
            required.ocsp_response = Some(signed_staple(&required, &issuer, 120));
            let hash = required.hash.clone();
            cache.add(required.clone()).await;
            let ordinary = signed_certificate().0;
            let old_hash = ordinary.hash.clone();
            cache.add(ordinary).await;
            let current_key = cache.state.read().unwrap().certificates[&hash]
                .key
                .clone()
                .unwrap();
            // Duplicate adds retain the current Good response even when the
            // imported metadata has no response of its own.
            required.ocsp_response = None;
            required.ocsp_status = None;
            if replace_other {
                cache
                    .replace_managed(&old_hash, required.clone(), "ocsp.example.com")
                    .await
                    .unwrap();
                assert!(cache.get_by_hash(&old_hash).await.is_none());
            } else {
                cache
                    .add_managed(required.clone(), "ocsp.example.com")
                    .await
                    .unwrap();
            }
            assert!(Arc::ptr_eq(
                &current_key,
                cache.state.read().unwrap().certificates[&hash]
                    .key
                    .as_ref()
                    .unwrap()
            ));

            // A stable same-hash replacement really installs the prepared
            // containers, so it can recover an unusable Unknown entry.
            cache
                .update_ocsp_if_present(&hash, Some(crate::ocsp::OcspStatus::Unknown), None)
                .await
                .unwrap();
            required.ocsp_response = Some(signed_staple(&required, &issuer, 120));
            required.ocsp_status = Some(crate::ocsp::OcspStatus::Good);
            cache
                .replace_managed(&hash, required, "ocsp.example.com")
                .await
                .unwrap();
            let current = cache.get_by_hash(&hash).await.unwrap();
            assert_eq!(current.ocsp_status, Some(crate::ocsp::OcspStatus::Good));
            assert!(
                cache
                    .resolve("ocsp.example.com")
                    .unwrap()
                    .key
                    .ocsp
                    .is_some()
            );
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
    async fn promotion_reclaims_older_entries_without_changing_the_imported_credentials() {
        let cache = CertCache::new(CacheOptions::default());
        let mut older = Vec::new();
        for _ in 0..6 {
            let (mut cert, issuer) = signed_certificate();
            cert.managed = true;
            cert.not_after = Utc::now() + ChronoDuration::days(30);
            cert.ocsp_response = Some(signed_staple(&cert, &issuer, 3600));
            older.push(cert.clone());
            cache.add(cert).await;
        }
        let (mut imported, issuer) = signed_certificate();
        imported.tags = vec!["operator".into()];
        imported.issuer_key = "managed-ca".into();
        imported.ari = Some(crate::RenewalInfo {
            suggested_window: Some(crate::acme_client::RenewalWindow {
                start: (Utc::now() + ChronoDuration::days(10)).to_rfc3339(),
                end: (Utc::now() + ChronoDuration::days(11)).to_rfc3339(),
            }),
            selected_time: Some(Utc::now() + ChronoDuration::hours(252)),
            retry_after: Some(3600),
            ..Default::default()
        });
        imported.ocsp_response = Some(signed_staple(&imported, &issuer, 3600));
        let hash = imported.hash.clone();
        cache.add(imported.clone()).await;
        let (original, key, deadline) = {
            let state = cache.state.read().unwrap();
            let entry = &state.certificates[&hash];
            (
                entry.certificate.clone(),
                entry.key.clone().unwrap(),
                entry.ocsp_deadline(),
            )
        };
        let events = Arc::new(Mutex::new(Vec::new()));
        // Model an existing over-capacity working set at the publication
        // boundary. This deliberately bypasses set_options' immediate resize
        // so one promotion must reclaim several older managed entries.
        {
            let weak = Arc::downgrade(&cache);
            let mut options = cache.options.write().unwrap();
            options.capacity = 2;
            options.on_event = Some(Arc::new({
                let events = events.clone();
                move |event| {
                    let cache = weak.upgrade().unwrap();
                    assert!(
                        cache.state.try_read().is_ok(),
                        "callback retained state lock"
                    );
                    assert!(
                        cache.options.try_read().is_ok(),
                        "callback retained options lock"
                    );
                    events.lock().unwrap().push(event);
                }
            }));
            cache.state.write().unwrap().capacity = 2;
        }
        let mut incoming = imported.clone();
        incoming.managed = true;
        incoming.tags = vec!["application".into()];
        incoming.ocsp_response = Some(vec![1, 2, 3]);
        incoming.ari = None;
        cache.add(incoming.clone()).await;
        assert_eq!(cache.count().await, 2);
        let current = cache.get_by_hash(&hash).await.unwrap();
        assert!(current.managed);
        assert_eq!(current.tags, vec!["operator", "application"]);
        assert_eq!(current.cert_chain, original.cert_chain);
        assert_eq!(current.private_key_der, original.private_key_der);
        assert_eq!(current.ocsp_response, original.ocsp_response);
        assert_eq!(current.ocsp_status, original.ocsp_status);
        assert_eq!(
            current.ari.as_ref().unwrap().selected_time,
            original.ari.as_ref().unwrap().selected_time
        );
        assert_eq!(
            serde_json::to_value(&current.ari).unwrap(),
            serde_json::to_value(&original.ari).unwrap()
        );
        assert!(!original.managed);
        assert_eq!(original.tags, vec!["operator"]);
        let removed: HashSet<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                CacheEvent::Removed { hash, .. } => Some(hash.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(removed.len(), 5);
        assert!(
            !removed.contains(&hash),
            "incoming promotion must survive repeated pool swaps"
        );
        assert_cache_indices(&cache);
        {
            let state = cache.state.read().unwrap();
            assert!(Arc::ptr_eq(
                &key,
                state.certificates[&hash].key.as_ref().unwrap()
            ));
            assert_eq!(state.certificates[&hash].ocsp_deadline(), deadline);
            let live: HashSet<_> = state.certificates.keys().cloned().collect();
            let leaves: HashSet<_> = state.chains_by_leaf.values().flatten().cloned().collect();
            let deadlines: HashSet<_> = state.ocsp_deadlines.values().flatten().cloned().collect();
            assert_eq!(leaves, live);
            assert_eq!(deadlines, live);
            assert!(
                state
                    .index
                    .values()
                    .flatten()
                    .all(|hash| live.contains(hash))
            );
        }
        assert_eq!(
            signed_cache_handshake(cache.clone(), imported.cert_chain[1].clone())
                .await
                .unwrap(),
            imported.cert_chain[0].as_ref()
        );
        // Removed leaves cannot disturb an unrelated survivor, and quarantine
        // still prevents a removed promoted leaf from being republished.
        for cert in older.iter().filter(|cert| removed.contains(&cert.hash)) {
            cache
                .deny_revoked_certificate(&crate::storage::certificate_leaf_hash(cert).unwrap())
                .await;
        }
        assert!(cache.get_by_hash(&hash).await.is_some());
        cache
            .deny_revoked_certificate(&crate::storage::certificate_leaf_hash(&imported).unwrap())
            .await;
        cache.add(incoming).await;
        assert!(cache.get_by_hash(&hash).await.is_none());
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn capacity_resize_reclaims_all_indices_and_dispatches_outside_both_locks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache = CertCache::new(CacheOptions::default());
        let mut originals = Vec::new();
        for _ in 0..6 {
            let (mut cert, issuer) = signed_certificate();
            cert.managed = true;
            cert.ocsp_response = Some(signed_staple(&cert, &issuer, 3600));
            originals.push(cert.clone());
            cache.add(cert).await;
        }
        let removed = Arc::new(AtomicUsize::new(0));
        let weak = Arc::downgrade(&cache);
        cache
            .set_options(CacheOptions {
                capacity: 1,
                on_event: Some(Arc::new({
                    let removed = removed.clone();
                    move |event| {
                        assert!(matches!(event, CacheEvent::Removed { .. }));
                        let cache = weak.upgrade().unwrap();
                        // Both guards must have been released before invoking
                        // user code, which can re-enter configuration and TLS.
                        assert_eq!(
                            cache
                                .options
                                .try_read()
                                .expect("options lock retained")
                                .capacity,
                            1
                        );
                        assert!(cache.state.try_read().is_ok(), "state lock retained");
                        assert!(cache.resolve("ocsp.example.com").is_some());
                        removed.fetch_add(1, Ordering::SeqCst);
                    }
                })),
                ..Default::default()
            })
            .await;
        assert_eq!(removed.load(Ordering::SeqCst), 5);
        let current = cache.get_all().await;
        assert_eq!(current.len(), 1);
        assert_eq!(cache.maintenance_snapshot(true).len(), 1);
        assert_cache_indices(&cache);
        {
            let state = cache.state.read().unwrap();
            assert_eq!(state.index["ocsp.example.com"].len(), 1);
            assert_eq!(state.chains_by_leaf.len(), 1);
            assert_eq!(
                state
                    .ocsp_deadlines
                    .values()
                    .map(HashSet::len)
                    .sum::<usize>(),
                1
            );
            for hashes in state
                .chains_by_leaf
                .values()
                .chain(state.ocsp_deadlines.values())
            {
                assert!(
                    hashes
                        .iter()
                        .all(|hash| state.certificates.contains_key(hash))
                );
            }
        }
        let surviving = &current[0];
        assert_eq!(
            signed_cache_handshake(cache.clone(), surviving.cert_chain[1].clone())
                .await
                .unwrap(),
            surviving.cert_chain[0].as_ref()
        );
        // Evicted leaves have no stale reverse membership; their quarantine
        // cannot remove an unrelated survivor or leave dangling deadlines.
        cache
            .set_options(CacheOptions {
                capacity: 1,
                ..Default::default()
            })
            .await;
        for cert in originals.iter().filter(|cert| cert.hash != surviving.hash) {
            let leaf = crate::storage::certificate_leaf_hash(cert).unwrap();
            cache.deny_revoked_certificate(&leaf).await;
        }
        assert!(cache.get_by_hash(&surviving.hash).await.is_some());
        assert_cache_indices(&cache);
    }

    #[tokio::test]
    async fn prepared_admission_uses_current_capacity_after_an_old_options_snapshot() {
        let cache = CertCache::new(CacheOptions::default());
        for hash in ["first", "second", "third"] {
            cache.add(make_cert(&["example.com"], hash, true)).await;
        }
        let (mut incoming, _) = signed_certificate();
        incoming.managed = true;
        let root = incoming.cert_chain[1].clone();
        let hash = incoming.hash.clone();
        let prepared = PreparedKey::for_certificate(&incoming).await;
        let leaf_hash = crate::storage::certificate_leaf_hash(&incoming);
        // Capture precisely the publication boundary that can race resizing:
        // key preparation and the callback/options snapshot are complete, but
        // publication has not acquired the certificate write lock yet.
        let old_options = cache.options.read().unwrap().clone();
        assert_eq!(old_options.capacity, 0);
        cache
            .set_options(CacheOptions {
                capacity: 1,
                ..Default::default()
            })
            .await;
        let mut events = Vec::new();
        cache
            .state
            .write()
            .unwrap()
            .add(incoming, prepared, leaf_hash, &mut events);
        cache.notify_ocsp_schedule();
        dispatch_events(&old_options, events);
        assert_eq!(cache.count().await, 1);
        assert!(cache.get_by_hash(&hash).await.is_some());
        assert_cache_indices(&cache);
        assert!(signed_cache_handshake(cache, root).await.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_resize_and_publication_keep_the_latest_finite_bound() {
        let cache = CertCache::new(CacheOptions::default());
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let publisher = tokio::spawn({
            let cache = cache.clone();
            let barrier = barrier.clone();
            async move {
                for index in 0..128 {
                    barrier.wait().await;
                    cache
                        .add(make_cert(
                            &["example.com"],
                            &format!("concurrent-{index}"),
                            true,
                        ))
                        .await;
                    barrier.wait().await;
                }
            }
        });
        for index in 0..128 {
            barrier.wait().await;
            let capacity = 1 + index % 4;
            cache
                .set_options(CacheOptions {
                    capacity,
                    ..Default::default()
                })
                .await;
            barrier.wait().await;
            assert!(cache.count().await <= capacity);
        }
        publisher.await.unwrap();
        assert_cache_indices(&cache);
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
