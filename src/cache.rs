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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rand::Rng;
use tokio::sync::{RwLock, watch};
use tracing::{debug, info};

use crate::certificates::Certificate;
use crate::error::Result;

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
    pub get_config_for_cert:
        Option<Arc<dyn Fn(&Certificate) -> Arc<dyn std::any::Any + Send + Sync> + Send + Sync>>,
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
/// Wildcard matching is performed by replacing each label of the queried
/// domain with `*` and checking the index.
///
/// When the cache is dropped (or [`CertCache::stop`] is called), any
/// background maintenance task is signalled to stop.
///
/// **Do not construct this struct directly** -- use [`CertCache::new`].
pub struct CertCache {
    /// Primary store: certificate hash -> Certificate.
    cache: RwLock<HashMap<String, Certificate>>,

    /// Name index: lowercase SAN -> list of certificate hashes.
    cache_index: RwLock<HashMap<String, Vec<String>>>,

    /// Cache configuration. Wrapped in a `RwLock` so options can be updated
    /// at runtime (e.g. via `set_options`).
    options: RwLock<CacheOptions>,

    /// Sender half of a watch channel used to signal the maintenance task to
    /// stop. Sending `true` requests a graceful shutdown.
    stop_tx: watch::Sender<bool>,

    /// Receiver half of a watch channel that the maintenance loop signals
    /// (by sending `true`) when it has exited. Used by [`CertCache::stop_and_wait`].
    done_rx: RwLock<watch::Receiver<bool>>,

    /// Sender half of the "done" watch channel, exposed so that the
    /// maintenance loop can signal completion.
    done_tx: watch::Sender<bool>,
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertCache")
            .field("cache", &"<RwLock<HashMap>>")
            .field("cache_index", &"<RwLock<HashMap>>")
            .finish()
    }
}

impl CertCache {
    /// Create a new certificate cache with the given options.
    ///
    /// The returned cache is wrapped in an `Arc` for shared ownership.
    /// A background maintenance task is **not** started automatically; call
    /// [`start_maintenance`](crate::maintain::start_maintenance) if periodic renewal/OCSP checking
    /// is desired.
    pub fn new(options: CacheOptions) -> Arc<Self> {
        let opts = normalize_options(options);
        let (stop_tx, _stop_rx) = watch::channel(false);
        let (done_tx, done_rx) = watch::channel(false);

        Arc::new(Self {
            cache: RwLock::new(HashMap::new()),
            cache_index: RwLock::new(HashMap::new()),
            options: RwLock::new(opts),
            stop_tx,
            done_rx: RwLock::new(done_rx),
            done_tx,
        })
    }

    /// Update the cache options at runtime.
    ///
    /// Intervals that are zero or negative are replaced with their defaults.
    pub async fn set_options(&self, options: CacheOptions) {
        let opts = normalize_options(options);
        let mut guard = self.options.write().await;
        *guard = opts;
    }

    /// Signal the maintenance task (if running) to stop.
    ///
    /// This is a non-blocking operation. The maintenance task will observe
    /// the signal on its next iteration and exit gracefully.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Subscribe to the stop signal. Returns a `watch::Receiver<bool>` that
    /// yields `true` when the cache is being shut down.
    pub fn subscribe_stop(&self) -> watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    /// Signal the maintenance task to stop and wait until it has actually
    /// exited.
    ///
    /// This sends the stop signal and then awaits the "done" channel that
    /// the maintenance loop signals on exit. If no maintenance loop is
    /// running, this returns immediately after sending the stop signal.
    pub async fn stop_and_wait(&self) {
        let _ = self.stop_tx.send(true);

        let mut done_rx = self.done_rx.write().await;
        // If already done, return immediately.
        if *done_rx.borrow() {
            return;
        }
        // Wait for the maintenance loop to signal done.
        let _ = done_rx.changed().await;
    }

    /// Signal that the maintenance loop has exited.
    ///
    /// This is called by the maintenance loop when it is about to return,
    /// so that [`CertCache::stop_and_wait`] can resolve.
    pub fn signal_done(&self) {
        let _ = self.done_tx.send(true);
    }

    // -----------------------------------------------------------------------
    // Add / update
    // -----------------------------------------------------------------------

    /// Add a certificate to the cache.
    ///
    /// If a certificate with the same hash already exists, its tags are merged
    /// (any tags present on `cert` but missing from the cached copy are
    /// appended) and no duplicate is created.
    ///
    /// When the cache is at capacity, a random **managed** certificate is
    /// evicted to make room.
    pub async fn add(&self, cert: Certificate) {
        let mut cache = self.cache.write().await;
        let mut index = self.cache_index.write().await;
        let options = self.options.read().await;

        self.unsynced_add(&mut cache, &mut index, &options, cert)
            .await;
    }

    /// Internal add implementation that operates on already-locked maps.
    async fn unsynced_add(
        &self,
        cache: &mut HashMap<String, Certificate>,
        index: &mut HashMap<String, Vec<String>>,
        options: &CacheOptions,
        cert: Certificate,
    ) {
        let cert_hash = cert.hash.clone();

        // If the certificate already exists, merge tags and return.
        if let Some(existing) = cache.get_mut(&cert_hash) {
            let mut merged = false;
            for tag in &cert.tags {
                if !existing.tags.contains(tag) {
                    existing.tags.push(tag.clone());
                    merged = true;
                }
            }

            let log_action = if merged {
                "certificate already cached; appended missing tags"
            } else {
                "certificate already cached"
            };
            debug!(
                subjects = ?cert.names,
                managed = cert.managed,
                issuer_key = %cert.issuer_key,
                hash = %cert_hash,
                log_action,
            );

            if let Some(ref on_event) = options.on_event {
                on_event(CacheEvent::Updated {
                    names: cert.names.clone(),
                    hash: cert_hash,
                });
            }
            return;
        }

        // Evict a random managed cert if at capacity.
        if options.capacity > 0 && cache.len() >= options.capacity {
            let cache_size = cache.len();
            let target_idx = {
                use rand::RngExt;
                rand::rng().random_range(0..cache_size)
            };

            // Collect all hashes so we can pick one by index.
            let hashes: Vec<String> = cache.keys().cloned().collect();

            // Starting from the random index, find the first managed cert to evict.
            for offset in 0..cache_size {
                let idx = (target_idx + offset) % cache_size;
                let hash = &hashes[idx];
                if let Some(evict_cert) = cache.get(hash) {
                    if evict_cert.managed {
                        let evict_names = evict_cert.names.clone();
                        let evict_hash = evict_cert.hash.clone();

                        debug!(
                            removing_subjects = ?evict_names,
                            removing_hash = %evict_hash,
                            inserting_subjects = ?cert.names,
                            inserting_hash = %cert_hash,
                            "cache full; evicting random managed certificate",
                        );

                        Self::unsynced_remove_by_hash(cache, index, &evict_hash);

                        if let Some(ref on_event) = options.on_event {
                            on_event(CacheEvent::Removed {
                                names: evict_names,
                                hash: evict_hash,
                            });
                        }
                        break;
                    }
                }
            }
        }

        // Update the name index.
        for name in &cert.names {
            let lower = name.to_lowercase();
            index.entry(lower).or_default().push(cert_hash.clone());
        }

        let event_names = cert.names.clone();
        let event_hash = cert_hash.clone();

        info!(
            subjects = ?cert.names,
            managed = cert.managed,
            issuer_key = %cert.issuer_key,
            hash = %cert_hash,
            expires = %cert.not_after,
            cache_size = cache.len() + 1,
            cache_capacity = options.capacity,
            "added certificate to cache",
        );

        // Store the certificate.
        cache.insert(cert_hash, cert);

        if let Some(ref on_event) = options.on_event {
            on_event(CacheEvent::Added {
                names: event_names,
                hash: event_hash,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Remove
    // -----------------------------------------------------------------------

    /// Remove a certificate from the cache by its hash.
    pub async fn remove(&self, hash: &str) {
        let mut cache = self.cache.write().await;
        let mut index = self.cache_index.write().await;
        let options = self.options.read().await;

        if let Some(cert) = cache.get(hash) {
            let names = cert.names.clone();
            let hash_owned = hash.to_owned();

            Self::unsynced_remove_by_hash(&mut cache, &mut index, hash);

            debug!(
                subjects = ?names,
                hash = %hash_owned,
                cache_size = cache.len(),
                "removed certificate from cache",
            );

            if let Some(ref on_event) = options.on_event {
                on_event(CacheEvent::Removed {
                    names,
                    hash: hash_owned,
                });
            }
        }
    }

    /// Remove certificates with the given hashes from the cache.
    ///
    /// Certificates whose hashes are not found in the cache are silently
    /// skipped. The operation holds a single write lock for the entire batch.
    pub async fn remove_many(&self, hashes: &[String]) {
        let mut cache = self.cache.write().await;
        let mut index = self.cache_index.write().await;
        let options = self.options.read().await;

        for hash in hashes {
            if let Some(cert) = cache.get(hash.as_str()) {
                let names = cert.names.clone();
                let hash_owned = hash.clone();

                Self::unsynced_remove_by_hash(&mut cache, &mut index, hash);

                if let Some(ref on_event) = options.on_event {
                    on_event(CacheEvent::Removed {
                        names,
                        hash: hash_owned,
                    });
                }
            }
        }
    }

    /// Remove managed certificates matching the given subjects (and optionally
    /// issuer keys) from the cache.
    ///
    /// If [`SubjectIssuer::issuer_key`] is empty, all managed certificates for
    /// that subject are removed regardless of issuer.
    pub async fn remove_managed(&self, subjects: &[SubjectIssuer]) {
        let mut to_remove = Vec::new();

        for subj in subjects {
            let lower = subj.subject.to_lowercase();
            let certs = self.get_all_matching_exact(&lower).await;
            for cert in certs {
                if !cert.managed {
                    continue;
                }
                if subj.issuer_key.is_empty() || cert.issuer_key == subj.issuer_key {
                    to_remove.push(cert.hash.clone());
                }
            }
        }

        self.remove_many(&to_remove).await;
    }

    /// Internal removal that operates on already-locked maps.
    fn unsynced_remove_by_hash(
        cache: &mut HashMap<String, Certificate>,
        index: &mut HashMap<String, Vec<String>>,
        hash: &str,
    ) {
        if let Some(cert) = cache.remove(hash) {
            // Remove all index entries for this cert.
            for name in &cert.names {
                let lower = name.to_lowercase();
                if let Some(hashes) = index.get_mut(&lower) {
                    hashes.retain(|h| h != hash);
                    if hashes.is_empty() {
                        index.remove(&lower);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Replace
    // -----------------------------------------------------------------------

    /// Atomically replace an old certificate with a new one.
    ///
    /// The old certificate is removed and the new one is added in a single
    /// lock acquisition, ensuring no window where neither certificate is
    /// available.
    pub async fn replace(&self, old_hash: &str, new_cert: Certificate) {
        let mut cache = self.cache.write().await;
        let mut index = self.cache_index.write().await;
        let options = self.options.read().await;

        // Remove old cert.
        if let Some(old_cert) = cache.get(old_hash) {
            let old_names = old_cert.names.clone();
            let old_hash_owned = old_hash.to_owned();
            Self::unsynced_remove_by_hash(&mut cache, &mut index, old_hash);

            if let Some(ref on_event) = options.on_event {
                on_event(CacheEvent::Removed {
                    names: old_names,
                    hash: old_hash_owned,
                });
            }
        }

        let new_names = new_cert.names.clone();
        let new_expires = new_cert.not_after;

        // Add new cert.
        self.unsynced_add(&mut cache, &mut index, &options, new_cert)
            .await;

        info!(
            subjects = ?new_names,
            expires = %new_expires,
            "replaced certificate in cache",
        );
    }

    // -----------------------------------------------------------------------
    // Lookups
    // -----------------------------------------------------------------------

    /// Look up a certificate by domain name.
    ///
    /// The lookup follows this strategy:
    /// 1. Exact match on the lowercase name.
    /// 2. Wildcard match: replace the first label with `*` and try again (e.g. `sub.example.com` ->
    ///    `*.example.com`).
    ///
    /// When multiple certificates match, the best one is selected:
    /// - Non-expired certificates are preferred over expired ones.
    /// - Among non-expired certs, the one with the longest remaining lifetime wins.
    /// - Managed certificates are preferred over unmanaged ones.
    pub async fn get_by_name(&self, name: &str) -> Option<Certificate> {
        let candidates = self.all_matching_certificates(name).await;
        select_best_certificate(candidates)
    }

    /// Look up a certificate by its content hash.
    pub async fn get_by_hash(&self, hash: &str) -> Option<Certificate> {
        let cache = self.cache.read().await;
        cache.get(hash).cloned()
    }

    /// Return all certificates that could serve the given name, including
    /// both exact and wildcard matches.
    ///
    /// Each label of the domain is replaced with `*` in turn to search for
    /// wildcard certificates. For example, looking up `sub.example.com` will
    /// also check `*.example.com`, `sub.*.com`, and `sub.example.*`. This
    pub async fn all_matching_certificates(&self, name: &str) -> Vec<Certificate> {
        let lower = name.to_lowercase();
        let mut certs = self.get_all_matching_exact(&lower).await;

        // Try wildcard matches by replacing each label with '*'.
        let labels: Vec<&str> = lower.split('.').collect();
        let mut wildcard_labels: Vec<String> = labels.iter().map(|l| l.to_string()).collect();
        for i in 0..wildcard_labels.len() {
            let original = wildcard_labels[i].clone();
            wildcard_labels[i] = "*".to_string();
            let candidate = wildcard_labels.join(".");
            let mut wildcard_certs = self.get_all_matching_exact(&candidate).await;
            certs.append(&mut wildcard_certs);
            wildcard_labels[i] = original;
        }

        certs
    }

    /// Return all certificates whose index entry exactly matches `subject`
    /// (no wildcard expansion).
    async fn get_all_matching_exact(&self, subject: &str) -> Vec<Certificate> {
        let cache = self.cache.read().await;
        let index = self.cache_index.read().await;

        match index.get(subject) {
            Some(hashes) => hashes
                .iter()
                .filter_map(|h| cache.get(h).cloned())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Return the number of certificates currently in the cache.
    pub async fn count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Return all certificates currently in the cache.
    pub async fn get_all(&self) -> Vec<Certificate> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    /// Return all managed certificates in the cache.
    pub async fn get_managed_certificates(&self) -> Vec<Certificate> {
        let cache = self.cache.read().await;
        cache.values().filter(|c| c.managed).cloned().collect()
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
    /// certificates.
    pub async fn cache_unmanaged_pem(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
        tags: Vec<String>,
    ) -> Result<()> {
        let mut cert = Certificate::from_pem(cert_pem, key_pem)?;
        cert.managed = false;
        cert.tags = tags;
        self.add(cert).await;
        Ok(())
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
    /// certificate cannot be parsed.
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
        self.add(cert).await;
        Ok(())
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
    /// certificates.
    pub async fn cache_unmanaged_replacing(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
        tags: Vec<String>,
    ) -> Result<()> {
        let mut cert = Certificate::from_pem(cert_pem, key_pem)?;
        cert.managed = false;
        cert.tags = tags;

        // Collect hashes of all existing certs that share any SAN with the
        // new certificate so they can be removed.
        let mut to_remove = Vec::new();
        for name in &cert.names {
            let existing = self.all_matching_certificates(name).await;
            for existing_cert in existing {
                if !to_remove.contains(&existing_cert.hash) {
                    to_remove.push(existing_cert.hash.clone());
                }
            }
        }

        // Remove old certs, then add the new one.
        if !to_remove.is_empty() {
            self.remove_many(&to_remove).await;
        }
        self.add(cert).await;
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
fn select_best_certificate(mut candidates: Vec<Certificate>) -> Option<Certificate> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(candidates.remove(0));
    }

    let now = Utc::now();

    candidates.sort_by(|a, b| {
        let a_expired = a.not_after < now;
        let b_expired = b.not_after < now;

        // Prefer non-expired.
        match (a_expired, b_expired) {
            (false, true) => return std::cmp::Ordering::Less,
            (true, false) => return std::cmp::Ordering::Greater,
            _ => {}
        }

        // Prefer managed.
        match (a.managed, b.managed) {
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            _ => {}
        }

        // Prefer longer remaining lifetime (later not_after).
        b.not_after.cmp(&a.not_after)
    });

    Some(candidates.remove(0))
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
}
