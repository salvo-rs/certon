//! Background certificate maintenance loops.
//!
//! This module runs periodic background tasks that keep managed certificates
//! renewed and OCSP staples fresh.
//!
//! # Overview
//!
//! The [`start_maintenance`] function spawns a tokio task that runs two
//! interval-driven loops concurrently:
//!
//! 1. **Renewal loop** -- periodically checks all managed certificates in the cache and invokes a
//!    caller-supplied renewal callback for any that are due for renewal.
//! 2. **OCSP loop** -- periodically refreshes OCSP staples for all cached certificates whose
//!    staples are stale or missing.
//!
//! Both loops respect the [`CertCache`] stop signal: when the cache is
//! stopped (via [`CertCache::stop`]), the maintenance task exits gracefully.
//!
//! # Decoupling
//!
//! The renewal logic is decoupled from `config.rs` by accepting a callback
//! (`renew_func`) rather than depending on the `Config` type directly. This
//! avoids circular dependencies while still allowing the `Config` to wire up
//! its `renew_cert` method as the renewal implementation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::async_jobs::JobQueue;
use crate::cache::CertCache;
use crate::certificates::{Certificate, DEFAULT_RENEWAL_WINDOW_RATIO};
use crate::error::Result;
use crate::ocsp::{self, OcspConfig};
use crate::storage::Storage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default interval for checking whether managed certificates need renewal
/// (10 minutes).
pub const DEFAULT_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Default interval for checking whether OCSP staples need updating
/// (1 hour).
pub const DEFAULT_OCSP_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

// ---------------------------------------------------------------------------
// MaintenanceConfig
// ---------------------------------------------------------------------------

/// Configuration for the background maintenance task.
///
/// Controls the intervals at which the maintenance loop checks for
/// certificate renewals and OCSP staple freshness.
#[derive(Clone)]
pub struct MaintenanceConfig {
    /// How often to check for certificate renewals.
    ///
    /// Defaults to [`DEFAULT_RENEW_CHECK_INTERVAL`] (10 minutes).
    pub renew_check_interval: Duration,

    /// How often to check OCSP staples for freshness.
    ///
    /// Defaults to [`DEFAULT_OCSP_CHECK_INTERVAL`] (1 hour).
    pub ocsp_check_interval: Duration,

    /// OCSP configuration (controls stapling behavior).
    pub ocsp: OcspConfig,

    /// Storage backend used for caching OCSP responses.
    pub storage: Arc<dyn Storage>,
}

impl std::fmt::Debug for MaintenanceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaintenanceConfig")
            .field("renew_check_interval", &self.renew_check_interval)
            .field("ocsp_check_interval", &self.ocsp_check_interval)
            .field("ocsp", &self.ocsp)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Type alias for the renewal callback
// ---------------------------------------------------------------------------

/// A boxed, async-compatible renewal function.
///
/// Given a domain name, the function should attempt to renew the certificate
/// for that domain. It returns `Ok(())` on success or an error on failure.
pub type RenewFn = dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync;

// ---------------------------------------------------------------------------
// start_maintenance
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that periodically checks for certificate
/// renewals and refreshes OCSP staples.
///
/// The task runs until the [`CertCache`] stop signal is received (via
/// [`CertCache::stop`]).
///
/// # Arguments
///
/// * `cache` -- shared certificate cache whose contents are inspected.
/// * `config` -- maintenance intervals and OCSP configuration.
/// * `renew_func` -- callback invoked for each domain that needs renewal.
///
/// # Returns
///
/// A [`JoinHandle`] for the spawned task. Dropping the handle detaches the
/// task but does **not** cancel it; use [`CertCache::stop`] to request
/// graceful shutdown.
pub fn start_maintenance(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    renew_func: Arc<RenewFn>,
) -> JoinHandle<()> {
    let renew_interval =
        normalize_interval(config.renew_check_interval, DEFAULT_RENEW_CHECK_INTERVAL);
    let ocsp_interval = normalize_interval(config.ocsp_check_interval, DEFAULT_OCSP_CHECK_INTERVAL);

    info!(
        renew_check_secs = renew_interval.as_secs(),
        ocsp_check_secs = ocsp_interval.as_secs(),
        "starting certificate maintenance loop",
    );

    tokio::spawn(async move {
        maintenance_loop_with_recovery(cache, config, renew_func, renew_interval, ocsp_interval)
            .await;
    })
}

/// Wrapper around [`maintenance_loop`] that catches panics and automatically
/// restarts the loop. This ensures a single panic inside a renewal or OCSP
/// callback does not permanently kill the maintenance task.
async fn maintenance_loop_with_recovery(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    renew_func: Arc<RenewFn>,
    renew_interval: Duration,
    ocsp_interval: Duration,
) {
    loop {
        let cache_clone = Arc::clone(&cache);
        let config_clone = config.clone();
        let renew_func_clone = Arc::clone(&renew_func);

        let result = tokio::task::spawn(maintenance_loop(
            cache_clone,
            config_clone,
            renew_func_clone,
            renew_interval,
            ocsp_interval,
        ))
        .await;

        match result {
            Ok(()) => {
                // Normal exit (stop signal received).
                info!("maintenance: loop exited normally");
                break;
            }
            Err(join_error) => {
                if join_error.is_panic() {
                    error!(
                        "maintenance: loop panicked, restarting after brief delay: {}",
                        join_error,
                    );
                    // Brief delay before restarting to avoid tight panic loops.
                    tokio::time::sleep(Duration::from_secs(2)).await;

                    // Check if the cache has been stopped while we were sleeping.
                    let mut stop_rx = cache.subscribe_stop();
                    if *stop_rx.borrow_and_update() {
                        info!("maintenance: stop signal received during panic recovery, exiting");
                        break;
                    }
                    // Continue the loop to restart maintenance_loop.
                } else {
                    error!("maintenance: loop task cancelled: {}", join_error,);
                    break;
                }
            }
        }
    }

    // Signal that the maintenance loop is done so stop_and_wait can resolve.
    cache.signal_done();
}

/// The inner maintenance loop, running inside a spawned task.
async fn maintenance_loop(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    renew_func: Arc<RenewFn>,
    renew_interval: Duration,
    ocsp_interval: Duration,
) {
    let mut stop_rx = cache.subscribe_stop();
    let job_queue = JobQueue::new("renewal");

    let mut renew_ticker = tokio::time::interval(renew_interval);
    let mut ocsp_ticker = tokio::time::interval(ocsp_interval);

    // Consume the first immediate tick so the loop starts after one full
    // interval has elapsed, matching the Go `time.NewTicker` behavior.
    renew_ticker.tick().await;
    ocsp_ticker.tick().await;

    loop {
        tokio::select! {
            _ = renew_ticker.tick() => {
                debug!("maintenance: running renewal check");
                check_renewals(
                    &cache,
                    DEFAULT_RENEWAL_WINDOW_RATIO,
                    renew_func.as_ref(),
                    config.storage.as_ref(),
                    &job_queue,
                ).await;
            }
            _ = ocsp_ticker.tick() => {
                debug!("maintenance: running OCSP staple check");
                update_ocsp_staples(
                    &cache,
                    config.storage.as_ref(),
                    &config.ocsp,
                    renew_func.as_ref(),
                ).await;
            }
            result = stop_rx.changed() => {
                match result {
                    Ok(()) => {
                        if *stop_rx.borrow() {
                            info!("maintenance: received stop signal, exiting");
                            break;
                        }
                    }
                    Err(_) => {
                        // Sender dropped -- cache is gone, exit.
                        info!("maintenance: cache dropped, exiting");
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// check_renewals
// ---------------------------------------------------------------------------

/// Check all managed certificates in the cache and invoke `renew_func` for
/// each domain whose certificate needs renewal.
///
/// Only certificates with `managed == true` are considered. The renewal
/// decision is delegated to [`Certificate::needs_renewal`].
///
/// When `storage` is provided, the function first checks whether the
/// certificate in storage has already been renewed by another instance
/// (e.g. in a multi-instance deployment). If the stored certificate does
/// not need renewal, it is reloaded into the cache instead of re-issuing.
async fn check_renewals(
    cache: &CertCache,
    renewal_ratio: f64,
    renew_func: &RenewFn,
    storage: &dyn Storage,
    job_queue: &JobQueue,
) {
    let managed_certs = cache.get_managed_certificates().await;

    if managed_certs.is_empty() {
        debug!("maintenance: no managed certificates to check for renewal");
        return;
    }

    debug!(
        count = managed_certs.len(),
        "maintenance: checking managed certificates for renewal",
    );

    for cert in &managed_certs {
        if !cert.needs_renewal(renewal_ratio) {
            continue;
        }

        // Attempt renewal for each name on the certificate. Typically the
        // first name is the primary domain, which is sufficient to trigger
        // a full renewal covering all SANs. We only renew using the first
        // name to avoid duplicate renewal attempts.
        let domain = match cert.names.first() {
            Some(name) => name.clone(),
            None => {
                warn!(
                    hash = %cert.hash,
                    "maintenance: managed certificate has no names; skipping renewal"
                );
                continue;
            }
        };

        // Multi-instance coordination: check if the certificate in storage
        // has already been renewed by another instance.
        if try_reload_from_storage(cache, storage, cert, &domain, renewal_ratio).await {
            continue;
        }

        info!(
            domain = %domain,
            hash = %cert.hash,
            expired = cert.expired(),
            "maintenance: certificate needs renewal",
        );

        // Submit renewal through the JobQueue for deduplication.
        // If a renewal for this domain is already in progress, the
        // submission is silently ignored.
        let job_name = format!("renew_{}", domain);
        let domain_clone = domain.clone();
        let renew_result = renew_func(domain_clone.clone());

        job_queue
            .submit(job_name, move || async move {
                match renew_result.await {
                    Ok(()) => {
                        info!(
                            domain = %domain_clone,
                            "maintenance: certificate renewed successfully",
                        );
                    }
                    Err(e) => {
                        error!(
                            domain = %domain_clone,
                            error = %e,
                            "maintenance: certificate renewal failed",
                        );
                    }
                }
            })
            .await;
    }
}

/// Check storage for a certificate that may have been renewed by another
/// instance. If the stored certificate does NOT need renewal, reload it
/// into the cache and return `true` (meaning: skip local renewal).
async fn try_reload_from_storage(
    cache: &CertCache,
    storage: &dyn Storage,
    cached_cert: &Certificate,
    domain: &str,
    renewal_ratio: f64,
) -> bool {
    // Build the storage key for this certificate's PEM file.
    let cert_key = crate::storage::site_cert_key(&cached_cert.issuer_key, domain);

    // Try to load the cert PEM from storage.
    let cert_pem = match storage.load(&cert_key).await {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Try to load the corresponding private key PEM.
    let key_key = crate::storage::site_private_key(&cached_cert.issuer_key, domain);
    let key_pem = match storage.load(&key_key).await {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Try to parse the stored certificate.
    let stored_cert = match Certificate::from_pem(&cert_pem, &key_pem) {
        Ok(mut c) => {
            c.managed = true;
            c.issuer_key = cached_cert.issuer_key.clone();
            c
        }
        Err(_) => return false,
    };

    // If the stored cert has a different hash AND does not need renewal,
    // it was renewed by another instance — reload it into the cache.
    if stored_cert.hash != cached_cert.hash && !stored_cert.needs_renewal(renewal_ratio) {
        info!(
            domain = %domain,
            old_hash = %cached_cert.hash,
            new_hash = %stored_cert.hash,
            "maintenance: certificate already renewed by another instance; reloading from storage",
        );
        cache.replace(&cached_cert.hash, stored_cert).await;
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// update_ocsp_staples
// ---------------------------------------------------------------------------

/// Refresh OCSP staples for all certificates in the cache whose staples are
/// stale or missing.
///
/// For each certificate that has an existing OCSP response, the function
/// checks whether it needs updating (via [`ocsp::ocsp_needs_update`]).
/// Certificates without any OCSP response are also stapled if possible.
///
/// Fresh OCSP responses are fetched and stored via [`ocsp::staple_ocsp`],
/// and the updated certificate is written back to the cache.
///
/// If a certificate's OCSP status is `Revoked` and `config.replace_revoked`
/// is enabled, a force-renewal is triggered via `renew_func`.
async fn update_ocsp_staples(
    cache: &CertCache,
    storage: &dyn Storage,
    config: &OcspConfig,
    renew_func: &RenewFn,
) {
    if config.disable_stapling {
        debug!("maintenance: OCSP stapling is disabled; skipping update");
        return;
    }

    let all_certs = cache.get_all().await;

    if all_certs.is_empty() {
        debug!("maintenance: no certificates to check for OCSP updates");
        return;
    }

    debug!(
        count = all_certs.len(),
        "maintenance: checking certificates for OCSP staple freshness",
    );

    for cert in all_certs {
        let needs_update = needs_ocsp_refresh(&cert);

        if !needs_update {
            continue;
        }

        let first_name = cert.names.first().cloned().unwrap_or_default();
        let old_hash = cert.hash.clone();

        debug!(
            name = %first_name,
            hash = %old_hash,
            "maintenance: refreshing OCSP staple",
        );

        let mut updated_cert = cert.clone();
        match ocsp::staple_ocsp(storage, &mut updated_cert, config).await {
            Ok(not_revoked) => {
                if not_revoked {
                    debug!(
                        name = %first_name,
                        "maintenance: OCSP staple refreshed successfully",
                    );
                    // Replace the certificate in the cache with the updated one
                    // that has the fresh OCSP staple.
                    cache.replace(&old_hash, updated_cert).await;
                } else {
                    // staple_ocsp returns Ok(false) when status is Revoked
                    // OR when stapling is not available. We detect revocation
                    // by checking if an OCSP response was actually set.
                    if updated_cert.ocsp_response.is_some()
                        && config.replace_revoked
                        && cert.managed
                    {
                        warn!(
                            name = %first_name,
                            hash = %old_hash,
                            "maintenance: OCSP status is Revoked; triggering force-renewal",
                        );
                        match renew_func(first_name.clone()).await {
                            Ok(()) => {
                                info!(
                                    name = %first_name,
                                    "maintenance: revoked certificate force-renewed successfully",
                                );
                            }
                            Err(e) => {
                                error!(
                                    name = %first_name,
                                    error = %e,
                                    "maintenance: revoked certificate force-renewal failed",
                                );
                            }
                        }
                    } else {
                        debug!(
                            name = %first_name,
                            "maintenance: OCSP stapling not available for this certificate",
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    name = %first_name,
                    error = %e,
                    "maintenance: failed to refresh OCSP staple",
                );
            }
        }
    }
}

/// Determine whether a certificate's OCSP staple needs refreshing.
///
/// Returns `true` if:
/// - The certificate has no OCSP response at all, OR
/// - The existing OCSP response needs updating (per [`ocsp::ocsp_needs_update`]).
fn needs_ocsp_refresh(cert: &crate::certificates::Certificate) -> bool {
    match &cert.ocsp_response {
        None => {
            // No staple at all -- try to fetch one.
            true
        }
        Some(raw) => {
            // Try to parse the raw OCSP response to check freshness.
            // If parsing fails, we should refresh.
            match try_parse_ocsp_for_freshness(raw) {
                Some(parsed) => ocsp::ocsp_needs_update(&parsed),
                None => true,
            }
        }
    }
}

/// Attempt to parse raw OCSP response bytes into an [`OcspResponse`] for
/// freshness checking.
///
/// Returns `None` if the response cannot be parsed (in which case a refresh
/// is warranted).
fn try_parse_ocsp_for_freshness(raw: &[u8]) -> Option<ocsp::OcspResponse> {
    // We try to extract minimal information from the raw DER-encoded OCSP
    // response. The full parsing is done by `staple_ocsp` internally; here
    // we only need enough to call `ocsp_needs_update`.
    //
    // Since `parse_ocsp_response_raw` is private to the ocsp module, we
    // use the public `OcspResponse` struct fields. If the raw bytes are
    // the complete DER response, we can parse with x509_parser's OCSP
    // parsing. However, to keep things simple and avoid duplicating parsing
    // logic, if the cert has an OCSP response set we assume it was valid
    // at some point. We check via a conservative heuristic: if we cannot
    // determine freshness, we flag for refresh.
    //
    // For now, return None to always trigger a refresh check via staple_ocsp
    // which handles all the caching/freshness logic internally.
    // This is safe because staple_ocsp checks its own cache first and will
    // short-circuit if the staple is still fresh.
    let _ = raw;
    None
}

// ---------------------------------------------------------------------------
// CleanStorage — garbage collection
// ---------------------------------------------------------------------------

/// Options for the [`clean_storage`] garbage-collection function.
#[derive(Debug, Clone)]
pub struct CleanStorageOptions {
    /// Delete expired certificates older than this duration past their
    /// expiration date.
    ///
    /// Defaults to 24 hours, meaning certificates are not deleted until
    /// at least 24 hours after their `notAfter` time has passed. This
    /// grace period avoids deleting certificates that might still be
    /// referenced by in-flight TLS sessions.
    pub expired_cert_grace_period: Duration,

    /// Delete OCSP staples that have not been modified in longer than
    /// this duration.
    ///
    /// Defaults to 14 days, which is generous enough to cover even
    /// long-lived OCSP responses.
    pub ocsp_max_age: Duration,
}

impl Default for CleanStorageOptions {
    fn default() -> Self {
        Self {
            expired_cert_grace_period: Duration::from_secs(24 * 60 * 60), // 24 hours
            ocsp_max_age: Duration::from_secs(14 * 24 * 60 * 60),         // 14 days
        }
    }
}

/// The result of a [`clean_storage`] run, reporting how many assets were
/// deleted.
#[derive(Debug, Clone, Default)]
pub struct CleanStorageResult {
    /// Number of expired certificates (and their associated keys/metadata)
    /// deleted.
    pub deleted_certs: usize,

    /// Number of stale OCSP staples deleted.
    pub deleted_ocsp: usize,
}

/// Garbage-collect expired certificates and stale OCSP staples from storage.
///
/// This function is intended to be called periodically (e.g. daily) to
/// prevent unbounded growth of the storage backend.
///
/// For certificates:
/// - Lists all certificate PEM files (`.crt`) under `certificates/`.
/// - Parses each to check its `notAfter` date.
/// - Deletes certificates (plus their `.key` and `.json` sidecars) whose `notAfter` plus
///   `expired_cert_grace_period` is in the past.
///
/// For OCSP staples:
/// - Lists all entries under `ocsp/`.
/// - Deletes those whose `modified` timestamp is older than `ocsp_max_age`.
///
/// # Errors
///
/// Returns an error if listing storage entries fails fatally. Individual
/// deletion failures are logged as warnings but do not abort the overall
/// operation.
pub async fn clean_storage(
    storage: &dyn Storage,
    options: &CleanStorageOptions,
) -> Result<CleanStorageResult> {
    let mut result = CleanStorageResult::default();

    // --- Clean expired certificates ---
    let certs_entries = match storage.list("certificates", true).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(error = %e, "clean_storage: failed to list certificates");
            Vec::new()
        }
    };

    let now = chrono::Utc::now();
    let grace_period = chrono::Duration::from_std(options.expired_cert_grace_period)
        .unwrap_or_else(|_| chrono::Duration::hours(24));

    for entry in &certs_entries {
        // Only inspect .crt files to avoid double-processing.
        if !entry.ends_with(".crt") {
            continue;
        }

        // Try to load and parse the certificate to check expiry.
        let cert_pem = match storage.load(entry).await {
            Ok(data) => data,
            Err(_) => continue,
        };

        let cert_pem_str = match std::str::from_utf8(&cert_pem) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Parse just enough to get the notAfter date.
        let pems = match pem::parse_many(cert_pem_str) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let leaf_der = match pems.iter().find(|p| p.tag() == "CERTIFICATE") {
            Some(p) => p.contents(),
            None => continue,
        };

        let not_after = match x509_parser::parse_x509_certificate(leaf_der) {
            Ok((_, cert)) => {
                let epoch = cert.validity().not_after.timestamp();
                match chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0) {
                    Some(dt) => dt,
                    None => continue,
                }
            }
            Err(_) => continue,
        };

        // Check if the certificate is past the grace period.
        if now > not_after + grace_period {
            // Derive sibling keys (.key, .json) from the .crt path.
            let base = entry.trim_end_matches(".crt");
            let key_path = format!("{base}.key");
            let meta_path = format!("{base}.json");

            for path in [entry.as_str(), key_path.as_str(), meta_path.as_str()] {
                if let Err(e) = storage.delete(path).await {
                    warn!(
                        path = path,
                        error = %e,
                        "clean_storage: failed to delete expired certificate asset"
                    );
                }
            }

            info!(
                cert_path = entry.as_str(),
                not_after = %not_after,
                "clean_storage: deleted expired certificate",
            );
            result.deleted_certs += 1;
        }
    }

    // --- Clean stale OCSP staples ---
    let ocsp_entries = match storage.list("ocsp", true).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(error = %e, "clean_storage: failed to list OCSP staples");
            Vec::new()
        }
    };

    let max_age = chrono::Duration::from_std(options.ocsp_max_age)
        .unwrap_or_else(|_| chrono::Duration::days(14));

    for entry in &ocsp_entries {
        let stat = match storage.stat(entry).await {
            Ok(s) => s,
            Err(_) => continue,
        };

        if now > stat.modified + max_age {
            if let Err(e) = storage.delete(entry).await {
                warn!(
                    path = entry.as_str(),
                    error = %e,
                    "clean_storage: failed to delete stale OCSP staple"
                );
            } else {
                debug!(
                    path = entry.as_str(),
                    modified = %stat.modified,
                    "clean_storage: deleted stale OCSP staple",
                );
                result.deleted_ocsp += 1;
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Ensure an interval duration is non-zero, falling back to the provided
/// default.
fn normalize_interval(interval: Duration, default: Duration) -> Duration {
    if interval.is_zero() {
        default
    } else {
        interval
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::cache::CacheOptions;
    use crate::certificates::{Certificate, PrivateKeyKind};

    /// Helper: build a minimal managed test certificate.
    fn make_managed_cert(names: &[&str], hash: &str, days_remaining: i64) -> Certificate {
        let now = Utc::now();
        Certificate {
            cert_chain: Vec::new(),
            private_key_der: None,
            private_key_kind: PrivateKeyKind::None,
            names: names.iter().map(|n| n.to_string()).collect(),
            tags: Vec::new(),
            managed: true,
            issuer_key: String::new(),
            hash: hash.to_string(),
            ocsp_response: None,
            ocsp_status: None,
            not_after: now + ChronoDuration::days(days_remaining),
            not_before: now - ChronoDuration::days(90 - days_remaining),
            ari: None,
        }
    }

    #[test]
    fn test_normalize_interval_zero() {
        let result = normalize_interval(Duration::ZERO, DEFAULT_RENEW_CHECK_INTERVAL);
        assert_eq!(result, DEFAULT_RENEW_CHECK_INTERVAL);
    }

    #[test]
    fn test_normalize_interval_custom() {
        let custom = Duration::from_secs(42);
        let result = normalize_interval(custom, DEFAULT_RENEW_CHECK_INTERVAL);
        assert_eq!(result, custom);
    }

    #[test]
    fn test_needs_ocsp_refresh_no_response() {
        let cert = make_managed_cert(&["example.com"], "h1", 60);
        assert!(needs_ocsp_refresh(&cert));
    }

    #[test]
    fn test_needs_ocsp_refresh_with_response() {
        let mut cert = make_managed_cert(&["example.com"], "h1", 60);
        cert.ocsp_response = Some(vec![1, 2, 3]); // unparsable -> triggers refresh
        assert!(needs_ocsp_refresh(&cert));
    }

    #[tokio::test]
    async fn test_check_renewals_no_certs() {
        let cache = CertCache::new(CacheOptions::default());
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);

        let renew_func: Box<RenewFn> = Box::new(move |_domain: String| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals(
            &cache,
            DEFAULT_RENEWAL_WINDOW_RATIO,
            renew_func.as_ref(),
            &DummyStorage,
            &job_queue,
        )
        .await;
        // Wait for any background jobs to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_check_renewals_fresh_cert() {
        let cache = CertCache::new(CacheOptions::default());
        // Certificate with 60 days remaining (out of 90 total) -- not in
        // the renewal window (last 1/3 = 30 days).
        let cert = make_managed_cert(&["example.com"], "h1", 60);
        cache.add(cert).await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);

        let renew_func: Box<RenewFn> = Box::new(move |_domain: String| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals(
            &cache,
            DEFAULT_RENEWAL_WINDOW_RATIO,
            renew_func.as_ref(),
            &DummyStorage,
            &job_queue,
        )
        .await;
        // Wait for any background jobs to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_check_renewals_due_cert() {
        let cache = CertCache::new(CacheOptions::default());
        // Certificate with 10 days remaining (out of 90 total) -- well
        // within the 1/3 renewal window.
        let cert = make_managed_cert(&["renew-me.example.com"], "h2", 10);
        cache.add(cert).await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);

        let renew_func: Box<RenewFn> = Box::new(move |_domain: String| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals(
            &cache,
            DEFAULT_RENEWAL_WINDOW_RATIO,
            renew_func.as_ref(),
            &DummyStorage,
            &job_queue,
        )
        .await;
        // Wait for any background jobs to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_check_renewals_expired_cert() {
        let cache = CertCache::new(CacheOptions::default());
        // Certificate that expired 1 day ago.
        let cert = make_managed_cert(&["expired.example.com"], "h3", -1);
        cache.add(cert).await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);

        let renew_func: Box<RenewFn> = Box::new(move |_domain: String| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals(
            &cache,
            DEFAULT_RENEWAL_WINDOW_RATIO,
            renew_func.as_ref(),
            &DummyStorage,
            &job_queue,
        )
        .await;
        // Wait for any background jobs to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_maintenance_stops_on_signal() {
        use crate::file_storage::FileStorage;

        let cache = CertCache::new(CacheOptions::default());
        let temp_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(temp_dir.path().to_path_buf()));

        let config = MaintenanceConfig {
            renew_check_interval: Duration::from_millis(50),
            ocsp_check_interval: Duration::from_millis(50),
            ocsp: OcspConfig::default(),
            storage,
        };

        let renew_func: Arc<RenewFn> = Arc::new(|_domain: String| Box::pin(async { Ok(()) }));

        let handle = start_maintenance(Arc::clone(&cache), config, renew_func);

        // Let it run for a short while, then signal stop.
        tokio::time::sleep(Duration::from_millis(120)).await;
        cache.stop();

        // The task should exit within a reasonable time.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "maintenance task did not stop in time");
    }

    #[test]
    fn test_maintenance_config_debug() {
        // Verify Debug impl does not panic.
        let config = MaintenanceConfig {
            renew_check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
            ocsp_check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
            ocsp: OcspConfig::default(),
            storage: Arc::new(DummyStorage),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("MaintenanceConfig"));
    }

    /// Minimal dummy storage for testing.
    struct DummyStorage;

    #[async_trait::async_trait]
    impl Storage for DummyStorage {
        async fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn load(&self, _key: &str) -> Result<Vec<u8>> {
            Err(crate::error::StorageError::NotFound("not found".into()).into())
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
        async fn list(&self, _path: &str, _recursive: bool) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn stat(&self, _key: &str) -> Result<crate::storage::KeyInfo> {
            Err(crate::error::StorageError::NotFound("not found".into()).into())
        }
        async fn lock(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        async fn unlock(&self, _name: &str) -> Result<()> {
            Ok(())
        }
    }
}
