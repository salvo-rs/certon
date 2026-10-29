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
//! (`renew_func`) rather than depending on the `CertManager` type directly. This
//! avoids circular dependencies while still allowing the `CertManager` to wire up
//! its `renew_cert` method as the renewal implementation.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::async_jobs::JobQueue;
use crate::cache::CertCache;
use crate::cert_store::{CertStore, KeyValueCertStore};
use crate::certificates::{Certificate, DEFAULT_RENEWAL_WINDOW_RATIO};
use crate::error::Result;
use crate::ocsp::{self, OcspConfig};
use crate::storage::Storage;

#[cfg(test)]
mod parallel_ocsp_tests;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default interval for checking whether managed certificates need renewal
/// (10 minutes).
pub const DEFAULT_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Default interval for checking whether OCSP staples need updating
/// (1 hour).
pub const DEFAULT_OCSP_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

const REVOCATION_READ_CONCURRENCY: usize = 8;
const OCSP_REFRESH_CONCURRENCY: usize = 8;
const FORCED_RENEWAL_CONCURRENCY: usize = 4;
const FORCED_RENEWAL_BACKLOG: usize = 64;

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

    /// Shared storage for OCSP responses and persistent revocation intent.
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

/// Why maintenance requested a certificate renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewalReason {
    Expiring,
    Revoked,
}

pub type ReasonedRenewFn =
    dyn Fn(String, RenewalReason) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync;

pub(crate) type ObservedRenewFn =
    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync;

#[derive(Clone)]
struct RenewalPolicy {
    renew: Arc<ReasonedRenewFn>,
    observed_renew: Option<Arc<ObservedRenewFn>>,
    certificates: Arc<dyn CertStore>,
    revocations: Arc<dyn Storage>,
    ratio: f64,
    ari_manager: Option<Arc<crate::CertManager>>,
}

struct ForcedRenewal {
    hash: String,
    leaf_hash: String,
    domain: String,
    _tracked: TrackedRenewal,
}

struct TrackedRenewal {
    key: String,
    tracked: Arc<Mutex<HashSet<String>>>,
}

impl Drop for TrackedRenewal {
    fn drop(&mut self) {
        self.tracked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

struct ForcedRenewals {
    sender: tokio::sync::mpsc::Sender<ForcedRenewal>,
    tracked: Arc<Mutex<HashSet<String>>>,
}

impl ForcedRenewals {
    fn new() -> (Self, tokio::sync::mpsc::Receiver<ForcedRenewal>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(FORCED_RENEWAL_BACKLOG);
        (
            Self {
                sender,
                tracked: Arc::new(Mutex::new(HashSet::new())),
            },
            receiver,
        )
    }

    fn try_submit(&self, cert: &Certificate, domain: String) {
        let leaf_hash = crate::storage::certificate_leaf_hash(cert).unwrap_or_default();
        let key = if leaf_hash.is_empty() {
            cert.hash.clone()
        } else {
            leaf_hash.clone()
        };
        {
            let mut tracked = self.tracked.lock().unwrap_or_else(|e| e.into_inner());
            if !tracked.insert(key.clone()) {
                return;
            }
        }
        let request = ForcedRenewal {
            hash: cert.hash.clone(),
            leaf_hash,
            domain,
            _tracked: TrackedRenewal {
                key,
                tracked: Arc::clone(&self.tracked),
            },
        };
        if let Err(error) = self.sender.try_send(request) {
            warn!(hash = %cert.hash, %error, "maintenance: force-renewal queue unavailable; retrying on next OCSP deadline");
        }
    }
}

async fn run_forced_renewals(
    cache: &CertCache,
    renew: &ReasonedRenewFn,
    observed: Option<&ObservedRenewFn>,
    mut receiver: tokio::sync::mpsc::Receiver<ForcedRenewal>,
) {
    let mut running: Vec<Pin<Box<dyn Future<Output = ()> + Send + '_>>> =
        Vec::with_capacity(FORCED_RENEWAL_CONCURRENCY);
    let mut closed = false;
    loop {
        if closed && running.is_empty() {
            break;
        }
        tokio::select! {
            request = receiver.recv(), if !closed && running.len() < FORCED_RENEWAL_CONCURRENCY => {
                match request {
                    Some(request) => running.push(Box::pin(async move {
                        // Keep deduplication until the callback future is dropped,
                        // including cancellation and unwinding.
                        let _tracked = request._tracked;
                        let Some(current) = cache.get_by_hash(&request.hash).await else { return };
                        if !current.managed
                            || current.ocsp_status != Some(ocsp::OcspStatus::Revoked)
                            || current.names.first() != Some(&request.domain)
                            || crate::storage::certificate_leaf_hash(&current).unwrap_or_default() != request.leaf_hash
                        {
                            return;
                        }
                        let result = match observed {
                            Some(observed) => observed(request.domain.clone(), request.leaf_hash).await,
                            None => renew(request.domain.clone(), RenewalReason::Revoked).await,
                        };
                        match result {
                            Ok(()) => info!(name = %request.domain, "maintenance: revoked certificate force-renewal finished"),
                            Err(error) => error!(name = %request.domain, %error, "maintenance: revoked certificate force-renewal failed"),
                        }
                    })),
                    None => closed = true,
                }
            }
            _ = std::future::poll_fn(|cx| {
                for position in 0..running.len() {
                    if running[position].as_mut().poll(cx).is_ready() {
                        drop(running.swap_remove(position));
                        return std::task::Poll::Ready(());
                    }
                }
                std::task::Poll::Pending
            }), if !running.is_empty() => {}
        }
    }
}

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
    let certificates = Arc::new(KeyValueCertStore::new(config.storage.clone()));
    let renew = Arc::new(move |domain, _reason| renew_func(domain));
    start_maintenance_with_policy(
        cache,
        config,
        renew,
        certificates,
        DEFAULT_RENEWAL_WINDOW_RATIO,
    )
}

/// Start maintenance using the manager's certificate store and renewal policy.
/// Each loop has an independent four-execution, 68-admitted expiration-renewal
/// budget. OCSP uses eight concurrent refreshes and an independent force-renewal
/// queue with four executions and 64 waiting requests. Saturation is logged and
/// retried on the certificate's next OCSP deadline. Stopping drops in-flight
/// refreshes and force-renewals, then awaits expiration jobs' cleanup.
///
/// Custom callbacks receive the domain observed at dispatch. They must recheck
/// their own persistent resource after asynchronous lock waits before forcing a
/// replacement; the manager's built-in callback performs that identity check.
pub fn start_maintenance_with_policy(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    renew: Arc<ReasonedRenewFn>,
    certificates: Arc<dyn CertStore>,
    ratio: f64,
) -> JoinHandle<()> {
    start_maintenance_with_observed_renewal(cache, config, renew, certificates, ratio, None, None)
}

pub(crate) fn start_maintenance_with_observed_renewal(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    renew: Arc<ReasonedRenewFn>,
    certificates: Arc<dyn CertStore>,
    ratio: f64,
    observed_renew: Option<Arc<ObservedRenewFn>>,
    ari_manager: Option<Arc<crate::CertManager>>,
) -> JoinHandle<()> {
    let policy = RenewalPolicy {
        renew,
        observed_renew,
        certificates,
        revocations: config.storage.clone(),
        ratio,
        ari_manager,
    };
    let renew_interval =
        normalize_interval(config.renew_check_interval, DEFAULT_RENEW_CHECK_INTERVAL);
    let ocsp_interval = normalize_interval(config.ocsp_check_interval, DEFAULT_OCSP_CHECK_INTERVAL);

    info!(
        renew_check_secs = renew_interval.as_secs(),
        ocsp_check_secs = ocsp_interval.as_secs(),
        "starting certificate maintenance loop",
    );

    let maintenance = cache.maintenance_guard();
    tokio::spawn(async move {
        let _maintenance = maintenance;
        maintenance_loop_with_recovery(cache, config, policy, renew_interval, ocsp_interval).await;
    })
}

/// Wrapper around [`maintenance_loop`] that catches panics and automatically
/// restarts the loop. This ensures a single panic inside a renewal or OCSP
/// callback does not permanently kill the maintenance task.
async fn maintenance_loop_with_recovery(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    policy: RenewalPolicy,
    renew_interval: Duration,
    ocsp_interval: Duration,
) {
    loop {
        let cache_clone = Arc::clone(&cache);
        let config_clone = config.clone();
        let policy_clone = policy.clone();

        let inner_maintenance = cache_clone.maintenance_guard();
        let task = tokio::task::spawn(async move {
            let _maintenance = inner_maintenance;
            maintenance_loop(
                cache_clone,
                config_clone,
                policy_clone,
                renew_interval,
                ocsp_interval,
            )
            .await;
        });
        // Aborting this outer task must not detach the inner maintenance loop.
        struct AbortOnDrop(tokio::task::AbortHandle);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _abort_on_drop = AbortOnDrop(task.abort_handle());
        let result = task.await;

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
}

/// The inner maintenance loop, running inside a spawned task.
async fn maintenance_loop(
    cache: Arc<CertCache>,
    config: MaintenanceConfig,
    policy: RenewalPolicy,
    renew_interval: Duration,
    ocsp_interval: Duration,
) {
    let mut stop_rx = cache.subscribe_stop();
    if *stop_rx.borrow() {
        return;
    }
    // Renewals have their own bounded budget; foreground manager families do
    // not consume these slots. The budget is per maintenance loop, not global.
    let job_queue = JobQueue::certificate_jobs("renewal");
    let (forced, force_receiver) = ForcedRenewals::new();
    let force_renewals = run_forced_renewals(
        &cache,
        policy.renew.as_ref(),
        policy.observed_renew.as_deref(),
        force_receiver,
    );

    let mut renew_ticker = tokio::time::interval(renew_interval);
    let mut ocsp_ticker = tokio::time::interval(ocsp_interval);

    // Consume the first immediate tick so the loop starts after one full
    // interval has elapsed, matching the Go `time.NewTicker` behavior.
    renew_ticker.tick().await;
    ocsp_ticker.tick().await;

    // These futures persist independently. A saturated renewal scan may wait
    // for admission for a long time without starving the OCSP ticker.
    let renewals = async {
        let mut ari_changed = cache.subscribe_ari();
        loop {
            tokio::select! {
                _ = renew_ticker.tick() => {}
                _ = ari_changed.changed() => {}
            }
            debug!("maintenance: running renewal check");
            if let Err(error) = refresh_revocations(&cache, config.storage.as_ref()).await {
                warn!(%error, "maintenance: failed to refresh revocation intent");
            }
            check_renewals_with_policy(&cache, &policy, &job_queue).await;
        }
    };
    let (marker_requests, mut marker_receiver) = tokio::sync::mpsc::channel(1);
    let revocations = async {
        // Coalesce periodic requests while a marker scan is running. Its
        // backend waits must not stop polling admitted OCSP responses.
        while marker_receiver.recv().await.is_some() {
            if let Err(error) = refresh_revocations(&cache, config.storage.as_ref()).await {
                warn!(%error, "maintenance: failed to refresh revocation intent");
            }
        }
    };
    let ocsp = run_ocsp_refreshes(
        &cache,
        config.storage.as_ref(),
        &config.ocsp,
        &forced,
        ocsp_ticker,
        marker_requests,
    );
    // Stop remains selectable throughout storage work, callback awaits, and
    // admission backpressure. Cancelling an unadmitted submit is harmless.
    let ari = async {
        match &policy.ari_manager {
            Some(manager) => crate::ari::run(manager).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        biased;
        _ = stop_rx.wait_for(|stop| *stop) => {
            info!("maintenance: received stop signal, exiting");
        }
        _ = renewals => {}
        _ = ocsp => {}
        _ = force_renewals => {}
        _ = revocations => {}
        _ = ari => {}
    }
    job_queue.shutdown().await;
}

async fn run_ocsp_refreshes(
    cache: &CertCache,
    storage: &dyn Storage,
    config: &OcspConfig,
    forced: &ForcedRenewals,
    mut ticker: tokio::time::Interval,
    marker_requests: tokio::sync::mpsc::Sender<()>,
) {
    let mut changed = cache.subscribe_ocsp();
    let mut tracked = HashSet::new();
    let mut pending: VecDeque<Arc<Certificate>> = VecDeque::new();
    let mut refreshes = Vec::with_capacity(OCSP_REFRESH_CONCURRENCY);
    loop {
        // Keep only one periodic snapshot, and borrow at most the available
        // number of due-index entries. Publications during a slow request do
        // not accumulate an unbounded queue of obsolete certificate snapshots.
        if !config.disable_stapling {
            let due = cache.due_ocsp_snapshot(&tracked, OCSP_REFRESH_CONCURRENCY - refreshes.len());
            for cert in due.into_iter().rev() {
                pending.push_front(cert);
            }
        }
        while refreshes.len() < OCSP_REFRESH_CONCURRENCY {
            let Some(cert) = pending.pop_front() else {
                break;
            };
            if !cache.ocsp_refresh_due(&cert.hash) || !tracked.insert(cert.hash.clone()) {
                continue;
            }
            let hash = cert.hash.clone();
            refreshes.push(Box::pin(async move {
                refresh_ocsp_certificate(cache, storage, config, forced, cert).await;
                hash
            }));
        }
        // At most seven in-flight hashes are skipped here. A full pool waits
        // for completion instead of repeatedly selecting an unadmittable timer.
        let deadline = if config.disable_stapling || refreshes.len() == OCSP_REFRESH_CONCURRENCY {
            None
        } else {
            cache.next_ocsp_deadline_excluding(&tracked)
        };
        let due = async {
            match deadline {
                Some(deadline) => {
                    let delay = (deadline - chrono::Utc::now()).to_std().unwrap_or_default();
                    tokio::time::sleep(delay).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = ticker.tick() => {
                let _ = marker_requests.try_send(());
                if !config.disable_stapling {
                    pending = cache.ocsp_snapshot(true).into();
                }
            }
            _ = due => {}
            _ = changed.changed() => {}
            hash = std::future::poll_fn(|cx| {
                for position in 0..refreshes.len() {
                    if let std::task::Poll::Ready(hash) = refreshes[position].as_mut().poll(cx) {
                        drop(refreshes.swap_remove(position));
                        return std::task::Poll::Ready(hash);
                    }
                }
                std::task::Poll::Pending
            }), if !refreshes.is_empty() => { tracked.remove(&hash); }
        }
    }
}

pub(crate) async fn refresh_revocations(cache: &CertCache, storage: &dyn Storage) -> Result<usize> {
    let mut invalidated = 0;
    let mut first_error: Option<(usize, crate::error::Error)> = None;
    let mut seen = std::collections::HashSet::new();
    let mut hashes = cache
        .maintenance_snapshot(true)
        .into_iter()
        .filter_map(|cert| crate::storage::certificate_leaf_hash(&cert))
        .filter(|hash| seen.insert(hash.clone()))
        .enumerate();
    let mut reads = Vec::with_capacity(REVOCATION_READ_CONCURRENCY);
    for (index, hash) in hashes.by_ref().take(REVOCATION_READ_CONCURRENCY) {
        reads.push(Box::pin(read_revocation(storage, index, hash)));
    }
    while !reads.is_empty() {
        // Borrowed futures need no task or runtime ownership. A slow earlier
        // read cannot block quarantine of ready later leaves; cancelling the
        // scan drops every in-flight backend read before its caller exits.
        let (index, hash, result) = std::future::poll_fn(|cx| {
            for position in 0..reads.len() {
                if let std::task::Poll::Ready(result) = reads[position].as_mut().poll(cx) {
                    drop(reads.swap_remove(position));
                    return std::task::Poll::Ready(result);
                }
            }
            std::task::Poll::Pending
        })
        .await;
        match result {
            Ok(true) => {
                cache.deny_revoked_certificate(&hash).await;
                invalidated += 1;
            }
            Ok(false) => {}
            Err(error) => {
                // One damaged or unavailable marker must not permanently
                // shield other leaves. Keep the first snapshot-order error,
                // irrespective of backend completion order.
                if first_error.as_ref().is_none_or(|(first, _)| index < *first) {
                    first_error = Some((index, error));
                }
            }
        }
        if let Some((index, hash)) = hashes.next() {
            reads.push(Box::pin(read_revocation(storage, index, hash)));
        }
    }
    match first_error {
        Some((_, error)) => Err(error),
        None => Ok(invalidated),
    }
}

async fn read_revocation(
    storage: &dyn Storage,
    index: usize,
    hash: String,
) -> (usize, String, Result<bool>) {
    let result = crate::storage::load_revocation(storage, &hash)
        .await
        .map(|marker| marker.is_some());
    (index, hash, result)
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
async fn check_renewals_with_policy(
    cache: &CertCache,
    policy: &RenewalPolicy,
    job_queue: &JobQueue,
) {
    let managed_certs = cache.maintenance_snapshot(true);

    if managed_certs.is_empty() {
        debug!("maintenance: no managed certificates to check for renewal");
        return;
    }

    debug!(
        count = managed_certs.len(),
        "maintenance: checking managed certificates for renewal",
    );

    for cert in &managed_certs {
        if cert.not_before <= chrono::Utc::now()
            && !crate::ari::needs_renewal(
                cert,
                policy.ratio,
                policy
                    .ari_manager
                    .as_ref()
                    .is_some_and(|manager| manager.policy.disable_ari),
            )
        {
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
        if try_reload_from_storage(
            cache,
            policy.certificates.as_ref(),
            policy.revocations.as_ref(),
            cert,
            &domain,
            policy.ratio,
            policy
                .ari_manager
                .as_ref()
                .is_some_and(|manager| manager.policy.disable_ari),
        )
        .await
        {
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
        let renew = Arc::clone(&policy.renew);

        job_queue
            .submit(job_name, move || async move {
                match renew(domain_clone.clone(), RenewalReason::Expiring).await {
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
/// instance. Only reload a currently valid certificate that does not need
/// renewal, returning `true` to skip local issuance.
async fn try_reload_from_storage(
    cache: &CertCache,
    certificates: &dyn CertStore,
    revocations: &dyn Storage,
    cached_cert: &Certificate,
    domain: &str,
    renewal_ratio: f64,
    disable_ari: bool,
) -> bool {
    let resource = match certificates.load(&cached_cert.issuer_key, domain).await {
        Ok(Some(resource)) => resource,
        _ => return false,
    };
    let mut stored_cert =
        match crate::manager::CertManager::parse_managed_certificate(&resource, domain) {
            Ok(cert) => cert,
            Err(_) => return false,
        };

    if let Some(hash) = crate::storage::certificate_leaf_hash(&stored_cert) {
        match crate::storage::load_revocation(revocations, &hash).await {
            Ok(None) => {}
            Ok(Some(_)) => {
                cache.deny_revoked_certificate(&hash).await;
                return false;
            }
            Err(error) => {
                warn!(%error, "maintenance: cannot verify revocation status for reload");
                return false;
            }
        }
    }
    crate::ari::attach_cached(revocations, cache, &mut stored_cert, disable_ari).await;
    // If the stored cert has a different hash AND does not need renewal,
    // it was renewed by another instance — reload it into the cache.
    if stored_cert.hash != cached_cert.hash
        && stored_cert.not_before <= chrono::Utc::now()
        && !stored_cert.expired()
        && !crate::ari::needs_renewal(&stored_cert, renewal_ratio, disable_ari)
        && crate::manager::CertManager::covers_certificate(&stored_cert, cached_cert)
    {
        info!(
            domain = %domain,
            old_hash = %cached_cert.hash,
            new_hash = %stored_cert.hash,
            "maintenance: certificate already renewed by another instance; reloading from storage",
        );
        return cache
            .replace_managed(&cached_cert.hash, stored_cert, domain)
            .await
            .is_ok();
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
#[cfg(test)]
async fn update_ocsp_staples(
    cache: &CertCache,
    storage: &dyn Storage,
    config: &OcspConfig,
    renew_func: &ReasonedRenewFn,
) {
    let (forced, receiver) = ForcedRenewals::new();
    let refresh = async {
        update_ocsp_staples_for(cache, storage, config, &forced, true).await;
        drop(forced);
    };
    tokio::join!(
        refresh,
        run_forced_renewals(cache, renew_func, None, receiver)
    );
}

#[cfg(test)]
async fn update_ocsp_staples_for(
    cache: &CertCache,
    storage: &dyn Storage,
    config: &OcspConfig,
    forced: &ForcedRenewals,
    periodic: bool,
) {
    if config.disable_stapling {
        debug!("maintenance: OCSP stapling is disabled; skipping update");
        return;
    }

    let all_certs = cache.ocsp_snapshot(periodic);

    if all_certs.is_empty() {
        debug!("maintenance: no certificates to check for OCSP updates");
        return;
    }

    debug!(
        count = all_certs.len(),
        "maintenance: checking certificates for OCSP staple freshness",
    );

    let mut seen = HashSet::new();
    let mut certificates = all_certs
        .into_iter()
        .filter(|cert| seen.insert(cert.hash.clone()) && cache.ocsp_refresh_due(&cert.hash));
    let mut refreshes = Vec::with_capacity(OCSP_REFRESH_CONCURRENCY);
    for cert in certificates.by_ref().take(OCSP_REFRESH_CONCURRENCY) {
        refreshes.push(Box::pin(refresh_ocsp_certificate(
            cache, storage, config, forced, cert,
        )));
    }
    while !refreshes.is_empty() {
        std::future::poll_fn(|cx| {
            for position in 0..refreshes.len() {
                if refreshes[position].as_mut().poll(cx).is_ready() {
                    drop(refreshes.swap_remove(position));
                    return std::task::Poll::Ready(());
                }
            }
            std::task::Poll::Pending
        })
        .await;
        if let Some(cert) = certificates.next() {
            refreshes.push(Box::pin(refresh_ocsp_certificate(
                cache, storage, config, forced, cert,
            )));
        }
    }
}

async fn refresh_ocsp_certificate(
    cache: &CertCache,
    storage: &dyn Storage,
    config: &OcspConfig,
    forced: &ForcedRenewals,
    cert: Arc<Certificate>,
) {
    let first_name = cert.names.first().cloned().unwrap_or_default();
    let old_hash = cert.hash.clone();

    debug!(
        name = %first_name,
        hash = %old_hash,
        "maintenance: refreshing OCSP staple",
    );

    let mut updated_cert = Arc::unwrap_or_clone(cert);
    let outcome = ocsp::staple_ocsp(storage, &mut updated_cert, config).await;
    // Publish removal of an unusable staple as well as successful refreshes.
    // Otherwise a failed refresh keeps serving the expired response forever.
    let Some(current) = cache
        .update_ocsp_if_present(
            &old_hash,
            updated_cert.ocsp_status,
            updated_cert.ocsp_response.clone(),
        )
        .await
    else {
        // Renewal or removal won while this response was in flight.
        return;
    };
    let first_name = current.first_name;
    match outcome {
        Ok(true) if current.ocsp_status == Some(ocsp::OcspStatus::Good) => {
            debug!(name = %first_name, "maintenance: OCSP staple refreshed successfully");
        }
        Ok(_) => {
            debug!(name = %first_name, "maintenance: no usable OCSP staple is available");
        }
        Err(e) => {
            warn!(name = %first_name, error = %e, "maintenance: failed to refresh OCSP staple");
        }
    }
    // Use policy and sticky status captured in the cache update, not the
    // scan's earlier snapshot. This does not serialize later policy changes
    // with the asynchronous renewal callback.
    if current.ocsp_status == Some(ocsp::OcspStatus::Revoked)
        && config.replace_revoked
        && current.managed
    {
        warn!(name = %first_name, hash = %old_hash, "maintenance: OCSP status is Revoked; triggering force-renewal");
        forced.try_submit(&updated_cert, first_name);
    }
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
/// - Lists legacy PEM files and private resource snapshots under `certificates/`.
/// - Loads each site's current resource and checks its `notAfter` date.
/// - Deletes snapshots and legacy `.crt` / `.key` / `.json` assets whose `notAfter` plus
///   `expired_cert_grace_period` is in the past.
///
/// Callers must externally coordinate this operation with certificate issuance
/// and renewal against the same storage. Reading expiry and deleting assets
/// are separate operations, so cleanup must not race a writer publishing a
/// replacement resource.
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

    // Group old three-file layouts and new private snapshots by site. Always
    // inspect the canonical resource: a stale legacy .crt must not cause a
    // newly renewed snapshot for the same site to be deleted.
    let mut sites = std::collections::BTreeSet::new();
    for entry in &certs_entries {
        if let Some(site) = entry.strip_suffix("/_certon/resource.v1.key") {
            sites.insert(site.to_owned());
        } else if entry.ends_with(".crt")
            && let Some((site, _)) = entry.rsplit_once('/')
        {
            sites.insert(site.to_owned());
        }
    }

    for site in sites {
        let Some((issuer, domain)) = site
            .strip_prefix("certificates/")
            .and_then(|path| path.split_once('/'))
        else {
            continue;
        };
        if domain.contains('/') {
            continue;
        }
        let snapshot = format!("{site}/_certon/resource.v1.key");
        let cert_pem = match crate::storage::load_certificate(storage, issuer, domain).await {
            Ok(resource) => resource.certificate_pem,
            Err(_) => {
                // A prior cleanup may have removed the legacy sidecars before
                // .crt deletion failed. Retry from that cert only after proving
                // no canonical snapshot exists. Present, malformed or unreadable
                // snapshots must never fall back to an older expired .crt.
                if !matches!(
                    storage.load(&snapshot).await,
                    Err(crate::Error::Storage(crate::error::StorageError::NotFound(
                        _
                    )))
                ) {
                    continue;
                }
                match storage
                    .load(&crate::storage::site_cert_key(issuer, domain))
                    .await
                {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                }
            }
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

        if now <= not_after + grace_period {
            continue;
        }

        // Keep the certificate as retryable expiry evidence until both legacy
        // sidecars are gone. The snapshot remains authoritative until all legacy
        // assets are removed, preventing resurrection through the legacy loader.
        let sidecars = [
            crate::storage::site_private_key(issuer, domain),
            crate::storage::site_meta_key(issuer, domain),
        ];
        let mut sidecars_deleted = true;
        for path in sidecars {
            match storage.delete(&path).await {
                Ok(()) | Err(crate::Error::Storage(crate::error::StorageError::NotFound(_))) => {}
                Err(error) => {
                    sidecars_deleted = false;
                    warn!(path, error = %error, "clean_storage: failed to delete expired certificate asset");
                }
            }
        }
        if !sidecars_deleted {
            continue;
        }
        let cert_path = crate::storage::site_cert_key(issuer, domain);
        match storage.delete(&cert_path).await {
            Ok(()) | Err(crate::Error::Storage(crate::error::StorageError::NotFound(_))) => {}
            Err(error) => {
                warn!(path = cert_path, error = %error, "clean_storage: failed to delete expired certificate");
                continue;
            }
        }
        match storage.delete(&snapshot).await {
            Ok(()) | Err(crate::Error::Storage(crate::error::StorageError::NotFound(_))) => {
                info!(site, not_after = %not_after, "clean_storage: deleted expired certificate");
                result.deleted_certs += 1;
            }
            Err(error) => {
                warn!(path = snapshot, error = %error, "clean_storage: failed to delete expired certificate snapshot")
            }
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::cache::CacheOptions;
    use crate::certificates::{Certificate, PrivateKeyKind};

    /// Pause the actual OCSP cache read while another lifecycle operation runs.
    struct GatedOcspStorage {
        files: crate::FileStorage,
        loads: AtomicUsize,
        block_next_load: AtomicBool,
        offline: AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl GatedOcspStorage {
        fn new(path: &std::path::Path) -> Self {
            Self {
                files: crate::FileStorage::new(path),
                loads: AtomicUsize::new(0),
                block_next_load: AtomicBool::new(false),
                offline: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Storage for GatedOcspStorage {
        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            if self.block_next_load.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            if self.offline.load(Ordering::SeqCst) {
                return Err(crate::Error::Other("OCSP storage is offline".into()));
            }
            self.files.load(key).await
        }
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.files.store(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.files.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            self.files.exists(key).await
        }
        async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
            self.files.list(path, recursive).await
        }
        async fn stat(&self, key: &str) -> Result<crate::storage::KeyInfo> {
            self.files.stat(key).await
        }
        async fn lock(&self, name: &str) -> Result<()> {
            self.files.lock(name).await
        }
        async fn unlock(&self, name: &str) -> Result<()> {
            self.files.unlock(name).await
        }
    }

    fn signed_certificate() -> (Certificate, rcgen::KeyPair) {
        let (chain, issuer_key, leaf_key) = crate::ocsp::tests::signed_chain();
        let pem: String = chain
            .iter()
            .map(|der| ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.as_ref())))
            .collect();
        let mut cert = Certificate::from_pem(pem.as_bytes(), leaf_key.as_bytes()).unwrap();
        cert.managed = true;
        (cert, issuer_key)
    }

    fn signed_status(cert: &Certificate, issuer: &rcgen::KeyPair, status: u8) -> Vec<u8> {
        crate::ocsp::tests::signed_response(
            &cert.cert_chain,
            issuer,
            status,
            Utc::now() - ChronoDuration::hours(1),
            Utc::now() + ChronoDuration::hours(1),
        )
    }

    async fn read_ocsp_request(socket: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt;
        let mut request = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0, "OCSP client closed before sending its request");
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() <= 8192);
            if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                if request.len() >= end + 4 + length {
                    return;
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn certificates_without_ocsp_support_keep_the_periodic_hour_poll() {
        let cache = CertCache::new(CacheOptions::default());
        let (mut cert, _) = signed_certificate();
        cert.managed = false;
        cache.add(cert).await;
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(GatedOcspStorage::new(directory.path()));
        // Make storage failure immediate; with no AIA or responder override it
        // must not convert the ordinary periodic poll into a short retry timer.
        storage.offline.store(true, Ordering::SeqCst);
        let maintenance = start_maintenance(
            cache.clone(),
            MaintenanceConfig {
                renew_check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
                ocsp_check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
                ocsp: OcspConfig::default(),
                storage: storage.clone(),
            },
            Arc::new(|_| Box::pin(async { Ok(()) })),
        );
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert_eq!(storage.loads.load(Ordering::SeqCst), 0);
        tokio::time::advance(DEFAULT_OCSP_CHECK_INTERVAL - Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert_eq!(storage.loads.load(Ordering::SeqCst), 1);
        assert!(cache.next_ocsp_deadline().is_none());
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert_eq!(storage.loads.load(Ordering::SeqCst), 1);
        cache.stop_and_wait().await;
        maintenance.await.unwrap();
    }

    #[tokio::test]
    async fn default_maintenance_refreshes_a_new_short_ttl_staple_before_expiry() {
        use tokio::io::AsyncWriteExt;
        let cache = CertCache::new(CacheOptions::default());
        let (mut cert, issuer) = signed_certificate();
        cert.managed = false;
        let old = crate::cache::tests::signed_staple(&cert, &issuer, 8);
        let replacement = crate::cache::tests::signed_staple(&cert, &issuer, 3600);
        cert.ocsp_status = Some(ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(old.clone());
        let hash = cert.hash.clone();
        let domain = cert.names[0].clone();
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::FileStorage::new(directory.path()));
        storage
            .store(&crate::storage::ocsp_key(&domain, &hash), &old)
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server_response = replacement.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_ocsp_request(&mut socket).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&server_response).await.unwrap();
        });
        let mut ocsp = OcspConfig::default();
        ocsp.responder_overrides.insert(domain.clone(), url);
        let maintenance = start_maintenance(
            cache.clone(),
            MaintenanceConfig {
                renew_check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
                ocsp_check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
                ocsp,
                storage,
            },
            Arc::new(|_| Box::pin(async { Ok(()) })),
        );
        // Publish after the idle loop is running: the watch must recompute its
        // original one-hour wait instead of missing this new short deadline.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        cache.add(cert).await;
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if cache.resolve(&domain).unwrap().key.ocsp.as_ref() == Some(&replacement) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("one-hour maintenance interval missed the signed staple's deadline");
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(
            cache.resolve(&domain).unwrap().key.ocsp.as_ref(),
            Some(&replacement)
        );
        cache.stop_and_wait().await;
        maintenance.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unchanged_good_and_failed_responses_back_off_and_retain_only_fresh_staples() {
        use tokio::io::AsyncWriteExt;
        for available in [false, true] {
            let cache = CertCache::new(CacheOptions::default());
            let (mut cert, issuer) = signed_certificate();
            cert.managed = false;
            let response = crate::ocsp::tests::signed_response(
                &cert.cert_chain,
                &issuer,
                0,
                Utc::now() - ChronoDuration::hours(1),
                Utc::now() + ChronoDuration::seconds(10),
            );
            cert.ocsp_status = Some(ocsp::OcspStatus::Good);
            cert.ocsp_response = Some(response.clone());
            let hash = cert.hash.clone();
            let domain = cert.names[0].clone();
            let directory = tempfile::tempdir().unwrap();
            let storage = Arc::new(crate::FileStorage::new(directory.path()));
            storage
                .store(&crate::storage::ocsp_key(&domain, &hash), &response)
                .await
                .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let server_response = response.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    read_ocsp_request(&mut socket).await;
                    observed.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = if available {
                        ("200 OK", server_response.as_slice())
                    } else {
                        ("503 Unavailable", b"offline".as_slice())
                    };
                    socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                    socket.write_all(body).await.unwrap();
                }
            });
            let mut ocsp = OcspConfig::default();
            ocsp.responder_overrides.insert(domain.clone(), url);
            cache.add(cert).await;
            update_ocsp_staples(&cache, storage.as_ref(), &ocsp, &|_, _| {
                Box::pin(async { Ok(()) })
            })
            .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                cache.resolve(&domain).unwrap().key.ocsp.as_ref(),
                Some(&response)
            );
            let deadline = cache.next_ocsp_deadline().unwrap();
            assert!(deadline > Utc::now());
            for _ in 0..5 {
                update_ocsp_staples(&cache, storage.as_ref(), &ocsp, &|_, _| {
                    Box::pin(async { Ok(()) })
                })
                .await;
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "same or unavailable responder caused a refresh loop"
            );
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn ocsp_refresh_does_not_resurrect_removed_or_renewed_serving_keys() {
        for successful_refresh in [false, true] {
            // Also keep a control case to prove both genuine refresh outcomes
            // update the prebuilt TLS key when no lifecycle operation intervenes.
            for mutation in ["keep", "remove", "renew", "revoke", "retag"] {
                let cache = CertCache::new(CacheOptions::default());
                let (mut cert, issuer) = signed_certificate();
                cert.ocsp_status = Some(ocsp::OcspStatus::Good);
                cert.ocsp_response = Some(vec![0, 1, 2]);
                let hash = cert.hash.clone();
                let domain = cert.names[0].clone();
                let fresh_response = signed_status(&cert, &issuer, 0);
                let directory = tempfile::tempdir().unwrap();
                let storage = Arc::new(GatedOcspStorage::new(directory.path()));
                if successful_refresh {
                    storage
                        .store(&crate::storage::ocsp_key(&domain, &hash), &fresh_response)
                        .await
                        .unwrap();
                }
                cache.add(cert).await;
                assert_eq!(cache.resolve(&domain).unwrap().key.ocsp, None);
                storage.block_next_load.store(true, Ordering::SeqCst);
                let worker_cache = Arc::clone(&cache);
                let worker_storage = Arc::clone(&storage);
                let attempts = Arc::new(AtomicUsize::new(0));
                let called = Arc::clone(&attempts);
                let worker = tokio::spawn(async move {
                    let renew: Arc<ReasonedRenewFn> = Arc::new(move |_, reason| {
                        assert!(matches!(reason, RenewalReason::Revoked));
                        called.fetch_add(1, Ordering::SeqCst);
                        Box::pin(async { Ok(()) })
                    });
                    update_ocsp_staples(
                        &worker_cache,
                        worker_storage.as_ref(),
                        &OcspConfig::default(),
                        renew.as_ref(),
                    )
                    .await;
                });
                tokio::time::timeout(Duration::from_secs(2), storage.entered.notified())
                    .await
                    .unwrap();
                let replacement = match mutation {
                    "remove" => {
                        cache.remove(&hash).await;
                        None
                    }
                    "renew" => {
                        let (replacement, _) = signed_certificate();
                        cache.replace(&hash, replacement.clone()).await;
                        Some(replacement)
                    }
                    "retag" => {
                        let mut current = cache.get_by_hash(&hash).await.unwrap();
                        current.tags = vec!["updated-tag".into()];
                        current.managed = false;
                        current.issuer_key = "updated-issuer".into();
                        cache.replace(&hash, current).await;
                        None
                    }
                    "revoke" => {
                        let mut revoked = cache.get_by_hash(&hash).await.unwrap();
                        let newer = crate::FileStorage::new(directory.path().join("newer"));
                        newer
                            .store(
                                &crate::storage::ocsp_key(&domain, &hash),
                                &signed_status(&revoked, &issuer, 1),
                            )
                            .await
                            .unwrap();
                        assert!(
                            !ocsp::staple_ocsp(&newer, &mut revoked, &OcspConfig::default())
                                .await
                                .unwrap()
                        );
                        assert_eq!(revoked.ocsp_status, Some(ocsp::OcspStatus::Revoked));
                        cache.replace(&hash, revoked).await;
                        None
                    }
                    _ => None,
                };
                storage.release.notify_one();
                tokio::time::timeout(Duration::from_secs(2), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    attempts.load(Ordering::SeqCst),
                    usize::from(mutation == "revoke")
                );
                match mutation {
                    "remove" => {
                        assert!(cache.get_by_hash(&hash).await.is_none());
                        assert!(cache.resolve(&domain).is_none());
                    }
                    "renew" => {
                        let replacement = replacement.unwrap();
                        assert!(cache.get_by_hash(&hash).await.is_none());
                        let serving = cache.resolve(&domain).unwrap();
                        assert_eq!(serving.hash, replacement.hash);
                        assert_eq!(serving.key.cert, replacement.cert_chain);
                        assert_eq!(cache.count().await, 1);
                    }
                    "revoke" => {
                        let actual = cache.get_by_hash(&hash).await.unwrap();
                        assert_eq!(actual.ocsp_status, Some(ocsp::OcspStatus::Revoked));
                        assert!(cache.resolve(&domain).is_none());
                    }
                    "retag" => {
                        let actual = cache.get_by_hash(&hash).await.unwrap();
                        assert_eq!(actual.tags, vec!["updated-tag"]);
                        assert!(!actual.managed);
                        assert_eq!(actual.issuer_key, "updated-issuer");
                        assert_eq!(
                            cache.resolve(&domain).unwrap().key.ocsp,
                            successful_refresh.then_some(fresh_response)
                        );
                    }
                    _ => {
                        let serving = cache.resolve(&domain).unwrap();
                        assert_eq!(serving.hash, hash);
                        assert_eq!(
                            serving.key.ocsp,
                            successful_refresh.then_some(fresh_response)
                        );
                        let actual = cache.get_by_hash(&hash).await.unwrap();
                        assert_eq!(
                            actual.ocsp_status,
                            successful_refresh.then_some(ocsp::OcspStatus::Good)
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn in_flight_revocation_respects_current_unmanaged_policy() {
        let cache = CertCache::new(CacheOptions::default());
        let (mut cert, issuer) = signed_certificate();
        let hash = cert.hash.clone();
        let domain = cert.names[0].clone();
        cert.ocsp_status = Some(ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(vec![0, 1, 2]);
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(GatedOcspStorage::new(directory.path()));
        storage
            .store(
                &crate::storage::ocsp_key(&domain, &hash),
                &signed_status(&cert, &issuer, 1),
            )
            .await
            .unwrap();
        cache.add(cert).await;
        storage.block_next_load.store(true, Ordering::SeqCst);
        let attempts = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&attempts);
        let worker_cache = Arc::clone(&cache);
        let worker_storage = Arc::clone(&storage);
        let worker = tokio::spawn(async move {
            let renew: Arc<ReasonedRenewFn> = Arc::new(move |_, _| {
                called.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            });
            update_ocsp_staples(
                &worker_cache,
                worker_storage.as_ref(),
                &OcspConfig::default(),
                renew.as_ref(),
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(2), storage.entered.notified())
            .await
            .unwrap();
        let mut current = cache.get_by_hash(&hash).await.unwrap();
        current.managed = false;
        current.tags = vec!["manual".into()];
        current.issuer_key = "manual-issuer".into();
        cache.replace(&hash, current).await;
        storage.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "an OCSP refresh must not restart management disabled while it was waiting"
        );
        let current = cache.get_by_hash(&hash).await.unwrap();
        assert!(!current.managed);
        assert_eq!(current.tags, vec!["manual"]);
        assert_eq!(current.issuer_key, "manual-issuer");
        assert_eq!(current.ocsp_status, Some(ocsp::OcspStatus::Revoked));
        assert!(cache.resolve(&domain).is_none());
    }

    #[tokio::test]
    async fn verified_revocation_remains_sticky_and_retries_failed_replacement() {
        let cache = CertCache::new(CacheOptions::default());
        let (mut cert, issuer) = signed_certificate();
        let hash = cert.hash.clone();
        let domain = cert.names[0].clone();
        let directory = tempfile::tempdir().unwrap();
        let storage = GatedOcspStorage::new(directory.path());
        let key = crate::storage::ocsp_key(&domain, &hash);
        storage
            .store(&key, &signed_status(&cert, &issuer, 1))
            .await
            .unwrap();
        // Start with a serving key that has an old staple, then discover a
        // correctly signed revocation through the production refresh path.
        cert.ocsp_status = Some(ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(vec![0, 1, 2]);
        cache.add(cert.clone()).await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&attempts);
        let renew: Arc<ReasonedRenewFn> = Arc::new(move |_, reason| {
            assert!(matches!(reason, RenewalReason::Revoked));
            called.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(crate::Error::Other("CA is unavailable".into())) })
        });
        for step in 0..4 {
            if step == 1 {
                storage.offline.store(true, Ordering::SeqCst);
            } else if step >= 2 {
                storage.offline.store(false, Ordering::SeqCst);
                // Neither Unknown nor a still-fresh older Good response may
                // undo a revocation already verified for this certificate.
                let status = if step == 2 { 2 } else { 0 };
                storage
                    .store(&key, &signed_status(&cert, &issuer, status))
                    .await
                    .unwrap();
            }
            // Exercise each refresh outcome directly. The production scanner
            // now schedules even initially unscheduled revoked leaves with a
            // retry deadline instead of immediately forcing them repeatedly.
            let (forced, receiver) = ForcedRenewals::new();
            refresh_ocsp_certificate(
                &cache,
                &storage,
                &OcspConfig::default(),
                &forced,
                Arc::new(cache.get_by_hash(&hash).await.unwrap()),
            )
            .await;
            drop(forced);
            run_forced_renewals(&cache, renew.as_ref(), None, receiver).await;
            let actual = cache.get_by_hash(&hash).await.unwrap();
            assert_eq!(actual.ocsp_status, Some(ocsp::OcspStatus::Revoked));
            assert!(actual.ocsp_response.is_none());
            assert!(cache.resolve(&domain).is_none());
            assert_eq!(attempts.load(Ordering::SeqCst), step + 1);
        }
        let (replacement, _) = signed_certificate();
        cache.replace(&hash, replacement.clone()).await;
        assert_eq!(
            cache
                .get_by_hash(&replacement.hash)
                .await
                .unwrap()
                .ocsp_status,
            None
        );
    }

    #[tokio::test]
    async fn unavailable_ocsp_clears_cached_staple_without_requesting_renewal() {
        let cache = CertCache::new(CacheOptions::default());
        let mut cert = make_managed_cert(&["unavailable.example.com"], "stale-staple", 60);
        cert.ocsp_status = Some(ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(vec![0, 1, 2]);
        cache.add(cert).await;
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        let renew: Arc<ReasonedRenewFn> = Arc::new(|_, _| {
            Box::pin(async {
                panic!("an unavailable OCSP responder must not be interpreted as revocation")
            })
        });
        update_ocsp_staples(&cache, &storage, &OcspConfig::default(), renew.as_ref()).await;
        let cached = cache.get_by_name("unavailable.example.com").await.unwrap();
        assert!(cached.ocsp_response.is_none());
        assert!(cached.ocsp_status.is_none());
    }

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

    #[tokio::test]
    async fn test_check_renewals_no_certs() {
        let cache = CertCache::new(CacheOptions::default());
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);

        let renew_func: Arc<ReasonedRenewFn> = Arc::new(move |_domain: String, _reason| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals_with_policy(
            &cache,
            &RenewalPolicy {
                observed_renew: None,
                renew: renew_func,
                revocations: Arc::new(DummyStorage),
                certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
                ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
                ari_manager: None,
            },
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

        let renew_func: Arc<ReasonedRenewFn> = Arc::new(move |_domain: String, _reason| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals_with_policy(
            &cache,
            &RenewalPolicy {
                observed_renew: None,
                renew: renew_func,
                revocations: Arc::new(DummyStorage),
                certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
                ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
                ari_manager: None,
            },
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

        let renew_func: Arc<ReasonedRenewFn> = Arc::new(move |_domain: String, _reason| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals_with_policy(
            &cache,
            &RenewalPolicy {
                observed_renew: None,
                renew: renew_func,
                revocations: Arc::new(DummyStorage),
                certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
                ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
                ari_manager: None,
            },
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

        let renew_func: Arc<ReasonedRenewFn> = Arc::new(move |_domain: String, _reason| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let job_queue = JobQueue::new("test");
        check_renewals_with_policy(
            &cache,
            &RenewalPolicy {
                observed_renew: None,
                renew: renew_func,
                revocations: Arc::new(DummyStorage),
                certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
                ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
                ari_manager: None,
            },
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

    #[tokio::test]
    async fn maintenance_uses_the_custom_renewal_ratio() {
        let cache = CertCache::new(CacheOptions::default());
        cache
            .add(make_managed_cert(&["example.com"], "custom-ratio", 40))
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let policy = RenewalPolicy {
            ari_manager: None,
            observed_renew: None,
            revocations: Arc::new(DummyStorage),
            ratio: 0.5,
            certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
            renew: Arc::new(move |_domain, reason| {
                assert_eq!(reason, RenewalReason::Expiring);
                counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }),
        };
        let jobs = JobQueue::new("custom-ratio");
        check_renewals_with_policy(&cache, &policy, &jobs).await;
        jobs.wait("renew_example.com").await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn maintenance_reloads_from_the_custom_certificate_store() {
        use crate::cert_store::CertStore;
        use crate::cert_store::tests::InMemory;
        let cache = CertCache::new(CacheOptions::default());
        let old_resource = cleanup_resource(true);
        let old =
            crate::manager::CertManager::parse_managed_certificate(&old_resource, "example.com")
                .unwrap();
        cache.add(old.clone()).await;
        let generated = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let resource = crate::CertificateResource {
            sans: vec!["example.com".into()],
            certificate_pem: generated.cert.pem().into_bytes(),
            private_key_pem: generated.signing_key.serialize_pem().into_bytes(),
            issuer_key: "ca".into(),
            issuer_data: None,
        };
        let store = Arc::new(InMemory::default());
        store.save("ca", &resource).await.unwrap();
        let policy = RenewalPolicy {
            ari_manager: None,
            observed_renew: None,
            revocations: Arc::new(DummyStorage),
            ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
            certificates: store,
            renew: Arc::new(|_, _| panic!("fresh certificate must be reloaded rather than issued")),
        };
        check_renewals_with_policy(&cache, &policy, &JobQueue::new("reload")).await;
        let current = cache.get_all().await;
        assert_eq!(current.len(), 1);
        assert_ne!(current[0].hash, old.hash);
        assert_eq!(current[0].issuer_key, "ca");
    }

    fn cleanup_resource(expired: bool) -> crate::CertificateResource {
        use chrono::Datelike;
        let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        let year = Utc::now().year();
        params.not_before = rcgen::date_time_ymd(year - 4, 1, 1);
        params.not_after = rcgen::date_time_ymd(if expired { year - 2 } else { year + 4 }, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        crate::CertificateResource {
            sans: vec!["example.com".into()],
            certificate_pem: certificate.pem().into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
            issuer_key: "ca".into(),
            issuer_data: None,
        }
    }

    async fn write_legacy_resource(storage: &dyn Storage, resource: &crate::CertificateResource) {
        storage
            .store(
                &crate::storage::site_cert_key("ca", "example.com"),
                &resource.certificate_pem,
            )
            .await
            .unwrap();
        storage
            .store(
                &crate::storage::site_private_key("ca", "example.com"),
                &resource.private_key_pem,
            )
            .await
            .unwrap();
        storage
            .store(
                &crate::storage::site_meta_key("ca", "example.com"),
                &serde_json::to_vec(resource).unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cleanup_removes_published_resources_and_legacy_assets_without_resurrection() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        write_legacy_resource(&storage, &cleanup_resource(false)).await;
        crate::storage::store_certificate(&storage, "ca", &cleanup_resource(true))
            .await
            .unwrap();
        let result = clean_storage(&storage, &CleanStorageOptions::default())
            .await
            .unwrap();
        assert_eq!(result.deleted_certs, 1);
        assert!(matches!(
            crate::storage::load_certificate(&storage, "ca", "example.com").await,
            Err(crate::Error::Storage(crate::error::StorageError::NotFound(
                _
            )))
        ));
        for path in [
            crate::storage::site_cert_key("ca", "example.com"),
            crate::storage::site_private_key("ca", "example.com"),
            crate::storage::site_meta_key("ca", "example.com"),
            "certificates/ca/example.com/_certon/resource.v1.key".into(),
        ] {
            assert!(
                !storage.exists(&path).await.unwrap(),
                "resource was left behind: {path}"
            );
        }
    }

    #[tokio::test]
    async fn cleanup_does_not_let_an_expired_legacy_certificate_delete_a_fresh_publication() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::FileStorage::new(directory.path());
        write_legacy_resource(&storage, &cleanup_resource(true)).await;
        let fresh = cleanup_resource(false);
        crate::storage::store_certificate(&storage, "ca", &fresh)
            .await
            .unwrap();
        let result = clean_storage(&storage, &CleanStorageOptions::default())
            .await
            .unwrap();
        assert_eq!(result.deleted_certs, 0);
        let loaded = crate::storage::load_certificate(&storage, "ca", "example.com")
            .await
            .unwrap();
        assert_eq!(loaded.certificate_pem, fresh.certificate_pem);
        assert_eq!(loaded.private_key_pem, fresh.private_key_pem);
    }

    struct CleanupFaultStorage {
        files: crate::FileStorage,
        fail_delete_suffix: Option<&'static str>,
        fail_delete_once: std::sync::atomic::AtomicBool,
        deny_snapshot_load: bool,
    }

    #[async_trait::async_trait]
    impl Storage for CleanupFaultStorage {
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.files.store(key, value).await
        }
        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            if self.deny_snapshot_load && key.ends_with("/_certon/resource.v1.key") {
                return Err(crate::error::StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "snapshot unavailable",
                ))
                .into());
            }
            self.files.load(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            if self
                .fail_delete_suffix
                .is_some_and(|suffix| key.ends_with(suffix))
                && self.fail_delete_once.swap(false, Ordering::SeqCst)
            {
                return Err(crate::Error::Other(
                    "transient certificate deletion failure".into(),
                ));
            }
            self.files.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            self.files.exists(key).await
        }
        async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
            self.files.list(path, recursive).await
        }
        async fn stat(&self, key: &str) -> Result<crate::storage::KeyInfo> {
            self.files.stat(key).await
        }
        async fn lock(&self, name: &str) -> Result<()> {
            self.files.lock(name).await
        }
        async fn unlock(&self, name: &str) -> Result<()> {
            self.files.unlock(name).await
        }
    }

    #[tokio::test]
    async fn cleanup_retries_each_partial_legacy_asset_deletion() {
        for suffix in [".key", ".json", ".crt"] {
            let directory = tempfile::tempdir().unwrap();
            let storage = CleanupFaultStorage {
                files: crate::FileStorage::new(directory.path()),
                fail_delete_suffix: Some(suffix),
                fail_delete_once: std::sync::atomic::AtomicBool::new(true),
                deny_snapshot_load: false,
            };
            write_legacy_resource(&storage, &cleanup_resource(true)).await;
            let cert = crate::storage::site_cert_key("ca", "example.com");
            let key = crate::storage::site_private_key("ca", "example.com");
            let meta = crate::storage::site_meta_key("ca", "example.com");
            let first = clean_storage(&storage, &CleanStorageOptions::default())
                .await
                .unwrap();
            assert_eq!(first.deleted_certs, 0, "failure: {suffix}");
            assert!(
                storage.exists(&cert).await.unwrap(),
                "lost expiry evidence after {suffix} deletion failed"
            );
            assert_eq!(
                storage.exists(&key).await.unwrap(),
                suffix == ".key",
                "failure: {suffix}"
            );
            assert_eq!(
                storage.exists(&meta).await.unwrap(),
                suffix == ".json",
                "failure: {suffix}"
            );
            let second = clean_storage(&storage, &CleanStorageOptions::default())
                .await
                .unwrap();
            assert_eq!(second.deleted_certs, 1, "failure: {suffix}");
            for path in [&cert, &key, &meta] {
                assert!(
                    !storage.exists(path).await.unwrap(),
                    "asset left after retry: {path}; failure: {suffix}"
                );
            }
        }
    }

    #[tokio::test]
    async fn cleanup_cert_only_fallback_never_bypasses_a_snapshot() {
        let snapshot = "certificates/ca/example.com/_certon/resource.v1.key";
        for authority in ["fresh", "malformed", "unavailable"] {
            let directory = tempfile::tempdir().unwrap();
            let storage = CleanupFaultStorage {
                files: crate::FileStorage::new(directory.path()),
                fail_delete_suffix: None,
                fail_delete_once: std::sync::atomic::AtomicBool::new(false),
                deny_snapshot_load: authority == "unavailable",
            };
            write_legacy_resource(&storage, &cleanup_resource(true)).await;
            storage
                .delete(&crate::storage::site_private_key("ca", "example.com"))
                .await
                .unwrap();
            let fresh = cleanup_resource(false);
            let bytes = if authority == "malformed" {
                b"invalid snapshot JSON".to_vec()
            } else {
                serde_json::to_vec(&serde_json::json!({
                    "version": 1, "metadata": &fresh,
                    "certificate_pem": &fresh.certificate_pem,
                    "private_key_pem": &fresh.private_key_pem,
                }))
                .unwrap()
            };
            storage.store(snapshot, &bytes).await.unwrap();
            let result = clean_storage(&storage, &CleanStorageOptions::default())
                .await
                .unwrap();
            assert_eq!(result.deleted_certs, 0, "authority: {authority}");
            assert!(
                storage.exists(snapshot).await.unwrap(),
                "authority: {authority}"
            );
            assert!(
                storage
                    .exists(&crate::storage::site_cert_key("ca", "example.com"))
                    .await
                    .unwrap(),
                "authority: {authority}"
            );
            assert!(
                storage
                    .exists(&crate::storage::site_meta_key("ca", "example.com"))
                    .await
                    .unwrap(),
                "authority: {authority}"
            );
        }
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

    #[tokio::test]
    async fn maintenance_shutdown_is_registered_before_task_start() {
        for stopped_before_start in [false, true] {
            let cache = CertCache::new(CacheOptions::default());
            if stopped_before_start {
                cache.stop();
            }
            let handle = start_maintenance(
                Arc::clone(&cache),
                MaintenanceConfig {
                    renew_check_interval: Duration::from_secs(3600),
                    ocsp_check_interval: Duration::from_secs(3600),
                    ocsp: OcspConfig::default(),
                    storage: Arc::new(DummyStorage),
                },
                Arc::new(|_| Box::pin(async { Ok(()) })),
            );
            tokio::time::timeout(Duration::from_secs(1), cache.stop_and_wait())
                .await
                .unwrap();
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn saturated_maintenance_can_stop_and_drops_never_completing_renewals() {
        use crate::async_jobs::{CERTIFICATE_JOB_CONCURRENCY, CERTIFICATE_JOB_PENDING};

        #[derive(Debug)]
        struct AbsentStore(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl CertStore for AbsentStore {
            async fn load(&self, _: &str, _: &str) -> Result<Option<crate::CertificateResource>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            async fn save(&self, _: &str, _: &crate::CertificateResource) -> Result<()> {
                unreachable!()
            }
            async fn has(&self, _: &str, _: &str) -> Result<bool> {
                Ok(false)
            }
            async fn remove(&self, _: &str, _: &str) -> Result<()> {
                unreachable!()
            }
        }
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let cache = CertCache::new(CacheOptions::default());
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(GatedOcspStorage::new(directory.path()));
        for index in 0..1000 {
            cache
                .add(make_managed_cert(
                    &[&format!("host-{index}.example.com")],
                    &index.to_string(),
                    0,
                ))
                .await;
        }
        let loads = Arc::new(AtomicUsize::new(0));
        let constructed = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let handle = start_maintenance_with_policy(
            cache.clone(),
            MaintenanceConfig {
                renew_check_interval: Duration::from_millis(1),
                ocsp_check_interval: Duration::from_millis(5),
                ocsp: OcspConfig::default(),
                storage: storage.clone(),
            },
            Arc::new({
                let constructed = constructed.clone();
                let active = active.clone();
                move |_, _| {
                    // Callback construction itself must wait for execution.
                    constructed.fetch_add(1, Ordering::SeqCst);
                    let active = active.clone();
                    Box::pin(async move {
                        active.fetch_add(1, Ordering::SeqCst);
                        let _active = Active(active);
                        std::future::pending().await
                    })
                }
            }),
            Arc::new(AbsentStore(loads.clone())),
            DEFAULT_RENEWAL_WINDOW_RATIO,
        );
        let capacity = CERTIFICATE_JOB_CONCURRENCY + CERTIFICATE_JOB_PENDING;
        tokio::time::timeout(Duration::from_secs(2), async {
            while loads.load(Ordering::SeqCst) < capacity + 1
                || active.load(Ordering::SeqCst) < CERTIFICATE_JOB_CONCURRENCY
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            loads.load(Ordering::SeqCst),
            capacity + 1,
            "scan must backpressure at the first unadmitted renewal"
        );
        assert_eq!(
            constructed.load(Ordering::SeqCst),
            CERTIFICATE_JOB_CONCURRENCY
        );
        // Add a real OCSP candidate only after renewal admission is saturated.
        // Its authenticated disk-cached response must still reach the TLS key
        // while the renewal scan remains blocked on its 69th submission.
        let (mut probe, issuer) = signed_certificate();
        probe.managed = false;
        let response = signed_status(&probe, &issuer, 0);
        storage
            .store(
                &crate::storage::ocsp_key(&probe.names[0], &probe.hash),
                &response,
            )
            .await
            .unwrap();
        let domain = probe.names[0].clone();
        let hash = probe.hash.clone();
        cache.add(probe).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if cache
                    .get_by_hash(&hash)
                    .await
                    .unwrap()
                    .ocsp_response
                    .as_ref()
                    == Some(&response)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("saturated renewal scan starved OCSP refresh");
        assert_eq!(cache.resolve(&domain).unwrap().key.ocsp, Some(response));
        assert_eq!(loads.load(Ordering::SeqCst), capacity + 1);
        tokio::time::timeout(Duration::from_secs(1), cache.stop_and_wait())
            .await
            .unwrap();
        handle.await.unwrap();
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "stop returned before renewal futures were dropped"
        );
        assert_eq!(
            constructed.load(Ordering::SeqCst),
            CERTIFICATE_JOB_CONCURRENCY,
            "queued renewals ran during shutdown"
        );
        assert_eq!(Arc::strong_count(&cache), 1);
    }

    #[tokio::test]
    async fn aborting_outer_maintenance_joins_inner_registration() {
        let cache = CertCache::new(CacheOptions::default());
        let handle = start_maintenance(
            Arc::clone(&cache),
            MaintenanceConfig {
                renew_check_interval: Duration::from_secs(3600),
                ocsp_check_interval: Duration::from_secs(3600),
                ocsp: OcspConfig::default(),
                storage: Arc::new(DummyStorage),
            },
            Arc::new(|_| Box::pin(async { Ok(()) })),
        );
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), cache.stop_and_wait())
            .await
            .unwrap();
        assert_eq!(
            Arc::strong_count(&cache),
            1,
            "inner maintenance task was detached"
        );
    }
}
