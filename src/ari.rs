//! Internal ARI lifecycle state. Advisory failures never invalidate a certificate.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::acme_client::RenewalInfo;
use crate::certificates::Certificate;
use crate::error::{Error, Result, StorageError};
use crate::manager::CertManager;
use crate::storage::{Storage, acquire, certificate_leaf_hash, resource_leaf_hash};

const FALLBACK: i64 = 6 * 60 * 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 4;

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    version: u8,
    issuer: String,
    leaf: String,
    info: Option<RenewalInfo>,
    // RenewalInfo deliberately excludes this local choice from wire JSON.
    selected_time: Option<DateTime<Utc>>,
    next_check: DateTime<Utc>,
    failures: u32,
}

fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn identity(issuer: &str, leaf: &str) -> String {
    format!("{}/{leaf}", digest(issuer))
}

fn key(issuer: &str, leaf: &str) -> String {
    format!("ari/{}/state.json", identity(issuer, leaf))
}

fn window(info: &RenewalInfo) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let window = info.suggested_window.as_ref()?;
    let start = DateTime::parse_from_rfc3339(&window.start)
        .ok()?
        .with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339(&window.end)
        .ok()?
        .with_timezone(&Utc);
    (start < end).then_some((start, end))
}

/// A deterministic fallback also makes manually attached, unprepared ARI pure.
pub(crate) fn selected_time(cert: &Certificate, info: &RenewalInfo) -> Option<DateTime<Utc>> {
    let (start, end) = window(info)?;
    if let Some(selected) = info
        .selected_time
        .filter(|selected| *selected >= start && *selected < end)
    {
        return Some(selected);
    }
    let leaf = certificate_leaf_hash(cert)?;
    let digest = Sha256::digest(format!("{leaf}/{start}/{end}").as_bytes());
    let random = u64::from_be_bytes(digest[..8].try_into().ok()?);
    // Whole milliseconds keep checked arithmetic bounded even for hostile dates.
    let span = (end - start).num_milliseconds();
    if span <= 0 {
        return Some(start);
    }
    start.checked_add_signed(chrono::Duration::milliseconds(
        (random % span as u64) as i64,
    ))
}

pub(crate) fn needs_renewal(cert: &Certificate, ratio: f64, disabled: bool) -> bool {
    cert.needs_renewal_with_ari(ratio, !disabled)
}

async fn load(storage: &dyn Storage, issuer: &str, leaf: &str) -> Result<Option<Record>> {
    let data = match storage.load(&key(issuer, leaf)).await {
        Ok(data) => data,
        Err(Error::Storage(StorageError::NotFound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut record: Record = serde_json::from_slice(&data)
        .map_err(|error| StorageError::Deserialize(error.to_string()))?;
    if record.version != 1 || record.issuer != issuer || record.leaf != leaf {
        return Err(
            StorageError::Deserialize("ARI record identity/version mismatch".into()).into(),
        );
    }
    if let Some(info) = &mut record.info {
        let (start, end) =
            window(info).ok_or_else(|| StorageError::Deserialize("invalid ARI window".into()))?;
        if !record
            .selected_time
            .is_some_and(|time| time >= start && time < end)
        {
            return Err(StorageError::Deserialize("invalid ARI selected time".into()).into());
        }
        info.selected_time = record.selected_time;
    }
    Ok(Some(record))
}

/// Load only advisory state. Certificate/marker failures are handled by callers.
fn fingerprint(record: Option<&Record>) -> Option<String> {
    record
        .and_then(|record| serde_json::to_string(record).ok())
        .map(|json| digest(&json))
}

pub(crate) async fn attach(storage: &dyn Storage, cert: &mut Certificate, disabled: bool) {
    attach_impl(storage, None, cert, disabled).await;
}

pub(crate) async fn attach_cached(
    storage: &dyn Storage,
    cache: &crate::CertCache,
    cert: &mut Certificate,
    disabled: bool,
) {
    attach_impl(storage, Some(cache), cert, disabled).await;
}

async fn attach_impl(
    storage: &dyn Storage,
    cache: Option<&crate::CertCache>,
    cert: &mut Certificate,
    disabled: bool,
) {
    cert.ari = None;
    if disabled {
        return;
    }
    let Some(leaf) = certificate_leaf_hash(cert) else {
        return;
    };
    let loaded = match tokio::time::timeout(
        Duration::from_secs(5),
        load(storage, &cert.issuer_key, &leaf),
    )
    .await
    {
        Ok(Ok(record)) => Some((
            fingerprint(record.as_ref()),
            record.and_then(|record| record.info),
        )),
        Ok(Err(error)) => {
            warn!(%error, "cannot load advisory ARI state; using renewal fallback");
            None
        }
        Err(_) => {
            warn!("advisory ARI load timed out; using renewal fallback");
            None
        }
    };
    cert.ari = match cache {
        Some(cache) => cache.reconcile_ari(&cert.hash, &cert.issuer_key, loaded),
        None => loaded.and_then(|(_, info)| info),
    };
}

fn after(seconds: i64) -> DateTime<Utc> {
    Utc::now() + chrono::Duration::seconds(seconds)
}

fn retry_seconds(value: Option<u64>) -> i64 {
    value.unwrap_or(FALLBACK as u64).clamp(60, 24 * 60 * 60) as i64
}

/// Called only for a managed snapshot; lifecycle locks are never acquired here.
/// The separate ARI lock serializes the selected point across processes.
pub(crate) async fn refresh(manager: &CertManager, cert: &Certificate) -> DateTime<Utc> {
    if manager.policy.disable_ari || cert.expired() {
        return after(FALLBACK);
    }
    let Some(leaf) = certificate_leaf_hash(cert) else {
        return after(FALLBACK);
    };
    match tokio::time::timeout(REQUEST_TIMEOUT, refresh_inner(manager, cert, &leaf)).await {
        Ok(Ok(next)) => next,
        Ok(Err(error)) => {
            warn!(%error, "ARI unavailable; retaining certificate and renewal fallback");
            after(FALLBACK)
        }
        Err(_) => {
            warn!("ARI refresh timed out; retaining certificate");
            after(60)
        }
    }
}

async fn refresh_inner(
    manager: &CertManager,
    cert: &Certificate,
    leaf: &str,
) -> Result<DateTime<Utc>> {
    let name = cert
        .names
        .first()
        .ok_or_else(|| Error::Other("ARI certificate has no names".into()))?;
    let _lock = acquire(
        manager.storage.clone(),
        &format!("ari_{}", digest(&identity(&cert.issuer_key, leaf))),
    )
    .await?;
    // Recheck before starting a new request. A late response is confined to its
    // own leaf's sidecar and conditional cache update, never a replacement leaf.
    let previous = load(manager.storage.as_ref(), &cert.issuer_key, leaf).await?;
    let Some(resource) = manager.certificates.load(&cert.issuer_key, name).await? else {
        return Ok(after(FALLBACK));
    };
    if resource_leaf_hash(&resource)? != leaf
        || cert.expired()
        || manager
            .cache
            .ari_certificate(&cert.hash)
            .is_none_or(|current| current.issuer_key != cert.issuer_key)
    {
        return Ok(after(FALLBACK));
    }
    manager.cache.reconcile_ari(
        &cert.hash,
        &cert.issuer_key,
        Some((
            fingerprint(previous.as_ref()),
            previous.as_ref().and_then(|record| record.info.clone()),
        )),
    );
    let unpersisted = manager
        .cache
        .has_unpersisted_ari(&cert.hash, &cert.issuer_key);
    if let Some(record) = &previous
        && record.next_check > Utc::now()
        && !unpersisted
    {
        manager
            .cache
            .update_ari(&cert.issuer_key, leaf, record.info.clone(), None);
        return Ok(record.next_check);
    }
    let Some(issuer) = manager
        .issuers
        .iter()
        .find(|issuer| issuer.issuer_key() == cert.issuer_key)
    else {
        return Ok(after(FALLBACK));
    };
    let response = tokio::time::timeout(
        Duration::from_secs(20),
        issuer.renewal_info(&cert.cert_chain[0]),
    )
    .await
    .unwrap_or_else(|_| Err(Error::Timeout("ARI endpoint timed out".into())));
    let mut record = Record {
        version: 1,
        issuer: cert.issuer_key.clone(),
        leaf: leaf.to_owned(),
        info: None,
        selected_time: None,
        next_check: after(FALLBACK),
        failures: 0,
    };
    match response {
        Ok(Some(mut info)) if window(&info).is_some() && info.retry_after.is_some() => {
            // Ignore any selected_time supplied by an issuer; it is local state.
            info.selected_time = None;
            let selected = previous
                .as_ref()
                .filter(|old| old.info.as_ref().and_then(window) == window(&info))
                .and_then(|old| old.selected_time)
                .or_else(|| selected_time(cert, &info));
            info.selected_time = selected;
            record.next_check = after(retry_seconds(info.retry_after));
            record.selected_time = selected;
            record.info = Some(info);
        }
        Ok(_) => {} // Unsupported or invalid responses use the original policy.
        Err(error) => {
            // A temporary outage must not discard a previously agreed point.
            record.info = manager.cache.reconcile_ari(
                &cert.hash,
                &cert.issuer_key,
                Some((
                    fingerprint(previous.as_ref()),
                    previous.as_ref().and_then(|record| record.info.clone()),
                )),
            );
            record.selected_time = record
                .info
                .as_ref()
                .and_then(|info| selected_time(cert, info));
            warn!(%error, "ARI request failed; retaining the last valid renewal point");
            // Timeout/server failures use capped exponential retry. Other
            // protocol failures use the RFC's long-term/default interval.
            if matches!(
                error,
                Error::Timeout(_) | Error::Acme(crate::error::AcmeError::RenewalInfoTemporary(_))
            ) {
                record.failures = previous
                    .as_ref()
                    .map_or(1, |old| old.failures.saturating_add(1));
                record.next_check = after(if record.failures >= 8 {
                    FALLBACK
                } else {
                    60 * (1 << record.failures)
                });
            }
        }
    }
    // Persistence is advisory too: keep the in-memory schedule even if saving
    // fails, and do not retry successful certificate issuance as a result.
    let persisted = match manager
        .storage
        .store(
            &key(&cert.issuer_key, leaf),
            &serde_json::to_vec(&record).map_err(|e| StorageError::Serialize(e.to_string()))?,
        )
        .await
    {
        Ok(()) => true,
        Err(error) => {
            warn!(%error, "cannot persist advisory ARI state");
            false
        }
    };
    manager.cache.update_ari(
        &cert.issuer_key,
        leaf,
        record.info,
        (!persisted).then(|| fingerprint(previous.as_ref())),
    );
    Ok(record.next_check)
}

struct Scheduled {
    cert: Arc<Certificate>,
    next_check: DateTime<Utc>,
    notified: Option<DateTime<Utc>>,
    queued: bool,
    refresh_requested: bool,
}

impl Scheduled {
    fn deadline(&self) -> Option<DateTime<Utc>> {
        let selected = self
            .cert
            .ari
            .as_ref()
            .and_then(|info| selected_time(&self.cert, info))
            .filter(|time| self.notified != Some(*time));
        (!self.queued)
            .then_some(self.next_check)
            .into_iter()
            .chain(selected)
            .min()
    }
}

type Timers = BTreeMap<DateTime<Utc>, HashSet<String>>;

fn unschedule(timers: &mut Timers, id: &str, entry: &Scheduled) {
    if let Some(time) = entry.deadline()
        && let Some(ids) = timers.get_mut(&time)
    {
        ids.remove(id);
        if ids.is_empty() {
            timers.remove(&time);
        }
    }
}

fn schedule(timers: &mut Timers, id: &str, entry: &Scheduled) {
    if let Some(time) = entry.deadline() {
        timers.entry(time).or_default().insert(id.to_owned());
    }
}

/// Four borrowed requests, one indexed timer per live leaf, and a low-frequency
/// membership scan. Finishing a request does not rescan every managed entry.
pub(crate) async fn run(manager: &CertManager) {
    if manager.policy.disable_ari {
        std::future::pending::<()>().await;
    }
    type Work<'a> = Pin<Box<dyn Future<Output = (String, DateTime<Utc>)> + Send + 'a>>;
    let mut work: Vec<Work<'_>> = Vec::new();
    let mut entries = HashMap::<String, Scheduled>::new();
    let mut timers = Timers::new();
    let mut ready = VecDeque::new();
    let mut scan = tokio::time::interval(Duration::from_secs(60));
    let mut changed = manager.cache.subscribe_ari_schedule();
    let mut reload_schedules = false;
    loop {
        while work.len() < MAX_IN_FLIGHT {
            let Some(id) = ready.pop_front() else {
                break;
            };
            let Some(entry) = entries.get(&id) else {
                continue;
            };
            let cert = entry.cert.clone();
            work.push(Box::pin(async move { (id, refresh(manager, &cert).await) }));
        }
        let delay = timers.first_key_value().map(|(time, _)| {
            (*time - Utc::now())
                .to_std()
                .unwrap_or_default()
                .min(Duration::from_secs(86400))
        });
        tokio::select! {
            _ = scan.tick() => {
                let mut live = HashSet::new();
                for cert in manager.cache.maintenance_snapshot(true) {
                    if cert.expired() { continue; }
                    let Some(leaf) = certificate_leaf_hash(&cert) else { continue; };
                    let id = identity(&cert.issuer_key, &leaf);
                    // Alternate chains share one request and selected point.
                    if !live.insert(id.clone()) { continue; }
                    if let Some(entry) = entries.get_mut(&id) {
                        unschedule(&mut timers, &id, entry);
                        entry.cert = cert;
                        if reload_schedules {
                            if entry.queued { entry.refresh_requested = true; } else { entry.next_check = Utc::now(); }
                        }
                        schedule(&mut timers, &id, entry);
                    } else {
                        let entry = Scheduled { cert, next_check: Utc::now(), notified: None, queued: false, refresh_requested: false };
                        schedule(&mut timers, &id, &entry);
                        entries.insert(id, entry);
                    }
                }
                entries.retain(|id, entry| {
                    if live.contains(id) { return true; }
                    unschedule(&mut timers, id, entry);
                    false
                });
                ready.retain(|id| live.contains(id));
                reload_schedules = false;
            }
            _ = async {
                match delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                while timers.first_key_value().is_some_and(|(time, _)| *time <= Utc::now()) {
                    let (_, ids) = timers.pop_first().unwrap();
                    let mut notify = false;
                    for id in ids {
                        let Some(entry) = entries.get_mut(&id) else { continue; };
                        if let Some(selected) = entry.cert.ari.as_ref().and_then(|info| selected_time(&entry.cert, info))
                            && selected <= Utc::now() && entry.notified != Some(selected) {
                                entry.notified = Some(selected);
                                notify = true;
                            }
                        if !entry.queued && entry.next_check <= Utc::now() {
                            entry.queued = true;
                            ready.push_back(id.clone());
                        }
                        schedule(&mut timers, &id, entry);
                    }
                    if notify { manager.cache.notify_ari(); }
                }
            }
            notification = changed.recv() => {
                match notification {
                    Ok(change) => {
                        if let Some(cert) = manager.cache.ari_certificate(&change.hash).filter(|cert| !cert.expired())
                            && let Some(leaf) = certificate_leaf_hash(&cert) {
                                let id = identity(&cert.issuer_key, &leaf);
                                if let Some(entry) = entries.get_mut(&id) {
                                    unschedule(&mut timers, &id, entry);
                                    entry.cert = cert;
                                    if change.reload {
                                        if entry.queued { entry.refresh_requested = true; } else { entry.next_check = Utc::now(); }
                                    }
                                    schedule(&mut timers, &id, entry);
                                } else {
                                    let entry = Scheduled { cert, next_check: Utc::now(), notified: None, queued: false, refresh_requested: false };
                                    schedule(&mut timers, &id, &entry);
                                    entries.insert(id, entry);
                                }
                            } else {
                                scan.reset_immediately();
                            }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => { reload_schedules = true; scan.reset_immediately(); },
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
            result = poll_fn(|cx| {
                for (index, task) in work.iter_mut().enumerate() {
                    if let Poll::Ready(result) = task.as_mut().poll(cx) { return Poll::Ready((index, result)); }
                }
                Poll::Pending
            }), if !work.is_empty() => {
                let (index, (id, deadline)) = result;
                drop(work.swap_remove(index));
                if let Some(entry) = entries.get_mut(&id) {
                    unschedule(&mut timers, &id, entry);
                    entry.next_check = if entry.refresh_requested { Utc::now() } else { deadline };
                    entry.refresh_requested = false;
                    entry.queued = false;
                    if let Some(cert) = manager.cache.ari_certificate(&entry.cert.hash) {
                        entry.cert = cert;
                    }
                    schedule(&mut timers, &id, entry);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
