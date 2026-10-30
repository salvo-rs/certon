use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::Semaphore;

use super::*;
use crate::async_jobs::{CERTIFICATE_JOB_CONCURRENCY, CERTIFICATE_JOB_PENDING};
use crate::{Certificate, CertificateResource};

#[derive(Debug)]
struct GatedStore {
    resources: HashMap<String, CertificateResource>,
    gate: AtomicBool,
    loads: AtomicUsize,
    active: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    started: Semaphore,
    release: Semaphore,
}

impl GatedStore {
    fn new(resources: HashMap<String, CertificateResource>) -> Self {
        Self {
            resources,
            gate: AtomicBool::new(true),
            loads: AtomicUsize::new(0),
            active: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
            started: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }

    async fn wait_started(&self, count: u32) {
        tokio::time::timeout(Duration::from_secs(5), self.started.acquire_many(count))
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}

struct ActiveLoad {
    active: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl Drop for ActiveLoad {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl CertStore for GatedStore {
    async fn load(&self, _: &str, domain: &str) -> Result<Option<CertificateResource>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if self.gate.load(Ordering::SeqCst) {
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveLoad {
                active: self.active.clone(),
                dropped: self.dropped.clone(),
            };
            self.started.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        Ok(self.resources.get(domain).cloned())
    }
    async fn save(&self, _: &str, _: &CertificateResource) -> Result<()> {
        unreachable!()
    }
    async fn has(&self, _: &str, _: &str) -> Result<bool> {
        unreachable!()
    }
    async fn remove(&self, _: &str, _: &str) -> Result<()> {
        unreachable!()
    }
}

pub(super) fn certificate(domain: &str, fresh: bool) -> (CertificateResource, Certificate) {
    let mut params =
        rcgen::CertificateParams::new(vec![domain.to_owned(), format!("alias.{domain}")]).unwrap();
    let now = std::time::SystemTime::now();
    params.not_before = (now - Duration::from_secs(if fresh { 86400 } else { 70 * 86400 })).into();
    params.not_after =
        (now + Duration::from_secs(if fresh { 90 * 86400 } else { 20 * 86400 })).into();
    let key = rcgen::KeyPair::generate().unwrap();
    let signed = params.self_signed(&key).unwrap();
    let resource = CertificateResource {
        certificate_pem: signed.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        sans: vec![domain.into()],
        issuer_key: "preflight-ca".into(),
        issuer_data: None,
    };
    let cert = crate::manager::CertManager::parse_managed_certificate(&resource, domain).unwrap();
    assert_eq!(cert.needs_renewal(DEFAULT_RENEWAL_WINDOW_RATIO), !fresh);
    (resource, cert)
}

fn policy(
    store: Arc<GatedStore>,
    callbacks: Arc<AtomicUsize>,
) -> (RenewalPolicy, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let policy = RenewalPolicy {
        renew: Arc::new(move |_, reason| {
            assert_eq!(reason, RenewalReason::Expiring);
            let callbacks = callbacks.clone();
            Box::pin(async move {
                callbacks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }),
        observed_renew: None,
        certificates: store,
        revocations: Arc::new(crate::FileStorage::new(directory.path())),
        ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
        ari_manager: None,
    };
    (policy, directory)
}

#[tokio::test]
async fn preflight_shares_both_execution_and_admission_limits() {
    let cache = CertCache::new(Default::default());
    for index in 0..100 {
        cache
            .add(certificate(&format!("host-{index}.example"), false).1)
            .await;
    }
    let store = Arc::new(GatedStore::new(HashMap::new()));
    let callbacks = Arc::new(AtomicUsize::new(0));
    let (policy, _directory) = policy(store.clone(), callbacks.clone());
    let jobs = Arc::new(JobQueue::certificate_jobs("bounded-preflight"));
    let producer = tokio::spawn({
        let cache = cache.clone();
        let jobs = jobs.clone();
        async move { check_renewals_with_policy(&cache, &policy, &jobs).await }
    });
    store.wait_started(CERTIFICATE_JOB_CONCURRENCY as u32).await;
    let capacity = CERTIFICATE_JOB_CONCURRENCY + CERTIFICATE_JOB_PENDING;
    tokio::time::timeout(Duration::from_secs(5), async {
        while jobs.len().await < capacity {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(jobs.len().await, capacity);
    assert_eq!(
        store.loads.load(Ordering::SeqCst),
        CERTIFICATE_JOB_CONCURRENCY
    );
    assert_eq!(
        store.active.load(Ordering::SeqCst),
        CERTIFICATE_JOB_CONCURRENCY
    );
    assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    producer.abort();
    assert!(producer.await.unwrap_err().is_cancelled());
    jobs.shutdown().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.dropped.load(Ordering::SeqCst),
        CERTIFICATE_JOB_CONCURRENCY
    );
}

#[tokio::test]
async fn duplicate_scans_do_not_repeat_a_running_preflight() {
    let cache = CertCache::new(Default::default());
    cache.add(certificate("dedup.example", false).1).await;
    let store = Arc::new(GatedStore::new(HashMap::new()));
    let (policy, _directory) = policy(store.clone(), Arc::new(AtomicUsize::new(0)));
    let jobs = JobQueue::certificate_jobs("dedup-preflight");
    check_renewals_with_policy(&cache, &policy, &jobs).await;
    store.wait_started(1).await;
    check_renewals_with_policy(&cache, &policy, &jobs).await;
    assert_eq!(jobs.len().await, 1);
    assert_eq!(store.loads.load(Ordering::SeqCst), 1);
    jobs.shutdown().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    assert_eq!(store.dropped.load(Ordering::SeqCst), 1);
}

async fn withdraw(cache: &CertCache, old: &Certificate, mutation: &str) {
    match mutation {
        "remove" => cache.remove(&old.hash).await,
        "replace" => {
            cache
                .replace(&old.hash, certificate("stale.example", true).1)
                .await
        }
        _ => {
            let mut current = old.clone();
            match mutation {
                "unmanage" => current.managed = false,
                "issuer" => current.issuer_key = "different-ca".into(),
                "alias" => current.names.insert(0, "alias.stale.example".into()),
                "ari" => {
                    let start = chrono::Utc::now() + chrono::Duration::hours(1);
                    current.ari = Some(crate::RenewalInfo {
                        suggested_window: Some(crate::RenewalWindow {
                            start: start.to_rfc3339(),
                            end: (start + chrono::Duration::hours(1)).to_rfc3339(),
                        }),
                        selected_time: Some(start),
                        ..Default::default()
                    });
                }
                _ => unreachable!(),
            }
            cache.replace(&old.hash, current).await;
        }
    }
}

#[tokio::test]
async fn queued_jobs_recheck_management_identity_and_ari_before_any_preflight_io() {
    for mutation in ["remove", "replace", "unmanage", "issuer", "alias", "ari"] {
        let cache = CertCache::new(Default::default());
        let old = certificate("stale.example", false).1;
        cache.add(old.clone()).await;
        let store = Arc::new(GatedStore::new(HashMap::new()));
        store.gate.store(false, Ordering::SeqCst);
        let callbacks = Arc::new(AtomicUsize::new(0));
        let (policy, _directory) = policy(store.clone(), callbacks.clone());
        let jobs = JobQueue::with_limits("queued-stale-preflight", 1, 1);
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        jobs.submit("blocker".into(), {
            let started = started.clone();
            let release = release.clone();
            move || async move {
                started.add_permits(1);
                release.acquire().await.unwrap().forget();
            }
        })
        .await;
        started.acquire().await.unwrap().forget();
        check_renewals_with_policy(&cache, &policy, &jobs).await;
        assert_eq!(jobs.len().await, 2);
        withdraw(&cache, &old, mutation).await;
        release.add_permits(1);
        wait_for_renewal_jobs(&jobs).await;
        assert_eq!(store.loads.load(Ordering::SeqCst), 0, "{mutation}");
        assert_eq!(callbacks.load(Ordering::SeqCst), 0, "{mutation}");
        jobs.shutdown().await;
    }
}

#[tokio::test]
async fn in_flight_preflight_cannot_restore_withdrawn_management_or_invoke_renewal() {
    for mutation in ["remove", "replace", "unmanage", "issuer", "alias"] {
        let cache = CertCache::new(Default::default());
        let old = certificate("stale.example", false).1;
        let (resource, replacement) = certificate("stale.example", true);
        cache.add(old.clone()).await;
        let store = Arc::new(GatedStore::new(HashMap::from([(
            "stale.example".into(),
            resource,
        )])));
        let callbacks = Arc::new(AtomicUsize::new(0));
        let (policy, _directory) = policy(store.clone(), callbacks.clone());
        let jobs = JobQueue::certificate_jobs("in-flight-stale-preflight");
        check_renewals_with_policy(&cache, &policy, &jobs).await;
        store.wait_started(1).await;
        withdraw(&cache, &old, mutation).await;
        store.release.add_permits(1);
        wait_for_renewal_jobs(&jobs).await;
        assert!(
            cache.get_by_hash(&replacement.hash).await.is_none(),
            "{mutation}"
        );
        assert_eq!(callbacks.load(Ordering::SeqCst), 0, "{mutation}");
        assert_eq!(store.active.load(Ordering::SeqCst), 0);
        jobs.shutdown().await;
    }
}

struct MarkerStorage {
    files: crate::FileStorage,
    response: &'static str,
    gated: bool,
    slow: Option<String>,
    reads: AtomicUsize,
    active: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    entered: Semaphore,
    release: Semaphore,
}

impl MarkerStorage {
    fn new(path: &std::path::Path, response: &'static str, gated: bool) -> Self {
        Self {
            files: crate::FileStorage::new(path),
            response,
            gated,
            slow: None,
            reads: AtomicUsize::new(0),
            active: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }

    async fn wait_started(&self, count: u32) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.acquire_many(count))
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}

#[async_trait::async_trait]
impl Storage for MarkerStorage {
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveLoad {
                active: self.active.clone(),
                dropped: self.dropped.clone(),
            };
            self.entered.add_permits(1);
            if self.gated && self.slow.as_deref().is_none_or(|slow| slow == key) {
                self.release.acquire().await.unwrap().forget();
            }
            return match self.response {
                "pending" => Ok(br#"{"version":1,"confirmed":false}"#.to_vec()),
                "confirmed" => Ok(br#"{"version":1,"confirmed":true}"#.to_vec()),
                "malformed" => Ok(b"not valid marker JSON".to_vec()),
                "error" => Err(crate::error::StorageError::Io(std::io::Error::other(
                    "marker backend unavailable",
                ))
                .into()),
                _ => Err(crate::error::StorageError::NotFound(key.into()).into()),
            };
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
    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        self.files.list(prefix, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<crate::KeyInfo> {
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
async fn own_marker_hit_and_read_failure_stop_preflight_and_renewal() {
    for response in ["none", "pending", "confirmed", "malformed", "error"] {
        let cache = CertCache::new(Default::default());
        let cert = certificate("marker.example", false).1;
        cache.add(cert.clone()).await;
        let store = Arc::new(GatedStore::new(HashMap::new()));
        store.gate.store(false, Ordering::SeqCst);
        let callbacks = Arc::new(AtomicUsize::new(0));
        let (mut policy, directory) = policy(store.clone(), callbacks.clone());
        let markers = Arc::new(MarkerStorage::new(directory.path(), response, false));
        policy.revocations = markers.clone();
        let jobs = JobQueue::certificate_jobs("own-marker");
        check_renewals_with_policy(&cache, &policy, &jobs).await;
        wait_for_renewal_jobs(&jobs).await;
        assert_eq!(markers.reads.load(Ordering::SeqCst), 1, "{response}");
        assert_eq!(
            store.loads.load(Ordering::SeqCst),
            usize::from(response == "none"),
            "{response}"
        );
        assert_eq!(
            callbacks.load(Ordering::SeqCst),
            usize::from(response == "none"),
            "{response}"
        );
        assert_eq!(
            cache.get_by_hash(&cert.hash).await.is_none(),
            matches!(response, "pending" | "confirmed"),
            "{response}"
        );
        jobs.shutdown().await;
    }
}

#[tokio::test]
async fn own_marker_wait_shares_the_execution_and_admission_budget() {
    let cache = CertCache::new(Default::default());
    for index in 0..100 {
        cache
            .add(certificate(&format!("marker-{index}.example"), false).1)
            .await;
    }
    let store = Arc::new(GatedStore::new(HashMap::new()));
    store.gate.store(false, Ordering::SeqCst);
    let callbacks = Arc::new(AtomicUsize::new(0));
    let (mut policy, directory) = policy(store.clone(), callbacks.clone());
    let markers = Arc::new(MarkerStorage::new(directory.path(), "none", true));
    policy.revocations = markers.clone();
    let jobs = Arc::new(JobQueue::certificate_jobs("bounded-markers"));
    let producer = tokio::spawn({
        let cache = cache.clone();
        let jobs = jobs.clone();
        async move { check_renewals_with_policy(&cache, &policy, &jobs).await }
    });
    markers
        .wait_started(CERTIFICATE_JOB_CONCURRENCY as u32)
        .await;
    let capacity = CERTIFICATE_JOB_CONCURRENCY + CERTIFICATE_JOB_PENDING;
    tokio::time::timeout(Duration::from_secs(5), async {
        while jobs.len().await < capacity {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(jobs.len().await, capacity);
    assert_eq!(
        markers.reads.load(Ordering::SeqCst),
        CERTIFICATE_JOB_CONCURRENCY
    );
    assert_eq!(
        markers.active.load(Ordering::SeqCst),
        CERTIFICATE_JOB_CONCURRENCY
    );
    assert_eq!(store.loads.load(Ordering::SeqCst), 0);
    assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    producer.abort();
    assert!(producer.await.unwrap_err().is_cancelled());
    jobs.shutdown().await;
    assert_eq!(markers.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        markers.dropped.load(Ordering::SeqCst),
        CERTIFICATE_JOB_CONCURRENCY
    );
}

#[tokio::test]
async fn duplicate_scans_do_not_start_another_own_marker_read() {
    let cache = CertCache::new(Default::default());
    cache
        .add(certificate("dedup-marker.example", false).1)
        .await;
    let store = Arc::new(GatedStore::new(HashMap::new()));
    let (mut policy, directory) = policy(store, Arc::new(AtomicUsize::new(0)));
    let markers = Arc::new(MarkerStorage::new(directory.path(), "none", true));
    policy.revocations = markers.clone();
    let jobs = JobQueue::certificate_jobs("dedup-markers");
    check_renewals_with_policy(&cache, &policy, &jobs).await;
    markers.wait_started(1).await;
    for _ in 0..10 {
        check_renewals_with_policy(&cache, &policy, &jobs).await;
    }
    assert_eq!(jobs.len().await, 1);
    assert_eq!(markers.reads.load(Ordering::SeqCst), 1);
    jobs.shutdown().await;
    assert_eq!(markers.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn own_marker_wait_rechecks_withdrawal_identity_and_ari_before_preflight() {
    for mutation in ["remove", "replace", "unmanage", "issuer", "alias", "ari"] {
        let cache = CertCache::new(Default::default());
        let old = certificate("stale.example", false).1;
        cache.add(old.clone()).await;
        let store = Arc::new(GatedStore::new(HashMap::new()));
        store.gate.store(false, Ordering::SeqCst);
        let callbacks = Arc::new(AtomicUsize::new(0));
        let (mut policy, directory) = policy(store.clone(), callbacks.clone());
        let markers = Arc::new(MarkerStorage::new(directory.path(), "none", true));
        policy.revocations = markers.clone();
        let jobs = JobQueue::certificate_jobs("stale-markers");
        check_renewals_with_policy(&cache, &policy, &jobs).await;
        markers.wait_started(1).await;
        withdraw(&cache, &old, mutation).await;
        markers.release.add_permits(1);
        wait_for_renewal_jobs(&jobs).await;
        assert_eq!(store.loads.load(Ordering::SeqCst), 0, "{mutation}");
        assert_eq!(callbacks.load(Ordering::SeqCst), 0, "{mutation}");
        assert_eq!(markers.active.load(Ordering::SeqCst), 0);
        jobs.shutdown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn ari_notification_renews_a_healthy_leaf_while_an_unrelated_marker_scan_is_pending() {
    let cache = CertCache::new(Default::default());
    let slow = certificate("slow-ari.example", true).1;
    let mut healthy = certificate("healthy-ari.example", true).1;
    cache.add(slow.clone()).await;
    cache.add(healthy.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let mut markers = MarkerStorage::new(directory.path(), "none", true);
    markers.slow = Some(format!(
        "revocations/{}.json",
        crate::storage::certificate_leaf_hash(&slow).unwrap()
    ));
    let markers = Arc::new(markers);
    let store = Arc::new(GatedStore::new(HashMap::new()));
    store.gate.store(false, Ordering::SeqCst);
    let renewed = Arc::new(Semaphore::new(0));
    let maintenance = start_maintenance_with_policy(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(600),
            ocsp_check_interval: Duration::from_secs(1),
            storage: markers.clone(),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
        },
        Arc::new({
            let renewed = renewed.clone();
            move |name, reason| {
                assert_eq!(name, "healthy-ari.example");
                assert_eq!(reason, RenewalReason::Expiring);
                let renewed = renewed.clone();
                Box::pin(async move {
                    renewed.add_permits(1);
                    Ok(())
                })
            }
        }),
        store.clone(),
        DEFAULT_RENEWAL_WINDOW_RATIO,
    );
    markers.wait_started(2).await;
    assert_eq!(markers.active.load(Ordering::SeqCst), 1);
    let selected = chrono::Utc::now() - chrono::Duration::minutes(1);
    healthy.ari = Some(crate::RenewalInfo {
        suggested_window: Some(crate::RenewalWindow {
            start: (selected - chrono::Duration::minutes(1)).to_rfc3339(),
            end: (selected + chrono::Duration::minutes(1)).to_rfc3339(),
        }),
        selected_time: Some(selected),
        ..Default::default()
    });
    let hash = healthy.hash.clone();
    cache.replace(&hash, healthy).await;
    cache.notify_ari();
    tokio::time::timeout(Duration::from_secs(5), renewed.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(store.loads.load(Ordering::SeqCst), 1);
    assert_eq!(
        markers.active.load(Ordering::SeqCst),
        1,
        "unrelated marker must remain gated"
    );
    cache.stop_and_wait().await;
    maintenance.await.unwrap();
    assert_eq!(markers.active.load(Ordering::SeqCst), 0);
}
