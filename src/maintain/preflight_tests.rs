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

fn certificate(domain: &str, fresh: bool) -> (CertificateResource, Certificate) {
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
        jobs.wait("renew_stale.example").await;
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
        jobs.wait("renew_stale.example").await;
        assert!(
            cache.get_by_hash(&replacement.hash).await.is_none(),
            "{mutation}"
        );
        assert_eq!(callbacks.load(Ordering::SeqCst), 0, "{mutation}");
        assert_eq!(store.active.load(Ordering::SeqCst), 0);
        jobs.shutdown().await;
    }
}
