use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use certon::maintain::{MaintenanceConfig, ReasonedRenewFn, start_maintenance_with_policy};
use certon::{
    CertCache, CertStore, Certificate, CertificateResource, KeyInfo, OcspConfig, Result, Storage,
};
use tokio::sync::Semaphore;

#[derive(Debug)]
struct MarkerStorage {
    slow: String,
    entered: Semaphore,
    other_completed: Semaphore,
    release: Semaphore,
    reads: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
}

impl MarkerStorage {
    fn new(slow: String, released: usize) -> Self {
        Self {
            slow,
            entered: Semaphore::new(0),
            other_completed: Semaphore::new(0),
            release: Semaphore::new(released),
            reads: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }
}

struct ActiveRead<'a>(&'a AtomicUsize);
impl Drop for ActiveRead<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Storage for MarkerStorage {
    async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let _active = ActiveRead(&self.active);
            if key == self.slow || self.slow == "*" {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            } else {
                self.other_completed.add_permits(1);
            }
        }
        Err(certon::error::StorageError::NotFound(key.into()).into())
    }
    async fn delete(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn exists(&self, _: &str) -> Result<bool> {
        Ok(false)
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        Ok(vec![])
    }
    async fn stat(&self, _: &str) -> Result<KeyInfo> {
        unreachable!()
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

fn due_certificate(name: &str) -> Certificate {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.not_before = (std::time::SystemTime::now() - Duration::from_secs(80 * 86400)).into();
    params.not_after = (std::time::SystemTime::now() + Duration::from_secs(10 * 86400)).into();
    let key = rcgen::KeyPair::generate().unwrap();
    let signed = params.self_signed(&key).unwrap();
    let mut cert =
        Certificate::from_pem(signed.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    assert!(cert.needs_renewal(1.0 / 3.0));
    cert.managed = true;
    cert.names = vec![name.into()];
    cert.issuer_key = "review-ca".into();
    cert
}

#[derive(Debug, Default)]
struct EmptyCertStore {
    loads: AtomicUsize,
}
#[async_trait]
impl CertStore for EmptyCertStore {
    async fn load(&self, _: &str, _: &str) -> Result<Option<CertificateResource>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    async fn save(&self, _: &str, _: &CertificateResource) -> Result<()> {
        Ok(())
    }
    async fn has(&self, _: &str, _: &str) -> Result<bool> {
        Ok(false)
    }
    async fn remove(&self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
}

async fn exercise(gate: bool) -> bool {
    let cache = CertCache::new(Default::default());
    let mut slow = String::new();
    for name in ["slow.example", "healthy.example"] {
        let cert = due_certificate(name);
        if name == "slow.example" {
            slow = format!(
                "revocations/{}.json",
                certon::certificates::hash_certificate_chain(&cert.cert_chain[..1])
            );
        }
        cache.add(cert).await;
    }
    let storage = Arc::new(MarkerStorage::new(slow, usize::from(!gate) * 100));
    let certificates = Arc::new(EmptyCertStore::default());
    let seen = Arc::new(AtomicUsize::new(0));
    let healthy_renewed = Arc::new(Semaphore::new(0));
    let all_renewed = Arc::new(Semaphore::new(0));
    let renew: Arc<ReasonedRenewFn> = {
        let seen = seen.clone();
        let healthy_renewed = healthy_renewed.clone();
        let all_renewed = all_renewed.clone();
        Arc::new(move |name, _| {
            let seen = seen.clone();
            let healthy_renewed = healthy_renewed.clone();
            let all_renewed = all_renewed.clone();
            Box::pin(async move {
                let bit = if name == "healthy.example" {
                    healthy_renewed.add_permits(1);
                    2
                } else {
                    1
                };
                seen.fetch_or(bit, Ordering::SeqCst);
                all_renewed.add_permits(1);
                Ok(())
            })
        })
    };
    let task = start_maintenance_with_policy(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(60),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: storage.clone(),
        },
        renew,
        certificates.clone(),
        1.0 / 3.0,
    );
    storage.entered.acquire().await.unwrap().forget();
    storage.other_completed.acquire().await.unwrap().forget();
    let independently_renewed =
        tokio::time::timeout(Duration::from_secs(1), healthy_renewed.acquire())
            .await
            .is_ok();
    eprintln!(
        "gate={gate} healthy_marker_completed=true healthy_renewed_while_slow_marker_pending={independently_renewed} preflight_loads={}",
        certificates.loads.load(Ordering::SeqCst)
    );
    storage.release.add_permits(100);
    tokio::time::timeout(Duration::from_secs(1), async {
        while seen.load(Ordering::SeqCst) != 3 {
            all_renewed.acquire().await.unwrap().forget();
        }
    })
    .await
    .unwrap();
    eprintln!(
        "after_release both_domains_renewed=true preflight_loads={}",
        certificates.loads.load(Ordering::SeqCst)
    );
    cache.stop_and_wait().await;
    task.await.unwrap();
    independently_renewed
}

#[tokio::test(start_paused = true)]
async fn unrelated_marker_read_should_not_block_healthy_due_domain() {
    assert!(
        exercise(true).await,
        "healthy renewal is globally blocked before the per-domain preflight budget"
    );
}

#[tokio::test(start_paused = true)]
async fn healthy_markers_allow_both_due_domains_to_renew() {
    assert!(exercise(false).await);
}

#[tokio::test(start_paused = true)]
async fn coalesced_scans_and_renewal_reads_are_bounded_deduplicated_and_dropped_on_stop() {
    for count in [1, 100] {
        let cache = CertCache::new(Default::default());
        for index in 0..count {
            cache
                .add(due_certificate(&format!("site-{index}.example")))
                .await;
        }
        let storage = Arc::new(MarkerStorage::new("*".into(), 0));
        let certificates = Arc::new(EmptyCertStore::default());
        let callbacks = Arc::new(AtomicUsize::new(0));
        let maintenance = start_maintenance_with_policy(
            cache.clone(),
            MaintenanceConfig {
                renew_check_interval: Duration::from_secs(60),
                ocsp_check_interval: Duration::from_secs(10),
                ocsp: OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                },
                storage: storage.clone(),
            },
            Arc::new({
                let callbacks = callbacks.clone();
                move |_, _| {
                    let callbacks = callbacks.clone();
                    Box::pin(async move {
                        callbacks.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                }
            }),
            certificates.clone(),
            1.0 / 3.0,
        );
        // One eight-read global scan plus four bounded per-job reads. For a
        // single domain, the own check and one global read stay deduplicated.
        let expected = count.min(8) + count.min(4);
        tokio::time::timeout(
            Duration::from_secs(120),
            storage.entered.acquire_many(expected as u32),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        tokio::time::advance(Duration::from_secs(600)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(storage.reads.load(Ordering::SeqCst), expected);
        assert_eq!(storage.active.load(Ordering::SeqCst), expected);
        assert_eq!(storage.peak.load(Ordering::SeqCst), expected);
        assert_eq!(certificates.loads.load(Ordering::SeqCst), 0);
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        cache.stop_and_wait().await;
        maintenance.await.unwrap();
        assert_eq!(storage.active.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(600)).await;
        assert_eq!(storage.reads.load(Ordering::SeqCst), expected);
    }
}
