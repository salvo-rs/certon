use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use certon::maintain::{MaintenanceConfig, ReasonedRenewFn, start_maintenance_with_policy};
use certon::{
    CertCache, CertStore, Certificate, CertificateResource, KeyInfo, OcspConfig, Result, Storage,
};
use tokio::sync::Semaphore;

#[derive(Debug, Default)]
struct EmptyStorage;

#[async_trait]
impl Storage for EmptyStorage {
    async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        Err(certon::error::StorageError::NotFound(key.to_owned()).into())
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

#[derive(Debug)]
struct GatedStore {
    loads: AtomicUsize,
    load_drops: Arc<AtomicUsize>,
    entered: Semaphore,
    release: Semaphore,
}

impl Default for GatedStore {
    fn default() -> Self {
        Self {
            loads: AtomicUsize::new(0),
            load_drops: Arc::new(AtomicUsize::new(0)),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

struct LoadDrop(Arc<AtomicUsize>);
impl Drop for LoadDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl CertStore for GatedStore {
    async fn load(&self, _: &str, _: &str) -> Result<Option<CertificateResource>> {
        if self.loads.fetch_add(1, Ordering::SeqCst) == 0 {
            let _drop = LoadDrop(self.load_drops.clone());
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
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

async fn fixture() -> (
    Arc<CertCache>,
    Arc<GatedStore>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let cache = CertCache::new(Default::default());
    for name in ["a.example", "b.example"] {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.not_before = (std::time::SystemTime::now() - Duration::from_secs(60 * 86400)).into();
        params.not_after = (std::time::SystemTime::now() + Duration::from_secs(12 * 3600)).into();
        let key = rcgen::KeyPair::generate().unwrap();
        let signed = params.self_signed(&key).unwrap();
        let mut cert =
            Certificate::from_pem(signed.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        cert.managed = true;
        cert.names = vec![name.to_owned()];
        cert.issuer_key = "probe-ca".into();
        cache.add(cert).await;
    }
    let store = Arc::new(GatedStore::default());
    let renewals = Arc::new(AtomicUsize::new(0));
    let domains_seen = Arc::new(AtomicUsize::new(0));
    let counter = renewals.clone();
    let seen = domains_seen.clone();
    let renew: Arc<ReasonedRenewFn> = Arc::new(move |domain, _| {
        let counter = counter.clone();
        let seen = seen.clone();
        Box::pin(async move {
            seen.fetch_or(if domain == "a.example" { 1 } else { 2 }, Ordering::SeqCst);
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    });
    let task = start_maintenance_with_policy(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(1),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: Arc::new(EmptyStorage),
        },
        renew,
        store.clone(),
        1.0 / 3.0,
    );
    (cache, store, renewals, domains_seen, task)
}

#[tokio::test]
async fn one_gated_preflight_does_not_block_the_other_due_domain() {
    let (cache, store, renewals, domains_seen, task) = fixture().await;
    store.entered.acquire().await.unwrap().forget();
    tokio::time::timeout(Duration::from_secs(2), async {
        while renewals.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the other due domain was blocked behind a gated preflight");
    assert_eq!(
        store.load_drops.load(Ordering::SeqCst),
        0,
        "the first preflight must remain gated"
    );
    assert!(store.loads.load(Ordering::SeqCst) >= 2);
    eprintln!("gated_preflight: other_domain_reached_callback=true first_load_still_gated=true");
    store.release.add_permits(1);
    for _ in 0..1000 {
        if domains_seen.load(Ordering::SeqCst) == 3 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(domains_seen.load(Ordering::SeqCst), 3);
    eprintln!(
        "released_preflight: both_domains_reached_callback=true callback_count={}",
        renewals.load(Ordering::SeqCst)
    );
    cache.stop_and_wait().await;
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stop_drops_gated_preflight_without_waiting_for_the_backend() {
    let (cache, store, renewals, _, task) = fixture().await;
    store.entered.acquire().await.unwrap().forget();
    cache.stop_and_wait().await;
    task.await.unwrap();
    assert_eq!(store.load_drops.load(Ordering::SeqCst), 1);
    let completed = renewals.load(Ordering::SeqCst);
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(renewals.load(Ordering::SeqCst), completed);
    eprintln!("stop_during_preflight: load_future_dropped=1 no_callbacks_after_stop=true");
}
