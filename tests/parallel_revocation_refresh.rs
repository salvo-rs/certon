use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::{CertManager, Certificate, FileStorage, Result, Storage};
use tokio::sync::Semaphore;

struct ActiveRead(Arc<AtomicUsize>);
impl Drop for ActiveRead {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct GatedStorage {
    files: FileStorage,
    active: Arc<AtomicUsize>,
    peak: AtomicUsize,
    reads: AtomicUsize,
    block_all: AtomicBool,
    slow_key: Mutex<Option<String>>,
    failures: Mutex<HashMap<String, String>>,
    release: Semaphore,
}
#[async_trait::async_trait]
impl Storage for GatedStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.files.store(key, value).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let _active = ActiveRead(self.active.clone());
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.reads.fetch_add(1, Ordering::SeqCst);
            let blocked = self.block_all.load(Ordering::SeqCst)
                || self.slow_key.lock().unwrap().as_deref() == Some(key);
            if blocked {
                self.release.acquire().await.unwrap().forget();
            }
            if let Some(message) = self.failures.lock().unwrap().get(key) {
                return Err(certon::Error::Other(message.clone()));
            }
            return self.files.load(key).await;
        }
        self.files.load(key).await
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
    async fn stat(&self, key: &str) -> Result<certon::storage::KeyInfo> {
        self.files.stat(key).await
    }
    async fn lock(&self, name: &str) -> Result<()> {
        self.files.lock(name).await
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        self.files.unlock(name).await
    }
}

async fn fixture(count: usize) -> (tempfile::TempDir, Arc<GatedStorage>, Arc<CertManager>) {
    certon::install_default_crypto_provider();
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(GatedStorage {
        files: FileStorage::new(directory.path()),
        active: Arc::new(AtomicUsize::new(0)),
        peak: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        block_all: AtomicBool::new(false),
        slow_key: Mutex::new(None),
        failures: Mutex::new(HashMap::new()),
        release: Semaphore::new(0),
    });
    let manager = Arc::new(CertManager::builder().storage(storage.clone()).build());
    for i in 0..count {
        let name = format!("site-{i}.example.com");
        let generated = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
        let mut cert = Certificate::from_pem(
            generated.cert.pem().as_bytes(),
            generated.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        cert.managed = true;
        cert.names = vec![name];
        manager.cache.add(cert).await;
    }
    (directory, storage, manager)
}

fn marker_key(cert: &Certificate) -> String {
    format!(
        "revocations/{}.json",
        certon::certificates::hash_certificate_chain(&cert.cert_chain[..1])
    )
}

async fn until<F, Fut>(mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition().await {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("gated revocation refresh did not reach the expected state");
}

#[tokio::test]
async fn refresh_overlaps_slow_reads_without_exceeding_eight_in_flight() {
    let (_directory, storage, manager) = fixture(25).await;
    storage.block_all.store(true, Ordering::SeqCst);
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.refresh_revocations().await }
    });
    until(|| async { storage.active.load(Ordering::SeqCst) == 8 }).await;
    assert_eq!(storage.peak.load(Ordering::SeqCst), 8);
    assert_eq!(storage.reads.load(Ordering::SeqCst), 8);
    assert!(!task.is_finished());
    storage.release.add_permits(25);
    assert_eq!(task.await.unwrap().unwrap(), 0);
    assert_eq!(storage.reads.load(Ordering::SeqCst), 25);
    assert_eq!(storage.peak.load(Ordering::SeqCst), 8);
    assert_eq!(storage.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fast_revoked_leaves_are_quarantined_before_a_slow_earlier_error_finishes() {
    let (_directory, storage, manager) = fixture(12).await;
    let mut snapshot = manager.cache.get_managed_certificates().await;
    // This fixture inserts into the managed sampling pool in numeric order;
    // the public owned snapshot itself has arbitrary HashMap order.
    snapshot.sort_by_key(|cert| {
        cert.names[0]
            .strip_prefix("site-")
            .unwrap()
            .split('.')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap()
    });
    let first = marker_key(&snapshot[0]);
    *storage.slow_key.lock().unwrap() = Some(first.clone());
    storage
        .failures
        .lock()
        .unwrap()
        .insert(first, "first snapshot marker failed".into());
    storage.failures.lock().unwrap().insert(
        marker_key(&snapshot[1]),
        "later snapshot marker failed".into(),
    );
    for cert in &snapshot[2..] {
        storage
            .store(&marker_key(cert), br#"{"version":1,"confirmed":true}"#)
            .await
            .unwrap();
    }
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.refresh_revocations().await }
    });
    until(|| async {
        manager
            .cache
            .get_by_hash(&snapshot[11].hash)
            .await
            .is_none()
    })
    .await;
    assert!(
        !task.is_finished(),
        "refresh returned before the slow read completed"
    );
    assert_eq!(storage.active.load(Ordering::SeqCst), 1);
    storage.release.add_permits(1);
    let error = task.await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("first snapshot marker failed"),
        "{error}"
    );
    assert_eq!(storage.reads.load(Ordering::SeqCst), 12);
    assert_eq!(manager.cache.get_all().await.len(), 2);
}

#[tokio::test]
async fn cancelling_refresh_drops_every_in_flight_read() {
    let (_directory, storage, manager) = fixture(25).await;
    storage.block_all.store(true, Ordering::SeqCst);
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.refresh_revocations().await }
    });
    until(|| async { storage.active.load(Ordering::SeqCst) == 8 }).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(storage.active.load(Ordering::SeqCst), 0);
    assert_eq!(storage.reads.load(Ordering::SeqCst), 8);
    storage.release.add_permits(25);
    tokio::task::yield_now().await;
    assert_eq!(storage.reads.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn stopping_maintenance_drops_in_flight_marker_reads() {
    let (_directory, storage, manager) = fixture(25).await;
    storage.block_all.store(true, Ordering::SeqCst);
    let maintenance = certon::maintain::start_maintenance(
        manager.cache.clone(),
        certon::maintain::MaintenanceConfig {
            renew_check_interval: Duration::from_millis(1),
            ocsp_check_interval: Duration::from_secs(3600),
            storage: storage.clone(),
            ocsp: certon::OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
        },
        Arc::new(|_| Box::pin(async { panic!("refresh must finish before the renewal scan") })),
    );
    until(|| async { storage.active.load(Ordering::SeqCst) == 8 }).await;
    tokio::time::timeout(Duration::from_secs(5), manager.cache.stop_and_wait())
        .await
        .unwrap();
    maintenance.await.unwrap();
    assert_eq!(storage.active.load(Ordering::SeqCst), 0);
    assert_eq!(storage.reads.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn refresh_handles_empty_short_and_alternate_chain_snapshots() {
    for count in [0, 1, 7] {
        let (_directory, storage, manager) = fixture(count).await;
        assert_eq!(manager.refresh_revocations().await.unwrap(), 0);
        assert_eq!(storage.reads.load(Ordering::SeqCst), count);
        assert_eq!(storage.active.load(Ordering::SeqCst), 0);
    }
    let (_directory, storage, manager) = fixture(1).await;
    let original = manager.cache.get_all().await.pop().unwrap();
    let mut alternate = original.clone();
    alternate.cert_chain.push(original.cert_chain[0].clone());
    alternate.hash = certon::certificates::hash_certificate_chain(&alternate.cert_chain);
    manager.cache.add(alternate.clone()).await;
    alternate.cert_chain.push(original.cert_chain[0].clone());
    alternate.hash = certon::certificates::hash_certificate_chain(&alternate.cert_chain);
    alternate.managed = false;
    manager.cache.add(alternate).await;
    assert_eq!(manager.cache.get_all().await.len(), 3);
    storage
        .store(&marker_key(&original), br#"{"version":1,"confirmed":true}"#)
        .await
        .unwrap();
    assert_eq!(manager.refresh_revocations().await.unwrap(), 1);
    assert_eq!(storage.reads.load(Ordering::SeqCst), 1);
    assert!(manager.cache.get_all().await.is_empty());
    assert_eq!(manager.refresh_revocations().await.unwrap(), 0);
    assert_eq!(storage.reads.load(Ordering::SeqCst), 1);
}
