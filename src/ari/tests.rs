use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use tokio::sync::{Notify, Semaphore};
use x509_parser::prelude::FromDer;

use super::*;
use crate::{CertIssuer, CertificateResource, IssuedCertificate, OcspConfig};

#[derive(Default)]
struct Memory {
    data: Mutex<HashMap<String, Vec<u8>>>,
    locks: Mutex<HashSet<String>>,
    changed: Notify,
    fail_ari: AtomicBool,
    fail_ari_store: AtomicBool,
    hang_ari: AtomicBool,
    fail_cert: AtomicBool,
    fail_marker: AtomicBool,
    ari_reads: AtomicUsize,
    load_gate: Mutex<Option<Arc<LoadGate>>>,
}

struct LoadGate {
    entered: Notify,
    release: Semaphore,
}

#[async_trait::async_trait]
impl Storage for Memory {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        if key.starts_with("ari/")
            && (self.fail_ari.load(Ordering::SeqCst) || self.fail_ari_store.load(Ordering::SeqCst))
        {
            return Err(Error::Other("ARI store failed".into()));
        }
        if key.starts_with("certificates/") && self.fail_cert.load(Ordering::SeqCst) {
            return Err(StorageError::Serialize("certificate store failed".into()).into());
        }
        self.data.lock().unwrap().insert(key.into(), data.to_vec());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("ari/") {
            self.ari_reads.fetch_add(1, Ordering::SeqCst);
            let gate = self.load_gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.acquire().await.unwrap().forget();
            }
            if self.hang_ari.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.fail_ari.load(Ordering::SeqCst) {
                return Err(Error::Other("ARI load failed".into()));
            }
        }
        if key.starts_with("revocations/") && self.fail_marker.load(Ordering::SeqCst) {
            return Err(StorageError::Deserialize("marker read failed".into()).into());
        }
        self.data
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.into()).into())
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.data.lock().unwrap().contains_key(key))
    }
    async fn list(&self, prefix: &str, _: bool) -> Result<Vec<String>> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }
    async fn stat(&self, _: &str) -> Result<crate::KeyInfo> {
        unreachable!()
    }
    async fn lock(&self, name: &str) -> Result<()> {
        loop {
            let notified = self.changed.notified();
            if self.locks.lock().unwrap().insert(name.into()) {
                return Ok(());
            }
            notified.await;
        }
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        self.locks.lock().unwrap().remove(name);
        self.changed.notify_waiters();
        Ok(())
    }
}

struct Public(Vec<u8>);
impl PublicKeyData for Public {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct Issuer {
    info: Mutex<Option<RenewalInfo>>,
    calls: AtomicUsize,
    issues: AtomicUsize,
    issued: Notify,
    active: AtomicUsize,
    peak: AtomicUsize,
    gate: Semaphore,
    gated: AtomicBool,
    entered: Notify,
    upstream: Mutex<Option<Arc<crate::AcmeIssuer>>>,
    dynamic: AtomicBool,
    short_window: AtomicBool,
}

impl Issuer {
    fn new(info: Option<RenewalInfo>) -> Self {
        Self {
            info: Mutex::new(info),
            calls: AtomicUsize::new(0),
            issues: AtomicUsize::new(0),
            issued: Notify::new(),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            gate: Semaphore::new(0),
            gated: AtomicBool::new(false),
            entered: Notify::new(),
            upstream: Mutex::new(None),
            dynamic: AtomicBool::new(false),
            short_window: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl CertIssuer for Issuer {
    fn issuer_key(&self) -> String {
        "ari-test-issuer".into()
    }
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.issues.fetch_add(1, Ordering::SeqCst);
        self.issued.notify_one();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = Public(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let mut params = CertificateParams::new(domains.to_vec()).unwrap();
        dates(&mut params, 1, 90);
        params.use_authority_key_identifier_extension = true;
        let mut root_params = CertificateParams::new(vec!["root".into()]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = rcgen::Issuer::new(root_params, KeyPair::generate().unwrap());
        Ok(IssuedCertificate {
            certificate_pem: params.signed_by(&public, &root).unwrap().pem().into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    async fn renewal_info(&self, leaf: &[u8]) -> Result<Option<RenewalInfo>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _active = Active(&self.active);
        self.entered.notify_one();
        if self.gated.load(Ordering::SeqCst) {
            self.gate.acquire().await.unwrap().forget();
        }
        let upstream = self.upstream.lock().unwrap().clone();
        if let Some(upstream) = upstream {
            return upstream.renewal_info(leaf).await;
        }
        let mut info = if self.short_window.load(Ordering::SeqCst) {
            Some(info(2, 3))
        } else {
            self.info.lock().unwrap().clone()
        };
        if self.dynamic.load(Ordering::SeqCst)
            && let Some(window) = info
                .as_mut()
                .and_then(|info| info.suggested_window.as_mut())
        {
            let shift = chrono::Duration::seconds(self.calls.load(Ordering::SeqCst) as i64);
            window.start =
                (DateTime::parse_from_rfc3339(&window.start).unwrap() + shift).to_rfc3339();
            window.end = (DateTime::parse_from_rfc3339(&window.end).unwrap() + shift).to_rfc3339();
        }
        Ok(info)
    }
}

fn dates(params: &mut CertificateParams, ago: i64, remain: i64) {
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    params.not_before = epoch + Duration::from_secs((Utc::now().timestamp() - ago * 86400) as u64);
    params.not_after =
        epoch + Duration::from_secs((Utc::now().timestamp() + remain * 86400) as u64);
}

fn resource(name: &str, ago: i64, remain: i64) -> CertificateResource {
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    dates(&mut params, ago, remain);
    let key = KeyPair::generate().unwrap();
    CertificateResource {
        sans: vec![name.into()],
        certificate_pem: params.self_signed(&key).unwrap().pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_key: "ari-test-issuer".into(),
        issuer_data: None,
    }
}

fn info(start: i64, end: i64) -> RenewalInfo {
    RenewalInfo {
        suggested_window: Some(crate::RenewalWindow {
            start: after(start).to_rfc3339(),
            end: after(end).to_rfc3339(),
        }),
        retry_after: Some(60),
        ..Default::default()
    }
}

fn manager(
    storage: Arc<dyn Storage>,
    issuer: Arc<Issuer>,
    disabled: bool,
    cache: Option<Arc<crate::CertCache>>,
) -> CertManager {
    let mut builder = CertManager::builder()
        .storage(storage)
        .issuers(vec![issuer])
        .disable_ari(disabled)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        });
    if let Some(cache) = cache {
        builder = builder.cache(cache);
    }
    builder.build()
}

async fn cached(manager: &CertManager, resource: &CertificateResource) -> Certificate {
    manager
        .certificates
        .save(&resource.issuer_key, resource)
        .await
        .unwrap();
    manager.cache_certificate(&resource.sans[0]).await.unwrap()
}

async fn expire_record(storage: &dyn Storage, cert: &Certificate) {
    let leaf = certificate_leaf_hash(cert).unwrap();
    let mut record = load(storage, &cert.issuer_key, &leaf)
        .await
        .unwrap()
        .unwrap();
    record.next_check = after(-1);
    storage
        .store(
            &key(&cert.issuer_key, &leaf),
            &serde_json::to_vec(&record).unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn automatic_issue_persists_stable_point_across_restarts_and_refetches() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(crate::FileStorage::new(directory.path()));
    let issuer = Arc::new(Issuer::new(Some(info(86400 * 2, 86400 * 3))));
    let first = manager(storage.clone(), issuer.clone(), false, None);
    first.obtain("stable.example").await.unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    let cert = first.cache.get_by_name("stable.example").await.unwrap();
    let selected = cert.ari.as_ref().unwrap().selected_time.unwrap();
    let second = manager(storage.clone(), issuer.clone(), false, None);
    let reloaded = second.cache_certificate("stable.example").await.unwrap();
    assert_eq!(reloaded.ari.as_ref().unwrap().selected_time, Some(selected));
    expire_record(storage.as_ref(), &cert).await;
    refresh(&second, &reloaded).await;
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        second
            .cache
            .get_by_name("stable.example")
            .await
            .unwrap()
            .ari
            .unwrap()
            .selected_time,
        Some(selected)
    );
    *issuer.info.lock().unwrap() = Some(info(86400 * 4, 86400 * 5));
    expire_record(storage.as_ref(), &cert).await;
    refresh(&second, &reloaded).await;
    let later = second
        .cache
        .get_by_name("stable.example")
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time
        .unwrap();
    assert!(later > selected);
}

#[tokio::test]
async fn ari_defers_ratio_renewal_and_disabled_manager_does_not_erase_shared_choice() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(86400 * 2, 86400 * 3))));
    let enabled = manager(storage.clone(), issuer.clone(), false, None);
    let cert = cached(&enabled, &resource("defer.example", 80, 10)).await;
    assert!(cert.needs_renewal(1.0 / 3.0));
    refresh(&enabled, &cert).await;
    let selected = enabled
        .cache
        .get_by_name("defer.example")
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time;
    enabled.renew("defer.example", false).await.unwrap();
    assert_eq!(
        issuer.issues.load(Ordering::SeqCst),
        0,
        "lock-after-load planning must retain ARI"
    );
    let disabled = manager(
        storage.clone(),
        issuer.clone(),
        true,
        Some(enabled.cache.clone()),
    );
    disabled.cache_certificate("defer.example").await.unwrap();
    let reads = storage.ari_reads.load(Ordering::SeqCst);
    disabled.renew("defer.example", false).await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
    assert_eq!(storage.ari_reads.load(Ordering::SeqCst), reads);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    assert!(selected.is_some());
}

#[tokio::test]
async fn due_ari_reaches_actual_manager_renewal_even_when_ratio_is_fresh() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(-120, -60))));
    let manager = manager(storage, issuer.clone(), false, None);
    let cert = cached(&manager, &resource("early.example", 1, 90)).await;
    assert!(!cert.needs_renewal(1.0 / 3.0));
    refresh(&manager, &cert).await;
    manager.renew("early.example", false).await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sidecar_failure_does_not_repeat_successful_issuance_or_hide_primary_failures() {
    let storage = Arc::new(Memory::default());
    storage.fail_ari.store(true, Ordering::SeqCst);
    let issuer = Arc::new(Issuer::new(Some(info(60, 120))));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    manager.obtain("advisory.example").await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
    assert!(
        manager
            .cache
            .get_by_name("advisory.example")
            .await
            .is_some()
    );
    storage.fail_cert.store(true, Ordering::SeqCst);
    assert!(matches!(
        manager.obtain("store-fault.example").await,
        Err(Error::Storage(StorageError::Serialize(_)))
    ));
    storage.fail_cert.store(false, Ordering::SeqCst);
    storage.fail_marker.store(true, Ordering::SeqCst);
    assert!(matches!(
        manager.obtain("marker-fault.example").await,
        Err(Error::Storage(StorageError::Deserialize(_)))
    ));
}

#[tokio::test]
async fn late_response_never_changes_replacement_leaf_or_restarts_expired_removed_work() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(-120, -60))));
    issuer.gated.store(true, Ordering::SeqCst);
    let manager = Arc::new(manager(storage.clone(), issuer.clone(), false, None));
    let old = cached(&manager, &resource("late.example", 1, 90)).await;
    let task = {
        let manager = manager.clone();
        let old = old.clone();
        tokio::spawn(async move { refresh(&manager, &old).await })
    };
    issuer.entered.notified().await;
    let replacement = cached(&manager, &resource("late.example", 1, 91)).await;
    manager.cache.remove(&old.hash).await;
    issuer.gate.add_permits(1);
    task.await.unwrap();
    assert!(
        manager
            .cache
            .get_by_hash(&replacement.hash)
            .await
            .unwrap()
            .ari
            .is_none()
    );
    refresh(&manager, &old).await;
    let mut expired = replacement.clone();
    expired.not_after = after(-1);
    refresh(&manager, &expired).await;
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn hanging_network_uses_persisted_backoff_without_discarding_selected_point() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(86400 * 2, 86400 * 3))));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    let cert = cached(&manager, &resource("backoff.example", 80, 10)).await;
    refresh(&manager, &cert).await;
    let leaf = certificate_leaf_hash(&cert).unwrap();
    let first = load(storage.as_ref(), &cert.issuer_key, &leaf)
        .await
        .unwrap()
        .unwrap();
    issuer.gated.store(true, Ordering::SeqCst);
    for attempt in 1..=8 {
        expire_record(storage.as_ref(), &cert).await;
        let began = tokio::time::Instant::now();
        refresh(&manager, &cert).await;
        assert!(
            began.elapsed() >= Duration::from_secs(20),
            "must exercise an actually pending request"
        );
        let record = load(storage.as_ref(), &cert.issuer_key, &leaf)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.failures, attempt);
        assert_eq!(record.selected_time, first.selected_time);
        let expected = if attempt >= 8 {
            FALLBACK
        } else {
            60 * (1 << attempt)
        };
        assert!((record.next_check - Utc::now()).num_seconds() >= expected - 1);
        assert_eq!(issuer.active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn ari_only_storage_hang_is_bounded_and_force_renew_bypasses_advisory_load() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    cached(&manager, &resource("hang.example", 1, 90)).await;
    storage.hang_ari.store(true, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    manager.cache_certificate("hang.example").await.unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(5));
    // Only the post-publication best-effort refresh may wait for advisory I/O.
    manager.renew("hang.example", true).await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn maintenance_pool_is_bounded_and_stop_drops_all_pending_requests() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    issuer.gated.store(true, Ordering::SeqCst);
    let manager = manager(storage, issuer.clone(), false, None);
    for index in 0..7 {
        cached(&manager, &resource(&format!("pool{index}.example"), 1, 90)).await;
    }
    let task = crate::start_maintenance(&manager);
    tokio::time::timeout(Duration::from_secs(3), async {
        while issuer.active.load(Ordering::SeqCst) < 4 {
            issuer.entered.notified().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 4);
    manager.cache.stop();
    task.await.unwrap();
    assert_eq!(issuer.active.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.peak.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn selected_deadline_wakes_normal_maintenance_before_its_ten_minute_tick() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    issuer.short_window.store(true, Ordering::SeqCst);
    let mut manager = manager(storage.clone(), issuer.clone(), false, None);
    manager.policy.reuse_private_keys = true;
    let cert = cached(&manager, &resource("timer.example", 1, 90)).await;
    refresh(&manager, &cert).await;
    let selected = manager
        .cache
        .get_by_hash(&cert.hash)
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time
        .unwrap();
    let attempts = observe_timer_renewal(&mut manager, &issuer, "timer.example");
    assert!(selected > Utc::now());
    assert!(attempts.lock().unwrap().is_empty());
    let task = crate::start_maintenance(&manager);
    wait_for_issues(&issuer, 1).await;
    manager.cache.stop();
    task.await.unwrap();
    let attempts = attempts.lock().unwrap();
    assert_eq!(attempts.len(), 1);
    assert!(
        attempts[0] >= selected,
        "renewal must not start before the selected point"
    );
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
}

// Record the actual manager entry and give its replacement a later window.
// Otherwise reusing the same short mock window for every newly issued leaf can
// cause repeated legitimate renewals before the test gets to stop maintenance.
fn observe_timer_renewal(
    manager: &mut CertManager,
    issuer: &Arc<Issuer>,
    name: &'static str,
) -> Arc<Mutex<Vec<DateTime<Utc>>>> {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let observed = attempts.clone();
    let issuer = issuer.clone();
    manager.on_event = Some(Arc::new(move |event, data| {
        if event == crate::manager::EVENT_CERT_OBTAINING
            && data["identifier"] == name
            && data["renewal"] == true
        {
            observed.lock().unwrap().push(Utc::now());
            issuer.short_window.store(false, Ordering::SeqCst);
            *issuer.info.lock().unwrap() = Some(info(86400, 86400 * 2));
        }
        Ok(())
    }));
    attempts
}

async fn wait_for_issues(issuer: &Issuer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while issuer.issues.load(Ordering::SeqCst) < expected {
            issuer.issued.notified().await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn pure_ari_decision_preserves_emergency_and_invalid_window_fallbacks() {
    let resource = resource("pure.example", 80, 10);
    let mut cert =
        Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem).unwrap();
    cert.ari = Some(info(86400, 86400 * 2));
    for _ in 0..20 {
        assert!(!cert.needs_renewal(1.0 / 3.0));
    }
    assert!(needs_renewal(&cert, 1.0 / 3.0, true));
    cert.ari = Some(info(120, 60));
    assert!(cert.needs_renewal(1.0 / 3.0));
    cert.ari = Some(info(86400, 86400 * 2));
    cert.not_after = after(300);
    assert!(cert.needs_renewal(1.0 / 3.0));
    assert_eq!(retry_seconds(Some(u64::MAX)), 86400);
    assert_eq!(retry_seconds(Some(0)), 60);
}

#[tokio::test]
async fn two_managers_share_one_fetch_and_stable_window_choice() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(86400, 86400 * 2))));
    let first = manager(storage.clone(), issuer.clone(), false, None);
    let second = manager(storage, issuer.clone(), false, None);
    let cert = cached(&first, &resource("concurrent.example", 80, 10)).await;
    let other = second
        .cache_certificate("concurrent.example")
        .await
        .unwrap();
    tokio::join!(refresh(&first, &cert), refresh(&second, &other));
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    let a = first
        .cache
        .get_by_hash(&cert.hash)
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time;
    let b = second
        .cache
        .get_by_hash(&cert.hash)
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time;
    assert!(a.is_some());
    assert_eq!(a, b);
    refresh(&second, &other).await;
    assert_eq!(
        issuer.calls.load(Ordering::SeqCst),
        1,
        "Retry-After must suppress eager callers too"
    );
}

#[tokio::test]
async fn failing_sidecar_write_keeps_new_certificate_and_live_ari() {
    let storage = Arc::new(Memory::default());
    storage.fail_ari_store.store(true, Ordering::SeqCst);
    let issuer = Arc::new(Issuer::new(Some(info(86400, 86400 * 2))));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    manager.obtain("write-fault.example").await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    let live = manager
        .cache
        .get_by_name("write-fault.example")
        .await
        .unwrap();
    assert!(live.ari.is_some());
    assert!(
        manager
            .certificates
            .load(&live.issuer_key, "write-fault.example")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn disabled_reload_preserves_enabled_choice_without_reading_the_sidecar() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(-120, -60))));
    let enabled = manager(storage.clone(), issuer.clone(), false, None);
    let cert = cached(&enabled, &resource("shared.example", 1, 90)).await;
    refresh(&enabled, &cert).await;
    let selected = enabled
        .cache
        .get_by_hash(&cert.hash)
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time;
    let disabled = manager(
        storage.clone(),
        issuer.clone(),
        true,
        Some(enabled.cache.clone()),
    );
    let reads = storage.ari_reads.load(Ordering::SeqCst);
    disabled.renew("shared.example", false).await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 0);
    assert_eq!(storage.ari_reads.load(Ordering::SeqCst), reads);
    assert_eq!(
        disabled
            .cache
            .get_by_hash(&cert.hash)
            .await
            .unwrap()
            .ari
            .unwrap()
            .selected_time,
        selected
    );
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unsupported_and_invalid_windows_have_negative_cache_without_busy_refetch() {
    for suggestion in [None, Some(info(120, 60))] {
        let storage = Arc::new(Memory::default());
        let issuer = Arc::new(Issuer::new(suggestion));
        let manager = manager(storage.clone(), issuer.clone(), false, None);
        let cert = cached(&manager, &resource("unsupported.example", 80, 10)).await;
        refresh(&manager, &cert).await;
        refresh(&manager, &cert).await;
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
        let record = load(
            storage.as_ref(),
            &cert.issuer_key,
            &certificate_leaf_hash(&cert).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(record.info.is_none());
        assert!((record.next_check - Utc::now()).num_seconds() >= FALLBACK - 1);
        assert!(
            manager
                .cache
                .get_by_hash(&cert.hash)
                .await
                .unwrap()
                .needs_renewal(1.0 / 3.0)
        );
    }
}

type HttpReply = (u16, Option<String>, String);

struct HttpServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    responses: Arc<Mutex<VecDeque<HttpReply>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl HttpServer {
    async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::<(u16, Option<String>, String)>::new()));
        let seen = requests.clone();
        let replies = responses.clone();
        let base = url.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if bytes.windows(4).any(|slice| slice == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                let line = request.lines().next().unwrap_or_default().to_owned();
                seen.lock().unwrap().push(line.clone());
                let (status, retry, body) = if line.starts_with("GET /directory ") {
                    (200, None, serde_json::json!({"newNonce":format!("{base}/nonce"),"newAccount":format!("{base}/account"),"newOrder":format!("{base}/order"),"revokeCert":format!("{base}/revoke"),"keyChange":format!("{base}/key-change"),"renewalInfo":format!("{base}/ari")}).to_string())
                } else if line.starts_with("HEAD /nonce ") {
                    (200, None, String::new())
                } else {
                    assert!(
                        line.starts_with("GET /ari/"),
                        "ARI must not create accounts: {line}"
                    );
                    replies
                        .lock()
                        .unwrap()
                        .pop_front()
                        .expect("unexpected ARI request")
                };
                let retry = retry
                    .map(|value| format!("Retry-After: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nReplay-Nonce: dGVzdC1ub25jZQ\r\nContent-Length: {}\r\nConnection: close\r\n{retry}\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            responses,
            task,
        }
    }
}

#[tokio::test]
async fn real_acme_ari_get_runs_after_issue_without_account_or_tos_and_parses_retry_after() {
    let server = HttpServer::start().await;
    let storage = Arc::new(Memory::default());
    let upstream = Arc::new(
        crate::AcmeIssuer::builder()
            .storage(storage.clone())
            .ca(format!("{}/directory", server.url))
            .build(),
    );
    let issuer = Arc::new(Issuer::new(None));
    *issuer.upstream.lock().unwrap() = Some(upstream);
    server.responses.lock().unwrap().push_back((
        200,
        Some("120".into()),
        serde_json::to_string(&info(86400, 86400 * 2)).unwrap(),
    ));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    manager.obtain("http.example").await.unwrap();
    let cert = manager.cache.get_by_name("http.example").await.unwrap();
    assert!(
        cert.ari.is_some(),
        "requests={:?}, certID={:?}",
        server.requests.lock().unwrap(),
        crate::ari_cert_id(&cert.cert_chain[0])
    );
    assert_eq!(cert.ari.as_ref().unwrap().retry_after, Some(120));
    let id = crate::ari_cert_id(&cert.cert_chain[0]).unwrap();
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        [
            "GET /directory HTTP/1.1",
            "HEAD /nonce HTTP/1.1",
            &format!("GET /ari/{id} HTTP/1.1")
        ]
    );
    assert!(
        !storage
            .data
            .lock()
            .unwrap()
            .keys()
            .any(|key| key.starts_with("acme/"))
    );
    expire_record(storage.as_ref(), &cert).await;
    let date = (Utc::now() + chrono::Duration::seconds(240))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    server.responses.lock().unwrap().push_back((
        200,
        Some(date),
        serde_json::to_string(&info(86400, 86400 * 2)).unwrap(),
    ));
    refresh(&manager, &cert).await;
    let retry = manager
        .cache
        .get_by_hash(&cert.hash)
        .await
        .unwrap()
        .ari
        .unwrap()
        .retry_after
        .unwrap();
    assert!((238..=240).contains(&retry));
    expire_record(storage.as_ref(), &cert).await;
    server
        .responses
        .lock()
        .unwrap()
        .push_back((503, None, "temporary".into()));
    refresh(&manager, &cert).await;
    let record = load(
        storage.as_ref(),
        &cert.issuer_key,
        &certificate_leaf_hash(&cert).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(record.failures, 1);
    assert!(record.info.is_some());
}

#[tokio::test]
async fn volatile_choice_survives_old_sidecar_but_new_persisted_window_wins() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(86400, 86400 * 2))));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    let cert = cached(&manager, &resource("volatile.example", 1, 90)).await;
    refresh(&manager, &cert).await;
    expire_record(storage.as_ref(), &cert).await;
    storage.fail_ari_store.store(true, Ordering::SeqCst);
    *issuer.info.lock().unwrap() = Some(info(-120, -60));
    refresh(&manager, &cert).await;
    assert!(
        manager
            .cache
            .get_by_hash(&cert.hash)
            .await
            .unwrap()
            .needs_renewal(1.0 / 3.0)
    );
    // This read succeeds but returns the old future window, not NotFound.
    let loaded = manager.cache_certificate("volatile.example").await.unwrap();
    assert!(loaded.needs_renewal(1.0 / 3.0));
    // Simulate another instance successfully postponing this leaf afterwards.
    storage.fail_ari_store.store(false, Ordering::SeqCst);
    let leaf = certificate_leaf_hash(&cert).unwrap();
    let mut record = load(storage.as_ref(), &cert.issuer_key, &leaf)
        .await
        .unwrap()
        .unwrap();
    let next = info(86400 * 3, 86400 * 4);
    record.selected_time = selected_time(&cert, &next);
    record.info = Some(next);
    record.next_check = after(240);
    storage
        .store(
            &key(&cert.issuer_key, &leaf),
            &serde_json::to_vec(&record).unwrap(),
        )
        .await
        .unwrap();
    let calls = issuer.calls.load(Ordering::SeqCst);
    refresh(&manager, &cert).await;
    assert_eq!(
        issuer.calls.load(Ordering::SeqCst),
        calls,
        "a changed persisted record must win in refresh too"
    );
    manager.renew("volatile.example", false).await.unwrap();
    assert_eq!(
        issuer.issues.load(Ordering::SeqCst),
        0,
        "a newer persisted recommendation must cancel stale queued work"
    );
    assert!(
        !manager
            .cache
            .has_unpersisted_ari(&cert.hash, &cert.issuer_key)
    );
}

#[tokio::test]
async fn volatile_early_point_actually_renews_without_a_sidecar() {
    for old_record_exists in [false, true] {
        let storage = Arc::new(Memory::default());
        let issuer = Arc::new(Issuer::new(Some(info(86400, 86400 * 2))));
        let manager = manager(storage.clone(), issuer.clone(), false, None);
        let cert = cached(&manager, &resource("volatile-early.example", 1, 90)).await;
        if old_record_exists {
            refresh(&manager, &cert).await;
            expire_record(storage.as_ref(), &cert).await;
        }
        storage.fail_ari_store.store(true, Ordering::SeqCst);
        *issuer.info.lock().unwrap() = Some(info(-120, -60));
        refresh(&manager, &cert).await;
        manager
            .renew("volatile-early.example", false)
            .await
            .unwrap();
        assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn removal_during_advisory_load_prevents_starting_an_obsolete_get() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(60, 120))));
    let manager = Arc::new(manager(storage.clone(), issuer.clone(), false, None));
    let cert = cached(&manager, &resource("remove.example", 1, 90)).await;
    let gate = Arc::new(LoadGate {
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    *storage.load_gate.lock().unwrap() = Some(gate.clone());
    let task = {
        let manager = manager.clone();
        let cert = cert.clone();
        tokio::spawn(async move { refresh(&manager, &cert).await })
    };
    gate.entered.notified().await;
    manager.cache.remove(&cert.hash).await;
    gate.release.add_permits(1);
    task.await.unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_new_leaf_published_after_the_initial_scan_gets_its_short_window_timer() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    issuer.gated.store(true, Ordering::SeqCst);
    let mut manager = manager(storage.clone(), issuer.clone(), false, None);
    manager.policy.reuse_private_keys = true;
    cached(&manager, &resource("initial-scan.example", 1, 90)).await;
    let attempts = observe_timer_renewal(&mut manager, &issuer, "new-after-scan.example");
    let task = crate::start_maintenance(&manager);
    issuer.entered.notified().await; // Initial membership scan has completed.
    issuer.gated.store(false, Ordering::SeqCst);
    // Generate the recommendation when its real fetch returns, rather than
    // before initial issuance can wait on the shared key generation budget.
    issuer.short_window.store(true, Ordering::SeqCst);
    manager.obtain("new-after-scan.example").await.unwrap();
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 1);
    let cert = manager
        .cache
        .get_by_name("new-after-scan.example")
        .await
        .unwrap();
    let selected = cert.ari.unwrap().selected_time.unwrap();
    assert!(selected > Utc::now());
    assert!(attempts.lock().unwrap().is_empty());
    wait_for_issues(&issuer, 2).await;
    manager.cache.stop();
    task.await.unwrap();
    let attempts = attempts.lock().unwrap();
    assert_eq!(attempts.len(), 1);
    assert!(
        attempts[0] >= selected,
        "the new leaf's timer must not fire early"
    );
    assert_eq!(issuer.issues.load(Ordering::SeqCst), 2);
    assert_eq!(issuer.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn volatile_ari_never_crosses_issuer_identity_for_the_same_real_chain() {
    let storage = Arc::new(Memory::default());
    storage.fail_ari_store.store(true, Ordering::SeqCst);
    let issuer = Arc::new(Issuer::new(Some(info(-120, -60))));
    let manager = manager(storage.clone(), issuer, false, None);
    let cert = cached(&manager, &resource("issuer-bound.example", 1, 90)).await;
    refresh(&manager, &cert).await;
    let mut another = cert.clone();
    another.issuer_key = "different-issuer".into();
    attach_cached(storage.as_ref(), &manager.cache, &mut another, false).await;
    assert!(another.ari.is_none());
    manager
        .cache
        .replace_managed(&cert.hash, another.clone(), &cert.names[0])
        .await
        .unwrap();
    attach_cached(storage.as_ref(), &manager.cache, &mut another, false).await;
    assert!(another.ari.is_none());
    assert!(
        !manager
            .cache
            .has_unpersisted_ari(&cert.hash, &another.issuer_key)
    );
}

#[tokio::test]
async fn reloading_a_new_persisted_retry_after_replaces_the_old_negative_deadline() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    let manager = manager(storage.clone(), issuer.clone(), false, None);
    let cert = cached(&manager, &resource("new-retry.example", 1, 90)).await;
    let task = crate::start_maintenance(&manager);
    issuer.entered.notified().await;
    let leaf = certificate_leaf_hash(&cert).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while load(storage.as_ref(), &cert.issuer_key, &leaf)
            .await
            .unwrap()
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut record = load(storage.as_ref(), &cert.issuer_key, &leaf)
        .await
        .unwrap()
        .unwrap();
    assert!((record.next_check - Utc::now()).num_seconds() > 3600);
    let suggestion = info(86400, 86400 * 2);
    record.selected_time = selected_time(&cert, &suggestion);
    record.info = Some(suggestion.clone());
    // Model a second node's response received almost one minute earlier: its
    // absolute Retry-After deadline is now less than a second away.
    record.next_check = Utc::now() + chrono::Duration::milliseconds(800);
    storage
        .store(
            &key(&cert.issuer_key, &leaf),
            &serde_json::to_vec(&record).unwrap(),
        )
        .await
        .unwrap();
    *issuer.info.lock().unwrap() = Some(suggestion);
    manager
        .cache_certificate("new-retry.example")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        while issuer.calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    manager.cache.stop();
    task.await.unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn alternate_chains_emit_one_metadata_event_and_do_not_bypass_failed_write_backoff() {
    let storage = Arc::new(Memory::default());
    storage.fail_ari_store.store(true, Ordering::SeqCst);
    let issuer = Arc::new(Issuer::new(Some(info(86400, 86400 * 2))));
    issuer.dynamic.store(true, Ordering::SeqCst);
    let manager = manager(storage, issuer.clone(), false, None);
    let original = resource("many-chains.example", 1, 90);
    let first = cached(&manager, &original).await;
    let root_key = KeyPair::generate().unwrap();
    for index in 0..70 {
        let mut root = CertificateParams::new(vec![format!("tail-{index}")]).unwrap();
        root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let bundle = [
            original.certificate_pem.as_slice(),
            root.self_signed(&root_key).unwrap().pem().as_bytes(),
        ]
        .concat();
        // Real DER chains have distinct content hashes and the same real leaf.
        // Their tail is irrelevant to the advisory per-leaf scheduling identity.
        let mut chain = Certificate::from_pem(&bundle, &original.private_key_pem).unwrap();
        chain.managed = true;
        chain.issuer_key = first.issuer_key.clone();
        manager
            .cache
            .add_managed(chain, &first.names[0])
            .await
            .unwrap();
    }
    let mut events = manager.cache.subscribe_ari_schedule();
    refresh(&manager, &first).await;
    let event = events.try_recv().unwrap();
    assert!(!event.reload);
    assert!(
        matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "one leaf must not overflow its own bounded notification channel"
    );
    issuer.entered.notified().await;
    let task = crate::start_maintenance(&manager);
    issuer.entered.notified().await;
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        issuer.calls.load(Ordering::SeqCst),
        2,
        "a changed suggestion plus failed store must still wait for Retry-After"
    );
    manager.cache.stop();
    task.await.unwrap();
}
