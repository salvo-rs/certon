use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::{
    CacheOptions, CertCache, CertManager, Certificate, KeyInfo, OcspConfig, Result, Storage,
};
use chrono::{DateTime, Utc};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

#[derive(Default)]
struct Memory {
    marker_reads: Mutex<HashMap<String, usize>>,
    certificate_loads: Mutex<HashMap<String, usize>>,
    values: Mutex<HashMap<String, Vec<u8>>>,
    marker_errors: Mutex<HashSet<String>>,
    read_finished: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Storage for Memory {
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            *self
                .marker_reads
                .lock()
                .unwrap()
                .entry(key.into())
                .or_default() += 1;
            self.read_finished.notify_one();
            if self.marker_errors.lock().unwrap().contains(key) {
                return Err(certon::Error::Other("marker backend unavailable".into()));
            }
        }
        if key.starts_with("certificates/") && key.ends_with("resource.v1.key") {
            *self
                .certificate_loads
                .lock()
                .unwrap()
                .entry(key.into())
                .or_default() += 1;
        }
        self.values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| certon::error::StorageError::NotFound(key.into()).into())
    }
    async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn exists(&self, _: &str) -> Result<bool> {
        Ok(false)
    }
    async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        Err(certon::error::StorageError::NotFound(key.into()).into())
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Observed {
    scans: Mutex<Vec<usize>>,
    completed: Mutex<HashSet<String>>,
    denied: Mutex<HashSet<String>>,
    changed: tokio::sync::Notify,
}
struct ScanLayer(Arc<Observed>);
#[derive(Default)]
struct ScanEvent {
    message: String,
    count: Option<usize>,
    domain: String,
}
impl Visit for ScanEvent {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "count" {
            self.count = Some(value as usize);
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
        if field.name() == "domain" {
            self.domain = format!("{value:?}");
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "domain" {
            self.domain = value.into();
        }
    }
}
impl<S: Subscriber> Layer<S> for ScanLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != "certon::maintain" {
            return;
        }
        let mut value = ScanEvent::default();
        event.record(&mut value);
        if value
            .message
            .contains("maintenance: checking managed certificates for renewal")
        {
            self.0.scans.lock().unwrap().push(value.count.unwrap());
        }
        if value
            .message
            .contains("cannot verify renewal leaf revocation intent; skipping renewal")
        {
            self.0.denied.lock().unwrap().insert(value.domain.clone());
            self.0.changed.notify_one();
        }
        if value
            .message
            .contains("maintenance: certificate renewal failed")
        {
            self.0.completed.lock().unwrap().insert(value.domain);
            self.0.changed.notify_one();
        }
    }
}

fn metadata(index: usize, selected: Option<DateTime<Utc>>) -> Certificate {
    // This isolates scheduling/storage work, not TLS or key generation. The
    // public metadata-only cache accepts absent keys; distinct leaf bytes give
    // independently indexed identities. No network, private-key work or disk IO.
    let now = Utc::now();
    Certificate {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            index.to_be_bytes().to_vec(),
        )],
        private_key_der: None,
        private_key_kind: certon::certificates::PrivateKeyKind::None,
        names: vec![format!("metadata-{index}.example")],
        tags: Vec::new(),
        managed: true,
        issuer_key: "diagnostic-ca".into(),
        hash: format!("metadata-{index}"),
        ocsp_response: None,
        ocsp_status: None,
        not_before: now - chrono::Duration::days(1),
        not_after: now + chrono::Duration::days(90),
        ari: selected.map(|selected| certon::RenewalInfo {
            suggested_window: Some(certon::RenewalWindow {
                start: (selected - chrono::Duration::seconds(1)).to_rfc3339(),
                end: (selected + chrono::Duration::seconds(1)).to_rfc3339(),
            }),
            selected_time: Some(selected),
            retry_after: Some(3600),
            ..Default::default()
        }),
    }
}

async fn scenario(observed: &Arc<Observed>, n: usize, k: usize, staggered: bool, disabled: bool) {
    observed.scans.lock().unwrap().clear();
    observed.completed.lock().unwrap().clear();
    observed.denied.lock().unwrap().clear();
    let storage = Arc::new(Memory::default());
    let cache = CertCache::new(CacheOptions::default());
    let first_due = Utc::now() + chrono::Duration::seconds(2);
    let mut never_due = Vec::new();
    for index in 0..n {
        let selected = (index < k).then(|| {
            first_due
                + chrono::Duration::milliseconds(if staggered { index as i64 * 200 } else { 0 })
        });
        let cert = metadata(index, selected);
        if index >= k {
            never_due.push(certon::certificates::hash_certificate_chain(
                &cert.cert_chain[..1],
            ));
        }
        cache.add(cert).await;
    }
    let manager = CertManager::builder()
        .storage(storage.clone())
        .cache(cache.clone())
        .disable_ari(disabled)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    let handle = certon::start_maintenance(&manager);
    if disabled {
        // A negative control has no callback to await. Observe it through all
        // selected points, still far before the normal ten-minute interval.
        let last_due = first_due + chrono::Duration::milliseconds((k - 1) as i64 * 200);
        tokio::time::sleep(
            (last_due - Utc::now()).to_std().unwrap_or_default() + Duration::from_millis(100),
        )
        .await;
    } else {
        // Wait for each actual renewal callback to return (the intentionally
        // empty resource store makes it fail without issuance). Slow machines
        // may coalesce selected points; no exact staggered scan count is needed.
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let changed = observed.changed.notified();
                let all_complete = {
                    let completed = observed.completed.lock().unwrap();
                    (0..k).all(|index| completed.contains(&format!("metadata-{index}.example")))
                };
                if all_complete {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("every due job must finish its renewal callback");
    }
    cache.stop_and_wait().await;
    handle.await.unwrap();
    let scans = observed.scans.lock().unwrap().clone();
    if disabled {
        assert!(scans.is_empty());
    } else if staggered {
        assert!((1..=k).contains(&scans.len()));
    } else {
        assert_eq!(scans.len(), 1, "one coincident timer bucket coalesces");
    }
    assert!(scans.iter().all(|count| *count == n));
    let markers = storage.marker_reads.lock().unwrap();
    if !disabled {
        for index in 0..k {
            let leaf = certon::certificates::hash_certificate_chain(
                &metadata(index, None).cert_chain[..1],
            );
            assert!(
                markers
                    .get(&format!("revocations/{leaf}.json"))
                    .copied()
                    .unwrap_or_default()
                    > 0,
                "due job skipped its own marker"
            );
        }
    }
    for leaf in &never_due {
        assert_eq!(
            markers
                .get(&format!("revocations/{leaf}.json"))
                .copied()
                .unwrap_or_default(),
            0,
            "ARI-only wakeups must not scan unrelated leaf markers"
        );
    }
    let all_reads: usize = markers.values().sum();
    eprintln!(
        "CASE n={n} k={k} staggered={staggered} disabled={disabled} renewal_scans={} renewal_predicates={} global_marker_reads=0 own_marker_reads={all_reads}",
        scans.len(),
        scans.iter().sum::<usize>()
    );
}

#[tokio::test]
async fn ari_deadlines_check_due_leaf_markers_without_amplifying_global_scans() {
    let scans = Arc::new(Observed::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(ScanLayer(scans.clone())),
    )
    .unwrap();
    scenario(&scans, 500, 4, true, false).await;
    scenario(&scans, 500, 8, true, false).await;
    scenario(&scans, 2000, 8, true, false).await;
    scenario(&scans, 2000, 8, false, false).await;
    scenario(&scans, 2000, 8, true, true).await;
    denied_due_marker(&scans, false).await;
    denied_due_marker(&scans, true).await;
    periodic_scans_still_quarantine_non_due_leaves().await;
}

async fn denied_due_marker(observed: &Arc<Observed>, backend_error: bool) {
    observed.scans.lock().unwrap().clear();
    observed.completed.lock().unwrap().clear();
    observed.denied.lock().unwrap().clear();
    let storage = Arc::new(Memory::default());
    let cache = CertCache::new(CacheOptions::default());
    let due = metadata(0, Some(Utc::now() + chrono::Duration::milliseconds(300)));
    let due_hash = due.hash.clone();
    let leaf = certon::certificates::hash_certificate_chain(&due.cert_chain[..1]);
    let key = format!("revocations/{leaf}.json");
    if backend_error {
        storage.marker_errors.lock().unwrap().insert(key.clone());
    } else {
        storage
            .values
            .lock()
            .unwrap()
            .insert(key.clone(), br#"{"version":1,"confirmed":true}"#.to_vec());
    }
    cache.add(due).await;
    cache.add(metadata(1, None)).await;
    let manager = CertManager::builder()
        .storage(storage.clone())
        .cache(cache.clone())
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    let maintenance = certon::start_maintenance(&manager);
    tokio::time::timeout(Duration::from_secs(10), async {
        if backend_error {
            loop {
                let changed = observed.changed.notified();
                if observed
                    .denied
                    .lock()
                    .unwrap()
                    .contains("metadata-0.example")
                {
                    break;
                }
                changed.await;
            }
        } else {
            while cache.get_by_hash(&due_hash).await.is_some() {
                tokio::task::yield_now().await;
            }
        }
    })
    .await
    .expect("ARI due job must consume its revocation guard result before stop");
    cache.stop_and_wait().await;
    maintenance.await.unwrap();
    assert_eq!(
        storage.marker_reads.lock().unwrap().len(),
        1,
        "unrelated leaf was scanned"
    );
    assert_eq!(cache.get_by_hash(&due_hash).await.is_some(), backend_error);
    assert!(cache.get_by_hash("metadata-1").await.is_some());
    assert!(
        observed.completed.lock().unwrap().is_empty(),
        "denied job reached renewal callback"
    );
    // Each initial ARI identity check may load its absent resource once. A
    // forbidden job must not repeat it in renewal preflight. Stop may cancel
    // an initial check, so do not require all initial checks to finish.
    assert!(
        storage
            .certificate_loads
            .lock()
            .unwrap()
            .values()
            .all(|loads| *loads == 1)
    );
}

async fn periodic_scans_still_quarantine_non_due_leaves() {
    use certon::maintain::{MaintenanceConfig, start_maintenance_with_policy};
    tokio::time::pause();
    for (renew_secs, ocsp_secs) in [(60, 3600), (3600, 60)] {
        let storage = Arc::new(Memory::default());
        let cache = CertCache::new(CacheOptions::default());
        let callbacks = Arc::new(AtomicUsize::new(0));
        for index in 0..3 {
            let cert = metadata(index, None);
            if index == 1 {
                let leaf = certon::certificates::hash_certificate_chain(&cert.cert_chain[..1]);
                storage.values.lock().unwrap().insert(
                    format!("revocations/{leaf}.json"),
                    br#"{"version":1,"confirmed":true}"#.to_vec(),
                );
            }
            cache.add(cert).await;
        }
        let maintenance = start_maintenance_with_policy(
            cache.clone(),
            MaintenanceConfig {
                renew_check_interval: Duration::from_secs(renew_secs),
                ocsp_check_interval: Duration::from_secs(ocsp_secs),
                ocsp: OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                },
                storage: storage.clone(),
            },
            Arc::new({
                let callbacks = callbacks.clone();
                move |_, _| {
                    callbacks.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(()) })
                }
            }),
            Arc::new(certon::KeyValueCertStore::new(storage.clone())),
            1.0 / 3.0,
        );
        // Let both owned maintenance tasks consume the initial ticks before
        // advancing to either the renewal or OCSP periodic tick.
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(storage.marker_reads.lock().unwrap().is_empty());
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let changed = storage.read_finished.notified();
                if storage.marker_reads.lock().unwrap().len() == 3
                    && cache.get_by_hash("metadata-1").await.is_none()
                {
                    break;
                }
                tokio::select! {
                    _ = changed => {},
                    _ = tokio::task::yield_now() => {},
                }
            }
        })
        .await
        .expect("periodic global marker scan was suppressed");
        cache.stop_and_wait().await;
        maintenance.await.unwrap();
        assert!(
            cache.get_by_hash("metadata-1").await.is_none(),
            "periodic scans must quarantine non-due leaves"
        );
        assert_eq!(cache.count().await, 2);
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        assert!(
            storage
                .marker_reads
                .lock()
                .unwrap()
                .values()
                .all(|reads| *reads == 1)
        );
        eprintln!(
            "PERIODIC renewal_interval={renew_secs} ocsp_interval={ocsp_secs} global_marker_reads=3 non_due_leaf_quarantined=true disabled_stapling=true"
        );
    }
    tokio::time::resume();
}
