use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::*;
use crate::{CacheOptions, KeyInfo};

#[derive(Default)]
struct Markers {
    mode: AtomicU8,
    reads: AtomicUsize,
    gate: Mutex<Option<Arc<MarkerGate>>>,
}
struct MarkerGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}
#[async_trait::async_trait]
impl Storage for Markers {
    async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.acquire().await.unwrap().forget();
            }
            match self.mode.load(Ordering::SeqCst) {
                1 => {
                    return Err(crate::Error::Other(
                        "controlled marker backend failure".into(),
                    ));
                }
                2 => return Ok(br#"{"version":1,"confirmed":true}"#.to_vec()),
                _ => {}
            }
        }
        Err(crate::error::StorageError::NotFound(key.into()).into())
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
        Err(crate::error::StorageError::NotFound(key.into()).into())
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

fn certificate(id: u8) -> Certificate {
    let now = chrono::Utc::now();
    Certificate {
        cert_chain: vec![vec![id].into()],
        private_key_der: None,
        private_key_kind: crate::certificates::PrivateKeyKind::None,
        names: vec![format!("leaf-{id}.example")],
        tags: Vec::new(),
        managed: true,
        issuer_key: "retry-ca".into(),
        hash: format!("chain-{id}"),
        ocsp_response: None,
        ocsp_status: None,
        not_before: now - chrono::Duration::days(89),
        not_after: now + chrono::Duration::days(1),
        ari: None,
    }
}

fn policy(storage: Arc<Markers>, calls: Arc<AtomicUsize>) -> RenewalPolicy {
    RenewalPolicy {
        ari_manager: None,
        observed_renew: None,
        ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
        revocations: storage,
        certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
        renew: Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(crate::Error::Other("controlled renewal failure".into())) })
        }),
    }
}

#[tokio::test(start_paused = true)]
async fn backoff_is_monotonic_bounded_and_cannot_be_bypassed_by_same_leaf_metadata() {
    let cache = CertCache::new(CacheOptions::default());
    let mut cert = certificate(1);
    cache.add(cert.clone()).await;
    let identity = RenewalIdentity::new(&cert);
    let backoff = Arc::new(RenewalBackoff::default());
    for seconds in [60, 120, 240, 300, 300] {
        let mut attempt = backoff.reserve(&cache, identity.clone()).unwrap();
        attempt.started = true;
        drop(attempt);
        let at = backoff.deadline().unwrap();
        assert_eq!(
            at - tokio::time::Instant::now(),
            Duration::from_secs(seconds)
        );
        cert.tags.push("metadata update".into());
        cache.add(cert.clone()).await;
        let old_hash = cert.hash.clone();
        cert.hash.push('x'); // A distinct chain of the same leaf keeps the deadline.
        cache.add(cert.clone()).await;
        cache.remove(&old_hash).await;
        assert!(RenewalIdentity::new(&cert) == identity);
        assert!(backoff.reserve(&cache, identity.clone()).is_none());
        tokio::time::advance(Duration::from_secs(seconds) - Duration::from_nanos(1)).await;
        assert!(backoff.reserve(&cache, identity.clone()).is_none());
        tokio::time::advance(Duration::from_nanos(1)).await;
    }
    let mut success = backoff.reserve(&cache, identity).unwrap();
    success.started = true;
    success.success = true;
    drop(success);
    assert!(backoff.deadline().is_none());
    assert!(backoff.entries.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancellation_new_leaf_withdrawal_and_tokens_do_not_leave_stuck_records() {
    let cache = CertCache::new(Default::default());
    let first = certificate(1);
    cache.add(first.clone()).await;
    let identity = RenewalIdentity::new(&first);
    let backoff = Arc::new(RenewalBackoff::default());
    drop(backoff.reserve(&cache, identity.clone()).unwrap()); // Never executed.
    assert!(backoff.entries.lock().unwrap().is_empty());
    let mut old = backoff.reserve(&cache, identity.clone()).unwrap();
    old.started = true;
    backoff.prune(&HashSet::new());
    let current = backoff.reserve(&cache, identity.clone()).unwrap();
    drop(old); // An old completion must not remove/overwrite a new reservation.
    assert!(backoff.entries.lock().unwrap()[&identity].running);
    drop(current);
    let mut cancelled = backoff.reserve(&cache, identity.clone()).unwrap();
    cancelled.started = true;
    drop(cancelled);
    assert_eq!(
        backoff.deadline().unwrap() - tokio::time::Instant::now(),
        Duration::from_secs(60)
    );
    let replacement = certificate(2);
    cache.replace(&first.hash, replacement.clone()).await;
    let mut fresh = backoff
        .reserve(&cache, RenewalIdentity::new(&replacement))
        .unwrap();
    fresh.started = true;
    fresh.success = true;
    drop(fresh);
    backoff.prune(&HashSet::from([RenewalIdentity::new(&replacement)]));
    assert!(backoff.entries.lock().unwrap().is_empty());
    let mut withdrawn = backoff
        .reserve(&cache, RenewalIdentity::new(&replacement))
        .unwrap();
    withdrawn.started = true;
    let mut unmanaged = replacement.clone();
    unmanaged.managed = false;
    cache.replace(&replacement.hash, unmanaged).await;
    drop(withdrawn);
    assert!(backoff.entries.lock().unwrap().is_empty());
    cache.add(first.clone()).await;
    let mut removed = backoff.reserve(&cache, identity).unwrap();
    removed.started = true;
    cache.remove(&first.hash).await;
    drop(removed);
    assert!(backoff.entries.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn marker_failures_back_off_but_persisted_revocation_still_quarantines() {
    let cache = CertCache::new(Default::default());
    let cert = certificate(3);
    cache.add(cert.clone()).await;
    let markers = Arc::new(Markers::default());
    markers.mode.store(1, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = policy(markers.clone(), calls.clone());
    let backoff = Arc::new(RenewalBackoff::default());
    let jobs = JobQueue::certificate_jobs("marker-backoff");
    for _ in 0..8 {
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        wait_for_renewal_jobs(&jobs).await;
    }
    assert_eq!(markers.reads.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    markers.mode.store(2, Ordering::SeqCst);
    // The independent global scan is not gated by the failed renewal deadline.
    assert_eq!(
        refresh_revocations(&cache, markers.as_ref()).await.unwrap(),
        1
    );
    assert!(cache.managed_certificate(&cert.hash).is_none());
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    assert!(backoff.entries.lock().unwrap().is_empty());
    jobs.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn maintenance_retry_timer_retries_at_deadline_without_an_ari_or_periodic_wakeup() {
    let cache = CertCache::new(Default::default());
    cache.add(certificate(4)).await;
    let markers = Arc::new(Markers::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = policy(markers.clone(), calls.clone());
    let handle = start_maintenance_with_policy(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(600),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: markers,
        },
        policy.renew,
        policy.certificates,
        policy.ratio,
    );
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    cache.notify_ari();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(59)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(119)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    cache.stop_and_wait().await;
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_running_job_schedules_retry_and_stopping_drops_running_callbacks() {
    let cache = CertCache::new(Default::default());
    let cert = certificate(5);
    cache.add(cert.clone()).await;
    let markers = Arc::new(Markers::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut policy = policy(markers.clone(), calls.clone());
    let callback_calls = calls.clone();
    policy.renew = Arc::new(move |_, _| {
        callback_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    });
    let backoff = Arc::new(RenewalBackoff::default());
    let jobs = JobQueue::certificate_jobs("cancel-renewal");
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let identity = RenewalIdentity::new(&cert);
    jobs.cancel(&format!(
        "renew_{}_{}",
        cert.names[0],
        identity.job_suffix()
    ))
    .await;
    wait_for_renewal_jobs(&jobs).await;
    assert_eq!(
        backoff.deadline().unwrap() - tokio::time::Instant::now(),
        Duration::from_secs(60)
    );
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    assert!(jobs.is_empty().await);
    tokio::time::advance(Duration::from_secs(60)).await;
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    jobs.shutdown().await;
    assert_eq!(
        backoff.deadline().unwrap() - tokio::time::Instant::now(),
        Duration::from_secs(120)
    );

    // Exercise the actual stop select while the same callback is pending.
    let handle = start_maintenance_with_policy(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(600),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: markers,
        },
        policy.renew,
        policy.certificates,
        policy.ratio,
    );
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    cache.notify_ari();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    cache.stop_and_wait().await;
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn closed_queue_rejection_does_not_rearm_an_elapsed_failure_timer() {
    let cache = CertCache::new(Default::default());
    cache.add(certificate(6)).await;
    let policy = policy(Arc::new(Markers::default()), Arc::new(AtomicUsize::new(0)));
    let backoff = Arc::new(RenewalBackoff::default());
    let jobs = JobQueue::certificate_jobs("closed-renewal");
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    wait_for_renewal_jobs(&jobs).await;
    jobs.shutdown().await;
    tokio::time::advance(Duration::from_secs(60)).await;
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    assert_eq!(
        backoff.deadline().unwrap() - tokio::time::Instant::now(),
        Duration::from_secs(60)
    );
    assert_eq!(
        backoff
            .entries
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .failures,
        1
    );
}

#[tokio::test(start_paused = true)]
async fn due_retry_with_empty_names_suspends_timer_without_spinning_the_real_loop() {
    use tracing_subscriber::layer::SubscriberExt;
    struct Warnings(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = Message(String::new());
            event.record(&mut message);
            if message.0.contains("managed certificate has no names") {
                // A broken past-deadline loop otherwise never yields to a
                // timeout. Abort that real loop after three warnings, making
                // the regression an assertion failure instead of a hung test.
                assert!(
                    self.0.fetch_add(1, Ordering::SeqCst) < 2,
                    "past retry timer spun"
                );
            }
        }
    }
    let warnings = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(Warnings(warnings.clone()));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let cache = CertCache::new(Default::default());
    let mut cert = certificate(7);
    cache.add(cert.clone()).await;
    let markers = Arc::new(Markers::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = policy(markers.clone(), calls.clone());
    let handle = start_maintenance_with_policy(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(600),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: markers,
        },
        policy.renew,
        policy.certificates,
        policy.ratio,
    );
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    cache.notify_ari();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    cert.names.clear();
    cache.replace(&cert.hash, cert.clone()).await;
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(warnings.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(warnings.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    cache.stop_and_wait().await;
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn successful_storage_reload_clears_history_for_same_leaf_chains_and_replacements() {
    use crate::CertStore;
    for same_leaf in [false, true] {
        let cache = CertCache::new(Default::default());
        let (fresh_resource, fresh) = super::preflight_tests::certificate("reload.example", true);
        let mut old = if same_leaf {
            fresh.clone()
        } else {
            super::preflight_tests::certificate("reload.example", false).1
        };
        if same_leaf {
            old.cert_chain.push(old.cert_chain[0].clone());
            old.hash = crate::certificates::hash_certificate_chain(&old.cert_chain);
            let selected = chrono::Utc::now() - chrono::Duration::seconds(2);
            old.ari = Some(crate::RenewalInfo {
                suggested_window: Some(crate::RenewalWindow {
                    start: (selected - chrono::Duration::seconds(1)).to_rfc3339(),
                    end: (selected + chrono::Duration::seconds(1)).to_rfc3339(),
                }),
                selected_time: Some(selected),
                ..Default::default()
            });
        }
        cache.add(old.clone()).await;
        let markers = Arc::new(Markers::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(crate::cert_store::tests::InMemory::default());
        let mut policy = policy(markers, calls.clone());
        policy.certificates = store.clone();
        let backoff = Arc::new(RenewalBackoff::default());
        let jobs = JobQueue::certificate_jobs("reload-backoff");
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        wait_for_renewal_jobs(&jobs).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        store
            .save(&fresh.issuer_key, &fresh_resource)
            .await
            .unwrap();
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        assert!(jobs.is_empty().await);
        tokio::time::advance(Duration::from_secs(60)).await;
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        wait_for_renewal_jobs(&jobs).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cache.managed_certificate(&fresh.hash).is_some());
        assert!(backoff.entries.lock().unwrap().is_empty());
        jobs.shutdown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn successful_callback_replacement_clears_history_and_new_due_leaf_is_independent() {
    let cache = CertCache::new(Default::default());
    let old = super::preflight_tests::certificate("success.example", false).1;
    let fresh = super::preflight_tests::certificate("success.example", true).1;
    cache.add(old.clone()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut policy = policy(Arc::new(Markers::default()), calls.clone());
    policy.renew = Arc::new({
        let cache = cache.clone();
        let calls = calls.clone();
        let old_hash = old.hash.clone();
        let fresh = fresh.clone();
        move |_, _| {
            let cache = cache.clone();
            let old_hash = old_hash.clone();
            let fresh = fresh.clone();
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                cache.replace(&old_hash, fresh).await;
                Ok(())
            })
        }
    });
    let backoff = Arc::new(RenewalBackoff::default());
    let jobs = JobQueue::certificate_jobs("success-backoff");
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    wait_for_renewal_jobs(&jobs).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(backoff.entries.lock().unwrap().is_empty());
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    assert!(jobs.is_empty().await);
    let next = super::preflight_tests::certificate("success.example", false).1;
    cache.replace(&fresh.hash, next).await;
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    wait_for_renewal_jobs(&jobs).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(backoff.entries.lock().unwrap().is_empty());
    jobs.shutdown().await;
}

#[tokio::test]
async fn ari_moving_future_during_marker_wait_does_not_create_a_failure_penalty() {
    let cache = CertCache::new(Default::default());
    let mut cert = certificate(8);
    cert.not_before = chrono::Utc::now() - chrono::Duration::days(70);
    cert.not_after = chrono::Utc::now() + chrono::Duration::days(20);
    cache.add(cert.clone()).await;
    let markers = Arc::new(Markers::default());
    let gate = Arc::new(MarkerGate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    *markers.gate.lock().unwrap() = Some(gate.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = policy(markers.clone(), calls.clone());
    let manager = Arc::new(
        crate::CertManager::builder()
            .cache(cache.clone())
            .storage(markers.clone())
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build(),
    );
    let handle = start_maintenance_with_observed_renewal(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(600),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: markers.clone(),
        },
        policy.renew,
        policy.certificates,
        policy.ratio,
        None,
        Some(manager),
    );
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            cache.notify_ari();
            tokio::select! {
                _ = gate.entered.notified() => break,
                _ = tokio::time::sleep(Duration::from_millis(1)) => {},
            }
        }
    })
    .await
    .unwrap();
    let selected = chrono::Utc::now() + chrono::Duration::seconds(5);
    let leaf = crate::storage::certificate_leaf_hash(&cert).unwrap();
    cache.update_ari(
        &cert.issuer_key,
        &leaf,
        Some(crate::RenewalInfo {
            suggested_window: Some(crate::RenewalWindow {
                start: (selected - chrono::Duration::seconds(1)).to_rfc3339(),
                end: (selected + chrono::Duration::seconds(1)).to_rfc3339(),
            }),
            selected_time: Some(selected),
            ..Default::default()
        }),
        None,
    );
    gate.release.add_permits(1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(7), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the new ARI selected point must not acquire a spurious 60-second failure delay");
    assert!(chrono::Utc::now() >= selected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(markers.reads.load(Ordering::SeqCst), 2);
    cache.stop_and_wait().await;
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn permanent_callback_errors_never_retry_more_often_than_the_renewal_interval() {
    // Include the structured errors supplied by the preceding ACME fix: the
    // maintenance policy must retain their permanent classification too.
    for (interval, kind) in [(600, 0), (1200, 1), (30, 1), (600, 2), (600, 3)] {
        let cache = CertCache::new(Default::default());
        cache.add(certificate(9)).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut policy = policy(Arc::new(Markers::default()), calls.clone());
        policy.renew = Arc::new({
            let calls = calls.clone();
            move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Err(match kind {
                        0 => crate::Error::NoRetry("controlled permanent renewal failure".into()),
                        1 => crate::Error::Config("controlled permanent config failure".into()),
                        _ => crate::error::AcmeError::HttpResponse {
                            status: if kind == 2 { 400 } else { 403 },
                            problem_type: Some(format!(
                                "urn:ietf:params:acme:error:{}",
                                if kind == 2 {
                                    "rejectedIdentifier"
                                } else {
                                    "unauthorized"
                                }
                            )),
                            message: "controlled permanent HTTP failure".into(),
                        }
                        .into(),
                    })
                })
            }
        });
        let backoff = Arc::new(RenewalBackoff::new(Duration::from_secs(interval)));
        let jobs = JobQueue::certificate_jobs("permanent-backoff");
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        wait_for_renewal_jobs(&jobs).await;
        let delay = Duration::from_secs(interval.max(60));
        assert_eq!(
            backoff.deadline().unwrap() - tokio::time::Instant::now(),
            delay
        );
        tokio::time::advance(delay - Duration::from_nanos(1)).await;
        for _ in 0..8 {
            check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_nanos(1)).await;
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        wait_for_renewal_jobs(&jobs).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            backoff.deadline().unwrap() - tokio::time::Instant::now(),
            Duration::from_secs(interval.max(120))
        );
        jobs.shutdown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn same_leaf_ari_changes_do_not_shorten_an_existing_failure_deadline() {
    let cache = CertCache::new(Default::default());
    let mut cert = certificate(10);
    cert.not_before = chrono::Utc::now() - chrono::Duration::days(70);
    cert.not_after = chrono::Utc::now() + chrono::Duration::days(20);
    cache.add(cert.clone()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let markers = Arc::new(Markers::default());
    let policy = policy(markers.clone(), calls.clone());
    let jobs = JobQueue::certificate_jobs("metadata-deadline");
    let backoff = Arc::new(RenewalBackoff::default());
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    wait_for_renewal_jobs(&jobs).await;
    let deadline = backoff.deadline().unwrap();
    let leaf = crate::storage::certificate_leaf_hash(&cert).unwrap();
    for offset in [5, -5] {
        let selected = chrono::Utc::now() + chrono::Duration::seconds(offset);
        cache.update_ari(
            &cert.issuer_key,
            &leaf,
            Some(crate::RenewalInfo {
                suggested_window: Some(crate::RenewalWindow {
                    start: (selected - chrono::Duration::seconds(1)).to_rfc3339(),
                    end: (selected + chrono::Duration::seconds(1)).to_rfc3339(),
                }),
                selected_time: Some(selected),
                ..Default::default()
            }),
            None,
        );
        check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        assert_eq!(backoff.deadline(), Some(deadline));
        assert!(jobs.is_empty().await);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(markers.reads.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(60)).await;
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    wait_for_renewal_jobs(&jobs).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    jobs.shutdown().await;
}
