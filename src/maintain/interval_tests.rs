use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::{CacheOptions, KeyInfo};

#[derive(Default)]
struct Markers {
    reads: AtomicUsize,
    panic_next: AtomicBool,
}

#[async_trait::async_trait]
impl Storage for Markers {
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") {
            self.reads.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_next.swap(false, Ordering::SeqCst),
                "controlled marker panic"
            );
        }
        Err(crate::error::StorageError::NotFound(key.into()).into())
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
        Err(crate::error::StorageError::NotFound(key.into()).into())
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

fn options(renew: Duration, ocsp: Duration) -> CacheOptions {
    CacheOptions {
        renew_check_interval: renew,
        ocsp_check_interval: ocsp,
        ..Default::default()
    }
}

fn certificate(due: bool) -> Certificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["interval.example".into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let now = std::time::SystemTime::now();
    params.not_before = (now - Duration::from_secs(if due { 89 } else { 1 } * 86400)).into();
    params.not_after = (now + Duration::from_secs(if due { 1 } else { 90 } * 86400)).into();
    let leaf = params.self_signed(&key).unwrap();
    let mut cert =
        Certificate::from_pem(leaf.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    cert.managed = true;
    cert.issuer_key = "interval-ca".into();
    cert
}

async fn settle() {
    for _ in 0..30 {
        tokio::task::yield_now().await;
    }
}
async fn advance(duration: Duration) {
    tokio::time::advance(duration).await;
    settle().await;
}

struct Fixture {
    cache: Arc<CertCache>,
    storage: Arc<Markers>,
    handle: JoinHandle<()>,
}
impl Fixture {
    async fn new(configured: CacheOptions, explicit: Option<MaintenanceIntervals>) -> Self {
        let cache = CertCache::new(configured);
        cache.add(certificate(false)).await;
        let storage = Arc::new(Markers::default());
        let ocsp = OcspConfig {
            disable_stapling: true,
            ..Default::default()
        };
        let handle = if let Some(intervals) = explicit {
            start_maintenance(
                cache.clone(),
                MaintenanceConfig {
                    renew_check_interval: intervals.renew,
                    ocsp_check_interval: intervals.ocsp,
                    storage: storage.clone(),
                    ocsp,
                },
                Arc::new(|_| Box::pin(async { Ok(()) })),
            )
        } else {
            let manager = crate::CertManager::builder()
                .cache(cache.clone())
                .storage(storage.clone())
                .disable_ari(true)
                .ocsp(ocsp)
                .build();
            crate::start_maintenance(&manager)
        };
        Self {
            cache,
            storage,
            handle,
        }
    }
    fn reads(&self) -> usize {
        self.storage.reads.load(Ordering::SeqCst)
    }
    async fn stop(self) {
        self.cache.stop_and_wait().await;
        self.handle.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn high_level_uses_each_configured_interval_from_startup() {
    for renewal in [true, false] {
        let short = Duration::from_millis(20);
        let long = Duration::from_secs(3600);
        let fixture = Fixture::new(
            if renewal {
                options(short, long)
            } else {
                options(long, short)
            },
            None,
        )
        .await;
        settle().await;
        assert_eq!(fixture.reads(), 0, "startup is not an immediate scan");
        for expected in 1..=5 {
            advance(short).await;
            assert_eq!(fixture.reads(), expected);
        }
        fixture.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn unrelated_update_bursts_cannot_starve_a_ready_ticker_but_own_changes_win() {
    for renewal in [true, false] {
        let short = Duration::from_millis(20);
        let cache = CertCache::new(options(short, short));
        let source = IntervalSource::Cache(cache.subscribe_maintenance_intervals());
        let mut ticker = MaintenanceTicker::new(&source, renewal);
        for index in 1..=16 {
            tokio::time::advance(short).await;
            let other = Duration::from_secs(100 + index);
            cache
                .set_options(if renewal {
                    options(short, other)
                } else {
                    options(other, short)
                })
                .await;
            assert!(
                ticker.next().await,
                "unrelated watch update hid an already-ready tick"
            );
        }
        tokio::time::advance(short).await;
        let long = Duration::from_secs(3600);
        cache.set_options(options(long, long)).await;
        assert!(
            !ticker.next().await,
            "own interval change must reset the old ready tick"
        );
        assert_eq!(ticker.period, long);
    }
}

#[tokio::test(start_paused = true)]
async fn runtime_changes_reset_only_the_changed_timer_after_a_full_period() {
    let fixture = Fixture::new(
        options(Duration::from_millis(100), Duration::from_millis(150)),
        None,
    )
    .await;
    settle().await;
    advance(Duration::from_millis(40)).await;
    fixture
        .cache
        .set_options(options(
            Duration::from_millis(20),
            Duration::from_millis(150),
        ))
        .await;
    settle().await;
    assert_eq!(fixture.reads(), 0);
    advance(Duration::from_millis(19)).await;
    assert_eq!(fixture.reads(), 0);
    advance(Duration::from_millis(1)).await;
    assert_eq!(fixture.reads(), 1);
    for _ in 0..4 {
        advance(Duration::from_millis(20)).await;
    }
    assert_eq!(fixture.reads(), 5); // t=140, renewal ticks 60/80/100/120/140.
    advance(Duration::from_millis(10)).await;
    assert_eq!(
        fixture.reads(),
        6,
        "OCSP's original t=150 tick must survive the renewal update"
    );
    fixture
        .cache
        .set_options(options(
            Duration::from_millis(20),
            Duration::from_millis(1000),
        ))
        .await;
    settle().await;
    advance(Duration::from_millis(10)).await;
    assert_eq!(
        fixture.reads(),
        7,
        "renewal t=160 must survive the OCSP update"
    );
    fixture
        .cache
        .set_options(options(
            Duration::from_millis(200),
            Duration::from_millis(1000),
        ))
        .await;
    settle().await;
    advance(Duration::from_millis(199)).await;
    assert_eq!(fixture.reads(), 7);
    advance(Duration::from_millis(1)).await;
    assert_eq!(fixture.reads(), 8);
    fixture
        .cache
        .set_options(options(
            Duration::from_millis(200),
            Duration::from_millis(20),
        ))
        .await;
    settle().await;
    advance(Duration::from_millis(19)).await;
    assert_eq!(fixture.reads(), 8);
    advance(Duration::from_millis(1)).await;
    assert_eq!(fixture.reads(), 9);
    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn startup_races_and_unchanged_noninterval_updates_keep_the_final_pair_and_phase() {
    let short = Duration::from_millis(100);
    let long = Duration::from_secs(3600);
    let fixture = Fixture::new(options(long, long), None).await;
    // The spawned maintenance loop has not been polled between these updates.
    for milliseconds in [20, 80, 40, 100] {
        fixture
            .cache
            .set_options(options(Duration::from_millis(milliseconds), long))
            .await;
    }
    settle().await;
    advance(Duration::from_millis(40)).await;
    let mut configured = options(short, long);
    configured.capacity = 10;
    configured.on_event = Some(Arc::new(|_| {}));
    fixture.cache.set_options(configured).await;
    settle().await;
    advance(Duration::from_millis(40)).await;
    fixture.cache.set_options(options(short, long)).await;
    settle().await;
    advance(Duration::from_millis(19)).await;
    assert_eq!(fixture.reads(), 0);
    advance(Duration::from_millis(1)).await;
    assert_eq!(
        fixture.reads(),
        1,
        "same intervals must not restart the original t=100 deadline"
    );
    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn zero_and_unrepresentable_intervals_fall_back_and_explicit_config_keeps_precedence() {
    for invalid in [Duration::ZERO, Duration::MAX] {
        let fixture = Fixture::new(options(invalid, invalid), None).await;
        let pair = *fixture.cache.subscribe_maintenance_intervals().borrow();
        assert_eq!(pair.renew, DEFAULT_RENEW_CHECK_INTERVAL);
        assert_eq!(pair.ocsp, DEFAULT_OCSP_CHECK_INTERVAL);
        settle().await;
        advance(Duration::from_secs(599)).await;
        assert_eq!(fixture.reads(), 0);
        advance(Duration::from_secs(1)).await;
        assert_eq!(fixture.reads(), 1);
        fixture
            .cache
            .set_options(options(
                Duration::from_millis(20),
                Duration::from_secs(3600),
            ))
            .await;
        settle().await;
        advance(Duration::from_millis(20)).await;
        assert_eq!(fixture.reads(), 2);
        fixture.cache.set_options(options(invalid, invalid)).await;
        settle().await;
        advance(Duration::from_millis(20)).await;
        assert_eq!(
            fixture.reads(),
            2,
            "invalid runtime updates must adopt the default full period"
        );
        fixture.stop().await;
    }
    let fixture = Fixture::new(
        options(Duration::from_millis(10), Duration::from_millis(10)),
        Some(MaintenanceIntervals::new(
            Duration::from_millis(100),
            Duration::from_secs(3600),
        )),
    )
    .await;
    settle().await;
    fixture
        .cache
        .set_options(options(Duration::from_millis(1), Duration::from_millis(1)))
        .await;
    advance(Duration::from_millis(99)).await;
    assert_eq!(fixture.reads(), 0);
    advance(Duration::from_millis(1)).await;
    assert_eq!(
        fixture.reads(),
        1,
        "explicit low-level MaintenanceConfig owns the period"
    );
    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn actual_clock_overflow_falls_back_after_a_valid_configuration_clock() {
    // Locate this platform's representable range rather than assuming Linux's
    // and Windows' Instant implementations have the same upper bound.
    let configured_at = std::time::Instant::now();
    let (mut low, mut high) = (0u64, u64::MAX);
    while low < high {
        let middle = low + (high - low) / 2 + 1;
        if configured_at
            .checked_add(Duration::from_secs(middle))
            .is_some()
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let huge = Duration::from_secs(low.checked_sub(3600).unwrap());
    assert!(configured_at.checked_add(huge).is_some());
    let cache = CertCache::new(options(huge, huge));
    let cert = certificate(true);
    cache.add(cert.clone()).await;
    let backoff = dynamic_backoff(&cache);
    let identity = RenewalIdentity::new(&cert);
    let mut failure = backoff.reserve(&cache, identity.clone()).unwrap();
    assert!(failure.begin());
    failure.permanent = true;
    drop(failure);
    tokio::time::advance(Duration::from_secs(7200)).await;
    assert!(tokio::time::Instant::now().checked_add(huge).is_none());
    // Both ticker construction/reset and floor calculations use this helper
    // against the actual clock, rather than trusting the setter's old check.
    let (period, first) = interval_deadline(
        tokio::time::Instant::now(),
        huge,
        DEFAULT_RENEW_CHECK_INTERVAL,
    );
    assert_eq!(period, DEFAULT_RENEW_CHECK_INTERVAL);
    assert_eq!(
        first - tokio::time::Instant::now(),
        DEFAULT_RENEW_CHECK_INTERVAL
    );
    backoff.deadline();
    assert_eq!(
        backoff.entries.lock().unwrap()[&identity].minimum_delay,
        DEFAULT_RENEW_CHECK_INTERVAL
    );
    // Use a non-due leaf for actual high-level periodic marker counting. UTC
    // certificate validity never followed the controllable Tokio clock.
    cache.remove(&cert.hash).await;
    cache.add(certificate(false)).await;
    let storage = Arc::new(Markers::default());
    let manager = crate::CertManager::builder()
        .cache(cache.clone())
        .storage(storage.clone())
        .disable_ari(true)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    let handle = crate::start_maintenance(&manager);
    settle().await;
    advance(Duration::from_secs(599)).await;
    assert_eq!(storage.reads.load(Ordering::SeqCst), 0);
    advance(Duration::from_secs(1)).await;
    assert_eq!(storage.reads.load(Ordering::SeqCst), 1);
    cache.stop_and_wait().await;
    handle.await.unwrap();
}

#[tokio::test]
async fn a_blocking_old_callback_destructor_cannot_publish_stale_intervals() {
    struct BlockDrop(
        std::sync::mpsc::Sender<()>,
        Mutex<std::sync::mpsc::Receiver<()>>,
    );
    impl Drop for BlockDrop {
        fn drop(&mut self) {
            let _ = self.0.send(());
            self.1
                .get_mut()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
    }
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let token = BlockDrop(entered, Mutex::new(wait));
    let mut initial = options(Duration::from_secs(1), Duration::from_secs(1));
    initial.on_event = Some(Arc::new(move |_| {
        std::hint::black_box(&token);
    }));
    let cache = CertCache::new(initial);
    let mut intervals = cache.subscribe_maintenance_intervals();
    let runtime = tokio::runtime::Handle::current();
    let first = std::thread::spawn({
        let cache = cache.clone();
        move || {
            runtime.block_on(
                cache.set_options(options(Duration::from_secs(2), Duration::from_secs(2))),
            )
        }
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    cache
        .set_options(options(Duration::from_secs(3), Duration::from_secs(4)))
        .await;
    release.send(()).unwrap();
    first.join().unwrap();
    let pair = *intervals.borrow_and_update();
    assert_eq!(pair.renew, Duration::from_secs(3));
    assert_eq!(pair.ocsp, Duration::from_secs(4));
    assert!(!intervals.has_changed().unwrap());
}

fn dynamic_backoff(cache: &CertCache) -> Arc<RenewalBackoff> {
    Arc::new(RenewalBackoff::with_intervals(IntervalSource::Cache(
        cache.subscribe_maintenance_intervals(),
    )))
}

#[tokio::test(start_paused = true)]
async fn permanent_retry_deadlines_extend_from_completion_and_never_shorten() {
    let cache = CertCache::new(options(Duration::from_secs(600), Duration::from_secs(3600)));
    let cert = certificate(true);
    cache.add(cert.clone()).await;
    let backoff = dynamic_backoff(&cache);
    let identity = RenewalIdentity::new(&cert);
    let origin = tokio::time::Instant::now();
    let mut failure = backoff.reserve(&cache, identity.clone()).unwrap();
    assert!(failure.begin());
    failure.permanent = true;
    drop(failure);
    advance(Duration::from_secs(100)).await;
    cache
        .set_options(options(
            Duration::from_secs(1200),
            Duration::from_secs(3600),
        ))
        .await;
    advance(Duration::from_secs(500)).await;
    // No ticker/watch consumer has run. Admission itself must use the latest floor.
    assert!(backoff.reserve(&cache, identity.clone()).is_none());
    assert_eq!(backoff.deadline(), Some(origin + Duration::from_secs(1200)));
    cache
        .set_options(options(Duration::from_secs(30), Duration::from_secs(3600)))
        .await;
    assert_eq!(backoff.deadline(), Some(origin + Duration::from_secs(1200)));
    advance(Duration::from_secs(600)).await;
    let mut next = backoff.reserve(&cache, identity.clone()).unwrap();
    assert!(next.begin());
    next.permanent = true;
    drop(next);
    assert_eq!(backoff.entries.lock().unwrap()[&identity].failures, 2);
    assert_eq!(backoff.deadline(), Some(origin + Duration::from_secs(1320)));
    advance(Duration::from_secs(120)).await;
    backoff.suspend_if_elapsed(&identity);
    for _ in 0..5 {
        assert!(
            backoff.deadline().is_none(),
            "must not resurrect a suspended past timer"
        );
    }
    cache
        .set_options(options(
            Duration::from_secs(1800),
            Duration::from_secs(3600),
        ))
        .await;
    assert_eq!(
        backoff.deadline(),
        Some(origin + Duration::from_secs(3000)),
        "a genuinely later floor can rearm a suspended permanent entry"
    );
}

#[tokio::test(start_paused = true)]
async fn queued_retry_rechecks_floor_after_actual_job_admission_and_inflight_failure_uses_latest() {
    let cache = CertCache::new(options(Duration::from_secs(600), Duration::from_secs(3600)));
    let cert = certificate(true);
    cache.add(cert.clone()).await;
    let backoff = dynamic_backoff(&cache);
    let identity = RenewalIdentity::new(&cert);
    let origin = tokio::time::Instant::now();
    let mut failure = backoff.reserve(&cache, identity.clone()).unwrap();
    failure.begin();
    failure.permanent = true;
    drop(failure);
    advance(Duration::from_secs(600)).await;
    let jobs = Arc::new(JobQueue::with_limits("interval-admission", 1, 0));
    let blocker = Arc::new(tokio::sync::Semaphore::new(0));
    jobs.submit("blocker".into(), {
        let blocker = blocker.clone();
        move || async move {
            blocker.acquire().await.unwrap().forget();
        }
    })
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let markers = Arc::new(Markers::default());
    let scan = tokio::spawn({
        let cache = cache.clone();
        let jobs = jobs.clone();
        let backoff = backoff.clone();
        let calls = calls.clone();
        let markers = markers.clone();
        async move {
            let policy = RenewalPolicy {
                renew: Arc::new(move |_, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Err(crate::Error::Config("permanent".into())) })
                }),
                observed_renew: None,
                certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
                revocations: markers,
                ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
                ari_manager: None,
            };
            check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
        }
    });
    settle().await;
    assert!(backoff.entries.lock().unwrap()[&identity].running);
    cache
        .set_options(options(
            Duration::from_secs(1200),
            Duration::from_secs(3600),
        ))
        .await;
    blocker.add_permits(1);
    scan.await.unwrap();
    wait_for_renewal_jobs(&jobs).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "queued old retry must not use the old short floor"
    );
    assert_eq!(backoff.deadline(), Some(origin + Duration::from_secs(1200)));
    assert_eq!(backoff.entries.lock().unwrap()[&identity].failures, 1);
    assert_eq!(
        markers.reads.load(Ordering::SeqCst),
        0,
        "deferred jobs must not begin marker preflight"
    );
    advance(Duration::from_secs(600)).await;
    let mut in_flight = backoff.reserve(&cache, identity.clone()).unwrap();
    assert!(in_flight.begin());
    advance(Duration::from_secs(100)).await;
    cache
        .set_options(options(
            Duration::from_secs(1800),
            Duration::from_secs(3600),
        ))
        .await;
    in_flight.permanent = true;
    drop(in_flight);
    assert_eq!(backoff.deadline(), Some(origin + Duration::from_secs(3100)));
    jobs.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_callback_waiting_during_an_update_uses_the_latest_floor_on_failure() {
    let cache = CertCache::new(options(Duration::from_secs(600), Duration::from_secs(3600)));
    cache.add(certificate(true)).await;
    let backoff = dynamic_backoff(&cache);
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let policy = RenewalPolicy {
        renew: Arc::new({
            let release = release.clone();
            let entered = entered.clone();
            move |_, _| {
                let release = release.clone();
                let entered = entered.clone();
                Box::pin(async move {
                    entered.notify_one();
                    release.acquire().await.unwrap().forget();
                    Err(crate::Error::Config("permanent after wait".into()))
                })
            }
        }),
        observed_renew: None,
        certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
        revocations: Arc::new(Markers::default()),
        ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
        ari_manager: None,
    };
    let jobs = JobQueue::certificate_jobs("inflight-options");
    check_renewals_with_backoff(&cache, &policy, &jobs, &backoff).await;
    entered.notified().await;
    advance(Duration::from_secs(100)).await;
    cache
        .set_options(options(
            Duration::from_secs(1200),
            Duration::from_secs(3600),
        ))
        .await;
    let completion = tokio::time::Instant::now();
    release.add_permits(1);
    wait_for_renewal_jobs(&jobs).await;
    assert_eq!(
        backoff.deadline(),
        Some(completion + Duration::from_secs(1200))
    );
    jobs.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn panic_recovery_adopts_latest_options_and_stop_still_joins() {
    let fixture = Fixture::new(
        options(Duration::from_millis(20), Duration::from_secs(3600)),
        None,
    )
    .await;
    settle().await;
    fixture.storage.panic_next.store(true, Ordering::SeqCst);
    advance(Duration::from_millis(20)).await;
    assert_eq!(fixture.reads(), 1);
    fixture
        .cache
        .set_options(options(
            Duration::from_millis(50),
            Duration::from_secs(3600),
        ))
        .await;
    advance(Duration::from_secs(2)).await;
    advance(Duration::from_millis(49)).await;
    assert_eq!(
        fixture.reads(),
        1,
        "restart must wait a full latest interval"
    );
    advance(Duration::from_millis(1)).await;
    assert_eq!(fixture.reads(), 2);
    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn ari_notifications_and_transient_retry_deadlines_survive_interval_updates() {
    let cache = CertCache::new(options(
        Duration::from_secs(3600),
        Duration::from_secs(3600),
    ));
    let mut cert = certificate(false);
    let selected = chrono::Utc::now() - chrono::Duration::seconds(1);
    cert.ari = Some(crate::RenewalInfo {
        suggested_window: Some(crate::RenewalWindow {
            start: (selected - chrono::Duration::seconds(1)).to_rfc3339(),
            end: (selected + chrono::Duration::seconds(1)).to_rfc3339(),
        }),
        selected_time: Some(selected),
        ..Default::default()
    });
    cache.add(cert).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = RenewalPolicy {
        renew: Arc::new({
            let calls = calls.clone();
            move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(crate::Error::Other("temporary".into())) })
            }
        }),
        observed_renew: None,
        certificates: Arc::new(crate::cert_store::tests::InMemory::default()),
        revocations: Arc::new(Markers::default()),
        ratio: DEFAULT_RENEWAL_WINDOW_RATIO,
        ari_manager: None,
    };
    let intervals = IntervalSource::Cache(cache.subscribe_maintenance_intervals());
    let handle = start_maintenance_impl(
        cache.clone(),
        MaintenanceConfig {
            renew_check_interval: Duration::from_secs(3600),
            ocsp_check_interval: Duration::from_secs(3600),
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
            storage: Arc::new(Markers::default()),
        },
        policy,
        intervals,
    );
    settle().await;
    cache
        .set_options(options(
            Duration::from_secs(7200),
            Duration::from_secs(7200),
        ))
        .await;
    cache.notify_ari();
    settle().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "ARI must not wait for the updated periodic timer"
    );
    advance(Duration::from_secs(30)).await;
    cache
        .set_options(options(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        ))
        .await;
    settle().await;
    advance(Duration::from_secs(29)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    advance(Duration::from_secs(1)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a transient retry keeps its original deadline"
    );
    cache.stop_and_wait().await;
    handle.await.unwrap();
}

#[tokio::test]
async fn extending_periodic_intervals_does_not_delay_a_due_ocsp_refresh() {
    use tokio::io::AsyncWriteExt;
    let cache = CertCache::new(options(
        Duration::from_secs(3600),
        Duration::from_secs(3600),
    ));
    let (mut cert, issuer) = super::tests::signed_certificate();
    cert.managed = false;
    let old = crate::cache::tests::signed_staple(&cert, &issuer, 8);
    let replacement = crate::cache::tests::signed_staple(&cert, &issuer, 3600);
    cert.ocsp_status = Some(ocsp::OcspStatus::Good);
    cert.ocsp_response = Some(old.clone());
    let domain = cert.names[0].clone();
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(directory.path()));
    storage
        .store(&crate::storage::ocsp_key(&domain, &cert.hash), &old)
        .await
        .unwrap();
    cache.add(cert).await;
    let deadline = cache.next_ocsp_deadline().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let body = replacement.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        super::tests::read_ocsp_request(&mut socket).await;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(&body).await.unwrap();
    });
    let mut ocsp = OcspConfig::default();
    ocsp.responder_overrides.insert(domain.clone(), url);
    let manager = crate::CertManager::builder()
        .cache(cache.clone())
        .storage(storage)
        .disable_ari(true)
        .ocsp(ocsp)
        .build();
    let handle = crate::start_maintenance(&manager);
    for hours in 2..=5 {
        cache
            .set_options(options(
                Duration::from_secs(hours * 3600),
                Duration::from_secs(hours * 3600),
            ))
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(cache.next_ocsp_deadline(), Some(deadline));
    }
    tokio::time::timeout(Duration::from_secs(6), async {
        while cache.resolve(&domain).unwrap().key.ocsp.as_ref() != Some(&replacement) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("period changes must not postpone the independent due-index refresh");
    cache.stop_and_wait().await;
    handle.await.unwrap();
    server.await.unwrap();
}
