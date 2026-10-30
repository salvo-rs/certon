use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::io::AsyncWriteExt;

use super::tests::{read_ocsp_request, signed_certificate};
use super::*;

struct Fixture {
    cache: Arc<CertCache>,
    storage: Arc<crate::FileStorage>,
    config: OcspConfig,
    cert: Certificate,
    issuer: rcgen::KeyPair,
    raw: Vec<u8>,
    reply: Arc<Mutex<(u16, Vec<u8>)>>,
    calls: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Semaphore>,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(remaining: i64) -> Self {
        let (mut cert, issuer) = signed_certificate();
        cert.managed = false;
        let raw = crate::ocsp::tests::signed_response(
            &cert.cert_chain,
            &issuer,
            0,
            Utc::now() - ChronoDuration::hours(49),
            Utc::now() + ChronoDuration::seconds(remaining),
        );
        cert.ocsp_status = Some(ocsp::OcspStatus::Good);
        cert.ocsp_response = Some(raw.clone());
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::FileStorage::new(directory.path()));
        storage
            .store(&crate::storage::ocsp_key(&cert.names[0], &cert.hash), &raw)
            .await
            .unwrap();
        let cache = CertCache::new(crate::CacheOptions::default());
        cache.add(cert.clone()).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let reply = Arc::new(Mutex::new((200, raw.clone())));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let server = tokio::spawn({
            let reply = reply.clone();
            let calls = calls.clone();
            let gate = gate.clone();
            async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    read_ocsp_request(&mut socket).await;
                    calls.fetch_add(1, Ordering::SeqCst);
                    // A 0 status models an in-flight request that can be cancelled.
                    let (mut status, body) = reply.lock().unwrap().clone();
                    if status == 0 {
                        gate.acquire().await.unwrap().forget();
                        status = 200;
                    }
                    let header = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if socket.write_all(header.as_bytes()).await.is_ok() {
                        let _ = socket.write_all(&body).await;
                    }
                }
            }
        });
        let mut config = OcspConfig::default();
        config
            .responder_overrides
            .insert(cert.names[0].clone(), url);
        Self {
            cache,
            storage,
            config,
            cert,
            issuer,
            raw,
            reply,
            calls,
            gate,
            server,
            _directory: directory,
        }
    }

    async fn refresh(&self) {
        update_ocsp_staples(&self.cache, self.storage.as_ref(), &self.config, &|_, _| {
            Box::pin(async { Ok(()) })
        })
        .await;
    }

    fn force_due(&self) {
        crate::cache::tests::force_ocsp_due(&self.cache, &self.cert.hash);
    }

    fn delay(&self) -> ChronoDuration {
        self.cache.next_ocsp_deadline().unwrap() - Utc::now()
    }

    fn respond(&self, status: u16, raw: Vec<u8>) {
        *self.reply.lock().unwrap() = (status, raw);
    }

    fn signed(&self, status: u8, remaining: i64) -> Vec<u8> {
        crate::ocsp::tests::signed_response(
            &self.cert.cert_chain,
            &self.issuer,
            status,
            Utc::now() - ChronoDuration::hours(49),
            Utc::now() + ChronoDuration::seconds(remaining),
        )
    }
}

#[tokio::test]
async fn long_lived_unchanged_good_refreshes_back_off_and_index_gates_network_work() {
    let fixture = Fixture::new(47 * 3600).await;
    assert!(
        fixture.cache.next_ocsp_deadline().unwrap() < Utc::now(),
        "first midpoint refresh must remain due"
    );
    for (step, maximum) in [(1, 60), (2, 120), (3, 240), (4, 300), (5, 300)] {
        if step > 1 {
            fixture.force_due();
        }
        fixture.refresh().await;
        assert_eq!(fixture.calls.load(Ordering::SeqCst), step);
        let delay = fixture.delay().num_milliseconds();
        assert!(
            delay >= maximum * 800 - 1000 && delay <= maximum * 1000,
            "step={step} delay={delay}"
        );
        for _ in 0..3 {
            fixture.refresh().await;
        }
        assert_eq!(
            fixture.calls.load(Ordering::SeqCst),
            step,
            "a future retry must gate the actual responder request"
        );
        assert_eq!(
            fixture
                .cache
                .resolve(&fixture.cert.names[0])
                .unwrap()
                .key
                .ocsp
                .as_ref(),
            Some(&fixture.raw)
        );
    }
}

#[tokio::test]
async fn changed_good_network_failures_and_invalid_signatures_do_not_receive_unchanged_backoff() {
    let fixture = Fixture::new(47 * 3600).await;
    fixture.refresh().await;
    assert!(fixture.delay() > ChronoDuration::seconds(45));
    let changed = fixture.signed(0, 46 * 3600);
    fixture.respond(200, changed.clone());
    fixture.force_due();
    fixture.refresh().await;
    assert!(fixture.delay() <= ChronoDuration::seconds(30));
    let boundary = Fixture::new(3620).await;
    boundary.refresh().await;
    assert_eq!(boundary.calls.load(Ordering::SeqCst), 1);
    assert!(boundary.delay() > ChronoDuration::zero());
    assert!(
        boundary.delay() <= ChronoDuration::seconds(20),
        "retry must enter the one-hour urgent window on time"
    );
    assert_eq!(
        fixture
            .cache
            .resolve(&fixture.cert.names[0])
            .unwrap()
            .key
            .ocsp
            .as_ref(),
        Some(&changed)
    );
    fixture.force_due();
    fixture.refresh().await;
    assert!(fixture.delay() > ChronoDuration::seconds(45));
    // Public Ok(true) still uses a fresh fallback, but it is not proof of a
    // successful network response. Signature failure follows the same policy.
    let mut invalid = changed.clone();
    *invalid.last_mut().unwrap() ^= 1;
    for (status, raw) in [(503, b"offline".to_vec()), (200, invalid)] {
        fixture.respond(status, raw);
        fixture.force_due();
        fixture.refresh().await;
        assert!(fixture.delay() <= ChronoDuration::seconds(30));
        assert_eq!(
            fixture
                .cache
                .resolve(&fixture.cert.names[0])
                .unwrap()
                .key
                .ocsp
                .as_ref(),
            Some(&changed)
        );
        fixture.respond(200, changed.clone());
        fixture.force_due();
        fixture.refresh().await;
        assert!(
            fixture.delay() > ChronoDuration::seconds(45)
                && fixture.delay() <= ChronoDuration::seconds(60),
            "failed refresh must reset the streak"
        );
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn urgent_good_unknown_and_revoked_responses_keep_short_retries_and_revocation_sticky() {
    let fixture = Fixture::new(1800).await;
    fixture.refresh().await;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert!(fixture.delay() <= ChronoDuration::seconds(30));
    fixture.respond(200, fixture.signed(2, 47 * 3600));
    fixture.force_due();
    fixture.refresh().await;
    assert!(fixture.delay() <= ChronoDuration::seconds(30));
    assert!(
        fixture
            .cache
            .resolve(&fixture.cert.names[0])
            .unwrap()
            .key
            .ocsp
            .is_none()
    );
    // A separate fresh cache exercises an actual revoked network response;
    // the Unknown cache above intentionally reuses its cached signed status.
    let revoked = Fixture::new(47 * 3600).await;
    revoked.respond(200, revoked.signed(1, 47 * 3600));
    revoked.refresh().await;
    assert_eq!(revoked.calls.load(Ordering::SeqCst), 1);
    assert!(revoked.cache.resolve(&revoked.cert.names[0]).is_none());
    assert!(revoked.delay() <= ChronoDuration::seconds(30));
    revoked.respond(200, revoked.raw.clone());
    revoked.force_due();
    revoked.refresh().await;
    assert!(
        revoked.cache.resolve(&revoked.cert.names[0]).is_none(),
        "a replay cannot revive a revoked leaf"
    );
}

#[tokio::test]
async fn cancelled_or_superseded_network_work_cannot_extend_a_newer_publication() {
    for cancel in [true, false] {
        let fixture = Fixture::new(47 * 3600).await;
        fixture.respond(0, fixture.raw.clone());
        let (forced, _receiver) = ForcedRenewals::new();
        let task = tokio::spawn({
            let cache = fixture.cache.clone();
            let storage = fixture.storage.clone();
            let config = fixture.config.clone();
            async move {
                let cert = cache.maintenance_snapshot(false).pop().unwrap();
                refresh_ocsp_certificate(&cache, storage.as_ref(), &config, &forced, cert).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert!(fixture.cache.next_ocsp_deadline().unwrap() < Utc::now());
        } else {
            // Publish the same signed bytes while the old HTTP request waits.
            // Byte equality alone must not authorize the longer retry.
            fixture
                .cache
                .update_ocsp_if_present(
                    &fixture.cert.hash,
                    Some(ocsp::OcspStatus::Good),
                    Some(fixture.raw.clone()),
                )
                .await
                .unwrap();
            fixture.gate.add_permits(1);
            task.await.unwrap();
            assert!(fixture.delay() <= ChronoDuration::seconds(30));
        }
    }
}
