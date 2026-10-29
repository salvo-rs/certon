use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore};

use super::*;
use crate::cache::CacheOptions;

fn certificate(name: &str, must_staple: bool) -> (Certificate, rcgen::KeyPair) {
    let issuer_key = rcgen::KeyPair::generate().unwrap();
    let mut issuer = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let root = issuer.self_signed(&issuer_key).unwrap();
    let issuer = rcgen::Issuer::new(issuer, &issuer_key);
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    if must_staple {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 3, 2, 1, 5],
            ));
    }
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &issuer).unwrap();
    let mut cert = Certificate::from_pem(
        format!("{}{}", leaf.pem(), root.pem()).as_bytes(),
        key.serialize_pem().as_bytes(),
    )
    .unwrap();
    cert.managed = true;
    (cert, issuer_key)
}

fn response(cert: &Certificate, key: &rcgen::KeyPair, status: u8, hours_ago: i64) -> Vec<u8> {
    crate::ocsp::tests::signed_response(
        &cert.cert_chain,
        key,
        status,
        Utc::now() - ChronoDuration::hours(hours_ago),
        Utc::now() + ChronoDuration::hours(1),
    )
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

struct Responder {
    url: String,
    entered: Arc<Notify>,
    release: Arc<Semaphore>,
    task: JoinHandle<()>,
}

impl Responder {
    async fn new(body: Vec<u8>, gated: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(usize::from(!gated)));
        let observed = entered.clone();
        let gate = release.clone();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 1024];
                let count = socket.read(&mut bytes).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&bytes[..count]);
                if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            observed.notify_one();
            let _permit = gate.acquire().await.unwrap();
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
        Self {
            url,
            entered,
            release,
            task,
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(storage: Arc<dyn Storage>, ocsp: OcspConfig) -> MaintenanceConfig {
    MaintenanceConfig {
        renew_check_interval: Duration::from_secs(3600),
        ocsp_check_interval: Duration::from_secs(3600),
        storage,
        ocsp,
    }
}

async fn tls(cache: Arc<CertCache>, cert: &Certificate) -> Vec<u8> {
    crate::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert_chain[1].clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(crate::handshake::CertResolver::new(cache)));
    let (server_io, client_io) = tokio::io::duplex(16384);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let name = rustls::pki_types::ServerName::try_from(cert.names[0].clone()).unwrap();
    let (server, client) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect(name, client_io)
    );
    server.unwrap();
    client.unwrap().get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

#[tokio::test]
async fn a_gated_responder_does_not_block_a_later_due_must_staple_refresh() {
    let cache = CertCache::new(CacheOptions::default());
    let (mut a, a_key) = certificate("slow-ocsp.example.com", false);
    let (mut b, b_key) = certificate("healthy-ocsp.example.com", true);
    a.ocsp_response = Some(response(&a, &a_key, 0, 4));
    b.ocsp_response = Some(response(&b, &b_key, 0, 2));
    let fresh_b = response(&b, &b_key, 0, 0);
    let slow = Responder::new(response(&a, &a_key, 0, 0), true).await;
    let healthy = Responder::new(fresh_b.clone(), false).await;
    let mut ocsp = OcspConfig::default();
    ocsp.responder_overrides
        .insert(a.names[0].clone(), slow.url.clone());
    ocsp.responder_overrides
        .insert(b.names[0].clone(), healthy.url.clone());
    cache.add(a.clone()).await;
    cache.add(b.clone()).await;
    assert_eq!(
        cache.ocsp_snapshot(false)[0].hash,
        a.hash,
        "the blocking responder must be first even with randomized HashMap order"
    );
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(directory.path()));
    let maintenance = start_maintenance(
        cache.clone(),
        config(storage, ocsp),
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );
    tokio::time::timeout(Duration::from_secs(5), slow.entered.notified())
        .await
        .unwrap();
    wait_for(|| {
        cache
            .resolve(&b.names[0])
            .is_some_and(|entry| entry.key.ocsp.as_ref() == Some(&fresh_b))
    })
    .await;
    assert_eq!(
        slow.release.available_permits(),
        0,
        "A is still explicitly gated"
    );
    assert_eq!(tls(cache.clone(), &b).await, b.cert_chain[0].as_ref());
    tokio::time::timeout(Duration::from_secs(5), cache.stop_and_wait())
        .await
        .unwrap();
    maintenance.await.unwrap();
}

#[tokio::test]
async fn a_blocked_force_renewal_does_not_block_a_new_must_staple_refresh() {
    let cache = CertCache::new(CacheOptions::default());
    let (mut a, a_key) = certificate("revoked-ocsp.example.com", false);
    a.ocsp_response = Some(response(&a, &a_key, 0, 4));
    let revoked = Responder::new(response(&a, &a_key, 1, 0), false).await;
    let (mut b, b_key) = certificate("later-ocsp.example.com", true);
    b.ocsp_response = Some(response(&b, &b_key, 0, 2));
    let fresh_b = response(&b, &b_key, 0, 0);
    let healthy = Responder::new(fresh_b.clone(), false).await;
    let mut ocsp = OcspConfig::default();
    ocsp.responder_overrides
        .insert(a.names[0].clone(), revoked.url.clone());
    ocsp.responder_overrides
        .insert(b.names[0].clone(), healthy.url.clone());
    cache.add(a).await;
    let active = Arc::new(AtomicUsize::new(0));
    let count = active.clone();
    let renewal: Arc<RenewFn> = Arc::new(move |_| {
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let count = count.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            let _active = Active(count);
            std::future::pending().await
        })
    });
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(directory.path()));
    let maintenance = start_maintenance(cache.clone(), config(storage, ocsp), renewal);
    wait_for(|| active.load(Ordering::SeqCst) == 1).await;
    // Publish only after the old force callback has started. A serial scanner
    // cannot observe B until that callback returns, independently of map order.
    cache.add(b.clone()).await;
    wait_for(|| {
        cache
            .resolve(&b.names[0])
            .is_some_and(|entry| entry.key.ocsp.as_ref() == Some(&fresh_b))
    })
    .await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_eq!(tls(cache.clone(), &b).await, b.cert_chain[0].as_ref());
    tokio::time::timeout(Duration::from_secs(5), cache.stop_and_wait())
        .await
        .unwrap();
    maintenance.await.unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_new_deadline_is_admitted_while_an_earlier_responder_is_still_gated() {
    let cache = CertCache::new(CacheOptions::default());
    let (mut a, a_key) = certificate("first-gated.example.com", false);
    a.ocsp_response = Some(response(&a, &a_key, 0, 4));
    let slow = Responder::new(response(&a, &a_key, 0, 0), true).await;
    let (mut b, b_key) = certificate("new-deadline.example.com", true);
    b.ocsp_response = Some(response(&b, &b_key, 0, 2));
    let fresh_b = response(&b, &b_key, 0, 0);
    let healthy = Responder::new(fresh_b.clone(), false).await;
    let mut ocsp = OcspConfig::default();
    ocsp.responder_overrides
        .insert(a.names[0].clone(), slow.url.clone());
    ocsp.responder_overrides
        .insert(b.names[0].clone(), healthy.url.clone());
    cache.add(a).await;
    let original_minimum = cache.next_ocsp_deadline();
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(directory.path()));
    let maintenance = start_maintenance(
        cache.clone(),
        config(storage, ocsp),
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );
    tokio::time::timeout(Duration::from_secs(5), slow.entered.notified())
        .await
        .unwrap();
    // This publication does not change the global minimum, still owned by A.
    // It must wake maintenance and enter an unused slot before A completes.
    cache.add(b.clone()).await;
    assert_eq!(cache.next_ocsp_deadline(), original_minimum);
    wait_for(|| {
        cache
            .resolve(&b.names[0])
            .is_some_and(|entry| entry.key.ocsp.as_ref() == Some(&fresh_b))
    })
    .await;
    assert_eq!(slow.release.available_permits(), 0);
    assert_eq!(tls(cache.clone(), &b).await, b.cert_chain[0].as_ref());
    tokio::time::timeout(Duration::from_secs(5), cache.stop_and_wait())
        .await
        .unwrap();
    maintenance.await.unwrap();
}

struct ActiveRead<'a>(&'a AtomicUsize);

impl Drop for ActiveRead<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct GatedReads {
    active: AtomicUsize,
    total: AtomicUsize,
    peak: AtomicUsize,
    release: Semaphore,
    markers_only: bool,
}

#[async_trait::async_trait]
impl Storage for GatedReads {
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if self.markers_only && key.starts_with("ocsp/") {
            return Err(crate::error::StorageError::NotFound(key.into()).into());
        }
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.total.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveRead(&self.active);
        let permit = self.release.acquire().await.unwrap();
        permit.forget();
        Err(crate::error::StorageError::NotFound("no stored staple".into()).into())
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
    async fn stat(&self, _: &str) -> Result<crate::storage::KeyInfo> {
        unreachable!()
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn maintenance_bounds_refreshes_and_drops_all_reads_on_stop_or_abort() {
    for abort in [false, true] {
        let cache = CertCache::new(CacheOptions::default());
        for index in 0..20 {
            let (mut cert, key) = certificate(&format!("bounded-{index}.example.com"), false);
            cert.ocsp_response = Some(response(&cert, &key, 0, 2));
            cache.add(cert).await;
        }
        let storage = Arc::new(GatedReads {
            active: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            release: Semaphore::new(0),
            markers_only: false,
        });
        let maintenance = start_maintenance(
            cache.clone(),
            config(storage.clone(), OcspConfig::default()),
            Arc::new(|_| Box::pin(async { Ok(()) })),
        );
        wait_for(|| storage.active.load(Ordering::SeqCst) == OCSP_REFRESH_CONCURRENCY).await;
        assert_eq!(
            storage.total.load(Ordering::SeqCst),
            OCSP_REFRESH_CONCURRENCY
        );
        // One completion admits exactly one replacement without opening the
        // remaining twelve reads or losing the concurrency bound.
        storage.release.add_permits(1);
        wait_for(|| storage.total.load(Ordering::SeqCst) == OCSP_REFRESH_CONCURRENCY + 1).await;
        assert_eq!(
            storage.peak.load(Ordering::SeqCst),
            OCSP_REFRESH_CONCURRENCY
        );
        if abort {
            maintenance.abort();
            assert!(maintenance.await.unwrap_err().is_cancelled());
        } else {
            cache.stop();
            maintenance.await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), cache.stop_and_wait())
            .await
            .unwrap();
        assert_eq!(storage.active.load(Ordering::SeqCst), 0);
        assert_eq!(
            storage.total.load(Ordering::SeqCst),
            OCSP_REFRESH_CONCURRENCY + 1
        );
    }
}

#[tokio::test]
async fn a_slow_periodic_marker_scan_does_not_stop_ocsp_responses_being_polled() {
    let cache = CertCache::new(CacheOptions::default());
    let (a, _) = certificate("marker-blocked.example.com", false);
    cache.add(a).await;
    let storage = Arc::new(GatedReads {
        active: AtomicUsize::new(0),
        total: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        release: Semaphore::new(0),
        markers_only: true,
    });
    let (mut b, key) = certificate("marker-independent.example.com", true);
    b.ocsp_response = Some(response(&b, &key, 0, 2));
    let fresh = response(&b, &key, 0, 0);
    let responder = Responder::new(fresh.clone(), false).await;
    let mut ocsp = OcspConfig::default();
    ocsp.responder_overrides
        .insert(b.names[0].clone(), responder.url.clone());
    let mut settings = config(storage.clone(), ocsp);
    settings.ocsp_check_interval = Duration::from_millis(20);
    let maintenance = start_maintenance(
        cache.clone(),
        settings,
        Arc::new(|_| Box::pin(async { Ok(()) })),
    );
    wait_for(|| storage.active.load(Ordering::SeqCst) == 1).await;
    cache.add(b.clone()).await;
    wait_for(|| {
        cache
            .resolve(&b.names[0])
            .is_some_and(|entry| entry.key.ocsp.as_ref() == Some(&fresh))
    })
    .await;
    assert_eq!(storage.active.load(Ordering::SeqCst), 1);
    assert_eq!(tls(cache.clone(), &b).await, b.cert_chain[0].as_ref());
    tokio::time::timeout(Duration::from_secs(5), cache.stop_and_wait())
        .await
        .unwrap();
    maintenance.await.unwrap();
    assert_eq!(storage.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn force_queue_has_a_hard_bound_deduplicates_and_releases_cancelled_leases() {
    let (queue, mut receiver) = ForcedRenewals::new();
    let (mut first, _) = certificate("deduplicated.example.com", false);
    first.ocsp_status = Some(ocsp::OcspStatus::Revoked);
    for _ in 0..1000 {
        queue.try_submit(&first, first.names[0].clone());
    }
    assert_eq!(receiver.len(), 1);
    for index in 0..FORCED_RENEWAL_BACKLOG + 10 {
        let (cert, _) = certificate(&format!("queued-{index}.example.com"), false);
        queue.try_submit(&cert, cert.names[0].clone());
    }
    assert_eq!(receiver.len(), FORCED_RENEWAL_BACKLOG);
    assert_eq!(queue.tracked.lock().unwrap().len(), FORCED_RENEWAL_BACKLOG);
    while let Ok(request) = receiver.try_recv() {
        drop(request);
    }
    assert!(queue.tracked.lock().unwrap().is_empty());
    queue.try_submit(&first, first.names[0].clone());
    assert_eq!(
        receiver.len(),
        1,
        "cancelled requests must be resubmittable"
    );
    drop(receiver);
    assert!(queue.tracked.lock().unwrap().is_empty());
    queue.try_submit(&first, first.names[0].clone());
    assert!(
        queue.tracked.lock().unwrap().is_empty(),
        "closed admission cannot leak deduplication state"
    );
}

#[tokio::test]
async fn queued_force_renewals_skip_removed_or_retagged_certificates() {
    let cache = CertCache::new(CacheOptions::default());
    let (queue, receiver) = ForcedRenewals::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for mutation in ["remove", "replace", "unmanage", "keep"] {
        let (mut cert, _) = certificate(&format!("{mutation}.example.com"), false);
        cert.ocsp_status = Some(ocsp::OcspStatus::Revoked);
        cache.add(cert.clone()).await;
        queue.try_submit(&cert, cert.names[0].clone());
        match mutation {
            "remove" => cache.remove(&cert.hash).await,
            "replace" => {
                let (replacement, _) = certificate(&cert.names[0], false);
                cache.replace(&cert.hash, replacement).await;
            }
            "unmanage" => {
                cert.managed = false;
                cache.replace(&cert.hash.clone(), cert).await;
            }
            _ => {}
        }
    }
    drop(queue);
    let observed = calls.clone();
    let renew: Arc<ReasonedRenewFn> = Arc::new(move |domain, _| {
        assert_eq!(domain, "keep.example.com");
        observed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    });
    run_forced_renewals(&cache, renew.as_ref(), None, receiver).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn saturated_force_renewals_never_hold_ocsp_admission_or_spin_the_due_index() {
    let cache = CertCache::new(CacheOptions::default());
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(directory.path()));
    let mut hashes = Vec::new();
    for index in 0..FORCED_RENEWAL_BACKLOG + FORCED_RENEWAL_CONCURRENCY + 4 {
        let (mut cert, key) = certificate(&format!("revoked-{index}.example.com"), false);
        cert.ocsp_response = Some(response(&cert, &key, 0, 2));
        storage
            .store(
                &crate::storage::ocsp_key(&cert.names[0], &cert.hash),
                &response(&cert, &key, 1, 0),
            )
            .await
            .unwrap();
        hashes.push(cert.hash.clone());
        cache.add(cert).await;
    }
    let active = Arc::new(AtomicUsize::new(0));
    let count = active.clone();
    let renew: Arc<RenewFn> = Arc::new(move |_| {
        let count = count.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveRead(&count);
            std::future::pending().await
        })
    });
    let (mut healthy, key) = certificate("saturated-healthy.example.com", true);
    healthy.ocsp_response = Some(response(&healthy, &key, 0, 2));
    let fresh = response(&healthy, &key, 0, 0);
    let responder = Responder::new(fresh.clone(), false).await;
    let mut ocsp = OcspConfig::default();
    ocsp.responder_overrides
        .insert(healthy.names[0].clone(), responder.url.clone());
    let mut settings = config(storage, ocsp);
    settings.ocsp_check_interval = Duration::from_millis(20);
    let maintenance = start_maintenance(cache.clone(), settings, renew);
    wait_for(|| {
        active.load(Ordering::SeqCst) == FORCED_RENEWAL_CONCURRENCY
            && hashes.iter().all(|hash| !cache.ocsp_refresh_due(hash))
    })
    .await;
    assert!(cache.next_ocsp_deadline().unwrap() > Utc::now());
    cache.add(healthy.clone()).await;
    wait_for(|| {
        cache
            .resolve(&healthy.names[0])
            .is_some_and(|entry| entry.key.ocsp.as_ref() == Some(&fresh))
    })
    .await;
    assert_eq!(active.load(Ordering::SeqCst), FORCED_RENEWAL_CONCURRENCY);
    assert_eq!(
        tls(cache.clone(), &healthy).await,
        healthy.cert_chain[0].as_ref()
    );
    tokio::time::timeout(Duration::from_secs(5), cache.stop_and_wait())
        .await
        .unwrap();
    maintenance.await.unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelling_force_workers_drops_callbacks_before_releasing_deduplication() {
    struct PendingCallback {
        tracked: Arc<Mutex<HashSet<String>>>,
        leaf: String,
        active: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl Future for PendingCallback {
        type Output = Result<()>;
        fn poll(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingCallback {
        fn drop(&mut self) {
            assert!(
                self.tracked.lock().unwrap().contains(&self.leaf),
                "same-leaf admission reopened before the callback's Drop"
            );
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    let cache = CertCache::new(CacheOptions::default());
    let (queue, receiver) = ForcedRenewals::new();
    let tracked = queue.tracked.clone();
    let active = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut leaves = std::collections::HashMap::new();
    for index in 0..FORCED_RENEWAL_CONCURRENCY + 2 {
        let (mut cert, _) = certificate(&format!("cancel-force-{index}.example.com"), false);
        cert.ocsp_status = Some(ocsp::OcspStatus::Revoked);
        leaves.insert(
            cert.names[0].clone(),
            crate::storage::certificate_leaf_hash(&cert).unwrap(),
        );
        cache.add(cert.clone()).await;
        queue.try_submit(&cert, cert.names[0].clone());
    }
    let observed_active = active.clone();
    let observed_drops = drops.clone();
    let observed_tracked = tracked.clone();
    let renew: Arc<ReasonedRenewFn> = Arc::new(move |name, _| {
        observed_active.fetch_add(1, Ordering::SeqCst);
        Box::pin(PendingCallback {
            tracked: observed_tracked.clone(),
            leaf: leaves[&name].clone(),
            active: observed_active.clone(),
            drops: observed_drops.clone(),
        })
    });
    let worker =
        tokio::spawn(
            async move { run_forced_renewals(&cache, renew.as_ref(), None, receiver).await },
        );
    wait_for(|| active.load(Ordering::SeqCst) == FORCED_RENEWAL_CONCURRENCY).await;
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert_eq!(drops.load(Ordering::SeqCst), FORCED_RENEWAL_CONCURRENCY);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(tracked.lock().unwrap().is_empty());
}

fn resource(cert: &Certificate) -> crate::CertificateResource {
    crate::CertificateResource {
        sans: vec![cert.names[0].clone()],
        issuer_key: "observed-CA".into(),
        issuer_data: None,
        certificate_pem: cert
            .cert_chain
            .iter()
            .map(|der| pem::encode(&pem::Pem::new("CERTIFICATE", der.as_ref())))
            .collect::<String>()
            .into_bytes(),
        private_key_pem: pem::encode(&pem::Pem::new(
            "PRIVATE KEY",
            cert.private_key_der.as_deref().unwrap(),
        ))
        .into_bytes(),
    }
}

struct NoIssuance(AtomicUsize);

#[async_trait::async_trait]
impl crate::CertIssuer for NoIssuance {
    fn issuer_key(&self) -> String {
        "observed-CA".into()
    }
    async fn issue(&self, _: &[u8], _: &[String]) -> Result<crate::IssuedCertificate> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(crate::Error::Other("test issuer rejects issuance".into()))
    }
}

#[tokio::test]
async fn delayed_default_force_renewal_reloads_a_shared_replacement_without_reissuing_it() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(crate::FileStorage::new(directory.path()));
    let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
    let issuer = Arc::new(NoIssuance(AtomicUsize::new(0)));
    let manager = Arc::new(
        crate::CertManager::builder()
            .storage(storage.clone())
            .certificates(certificates.clone())
            .issuers(vec![issuer.clone()])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build(),
    );
    let (mut old, _) = certificate("changed-resource.example.com", false);
    old.ocsp_status = Some(ocsp::OcspStatus::Revoked);
    certificates
        .save("observed-CA", &resource(&old))
        .await
        .unwrap();
    manager.cache.add(old.clone()).await;
    let leaf = crate::storage::certificate_leaf_hash(&old).unwrap();
    // Keep the old cache and storage until the force callback is queued behind
    // the domain lock; a separate instance publishes B during that wait.
    let guard = crate::storage::acquire(storage, "issue_cert_changed-resource.example.com")
        .await
        .unwrap();
    let worker_manager = manager.clone();
    let entered = Arc::new(Notify::new());
    let observed = entered.clone();
    let worker = tokio::spawn(async move {
        observed.notify_one();
        worker_manager
            .renew_observed_revocation("changed-resource.example.com", &leaf)
            .await
    });
    entered.notified().await;
    let (new, _) = certificate("changed-resource.example.com", false);
    certificates
        .save("observed-CA", &resource(&new))
        .await
        .unwrap();
    drop(guard);
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(issuer.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        tls(manager.cache.clone(), &new).await,
        new.cert_chain[0].as_ref()
    );
}

#[tokio::test]
async fn delayed_default_force_renewal_does_not_restore_removed_management() {
    for remove in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::FileStorage::new(directory.path()));
        let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
        let issuer = Arc::new(NoIssuance(AtomicUsize::new(0)));
        let manager = Arc::new(
            crate::CertManager::builder()
                .storage(storage.clone())
                .certificates(certificates.clone())
                .issuers(vec![issuer.clone()])
                .ocsp(OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                })
                .build(),
        );
        let (mut old, _) = certificate("changed-policy.example.com", false);
        old.ocsp_status = Some(ocsp::OcspStatus::Revoked);
        certificates
            .save("observed-CA", &resource(&old))
            .await
            .unwrap();
        manager.cache.add(old.clone()).await;
        let leaf = crate::storage::certificate_leaf_hash(&old).unwrap();
        let guard = crate::storage::acquire(storage, "issue_cert_changed-policy.example.com")
            .await
            .unwrap();
        let worker_manager = manager.clone();
        let entered = Arc::new(Notify::new());
        let observed = entered.clone();
        let worker = tokio::spawn(async move {
            observed.notify_one();
            worker_manager
                .renew_observed_revocation("changed-policy.example.com", &leaf)
                .await
        });
        entered.notified().await;
        if remove {
            manager.cache.remove(&old.hash).await;
        } else {
            old.managed = false;
            manager.cache.replace(&old.hash.clone(), old.clone()).await;
        }
        drop(guard);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(issuer.0.load(Ordering::SeqCst), 0);
        if remove {
            assert!(manager.cache.get_by_hash(&old.hash).await.is_none());
        } else {
            let current = manager.cache.get_by_hash(&old.hash).await.unwrap();
            assert!(!current.managed);
            assert_eq!(current.ocsp_status, Some(ocsp::OcspStatus::Revoked));
        }
        assert!(
            manager
                .cache
                .resolve("changed-policy.example.com")
                .is_none()
        );
    }
}

#[tokio::test]
async fn a_shared_revoked_replacement_keeps_its_retry_deadline_after_one_failed_recovery() {
    for imported in [false, true] {
        let (mut old, _) = certificate("new-revoked.example.com", false);
        old.ocsp_status = Some(ocsp::OcspStatus::Revoked);
        let (new, key) = certificate("new-revoked.example.com", false);
        let responder = Responder::new(response(&new, &key, 1, 0), false).await;
        let mut ocsp = OcspConfig::default();
        ocsp.responder_overrides
            .insert(new.names[0].clone(), responder.url.clone());
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::FileStorage::new(directory.path()));
        let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
        let issuer = Arc::new(NoIssuance(AtomicUsize::new(0)));
        let manager = crate::CertManager::builder()
            .storage(storage)
            .certificates(certificates.clone())
            .issuers(vec![issuer.clone()])
            .ocsp(ocsp)
            .build();
        certificates
            .save("observed-CA", &resource(&old))
            .await
            .unwrap();
        manager.cache.add(old.clone()).await;
        if imported {
            let mut unmanaged = new.clone().with_ocsp(response(&new, &key, 1, 0));
            unmanaged.managed = false;
            manager.cache.add(unmanaged).await;
            let cached = manager.cache.get_by_hash(&new.hash).await.unwrap();
            assert!(!cached.managed);
            assert_eq!(cached.ocsp_status, Some(ocsp::OcspStatus::Revoked));
            assert!(
                manager.cache.ocsp_refresh_due(&new.hash),
                "an untracked import starts without a retry deadline"
            );
        }
        let old_leaf = crate::storage::certificate_leaf_hash(&old).unwrap();
        certificates
            .save("observed-CA", &resource(&new))
            .await
            .unwrap();
        let error = manager
            .renew_observed_revocation(&old.names[0], &old_leaf)
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::Error::Other(message) if message == "test issuer rejects issuance")
        );
        assert_eq!(issuer.0.load(Ordering::SeqCst), 1);
        let current = manager.cache.get_by_hash(&new.hash).await.unwrap();
        assert!(current.managed);
        assert_eq!(current.ocsp_status, Some(ocsp::OcspStatus::Revoked));
        assert!(current.ocsp_response.is_none());
        assert!(manager.cache.resolve(&new.names[0]).is_none());
        // cache_certificate retains managed siblings for coverage. Later cleanup
        // of A must not remove the only recovery deadline for the newly revoked B.
        manager.cache.remove(&old.hash).await;
        assert!(manager.cache.get_by_hash(&old.hash).await.is_none());
        let deadline = manager.cache.next_ocsp_deadline().unwrap();
        assert!(deadline > Utc::now());
        assert!(deadline <= Utc::now() + ChronoDuration::seconds(30));
    }
}
