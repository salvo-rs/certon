use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use certon::{
    CertIssuer, CertManager, CertStore, CertificateResource, FileStorage, IssuedCertificate,
    OcspConfig, Result, Storage,
};
use chrono::Datelike;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
use tokio::sync::Notify;
use x509_parser::prelude::FromDer;
struct CsrPublicKey(Vec<u8>);
impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct TestIssuer {
    ca: rcgen::Issuer<'static, KeyPair>,
    root: rustls::pki_types::CertificateDer<'static>,
    calls: AtomicUsize,
    mode: AtomicU8,
    entered: Notify,
    name: &'static str,
    not_before_year: i32,
    not_after_year: i32,
    revoke_calls: AtomicUsize,
    revoke_mode: AtomicU8,
    revoke_entered: Notify,
    revoke_release: Notify,
    issue_release: Notify,
    revoked: std::sync::Mutex<Vec<Vec<u8>>>,
}
impl TestIssuer {
    fn new() -> Self {
        let mut params = CertificateParams::new(vec!["test-root".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        Self {
            ca: rcgen::Issuer::new(params, key),
            root,
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            entered: Notify::new(),
            name: "test-ca",
            not_before_year: chrono::Utc::now().year() - 2,
            not_after_year: chrono::Utc::now().year() + 4,
            revoke_calls: AtomicUsize::new(0),
            revoke_mode: AtomicU8::new(0),
            revoke_entered: Notify::new(),
            revoke_release: Notify::new(),
            issue_release: Notify::new(),
            revoked: std::sync::Mutex::new(Vec::new()),
        }
    }
}
#[async_trait::async_trait]
impl CertIssuer for TestIssuer {
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        let serial = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 3 {
            self.entered.notify_one();
            self.issue_release.notified().await;
        }
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = CsrPublicKey(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let mut params = CertificateParams::new(domains.to_vec()).unwrap();
        params.serial_number = Some((serial as u64).into());
        params.not_before = rcgen::date_time_ymd(self.not_before_year, 1, 1);
        params.not_after = rcgen::date_time_ymd(self.not_after_year, 1, 1);
        let cert = params.signed_by(&public, &self.ca).unwrap();
        Ok(IssuedCertificate {
            certificate_pem: cert.pem().into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    fn as_revoker(&self) -> Option<&dyn certon::Revoker> {
        Some(self)
    }
    fn issuer_key(&self) -> String {
        self.name.into()
    }
}
#[async_trait::async_trait]
impl certon::Revoker for TestIssuer {
    // Deliberately implement only the original PEM method: manager must keep
    // existing third-party Revokers compatible through the resource default.
    async fn revoke(&self, pem: &[u8], _reason: Option<u8>) -> Result<()> {
        self.revoke_calls.fetch_add(1, Ordering::SeqCst);
        assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        self.revoked.lock().unwrap().push(pem.to_vec());
        self.revoke_entered.notify_one();
        match self.revoke_mode.load(Ordering::SeqCst) {
            1 => self.revoke_release.notified().await,
            2 => return Err(certon::Error::Other("provider unavailable".into())),
            3 => panic!("provider panic"),
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct TestStore {
    resource: std::sync::Mutex<Option<CertificateResource>>,
    fail_remove: std::sync::atomic::AtomicBool,
    removed: Notify,
    gate_remove: std::sync::atomic::AtomicBool,
    remove_entered: Notify,
    remove_release: Notify,
}
#[async_trait::async_trait]
impl CertStore for TestStore {
    async fn load(&self, _issuer: &str, _domain: &str) -> Result<Option<CertificateResource>> {
        Ok(self.resource.lock().unwrap().clone())
    }
    async fn save(&self, _issuer: &str, resource: &CertificateResource) -> Result<()> {
        *self.resource.lock().unwrap() = Some(resource.clone());
        Ok(())
    }
    async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
        Ok(self.load(issuer, domain).await?.is_some())
    }
    async fn remove(&self, _issuer: &str, _domain: &str) -> Result<()> {
        if self.gate_remove.load(Ordering::SeqCst) {
            self.remove_entered.notify_one();
            self.remove_release.notified().await;
        }
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(certon::Error::Other("injected remove failure".into()));
        }
        *self.resource.lock().unwrap() = None;
        self.removed.notify_one();
        Ok(())
    }
}

fn manager(
    storage: Arc<dyn Storage>,
    store: Arc<dyn CertStore>,
    issuer: Arc<TestIssuer>,
) -> Arc<CertManager> {
    Arc::new(
        CertManager::builder()
            .storage(storage)
            .certificates(store)
            .issuers(vec![issuer])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build(),
    )
}

async fn handshake(
    manager: &CertManager,
    issuer: &TestIssuer,
) -> std::result::Result<Vec<u8>, String> {
    certon::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(issuer.root.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (server_io, client_io) = tokio::io::duplex(16384);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(manager.server_config()));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let (server, client) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect("example.com".try_into().unwrap(), client_io)
    );
    server.map_err(|error| error.to_string())?;
    Ok(client
        .map_err(|error| error.to_string())?
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()[0]
        .to_vec())
}

async fn fixture() -> (
    tempfile::TempDir,
    Arc<dyn Storage>,
    Arc<TestStore>,
    Arc<TestIssuer>,
    Arc<CertManager>,
) {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let store = Arc::new(TestStore::default());
    let issuer = Arc::new(TestIssuer::new());
    let manager = manager(storage.clone(), store.clone(), issuer.clone());
    manager.manage(&["example.com".into()]).await.unwrap();
    assert!(handshake(&manager, &issuer).await.is_ok());
    (directory, storage, store, issuer, manager)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledged_revocation_stays_quarantined_after_remove_failure_and_retry() {
    let (_dir, storage, store, issuer, manager) = fixture().await;
    let old = manager.cache.get_all().await[0].clone();
    store.fail_remove.store(true, Ordering::SeqCst);
    assert!(manager.revoke("example.com", Some(1)).await.is_err());
    assert!(
        handshake(&manager, &issuer).await.is_err(),
        "CA-revoked leaf is still served after cleanup failure"
    );
    assert!(manager.load_certificate("example.com").await.is_err());
    // Even a stale in-flight cache publisher or alternate chain cannot restore the leaf.
    let mut alternate = old.clone();
    alternate.cert_chain.push(issuer.root.clone());
    alternate.hash = certon::certificates::hash_certificate_chain(&alternate.cert_chain);
    manager.cache.add(old).await;
    manager.cache.add(alternate).await;
    assert!(handshake(&manager, &issuer).await.is_err());
    let restarted = self::manager(storage, store.clone(), issuer.clone());
    assert!(restarted.manage(&["example.com".into()]).await.is_err());
    store.fail_remove.store(false, Ordering::SeqCst);
    restarted.revoke("example.com", None).await.unwrap();
    assert!(store.resource.lock().unwrap().is_none());
    assert_eq!(
        issuer.revoke_calls.load(Ordering::SeqCst),
        1,
        "confirmed cleanup retry must not revoke twice"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_does_not_interrupt_revocation_or_restore_the_leaf() {
    let (_dir, storage, store, issuer, manager) = fixture().await;
    issuer.revoke_mode.store(1, Ordering::SeqCst);
    let worker = manager.clone();
    let task = tokio::spawn(async move { worker.revoke("example.com", None).await });
    issuer.revoke_entered.notified().await;
    assert!(
        handshake(&manager, &issuer).await.is_err(),
        "revocation intent must quarantine before CA I/O"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        self::manager(storage, store.clone(), issuer.clone())
            .load_certificate("example.com")
            .await
            .is_err()
    );
    issuer.revoke_release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), store.removed.notified())
        .await
        .unwrap();
    assert!(store.resource.lock().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_failure_and_panic_leave_intent_blocked_and_errors_visible() {
    for mode in [2, 3] {
        let (_dir, storage, store, issuer, manager) = fixture().await;
        issuer.revoke_mode.store(mode, Ordering::SeqCst);
        let error = manager
            .revoke("example.com", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(if mode == 3 {
            "revocation task failed"
        } else {
            "provider unavailable"
        }));
        assert!(handshake(&manager, &issuer).await.is_err());
        assert!(
            self::manager(storage, store, issuer.clone())
                .load_certificate("example.com")
                .await
                .is_err()
        );
        issuer.revoke_mode.store(0, Ordering::SeqCst);
        manager.revoke("example.com", None).await.unwrap();
        assert_eq!(issuer.revoke_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_waits_for_renewal_and_revokes_the_new_leaf() {
    let (_dir, _storage, _store, issuer, manager) = fixture().await;
    let old = handshake(&manager, &issuer).await.unwrap();
    issuer.mode.store(3, Ordering::SeqCst);
    let renew_manager = manager.clone();
    let renewal = tokio::spawn(async move { renew_manager.renew("example.com", true).await });
    issuer.entered.notified().await;
    let revoke_manager = manager.clone();
    let revocation = tokio::spawn(async move { revoke_manager.revoke("EXAMPLE.COM", None).await });
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(80),
            issuer.revoke_entered.notified()
        )
        .await
        .is_err(),
        "revoke ignored the renewal lock"
    );
    issuer.issue_release.notify_one();
    renewal.await.unwrap().unwrap();
    revocation.await.unwrap().unwrap();
    let pem = {
        let revoked = issuer.revoked.lock().unwrap();
        pem::parse(&revoked[0]).unwrap()
    };
    assert_ne!(pem.contents(), old);
    assert!(handshake(&manager, &issuer).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewal_waits_for_pending_revocation_and_cannot_publish_old_leaf() {
    let (_dir, _storage, _store, issuer, manager) = fixture().await;
    issuer.revoke_mode.store(1, Ordering::SeqCst);
    let revoke_manager = manager.clone();
    let revocation = tokio::spawn(async move { revoke_manager.revoke("example.com", None).await });
    issuer.revoke_entered.notified().await;
    let renew_manager = manager.clone();
    let mut renewal = tokio::spawn(async move { renew_manager.renew("example.com", true).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(80), &mut renewal)
            .await
            .is_err()
    );
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    issuer.revoke_release.notify_one();
    revocation.await.unwrap().unwrap();
    assert!(renewal.await.unwrap().is_err());
    assert!(handshake(&manager, &issuer).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn externally_replaced_resource_and_cache_are_not_deleted_by_old_revocation() {
    let (_dir, _storage, store, issuer, manager) = fixture().await;
    issuer.revoke_mode.store(1, Ordering::SeqCst);
    let revoke_manager = manager.clone();
    let revocation = tokio::spawn(async move { revoke_manager.revoke("example.com", None).await });
    issuer.revoke_entered.notified().await;
    // Simulate a custom store writer which bypasses certon's lifecycle lock.
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    let domains = vec!["example.com".into()];
    let csr = certon::crypto::generate_csr(&key, &domains, false).unwrap();
    let issued = issuer.issue(&csr, &domains).await.unwrap();
    let resource = CertificateResource {
        sans: domains,
        certificate_pem: issued.certificate_pem,
        private_key_pem: certon::crypto::encode_private_key_pem(&key)
            .unwrap()
            .into_bytes(),
        issuer_key: issuer.issuer_key(),
        issuer_data: None,
    };
    store.save(&issuer.issuer_key(), &resource).await.unwrap();
    let mut fresh =
        certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
            .unwrap();
    fresh.managed = true;
    manager.cache.add(fresh.clone()).await;
    issuer.revoke_release.notify_one();
    revocation.await.unwrap().unwrap();
    assert_eq!(
        store
            .resource
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .certificate_pem,
        resource.certificate_pem
    );
    assert_eq!(
        handshake(&manager, &issuer).await.unwrap(),
        fresh.cert_chain[0].as_ref()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_during_cleanup_keeps_confirmed_revocation_running() {
    let (_dir, _storage, store, issuer, manager) = fixture().await;
    store.gate_remove.store(true, Ordering::SeqCst);
    let worker = manager.clone();
    let task = tokio::spawn(async move { worker.revoke("example.com", None).await });
    store.remove_entered.notified().await;
    assert_eq!(issuer.revoke_calls.load(Ordering::SeqCst), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(handshake(&manager, &issuer).await.is_err());
    store.remove_release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), store.removed.notified())
        .await
        .unwrap();
    assert!(store.resource.lock().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_live_instances_quarantine_on_explicit_shared_marker_refresh() {
    let (_dir, storage, store, issuer, manager) = fixture().await;
    let peer = self::manager(storage.clone(), store.clone(), issuer.clone());
    let maintenance_peer = self::manager(storage.clone(), store, issuer.clone());
    peer.manage(&["example.com".into()]).await.unwrap();
    maintenance_peer
        .manage(&["example.com".into()])
        .await
        .unwrap();
    manager.revoke("example.com", None).await.unwrap();
    // This boundary is deliberate: no cross-process push protocol is claimed.
    assert!(handshake(&peer, &issuer).await.is_ok());
    assert_eq!(peer.refresh_revocations().await.unwrap(), 1);
    assert!(handshake(&peer, &issuer).await.is_err());
    let maintenance = certon::maintain::start_maintenance(
        maintenance_peer.cache.clone(),
        certon::maintain::MaintenanceConfig {
            renew_check_interval: std::time::Duration::from_millis(5),
            ocsp_check_interval: std::time::Duration::from_millis(5),
            storage,
            ocsp: OcspConfig {
                disable_stapling: true,
                ..Default::default()
            },
        },
        Arc::new(|_| {
            Box::pin(async {
                panic!("fresh revoked leaf must be quarantined, not renewed implicitly")
            })
        }),
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !maintenance_peer.cache.get_all().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(handshake(&maintenance_peer, &issuer).await.is_err());
    maintenance_peer.cache.stop_and_wait().await;
    maintenance.await.unwrap();
}

struct MarkerFaultStorage {
    inner: Arc<dyn Storage>,
    fail_read: std::sync::atomic::AtomicBool,
    fail_write: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl Storage for MarkerFaultStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        if key.starts_with("revocations/") && self.fail_write.load(Ordering::SeqCst) {
            return Err(certon::Error::Other("marker write unavailable".into()));
        }
        self.inner.store(key, value).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") && self.fail_read.load(Ordering::SeqCst) {
            return Err(certon::Error::Other("marker read unavailable".into()));
        }
        self.inner.load(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key).await
    }
    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        self.inner.list(path, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<certon::storage::KeyInfo> {
        self.inner.stat(key).await
    }
    async fn lock(&self, name: &str) -> Result<()> {
        self.inner.lock(name).await
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        self.inner.unlock(name).await
    }
}

#[tokio::test]
async fn intent_storage_failure_prevents_ca_call_and_failed_marker_reads_prevent_reload() {
    let (_dir, storage, store, issuer, _manager) = fixture().await;
    let faulty = Arc::new(MarkerFaultStorage {
        inner: storage.clone(),
        fail_read: false.into(),
        fail_write: true.into(),
    });
    let manager = self::manager(faulty.clone(), store.clone(), issuer.clone());
    assert!(
        manager
            .revoke("example.com", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("marker write unavailable")
    );
    assert_eq!(issuer.revoke_calls.load(Ordering::SeqCst), 0);
    assert!(
        manager
            .load_certificate("example.com")
            .await
            .unwrap()
            .is_some()
    );
    faulty.fail_write.store(false, Ordering::SeqCst);
    faulty.fail_read.store(true, Ordering::SeqCst);
    assert!(
        manager
            .load_certificate("example.com")
            .await
            .unwrap_err()
            .to_string()
            .contains("marker read unavailable")
    );
    faulty.fail_read.store(false, Ordering::SeqCst);
    issuer.revoke_mode.store(2, Ordering::SeqCst);
    assert!(manager.revoke("example.com", None).await.is_err());
    let keys = storage.list("revocations", true).await.unwrap();
    assert_eq!(keys.len(), 1);
    for bytes in [
        b"not-json".as_slice(),
        b"{\"version\":2,\"confirmed\":true}".as_slice(),
    ] {
        storage.store(&keys[0], bytes).await.unwrap();
        let restarted = self::manager(storage.clone(), store.clone(), issuer.clone());
        assert!(
            restarted
                .load_certificate("example.com")
                .await
                .unwrap_err()
                .to_string()
                .contains("revocation marker")
        );
    }
}

#[tokio::test]
async fn public_managed_reload_helper_cannot_bypass_persisted_intent() {
    let (_dir, storage, store, issuer, manager) = fixture().await;
    let resource = store.resource.lock().unwrap().clone().unwrap();
    certon::storage::store_certificate(storage.as_ref(), &issuer.issuer_key(), &resource)
        .await
        .unwrap();
    issuer.revoke_mode.store(2, Ordering::SeqCst);
    assert!(manager.revoke("example.com", None).await.is_err());
    let cache = certon::CertCache::new(Default::default());
    assert!(
        certon::certificates::reload_managed_certificate(
            &cache,
            storage.as_ref(),
            "example.com",
            &issuer.issuer_key()
        )
        .await
        .is_err()
    );
    assert!(cache.get_all().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_renewal_recovers_with_a_new_leaf_after_pending_or_confirmed_intent() {
    for confirmed in [false, true] {
        let (_dir, _storage, store, issuer, manager) = fixture().await;
        let old = manager.cache.get_all().await[0].clone();
        if confirmed {
            store.fail_remove.store(true, Ordering::SeqCst);
        } else {
            issuer.revoke_mode.store(2, Ordering::SeqCst);
        }
        assert!(manager.revoke("example.com", None).await.is_err());
        assert!(manager.renew("example.com", false).await.is_err());
        manager.renew("example.com", true).await.unwrap();
        let fresh = handshake(&manager, &issuer).await.unwrap();
        assert_ne!(fresh, old.cert_chain[0].as_ref());
        assert_eq!(
            manager
                .load_certificate("example.com")
                .await
                .unwrap()
                .unwrap()
                .cert_chain[0]
                .as_ref(),
            fresh
        );
        manager.cache.add(old).await;
        assert_eq!(handshake(&manager, &issuer).await.unwrap(), fresh);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_store_aliases_serialize_the_same_leaf_before_revoking_the_replacement() {
    let (_dir, _storage, store, issuer, manager) = fixture().await;
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    let names = vec!["example.com".into(), "alias.example.com".into()];
    let csr = certon::crypto::generate_csr(&key, &names, false).unwrap();
    let issued = issuer.issue(&csr, &names).await.unwrap();
    let resource = CertificateResource {
        sans: vec!["example.com".into()],
        certificate_pem: issued.certificate_pem,
        private_key_pem: certon::crypto::encode_private_key_pem(&key)
            .unwrap()
            .into_bytes(),
        issuer_key: issuer.issuer_key(),
        issuer_data: None,
    };
    store.save(&issuer.issuer_key(), &resource).await.unwrap();
    for cached in manager.cache.get_all().await {
        manager.cache.remove(&cached.hash).await;
    }
    manager.cache_certificate("example.com").await.unwrap();
    issuer.mode.store(3, Ordering::SeqCst);
    let worker = manager.clone();
    let renewal = tokio::spawn(async move { worker.renew("alias.example.com", true).await });
    issuer.entered.notified().await;
    let worker = manager.clone();
    let revocation = tokio::spawn(async move { worker.revoke("example.com", None).await });
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(80),
            issuer.revoke_entered.notified()
        )
        .await
        .is_err()
    );
    issuer.issue_release.notify_one();
    renewal.await.unwrap().unwrap();
    revocation.await.unwrap().unwrap();
    let revoked = { issuer.revoked.lock().unwrap()[0].clone() };
    assert_ne!(revoked, resource.certificate_pem);
    assert!(store.resource.lock().unwrap().is_none());
    assert!(handshake(&manager, &issuer).await.is_err());
}
