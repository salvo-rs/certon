use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::async_jobs::RetryConfig;
use certon::{
    CertIssuer, CertManager, FileStorage, IssuedCertificate, OcspConfig, Result, Storage,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
use x509_parser::prelude::FromDer;

struct TrackedStorage {
    inner: FileStorage,
    locks: Mutex<Vec<String>>,
    changed: tokio::sync::Notify,
    io: AtomicUsize,
    keys: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl Storage for TrackedStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.keys.lock().unwrap().push(key.into());
        self.io.fetch_add(1, Ordering::SeqCst);
        self.inner.store(key, value).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.keys.lock().unwrap().push(key.into());
        self.io.fetch_add(1, Ordering::SeqCst);
        self.inner.load(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.io.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.keys.lock().unwrap().push(key.into());
        self.io.fetch_add(1, Ordering::SeqCst);
        self.inner.exists(key).await
    }
    async fn list(&self, key: &str, recursive: bool) -> Result<Vec<String>> {
        self.io.fetch_add(1, Ordering::SeqCst);
        self.inner.list(key, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<certon::KeyInfo> {
        self.io.fetch_add(1, Ordering::SeqCst);
        self.inner.stat(key).await
    }
    async fn lock(&self, name: &str) -> Result<()> {
        self.locks.lock().unwrap().push(name.into());
        self.changed.notify_one();
        self.inner.lock(name).await
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        self.inner.unlock(name).await
    }
}

impl TrackedStorage {
    async fn wait_for_locks(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = self.changed.notified();
                if self.locks.lock().unwrap().len() >= count {
                    return;
                }
                changed.await;
            }
        })
        .await
        .unwrap();
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
    ca: rcgen::Issuer<'static, KeyPair>,
    root: rustls::pki_types::CertificateDer<'static>,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    failures: AtomicUsize,
    subjects: Mutex<Vec<Vec<String>>>,
}

#[async_trait::async_trait]
impl CertIssuer for Issuer {
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.subjects.lock().unwrap().push(domains.to_vec());
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(certon::Error::Other("temporary CA failure".into()));
        }
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = Public(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let leaf = CertificateParams::new(domains.to_vec())
            .unwrap()
            .signed_by(&public, &self.ca)
            .unwrap();
        Ok(IssuedCertificate {
            certificate_pem: leaf.pem().into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    fn issuer_key(&self) -> String {
        "canonical-test-ca".into()
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Arc<TrackedStorage>,
    issuer: Arc<Issuer>,
    manager: Arc<CertManager>,
    transforms: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(TrackedStorage {
            inner: FileStorage::new(directory.path()),
            locks: Mutex::new(Vec::new()),
            changed: tokio::sync::Notify::new(),
            io: AtomicUsize::new(0),
            keys: Mutex::new(Vec::new()),
        });
        let mut params = CertificateParams::new(vec!["test CA".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        let issuer = Arc::new(Issuer {
            ca: rcgen::Issuer::new(params, key),
            root,
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            failures: AtomicUsize::new(0),
            subjects: Mutex::new(Vec::new()),
        });
        let transforms = Arc::new(AtomicUsize::new(0));
        let manager = Arc::new(
            CertManager::builder()
                .storage(storage.clone())
                .issuers(vec![issuer.clone()])
                .background_retry_config(RetryConfig {
                    intervals: vec![Duration::from_millis(20)],
                    max_duration: Duration::from_secs(5),
                    max_retries: 3,
                })
                .ocsp(OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                })
                .subject_transformer(Arc::new({
                    let transforms = transforms.clone();
                    move |_| {
                        transforms.fetch_add(1, Ordering::SeqCst);
                        Ok("*.EXAMPLE.COM".into())
                    }
                }))
                .build(),
        );
        Self {
            _directory: directory,
            storage,
            issuer,
            manager,
            transforms,
        }
    }

    async fn handshake(&self, name: &'static str) {
        certon::install_default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.issuer.root.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (a, b) = tokio::io::duplex(16384);
        let server = tokio_rustls::TlsAcceptor::from(Arc::new(self.manager.server_config()));
        let client = tokio_rustls::TlsConnector::from(Arc::new(config));
        let (server, client) = tokio::join!(
            server.accept(a),
            client.connect(name.try_into().unwrap(), b)
        );
        assert!(server.is_ok());
        assert!(client.is_ok());
    }

    async fn wait_for_certificate(&self, name: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.manager.cache.get_by_name(name).await.is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("background issuance did not publish its certificate");
    }

    fn assert_no_alias_storage(&self) {
        let keys = self.storage.keys.lock().unwrap();
        assert!(
            keys.iter()
                .all(|key| !key.contains("/a.example.com/") && !key.contains("/b.example.com/")),
            "raw aliases were used for storage: {keys:?}"
        );
    }
}

#[tokio::test]
async fn aliases_share_the_canonical_lock_and_issue_only_one_wildcard() {
    let fixture = Fixture::new();
    let a = tokio::spawn({
        let manager = fixture.manager.clone();
        async move { manager.obtain("a.example.com").await }
    });
    tokio::time::timeout(Duration::from_secs(3), fixture.issuer.entered.notified())
        .await
        .unwrap();
    let b = tokio::spawn({
        let manager = fixture.manager.clone();
        async move { manager.obtain("b.example.com").await }
    });
    fixture.storage.wait_for_locks(2).await;
    let locks = fixture.storage.locks.lock().unwrap().clone();
    // Release before assertions so a deliberately broken implementation cannot
    // leave a worker or file lock behind during test teardown.
    fixture.issuer.release.add_permits(2);
    let (a, b) = tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(a, b) })
        .await
        .unwrap();
    a.unwrap().unwrap();
    b.unwrap().unwrap();
    assert_eq!(
        locks[0], locks[1],
        "aliases acquired different certificate locks"
    );
    assert!(locks[0].ends_with("*.example.com"));
    assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 2);
    assert!(
        fixture
            .manager
            .load_certificate("*.example.com")
            .await
            .unwrap()
            .is_some()
    );
    fixture.handshake("a.example.com").await;
    fixture.handshake("b.example.com").await;
}

#[tokio::test]
async fn a_canonical_storage_hit_does_not_take_an_alias_lock_or_transform_twice() {
    let fixture = Fixture::new();
    fixture.issuer.release.add_permits(1);
    fixture.manager.obtain("a.example.com").await.unwrap();
    fixture.manager.obtain("b.example.com").await.unwrap();
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.storage.locks.lock().unwrap().len(), 1);
    assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
    fixture.handshake("b.example.com").await;
}

#[tokio::test]
async fn invalid_or_rejected_transforms_fail_before_storage_and_locking() {
    for rejected in [false, true] {
        let fixture = Fixture::new();
        let manager = CertManager::builder()
            .storage(fixture.storage.clone())
            .issuers(vec![fixture.issuer.clone()])
            .subject_transformer(Arc::new(move |_| {
                if rejected {
                    Err(certon::Error::Config("alias denied".into()))
                } else {
                    Ok("invalid name".into())
                }
            }))
            .build();
        assert!(matches!(
            manager.obtain("a.example.com").await,
            Err(certon::Error::Config(_))
        ));
        assert!(matches!(
            manager.obtain_in_background("a.example.com").await,
            Err(certon::Error::Config(_))
        ));
        assert!(matches!(
            manager.manage(&["a.example.com".into()]).await,
            Err(certon::Error::Config(_))
        ));
        assert!(matches!(
            manager
                .manage_in_background(&["a.example.com".into()])
                .await,
            Err(certon::Error::Config(_))
        ));
        assert_eq!(fixture.storage.io.load(Ordering::SeqCst), 0);
        assert!(fixture.storage.locks.lock().unwrap().is_empty());
        assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn foreground_management_plans_with_canonical_storage_identity() {
    let fixture = Fixture::new();
    fixture.issuer.release.add_permits(1);
    fixture
        .manager
        .manage(&["a.example.com".into(), "b.example.com".into()])
        .await
        .unwrap();
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
    fixture.assert_no_alias_storage();
    fixture.handshake("a.example.com").await;
    fixture.handshake("b.example.com").await;
}

#[tokio::test]
async fn queued_retries_keep_one_canonical_identity_but_resubmission_transforms_again() {
    let mut fixture = Fixture::new();
    let transforms = fixture.transforms.clone();
    Arc::get_mut(&mut fixture.manager)
        .unwrap()
        .subject_transformer = Some(Arc::new(move |_| {
        if transforms.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok("*.EXAMPLE.COM".into())
        } else {
            Ok("*.CHANGED.EXAMPLE.NET".into())
        }
    }));
    fixture.issuer.failures.store(1, Ordering::SeqCst);
    fixture.issuer.release.add_permits(3);
    fixture
        .manager
        .manage_in_background(&["a.example.com".into()])
        .await
        .unwrap();
    fixture.wait_for_certificate("a.example.com").await;
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.issuer.subjects.lock().unwrap(),
        vec![vec!["*.example.com"], vec!["*.example.com"]]
    );
    fixture.assert_no_alias_storage();
    fixture.handshake("a.example.com").await;

    fixture
        .manager
        .manage_in_background(&["a.example.com".into()])
        .await
        .unwrap();
    fixture.wait_for_certificate("a.changed.example.net").await;
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.issuer.subjects.lock().unwrap().last().unwrap(),
        &["*.changed.example.net"]
    );
    fixture.handshake("a.changed.example.net").await;
}

#[tokio::test]
async fn queued_aliases_are_deduplicated_before_taking_lifecycle_locks() {
    let fixture = Fixture::new();
    fixture
        .manager
        .manage_in_background(&["a.example.com".into()])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), fixture.issuer.entered.notified())
        .await
        .unwrap();
    // More aliases than the queue's 68 records must still complete admission
    // while the first issuance is blocked. Distinct raw-name jobs would fill
    // admission and block this call, even before they could take a domain lock.
    let aliases = (0..1000)
        .map(|i| format!("alias-{i}.example.com"))
        .collect::<Vec<_>>();
    let submitted = tokio::time::timeout(
        Duration::from_secs(3),
        fixture.manager.manage_in_background(&aliases),
    )
    .await;
    fixture.issuer.release.add_permits(1001);
    submitted
        .expect("aliases exhausted background queue admission")
        .unwrap();
    fixture.wait_for_certificate("a.example.com").await;
    assert_eq!(
        fixture.storage.locks.lock().unwrap().len(),
        1,
        "aliases occupied separate queued jobs"
    );
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 1001);
    assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
    fixture.assert_no_alias_storage();
}

#[tokio::test(start_paused = true)]
async fn direct_background_obtain_retries_without_transforming_again() {
    let fixture = Fixture::new();
    fixture.issuer.failures.store(1, Ordering::SeqCst);
    fixture.issuer.release.add_permits(2);
    // File I/O and key generation use the blocking pool. Prevent auto-advance
    // from consuming their virtual deadline while waiting for real work.
    let keep_awake = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let obtain = tokio::spawn({
        let manager = fixture.manager.clone();
        async move { manager.obtain_in_background("a.example.com").await }
    });
    fixture.issuer.entered.notified().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    obtain.await.unwrap().unwrap();
    keep_awake.abort();
    keep_awake.await.unwrap_err();
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.issuer.subjects.lock().unwrap(),
        vec![vec!["*.example.com"], vec!["*.example.com"]]
    );
    fixture.assert_no_alias_storage();
    fixture.handshake("a.example.com").await;
}

#[tokio::test]
async fn explicit_renewal_uses_the_managed_identifier_without_transforming() {
    let fixture = Fixture::new();
    fixture.issuer.release.add_permits(2);
    fixture.manager.obtain("a.example.com").await.unwrap();
    fixture.manager.renew("*.example.com", true).await.unwrap();
    assert_eq!(fixture.transforms.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.issuer.subjects.lock().unwrap(),
        vec![vec!["*.example.com"], vec!["*.example.com"]]
    );
    fixture.handshake("b.example.com").await;
}
