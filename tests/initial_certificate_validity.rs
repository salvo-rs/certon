use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use certon::{
    CertIssuer, CertManager, CertStore, CertificateResource, FileStorage, IssuedCertificate,
    KeyValueCertStore, OcspConfig, Result, Storage,
};
use chrono::Datelike;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
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
struct Issuer {
    ca: rcgen::Issuer<'static, KeyPair>,
    root: rustls::pki_types::CertificateDer<'static>,
    fail: AtomicBool,
    calls: AtomicUsize,
    requests: std::sync::Mutex<Vec<Vec<String>>>,
}
impl Issuer {
    fn new() -> Self {
        let mut params = CertificateParams::new(vec!["test-root".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        Self {
            ca: rcgen::Issuer::new(params, key),
            root,
            fail: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            requests: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn resource(&self, before: i32, after: i32) -> CertificateResource {
        self.resource_with_names(before, after, &["example.com"])
    }
    fn resource_with_names(&self, before: i32, after: i32, names: &[&str]) -> CertificateResource {
        let mut params =
            CertificateParams::new(names.iter().map(|name| (*name).into()).collect::<Vec<_>>())
                .unwrap();
        params.not_before = rcgen::date_time_ymd(before, 1, 1);
        params.not_after = rcgen::date_time_ymd(after, 1, 1);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.ca).unwrap();
        CertificateResource {
            sans: vec![names[0].into()],
            certificate_pem: cert.pem().into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
            issuer_key: self.issuer_key(),
            issuer_data: None,
        }
    }
}
#[async_trait::async_trait]
impl CertIssuer for Issuer {
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(domains.to_vec());
        if self.fail.load(Ordering::SeqCst) {
            return Err(certon::Error::Config("test CA is unavailable".into()));
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
        let year = chrono::Utc::now().year();
        // A successful renewal must leave even the takeover test's wide 95%
        // renewal window, so later ticks cannot race another publication.
        params.not_before = rcgen::date_time_ymd(1970, 1, 1)
            + Duration::from_secs((chrono::Utc::now().timestamp() - 60).try_into().unwrap());
        params.not_after = rcgen::date_time_ymd(year + 4, 1, 1);
        let cert = params.signed_by(&public, &self.ca).unwrap();
        Ok(IssuedCertificate {
            certificate_pem: cert.pem().into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    fn issuer_key(&self) -> String {
        "reload-test-ca".into()
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Arc<dyn Storage>,
    store: Arc<dyn CertStore>,
    issuer: Arc<Issuer>,
    manager: Arc<CertManager>,
    old: certon::Certificate,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
        let store: Arc<dyn CertStore> = Arc::new(KeyValueCertStore::new(storage.clone()));
        let issuer = Arc::new(Issuer::new());
        let year = chrono::Utc::now().year();
        let resource = issuer.resource(year - 4, year + 1);
        store.save(&issuer.issuer_key(), &resource).await.unwrap();
        let manager = Arc::new(
            CertManager::builder()
                .storage(storage.clone())
                .certificates(store.clone())
                .issuers(vec![issuer.clone()])
                .ocsp(OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                })
                .build(),
        );
        let old = manager.cache_certificate("example.com").await.unwrap();
        assert!(!old.expired());
        assert!(old.needs_renewal(1.0 / 3.0));
        Self {
            _directory: directory,
            storage,
            store,
            issuer,
            manager,
            old,
        }
    }
    async fn store_invalid(&self, future: bool) -> certon::Certificate {
        let year = chrono::Utc::now().year();
        let resource = if future {
            self.issuer.resource(year + 1, year + 5)
        } else {
            self.issuer.resource(year - 3, year - 1)
        };
        self.store
            .save(&self.issuer.issuer_key(), &resource)
            .await
            .unwrap();
        let mut cert =
            certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                .unwrap();
        cert.managed = true;
        cert.issuer_key = self.issuer.issuer_key();
        cert
    }
    async fn operation(&self, api: &str) -> Result<()> {
        match api {
            "manage" => self.manager.manage(&["example.com".into()]).await,
            "obtain" => self.manager.obtain("example.com").await,
            "cache" => self
                .manager
                .cache_certificate("example.com")
                .await
                .map(|_| ()),
            _ => panic!("unknown initial API"),
        }
    }
    async fn handshake(&self) -> Vec<u8> {
        self.try_handshake().await.unwrap()
    }
    async fn try_handshake(&self) -> std::result::Result<Vec<u8>, String> {
        self.try_handshake_for("example.com").await
    }
    async fn try_handshake_for(&self, domain: &str) -> std::result::Result<Vec<u8>, String> {
        certon::install_default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.issuer.root.clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (server_io, client_io) = tokio::io::duplex(16384);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(self.manager.server_config()));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (server, client) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(domain.to_owned().try_into().unwrap(), client_io)
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
}

async fn cold_repair(future: bool) {
    for api in ["manage", "obtain"] {
        let fixture = Fixture::new().await;
        fixture.manager.cache.remove(&fixture.old.hash).await;
        let invalid = fixture.store_invalid(future).await;
        let error = fixture.operation(api).await.expect_err(
            "invalid storage must not report a successful initial load when renewal fails",
        );
        assert!(
            error.to_string().contains("test CA is unavailable"),
            "{api}: {error}"
        );
        assert!(fixture.issuer.calls.load(Ordering::SeqCst) > 0);
        assert!(
            fixture.manager.cache.get_all().await.is_empty(),
            "{api} published an unusable leaf before failed renewal"
        );
        assert!(fixture.try_handshake().await.is_err());
        fixture.issuer.fail.store(false, Ordering::SeqCst);
        fixture.operation(api).await.unwrap();
        let served = fixture.handshake().await;
        assert_ne!(served, invalid.cert_chain[0].as_ref());
        let current = fixture
            .manager
            .cache
            .get_by_name("example.com")
            .await
            .unwrap();
        assert!(!current.expired());
        assert!(current.not_before <= chrono::Utc::now());
        assert_eq!(served, current.cert_chain[0].as_ref());
    }
}
#[tokio::test]
async fn initial_future_storage_is_repaired_before_manage_or_obtain_publish() {
    cold_repair(true).await;
}
#[tokio::test]
async fn initial_expired_storage_is_repaired_before_manage_or_obtain_publish() {
    cold_repair(false).await;
}

#[tokio::test]
async fn public_cache_rejects_invalid_storage_and_preserves_a_working_leaf() {
    for future in [true, false] {
        let fixture = Fixture::new().await;
        let invalid = fixture.store_invalid(future).await;
        match fixture.operation("cache").await.unwrap_err() {
            certon::Error::Cert(certon::error::CertError::NotYetValid(_)) => assert!(future),
            certon::Error::Cert(certon::error::CertError::Expired(_)) => assert!(!future),
            other => panic!("unexpected validity error: {other}"),
        }
        assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&invalid.hash)
                .await
                .is_none()
        );
        assert_eq!(
            fixture.handshake().await,
            fixture.old.cert_chain[0].as_ref()
        );
        let year = chrono::Utc::now().year();
        let valid = fixture.issuer.resource(year - 1, year + 4);
        fixture
            .store
            .save(&fixture.issuer.issuer_key(), &valid)
            .await
            .unwrap();
        fixture.operation("cache").await.unwrap();
        let expected =
            certon::Certificate::from_pem(&valid.certificate_pem, &valid.private_key_pem).unwrap();
        assert_eq!(fixture.handshake().await, expected.cert_chain[0].as_ref());
        assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn failed_initial_repair_keeps_an_existing_unmanaged_working_leaf() {
    for api in ["manage", "obtain"] {
        for future in [true, false] {
            let fixture = Fixture::new().await;
            let old = fixture
                .store
                .load(&fixture.issuer.issuer_key(), "example.com")
                .await
                .unwrap()
                .unwrap();
            fixture.manager.cache.remove(&fixture.old.hash).await;
            fixture
                .manager
                .cache
                .cache_unmanaged_pem(
                    &old.certificate_pem,
                    &old.private_key_pem,
                    vec!["operator".into()],
                )
                .await
                .unwrap();
            let invalid = fixture.store_invalid(future).await;
            assert!(fixture.operation(api).await.is_err());
            assert!(
                fixture
                    .manager
                    .cache
                    .get_by_hash(&invalid.hash)
                    .await
                    .is_none()
            );
            assert_eq!(fixture.manager.cache.get_all().await.len(), 1);
            assert_eq!(
                fixture.handshake().await,
                fixture.old.cert_chain[0].as_ref()
            );
            assert_eq!(
                fixture
                    .manager
                    .cache
                    .get_by_hash(&fixture.old.hash)
                    .await
                    .unwrap()
                    .tags,
                vec!["operator"]
            );
            fixture.issuer.fail.store(false, Ordering::SeqCst);
            fixture.operation(api).await.unwrap();
            assert_ne!(
                fixture.handshake().await,
                fixture.old.cert_chain[0].as_ref()
            );
        }
    }
}

#[tokio::test]
async fn already_managed_invalid_leaves_do_not_skip_foreground_or_background_repair() {
    for background in [false, true] {
        for future in [true, false] {
            let fixture = Fixture::new().await;
            fixture.manager.cache.remove(&fixture.old.hash).await;
            let invalid = fixture.store_invalid(future).await;
            fixture.manager.cache.add(invalid.clone()).await;
            fixture.issuer.fail.store(false, Ordering::SeqCst);
            if background {
                fixture
                    .manager
                    .manage_in_background(&["example.com".into()])
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if fixture.issuer.calls.load(Ordering::SeqCst) > 0
                            && let Some(current) =
                                fixture.manager.cache.get_by_name("example.com").await
                            && current.hash != invalid.hash
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("background manage skipped an invalid managed leaf");
            } else {
                fixture.operation("manage").await.unwrap();
            }
            assert!(
                fixture
                    .manager
                    .cache
                    .get_by_hash(&invalid.hash)
                    .await
                    .is_none()
            );
            assert!(fixture.issuer.calls.load(Ordering::SeqCst) > 0);
            fixture.handshake().await;
        }
    }
}

#[tokio::test]
async fn invalid_managed_siblings_remain_tracked_without_hiding_a_valid_cached_leaf() {
    for background in [false, true] {
        for future in [true, false] {
            let fixture = Fixture::new().await;
            let invalid = fixture.store_invalid(future).await;
            fixture.manager.cache.add(invalid.clone()).await;
            if background {
                fixture
                    .manager
                    .manage_in_background(&["example.com".into()])
                    .await
                    .unwrap();
            } else {
                fixture.operation("manage").await.unwrap();
            }
            assert!(
                fixture
                    .manager
                    .cache
                    .get_by_hash(&invalid.hash)
                    .await
                    .is_some()
            );
            assert!(
                fixture
                    .manager
                    .cache
                    .get_by_hash(&fixture.old.hash)
                    .await
                    .is_some()
            );
            assert_eq!(
                fixture.handshake().await,
                fixture.old.cert_chain[0].as_ref()
            );
            assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn current_valid_storage_is_loaded_without_extra_issuance() {
    for api in ["manage", "obtain", "cache"] {
        let fixture = Fixture::new().await;
        fixture.manager.cache.remove(&fixture.old.hash).await;
        let year = chrono::Utc::now().year();
        let resource = fixture.issuer.resource(year - 1, year + 4);
        fixture
            .store
            .save(&fixture.issuer.issuer_key(), &resource)
            .await
            .unwrap();
        fixture.operation(api).await.unwrap();
        fixture.operation("manage").await.unwrap();
        assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
        let cert =
            certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                .unwrap();
        assert_eq!(fixture.handshake().await, cert.cert_chain[0].as_ref());
    }
}

#[derive(Debug)]
struct AppearingStore {
    inner: Arc<dyn CertStore>,
    resource: std::sync::Mutex<Option<CertificateResource>>,
}
#[async_trait::async_trait]
impl CertStore for AppearingStore {
    async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>> {
        self.inner.load(issuer, domain).await
    }
    async fn save(&self, issuer: &str, resource: &CertificateResource) -> Result<()> {
        self.inner.save(issuer, resource).await
    }
    async fn remove(&self, issuer: &str, domain: &str) -> Result<()> {
        self.inner.remove(issuer, domain).await
    }
    async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
        let exists = self.inner.has(issuer, domain).await?;
        let appearing = self.resource.lock().unwrap().take();
        if let Some(resource) = appearing {
            self.inner.save(issuer, &resource).await?;
        }
        Ok(exists)
    }
}
#[tokio::test]
async fn obtain_repairs_invalid_storage_appearing_at_the_locked_recheck() {
    for future in [true, false] {
        let mut fixture = Fixture::new().await;
        fixture.manager.cache.remove(&fixture.old.hash).await;
        fixture.store_invalid(future).await;
        let resource = fixture
            .store
            .load(&fixture.issuer.issuer_key(), "example.com")
            .await
            .unwrap()
            .unwrap();
        fixture
            .store
            .remove(&fixture.issuer.issuer_key(), "example.com")
            .await
            .unwrap();
        Arc::get_mut(&mut fixture.manager).unwrap().certificates = Arc::new(AppearingStore {
            inner: fixture.store.clone(),
            resource: std::sync::Mutex::new(Some(resource)),
        });
        fixture.issuer.fail.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), fixture.operation("obtain"))
            .await
            .expect("locked recheck tried to reacquire its domain lock")
            .unwrap();
        assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
        fixture.handshake().await;
        let lock = certon::try_acquire(
            fixture.storage.clone(),
            "issue_cert_example.com",
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .expect("initial operation left the lifecycle lock held");
        lock.release().await.unwrap();
    }
}

#[tokio::test]
async fn failed_obtain_repair_keeps_managed_metadata_and_a_valid_serving_leaf() {
    for future in [true, false] {
        let fixture = Fixture::new().await;
        let invalid = fixture.store_invalid(future).await;
        fixture.manager.cache.add(invalid.clone()).await;
        assert!(fixture.operation("obtain").await.is_err());
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&invalid.hash)
                .await
                .is_some()
        );
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&fixture.old.hash)
                .await
                .is_some()
        );
        assert_eq!(
            fixture.handshake().await,
            fixture.old.cert_chain[0].as_ref()
        );
        fixture.issuer.fail.store(false, Ordering::SeqCst);
        fixture.operation("obtain").await.unwrap();
        assert_ne!(
            fixture.handshake().await,
            fixture.old.cert_chain[0].as_ref()
        );
    }
}

#[tokio::test]
async fn invalid_overlapping_managed_leaf_keeps_its_coverage_for_maintenance() {
    for future in [true, false] {
        let fixture = Fixture::new().await;
        fixture.manager.cache.remove(&fixture.old.hash).await;
        let year = chrono::Utc::now().year();
        let ab = fixture.issuer.resource_with_names(
            if future { year + 1 } else { year - 3 },
            if future { year + 5 } else { year - 1 },
            &["a.example.com", "b.example.com"],
        );
        fixture
            .store
            .save(&fixture.issuer.issuer_key(), &ab)
            .await
            .unwrap();
        let invalid = fixture
            .manager
            .load_certificate("a.example.com")
            .await
            .unwrap()
            .unwrap();
        fixture.manager.cache.add(invalid.clone()).await;
        let ac = fixture.issuer.resource_with_names(
            year - 1,
            year + 5,
            &["a.example.com", "c.example.com"],
        );
        let mut valid =
            certon::Certificate::from_pem(&ac.certificate_pem, &ac.private_key_pem).unwrap();
        valid.managed = true;
        valid.issuer_key = fixture.issuer.issuer_key();
        valid.names = vec!["a.example.com".into(), "c.example.com".into()];
        fixture.manager.cache.add(valid.clone()).await;
        fixture
            .manager
            .manage(&["a.example.com".into()])
            .await
            .unwrap();
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&invalid.hash)
                .await
                .is_some(),
            "manage forgot the only certificate tracking b.example.com"
        );
        assert_eq!(
            fixture.try_handshake_for("a.example.com").await.unwrap(),
            valid.cert_chain[0].as_ref()
        );
        assert!(fixture.try_handshake_for("b.example.com").await.is_err());
        let outcomes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let manager = fixture.manager.clone();
        let recorded = outcomes.clone();
        let renew: Arc<certon::maintain::ReasonedRenewFn> = Arc::new(move |domain, reason| {
            let manager = manager.clone();
            let recorded = recorded.clone();
            Box::pin(async move {
                let result = manager
                    .renew(&domain, reason == certon::maintain::RenewalReason::Revoked)
                    .await;
                recorded.lock().unwrap().push(result.is_ok());
                result
            })
        });
        let task = certon::maintain::start_maintenance_with_policy(
            fixture.manager.cache.clone(),
            certon::maintain::MaintenanceConfig {
                renew_check_interval: Duration::from_millis(5),
                ocsp_check_interval: Duration::from_secs(3600),
                storage: fixture.storage.clone(),
                ocsp: fixture.manager.policy.ocsp.clone(),
            },
            renew,
            fixture.store.clone(),
            fixture.manager.policy.renewal_window_ratio,
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while outcomes.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("maintenance forgot the invalid managed SAN coverage");
        assert!(!outcomes.lock().unwrap()[0]);
        assert_eq!(
            fixture.try_handshake_for("a.example.com").await.unwrap(),
            valid.cert_chain[0].as_ref()
        );
        fixture.issuer.fail.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !outcomes.lock().unwrap().contains(&true) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("maintenance did not repair the invalid managed SAN coverage");
        fixture.manager.cache.stop_and_wait().await;
        task.await.unwrap();
        assert!(fixture.issuer.requests.lock().unwrap().iter().all(|names| {
            ["a.example.com", "b.example.com", "c.example.com"]
                .iter()
                .all(|name| names.iter().any(|actual| actual == name))
        }));
        let replacement = fixture.try_handshake_for("b.example.com").await.unwrap();
        assert_eq!(
            replacement,
            fixture.try_handshake_for("a.example.com").await.unwrap()
        );
        assert_eq!(
            replacement,
            fixture.try_handshake_for("c.example.com").await.unwrap()
        );
    }
}
