use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use certon::{
    CertIssuer, CertManager, CertStore, CertificateResource, FileStorage, IssuedCertificate,
    KeyValueCertStore, OcspConfig, Result, Storage,
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
    requests: std::sync::Mutex<Vec<Vec<String>>>,
    csr_public_keys: std::sync::Mutex<Vec<Vec<u8>>>,
    name: &'static str,
    not_before_year: i32,
    not_after_year: i32,
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
            requests: std::sync::Mutex::new(Vec::new()),
            csr_public_keys: std::sync::Mutex::new(Vec::new()),
            name: "test-ca",
            not_before_year: chrono::Utc::now().year() - 2,
            not_after_year: chrono::Utc::now().year() + 4,
        }
    }
}
#[async_trait::async_trait]
impl CertIssuer for TestIssuer {
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.requests.lock().unwrap().push(domains.to_vec());
        let serial = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 4 {
            return Err(certon::Error::Other("issuer unavailable".into()));
        }
        if mode == 3 {
            self.entered.notify_one();
            std::future::pending::<()>().await;
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
        self.csr_public_keys.lock().unwrap().push(public.0.clone());
        let names = if mode == 2 {
            vec!["wrong.example.com".into()]
        } else if mode == 5 {
            domains[..1].to_vec()
        } else {
            domains.to_vec()
        };
        let mut params = CertificateParams::new(names).unwrap();
        params.serial_number = Some((serial as u64).into());
        params.not_before = rcgen::date_time_ymd(self.not_before_year, 1, 1);
        params.not_after = rcgen::date_time_ymd(self.not_after_year, 1, 1);
        let cert = if mode == 1 {
            params
                .signed_by(&KeyPair::generate().unwrap(), &self.ca)
                .unwrap()
        } else {
            params.signed_by(&public, &self.ca).unwrap()
        };
        Ok(IssuedCertificate {
            certificate_pem: cert.pem().into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    fn issuer_key(&self) -> String {
        self.name.into()
    }
}
fn manager(storage: Arc<dyn Storage>, issuer: Arc<TestIssuer>) -> Arc<CertManager> {
    Arc::new(
        CertManager::builder()
            .storage(storage)
            .issuers(vec![issuer])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build(),
    )
}

async fn handshake(manager: &CertManager, issuer: &TestIssuer) -> Vec<u8> {
    handshake_for_domain(manager, issuer, "example.com").await
}

async fn handshake_for_domain(manager: &CertManager, issuer: &TestIssuer, domain: &str) -> Vec<u8> {
    certon::install_default_crypto_provider();
    let config = manager.server_config();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(issuer.root.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (server_io, client_io) = tokio::io::duplex(16384);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let (server, client) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect(domain.to_owned().try_into().unwrap(), client_io)
    );
    server.unwrap();
    client.unwrap().get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manage_and_renew_publish_certificates_before_returning() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(TestIssuer::new());
    let manager = manager(Arc::new(FileStorage::new(directory.path())), issuer.clone());
    manager.manage(&["example.com".into()]).await.unwrap();
    let first = handshake(&manager, &issuer).await;
    manager.renew("example.com", true).await.unwrap();
    let renewed = handshake(&manager, &issuer).await;
    assert_ne!(first, renewed);
    assert_eq!(manager.cache.get_all().await.len(), 1);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn mismatched_keys_and_names_never_replace_a_working_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(TestIssuer::new());
    let manager = manager(Arc::new(FileStorage::new(directory.path())), issuer.clone());
    manager.manage(&["example.com".into()]).await.unwrap();
    let original = manager.cache.get_all().await[0].hash.clone();
    for mode in [1, 2] {
        issuer.mode.store(mode, Ordering::SeqCst);
        assert!(manager.renew("example.com", true).await.is_err());
        assert_eq!(
            manager
                .load_certificate("example.com")
                .await
                .unwrap()
                .unwrap()
                .hash,
            original
        );
        assert_eq!(manager.cache.get_all().await[0].hash, original);
    }
}

#[tokio::test]
async fn cancelling_a_renewal_releases_the_distributed_lock() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let issuer = Arc::new(TestIssuer::new());
    let manager = manager(storage.clone(), issuer.clone());
    manager.manage(&["example.com".into()]).await.unwrap();
    issuer.mode.store(3, Ordering::SeqCst);
    let worker = manager.clone();
    let task = tokio::spawn(async move { worker.renew("example.com", true).await });
    issuer.entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let lock = certon::try_acquire(
        storage,
        "issue_cert_example.com",
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap()
    .expect("cancelled renewal released its lock");
    lock.release().await.unwrap();
}

#[tokio::test]
async fn listen_keeps_its_bound_socket_alive() {
    let bound = certon::listen(&[], "127.0.0.1:0").await.unwrap();
    let address = bound.listener.local_addr().unwrap();
    assert!(tokio::net::TcpListener::bind(address).await.is_err());
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (accepted, _) = bound.listener.accept().await.unwrap();
    drop((stream, accepted, bound));
    tokio::net::TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn restart_uses_the_new_certificate_from_a_fallback_issuer() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let mut preferred = TestIssuer::new();
    preferred.not_after_year = chrono::Utc::now().year() + 30; // The older certificate expires later.
    let preferred = Arc::new(preferred);
    let mut fallback = TestIssuer::new();
    fallback.name = "fallback-ca";
    fallback.not_before_year = chrono::Utc::now().year() - 1;
    let fallback = Arc::new(fallback);
    let make_manager = || {
        CertManager::builder()
            .storage(storage.clone())
            .issuers(vec![preferred.clone(), fallback.clone()])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build()
    };
    let first = make_manager();
    first.manage(&["example.com".into()]).await.unwrap();
    preferred.mode.store(4, Ordering::SeqCst);
    first.renew("example.com", true).await.unwrap();
    let renewed = first.cache.get_all().await[0].clone();
    assert_eq!(renewed.issuer_key, "fallback-ca");
    drop(first);
    let restarted = make_manager();
    restarted.manage(&["example.com".into()]).await.unwrap();
    let loaded = restarted.cache.get_all().await;
    assert_eq!(loaded[0].issuer_key, "fallback-ca");
    assert_eq!(loaded[0].hash, renewed.hash);
    assert_eq!(preferred.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_forced_renewal_keeps_an_already_cached_new_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let issuer = Arc::new(TestIssuer::new());
    let serving = manager(storage.clone(), issuer.clone());
    serving.manage(&["example.com".into()]).await.unwrap();
    let old = serving.cache.get_by_name("example.com").await.unwrap();
    let writer = manager(storage, issuer.clone());
    writer.renew("example.com", true).await.unwrap();
    let fresh = serving.cache_certificate("example.com").await.unwrap();
    assert_ne!(fresh.hash, old.hash);
    // The name index preserves insertion order; do not use get_all(), which
    // iterates a HashMap and might choose the incoming hash as the old entry.
    let hashes: Vec<_> = serving
        .cache
        .all_matching_certificates("example.com")
        .await
        .into_iter()
        .map(|cert| cert.hash)
        .collect();
    assert_eq!(hashes, [old.hash.clone(), fresh.hash.clone()]);

    serving.renew("example.com", false).await.unwrap();

    assert!(serving.cache.get_by_hash(&old.hash).await.is_none());
    assert!(serving.cache.get_by_hash(&fresh.hash).await.is_some());
    assert_eq!(serving.cache.count().await, 1);
    assert_eq!(
        handshake(&serving, &issuer).await,
        fresh.cert_chain[0].as_ref()
    );
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
}

async fn certificate_resource(issuer: &TestIssuer) -> CertificateResource {
    resource_with_names(issuer, &["example.com"], "example.com").await
}

async fn resource_with_names(
    issuer: &TestIssuer,
    names: &[&str],
    lookup: &str,
) -> CertificateResource {
    let key = certon::crypto::generate_private_key(certon::KeyType::EcdsaP256).unwrap();
    let domains: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    let csr = certon::crypto::generate_csr(&key, &domains, false).unwrap();
    let issued = issuer.issue(&csr, &domains).await.unwrap();
    CertificateResource {
        sans: vec![lookup.to_owned()],
        certificate_pem: issued.certificate_pem,
        private_key_pem: certon::crypto::encode_private_key_pem(&key)
            .unwrap()
            .into_bytes(),
        issuer_key: issuer.issuer_key(),
        issuer_data: None,
    }
}

fn multiple_issuer_manager(
    storage: Arc<dyn Storage>,
    certificates: Arc<dyn CertStore>,
    issuers: Vec<Arc<dyn CertIssuer>>,
) -> CertManager {
    CertManager::builder()
        .storage(storage)
        .certificates(certificates)
        .issuers(issuers)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newer_invalid_candidates_do_not_shadow_a_usable_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
    let primary = Arc::new(TestIssuer::new());
    let primary_resource = certificate_resource(&primary).await;
    certificates
        .save(&primary.issuer_key(), &primary_resource)
        .await
        .unwrap();
    let mut secondary = TestIssuer::new();
    secondary.name = "secondary-ca";
    secondary.not_before_year += 1;
    let secondary = Arc::new(secondary);
    for invalid_mode in [1, 2] {
        secondary.mode.store(invalid_mode, Ordering::SeqCst);
        let invalid = certificate_resource(&secondary).await;
        let primary_certificate = certon::Certificate::from_pem(
            &primary_resource.certificate_pem,
            &primary_resource.private_key_pem,
        )
        .unwrap();
        let secondary_certificate =
            certon::Certificate::from_pem(&invalid.certificate_pem, &invalid.private_key_pem)
                .unwrap();
        assert!(secondary_certificate.not_before > primary_certificate.not_before);
        certificates
            .save(&secondary.issuer_key(), &invalid)
            .await
            .unwrap();
        // A bad resource must be skipped both before and after a good resource.
        for invalid_first in [false, true] {
            let issuers: Vec<Arc<dyn CertIssuer>> = if invalid_first {
                vec![secondary.clone(), primary.clone()]
            } else {
                vec![primary.clone(), secondary.clone()]
            };
            let manager = multiple_issuer_manager(storage.clone(), certificates.clone(), issuers);
            manager.manage(&["example.com".into()]).await.unwrap();
            let cached = manager.cache.get_by_name("example.com").await.unwrap();
            assert_eq!(cached.issuer_key, primary.issuer_key());
            assert_eq!(
                handshake(&manager, &primary).await,
                primary_certificate.cert_chain[0].as_ref()
            );
        }
    }
}

#[tokio::test]
async fn all_invalid_candidates_return_validation_errors_rather_than_absence() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
    let primary = Arc::new(TestIssuer::new());
    primary.mode.store(1, Ordering::SeqCst);
    let mut secondary = TestIssuer::new();
    secondary.name = "secondary-ca";
    secondary.mode.store(2, Ordering::SeqCst);
    let secondary = Arc::new(secondary);
    for issuer in [&primary, &secondary] {
        certificates
            .save(&issuer.issuer_key(), &certificate_resource(issuer).await)
            .await
            .unwrap();
    }
    let manager = multiple_issuer_manager(storage, certificates, vec![primary, secondary]);
    let error = manager.load_certificate("example.com").await.unwrap_err();
    assert!(matches!(error, certon::Error::Config(_)));
    let message = error.to_string();
    assert!(
        message.contains("no valid certificate resource"),
        "{message}"
    );
    assert!(
        message.contains("test-ca") && message.contains("secondary-ca"),
        "{message}"
    );
    assert!(
        message.contains("mismatch") && message.contains("does not cover"),
        "{message}"
    );
}

#[derive(Debug)]
struct FailingSecondaryStore {
    inner: KeyValueCertStore,
    storage_error: bool,
}
#[async_trait::async_trait]
impl CertStore for FailingSecondaryStore {
    async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>> {
        if issuer == "secondary-ca" {
            return Err(if self.storage_error {
                certon::Error::Storage(certon::error::StorageError::Io(std::io::Error::other(
                    "secondary backend offline",
                )))
            } else {
                certon::Error::Other("secondary backend offline".into())
            });
        }
        self.inner.load(issuer, domain).await
    }
    async fn save(&self, issuer: &str, resource: &CertificateResource) -> Result<()> {
        self.inner.save(issuer, resource).await
    }
    async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
        self.inner.has(issuer, domain).await
    }
    async fn remove(&self, issuer: &str, domain: &str) -> Result<()> {
        self.inner.remove(issuer, domain).await
    }
}

#[tokio::test]
async fn candidate_backend_errors_propagate_after_valid_or_invalid_resources() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let primary = Arc::new(TestIssuer::new());
    let mut secondary = TestIssuer::new();
    secondary.name = "secondary-ca";
    let secondary = Arc::new(secondary);
    for primary_mode in [0, 1] {
        primary.mode.store(primary_mode, Ordering::SeqCst);
        for storage_error in [false, true] {
            let certificates = Arc::new(FailingSecondaryStore {
                inner: KeyValueCertStore::new(storage.clone()),
                storage_error,
            });
            certificates
                .save(&primary.issuer_key(), &certificate_resource(&primary).await)
                .await
                .unwrap();
            let manager = multiple_issuer_manager(
                storage.clone(),
                certificates,
                vec![primary.clone(), secondary.clone()],
            );
            let error = manager.load_certificate("example.com").await.unwrap_err();
            if storage_error {
                assert!(matches!(
                    error,
                    certon::Error::Storage(certon::error::StorageError::Io(_))
                ));
            } else {
                assert!(matches!(error, certon::Error::Other(_)));
            }
            assert!(
                error.to_string().contains("secondary backend offline"),
                "{error}"
            );
        }
    }
}

fn managed_resource(resource: &CertificateResource) -> certon::Certificate {
    let mut cert =
        certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
            .unwrap();
    cert.managed = true;
    cert.issuer_key = resource.issuer_key.clone();
    cert
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_publication_keeps_all_uncovered_overlap_names_serving() {
    for multi_san_first in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
        let mut issuer = TestIssuer::new();
        issuer.not_after_year = chrono::Utc::now().year() + 2;
        let ab = resource_with_names(
            &issuer,
            &["a.example.com", "b.example.com"],
            "b.example.com",
        )
        .await;
        let ac = resource_with_names(
            &issuer,
            &["a.example.com", "c.example.com"],
            "c.example.com",
        )
        .await;
        let only_a = resource_with_names(&issuer, &["a.example.com"], "a.example.com").await;
        issuer.not_after_year += 2;
        let issuer = Arc::new(issuer);
        let manager = manager(storage, issuer.clone());
        manager
            .certificates
            .save(&issuer.issuer_key(), &ab)
            .await
            .unwrap();
        manager
            .certificates
            .save(&issuer.issuer_key(), &ac)
            .await
            .unwrap();
        let ab = managed_resource(&ab);
        let ac = managed_resource(&ac);
        let only_a = managed_resource(&only_a);
        // Cover both the primary replacement and stale cleanup paths without
        // depending on HashMap order.
        let initial = if multi_san_first {
            vec![ab.clone(), only_a.clone(), ac.clone()]
        } else {
            vec![only_a.clone(), ab.clone(), ac.clone()]
        };
        for cert in initial {
            manager.cache.add(cert).await;
        }
        manager.obtain("a.example.com").await.unwrap();
        let fresh = manager
            .load_certificate("a.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(fresh.hash, only_a.hash);
        assert!(manager.cache.get_by_hash(&only_a.hash).await.is_none());
        assert!(manager.cache.get_by_hash(&ab.hash).await.is_some());
        assert!(manager.cache.get_by_hash(&ac.hash).await.is_some());
        assert_eq!(
            handshake_for_domain(&manager, &issuer, "a.example.com").await,
            fresh.cert_chain[0].as_ref()
        );
        assert_eq!(
            handshake_for_domain(&manager, &issuer, "b.example.com").await,
            ab.cert_chain[0].as_ref()
        );
        assert_eq!(
            handshake_for_domain(&manager, &issuer, "c.example.com").await,
            ac.cert_chain[0].as_ref()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_repairs_fresh_partial_storage_and_keeps_the_lookup_key_on_restart() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let mut issuer = TestIssuer::new();
    // An explicitly expired leaf makes this independent of the current month.
    issuer.not_before_year = chrono::Utc::now().year() - 4;
    issuer.not_after_year = chrono::Utc::now().year() - 1;
    let ab = resource_with_names(
        &issuer,
        &["a.example.com", "b.example.com"],
        "a.example.com",
    )
    .await;
    issuer.not_before_year = chrono::Utc::now().year() - 2;
    issuer.not_after_year = chrono::Utc::now().year() + 4;
    let ac = resource_with_names(
        &issuer,
        &["a.example.com", "c.example.com"],
        "c.example.com",
    )
    .await;
    let fresh_a = resource_with_names(&issuer, &["a.example.com"], "a.example.com").await;
    let issuer = Arc::new(issuer);
    issuer.requests.lock().unwrap().clear();
    let renewed = Arc::new(Notify::new());
    let event = renewed.clone();
    let manager = Arc::new(
        CertManager::builder()
            .storage(storage.clone())
            .issuers(vec![issuer.clone()])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .on_event(Arc::new(move |name, _| {
                if name == certon::manager::EVENT_CERT_RENEWED {
                    event.notify_one();
                }
                Ok(())
            }))
            .build(),
    );
    manager
        .certificates
        .save(&issuer.issuer_key(), &ab)
        .await
        .unwrap();
    manager
        .certificates
        .save(&issuer.issuer_key(), &ac)
        .await
        .unwrap();
    // Simulate an already-cached certificate reaching expiry. The public
    // cache loader now rejects expired storage resources before publication.
    let old_ab = manager
        .load_certificate("a.example.com")
        .await
        .unwrap()
        .unwrap();
    manager.cache.add(old_ab.clone()).await;
    let old_ac = manager.cache_certificate("c.example.com").await.unwrap();
    assert!(old_ab.needs_renewal(manager.policy.renewal_window_ratio));
    assert!(!old_ac.needs_renewal(manager.policy.renewal_window_ratio));
    manager
        .certificates
        .save(&issuer.issuer_key(), &fresh_a)
        .await
        .unwrap();
    let current = manager
        .load_certificate("a.example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(!current.needs_renewal(manager.policy.renewal_window_ratio));
    let worker = manager.clone();
    let renew: Arc<certon::maintain::ReasonedRenewFn> = Arc::new(move |domain, reason| {
        let manager = worker.clone();
        Box::pin(async move {
            manager
                .renew(&domain, reason == certon::maintain::RenewalReason::Revoked)
                .await
        })
    });
    let maintenance = certon::maintain::start_maintenance_with_policy(
        manager.cache.clone(),
        certon::MaintenanceConfig {
            renew_check_interval: std::time::Duration::from_millis(10),
            ocsp_check_interval: std::time::Duration::from_secs(3600),
            ocsp: manager.policy.ocsp.clone(),
            storage: storage.clone(),
        },
        renew,
        manager.certificates.clone(),
        manager.policy.renewal_window_ratio,
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), renewed.notified())
        .await
        .expect("partial publication was not repaired");
    manager.cache.stop_and_wait().await;
    maintenance.await.unwrap();
    let requests = issuer.requests.lock().unwrap().clone();
    assert_eq!(
        requests,
        [vec![
            "a.example.com".to_owned(),
            "b.example.com".to_owned(),
            "c.example.com".to_owned()
        ]]
    );
    let persisted = manager
        .certificates
        .load(&issuer.issuer_key(), "a.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.sans, ["a.example.com"]);
    assert_eq!(manager.cache.count().await, 1);
    let fresh = manager.cache.get_by_name("a.example.com").await.unwrap();
    for domain in ["a.example.com", "b.example.com", "c.example.com"] {
        assert_eq!(
            handshake_for_domain(&manager, &issuer, domain).await,
            fresh.cert_chain[0].as_ref()
        );
    }
    let restarted = self::manager(storage, issuer.clone());
    restarted.manage(&["a.example.com".into()]).await.unwrap();
    for domain in ["a.example.com", "b.example.com", "c.example.com"] {
        assert_eq!(
            handshake_for_domain(&restarted, &issuer, domain).await,
            fresh.cert_chain[0].as_ref()
        );
    }
}

#[tokio::test]
async fn renewal_rejects_a_ca_that_drops_a_requested_san_before_saving() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let issuer = Arc::new(TestIssuer::new());
    let resource = resource_with_names(
        &issuer,
        &["a.example.com", "b.example.com"],
        "a.example.com",
    )
    .await;
    let manager = manager(storage, issuer.clone());
    manager
        .certificates
        .save(&issuer.issuer_key(), &resource)
        .await
        .unwrap();
    let old = manager.cache_certificate("a.example.com").await.unwrap();
    issuer.mode.store(5, Ordering::SeqCst);
    let error = manager.renew("a.example.com", true).await.unwrap_err();
    assert!(error.to_string().contains("b.example.com"), "{error}");
    let persisted = manager
        .certificates
        .load(&issuer.issuer_key(), "a.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.certificate_pem, resource.certificate_pem);
    assert_eq!(
        manager
            .cache
            .get_by_name("b.example.com")
            .await
            .unwrap()
            .hash,
        old.hash
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewal_preserves_wildcard_sans_and_their_storage_identity() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let issuer = Arc::new(TestIssuer::new());
    let resource =
        resource_with_names(&issuer, &["*.example.com", "example.net"], "*.example.com").await;
    let manager = manager(storage.clone(), issuer.clone());
    manager
        .certificates
        .save(&issuer.issuer_key(), &resource)
        .await
        .unwrap();
    manager.cache_certificate("*.example.com").await.unwrap();
    issuer.requests.lock().unwrap().clear();
    manager.renew("*.example.com", true).await.unwrap();
    assert_eq!(
        *issuer.requests.lock().unwrap(),
        [vec!["*.example.com".to_owned(), "example.net".to_owned()]]
    );
    assert!(
        manager
            .cache
            .get_by_name("nested.tenant.example.com")
            .await
            .is_none()
    );
    let persisted = manager
        .certificates
        .load(&issuer.issuer_key(), "*.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.sans, ["*.example.com"]);
    let restarted = self::manager(storage, issuer.clone());
    restarted.manage(&["*.example.com".into()]).await.unwrap();
    handshake_for_domain(&restarted, &issuer, "tenant.example.com").await;
    handshake_for_domain(&restarted, &issuer, "example.net").await;
}

fn leaf_public_key(resource: &CertificateResource) -> Vec<u8> {
    let cert = certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
        .unwrap();
    let (_, leaf) =
        x509_parser::certificate::X509Certificate::from_der(cert.cert_chain[0].as_ref()).unwrap();
    leaf.public_key().subject_public_key.data.to_vec()
}

async fn renewal_key_for_newest_fallback(reuse: bool) {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
    let preferred = Arc::new(TestIssuer::new());
    let old = certificate_resource(&preferred).await;
    let old_public = leaf_public_key(&old);
    certificates
        .save(&preferred.issuer_key(), &old)
        .await
        .unwrap();
    let mut fallback = TestIssuer::new();
    fallback.name = "fallback-ca";
    fallback.not_before_year += 1;
    let fallback = Arc::new(fallback);
    let selected = certificate_resource(&fallback).await;
    let selected_public = leaf_public_key(&selected);
    assert_ne!(old_public, selected_public);
    certificates
        .save(&fallback.issuer_key(), &selected)
        .await
        .unwrap();
    let manager = CertManager::builder()
        .storage(storage)
        .certificates(certificates.clone())
        .issuers(vec![preferred.clone(), fallback.clone()])
        .reuse_private_keys(reuse)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    let cached = manager.cache_certificate("example.com").await.unwrap();
    assert_eq!(cached.issuer_key, fallback.issuer_key());
    // Keep the older preferred issuer's key in storage while it is unavailable.
    preferred.mode.store(4, Ordering::SeqCst);
    fallback.csr_public_keys.lock().unwrap().clear();
    manager.renew("example.com", true).await.unwrap();
    let recorded = fallback.csr_public_keys.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    if reuse {
        assert_eq!(
            recorded[0], selected_public,
            "renewal must reuse the selected fallback resource's key"
        );
    } else {
        assert_ne!(
            recorded[0], selected_public,
            "disabled reuse must rotate the selected key"
        );
    }
    assert_ne!(
        recorded[0], old_public,
        "older preferred-CA key must not be resurrected"
    );
    let renewed = certificates
        .load(&fallback.issuer_key(), "example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(leaf_public_key(&renewed), recorded[0]);
    assert_eq!(
        certificates
            .load(&preferred.issuer_key(), "example.com")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        old.private_key_pem
    );
    handshake(&manager, &fallback).await;
}

#[tokio::test]
async fn renewal_reuses_the_selected_fallback_resource_private_key() {
    renewal_key_for_newest_fallback(true).await;
}

#[tokio::test]
async fn renewal_rotates_the_key_when_reuse_is_disabled() {
    renewal_key_for_newest_fallback(false).await;
}

#[tokio::test]
async fn first_obtain_generates_a_key_when_reuse_is_enabled_without_a_resource() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(TestIssuer::new());
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .issuers(vec![issuer.clone()])
        .reuse_private_keys(true)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    manager.obtain("example.com").await.unwrap();
    assert_eq!(issuer.csr_public_keys.lock().unwrap().len(), 1);
    handshake(&manager, &issuer).await;
}
