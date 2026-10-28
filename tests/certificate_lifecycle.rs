use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use certon::{
    CertIssuer, CertManager, FileStorage, IssuedCertificate, OcspConfig, Result, Storage,
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
        }
    }
}
#[async_trait::async_trait]
impl CertIssuer for TestIssuer {
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
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
        let names = if mode == 2 {
            vec!["wrong.example.com".into()]
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
        connector.connect("example.com".try_into().unwrap(), client_io)
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
