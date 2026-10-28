use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use certon::{
    CertIssuer, CertManager, CertStore, Certificate, CertificateResource, Error, FileStorage,
    IssuedCertificate, KeyValueCertStore, Result, Storage,
};
use chrono::Datelike;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

struct StoredIssuer(&'static str);

#[async_trait::async_trait]
impl CertIssuer for StoredIssuer {
    async fn issue(&self, _: &[u8], _: &[String]) -> Result<IssuedCertificate> {
        panic!("client credential selection must not issue a certificate")
    }

    fn issuer_key(&self) -> String {
        self.0.into()
    }
}

struct MarkerStorage {
    files: FileStorage,
    fail_marker_reads: AtomicBool,
    gate_next_marker: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl Storage for MarkerStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.files.store(key, value).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if key.starts_with("revocations/") && self.gate_next_marker.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        if key.starts_with("revocations/") && self.fail_marker_reads.load(Ordering::SeqCst) {
            return Err(certon::error::StorageError::Io(std::io::Error::other(
                "revocation backend unavailable",
            ))
            .into());
        }
        self.files.load(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.files.delete(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.files.exists(key).await
    }
    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        self.files.list(prefix, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<certon::KeyInfo> {
        self.files.stat(key).await
    }
    async fn lock(&self, key: &str) -> Result<()> {
        self.files.lock(key).await
    }
    async fn unlock(&self, key: &str) -> Result<()> {
        self.files.unlock(key).await
    }
}

#[derive(Clone, Copy)]
enum Validity {
    Current,
    Future,
    Expired,
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Arc<MarkerStorage>,
    manager: CertManager,
    issuer: rcgen::Issuer<'static, KeyPair>,
    root: CertificateDer<'static>,
    server: Arc<rustls::ServerConfig>,
}

impl Fixture {
    fn new() -> Self {
        certon::install_default_crypto_provider();
        let mut params = CertificateParams::new(vec!["mTLS identity test CA".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        let issuer = rcgen::Issuer::new(params, key);
        let mut server_params = CertificateParams::new(vec!["server.example".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(root.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(MarkerStorage {
            files: FileStorage::new(directory.path()),
            fail_marker_reads: AtomicBool::new(false),
            gate_next_marker: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        let manager = CertManager::builder()
            .storage(storage.clone())
            .issuers(vec![
                Arc::new(StoredIssuer("ca-a")),
                Arc::new(StoredIssuer("ca-b")),
            ])
            .build();
        Self {
            _directory: directory,
            storage,
            manager,
            issuer,
            root,
            server: Arc::new(server),
        }
    }

    fn resource(&self, issuer: &str, validity: Validity, must_staple: bool) -> CertificateResource {
        let mut params = CertificateParams::new(vec!["client.example".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let year = chrono::Utc::now().year();
        let (start, end) = match validity {
            Validity::Current => (year - 1, year + 1),
            Validity::Future => (year + 1, year + 2),
            Validity::Expired => (year - 2, year - 1),
        };
        params.not_before = rcgen::date_time_ymd(start, 1, 1);
        params.not_after = rcgen::date_time_ymd(end, 1, 1);
        if must_staple {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                    vec![0x30, 0x03, 0x02, 0x01, 0x05],
                ));
        }
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &self.issuer).unwrap();
        CertificateResource {
            sans: vec!["client.example".into()],
            certificate_pem: leaf.pem().into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
            issuer_key: issuer.into(),
            issuer_data: None,
        }
    }

    fn certificate(resource: &CertificateResource) -> Certificate {
        let mut cert =
            Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem).unwrap();
        cert.managed = true;
        cert.issuer_key = resource.issuer_key.clone();
        cert
    }

    async fn save(&self, resource: &CertificateResource, cached: bool) {
        KeyValueCertStore::new(self.storage.clone())
            .save(&resource.issuer_key, resource)
            .await
            .unwrap();
        if cached {
            self.manager.cache.add(Self::certificate(resource)).await;
        }
    }

    async fn mark_revoked(&self, cert: &Certificate, confirmed: bool) {
        let leaf_hash = certon::certificates::hash_certificate_chain(&cert.cert_chain[..1]);
        self.storage
            .store(
                &format!("revocations/{leaf_hash}.json"),
                format!(r#"{{"version":1,"confirmed":{confirmed}}}"#).as_bytes(),
            )
            .await
            .unwrap();
    }

    async fn handshake(&self) -> Vec<CertificateDer<'static>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        let client = self
            .manager
            .client_config("client.example", roots)
            .await
            .unwrap();
        let (a, b) = tokio::io::duplex(16 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(self.server.clone());
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (server, client) = tokio::join!(
            acceptor.accept(a),
            connector.connect("server.example".try_into().unwrap(), b)
        );
        client.unwrap();
        server
            .unwrap()
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .to_vec()
    }
}

#[tokio::test]
async fn warm_and_cold_credentials_reject_inapplicable_validity() {
    for cached in [false, true] {
        for validity in [Validity::Expired, Validity::Future] {
            let fixture = Fixture::new();
            let resource = fixture.resource("ca-a", validity, false);
            fixture.save(&resource, cached).await;
            let error = fixture
                .manager
                .client_credentials("client.example")
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                Error::Cert(
                    certon::error::CertError::Expired(_) | certon::error::CertError::NotYetValid(_)
                )
            ));
            assert!(
                fixture
                    .manager
                    .client_config("client.example", rustls::RootCertStore::empty())
                    .await
                    .is_err()
            );
            if cached {
                assert!(
                    fixture
                        .manager
                        .cache
                        .get_by_name("client.example")
                        .await
                        .is_some(),
                    "lifecycle metadata was removed"
                );
            }
        }
    }
}

#[tokio::test]
async fn current_sibling_is_selected_before_a_future_leaf_in_cache_or_storage() {
    for cached in [false, true] {
        let fixture = Fixture::new();
        let future = fixture.resource("ca-a", Validity::Future, false);
        let current = fixture.resource("ca-b", Validity::Current, false);
        fixture.save(&future, cached).await;
        fixture.save(&current, cached).await;
        assert_eq!(
            fixture.handshake().await[0],
            Fixture::certificate(&current).cert_chain[0]
        );
    }
}

#[tokio::test]
async fn warm_and_cold_credentials_check_new_pending_and_confirmed_intent() {
    for cached in [false, true] {
        for confirmed in [false, true] {
            let fixture = Fixture::new();
            let resource = fixture.resource("ca-a", Validity::Current, false);
            fixture.save(&resource, cached).await;
            fixture
                .mark_revoked(&Fixture::certificate(&resource), confirmed)
                .await;
            assert!(matches!(
                fixture.manager.client_credentials("client.example").await,
                Err(Error::Cert(certon::error::CertError::Revoked(_)))
            ));
            assert!(
                fixture
                    .manager
                    .client_config("client.example", rustls::RootCertStore::empty())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn marker_backend_failure_is_not_bypassed_by_a_warm_cache() {
    for cached in [false, true] {
        let fixture = Fixture::new();
        let resource = fixture.resource("ca-a", Validity::Current, false);
        fixture.save(&resource, cached).await;
        fixture
            .storage
            .fail_marker_reads
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            fixture.manager.client_credentials("client.example").await,
            Err(Error::Storage(certon::error::StorageError::Io(_)))
        ));
        assert!(
            fixture
                .manager
                .client_config("client.example", rustls::RootCertStore::empty())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn a_revoked_cache_leaf_cannot_return_via_cold_storage_but_a_new_leaf_can() {
    let fixture = Fixture::new();
    let revoked = fixture.resource("ca-a", Validity::Current, false);
    fixture.save(&revoked, true).await;
    let mut cert = Fixture::certificate(&revoked);
    cert.ocsp_status = Some(certon::ocsp::OcspStatus::Revoked);
    // Same-hash replace explicitly publishes the local revocation evidence.
    fixture
        .manager
        .cache
        .replace(&cert.hash.clone(), cert.clone())
        .await;
    assert!(matches!(
        fixture.manager.client_credentials("client.example").await,
        Err(Error::Cert(certon::error::CertError::Revoked(_)))
    ));
    assert_eq!(
        fixture
            .manager
            .cache
            .get_by_hash(&cert.hash)
            .await
            .unwrap()
            .ocsp_status,
        Some(certon::ocsp::OcspStatus::Revoked)
    );
    let current = fixture.resource("ca-b", Validity::Current, false);
    fixture.save(&current, false).await;
    assert_eq!(
        fixture.handshake().await[0],
        Fixture::certificate(&current).cert_chain[0]
    );
}

#[tokio::test]
async fn persisted_revocation_uses_an_independent_usable_sibling() {
    for cached in [false, true] {
        let fixture = Fixture::new();
        let revoked = fixture.resource("ca-a", Validity::Current, false);
        let current = fixture.resource("ca-b", Validity::Current, false);
        fixture.save(&revoked, cached).await;
        fixture.save(&current, cached).await;
        fixture
            .mark_revoked(&Fixture::certificate(&revoked), false)
            .await;
        assert_eq!(
            fixture.handshake().await[0],
            Fixture::certificate(&current).cert_chain[0]
        );
    }
}

#[tokio::test]
async fn client_auth_only_must_staple_identities_do_not_require_a_server_staple() {
    for cached in [false, true] {
        let fixture = Fixture::new();
        let resource = fixture.resource("ca-a", Validity::Current, true);
        fixture.save(&resource, cached).await;
        assert_eq!(
            fixture.handshake().await[0],
            Fixture::certificate(&resource).cert_chain[0]
        );
    }
}

#[tokio::test]
async fn local_revocation_during_a_marker_read_invalidates_the_captured_candidate() {
    let fixture = Fixture::new();
    let resource = fixture.resource("ca-a", Validity::Current, false);
    fixture.save(&resource, true).await;
    let mut revoked = Fixture::certificate(&resource);
    revoked.ocsp_status = Some(certon::ocsp::OcspStatus::Revoked);
    fixture
        .storage
        .gate_next_marker
        .store(true, Ordering::SeqCst);
    let selection = fixture.manager.client_credentials("client.example");
    let update = async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.storage.entered.notified(),
        )
        .await
        .unwrap();
        fixture
            .manager
            .cache
            .replace(&revoked.hash.clone(), revoked)
            .await;
        fixture.storage.release.add_permits(1);
    };
    let (selected, ()) = tokio::join!(selection, update);
    assert!(matches!(
        selected,
        Err(Error::Cert(certon::error::CertError::Revoked(_)))
    ));
}

#[tokio::test]
async fn a_quarantined_leaf_cannot_be_restored_from_storage_after_marker_disappears() {
    let fixture = Fixture::new();
    let resource = fixture.resource("ca-a", Validity::Current, false);
    fixture.save(&resource, true).await;
    let cert = Fixture::certificate(&resource);
    fixture.mark_revoked(&cert, true).await;
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
    assert!(
        fixture
            .manager
            .cache
            .get_by_name("client.example")
            .await
            .is_none()
    );
    let leaf_hash = certon::certificates::hash_certificate_chain(&cert.cert_chain[..1]);
    fixture
        .storage
        .delete(&format!("revocations/{leaf_hash}.json"))
        .await
        .unwrap();
    assert!(matches!(
        fixture.manager.client_credentials("client.example").await,
        Err(Error::Cert(certon::error::CertError::Revoked(_)))
    ));
}
