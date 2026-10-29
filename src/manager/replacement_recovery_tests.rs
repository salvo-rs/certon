use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use x509_parser::prelude::FromDer;

use crate::{
    CertIssuer, CertManager, Certificate, CertificateResource, IssuedCertificate, OcspConfig,
    Result, Storage,
};

const DOMAIN: &str = "round6-replacement.example.com";

struct Public(Vec<u8>);
impl PublicKeyData for Public {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

struct Ca {
    params: CertificateParams,
    key: KeyPair,
    root: rustls::pki_types::CertificateDer<'static>,
    storage: Arc<dyn Storage>,
    issues: AtomicUsize,
    must_staple: AtomicBool,
    fail: AtomicBool,
    gated: AtomicBool,
    gate: tokio::sync::Semaphore,
    active: AtomicUsize,
    aia: Mutex<Option<String>>,
}

impl Ca {
    fn new(storage: Arc<dyn Storage>) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        Self {
            params,
            key,
            root,
            storage,
            issues: AtomicUsize::new(0),
            must_staple: AtomicBool::new(true),
            fail: AtomicBool::new(false),
            gated: AtomicBool::new(false),
            gate: tokio::sync::Semaphore::new(0),
            active: AtomicUsize::new(0),
            aia: Mutex::new(None),
        }
    }
    fn params(must_staple: bool, seconds_ago: i64) -> CertificateParams {
        let mut params = CertificateParams::new(vec![DOMAIN.into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, DOMAIN);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        params.not_before =
            epoch + Duration::from_secs((Utc::now().timestamp() - seconds_ago) as u64);
        params.not_after =
            epoch + Duration::from_secs((Utc::now().timestamp() + 90 * 86400) as u64);
        if must_staple {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                    vec![0x30, 3, 2, 1, 5],
                ));
        }
        params
    }
    fn old_resource(&self) -> CertificateResource {
        self.resource(false, 3 * 86400)
    }

    fn resource(&self, must_staple: bool, seconds_ago: i64) -> CertificateResource {
        let key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::new(self.params.clone(), &self.key);
        let leaf = Self::params(must_staple, seconds_ago)
            .signed_by(&key, &issuer)
            .unwrap();
        CertificateResource {
            sans: vec![DOMAIN.into()],
            issuer_key: self.issuer_key(),
            issuer_data: None,
            certificate_pem: format!(
                "{}{}",
                leaf.pem(),
                pem::encode(&pem::Pem::new("CERTIFICATE", self.root.as_ref()))
            )
            .into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
        }
    }
    async fn set_status(&self, cert: &Certificate, status: u8) {
        let response = crate::ocsp::tests::signed_response(
            &cert.cert_chain,
            &self.key,
            status,
            Utc::now() - chrono::Duration::minutes(1),
            Utc::now() + chrono::Duration::hours(12),
        );
        self.storage
            .store(&crate::storage::ocsp_key(DOMAIN, &cert.hash), &response)
            .await
            .unwrap();
    }
}

#[async_trait::async_trait]
impl CertIssuer for Ca {
    fn issuer_key(&self) -> String {
        "round6-ca".into()
    }
    async fn issue(&self, csr: &[u8], names: &[String]) -> Result<IssuedCertificate> {
        self.issues.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(crate::Error::Other("test CA unavailable".into()));
        }
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = Active(&self.active);
        if self.gated.load(Ordering::SeqCst) {
            self.gate.acquire().await.unwrap().forget();
        }
        assert_eq!(names, &[DOMAIN.to_owned()]);
        let (_, request) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = Public(
            request
                .certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let issuer = rcgen::Issuer::new(self.params.clone(), &self.key);
        let mut params = Self::params(self.must_staple.load(Ordering::SeqCst), 60);
        if let Some(url) = self.aia.lock().unwrap().as_ref() {
            let wrap =
                |tag: u8, bytes: &[u8]| [vec![tag, bytes.len() as u8], bytes.to_vec()].concat();
            let access = wrap(
                0x30,
                &[
                    vec![0x06, 8, 0x2b, 6, 1, 5, 5, 7, 0x30, 2],
                    wrap(0x86, url.as_bytes()),
                ]
                .concat(),
            );
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    wrap(0x30, &access),
                ));
        }
        let leaf = params.signed_by(&public, &issuer).unwrap();
        let chain = vec![leaf.der().clone(), self.root.clone()];
        let response = crate::ocsp::tests::signed_response(
            &chain,
            &self.key,
            0,
            Utc::now() - chrono::Duration::minutes(1),
            Utc::now() + chrono::Duration::hours(12),
        );
        self.storage
            .store(
                &crate::storage::ocsp_key(
                    DOMAIN,
                    &crate::certificates::hash_certificate_chain(&chain),
                ),
                &response,
            )
            .await
            .unwrap();
        Ok(IssuedCertificate {
            certificate_pem: format!(
                "{}{}",
                leaf.pem(),
                pem::encode(&pem::Pem::new("CERTIFICATE", self.root.as_ref()))
            )
            .into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
}

fn manager(storage: Arc<dyn Storage>, ca: Arc<Ca>) -> CertManager {
    let must_staple = ca.must_staple.load(Ordering::SeqCst);
    CertManager::builder()
        .storage(storage)
        .issuers(vec![ca])
        .disable_ari(true)
        .must_staple(must_staple)
        .ocsp(OcspConfig::default())
        .build()
}

async fn handshake(manager: &CertManager, ca: &Ca) -> Result<Vec<u8>> {
    crate::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.root.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (server_io, client_io) = tokio::io::duplex(16384);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(manager.server_config()));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let (server, client) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect(DOMAIN.try_into().unwrap(), client_io)
    );
    server.map_err(|e| crate::Error::Other(e.to_string()))?;
    Ok(client
        .map_err(|e| crate::Error::Other(e.to_string()))?
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()[0]
        .to_vec())
}

struct ControlledStorage {
    files: crate::FileStorage,
    gate_key: Mutex<Option<String>>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    fail_marker: AtomicBool,
    fail_resource: AtomicBool,
}

impl ControlledStorage {
    fn new(path: &std::path::Path) -> Self {
        Self {
            files: crate::FileStorage::new(path),
            gate_key: Mutex::new(None),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            fail_marker: AtomicBool::new(false),
            fail_resource: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl Storage for ControlledStorage {
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let gated = {
            let mut gate = self.gate_key.lock().unwrap();
            if gate.as_deref() == Some(key) {
                gate.take();
                true
            } else {
                false
            }
        };
        if gated {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        if (key.starts_with("revocations/") && self.fail_marker.load(Ordering::SeqCst))
            || (key.starts_with("certificates/") && self.fail_resource.load(Ordering::SeqCst))
        {
            return Err(crate::error::StorageError::Deserialize(
                "primary backend unavailable".into(),
            )
            .into());
        }
        self.files.load(key).await
    }
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.files.store(key, value).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.files.delete(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.files.exists(key).await
    }
    async fn list(&self, key: &str, recursive: bool) -> Result<Vec<String>> {
        self.files.list(key, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<crate::storage::KeyInfo> {
        self.files.stat(key).await
    }
    async fn lock(&self, key: &str) -> Result<()> {
        self.files.lock(key).await
    }
    async fn unlock(&self, key: &str) -> Result<()> {
        self.files.unlock(key).await
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Arc<ControlledStorage>,
    ca: Arc<Ca>,
    manager: Arc<CertManager>,
    a: Certificate,
    b: Certificate,
}

impl Fixture {
    async fn new(must_staple: bool) -> Self {
        Self::with_aia(must_staple, None).await
    }

    async fn with_aia(must_staple: bool, aia: Option<String>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(ControlledStorage::new(directory.path()));
        let ca = Arc::new(Ca::new(storage.clone()));
        *ca.aia.lock().unwrap() = aia;
        ca.must_staple.store(must_staple, Ordering::SeqCst);
        let old_instance = Arc::new(manager(storage.clone(), ca.clone()));
        let resource_a = ca.old_resource();
        old_instance
            .certificates
            .save(&ca.issuer_key(), &resource_a)
            .await
            .unwrap();
        let cert_a =
            Certificate::from_pem(&resource_a.certificate_pem, &resource_a.private_key_pem)
                .unwrap();
        ca.set_status(&cert_a, 0).await;
        let a = old_instance.cache_certificate(DOMAIN).await.unwrap();
        assert!(!a.needs_renewal(1.0 / 3.0));
        assert_eq!(
            handshake(&old_instance, &ca).await.unwrap(),
            a.cert_chain[0].as_ref()
        );
        // B is issued through the ordinary public transaction with its required
        // verified Good response before any subsequent revocation or outage.
        let new_instance = manager(storage.clone(), ca.clone());
        new_instance.renew(DOMAIN, true).await.unwrap();
        let b = new_instance.cache.get_by_name(DOMAIN).await.unwrap();
        assert_ne!(a.hash, b.hash);
        assert_eq!(crate::ocsp::requires_ocsp_staple(&b).unwrap(), must_staple);
        assert_eq!(b.ocsp_status, Some(crate::ocsp::OcspStatus::Good));
        assert_eq!(
            handshake(&new_instance, &ca).await.unwrap(),
            b.cert_chain[0].as_ref()
        );
        assert_eq!(ca.issues.load(Ordering::SeqCst), 1);
        Self {
            _directory: directory,
            storage,
            ca,
            manager: old_instance,
            a,
            b,
        }
    }

    async fn revoke_a(&mut self) {
        self.ca.set_status(&self.a, 1).await;
        assert!(
            !crate::ocsp::staple_ocsp(self.storage.as_ref(), &mut self.a, &OcspConfig::default())
                .await
                .unwrap()
        );
        assert_eq!(self.a.ocsp_status, Some(crate::ocsp::OcspStatus::Revoked));
        self.manager
            .cache
            .replace(&self.a.hash, self.a.clone())
            .await;
    }

    async fn observe(&self) -> Result<()> {
        self.manager
            .renew_observed_revocation(
                DOMAIN,
                &crate::storage::certificate_leaf_hash(&self.a).unwrap(),
            )
            .await
    }

    async fn recovered(&self) {
        assert_eq!(self.ca.issues.load(Ordering::SeqCst), 2);
        let recovered = self.manager.cache.get_by_name(DOMAIN).await.unwrap();
        assert_ne!(recovered.hash, self.b.hash);
        assert_eq!(recovered.ocsp_status, Some(crate::ocsp::OcspStatus::Good));
        assert_eq!(
            handshake(&self.manager, &self.ca).await.unwrap(),
            recovered.cert_chain[0].as_ref()
        );
    }

    async fn schedule_revocation(&self) {
        let mut due = self.a.clone();
        due.ocsp_response = Some(crate::ocsp::tests::signed_response(
            &due.cert_chain,
            &self.ca.key,
            0,
            Utc::now() - chrono::Duration::hours(4),
            Utc::now() + chrono::Duration::hours(1),
        ));
        self.manager.cache.replace(&due.hash.clone(), due).await;
        self.ca.set_status(&self.a, 1).await;
        self.ca.set_status(&self.b, 1).await;
    }
}

#[tokio::test]
async fn observed_callback_recovers_a_new_revoked_must_staple_replacement() {
    let mut fixture = Fixture::new(true).await;
    fixture.revoke_a().await;
    fixture.ca.set_status(&fixture.b, 1).await;
    fixture.observe().await.unwrap();
    fixture.recovered().await;
    fixture.manager.manage(&[DOMAIN.into()]).await.unwrap();
    assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn default_maintenance_recovers_the_shared_revoked_must_staple_replacement() {
    let fixture = Fixture::new(true).await;
    fixture.schedule_revocation().await;
    let maintenance = crate::start_maintenance(&fixture.manager);
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture
            .manager
            .cache
            .resolve(DOMAIN)
            .is_none_or(|entry| entry.hash == fixture.a.hash || entry.hash == fixture.b.hash)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.manager.cache.stop_and_wait(),
    )
    .await
    .unwrap();
    maintenance.await.unwrap();
    fixture.recovered().await;
}

#[tokio::test]
async fn healthy_replacement_is_only_reloaded_for_both_certificate_types() {
    for must_staple in [false, true] {
        let mut fixture = Fixture::new(must_staple).await;
        fixture.revoke_a().await;
        fixture.observe().await.unwrap();
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        assert_eq!(
            handshake(&fixture.manager, &fixture.ca).await.unwrap(),
            fixture.b.cert_chain[0].as_ref()
        );
    }
}

#[tokio::test]
async fn fresh_unknown_or_unavailable_ocsp_does_not_force_the_replacement() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for unavailable in [false, true] {
        let mut fixture = Fixture::new(true).await;
        fixture.revoke_a().await;
        let server = if unavailable {
            fixture
                .storage
                .delete(&crate::storage::ocsp_key(DOMAIN, &fixture.b.hash))
                .await
                .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            Arc::get_mut(&mut fixture.manager)
                .unwrap()
                .policy
                .ocsp
                .responder_overrides
                .insert(DOMAIN.into(), url);
            Some(tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            }))
        } else {
            fixture.ca.set_status(&fixture.b, 2).await;
            None
        };
        let error = fixture.observe().await.unwrap_err();
        assert!(matches!(
            error,
            crate::Error::Cert(crate::error::CertError::OcspFailed(_))
        ));
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&fixture.b.hash)
                .await
                .is_none()
        );
        assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
        if let Some(server) = server {
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn due_unknown_replacement_uses_one_normal_renewal_attempt() {
    let mut fixture = Fixture::new(true).await;
    fixture.revoke_a().await;
    fixture.ca.set_status(&fixture.b, 2).await;
    let forced = Arc::new(Mutex::new(Vec::new()));
    let observed = forced.clone();
    let manager = Arc::get_mut(&mut fixture.manager).unwrap();
    manager.policy.renewal_window_ratio = 1.0;
    manager.on_event = Some(Arc::new(move |event, data| {
        if event == super::EVENT_CERT_OBTAINING {
            observed
                .lock()
                .unwrap()
                .push(data["forced"].as_bool().unwrap());
        }
        Ok(())
    }));
    fixture.observe().await.unwrap();
    fixture.recovered().await;
    assert_eq!(*forced.lock().unwrap(), vec![false]);
}

#[tokio::test]
async fn a_ca_failure_is_a_single_attempt_and_never_serves_the_revoked_replacement() {
    let mut fixture = Fixture::new(true).await;
    fixture.revoke_a().await;
    fixture.ca.set_status(&fixture.b, 1).await;
    fixture.ca.fail.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), fixture.observe())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 2);
    assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
}

#[tokio::test]
async fn planning_wait_rechecks_replacement_identity_and_management() {
    for mutation in ["replace", "remove", "unmanage"] {
        let mut fixture = Fixture::new(true).await;
        fixture.revoke_a().await;
        fixture.ca.set_status(&fixture.b, 1).await;
        *fixture.storage.gate_key.lock().unwrap() =
            Some(crate::storage::ocsp_key(DOMAIN, &fixture.b.hash));
        let manager = fixture.manager.clone();
        let leaf = crate::storage::certificate_leaf_hash(&fixture.a).unwrap();
        let worker =
            tokio::spawn(async move { manager.renew_observed_revocation(DOMAIN, &leaf).await });
        tokio::time::timeout(Duration::from_secs(5), fixture.storage.entered.notified())
            .await
            .unwrap();
        let replacement = match mutation {
            "replace" => {
                let resource = fixture.ca.resource(true, 1);
                let cert =
                    Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                        .unwrap();
                fixture.ca.set_status(&cert, 0).await;
                fixture
                    .manager
                    .certificates
                    .save(&fixture.ca.issuer_key(), &resource)
                    .await
                    .unwrap();
                Some(cert)
            }
            "remove" => {
                fixture.manager.cache.remove(&fixture.a.hash).await;
                None
            }
            "unmanage" => {
                let mut unmanaged = fixture.a.clone();
                unmanaged.managed = false;
                fixture
                    .manager
                    .cache
                    .replace(&unmanaged.hash.clone(), unmanaged)
                    .await;
                None
            }
            _ => unreachable!(),
        };
        fixture.storage.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&fixture.b.hash)
                .await
                .is_none()
        );
        if let Some(replacement) = replacement {
            assert_eq!(
                handshake(&fixture.manager, &fixture.ca).await.unwrap(),
                replacement.cert_chain[0].as_ref()
            );
        } else {
            assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
        }
    }
}

#[tokio::test]
async fn primary_store_and_marker_failures_propagate_without_issuance() {
    for marker in [false, true] {
        let mut fixture = Fixture::new(true).await;
        fixture.revoke_a().await;
        fixture.ca.set_status(&fixture.b, 1).await;
        if marker {
            fixture.storage.fail_marker.store(true, Ordering::SeqCst);
        } else {
            fixture.storage.fail_resource.store(true, Ordering::SeqCst);
        }
        let error = fixture.observe().await.unwrap_err();
        assert!(matches!(error, crate::Error::Storage(_)), "{error:?}");
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&fixture.b.hash)
                .await
                .is_none()
        );
        assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
    }
}

#[tokio::test]
async fn revocation_intent_or_local_quarantine_cannot_be_bypassed_by_replacement_recovery() {
    for kind in ["pending", "confirmed", "local"] {
        let mut fixture = Fixture::new(true).await;
        fixture.revoke_a().await;
        fixture.ca.set_status(&fixture.b, 1).await;
        let leaf = crate::storage::certificate_leaf_hash(&fixture.b).unwrap();
        if kind == "local" {
            fixture.manager.cache.deny_revoked_certificate(&leaf).await;
        } else {
            crate::storage::store_revocation(fixture.storage.as_ref(), &leaf, kind == "confirmed")
                .await
                .unwrap();
        }
        let error = fixture.observe().await.unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::Cert(crate::error::CertError::Revoked(_))
            ),
            "{error:?}"
        );
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&fixture.b.hash)
                .await
                .is_none()
        );
        assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
    }
}

#[tokio::test]
async fn stopping_default_maintenance_cancels_replacement_recovery_during_a_slow_ca() {
    let fixture = Fixture::new(true).await;
    fixture.schedule_revocation().await;
    fixture.ca.gated.store(true, Ordering::SeqCst);
    let maintenance = crate::start_maintenance(&fixture.manager);
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.ca.active.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.manager.cache.stop_and_wait(),
    )
    .await
    .unwrap();
    maintenance.await.unwrap();
    assert_eq!(fixture.ca.active.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 2);
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&fixture.b.hash)
            .await
            .is_none()
    );
    assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
}

#[tokio::test]
async fn admission_aia_wait_cannot_restore_management_after_the_observation_is_removed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for remove in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/issuer.der", listener.local_addr().unwrap());
        let mut fixture = Fixture::with_aia(true, Some(url)).await;
        fixture.revoke_a().await;
        let mut resource = fixture
            .manager
            .certificates
            .load(&fixture.ca.issuer_key(), DOMAIN)
            .await
            .unwrap()
            .unwrap();
        resource.certificate_pem = pem::encode(&pem::Pem::new(
            "CERTIFICATE",
            fixture.b.cert_chain[0].as_ref(),
        ))
        .into_bytes();
        let mut leaf_only =
            Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem).unwrap();
        leaf_only.managed = true;
        leaf_only.issuer_key = fixture.ca.issuer_key();
        fixture
            .storage
            .store(
                &crate::storage::ocsp_key(DOMAIN, &leaf_only.hash),
                fixture.b.ocsp_response.as_ref().unwrap(),
            )
            .await
            .unwrap();
        fixture
            .manager
            .certificates
            .save(&fixture.ca.issuer_key(), &resource)
            .await
            .unwrap();
        let cached_events = Arc::new(AtomicUsize::new(0));
        let counted = cached_events.clone();
        Arc::get_mut(&mut fixture.manager).unwrap().on_event = Some(Arc::new(move |event, _| {
            if event == super::EVENT_CACHED_MANAGED_CERT {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let body = fixture.ca.root.clone();
        let server = tokio::spawn({
            let entered = entered.clone();
            let release = release.clone();
            async move {
                for request in 1..=2 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut bytes = [0; 4096];
                    assert!(socket.read(&mut bytes).await.unwrap() > 0);
                    if request == 2 {
                        entered.notify_one();
                        release.acquire().await.unwrap().forget();
                    }
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                    socket.write_all(body.as_ref()).await.unwrap();
                }
            }
        });
        let manager = fixture.manager.clone();
        let leaf = crate::storage::certificate_leaf_hash(&fixture.a).unwrap();
        let worker =
            tokio::spawn(async move { manager.renew_observed_revocation(DOMAIN, &leaf).await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&leaf_only.hash)
                .await
                .is_none()
        );
        if remove {
            fixture.manager.cache.remove(&fixture.a.hash).await;
        } else {
            let mut old = fixture.a.clone();
            old.managed = false;
            fixture.manager.cache.replace(&old.hash.clone(), old).await;
        }
        release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server.await.unwrap();
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&leaf_only.hash)
                .await
                .is_none(),
            "stale admission recreated managed B after A was withdrawn"
        );
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        assert_eq!(cached_events.load(Ordering::SeqCst), 0);
        assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
    }
}

#[tokio::test]
async fn warm_replacement_revocation_is_sticky_against_an_older_good_storage_response() {
    let mut fixture = Fixture::new(true).await;
    fixture.revoke_a().await;
    fixture.ca.set_status(&fixture.b, 1).await;
    let mut revoked = fixture.b.clone();
    assert!(
        !crate::ocsp::staple_ocsp(
            fixture.storage.as_ref(),
            &mut revoked,
            &OcspConfig::default()
        )
        .await
        .unwrap()
    );
    fixture.manager.cache.add(revoked).await;
    fixture
        .storage
        .store(
            &crate::storage::ocsp_key(DOMAIN, &fixture.b.hash),
            fixture.b.ocsp_response.as_ref().unwrap(),
        )
        .await
        .unwrap();
    fixture.observe().await.unwrap();
    fixture.recovered().await;
}

#[tokio::test]
async fn skipped_admission_preserves_verified_revocation_without_promoting_the_existing_entry() {
    let mut fixture = Fixture::new(true).await;
    fixture.revoke_a().await;
    let mut imported = fixture.b.clone();
    imported.managed = false;
    imported.tags = vec!["operator-import".into()];
    fixture.manager.cache.add(imported).await;
    fixture.manager.cache.remove(&fixture.a.hash).await;
    fixture.ca.set_status(&fixture.b, 1).await;
    let raw = fixture
        .storage
        .load(&crate::storage::ocsp_key(DOMAIN, &fixture.b.hash))
        .await
        .unwrap();
    let incoming = fixture.b.clone().with_ocsp(raw);
    let updates = Arc::new(AtomicUsize::new(0));
    let counted = updates.clone();
    let hash = fixture.b.hash.clone();
    fixture.manager.cache.set_options(crate::cache::CacheOptions {
        on_event: Some(Arc::new(move |event| {
            if matches!(event, crate::cache::CacheEvent::Updated { hash: updated, .. } if updated == hash) {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        })),
        ..Default::default()
    }).await;
    let mut changed = fixture.manager.cache.subscribe_ocsp();
    changed.borrow_and_update();
    let observed = crate::storage::certificate_leaf_hash(&fixture.a).unwrap();
    assert!(
        !fixture
            .manager
            .cache
            .add_managed_if_observed_revoked(incoming.clone(), DOMAIN, &observed)
            .await
            .unwrap()
    );
    let current = fixture
        .manager
        .cache
        .get_by_hash(&fixture.b.hash)
        .await
        .unwrap();
    assert!(!current.managed);
    assert_eq!(current.tags, vec!["operator-import"]);
    assert_eq!(current.ocsp_status, Some(crate::ocsp::OcspStatus::Revoked));
    assert_eq!(updates.load(Ordering::SeqCst), 1);
    assert!(changed.has_changed().unwrap());
    assert!(fixture.manager.cache.next_ocsp_deadline().unwrap() > Utc::now());
    assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
    changed.borrow_and_update();
    assert!(
        !fixture
            .manager
            .cache
            .add_managed_if_observed_revoked(incoming, DOMAIN, &observed)
            .await
            .unwrap()
    );
    assert_eq!(updates.load(Ordering::SeqCst), 1);
    assert!(!changed.has_changed().unwrap());
}

#[tokio::test]
async fn planning_skip_still_quarantines_an_existing_unmanaged_replacement() {
    for mutation in ["remove", "unmanage", "replace"] {
        let mut fixture = Fixture::new(true).await;
        fixture.revoke_a().await;
        let mut imported = fixture.b.clone();
        imported.managed = false;
        imported.tags = vec!["operator-import".into()];
        fixture.manager.cache.add(imported).await;
        assert_eq!(
            handshake(&fixture.manager, &fixture.ca).await.unwrap(),
            fixture.b.cert_chain[0].as_ref()
        );
        fixture.ca.set_status(&fixture.b, 1).await;
        *fixture.storage.gate_key.lock().unwrap() =
            Some(crate::storage::ocsp_key(DOMAIN, &fixture.b.hash));
        let updates = Arc::new(AtomicUsize::new(0));
        let counted = updates.clone();
        let hash = fixture.b.hash.clone();
        fixture.manager.cache.set_options(crate::cache::CacheOptions {
            on_event: Some(Arc::new(move |event| {
                if matches!(event, crate::cache::CacheEvent::Updated { hash: updated, .. } if updated == hash) {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
            })),
            ..Default::default()
        }).await;
        let manager = fixture.manager.clone();
        let observed = crate::storage::certificate_leaf_hash(&fixture.a).unwrap();
        let worker =
            tokio::spawn(async move { manager.renew_observed_revocation(DOMAIN, &observed).await });
        tokio::time::timeout(Duration::from_secs(5), fixture.storage.entered.notified())
            .await
            .unwrap();
        let replacement = match mutation {
            "replace" => {
                let resource = fixture.ca.resource(true, 1);
                let cert =
                    Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                        .unwrap();
                fixture.ca.set_status(&cert, 0).await;
                fixture
                    .manager
                    .certificates
                    .save(&fixture.ca.issuer_key(), &resource)
                    .await
                    .unwrap();
                Some(cert)
            }
            "remove" => {
                fixture.manager.cache.remove(&fixture.a.hash).await;
                None
            }
            "unmanage" => {
                let mut old = fixture.a.clone();
                old.managed = false;
                fixture.manager.cache.replace(&old.hash.clone(), old).await;
                None
            }
            _ => unreachable!(),
        };
        fixture.storage.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let current = fixture
            .manager
            .cache
            .get_by_hash(&fixture.b.hash)
            .await
            .unwrap();
        assert!(!current.managed);
        assert_eq!(current.tags, vec!["operator-import"]);
        assert_eq!(
            current.ocsp_status,
            Some(crate::ocsp::OcspStatus::Revoked),
            "{mutation}: verified evidence was lost at a stale planning return"
        );
        assert!(current.ocsp_response.is_none());
        assert_eq!(updates.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.ca.issues.load(Ordering::SeqCst), 1);
        if let Some(replacement) = replacement {
            assert_eq!(
                handshake(&fixture.manager, &fixture.ca).await.unwrap(),
                replacement.cert_chain[0].as_ref()
            );
        } else {
            assert!(handshake(&fixture.manager, &fixture.ca).await.is_err());
        }
    }
}
