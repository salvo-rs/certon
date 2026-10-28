use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::{
    CertIssuer, CertManager, CertStore, Certificate, CertificateResource, FileStorage,
    IssuedCertificate, KeyValueCertStore, OcspConfig, Result, Revoker, Storage,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};

const DOMAIN: &str = "revoke-target.example.com";

struct MockCa {
    name: &'static str,
    issuer: rcgen::Issuer<'static, KeyPair>,
    root: rustls::pki_types::CertificateDer<'static>,
    leaf_key: String,
    not_before_offset: i64,
    fail_issuance: bool,
    issues: AtomicUsize,
    revokes: AtomicUsize,
    fail_revocation: AtomicBool,
    supports_revocation: AtomicBool,
    revoked: Mutex<Vec<Vec<u8>>>,
}

fn timestamp(offset: i64) -> rcgen::CertificateParams {
    let mut params = CertificateParams::new(vec![DOMAIN.into()]).unwrap();
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    params.not_before = epoch
        + Duration::from_secs(
            (chrono::Utc::now().timestamp() + offset)
                .try_into()
                .unwrap(),
        );
    params.not_after = epoch
        + Duration::from_secs(
            (chrono::Utc::now().timestamp() + 365 * 86400)
                .try_into()
                .unwrap(),
        );
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params
}

impl MockCa {
    fn new(name: &'static str, leaf_key: String, offset: i64, fail_issuance: bool) -> Arc<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        Arc::new(Self {
            name,
            issuer: rcgen::Issuer::new(params, key),
            root,
            leaf_key,
            not_before_offset: offset,
            fail_issuance,
            issues: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            fail_revocation: AtomicBool::new(false),
            supports_revocation: AtomicBool::new(true),
            revoked: Mutex::new(Vec::new()),
        })
    }

    fn resource(&self, names: &[String]) -> CertificateResource {
        self.resource_with_validity(names, self.not_before_offset, 365 * 86400)
    }

    fn resource_with_validity(
        &self,
        names: &[String],
        before: i64,
        after: i64,
    ) -> CertificateResource {
        let key = KeyPair::from_pem(&self.leaf_key).unwrap();
        let mut params = timestamp(before);
        params.not_after = rcgen::date_time_ymd(1970, 1, 1)
            + Duration::from_secs((chrono::Utc::now().timestamp() + after).try_into().unwrap());
        params.subject_alt_names = names
            .iter()
            .map(|name| rcgen::SanType::DnsName(name.clone().try_into().unwrap()))
            .collect();
        let leaf = params.signed_by(&key, &self.issuer).unwrap();
        CertificateResource {
            sans: names.to_vec(),
            certificate_pem: leaf.pem().into_bytes(),
            private_key_pem: self.leaf_key.as_bytes().to_vec(),
            issuer_key: self.name.into(),
            issuer_data: None,
        }
    }
}

#[async_trait::async_trait]
impl CertIssuer for MockCa {
    async fn issue(&self, csr: &[u8], names: &[String]) -> Result<IssuedCertificate> {
        self.issues.fetch_add(1, Ordering::SeqCst);
        if self.fail_issuance {
            return Err(certon::Error::Other(
                "primary CA temporarily unavailable".into(),
            ));
        }
        // The manager's public reuse_private_keys policy makes the actual CSR
        // use this known key. Verify its SPKI is really present in the CSR.
        let spki = KeyPair::from_pem(&self.leaf_key)
            .unwrap()
            .subject_public_key_info();
        assert!(csr.windows(spki.len()).any(|part| part == spki));
        Ok(IssuedCertificate {
            certificate_pem: self.resource(names).certificate_pem,
            private_key_pem: Vec::new(),
            metadata: Default::default(),
        })
    }
    fn issuer_key(&self) -> String {
        self.name.into()
    }
    fn as_revoker(&self) -> Option<&dyn Revoker> {
        self.supports_revocation
            .load(Ordering::SeqCst)
            .then_some(self)
    }
}

#[async_trait::async_trait]
impl Revoker for MockCa {
    async fn revoke(&self, cert_pem: &[u8], _: Option<u8>) -> Result<()> {
        assert!(cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        self.revokes.fetch_add(1, Ordering::SeqCst);
        self.revoked.lock().unwrap().push(cert_pem.to_vec());
        if self.fail_revocation.load(Ordering::SeqCst) {
            return Err(certon::Error::Other("selected CA revocation failed".into()));
        }
        Ok(())
    }
}

fn handshake(
    manager: &CertManager,
    a: &MockCa,
    b: &MockCa,
) -> std::result::Result<Vec<u8>, String> {
    certon::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(a.root.clone()).unwrap();
    roots.add(b.root.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client = rustls::Connection::Client(
        rustls::ClientConnection::new(Arc::new(client), DOMAIN.try_into().unwrap()).unwrap(),
    );
    let mut server = rustls::Connection::Server(
        rustls::ServerConnection::new(Arc::new(manager.server_config())).unwrap(),
    );
    fn transfer(
        from: &mut rustls::Connection,
        to: &mut rustls::Connection,
    ) -> std::result::Result<(), String> {
        let mut bytes = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut bytes)
                .map_err(|error| error.to_string())?;
        }
        let mut input = Cursor::new(bytes);
        while input.position() < input.get_ref().len() as u64 {
            assert!(to.read_tls(&mut input).map_err(|error| error.to_string())? > 0);
            to.process_new_packets()
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
    for _ in 0..32 {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(client.peer_certificates().unwrap()[0].to_vec());
        }
    }
    Err("TLS handshake made no progress".into())
}

#[tokio::test]
async fn revoke_selects_the_latest_stored_resource_after_a_real_fallback_renewal() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let store = Arc::new(KeyValueCertStore::new(storage.clone()));
    let leaf_key = KeyPair::generate().unwrap().serialize_pem();
    let a = MockCa::new("primary-a", leaf_key.clone(), -2 * 86400, true);
    let b = MockCa::new("fallback-b", leaf_key, -86400, false);
    let initial = a.resource(&[DOMAIN.into()]);
    let a_leaf = Certificate::from_pem(&initial.certificate_pem, &initial.private_key_pem)
        .unwrap()
        .cert_chain[0]
        .to_vec();
    store.save(&a.issuer_key(), &initial).await.unwrap();
    let manager = CertManager::builder()
        .storage(storage)
        .certificates(store.clone())
        .issuers(vec![a.clone(), b.clone()])
        .reuse_private_keys(true)
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .build();
    manager.cache_certificate(DOMAIN).await.unwrap();
    assert_eq!(handshake(&manager, &a, &b).unwrap(), a_leaf);

    // Use the ordinary public renewal fallback flow, not an injected B resource.
    manager.renew(DOMAIN, true).await.unwrap();
    assert_eq!(a.issues.load(Ordering::SeqCst), 1);
    assert_eq!(b.issues.load(Ordering::SeqCst), 1);
    assert!(store.load(&a.issuer_key(), DOMAIN).await.unwrap().is_some());
    let fallback = store.load(&b.issuer_key(), DOMAIN).await.unwrap().unwrap();
    let b_leaf = Certificate::from_pem(&fallback.certificate_pem, &fallback.private_key_pem)
        .unwrap()
        .cert_chain[0]
        .to_vec();
    assert_ne!(b_leaf, a_leaf);
    assert_eq!(handshake(&manager, &a, &b).unwrap(), b_leaf);
    assert_eq!(
        manager
            .load_certificate(DOMAIN)
            .await
            .unwrap()
            .unwrap()
            .issuer_key,
        b.issuer_key()
    );

    manager.revoke(DOMAIN, None).await.unwrap();
    assert_eq!(a.revokes.load(Ordering::SeqCst), 0);
    assert_eq!(b.revokes.load(Ordering::SeqCst), 1);
    assert!(store.load(&a.issuer_key(), DOMAIN).await.unwrap().is_some());
    assert!(store.load(&b.issuer_key(), DOMAIN).await.unwrap().is_none());
    assert!(handshake(&manager, &a, &b).is_err());
}

#[derive(Debug)]
struct FaultStore {
    inner: KeyValueCertStore,
    failed_load: Mutex<Option<String>>,
    failed_remove: Mutex<Option<String>>,
    observe_empty_b: AtomicBool,
    empty_b_read: tokio::sync::Notify,
}
impl FaultStore {
    fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            inner: KeyValueCertStore::new(storage),
            failed_load: Mutex::new(None),
            failed_remove: Mutex::new(None),
            observe_empty_b: AtomicBool::new(false),
            empty_b_read: tokio::sync::Notify::new(),
        }
    }
}
#[async_trait::async_trait]
impl CertStore for FaultStore {
    async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>> {
        if self.failed_load.lock().unwrap().as_deref() == Some(issuer) {
            return Err(certon::Error::Other("selected store read failed".into()));
        }
        let resource = self.inner.load(issuer, domain).await?;
        if issuer == "fallback-b" && self.observe_empty_b.swap(false, Ordering::SeqCst) {
            assert!(resource.is_none());
            self.empty_b_read.notify_one();
        }
        Ok(resource)
    }
    async fn save(&self, issuer: &str, resource: &CertificateResource) -> Result<()> {
        self.inner.save(issuer, resource).await
    }
    async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
        Ok(self.load(issuer, domain).await?.is_some())
    }
    async fn remove(&self, issuer: &str, domain: &str) -> Result<()> {
        if self.failed_remove.lock().unwrap().as_deref() == Some(issuer) {
            return Err(certon::Error::Other("selected store cleanup failed".into()));
        }
        self.inner.remove(issuer, domain).await
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Arc<dyn Storage>,
    store: Arc<FaultStore>,
    a: Arc<MockCa>,
    b: Arc<MockCa>,
    a_resource: CertificateResource,
    b_resource: CertificateResource,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
        let store = Arc::new(FaultStore::new(storage.clone()));
        let key = KeyPair::generate().unwrap().serialize_pem();
        let a = MockCa::new("primary-a", key.clone(), -2 * 86400, true);
        let b = MockCa::new("fallback-b", key, -86400, false);
        let a_resource = a.resource(&[DOMAIN.into()]);
        let b_resource = b.resource(&[DOMAIN.into()]);
        store.save(&a.issuer_key(), &a_resource).await.unwrap();
        store.save(&b.issuer_key(), &b_resource).await.unwrap();
        Self {
            _directory: directory,
            storage,
            store,
            a,
            b,
            a_resource,
            b_resource,
        }
    }
    fn manager(&self) -> CertManager {
        CertManager::builder()
            .storage(self.storage.clone())
            .certificates(self.store.clone())
            .issuers(vec![self.a.clone(), self.b.clone()])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build()
    }
}

#[tokio::test]
async fn pending_and_confirmed_retries_do_not_switch_to_the_unmarked_backup() {
    for confirmed in [false, true] {
        let fixture = Fixture::new().await;
        if confirmed {
            *fixture.store.failed_remove.lock().unwrap() = Some(fixture.b.issuer_key());
        } else {
            fixture.b.fail_revocation.store(true, Ordering::SeqCst);
        }
        let manager = fixture.manager();
        manager.cache_certificate(DOMAIN).await.unwrap();
        assert!(manager.revoke(DOMAIN, None).await.is_err());
        assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 1);
        assert!(handshake(&manager, &fixture.a, &fixture.b).is_err());
        assert!(
            fixture
                .store
                .load(&fixture.b.issuer_key(), DOMAIN)
                .await
                .unwrap()
                .is_some()
        );
        fixture.b.fail_revocation.store(false, Ordering::SeqCst);
        *fixture.store.failed_remove.lock().unwrap() = None;
        // A fresh manager has no in-memory target history. The persistent leaf
        // marker must not change default resource ranking after restart.
        fixture.manager().revoke(DOMAIN, None).await.unwrap();
        assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.b.revokes.load(Ordering::SeqCst),
            if confirmed { 1 } else { 2 }
        );
        assert!(
            fixture
                .store
                .load(&fixture.a.issuer_key(), DOMAIN)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fixture
                .store
                .load(&fixture.b.issuer_key(), DOMAIN)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fixture
                .b
                .revoked
                .lock()
                .unwrap()
                .iter()
                .all(|pem| pem == &fixture.b_resource.certificate_pem)
        );
    }
}

#[tokio::test]
async fn explicit_issuer_can_revoke_an_invalid_resource_without_touching_the_latest_sibling() {
    let fixture = Fixture::new().await;
    let mut broken =
        fixture
            .a
            .resource_with_validity(&["wrong.example.com".into()], -3 * 86400, -86400);
    broken.sans = vec![DOMAIN.into()];
    broken.private_key_pem = b"damaged private key".to_vec();
    fixture
        .store
        .save(&fixture.a.issuer_key(), &broken)
        .await
        .unwrap();
    let manager = fixture.manager();
    let latest = manager.cache_certificate(DOMAIN).await.unwrap();
    manager
        .revoke_from_issuer(DOMAIN, &fixture.a.issuer_key(), None)
        .await
        .unwrap();
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.a.revoked.lock().unwrap()[0], broken.certificate_pem);
    assert_eq!(
        handshake(&manager, &fixture.a, &fixture.b).unwrap(),
        latest.cert_chain[0].as_ref()
    );
    assert!(
        manager
            .revoke_from_issuer(DOMAIN, "not-configured", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not configured")
    );
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn selected_backend_and_unsupported_provider_errors_do_not_redirect_revocation() {
    let fixture = Fixture::new().await;
    let manager = fixture.manager();
    manager.cache_certificate(DOMAIN).await.unwrap();
    *fixture.store.failed_load.lock().unwrap() = Some(fixture.b.issuer_key());
    assert!(
        manager
            .revoke(DOMAIN, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("store read failed")
    );
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 0);
    // Explicit A is independent of B's backend failure.
    manager
        .revoke_from_issuer(DOMAIN, &fixture.a.issuer_key(), None)
        .await
        .unwrap();
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 1);
    let fixture = Fixture::new().await;
    let manager = fixture.manager();
    manager.cache_certificate(DOMAIN).await.unwrap();
    fixture.b.supports_revocation.store(false, Ordering::SeqCst);
    assert!(
        manager
            .revoke(DOMAIN, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not support")
    );
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 0);
    assert!(handshake(&manager, &fixture.a, &fixture.b).is_ok());
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_selected_marker_read_failure_never_redirects_to_another_issuer() {
    for explicit in [false, true] {
        let fixture = Fixture::new().await;
        let leaf = Certificate::from_pem(
            &fixture.b_resource.certificate_pem,
            &fixture.b_resource.private_key_pem,
        )
        .unwrap();
        let hash = certon::certificates::hash_certificate_chain(&leaf.cert_chain[..1]);
        fixture
            .storage
            .store(&format!("revocations/{hash}.json"), b"damaged marker")
            .await
            .unwrap();
        let manager = fixture.manager();
        let error = if explicit {
            manager
                .revoke_from_issuer(DOMAIN, &fixture.b.issuer_key(), None)
                .await
        } else {
            manager.revoke(DOMAIN, None).await
        }
        .unwrap_err();
        assert!(
            error.to_string().contains("invalid revocation marker"),
            "{error}"
        );
        assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 0);
        assert!(
            fixture
                .store
                .load(&fixture.a.issuer_key(), DOMAIN)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fixture
                .store
                .load(&fixture.b.issuer_key(), DOMAIN)
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn default_selection_prefers_a_current_resource_over_a_newer_future_certificate() {
    let fixture = Fixture::new().await;
    let future = fixture
        .b
        .resource_with_validity(&[DOMAIN.into()], 86400, 365 * 86400);
    fixture
        .store
        .save(&fixture.b.issuer_key(), &future)
        .await
        .unwrap();
    fixture.manager().revoke(DOMAIN, None).await.unwrap();
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 0);
    fixture
        .manager()
        .revoke_from_issuer(DOMAIN, &fixture.b.issuer_key(), None)
        .await
        .unwrap();
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn default_target_is_the_selected_stored_resource_not_an_unmanaged_cached_sibling() {
    let fixture = Fixture::new().await;
    let manager = fixture.manager();
    let other = MockCa::new(
        "cache-only",
        KeyPair::generate().unwrap().serialize_pem(),
        -60,
        false,
    );
    let cached = other.resource_with_validity(&[DOMAIN.into()], -60, 730 * 86400);
    let imported = Certificate::from_pem(&cached.certificate_pem, &cached.private_key_pem).unwrap();
    let leaf = imported.cert_chain[0].to_vec();
    manager.cache.add(imported).await;
    assert_eq!(handshake(&manager, &other, &fixture.b).unwrap(), leaf);
    manager.revoke(DOMAIN, None).await.unwrap();
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 1);
    assert_eq!(handshake(&manager, &other, &fixture.b).unwrap(), leaf);
}

#[tokio::test]
async fn leaf_lock_recheck_reselects_a_new_fallback_even_when_the_old_issuer_resource_remains() {
    let fixture = Fixture::new().await;
    fixture
        .store
        .remove(&fixture.b.issuer_key(), DOMAIN)
        .await
        .unwrap();
    fixture.store.observe_empty_b.store(true, Ordering::SeqCst);
    let cert = Certificate::from_pem(
        &fixture.a_resource.certificate_pem,
        &fixture.a_resource.private_key_pem,
    )
    .unwrap();
    let hash = certon::certificates::hash_certificate_chain(&cert.cert_chain[..1]);
    // Model another alias's renewal, holding the old leaf while publishing B.
    let alias_renewal =
        certon::acquire(fixture.storage.clone(), &format!("certificate_leaf_{hash}"))
            .await
            .unwrap();
    let manager = Arc::new(fixture.manager());
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.revoke(DOMAIN, None).await }
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.store.empty_b_read.notified(),
    )
    .await
    .unwrap();
    fixture
        .store
        .save(&fixture.b.issuer_key(), &fixture.b_resource)
        .await
        .unwrap();
    alias_renewal.release().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(fixture.a.revokes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.b.revokes.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .store
            .load(&fixture.a.issuer_key(), DOMAIN)
            .await
            .unwrap()
            .is_some()
    );
}
