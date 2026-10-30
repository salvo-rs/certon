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
        }
    }
    fn resource(&self, before: i32, after: i32) -> CertificateResource {
        let mut params = CertificateParams::new(vec!["example.com".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(before, 1, 1);
        params.not_after = rcgen::date_time_ymd(after, 1, 1);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.ca).unwrap();
        CertificateResource {
            sans: vec!["example.com".into()],
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
    fn maintain(&self, outcomes: Arc<std::sync::Mutex<Vec<bool>>>) -> tokio::task::JoinHandle<()> {
        let manager = self.manager.clone();
        // Exercise the same manager renewal callback used by crate-level
        // maintenance; a rejected reload must not later publish B as a no-op.
        let renew: Arc<certon::maintain::ReasonedRenewFn> = Arc::new(move |domain, reason| {
            let manager = manager.clone();
            let outcomes = outcomes.clone();
            Box::pin(async move {
                let result = manager
                    .renew(&domain, reason == certon::maintain::RenewalReason::Revoked)
                    .await;
                outcomes.lock().unwrap().push(result.is_ok());
                result
            })
        });
        certon::maintain::start_maintenance_with_policy(
            self.manager.cache.clone(),
            certon::maintain::MaintenanceConfig {
                renew_check_interval: Duration::from_millis(5),
                ocsp_check_interval: Duration::from_secs(3600),
                storage: self.storage.clone(),
                ocsp: OcspConfig {
                    disable_stapling: true,
                    ..Default::default()
                },
            },
            renew,
            self.store.clone(),
            self.manager.policy.renewal_window_ratio,
        )
    }
    async fn handshake(&self) -> Vec<u8> {
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
            connector.connect("example.com".try_into().unwrap(), client_io)
        );
        server.unwrap();
        client.unwrap().get_ref().1.peer_certificates().unwrap()[0].to_vec()
    }
}

async fn wait_for(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("maintenance did not complete an attempt");
}

#[tokio::test]
async fn maintenance_keeps_valid_leaf_when_future_or_expired_storage_and_renewal_fail() {
    for future in [true, false] {
        let fixture = Fixture::new().await;
        assert_eq!(
            fixture.handshake().await,
            fixture.old.cert_chain[0].as_ref()
        );
        let year = chrono::Utc::now().year();
        let candidate = if future {
            fixture.issuer.resource(year + 1, year + 5)
        } else {
            fixture.issuer.resource(year - 3, year - 1)
        };
        fixture
            .store
            .save(&fixture.issuer.issuer_key(), &candidate)
            .await
            .unwrap();
        let outcomes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let task = fixture.maintain(outcomes.clone());
        wait_for(|| !outcomes.lock().unwrap().is_empty()).await;
        assert!(
            !outcomes.lock().unwrap()[0],
            "unusable storage leaf incorrectly skipped renewal and reported success"
        );
        assert!(fixture.issuer.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(
            fixture.handshake().await,
            fixture.old.cert_chain[0].as_ref()
        );
        // Once the CA recovers, the normal renewal path must issue and publish
        // a currently valid leaf rather than getting stuck on future B.
        fixture.issuer.fail.store(false, Ordering::SeqCst);
        // Maintenance now retains at least a 60-second failed-attempt deadline.
        // Advance only that monotonic backoff; certificate validity uses UTC.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::resume();
        wait_for(|| outcomes.lock().unwrap().contains(&true)).await;
        let renewed = fixture.handshake().await;
        assert_ne!(renewed, fixture.old.cert_chain[0].as_ref());
        let stored = fixture
            .store
            .load(&fixture.issuer.issuer_key(), "example.com")
            .await
            .unwrap()
            .unwrap();
        let cert = certon::Certificate::from_pem(&stored.certificate_pem, &stored.private_key_pem)
            .unwrap();
        assert_eq!(renewed, cert.cert_chain[0].as_ref());
        fixture.manager.cache.stop_and_wait().await;
        task.await.unwrap();
    }
}

#[tokio::test]
async fn maintenance_reloads_a_currently_valid_stored_leaf_without_issuance() {
    let fixture = Fixture::new().await;
    let year = chrono::Utc::now().year();
    let resource = fixture.issuer.resource(year - 1, year + 4);
    let replacement =
        certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
            .unwrap();
    fixture
        .store
        .save(&fixture.issuer.issuer_key(), &resource)
        .await
        .unwrap();
    let outcomes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let task = fixture.maintain(outcomes.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture
            .manager
            .cache
            .get_by_hash(&replacement.hash)
            .await
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture.handshake().await,
        replacement.cert_chain[0].as_ref()
    );
    assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 0);
    assert!(outcomes.lock().unwrap().is_empty());
    fixture.manager.cache.stop_and_wait().await;
    task.await.unwrap();
}

#[tokio::test]
async fn public_reload_rejects_future_and_expired_leaves_before_replacing_live_cache() {
    for state in ["future", "expired", "valid"] {
        let fixture = Fixture::new().await;
        let year = chrono::Utc::now().year();
        let resource = match state {
            "future" => fixture.issuer.resource(year + 1, year + 5),
            "expired" => fixture.issuer.resource(year - 3, year - 1),
            _ => fixture.issuer.resource(year - 1, year + 4),
        };
        let cert =
            certon::Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem)
                .unwrap();
        fixture
            .store
            .save(&fixture.issuer.issuer_key(), &resource)
            .await
            .unwrap();
        let result = certon::certificates::reload_managed_certificate(
            &fixture.manager.cache,
            fixture.storage.as_ref(),
            "example.com",
            &fixture.issuer.issuer_key(),
        )
        .await;
        if state == "valid" {
            result.unwrap();
            assert_eq!(fixture.handshake().await, cert.cert_chain[0].as_ref());
        } else {
            match result.unwrap_err() {
                certon::Error::Cert(certon::error::CertError::NotYetValid(_)) => {
                    assert_eq!(state, "future")
                }
                certon::Error::Cert(certon::error::CertError::Expired(_)) => {
                    assert_eq!(state, "expired")
                }
                other => panic!("unexpected reload error: {other}"),
            }
            assert_eq!(
                fixture.handshake().await,
                fixture.old.cert_chain[0].as_ref()
            );
        }
    }
}

#[tokio::test]
async fn unmanaged_import_is_taken_over_and_renewed_by_real_maintenance() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let store: Arc<dyn CertStore> = Arc::new(KeyValueCertStore::new(storage.clone()));
    let issuer = Arc::new(Issuer::new());
    let year = chrono::Utc::now().year();
    let resource = issuer.resource(year - 1, year + 4);
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
    manager
        .cache
        .cache_unmanaged_pem(
            &resource.certificate_pem,
            &resource.private_key_pem,
            vec!["operator".into()],
        )
        .await
        .unwrap();
    let old = manager.cache.get_by_name("example.com").await.unwrap();
    assert!(!old.managed);
    let mut fixture = Fixture {
        _directory: directory,
        storage,
        store,
        issuer,
        manager,
        old,
    };
    assert_eq!(
        fixture.handshake().await,
        fixture.old.cert_chain[0].as_ref()
    );
    fixture
        .manager
        .manage(&["example.com".into()])
        .await
        .unwrap();
    let promoted = fixture
        .manager
        .cache
        .get_by_hash(&fixture.old.hash)
        .await
        .unwrap();
    assert!(
        promoted.managed,
        "manage returned success without enrolling the imported leaf in maintenance"
    );
    assert_eq!(promoted.issuer_key, fixture.issuer.issuer_key());
    assert_eq!(
        promoted.names.first().map(String::as_str),
        Some("example.com")
    );
    assert_eq!(promoted.tags, vec!["operator"]);
    assert_eq!(
        fixture.manager.cache.get_managed_certificates().await.len(),
        1
    );
    assert_eq!(
        fixture.issuer.calls.load(Ordering::SeqCst),
        0,
        "takeover must not needlessly reissue a fresh import"
    );
    // Enter a wider renewal window after takeover. Both the scan and its real
    // manager callback use that policy, exercising the managed sampling pool.
    Arc::get_mut(&mut fixture.manager)
        .unwrap()
        .policy
        .renewal_window_ratio = 0.95;
    fixture.issuer.fail.store(false, Ordering::SeqCst);
    let outcomes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let maintenance = fixture.maintain(outcomes.clone());
    wait_for(|| outcomes.lock().unwrap().contains(&true)).await;
    fixture.manager.cache.stop_and_wait().await;
    maintenance.await.unwrap();
    assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
    let renewed = fixture.handshake().await;
    assert_ne!(renewed, fixture.old.cert_chain[0].as_ref());
    let current = fixture
        .manager
        .cache
        .get_by_name("example.com")
        .await
        .unwrap();
    assert!(current.managed);
    assert!(!current.needs_renewal(fixture.manager.policy.renewal_window_ratio));
    assert_eq!(renewed, current.cert_chain[0].as_ref());
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&fixture.old.hash)
            .await
            .is_none()
    );
}
