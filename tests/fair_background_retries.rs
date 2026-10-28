use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::async_jobs::RetryConfig;
use certon::{
    CertIssuer, CertManager, CertStore, CertificateResource, FileStorage, IssuedCertificate,
    KeyValueCertStore, OcspConfig, Result, Storage,
};
use chrono::Datelike;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
use x509_parser::prelude::FromDer;

struct CsrKey(Vec<u8>);
impl PublicKeyData for CsrKey {
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
    failures: Mutex<HashMap<String, usize>>,
    calls: Mutex<Vec<String>>,
    gated: Mutex<Option<String>>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    active: std::sync::atomic::AtomicUsize,
    maximum: std::sync::atomic::AtomicUsize,
}
impl Issuer {
    fn new() -> Self {
        let mut params = CertificateParams::new(vec!["retry-test-root".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap().der().clone();
        Self {
            ca: rcgen::Issuer::new(params, key),
            root,
            failures: Mutex::default(),
            calls: Mutex::default(),
            gated: Mutex::new(None),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            active: std::sync::atomic::AtomicUsize::new(0),
            maximum: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn fail(&self, domain: &str, attempts: usize) {
        self.failures
            .lock()
            .unwrap()
            .insert(domain.into(), attempts);
    }
    fn calls(&self, domain: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|called| called.as_str() == domain)
            .count()
    }
    fn old_resource(&self, names: &[&str]) -> CertificateResource {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let year = chrono::Utc::now().year();
        params.not_before = rcgen::date_time_ymd(year - 4, 1, 1);
        params.not_after = rcgen::date_time_ymd(year + 1, 1, 1);
        let cert = params.signed_by(&key, &self.ca).unwrap();
        CertificateResource {
            sans: names.iter().map(|name| name.to_string()).collect(),
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
        let domain = &domains[0];
        self.calls.lock().unwrap().push(domain.clone());
        let failed = {
            let mut failures = self.failures.lock().unwrap();
            let remaining = failures.entry(domain.clone()).or_default();
            if *remaining == 0 {
                false
            } else {
                if *remaining != usize::MAX {
                    *remaining -= 1;
                }
                true
            }
        };
        if failed {
            return Err(certon::Error::Other(
                "per-domain transient issuer failure".into(),
            ));
        }
        use std::sync::atomic::Ordering;
        struct Active<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        let _active = Active(&self.active);
        let gated = self.gated.lock().unwrap().as_deref() == Some(domain.as_str());
        if gated {
            self.entered.notify_one();
            let _permit = self.release.acquire().await.unwrap();
        }
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = CsrKey(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let cert = CertificateParams::new(domains.to_vec())
            .unwrap()
            .signed_by(&public, &self.ca)
            .unwrap();
        Ok(IssuedCertificate {
            certificate_pem: cert.pem().into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    fn issuer_key(&self) -> String {
        "retry-test-ca".into()
    }
    fn as_revoker(&self) -> Option<&dyn certon::Revoker> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl certon::Revoker for Issuer {
    async fn revoke(&self, _: &[u8], _: Option<u8>) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct AliasStore {
    resource: Mutex<Option<CertificateResource>>,
    keep_on_remove: bool,
}
#[async_trait::async_trait]
impl CertStore for AliasStore {
    async fn load(&self, _: &str, _: &str) -> Result<Option<CertificateResource>> {
        Ok(self.resource.lock().unwrap().clone())
    }
    async fn save(&self, _: &str, resource: &CertificateResource) -> Result<()> {
        *self.resource.lock().unwrap() = Some(resource.clone());
        Ok(())
    }
    async fn has(&self, _: &str, _: &str) -> Result<bool> {
        Ok(self.resource.lock().unwrap().is_some())
    }
    async fn remove(&self, _: &str, _: &str) -> Result<()> {
        if self.keep_on_remove {
            return Err(certon::Error::Other(
                "keep revoked resource to exercise tombstone checks".into(),
            ));
        }
        *self.resource.lock().unwrap() = None;
        Ok(())
    }
}

struct ObservedStorage {
    files: FileStorage,
    leaf_requests: std::sync::atomic::AtomicUsize,
    a_domain_requests: std::sync::atomic::AtomicUsize,
    release_a_retry: tokio::sync::Semaphore,
}
#[async_trait::async_trait]
impl Storage for ObservedStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.files.store(key, value).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.files.load(key).await
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
    async fn stat(&self, key: &str) -> Result<certon::storage::KeyInfo> {
        self.files.stat(key).await
    }
    async fn lock(&self, key: &str) -> Result<()> {
        if key == "issue_cert_a.example.com"
            && self
                .a_domain_requests
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                > 0
        {
            let _permit = self.release_a_retry.acquire().await.unwrap();
        }
        if key.starts_with("certificate_leaf_") {
            self.leaf_requests
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.files.lock(key).await
    }
    async fn unlock(&self, key: &str) -> Result<()> {
        self.files.unlock(key).await
    }
}

async fn until<F, Fut>(mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition().await {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("background condition did not complete");
}

async fn handshake(manager: &CertManager, issuer: &Issuer, domain: &str) -> Vec<u8> {
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
        connector.connect(domain.to_owned().try_into().unwrap(), client_io)
    );
    server.unwrap();
    client.unwrap().get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

fn config() -> RetryConfig {
    RetryConfig {
        intervals: vec![Duration::from_secs(3600)],
        max_duration: Duration::from_secs(86400),
        max_retries: 0,
    }
}

#[tokio::test]
async fn four_backing_off_domains_do_not_delay_a_healthy_domains_first_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let issuer = Arc::new(Issuer::new());
    let bad: Vec<_> = (0..4).map(|i| format!("bad-{i}.example.com")).collect();
    for domain in &bad {
        issuer.fail(domain, usize::MAX);
    }
    let manager = CertManager::builder()
        .storage(storage.clone())
        .issuers(vec![issuer.clone()])
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .background_retry_config(config())
        .build();
    manager.manage_in_background(&bad).await.unwrap();
    until(|| async { bad.iter().all(|domain| issuer.calls(domain) == 1) }).await;
    manager
        .manage_in_background(&["healthy.example.com".into()])
        .await
        .unwrap();
    until(|| async {
        manager
            .cache
            .get_by_name("healthy.example.com")
            .await
            .is_some()
    })
    .await;
    assert_eq!(issuer.calls("healthy.example.com"), 1);
    assert!(
        !handshake(&manager, &issuer, "healthy.example.com")
            .await
            .is_empty()
    );
    for domain in &bad {
        assert_eq!(issuer.calls(domain), 1, "healthy work waited until a retry");
        let lock = certon::try_acquire(
            storage.clone(),
            &format!("issue_cert_{domain}"),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .expect("backoff retained a domain transaction lock");
        lock.release().await.unwrap();
    }
}

#[tokio::test]
async fn full_retry_backlog_is_observable_and_a_shed_domain_can_be_resubmitted() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(Issuer::new());
    let domains: Vec<_> = (0..68).map(|i| format!("bad-{i}.example.com")).collect();
    for domain in &domains {
        issuer.fail(domain, usize::MAX);
    }
    let shed = Arc::new(Mutex::new(Vec::new()));
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .issuers(vec![issuer.clone()])
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .background_retry_config(config())
        .on_event({
            let shed = shed.clone();
            Arc::new(move |name, data| {
                if name == certon::manager::EVENT_CERT_FAILED
                    && data["error_kind"] == "retry_backlog_full"
                {
                    assert_eq!(data["background"], true);
                    shed.lock()
                        .unwrap()
                        .push(data["identifier"].as_str().unwrap().to_string());
                }
                Ok(())
            })
        })
        .build();
    manager.manage_in_background(&domains).await.unwrap();
    until(|| async { shed.lock().unwrap().len() == 4 }).await;
    let domain = shed.lock().unwrap()[0].clone();
    issuer.fail(&domain, 0);
    manager
        .manage_in_background(std::slice::from_ref(&domain))
        .await
        .unwrap();
    until(|| async { manager.cache.get_by_name(&domain).await.is_some() }).await;
    assert_eq!(issuer.calls(&domain), 2);
    assert!(!handshake(&manager, &issuer, &domain).await.is_empty());
    // Rejected renewal retention must also be resubmittable: its first failed
    // attempt already cached the old leaf as managed, unlike a first issuance.
    let old = issuer.old_resource(&["renew.example.com"]);
    manager
        .certificates
        .save(&issuer.issuer_key(), &old)
        .await
        .unwrap();
    issuer.fail("renew.example.com", 1);
    manager
        .manage_in_background(&["renew.example.com".into()])
        .await
        .unwrap();
    until(|| async {
        shed.lock()
            .unwrap()
            .iter()
            .any(|domain| domain == "renew.example.com")
    })
    .await;
    assert!(
        manager
            .cache
            .get_by_name("renew.example.com")
            .await
            .unwrap()
            .managed
    );
    manager
        .manage_in_background(&["renew.example.com".into()])
        .await
        .unwrap();
    until(|| async {
        manager
            .cache
            .get_by_name("renew.example.com")
            .await
            .is_some_and(|cert| !cert.needs_renewal(1.0 / 3.0))
    })
    .await;
    assert_eq!(issuer.calls("renew.example.com"), 2);
}

#[tokio::test]
async fn failed_renewal_retries_even_after_caching_the_old_managed_leaf() {
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let store = Arc::new(KeyValueCertStore::new(storage.clone()));
    let issuer = Arc::new(Issuer::new());
    let mut old = issuer.old_resource(&["example.com", "www.example.com"]);
    old.sans = vec!["example.com".into()]; // canonical store alias, separate from leaf SAN coverage
    store.save(&issuer.issuer_key(), &old).await.unwrap();
    issuer.fail("example.com", 1);
    let manager = CertManager::builder()
        .storage(storage)
        .certificates(store)
        .issuers(vec![issuer.clone()])
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .background_retry_config(RetryConfig {
            intervals: vec![Duration::from_millis(20)],
            max_duration: Duration::from_secs(5),
            max_retries: 3,
        })
        .build();
    manager
        .manage_in_background(&["example.com".into()])
        .await
        .unwrap();
    until(|| async {
        issuer.calls("example.com") >= 2
            && manager
                .cache
                .get_by_name("example.com")
                .await
                .is_some_and(|cert| !cert.needs_renewal(1.0 / 3.0))
    })
    .await;
    assert_eq!(issuer.calls("example.com"), 2);
    let renewed = handshake(&manager, &issuer, "example.com").await;
    assert_ne!(
        renewed,
        certon::Certificate::from_pem(&old.certificate_pem, &old.private_key_pem)
            .unwrap()
            .cert_chain[0]
            .as_ref()
    );
    assert_eq!(
        handshake(&manager, &issuer, "www.example.com").await,
        renewed
    );
}

#[tokio::test]
async fn invalid_background_retry_settings_fail_before_any_submission() {
    for config in [
        RetryConfig {
            intervals: vec![],
            ..config()
        },
        RetryConfig {
            max_duration: Duration::MAX,
            ..config()
        },
        RetryConfig {
            intervals: vec![Duration::MAX],
            ..config()
        },
    ] {
        let directory = tempfile::tempdir().unwrap();
        let issuer = Arc::new(Issuer::new());
        let manager = CertManager::builder()
            .storage(Arc::new(FileStorage::new(directory.path())))
            .issuers(vec![issuer.clone()])
            .background_retry_config(config)
            .build();
        assert!(matches!(
            manager.manage_in_background(&["example.com".into()]).await,
            Err(certon::Error::Config(_))
        ));
        assert!(issuer.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn retried_alias_waits_for_the_leaf_lock_then_reloads_the_other_alias_replacement() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(ObservedStorage {
        files: FileStorage::new(directory.path()),
        leaf_requests: AtomicUsize::new(0),
        a_domain_requests: AtomicUsize::new(0),
        release_a_retry: tokio::sync::Semaphore::new(0),
    });
    let issuer = Arc::new(Issuer::new());
    let old = issuer.old_resource(&["a.example.com", "b.example.com"]);
    let store = Arc::new(AliasStore {
        resource: Mutex::new(Some(old.clone())),
        keep_on_remove: false,
    });
    issuer.fail("a.example.com", 1);
    let manager = Arc::new(
        CertManager::builder()
            .storage(storage.clone())
            .certificates(store.clone())
            .issuers(vec![issuer.clone()])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .background_retry_config(RetryConfig {
                intervals: vec![Duration::from_millis(100)],
                max_duration: Duration::from_secs(5),
                max_retries: 3,
            })
            .build(),
    );
    manager
        .manage_in_background(&["a.example.com".into()])
        .await
        .unwrap();
    until(|| async { issuer.calls("a.example.com") == 1 }).await;
    *issuer.gated.lock().unwrap() = Some("b.example.com".into());
    let foreground = tokio::spawn({
        let manager = manager.clone();
        async move { manager.renew("b.example.com", true).await }
    });
    tokio::time::timeout(Duration::from_secs(5), issuer.entered.notified())
        .await
        .unwrap();
    // Allow A's next transaction only after B is known to hold the old leaf
    // lock; this ordering does not depend on CI speed or a lucky retry timer.
    storage.release_a_retry.add_permits(1);
    // Initial A, then B, then A's next attempt must each request the shared leaf
    // lock. The retry must wait there instead of issuing concurrently with B.
    until(|| async { storage.leaf_requests.load(Ordering::SeqCst) >= 3 }).await;
    assert_eq!(issuer.calls("a.example.com"), 1);
    assert_eq!(issuer.calls("b.example.com"), 1);
    issuer.release.add_permits(1);
    foreground.await.unwrap().unwrap();
    until(|| async { storage.leaf_requests.load(Ordering::SeqCst) >= 4 }).await;
    let fresh = store.resource.lock().unwrap().clone().unwrap();
    let fresh_leaf =
        certon::Certificate::from_pem(&fresh.certificate_pem, &fresh.private_key_pem).unwrap();
    until(|| async {
        manager
            .cache
            .get_by_name("a.example.com")
            .await
            .is_some_and(|cert| cert.hash == fresh_leaf.hash)
    })
    .await;
    assert_eq!(
        issuer.calls("a.example.com"),
        1,
        "retry did not re-read B's renewed resource"
    );
    assert_eq!(issuer.maximum.load(Ordering::SeqCst), 1);
    assert_ne!(fresh.certificate_pem, old.certificate_pem);
    assert_eq!(
        handshake(&manager, &issuer, "a.example.com").await,
        handshake(&manager, &issuer, "b.example.com").await
    );
}

#[tokio::test]
async fn revocation_during_backoff_is_rechecked_before_a_retry_can_issue() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(Issuer::new());
    let old = issuer.old_resource(&["a.example.com", "b.example.com"]);
    let old_cert =
        certon::Certificate::from_pem(&old.certificate_pem, &old.private_key_pem).unwrap();
    let store = Arc::new(AliasStore {
        resource: Mutex::new(Some(old)),
        keep_on_remove: true,
    });
    issuer.fail("a.example.com", 1);
    let completed = Arc::new(tokio::sync::Notify::new());
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .certificates(store)
        .issuers(vec![issuer.clone()])
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .background_retry_config(RetryConfig {
            intervals: vec![Duration::from_secs(1)],
            max_duration: Duration::from_secs(5),
            max_retries: 2,
        })
        .on_event({
            let completed = completed.clone();
            Arc::new(move |event, data| {
                if event == certon::manager::EVENT_CERT_FAILED && data["background"] == true {
                    completed.notify_one();
                }
                Ok(())
            })
        })
        .build();
    manager
        .manage_in_background(&["a.example.com".into()])
        .await
        .unwrap();
    until(|| async { issuer.calls("a.example.com") == 1 }).await;
    // Cleanup intentionally fails; the confirmed tombstone must still prevent
    // the retained old resource from being retried or republished through A.
    assert!(manager.revoke("b.example.com", None).await.is_err());
    tokio::time::timeout(Duration::from_secs(5), completed.notified())
        .await
        .unwrap();
    assert_eq!(issuer.calls("a.example.com"), 1);
    assert!(manager.cache.get_by_hash(&old_cert.hash).await.is_none());
    assert!(manager.cache_certificate("a.example.com").await.is_err());
}

#[tokio::test]
async fn permanent_storage_certificate_errors_do_not_turn_into_background_retries() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let store = Arc::new(KeyValueCertStore::new(storage.clone()));
    let issuer = Arc::new(Issuer::new());
    let mut resource = issuer.old_resource(&["example.com"]);
    resource.private_key_pem = KeyPair::generate().unwrap().serialize_pem().into_bytes();
    store.save(&issuer.issuer_key(), &resource).await.unwrap();
    let failures = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(tokio::sync::Notify::new());
    let manager = CertManager::builder()
        .storage(storage)
        .certificates(store)
        .issuers(vec![issuer.clone()])
        .background_retry_config(RetryConfig {
            intervals: vec![Duration::ZERO],
            ..config()
        })
        .on_event({
            let failures = failures.clone();
            let done = done.clone();
            Arc::new(move |event, data| {
                if event == certon::manager::EVENT_CERT_FAILED && data["background"] == true {
                    assert_eq!(data["error_kind"], "operation_failed");
                    failures.fetch_add(1, Ordering::SeqCst);
                    done.notify_one();
                }
                Ok(())
            })
        })
        .build();
    manager
        .manage_in_background(&["example.com".into()])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), done.notified())
        .await
        .unwrap();
    assert_eq!(failures.load(Ordering::SeqCst), 1);
    assert_eq!(issuer.calls("example.com"), 0);
    assert_eq!(manager.cache.count().await, 0);
}
