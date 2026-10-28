use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::policy::CertificateSelector;
use certon::rate_limiter::RateLimiter;
use certon::{
    CacheOptions, CertCache, CertIssuer, CertManager, Certificate, FileStorage, IssuedCertificate,
    OcspConfig, OnDemandConfig, Result,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData};
use rustls::{ClientConnection, ServerConnection, SignatureScheme};
use x509_parser::prelude::FromDer;

fn leaf(ed25519: bool, expiry: i32) -> Certificate {
    let key = KeyPair::generate_for(if ed25519 {
        &rcgen::PKCS_ED25519
    } else {
        &rcgen::PKCS_ECDSA_P256_SHA256
    })
    .unwrap();
    let mut params = CertificateParams::new(vec!["example.com".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(expiry, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    Certificate::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
}

fn handshake(
    config: Arc<rustls::ServerConfig>,
    trusted: &[rustls::pki_types::CertificateDer<'static>],
    name: &str,
    scheme: SignatureScheme,
) -> std::result::Result<Vec<u8>, rustls::Error> {
    certon::install_default_crypto_provider();
    let mut provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap()
        .as_ref()
        .clone();
    provider.signature_verification_algorithms.mapping = std::slice::from_ref(
        provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(supported, _)| *supported == scheme)
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    for cert in trusted {
        roots.add(cert.clone()).unwrap();
    }
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let mut client =
        ClientConnection::new(Arc::new(client), name.to_owned().try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(config).unwrap();
    for _ in 0..10 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        server.read_tls(&mut std::io::Cursor::new(bytes)).unwrap();
        server.process_new_packets()?;
        let mut bytes = Vec::new();
        server.write_tls(&mut bytes).unwrap();
        client.read_tls(&mut std::io::Cursor::new(bytes)).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(client.peer_certificates().unwrap()[0].to_vec());
        }
    }
    panic!("handshake did not finish");
}

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
            calls: AtomicUsize::new(0),
        }
    }
}
#[async_trait::async_trait]
impl CertIssuer for Issuer {
    async fn issue(&self, csr: &[u8], domains: &[String]) -> Result<IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = CsrPublicKey(
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
        "on-demand-test".into()
    }
}

#[tokio::test(start_paused = true)]
async fn explicit_obtain_callback_keeps_allowlist_rate_limit_and_single_flight() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(Issuer::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let obtained = Arc::new(tokio::sync::Notify::new());
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .issuers(vec![issuer.clone()])
        .on_demand(Arc::new(OnDemandConfig {
            decision_func: None,
            host_allowlist: Some(
                ["allowed.example.com".into(), "second.example.com".into()].into(),
            ),
            rate_limit: Some(Arc::new(RateLimiter::new(1, Duration::from_secs(3600)))),
            obtain_func: Some(Arc::new({
                let calls = calls.clone();
                let obtained = obtained.clone();
                move |name| {
                    let calls = calls.clone();
                    let obtained = obtained.clone();
                    Box::pin(async move {
                        calls.lock().unwrap().push(name);
                        obtained.notify_one();
                        Ok(())
                    })
                }
            })),
        }))
        .build();
    let config = Arc::new(manager.server_config());
    let request = |name| {
        handshake(
            config.clone(),
            std::slice::from_ref(&issuer.root),
            name,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        )
    };
    assert!(request("blocked.example.com").is_err());
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(calls.lock().unwrap().is_empty());
    assert!(request("allowed.example.com").is_err());
    assert!(request("allowed.example.com").is_err());
    tokio::time::timeout(Duration::from_secs(1), obtained.notified())
        .await
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), ["allowed.example.com"]);
    assert!(request("second.example.com").is_err());
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(*calls.lock().unwrap(), ["allowed.example.com"]);
    assert_eq!(
        issuer.calls.load(Ordering::SeqCst),
        0,
        "explicit callback must not be replaced"
    );
}

#[tokio::test(start_paused = true)]
async fn decision_function_and_missing_policy_still_deny_issuance() {
    for decision in [
        None,
        Some(Arc::new(|_: &str| false) as Arc<dyn Fn(&str) -> bool + Send + Sync>),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let has_decision = decision.is_some();
        let manager = CertManager::builder()
            .storage(Arc::new(FileStorage::new(directory.path())))
            .on_demand(Arc::new(OnDemandConfig {
                decision_func: decision,
                host_allowlist: has_decision.then(|| ["example.com".into()].into()),
                rate_limit: None,
                obtain_func: Some(Arc::new({
                    let calls = calls.clone();
                    move |_| {
                        let calls = calls.clone();
                        Box::pin(async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        })
                    }
                })),
            }))
            .build();
        assert!(
            handshake(
                Arc::new(manager.server_config()),
                &[],
                "example.com",
                SignatureScheme::ECDSA_NISTP256_SHA256
            )
            .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn absent_callback_uses_manager_to_obtain_publish_and_serve_next_handshake() {
    let directory = tempfile::tempdir().unwrap();
    let issuer = Arc::new(Issuer::new());
    let obtained = Arc::new(tokio::sync::Notify::new());
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .issuers(vec![issuer.clone()])
        .ocsp(OcspConfig {
            disable_stapling: true,
            ..Default::default()
        })
        .on_demand(Arc::new(OnDemandConfig {
            decision_func: None,
            host_allowlist: Some(["example.com".into()].into()),
            rate_limit: None,
            obtain_func: None,
        }))
        .on_event({
            let obtained = obtained.clone();
            Arc::new(move |event, _| {
                if event == certon::manager::EVENT_CERT_OBTAINED {
                    obtained.notify_one();
                }
                Ok(())
            })
        })
        .build();
    let config = Arc::new(manager.server_config());
    assert!(
        handshake(
            config.clone(),
            std::slice::from_ref(&issuer.root),
            "example.com",
            SignatureScheme::ECDSA_NISTP256_SHA256
        )
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), obtained.notified())
        .await
        .unwrap();
    let cached = manager.cache.get_by_name("example.com").await.unwrap();
    assert!(cached.managed);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        handshake(
            config,
            std::slice::from_ref(&issuer.root),
            "example.com",
            SignatureScheme::ECDSA_NISTP256_SHA256
        )
        .unwrap(),
        cached.cert_chain[0].as_ref()
    );
}

struct Selector {
    cache: Arc<CertCache>,
    old_hash: String,
    pointers: HashMap<String, usize>,
    mode: AtomicU8,
    calls: AtomicUsize,
}
impl CertificateSelector for Selector {
    fn select_certificate(
        &self,
        hello: &rustls::server::ClientHello<'_>,
        choices: &[&Certificate],
    ) -> Option<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(hello.server_name(), Some("example.com"));
        assert_eq!(
            hello.alpn().unwrap().collect::<Vec<_>>(),
            [b"h2".as_slice()]
        );
        let ed25519 = hello.signature_schemes() == [SignatureScheme::ED25519];
        assert_eq!(choices.len(), if ed25519 { 1 } else { 2 });
        for cert in choices {
            assert_eq!(
                cert.private_key_der.as_ref().unwrap().as_ptr() as usize,
                self.pointers[&cert.hash],
                "selector must borrow cached bytes, not deep clones"
            );
            assert!(
                certon::handshake::cert_to_certified_key(cert)
                    .unwrap()
                    .key
                    .choose_scheme(hello.signature_schemes())
                    .is_some()
            );
        }
        // Prove the user callback can re-enter a cache write without deadlock.
        // A bounded OS-thread wait also fails promptly if the read lock leaks.
        let (done, complete) = std::sync::mpsc::channel();
        let cache = self.cache.clone();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(cache.remove("not-cached"));
            let _ = done.send(());
        });
        complete
            .recv_timeout(Duration::from_secs(2))
            .expect("selector invoked while holding cache lock");
        match self.mode.load(Ordering::SeqCst) {
            0 => choices.iter().position(|cert| cert.hash == self.old_hash),
            1 => None,
            _ => Some(usize::MAX),
        }
    }
}

#[tokio::test]
async fn custom_selection_receives_real_hello_and_only_shared_compatible_candidates() {
    let directory = tempfile::tempdir().unwrap();
    let cache = CertCache::new(CacheOptions::default());
    let old = leaf(false, 2040);
    let fresh = leaf(false, 2050);
    let ed25519 = leaf(true, 2060);
    let old_hash = old.hash.clone();
    let trusted = [
        old.cert_chain[0].clone(),
        fresh.cert_chain[0].clone(),
        ed25519.cert_chain[0].clone(),
    ];
    let mut pointers = HashMap::new();
    for cert in [old, fresh, ed25519] {
        pointers.insert(
            cert.hash.clone(),
            cert.private_key_der.as_ref().unwrap().as_ptr() as usize,
        );
        cache.add(cert).await;
    }
    let selector = Arc::new(Selector {
        cache: cache.clone(),
        old_hash,
        pointers,
        mode: AtomicU8::new(0),
        calls: AtomicUsize::new(0),
    });
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .cache(cache)
        .cert_selection(selector.clone())
        .build();
    let config = Arc::new(manager.server_config());
    for mode in [0, 1, 2] {
        selector.mode.store(mode, Ordering::SeqCst);
        let chosen = handshake(
            config.clone(),
            &trusted,
            "example.com",
            SignatureScheme::ECDSA_NISTP256_SHA256,
        )
        .unwrap();
        assert_eq!(chosen, trusted[usize::from(mode != 0)].as_ref());
    }
    assert_eq!(
        handshake(
            config.clone(),
            &trusted,
            "example.com",
            SignatureScheme::ED25519
        )
        .unwrap(),
        trusted[2].as_ref()
    );
    assert_eq!(selector.calls.load(Ordering::SeqCst), 4);
    assert!(
        handshake(
            config,
            &trusted,
            "example.com",
            SignatureScheme::RSA_PSS_SHA256
        )
        .is_err()
    );
    assert_eq!(
        selector.calls.load(Ordering::SeqCst),
        4,
        "no selector call without compatible candidates"
    );
}
