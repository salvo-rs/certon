use std::sync::{Arc, Mutex};

use certon::cache::{CacheEvent, CacheOptions, SubjectIssuer};
use certon::{CertCache, CertManager, Certificate, Error, FileStorage, Storage};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const DOMAIN: &str = "leaf-index.example.com";

#[derive(Clone)]
struct Identity {
    full: Certificate,
    without_root: Certificate,
    full_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Arc<FileStorage>,
    manager: CertManager,
    issuer: rcgen::Issuer<'static, KeyPair>,
    root: CertificateDer<'static>,
    root_pem: String,
    events: Arc<Mutex<Vec<CacheEvent>>>,
}

impl Fixture {
    fn new() -> Self {
        certon::install_default_crypto_provider();
        let mut params = CertificateParams::new(vec!["leaf index CA".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap();
        let root = ca.der().clone();
        let root_pem = ca.pem();
        let issuer = rcgen::Issuer::new(params, key);
        let events = Arc::new(Mutex::new(Vec::new()));
        let cache = CertCache::new(CacheOptions {
            on_event: Some(Arc::new({
                let events = events.clone();
                move |event| events.lock().unwrap().push(event)
            })),
            ..Default::default()
        });
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let manager = CertManager::builder()
            .storage(storage.clone())
            .cache(cache)
            .build();
        Self {
            _directory: directory,
            storage,
            manager,
            issuer,
            root,
            root_pem,
            events,
        }
    }

    fn identity(&self) -> Identity {
        let params = CertificateParams::new(vec![DOMAIN.into()]).unwrap();
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &self.issuer).unwrap();
        let full_pem = format!("{}{}", leaf.pem(), self.root_pem).into_bytes();
        let key_pem = key.serialize_pem().into_bytes();
        let mut full = Certificate::from_pem(&full_pem, &key_pem).unwrap();
        full.managed = true;
        full.issuer_key = "leaf-index-ca".into();
        // Omitting the trusted root is a legal alternate presentation of the
        // same leaf, and changes the cache's chain identity without changing
        // the certificate being revoked.
        let mut without_root = Certificate::from_pem(leaf.pem().as_bytes(), &key_pem).unwrap();
        without_root.managed = true;
        without_root.issuer_key = full.issuer_key.clone();
        assert_ne!(full.hash, without_root.hash);
        Identity {
            full,
            without_root,
            full_pem,
            key_pem,
        }
    }

    async fn mark_revoked(&self, identity: &Identity) {
        let leaf_hash =
            certon::certificates::hash_certificate_chain(&identity.full.cert_chain[..1]);
        self.storage
            .store(
                &format!("revocations/{leaf_hash}.json"),
                br#"{"version":1,"confirmed":true}"#,
            )
            .await
            .unwrap();
    }

    fn removed_events(&self) -> Vec<String> {
        let mut hashes = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                CacheEvent::Removed { hash, .. } => Some(hash.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        hashes.sort();
        hashes
    }

    async fn handshake(&self, manager: &CertManager) -> Vec<CertificateDer<'static>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(manager.server_config()));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (server, client) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(DOMAIN.try_into().unwrap(), client_io)
        );
        server.unwrap();
        client
            .unwrap()
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .to_vec()
    }
}

#[tokio::test]
async fn one_leaf_marker_quarantines_legal_managed_and_unmanaged_chains_only() {
    let fixture = Fixture::new();
    let identity = fixture.identity();
    let unrelated = fixture.identity();
    // Verify both chain forms are real, usable TLS identities, not just hash
    // variations formed by appending an unrelated or duplicate certificate.
    for cert in [&identity.full, &identity.without_root] {
        let manager = CertManager::builder()
            .storage(fixture.storage.clone())
            .build();
        manager.cache.add(cert.clone()).await;
        assert_eq!(fixture.handshake(&manager).await[0], cert.cert_chain[0]);
    }
    fixture.manager.cache.add(identity.full.clone()).await;
    let mut unmanaged = identity.without_root.clone();
    unmanaged.managed = false;
    fixture.manager.cache.add(unmanaged.clone()).await;
    fixture.manager.cache.add(unrelated.full.clone()).await;
    fixture.events.lock().unwrap().clear();
    fixture.mark_revoked(&identity).await;
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&identity.full.hash)
            .await
            .is_none()
    );
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&unmanaged.hash)
            .await
            .is_none()
    );
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&unrelated.full.hash)
            .await
            .is_some()
    );
    let mut expected = vec![identity.full.hash, unmanaged.hash];
    expected.sort();
    assert_eq!(fixture.removed_events(), expected);
    assert_eq!(
        fixture.handshake(&fixture.manager).await[0],
        unrelated.full.cert_chain[0]
    );
}

#[tokio::test]
async fn duplicate_hash_metadata_keeps_the_retained_leaf_membership_and_key() {
    let fixture = Fixture::new();
    let retained = fixture.identity();
    let incoming = fixture.identity();
    fixture.manager.cache.add(retained.full.clone()).await;
    fixture.manager.cache.add(incoming.full.clone()).await;
    let mut duplicate = incoming.full.clone();
    // The public raw Certificate API historically accepts caller-supplied
    // hashes. Duplicate publication merges metadata while retaining the old
    // certificate/key; the leaf index must reflect that retained object.
    duplicate.hash = retained.full.hash.clone();
    duplicate.tags.push("duplicate".into());
    fixture.manager.cache.add(duplicate).await;
    let cached = fixture
        .manager
        .cache
        .get_by_hash(&retained.full.hash)
        .await
        .unwrap();
    assert_eq!(cached.cert_chain[0], retained.full.cert_chain[0]);
    fixture.mark_revoked(&incoming).await;
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&retained.full.hash)
            .await
            .is_some()
    );
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&incoming.full.hash)
            .await
            .is_none()
    );
    assert_eq!(
        fixture.handshake(&fixture.manager).await[0],
        retained.full.cert_chain[0]
    );
    fixture.mark_revoked(&retained).await;
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
    assert_eq!(fixture.manager.cache.count().await, 0);
}

#[tokio::test]
async fn removal_replacement_and_eviction_do_not_leave_a_stale_leaf_association() {
    for operation in [
        "remove",
        "remove_many",
        "remove_managed",
        "replace",
        "unmanaged_replace",
        "evict",
    ] {
        let fixture = Fixture::new();
        let old = fixture.identity();
        let replacement = fixture.identity();
        fixture.manager.cache.add(old.full.clone()).await;
        match operation {
            "remove" => fixture.manager.cache.remove(&old.full.hash).await,
            "remove_many" => {
                fixture
                    .manager
                    .cache
                    .remove_many(std::slice::from_ref(&old.full.hash))
                    .await
            }
            "remove_managed" => {
                fixture
                    .manager
                    .cache
                    .remove_managed(&[SubjectIssuer {
                        subject: DOMAIN.into(),
                        issuer_key: old.full.issuer_key.clone(),
                    }])
                    .await
            }
            "replace" => {
                fixture
                    .manager
                    .cache
                    .replace(&old.full.hash, replacement.full.clone())
                    .await
            }
            "unmanaged_replace" => fixture
                .manager
                .cache
                .cache_unmanaged_replacing(&replacement.full_pem, &replacement.key_pem, Vec::new())
                .await
                .unwrap(),
            "evict" => {
                fixture
                    .manager
                    .cache
                    .set_options(CacheOptions {
                        capacity: 1,
                        ..Default::default()
                    })
                    .await;
                fixture.manager.cache.add(replacement.full.clone()).await;
                fixture
                    .manager
                    .cache
                    .set_options(CacheOptions::default())
                    .await;
            }
            _ => unreachable!(),
        }
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&old.full.hash)
                .await
                .is_none(),
            "{operation} did not remove the original"
        );
        // Retain a managed alternate so public marker refresh still visits the
        // old leaf, then reuse its removed hash for a genuinely different leaf.
        // A stale reverse entry would incorrectly remove this new identity.
        fixture.manager.cache.add(old.without_root.clone()).await;
        let mut reused = replacement.full.clone();
        reused.hash = old.full.hash.clone();
        fixture.manager.cache.add(reused.clone()).await;
        fixture.mark_revoked(&old).await;
        assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
        assert!(
            fixture
                .manager
                .cache
                .get_by_hash(&old.without_root.hash)
                .await
                .is_none()
        );
        assert_eq!(
            fixture
                .manager
                .cache
                .get_by_hash(&reused.hash)
                .await
                .unwrap()
                .cert_chain[0],
            replacement.full.cert_chain[0],
            "{operation} left a stale association with the removed leaf",
        );
        assert_eq!(
            fixture.handshake(&fixture.manager).await[0],
            replacement.full.cert_chain[0]
        );
    }
}

#[tokio::test]
async fn duplicate_promotion_and_repeated_metadata_updates_do_not_lose_quarantine() {
    let fixture = Fixture::new();
    let identity = fixture.identity();
    let mut imported = identity.full.clone();
    imported.managed = false;
    imported.tags.push("manual".into());
    fixture.manager.cache.add(imported.clone()).await;
    for iteration in 0..8 {
        let mut updated = identity.full.clone();
        updated.managed = iteration % 2 == 0;
        updated.tags.push(format!("tag-{iteration}"));
        fixture.manager.cache.add(updated).await;
    }
    let retained = fixture
        .manager
        .cache
        .get_by_hash(&identity.full.hash)
        .await
        .unwrap();
    assert!(retained.managed);
    assert!(retained.tags.contains(&"manual".into()));
    fixture.mark_revoked(&identity).await;
    fixture.events.lock().unwrap().clear();
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
    assert_eq!(fixture.removed_events(), vec![identity.full.hash.clone()]);
    fixture.manager.cache.add(imported).await;
    fixture
        .manager
        .cache
        .add(identity.without_root.clone())
        .await;
    assert_eq!(fixture.manager.cache.count().await, 0);
    assert!(matches!(
        fixture
            .manager
            .cache
            .cache_unmanaged_pem(&identity.full_pem, &identity.key_pem, Vec::new(),)
            .await,
        Err(Error::Cert(certon::error::CertError::Revoked(_)))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_republication_and_quarantine_cannot_restore_any_chain_of_the_leaf() {
    let fixture = Fixture::new();
    let identity = fixture.identity();
    let unrelated = fixture.identity();
    fixture.manager.cache.add(identity.full.clone()).await;
    fixture
        .manager
        .cache
        .add(identity.without_root.clone())
        .await;
    fixture.manager.cache.add(unrelated.full.clone()).await;
    fixture.mark_revoked(&identity).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let mut publishers = tokio::task::JoinSet::new();
    for publisher in 0..8 {
        let cache = fixture.manager.cache.clone();
        let barrier = barrier.clone();
        let identity = identity.clone();
        publishers.spawn(async move {
            barrier.wait().await;
            for _ in 0..16 {
                match publisher % 4 {
                    0 => cache.add(identity.full.clone()).await,
                    1 => {
                        cache
                            .replace(&identity.without_root.hash, identity.without_root.clone())
                            .await
                    }
                    2 => {
                        let result = cache
                            .cache_unmanaged_pem(&identity.full_pem, &identity.key_pem, Vec::new())
                            .await;
                        assert!(
                            result.is_ok()
                                || matches!(
                                    result,
                                    Err(Error::Cert(certon::error::CertError::Revoked(_)))
                                )
                        );
                    }
                    _ => {
                        let result = cache
                            .cache_unmanaged_certified_key(
                                identity.without_root.cert_chain.clone(),
                                PrivatePkcs8KeyDer::from(
                                    identity.without_root.private_key_der.clone().unwrap(),
                                )
                                .into(),
                                Vec::new(),
                            )
                            .await;
                        assert!(
                            result.is_ok()
                                || matches!(
                                    result,
                                    Err(Error::Cert(certon::error::CertError::Revoked(_)))
                                )
                        );
                    }
                }
            }
        });
    }
    barrier.wait().await;
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 1);
    while let Some(result) = publishers.join_next().await {
        result.unwrap();
    }
    assert_eq!(fixture.manager.cache.count().await, 1);
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&identity.full.hash)
            .await
            .is_none()
    );
    assert!(
        fixture
            .manager
            .cache
            .get_by_hash(&identity.without_root.hash)
            .await
            .is_none()
    );
    assert_eq!(
        fixture.handshake(&fixture.manager).await[0],
        unrelated.full.cert_chain[0]
    );
    assert_eq!(fixture.manager.refresh_revocations().await.unwrap(), 0);
}
