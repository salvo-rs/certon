use std::sync::Arc;
use std::time::Duration;

use certon::error::{CertError, Error};
use certon::{
    CacheOptions, CertCache, CertResolver, Certificate, CertificateResource, FileStorage, Storage,
};

fn resource(names: &[&str]) -> (CertificateResource, Certificate) {
    resource_with_window(names, -86400, 90 * 86400)
}

fn resource_with_window(
    names: &[&str],
    before: i64,
    after: i64,
) -> (CertificateResource, Certificate) {
    certon::install_default_crypto_provider();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|name| (*name).into()).collect::<Vec<_>>())
            .unwrap();
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    params.not_before =
        epoch + Duration::from_secs((chrono::Utc::now().timestamp() + before) as u64);
    params.not_after = epoch + Duration::from_secs((chrono::Utc::now().timestamp() + after) as u64);
    let leaf = params.self_signed(&key).unwrap();
    let resource = CertificateResource {
        sans: names.iter().map(|name| (*name).into()).collect(),
        certificate_pem: leaf.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_key: "reload-ca".into(),
        issuer_data: None,
    };
    let mut cert =
        Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem).unwrap();
    cert.managed = true;
    cert.issuer_key = resource.issuer_key.clone();
    cert.tags.push("last-working".into());
    (resource, cert)
}

async fn handshake(cache: Arc<CertCache>, name: &str, trusted: &[&Certificate]) -> Option<Vec<u8>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in trusted {
        roots.add(cert.cert_chain[0].clone()).unwrap();
    }
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut resolver = CertResolver::new(cache);
    // IP addresses do not produce SNI; explicitly choose that identity then.
    resolver.set_default_server_name(Some(name.into()));
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    let (client_io, server_io) = tokio::io::duplex(65536);
    let name = rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap();
    let (client, server) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            tokio_rustls::TlsConnector::from(Arc::new(client)).connect(name, client_io),
            tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(server_io)
        )
    })
    .await
    .ok()?;
    server.ok()?;
    let client = client.ok()?;
    Some(client.get_ref().1.peer_certificates()?.first()?.to_vec())
}

async fn invalid_replacement(mismatched_key: bool, keep_old: bool) {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let cache = CertCache::new(CacheOptions::default());
    let (_, old) = resource(&["reload.example"]);
    if keep_old {
        cache.add(old.clone()).await;
        assert_eq!(
            handshake(cache.clone(), "reload.example", &[&old]).await,
            Some(old.cert_chain[0].to_vec())
        );
    }
    let (mut bad, incoming) = resource(&[if mismatched_key {
        "reload.example"
    } else {
        "unrelated.example"
    }]);
    // Storage address/metadata must never authorize an unrelated actual SAN.
    bad.sans = vec!["reload.example".into()];
    if mismatched_key {
        bad.private_key_pem = rcgen::KeyPair::generate()
            .unwrap()
            .serialize_pem()
            .into_bytes();
    }
    certon::storage::store_certificate(&storage, "reload-ca", &bad)
        .await
        .unwrap();
    let result = certon::certificates::reload_managed_certificate(
        &cache,
        &storage,
        "reload.example",
        "reload-ca",
    )
    .await;
    let tls_after = if keep_old {
        handshake(cache.clone(), "reload.example", &[&old, &incoming]).await
    } else {
        None
    };
    let retained = cache.get_by_hash(&old.hash).await;
    assert!(
        matches!(result, Err(Error::Config(_))),
        "wrong identity or key was admitted: {result:?}; old_retained={}; tls_after={}",
        retained.is_some(),
        tls_after.is_some()
    );
    assert!(cache.get_by_hash(&incoming.hash).await.is_none());
    if keep_old {
        let retained = retained.unwrap();
        assert_eq!(retained.tags, old.tags);
        assert_eq!(retained.issuer_key, old.issuer_key);
        assert_eq!(retained.managed, old.managed);
        assert_eq!(retained.names, old.names);
        assert_eq!(tls_after, Some(old.cert_chain[0].to_vec()));
    } else {
        assert!(cache.get_by_name("reload.example").await.is_none());
    }
}

#[tokio::test]
async fn mismatched_private_key_preserves_the_last_working_tls_leaf() {
    invalid_replacement(true, true).await;
}

#[tokio::test]
async fn wrong_san_preserves_the_last_working_tls_leaf() {
    invalid_replacement(false, true).await;
}

#[tokio::test]
async fn invalid_cold_reload_does_not_publish_an_unusable_entry() {
    for mismatched_key in [false, true] {
        invalid_replacement(mismatched_key, false).await;
    }
}

#[tokio::test]
async fn valid_replacement_still_replaces_and_serves_the_new_identity() {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let cache = CertCache::new(CacheOptions::default());
    let (_, old) = resource(&["reload.example"]);
    let (new_resource, new) = resource(&["reload.example"]);
    cache.add(old.clone()).await;
    assert_eq!(
        handshake(cache.clone(), "reload.example", &[&old]).await,
        Some(old.cert_chain[0].to_vec())
    );
    certon::storage::store_certificate(&storage, "reload-ca", &new_resource)
        .await
        .unwrap();
    certon::certificates::reload_managed_certificate(
        &cache,
        &storage,
        "reload.example",
        "reload-ca",
    )
    .await
    .unwrap();
    assert!(cache.get_by_hash(&old.hash).await.is_none());
    assert_eq!(
        handshake(cache, "reload.example", &[&new]).await,
        Some(new.cert_chain[0].to_vec())
    );
}

#[tokio::test]
async fn actual_wildcard_ip_and_storage_aliases_remain_supported() {
    for (names, lookup, handshake_names) in [
        (
            vec!["secondary.example.com", "*.example.com"],
            "a.example.com",
            vec!["a.example.com", "b.example.com"],
        ),
        (
            vec!["*.example.com"],
            "*.example.com",
            vec!["a.example.com"],
        ),
        (vec!["127.0.0.1"], "127.0.0.1", vec!["127.0.0.1"]),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let cache = CertCache::new(CacheOptions::default());
        let (mut resource, expected) = resource(&names);
        resource.sans = vec![lookup.into()];
        certon::storage::store_certificate(&storage, "reload-ca", &resource)
            .await
            .unwrap();
        certon::certificates::reload_managed_certificate(&cache, &storage, lookup, "reload-ca")
            .await
            .unwrap();
        let cached = cache.get_by_hash(&expected.hash).await.unwrap();
        assert!(cached.managed);
        assert_eq!(cached.issuer_key, "reload-ca");
        assert_eq!(
            cached.names[0], lookup,
            "retain the storage alias for later maintenance"
        );
        for name in handshake_names {
            assert_eq!(
                handshake(cache.clone(), name, &[&expected]).await,
                Some(expected.cert_chain[0].to_vec())
            );
        }
    }
}

#[tokio::test]
async fn cn_only_is_not_a_managed_identity_but_raw_metadata_import_is_unchanged() {
    certon::install_default_crypto_provider();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "reload.example");
    let leaf = params.self_signed(&key).unwrap();
    let resource = CertificateResource {
        sans: vec!["reload.example".into()],
        certificate_pem: leaf.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_key: "reload-ca".into(),
        issuer_data: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let cache = CertCache::new(CacheOptions::default());
    certon::storage::store_certificate(&storage, "reload-ca", &resource)
        .await
        .unwrap();
    let result = certon::certificates::reload_managed_certificate(
        &cache,
        &storage,
        "reload.example",
        "reload-ca",
    )
    .await;
    assert!(matches!(result, Err(Error::Config(_))));
    assert!(cache.get_by_name("reload.example").await.is_none());
    let imported =
        Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem).unwrap();
    assert!(!imported.managed);
    cache.add(imported.clone()).await;
    assert!(cache.get_by_hash(&imported.hash).await.is_some());
}

#[tokio::test]
async fn manual_revocation_still_quarantines_the_same_leaf_even_with_a_bad_replacement_key() {
    for confirmed in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let cache = CertCache::new(CacheOptions::default());
        let (mut resource, old) = resource(&["reload.example"]);
        cache.add(old.clone()).await;
        assert!(
            handshake(cache.clone(), "reload.example", &[&old])
                .await
                .is_some()
        );
        resource.private_key_pem = rcgen::KeyPair::generate()
            .unwrap()
            .serialize_pem()
            .into_bytes();
        certon::storage::store_certificate(&storage, "reload-ca", &resource)
            .await
            .unwrap();
        let leaf_hash = certon::certificates::hash_certificate_chain(&old.cert_chain[..1]);
        storage
            .store(
                &format!("revocations/{leaf_hash}.json"),
                &serde_json::to_vec(&serde_json::json!({"version":1,"confirmed":confirmed}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let result = certon::certificates::reload_managed_certificate(
            &cache,
            &storage,
            "reload.example",
            "reload-ca",
        )
        .await;
        assert!(matches!(result, Err(Error::Cert(CertError::Revoked(_)))));
        assert!(cache.get_by_hash(&old.hash).await.is_none());
        assert!(handshake(cache, "reload.example", &[&old]).await.is_none());
    }
}

#[tokio::test]
async fn partial_san_replacement_preserves_other_names_and_full_coverage_still_replaces() {
    for full_coverage in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let cache = CertCache::new(CacheOptions::default());
        let old_names = if full_coverage {
            vec!["a.example.com"]
        } else {
            vec!["a.example.com", "b.example.com"]
        };
        let new_names = if full_coverage {
            vec!["a.example.com", "b.example.com"]
        } else {
            vec!["a.example.com"]
        };
        let (_, old) = resource(&old_names);
        cache.add(old.clone()).await;
        let (mut incoming, new) = resource_with_window(&new_names, -86400, 91 * 86400);
        incoming.sans = vec!["a.example.com".into()];
        certon::storage::store_certificate(&storage, "reload-ca", &incoming)
            .await
            .unwrap();
        certon::certificates::reload_managed_certificate(
            &cache,
            &storage,
            "a.example.com",
            "reload-ca",
        )
        .await
        .unwrap();
        assert_eq!(cache.get_by_hash(&old.hash).await.is_none(), full_coverage);
        assert_eq!(
            handshake(cache.clone(), "a.example.com", &[&old, &new]).await,
            Some(new.cert_chain[0].to_vec())
        );
        let expected_b = if full_coverage { &new } else { &old };
        assert_eq!(
            handshake(cache, "b.example.com", &[&old, &new]).await,
            Some(expected_b.cert_chain[0].to_vec())
        );
    }
}

#[tokio::test]
async fn time_invalid_replacements_preserve_the_working_leaf() {
    for future in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let cache = CertCache::new(CacheOptions::default());
        let (_, old) = resource(&["reload.example"]);
        cache.add(old.clone()).await;
        let (incoming, _) = if future {
            resource_with_window(&["reload.example"], 86400, 2 * 86400)
        } else {
            resource_with_window(&["reload.example"], -2 * 86400, -86400)
        };
        certon::storage::store_certificate(&storage, "reload-ca", &incoming)
            .await
            .unwrap();
        let result = certon::certificates::reload_managed_certificate(
            &cache,
            &storage,
            "reload.example",
            "reload-ca",
        )
        .await;
        assert!(matches!(
            (future, result),
            (true, Err(Error::Cert(CertError::NotYetValid(_))))
                | (false, Err(Error::Cert(CertError::Expired(_))))
        ));
        assert!(cache.get_by_hash(&old.hash).await.is_some());
        assert_eq!(
            handshake(cache, "reload.example", &[&old]).await,
            Some(old.cert_chain[0].to_vec())
        );
    }
}
