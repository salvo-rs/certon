use super::*;

fn alternate_chain(cert: &Certificate) -> Certificate {
    let mut alternate = cert.clone();
    // Exercise another complete-chain identity while retaining the same leaf
    // and its real immediate issuer for signed OCSP validation. The public TLS
    // regression separately uses two independently valid CA encodings.
    alternate.cert_chain.push(cert.cert_chain[1].clone());
    alternate.hash = crate::certificates::hash_certificate_chain(&alternate.cert_chain);
    assert_ne!(cert.hash, alternate.hash);
    alternate
}

#[tokio::test]
async fn signed_refresh_updates_all_live_siblings_and_their_events_and_deadlines() {
    for sibling_managed in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        let cache = CertCache::new(CacheOptions {
            on_event: Some(Arc::new(move |event| seen.lock().unwrap().push(event))),
            ..CacheOptions::default()
        });
        let (mut a, issuer) = tests::signed_certificate();
        a.managed = true;
        a.ocsp_response = Some(tests::signed_staple(&a, &issuer, 3600));
        let mut b = alternate_chain(&a);
        b.managed = sibling_managed;
        b.names.insert(0, "other-store-alias.example".into());
        let (mut unrelated, unrelated_issuer) = tests::signed_certificate();
        unrelated.managed = true;
        unrelated.ocsp_response = Some(tests::signed_staple(&unrelated, &unrelated_issuer, 3600));
        for cert in [&a, &b, &unrelated] {
            cache.add(cert.clone()).await;
        }
        events.lock().unwrap().clear();
        let revoked = crate::ocsp::tests::signed_response(
            &a.cert_chain,
            &issuer,
            1,
            Utc::now() - chrono::Duration::seconds(1),
            Utc::now() + chrono::Duration::hours(1),
        );
        let published = cache
            .update_ocsp_if_present(&a.hash, None, Some(revoked))
            .await
            .unwrap();
        assert_eq!(
            published.ocsp_status,
            Some(crate::ocsp::OcspStatus::Revoked)
        );
        for hash in [&a.hash, &b.hash] {
            let cert = cache.get_by_hash(hash).await.unwrap();
            assert_eq!(cert.ocsp_status, Some(crate::ocsp::OcspStatus::Revoked));
            assert!(cert.ocsp_response.is_none());
            let state = cache.state.read().unwrap();
            let entry = &state.certificates[hash];
            assert!(entry.serving_key(Utc::now()).is_none());
            let deadline = entry.ocsp_deadline().unwrap();
            assert!(deadline > Utc::now());
            assert!(deadline <= Utc::now() + chrono::Duration::seconds(30));
            assert!(state.ocsp_deadlines[&deadline].contains(hash));
        }
        assert_eq!(
            cache
                .get_by_hash(&unrelated.hash)
                .await
                .unwrap()
                .ocsp_status,
            Some(crate::ocsp::OcspStatus::Good)
        );
        assert!(
            cache.resolve(&a.names[0]).is_some(),
            "another leaf stays usable"
        );
        {
            let mut updates = HashMap::<String, usize>::new();
            for event in events.lock().unwrap().iter() {
                if let CacheEvent::Updated { hash, .. } = event {
                    *updates.entry(hash.clone()).or_default() += 1;
                }
            }
            assert_eq!(
                updates,
                HashMap::from([(a.hash.clone(), 1), (b.hash.clone(), 1)])
            );
        }
        // A previously signed Good response cannot undo either chain's state.
        cache
            .update_ocsp_if_present(
                &b.hash,
                Some(crate::ocsp::OcspStatus::Good),
                Some(tests::signed_staple(&b, &issuer, 3600)),
            )
            .await
            .unwrap();
        assert_eq!(
            cache.get_by_hash(&b.hash).await.unwrap().ocsp_status,
            Some(crate::ocsp::OcspStatus::Revoked)
        );
        let leaf = crate::storage::certificate_leaf_hash(&a).unwrap();
        assert!(cache.has_ocsp_revoked_leaf("a-new-store-alias", &leaf));
        assert!(cache.client_leaf_is_revoked("a-new-store-alias", &leaf));
    }
}

#[tokio::test]
async fn raw_and_unmanaged_admission_cannot_restore_a_revoked_live_leaf() {
    let cache = CertCache::new(CacheOptions::default());
    let (mut a, issuer) = tests::signed_certificate();
    a.managed = true;
    a.ocsp_response = Some(tests::signed_staple(&a, &issuer, 3600));
    cache.add(a.clone()).await;
    cache
        .update_ocsp_if_present(&a.hash, Some(crate::ocsp::OcspStatus::Revoked), None)
        .await
        .unwrap();
    let b = alternate_chain(&a);
    cache.add(b.clone()).await;
    let published = cache.get_by_hash(&b.hash).await.unwrap();
    assert_eq!(
        published.ocsp_status,
        Some(crate::ocsp::OcspStatus::Revoked)
    );
    assert!(published.ocsp_response.is_none());
    assert!(cache.resolve(&a.names[0]).is_none());
    let (unrelated, _) = tests::signed_certificate();
    cache.add(unrelated.clone()).await;
    let pem: String = a
        .cert_chain
        .iter()
        .map(|der| pem::encode(&pem::Pem::new("CERTIFICATE", der.as_ref())))
        .collect();
    let key = pem::encode(&pem::Pem::new(
        "PRIVATE KEY",
        a.private_key_der.clone().unwrap(),
    ));
    for replacing in [false, true] {
        let result = if replacing {
            cache
                .cache_unmanaged_replacing(pem.as_bytes(), key.as_bytes(), Vec::new())
                .await
        } else {
            cache
                .cache_unmanaged_pem(pem.as_bytes(), key.as_bytes(), Vec::new())
                .await
        };
        assert!(matches!(
            result,
            Err(crate::Error::Cert(crate::error::CertError::Revoked(_)))
        ));
        assert!(
            cache.get_by_hash(&unrelated.hash).await.is_some(),
            "rejection precedes removal"
        );
    }
}

#[tokio::test]
async fn rejected_new_chain_still_propagates_its_signed_status_to_existing_siblings() {
    let cache = CertCache::new(CacheOptions::default());
    let (mut a, issuer) = crate::ocsp::tests::short_lived_certificate(Some(5));
    a.managed = true;
    a.ocsp_response = Some(tests::signed_staple(&a, &issuer, 120));
    cache.add(a.clone()).await;
    let mut b = alternate_chain(&a);
    b.ocsp_response = Some(crate::ocsp::tests::signed_response(
        &b.cert_chain,
        &issuer,
        1,
        Utc::now() - chrono::Duration::seconds(1),
        Utc::now() + chrono::Duration::hours(1),
    ));
    let result = cache.add_managed(b.clone(), &a.names[0]).await;
    assert!(matches!(
        result,
        Err(crate::Error::Cert(crate::error::CertError::OcspFailed(_)))
    ));
    assert!(cache.get_by_hash(&b.hash).await.is_none());
    assert_eq!(
        cache.get_by_hash(&a.hash).await.unwrap().ocsp_status,
        Some(crate::ocsp::OcspStatus::Revoked)
    );
    assert!(cache.resolve(&a.names[0]).is_none());
}

#[tokio::test]
async fn publication_reports_live_sibling_updates_without_updating_a_removed_chain() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = events.clone();
    let cache = CertCache::new(CacheOptions {
        on_event: Some(Arc::new(move |event| seen.lock().unwrap().push(event))),
        ..CacheOptions::default()
    });
    let (mut a, issuer) = tests::signed_certificate();
    a.managed = true;
    a.ocsp_response = Some(tests::signed_staple(&a, &issuer, 3600));
    let b = alternate_chain(&a);
    cache.add(a.clone()).await;
    cache.add(b.clone()).await;
    events.lock().unwrap().clear();
    let mut incoming = a.clone();
    incoming.ocsp_response = Some(crate::ocsp::tests::signed_response(
        &a.cert_chain,
        &issuer,
        1,
        Utc::now() - chrono::Duration::seconds(1),
        Utc::now() + chrono::Duration::hours(1),
    ));
    cache
        .replace_managed(&b.hash, incoming, &a.names[0])
        .await
        .unwrap();
    assert!(cache.get_by_hash(&b.hash).await.is_none());
    assert_eq!(
        cache.get_by_hash(&a.hash).await.unwrap().ocsp_status,
        Some(crate::ocsp::OcspStatus::Revoked)
    );
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, CacheEvent::Removed { hash, .. } if hash == &b.hash))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, CacheEvent::Updated { hash, .. } if hash == &a.hash))
    );
}

#[tokio::test]
async fn authenticated_update_survives_removal_of_its_original_chain_during_aia() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for remove_target in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/issuer", listener.local_addr().unwrap());
        let issuer_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let root = ca.self_signed(&issuer_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, &issuer_key);
        let wrap = |tag: u8, value: &[u8]| [vec![tag, value.len() as u8], value.to_vec()].concat();
        let access = wrap(
            0x30,
            &[
                vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02],
                wrap(0x86, url.as_bytes()),
            ]
            .concat(),
        );
        let mut params = rcgen::CertificateParams::new(vec!["ocsp.example.com".into()]).unwrap();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                wrap(0x30, &access),
            ));
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &issuer).unwrap();
        let mut a =
            Certificate::from_pem(leaf.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        a.managed = true;
        let mut b = a.clone();
        b.cert_chain.push(root.der().clone());
        b.hash = crate::certificates::hash_certificate_chain(&b.cert_chain);
        b.ocsp_response = Some(tests::signed_staple(&b, &issuer_key, 3600));
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        let cache = CertCache::new(CacheOptions {
            on_event: Some(Arc::new(move |event| seen.lock().unwrap().push(event))),
            ..CacheOptions::default()
        });
        cache.add(a.clone()).await;
        cache.add(b.clone()).await;
        events.lock().unwrap().clear();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let server = tokio::spawn({
            let entered = entered.clone();
            let release = release.clone();
            async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                entered.notify_one();
                release.notified().await;
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", root.der().len()).as_bytes()).await.unwrap();
                socket.write_all(root.der()).await.unwrap();
            }
        });
        let raw = crate::ocsp::tests::signed_response(
            &b.cert_chain,
            &issuer_key,
            1,
            Utc::now() - chrono::Duration::seconds(1),
            Utc::now() + chrono::Duration::hours(1),
        );
        let update = tokio::spawn({
            let cache = cache.clone();
            let hash = a.hash.clone();
            async move { cache.update_ocsp_if_present(&hash, None, Some(raw)).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
            .await
            .unwrap();
        if remove_target {
            cache.remove(&a.hash).await;
            events.lock().unwrap().clear();
        }
        release.notify_one();
        let published = update.await.unwrap();
        server.await.unwrap();
        assert_eq!(published.is_some(), !remove_target);
        let sibling = cache.get_by_hash(&b.hash).await.unwrap();
        assert_eq!(
            sibling.ocsp_status,
            Some(crate::ocsp::OcspStatus::Revoked),
            "target removed: {remove_target}"
        );
        assert!(sibling.ocsp_response.is_none());
        assert!(cache.resolve("ocsp.example.com").is_none());
        let state = cache.state.read().unwrap();
        let deadline = state.certificates[&b.hash].ocsp_deadline().unwrap();
        assert!(deadline > Utc::now() && deadline <= Utc::now() + chrono::Duration::seconds(30));
        assert!(state.ocsp_deadlines[&deadline].contains(&b.hash));
        drop(state);
        let events = events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(
                    |event| matches!(event, CacheEvent::Updated { hash, .. } if hash == &b.hash)
                )
                .count(),
            1
        );
    }
}
