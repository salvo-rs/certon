use std::sync::{Arc, Mutex};

use certon::cache::CacheEvent;
use certon::{CacheOptions, CertCache, Certificate};

fn certificate(index: usize, managed: bool) -> Certificate {
    let name = format!("capacity-{index}.example");
    let key = rcgen::KeyPair::generate().unwrap();
    let signed = rcgen::CertificateParams::new(vec![name.clone()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut cert =
        Certificate::from_pem(signed.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    cert.managed = managed;
    cert.issuer_key = "capacity-test".into();
    cert.names = vec![name];
    cert
}

#[tokio::test]
async fn reducing_capacity_immediately_reclaims_existing_managed_certificates() {
    for initial_capacity in [0, 12] {
        let cache = CertCache::new(CacheOptions {
            capacity: initial_capacity,
            ..Default::default()
        });
        for index in 0..12 {
            cache.add(certificate(index, true)).await;
        }
        assert_eq!(cache.count().await, 12);
        cache
            .set_options(CacheOptions {
                capacity: 2,
                ..Default::default()
            })
            .await;
        assert_eq!(
            cache.count().await,
            2,
            "resize must reclaim existing entries"
        );
        for index in 12..24 {
            let cert = certificate(index, true);
            let hash = cert.hash.clone();
            cache.add(cert).await;
            assert_eq!(cache.count().await, 2);
            assert!(cache.get_by_hash(&hash).await.is_some());
        }
        cache.set_options(CacheOptions::default()).await;
        for index in 24..28 {
            cache.add(certificate(index, true)).await;
        }
        assert_eq!(cache.count().await, 6, "zero restores unlimited capacity");
    }
}

#[tokio::test]
async fn shrinking_preserves_unmanaged_entries_and_dispatches_removal_events() {
    let cache = CertCache::new(CacheOptions::default());
    let mut protected = Vec::new();
    for index in 0..3 {
        let cert = certificate(index, false);
        protected.push((cert.hash.clone(), cert.names[0].clone()));
        cache.add(cert).await;
    }
    let mut managed = Vec::new();
    for index in 3..8 {
        let cert = certificate(index, true);
        managed.push((cert.hash.clone(), cert.names[0].clone()));
        cache.add(cert).await;
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    cache
        .set_options(CacheOptions {
            capacity: 2,
            on_event: Some(Arc::new({
                let events = events.clone();
                move |event| {
                    events.lock().unwrap().push(event);
                }
            })),
            ..Default::default()
        })
        .await;
    assert_eq!(cache.count().await, 3, "unmanaged entries are protected");
    let removed: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            CacheEvent::Removed { hash, .. } => Some(hash.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(removed.len(), managed.len());
    for (hash, name) in managed {
        assert!(removed.contains(&hash));
        assert!(cache.get_by_hash(&hash).await.is_none());
        assert!(cache.get_by_name(&name).await.is_none());
    }
    for (hash, name) in protected {
        assert!(cache.get_by_hash(&hash).await.is_some());
        assert!(cache.get_by_name(&name).await.is_some());
    }
    // Keep the existing admission policy when protected entries alone exceed
    // the limit: a new certificate may enter, evicting an older managed one.
    cache.add(certificate(8, true)).await;
    assert_eq!(cache.count().await, 4);
    cache.add(certificate(9, true)).await;
    assert_eq!(cache.count().await, 4);
    assert!(cache.get_by_name("capacity-8.example").await.is_none());
    assert!(cache.get_by_name("capacity-9.example").await.is_some());
}

#[tokio::test]
async fn taking_over_protected_imports_converges_to_the_configured_capacity() {
    let cache = CertCache::new(CacheOptions {
        capacity: 2,
        ..Default::default()
    });
    let mut imported = Vec::new();
    for index in 0..12 {
        let cert = certificate(index, false);
        cache.add(cert.clone()).await;
        imported.push(cert);
    }
    assert_eq!(cache.count().await, 12, "imports retain their protection");
    for (index, original) in imported.iter().enumerate() {
        let mut managed = original.clone();
        managed.managed = true;
        managed.tags.push("taken-over".into());
        cache.add(managed).await;
        let current = cache.get_by_hash(&original.hash).await.unwrap();
        assert!(current.managed, "the incoming takeover must be retained");
        assert!(current.tags.iter().any(|tag| tag == "taken-over"));
        for protected in &imported[index + 1..] {
            assert!(cache.get_by_hash(&protected.hash).await.is_some());
        }
    }
    assert_eq!(cache.count().await, 2, "no protected entries remain");
    assert_eq!(cache.get_managed_certificates().await.len(), 2);
    for index in 12..24 {
        let incoming = certificate(index, true);
        let hash = incoming.hash.clone();
        cache.add(incoming).await;
        assert_eq!(cache.count().await, 2);
        assert!(cache.get_by_hash(&hash).await.is_some());
    }
}

#[tokio::test]
async fn mixed_takeover_evicts_older_managed_entries_but_keeps_protected_imports() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let cache = CertCache::new(CacheOptions {
        capacity: 2,
        on_event: Some(Arc::new({
            let events = events.clone();
            move |event| events.lock().unwrap().push(event)
        })),
        ..Default::default()
    });
    let protected = certificate(0, false);
    let first = certificate(1, false);
    let second = certificate(2, false);
    for cert in [&protected, &first, &second] {
        cache.add(cert.clone()).await;
    }
    let mut first_managed = first.clone();
    first_managed.managed = true;
    cache.add(first_managed).await;
    assert_eq!(
        cache.count().await,
        3,
        "no older managed entry can make room"
    );
    events.lock().unwrap().clear();
    let mut second_managed = second.clone();
    second_managed.managed = true;
    cache.add(second_managed.clone()).await;
    assert_eq!(cache.count().await, 2);
    assert!(cache.get_by_hash(&protected.hash).await.is_some());
    assert!(cache.get_by_hash(&second.hash).await.unwrap().managed);
    assert!(cache.get_by_hash(&first.hash).await.is_none());
    assert!(cache.get_by_name(&first.names[0]).await.is_none());
    let removed: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            CacheEvent::Removed { hash, .. } => Some(hash.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(removed, vec![first.hash]);
    // A further duplicate is metadata-only, not a new admission or eviction.
    events.lock().unwrap().clear();
    second_managed.tags.push("another-owner".into());
    cache.add(second_managed).await;
    assert_eq!(cache.count().await, 2);
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|event| matches!(event, CacheEvent::Updated { .. }))
    );
}
