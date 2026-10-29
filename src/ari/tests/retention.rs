use super::*;

fn der_expiry(cert: &Certificate) -> DateTime<Utc> {
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert.cert_chain[0]).unwrap();
    DateTime::from_timestamp(parsed.validity().not_after.timestamp(), 0).unwrap()
}

async fn store_record(storage: &dyn Storage, record: &Record) {
    storage
        .store(
            &key(&record.issuer, &record.leaf),
            &serde_json::to_vec(record).unwrap(),
        )
        .await
        .unwrap();
}

async fn record(storage: &dyn Storage, cert: &Certificate) -> Record {
    load(
        storage,
        &cert.issuer_key,
        &certificate_leaf_hash(cert).unwrap(),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn all_new_records_retain_real_der_expiry_even_if_public_dates_change() {
    for response in ["positive", "unsupported", "invalid", "error"] {
        let storage = Arc::new(Memory::default());
        let info = match response {
            "positive" => Some(info(86400, 86400 * 2)),
            "invalid" => Some(info(120, 60)),
            _ => None,
        };
        let issuer = Arc::new(Issuer::new(info));
        issuer.gated.store(response == "error", Ordering::SeqCst);
        let manager = manager(storage.clone(), issuer.clone(), false, None);
        let mut cert = cached(&manager, &resource("expiry.example", 1, 90)).await;
        let expected = der_expiry(&cert);
        cert.not_after = after(86400 * 900);
        refresh(&manager, &cert).await;
        let record = record(storage.as_ref(), &cert).await;
        assert_eq!(record.leaf_not_after, Some(expected), "{response}");
        assert_ne!(record.leaf_not_after, Some(cert.not_after));
        assert_eq!(record.info.is_some(), response == "positive");
        assert_eq!(record.failures, u32::from(response == "error"));
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn legacy_upgrade_preserves_schedule_before_future_retry_and_missing_issuer_exits() {
    for positive in [false, true] {
        for missing_issuer in [false, true] {
            let storage = Arc::new(Memory::default());
            let issuer = Arc::new(Issuer::new(positive.then(|| info(86400, 86400 * 2))));
            let mut manager = manager(storage.clone(), issuer.clone(), false, None);
            let cert = cached(&manager, &resource("legacy.example", 1, 90)).await;
            refresh(&manager, &cert).await;
            let mut legacy = record(storage.as_ref(), &cert).await;
            legacy.leaf_not_after = None;
            legacy.failures = 3;
            legacy.next_check = after(if missing_issuer { -60 } else { 3600 });
            store_record(storage.as_ref(), &legacy).await;
            let bytes = storage
                .load(&key(&legacy.issuer, &legacy.leaf))
                .await
                .unwrap();
            assert!(
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap()
                    .get("leaf_not_after")
                    .is_none()
            );

            // Attach reads do not write metadata, even with a live certificate.
            let mut attached = cert.clone();
            attach(storage.as_ref(), &mut attached, false).await;
            assert_eq!(
                storage
                    .load(&key(&legacy.issuer, &legacy.leaf))
                    .await
                    .unwrap(),
                bytes
            );
            if missing_issuer {
                manager.issuers.clear();
            }
            let next = refresh(&manager, &cert).await;
            let upgraded = record(storage.as_ref(), &cert).await;
            assert_eq!(upgraded.leaf_not_after, Some(der_expiry(&cert)));
            assert_eq!(fingerprint(Some(&legacy)), fingerprint(Some(&upgraded)));
            let mut stripped = upgraded;
            stripped.leaf_not_after = None;
            assert_eq!(
                serde_json::to_value(stripped).unwrap(),
                serde_json::to_value(&legacy).unwrap()
            );
            if !missing_issuer {
                assert_eq!(next, legacy.next_check);
            }
            assert_eq!(
                issuer.calls.load(Ordering::SeqCst),
                1,
                "metadata upgrade must not GET"
            );
        }
    }
}

#[tokio::test]
async fn metadata_upgrade_cannot_discard_a_failed_store_volatile_due_point() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(Some(info(86400, 86400 * 2))));
    let mut manager = manager(storage.clone(), issuer.clone(), false, None);
    let cert = cached(&manager, &resource("volatile-retention.example", 1, 90)).await;
    refresh(&manager, &cert).await;
    let mut legacy = record(storage.as_ref(), &cert).await;
    legacy.leaf_not_after = None;
    legacy.next_check = after(-60);
    store_record(storage.as_ref(), &legacy).await;

    storage.fail_ari_store.store(true, Ordering::SeqCst);
    *issuer.info.lock().unwrap() = Some(info(-120, -60));
    refresh(&manager, &cert).await;
    let due = manager
        .cache
        .get_by_hash(&cert.hash)
        .await
        .unwrap()
        .ari
        .unwrap()
        .selected_time;
    assert!(due.unwrap() < Utc::now());
    assert!(
        manager
            .cache
            .has_unpersisted_ari(&cert.hash, &cert.issuer_key)
    );
    manager.issuers.clear();
    let calls = issuer.calls.load(Ordering::SeqCst);

    // First the upgrade write fails, then another refresh successfully saves
    // only expiry. Neither changes the recommendation fingerprint.
    for fails in [true, false] {
        storage.fail_ari_store.store(fails, Ordering::SeqCst);
        refresh(&manager, &cert).await;
        let persisted = record(storage.as_ref(), &cert).await;
        assert_eq!(persisted.leaf_not_after.is_some(), !fails);
        assert_eq!(fingerprint(Some(&legacy)), fingerprint(Some(&persisted)));
        let mut attached = cert.clone();
        attach_cached(storage.as_ref(), &manager.cache, &mut attached, false).await;
        assert_eq!(attached.ari.unwrap().selected_time, due);
        assert!(
            manager
                .cache
                .has_unpersisted_ari(&cert.hash, &cert.issuer_key)
        );
        assert_eq!(issuer.calls.load(Ordering::SeqCst), calls);
    }
}

#[tokio::test]
async fn ineligible_legacy_records_are_not_upgraded() {
    for condition in ["disabled", "expired", "removed", "unmanaged", "replaced"] {
        let storage = Arc::new(Memory::default());
        let issuer = Arc::new(Issuer::new(None));
        let mut manager = manager(storage.clone(), issuer.clone(), false, None);
        let mut cert = cached(&manager, &resource("withdrawn.example", 1, 90)).await;
        refresh(&manager, &cert).await;
        let mut legacy = record(storage.as_ref(), &cert).await;
        legacy.leaf_not_after = None;
        store_record(storage.as_ref(), &legacy).await;
        match condition {
            "disabled" => manager.policy.disable_ari = true,
            "expired" => cert.not_after = after(-1),
            "removed" => manager.cache.remove(&cert.hash).await,
            "unmanaged" => {
                manager.cache.remove(&cert.hash).await;
                let mut unmanaged = cert.clone();
                unmanaged.managed = false;
                manager.cache.add(unmanaged).await;
            }
            "replaced" => {
                cached(&manager, &resource("withdrawn.example", 1, 91)).await;
            }
            _ => unreachable!(),
        }
        refresh(&manager, &cert).await;
        assert!(
            record(storage.as_ref(), &cert)
                .await
                .leaf_not_after
                .is_none(),
            "{condition}"
        );
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1, "{condition}");
    }
}

#[tokio::test]
async fn an_upgrade_write_wait_does_not_authorize_a_get_after_withdrawal() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    let manager = Arc::new(manager(storage.clone(), issuer.clone(), false, None));
    let cert = cached(&manager, &resource("upgrade-wait.example", 1, 90)).await;
    refresh(&manager, &cert).await;
    let mut legacy = record(storage.as_ref(), &cert).await;
    legacy.leaf_not_after = None;
    legacy.next_check = after(-60);
    store_record(storage.as_ref(), &legacy).await;
    let gate = Arc::new(LoadGate {
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    *storage.store_gate.lock().unwrap() = Some(gate.clone());
    let task = {
        let manager = manager.clone();
        let cert = cert.clone();
        tokio::spawn(async move { refresh(&manager, &cert).await })
    };
    tokio::time::timeout(Duration::from_secs(3), gate.entered.notified())
        .await
        .unwrap();
    manager.cache.remove(&cert.hash).await;
    gate.release.add_permits(1);
    task.await.unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        record(storage.as_ref(), &cert).await.leaf_not_after,
        Some(der_expiry(&cert))
    );
}

#[tokio::test]
async fn retention_uses_one_strict_boundary_and_preserves_arithmetic_overflow() {
    let storage = Arc::new(Memory::default());
    let issuer = Arc::new(Issuer::new(None));
    let manager = manager(storage.clone(), issuer, false, None);
    let cert = cached(&manager, &resource("boundary.example", 1, 90)).await;
    refresh(&manager, &cert).await;
    let mut record = record(storage.as_ref(), &cert).await;
    let path = key(&record.issuer, &record.leaf);
    let now = Utc::now();
    let grace = Duration::from_secs(86400);
    record.leaf_not_after = Some(now - chrono::Duration::days(1));
    store_record(storage.as_ref(), &record).await;
    clean_expired(storage.as_ref(), now, grace).await;
    assert!(
        storage.exists(&path).await.unwrap(),
        "exact boundary must be retained"
    );
    record.leaf_not_after = Some(DateTime::<Utc>::MAX_UTC);
    store_record(storage.as_ref(), &record).await;
    clean_expired(storage.as_ref(), now, grace).await;
    assert!(
        storage.exists(&path).await.unwrap(),
        "date addition overflow must retain"
    );
    record.leaf_not_after = Some(now - chrono::Duration::days(2));
    store_record(storage.as_ref(), &record).await;
    clean_expired(storage.as_ref(), now, Duration::MAX).await;
    assert!(
        storage.exists(&path).await.unwrap(),
        "unrepresentable grace must retain"
    );
    record.leaf_not_after =
        Some(now - chrono::Duration::days(1) - chrono::Duration::nanoseconds(1));
    store_record(storage.as_ref(), &record).await;
    clean_expired(storage.as_ref(), now, grace).await;
    assert!(
        !storage.exists(&path).await.unwrap(),
        "strictly expired must be collected"
    );
}
