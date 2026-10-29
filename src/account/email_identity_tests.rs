use std::sync::Arc;

use super::*;
const CA: &str = "https://email-bound.example/directory";
const PLUS: &str = "operator+prod@example.com";
const LITERAL: &str = "operator_plus_prod@example.com";
fn registered(contact: &str, id: &str) -> AcmeAccount {
    let mut account = new_account(contact, KeyType::EcdsaP256).unwrap();
    account.status = "valid".into();
    account.location = format!("https://email-bound.example/account/{id}");
    account
}
#[tokio::test]
async fn empty_and_literal_default_are_separate_configured_identities() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::FileStorage::new(dir.path());
    let empty = registered("mutable-contact@example.com", "empty");
    let literal = registered("mutable-contact@example.com", "literal");
    save_account_for_email(&storage, CA, "", &empty)
        .await
        .unwrap();
    save_account_for_email(&storage, CA, "default", &literal)
        .await
        .unwrap();
    assert!(!same_account_slot(CA, "", "default"));
    assert_eq!(
        get_account(&storage, CA, "")
            .await
            .unwrap()
            .unwrap()
            .location,
        empty.location
    );
    assert_eq!(
        get_account(&storage, CA, "default")
            .await
            .unwrap()
            .unwrap()
            .location,
        literal.location
    );
    assert_eq!(
        most_recent_account_email(&storage, CA)
            .await
            .unwrap()
            .as_deref(),
        Some("default")
    );
    assert_eq!(
        get_account_by_key(&storage, CA, &empty.private_key_pem)
            .await
            .unwrap()
            .unwrap()
            .location,
        empty.location
    );
}
#[tokio::test]
async fn discovery_uses_configured_identity_not_mutable_contact() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::FileStorage::new(dir.path());
    let account = registered(LITERAL, "callback-contact");
    save_account_for_email(&storage, CA, PLUS, &account)
        .await
        .unwrap();
    assert!(get_account(&storage, CA, LITERAL).await.unwrap().is_none());
    assert_eq!(
        most_recent_account_email(&storage, CA)
            .await
            .unwrap()
            .as_deref(),
        Some(PLUS)
    );
    let loaded = get_account_by_key(&storage, CA, &account.private_key_pem)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.location, account.location);
    assert_eq!(loaded.contact, account.contact);
}
#[tokio::test]
async fn copied_snapshot_must_match_its_actual_hashed_slot() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::FileStorage::new(dir.path());
    let account = registered(PLUS, "first");
    save_account_for_email(&storage, CA, PLUS, &account)
        .await
        .unwrap();
    let issuer = crate::storage::issuer_key(CA);
    let first = storage_key_account_snapshot(&issuer, PLUS);
    let second = storage_key_account_snapshot(&issuer, LITERAL);
    assert_ne!(first, second);
    storage
        .store(&second, &storage.load(&first).await.unwrap())
        .await
        .unwrap();
    assert!(get_account(&storage, CA, LITERAL).await.is_err());
    assert!(most_recent_account_email(&storage, CA).await.is_err());
    assert!(
        get_account_by_key(&storage, CA, "an-unmatched-key")
            .await
            .is_err()
    );
    assert_eq!(
        get_account(&storage, CA, PLUS)
            .await
            .unwrap()
            .unwrap()
            .location,
        account.location
    );
}

#[tokio::test]
async fn bound_weak_email_upgrade_preserves_foreign_accounts_and_the_original_source() {
    for (old_email, fresh_email) in [
        (PLUS, LITERAL),
        (LITERAL, PLUS),
        ("", "default"),
        ("default", ""),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::FileStorage::new(dir.path()));
        let old = registered("changed-contact@example.com", "old-bound");
        let source = legacy_account_keys(&crate::storage::issuer_key(CA), old_email)[0].clone();
        let bytes = serde_json::to_vec(&AccountSnapshot {
            version: 2,
            ca_url: Some(canonical_account_ca(CA)),
            configured_email: RequiredEmail {
                present: true,
                value: canonical_account_email(old_email),
            },
            registration: old.clone(),
            private_key_pem: old.private_key_pem.clone(),
        })
        .unwrap();
        storage.store(&source, &bytes).await.unwrap();
        assert!(
            get_account(storage.as_ref(), CA, old_email).await.is_err(),
            "weak slots require explicit upgrade"
        );
        assert!(
            get_account(storage.as_ref(), CA, fresh_email)
                .await
                .unwrap()
                .is_none(),
            "a fully bound foreign source must not block fresh registration"
        );
        assert!(
            migrate_account_ca_identity(storage.clone(), CA, fresh_email, &old)
                .await
                .is_err(),
            "explicit import must not rebind foreign data"
        );
        migrate_account_ca_identity(storage.clone(), CA, old_email, &old)
            .await
            .unwrap();
        assert_eq!(storage.load(&source).await.unwrap(), bytes);
        let fresh = registered("changed-contact@example.com", "fresh");
        save_account_for_email(storage.as_ref(), CA, fresh_email, &fresh)
            .await
            .unwrap();
        assert_eq!(
            get_account(storage.as_ref(), CA, old_email)
                .await
                .unwrap()
                .unwrap()
                .location,
            old.location
        );
        assert_eq!(
            get_account(storage.as_ref(), CA, fresh_email)
                .await
                .unwrap()
                .unwrap()
                .location,
            fresh.location
        );
        delete_account_for_email(storage.as_ref(), CA, old_email)
            .await
            .unwrap();
        assert!(
            get_account(storage.as_ref(), CA, old_email)
                .await
                .unwrap()
                .is_none(),
            "a retired old generation must not resurrect"
        );
        assert_eq!(
            get_account(storage.as_ref(), CA, fresh_email)
                .await
                .unwrap()
                .unwrap()
                .location,
            fresh.location
        );
        assert_eq!(storage.load(&source).await.unwrap(), bytes);
        let replacement = registered("replacement-contact@example.com", "replacement");
        save_account_for_email(storage.as_ref(), CA, old_email, &replacement)
            .await
            .unwrap();
        assert_eq!(
            get_account(storage.as_ref(), CA, old_email)
                .await
                .unwrap()
                .unwrap()
                .location,
            replacement.location
        );
        assert_eq!(storage.load(&source).await.unwrap(), bytes);
    }
}

#[tokio::test]
async fn ambiguous_unbound_email_sources_need_explicit_original_key_proof() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(dir.path()));
    let old = registered("mutable-contact@example.com", "old-unbound");
    let source = legacy_account_keys(&crate::storage::issuer_key(CA), PLUS)[0].clone();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "registration": &old,
        "private_key_pem": &old.private_key_pem,
    }))
    .unwrap();
    storage.store(&source, &bytes).await.unwrap();
    assert!(get_account(storage.as_ref(), CA, PLUS).await.is_err());
    assert!(get_account(storage.as_ref(), CA, LITERAL).await.is_err());
    let wrong = registered("mutable-contact@example.com", "wrong");
    assert!(
        migrate_account_ca_identity(storage.clone(), CA, PLUS, &wrong)
            .await
            .is_err()
    );
    assert_eq!(storage.load(&source).await.unwrap(), bytes);
    migrate_account_ca_identity(storage.clone(), CA, PLUS, &old)
        .await
        .unwrap();
    assert_eq!(
        get_account(storage.as_ref(), CA, PLUS)
            .await
            .unwrap()
            .unwrap()
            .location,
        old.location
    );
    assert!(
        get_account(storage.as_ref(), CA, LITERAL).await.is_err(),
        "unbound legacy source has no evidence that it belongs to the collision partner"
    );
    assert_eq!(storage.load(&source).await.unwrap(), bytes);
}

#[tokio::test]
async fn old_email_resembling_the_namespace_marker_does_not_alias_new_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::FileStorage::new(dir.path());
    let old = registered("_certon-account-v2", "old-marker");
    let source =
        legacy_account_keys(&crate::storage::issuer_key(CA), "_certon-account-v2")[0].clone();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1, "registration": &old, "private_key_pem": &old.private_key_pem,
    }))
    .unwrap();
    storage.store(&source, &bytes).await.unwrap();
    assert!(
        get_account(&storage, CA, "_certon-account-v2")
            .await
            .is_err()
    );
    let current = registered(PLUS, "current");
    save_account_for_email(&storage, CA, PLUS, &current)
        .await
        .unwrap();
    assert_eq!(
        get_account(&storage, CA, PLUS)
            .await
            .unwrap()
            .unwrap()
            .location,
        current.location
    );
    assert_eq!(
        most_recent_account_email(&storage, CA)
            .await
            .unwrap()
            .as_deref(),
        Some(PLUS)
    );
    assert!(
        get_account_by_key(&storage, CA, &old.private_key_pem)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(storage.load(&source).await.unwrap(), bytes);
}

#[tokio::test]
async fn explicit_upgrade_prefers_bound_current_ca_metadata_over_an_old_slug_copy() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(crate::FileStorage::new(dir.path()));
    let old = registered("old-contact@example.com", "same-registration");
    let mut current = old.clone();
    current.contact = vec!["mailto:current-contact@example.com".into()];
    current.status = "deactivated".into();
    let old_key = legacy_account_keys(&crate::storage::legacy_issuer_key(CA), PLUS)[0].clone();
    let current_key = legacy_account_keys(&crate::storage::issuer_key(CA), PLUS)[0].clone();
    let old_bytes = serde_json::to_vec(&serde_json::json!({
        "version":1, "registration":&old, "private_key_pem":&old.private_key_pem,
    }))
    .unwrap();
    let current_bytes = serde_json::to_vec(&AccountSnapshot {
        version: 2,
        ca_url: Some(canonical_account_ca(CA)),
        configured_email: RequiredEmail {
            present: true,
            value: canonical_account_email(PLUS),
        },
        registration: current.clone(),
        private_key_pem: current.private_key_pem.clone(),
    })
    .unwrap();
    storage.store(&old_key, &old_bytes).await.unwrap();
    storage.store(&current_key, &current_bytes).await.unwrap();
    migrate_account_ca_identity(storage.clone(), CA, PLUS, &old)
        .await
        .unwrap();
    let loaded = get_account(storage.as_ref(), CA, PLUS)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.status, current.status);
    assert_eq!(loaded.contact, current.contact);
    assert_eq!(loaded.location, current.location);
    assert!(same_account_key(&loaded, &current).unwrap());
    assert_eq!(storage.load(&old_key).await.unwrap(), old_bytes);
    assert_eq!(storage.load(&current_key).await.unwrap(), current_bytes);
}
