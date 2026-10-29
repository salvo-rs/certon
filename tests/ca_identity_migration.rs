use std::sync::Arc;

use certon::account::{
    AcmeAccount, delete_account_locally, get_account, migrate_account_ca_identity, new_account,
    save_account,
};
use certon::{FileStorage, KeyType, Storage};

const CA: &str = "https://ca.example:8443/directory?tenant=one";
const OTHER_CA: &str = "https://ca.example:9443/directory?tenant=two";
const EMAIL: &str = "operator@example.com";

fn account(location: &str) -> AcmeAccount {
    let mut account = new_account(EMAIL, KeyType::EcdsaP256).unwrap();
    account.location = location.into();
    account
}
fn old_key(ca: &str, email: &str) -> String {
    let issuer = certon::storage::safe_key(&certon::storage::legacy_issuer_key(ca));
    let email = certon::storage::safe_key(if email.is_empty() { "default" } else { email });
    format!("acme/{issuer}/users/{email}/_certon/account.v1.key")
}
fn current_key(ca: &str, email: &str) -> String {
    let issuer = certon::storage::issuer_key(ca);
    format!(
        "{}/_certon/account.v1.key",
        certon::storage::account_key_prefix(&issuer, email)
    )
}
async fn old_account(
    storage: &dyn Storage,
    ca: &str,
    email: &str,
    account: &AcmeAccount,
) -> Vec<u8> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1, "registration": account, "private_key_pem": account.private_key_pem,
    }))
    .unwrap();
    storage.store(&old_key(ca, email), &bytes).await.unwrap();
    bytes
}
fn public_identity(account: &AcmeAccount) -> String {
    let key = certon::crypto::decode_private_key_pem(&account.private_key_pem).unwrap();
    certon::acme_client::key_authorization("migration-test", &key).unwrap()
}

#[tokio::test]
async fn legacy_migration_requires_proof_and_does_not_adopt_another_endpoint() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let original = account("https://ca.example:8443/account/old");
    let bytes = old_account(storage.as_ref(), CA, EMAIL, &original).await;
    assert!(
        get_account(storage.as_ref(), CA, EMAIL)
            .await
            .unwrap_err()
            .to_string()
            .contains("migrate")
    );
    assert!(
        get_account(storage.as_ref(), OTHER_CA, EMAIL)
            .await
            .is_err()
    );
    let foreign = account("https://ca.example:9443/account/foreign");
    assert!(
        migrate_account_ca_identity(storage.clone(), CA, EMAIL, &foreign)
            .await
            .is_err()
    );
    assert!(!storage.exists(&current_key(CA, EMAIL)).await.unwrap());
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    let loaded = get_account(storage.as_ref(), CA, EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.location, original.location);
    assert_eq!(public_identity(&loaded), public_identity(&original));
    assert_eq!(storage.load(&old_key(CA, EMAIL)).await.unwrap(), bytes);
    assert!(
        get_account(storage.as_ref(), OTHER_CA, EMAIL)
            .await
            .is_err()
    );
    save_account(storage.as_ref(), CA, &foreign).await.unwrap();
    assert!(
        migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
            .await
            .is_err()
    );
    let unchanged = get_account(storage.as_ref(), CA, EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(public_identity(&unchanged), public_identity(&foreign));
}

#[tokio::test]
async fn retired_legacy_generation_cannot_resurrect_or_block_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let original = account("https://ca.example:8443/account/old");
    let old_bytes = old_account(storage.as_ref(), CA, EMAIL, &original).await;
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    delete_account_locally(storage.as_ref(), CA, &original)
        .await
        .unwrap();
    assert!(
        get_account(storage.as_ref(), CA, EMAIL)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(storage.load(&old_key(CA, EMAIL)).await.unwrap(), old_bytes);
    let replacement = account("https://ca.example:8443/account/new");
    save_account(storage.as_ref(), CA, &replacement)
        .await
        .unwrap();
    assert_eq!(
        public_identity(
            &get_account(storage.as_ref(), CA, EMAIL)
                .await
                .unwrap()
                .unwrap()
        ),
        public_identity(&replacement)
    );
    delete_account_locally(storage.as_ref(), CA, &replacement)
        .await
        .unwrap();
    // A different legacy generation was never retired by the original receipt.
    old_account(storage.as_ref(), CA, EMAIL, &replacement).await;
    assert!(get_account(storage.as_ref(), CA, EMAIL).await.is_err());
}

#[tokio::test]
async fn v2_bindings_require_both_fields_and_keep_empty_identity_explicit() {
    for email in [EMAIL, ""] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let mut original = account("https://ca.example/account/known");
        if email.is_empty() {
            original.contact.clear();
        }
        let private_ca =
            "https://PRIVATE_USER:PRIVATE_PASS@ca.example/directory?token=PRIVATE_QUERY";
        save_account(storage.as_ref(), private_ca, &original)
            .await
            .unwrap();
        let key = current_key(private_ca, email);
        let original_bytes = storage.load(&key).await.unwrap();
        assert!(
            get_account(storage.as_ref(), private_ca, email)
                .await
                .unwrap()
                .is_some()
        );
        for field in ["ca_url", "configured_email"] {
            let mut snapshot: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
            snapshot.as_object_mut().unwrap().remove(field);
            storage
                .store(&key, &serde_json::to_vec(&snapshot).unwrap())
                .await
                .unwrap();
            let error = get_account(storage.as_ref(), private_ca, email)
                .await
                .unwrap_err()
                .to_string();
            for secret in ["PRIVATE_USER", "PRIVATE_PASS", "PRIVATE_QUERY"] {
                assert!(!error.contains(secret));
            }
        }
        for (field, foreign) in [
            ("ca_url", OTHER_CA),
            ("configured_email", "foreign@example.com"),
        ] {
            let mut snapshot: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
            snapshot[field] = foreign.into();
            storage
                .store(&key, &serde_json::to_vec(&snapshot).unwrap())
                .await
                .unwrap();
            assert!(
                get_account(storage.as_ref(), private_ca, email)
                    .await
                    .is_err()
            );
            assert!(
                migrate_account_ca_identity(storage.clone(), private_ca, email, &original)
                    .await
                    .is_err()
            );
            assert_eq!(
                storage.load(&key).await.unwrap(),
                serde_json::to_vec(&snapshot).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn canonical_urls_and_versioned_paths_keep_legacy_slugs_distinct() {
    let first =
        certon::storage::issuer_key("HTTPS://CA.EXAMPLE:443/a/../directory?tenant=one#first");
    let equivalent = certon::storage::issuer_key("https://ca.example/directory?tenant=one#second");
    assert_eq!(first, equivalent);
    for other in [
        "http://ca.example/directory?tenant=one",
        "https://ca.example:444/directory?tenant=one",
        "https://ca.example/directory?tenant=two",
        "https://user:pass@ca.example/directory?tenant=one",
        "not a URL",
    ] {
        assert_ne!(first, certon::storage::issuer_key(other));
    }
    let digest = first.strip_prefix("_certon-ca-v2/").unwrap();
    assert_eq!(digest.len(), 64);
    let old_endpoint = format!("https://_certon-ca-v2/{digest}");
    let old_slug = certon::storage::legacy_issuer_key(&old_endpoint);
    assert_ne!(
        certon::storage::certs_prefix(&first),
        certon::storage::certs_prefix(&old_slug)
    );
    assert_ne!(
        certon::storage::acme_ca_prefix(&first),
        certon::storage::acme_ca_prefix(&old_slug)
    );
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let new_lock = format!("acme_account_{first}");
    let old_lock = format!("acme_account_{old_slug}");
    storage.lock(&new_lock).await.unwrap();
    assert!(
        storage
            .try_lock(&old_lock, std::time::Duration::from_secs(2))
            .await
            .unwrap()
    );
    storage.unlock(&old_lock).await.unwrap();
    storage.unlock(&new_lock).await.unwrap();
}
