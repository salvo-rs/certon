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
    let needs_migration = get_account(storage.as_ref(), CA, EMAIL).await.unwrap_err();
    assert!(needs_migration.to_string().contains("migrate"));
    assert!(
        !certon::async_jobs::should_retry(&needs_migration),
        "operator migration cannot be repaired by background CA retries"
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
    let legacy_account = account("https://legacy.example/account/original");
    let legacy_bytes = old_account(&storage, &old_endpoint, EMAIL, &legacy_account).await;
    let current_ca = "https://ca.example/directory?tenant=one";
    assert!(
        get_account(&storage, current_ca, EMAIL)
            .await
            .unwrap()
            .is_none()
    );
    let current = account("https://ca.example/account/current");
    save_account(&storage, current_ca, &current).await.unwrap();
    assert_eq!(
        storage.load(&old_key(&old_endpoint, EMAIL)).await.unwrap(),
        legacy_bytes
    );
    assert_eq!(
        public_identity(
            &get_account(&storage, current_ca, EMAIL)
                .await
                .unwrap()
                .unwrap()
        ),
        public_identity(&current)
    );
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

struct ReceiptStorage {
    files: FileStorage,
    mode: std::sync::atomic::AtomicU8,
    fail_reads: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Storage for ReceiptStorage {
    async fn store(&self, key: &str, value: &[u8]) -> certon::Result<()> {
        if key.contains("/account-migrations/") {
            match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
                1 => return Err(certon::Error::Other("receipt storage unavailable".into())),
                2 => {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                _ => {}
            }
        }
        self.files.store(key, value).await
    }
    async fn load(&self, key: &str) -> certon::Result<Vec<u8>> {
        if key.contains("/account-migrations/")
            && self.fail_reads.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(certon::Error::Other("receipt reads unavailable".into()));
        }
        self.files.load(key).await
    }
    async fn delete(&self, key: &str) -> certon::Result<()> {
        self.files.delete(key).await
    }
    async fn exists(&self, key: &str) -> certon::Result<bool> {
        self.files.exists(key).await
    }
    async fn list(&self, key: &str, recursive: bool) -> certon::Result<Vec<String>> {
        self.files.list(key, recursive).await
    }
    async fn stat(&self, key: &str) -> certon::Result<certon::KeyInfo> {
        self.files.stat(key).await
    }
    async fn lock(&self, key: &str) -> certon::Result<()> {
        self.files.lock(key).await
    }
    async fn unlock(&self, key: &str) -> certon::Result<()> {
        self.files.unlock(key).await
    }
}

#[tokio::test]
async fn failed_or_cancelled_receipt_publication_is_retryable_and_fail_closed() {
    use std::sync::atomic::Ordering;
    for mode in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(ReceiptStorage {
            files: FileStorage::new(directory.path()),
            mode: mode.into(),
            fail_reads: false.into(),
            entered: Default::default(),
            release: Default::default(),
        });
        let original = account("https://ca.example:8443/account/old");
        old_account(storage.as_ref(), CA, EMAIL, &original).await;
        if mode == 1 {
            assert!(
                migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("receipt storage")
            );
        } else {
            let migration = tokio::spawn({
                let storage = storage.clone();
                let original = original.clone();
                async move { migrate_account_ca_identity(storage, CA, EMAIL, &original).await }
            });
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                storage.entered.notified(),
            )
            .await
            .unwrap();
            migration.abort();
            assert!(migration.await.unwrap_err().is_cancelled());
        }
        assert_eq!(
            public_identity(
                &get_account(storage.as_ref(), CA, EMAIL)
                    .await
                    .unwrap()
                    .unwrap()
            ),
            public_identity(&original)
        );
        // A partially migrated target is complete, but no receipt was accepted.
        delete_account_locally(storage.as_ref(), CA, &original)
            .await
            .unwrap();
        assert!(get_account(storage.as_ref(), CA, EMAIL).await.is_err());
        storage.mode.store(0, Ordering::SeqCst);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original),
        )
        .await
        .unwrap()
        .unwrap();
        delete_account_locally(storage.as_ref(), CA, &original)
            .await
            .unwrap();
        storage.fail_reads.store(true, Ordering::SeqCst);
        assert!(
            get_account(storage.as_ref(), CA, EMAIL)
                .await
                .unwrap_err()
                .to_string()
                .contains("receipt reads")
        );
        storage.fail_reads.store(false, Ordering::SeqCst);
        assert!(
            get_account(storage.as_ref(), CA, EMAIL)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn malformed_or_foreign_receipts_do_not_retire_old_accounts() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let original = account("https://ca.example:8443/account/old");
    old_account(storage.as_ref(), CA, EMAIL, &original).await;
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    delete_account_locally(storage.as_ref(), CA, &original)
        .await
        .unwrap();
    let receipt_key = storage
        .list("acme", true)
        .await
        .unwrap()
        .into_iter()
        .find(|key| key.contains("/account-migrations/") && key.ends_with(".key"))
        .unwrap();
    let original_bytes = storage.load(&receipt_key).await.unwrap();
    for field in [
        "ca_url",
        "configured_email",
        "source_issuer",
        "source_email",
        "public_key_identity",
        "location",
    ] {
        let mut receipt: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
        receipt[field] = "foreign".into();
        storage
            .store(&receipt_key, &serde_json::to_vec(&receipt).unwrap())
            .await
            .unwrap();
        assert!(
            get_account(storage.as_ref(), CA, EMAIL).await.is_err(),
            "foreign {field} was accepted"
        );
    }
    storage.store(&receipt_key, b"invalid JSON").await.unwrap();
    assert!(get_account(storage.as_ref(), CA, EMAIL).await.is_err());
    storage.store(&receipt_key, &original_bytes).await.unwrap();
    assert!(
        get_account(storage.as_ref(), CA, EMAIL)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn discovery_reads_bound_identity_instead_of_a_lossy_directory_name() {
    for email in ["operator+prod@example.com", ""] {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let mut original = new_account(email, KeyType::EcdsaP256).unwrap();
        original.location = "https://ca.example/account/known".into();
        save_account(&storage, CA, &original).await.unwrap();
        let found = certon::account::get_account_by_key(&storage, CA, &original.private_key_pem)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(public_identity(&found), public_identity(&original));
        assert_eq!(
            certon::account::most_recent_account_email(&storage, CA)
                .await
                .unwrap()
                .as_deref(),
            (!email.is_empty()).then_some(email)
        );
    }
}

#[tokio::test]
async fn migration_retry_preserves_current_destination_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let original = account("https://ca.example:8443/account/old");
    old_account(storage.as_ref(), CA, EMAIL, &original).await;
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    let mut current = original.clone();
    current.status = "updated-since-migration".into();
    current
        .contact
        .push("mailto:extra-contact@example.com".into());
    save_account(storage.as_ref(), CA, &current).await.unwrap();
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    let loaded = get_account(storage.as_ref(), CA, EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.status, current.status);
    assert_eq!(loaded.contact, current.contact);
    assert_eq!(public_identity(&loaded), public_identity(&original));
}

#[tokio::test]
async fn unbound_split_files_under_the_new_ca_need_explicit_upgrade_too() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let original = account("https://ca.example:8443/account/imported");
    let prefix = certon::storage::account_key_prefix(&certon::storage::issuer_key(CA), EMAIL);
    let registration = format!("{prefix}/operator.json");
    let private_key = format!("{prefix}/operator.key");
    storage
        .store(&registration, &serde_json::to_vec(&original).unwrap())
        .await
        .unwrap();
    assert!(get_account(storage.as_ref(), CA, EMAIL).await.is_err());
    storage
        .store(&private_key, original.private_key_pem.as_bytes())
        .await
        .unwrap();
    assert!(
        get_account(storage.as_ref(), CA, EMAIL)
            .await
            .unwrap_err()
            .to_string()
            .contains("migrate")
    );
    migrate_account_ca_identity(storage.clone(), CA, EMAIL, &original)
        .await
        .unwrap();
    let loaded = get_account(storage.as_ref(), CA, EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(public_identity(&loaded), public_identity(&original));
    assert!(storage.exists(&registration).await.unwrap());
    assert!(storage.exists(&private_key).await.unwrap());
}
