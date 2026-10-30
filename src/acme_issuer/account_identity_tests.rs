use std::sync::atomic::{AtomicU8, Ordering};

use super::*;
use crate::FileStorage;
use crate::account::{migrate_contact_account, new_account, save_account};
use crate::storage::KeyInfo;

const CA: &str = "https://identity.example.test/directory";
const IDENTITY: &str = "original@example.com";
const CONTACT: &str = "replacement@example.com";

fn registered(email: &str, generation: &str) -> AcmeAccount {
    let mut account = new_account(email, KeyType::EcdsaP256).unwrap();
    account.status = "valid".into();
    account.location = format!("https://identity.example.test/account/{generation}");
    account
}

fn snapshot(email: &str) -> String {
    format!(
        "{}/_certon/account.v1.key",
        crate::storage::account_key_prefix(&issuer_key(CA), email)
    )
}

struct FaultStorage {
    inner: FileStorage,
    mode: AtomicU8,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl Storage for FaultStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 10 && key == snapshot(CONTACT) {
            return Err(Error::Other("unrelated alias must not be written".into()));
        }
        if mode == 1 {
            return Err(Error::Other("identity write fault".into()));
        }
        if mode == 2 {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.inner.store(key, value).await?;
        if mode == 3 {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if self.mode.load(Ordering::SeqCst) == 7 && key == snapshot(CONTACT) {
            return Err(Error::Other("identity read fault".into()));
        }
        self.inner.load(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        let mode = self.mode.load(Ordering::SeqCst);
        let prefix = crate::storage::account_key_prefix(&issuer_key(CA), CONTACT);
        if mode == 8 && key == format!("{prefix}/replacement.key") {
            return Err(Error::Other("legacy key delete fault".into()));
        }
        if mode == 10 && key == snapshot(CONTACT) {
            return Err(Error::Other("unrelated alias must not be deleted".into()));
        }
        if mode == 4 && key == snapshot(CONTACT) {
            return Err(Error::Other("alias delete fault".into()));
        }
        self.inner.delete(key).await?;
        if mode == 9 && key == format!("{prefix}/replacement.json") {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        if mode == 5 && key == snapshot(CONTACT) {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key).await
    }
    async fn list(&self, key: &str, recursive: bool) -> Result<Vec<String>> {
        self.inner.list(key, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        self.inner.stat(key).await
    }
    async fn lock(&self, key: &str) -> Result<()> {
        if self.mode.load(Ordering::SeqCst) == 6 {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.lock(key).await
    }
    async fn unlock(&self, key: &str) -> Result<()> {
        self.inner.unlock(key).await
    }
}

fn faulty(path: &std::path::Path) -> Arc<FaultStorage> {
    Arc::new(FaultStorage {
        inner: FileStorage::new(path),
        mode: AtomicU8::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    })
}

#[tokio::test]
async fn identity_snapshot_failure_and_cancellation_keep_complete_generations() {
    for mode in [1, 2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        let old = registered(CONTACT, "old");
        let new = registered(CONTACT, "new");
        save_account_for_email(storage.as_ref(), CA, IDENTITY, &old)
            .await
            .unwrap();
        storage.mode.store(mode, Ordering::SeqCst);
        let writer = storage.clone();
        let replacement = new.clone();
        let task = tokio::spawn(async move {
            save_account_for_email(writer.as_ref(), CA, IDENTITY, &replacement).await
        });
        if mode == 1 {
            assert!(task.await.unwrap().is_err());
        } else {
            tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        let actual = get_account(&storage.inner, CA, IDENTITY)
            .await
            .unwrap()
            .unwrap();
        let expected = if mode == 3 { new } else { old };
        assert_eq!(actual.location, expected.location);
        assert_eq!(actual.private_key_pem, expected.private_key_pem);
        assert_eq!(actual.contact, expected.contact);
        assert!(
            get_account(&storage.inner, CA, CONTACT)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn legacy_migration_failure_or_cancellation_keeps_the_original_alias() {
    for mode in [1, 2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        let legacy = registered(CONTACT, "legacy");
        save_account(storage.as_ref(), CA, &legacy).await.unwrap();
        let candidate = legacy.clone();
        storage.mode.store(mode, Ordering::SeqCst);
        let writer = storage.clone();
        let task = tokio::spawn(async move {
            migrate_contact_account(writer.as_ref(), CA, IDENTITY, &candidate).await
        });
        if mode == 1 {
            assert!(task.await.unwrap().is_err());
        } else {
            tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        let alias = get_account(&storage.inner, CA, CONTACT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alias.location, legacy.location);
        assert_eq!(alias.private_key_pem, legacy.private_key_pem);
        let canonical = get_account(&storage.inner, CA, IDENTITY).await.unwrap();
        if mode == 3 {
            assert_eq!(canonical.unwrap().private_key_pem, legacy.private_key_pem);
        } else {
            assert!(canonical.is_none());
        }
    }
}

#[tokio::test]
async fn migration_does_not_treat_corruption_or_storage_errors_as_missing() {
    let directory = tempfile::tempdir().unwrap();
    let storage = faulty(directory.path());
    let legacy = registered(CONTACT, "legacy");
    save_account(storage.as_ref(), CA, &legacy).await.unwrap();
    storage.mode.store(7, Ordering::SeqCst);
    let error = migrate_contact_account(storage.as_ref(), CA, IDENTITY, &legacy)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("read fault"));
    assert!(
        get_account(&storage.inner, CA, IDENTITY)
            .await
            .unwrap()
            .is_none()
    );
    storage.mode.store(0, Ordering::SeqCst);
    storage
        .inner
        .store(&snapshot(CONTACT), b"malformed snapshot")
        .await
        .unwrap();
    assert!(
        migrate_contact_account(storage.as_ref(), CA, IDENTITY, &legacy)
            .await
            .is_err()
    );
    assert!(
        get_account(&storage.inner, CA, IDENTITY)
            .await
            .unwrap()
            .is_none()
    );
    // A newer identity-bound slot at the callback contact is not an old
    // contact-layout alias, even if its private key matches the candidate.
    let other = registered("another@example.com", "another");
    save_account_for_email(&storage.inner, CA, CONTACT, &other)
        .await
        .unwrap();
    let mut candidate = other;
    candidate.contact = vec![format!("mailto:{CONTACT}")];
    let error = migrate_contact_account(storage.as_ref(), CA, IDENTITY, &candidate)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("identity-bound"));
    assert!(
        get_account(&storage.inner, CA, IDENTITY)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn delayed_failure_recovery_preserves_new_storage_and_cache_generations() {
    let directory = tempfile::tempdir().unwrap();
    let storage = faulty(directory.path());
    let old = registered(CONTACT, "old");
    // A CA can recreate the same supplied key under a new account URI.
    // Comparing only keys would incorrectly delete this newer registration.
    let mut new = old.clone();
    new.location = "https://identity.example.test/account/new".into();
    save_account_for_email(storage.as_ref(), CA, IDENTITY, &old)
        .await
        .unwrap();
    let issuer = Arc::new(
        AcmeIssuer::builder()
            .ca(CA)
            .test_ca(CA)
            .email(IDENTITY)
            .storage(storage.clone())
            .build(),
    );
    *issuer.account.lock().await = Some(old.clone());
    storage.mode.store(6, Ordering::SeqCst);
    let task = tokio::spawn({
        let issuer = issuer.clone();
        async move { issuer.delete_account_and_clear_cache(CA, &old, false).await }
    });
    tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
        .await
        .unwrap();
    {
        let mut cache = issuer
            .account
            .try_lock()
            .expect("recovery must not hold the cache mutex while acquiring the CA lock");
        *cache = Some(new.clone());
    }
    save_account_for_email(&storage.inner, CA, IDENTITY, &new)
        .await
        .unwrap();
    storage.mode.store(0, Ordering::SeqCst);
    storage.release.notify_one();
    task.await.unwrap().unwrap();
    assert_eq!(
        get_account(&storage.inner, CA, IDENTITY)
            .await
            .unwrap()
            .unwrap()
            .location,
        new.location
    );
    assert_eq!(
        issuer.account.lock().await.as_ref().unwrap().location,
        new.location
    );
}

#[tokio::test]
async fn recovery_deletes_the_failed_canonical_last_and_retains_cancelled_cleanup_intent() {
    for mode in [4, 5] {
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        let old = registered(CONTACT, "old");
        save_account(storage.as_ref(), CA, &old).await.unwrap();
        save_account_for_email(storage.as_ref(), CA, IDENTITY, &old)
            .await
            .unwrap();
        let issuer = Arc::new(
            AcmeIssuer::builder()
                .ca(CA)
                .test_ca(CA)
                .email(IDENTITY)
                .storage(storage.clone())
                .build(),
        );
        *issuer.account.lock().await = Some(old.clone());
        storage.mode.store(mode, Ordering::SeqCst);
        let task = tokio::spawn({
            let issuer = issuer.clone();
            let old = old.clone();
            async move { issuer.delete_account_and_clear_cache(CA, &old, false).await }
        });
        if mode == 4 {
            assert!(task.await.unwrap().is_err());
        } else {
            tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert!(
            get_account(&storage.inner, CA, IDENTITY)
                .await
                .unwrap()
                .is_some()
        );
        assert!(issuer.account.lock().await.is_some());
        storage.mode.store(0, Ordering::SeqCst);
        tokio::time::timeout(
            Duration::from_secs(5),
            issuer.delete_account_and_clear_cache(CA, &old, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            get_account(&storage.inner, CA, IDENTITY)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_account(&storage.inner, CA, CONTACT)
                .await
                .unwrap()
                .is_none()
        );
        assert!(issuer.account.lock().await.is_none());
    }
}

#[tokio::test]
async fn recovery_preserves_an_unrelated_contact_account() {
    let directory = tempfile::tempdir().unwrap();
    let storage = faulty(directory.path());
    let old = registered(CONTACT, "old");
    // Even a matching URI is insufficient when the alias has another key.
    let unrelated = registered(CONTACT, "old");
    save_account(storage.as_ref(), CA, &unrelated)
        .await
        .unwrap();
    save_account_for_email(storage.as_ref(), CA, IDENTITY, &old)
        .await
        .unwrap();
    let issuer = AcmeIssuer::builder()
        .ca(CA)
        .test_ca(CA)
        .email(IDENTITY)
        .storage(storage.clone())
        .build();
    storage.mode.store(10, Ordering::SeqCst);
    issuer
        .delete_account_and_clear_cache(CA, &old, false)
        .await
        .unwrap();
    assert!(
        get_account(issuer.storage.as_ref(), CA, IDENTITY)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        get_account(issuer.storage.as_ref(), CA, CONTACT)
            .await
            .unwrap()
            .unwrap()
            .location,
        unrelated.location
    );
}

#[tokio::test]
async fn recovery_of_legacy_pair_alias_can_retry_a_partial_delete() {
    legacy_pair_partial_delete(true).await;
}

#[tokio::test]
async fn recovery_of_legacy_pair_canonical_can_retry_a_partial_delete() {
    legacy_pair_partial_delete(false).await;
}

async fn legacy_pair_partial_delete(has_alias: bool) {
    for mode in [8, 9] {
        let identity = if has_alias { IDENTITY } else { CONTACT };
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        let old = registered(CONTACT, "legacy");
        let prefix = crate::storage::account_key_prefix(&issuer_key(CA), CONTACT);
        storage
            .inner
            .store(
                &format!("{prefix}/replacement.json"),
                &serde_json::to_vec(&old).unwrap(),
            )
            .await
            .unwrap();
        storage
            .inner
            .store(
                &format!("{prefix}/replacement.key"),
                old.private_key_pem.as_bytes(),
            )
            .await
            .unwrap();
        // The operator-confirmed legacy import publishes its CA/configured
        // identity binding before ordinary recovery may use the old account.
        // Keep both old files to exercise the original partial-delete faults.
        save_account_for_email(&storage.inner, CA, CONTACT, &old)
            .await
            .unwrap();
        if has_alias {
            migrate_contact_account(storage.as_ref(), CA, identity, &old)
                .await
                .unwrap()
                .unwrap();
        }
        let issuer = Arc::new(
            AcmeIssuer::builder()
                .ca(CA)
                .test_ca(CA)
                .email(identity)
                .storage(storage.clone())
                .build(),
        );
        *issuer.account.lock().await = Some(old.clone());
        storage.mode.store(mode, Ordering::SeqCst);
        let task = tokio::spawn({
            let issuer = issuer.clone();
            let old = old.clone();
            async move { issuer.delete_account_and_clear_cache(CA, &old, false).await }
        });
        if mode == 8 {
            assert!(task.await.unwrap().is_err());
        } else {
            tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert!(
            !storage
                .inner
                .exists(&format!("{prefix}/replacement.json"))
                .await
                .unwrap()
        );
        assert!(
            storage
                .inner
                .exists(&format!("{prefix}/replacement.key"))
                .await
                .unwrap()
        );
        let alias = get_account(&storage.inner, CA, CONTACT).await;
        assert!(
            alias.as_ref().is_ok_and(|value| value.is_some()),
            "partial legacy cleanup must retain atomic proof for retry: {alias:?}"
        );
        assert!(
            get_account(&storage.inner, CA, identity)
                .await
                .unwrap()
                .is_some()
        );
        storage.mode.store(0, Ordering::SeqCst);
        tokio::time::timeout(
            Duration::from_secs(5),
            issuer.delete_account_and_clear_cache(CA, &old, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            get_account(&storage.inner, CA, identity)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_account(&storage.inner, CA, CONTACT)
                .await
                .unwrap()
                .is_none()
        );
        assert!(issuer.account.lock().await.is_none());
    }
}
