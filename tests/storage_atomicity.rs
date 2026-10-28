use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use certon::account::{get_account, new_account, save_account};
use certon::storage::{CertificateResource, KeyInfo, load_certificate, store_certificate};
use certon::{CertStore, Error, FileStorage, KeyType, KeyValueCertStore, Result, Storage};

/// Inject failures on either side of a backend's atomic publication boundary.
struct FaultStorage {
    inner: FileStorage,
    mode: AtomicU8,
    entered: tokio::sync::Notify,
}

#[async_trait]
impl Storage for FaultStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 1 {
            return Err(Error::Other("injected write failure".into()));
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
        self.inner.load(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key).await
    }
    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        self.inner.list(path, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        self.inner.stat(key).await
    }
    async fn lock(&self, name: &str) -> Result<()> {
        self.inner.lock(name).await
    }
    async fn unlock(&self, name: &str) -> Result<()> {
        self.inner.unlock(name).await
    }
}

fn resource(value: u8) -> CertificateResource {
    CertificateResource {
        sans: vec!["example.com".into()],
        certificate_pem: vec![value; 16],
        private_key_pem: vec![value; 32],
        issuer_data: Some(serde_json::json!({"generation": value})),
        issuer_key: "ca".into(),
    }
}

fn faulty(path: &std::path::Path) -> Arc<FaultStorage> {
    Arc::new(FaultStorage {
        inner: FileStorage::new(path),
        mode: AtomicU8::new(0),
        entered: tokio::sync::Notify::new(),
    })
}

#[tokio::test]
async fn failed_renewal_keeps_complete_snapshot_and_legacy_resources() {
    for legacy in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        let old = resource(1);
        if legacy {
            storage
                .inner
                .store(
                    &certon::storage::site_cert_key("ca", "example.com"),
                    &old.certificate_pem,
                )
                .await
                .unwrap();
            storage
                .inner
                .store(
                    &certon::storage::site_private_key("ca", "example.com"),
                    &old.private_key_pem,
                )
                .await
                .unwrap();
            storage
                .inner
                .store(
                    &certon::storage::site_meta_key("ca", "example.com"),
                    &serde_json::to_vec(&old).unwrap(),
                )
                .await
                .unwrap();
        } else {
            store_certificate(storage.as_ref(), "ca", &old)
                .await
                .unwrap();
        }
        storage.mode.store(1, Ordering::SeqCst);
        assert!(
            store_certificate(storage.as_ref(), "ca", &resource(2))
                .await
                .is_err()
        );
        // Reopen through the other public reader, as after a restart.
        let reader = KeyValueCertStore::new(Arc::new(FileStorage::new(directory.path())));
        let actual = reader.load("ca", "example.com").await.unwrap().unwrap();
        assert_eq!(actual.certificate_pem, old.certificate_pem);
        assert_eq!(actual.private_key_pem, old.private_key_pem);
        assert_eq!(actual.issuer_data, old.issuer_data);
    }
}

#[tokio::test]
async fn cancelled_renewal_observes_only_complete_old_or_new_snapshot() {
    for mode in [2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        store_certificate(storage.as_ref(), "ca", &resource(1))
            .await
            .unwrap();
        storage.mode.store(mode, Ordering::SeqCst);
        let writer = storage.clone();
        let task = tokio::spawn(async move {
            let store = KeyValueCertStore::new(writer);
            store.save("ca", &resource(2)).await
        });
        tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let reader = FileStorage::new(directory.path());
        let actual = load_certificate(&reader, "ca", "example.com")
            .await
            .unwrap();
        let expected = resource(if mode == 2 { 1 } else { 2 });
        assert_eq!(actual.certificate_pem, expected.certificate_pem);
        assert_eq!(actual.private_key_pem, expected.private_key_pem);
        assert_eq!(actual.issuer_data, expected.issuer_data);
    }
}

#[tokio::test]
async fn account_overwrite_failure_and_cancellation_preserve_a_complete_account() {
    let ca = "https://acme.example.com/directory";
    for mode in [1, 2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let storage = faulty(directory.path());
        let mut old = new_account("user@example.com", KeyType::EcdsaP256).unwrap();
        old.location = "old-location".into();
        let mut new = new_account("user@example.com", KeyType::EcdsaP256).unwrap();
        new.location = "new-location".into();
        save_account(storage.as_ref(), ca, &old).await.unwrap();
        storage.mode.store(mode, Ordering::SeqCst);
        let writer = storage.clone();
        let replacement = new.clone();
        let task =
            tokio::spawn(async move { save_account(writer.as_ref(), ca, &replacement).await });
        if mode == 1 {
            assert!(task.await.unwrap().is_err());
        } else {
            tokio::time::timeout(Duration::from_secs(5), storage.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        let actual = get_account(&FileStorage::new(directory.path()), ca, "user@example.com")
            .await
            .unwrap()
            .unwrap();
        let expected = if mode == 3 { new } else { old };
        assert_eq!(actual.location, expected.location);
        assert_eq!(actual.private_key_pem, expected.private_key_pem);
    }
}

#[tokio::test]
async fn legacy_account_and_snapshot_names_do_not_collide() {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let ca = "https://acme.example.com/directory";
    let account = new_account("account.v1@example.com", KeyType::EcdsaP256).unwrap();
    let issuer = certon::storage::issuer_key(ca);
    let prefix = certon::storage::account_key_prefix(&issuer, "account.v1@example.com");
    let registration_key = format!("{prefix}/account.v1.json");
    let private_key = format!("{prefix}/account.v1.key");
    storage
        .store(&registration_key, &serde_json::to_vec(&account).unwrap())
        .await
        .unwrap();
    assert!(
        get_account(&storage, ca, "account.v1@example.com")
            .await
            .is_err(),
        "a missing legacy private key is corruption, not a new account"
    );
    storage
        .store(&private_key, account.private_key_pem.as_bytes())
        .await
        .unwrap();
    let loaded = get_account(&storage, ca, "account.v1@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.private_key_pem, account.private_key_pem);
    save_account(&storage, ca, &account).await.unwrap();
    let loaded = get_account(&storage, ca, "account.v1@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.private_key_pem, account.private_key_pem);
    certon::account::delete_account_locally(&storage, ca, &account)
        .await
        .unwrap();
    assert!(
        get_account(&storage, ca, "account.v1@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn legacy_certificate_and_snapshot_names_do_not_collide() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let mut old = resource(1);
    old.sans = vec!["resource.v1".into()];
    storage
        .store(
            &certon::storage::site_cert_key("ca", "resource.v1"),
            &old.certificate_pem,
        )
        .await
        .unwrap();
    storage
        .store(
            &certon::storage::site_private_key("ca", "resource.v1"),
            &old.private_key_pem,
        )
        .await
        .unwrap();
    storage
        .store(
            &certon::storage::site_meta_key("ca", "resource.v1"),
            &serde_json::to_vec(&old).unwrap(),
        )
        .await
        .unwrap();
    let store = KeyValueCertStore::new(storage.clone());
    assert_eq!(
        store
            .load("ca", "resource.v1")
            .await
            .unwrap()
            .unwrap()
            .private_key_pem,
        old.private_key_pem
    );
    let mut new = old.clone();
    new.private_key_pem = vec![2; 32];
    store.save("ca", &new).await.unwrap();
    assert_eq!(
        load_certificate(storage.as_ref(), "ca", "resource.v1")
            .await
            .unwrap()
            .private_key_pem,
        new.private_key_pem
    );
    store.remove("ca", "resource.v1").await.unwrap();
    assert!(store.load("ca", "resource.v1").await.unwrap().is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn snapshots_containing_secrets_have_private_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    store_certificate(&storage, "ca", &resource(1))
        .await
        .unwrap();
    let snapshot = directory
        .path()
        .join("certificates/ca/example.com/_certon/resource.v1.key");
    assert_eq!(
        std::fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn corrupt_legacy_lock_metadata_and_old_owner_release_do_not_break_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let old = FileStorage::new(directory.path());
    let successor = FileStorage::new(directory.path());
    let contender = FileStorage::new(directory.path());
    std::fs::create_dir_all(directory.path().join("locks")).unwrap();
    std::fs::write(directory.path().join("locks/test.lock"), b"{broken json").unwrap();
    assert!(old.try_lock("test", Duration::from_secs(1)).await.unwrap());
    assert!(
        !successor
            .try_lock("test", Duration::from_millis(80))
            .await
            .unwrap()
    );
    old.unlock("test").await.unwrap();
    assert!(
        successor
            .try_lock("test", Duration::from_secs(1))
            .await
            .unwrap()
    );
    old.unlock("test").await.unwrap();
    assert!(
        !contender
            .try_lock("test", Duration::from_millis(80))
            .await
            .unwrap()
    );
    successor.unlock("test").await.unwrap();
    assert!(
        contender
            .try_lock("test", Duration::from_secs(1))
            .await
            .unwrap()
    );
    contender.unlock("test").await.unwrap();
}

#[tokio::test]
async fn cancelled_file_lock_waiter_cannot_strand_the_os_lock() {
    let directory = tempfile::tempdir().unwrap();
    let owner = FileStorage::new(directory.path());
    owner.lock("cancelled").await.unwrap();
    let waiter = Arc::new(FileStorage::new(directory.path()));
    let waiting = waiter.clone();
    let task = tokio::spawn(async move { waiting.lock("cancelled").await });
    // Observe contention through a separate backend before cancelling the waiter.
    let successor = FileStorage::new(directory.path());
    assert!(
        !successor
            .try_lock("cancelled", Duration::from_millis(80))
            .await
            .unwrap()
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    owner.unlock("cancelled").await.unwrap();
    assert!(
        successor
            .try_lock("cancelled", Duration::from_secs(1))
            .await
            .unwrap()
    );
    successor.unlock("cancelled").await.unwrap();
}

#[test]
fn lock_owner_child() {
    let Some(path) = std::env::var_os("CERTON_LOCK_CHILD_PATH") else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let storage = FileStorage::new(&path);
    runtime.block_on(storage.lock("process")).unwrap();
    std::fs::write(std::path::Path::new(&path).join("ready"), b"locked").unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[tokio::test]
async fn process_crash_releases_lock_without_deleting_its_inode() {
    let directory = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "lock_owner_child", "--nocapture"])
        .env("CERTON_LOCK_CHILD_PATH", directory.path())
        .stdout(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().unwrap();
    let storage = FileStorage::new(directory.path());
    let ready = directory.path().join("ready");
    let started = tokio::time::timeout(Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let held = if started.is_ok() {
        !storage
            .try_lock("process", Duration::from_millis(80))
            .await
            .unwrap()
    } else {
        false
    };
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(started.is_ok(), "child must acquire its OS lock");
    assert!(held, "a live process owns its lock");
    assert!(
        storage
            .try_lock("process", Duration::from_secs(1))
            .await
            .unwrap()
    );
    assert!(directory.path().join("locks/process.lock").exists());
    storage.unlock("process").await.unwrap();
}
