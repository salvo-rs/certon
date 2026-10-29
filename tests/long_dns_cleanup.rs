use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use certon::maintain::{CleanStorageOptions, clean_storage};
use certon::{CertificateResource, KeyInfo, Result, Storage};
use chrono::Utc;

#[derive(Default)]
struct MemoryStorage {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_read: Mutex<Option<String>>,
    fail_delete_once: Mutex<Option<String>>,
    blocked_delete: Mutex<Option<String>>,
    delete_entered: tokio::sync::Notify,
    delete_release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(key.into(), bytes.into());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if self.fail_read.lock().unwrap().as_deref() == Some(key) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "snapshot inaccessible",
            )
            .into());
        }
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| certon::error::StorageError::NotFound(key.into()).into())
    }
    async fn delete(&self, key: &str) -> Result<()> {
        let blocked = self.blocked_delete.lock().unwrap().as_deref() == Some(key);
        if blocked {
            self.delete_entered.notify_one();
            self.delete_release.notified().await;
        }
        {
            let mut fail = self.fail_delete_once.lock().unwrap();
            if fail.as_deref() == Some(key) {
                *fail = None;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "transient deletion failure",
                )
                .into());
            }
        }
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.entries.lock().unwrap().contains_key(key))
    }
    async fn list(&self, prefix: &str, _: bool) -> Result<Vec<String>> {
        let prefix = format!("{prefix}/");
        Ok(self
            .entries
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect())
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        Ok(KeyInfo {
            key: key.into(),
            modified: Utc::now(),
            size: self.load(key).await?.len() as u64,
            is_terminal: true,
        })
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

fn long_name(wildcard: bool) -> String {
    let name = if wildcard {
        format!(
            "*.{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(59)
        )
    } else {
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        )
    };
    assert_eq!(name.len(), 253);
    name
}

fn resource(name: &str, expired: bool) -> CertificateResource {
    let now = std::time::SystemTime::now();
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.not_before = (now - Duration::from_secs(90 * 86400)).into();
    params.not_after = if expired {
        now - Duration::from_secs(7 * 86400)
    } else {
        now + Duration::from_secs(30 * 86400)
    }
    .into();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    CertificateResource {
        sans: vec![name.into()],
        certificate_pem: cert.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_key: "long-ca".into(),
        issuer_data: None,
    }
}

fn snapshot(resource: &CertificateResource) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "metadata": resource,
        "certificate_pem": resource.certificate_pem, "private_key_pem": resource.private_key_pem,
    }))
    .unwrap()
}

fn old_site(resource: &CertificateResource) -> String {
    format!(
        "certificates/long-ca/{}",
        certon::storage::safe_key(&resource.names_key())
    )
}

fn snapshot_key(site: &str) -> String {
    format!("{site}/_certon/resource.v1.key")
}

fn canonical_keys(resource: &CertificateResource) -> [String; 3] {
    let name = resource.names_key();
    [
        certon::storage::site_cert_key("long-ca", &name),
        certon::storage::site_private_key("long-ca", &name),
        certon::storage::site_meta_key("long-ca", &name),
    ]
}

fn old_keys(resource: &CertificateResource) -> [String; 3] {
    let site = old_site(resource);
    let name = certon::storage::safe_key(&resource.names_key());
    [
        format!("{site}/{name}.crt"),
        format!("{site}/{name}.key"),
        format!("{site}/{name}.json"),
    ]
}

async fn legacy(storage: &dyn Storage, resource: &CertificateResource, keys: [String; 3]) {
    for (key, bytes) in keys.into_iter().zip([
        resource.certificate_pem.clone(),
        resource.private_key_pem.clone(),
        serde_json::to_vec(resource).unwrap(),
    ]) {
        storage.store(&key, &bytes).await.unwrap();
    }
}

#[tokio::test]
async fn real_file_cleanup_collects_hashed_sites_and_bounded_legacy_names() {
    let directory = tempfile::tempdir().unwrap();
    let storage = certon::FileStorage::new(directory.path());
    let cert = resource(&long_name(true), true);
    let site = certon::storage::certs_site_prefix("long-ca", &cert.names_key());
    assert!(site.contains("/_certon-long-v1/"));
    certon::storage::store_certificate(&storage, "long-ca", &cert)
        .await
        .unwrap();
    let keys = canonical_keys(&cert);
    legacy(&storage, &cert, keys.clone()).await;
    let result = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(result.deleted_certs, 1);
    for key in keys.into_iter().chain([snapshot_key(&site)]) {
        assert!(!storage.exists(&key).await.unwrap(), "left {key}");
    }
}

#[tokio::test]
async fn canonical_snapshot_is_authoritative_over_old_long_layouts() {
    let name = long_name(true);
    for authority in ["fresh", "malformed", "wrong-identity", "unavailable"] {
        let storage = MemoryStorage::default();
        let old = resource(&name, true);
        let fresh = resource(&name, false);
        let canonical = certon::storage::certs_site_prefix("long-ca", &name);
        let key = snapshot_key(&canonical);
        storage
            .store(&snapshot_key(&old_site(&old)), &snapshot(&old))
            .await
            .unwrap();
        legacy(&storage, &old, old_keys(&old)).await;
        let bytes = match authority {
            "malformed" => b"invalid snapshot".to_vec(),
            "wrong-identity" => snapshot(&resource("unrelated.example", true)),
            _ => snapshot(&fresh),
        };
        storage.store(&key, &bytes).await.unwrap();
        if authority == "unavailable" {
            *storage.fail_read.lock().unwrap() = Some(key);
        }
        let before = storage.entries.lock().unwrap().clone();
        let result = clean_storage(&storage, &CleanStorageOptions::default())
            .await
            .unwrap();
        assert_eq!(result.deleted_certs, 0, "{authority}");
        assert_eq!(*storage.entries.lock().unwrap(), before, "{authority}");
    }
}

#[tokio::test]
async fn old_authoritative_snapshot_survives_new_layout_legacy_failure_or_cancellation() {
    for cancellation in [false, true] {
        let storage = Arc::new(MemoryStorage::default());
        let name = long_name(true);
        let authority = resource(&name, true);
        let nonauthoritative = resource(&name, false);
        let old_snapshot = snapshot_key(&old_site(&authority));
        storage
            .store(&old_snapshot, &snapshot(&authority))
            .await
            .unwrap();
        legacy(storage.as_ref(), &authority, old_keys(&authority)).await;
        let new_keys = canonical_keys(&nonauthoritative);
        legacy(storage.as_ref(), &nonauthoritative, new_keys.clone()).await;
        if cancellation {
            *storage.blocked_delete.lock().unwrap() = Some(new_keys[1].clone());
            let task = tokio::spawn({
                let storage = storage.clone();
                async move { clean_storage(storage.as_ref(), &CleanStorageOptions::default()).await }
            });
            tokio::time::timeout(Duration::from_secs(5), storage.delete_entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            *storage.blocked_delete.lock().unwrap() = None;
        } else {
            *storage.fail_delete_once.lock().unwrap() = Some(new_keys[1].clone());
            let first = clean_storage(storage.as_ref(), &CleanStorageOptions::default())
                .await
                .unwrap();
            assert_eq!(first.deleted_certs, 0);
        }
        assert_eq!(
            storage.load(&old_snapshot).await.unwrap(),
            snapshot(&authority)
        );
        let current = certon::storage::load_certificate(storage.as_ref(), "long-ca", &name)
            .await
            .unwrap();
        assert_eq!(
            current.certificate_pem, authority.certificate_pem,
            "old snapshot must remain authoritative"
        );
        let retry = clean_storage(storage.as_ref(), &CleanStorageOptions::default())
            .await
            .unwrap();
        assert_eq!(retry.deleted_certs, 1);
        assert!(storage.entries.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn canonical_snapshot_remains_until_older_snapshot_deletion_succeeds() {
    let storage = MemoryStorage::default();
    let name = long_name(true);
    let current = resource(&name, true);
    let older = resource(&name, false);
    certon::storage::store_certificate(&storage, "long-ca", &current)
        .await
        .unwrap();
    let canonical_snapshot = snapshot_key(&certon::storage::certs_site_prefix("long-ca", &name));
    let old_snapshot = snapshot_key(&old_site(&older));
    storage
        .store(&old_snapshot, &snapshot(&older))
        .await
        .unwrap();
    *storage.fail_delete_once.lock().unwrap() = Some(old_snapshot.clone());
    let first = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(first.deleted_certs, 0);
    assert!(storage.exists(&canonical_snapshot).await.unwrap());
    assert!(storage.exists(&old_snapshot).await.unwrap());
    let second = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(second.deleted_certs, 1);
    assert!(storage.entries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn identityless_hashed_legacy_import_is_conservatively_retained() {
    let storage = MemoryStorage::default();
    let cert = resource(&long_name(true), true);
    legacy(&storage, &cert, canonical_keys(&cert)).await;
    let before = storage.entries.lock().unwrap().clone();
    let result = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(result.deleted_certs, 0);
    assert_eq!(*storage.entries.lock().unwrap(), before);
}

#[tokio::test]
async fn raw_long_certificate_can_retry_after_legacy_sidecars_are_gone() {
    let storage = MemoryStorage::default();
    let cert = resource(&long_name(false), true);
    let keys = old_keys(&cert);
    legacy(&storage, &cert, keys.clone()).await;
    *storage.fail_delete_once.lock().unwrap() = Some(keys[0].clone());
    let first = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(first.deleted_certs, 0);
    assert!(storage.exists(&keys[0]).await.unwrap());
    assert!(!storage.exists(&keys[1]).await.unwrap());
    assert!(!storage.exists(&keys[2]).await.unwrap());
    let second = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(second.deleted_certs, 1);
    assert!(storage.entries.lock().unwrap().is_empty());
}

fn set_modified(path: &std::path::Path, time: std::time::SystemTime) {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_WRITE_ATTRIBUTES and FILE_FLAG_BACKUP_SEMANTICS allow setting
        // directory metadata without opening it for ordinary file writes.
        options.access_mode(0x100).custom_flags(0x0200_0000);
    }
    options
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(time))
        .unwrap();
}

#[tokio::test]
async fn an_old_ocsp_namespace_never_removes_a_fresh_nested_staple() {
    let directory = tempfile::tempdir().unwrap();
    let storage = certon::FileStorage::new(directory.path());
    let name = long_name(true);
    let fresh = certon::storage::ocsp_key(&name, &"a".repeat(64));
    let old = certon::storage::ocsp_key(&name, &"b".repeat(64));
    let namespace = "ocsp/_certon-long-v1";
    assert!(fresh.starts_with(&format!("{namespace}/")));
    storage
        .store(&fresh, b"fresh signed response bytes")
        .await
        .unwrap();
    storage.store(&old, b"old response bytes").await.unwrap();
    let old_time = std::time::SystemTime::now() - Duration::from_secs(30 * 86400);
    set_modified(&directory.path().join(&old), old_time);
    // Updating an existing child does not advance the directory's mtime.
    // Recreate that state after all entry creation has completed.
    set_modified(&directory.path().join(namespace), old_time);
    let listing = storage.list("ocsp", true).await.unwrap();
    assert!(listing.iter().any(|key| key == namespace));
    assert!(listing.contains(&fresh) && listing.contains(&old));
    assert!(!storage.stat(namespace).await.unwrap().is_terminal);
    assert!(storage.stat(&fresh).await.unwrap().is_terminal);
    let result = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(result.deleted_ocsp, 1);
    assert_eq!(
        storage.load(&fresh).await.unwrap(),
        b"fresh signed response bytes"
    );
    assert!(!storage.exists(&old).await.unwrap());
    assert!(storage.exists(namespace).await.unwrap());
}
