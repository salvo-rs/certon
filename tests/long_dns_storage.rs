use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use certon::error::StorageError;
use certon::storage::{
    CertificateResource, KeyInfo, certs_site_prefix, load_certificate, safe_key, site_cert_key,
    site_meta_key, site_private_key, store_certificate,
};
use certon::{CertStore, Error, FileStorage, KeyValueCertStore, Result, Storage};

#[derive(Default)]
struct Memory {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_load: Mutex<Option<String>>,
    block_delete: Mutex<Option<(String, bool)>>,
    entered: tokio::sync::Notify,
}
#[async_trait]
impl Storage for Memory {
    async fn store(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.values.lock().unwrap().insert(key.into(), bytes.into());
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if self.fail_load.lock().unwrap().as_deref() == Some(key) {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "load denied",
            ))
            .into());
        }
        self.values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.into()).into())
    }
    async fn delete(&self, key: &str) -> Result<()> {
        let mode = self
            .block_delete
            .lock()
            .unwrap()
            .clone()
            .filter(|(blocked, _)| blocked == key);
        if let Some((_, pause)) = mode {
            self.entered.notify_one();
            if pause {
                std::future::pending::<()>().await;
            }
            return Err(StorageError::Io(std::io::Error::other("delete denied")).into());
        }
        self.values.lock().unwrap().remove(key);
        Ok(())
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.values.lock().unwrap().contains_key(key))
    }
    async fn list(&self, prefix: &str, _: bool) -> Result<Vec<String>> {
        Ok(self
            .values
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    async fn stat(&self, _: &str) -> Result<KeyInfo> {
        unreachable!()
    }
    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}
fn name(wildcard: bool) -> String {
    let prefix = if wildcard { "*." } else { "" };
    let name = format!(
        "{prefix}{}.{}.{}.{}.example.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(253 - prefix.len() - 12 - 3 * 63 - 3)
    );
    assert_eq!(name.len(), 253);
    name
}
fn resource(name: &str, generation: u8) -> CertificateResource {
    CertificateResource {
        sans: vec![name.into()],
        certificate_pem: vec![generation; 16],
        private_key_pem: vec![generation; 32],
        issuer_key: "ca".into(),
        issuer_data: None,
    }
}
fn snapshot(site: &str) -> String {
    format!("{site}/_certon/resource.v1.key")
}
fn raw_site(name: &str) -> String {
    format!("certificates/ca/{}", safe_key(name))
}
async fn legacy(
    memory: &Memory,
    site: &str,
    name: &str,
    old: bool,
    resource: &CertificateResource,
) {
    let keys = if old {
        ["crt", "key", "json"].map(|ext| format!("{site}/{}.{ext}", safe_key(name)))
    } else {
        [
            site_cert_key("ca", name),
            site_private_key("ca", name),
            site_meta_key("ca", name),
        ]
    };
    for (key, bytes) in keys.into_iter().zip([
        resource.certificate_pem.clone(),
        resource.private_key_pem.clone(),
        serde_json::to_vec(resource).unwrap(),
    ]) {
        memory.store(&key, &bytes).await.unwrap();
    }
}

#[test]
fn long_derived_keys_are_bounded_distinct_and_ordinary_paths_unchanged() {
    assert_eq!(
        site_meta_key("ca", "example.com"),
        "certificates/ca/example.com/example.com.json"
    );
    for domain in [name(false), name(true), "x".repeat(250), "x".repeat(251)] {
        for key in [
            site_cert_key("ca", &domain),
            site_private_key("ca", &domain),
            site_meta_key("ca", &domain),
            certon::storage::ocsp_key(&domain, &"a".repeat(64)),
        ] {
            assert!(key.split('/').all(|part| part.len() <= 255), "{key}");
        }
    }
    assert_ne!(
        certs_site_prefix("ca", &name(true)),
        certs_site_prefix("ca", &name(true).replace('a', "b"))
    );
    let derived = certs_site_prefix("ca", &name(true));
    let token = derived.rsplit('/').next().unwrap();
    assert_ne!(derived, certs_site_prefix("ca", token));
}

#[tokio::test]
async fn old_long_snapshots_and_legacy_assets_remain_readable_on_generic_backends() {
    for wildcard in [false, true] {
        let name = name(wildcard);
        let old = resource(&name, 1);
        let memory = Memory::default();
        store_certificate(&memory, "ca", &old).await.unwrap();
        let new_key = snapshot(&certs_site_prefix("ca", &name));
        let bytes = memory.load(&new_key).await.unwrap();
        memory.delete(&new_key).await.unwrap();
        memory
            .store(&snapshot(&raw_site(&name)), &bytes)
            .await
            .unwrap();
        assert_eq!(
            load_certificate(&memory, "ca", &name)
                .await
                .unwrap()
                .certificate_pem,
            old.certificate_pem
        );
        memory.values.lock().unwrap().clear();
        legacy(&memory, &raw_site(&name), &name, true, &old).await;
        assert_eq!(
            KeyValueCertStore::new(Arc::new(memory))
                .load("ca", &name)
                .await
                .unwrap()
                .unwrap()
                .private_key_pem,
            old.private_key_pem
        );
    }
}

#[tokio::test]
async fn canonical_snapshot_errors_and_partial_legacy_never_resurrect_an_older_generation() {
    let name = name(true);
    let old = resource(&name, 1);
    let new = resource(&name, 2);
    let memory = Arc::new(Memory::default());
    store_certificate(memory.as_ref(), "ca", &old)
        .await
        .unwrap();
    let canonical = snapshot(&certs_site_prefix("ca", &name));
    let old_key = snapshot(&raw_site(&name));
    memory
        .store(&old_key, &memory.load(&canonical).await.unwrap())
        .await
        .unwrap();
    store_certificate(memory.as_ref(), "ca", &new)
        .await
        .unwrap();
    assert_eq!(
        load_certificate(memory.as_ref(), "ca", &name)
            .await
            .unwrap()
            .certificate_pem,
        new.certificate_pem
    );
    memory.store(&canonical, b"bad snapshot").await.unwrap();
    assert!(matches!(
        load_certificate(memory.as_ref(), "ca", &name).await,
        Err(Error::Storage(StorageError::Deserialize(_)))
    ));
    *memory.fail_load.lock().unwrap() = Some(canonical.clone());
    assert!(matches!(
        load_certificate(memory.as_ref(), "ca", &name).await,
        Err(Error::Storage(StorageError::Io(_)))
    ));
    *memory.fail_load.lock().unwrap() = None;
    memory.values.lock().unwrap().clear();
    memory
        .store(
            &format!("{}/{}.crt", raw_site(&name), safe_key(&name)),
            b"partial",
        )
        .await
        .unwrap();
    assert!(matches!(
        KeyValueCertStore::new(memory).load("ca", &name).await,
        Err(Error::Storage(StorageError::Deserialize(_)))
    ));
}

#[tokio::test]
async fn removal_failure_or_cancellation_keeps_the_authoritative_old_layout_snapshot() {
    for pause in [false, true] {
        let name = name(true);
        let old = resource(&name, 1);
        let stale = resource(&name, 2);
        let memory = Arc::new(Memory::default());
        store_certificate(memory.as_ref(), "ca", &old)
            .await
            .unwrap();
        let canonical = snapshot(&certs_site_prefix("ca", &name));
        let bytes = memory.load(&canonical).await.unwrap();
        memory.delete(&canonical).await.unwrap();
        memory
            .store(&snapshot(&raw_site(&name)), &bytes)
            .await
            .unwrap();
        legacy(
            memory.as_ref(),
            &certs_site_prefix("ca", &name),
            &name,
            false,
            &stale,
        )
        .await;
        *memory.block_delete.lock().unwrap() = Some((site_cert_key("ca", &name), pause));
        let store = KeyValueCertStore::new(memory.clone());
        let remove_name = name.clone();
        let task = tokio::spawn(async move { store.remove("ca", &remove_name).await });
        if pause {
            tokio::time::timeout(Duration::from_secs(5), memory.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(
            load_certificate(memory.as_ref(), "ca", &name)
                .await
                .unwrap()
                .certificate_pem,
            old.certificate_pem
        );
        *memory.block_delete.lock().unwrap() = None;
        let store = KeyValueCertStore::new(memory.clone());
        store.remove("ca", &name).await.unwrap();
        assert!(store.load("ca", &name).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn file_storage_missing_old_long_keys_and_long_lock_exclusion() {
    let directory = tempfile::tempdir().unwrap();
    let first = FileStorage::new(directory.path());
    let second = FileStorage::new(directory.path());
    let impossible = format!("legacy/{}.json", name(false));
    assert!(matches!(
        first.load(&impossible).await,
        Err(Error::Storage(StorageError::NotFound(_)))
    ));
    assert!(!first.exists(&impossible).await.unwrap());
    first.delete(&impossible).await.unwrap();
    assert!(matches!(
        first.stat(&impossible).await,
        Err(Error::Storage(StorageError::NotFound(_)))
    ));
    assert!(first.store(&impossible, b"cannot fit").await.is_err());
    for lock in [
        "issue_cert_example.com".to_owned(),
        format!("issue_cert_{}", name(false)),
        format!("issue_cert_{}", name(true)),
    ] {
        first.lock(&lock).await.unwrap();
        assert!(
            !second
                .try_lock(&lock, Duration::from_millis(100))
                .await
                .unwrap()
        );
        first.unlock(&lock).await.unwrap();
        second.lock(&lock).await.unwrap();
        second.unlock(&lock).await.unwrap();
    }
}

#[tokio::test]
async fn bounded_long_legacy_assets_can_be_loaded_and_removed_on_file_storage() {
    for name in ["example.com".into(), name(false), name(true)] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let resource = resource(&name, 3);
        for (key, bytes) in [
            site_cert_key("ca", &name),
            site_private_key("ca", &name),
            site_meta_key("ca", &name),
        ]
        .into_iter()
        .zip([
            resource.certificate_pem.clone(),
            resource.private_key_pem.clone(),
            serde_json::to_vec(&resource).unwrap(),
        ]) {
            storage.store(&key, &bytes).await.unwrap();
        }
        let store = KeyValueCertStore::new(storage);
        let loaded = store.load("ca", &name).await.unwrap().unwrap();
        assert_eq!(loaded.certificate_pem, resource.certificate_pem);
        assert_eq!(loaded.private_key_pem, resource.private_key_pem);
        store.remove("ca", &name).await.unwrap();
        assert!(store.load("ca", &name).await.unwrap().is_none());
    }
}
