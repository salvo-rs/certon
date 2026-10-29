use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use certon::error::StorageError;
use certon::maintain::{CleanStorageOptions, clean_storage};
use certon::{CertificateResource, KeyInfo, Result, Storage};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Entry {
    bytes: Vec<u8>,
    modified: DateTime<Utc>,
}

#[derive(Default)]
struct MemoryStorage {
    entries: Mutex<BTreeMap<String, Entry>>,
    failed_deletes: Mutex<HashSet<String>>,
    failed_loads: Mutex<HashSet<String>>,
    fail_ari_list: AtomicBool,
    delete_attempts: Mutex<HashMap<String, usize>>,
}

impl MemoryStorage {
    fn insert(&self, key: impl Into<String>, bytes: Vec<u8>, modified: DateTime<Utc>) {
        self.entries
            .lock()
            .unwrap()
            .insert(key.into(), Entry { bytes, modified });
    }

    async fn put_record(&self, issuer: &str, label: &str, expiry: Option<DateTime<Utc>>) -> String {
        let leaf = digest(label);
        let key = ari_key(issuer, &leaf);
        self.store(
            &key,
            &serde_json::to_vec(&record(issuer, &leaf, expiry)).unwrap(),
        )
        .await
        .unwrap();
        key
    }

    fn attempts(&self, key: &str) -> usize {
        self.delete_attempts
            .lock()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or_default()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.insert(key, bytes.to_vec(), Utc::now());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        if self.failed_loads.lock().unwrap().contains(key) {
            return Err(StorageError::Deserialize("injected read failure".into()).into());
        }
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .map(|entry| entry.bytes.clone())
            .ok_or_else(|| StorageError::NotFound(key.to_owned()).into())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        *self
            .delete_attempts
            .lock()
            .unwrap()
            .entry(key.to_owned())
            .or_default() += 1;
        if self.failed_deletes.lock().unwrap().contains(key) {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected delete failure",
            ))
            .into());
        }
        let prefix = format!("{key}/");
        self.entries
            .lock()
            .unwrap()
            .retain(|candidate, _| candidate != key && !candidate.starts_with(&prefix));
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let prefix = format!("{key}/");
        Ok(self
            .entries
            .lock()
            .unwrap()
            .keys()
            .any(|candidate| candidate == key || candidate.starts_with(&prefix)))
    }

    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        if path == "ari" && self.fail_ari_list.load(Ordering::SeqCst) {
            return Err(StorageError::Deserialize("injected ARI listing failure".into()).into());
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let mut keys = BTreeSet::new();
        for key in self.entries.lock().unwrap().keys() {
            if let Some(suffix) = key.strip_prefix(&prefix) {
                let suffix = if recursive {
                    suffix
                } else {
                    suffix.split('/').next().unwrap()
                };
                keys.insert(format!("{prefix}{suffix}"));
            }
        }
        Ok(keys.into_iter().collect())
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .map(|entry| KeyInfo {
                key: key.to_owned(),
                modified: entry.modified,
                size: entry.bytes.len() as u64,
                is_terminal: true,
            })
            .ok_or_else(|| StorageError::NotFound(key.to_owned()).into())
    }

    async fn lock(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn unlock(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ari_key(issuer: &str, leaf: &str) -> String {
    format!("ari/{}/{leaf}/state.json", digest(issuer))
}

fn record(issuer: &str, leaf: &str, expiry: Option<DateTime<Utc>>) -> Value {
    let mut value = json!({
        "version": 1, "issuer": issuer, "leaf": leaf, "info": null,
        "selected_time": null, "next_check": Utc::now() + chrono::Duration::hours(6), "failures": 0,
    });
    if let Some(expiry) = expiry {
        value["leaf_not_after"] = json!(expiry);
    }
    value
}

#[tokio::test]
async fn expired_orphan_ari_is_collected_without_polluting_certificate_or_ocsp_counts() {
    let storage = MemoryStorage::default();
    let now = Utc::now();
    let orphan_a = storage
        .put_record(
            "historic-ca-a",
            "old-leaf-a",
            Some(now - chrono::Duration::days(3)),
        )
        .await;
    let orphan_b = storage
        .put_record(
            "historic-ca-b",
            "old-leaf-b",
            Some(now - chrono::Duration::days(100)),
        )
        .await;
    // Neither ARI identity has a corresponding certificate resource. A separate
    // expired resource still exercises the existing public deletion counter.
    let mut params = rcgen::CertificateParams::new(vec!["expired.example".into()]).unwrap();
    params.not_before = (std::time::SystemTime::now() - Duration::from_secs(7 * 86400)).into();
    params.not_after = (std::time::SystemTime::now() - Duration::from_secs(3 * 86400)).into();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let resource = CertificateResource {
        sans: vec!["expired.example".into()],
        issuer_key: "unrelated-ca".into(),
        issuer_data: None,
        certificate_pem: cert.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
    };
    certon::storage::store_certificate(&storage, "unrelated-ca", &resource)
        .await
        .unwrap();
    storage.insert("ocsp/old", vec![1], now - chrono::Duration::days(30));
    storage.insert("ocsp/current", vec![2], now);
    storage
        .store("acme/account.json", b"keep-account")
        .await
        .unwrap();

    let result = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert!(
        !storage.exists(&orphan_a).await.unwrap(),
        "expired historical ARI must not require a live certificate to be reclaimed"
    );
    assert!(!storage.exists(&orphan_b).await.unwrap());
    assert_eq!(result.deleted_certs, 1);
    assert_eq!(result.deleted_ocsp, 1);
    assert!(matches!(
        certon::storage::load_certificate(&storage, "unrelated-ca", "expired.example").await,
        Err(certon::Error::Storage(StorageError::NotFound(_)))
    ));
    assert_eq!(storage.load("ocsp/current").await.unwrap(), vec![2]);
    assert_eq!(
        storage.load("acme/account.json").await.unwrap(),
        b"keep-account"
    );
}

#[tokio::test]
async fn live_uncertain_and_noncanonical_ari_records_are_retained_verbatim() {
    let storage = MemoryStorage::default();
    let now = Utc::now();
    let issuer = "retained-ca";
    let expired = Some(now - chrono::Duration::days(3));
    let mut retained = Vec::new();
    for (label, expiry) in [
        ("live", Some(now + chrono::Duration::days(2))),
        ("within-grace", Some(now - chrono::Duration::hours(12))),
        ("legacy-missing-expiry", None),
        ("date-addition-overflow", Some(DateTime::<Utc>::MAX_UTC)),
    ] {
        let leaf = digest(label);
        retained.push((
            ari_key(issuer, &leaf),
            serde_json::to_vec(&record(issuer, &leaf, expiry)).unwrap(),
        ));
    }
    // MAX_UTC is a valid serialized timestamp, not merely malformed input.
    assert_eq!(
        serde_json::from_value::<DateTime<Utc>>(json!(DateTime::<Utc>::MAX_UTC)).unwrap(),
        DateTime::<Utc>::MAX_UTC
    );
    for label in [
        "null-expiry",
        "invalid-expiry",
        "future-version",
        "different-issuer",
        "different-leaf",
    ] {
        let leaf = digest(label);
        let mut value = record(issuer, &leaf, expired);
        match label {
            "null-expiry" => value["leaf_not_after"] = Value::Null,
            "invalid-expiry" => value["leaf_not_after"] = json!("not-a-date"),
            "future-version" => value["version"] = json!(2),
            "different-issuer" => value["issuer"] = json!("another-issuer"),
            "different-leaf" => value["leaf"] = json!(digest("other-leaf")),
            _ => unreachable!(),
        }
        retained.push((ari_key(issuer, &leaf), serde_json::to_vec(&value).unwrap()));
    }
    let leaf = digest("path-controls");
    let valid_payload = serde_json::to_vec(&record(issuer, &leaf, expired)).unwrap();
    retained.extend([
        (
            ari_key(issuer, &digest("malformed-json")),
            b"{invalid json".to_vec(),
        ),
        (
            format!("ari/{}/not-a-leaf/state.json", digest(issuer)),
            valid_payload.clone(),
        ),
        (
            ari_key(issuer, &leaf.to_uppercase()),
            serde_json::to_vec(&record(issuer, &leaf.to_uppercase(), expired)).unwrap(),
        ),
        (
            format!("ari/{}/{leaf}/history/state.json", digest(issuer)),
            valid_payload.clone(),
        ),
        (
            format!("ari/{}/{leaf}/state.json.backup", digest(issuer)),
            valid_payload.clone(),
        ),
        (
            format!("ari-backup/{}/{leaf}/state.json", digest(issuer)),
            valid_payload,
        ),
    ]);
    for (key, bytes) in &retained {
        storage.store(key, bytes).await.unwrap();
    }

    let result = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(result.deleted_certs, 0);
    assert_eq!(result.deleted_ocsp, 0);
    for (key, bytes) in retained {
        assert_eq!(
            storage.load(&key).await.unwrap(),
            bytes,
            "conservative retention changed {key}"
        );
        assert_eq!(
            storage.attempts(&key),
            0,
            "retained records must not be offered for deletion: {key}"
        );
    }
}

#[tokio::test]
async fn overflowing_grace_retains_history_and_zero_grace_reclaims_it() {
    let storage = MemoryStorage::default();
    let key = storage
        .put_record(
            "grace-ca",
            "expired",
            Some(Utc::now() - chrono::Duration::hours(12)),
        )
        .await;
    let result = clean_storage(
        &storage,
        &CleanStorageOptions {
            expired_cert_grace_period: Duration::MAX,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(storage.exists(&key).await.unwrap());
    assert_eq!((result.deleted_certs, result.deleted_ocsp), (0, 0));
    assert_eq!(storage.attempts(&key), 0);

    clean_storage(
        &storage,
        &CleanStorageOptions {
            expired_cert_grace_period: Duration::ZERO,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        !storage.exists(&key).await.unwrap(),
        "the existing grace option must apply to ARI too"
    );
}

#[tokio::test]
async fn failed_ari_deletion_retries_without_blocking_other_cleanup() {
    let storage = MemoryStorage::default();
    let expired = Some(Utc::now() - chrono::Duration::days(3));
    let failed = storage
        .put_record("retry-ca", "delete-fails-once", expired)
        .await;
    let other = storage
        .put_record("retry-ca", "independent-history", expired)
        .await;
    storage
        .failed_deletes
        .lock()
        .unwrap()
        .insert(failed.clone());
    storage.insert("ocsp/old", vec![1], Utc::now() - chrono::Duration::days(30));

    let first = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert!(storage.exists(&failed).await.unwrap());
    assert!(!storage.exists(&other).await.unwrap());
    assert_eq!(storage.attempts(&failed), 1);
    assert_eq!((first.deleted_certs, first.deleted_ocsp), (0, 1));
    storage.failed_deletes.lock().unwrap().clear();
    let second = clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert!(!storage.exists(&failed).await.unwrap());
    assert_eq!(storage.attempts(&failed), 2);
    assert_eq!((second.deleted_certs, second.deleted_ocsp), (0, 0));
}

#[tokio::test]
async fn ari_list_and_read_faults_preserve_records_until_a_later_successful_run() {
    let storage = MemoryStorage::default();
    let key = storage
        .put_record(
            "fault-ca",
            "read-fails-once",
            Some(Utc::now() - chrono::Duration::days(3)),
        )
        .await;
    storage.fail_ari_list.store(true, Ordering::SeqCst);
    clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(storage.attempts(&key), 0);
    storage.fail_ari_list.store(false, Ordering::SeqCst);
    storage.failed_loads.lock().unwrap().insert(key.clone());
    clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(storage.attempts(&key), 0);
    assert!(storage.exists(&key).await.unwrap());
    storage.failed_loads.lock().unwrap().clear();
    clean_storage(&storage, &CleanStorageOptions::default())
        .await
        .unwrap();
    assert!(!storage.exists(&key).await.unwrap());
    assert_eq!(storage.attempts(&key), 1);
}
