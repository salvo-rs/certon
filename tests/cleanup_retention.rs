use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use certon::maintain::{CleanStorageOptions, clean_storage};
use certon::{CertificateResource, FileStorage, KeyInfo, Result, Storage};
use chrono::{DateTime, Utc};

/// Real storage operations, with controllable backend modification timestamps
/// and one cancellable deletion. The wrapper does not reinterpret GC options.
struct TestStorage {
    files: FileStorage,
    modified: HashMap<String, DateTime<Utc>>,
    gated_key: Option<String>,
    block_delete: AtomicBool,
    delete_entered: tokio::sync::Notify,
    delete_release: tokio::sync::Notify,
}

impl TestStorage {
    fn new(path: &std::path::Path) -> Self {
        Self {
            files: FileStorage::new(path),
            modified: HashMap::new(),
            gated_key: None,
            block_delete: AtomicBool::new(false),
            delete_entered: tokio::sync::Notify::new(),
            delete_release: tokio::sync::Notify::new(),
        }
    }
}

#[async_trait::async_trait]
impl Storage for TestStorage {
    async fn store(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.files.store(key, bytes).await
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        self.files.load(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        if self.gated_key.as_deref() == Some(key) && self.block_delete.load(Ordering::SeqCst) {
            self.delete_entered.notify_one();
            self.delete_release.notified().await;
        }
        self.files.delete(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.files.exists(key).await
    }
    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        self.files.list(prefix, recursive).await
    }
    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let mut info = self.files.stat(key).await?;
        if let Some(modified) = self.modified.get(key) {
            info.modified = *modified;
        }
        Ok(info)
    }
    async fn lock(&self, key: &str) -> Result<()> {
        self.files.lock(key).await
    }
    async fn unlock(&self, key: &str) -> Result<()> {
        self.files.unlock(key).await
    }
}

fn resource(name: &str, expiry: DateTime<Utc>) -> CertificateResource {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.not_before = std::time::SystemTime::from(expiry - chrono::Duration::days(90)).into();
    params.not_after = std::time::SystemTime::from(expiry).into();
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    CertificateResource {
        sans: vec![name.into()],
        certificate_pem: certificate.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_key: "retention-ca".into(),
        issuer_data: None,
    }
}

async fn store_resource(storage: &dyn Storage, resource: &CertificateResource, legacy: bool) {
    if legacy {
        let name = &resource.sans[0];
        for (key, value) in [
            (
                certon::storage::site_cert_key("retention-ca", name),
                resource.certificate_pem.clone(),
            ),
            (
                certon::storage::site_private_key("retention-ca", name),
                resource.private_key_pem.clone(),
            ),
            (
                certon::storage::site_meta_key("retention-ca", name),
                serde_json::to_vec(resource).unwrap(),
            ),
        ] {
            storage.store(&key, &value).await.unwrap();
        }
    } else {
        certon::storage::store_certificate(storage, "retention-ca", resource)
            .await
            .unwrap();
    }
}

async fn assert_resource(storage: &dyn Storage, expected: &CertificateResource) {
    let actual = certon::storage::load_certificate(storage, "retention-ca", &expected.sans[0])
        .await
        .unwrap();
    assert_eq!(actual.certificate_pem, expected.certificate_pem);
    assert_eq!(actual.private_key_pem, expected.private_key_pem);
}

#[tokio::test]
async fn maximum_retention_preserves_snapshots_legacy_credentials_and_staples() {
    let directory = tempfile::tempdir().unwrap();
    let mut storage = TestStorage::new(directory.path());
    storage
        .modified
        .insert("ocsp/old".into(), Utc::now() - chrono::Duration::days(30));
    let snapshot = resource("snapshot.example", Utc::now() - chrono::Duration::days(7));
    let legacy = resource("legacy.example", Utc::now() - chrono::Duration::days(7));
    store_resource(&storage, &snapshot, false).await;
    store_resource(&storage, &legacy, true).await;
    storage.store("ocsp/old", b"old staple").await.unwrap();
    let result = clean_storage(
        &storage,
        &CleanStorageOptions {
            expired_cert_grace_period: Duration::MAX,
            ocsp_max_age: Duration::MAX,
        },
    )
    .await
    .unwrap();
    eprintln!(
        "DurationMAX deletion counts: certificates={} OCSP={}",
        result.deleted_certs, result.deleted_ocsp
    );
    assert_eq!(result.deleted_certs, 0);
    assert_eq!(result.deleted_ocsp, 0);
    assert_resource(&storage, &snapshot).await;
    assert_resource(&storage, &legacy).await;
    assert_eq!(storage.load("ocsp/old").await.unwrap(), b"old staple");
}

#[tokio::test]
async fn chrono_representable_certificate_grace_beyond_datetime_range_is_retained() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(TestStorage::new(directory.path()));
    let cert = resource("overflow.example", Utc::now() - chrono::Duration::days(7));
    store_resource(storage.as_ref(), &cert, false).await;
    let grace = Duration::from_secs(10_000_000_000_000);
    assert!(chrono::Duration::from_std(grace).is_ok());
    let task = tokio::spawn({
        let storage = storage.clone();
        async move {
            clean_storage(
                storage.as_ref(),
                &CleanStorageOptions {
                    expired_cert_grace_period: grace,
                    ..Default::default()
                },
            )
            .await
        }
    });
    let result = task
        .await
        .expect("representable duration must not cause timestamp arithmetic to panic")
        .unwrap();
    assert_eq!(result.deleted_certs, 0);
    assert_resource(storage.as_ref(), &cert).await;
}

#[tokio::test]
async fn ocsp_modification_timestamp_overflow_is_retained() {
    let directory = tempfile::tempdir().unwrap();
    let mut storage = TestStorage::new(directory.path());
    // Custom storage timestamps need not be representable by the platform's
    // filesystem clock. This is a valid public KeyInfo timestamp.
    storage.modified.insert(
        "ocsp/future".into(),
        DateTime::<Utc>::MAX_UTC - chrono::Duration::days(1),
    );
    storage.store("ocsp/future", b"keep").await.unwrap();
    let result = clean_storage(
        &storage,
        &CleanStorageOptions {
            ocsp_max_age: Duration::from_secs(2 * 86400),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(result.deleted_ocsp, 0);
    assert_eq!(storage.load("ocsp/future").await.unwrap(), b"keep");
}

#[tokio::test]
async fn default_finite_and_zero_retention_still_collect_only_eligible_resources() {
    for options in [
        CleanStorageOptions::default(),
        CleanStorageOptions {
            expired_cert_grace_period: Duration::from_secs(3600),
            ocsp_max_age: Duration::from_secs(7200),
        },
        CleanStorageOptions {
            expired_cert_grace_period: Duration::ZERO,
            ocsp_max_age: Duration::ZERO,
        },
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut storage = TestStorage::new(directory.path());
        let now = Utc::now();
        let grace = chrono::Duration::from_std(options.expired_cert_grace_period).unwrap();
        let age = chrono::Duration::from_std(options.ocsp_max_age).unwrap();
        storage.modified.insert(
            "ocsp/eligible".into(),
            now - age - chrono::Duration::days(1),
        );
        storage.modified.insert(
            "ocsp/retained".into(),
            now - age + chrono::Duration::hours(1),
        );
        storage.store("ocsp/eligible", b"delete").await.unwrap();
        storage.store("ocsp/retained", b"keep").await.unwrap();
        let mut retained = Vec::new();
        for legacy in [false, true] {
            let suffix = if legacy { "legacy" } else { "snapshot" };
            let expired = resource(
                &format!("eligible-{suffix}.example"),
                now - grace - chrono::Duration::days(1),
            );
            let recent = resource(
                &format!("retained-{suffix}.example"),
                now - grace + chrono::Duration::hours(1),
            );
            store_resource(&storage, &expired, legacy).await;
            store_resource(&storage, &recent, legacy).await;
            retained.push(recent);
        }
        let result = clean_storage(&storage, &options).await.unwrap();
        assert_eq!(result.deleted_certs, 2, "{options:?}");
        assert_eq!(result.deleted_ocsp, 1, "{options:?}");
        for cert in retained {
            assert_resource(&storage, &cert).await;
        }
        assert_eq!(storage.load("ocsp/retained").await.unwrap(), b"keep");
    }
}

#[tokio::test]
async fn malformed_snapshot_and_certificate_expiry_are_not_deletion_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let storage = TestStorage::new(directory.path());
    let cert = resource(
        "broken-snapshot.example",
        Utc::now() - chrono::Duration::days(7),
    );
    store_resource(&storage, &cert, true).await;
    let snapshot = "certificates/retention-ca/broken-snapshot.example/_certon/resource.v1.key";
    storage
        .store(snapshot, b"malformed snapshot")
        .await
        .unwrap();
    let mut bad_pem = resource("broken-pem.example", Utc::now() - chrono::Duration::days(7));
    bad_pem.certificate_pem = b"not a certificate".to_vec();
    store_resource(&storage, &bad_pem, false).await;
    let result = clean_storage(
        &storage,
        &CleanStorageOptions {
            expired_cert_grace_period: Duration::ZERO,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(result.deleted_certs, 0);
    assert_eq!(storage.load(snapshot).await.unwrap(), b"malformed snapshot");
    assert_eq!(
        storage
            .load(&certon::storage::site_cert_key(
                "retention-ca",
                &cert.sans[0]
            ))
            .await
            .unwrap(),
        cert.certificate_pem
    );
    assert_resource(&storage, &bad_pem).await;
}

#[tokio::test]
async fn cancelling_an_eligible_cleanup_keeps_expiry_evidence_for_retry() {
    let directory = tempfile::tempdir().unwrap();
    let mut storage = TestStorage::new(directory.path());
    let cert = resource("cancel.example", Utc::now() - chrono::Duration::days(7));
    storage.gated_key = Some(certon::storage::site_private_key(
        "retention-ca",
        &cert.sans[0],
    ));
    storage.block_delete.store(true, Ordering::SeqCst);
    let storage = Arc::new(storage);
    store_resource(storage.as_ref(), &cert, true).await;
    let cleanup = tokio::spawn({
        let storage = storage.clone();
        async move { clean_storage(storage.as_ref(), &CleanStorageOptions::default()).await }
    });
    tokio::time::timeout(Duration::from_secs(5), storage.delete_entered.notified())
        .await
        .unwrap();
    cleanup.abort();
    assert!(cleanup.await.unwrap_err().is_cancelled());
    assert_resource(storage.as_ref(), &cert).await;
    storage.block_delete.store(false, Ordering::SeqCst);
    let result = clean_storage(storage.as_ref(), &CleanStorageOptions::default())
        .await
        .unwrap();
    assert_eq!(result.deleted_certs, 1);
    assert!(
        !storage
            .exists(&certon::storage::site_cert_key(
                "retention-ca",
                &cert.sans[0]
            ))
            .await
            .unwrap()
    );
}
