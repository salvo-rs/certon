use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, mpsc};
use std::time::Duration;

use super::{FileStorage, Storage};
use crate::{CertStore, CertificateResource, KeyValueCertStore};

const DOMAIN: &str = "commit-order.example.com";
const ISSUER: &str = "commit-order-ca";
const LOCK: &str = "issue_cert_commit-order.example.com";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Stage {
    BeforeRename,
    AfterRename,
}

type Gate = (mpsc::Sender<()>, mpsc::Receiver<()>);
static GATES: LazyLock<Mutex<HashMap<(PathBuf, Stage), Gate>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn pause_commit(destination: &Path, stage: Stage) {
    let gate = GATES
        .lock()
        .unwrap()
        .remove(&(destination.to_owned(), stage));
    if let Some((entered, release)) = gate {
        let _ = entered.send(());
        release.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}

struct Release(Option<mpsc::Sender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

fn gate(destination: PathBuf, stage: Stage) -> (mpsc::Receiver<()>, Release) {
    let (entered, receive) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    GATES
        .lock()
        .unwrap()
        .insert((destination, stage), (entered, wait));
    (receive, Release(Some(release)))
}

fn resource() -> CertificateResource {
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec![DOMAIN.into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    CertificateResource {
        sans: vec![DOMAIN.into()],
        certificate_pem: certificate.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        issuer_data: None,
        issuer_key: ISSUER.into(),
    }
}

async fn cancelled_writer(
    first: Arc<FileStorage>,
    destination: PathBuf,
    stage: Stage,
) -> (Release, CertificateResource) {
    let a = resource();
    let (entered, release) = gate(destination, stage);
    let writer = tokio::spawn({
        let first = first.clone();
        let a = a.clone();
        async move {
            let _lock = crate::storage::acquire(first.clone(), LOCK).await.unwrap();
            KeyValueCertStore::new(first)
                .save(ISSUER, &a)
                .await
                .unwrap();
        }
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let observer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(first.lock_filename(LOCK))
        .unwrap();
    assert!(matches!(
        observer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    tokio::time::timeout(
        Duration::from_secs(1),
        first.store("independent-before-cancel", b"ok"),
    )
    .await
    .unwrap()
    .unwrap();
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), async {
        while first.held_locks.lock().await.contains_key(LOCK) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Awaiting unlock can complete with a write lease still outstanding.
    first.unlock(LOCK).await.unwrap();
    (release, a)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_commit_keeps_successor_writes_and_deletes_after_its_commit() {
    for stage in [Stage::BeforeRename, Stage::AfterRename] {
        for delete in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let first = Arc::new(FileStorage::new(directory.path()));
            let second: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
            let initial = resource();
            KeyValueCertStore::new(first.clone())
                .save(ISSUER, &initial)
                .await
                .unwrap();
            let destination = directory
                .path()
                .join(crate::storage::site_snapshot_key(ISSUER, DOMAIN));
            let (release, _) = cancelled_writer(first.clone(), destination, stage).await;
            assert!(
                crate::storage::try_acquire(second.clone(), LOCK, Duration::from_millis(50))
                    .await
                    .unwrap()
                    .is_none()
            );
            // Keeping lock handles alive must not serialize unrelated writes or
            // require a blocking worker to wait for another blocking worker.
            tokio::time::timeout(Duration::from_secs(1), first.store("independent", b"ok"))
                .await
                .unwrap()
                .unwrap();
            let b = resource();
            let expected = b.certificate_pem.clone();
            let mut successor = tokio::spawn({
                let second = second.clone();
                async move {
                    let _lock = crate::storage::acquire(second.clone(), LOCK).await.unwrap();
                    let store = KeyValueCertStore::new(second);
                    if delete {
                        store.remove(ISSUER, DOMAIN).await
                    } else {
                        store.save(ISSUER, &b).await
                    }
                }
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut successor)
                    .await
                    .is_err()
            );
            drop(release);
            tokio::time::timeout(Duration::from_secs(2), successor)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let observed = KeyValueCertStore::new(second)
                .load(ISSUER, DOMAIN)
                .await
                .unwrap();
            if delete {
                assert!(observed.is_none());
            } else {
                assert_eq!(observed.unwrap().certificate_pem, expected);
            }
            assert!(
                !std::fs::read_dir(
                    directory
                        .path()
                        .join(crate::storage::certs_site_prefix(ISSUER, DOMAIN))
                        .join("_certon")
                )
                .into_iter()
                .flatten()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".certon-write-"))
            );
        }
    }
}

#[test]
fn runtime_shutdown_keeps_a_submitted_commit_locked() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let first = Arc::new(FileStorage::new(directory.path()));
    let destination = directory
        .path()
        .join(crate::storage::site_snapshot_key(ISSUER, DOMAIN));
    let (entered, release) = gate(destination, Stage::BeforeRename);
    runtime.spawn(async move {
        let _lock = crate::storage::acquire(first.clone(), LOCK).await.unwrap();
        KeyValueCertStore::new(first)
            .save(ISSUER, &resource())
            .await
            .unwrap();
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    runtime.shutdown_background();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let second: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
        assert!(
            crate::storage::try_acquire(second.clone(), LOCK, Duration::from_millis(100))
                .await
                .unwrap()
                .is_none()
        );
        drop(release);
        let guard = crate::storage::try_acquire(second.clone(), LOCK, Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap();
        let b = resource();
        KeyValueCertStore::new(second.clone())
            .save(ISSUER, &b)
            .await
            .unwrap();
        assert_eq!(
            KeyValueCertStore::new(second)
                .load(ISSUER, DOMAIN)
                .await
                .unwrap()
                .unwrap()
                .certificate_pem,
            b.certificate_pem
        );
        guard.release().await.unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_failed_rename_releases_its_lock_and_temporary_file() {
    let directory = tempfile::tempdir().unwrap();
    let first = Arc::new(FileStorage::new(directory.path()));
    let second: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let destination = directory
        .path()
        .join(crate::storage::site_snapshot_key(ISSUER, DOMAIN));
    let (release, _) = cancelled_writer(first, destination.clone(), Stage::BeforeRename).await;
    std::fs::create_dir(&destination).unwrap();
    assert!(
        crate::storage::try_acquire(second.clone(), LOCK, Duration::from_millis(50))
            .await
            .unwrap()
            .is_none()
    );
    drop(release);
    let guard = crate::storage::try_acquire(second, LOCK, Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();
    assert!(destination.is_dir());
    assert_eq!(
        std::fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .count(),
        1
    );
    guard.release().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_marker_still_blocks_a_completed_cancelled_commit() {
    struct Issuer;
    #[async_trait::async_trait]
    impl crate::CertIssuer for Issuer {
        fn issuer_key(&self) -> String {
            ISSUER.into()
        }
        async fn issue(&self, _: &[u8], _: &[String]) -> crate::Result<crate::IssuedCertificate> {
            panic!("the regression never requests issuance")
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let first = Arc::new(FileStorage::new(directory.path()));
    let second: Arc<dyn Storage> = Arc::new(FileStorage::new(directory.path()));
    let destination = directory
        .path()
        .join(crate::storage::site_snapshot_key(ISSUER, DOMAIN));
    let (release, a) = cancelled_writer(first, destination, Stage::AfterRename).await;
    let leaf = crate::storage::resource_leaf_hash(&a).unwrap();
    crate::storage::store_revocation(second.as_ref(), &leaf, true)
        .await
        .unwrap();
    drop(release);
    let guard = crate::storage::try_acquire(second.clone(), LOCK, Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();
    let manager = crate::CertManager::builder()
        .storage(second)
        .issuers(vec![Arc::new(Issuer)])
        .build();
    assert!(matches!(
        manager.cache_certificate(DOMAIN).await,
        Err(crate::Error::Cert(crate::error::CertError::Revoked(_)))
    ));
    guard.release().await.unwrap();
}

#[test]
fn failed_temporary_writes_release_leases_after_cleanup() {
    for panic in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock");
        let owner = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        owner.try_lock().unwrap();
        let observer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let temporary = directory.path().join("temporary");
        let result = std::panic::catch_unwind(|| {
            super::TemporaryWrite::write_with_locks(
                temporary.clone(),
                0o600,
                vec![Arc::new(owner)],
                |file| {
                    use std::io::Write;
                    file.write_all(b"partial")?;
                    assert!(matches!(
                        observer.try_lock(),
                        Err(std::fs::TryLockError::WouldBlock)
                    ));
                    if panic {
                        panic!("injected leased writer failure");
                    }
                    Err(std::io::Error::other("injected leased writer failure"))
                },
            )
        });
        if panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!temporary.exists());
        observer.try_lock().unwrap();
    }
}
