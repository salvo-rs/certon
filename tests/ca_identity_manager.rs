use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use certon::{
    CertIssuer, CertManager, CertStore, CertificateResource, FileStorage, IssuedCertificate,
    KeyValueCertStore, OcspConfig, Storage,
};
use x509_parser::prelude::FromDer;

const CA: &str = "https://ca.example:8443/directory?tenant=one";
const NAME: &str = "isolation.example";

struct Issuer {
    calls: AtomicUsize,
    ari_calls: AtomicUsize,
    ari_changed: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl CertIssuer for Issuer {
    async fn issue(&self, _: &[u8], _: &[String]) -> certon::Result<IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(certon::Error::Other("unexpected new issuance".into()))
    }
    fn issuer_key(&self) -> String {
        certon::storage::issuer_key(CA)
    }
    async fn renewal_info(&self, _: &[u8]) -> certon::Result<Option<certon::RenewalInfo>> {
        self.ari_calls.fetch_add(1, Ordering::SeqCst);
        self.ari_changed.notify_one();
        Ok(None)
    }
    fn legacy_issuer_key(&self) -> Option<String> {
        Some(certon::storage::legacy_issuer_key(CA))
    }
}

#[derive(Default)]
struct MemoryStore(
    std::sync::Mutex<std::collections::HashMap<(String, String), CertificateResource>>,
);
impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryStore")
    }
}
#[async_trait::async_trait]
impl CertStore for MemoryStore {
    async fn load(&self, issuer: &str, name: &str) -> certon::Result<Option<CertificateResource>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&(issuer.into(), name.into()))
            .cloned())
    }
    async fn save(&self, issuer: &str, resource: &CertificateResource) -> certon::Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert((issuer.into(), resource.names_key()), resource.clone());
        Ok(())
    }
    async fn has(&self, issuer: &str, name: &str) -> certon::Result<bool> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .contains_key(&(issuer.into(), name.into())))
    }
    async fn remove(&self, issuer: &str, name: &str) -> certon::Result<()> {
        self.0.lock().unwrap().remove(&(issuer.into(), name.into()));
        Ok(())
    }
}

struct PublicKey(Vec<u8>);
impl rcgen::PublicKeyData for PublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
struct RecoveryIssuer {
    calls: AtomicUsize,
    revocations: AtomicUsize,
    ca: rcgen::Issuer<'static, rcgen::KeyPair>,
    root: rustls::pki_types::CertificateDer<'static>,
}
impl RecoveryIssuer {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&key).unwrap().der().clone();
        Self {
            calls: 0.into(),
            revocations: 0.into(),
            ca: rcgen::Issuer::new(params, key),
            root,
        }
    }
}
#[async_trait::async_trait]
impl CertIssuer for RecoveryIssuer {
    async fn issue(&self, csr: &[u8], names: &[String]) -> certon::Result<IssuedCertificate> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        let public = PublicKey(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let cert = rcgen::CertificateParams::new(names.to_vec())
            .unwrap()
            .signed_by(&public, &self.ca)
            .unwrap();
        Ok(IssuedCertificate {
            certificate_pem: format!(
                "{}{}",
                cert.pem(),
                pem::encode(&pem::Pem::new("CERTIFICATE", self.root.as_ref()))
            )
            .into_bytes(),
            private_key_pem: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }
    fn issuer_key(&self) -> String {
        certon::storage::issuer_key(CA)
    }
    fn legacy_issuer_key(&self) -> Option<String> {
        Some(certon::storage::legacy_issuer_key(CA))
    }
    fn as_revoker(&self) -> Option<&dyn certon::Revoker> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl certon::Revoker for RecoveryIssuer {
    async fn revoke(&self, _: &[u8], _: Option<u8>) -> certon::Result<()> {
        self.revocations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn same_material(first: &CertificateResource, second: &CertificateResource) -> bool {
    first.sans == second.sans
        && first.certificate_pem == second.certificate_pem
        && first.private_key_pem == second.private_key_pem
        && first.issuer_data == second.issuer_data
}

/// Executable form of the offline migration procedure in MIGRATION.md. All
/// writers for these identities are paused; these comparisons are not a CAS.
async fn migrate_certificate_offline(
    store: &dyn CertStore,
    backup: &dyn Storage,
    backup_key: &str,
    directory_url: &str,
    name: &str,
    expected: &CertificateResource,
) -> certon::Result<()> {
    if !backup_key.ends_with(".key") {
        return Err(certon::Error::Config(
            "private migration backup key must end in .key".into(),
        ));
    }
    let old = certon::storage::legacy_issuer_key(directory_url);
    let new = certon::storage::issuer_key(directory_url);
    let source = store.load(&old, name).await?;
    let target = store.load(&new, name).await?;
    if source.as_ref().is_some_and(|resource| {
        !same_material(resource, expected) || resource.issuer_key != expected.issuer_key
    }) || target
        .as_ref()
        .is_some_and(|resource| !same_material(resource, expected) || resource.issuer_key != new)
        || (source.is_none() && target.is_none())
    {
        return Err(certon::Error::Config(
            "migration source or destination is not the verified generation".into(),
        ));
    }
    // CertificateResource's standalone serde omits PEM/key bytes. Include them
    // explicitly and keep the backup outside every active CertStore namespace.
    let bytes = serde_json::to_vec(&serde_json::json!({
        "metadata": expected, "certificate_pem": expected.certificate_pem,
        "private_key_pem": expected.private_key_pem,
    }))
    .map_err(|_| certon::Error::Config("cannot encode private migration backup".into()))?;
    match backup.load(backup_key).await {
        Ok(existing) if existing != bytes => {
            return Err(certon::Error::Config(
                "backup key already contains another generation".into(),
            ));
        }
        Ok(_) => {}
        Err(certon::Error::Storage(certon::error::StorageError::NotFound(_))) => {
            backup.store(backup_key, &bytes).await?
        }
        Err(error) => return Err(error),
    }
    if target.is_none() {
        let mut migrated = expected.clone();
        migrated.issuer_key = new.clone();
        store.save(&new, &migrated).await?;
    }
    let current = store
        .load(&new, name)
        .await?
        .ok_or_else(|| certon::Error::Config("migration destination disappeared".into()))?;
    if !same_material(&current, expected) || current.issuer_key != new {
        return Err(certon::Error::Config(
            "migration destination changed before retirement".into(),
        ));
    }
    if let Some(source) = store.load(&old, name).await? {
        if !same_material(&source, expected) || source.issuer_key != expected.issuer_key {
            return Err(certon::Error::Config(
                "migration source changed before retirement".into(),
            ));
        }
        store.remove(&old, name).await?;
    }
    if store.load(&old, name).await?.is_some() {
        return Err(certon::Error::Config(
            "legacy source is still active; migration is incomplete".into(),
        ));
    }
    Ok(())
}

struct ControlledMigrationStore {
    inner: Arc<dyn CertStore>,
    mode: std::sync::atomic::AtomicU8,
    old_reads: AtomicUsize,
    changed: CertificateResource,
    entered: tokio::sync::Notify,
}
impl std::fmt::Debug for ControlledMigrationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlledMigrationStore")
    }
}
#[async_trait::async_trait]
impl CertStore for ControlledMigrationStore {
    async fn load(&self, issuer: &str, name: &str) -> certon::Result<Option<CertificateResource>> {
        if issuer == certon::storage::legacy_issuer_key(CA)
            && self.old_reads.fetch_add(1, Ordering::SeqCst) == 1
            && self.mode.load(Ordering::SeqCst) == 3
        {
            self.inner.save(issuer, &self.changed).await?;
        }
        self.inner.load(issuer, name).await
    }
    async fn save(&self, issuer: &str, resource: &CertificateResource) -> certon::Result<()> {
        self.inner.save(issuer, resource).await
    }
    async fn has(&self, issuer: &str, name: &str) -> certon::Result<bool> {
        self.inner.has(issuer, name).await
    }
    async fn remove(&self, issuer: &str, name: &str) -> certon::Result<()> {
        match self.mode.load(Ordering::SeqCst) {
            1 => return Err(certon::Error::Other("legacy retirement unavailable".into())),
            2 => {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            _ => {}
        }
        self.inner.remove(issuer, name).await
    }
}

fn migration_resource(issuer: &str) -> CertificateResource {
    let generated = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    CertificateResource {
        sans: vec![NAME.into()],
        certificate_pem: generated.cert.pem().into_bytes(),
        private_key_pem: generated.signing_key.serialize_pem().into_bytes(),
        issuer_data: None,
        issuer_key: issuer.into(),
    }
}

#[tokio::test]
async fn incomplete_offline_retirement_is_retryable_without_deleting_changed_generations() {
    for custom in [false, true] {
        for mode in [1, 2, 3, 4, 5, 6] {
            let directory = tempfile::tempdir().unwrap();
            let active = Arc::new(FileStorage::new(directory.path().join("active")));
            let inner: Arc<dyn CertStore> = if custom {
                Arc::new(MemoryStore::default())
            } else {
                Arc::new(KeyValueCertStore::new(active))
            };
            let old = certon::storage::legacy_issuer_key(CA);
            let new = certon::storage::issuer_key(CA);
            let expected = migration_resource(&old);
            let foreign = migration_resource(&old);
            inner.save(&old, &expected).await.unwrap();
            let controlled = Arc::new(ControlledMigrationStore {
                inner: inner.clone(),
                mode: mode.into(),
                old_reads: 0.into(),
                changed: foreign.clone(),
                entered: Default::default(),
            });
            let backup_path = directory.path().join("private-backup");
            if mode == 5 {
                tokio::fs::write(&backup_path, b"not a directory")
                    .await
                    .unwrap();
            }
            let backup = Arc::new(FileStorage::new(backup_path));
            if mode == 6 {
                backup
                    .store(
                        "verified-generation.key",
                        b"another private backup generation",
                    )
                    .await
                    .unwrap();
            }
            if mode == 4 {
                let mut target = foreign.clone();
                target.issuer_key = new.clone();
                inner.save(&new, &target).await.unwrap();
            }
            if mode == 2 {
                let migration = tokio::spawn({
                    let store = controlled.clone();
                    let backup = backup.clone();
                    let expected = expected.clone();
                    async move {
                        migrate_certificate_offline(
                            store.as_ref(),
                            backup.as_ref(),
                            "verified-generation.key",
                            CA,
                            NAME,
                            &expected,
                        )
                        .await
                    }
                });
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    controlled.entered.notified(),
                )
                .await
                .unwrap();
                migration.abort();
                assert!(migration.await.unwrap_err().is_cancelled());
            } else {
                assert!(
                    migrate_certificate_offline(
                        controlled.as_ref(),
                        backup.as_ref(),
                        "verified-generation.key",
                        CA,
                        NAME,
                        &expected
                    )
                    .await
                    .is_err()
                );
            }
            let source = inner.load(&old, NAME).await.unwrap().unwrap();
            assert!(same_material(
                &source,
                if mode == 3 { &foreign } else { &expected }
            ));
            if mode == 4 {
                assert!(same_material(
                    &inner.load(&new, NAME).await.unwrap().unwrap(),
                    &foreign
                ));
            }
            if mode >= 5 {
                assert!(inner.load(&new, NAME).await.unwrap().is_none());
            }
            if mode == 6 {
                assert_eq!(
                    backup.load("verified-generation.key").await.unwrap(),
                    b"another private backup generation"
                );
            }
            if mode <= 2 {
                controlled.mode.store(0, Ordering::SeqCst);
                migrate_certificate_offline(
                    controlled.as_ref(),
                    backup.as_ref(),
                    "verified-generation.key",
                    CA,
                    NAME,
                    &expected,
                )
                .await
                .unwrap();
                assert!(inner.load(&old, NAME).await.unwrap().is_none());
                assert!(same_material(
                    &inner.load(&new, NAME).await.unwrap().unwrap(),
                    &expected
                ));
            }
        }
    }
}

#[tokio::test]
async fn old_certificate_credentials_require_operator_migration_across_manager_paths() {
    for custom in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let certificates: Arc<dyn CertStore> = if custom {
            Arc::new(MemoryStore::default())
        } else {
            Arc::new(KeyValueCertStore::new(storage.clone()))
        };
        let issuer = Arc::new(Issuer {
            calls: 0.into(),
            ari_calls: 0.into(),
            ari_changed: Default::default(),
        });
        let legacy = issuer.legacy_issuer_key().unwrap();
        let new = issuer.issuer_key();
        let generated = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
        let resource = CertificateResource {
            sans: vec![NAME.into()],
            certificate_pem: generated.cert.pem().into_bytes(),
            private_key_pem: generated.signing_key.serialize_pem().into_bytes(),
            issuer_data: None,
            issuer_key: legacy.clone(),
        };
        certificates.save(&legacy, &resource).await.unwrap();
        let manager = CertManager::builder()
            .storage(storage.clone())
            .certificates(certificates.clone())
            .issuers(vec![issuer.clone()])
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build();
        for result in [
            manager.obtain(NAME).await,
            manager.manage(&[NAME.into()]).await,
            manager.renew(NAME, true).await,
            manager.revoke(NAME, None).await,
            manager.client_credentials(NAME).await.map(|_| ()),
            manager.cache_certificate(NAME).await.map(|_| ()),
        ] {
            assert!(result.unwrap_err().to_string().contains("migrate"));
        }
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
        assert!(certificates.load(&new, NAME).await.unwrap().is_none());
        assert!(manager.cache.get_by_name(NAME).await.is_none());
        // The operator has independently confirmed the original full endpoint.
        let original = certificates.load(&legacy, NAME).await.unwrap().unwrap();
        let backup_directory = tempfile::tempdir().unwrap();
        let backup = FileStorage::new(backup_directory.path());
        migrate_certificate_offline(
            certificates.as_ref(),
            &backup,
            "verified-generation.key",
            CA,
            NAME,
            &original,
        )
        .await
        .unwrap();
        manager.obtain(NAME).await.unwrap();
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
        let loaded = manager.load_certificate(NAME).await.unwrap().unwrap();
        assert_eq!(loaded.issuer_key, new);
        assert_eq!(loaded.cert_chain[0].as_ref(), generated.cert.der().as_ref());
        let maintenance = certon::start_maintenance(&manager);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while issuer.ari_calls.load(Ordering::SeqCst) == 0 {
                issuer.ari_changed.notified().await;
            }
        })
        .await
        .expect("the migrated certificate must match the new issuer for ARI refresh");
        manager.cache.stop_and_wait().await;
        maintenance.await.unwrap();
        // A new namespace must not weaken the shared leaf revocation guard.
        let leaf = certon::certificates::hash_certificate_chain(&loaded.cert_chain[..1]);
        storage
            .store(
                &format!("revocations/{leaf}.json"),
                br#"{"version":1,"confirmed":true}"#,
            )
            .await
            .unwrap();
        assert!(matches!(
            manager.cache_certificate(NAME).await,
            Err(certon::Error::Cert(certon::error::CertError::Revoked(_)))
        ));
    }
}

#[tokio::test]
async fn completed_certificate_migration_can_revoke_and_obtain_a_new_leaf() {
    let mut failures = Vec::new();
    for custom in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path().join("active")));
        let certificates: Arc<dyn CertStore> = if custom {
            Arc::new(MemoryStore::default())
        } else {
            Arc::new(KeyValueCertStore::new(storage.clone()))
        };
        let issuer = Arc::new(RecoveryIssuer::new());
        let old = issuer.legacy_issuer_key().unwrap();
        let new = issuer.issuer_key();
        let generated = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
        let original = CertificateResource {
            sans: vec![NAME.into()],
            certificate_pem: generated.cert.pem().into_bytes(),
            private_key_pem: generated.signing_key.serialize_pem().into_bytes(),
            issuer_data: None,
            issuer_key: old.clone(),
        };
        certificates.save(&old, &original).await.unwrap();
        let manager = CertManager::builder()
            .storage(storage.clone())
            .certificates(certificates.clone())
            .issuers(vec![issuer.clone()])
            .disable_ari(true)
            .ocsp(OcspConfig {
                disable_stapling: true,
                ..Default::default()
            })
            .build();
        assert!(
            manager
                .obtain(NAME)
                .await
                .unwrap_err()
                .to_string()
                .contains("migrate")
        );
        let backup = FileStorage::new(directory.path().join("offline-private-backup"));
        migrate_certificate_offline(
            certificates.as_ref(),
            &backup,
            "verified-generation.key",
            CA,
            NAME,
            &original,
        )
        .await
        .unwrap();
        migrate_certificate_offline(
            certificates.as_ref(),
            &backup,
            "verified-generation.key",
            CA,
            NAME,
            &original,
        )
        .await
        .unwrap();
        assert!(certificates.load(&old, NAME).await.unwrap().is_none());
        let backed_up: serde_json::Value =
            serde_json::from_slice(&backup.load("verified-generation.key").await.unwrap()).unwrap();
        assert_eq!(
            serde_json::from_value::<Vec<u8>>(backed_up["private_key_pem"].clone()).unwrap(),
            original.private_key_pem
        );
        assert_eq!(
            serde_json::from_value::<Vec<u8>>(backed_up["certificate_pem"].clone()).unwrap(),
            original.certificate_pem
        );
        manager.obtain(NAME).await.unwrap();
        let old_leaf = manager.cache.get_by_name(NAME).await.unwrap();
        let old_hash = certon::certificates::hash_certificate_chain(&old_leaf.cert_chain[..1]);
        manager.revoke(NAME, None).await.unwrap();
        assert_eq!(issuer.revocations.load(Ordering::SeqCst), 1);
        assert!(certificates.load(&new, NAME).await.unwrap().is_none());
        assert!(
            storage
                .exists(&format!("revocations/{old_hash}.json"))
                .await
                .unwrap()
        );
        let outcome = manager.obtain(NAME).await;
        eprintln!(
            "custom_store={custom} obtain_after_migrate_and_revoke_ok={} legacy_active_remaining={} issue_calls={}",
            outcome.is_ok(),
            certificates.load(&old, NAME).await.unwrap().is_some(),
            issuer.calls.load(Ordering::SeqCst)
        );
        if outcome.is_err() {
            failures.push(custom);
            continue;
        }
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
        let fresh = manager.cache.get_by_name(NAME).await.unwrap();
        assert_ne!(fresh.cert_chain[0], old_leaf.cert_chain[0]);
        assert_eq!(fresh.issuer_key, new);
        let fresh_resource = certificates.load(&new, NAME).await.unwrap().unwrap();
        let mut revoked_backup = original.clone();
        revoked_backup.issuer_key = new.clone();
        certificates.save(&new, &revoked_backup).await.unwrap();
        assert!(matches!(
            manager.cache_certificate(NAME).await,
            Err(certon::Error::Cert(certon::error::CertError::Revoked(_)))
        ));
        certificates.save(&new, &fresh_resource).await.unwrap();
        manager.cache_certificate(NAME).await.unwrap();
        // Even a durably revoked old copy cannot be automatically skipped when
        // its ownership/retirement was not completed through the offline flow.
        certificates.save(&old, &original).await.unwrap();
        certificates.remove(&new, NAME).await.unwrap();
        assert!(
            manager
                .obtain(NAME)
                .await
                .unwrap_err()
                .to_string()
                .contains("migrate")
        );
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
        certificates.save(&new, &fresh_resource).await.unwrap();
        certificates.remove(&old, NAME).await.unwrap();
    }
    assert!(
        failures.is_empty(),
        "revoked migrations were blocked by an active legacy copy: {failures:?}"
    );
}
