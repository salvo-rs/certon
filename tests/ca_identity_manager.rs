use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use certon::{
    CertIssuer, CertManager, CertStore, CertificateResource, FileStorage, IssuedCertificate,
    KeyValueCertStore, OcspConfig, Storage,
};

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
        let mut original = certificates.load(&legacy, NAME).await.unwrap().unwrap();
        original.issuer_key = new.clone();
        certificates.save(&new, &original).await.unwrap();
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
