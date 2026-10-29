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
    fn legacy_issuer_key(&self) -> Option<String> {
        Some(certon::storage::legacy_issuer_key(CA))
    }
}

#[tokio::test]
async fn old_certificate_credentials_require_operator_migration_across_manager_paths() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileStorage::new(directory.path()));
    let certificates = Arc::new(KeyValueCertStore::new(storage.clone()));
    let issuer = Arc::new(Issuer { calls: 0.into() });
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
        .disable_ari(true)
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
    certificates.save(&new, &original).await.unwrap();
    manager.obtain(NAME).await.unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
    let loaded = manager.load_certificate(NAME).await.unwrap().unwrap();
    assert_eq!(loaded.issuer_key, new);
    assert_eq!(loaded.cert_chain[0].as_ref(), generated.cert.der().as_ref());
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
