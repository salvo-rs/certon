#![cfg(feature = "rsa-keys")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use certon::{CertIssuer, CertManager, FileStorage, IssuedCertificate, KeyType, Result};
use x509_parser::prelude::FromDer;

struct InspectRsaCsr(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl CertIssuer for InspectRsaCsr {
    async fn issue(&self, csr: &[u8], _: &[String]) -> Result<IssuedCertificate> {
        let (_, parsed) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr).unwrap();
        assert_eq!(
            parsed
                .certification_request_info
                .subject_pki
                .algorithm
                .algorithm
                .to_id_string(),
            "1.2.840.113549.1.1.1"
        );
        parsed.verify_signature().unwrap();
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(certon::Error::Other(
            "test issuer received valid RSA CSR".into(),
        ))
    }
    fn issuer_key(&self) -> String {
        "rsa-test".into()
    }
}

#[tokio::test]
async fn async_manager_obtain_prepares_a_real_rsa_csr() {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let manager = CertManager::builder()
        .storage(Arc::new(FileStorage::new(directory.path())))
        .key_type(KeyType::Rsa2048)
        .issuers(vec![Arc::new(InspectRsaCsr(calls.clone()))])
        .build();
    let error = manager.obtain("example.com").await.unwrap_err();
    assert!(error.to_string().contains("received valid RSA CSR"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn async_account_creation_prepares_and_reloads_a_real_rsa_key() {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let ca = "https://ca.example/directory";
    let (mut account, created) =
        certon::account::get_or_create_account(&storage, ca, "user@example.com", KeyType::Rsa2048)
            .await
            .unwrap();
    assert!(created);
    let key = certon::crypto::decode_private_key_pem(&account.private_key_pem).unwrap();
    assert_eq!(key.key_type(), KeyType::Rsa2048);
    account.status = "valid".into();
    account.location = "https://ca.example/account/1".into();
    certon::account::save_account(&storage, ca, &account)
        .await
        .unwrap();
    let (reloaded, created) =
        certon::account::get_or_create_account(&storage, ca, "user@example.com", KeyType::Rsa2048)
            .await
            .unwrap();
    assert!(!created);
    assert_eq!(reloaded.private_key_pem, account.private_key_pem);
}
