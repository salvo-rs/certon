use std::sync::Arc;

use certon::account::{get_account, new_account, save_account};
use certon::{CertStore, CertificateResource, FileStorage, KeyType, KeyValueCertStore};

fn public_identity(pem: &str) -> String {
    let key = certon::crypto::decode_private_key_pem(pem).unwrap();
    certon::acme_client::key_authorization("storage-identity-probe", &key).unwrap()
}

#[tokio::test]
async fn distinct_ca_directories_keep_accounts_and_certificate_resources_separate() {
    let cases = [
        (
            "different-port",
            "https://ca.example:8443/directory",
            "https://ca.example:9443/directory",
            true,
        ),
        (
            "different-tenant-query",
            "https://ca.example/directory?tenant=one",
            "https://ca.example/directory?tenant=two",
            true,
        ),
        (
            "different-path",
            "https://ca.example/a-b/directory",
            "https://ca.example/a/b-directory",
            true,
        ),
        (
            "different-host-control",
            "https://one-ca.example/directory",
            "https://two-ca.example/directory",
            true,
        ),
        (
            "distinct-path-control",
            "https://ca.example/production/directory",
            "https://ca.example/staging/directory",
            true,
        ),
        (
            "same-directory-control",
            "https://ca.example/directory",
            "https://ca.example/directory",
            false,
        ),
    ];
    let mut failures = Vec::new();
    for (label, first_ca, second_ca, should_be_distinct) in cases {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let first_key = certon::storage::issuer_key(first_ca);
        let second_key = certon::storage::issuer_key(second_ca);
        let mut first = new_account("operator@example.com", KeyType::EcdsaP256).unwrap();
        first.location = format!("{first_ca}/account/first");
        let mut second = new_account("operator@example.com", KeyType::EcdsaP256).unwrap();
        second.location = format!("{second_ca}/account/second");
        save_account(storage.as_ref(), first_ca, &first)
            .await
            .unwrap();
        let absent_before_second_registration =
            get_account(storage.as_ref(), second_ca, "operator@example.com")
                .await
                .unwrap()
                .is_none();
        save_account(storage.as_ref(), second_ca, &second)
            .await
            .unwrap();
        let reloaded_first = get_account(storage.as_ref(), first_ca, "operator@example.com")
            .await
            .unwrap()
            .unwrap();
        let first_account_preserved = reloaded_first.location == first.location
            && public_identity(&reloaded_first.private_key_pem)
                == public_identity(&first.private_key_pem);
        let first_account_replaced_by_second = reloaded_first.location == second.location
            && public_identity(&reloaded_first.private_key_pem)
                == public_identity(&second.private_key_pem);

        let certificate_store = KeyValueCertStore::new(storage.clone());
        let first_cert =
            rcgen::generate_simple_self_signed(vec!["isolation.example".into()]).unwrap();
        let second_cert =
            rcgen::generate_simple_self_signed(vec!["isolation.example".into()]).unwrap();
        let resource = |pem: String, key: String, issuer_key: String| CertificateResource {
            sans: vec!["isolation.example".into()],
            certificate_pem: pem.into_bytes(),
            private_key_pem: key.into_bytes(),
            issuer_data: None,
            issuer_key,
        };
        let first_resource = resource(
            first_cert.cert.pem(),
            first_cert.signing_key.serialize_pem(),
            first_key.clone(),
        );
        let second_resource = resource(
            second_cert.cert.pem(),
            second_cert.signing_key.serialize_pem(),
            second_key.clone(),
        );
        certificate_store
            .save(&first_key, &first_resource)
            .await
            .unwrap();
        certificate_store
            .save(&second_key, &second_resource)
            .await
            .unwrap();
        let loaded_first = certificate_store
            .load(&first_key, "isolation.example")
            .await
            .unwrap()
            .unwrap();
        let first_certificate_preserved = loaded_first.certificate_pem
            == first_resource.certificate_pem
            && loaded_first.private_key_pem == first_resource.private_key_pem;
        let first_certificate_replaced_by_second = loaded_first.certificate_pem
            == second_resource.certificate_pem
            && loaded_first.private_key_pem == second_resource.private_key_pem;
        eprintln!(
            "CASE {label}: issuer_key_equal={} absent_before_second_registration={absent_before_second_registration} first_account_preserved={first_account_preserved} first_account_replaced_by_second={first_account_replaced_by_second} first_certificate_preserved={first_certificate_preserved} first_certificate_replaced_by_second={first_certificate_replaced_by_second}",
            first_key == second_key
        );
        if should_be_distinct {
            if !absent_before_second_registration
                || !first_account_preserved
                || !first_certificate_preserved
            {
                failures.push(label);
            }
        } else {
            assert!(!absent_before_second_registration);
            assert!(first_account_replaced_by_second && first_certificate_replaced_by_second);
        }
    }
    assert!(
        failures.is_empty(),
        "distinct CA identities shared persistent state: {failures:?}"
    );
}
