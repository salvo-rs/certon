use certon::account::{get_account, new_account, save_account};
use certon::{FileStorage, KeyType};
const CA: &str = "https://account-identity.example/directory";
fn public_identity(pem: &str) -> String {
    let key = certon::crypto::decode_private_key_pem(pem).unwrap();
    certon::acme_client::key_authorization("configured-account-identity", &key).unwrap()
}
#[tokio::test]
async fn configured_emails_keep_distinct_persisted_key_and_registration_identities() {
    let mut failures = Vec::new();
    for (first_email, second_email) in [
        (
            "operator+prod@example.com",
            "operator_plus_prod@example.com",
        ),
        (
            "operator++prod@example.com",
            "operator_plus__plus_prod@example.com",
        ),
        ("first@example.com", "second@example.com"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let mut first = new_account(first_email, KeyType::EcdsaP256).unwrap();
        first.status = "valid".into();
        first.location = "https://account-identity.example/account/first".into();
        let mut second = new_account(second_email, KeyType::EcdsaP256).unwrap();
        second.status = "valid".into();
        second.location = "https://account-identity.example/account/second".into();
        save_account(&storage, CA, &first).await.unwrap();
        let second_absent = get_account(&storage, CA, second_email)
            .await
            .unwrap()
            .is_none();
        save_account(&storage, CA, &second).await.unwrap();
        let storage = FileStorage::new(directory.path());
        let a = get_account(&storage, CA, first_email)
            .await
            .unwrap()
            .unwrap();
        let b = get_account(&storage, CA, second_email)
            .await
            .unwrap()
            .unwrap();
        let first_preserved = a.location == first.location
            && public_identity(&a.private_key_pem) == public_identity(&first.private_key_pem);
        let second_preserved = b.location == second.location
            && public_identity(&b.private_key_pem) == public_identity(&second.private_key_pem);
        eprintln!(
            "first={first_email} second={second_email} absent_before_save={second_absent} first_preserved={first_preserved} second_preserved={second_preserved}"
        );
        if !(second_absent && first_preserved && second_preserved) {
            failures.push((first_email, second_email));
        }
    }
    assert!(
        failures.is_empty(),
        "distinct configured email identities shared state: {failures:?}"
    );
}
#[tokio::test]
async fn intentional_email_normalizations_reuse_one_registered_account() {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let mut account = new_account("operator+prod@example.com", KeyType::EcdsaP256).unwrap();
    account.location = "https://account-identity.example/account/normalized".into();
    save_account(&storage, CA, &account).await.unwrap();
    for identity in [
        "operator+prod@example.com",
        "OPERATOR+PROD@EXAMPLE.COM",
        "mailto:operator+prod@example.com",
        "  operator+prod@example.com  ",
    ] {
        let actual = get_account(&storage, CA, identity).await.unwrap().unwrap();
        assert_eq!(actual.location, account.location);
        assert_eq!(
            public_identity(&actual.private_key_pem),
            public_identity(&account.private_key_pem)
        );
    }
}

#[tokio::test]
async fn empty_and_literal_default_roundtrip_as_independent_public_accounts() {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let mut empty = new_account("", KeyType::EcdsaP256).unwrap();
    let mut literal = new_account("default", KeyType::EcdsaP256).unwrap();
    assert!(empty.contact.is_empty());
    assert_eq!(literal.contact, vec!["mailto:default"]);
    empty.location = "https://account-identity.example/account/empty".into();
    literal.location = "https://account-identity.example/account/literal".into();
    save_account(&storage, CA, &empty).await.unwrap();
    save_account(&storage, CA, &literal).await.unwrap();
    assert_eq!(
        get_account(&storage, CA, "")
            .await
            .unwrap()
            .unwrap()
            .location,
        empty.location
    );
    assert_eq!(
        get_account(&storage, CA, "default")
            .await
            .unwrap()
            .unwrap()
            .location,
        literal.location
    );
    certon::account::delete_account_locally(&storage, CA, &empty)
        .await
        .unwrap();
    assert!(get_account(&storage, CA, "").await.unwrap().is_none());
    assert_eq!(
        get_account(&storage, CA, "default")
            .await
            .unwrap()
            .unwrap()
            .location,
        literal.location
    );
    save_account(&storage, CA, &empty).await.unwrap();
    certon::account::delete_account_locally(&storage, CA, &literal)
        .await
        .unwrap();
    assert!(
        get_account(&storage, CA, "default")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        get_account(&storage, CA, "")
            .await
            .unwrap()
            .unwrap()
            .location,
        empty.location
    );
}
#[tokio::test]
async fn deleting_one_configured_email_keeps_the_collision_partner() {
    use certon::account::delete_account_locally;
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let mut first = new_account("operator+prod@example.com", KeyType::EcdsaP256).unwrap();
    first.location = "https://account-identity.example/account/first".into();
    let mut second = new_account("operator_plus_prod@example.com", KeyType::EcdsaP256).unwrap();
    second.location = "https://account-identity.example/account/second".into();
    save_account(&storage, CA, &first).await.unwrap();
    save_account(&storage, CA, &second).await.unwrap();
    delete_account_locally(&storage, CA, &first).await.unwrap();
    assert!(
        get_account(&storage, CA, "operator+prod@example.com")
            .await
            .unwrap()
            .is_none()
    );
    let kept = get_account(&storage, CA, "operator_plus_prod@example.com")
        .await
        .unwrap()
        .expect("deletion crossed the configured email identity");
    assert_eq!(kept.location, second.location);
    assert_eq!(
        public_identity(&kept.private_key_pem),
        public_identity(&second.private_key_pem)
    );
}
