//! Where certificates live, in certon's own vocabulary.
//!
//! [`Storage`] is a key-value store with filesystem-like paths and
//! cluster-wide locking. That is a fine description of *how* certon persists
//! things, and a poor description of *what* it persists — so somebody who
//! wants their certificates in Postgres, or Vault, or a Kubernetes Secret has
//! to implement a key-value store with distributed locking, and then
//! reverse-engineer a key layout that is certon's own convention.
//!
//! Six methods and a lock protocol, to answer "where do the certificates go".
//!
//! [`CertStore`] asks the question certon actually has. Four methods, each one
//! about a certificate, with no path scheme to reproduce and no locking to
//! implement. [`KeyValueCertStore`] satisfies it over any [`Storage`], which
//! is what happens by default, so nothing changes for anybody who does not
//! want it to.
//!
//! It also stops one decision forcing another. Redirecting certificates used
//! to mean redirecting the ACME account key and the lock files with them,
//! because there was one interface for all three. Certificates in a database
//! and an account key on disk is a perfectly ordinary arrangement, and it is
//! now expressible.
//!
//! ## What is not here yet
//!
//! OCSP staples, ACME account data and challenge state still go through
//! [`Storage`] directly. Certificates came first because they are the thing
//! people actually want to put somewhere else; the same treatment for the
//! other three is worth doing and is not done here.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{Error, Result, StorageError};
use crate::storage::{
    CertificateResource, Storage, site_cert_key, site_meta_key, site_private_key, store_certificate,
};

/// Somewhere certificates are kept.
///
/// A certificate is stored under the issuer that produced it, so two
/// authorities issuing for the same name do not overwrite each other.
/// `Debug` is required because a `CertManager` prints what it is using, and
/// "some store" is not a useful thing to read in a log. Name yours.
#[async_trait]
pub trait CertStore: Send + Sync + std::fmt::Debug {
    /// Everything held for `domain` under `issuer`, or `None` if nothing is.
    ///
    /// "Nothing is there" is `Ok(None)` rather than an error, because it is
    /// the ordinary answer on a first run and must be distinguishable from
    /// "the store is broken" — which is what the old `Result`-only signature
    /// made callers guess at, and what they guessed wrong by matching on
    /// `Err(_)` and carrying on.
    async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>>;

    /// Save a certificate, its key and its metadata.
    ///
    /// Atomicity depends on the backend. The key-value adapter writes three
    /// separate entries; callers must coordinate writers with shared locks.
    ///
    /// The storage name is `resource.names_key()` (the first SAN). Callers
    /// must supply names consistent with the certificate.
    async fn save(&self, issuer: &str, resource: &CertificateResource) -> Result<()>;

    /// Whether a complete set is held.
    ///
    /// Separate from [`load`](Self::load) because answering it need not read a
    /// private key off a disk, out of a vault, or across a network.
    async fn has(&self, issuer: &str, domain: &str) -> Result<bool>;

    /// Forget everything held for `domain` under `issuer`.
    ///
    /// Removing what is not there is not an error.
    async fn remove(&self, issuer: &str, domain: &str) -> Result<()>;
}

/// A [`CertStore`] over any [`Storage`], using certon's key layout.
///
/// The default, and what every existing deployment already has on disk.
pub struct KeyValueCertStore {
    storage: Arc<dyn Storage>,
}

impl std::fmt::Debug for KeyValueCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyValueCertStore").finish_non_exhaustive()
    }
}

impl KeyValueCertStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// The storage underneath, for the things that do not go through
    /// [`CertStore`] yet.
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

#[async_trait]
impl CertStore for KeyValueCertStore {
    async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>> {
        let key = self.read(&site_private_key(issuer, domain)).await?;
        let certificate = self.read(&site_cert_key(issuer, domain)).await?;
        let metadata = self.read(&site_meta_key(issuer, domain)).await?;
        let (key, certificate, metadata) = match (key, certificate, metadata) {
            (None, None, None) => return Ok(None),
            (Some(key), Some(certificate), Some(metadata)) => (key, certificate, metadata),
            _ => {
                return Err(Error::Storage(StorageError::Deserialize(format!(
                    "incomplete certificate resources for {domain} under {issuer}"
                ))));
            }
        };

        let mut resource: CertificateResource = serde_json::from_slice(&metadata).map_err(|e| {
            Error::Storage(StorageError::Deserialize(format!(
                "decoding certificate metadata: {e}"
            )))
        })?;
        resource.private_key_pem = key;
        resource.certificate_pem = certificate;
        resource.issuer_key = issuer.to_owned();
        Ok(Some(resource))
    }

    async fn save(&self, issuer: &str, resource: &CertificateResource) -> Result<()> {
        store_certificate(self.storage.as_ref(), issuer, resource).await
    }

    async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
        let mut present = 0;
        for key in [
            site_cert_key(issuer, domain),
            site_private_key(issuer, domain),
            site_meta_key(issuer, domain),
        ] {
            if self.storage.exists(&key).await? {
                present += 1;
            }
        }
        match present {
            0 => Ok(false),
            3 => Ok(true),
            _ => Err(Error::Storage(StorageError::Deserialize(format!(
                "incomplete certificate resources for {domain} under {issuer}"
            )))),
        }
    }

    async fn remove(&self, issuer: &str, domain: &str) -> Result<()> {
        for key in [
            site_cert_key(issuer, domain),
            site_private_key(issuer, domain),
            site_meta_key(issuer, domain),
        ] {
            match self.storage.delete(&key).await {
                Ok(()) | Err(Error::Storage(StorageError::NotFound(_))) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl KeyValueCertStore {
    /// Read a key, turning "not found" into `None` and leaving every other
    /// failure as a failure.
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.storage.load(key).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(Error::Storage(StorageError::NotFound(_))) => Ok(None),
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::file_storage::FileStorage;

    fn store() -> (tempfile::TempDir, KeyValueCertStore) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let store = KeyValueCertStore::new(Arc::new(FileStorage::new(directory.path())));
        (directory, store)
    }

    fn resource(domain: &str) -> CertificateResource {
        CertificateResource {
            sans: vec![domain.to_string()],
            certificate_pem: b"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n"
                .to_vec(),
            private_key_pem: b"-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----\n"
                .to_vec(),
            issuer_data: None,
            issuer_key: "ca".to_string(),
        }
    }

    /// A store that keeps certificates in memory and knows nothing about
    /// key-value paths, prefixes or locking.
    ///
    /// This is the whole point of the trait: everything below is what somebody
    /// putting certificates in a database has to write. Compare it with
    /// implementing `Storage`, which is six key-value methods plus a
    /// distributed lock protocol, and then working out certon's key layout.
    #[derive(Debug, Default)]
    pub(crate) struct InMemory {
        held: std::sync::Mutex<std::collections::HashMap<(String, String), CertificateResource>>,
    }

    #[async_trait]
    impl CertStore for InMemory {
        async fn load(&self, issuer: &str, domain: &str) -> Result<Option<CertificateResource>> {
            let held = self.held.lock().unwrap();
            Ok(held.get(&(issuer.into(), domain.into())).cloned())
        }

        async fn save(&self, issuer: &str, resource: &CertificateResource) -> Result<()> {
            let mut held = self.held.lock().unwrap();
            held.insert((issuer.into(), resource.names_key()), resource.clone());
            Ok(())
        }

        async fn has(&self, issuer: &str, domain: &str) -> Result<bool> {
            let held = self.held.lock().unwrap();
            Ok(held.contains_key(&(issuer.into(), domain.into())))
        }

        async fn remove(&self, issuer: &str, domain: &str) -> Result<()> {
            let mut held = self.held.lock().unwrap();
            held.remove(&(issuer.into(), domain.into()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_store_can_be_written_without_implementing_storage() {
        let store = InMemory::default();
        assert!(store.load("ca", "example.com").await.unwrap().is_none());

        store.save("ca", &resource("example.com")).await.unwrap();
        assert!(store.has("ca", "example.com").await.unwrap());
        assert_eq!(
            store
                .load("ca", "example.com")
                .await
                .unwrap()
                .unwrap()
                .certificate_pem,
            resource("example.com").certificate_pem
        );

        store.remove("ca", "example.com").await.unwrap();
        assert!(!store.has("ca", "example.com").await.unwrap());
    }

    #[tokio::test]
    async fn a_manager_takes_a_store_that_is_not_its_storage() {
        // Certificates in one place, the ACME account key and the locks in
        // another. One decision no longer forces the other.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let manager = crate::CertManager::builder()
            .storage(Arc::new(FileStorage::new(directory.path())))
            .certificates(Arc::new(InMemory::default()))
            .build();
        assert!(format!("{manager:?}").contains("InMemory"));
    }

    #[tokio::test]
    async fn nothing_stored_is_none_rather_than_an_error() {
        // The distinction the old signature could not make. A first run and a
        // broken disk used to look the same to a caller matching on `Err(_)`.
        let (_directory, store) = store();
        assert!(store.load("ca", "example.com").await.unwrap().is_none());
        assert!(!store.has("ca", "example.com").await.unwrap());
    }

    #[tokio::test]
    async fn what_was_saved_comes_back() {
        let (_directory, store) = store();
        store.save("ca", &resource("example.com")).await.unwrap();

        let loaded = store
            .load("ca", "example.com")
            .await
            .unwrap()
            .expect("it was just saved");
        assert_eq!(loaded.sans, vec!["example.com".to_string()]);
        assert_eq!(
            loaded.certificate_pem,
            resource("example.com").certificate_pem
        );
        assert_eq!(
            loaded.private_key_pem,
            resource("example.com").private_key_pem
        );
        assert_eq!(loaded.issuer_key, "ca");
        assert!(store.has("ca", "example.com").await.unwrap());
    }

    #[tokio::test]
    async fn two_issuers_do_not_overwrite_each_other() {
        // Both authorities can hold a certificate for one name, which is what
        // makes falling back from one to the other possible.
        let (_directory, store) = store();
        let mut first = resource("example.com");
        first.certificate_pem = b"first".to_vec();
        let mut second = resource("example.com");
        second.certificate_pem = b"second".to_vec();

        store.save("ca-one", &first).await.unwrap();
        store.save("ca-two", &second).await.unwrap();

        let one = store.load("ca-one", "example.com").await.unwrap().unwrap();
        let two = store.load("ca-two", "example.com").await.unwrap().unwrap();
        assert_eq!(one.certificate_pem, b"first".to_vec());
        assert_eq!(two.certificate_pem, b"second".to_vec());
    }

    #[tokio::test]
    async fn removing_forgets_everything_including_the_key() {
        // A certificate removed with its private key left behind is a private
        // key nobody is looking after any more.
        let (_directory, store) = store();
        store.save("ca", &resource("example.com")).await.unwrap();
        store.remove("ca", "example.com").await.unwrap();

        assert!(!store.has("ca", "example.com").await.unwrap());
        assert!(store.load("ca", "example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn removing_what_is_not_there_is_not_an_error() {
        let (_directory, store) = store();
        store.remove("ca", "absent.example.com").await.unwrap();
    }

    #[tokio::test]
    async fn a_half_written_certificate_is_not_a_certificate() {
        // Partial writes are corruption, not absence that permits reissuance.
        let (_directory, store) = store();
        store.save("ca", &resource("example.com")).await.unwrap();
        store
            .storage()
            .delete(&site_private_key("ca", "example.com"))
            .await
            .unwrap();

        assert!(store.load("ca", "example.com").await.is_err());
        assert!(store.has("ca", "example.com").await.is_err());
    }
    struct TestIssuer;
    #[async_trait]
    impl crate::CertIssuer for TestIssuer {
        async fn issue(&self, _: &[u8], _: &[String]) -> Result<crate::IssuedCertificate> {
            panic!("an existing certificate must not be issued again")
        }
        fn issuer_key(&self) -> String {
            "ca".into()
        }
        fn as_revoker(&self) -> Option<&dyn crate::Revoker> {
            Some(self)
        }
    }
    #[async_trait]
    impl crate::Revoker for TestIssuer {
        async fn revoke(&self, _: &[u8], _: Option<u8>) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn custom_store_supports_obtain_mtls_and_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(InMemory::default());
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let mut resource = resource("example.com");
        resource.certificate_pem = cert.cert.pem().into_bytes();
        resource.private_key_pem = cert.signing_key.serialize_pem().into_bytes();
        store.save("ca", &resource).await.unwrap();
        let manager = crate::CertManager::builder()
            .storage(Arc::new(FileStorage::new(directory.path())))
            .certificates(store.clone())
            .issuers(vec![Arc::new(TestIssuer)])
            .interactive(true)
            .build();
        manager.obtain("example.com").await.unwrap();
        let (chain, _) = manager.client_credentials("example.com").await.unwrap();
        assert_eq!(chain[0].as_ref(), cert.cert.der().as_ref());
        manager.revoke("example.com", None).await.unwrap();
        assert!(!store.has("ca", "example.com").await.unwrap());
        assert!(
            manager
                .load_certificate("example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[derive(Debug)]
    struct BrokenStore;
    #[async_trait]
    impl CertStore for BrokenStore {
        async fn load(&self, _: &str, _: &str) -> Result<Option<CertificateResource>> {
            Err(Error::Other("backend offline".into()))
        }
        async fn has(&self, _: &str, _: &str) -> Result<bool> {
            Err(Error::Other("backend offline".into()))
        }
        async fn save(&self, _: &str, _: &CertificateResource) -> Result<()> {
            unreachable!()
        }
        async fn remove(&self, _: &str, _: &str) -> Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn backend_failures_are_not_absence_or_success() {
        let directory = tempfile::tempdir().unwrap();
        let manager = crate::CertManager::builder()
            .storage(Arc::new(FileStorage::new(directory.path())))
            .certificates(Arc::new(BrokenStore))
            .issuers(vec![Arc::new(TestIssuer)])
            .interactive(true)
            .build();
        for result in [
            manager.obtain("example.com").await,
            manager.revoke("example.com", None).await,
            manager.load_certificate("example.com").await.map(|_| ()),
            manager.client_credentials("example.com").await.map(|_| ()),
        ] {
            assert!(result.unwrap_err().to_string().contains("backend offline"));
        }
    }
}
