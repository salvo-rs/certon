use std::sync::Arc;

use certon::{
    CertIssuer, CertManager, CertStore, Certificate, CertificateResource, FileStorage,
    IssuedCertificate, KeyValueCertStore, Result,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

struct StoredIssuer;

#[async_trait::async_trait]
impl CertIssuer for StoredIssuer {
    async fn issue(&self, _: &[u8], _: &[String]) -> Result<IssuedCertificate> {
        panic!("loading mTLS credentials must not issue a certificate")
    }

    fn issuer_key(&self) -> String {
        "mtls-test".into()
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    manager: CertManager,
    root: CertificateDer<'static>,
    client: Certificate,
    server: Arc<rustls::ServerConfig>,
}

impl Fixture {
    async fn new(cached: bool) -> Self {
        certon::install_default_crypto_provider();
        let mut ca_params = CertificateParams::new(vec!["mTLS test CA".into()]).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mTLS test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let root = ca_params.self_signed(&ca_key).unwrap().der().clone();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let mut client_params = CertificateParams::new(vec!["client.example".into()]).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
        let resource = CertificateResource {
            sans: vec!["client.example".into()],
            certificate_pem: client_cert.pem().into_bytes(),
            private_key_pem: client_key.serialize_pem().into_bytes(),
            issuer_key: "mtls-test".into(),
            issuer_data: None,
        };
        let client =
            Certificate::from_pem(&resource.certificate_pem, &resource.private_key_pem).unwrap();

        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let store = Arc::new(KeyValueCertStore::new(storage.clone()));
        store.save("mtls-test", &resource).await.unwrap();
        let manager = CertManager::builder()
            .storage(storage)
            .certificates(store)
            .issuers(vec![Arc::new(StoredIssuer)])
            .build();
        if cached {
            manager.cache_certificate("client.example").await.unwrap();
        }

        let mut server_params = CertificateParams::new(vec!["server.example".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(root.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap();
        Self {
            _directory: directory,
            manager,
            root,
            client,
            server: Arc::new(server),
        }
    }

    async fn handshake(
        &self,
        roots: impl Into<Arc<rustls::RootCertStore>>,
    ) -> std::io::Result<Vec<CertificateDer<'static>>> {
        let config = self
            .manager
            .client_config("client.example", roots)
            .await
            .unwrap();
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(self.server.clone());
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let (server, client) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect("server.example".try_into().unwrap(), client_io)
        );
        client?;
        let server = server?;
        Ok(server.get_ref().1.peer_certificates().unwrap().to_vec())
    }
}

#[tokio::test]
async fn supplied_roots_authenticate_server_and_managed_credentials_authenticate_client() {
    for cached in [false, true] {
        let fixture = Fixture::new(cached).await;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(fixture.root.clone()).unwrap();
        // Accept a shared root store as well as an owned one.
        let peer = fixture.handshake(Arc::new(roots)).await.unwrap();
        assert_eq!(peer[0], fixture.client.cert_chain[0]);
    }
}

#[tokio::test]
async fn empty_or_unrelated_roots_still_reject_the_server() {
    let fixture = Fixture::new(true).await;
    for unrelated in [false, true] {
        let mut roots = rustls::RootCertStore::empty();
        if unrelated {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["unrelated.example".into()]).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Unrelated CA");
            let cert = params.self_signed(&key).unwrap();
            roots.add(cert.der().clone()).unwrap();
        }
        let error = fixture.handshake(roots).await.unwrap_err();
        assert!(
            matches!(
                error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "unexpected TLS error: {error:?}"
        );
    }
}
