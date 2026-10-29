#[path = "common/challenge_tls.rs"]
mod challenge_tls;

use std::sync::Arc;
use std::time::Duration;

use certon::{CertCache, CertResolver, DistributedSolver, FileStorage, Solver, TlsAlpn01Solver};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};

fn assert_ip_proof(der: &[u8], address: &str, key_auth: &str) {
    let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    cert.verify_signature(None).unwrap();
    let sans = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(sans.value.general_names.len(), 1);
    let expected = match address.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    assert!(
        matches!(sans.value.general_names[0],x509_parser::extensions::GeneralName::IPAddress(bytes) if bytes == expected)
    );
    let proof = cert
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .unwrap();
    assert!(proof.critical);
    assert_eq!(
        proof.value,
        [vec![4, 32], Sha256::digest(key_auth.as_bytes()).to_vec()].concat()
    );
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn peer(port: u16, server_name: &'static str) -> Vec<u8> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        challenge_tls::peer_certificate(stream, server_name),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn standalone_ip_proofs_use_reverse_sni_and_canonical_cleanup_ownership() {
    for (input, canonical, sni) in [
        ("192.0.2.7", "192.0.2.7", "7.2.0.192.in-addr.arpa"),
        (
            "2001:0DB8:0:0:0:0:0:7",
            "2001:db8::7",
            "7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ),
    ] {
        let port = free_port().await;
        let solver = TlsAlpn01Solver::new(port);
        solver
            .present(input, "old-token", "old-token.thumb")
            .await
            .unwrap();
        let old = peer(port, sni).await;
        assert_ip_proof(&old, canonical, "old-token.thumb");
        solver
            .present(canonical, "new-token", "new-token.thumb")
            .await
            .unwrap();
        solver
            .cleanup(input, "old-token", "old-token.thumb")
            .await
            .unwrap();
        let new = peer(port, sni).await;
        assert_ne!(old, new);
        assert_ip_proof(&new, canonical, "new-token.thumb");
        solver
            .cleanup(canonical, "new-token", "new-token.thumb")
            .await
            .unwrap();
        assert!(
            TcpStream::connect(("127.0.0.1", port)).await.is_err(),
            "cleanup must close the proof listener"
        );
    }
}

#[tokio::test]
async fn distributed_ip_proofs_keep_the_ip_storage_identity_and_reverse_sni_lookup() {
    for (input, canonical, host, sni) in [
        (
            "192.0.2.8",
            "192.0.2.8",
            "192.0.2.8:80",
            "8.2.0.192.in-addr.arpa",
        ),
        (
            "2001:0DB8:0:0:0:0:0:8",
            "2001:db8::8",
            "[2001:db8::8]:80",
            "8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ),
    ] {
        let port = free_port().await;
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FileStorage::new(directory.path()));
        let solver = DistributedSolver::with_prefix(
            Box::new(TlsAlpn01Solver::new(port)),
            storage,
            "ip-ca".into(),
        );
        let handler = certon::http_handler::HttpChallengeHandler::with_prefix(
            Arc::default(),
            Some(Arc::new(FileStorage::new(directory.path()))),
            "ip-ca".into(),
        );
        solver
            .present(input, "distributed-token", "distributed-token.thumb")
            .await
            .unwrap();
        let cert = peer(port, sni).await;
        assert_ip_proof(&cert, canonical, "distributed-token.thumb");
        let path = "/.well-known/acme-challenge/distributed-token";
        assert_eq!(
            handler.handle_http_request("GET", host, path).await,
            Some((200, "distributed-token.thumb".into()))
        );
        solver
            .cleanup(canonical, "distributed-token", "distributed-token.thumb")
            .await
            .unwrap();
        assert_eq!(
            handler.handle_http_request("GET", host, path).await,
            Some((404, String::new()))
        );
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
}

async fn resolver_peer(resolver: Arc<CertResolver>, sni: &'static str) -> Option<Vec<u8>> {
    let mut client = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(challenge_tls::ChallengeVerifier))
        .with_no_client_auth();
    client.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let (client_io, server_io) = tokio::io::duplex(65536);
    let (client, server) = tokio::join!(
        tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(sni.try_into().unwrap(), client_io),
        tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(server_io)
    );
    match client {
        Ok(client) => {
            assert!(server.is_ok());
            Some(client.get_ref().1.peer_certificates().unwrap()[0].to_vec())
        }
        Err(_) => {
            assert!(server.is_err());
            None
        }
    }
}

#[tokio::test]
async fn application_resolver_ip_proof_set_and_remove_share_the_reverse_sni_mapping() {
    certon::install_default_crypto_provider();
    for (input, canonical, sni) in [
        ("192.0.2.9", "192.0.2.9", "9.2.0.192.in-addr.arpa"),
        (
            "2001:0DB8:0:0:0:0:0:9",
            "2001:db8::9",
            "9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ),
    ] {
        let auth = "resolver-token.thumb";
        let mut params = rcgen::CertificateParams::new(vec![canonical.into()]).unwrap();
        let mut proof = rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 1, 31],
            [vec![4, 32], Sha256::digest(auth.as_bytes()).to_vec()].concat(),
        );
        proof.set_criticality(true);
        params.custom_extensions.push(proof);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der()).unwrap();
        assert_eq!(
            rcgen::PublicKeyData::subject_public_key_info(&key),
            parsed.public_key().raw
        );
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let key = Arc::new(rustls::sign::CertifiedKey::new(
            vec![certificate.der().clone()],
            certon::handshake::signing_key_from_der(&private).unwrap(),
        ));
        // The proof's critical ACME extension is intentionally unsupported by
        // webpki's ordinary server-certificate parser used by keys_match.
        // The certificate above and the signing key use the same rcgen key;
        // assert_ip_proof additionally verifies its self-signature and contents.
        let resolver = Arc::new(CertResolver::new(CertCache::new(Default::default())));
        resolver.set_challenge_cert(input.into(), key).await;
        let der = resolver_peer(resolver.clone(), sni).await.unwrap();
        assert_ip_proof(&der, canonical, auth);
        resolver.remove_challenge_cert(canonical).await;
        assert!(resolver_peer(resolver, sni).await.is_none());
    }
}
