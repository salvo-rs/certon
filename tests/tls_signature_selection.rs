use std::sync::{Arc, Mutex};

use certon::{CacheOptions, CertCache, CertResolver, Certificate};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, SignatureScheme};

fn certificate(names: &[&str], ed25519: bool, expiry: i32) -> Certificate {
    let algorithm = if ed25519 {
        &rcgen::PKCS_ED25519
    } else {
        &rcgen::PKCS_ECDSA_P256_SHA256
    };
    let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(expiry, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    Certificate::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
}

#[derive(Debug)]
struct RecordingResolver {
    inner: CertResolver,
    selections: Mutex<Vec<Option<Vec<u8>>>>,
}

impl ResolvesServerCert for RecordingResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let result = self.inner.resolve(hello);
        self.selections
            .lock()
            .unwrap()
            .push(result.as_ref().map(|key| key.cert[0].to_vec()));
        result
    }
}

fn handshake(
    resolver: CertResolver,
    trusted: &[&Certificate],
    scheme: SignatureScheme,
    sni: bool,
    acme: bool,
) -> (Result<Vec<u8>, rustls::Error>, Arc<RecordingResolver>) {
    certon::install_default_crypto_provider();
    let mut provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap()
        .as_ref()
        .clone();
    // Keep certificate-chain verification unchanged; restrict only the schemes
    // advertised for the actual TLS handshake.
    provider.signature_verification_algorithms.mapping = std::slice::from_ref(
        provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(supported, _)| *supported == scheme)
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    for cert in trusted {
        roots.add(cert.cert_chain[0].clone()).unwrap();
    }
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.enable_sni = sni;
    let resolver = Arc::new(RecordingResolver {
        inner: resolver,
        selections: Mutex::new(Vec::new()),
    });
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    if acme {
        client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
        server_config.alpn_protocols = client_config.alpn_protocols.clone();
    }
    let mut client =
        ClientConnection::new(Arc::new(client_config), "example.com".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let result = (|| {
        for _ in 0..10 {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut std::io::Cursor::new(bytes)).unwrap();
            server.process_new_packets()?;
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut std::io::Cursor::new(bytes)).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(client.peer_certificates().unwrap()[0].to_vec());
            }
        }
        panic!("TLS handshake did not complete");
    })();
    (result, resolver)
}

#[tokio::test]
async fn same_domain_uses_compatible_certificate_before_comparing_expiry() {
    let ecdsa = certificate(&["example.com"], false, 2040);
    let ed25519 = certificate(&["example.com"], true, 2050);
    for reverse in [false, true] {
        let cache = CertCache::new(CacheOptions::default());
        for cert in if reverse {
            [&ed25519, &ecdsa]
        } else {
            [&ecdsa, &ed25519]
        } {
            cache.add(cert.clone()).await;
        }
        for (scheme, expected) in [
            (SignatureScheme::ECDSA_NISTP256_SHA256, &ecdsa),
            (SignatureScheme::ED25519, &ed25519),
        ] {
            let (result, _) = handshake(
                CertResolver::new(cache.clone()),
                &[&ecdsa, &ed25519],
                scheme,
                true,
                false,
            );
            assert_eq!(result.unwrap(), expected.cert_chain[0].as_ref());
        }
    }
}

#[tokio::test]
async fn incompatible_primary_does_not_hide_a_compatible_fallback() {
    let primary = certificate(&["primary.example.com"], true, 2050);
    let ecdsa = certificate(&["example.com"], false, 2040);
    let ed25519 = certificate(&["example.com"], true, 2050);
    let cache = CertCache::new(CacheOptions::default());
    for cert in [&primary, &ecdsa, &ed25519] {
        cache.add(cert.clone()).await;
    }
    let mut resolver = CertResolver::new(cache);
    resolver.set_default_server_name(Some("primary.example.com".into()));
    resolver.set_fallback_server_name(Some("example.com".into()));
    let (result, _) = handshake(
        resolver,
        &[&ecdsa],
        SignatureScheme::ECDSA_NISTP256_SHA256,
        false,
        false,
    );
    assert_eq!(result.unwrap(), ecdsa.cert_chain[0].as_ref());
}

#[tokio::test]
async fn default_certificate_is_checked_after_incompatible_cache_candidates() {
    let ecdsa = certificate(&["example.com"], false, 2040);
    let ed25519 = certificate(&["example.com"], true, 2050);
    let cache = CertCache::new(CacheOptions::default());
    cache.add(ed25519.clone()).await;
    let resolver = CertResolver::new(cache);
    resolver
        .set_default_cert(certon::handshake::cert_to_certified_key(&ecdsa).unwrap())
        .await;
    let (result, _) = handshake(
        resolver,
        &[&ecdsa],
        SignatureScheme::ECDSA_NISTP256_SHA256,
        true,
        false,
    );
    assert_eq!(result.unwrap(), ecdsa.cert_chain[0].as_ref());
}

#[tokio::test]
async fn incompatible_default_is_not_returned_without_sni() {
    let ecdsa = certificate(&["example.com"], false, 2040);
    let resolver = CertResolver::new(CertCache::new(CacheOptions::default()));
    resolver
        .set_default_cert(certon::handshake::cert_to_certified_key(&ecdsa).unwrap())
        .await;
    let (result, recording) =
        handshake(resolver, &[&ecdsa], SignatureScheme::ED25519, false, false);
    assert!(result.is_err());
    assert_eq!(*recording.selections.lock().unwrap(), vec![None]);
}

#[tokio::test]
async fn acme_challenge_checks_schemes_without_falling_back_to_regular_certificates() {
    let ecdsa = certificate(&["example.com"], false, 2040);
    let ed25519 = certificate(&["example.com"], true, 2050);
    for scheme in [
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
    ] {
        let cache = CertCache::new(CacheOptions::default());
        cache.add(ed25519.clone()).await;
        let resolver = CertResolver::new(cache);
        resolver
            .set_challenge_cert(
                "example.com".into(),
                certon::handshake::cert_to_certified_key(&ecdsa).unwrap(),
            )
            .await;
        let (result, recording) = handshake(resolver, &[&ecdsa, &ed25519], scheme, true, true);
        if scheme == SignatureScheme::ECDSA_NISTP256_SHA256 {
            assert_eq!(result.unwrap(), ecdsa.cert_chain[0].as_ref());
        } else {
            assert!(result.is_err());
            assert_eq!(*recording.selections.lock().unwrap(), vec![None]);
        }
    }
}
