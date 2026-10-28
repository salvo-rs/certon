use std::sync::Arc;

use tokio::net::TcpStream;

#[derive(Debug)]
struct ChallengeVerifier;
impl rustls::client::danger::ServerCertVerifier for ChallengeVerifier {
    // Availability-only test: ACME leaves have a specialized critical
    // extension. This verifier does not assert certificate/signature safety.
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) async fn peer_certificate(stream: TcpStream, domain: &'static str) -> Vec<u8> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ChallengeVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(domain.try_into().unwrap(), stream)
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"acme-tls/1".as_slice())
    );
    tls.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}
