//! HTTP-01 challenge with a simple TCP server.
//!
//! This example demonstrates setting up an HTTP-01 challenge solver to obtain
//! a certificate from Let's Encrypt (staging), then serving HTTPS on port 443
//! with tokio-rustls. The HTTP-01 solver runs a lightweight HTTP server on
//! port 80 to respond to the CA's validation requests.
//!
//! In production you would use port 80 for the challenge server and port 443
//! for your HTTPS application. Make sure both ports are open and DNS for
//! your domain points to this server.
//!
//! Usage: cargo run --example http01_challenge

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use certon::{
    AcmeIssuer, CertResolver, Config, FileStorage, Http01Solver, KeyType, Result, Storage,
    LETS_ENCRYPT_STAGING,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // -- Storage ---------------------------------------------------------------
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new("/tmp/certon-http01"));

    // -- HTTP-01 solver --------------------------------------------------------
    // The HTTP-01 solver listens on port 80 and serves the ACME challenge token
    // at /.well-known/acme-challenge/{token}. The CA will make an HTTP request
    // to this endpoint to verify domain ownership.
    let http01_solver = Arc::new(Http01Solver::new(80));

    // -- ACME Issuer -----------------------------------------------------------
    // Using Let's Encrypt staging to avoid rate limits during testing.
    // Switch to LETS_ENCRYPT_PRODUCTION for real certificates.
    let issuer = AcmeIssuer::builder()
        .ca(LETS_ENCRYPT_STAGING)
        .email("admin@example.com")
        .agreed(true)
        .storage(storage.clone())
        .http01_solver(http01_solver)
        // Disable TLS-ALPN-01 since we are using HTTP-01
        .disable_tlsalpn_challenge(true)
        .build();

    // -- Config ----------------------------------------------------------------
    let config = Config::builder()
        .storage(storage)
        .issuers(vec![Arc::new(issuer)])
        .key_type(KeyType::EcdsaP256)
        .build();

    // -- Obtain certificates ---------------------------------------------------
    let domains = vec!["example.com".into()];
    println!("Obtaining certificate for {:?} via HTTP-01 challenge...", domains);
    config.manage_sync(&domains).await?;
    println!("Certificate obtained successfully!");

    // -- Build the TLS config --------------------------------------------------
    let resolver = CertResolver::new(config.cache.clone());
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    // -- Start HTTPS server on port 443 ----------------------------------------
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("0.0.0.0:443").await.map_err(|e| {
        certon::Error::Other(format!("failed to bind HTTPS listener: {e}"))
    })?;

    println!("HTTPS server listening on 0.0.0.0:443");

    // Start background maintenance for certificate renewal.
    let _maintenance = certon::start_maintenance(&config);

    loop {
        let (stream, peer_addr) = listener.accept().await.map_err(|e| {
            certon::Error::Other(format!("accept error: {e}"))
        })?;

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    println!("TLS connection from {peer_addr}");

                    // Read the request (simplified: just read and respond).
                    let mut buf = vec![0u8; 4096];
                    let _ = tls_stream.read(&mut buf).await;

                    let response = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: text/plain\r\n\
                        Content-Length: 13\r\n\
                        Connection: close\r\n\
                        \r\n\
                        Hello, HTTPS!";

                    let _ = tls_stream.write_all(response).await;
                    let _ = tls_stream.shutdown().await;
                }
                Err(e) => {
                    eprintln!("TLS handshake failed with {peer_addr}: {e}");
                }
            }
        });
    }
}
