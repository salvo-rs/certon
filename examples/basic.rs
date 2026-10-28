//! Basic certificate management with default settings.
//!
//! This example obtains and manages TLS certificates for the specified domains
//! using Let's Encrypt with default settings. It demonstrates the simplest
//! possible usage of certon: a single function call that handles everything.
//!
//! Usage after reviewing the CA terms: cargo run --example basic -- --agree-ca-terms

use certon::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let domains = vec!["example.com".into(), "www.example.com".into()];

    // Review the CA terms before running with --agree-ca-terms.
    let agreed = std::env::args().any(|arg| arg == "--agree-ca-terms");

    // The simplest way: one function call.
    //
    // `certon::manage` will:
    //   1. Create a CertManager backed by the default FileStorage.
    //   2. Obtain (or load from storage) certificates for every domain.
    //   3. Return a rustls::ServerConfig wired up with a CertResolver.
    let tls_config = certon::manage_with_agreement(&domains, agreed).await?;

    // Use tls_config with your TLS server.
    // For example, with tokio-rustls:
    //
    //   use std::sync::Arc;
    //   use tokio::net::TcpListener;
    //   use tokio_rustls::TlsAcceptor;
    //
    //   let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    //   let listener = TcpListener::bind("0.0.0.0:443").await?;
    //   loop {
    //       let (stream, _) = listener.accept().await?;
    //       let tls_stream = acceptor.accept(stream).await?;
    //       // handle connection...
    //   }

    println!("TLS config ready for domains: {:?}", domains);
    println!("ALPN protocols: {:?}", tls_config.alpn_protocols);

    // Keep the process alive. For scheduled renewal, use CertManager with
    // certon::start_maintenance and keep its handle/cache for shutdown.
    tokio::signal::ctrl_c().await.ok();
    Ok(())
}
