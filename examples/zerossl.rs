//! Using ZeroSSL as the Certificate Authority.
//!
//! This example demonstrates how to use `ZeroSslIssuer` with an API key to
//! obtain certificates from ZeroSSL. ZeroSSL requires External Account Binding
//! (EAB) for ACME, which is handled automatically by `ZeroSslIssuer` using
//! the provided API key.
//!
//! To get a ZeroSSL API key:
//!   1. Create an account at https://zerossl.com
//!   2. Go to the Developer section
//!   3. Copy your API key
//!
//! Set the ZEROSSL_API_KEY environment variable before running this example.
//!
//! Usage: ZEROSSL_API_KEY=your_key cargo run --example zerossl

use std::sync::Arc;

use certon::{CertResolver, Config, FileStorage, KeyType, Result, Storage, ZeroSslIssuer};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // -- Read the API key from the environment ---------------------------------
    let api_key = std::env::var("ZEROSSL_API_KEY").unwrap_or_else(|_| {
        eprintln!("Error: ZEROSSL_API_KEY environment variable is not set.");
        eprintln!();
        eprintln!("To get a ZeroSSL API key:");
        eprintln!("  1. Create an account at https://zerossl.com");
        eprintln!("  2. Go to the Developer section");
        eprintln!("  3. Copy your API key");
        eprintln!();
        eprintln!("Then run: ZEROSSL_API_KEY=your_key cargo run --example zerossl");
        std::process::exit(1);
    });

    // -- Storage ---------------------------------------------------------------
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new("/tmp/certon-zerossl"));

    // -- ZeroSSL Issuer --------------------------------------------------------
    // The builder fetches EAB credentials from ZeroSSL's API automatically
    // using the provided API key. This is an async operation.
    let zerossl_issuer = ZeroSslIssuer::builder()
        .api_key(&api_key)
        .email("admin@example.com")
        .storage(storage.clone())
        .cert_key_type(KeyType::EcdsaP256)
        .build()
        .await?;

    println!("ZeroSSL issuer created successfully (EAB credentials obtained)");

    // -- Config ----------------------------------------------------------------
    let config = Config::builder()
        .storage(storage)
        .issuers(vec![Arc::new(zerossl_issuer)])
        .key_type(KeyType::EcdsaP256)
        .build();

    // -- Manage certificates ---------------------------------------------------
    let domains = vec!["example.com".into()];
    println!("Obtaining certificate from ZeroSSL for {:?}...", domains);
    config.manage_sync(&domains).await?;
    println!("Certificate obtained from ZeroSSL!");

    // -- Build the TLS config --------------------------------------------------
    let resolver = CertResolver::new(config.cache.clone());
    let _tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    println!("TLS config ready with ZeroSSL certificate");

    // Start background maintenance for certificate renewal.
    let _maintenance = certon::start_maintenance(&config);

    // Keep the process alive for certificate maintenance.
    tokio::signal::ctrl_c().await.ok();
    config.cache.stop();

    Ok(())
}
