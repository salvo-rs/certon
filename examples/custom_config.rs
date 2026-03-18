//! Custom configuration with the ConfigBuilder.
//!
//! This example shows how to use `Config::builder()` with custom settings,
//! multiple issuers, a specific key type, OCSP configuration, and event
//! callbacks. It also demonstrates starting background certificate maintenance.
//!
//! Usage: cargo run --example custom_config

use std::sync::Arc;

use certon::{
    AcmeIssuer, CertResolver, Config, FileStorage, KeyType, LETS_ENCRYPT_STAGING, OcspConfig,
    Result, Storage,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // -- Storage ---------------------------------------------------------------
    // Use a custom directory for certificate storage.
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new("/tmp/certon-example"));

    // -- Issuers ---------------------------------------------------------------
    // Configure the Let's Encrypt staging issuer (use staging for testing to
    // avoid rate limits).
    let le_staging = AcmeIssuer::builder()
        .ca(LETS_ENCRYPT_STAGING)
        .email("admin@example.com")
        .agreed(true)
        .storage(storage.clone())
        .cert_key_type(KeyType::EcdsaP256)
        .build();

    // You can configure multiple issuers. The Config will try each one in
    // order until one succeeds.
    let issuers: Vec<Arc<dyn certon::acme_issuer::CertIssuer>> = vec![Arc::new(le_staging)];

    // -- OCSP ------------------------------------------------------------------
    let ocsp = OcspConfig {
        disable_stapling: false,
        replace_revoked: true,
        responder_overrides: Default::default(),
    };

    // -- Event callback --------------------------------------------------------
    // Receive lifecycle events (cert_obtaining, cert_obtained, cert_failed, etc.)
    let on_event: Arc<dyn Fn(&str, &serde_json::Value) -> Result<()> + Send + Sync> =
        Arc::new(|event_name, data| {
            println!("[event] {}: {}", event_name, data);
            Ok(())
        });

    // -- Build the Config ------------------------------------------------------
    let config = Config::builder()
        .storage(storage)
        .issuers(issuers)
        .key_type(KeyType::EcdsaP256)
        .ocsp(ocsp)
        .renewal_window_ratio(1.0 / 3.0) // renew when 1/3 of lifetime remains
        .on_event(on_event)
        .interactive(false) // non-interactive (background retries)
        .build();

    // -- Manage domains --------------------------------------------------------
    let domains = vec!["example.com".into(), "www.example.com".into()];
    config.manage_sync(&domains).await?;

    // -- Build the TLS server config -------------------------------------------
    let resolver = CertResolver::new(config.cache.clone());
    let _tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    println!("TLS config ready with custom settings");
    println!("  Key type: {:?}", config.key_type);
    println!("  Renewal ratio: {}", config.renewal_window_ratio);
    println!("  Issuers: {}", config.issuers.len());

    // -- Start background maintenance ------------------------------------------
    // This spawns a task that periodically renews certificates and refreshes
    // OCSP staples.
    let _maintenance_handle = certon::start_maintenance(&config);

    // Keep the process alive for certificate maintenance.
    tokio::signal::ctrl_c().await.ok();

    // Gracefully stop maintenance when shutting down.
    config.cache.stop();

    Ok(())
}
