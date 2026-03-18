//! DNS-01 challenge for wildcard certificates.
//!
//! This example demonstrates how to implement a custom `DnsProvider` trait and
//! use the DNS-01 challenge solver to obtain wildcard certificates.
//!
//! DNS-01 is the only ACME challenge type that supports wildcard certificates
//! (e.g. `*.example.com`). It works by creating a TXT record at
//! `_acme-challenge.example.com` with a value derived from the challenge token.
//!
//! In production, you would implement `DnsProvider` to call your DNS hosting
//! provider's API (e.g. Cloudflare, Route 53, Google Cloud DNS).
//!
//! Usage: cargo run --example dns01_challenge

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use certon::{
    AcmeIssuer, CertResolver, Config, Dns01Solver, DnsProvider, FileStorage, KeyType,
    LETS_ENCRYPT_STAGING, Result, Storage,
};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Custom DNS provider implementation
// ---------------------------------------------------------------------------

/// A DNS provider that stores records in memory (for demonstration purposes).
///
/// In a real application, this would call the API of your DNS hosting provider
/// (e.g. Cloudflare, AWS Route 53, Google Cloud DNS, etc.).
struct ExampleDnsProvider {
    /// In-memory store of TXT records: (zone, name) -> Vec<value>
    records: RwLock<HashMap<(String, String), Vec<String>>>,
}

impl ExampleDnsProvider {
    fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl DnsProvider for ExampleDnsProvider {
    async fn set_record(&self, zone: &str, name: &str, value: &str, ttl: u32) -> Result<()> {
        println!(
            "[DNS] Creating TXT record: zone={}, name={}, value={}, ttl={}",
            zone, name, value, ttl
        );

        // In production, call your DNS API here:
        //   client.create_record(zone, RecordType::TXT, name, value, ttl).await?;

        let mut records = self.records.write().await;
        records
            .entry((zone.to_string(), name.to_string()))
            .or_default()
            .push(value.to_string());

        Ok(())
    }

    async fn delete_record(&self, zone: &str, name: &str, value: &str) -> Result<()> {
        println!(
            "[DNS] Deleting TXT record: zone={}, name={}, value={}",
            zone, name, value
        );

        // In production, call your DNS API here:
        //   client.delete_record(zone, RecordType::TXT, name, value).await?;

        let mut records = self.records.write().await;
        if let Some(values) = records.get_mut(&(zone.to_string(), name.to_string())) {
            values.retain(|v| v != value);
            if values.is_empty() {
                records.remove(&(zone.to_string(), name.to_string()));
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // -- Storage ---------------------------------------------------------------
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new("/tmp/certon-dns01"));

    // -- DNS provider and solver -----------------------------------------------
    let dns_provider = ExampleDnsProvider::new();
    let dns_solver = Dns01Solver::with_timeouts(
        Box::new(dns_provider),
        Duration::from_secs(120), // propagation timeout
        Duration::from_secs(4),   // propagation check interval
    );

    // -- ACME Issuer -----------------------------------------------------------
    // DNS-01 supports wildcard certificates, so we disable HTTP and TLS-ALPN
    // challenges and use only DNS-01.
    let issuer = AcmeIssuer::builder()
        .ca(LETS_ENCRYPT_STAGING)
        .email("admin@example.com")
        .agreed(true)
        .storage(storage.clone())
        .dns01_solver(Arc::new(dns_solver))
        .disable_http_challenge(true)
        .disable_tlsalpn_challenge(true)
        .build();

    // -- Config ----------------------------------------------------------------
    let config = Config::builder()
        .storage(storage)
        .issuers(vec![Arc::new(issuer)])
        .key_type(KeyType::EcdsaP256)
        .build();

    // -- Obtain wildcard certificate -------------------------------------------
    // DNS-01 is the only challenge type that supports wildcard domains.
    let domains = vec!["*.example.com".into(), "example.com".into()];
    println!(
        "Obtaining wildcard certificate for {:?} via DNS-01...",
        domains
    );
    config.manage_sync(&domains).await?;
    println!("Certificate obtained successfully!");

    // -- Build the TLS config --------------------------------------------------
    let resolver = CertResolver::new(config.cache.clone());
    let _tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    println!("TLS config ready for wildcard domain");

    // Start background maintenance for certificate renewal.
    let _maintenance = certon::start_maintenance(&config);

    // Keep the process alive for certificate maintenance.
    tokio::signal::ctrl_c().await.ok();
    config.cache.stop();

    Ok(())
}
