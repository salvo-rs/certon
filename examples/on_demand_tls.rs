//! On-demand TLS certificate issuance.
//!
//! This example demonstrates how to configure on-demand TLS, where certificates
//! are obtained automatically at TLS handshake time for previously unknown
//! domains. This is useful for SaaS platforms, reverse proxies, or any
//! application that serves many customer domains.
//!
//! On-demand TLS MUST be protected by at least one gating mechanism:
//!   - A `host_allowlist` that explicitly lists allowed domains, or
//!   - A `decision_func` that programmatically decides whether to issue.
//!
//! Without gating, an attacker could force your server to obtain certificates
//! for arbitrary domains, exhausting your CA rate limits.
//!
//! Usage: cargo run --example on_demand_tls

use std::collections::HashSet;
use std::sync::Arc;

use certon::{CertResolver, Config, FileStorage, OnDemandConfig, Result, Storage};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // -- Storage ---------------------------------------------------------------
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::new("/tmp/certon-ondemand"));

    // -- Build a host allowlist ------------------------------------------------
    // Only allow certificate issuance for these domains.
    let mut allowlist = HashSet::new();
    allowlist.insert("customer1.example.com".to_string());
    allowlist.insert("customer2.example.com".to_string());
    allowlist.insert("app.example.com".to_string());

    // -- On-demand config with allowlist ---------------------------------------
    let on_demand_allowlist = Arc::new(OnDemandConfig {
        decision_func: None,
        host_allowlist: Some(allowlist),
        rate_limit: None,
        obtain_func: None,
    });

    // -- Alternatively, use a decision function --------------------------------
    // A decision function can implement more complex logic, such as checking a
    // database of valid customer domains.
    let _on_demand_decision = Arc::new(OnDemandConfig {
        decision_func: Some(Arc::new(|hostname: &str| -> bool {
            // Example: allow any subdomain of example.com
            if hostname.ends_with(".example.com") {
                println!("[on-demand] Allowing certificate for: {hostname}");
                return true;
            }
            println!("[on-demand] Denying certificate for: {hostname}");
            false
        })),
        host_allowlist: None,
        rate_limit: None,
        obtain_func: None,
    });

    // -- Build the Config with on-demand TLS -----------------------------------
    let config = Config::builder()
        .storage(storage)
        .on_demand(on_demand_allowlist)
        .build();

    // -- Build the TLS config with on-demand resolver --------------------------
    // The CertResolver supports on-demand TLS: when a TLS handshake arrives
    // for an unknown domain, it triggers background certificate acquisition.
    // The first handshake for a new domain may fail (or use a default cert),
    // but subsequent handshakes will succeed once the certificate is cached.
    let on_demand_for_resolver = Arc::new(OnDemandConfig {
        decision_func: Some(Arc::new(|hostname: &str| -> bool {
            // Re-check allowlist logic in the resolver as well.
            hostname.ends_with(".example.com")
        })),
        host_allowlist: None,
        rate_limit: None,
        // The obtain function is called when a certificate needs to be
        // obtained for a new domain. It should use the Config to manage
        // the domain.
        obtain_func: None, // Will be wired up below
    });

    let resolver = CertResolver::with_on_demand(config.cache.clone(), on_demand_for_resolver);

    let _tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    println!("On-demand TLS server ready");
    println!("Allowed domains will get certificates automatically on first TLS handshake");

    // Start background maintenance for certificate renewal.
    let _maintenance = certon::start_maintenance(&config);

    // Keep the process alive.
    tokio::signal::ctrl_c().await.ok();
    config.cache.stop();

    Ok(())
}
