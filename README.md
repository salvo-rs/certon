# CertAuto

**Automatic HTTPS/TLS certificate management for Rust, powered by the ACME protocol.**

<!-- badges -->
[![Crates.io](https://img.shields.io/crates/v/certauto.svg)](https://crates.io/crates/certauto)
[![Documentation](https://docs.rs/certauto/badge.svg)](https://docs.rs/certauto)
[![License](https://img.shields.io/crates/l/certauto.svg)](LICENSE)

**English** | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md)

CertAuto brings production-grade automatic certificate management to Rust programs: obtain, renew, and serve TLS certificates from any ACME-compatible Certificate Authority, with just a few lines of code.

```rust
use certauto::Config;

#[tokio::main]
async fn main() -> certauto::Result<()> {
    let domains = vec!["example.com".into()];
    let tls_config = certauto::manage(&domains).await?;
    // Use tls_config with tokio-rustls, hyper, axum, salvo, etc.
    Ok(())
}
```

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
  - [Basic -- Manage Certificates with Defaults](#basic--manage-certificates-with-defaults)
  - [Custom CA and Email](#custom-ca-and-email)
  - [DNS-01 Challenge (Wildcard Certificates)](#dns-01-challenge-wildcard-certificates)
  - [ZeroSSL](#zerossl)
  - [Custom Storage Backend](#custom-storage-backend)
  - [On-Demand TLS](#on-demand-tls)
  - [Event Callbacks](#event-callbacks)
- [Architecture Overview](#architecture-overview)
- [The ACME Challenges](#the-acme-challenges)
  - [HTTP-01 Challenge](#http-01-challenge)
  - [TLS-ALPN-01 Challenge](#tls-alpn-01-challenge)
  - [DNS-01 Challenge](#dns-01-challenge)
- [Storage](#storage)
- [Certificate Maintenance](#certificate-maintenance)
- [On-Demand TLS (Detailed)](#on-demand-tls-detailed)
- [API Reference](#api-reference)
- [License](#license)

---

## Features

- **Fully automatic certificate management** -- obtain, renew, and cache TLS certificates without manual intervention
- **All three ACME challenge types** -- HTTP-01, TLS-ALPN-01, and DNS-01
- **Multiple CA support** -- Let's Encrypt (production and staging), ZeroSSL, Google Trust Services, or any ACME-compliant CA
- **OCSP stapling** -- automatic OCSP response fetching and stapling for improved privacy and performance; staples are persisted to storage across restarts
- **Wildcard certificates** -- via the DNS-01 challenge with a pluggable `DnsProvider` trait
- **On-demand TLS** -- obtain certificates at handshake time for previously unknown domains, with configurable allowlists, decision functions, and rate limiting
- **Certificate caching** -- in-memory `CertCache` with domain name indexing and wildcard matching for fast TLS handshake lookups
- **Configurable key types** -- ECDSA P-256 (default), ECDSA P-384, RSA 2048, RSA 4096, and Ed25519
- **Background maintenance** -- automatic renewal checks (every 10 minutes) and OCSP staple refresh (every hour)
- **Built-in rate limiting** -- prevents overwhelming CAs with too many requests
- **Retry with exponential backoff** -- failed certificate operations are retried with increasing delays (up to 30 days)
- **Distributed challenge solving** -- `DistributedSolver` coordinates challenges across multiple instances via shared `Storage`, enabling clustered deployments behind load balancers
- **File system storage with atomic writes** -- default `FileStorage` uses write-to-temp-then-rename for crash safety; distributed lock files with background keepalive for cluster coordination
- **Custom storage backends** -- implement the `Storage` trait to use databases, KV stores, or any other persistence layer
- **Event callbacks** -- observe certificate lifecycle events (`cert_obtaining`, `cert_obtained`, `cert_renewed`, `cert_failed`, `cert_revoked`, etc.)
- **Builder pattern** -- ergonomic `Config::builder()`, `AcmeIssuer::builder()`, and `ZeroSslIssuer::builder()` for easy configuration
- **External Account Binding (EAB)** -- first-class support for CAs that require EAB (e.g., ZeroSSL)
- **Certificate chain preference** -- select preferred chains by root/issuer Common Name or chain size
- **Certificate revocation** -- revoke compromised certificates via the ACME protocol
- **Native rustls integration** -- `CertResolver` implements `rustls::server::ResolvesServerCert` and plugs directly into any rustls-based server

## Requirements

1. **Rust 2021 edition** with a Tokio async runtime
2. **Public DNS name(s)** you control, pointed (A/AAAA records) at your server
3. **Port 80** accessible from the public internet (for HTTP-01 challenge), and/or **port 443** (for TLS-ALPN-01 challenge)
   - These can be forwarded to other ports you control
   - Or use the DNS-01 challenge to waive both requirements entirely
   - This is a requirement of the ACME protocol, not a library limitation
4. **Persistent storage** for certificates, keys, and metadata
   - Default: local file system (`~/.local/share/certauto` on Linux, `~/Library/Application Support/certauto` on macOS, `%APPDATA%/certauto` on Windows)
   - Custom backends available via the `Storage` trait

> **Before using this library, your domain names MUST be pointed (A/AAAA records) at your server (unless you use the DNS-01 challenge).**

## Installation

Add `certauto` to your `Cargo.toml`:

```toml
[dependencies]
certauto = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

The simplest way to get started -- one function call manages everything:

```rust
use certauto::Config;

#[tokio::main]
async fn main() -> certauto::Result<()> {
    let domains = vec!["example.com".into()];

    // Obtain (or load from storage) certificates and return a
    // rustls::ServerConfig ready for use with any TLS server.
    let tls_config = certauto::manage(&domains).await?;

    // Use tls_config with tokio-rustls, hyper, axum, salvo, etc.
    Ok(())
}
```

This will:
1. Create a `FileStorage` in the default OS-specific directory.
2. Obtain certificates from Let's Encrypt (production) for the given domains.
3. Return a `rustls::ServerConfig` wired up with a `CertResolver` that serves the managed certificates.

## Usage Examples

### Basic -- Manage Certificates with Defaults

```rust
use std::sync::Arc;
use certauto::{Config, FileStorage, Storage};

#[tokio::main]
async fn main() -> certauto::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
    let config = Config::builder()
        .storage(storage)
        .build();

    let domains = vec!["example.com".into(), "www.example.com".into()];
    config.manage_sync(&domains).await?;

    // Start background maintenance (renewal + OCSP refresh).
    let _handle = certauto::start_maintenance(&config);

    Ok(())
}
```

### Custom CA and Email

```rust
use std::sync::Arc;
use certauto::{
    AcmeIssuer, Config, FileStorage, Storage,
    LETS_ENCRYPT_STAGING,
};

let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());

let issuer = AcmeIssuer::builder()
    .ca(LETS_ENCRYPT_STAGING) // Use staging while developing!
    .email("admin@example.com")
    .agreed(true)
    .storage(storage.clone())
    .build();

let config = Config::builder()
    .storage(storage)
    .issuers(vec![Arc::new(issuer)])
    .build();
```

### DNS-01 Challenge (Wildcard Certificates)

The DNS-01 challenge is required for wildcard certificates and works even when your server is not publicly accessible.

```rust
use std::sync::Arc;
use certauto::{AcmeIssuer, Dns01Solver, DnsProvider};

// Implement DnsProvider for your DNS service (Cloudflare, Route53, etc.)
let dns_solver = Arc::new(Dns01Solver::new(
    Box::new(my_dns_provider),
));

let issuer = AcmeIssuer::builder()
    .dns01_solver(dns_solver)
    .email("admin@example.com")
    .agreed(true)
    .storage(storage.clone())
    .build();

// Now you can obtain wildcard certificates:
let domains = vec!["*.example.com".into()];
```

To implement a DNS provider, implement the `DnsProvider` trait:

```rust
use async_trait::async_trait;
use certauto::{DnsProvider, Result};

struct MyDnsProvider { /* ... */ }

#[async_trait]
impl DnsProvider for MyDnsProvider {
    async fn set_record(
        &self, zone: &str, name: &str, value: &str, ttl: u32,
    ) -> Result<()> {
        // Create a TXT record via your DNS provider's API
        Ok(())
    }

    async fn delete_record(
        &self, zone: &str, name: &str, value: &str,
    ) -> Result<()> {
        // Delete the TXT record
        Ok(())
    }
}
```

### ZeroSSL

ZeroSSL provides free certificates via ACME with External Account Binding. CertAuto handles EAB provisioning automatically using your ZeroSSL API key.

```rust
use std::sync::Arc;
use certauto::{Config, FileStorage, Storage, ZeroSslIssuer};

let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());

let issuer = ZeroSslIssuer::builder()
    .api_key("your-zerossl-api-key")
    .email("admin@example.com")
    .storage(storage.clone())
    .build()
    .await?;

let config = Config::builder()
    .storage(storage)
    .issuers(vec![Arc::new(issuer)])
    .build();
```

### Custom Storage Backend

Implement the `Storage` trait to use databases, Redis, S3, or any other persistence layer. All instances sharing the same storage are considered part of the same cluster.

```rust
use async_trait::async_trait;
use certauto::storage::{Storage, KeyInfo};
use certauto::Result;

struct MyDatabaseStorage { /* ... */ }

#[async_trait]
impl Storage for MyDatabaseStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        // Write to your database
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        // Read from your database
        todo!()
    }

    async fn delete(&self, key: &str) -> Result<()> {
        // Delete from your database
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        // Check key existence
        todo!()
    }

    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        // List keys under a prefix
        todo!()
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        // Return metadata for a key
        todo!()
    }

    async fn lock(&self, name: &str) -> Result<()> {
        // Acquire a distributed lock
        Ok(())
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        // Release the distributed lock
        Ok(())
    }
}
```

### On-Demand TLS

On-demand TLS obtains certificates at TLS handshake time for domains that have not been pre-configured. Always gate this with an allowlist or decision function to prevent abuse.

```rust
use std::collections::HashSet;
use std::sync::Arc;
use certauto::OnDemandConfig;

let on_demand = Arc::new(OnDemandConfig {
    host_allowlist: Some(HashSet::from([
        "a.example.com".into(),
        "b.example.com".into(),
    ])),
    decision_func: None,
    rate_limit: None,
    obtain_func: None, // Wired up by Config internally
});

let config = Config::builder()
    .storage(storage)
    .on_demand(on_demand)
    .build();
```

### Event Callbacks

Subscribe to certificate lifecycle events for logging, monitoring, or alerting:

```rust
use std::sync::Arc;

let config = Config::builder()
    .storage(storage)
    .on_event(Arc::new(|event: &str, data: &serde_json::Value| {
        println!("Certificate event: {} {:?}", event, data);
    }))
    .build();
```

Events emitted include:
- `cert_obtaining` -- a certificate obtain operation is starting
- `cert_obtained` -- a certificate was successfully obtained
- `cert_renewed` -- a certificate was successfully renewed
- `cert_failed` -- a certificate obtain or renewal operation failed
- `cert_revoked` -- a certificate was revoked
- `cached_managed_cert` -- a managed certificate was loaded from storage into cache

## Architecture Overview

```
                    +-----------+
                    |  Config   |  Central coordinator
                    +-----+-----+
                          |
          +---------------+---------------+
          |               |               |
    +-----v-----+   +----v----+   +------v------+
    |  Issuer   |   |  Cache  |   |   Storage   |
    +-----------+   +---------+   +-------------+
          |               |               |
    +-----v-----+   +----v--------+  +---v-----------+
    | AcmeIssuer|   | CertResolver|  | FileStorage   |
    | ZeroSSL   |   | (rustls)    |  | (or custom)   |
    +-----------+   +-------------+  +---------------+
          |
    +-----v-------+
    |  AcmeClient  |----> ACME CA (Let's Encrypt, ZeroSSL, etc.)
    +--------------+

    +------------------+
    | start_maintenance| ---> Renewal loop (every 10 min)
    |                  | ---> OCSP refresh loop (every 1 hr)
    +------------------+
```

**Key components:**

| Component | Role |
|---|---|
| `Config` | Central entry point; coordinates obtain, renew, revoke, and cache operations |
| `AcmeIssuer` / `ZeroSslIssuer` | Implement the `Issuer` trait; drive the ACME protocol flow |
| `AcmeClient` | Low-level ACME HTTP client (directory, nonce, JWS signing, order management) |
| `CertCache` | In-memory certificate store indexed by domain name (with wildcard matching) |
| `CertResolver` | Implements `rustls::server::ResolvesServerCert`; resolves certificates during TLS handshakes |
| `Storage` / `FileStorage` | Persistent key-value storage with distributed locking |
| `start_maintenance` | Background tokio task for automatic renewal and OCSP refresh |

## The ACME Challenges

The ACME protocol verifies domain ownership through challenges. CertAuto supports all three standard challenge types.

### HTTP-01 Challenge

The HTTP-01 challenge proves control of a domain by serving a specific token at `http://<domain>/.well-known/acme-challenge/<token>` on **port 80**.

CertAuto's `Http01Solver` starts a lightweight HTTP server that automatically serves the challenge response. The server is started when a challenge is presented and stopped when the challenge completes.

```rust
use certauto::Http01Solver;

let solver = Http01Solver::new(80); // or Http01Solver::default()
```

**Requirements:** Port 80 must be accessible from the public internet (directly or via port forwarding).

### TLS-ALPN-01 Challenge

The TLS-ALPN-01 challenge proves control of a domain by presenting a self-signed certificate with a special `acmeIdentifier` extension during a TLS handshake on **port 443**, negotiated via the `acme-tls/1` ALPN protocol.

CertAuto's `TlsAlpn01Solver` handles this by generating an ephemeral challenge certificate and serving it on a temporary TLS listener.

```rust
use certauto::TlsAlpn01Solver;

let solver = TlsAlpn01Solver::new(443); // or TlsAlpn01Solver::default()
```

**Requirements:** Port 443 must be accessible from the public internet. This is often the most convenient challenge type because it uses the same port as your production TLS server.

### DNS-01 Challenge

The DNS-01 challenge proves control of a domain by creating a specific TXT record at `_acme-challenge.<domain>`. This is the **only** challenge type that supports wildcard certificates and does not require your server to be publicly accessible.

CertAuto's `Dns01Solver` accepts a `DnsProvider` implementation that creates and deletes TXT records via your DNS provider's API. It automatically waits for DNS propagation before notifying the CA.

```rust
use certauto::Dns01Solver;

let solver = Dns01Solver::new(Box::new(my_cloudflare_provider));
// With custom propagation settings:
let solver = Dns01Solver::with_timeouts(
    Box::new(my_provider),
    std::time::Duration::from_secs(180),  // propagation timeout
    std::time::Duration::from_secs(5),    // check interval
);
```

**Requirements:** A DNS provider with an API, and an implementation of the `DnsProvider` trait.

## Storage

CertAuto requires persistent storage for certificates, private keys, metadata, OCSP staples, and lock files. Storage is abstracted behind the `Storage` trait, making it easy to swap backends.

**Default: `FileStorage`**

The built-in `FileStorage` stores everything on the local file system with these properties:

- **Atomic writes** -- data is written to a temporary file, then atomically renamed into place, preventing partial reads
- **Distributed locking** -- lock files contain a JSON timestamp refreshed by a background keepalive task every 5 seconds; stale locks (older than 10 seconds) are automatically broken
- **Platform-aware paths** -- defaults to `~/.local/share/certauto` (Linux), `~/Library/Application Support/certauto` (macOS), or `%APPDATA%/certauto` (Windows)

**Clustering:** Any instances sharing the same storage backend are considered part of the same cluster. For `FileStorage`, mounting a shared network folder is sufficient. For custom backends, ensure that all instances point to the same database/service.

**Storage layout:**

```
<root>/
  certificates/<issuer>/<domain>/
    <domain>.crt    -- PEM certificate chain
    <domain>.key    -- PEM private key
    <domain>.json   -- metadata (SANs, issuer info)
  ocsp/
    <domain>-<hash> -- cached OCSP responses
  acme/<issuer>/
    users/<email>/  -- ACME account data
  locks/
    <name>.lock     -- distributed lock files
```

## Certificate Maintenance

CertAuto runs background maintenance via `certauto::start_maintenance()`, which spawns a tokio task performing two periodic loops:

1. **Renewal loop** (every 10 minutes by default) -- iterates all managed certificates in the cache and renews any that have entered the renewal window (by default, when less than 1/3 of the certificate lifetime remains)

2. **OCSP refresh loop** (every 1 hour by default) -- fetches fresh OCSP responses for all cached certificates and persists them to storage

Both loops respect the `CertCache::stop()` signal for graceful shutdown.

```rust
let config = Config::builder().storage(storage).build();

// Start background maintenance.
let handle = certauto::start_maintenance(&config);

// ... later, to stop gracefully:
// config.cache.stop();
// handle.await;
```

## On-Demand TLS (Detailed)

On-demand TLS obtains certificates during TLS handshakes for domains that were not pre-configured. When a `ClientHello` arrives with an unknown SNI value, the `CertResolver` can trigger background certificate acquisition so that subsequent handshakes for the same domain succeed.

This is powerful but must be gated carefully to prevent abuse:

| Gate | Description |
|---|---|
| `host_allowlist` | A `HashSet<String>` of permitted hostnames (case-insensitive) |
| `decision_func` | A closure `Fn(&str) -> bool` for dynamic allow/deny logic |
| `rate_limit` | An optional `RateLimiter` to throttle issuance |

If neither `decision_func` nor `host_allowlist` is configured, on-demand issuance is **denied** (fail-closed) to prevent unbounded certificate requests.

Because `rustls::server::ResolvesServerCert::resolve` is synchronous, on-demand acquisition is spawned in the background. The current handshake receives the default certificate (or `None`); the next handshake for the same domain will find the certificate in cache.

## API Reference

Full API documentation is available on [docs.rs](https://docs.rs/certauto).

Key entry points:

- [`certauto::manage()`](https://docs.rs/certauto/latest/certauto/fn.manage.html) -- highest-level function, returns a ready-to-use `rustls::ServerConfig`
- [`Config::builder()`](https://docs.rs/certauto/latest/certauto/struct.ConfigBuilder.html) -- configure and build a `Config`
- [`AcmeIssuer::builder()`](https://docs.rs/certauto/latest/certauto/struct.AcmeIssuerBuilder.html) -- configure an ACME issuer
- [`Storage` trait](https://docs.rs/certauto/latest/certauto/trait.Storage.html) -- implement custom storage backends
- [`Solver` trait](https://docs.rs/certauto/latest/certauto/trait.Solver.html) -- implement custom challenge solvers
- [`DnsProvider` trait](https://docs.rs/certauto/latest/certauto/trait.DnsProvider.html) -- implement DNS providers for DNS-01 challenges

## Development and Testing

Let's Encrypt imposes [strict rate limits](https://letsencrypt.org/docs/rate-limits/) on its production endpoint. During development, always use the **staging** endpoint:

```rust
use certauto::LETS_ENCRYPT_STAGING;

let issuer = AcmeIssuer::builder()
    .ca(LETS_ENCRYPT_STAGING)
    .email("dev@example.com")
    .agreed(true)
    .storage(storage.clone())
    .build();
```

Staging certificates are not publicly trusted, but the rate limits are much more generous.

## License

CertAuto is licensed under the [Apache License 2.0](LICENSE).
