//! Custom storage backend.
//!
//! This example demonstrates how to implement the `Storage` trait for a custom
//! backend. The example uses a simple in-memory HashMap, but in production you
//! could back this with a database (PostgreSQL, Redis, DynamoDB, etc.) for
//! distributed deployments where multiple server instances share certificates.
//!
//! The Storage trait provides:
//! - `store` / `load` / `delete` / `exists` / `list` / `stat` for key-value ops
//! - `lock` / `unlock` for distributed locking during certificate issuance
//!
//! Usage: cargo run --example custom_storage

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use certon::{CertResolver, Config, KeyInfo, Result, Storage};
use chrono::Utc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// In-memory Storage implementation
// ---------------------------------------------------------------------------

/// A simple in-memory storage backend for demonstration.
///
/// In production, you would replace this with calls to your database or
/// distributed key-value store (Redis, PostgreSQL, DynamoDB, etc.).
struct MemoryStorage {
    data: RwLock<HashMap<String, Vec<u8>>>,
    locks: RwLock<HashMap<String, bool>>,
}

impl MemoryStorage {
    fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            locks: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let data = self.data.read().await;
        data.get(key).cloned().ok_or_else(|| {
            certon::Error::Storage(certon::error::StorageError::NotFound(format!(
                "key not found: {key}"
            )))
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.data.write().await;
        // Delete exact key and any keys prefixed by it (directory semantics).
        let prefix = format!("{key}/");
        data.retain(|k, _| k != key && !k.starts_with(&prefix));
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let data = self.data.read().await;
        // Check for exact match or any keys under this prefix.
        let prefix = format!("{key}/");
        Ok(data.contains_key(key) || data.keys().any(|k| k.starts_with(&prefix)))
    }

    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        let data = self.data.read().await;
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };

        let mut results = Vec::new();
        for key in data.keys() {
            if let Some(rest) = key.strip_prefix(&prefix) {
                if recursive || !rest.contains('/') {
                    results.push(key.clone());
                }
            }
        }
        results.sort();
        Ok(results)
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let data = self.data.read().await;
        match data.get(key) {
            Some(value) => Ok(KeyInfo {
                key: key.to_string(),
                modified: Utc::now(),
                size: value.len() as u64,
                is_terminal: true,
            }),
            None => {
                // Check if it is a directory prefix.
                let prefix = format!("{key}/");
                if data.keys().any(|k| k.starts_with(&prefix)) {
                    Ok(KeyInfo {
                        key: key.to_string(),
                        modified: Utc::now(),
                        size: 0,
                        is_terminal: false,
                    })
                } else {
                    Err(certon::Error::Storage(
                        certon::error::StorageError::NotFound(format!("key not found: {key}")),
                    ))
                }
            }
        }
    }

    async fn lock(&self, name: &str) -> Result<()> {
        // Simple spin lock. In production, use a proper distributed lock
        // (e.g. Redis SETNX, PostgreSQL advisory locks, DynamoDB conditional
        // writes, etc.).
        loop {
            {
                let mut locks = self.locks.write().await;
                if !locks.contains_key(name) {
                    locks.insert(name.to_string(), true);
                    return Ok(());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        let mut locks = self.locks.write().await;
        locks.remove(name);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // -- Create the custom storage backend -------------------------------------
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

    // -- Build the Config with our custom storage ------------------------------
    let config = Config::builder().storage(storage).build();

    // -- Manage certificates ---------------------------------------------------
    let domains = vec!["example.com".into()];
    println!("Managing certificates with in-memory storage backend...");
    config.manage_sync(&domains).await?;

    // -- Build the TLS config --------------------------------------------------
    let resolver = CertResolver::new(config.cache.clone());
    let _tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    println!("TLS config ready with custom storage backend");

    // You could also verify that the storage contains data:
    // let keys = storage.list("certificates", true).await?;
    // println!("Stored keys: {:?}", keys);

    Ok(())
}
