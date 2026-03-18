//! Storage abstraction for certificate assets.
//!
//! This module defines the [`Storage`] trait for persistent key-value storage
//! with basic filesystem-like (folder path) semantics, along with helper types
//! and functions for building storage key paths and managing certificate
//! resources transactionally.
//!
//! Keys use the forward slash `'/'` to separate path components and have no
//! leading or trailing slashes. A *terminal* key (file) has a value associated
//! with it, while a *non-terminal* key (directory) is only an implicit prefix
//! of other keys.
//!
//! Processes running in a cluster should use the same [`Storage`]
//! implementation (with the same configuration) in order to share certificates
//! and other TLS resources across the cluster.
//!
//!
//! # Key path layout
//!
//! ```text
//! certificates/<issuer>/<domain>/<domain>.crt   -- certificate PEM
//! certificates/<issuer>/<domain>/<domain>.key   -- private key PEM
//! certificates/<issuer>/<domain>/<domain>.json  -- metadata sidecar
//! ocsp/<domain>-<hash>                          -- OCSP staple
//! acme/<issuer>/users/<email>/...               -- ACME account data
//! locks/<name>                                  -- distributed locks
//! ```

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{Error, Result, StorageError};

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

/// Persistent key-value storage with filesystem-like path semantics.
///
/// Implementations **must** be safe for concurrent use and should block until
/// the requested operation is complete. For example, [`Storage::load`] should
/// always return the value from the most recent [`Storage::store`] call for a
/// given key, and concurrent calls to [`Storage::store`] must not corrupt data.
///
/// This is not a streaming API and is not suitable for very large values.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Store `value` at `key`, creating the key if it does not exist and
    /// overwriting any existing value.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Load the value stored at `key`.
    ///
    /// Returns [`StorageError::NotFound`] if the key does not exist.
    async fn load(&self, key: &str) -> Result<Vec<u8>>;

    /// Delete the named key. If the key is a directory (prefix of other keys),
    /// all keys prefixed by it should be deleted.
    ///
    /// Returns an error only if the key still exists when the method returns.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Returns `true` if the key exists (as either a file or directory) and
    /// there was no error checking.
    async fn exists(&self, key: &str) -> Result<bool>;

    /// List all keys under `path`.
    ///
    /// If `recursive` is `true`, non-terminal keys (directories) are walked
    /// recursively; otherwise only keys whose immediate prefix matches `path`
    /// are returned.
    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>>;

    /// Return metadata about `key`.
    ///
    /// Returns [`StorageError::NotFound`] if the key does not exist.
    async fn stat(&self, key: &str) -> Result<KeyInfo>;

    /// Acquire a distributed lock for `name`, blocking until it can be
    /// obtained or an error occurs.
    ///
    /// Locking is used for high-level jobs or transactions that need cluster
    /// synchronization (e.g. certificate issuance), **not** around every
    /// individual storage call.
    async fn lock(&self, name: &str) -> Result<()>;

    /// Release the distributed lock for `name`.
    ///
    /// Must only be called after a successful [`Storage::lock`] and after the
    /// critical section is finished.
    async fn unlock(&self, name: &str) -> Result<()>;

    /// Try to acquire a distributed lock for `name` with a timeout.
    ///
    /// Returns `Ok(true)` if the lock was acquired, `Ok(false)` if the
    /// timeout expired before the lock could be obtained.
    async fn try_lock(&self, name: &str, timeout: Duration) -> Result<bool> {
        match tokio::time::timeout(timeout, self.lock(name)).await {
            Ok(Ok(())) => Ok(true),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(false), // timeout expired
        }
    }
}

// ---------------------------------------------------------------------------
// Global lock tracking
// ---------------------------------------------------------------------------

/// Global registry of lock names currently owned by this process.
///
/// This allows a graceful shutdown procedure to release any locks that
/// were held at the time of shutdown, preventing stale lock files from
/// blocking other processes.
static OWNED_LOCKS: OnceLock<Mutex<HashMap<String, ()>>> = OnceLock::new();

fn owned_locks() -> &'static Mutex<HashMap<String, ()>> {
    OWNED_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record that we now own the lock named `name`.
///
/// Called automatically by [`Storage::lock`] implementations to keep the
/// global registry in sync.
pub fn track_lock(name: &str) {
    if let Ok(mut map) = owned_locks().lock() {
        map.insert(name.to_string(), ());
    }
}

/// Remove `name` from the global lock registry.
///
/// Called automatically by [`Storage::unlock`] implementations.
pub fn untrack_lock(name: &str) {
    if let Ok(mut map) = owned_locks().lock() {
        map.remove(name);
    }
}

/// Release all locks that this process still owns.
///
/// This is intended to be called during graceful shutdown so that stale
/// lock files do not prevent other processes from acquiring the same
/// locks.
pub async fn cleanup_own_locks(storage: &dyn Storage) {
    let names: Vec<String> = {
        match owned_locks().lock() {
            Ok(map) => map.keys().cloned().collect(),
            Err(_) => return,
        }
    };

    for name in &names {
        if let Err(e) = storage.unlock(name).await {
            warn!(lock = %name, error = %e, "failed to release lock during cleanup");
        }
    }

    // Clear the registry.
    if let Ok(mut map) = owned_locks().lock() {
        map.clear();
    }
}

// ---------------------------------------------------------------------------
// KeyInfo
// ---------------------------------------------------------------------------

/// Metadata about a key in storage.
///
/// `key` and `is_terminal` are required. `modified` and `size` are optional —
/// setting them makes certain operations more consistent, but they are not
/// crucial to basic functionality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The storage key this info describes.
    pub key: String,

    /// Last modification timestamp (UTC).
    pub modified: DateTime<Utc>,

    /// Size of the stored value in bytes.
    pub size: u64,

    /// `true` for files (terminal keys), `false` for directories (keys that
    /// act as a prefix for other keys).
    pub is_terminal: bool,
}

// ---------------------------------------------------------------------------
// Storage key path constants
// ---------------------------------------------------------------------------

/// Top-level storage prefix for certificate assets.
const PREFIX_CERTS: &str = "certificates";

/// Top-level storage prefix for OCSP staple data.
const PREFIX_OCSP: &str = "ocsp";

/// Top-level storage prefix for ACME-specific assets.
const PREFIX_ACME: &str = "acme";

/// Top-level storage prefix for lock files.
const PREFIX_LOCKS: &str = "locks";

// ---------------------------------------------------------------------------
// Safe key sanitization
// ---------------------------------------------------------------------------

/// Standardize and sanitize `s` for use as a single component of a storage key.
///
/// The transformation is idempotent:
///
/// 1. Convert to lowercase and trim whitespace.
/// 2. Replace specific characters:
///    - `' '`  -> `_`
///    - `'+'`  -> `_plus_`
///    - `'*'`  -> `wildcard_`
///    - `':'`  -> `'-'`
///    - `".."` -> `""` (prevent directory traversal)
/// 3. Remove all remaining characters that are not word characters (`[a-zA-Z0-9_]`), `@`, `.`, or
///    `-`.
pub fn safe_key(s: &str) -> String {
    let s = s.to_lowercase();
    let s = s.trim().to_owned();

    // Ordered character replacements.
    let s = s
        .replace(' ', "_")
        .replace('+', "_plus_")
        .replace('*', "wildcard_")
        .replace(':', "-")
        .replace("..", ""); // prevent directory traversal

    // Remove any character that is not a Unicode word character, `@`, `.`, or `-`.
    // Using `char::is_alphanumeric()` (Unicode-aware) instead of
    // `char::is_ascii_alphanumeric()` so that non-ASCII word characters
    // (e.g. accented letters, CJK characters) are preserved.
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '@' || ch == '.' || ch == '-' {
            out.push(ch);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Key path builders
// ---------------------------------------------------------------------------

/// Join path components with `/`, cleaning the result by stripping redundant
/// slashes.
fn path_join(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| p.trim_matches('/'))
        .collect::<Vec<_>>()
        .join("/")
}

/// Return the storage key prefix for certificates from a given issuer.
///
/// Example: `"certificates/<safe_issuer_key>"`
pub fn certs_prefix(issuer_key: &str) -> String {
    path_join(&[PREFIX_CERTS, &safe_key(issuer_key)])
}

/// Return the storage key prefix for a specific site (domain) under a given
/// issuer.
///
/// Example: `"certificates/<safe_issuer_key>/<safe_domain>"`
pub fn certs_site_prefix(issuer_key: &str, domain: &str) -> String {
    path_join(&[&certs_prefix(issuer_key), &safe_key(domain)])
}

/// Return the path to the certificate PEM file for `domain` under `issuer_key`.
///
/// Example: `"certificates/<issuer>/<domain>/<domain>.crt"`
pub fn site_cert_key(issuer_key: &str, domain: &str) -> String {
    let safe_domain = safe_key(domain);
    let filename = format!("{safe_domain}.crt");
    path_join(&[&certs_site_prefix(issuer_key, domain), &filename])
}

/// Return the path to the private key PEM file for `domain` under `issuer_key`.
///
/// Example: `"certificates/<issuer>/<domain>/<domain>.key"`
pub fn site_private_key(issuer_key: &str, domain: &str) -> String {
    let safe_domain = safe_key(domain);
    let filename = format!("{safe_domain}.key");
    path_join(&[&certs_site_prefix(issuer_key, domain), &filename])
}

/// Return the path to the metadata JSON file for `domain` under `issuer_key`.
///
/// Example: `"certificates/<issuer>/<domain>/<domain>.json"`
pub fn site_meta_key(issuer_key: &str, domain: &str) -> String {
    let safe_domain = safe_key(domain);
    let filename = format!("{safe_domain}.json");
    path_join(&[&certs_site_prefix(issuer_key, domain), &filename])
}

/// Return the path for an OCSP staple identified by `domain` and `hash`.
///
/// `domain` is the first SAN on the certificate (already sanitized by the
/// caller is fine, but this function applies [`safe_key`] again for safety).
/// `hash` is a hex-encoded hash of the PEM bundle.
///
/// Example: `"ocsp/<safe_domain>-<hash>"`
pub fn ocsp_key(domain: &str, hash: &str) -> String {
    let mut filename = String::new();
    if !domain.is_empty() {
        filename.push_str(&safe_key(domain));
        filename.push('-');
    }
    filename.push_str(hash);
    path_join(&[PREFIX_OCSP, &filename])
}

/// Sanitize a CA URL into a storage-safe issuer key.
///
/// The URL is parsed and reduced to `host` + a hyphen-collapsed path
/// component:
///
/// ```text
/// "https://acme.example.com/v2/directory"
///     -> "acme.example.com-v2-directory"
/// ```
///
/// If the URL cannot be parsed, the raw string is returned as-is.
pub fn issuer_key(ca_url: &str) -> String {
    match url::Url::parse(ca_url) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or(ca_url);
            let path = parsed.path();
            if path.is_empty() || path == "/" {
                host.to_owned()
            } else {
                let collapsed = path.replace(['/', '\\'], "-");
                let collapsed = collapsed.trim_matches('-');
                if collapsed.is_empty() {
                    host.to_owned()
                } else {
                    format!("{host}-{collapsed}")
                }
            }
        }
        Err(_) => ca_url.to_owned(),
    }
}

/// Return the ACME CA prefix for the given issuer key.
///
/// Example: `"acme/<safe_issuer_key>"`
pub fn acme_ca_prefix(issuer_key: &str) -> String {
    path_join(&[PREFIX_ACME, &safe_key(issuer_key)])
}

/// Return the storage key prefix for accounts under a given issuer.
///
/// Example: `"acme/<safe_issuer_key>/users/<safe_email>"`
pub fn account_key_prefix(issuer_key: &str, email: &str) -> String {
    let email = if email.is_empty() { "default" } else { email };
    path_join(&[&acme_ca_prefix(issuer_key), "users", &safe_key(email)])
}

/// Return the path for lock files.
///
/// Example: `"locks/<safe_name>"`
pub fn locks_key(name: &str) -> String {
    path_join(&[PREFIX_LOCKS, &safe_key(name)])
}

// ---------------------------------------------------------------------------
// StorageKeys — all keys for a single certificate
// ---------------------------------------------------------------------------

/// The set of storage keys associated with a single certificate.
///
/// Each field holds the full key path for one of the three assets that make
/// up a certificate resource: the certificate PEM, the private key PEM, and
/// the metadata JSON sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageKeys {
    /// Key for the certificate PEM file.
    pub cert: String,
    /// Key for the private key PEM file.
    pub key: String,
    /// Key for the certificate metadata JSON file.
    pub meta: String,
}

impl StorageKeys {
    /// Build the three storage keys for a certificate identified by
    /// `issuer_key` and `domain`.
    pub fn new(issuer_key: &str, domain: &str) -> Self {
        Self {
            cert: site_cert_key(issuer_key, domain),
            key: site_private_key(issuer_key, domain),
            meta: site_meta_key(issuer_key, domain),
        }
    }
}

// ---------------------------------------------------------------------------
// CertificateResource
// ---------------------------------------------------------------------------

/// A certificate together with its private key and associated metadata, ready
/// for storage and retrieval.
///
/// The struct bundles together everything needed to persist and reload a
/// certificate: the PEM-encoded certificate chain, the PEM-encoded private
/// key, the list of Subject Alternative Names, issuer-specific metadata, and
/// the issuer key that determines the storage path.
///
/// Note that `certificate_pem` and `private_key_pem` are marked
/// `#[serde(skip)]` because they are stored as separate files in storage
/// rather than inline in the JSON metadata sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResource {
    /// The Subject Alternative Names on the certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,

    /// PEM-encoded certificate (or chain).
    #[serde(skip)]
    pub certificate_pem: Vec<u8>,

    /// PEM-encoded private key.
    #[serde(skip)]
    pub private_key_pem: Vec<u8>,

    /// Arbitrary issuer-specific metadata (e.g. ACME certificate object).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_data: Option<serde_json::Value>,

    /// The unique key identifying the issuer of this certificate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_key: String,
}

impl CertificateResource {
    /// Produce a single string that identifies the set of SANs on this
    /// resource, suitable for use as a storage key component.
    ///
    /// The SANs are sorted, joined by commas, and truncated to 1024 characters
    /// to keep the key bounded in length.
    pub fn names_key(&self) -> String {
        let mut names = self.sans.clone();
        names.sort();
        let mut result = names.join(",");
        const MAX_LEN: usize = 1024;
        const TRUNC_SUFFIX: &str = "_trunc";
        if result.len() > MAX_LEN {
            result.truncate(MAX_LEN - TRUNC_SUFFIX.len());
            result.push_str(TRUNC_SUFFIX);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Transactional store / load helpers
// ---------------------------------------------------------------------------

/// A key-value pair for use in [`store_tx`].
struct KeyValue {
    key: String,
    value: Vec<u8>,
}

/// Store all key-value pairs transactionally: if any single store fails, the
/// previously-stored entries in this batch are rolled back (deleted).
async fn store_tx(storage: &dyn Storage, items: &[KeyValue]) -> Result<()> {
    for (i, kv) in items.iter().enumerate() {
        if let Err(e) = storage.store(&kv.key, &kv.value).await {
            // Roll back everything stored so far (best effort).
            for prev in items[..i].iter().rev() {
                let _ = storage.delete(&prev.key).await;
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Store a [`CertificateResource`] transactionally.
///
/// The private key, certificate PEM, and JSON metadata are all written
/// atomically — if any write fails, those that succeeded are rolled back
/// (best effort). The storage keys are derived from `issuer_key` and the
/// certificate's [`CertificateResource::names_key`].
///
/// # Errors
///
/// Returns a [`StorageError`] if any of the three writes fail. On partial
/// failure the already-written keys are deleted in reverse order.
pub async fn store_certificate(
    storage: &dyn Storage,
    issuer_key: &str,
    cert: &CertificateResource,
) -> Result<()> {
    let cert_key_name = cert.names_key();

    let meta_bytes = serde_json::to_vec_pretty(cert).map_err(|e| {
        Error::Storage(StorageError::Serialize(format!(
            "encoding certificate metadata: {e}"
        )))
    })?;

    let items = [
        KeyValue {
            key: site_private_key(issuer_key, &cert_key_name),
            value: cert.private_key_pem.clone(),
        },
        KeyValue {
            key: site_cert_key(issuer_key, &cert_key_name),
            value: cert.certificate_pem.clone(),
        },
        KeyValue {
            key: site_meta_key(issuer_key, &cert_key_name),
            value: meta_bytes,
        },
    ];

    store_tx(storage, &items).await
}

/// Load a [`CertificateResource`] from storage.
///
/// Reads the private key, certificate PEM, and metadata JSON from the
/// appropriate storage keys and assembles them into a single
/// [`CertificateResource`].
///
/// # Errors
///
/// Returns [`StorageError::NotFound`] if any of the three assets are missing,
/// or [`StorageError::Deserialize`] if the metadata JSON is malformed.
pub async fn load_certificate(
    storage: &dyn Storage,
    issuer_key: &str,
    domain: &str,
) -> Result<CertificateResource> {
    let key_bytes = storage.load(&site_private_key(issuer_key, domain)).await?;
    let cert_bytes = storage.load(&site_cert_key(issuer_key, domain)).await?;
    let meta_bytes = storage.load(&site_meta_key(issuer_key, domain)).await?;

    let mut cert_res: CertificateResource = serde_json::from_slice(&meta_bytes).map_err(|e| {
        Error::Storage(StorageError::Deserialize(format!(
            "decoding certificate metadata: {e}"
        )))
    })?;

    cert_res.private_key_pem = key_bytes;
    cert_res.certificate_pem = cert_bytes;
    cert_res.issuer_key = issuer_key.to_owned();

    Ok(cert_res)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- safe_key ----------------------------------------------------------

    #[test]
    fn safe_key_lowercase_and_trim() {
        assert_eq!(safe_key("  Hello World  "), "hello_world");
    }

    #[test]
    fn safe_key_replaces_special_chars() {
        assert_eq!(safe_key("a+b"), "a_plus_b");
        assert_eq!(safe_key("*.example.com"), "wildcard_.example.com");
        assert_eq!(safe_key("host:port"), "host-port");
    }

    #[test]
    fn safe_key_prevents_directory_traversal() {
        // ".." is stripped before the regex pass
        assert_eq!(safe_key("a/../../../foo"), "afoo");
        assert_eq!(safe_key("b\\..\\..\\..\\foo"), "bfoo");
    }

    #[test]
    fn safe_key_strips_slashes() {
        // Forward slashes are not word chars, so they get removed.
        assert_eq!(safe_key("c/foo"), "cfoo");
    }

    #[test]
    fn safe_key_idempotent() {
        let once = safe_key("*.Example.COM");
        let twice = safe_key(&once);
        assert_eq!(once, twice);
    }

    // -- issuer_key --------------------------------------------------------

    #[test]
    fn issuer_key_from_url() {
        assert_eq!(
            issuer_key("https://example.com/acme-ca/directory"),
            "example.com-acme-ca-directory"
        );
    }

    #[test]
    fn issuer_key_no_path() {
        assert_eq!(issuer_key("https://acme.example.com"), "acme.example.com");
    }

    #[test]
    fn issuer_key_non_url() {
        assert_eq!(issuer_key("not-a-url"), "not-a-url");
    }

    // -- key path builders -------------------------------------------------

    #[test]
    fn site_cert_key_format() {
        let ik = issuer_key("https://example.com/acme-ca/directory");
        // base = "certificates/example.com-acme-ca-directory"
        assert_eq!(
            site_cert_key(&ik, "example.com"),
            "certificates/example.com-acme-ca-directory/example.com/example.com.crt"
        );
    }

    #[test]
    fn site_key_key_format() {
        let ik = issuer_key("https://example.com/acme-ca/directory");
        assert_eq!(
            site_private_key(&ik, "example.com"),
            "certificates/example.com-acme-ca-directory/example.com/example.com.key"
        );
    }

    #[test]
    fn site_meta_key_format() {
        let ik = issuer_key("https://example.com/acme-ca/directory");
        assert_eq!(
            site_meta_key(&ik, "example.com"),
            "certificates/example.com-acme-ca-directory/example.com/example.com.json"
        );
    }

    #[test]
    fn wildcard_key_format() {
        let ik = issuer_key("https://example.com/acme-ca/directory");
        let base = "certificates/example.com-acme-ca-directory";
        assert_eq!(
            site_cert_key(&ik, "*.example.com"),
            format!("{base}/wildcard_.example.com/wildcard_.example.com.crt")
        );
        assert_eq!(
            site_private_key(&ik, "*.example.com"),
            format!("{base}/wildcard_.example.com/wildcard_.example.com.key")
        );
        assert_eq!(
            site_meta_key(&ik, "*.example.com"),
            format!("{base}/wildcard_.example.com/wildcard_.example.com.json")
        );
    }

    #[test]
    fn traversal_key_sanitized() {
        let ik = issuer_key("https://example.com/acme-ca/directory");
        let base = "certificates/example.com-acme-ca-directory";

        // "a/../../../foo" -> safe -> "afoo"
        assert_eq!(
            site_cert_key(&ik, "a/../../../foo"),
            format!("{base}/afoo/afoo.crt")
        );
        // "c/foo" -> safe -> "cfoo"
        assert_eq!(site_cert_key(&ik, "c/foo"), format!("{base}/cfoo/cfoo.crt"));
    }

    // -- StorageKeys -------------------------------------------------------

    #[test]
    fn storage_keys_new() {
        let ik = "example.com-acme-ca-directory";
        let sk = StorageKeys::new(ik, "example.com");
        assert!(sk.cert.ends_with(".crt"));
        assert!(sk.key.ends_with(".key"));
        assert!(sk.meta.ends_with(".json"));
    }

    // -- CertificateResource -----------------------------------------------

    #[test]
    fn names_key_basic() {
        let cr = CertificateResource {
            sans: vec!["b.example.com".into(), "a.example.com".into()],
            certificate_pem: vec![],
            private_key_pem: vec![],
            issuer_data: None,
            issuer_key: String::new(),
        };
        // Should be sorted and joined
        assert_eq!(cr.names_key(), "a.example.com,b.example.com");
    }

    #[test]
    fn names_key_truncation() {
        // Build a names list that exceeds 1024 chars
        let long_name = "x".repeat(200);
        let sans: Vec<String> = (0..10).map(|i| format!("{long_name}{i}")).collect();
        let cr = CertificateResource {
            sans,
            certificate_pem: vec![],
            private_key_pem: vec![],
            issuer_data: None,
            issuer_key: String::new(),
        };
        let key = cr.names_key();
        assert!(key.len() <= 1024);
        assert!(key.ends_with("_trunc"));
    }

    // -- ocsp_key ----------------------------------------------------------

    #[test]
    fn ocsp_key_with_domain() {
        assert_eq!(ocsp_key("example.com", "abc123"), "ocsp/example.com-abc123");
    }

    #[test]
    fn ocsp_key_without_domain() {
        assert_eq!(ocsp_key("", "abc123"), "ocsp/abc123");
    }

    // -- locks_key ---------------------------------------------------------

    #[test]
    fn locks_key_basic() {
        assert_eq!(locks_key("my-lock"), "locks/my-lock");
    }

    // -- account_key_prefix ------------------------------------------------

    #[test]
    fn account_key_prefix_with_email() {
        let ak = account_key_prefix("example.com-directory", "user@example.com");
        assert_eq!(ak, "acme/example.com-directory/users/user@example.com");
    }

    #[test]
    fn account_key_prefix_empty_email() {
        let ak = account_key_prefix("example.com-directory", "");
        assert_eq!(ak, "acme/example.com-directory/users/default");
    }
}
