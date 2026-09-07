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

use std::sync::Arc;
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
    ///
    /// This is the primitive an implementation provides. Callers should use
    /// [`acquire`], which hands back a guard that releases on drop — pairing
    /// `lock` and `unlock` by hand leaves the lock held on every early return,
    /// panic and cancellation.
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
// Holding a lock
// ---------------------------------------------------------------------------

/// A distributed lock, held for as long as this value lives.
///
/// [`Storage::lock`] and [`Storage::unlock`] are what an implementation
/// provides. This is what a caller uses, and the difference matters: pairing
/// the two by hand means every early return, every `?`, every panic and every
/// cancellation is a place the lock can be left held.
///
/// Cancellation is the one that bites. A lock backed by [`FileStorage`] is
/// kept alive by a background task that refreshes its timestamp, so a lock
/// nobody released is not stale — it is refreshed for as long as the process
/// runs, and no instance anywhere in the cluster can take it again.
///
/// Dropping this releases the lock. Because releasing is asynchronous and
/// `Drop` is not, the release is spawned; call [`release`](Self::release) to
/// wait for it and to see a failure. Acquisition and release finish in owned
/// tasks even if their callers are cancelled. The acquiring Tokio runtime
/// must remain running until release completes; runtime shutdown cannot
/// guarantee asynchronous cleanup. Cancelled acquisition may keep waiting
/// until the backend timeout, then releases any acquired lock.
///
/// [`FileStorage`]: crate::file_storage::FileStorage
pub struct LockGuard {
    storage: Arc<dyn Storage>,
    name: String,
    /// Set once the lock is known to be released, so `Drop` does not release
    /// it a second time.
    released: bool,
    runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for LockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockGuard")
            .field("name", &self.name)
            .finish()
    }
}

impl LockGuard {
    /// The name this guard holds.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Release the lock and wait for it, reporting a failure to do so.
    ///
    /// Dropping the guard does the same thing without waiting and without
    /// reporting. Use this where a caller can act on the failure.
    pub async fn release(mut self) -> Result<()> {
        self.released = true;
        let storage = Arc::clone(&self.storage);
        let name = self.name.clone();
        self.runtime
            .spawn(async move { storage.unlock(&name).await })
            .await
            .map_err(|e| crate::error::Error::Other(format!("lock release task failed: {e}")))?
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let storage = Arc::clone(&self.storage);
        let name = std::mem::take(&mut self.name);
        self.runtime.spawn(async move {
            if let Err(error) = storage.unlock(&name).await {
                warn!(lock = %name, %error, "failed to release a lock on drop");
            }
        });
    }
}

/// Take the lock named `name`, waiting until it is available.
///
/// The lock is held until the returned guard is dropped or
/// [`released`](LockGuard::release).
pub async fn acquire(storage: Arc<dyn Storage>, name: &str) -> Result<LockGuard> {
    let runtime = tokio::runtime::Handle::current();
    let name = name.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    runtime.clone().spawn(async move {
        let result = storage.lock(&name).await.map(|()| LockGuard {
            storage,
            name,
            released: false,
            runtime,
        });
        // If acquisition was cancelled, dropping the undelivered guard releases it.
        let _ = send.send(result);
    });
    receive
        .await
        .map_err(|e| crate::error::Error::Other(format!("lock acquisition task failed: {e}")))?
}

/// Take the lock named `name` if it becomes available within `timeout`.
///
/// `Ok(None)` means the timeout expired, which is not an error: it is the
/// answer to "is somebody else doing this?".
pub async fn try_acquire(
    storage: Arc<dyn Storage>,
    name: &str,
    timeout: Duration,
) -> Result<Option<LockGuard>> {
    let runtime = tokio::runtime::Handle::current();
    let name = name.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    runtime.clone().spawn(async move {
        let result = storage.try_lock(&name, timeout).await.map(|locked| {
            locked.then(|| LockGuard {
                storage,
                name,
                released: false,
                runtime,
            })
        });
        let _ = send.send(result);
    });
    receive
        .await
        .map_err(|e| crate::error::Error::Other(format!("lock acquisition task failed: {e}")))?
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
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for CertificateResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateResource")
            .field("sans", &self.sans)
            .field("certificate_pem_len", &self.certificate_pem.len())
            .field("private_key_pem", &"[REDACTED]")
            .field("private_key_pem_len", &self.private_key_pem.len())
            .field("issuer_data", &self.issuer_data)
            .field("issuer_key", &self.issuer_key)
            .finish()
    }
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

#[cfg(test)]
mod lock_guard_tests {
    use std::time::Duration;

    use super::*;
    use crate::file_storage::FileStorage;

    fn storage() -> (tempfile::TempDir, Arc<dyn Storage>) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let storage = Arc::new(FileStorage::new(directory.path()));
        (directory, storage)
    }

    /// Wait for a lock to become free, so a test does not race the spawned
    /// release. A failure here means it never became free.
    async fn becomes_free(storage: &Arc<dyn Storage>, name: &str) -> bool {
        for _ in 0..50 {
            if storage
                .try_lock(name, Duration::from_millis(50))
                .await
                .unwrap_or(false)
            {
                let _ = storage.unlock(name).await;
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_guard_holds_the_lock_while_it_lives() {
        let (_directory, storage) = storage();
        let guard = acquire(Arc::clone(&storage), "held").await.unwrap();
        assert_eq!(guard.name(), "held");
        assert!(
            !storage
                .try_lock("held", Duration::from_millis(200))
                .await
                .unwrap(),
            "somebody else took a lock that is held"
        );
        guard.release().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_a_guard_releases_the_lock() {
        let (_directory, storage) = storage();
        {
            let _guard = acquire(Arc::clone(&storage), "dropped").await.unwrap();
        }
        assert!(becomes_free(&storage, "dropped").await);
    }

    #[tokio::test]
    async fn a_cancelled_future_does_not_keep_the_lock_for_ever() {
        // This is the failure the guard exists for. With a matching `unlock`
        // written by hand, a future cancelled between the two never reached
        // the release — and a `FileStorage` lock is kept fresh by a background
        // task, so it did not go stale either. The lock was held for the life
        // of the process, and no instance anywhere could take it again.
        let (_directory, storage) = storage();
        let held = Arc::clone(&storage);

        let work = async move {
            let _guard = acquire(held, "cancelled").await.unwrap();
            // Never finishes. Something outside decides when this stops.
            std::future::pending::<()>().await;
        };
        // Exactly how a caller wrapping certon in a timeout would cancel it.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), work)
                .await
                .is_err()
        );

        assert!(
            becomes_free(&storage, "cancelled").await,
            "a cancelled future left the lock held"
        );
    }

    #[tokio::test]
    async fn releasing_explicitly_reports_a_failure_to_release() {
        let (_directory, storage) = storage();
        let guard = acquire(Arc::clone(&storage), "explicit").await.unwrap();
        guard.release().await.expect("releasing works");
        assert!(becomes_free(&storage, "explicit").await);
    }

    #[tokio::test]
    async fn try_acquire_says_no_rather_than_waiting_for_ever() {
        let (_directory, storage) = storage();
        let held = acquire(Arc::clone(&storage), "busy").await.unwrap();
        let second = try_acquire(Arc::clone(&storage), "busy", Duration::from_millis(200))
            .await
            .unwrap();
        assert!(second.is_none(), "it is somebody else's turn");
        held.release().await.unwrap();
    }
    struct PausedStorage {
        entered: tokio::sync::Notify,
        proceed: tokio::sync::Notify,
        released: tokio::sync::Notify,
        pause_acquire: bool,
    }

    #[async_trait]
    impl Storage for PausedStorage {
        async fn store(&self, _: &str, _: &[u8]) -> Result<()> {
            unreachable!()
        }
        async fn load(&self, _: &str) -> Result<Vec<u8>> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> Result<()> {
            unreachable!()
        }
        async fn exists(&self, _: &str) -> Result<bool> {
            unreachable!()
        }
        async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
            unreachable!()
        }
        async fn stat(&self, _: &str) -> Result<KeyInfo> {
            unreachable!()
        }
        async fn lock(&self, _: &str) -> Result<()> {
            if self.pause_acquire {
                self.entered.notify_one();
                self.proceed.notified().await;
            }
            Ok(())
        }
        async fn unlock(&self, _: &str) -> Result<()> {
            if !self.pause_acquire {
                self.entered.notify_one();
                self.proceed.notified().await;
            }
            self.released.notify_one();
            Ok(())
        }
    }

    async fn cancellation_during_transition(pause_acquire: bool) {
        let backend = Arc::new(PausedStorage {
            entered: Default::default(),
            proceed: Default::default(),
            released: Default::default(),
            pause_acquire,
        });
        let storage: Arc<dyn Storage> = backend.clone();
        let task = tokio::spawn(async move {
            let guard = acquire(storage, "transition").await.unwrap();
            guard.release().await.unwrap();
        });
        backend.entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        backend.proceed.notify_one();
        tokio::time::timeout(Duration::from_secs(2), backend.released.notified())
            .await
            .expect("cancellation must not strand the lock");
    }

    #[tokio::test]
    async fn cancellation_during_acquisition_releases_the_delivered_lock() {
        cancellation_during_transition(true).await;
    }

    #[tokio::test]
    async fn cancellation_during_explicit_release_finishes_unlocking() {
        cancellation_during_transition(false).await;
    }

    #[test]
    fn dropping_outside_the_runtime_uses_the_acquiring_runtime() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (_directory, storage) = storage();
        let guard = runtime
            .block_on(acquire(storage.clone(), "outside"))
            .unwrap();
        drop(guard);
        assert!(runtime.block_on(becomes_free(&storage, "outside")));
    }
}
