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
//! certificates/<issuer>/<domain>/_certon/resource.v1.key -- complete private snapshot
//! certificates/<issuer>/<domain>/<domain>.crt   -- legacy certificate PEM
//! certificates/<issuer>/<domain>/<domain>.key   -- private key PEM
//! certificates/<issuer>/<domain>/<domain>.json  -- metadata sidecar
//! revocations/<leaf-hash>.json                 -- persistent revocation intent
//! ocsp/<domain>-<hash>                          -- OCSP staple
//! acme/<issuer>/users/<email>/...               -- ACME account data
//! locks/<name>                                  -- distributed locks
//! ```

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
/// given key. A single-value store must publish atomically: concurrent readers,
/// cancellation and a crash may observe the old or new value, never a partial
/// value. Certificate and account snapshots rely on this guarantee.
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
/// Cancellation can otherwise strand a lock for the lifetime of the process.
/// [`FileStorage`] owns an OS lock through an open handle, and other backends
/// may maintain distributed leases until explicitly released.
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
    /// Set when an owned release task takes responsibility for cleanup, so
    /// `Drop` does not release the same lock a second time.
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
    certificate_site_prefix_from_safe_name(issuer_key, &safe_key(domain))
}

/// Bound only derived certificate components, preserving every ordinary path.
/// The extra namespace level cannot collide with a single legacy site name.
pub(crate) fn certificate_site_prefix_from_safe_name(issuer: &str, name: &str) -> String {
    if name.len() <= 255 {
        path_join(&[&certs_prefix(issuer), name])
    } else {
        path_join(&[
            &certs_prefix(issuer),
            "_certon-long-v1",
            &storage_identity_hash(name),
        ])
    }
}

pub(crate) fn storage_identity_hash(identity: &str) -> String {
    Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn certificate_sites(issuer: &str, domain: &str) -> Vec<String> {
    let name = safe_key(domain);
    let mut sites = vec![certificate_site_prefix_from_safe_name(issuer, &name)];
    let old = path_join(&[&certs_prefix(issuer), &name]);
    if old != sites[0] {
        sites.push(old);
    }
    sites
}

fn certificate_basename(name: &str) -> String {
    if name.len() <= 250 {
        name.to_owned()
    } else {
        format!("_certon-long-v1-{}", storage_identity_hash(name))
    }
}

/// Certificate PEM, private key, and metadata keys, in that order.
pub(crate) fn certificate_keys_for_site(site: &str, safe_name: &str) -> [String; 3] {
    legacy_certificate_keys_for_site(site, &certificate_basename(safe_name))
}

pub(crate) fn legacy_certificate_keys_for_site(site: &str, safe_name: &str) -> [String; 3] {
    ["crt", "key", "json"].map(|extension| format!("{site}/{safe_name}.{extension}"))
}

/// All compatible assets, ordered so the canonical snapshot is removed last.
pub(crate) fn certificate_storage_keys(issuer: &str, domain: &str) -> Vec<String> {
    let safe_name = safe_key(domain);
    let sites = certificate_sites(issuer, domain);
    let mut keys = Vec::new();
    for site in sites.iter().rev() {
        for key in legacy_certificate_keys_for_site(site, &safe_name)
            .into_iter()
            .chain(certificate_keys_for_site(site, &safe_name))
        {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    for site in sites.iter().rev() {
        keys.push(site_snapshot_key_from_prefix(site));
    }
    keys
}

/// Return the bounded legacy certificate PEM key. Ordinary paths are unchanged.
pub fn site_cert_key(issuer_key: &str, domain: &str) -> String {
    certificate_keys_for_site(&certs_site_prefix(issuer_key, domain), &safe_key(domain))[0].clone()
}

/// Return the bounded legacy private key key. Ordinary paths are unchanged.
pub fn site_private_key(issuer_key: &str, domain: &str) -> String {
    certificate_keys_for_site(&certs_site_prefix(issuer_key, domain), &safe_key(domain))[1].clone()
}

/// Return the bounded legacy metadata key. Ordinary paths are unchanged.
pub fn site_meta_key(issuer_key: &str, domain: &str) -> String {
    certificate_keys_for_site(&certs_site_prefix(issuer_key, domain), &safe_key(domain))[2].clone()
}

/// Return the OCSP staple key; long derived filenames use a versioned digest.
pub fn ocsp_key(domain: &str, hash: &str) -> String {
    let old = legacy_ocsp_key(domain, hash);
    let filename = old.strip_prefix("ocsp/").expect("OCSP prefix");
    if filename.len() <= 255 {
        old
    } else {
        format!("ocsp/_certon-long-v1/{}", storage_identity_hash(filename))
    }
}

pub(crate) fn legacy_ocsp_key(domain: &str, hash: &str) -> String {
    let prefix = if domain.is_empty() {
        String::new()
    } else {
        format!("{}-", safe_key(domain))
    };
    format!("{PREFIX_OCSP}/{prefix}{hash}")
}

/// Return the actual cache key along with its bytes, for precise corrupt cleanup.
pub(crate) async fn load_ocsp_cache(
    storage: &dyn Storage,
    domain: &str,
    hash: &str,
) -> Result<(String, Vec<u8>)> {
    let canonical = ocsp_key(domain, hash);
    match storage.load(&canonical).await {
        Ok(bytes) => Ok((canonical, bytes)),
        Err(Error::Storage(StorageError::NotFound(_))) => {
            let old = legacy_ocsp_key(domain, hash);
            if old == canonical {
                return Err(StorageError::NotFound(canonical).into());
            }
            let bytes = storage.load(&old).await?;
            Ok((old, bytes))
        }
        Err(error) => Err(error),
    }
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
/// Standalone serialization omits `certificate_pem` and `private_key_pem` to
/// preserve the legacy metadata format. Persistence stores these fields beside
/// the metadata inside one complete private snapshot.
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

/// The complete resource is published as one value. The `.key` suffix tells
/// file backends that this JSON contains a secret and needs private permissions.
pub(crate) fn site_snapshot_key(issuer: &str, domain: &str) -> String {
    site_snapshot_key_from_prefix(&certs_site_prefix(issuer, domain))
}

pub(crate) fn site_snapshot_key_from_prefix(site: &str) -> String {
    format!("{site}/_certon/resource.v1.key")
}

#[derive(Serialize, Deserialize)]
struct CertificateSnapshot {
    version: u32,
    metadata: CertificateResource,
    certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

/// Publish a complete, versioned certificate snapshot in one atomic store.
/// Failure or cancellation cannot mix a new key with an old certificate.
/// Legacy files remain readable but are not rewritten during renewal.
pub async fn store_certificate(
    storage: &dyn Storage,
    issuer_key: &str,
    cert: &CertificateResource,
) -> Result<()> {
    let snapshot = CertificateSnapshot {
        version: 1,
        metadata: cert.clone(),
        certificate_pem: cert.certificate_pem.clone(),
        private_key_pem: cert.private_key_pem.clone(),
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|e| {
        Error::Storage(StorageError::Serialize(format!(
            "encoding certificate metadata: {e}"
        )))
    })?;

    storage
        .store(&site_snapshot_key(issuer_key, &cert.names_key()), &bytes)
        .await
}

/// Load a [`CertificateResource`] from storage.
///
/// Prefers the complete atomic snapshot. If no snapshot exists, reads the
/// legacy private key, certificate PEM and metadata sidecar. A malformed
/// snapshot is an error, never a reason to resurrect an older legacy value.
///
/// # Errors
///
/// Returns [`StorageError::NotFound`] if no compatible assets exist,
/// or [`StorageError::Deserialize`] if the metadata JSON is malformed.
pub async fn load_certificate(
    storage: &dyn Storage,
    issuer_key: &str,
    domain: &str,
) -> Result<CertificateResource> {
    let sites = certificate_sites(issuer_key, domain);
    // Atomic snapshots take precedence across both generations of the layout.
    for site in &sites {
        match load_certificate_snapshot_from_site(storage, site, issuer_key).await {
            Ok(resource) => return Ok(resource),
            Err(Error::Storage(StorageError::NotFound(_))) => {}
            Err(error) => return Err(error),
        }
    }
    let name = safe_key(domain);
    for site in &sites {
        match load_legacy_certificate_from_site(storage, site, issuer_key, &name).await {
            Ok(resource) => return Ok(resource),
            Err(Error::Storage(StorageError::NotFound(_))) => {}
            Err(error) => return Err(error),
        }
    }
    Err(StorageError::NotFound(site_snapshot_key(issuer_key, domain)).into())
}

pub(crate) async fn load_certificate_snapshot_from_site(
    storage: &dyn Storage,
    site: &str,
    issuer: &str,
) -> Result<CertificateResource> {
    let bytes = storage.load(&site_snapshot_key_from_prefix(site)).await?;
    let mut snapshot: CertificateSnapshot = serde_json::from_slice(&bytes)
        .map_err(|e| StorageError::Deserialize(format!("decoding certificate snapshot: {e}")))?;
    if snapshot.version != 1 {
        return Err(
            StorageError::Deserialize("unsupported certificate snapshot version".into()).into(),
        );
    }
    snapshot.metadata.certificate_pem = snapshot.certificate_pem;
    snapshot.metadata.private_key_pem = snapshot.private_key_pem;
    snapshot.metadata.issuer_key = issuer.to_owned();
    Ok(snapshot.metadata)
}

async fn load_legacy_certificate_from_site(
    storage: &dyn Storage,
    site: &str,
    issuer: &str,
    safe_name: &str,
) -> Result<CertificateResource> {
    let bounded = certificate_keys_for_site(site, safe_name);
    let raw = legacy_certificate_keys_for_site(site, safe_name);
    for keys in [&bounded, &raw] {
        // A partial generation must not silently fall back to another one.
        let mut values = Vec::new();
        let mut missing = false;
        for key in keys {
            match storage.load(key).await {
                Ok(bytes) => values.push(bytes),
                Err(Error::Storage(StorageError::NotFound(_))) => {
                    missing = true;
                }
                Err(error) => return Err(error),
            }
        }
        if !missing {
            let mut resource: CertificateResource =
                serde_json::from_slice(&values[2]).map_err(|e| {
                    StorageError::Deserialize(format!("decoding certificate metadata: {e}"))
                })?;
            resource.certificate_pem = std::mem::take(&mut values[0]);
            resource.private_key_pem = std::mem::take(&mut values[1]);
            resource.issuer_key = issuer.to_owned();
            return Ok(resource);
        }
        if !values.is_empty() {
            return Err(StorageError::Deserialize(format!(
                "incomplete certificate resources at {site}"
            ))
            .into());
        }
        if raw == bounded {
            break;
        }
    }
    Err(StorageError::NotFound(site.to_owned()).into())
}

// Revocation intent is independent of the certificate store, so a failed
// certificate deletion cannot make the same leaf usable on a later load.
#[derive(Serialize, Deserialize)]
pub(crate) struct RevocationMarker {
    version: u32,
    pub confirmed: bool,
}

pub(crate) fn certificate_leaf_hash(cert: &crate::Certificate) -> Option<String> {
    cert.cert_chain
        .first()
        .map(|leaf| crate::certificates::hash_certificate_chain(std::slice::from_ref(leaf)))
}

pub(crate) fn resource_leaf_hash(resource: &CertificateResource) -> Result<String> {
    let pem = std::str::from_utf8(&resource.certificate_pem)
        .map_err(|error| Error::Config(format!("invalid certificate PEM: {error}")))?;
    let chain: Vec<rustls::pki_types::CertificateDer<'static>> = pem::parse_many(pem)
        .map_err(|error| Error::Config(format!("invalid certificate PEM: {error}")))?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| rustls::pki_types::CertificateDer::from(block.into_contents()))
        .collect();
    let leaf = chain
        .first()
        .ok_or_else(|| Error::Config("no certificate found for revocation".into()))?;
    x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| Error::Config(format!("invalid certificate for revocation: {error}")))?;
    Ok(crate::certificates::hash_certificate_chain(
        std::slice::from_ref(leaf),
    ))
}

fn revocation_key(leaf_hash: &str) -> String {
    format!("revocations/{leaf_hash}.json")
}

pub(crate) async fn load_revocation(
    storage: &dyn Storage,
    leaf_hash: &str,
) -> Result<Option<RevocationMarker>> {
    let bytes = match storage.load(&revocation_key(leaf_hash)).await {
        Ok(bytes) => bytes,
        Err(Error::Storage(StorageError::NotFound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    let marker: RevocationMarker = serde_json::from_slice(&bytes).map_err(|error| {
        StorageError::Deserialize(format!("invalid revocation marker: {error}"))
    })?;
    if marker.version != 1 {
        return Err(
            StorageError::Deserialize("unsupported revocation marker version".into()).into(),
        );
    }
    Ok(Some(marker))
}

pub(crate) async fn store_revocation(
    storage: &dyn Storage,
    leaf_hash: &str,
    confirmed: bool,
) -> Result<()> {
    let bytes = serde_json::to_vec(&RevocationMarker {
        version: 1,
        confirmed,
    })
    .map_err(|error| StorageError::Serialize(format!("encoding revocation marker: {error}")))?;
    storage.store(&revocation_key(leaf_hash), &bytes).await
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
        // A short, repeatedly cancelled file operation can itself leave a
        // partially acquired lock awaiting stale recovery on slow filesystems.
        // Wait once, allowing acquisition to finish before releasing it.
        let guard = try_acquire(Arc::clone(storage), name, Duration::from_secs(5))
            .await
            .expect("lock acquisition should not fail");
        match guard {
            Some(guard) => {
                guard.release().await.expect("release the probe lock");
                true
            }
            None => false,
        }
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

#[cfg(test)]
mod long_ocsp_tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Memory {
        entries: Mutex<BTreeMap<String, Vec<u8>>>,
        failure: Mutex<Option<String>>,
    }
    #[async_trait]
    impl Storage for Memory {
        async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            self.entries
                .lock()
                .unwrap()
                .insert(key.into(), value.into());
            Ok(())
        }
        async fn load(&self, key: &str) -> Result<Vec<u8>> {
            if self.failure.lock().unwrap().as_deref() == Some(key) {
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "load denied",
                ))
                .into());
            }
            self.entries
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.into()).into())
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.entries.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.entries.lock().unwrap().contains_key(key))
        }
        async fn list(&self, _: &str, _: bool) -> Result<Vec<String>> {
            unreachable!()
        }
        async fn stat(&self, _: &str) -> Result<KeyInfo> {
            unreachable!()
        }
        async fn lock(&self, _: &str) -> Result<()> {
            unreachable!()
        }
        async fn unlock(&self, _: &str) -> Result<()> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn old_long_ocsp_keys_are_read_only_on_canonical_not_found() {
        let storage = Memory::default();
        let name = "a".repeat(253);
        let hash = "b".repeat(64);
        let old = legacy_ocsp_key(&name, &hash);
        let canonical = ocsp_key(&name, &hash);
        assert_ne!(old, canonical);
        storage.store(&old, b"old response").await.unwrap();
        assert_eq!(
            load_ocsp_cache(&storage, &name, &hash).await.unwrap(),
            (old.clone(), b"old response".to_vec())
        );
        storage
            .store(&canonical, b"bad DER must not fall back")
            .await
            .unwrap();
        assert_eq!(
            load_ocsp_cache(&storage, &name, &hash).await.unwrap(),
            (canonical.clone(), b"bad DER must not fall back".to_vec())
        );
        *storage.failure.lock().unwrap() = Some(canonical.clone());
        assert!(matches!(
            load_ocsp_cache(&storage, &name, &hash).await,
            Err(Error::Storage(StorageError::Io(_)))
        ));
        assert_eq!(storage.load(&old).await.unwrap(), b"old response");
    }
}
