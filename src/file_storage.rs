//! File-system-based storage backend for certon.
//!
//! This module implements [`Storage`] using the local file system.  Highlights:
//!
//! * **Atomic writes** — data is first written to a temporary file in the same directory, then
//!   renamed into place so that readers never see a partial write.
//! * **Distributed locking** — lock files containing a JSON timestamp are created atomically.  A
//!   background keepalive task periodically updates the timestamp; stale locks whose timestamp
//!   exceeds twice the freshness interval are automatically removed.
//! * **Platform-aware defaults** — the default storage path follows OS conventions
//!   (`~/.local/share/certon` on Linux, `~/Library/Application Support/certon` on macOS,
//!   `%APPDATA%/certon` on Windows).

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::error::{Error, Result, StorageError};
use crate::storage::{KeyInfo, Storage, safe_key, track_lock, untrack_lock};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How often the keepalive task refreshes the lock file timestamp.
const LOCK_FRESHNESS_INTERVAL: Duration = Duration::from_secs(5);

/// How often to poll when waiting for a lock held by another process.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Maximum number of times an empty/truncated lock file is tolerated before
/// treating it as stale.
const MAX_EMPTY_LOCK_READS: u32 = 8;

/// Delay between retries when the lock file reads as empty (it may be in the
/// middle of being written).
const EMPTY_LOCK_RETRY_DELAY: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// Lock metadata
// ---------------------------------------------------------------------------

/// JSON structure stored inside lock files.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockMeta {
    created: chrono::DateTime<chrono::Utc>,
    updated: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// FileStorage
// ---------------------------------------------------------------------------

/// A [`Storage`] implementation backed by the local file system.
///
/// This is the default storage backend, suitable for single-server
/// deployments. For multi-server / clustered deployments, consider a
/// shared-filesystem or database-backed implementation.
///
/// # Locking
///
/// Locks are implemented as files under `<path>/locks/<safe_name>.lock`.  Each
/// lock file contains a `LockMeta` JSON object whose `updated` field is
/// refreshed every `LOCK_FRESHNESS_INTERVAL` (5 seconds) by a background tokio task.  If
/// another process finds the timestamp older than twice that interval the lock
/// is considered stale and forcibly removed.
///
/// # Atomic writes
///
/// Data is first written to a temporary file in the same directory, then
/// renamed into place. This ensures readers never see partial writes.
/// Default lock timeout (5 minutes).
const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub struct FileStorage {
    /// Root directory for all stored data.
    pub path: PathBuf,

    /// Maximum time to wait when acquiring a lock before returning an error.
    /// Defaults to 5 minutes.
    pub lock_timeout: Duration,

    /// Handles to keepalive tasks, keyed by lock name.
    lock_keepalives: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
}

impl FileStorage {
    /// Create a new `FileStorage` rooted at the given path.
    ///
    /// The path does not need to exist yet -- directories will be created
    /// on first write. For the platform-appropriate default location, use
    /// [`FileStorage::default()`] instead.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            lock_keepalives: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new `FileStorage` with a custom lock timeout.
    pub fn with_lock_timeout(path: impl Into<PathBuf>, lock_timeout: Duration) -> Self {
        Self {
            path: path.into(),
            lock_timeout,
            lock_keepalives: Mutex::new(HashMap::new()),
        }
    }

    // -- path helpers -------------------------------------------------------

    /// Map a storage key to an absolute filesystem path.
    fn filename(&self, key: &str) -> PathBuf {
        // Keys use forward-slash separators regardless of OS.
        let relative: PathBuf = key.split('/').collect();
        self.path.join(relative)
    }

    /// Return the directory that holds lock files.
    fn lock_dir(&self) -> PathBuf {
        self.path.join("locks")
    }

    /// Return the path to a specific lock file.
    fn lock_filename(&self, name: &str) -> PathBuf {
        self.lock_dir().join(format!("{}.lock", safe_key(name)))
    }

    // -- atomic file creation -----------------------------------------------

    /// Atomically create a new file at `path` with the given contents.
    ///
    /// The file is written to a temporary location first, then renamed.  On
    /// Unix the file permission is set to `mode`.
    async fn atomic_write(path: &Path, data: &[u8], _mode: u32) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
            #[cfg(unix)]
            {
                Self::set_dir_permissions(dir, 0o700).await.ok();
            }
        }

        // Build a temp file name in the same directory.
        let temp_name = format!(
            "{}.tmp.{}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            rand::random::<u64>(),
        );
        let temp_path = path.with_file_name(temp_name);

        // Write data to temp file.
        if let Err(e) = tokio::fs::write(&temp_path, data).await {
            // Clean up temp file on failure.
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        // Set file permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(_mode);
            if let Err(e) = tokio::fs::set_permissions(&temp_path, perms).await {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(e);
            }
        }

        // Rename into final location.
        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        Ok(())
    }

    #[cfg(unix)]
    async fn set_dir_permissions(dir: &Path, mode: u32) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        tokio::fs::set_permissions(dir, perms).await
    }

    // -- lock helpers -------------------------------------------------------

    /// Atomically create a lock file.  Returns `Ok(true)` if the file was
    /// created (lock acquired), `Ok(false)` if it already exists, or an error
    /// on unexpected I/O failure.
    async fn create_lock_file(filename: &Path) -> std::io::Result<bool> {
        // Ensure parent directory exists.
        if let Some(dir) = filename.parent() {
            tokio::fs::create_dir_all(dir).await?;
            #[cfg(unix)]
            {
                Self::set_dir_permissions(dir, 0o700).await.ok();
            }
        }

        // Use std::fs in a blocking task for O_EXCL semantics (tokio::fs does
        // not expose OpenOptions with create_new + write in a single atomic
        // step reliably on all platforms).
        let path = filename.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path);
            match file {
                Ok(f) => {
                    // Write initial lock metadata.
                    let now = chrono::Utc::now();
                    let meta = LockMeta {
                        created: now,
                        updated: now,
                    };
                    serde_json::to_writer(&f, &meta)?;
                    f.sync_all()?;
                    Ok(true)
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|e| std::io::Error::new(ErrorKind::Other, e))??;

        Ok(result)
    }

    /// Read and parse the metadata from a lock file.
    async fn read_lock_meta(filename: &Path) -> std::io::Result<Option<LockMeta>> {
        match tokio::fs::read(filename).await {
            Ok(bytes) => {
                if bytes.is_empty() {
                    return Ok(None);
                }
                let meta: LockMeta = serde_json::from_slice(&bytes)
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns `true` if the lock metadata indicates a stale lock.
    fn lock_is_stale(meta: &LockMeta) -> bool {
        let ref_time = meta.updated;
        let elapsed = chrono::Utc::now().signed_duration_since(ref_time);
        // Grace period: twice the freshness interval.
        elapsed
            > chrono::Duration::from_std(LOCK_FRESHNESS_INTERVAL * 2)
                .unwrap_or(chrono::Duration::MAX)
    }

    /// Update the `updated` timestamp in the lock file.
    async fn update_lock_freshness(filename: &Path) -> std::io::Result<bool> {
        let path = filename.to_path_buf();
        tokio::task::spawn_blocking(move || {
            // Open for read + write.
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(true), // lock released
                Err(e) => return Err(e),
            };

            // Read current metadata.
            let reader = std::io::BufReader::new(&file);
            let mut meta: LockMeta = match serde_json::from_reader(reader) {
                Ok(m) => m,
                Err(_) => return Ok(true), // corrupt / empty => stop keepalive
            };

            // Truncate and rewrite with updated timestamp.
            file.set_len(0)?;
            use std::io::Seek;
            (&file).seek(std::io::SeekFrom::Start(0))?;
            meta.updated = chrono::Utc::now();
            serde_json::to_writer(&file, &meta)
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
            file.sync_all()?;

            Ok(false) // keep going
        })
        .await
        .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?
    }

    /// Spawn a background task that periodically refreshes a lock file's
    /// timestamp.
    fn spawn_keepalive(filename: PathBuf) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(LOCK_FRESHNESS_INTERVAL).await;
                match Self::update_lock_freshness(&filename).await {
                    Ok(true) => return, // lock was released
                    Ok(false) => {}     // keep refreshing
                    Err(e) => {
                        error!(
                            lockfile = %filename.display(),
                            error = %e,
                            "keeping lock file fresh failed; stopping keepalive"
                        );
                        return;
                    }
                }
            }
        })
    }

    /// Core lock-acquisition loop.
    async fn obtain_lock(&self, name: &str) -> Result<()> {
        let filename = self.lock_filename(name);
        let mut empty_count: u32 = 0;

        loop {
            // Try to atomically create the lock file.
            match Self::create_lock_file(&filename).await {
                Ok(true) => {
                    // Lock acquired — start keepalive.
                    let handle = Self::spawn_keepalive(filename);
                    self.lock_keepalives
                        .lock()
                        .await
                        .insert(name.to_string(), handle);
                    return Ok(());
                }
                Ok(false) => {
                    // Lock file already exists — fall through to staleness check.
                }
                Err(e) => {
                    return Err(StorageError::LockFailed(format!("creating lock file: {e}")).into());
                }
            }

            // Lock file exists.  Read its metadata to check freshness.
            match Self::read_lock_meta(&filename).await {
                Ok(None) => {
                    // File disappeared or was empty.
                    empty_count += 1;
                    if empty_count < MAX_EMPTY_LOCK_READS {
                        tokio::time::sleep(EMPTY_LOCK_RETRY_DELAY).await;
                        continue;
                    }
                    // Treat as stale after too many empty reads.
                    info!(
                        name,
                        "lock file empty after {MAX_EMPTY_LOCK_READS} reads; treating as stale"
                    );
                    let _ = tokio::fs::remove_file(&filename).await;
                    continue;
                }
                Ok(Some(meta)) => {
                    if Self::lock_is_stale(&meta) {
                        info!(
                            name,
                            created = %meta.created,
                            updated = %meta.updated,
                            "lock is stale; removing and retrying"
                        );
                        match tokio::fs::remove_file(&filename).await {
                            Ok(()) => continue,
                            Err(e) if e.kind() == ErrorKind::NotFound => continue,
                            Err(e) => {
                                return Err(StorageError::LockFailed(format!(
                                    "unable to delete stale lockfile; deadlocked: {e}"
                                ))
                                .into());
                            }
                        }
                    }
                    // Lock is still fresh — wait and retry.
                    tokio::time::sleep(LOCK_POLL_INTERVAL).await;
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    // Lock file was just removed — retry immediately.
                    continue;
                }
                Err(e) => {
                    return Err(
                        StorageError::LockFailed(format!("accessing lock file: {e}")).into(),
                    );
                }
            }
        }
    }

    /// Try to acquire the lock with a maximum number of attempts.
    ///
    /// Returns `Ok(true)` if the lock was acquired, `Ok(false)` if
    /// `max_attempts` was reached without acquiring the lock.
    async fn try_obtain_lock(&self, name: &str, max_attempts: u32) -> Result<bool> {
        let filename = self.lock_filename(name);
        let mut empty_count: u32 = 0;
        let mut attempts: u32 = 0;

        loop {
            attempts += 1;
            if attempts > max_attempts {
                return Ok(false);
            }

            match Self::create_lock_file(&filename).await {
                Ok(true) => {
                    let handle = Self::spawn_keepalive(filename);
                    self.lock_keepalives
                        .lock()
                        .await
                        .insert(name.to_string(), handle);
                    return Ok(true);
                }
                Ok(false) => {
                    // Lock file already exists -- fall through to staleness check.
                }
                Err(e) => {
                    return Err(StorageError::LockFailed(format!("creating lock file: {e}")).into());
                }
            }

            match Self::read_lock_meta(&filename).await {
                Ok(None) => {
                    empty_count += 1;
                    if empty_count < MAX_EMPTY_LOCK_READS {
                        tokio::time::sleep(EMPTY_LOCK_RETRY_DELAY).await;
                        continue;
                    }
                    info!(
                        name,
                        "lock file empty after {MAX_EMPTY_LOCK_READS} reads; treating as stale"
                    );
                    let _ = tokio::fs::remove_file(&filename).await;
                    continue;
                }
                Ok(Some(meta)) => {
                    if Self::lock_is_stale(&meta) {
                        info!(
                            name,
                            created = %meta.created,
                            updated = %meta.updated,
                            "lock is stale; removing and retrying"
                        );
                        match tokio::fs::remove_file(&filename).await {
                            Ok(()) => continue,
                            Err(e) if e.kind() == ErrorKind::NotFound => continue,
                            Err(e) => {
                                return Err(StorageError::LockFailed(format!(
                                    "unable to delete stale lockfile; deadlocked: {e}"
                                ))
                                .into());
                            }
                        }
                    }
                    tokio::time::sleep(LOCK_POLL_INTERVAL).await;
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    continue;
                }
                Err(e) => {
                    return Err(
                        StorageError::LockFailed(format!("accessing lock file: {e}")).into(),
                    );
                }
            }
        }
    }

    /// Clean up empty ancestor directories up to (but not including)
    /// `self.path`.
    async fn clean_empty_dirs(&self, mut dir: &Path) {
        loop {
            if dir == self.path || !dir.starts_with(&self.path) {
                break;
            }
            // Try to remove — will fail if the directory is non-empty.
            if tokio::fs::remove_dir(dir).await.is_err() {
                break;
            }
            match dir.parent() {
                Some(parent) => dir = parent,
                None => break,
            }
        }
    }
}

impl Default for FileStorage {
    /// Create a `FileStorage` using the platform-appropriate default data
    /// directory and the default lock timeout.
    fn default() -> Self {
        Self::new(default_data_dir())
    }
}

impl std::fmt::Display for FileStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileStorage:{}", self.path.display())
    }
}

// ---------------------------------------------------------------------------
// Storage trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Storage for FileStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let filename = self.filename(key);

        // Determine permission mode based on whether this looks like a private
        // key (contains ".key" in path).
        let mode: u32 = if key.ends_with(".key") { 0o600 } else { 0o644 };

        Self::atomic_write(&filename, value, mode)
            .await
            .map_err(|e| Error::from(StorageError::Io(e)))
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let filename = self.filename(key);
        tokio::fs::read(&filename).await.map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                StorageError::NotFound(key.to_string()).into()
            } else {
                Error::from(StorageError::Io(e))
            }
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let filename = self.filename(key);

        // Try removing as a file first, then as a directory tree.
        match tokio::fs::remove_file(&filename).await {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => {
                // Might be a directory — remove recursively.
                match tokio::fs::remove_dir_all(&filename).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => return Err(StorageError::Io(e).into()),
                }
            }
        }

        // Clean up empty parent directories.
        if let Some(parent) = filename.parent() {
            self.clean_empty_dirs(parent).await;
        }

        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let filename = self.filename(key);
        match tokio::fs::metadata(&filename).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e).into()),
        }
    }

    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let walk_prefix = self.filename(prefix);
        let mut keys = Vec::new();

        // Use a manual stack-based walk so we can control recursion depth.
        let mut stack: Vec<PathBuf> = vec![walk_prefix.clone()];

        while let Some(dir) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(StorageError::Io(e).into()),
            };

            while let Some(entry) = entries.next_entry().await.map_err(StorageError::Io)? {
                let entry_path = entry.path();

                // Build the storage key by taking the suffix relative to
                // walk_prefix and joining it to the original prefix.
                let suffix = entry_path.strip_prefix(&walk_prefix).unwrap_or(&entry_path);
                // Normalise to forward slashes.
                let suffix_str = suffix
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let key = if prefix.is_empty() {
                    suffix_str
                } else {
                    format!("{prefix}/{suffix_str}")
                };

                keys.push(key);

                // If recursive, descend into subdirectories.
                let file_type = entry.file_type().await.map_err(StorageError::Io)?;
                if recursive && file_type.is_dir() {
                    stack.push(entry_path);
                }
            }
        }

        keys.sort();
        Ok(keys)
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        let filename = self.filename(key);
        let metadata = tokio::fs::metadata(&filename).await.map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                Error::from(StorageError::NotFound(key.to_string()))
            } else {
                Error::from(StorageError::Io(e))
            }
        })?;

        let modified: DateTime<Utc> = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH).into();

        Ok(KeyInfo {
            key: key.to_string(),
            modified,
            size: metadata.len(),
            is_terminal: !metadata.is_dir(),
        })
    }

    async fn lock(&self, name: &str) -> Result<()> {
        let result = match tokio::time::timeout(self.lock_timeout, self.obtain_lock(name)).await {
            Ok(result) => result,
            Err(_) => Err(StorageError::LockFailed(format!(
                "lock acquisition for {name:?} timed out after {:?}",
                self.lock_timeout,
            ))
            .into()),
        };
        if result.is_ok() {
            track_lock(name);
        }
        result
    }

    async fn try_lock(&self, name: &str, timeout: Duration) -> Result<bool> {
        match tokio::time::timeout(timeout, self.obtain_lock(name)).await {
            Ok(Ok(())) => {
                track_lock(name);
                Ok(true)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(false),
        }
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        // Cancel the keepalive task if one is running.
        if let Some(handle) = self.lock_keepalives.lock().await.remove(name) {
            handle.abort();
        }

        // Use spawn_blocking for the file removal so that it completes even
        // if the calling task is cancelled (e.g. via tokio::select! or
        // task abort).
        let filename = self.lock_filename(name);
        let result = tokio::task::spawn_blocking(move || match std::fs::remove_file(&filename) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::from(StorageError::Io(e))),
        })
        .await
        .map_err(|e| Error::Other(format!("unlock spawn_blocking failed: {e}")))?;

        untrack_lock(name);

        result
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the platform-appropriate default data directory for certon.
fn default_data_dir() -> PathBuf {
    // Try platform-specific directories first.
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("certon");
        }
        if let Some(home) = home_dir() {
            return home.join(".local").join("share").join("certon");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            return home
                .join("Library")
                .join("Application Support")
                .join("certon");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("certon");
        }
    }

    // Fallback for other platforms or when home is unavailable.
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        if let Some(home) = home_dir() {
            return home.join(".local").join("share").join("certon");
        }
    }

    // Last resort: current directory.
    PathBuf::from(".").join("certon")
}

/// Best-effort detection of the user's home directory from environment
/// variables.
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        if let (Ok(drive), Ok(path)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            return Some(PathBuf::from(format!("{drive}{path}")));
        }
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_key_basic() {
        assert_eq!(safe_key("Hello World"), "hello_world");
        assert_eq!(safe_key("*.example.com"), "wildcard_.example.com");
        assert_eq!(safe_key("a+b"), "a_plus_b");
        assert_eq!(safe_key("a:b"), "a-b");
        assert_eq!(safe_key("a..b"), "ab");
    }

    #[test]
    fn filename_mapping() {
        let fs = FileStorage::new("/data");
        assert_eq!(
            fs.filename("certificates/acme/example.com"),
            PathBuf::from("/data/certificates/acme/example.com")
        );
    }

    #[test]
    fn lock_filename_mapping() {
        let fs = FileStorage::new("/data");
        let lf = fs.lock_filename("my-lock");
        assert_eq!(lf, PathBuf::from("/data/locks/my-lock.lock"));
    }

    #[test]
    fn default_path_is_not_empty() {
        let dir = default_data_dir();
        assert!(
            dir.to_string_lossy().contains("certon"),
            "default dir should contain 'certon': {dir:?}"
        );
    }

    #[tokio::test]
    async fn store_load_delete_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = FileStorage::new(tmp.path());

        fs.store("test/key.txt", b"hello").await.unwrap();
        assert!(fs.exists("test/key.txt").await.unwrap());

        let data = fs.load("test/key.txt").await.unwrap();
        assert_eq!(data, b"hello");

        let info = fs.stat("test/key.txt").await.unwrap();
        assert_eq!(info.size, 5);
        assert!(info.is_terminal);

        fs.delete("test/key.txt").await.unwrap();
        assert!(!fs.exists("test/key.txt").await.unwrap());
    }

    #[tokio::test]
    async fn list_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = FileStorage::new(tmp.path());

        fs.store("a/b/c.txt", b"1").await.unwrap();
        fs.store("a/b/d.txt", b"2").await.unwrap();
        fs.store("a/e.txt", b"3").await.unwrap();

        let shallow = fs.list("a", false).await.unwrap();
        // Should contain "a/b" (dir) and "a/e.txt" (file)
        assert!(shallow.contains(&"a/b".to_string()));
        assert!(shallow.contains(&"a/e.txt".to_string()));
        // Should NOT contain the nested files at this level.
        assert!(!shallow.contains(&"a/b/c.txt".to_string()));

        let deep = fs.list("a", true).await.unwrap();
        assert!(deep.contains(&"a/b".to_string()));
        assert!(deep.contains(&"a/b/c.txt".to_string()));
        assert!(deep.contains(&"a/b/d.txt".to_string()));
        assert!(deep.contains(&"a/e.txt".to_string()));
    }

    #[tokio::test]
    async fn lock_unlock_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = FileStorage::new(tmp.path());

        fs.lock("mylock").await.unwrap();
        // Lock file should exist.
        assert!(fs.lock_filename("mylock").exists());

        fs.unlock("mylock").await.unwrap();
        // Lock file should be gone.
        assert!(!fs.lock_filename("mylock").exists());
    }
}
