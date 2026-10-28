//! File-system-based storage backend for certon.
//!
//! This module implements [`Storage`] using the local file system.  Highlights:
//!
//! * **Atomic writes** — data is first written to a temporary file in the same directory, then
//!   renamed into place so that readers never see a partial write.
//! * **Process locking** — OS advisory locks are held by open file handles. Process exit
//!   releases ownership automatically. Lock files are never removed or replaced, avoiding
//!   stale-owner unlink/renewal races. Shared filesystems must support cross-host OS locks;
//!   this backend does not provide fencing tokens or time-based lease takeover.
//! * **Platform-aware defaults** — the default storage path follows OS conventions
//!   (`~/.local/share/certon` on Linux, `~/Library/Application Support/certon` on macOS,
//!   `%APPDATA%/certon` on Windows).

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::error::{Error, Result, StorageError};
use crate::storage::{KeyInfo, Storage, safe_key};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How often to poll when waiting for a lock held by another process.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// FileStorage
// ---------------------------------------------------------------------------

/// Default lock acquisition timeout (5 minutes).
const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// A [`Storage`] implementation backed by the local file system.
///
/// This is the default storage backend, suitable for single-server
/// deployments. For multi-server / clustered deployments, consider a
/// shared-filesystem or database-backed implementation.
///
/// # Locking
///
/// Locks are OS advisory locks on permanent files under
/// `<path>/locks/<safe_name>.lock`. Ownership belongs to the open handle, so
/// a crashed process releases it and an old owner cannot unlink a successor's
/// lock. An active owner is never evicted based on timestamps. Empty or corrupt
/// legacy lock metadata is harmless. This is not a fencing protocol: a shared
/// filesystem must implement cross-host advisory locking correctly. Stop old
/// certon processes before upgrading; timestamp-based and OS locks must not be
/// mixed on the same storage directory.
///
/// # Atomic writes
///
/// Data is first written to a temporary file in the same directory, then
/// renamed into place. This ensures readers never see partial writes.
pub struct FileStorage {
    /// Root directory for all stored data.
    pub path: PathBuf,

    /// Maximum time to wait when acquiring a lock before returning an error.
    /// Defaults to 5 minutes.
    pub lock_timeout: Duration,

    /// Open handles own OS locks; dropping a handle releases only that lock.
    held_locks: Mutex<HashMap<String, std::fs::File>>,
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
            held_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new `FileStorage` with a custom lock timeout.
    pub fn with_lock_timeout(path: impl Into<PathBuf>, lock_timeout: Duration) -> Self {
        Self {
            path: path.into(),
            lock_timeout,
            held_locks: Mutex::new(HashMap::new()),
        }
    }

    // -- path helpers -------------------------------------------------------

    /// Map a storage key to a filesystem path under the storage root.
    fn filename(&self, key: &str) -> Result<PathBuf> {
        self.filename_inner(key, false)
    }

    /// Map a storage prefix to a filesystem path under the storage root.
    fn prefix_filename(&self, prefix: &str) -> Result<PathBuf> {
        self.filename_inner(prefix, true)
    }

    fn filename_inner(&self, key: &str, allow_empty: bool) -> Result<PathBuf> {
        if key.is_empty() {
            return if allow_empty {
                Ok(self.path.clone())
            } else {
                Err(invalid_key_error(key, "empty keys are not allowed"))
            };
        }

        if key.contains('\\') {
            return Err(invalid_key_error(
                key,
                "keys must use forward slash separators",
            ));
        }

        if key.contains('\0') {
            return Err(invalid_key_error(key, "keys must not contain NUL bytes"));
        }

        let mut relative = PathBuf::new();
        for component in key.split('/') {
            if component.is_empty() {
                return Err(invalid_key_error(
                    key,
                    "keys must not contain empty path components",
                ));
            }
            if component == "." || component == ".." {
                return Err(invalid_key_error(
                    key,
                    "keys must not contain dot path components",
                ));
            }
            if component.contains(':') {
                return Err(invalid_key_error(
                    key,
                    "keys must not contain drive or alternate-stream separators",
                ));
            }

            let component_path = Path::new(component);
            if component_path.is_absolute()
                || component_path.components().any(|part| {
                    matches!(
                        part,
                        Component::Prefix(_)
                            | Component::RootDir
                            | Component::ParentDir
                            | Component::CurDir
                    )
                })
            {
                return Err(invalid_key_error(
                    key,
                    "keys must be relative storage paths",
                ));
            }

            relative.push(component);
        }

        let filename = self.path.join(relative);
        if !filename.starts_with(&self.path) {
            return Err(invalid_key_error(
                key,
                "resolved key escapes the storage root",
            ));
        }

        Ok(filename)
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

        let data = data.to_vec();
        let temp_path_for_write = temp_path.clone();
        let write_result = tokio::task::spawn_blocking(move || {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(_mode);
            }

            let mut file = options.open(&temp_path_for_write)?;
            file.write_all(&data)?;
            file.sync_all()?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(std::io::Error::other);

        if let Err(e) = write_result.and_then(|inner| inner) {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        // Rename into final location.
        if let Err(e) = tokio::fs::rename(&temp_path, path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            let parent = parent.to_owned();
            tokio::task::spawn_blocking(move || std::fs::File::open(parent)?.sync_all())
                .await
                .map_err(std::io::Error::other)??;
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

    /// Open one permanent lock inode. Never unlink it: another process may
    /// already be waiting on the same inode.
    async fn obtain_lock(&self, name: &str) -> Result<()> {
        let filename = self.lock_filename(name);
        let mut file = tokio::task::spawn_blocking(move || {
            if let Some(parent) = filename.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(filename)
        })
        .await
        .map_err(|e| Error::Other(format!("opening lock task failed: {e}")))?
        .map_err(|e| StorageError::LockFailed(format!("opening lock file: {e}")))?;
        loop {
            // A cancelled blocking attempt drops its returned handle, which
            // releases any OS lock it acquired before cancellation.
            let (returned_file, locked) = tokio::task::spawn_blocking(move || {
                let locked = match file.try_lock() {
                    Ok(()) => true,
                    Err(std::fs::TryLockError::WouldBlock) => false,
                    Err(std::fs::TryLockError::Error(error)) => return Err(error),
                };
                Ok((file, locked))
            })
            .await
            .map_err(|e| Error::Other(format!("lock attempt task failed: {e}")))?
            .map_err(|e| StorageError::LockFailed(format!("locking file: {e}")))?;
            file = returned_file;
            if locked {
                self.held_locks.lock().await.insert(name.to_owned(), file);
                return Ok(());
            }
            tokio::time::sleep(LOCK_POLL_INTERVAL).await;
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
        let filename = self.filename(key)?;

        // Determine permission mode based on whether this looks like a private
        // key (contains ".key" in path).
        let mode: u32 = if key.ends_with(".key") { 0o600 } else { 0o644 };

        Self::atomic_write(&filename, value, mode)
            .await
            .map_err(|e| Error::from(StorageError::Io(e)))
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let filename = self.filename(key)?;
        tokio::fs::read(&filename).await.map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                StorageError::NotFound(key.to_string()).into()
            } else {
                Error::from(StorageError::Io(e))
            }
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let filename = self.filename(key)?;

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
        let filename = self.filename(key)?;
        match tokio::fs::metadata(&filename).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e).into()),
        }
    }

    async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let walk_prefix = self.prefix_filename(prefix)?;
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
        let filename = self.filename(key)?;
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
        match tokio::time::timeout(self.lock_timeout, self.obtain_lock(name)).await {
            Ok(result) => result,
            Err(_) => Err(StorageError::LockFailed(format!(
                "lock acquisition for {name:?} timed out after {:?}",
                self.lock_timeout,
            ))
            .into()),
        }
    }

    async fn try_lock(&self, name: &str, timeout: Duration) -> Result<bool> {
        match tokio::time::timeout(timeout, self.obtain_lock(name)).await {
            Ok(Ok(())) => Ok(true),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(false),
        }
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        // Removing our own handle cannot release another instance's lock.
        // There is no path-based check/remove operation and no renewal task.
        if let Some(file) = self.held_locks.lock().await.remove(name) {
            tokio::task::spawn_blocking(move || drop(file))
                .await
                .map_err(|e| Error::Other(format!("unlock task failed: {e}")))?;
        }
        Ok(())
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

fn invalid_key_error(key: &str, reason: &str) -> Error {
    StorageError::Io(std::io::Error::new(
        ErrorKind::InvalidInput,
        format!("invalid storage key {key:?}: {reason}"),
    ))
    .into()
}

/// Best-effort detection of the user's home directory from environment
/// variables.
#[allow(dead_code)]
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
            fs.filename("certificates/acme/example.com").unwrap(),
            PathBuf::from("/data/certificates/acme/example.com")
        );
    }

    #[test]
    fn filename_rejects_escape_keys() {
        let fs = FileStorage::new("/data");
        for key in [
            "",
            "../outside",
            "certs/../../outside",
            "/absolute",
            "certs//leaf",
            "certs/",
            "certs/./leaf",
            "certs\\leaf",
            "C:/outside",
            "certs/leaf:key",
        ] {
            assert!(fs.filename(key).is_err(), "key should be rejected: {key}");
        }
    }

    #[test]
    fn empty_prefix_maps_to_storage_root_for_listing() {
        let fs = FileStorage::new("/data");
        assert_eq!(fs.prefix_filename("").unwrap(), PathBuf::from("/data"));
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
        // The inode is permanent; availability follows OS ownership.
        assert!(fs.lock_filename("mylock").exists());
        let other = FileStorage::new(tmp.path());
        assert!(
            other
                .try_lock("mylock", Duration::from_secs(1))
                .await
                .unwrap()
        );
        other.unlock("mylock").await.unwrap();
    }
}
