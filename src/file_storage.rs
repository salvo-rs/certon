//! File-system-based storage backend for certon.
//!
//! This module implements [`Storage`] using the local file system.  Highlights:
//!
//! * **Atomic writes** — data is first written to a temporary file in the same directory, then
//!   renamed into place so that readers never see a partial write.
//! * **Process locking** — OS advisory locks are held by open file handles. Process exit releases
//!   ownership automatically. Lock files are never removed or replaced, avoiding stale-owner
//!   unlink/renewal races. Shared filesystems must support cross-host OS locks; this backend does
//!   not provide fencing tokens or time-based lease takeover.
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
#[cfg(test)]
use crate::storage::safe_key;
use crate::storage::{KeyInfo, Storage, storage_identity_hash};

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

/// Own exactly one successfully created temporary file across blocking tasks.
/// The file handle is closed before unlink/rename, including panic unwinding
/// and a blocking task whose result is abandoned by a cancelled caller.
struct TemporaryWrite {
    path: PathBuf,
    file: Option<std::fs::File>,
    armed: bool,
}

impl TemporaryWrite {
    fn write_with(
        path: PathBuf,
        _mode: u32,
        write_and_sync: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(_mode);
        }
        // A collision must never arm cleanup for somebody else's file.
        let file = options.open(&path)?;
        let mut temporary = Self {
            path,
            file: Some(file),
            armed: true,
        };
        write_and_sync(
            temporary
                .file
                .as_mut()
                .expect("new temporary owns its open file"),
        )?;
        temporary.close();
        Ok(temporary)
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn commit(mut self, destination: PathBuf) -> std::io::Result<()> {
        self.close();
        std::fs::rename(&self.path, &destination)?;
        self.armed = false;
        #[cfg(unix)]
        if let Some(parent) = destination.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

impl Drop for TemporaryWrite {
    fn drop(&mut self) {
        self.close();
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A [`Storage`] implementation backed by the local file system.
///
/// This is the default storage backend, suitable for single-server
/// deployments. For multi-server / clustered deployments, consider a
/// shared-filesystem or database-backed implementation.
///
/// # Directory trust
///
/// The root and its parent directories must be controlled by trusted operators.
/// Keep certificate files and private keys inaccessible to other accounts using
/// Unix permissions or Windows ACLs. Key validation rejects lexical traversal,
/// but filesystem operations can follow symbolic links, junctions and other
/// reparse points. This backend does not confine an attacker who can replace
/// directories or links beneath the root. Do not use an attacker-writable tree
/// or allow untrusted uploads in the storage directory.
///
/// Unix writes create restricted files and attempt to restrict the immediate
/// parent directory. This does not verify ownership or all ancestor permissions;
/// Windows ACLs must be configured by the operator before use.
///
/// # Locking
///
/// Locks are OS advisory locks on permanent files under
/// `<path>/locks/<safe_name>.lock`. Ownership belongs to the open handle, so
/// a crashed process releases it and an old owner cannot unlink a successor's
/// lock. An active owner is never evicted based on timestamps. Empty or corrupt
/// legacy lock metadata is harmless. Unlocking releases the registry mutex before
/// awaiting the blocking handle close; cancelling that await does not cancel the
/// submitted close worker, which owns the handle. This is not a fencing protocol: a shared
/// filesystem must implement cross-host advisory locking correctly. Stop old
/// certon processes before upgrading; timestamp-based and OS locks must not be
/// mixed on the same storage directory.
///
/// # Atomic writes
///
/// Data is first written to a temporary file in the same directory, then
/// renamed into place. This ensures readers never see partial writes.
/// Cancellation is not rollback: once the completed write is handed off for
/// rename, that blocking commit can still publish the whole replacement.
/// Until commit, the writer or its returned guard owns temporary-file cleanup,
/// including when a cancelled caller never receives the blocking task result.
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
        let identity = crate::storage::lock_storage_identity(name);
        let filename = format!("{identity}.lock");
        if filename.len() <= 255 {
            self.lock_dir().join(filename)
        } else {
            self.lock_dir()
                .join("_certon-long-v1")
                .join(format!("{}.lock", storage_identity_hash(&identity)))
        }
    }

    /// Old derived keys can contain a component that this filesystem cannot
    /// represent. Only an actual name-length error plus an oversized component
    /// proves absence; permissions and whole-path length errors still propagate.
    fn absent_long_component(error: &std::io::Error, key: &str) -> bool {
        #[cfg(windows)]
        {
            matches!(error.raw_os_error(), Some(123 | 206))
                && key.split('/').any(|part| part.encode_utf16().count() > 255)
        }
        #[cfg(unix)]
        {
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            let too_long = 63;
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            )))]
            let too_long = 36;
            error.raw_os_error() == Some(too_long) && key.split('/').any(|part| part.len() > 255)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (error, key);
            false
        }
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

        // Use an independent bounded basename: appending a suffix to the
        // destination would exceed filesystem limits for valid long keys.
        // Keeping the temporary file beside its destination preserves rename
        // atomicity and the existing create_new/permission/cleanup behavior.
        let temp_name = format!(".certon-write-{:032x}.tmp", rand::random::<u128>());
        let temp_path = path.with_file_name(temp_name);

        let data = data.to_vec();
        let temporary = tokio::task::spawn_blocking(move || {
            TemporaryWrite::write_with(temp_path, _mode, |file| {
                file.write_all(&data)?;
                file.sync_all()
            })
        })
        .await
        .map_err(std::io::Error::other)??;

        // Commit owns the guard too: cancelling this await cannot delete a
        // file that the blocking rename is still using. Successful rename
        // disarms cleanup; a failed/abandoned commit cleans its own source.
        let destination = path.to_owned();
        tokio::task::spawn_blocking(move || temporary.commit(destination))
            .await
            .map_err(std::io::Error::other)?
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
            if e.kind() == ErrorKind::NotFound || Self::absent_long_component(&e, key) {
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
            Err(e) if e.kind() == ErrorKind::NotFound || Self::absent_long_component(&e, key) => {}
            Err(_) => {
                // Might be a directory — remove recursively.
                match tokio::fs::remove_dir_all(&filename).await {
                    Ok(()) => {}
                    Err(e)
                        if e.kind() == ErrorKind::NotFound
                            || Self::absent_long_component(&e, key) => {}
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
            Err(e) if e.kind() == ErrorKind::NotFound || Self::absent_long_component(&e, key) => {
                Ok(false)
            }
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
            if e.kind() == ErrorKind::NotFound || Self::absent_long_component(&e, key) {
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
        // A close may wait for blocking capacity. Release bookkeeping first so
        // it cannot hold up independent keys on another runtime.
        let file = {
            let mut held_locks = self.held_locks.lock().await;
            held_locks.remove(name)
        };
        if let Some(file) = file {
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
    fn long_component_absence_never_hides_permission_or_whole_path_failures() {
        let long = format!("legacy/{}.json", "x".repeat(253));
        let permission = std::io::Error::new(ErrorKind::PermissionDenied, "denied");
        assert!(!FileStorage::absent_long_component(&permission, &long));
        #[cfg(windows)]
        for code in [123, 206] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(FileStorage::absent_long_component(&error, &long));
            assert!(!FileStorage::absent_long_component(
                &error,
                &"ordinary/".repeat(100)
            ));
            assert!(
                !FileStorage::absent_long_component(&error, &"é".repeat(200)),
                "Windows counts UTF-16 units, not UTF-8 bytes"
            );
        }
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
    async fn temporary_write_failure_and_panic_close_and_remove_the_owned_file() {
        let directory = tempfile::tempdir().unwrap();
        for stage in ["write", "fsync"] {
            let path = directory.path().join(format!("{stage}.tmp"));
            let error = TemporaryWrite::write_with(path.clone(), 0o600, |file| {
                file.write_all(if stage == "write" {
                    b"partial"
                } else {
                    b"complete"
                })?;
                Err(std::io::Error::other(format!("injected {stage} failure")))
            })
            .err()
            .unwrap();
            assert!(error.to_string().contains(stage));
            assert!(
                !path.exists(),
                "failed {stage} left its temporary private bytes"
            );
        }
        let path = directory.path().join("panic.tmp");
        let result = std::panic::catch_unwind(|| {
            TemporaryWrite::write_with(path.clone(), 0o600, |file| {
                file.write_all(b"private bytes before panic")?;
                panic!("injected temporary writer panic");
            })
        });
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn temporary_name_collision_never_deletes_or_changes_the_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("collision.tmp");
        std::fs::write(&path, b"another writer's private resource").unwrap();
        let error = TemporaryWrite::write_with(path.clone(), 0o600, |_| {
            panic!("a failed create_new must never invoke the writer")
        })
        .err()
        .unwrap();
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(path).unwrap(),
            b"another writer's private resource"
        );
    }

    #[test]
    fn failed_rename_cleans_its_source_and_preserves_the_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("rename.tmp");
        let destination = directory.path().join("existing-directory");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("old"), b"old resource").unwrap();
        let temporary = TemporaryWrite::write_with(source.clone(), 0o600, |file| {
            file.write_all(b"replacement")?;
            file.sync_all()
        })
        .unwrap();
        assert!(
            temporary.file.is_none(),
            "transfer must close the Windows file handle"
        );
        assert!(temporary.commit(destination.clone()).is_err());
        assert!(!source.exists());
        assert_eq!(
            std::fs::read(destination.join("old")).unwrap(),
            b"old resource"
        );
    }

    struct BlockingRelease(Option<std::sync::mpsc::Sender<()>>);
    impl BlockingRelease {
        fn signal(&mut self) {
            if let Some(release) = self.0.take() {
                let _ = release.send(());
            }
        }
    }
    impl Drop for BlockingRelease {
        fn drop(&mut self) {
            self.signal();
        }
    }

    #[test]
    fn cancellation_does_not_remove_a_temporary_file_while_its_writer_is_running() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("running.tmp");
        let destination = directory.path().join("canonical");
        std::fs::write(&destination, b"old").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let mut release = BlockingRelease(Some(release_tx));
            let caller = tokio::spawn({
                let source = source.clone();
                let destination = destination.clone();
                async move {
                    let temporary = tokio::task::spawn_blocking(move || {
                        TemporaryWrite::write_with(source, 0o600, |file| {
                            file.write_all(b"partial")?;
                            let _ = entered_tx.send(());
                            let _ = release_rx.recv();
                            file.write_all(b" complete")?;
                            file.sync_all()
                        })
                    })
                    .await
                    .map_err(std::io::Error::other)??;
                    tokio::task::spawn_blocking(move || temporary.commit(destination))
                        .await
                        .map_err(std::io::Error::other)?
                }
            });
            entered_rx.await.unwrap();
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            assert_eq!(
                std::fs::read(&source).unwrap(),
                b"partial",
                "the cancelled awaiter must not delete a still-running writer's file"
            );
            release.signal();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert!(!source.exists());
            assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        });
    }

    #[test]
    fn an_abandoned_commit_still_publishes_one_complete_file_and_leaves_no_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("commit.tmp");
        let destination = directory.path().join("canonical");
        std::fs::write(&destination, b"old").unwrap();
        let temporary = TemporaryWrite::write_with(source.clone(), 0o600, |file| {
            file.write_all(b"complete new resource")?;
            file.sync_all()
        })
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let mut release = BlockingRelease(Some(release_tx));
            let gate = tokio::task::spawn_blocking(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
            });
            entered_rx.await.unwrap();
            let commit = tokio::task::spawn_blocking({
                let destination = destination.clone();
                move || temporary.commit(destination)
            });
            drop(commit);
            assert!(
                source.exists(),
                "commit worker must retain its source while queued"
            );
            assert_eq!(std::fs::read(&destination).unwrap(), b"old");
            release.signal();
            gate.await.unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert!(!source.exists());
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                b"complete new resource"
            );
        });
    }

    #[tokio::test]
    async fn maximum_filename_round_trip_preserves_secret_mode_and_leaves_no_temp_file() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let key = format!("nested/{}.key", "p".repeat(251));
        assert_eq!(key.rsplit('/').next().unwrap().len(), 255);
        storage.store(&key, b"first").await.unwrap();
        storage.store(&key, b"replacement").await.unwrap();
        assert_eq!(storage.load(&key).await.unwrap(), b"replacement");
        assert_eq!(
            storage.list("nested", false).await.unwrap(),
            vec![key.clone()]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(directory.path().join(&key))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
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
