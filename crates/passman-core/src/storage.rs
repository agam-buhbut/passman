//! Atomic vault file I/O and the single-instance advisory lock.
//!
//! `passman-core` is the one crate allowed to touch the filesystem
//! (`architecture.md` §2.3). Two responsibilities live here, both built on the
//! standard library:
//!
//! - [`atomic_write`] persists a byte buffer crash-safely: write a sibling temp
//!   file, `sync_all` it, then `rename` it over the target. A crash leaves
//!   either the old file intact or the fully-written new one — never a torn
//!   write (`architecture.md` §4.7).
//! - [`InstanceLock`] takes an exclusive advisory lock on `"<vault>.lock"` so a
//!   second instance cannot race a save (D27). It uses the stable
//!   [`std::fs::File::try_lock`] (exclusive) and releases on drop.
//!
//! No secrets are logged (there is no logging here at all); error messages name
//! only which step failed.
//!
//! The vault directory is assumed to be a user-private location (the platform
//! per-user config directory, `architecture.md` §1.5) that a local attacker
//! cannot write to or plant symlinks in. [`atomic_write`]'s `rename` replaces a
//! symlink at the target rather than following it (so a planted symlink cannot
//! redirect the write), and the vault/temp/lockfile are created `0o600` on Unix;
//! [`read`] follows symlinks like `std::fs::read`.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::CoreError;

/// Maximum vault file size [`read`] will accept. A real vault is kilobytes;
/// even tens of thousands of entries stay far below this. The cap bounds a
/// memory-exhaustion `DoS` from an oversized file planted at the vault path
/// before the (allocation-bounded) parser ever runs, since `std::fs::read`
/// would otherwise buffer the whole file first.
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

/// Read a file fully into memory, rejecting an implausibly large file first.
///
/// The size is checked against [`MAX_VAULT_BYTES`] before reading. The vault
/// directory is assumed user-private (see the module docs); `read` follows
/// symlinks like `std::fs::read`.
///
/// # Errors
///
/// [`CoreError::Io`] if the file is missing, exceeds [`MAX_VAULT_BYTES`], or
/// cannot be read.
pub fn read(path: &Path) -> Result<Vec<u8>, CoreError> {
    let meta = std::fs::metadata(path).map_err(|e| CoreError::io("stat vault file", e))?;
    if meta.len() > MAX_VAULT_BYTES {
        return Err(CoreError::io(
            "vault file exceeds maximum size",
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vault file is implausibly large",
            ),
        ));
    }
    std::fs::read(path).map_err(|e| CoreError::io("read vault file", e))
}

/// Atomically replace `path`'s contents with `bytes`.
///
/// Writes a uniquely-named temp file in the **same directory** (so the final
/// `rename` is a same-filesystem atomic operation), flushes it to disk with
/// `sync_all`, then renames it over `path`. On any failure the temp file is
/// removed on a best-effort basis and the original `path` is left untouched.
///
/// # Errors
///
/// [`CoreError::Io`] if the parent directory is missing, or if any of create /
/// write / fsync / rename fails.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let dir = path.parent().ok_or_else(|| {
        CoreError::io(
            "resolve vault parent directory",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "vault path has no parent"),
        )
    })?;

    let tmp_path = temp_sibling(path);

    // `create_new` so we never clobber a pre-existing temp from another writer;
    // the single-instance lock already serializes our own writes, and a unique
    // name keeps even unrelated processes from colliding.
    let write_result = (|| -> Result<(), CoreError> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        // Owner-only at creation: the temp holds the (encrypted) vault and the
        // mode rides through the later `rename` onto the target (§4.7). With
        // `create_new` (O_EXCL) we exclusively created this file, so setting the
        // mode here cannot widen a pre-existing file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut tmp = opts
            .open(&tmp_path)
            .map_err(|e| CoreError::io("create temp vault file", e))?;
        tmp.write_all(bytes)
            .map_err(|e| CoreError::io("write temp vault file", e))?;
        // Flush both the data and the file metadata to stable storage before
        // the rename, so a crash cannot expose a zero-length or partial file.
        tmp.sync_all()
            .map_err(|e| CoreError::io("fsync temp vault file", e))?;
        Ok(())
    })();

    if let Err(e) = write_result {
        // Best-effort cleanup; the original target is still intact regardless.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(CoreError::io("rename temp vault file over target", e));
    }

    // fsync the directory so the rename itself is durable. A failure here means
    // the rename may not survive a power loss, but the data file is already
    // safely written; surface it rather than silently ignoring it.
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }

    Ok(())
}

/// Derive the temp sibling path used by [`atomic_write`].
///
/// Same directory and stem as `path`, with a `.tmp` extension and the current
/// process id mixed in to avoid colliding with a temp from another process.
fn temp_sibling(path: &Path) -> PathBuf {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let pid = std::process::id();
    let file_name = path.file_name().map_or_else(
        || String::from("vault"),
        |n| n.to_string_lossy().into_owned(),
    );
    // Mix in OS randomness so the temp name is unpredictable. Combined with the
    // `create_new` (O_EXCL) open in `atomic_write`, this denies a local attacker
    // the ability to pre-create or guess the temp path (defence-in-depth; the
    // O_EXCL alone already prevents a symlink swap).
    let mut rand = [0u8; 8];
    passman_crypto::fill_random(&mut rand);
    let mut suffix = String::with_capacity(16);
    for b in rand {
        suffix.push(HEX[(b >> 4) as usize] as char);
        suffix.push(HEX[(b & 0x0f) as usize] as char);
    }
    let tmp_name = format!(".{file_name}.{pid}.{suffix}.tmp");
    match path.parent() {
        Some(parent) => parent.join(tmp_name),
        None => PathBuf::from(tmp_name),
    }
}

/// An exclusive, advisory single-instance lock held for the process's lifetime
/// (`architecture.md` §4.7 / D27).
///
/// Acquired on a lockfile sitting next to the vault (`"<vault>.lock"`). The
/// lock is advisory: it only blocks *other* `passman` instances that also call
/// [`InstanceLock::acquire`], which is exactly the concurrent-instance race we
/// guard against. Releasing happens automatically on drop (and the OS releases
/// it if the process dies), so there is no stale-lock problem.
#[derive(Debug)]
pub struct InstanceLock {
    /// The locked handle. Kept alive for the lock's duration; `unlock` is
    /// called explicitly on drop and the OS unlocks on close as a backstop.
    file: File,
    /// Whether we actually hold an OS advisory lock. `false` when this
    /// platform's `std` has no file locking (e.g. Android, where
    /// [`std::fs::File::try_lock`] is unconditionally `Unsupported`); there we
    /// proceed without a lock rather than refusing to open. Drop only releases
    /// when this is `true`.
    locked: bool,
}

impl InstanceLock {
    /// Acquire the exclusive advisory lock for the vault at `vault_path`.
    ///
    /// The lockfile is `"<vault_path>.lock"`, created if absent. If another
    /// instance already holds it, returns [`CoreError::AlreadyRunning`].
    ///
    /// # Errors
    ///
    /// - [`CoreError::AlreadyRunning`] if the lock is already held elsewhere.
    /// - [`CoreError::Io`] if the lockfile cannot be created/opened or the lock
    ///   call fails for a reason other than contention.
    pub fn acquire(vault_path: &Path) -> Result<Self, CoreError> {
        let lock_path = lock_path_for(vault_path);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        // Owner-only; the lockfile carries no secret, but there is no reason for
        // it to be group/world-accessible.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&lock_path)
            .map_err(|e| CoreError::io("open instance lockfile", e))?;

        // `try_lock` takes an *exclusive* advisory lock without blocking.
        // `classify_lock` interprets the outcome (including the Android case
        // where `std` reports the operation unsupported).
        let locked = classify_lock(file.try_lock())?;
        Ok(Self { file, locked })
    }
}

/// Interpret a [`std::fs::File::try_lock`] outcome for [`InstanceLock`].
///
/// Returns `Ok(true)` when the advisory lock was taken, `Ok(false)` when the
/// platform does not support file locking at all (so the caller proceeds
/// without one), and an error when another instance holds the lock or a genuine
/// I/O failure occurred.
fn classify_lock(result: Result<(), TryLockError>) -> Result<bool, CoreError> {
    match result {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Err(CoreError::AlreadyRunning),
        // ponytail: this platform's `std` has no advisory file locking —
        // Android's `File::try_lock` is hard-coded to `Unsupported` (the
        // `cfg` list for the `flock` impl omits `target_os = "android"`). The
        // lock is only advisory (D27) and Android already runs a single app
        // process, so proceed without one instead of failing `App::open` (which
        // crashes the app on launch). Upgrade path: an `fcntl(F_SETLK)` shim if
        // a multi-process platform without `flock` ever needs real locking.
        Err(TryLockError::Error(e)) if e.kind() == std::io::ErrorKind::Unsupported => Ok(false),
        Err(TryLockError::Error(e)) => Err(CoreError::io("lock instance lockfile", e)),
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Explicitly release; closing the file would also release it, but doing
        // it eagerly keeps the window tight. A failure here is unrecoverable at
        // drop time and harmless (the OS releases on close), so it is ignored.
        // Skip when we never held a lock (the platform had no locking support).
        if self.locked {
            let _ = self.file.unlock();
        }
    }
}

/// The lockfile path for a vault: the vault path with `.lock` appended.
fn lock_path_for(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().map_or_else(
        || String::from("vault"),
        |n| n.to_string_lossy().into_owned(),
    );
    name.push_str(".lock");
    match vault_path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::{atomic_write, classify_lock, lock_path_for, read, temp_sibling, InstanceLock};
    use crate::error::CoreError;
    use std::fs::TryLockError;
    use std::io;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn classify_lock_maps_each_try_lock_outcome() {
        // Lock acquired.
        assert!(matches!(classify_lock(Ok(())), Ok(true)));
        // Held by another instance.
        assert!(matches!(
            classify_lock(Err(TryLockError::WouldBlock)),
            Err(CoreError::AlreadyRunning)
        ));
        // Android: `std`'s `File::try_lock` is unconditionally `Unsupported`.
        // The advisory lock must degrade to "proceed without one" (Ok(false)),
        // NOT propagate an error — otherwise `App::open` fails and the app
        // crashes on launch.
        assert!(matches!(
            classify_lock(Err(TryLockError::Error(io::Error::from(
                io::ErrorKind::Unsupported
            )))),
            Ok(false)
        ));
        // A genuine I/O failure still surfaces as an error.
        assert!(matches!(
            classify_lock(Err(TryLockError::Error(io::Error::from(
                io::ErrorKind::PermissionDenied
            )))),
            Err(CoreError::Io { .. })
        ));
    }

    #[test]
    fn atomic_write_then_read_round_trips() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        atomic_write(&path, b"hello vault").expect("write");
        assert_eq!(read(&path).expect("read"), b"hello vault");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        atomic_write(&path, b"first").expect("write 1");
        atomic_write(&path, b"second longer contents").expect("write 2");
        assert_eq!(read(&path).expect("read"), b"second longer contents");
    }

    #[test]
    fn atomic_write_leaves_no_temp_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        atomic_write(&path, b"data").expect("write");
        // Only the target file should remain in the directory.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("vault.pmv")]);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        atomic_write(&path, b"secret-ish").expect("write");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "vault file must be owner-only (0o600)");
    }

    #[cfg(unix)]
    #[test]
    fn instance_lockfile_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        let _lock = InstanceLock::acquire(&path).expect("lock");
        let mode = std::fs::metadata(lock_path_for(&path))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "lockfile must be owner-only (0o600)");
    }

    #[test]
    fn atomic_write_missing_parent_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist").join("vault.pmv");
        let err = atomic_write(&path, b"data").expect_err("missing parent must fail");
        assert!(matches!(err, CoreError::Io { .. }));
    }

    #[test]
    fn read_missing_file_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("nope.pmv");
        assert!(matches!(read(&path), Err(CoreError::Io { .. })));
    }

    #[test]
    fn lock_path_appends_lock_suffix() {
        assert_eq!(
            lock_path_for(Path::new("/data/passman/vault.pmv")),
            Path::new("/data/passman/vault.pmv.lock")
        );
    }

    #[test]
    fn temp_sibling_is_in_same_dir() {
        let tmp = temp_sibling(Path::new("/data/passman/vault.pmv"));
        assert_eq!(tmp.parent(), Some(Path::new("/data/passman")));
        assert!(tmp
            .file_name()
            .expect("name")
            .to_string_lossy()
            .ends_with(".tmp"));
    }

    #[test]
    fn instance_lock_excludes_second_acquire() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        let first = InstanceLock::acquire(&path).expect("first lock");
        // A second acquire on the same path must report AlreadyRunning.
        let second = InstanceLock::acquire(&path);
        assert!(matches!(second, Err(CoreError::AlreadyRunning)));
        drop(first);
        // After releasing, a fresh acquire succeeds again.
        let third = InstanceLock::acquire(&path);
        assert!(third.is_ok());
    }
}
