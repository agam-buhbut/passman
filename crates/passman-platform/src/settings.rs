//! The plaintext, non-secret `settings.toml` (`architecture.md` §1.5).
//!
//! Settings are stored *outside* the vault so options like `update_check` are
//! readable **before** unlock. They never hold vault content, keys, or labels.
//! The key set is **fixed and validated on load**: unknown keys are rejected
//! (`deny_unknown_fields`) and missing keys fall back to their documented
//! defaults (`#[serde(default)]`), so a partial or absent file is still valid.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// The complete, fixed set of passman settings.
///
/// Every field is a non-secret toggle with a documented default. Adding a key
/// to the file that is not listed here is a load error (the set is closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// Opt-in network update check (`architecture.md` §9.6). Default **off**:
    /// the binary makes no network connection unless this is set.
    pub update_check: bool,

    /// Gate the TOTP-seed HSM slot behind a distinct PIN, a knowledge factor
    /// separate from the master password (`architecture.md` §1.6). Default
    /// **off**.
    pub totp_seed_pin: bool,

    /// On clipboard clear, overwrite with a crypto fact rather than emptying it
    /// (`architecture.md` §5.3). Default **on**.
    pub clipboard_fact_overwrite: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            update_check: false,
            totp_seed_pin: false,
            clipboard_fact_overwrite: true,
        }
    }
}

impl Settings {
    /// Parse settings from TOML text, rejecting unknown keys and filling missing
    /// keys with their defaults.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Settings`] if the text is not valid TOML, has an unknown
    /// key, or has a value of the wrong type.
    pub fn from_toml(text: &str) -> Result<Self, PlatformError> {
        toml::from_str(text).map_err(|e| PlatformError::Settings(e.to_string()))
    }

    /// Serialize settings to TOML text.
    #[must_use]
    pub fn to_toml(&self) -> String {
        // A fixed struct of bools always serializes; default to empty on the
        // unreachable error rather than panicking.
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Load settings from `path`.
    ///
    /// A **missing** file yields the defaults (settings are optional and
    /// readable before unlock). A **present but invalid** file is an error —
    /// fail loud rather than silently substituting defaults for a corrupt file.
    ///
    /// # Errors
    ///
    /// - [`PlatformError::Settings`] if the file is present but invalid.
    /// - [`PlatformError::Io`] if the file exists but cannot be read.
    pub fn load(path: &Path) -> Result<Self, PlatformError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PlatformError::io("read settings file", e)),
        }
    }

    /// Write settings to `path` atomically, creating the parent directory if
    /// needed.
    ///
    /// The write is crash-safe: a uniquely-named temp file in the same directory
    /// is written and `fsync`ed, then renamed over `path`. A crash or a
    /// concurrent reader therefore never observes a truncated or partially
    /// written `settings.toml`; on any failure the original file is left intact.
    /// `load` fails closed on a corrupt file, so a torn write would otherwise
    /// lose the settings entirely.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Io`] if the directory cannot be created or the file
    /// cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), PlatformError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PlatformError::io("create settings directory", e))?;
        }
        atomic_write(path, &self.to_toml())
    }
}

/// Atomically replace `path`'s contents with `text`.
///
/// Mirrors the vault's write discipline in `passman-core::storage::atomic_write`
/// (reimplemented here so this crate has no dependency on the core): write a
/// sibling temp file in the **same directory** so the final `rename` is a
/// same-filesystem atomic operation, `sync_all` it, then rename it over `path`.
/// On any failure the temp file is removed best-effort and the original `path`
/// is left untouched.
fn atomic_write(path: &Path, text: &str) -> Result<(), PlatformError> {
    let tmp_path = temp_sibling(path);

    // Write + fsync the temp; on any failure remove it and leave `path` intact.
    if let Err(e) = write_temp(&tmp_path, text.as_bytes()) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // The rename is atomic on the same filesystem: a reader sees either the old
    // file or the fully written new one, never a torn write.
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(PlatformError::io(
            "rename temp settings file over target",
            e,
        ));
    }

    Ok(())
}

/// Create a fresh temp file, write all of `bytes`, and `sync_all` it.
///
/// On Unix the file is created `0o600` (owner-only) with `create_new` (`O_EXCL`)
/// so the mode is set on a file we exclusively created and a pre-existing temp
/// is never clobbered. The `sync_all` flushes data and metadata before the
/// caller renames, so a crash cannot expose a zero-length or partial file.
fn write_temp(tmp_path: &Path, bytes: &[u8]) -> Result<(), PlatformError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The settings file is non-secret, but owner-only is still correct.
        opts.mode(0o600);
    }
    let mut tmp = opts
        .open(tmp_path)
        .map_err(|e| PlatformError::io("create temp settings file", e))?;
    tmp.write_all(bytes)
        .map_err(|e| PlatformError::io("write temp settings file", e))?;
    tmp.sync_all()
        .map_err(|e| PlatformError::io("fsync temp settings file", e))?;
    Ok(())
}

/// Derive the temp sibling path used by [`atomic_write`].
///
/// Same directory as `path`, with a leading dot plus the process id, a monotonic
/// counter, and a nanosecond timestamp so concurrent or repeated saves never
/// collide. Combined with the `create_new` (`O_EXCL`) open in [`write_temp`], a
/// name clash fails the save loudly rather than overwriting another temp.
fn temp_sibling(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let file_name = path.file_name().map_or_else(
        || String::from("settings"),
        |n| n.to_string_lossy().into_owned(),
    );
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp_name = format!(".{file_name}.{pid}.{nanos}.{seq}.tmp");
    match path.parent() {
        Some(parent) => parent.join(tmp_name),
        None => PathBuf::from(tmp_name),
    }
}

#[cfg(test)]
mod tests {
    use super::Settings;
    use crate::error::PlatformError;

    #[test]
    fn defaults_match_architecture() {
        let d = Settings::default();
        assert!(!d.update_check, "update check off by default (§9.6)");
        assert!(!d.totp_seed_pin, "seed PIN off by default (§1.6)");
        assert!(
            d.clipboard_fact_overwrite,
            "fact-overwrite on by default (§5.3)"
        );
    }

    #[test]
    fn toml_round_trips() {
        let s = Settings {
            update_check: true,
            totp_seed_pin: true,
            clipboard_fact_overwrite: false,
        };
        let parsed = Settings::from_toml(&s.to_toml()).expect("round-trip");
        assert_eq!(parsed, s);
    }

    #[test]
    fn missing_keys_use_defaults() {
        // Only one key present; the rest fall back to defaults.
        let s = Settings::from_toml("update_check = true\n").expect("parse partial");
        assert!(s.update_check);
        assert!(!s.totp_seed_pin);
        assert!(s.clipboard_fact_overwrite);
    }

    #[test]
    fn empty_input_is_all_defaults() {
        assert_eq!(
            Settings::from_toml("").expect("parse empty"),
            Settings::default()
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = Settings::from_toml("telemetry = true\n").expect_err("unknown key");
        assert!(matches!(err, PlatformError::Settings(_)));
    }

    #[test]
    fn wrong_type_is_rejected() {
        let err =
            Settings::from_toml("update_check = \"yes\"\n").expect_err("wrong type must fail");
        assert!(matches!(err, PlatformError::Settings(_)));
    }

    #[test]
    fn load_missing_file_yields_defaults() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("settings.toml");
        assert_eq!(
            Settings::load(&path).expect("load missing"),
            Settings::default()
        );
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nested").join("settings.toml");
        let s = Settings {
            update_check: true,
            totp_seed_pin: false,
            clipboard_fact_overwrite: true,
        };
        s.save(&path).expect("save");
        assert_eq!(Settings::load(&path).expect("load"), s);
    }

    #[test]
    fn load_invalid_file_is_error_not_silent_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("settings.toml");
        std::fs::write(&path, "this is = not valid = toml =\n").expect("write");
        assert!(matches!(
            Settings::load(&path),
            Err(PlatformError::Settings(_))
        ));
    }

    #[test]
    fn atomic_save_round_trips_and_leaves_no_temp_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("settings.toml");
        let s = Settings {
            update_check: true,
            totp_seed_pin: true,
            clipboard_fact_overwrite: false,
        };
        s.save(&path).expect("save");
        assert_eq!(Settings::load(&path).expect("reload"), s);
        // The atomic write must not leave its temp sibling behind: the only
        // entry in the directory is the target file itself.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("settings.toml")]);
    }

    #[test]
    fn load_corrupt_file_fails_closed_without_panic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("settings.toml");
        // Non-UTF8 / non-TOML garbage (e.g. a torn write) must surface an error,
        // never panic and never silently fall back to defaults.
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01, b'=', 0xff]).expect("write garbage");
        assert!(
            Settings::load(&path).is_err(),
            "a corrupt settings file must fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_settings_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("settings.toml");
        Settings::default().save(&path).expect("save");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "settings file must be owner-only (0o600)"
        );
    }
}
