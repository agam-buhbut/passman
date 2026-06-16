//! Per-platform path resolution (`architecture.md` §1.5).
//!
//! Resolves the vault file, the settings file, and the optional log directory:
//!
//! | Platform | vault | settings | log |
//! |---|---|---|---|
//! | Linux | `$XDG_DATA_HOME/passman/vault.pmv` | `$XDG_CONFIG_HOME/passman/settings.toml` | `$XDG_STATE_HOME/passman/` |
//! | Windows | `%APPDATA%\passman\vault.pmv` | `%APPDATA%\passman\settings.toml` | `%LOCALAPPDATA%\passman\` |
//! | Android | `<files>/vault.pmv` | `<files>/settings.toml` | logcat (none) |
//!
//! Desktop paths come from [`directories::BaseDirs`] (XDG on Linux, Known
//! Folders on Windows). Android's app-private `files/` directory is not a system
//! base dir — the Kotlin shim passes it to [`Paths::under_base`].

use std::path::{Path, PathBuf};

use directories::BaseDirs;

use crate::error::PlatformError;

/// Application directory name under each platform base dir.
const APP_DIR: &str = "passman";
/// Vault file name (`architecture.md` §1.5).
const VAULT_FILE: &str = "vault.pmv";
/// Settings file name (`architecture.md` §1.5).
const SETTINGS_FILE: &str = "settings.toml";

/// Resolved locations for one passman installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    vault: PathBuf,
    settings: PathBuf,
    log_dir: Option<PathBuf>,
}

impl Paths {
    /// Resolve desktop paths via XDG (Linux) / Known Folders (Windows), per
    /// `architecture.md` §1.5.
    ///
    /// # Errors
    ///
    /// [`PlatformError::NoBaseDirectories`] if the platform base directories
    /// cannot be determined (e.g. no home directory).
    pub fn discover() -> Result<Self, PlatformError> {
        let base = BaseDirs::new().ok_or(PlatformError::NoBaseDirectories)?;
        let vault = base.data_dir().join(APP_DIR).join(VAULT_FILE);
        let settings = base.config_dir().join(APP_DIR).join(SETTINGS_FILE);
        // Linux exposes a dedicated state dir ($XDG_STATE_HOME); Windows does
        // not, so fall back to the local (non-roaming) data dir there
        // (%LOCALAPPDATA%), matching §1.5.
        let log_base = base.state_dir().unwrap_or_else(|| base.data_local_dir());
        Ok(Self {
            vault,
            settings,
            log_dir: Some(log_base.join(APP_DIR)),
        })
    }

    /// Place every file directly under one app-private base directory.
    ///
    /// Used on Android (the `files/` directory passed in from the Kotlin shim)
    /// and by tests. Android logs to logcat, so there is no log directory.
    #[must_use]
    pub fn under_base(base: &Path) -> Self {
        Self {
            vault: base.join(VAULT_FILE),
            settings: base.join(SETTINGS_FILE),
            log_dir: None,
        }
    }

    /// The vault file path (passed to `passman_core::App::open`).
    #[must_use]
    pub fn vault(&self) -> &Path {
        &self.vault
    }

    /// The settings file path.
    #[must_use]
    pub fn settings(&self) -> &Path {
        &self.settings
    }

    /// The optional log directory (`None` on Android).
    #[must_use]
    pub fn log_dir(&self) -> Option<&Path> {
        self.log_dir.as_deref()
    }

    /// Create the parent directory of the vault and settings files (and the log
    /// directory, if any), owner-only (`0o700`) on Unix. Idempotent.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Io`] if a directory cannot be created.
    pub fn ensure_dirs(&self) -> Result<(), PlatformError> {
        for dir in [self.vault.parent(), self.settings.parent(), self.log_dir()]
            .into_iter()
            .flatten()
        {
            create_dir_secure(dir)?;
        }
        Ok(())
    }
}

/// Create `dir` (and missing parents), then tighten it to owner-only on Unix.
fn create_dir_secure(dir: &Path) -> Result<(), PlatformError> {
    std::fs::create_dir_all(dir).map_err(|e| PlatformError::io("create app directory", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort tighten of our own app dir to owner-only. A failure here
        // (e.g. on a pre-existing dir we do not own) is non-fatal: the vault
        // file itself is created `0o600` by passman-core regardless.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Paths, SETTINGS_FILE, VAULT_FILE};
    use std::path::Path;

    #[test]
    fn under_base_places_files_directly() {
        let base = Path::new("/data/app/files");
        let p = Paths::under_base(base);
        assert_eq!(p.vault(), Path::new("/data/app/files/vault.pmv"));
        assert_eq!(p.settings(), Path::new("/data/app/files/settings.toml"));
        assert_eq!(p.log_dir(), None, "Android logs to logcat, no log dir");
    }

    #[test]
    fn discover_uses_passman_app_dir_and_filenames() {
        // The base is environment-dependent, but the app dir + filenames are
        // fixed. Skip the assertion only if base dirs are unavailable (headless
        // CI with no HOME), which is itself a valid `discover` outcome.
        if let Ok(p) = Paths::discover() {
            assert!(p.vault().ends_with(format!("passman/{VAULT_FILE}")));
            assert!(p
                .settings()
                .ends_with(format!("passman/{SETTINGS_FILE}")));
            assert!(p.log_dir().is_some_and(|d| d.ends_with("passman")));
        }
    }

    #[test]
    fn ensure_dirs_creates_parents() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a").join("b");
        let p = Paths::under_base(&nested);
        assert!(!nested.exists());
        p.ensure_dirs().expect("ensure_dirs");
        assert!(nested.is_dir(), "vault/settings parent dir created");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dirs_makes_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("vaultdir");
        Paths::under_base(&base).ensure_dirs().expect("ensure_dirs");
        let mode = std::fs::metadata(&base).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "app dir must be owner-only");
    }
}
