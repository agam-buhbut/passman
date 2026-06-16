//! The plaintext, non-secret `settings.toml` (`architecture.md` §1.5).
//!
//! Settings are stored *outside* the vault so options like `update_check` are
//! readable **before** unlock. They never hold vault content, keys, or labels.
//! The key set is **fixed and validated on load**: unknown keys are rejected
//! (`deny_unknown_fields`) and missing keys fall back to their documented
//! defaults (`#[serde(default)]`), so a partial or absent file is still valid.

use std::path::Path;

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

    /// Write settings to `path`, creating the parent directory if needed.
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
        std::fs::write(path, self.to_toml())
            .map_err(|e| PlatformError::io("write settings file", e))
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
        assert_eq!(Settings::from_toml("").expect("parse empty"), Settings::default());
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
        assert_eq!(Settings::load(&path).expect("load missing"), Settings::default());
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
}
