//! Error taxonomy for `passman-platform`.
//!
//! Settings are non-secret plaintext (`architecture.md` §1.5), so a parse-error
//! message (which may echo a key name) carries nothing sensitive. Path
//! resolution and directory creation surface the underlying [`std::io::Error`]
//! with a fixed, non-secret context label.

use thiserror::Error;

/// Errors from path resolution and settings handling.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The platform base directories could not be determined (e.g. no home
    /// directory). The shell should fall back to an explicit path.
    #[error("could not determine the platform base directories")]
    NoBaseDirectories,

    /// The settings file was present but is not valid (unknown key, wrong type,
    /// or malformed TOML). The contained message is the `toml` parse error and
    /// is non-secret (settings hold no secrets, §1.5).
    #[error("settings file is invalid: {0}")]
    Settings(String),

    /// A filesystem operation failed (read, write, or directory creation).
    #[error("filesystem error: {context}")]
    Io {
        /// Non-secret description of which step failed.
        context: &'static str,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

impl PlatformError {
    /// Wrap a [`std::io::Error`] with a fixed, non-secret context label.
    pub(crate) fn io(context: &'static str, source: std::io::Error) -> Self {
        PlatformError::Io { context, source }
    }
}
