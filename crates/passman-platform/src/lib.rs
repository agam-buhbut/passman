//! `passman-platform` — per-platform paths and the plaintext `settings.toml`.
//!
//! Keeps `passman-core` free of platform-path knowledge (`architecture.md`
//! §2.3): the shells resolve where the vault, settings, and logs live here, then
//! hand `passman-core` an explicit vault path. Two responsibilities:
//!
//! - [`Paths`] — resolve the vault / settings / log locations per platform
//!   (`architecture.md` §1.5): XDG on Linux, Known Folders on Windows, or an
//!   app-private base dir on Android.
//! - [`Settings`] — the fixed, validated, **non-secret** settings model
//!   (`architecture.md` §1.5). Plaintext TOML, readable before unlock; holds no
//!   vault content, keys, or labels.
//!
//! This crate does filesystem I/O (it is a platform shell, not one of the pure
//! security crates) but contains no `unsafe` and no cryptography.
#![forbid(unsafe_code)]

mod error;
mod paths;
mod settings;

pub use error::PlatformError;
pub use paths::Paths;
pub use settings::Settings;
