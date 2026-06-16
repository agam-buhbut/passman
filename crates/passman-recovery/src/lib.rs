//! `passman-recovery` — the recovery export/import format.
//!
//! The single-factor (password-only) escape hatch for when the HSM is gone.
//! Derives a recovery key from the master password via Argon2id + HKDF
//! (`architecture.md` §7.1), then AEAD-seals a payload carrying the TOTP seed,
//! the original vault KDF parameters, and every entry. Pure: no I/O (the caller
//! reads/writes the file), no logging. The per-entry policy travels as opaque
//! bytes (core serializes `EntryPolicy`), so this crate does not depend on
//! `passman-policy`. See `architecture.md` §7.2–§7.4.
//!
//! # Public surface
//!
//! - [`export`] / [`import`] — the two entry points. `export` seals an
//!   [`ExportPayload`] into the §7.2 file bytes (refusing Argon2 params below
//!   the recovery Floor); `import` is a bounds-checked, panic-free parser that
//!   recovers it.
//! - [`ExportPayload`], [`RecoveryEntry`] — this crate's own DTOs (it never
//!   references vault types). Secret fields are zeroizing.
//! - [`RecoveryPreset`] / [`FLOOR_PARAMS`] / [`meets_floor`] — the §7.4 cost
//!   presets and the Floor gate.
//! - [`RecoveryError`] — the error taxonomy.
//! - Format constants: [`MAGIC`], [`FORMAT_VERSION`], [`KDF_ALGORITHM_ARGON2ID`],
//!   [`RECOVERY_AD`], and the domain-separation string [`RECOVERY_INFO`].
//!
//! The Strong-password (zxcvbn) export gate (`architecture.md` §7.5 / §8.4) and
//! the fresh re-auth requirement are owned by `passman-core`, not this crate.
#![forbid(unsafe_code)]

mod error;
mod format;
mod kdf;
mod payload;
mod reader;

pub use error::RecoveryError;
pub use format::{
    export, import, FORMAT_VERSION, KDF_ALGORITHM_ARGON2ID, MAGIC, RECOVERY_AD, SALT_LEN,
};
#[cfg(feature = "test-util")]
pub use format::export_unchecked;
pub use kdf::{meets_floor, RecoveryPreset, FLOOR_PARAMS, RECOVERY_INFO};
pub use payload::{ExportPayload, RecoveryEntry, ENTRY_ID_LEN, PAYLOAD_VERSION, TOTP_SEED_LEN};
