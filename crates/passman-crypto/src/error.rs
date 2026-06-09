//! Error taxonomy for `passman-crypto`.
//!
//! A single [`CryptoError`] enum covers every fallible path in this crate.
//! Error messages never contain secret material (keys, plaintexts, passwords,
//! salts): they describe *what kind* of failure occurred, not the data
//! involved.

use thiserror::Error;

/// Errors produced by the cryptographic primitives in this crate.
///
/// Authentication failures ([`CryptoError::AeadAuth`]) are deliberately
/// detail-free: a caller cannot learn *why* a tag failed, only that it did.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Argon2id key derivation failed (e.g. invalid parameters or salt).
    ///
    /// The wrapped string is the `argon2` crate's own description, which
    /// describes parameter/length problems and never echoes the password.
    #[error("argon2id key derivation failed: {0}")]
    Kdf(String),

    /// AEAD decryption failed authentication, or encryption failed.
    ///
    /// Returned for any tag mismatch, tampered ciphertext, tampered associated
    /// data, or wrong key. It carries no detail by design — a padding-oracle
    /// style distinction between failure modes must not leak.
    #[error("AEAD authentication failed")]
    AeadAuth,

    /// An input had the wrong length for the operation.
    #[error("invalid length for {what}: expected {expected}, got {got}")]
    InvalidLength {
        /// Human-readable name of the input that was the wrong length.
        what: &'static str,
        /// The length the operation required.
        expected: usize,
        /// The length that was actually supplied.
        got: usize,
    },
}
