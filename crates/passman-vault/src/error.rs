//! Error taxonomy for `passman-vault`.
//!
//! [`VaultError`] covers every fallible path: parsing attacker-controlled
//! bytes, AEAD failures bubbled up from `passman-crypto`, and the
//! index↔envelope-set integrity check. Per the logging policy
//! (`architecture.md` §5.5) these messages describe *offsets and kinds* only —
//! never the bytes themselves, never secret material.

use thiserror::Error;

use passman_crypto::CryptoError;

/// Errors produced while parsing, serializing, or operating on a vault.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The input ended before a required field could be read.
    ///
    /// `field` names the structural element being read and `offset` is the byte
    /// position at which the buffer ran out. Neither leaks file content.
    #[error("truncated input: not enough bytes for {field} at offset {offset}")]
    Truncated {
        /// Name of the field whose read failed.
        field: &'static str,
        /// Byte offset at which the buffer was exhausted.
        offset: usize,
    },

    /// Bytes remained after the fully-parsed structure ended.
    ///
    /// `architecture.md` §4.7 mandates this be a hard format error (fail
    /// closed), not silently ignored.
    #[error("trailing bytes after end of vault: {extra} extra byte(s)")]
    TrailingBytes {
        /// Count of unexpected trailing bytes.
        extra: usize,
    },

    /// The `format_version` byte did not match a version this build supports.
    #[error("unsupported vault format version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// Version byte read from the input.
        got: u8,
        /// Version byte this build produces and accepts.
        expected: u8,
    },

    /// The `kdf_algorithm_id` byte did not match a known algorithm.
    #[error("unsupported kdf algorithm id: {got}")]
    UnsupportedKdfAlgorithm {
        /// Algorithm id byte read from the input.
        got: u8,
    },

    /// A single-byte present/absent discriminant held a value other than
    /// `0x00` or `0x01`.
    #[error("invalid present-flag byte for {field}: {got} (expected 0x00 or 0x01)")]
    InvalidFlag {
        /// Name of the optional field whose flag was malformed.
        field: &'static str,
        /// The out-of-range flag byte.
        got: u8,
    },

    /// The set of `EntryId`s listed in the sealed index did not exactly equal
    /// the set of envelope ids on disk (missing, extra, or duplicate).
    ///
    /// Treated as tampering and failed closed (`architecture.md` §4.5).
    #[error("sealed index does not match the envelope set (tamper-evident check failed)")]
    IndexMismatch,

    /// A decrypted entry's authenticated plaintext was structurally malformed
    /// (e.g. a field length prefix exceeded the recovered buffer, or the
    /// declared true length exceeded the padded buffer, or a field was not
    /// valid UTF-8).
    ///
    /// Because the plaintext is authenticated by the AEAD tag before this check
    /// runs, reaching this state implies a logic/version error rather than an
    /// attacker-supplied input; it is surfaced rather than panicked.
    #[error("malformed decrypted entry payload: {reason}")]
    MalformedRecord {
        /// Short, content-free description of the structural problem.
        reason: &'static str,
    },

    /// An entry id was requested for an operation but no envelope/index entry
    /// with that id exists.
    #[error("no entry with the requested id")]
    EntryNotFound,

    /// An opaque HSM wrap blob exceeded the `u16` length the on-disk format can
    /// encode (`architecture.md` §4.7 length-prefixes each blob with a `u16`).
    ///
    /// The §6.3 blobs sit far below this in practice; enforcing the bound at the
    /// construction/mutation boundary stops [`crate::Vault::to_bytes`] from
    /// silently clamping the length field and producing a corrupt, unparseable
    /// vault.
    #[error("HSM wrap blob too large to serialize: {which}")]
    BlobTooLarge {
        /// Which blob hit the limit (`"k_hsm_wrap_blob"` or
        /// `"totp_seed_wrap_blob"`).
        which: &'static str,
    },

    /// A cryptographic operation failed.
    ///
    /// Wraps [`CryptoError`]; for AEAD authentication this is deliberately
    /// detail-free (wrong key, tampered ciphertext, tampered AAD, and tampered
    /// tag are indistinguishable to the caller).
    #[error("crypto operation failed")]
    Crypto(#[from] CryptoError),
}
