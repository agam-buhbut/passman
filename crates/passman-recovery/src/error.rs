//! Error taxonomy for `passman-recovery`.
//!
//! [`RecoveryError`] covers every fallible path: parsing an attacker-controlled
//! recovery file (`import`), the weak-parameter gate (`export`), AEAD failures
//! bubbled up from `passman-crypto`, and structural problems in the
//! (authenticated) decrypted payload. Per the logging policy
//! (`architecture.md` §5.5) these messages carry *offsets and kinds* only —
//! never file bytes, never secret material (passwords, plaintexts, salts).

use thiserror::Error;

use passman_crypto::CryptoError;

/// Errors produced while exporting or importing a recovery file.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecoveryError {
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

    /// Bytes remained after the fully-parsed file structure ended.
    ///
    /// The recovery file is a fixed framing followed by exactly
    /// `payload_ct_len` bytes; anything after that is a hard format error
    /// (fail closed), not silently ignored.
    #[error("trailing bytes after end of recovery file: {extra} extra byte(s)")]
    TrailingBytes {
        /// Count of unexpected trailing bytes.
        extra: usize,
    },

    /// The leading magic did not match the recovery magic (`b"PSMREC"`).
    #[error("bad recovery file magic")]
    BadMagic,

    /// The `format_version` byte did not match a version this build supports.
    #[error("unsupported recovery format version: got {got}, expected {expected}")]
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

    /// `export` was asked to use Argon2 parameters weaker than the recovery
    /// Floor (`architecture.md` §7.4).
    ///
    /// Refusing here keeps the single-factor export from ever sitting behind a
    /// cheap KDF. The message names the offending and required costs but never
    /// the password.
    #[error(
        "recovery Argon2 parameters are below the floor: \
         got m={got_m} KiB/t={got_t}/p={got_p}, \
         floor m={floor_m} KiB/t={floor_t}/p={floor_p}"
    )]
    WeakParams {
        /// Supplied memory cost (KiB).
        got_m: u32,
        /// Supplied time cost.
        got_t: u32,
        /// Supplied parallelism.
        got_p: u8,
        /// Floor memory cost (KiB).
        floor_m: u32,
        /// Floor time cost.
        floor_t: u32,
        /// Floor parallelism.
        floor_p: u8,
    },

    /// AEAD decryption of the payload failed authentication.
    ///
    /// Returned for a wrong password, a tampered ciphertext/tag, a tampered
    /// header (the header Argon2 params feed the key, so altering them yields a
    /// wrong key), or a tampered salt. It is deliberately detail-free: a caller
    /// cannot tell *why* it failed, only that it did — no decryption oracle.
    #[error("recovery payload decryption failed")]
    Decrypt,

    /// The decrypted payload was structurally malformed (bad inner version, a
    /// field length prefix exceeding the recovered buffer, an entry-count that
    /// did not match the bytes present, or a non-UTF-8 text field).
    ///
    /// Because the payload is authenticated by the AEAD tag before this check
    /// runs, reaching this state implies a logic/version mismatch rather than
    /// attacker-supplied input; it is surfaced rather than panicked.
    #[error("malformed decrypted recovery payload: {reason}")]
    MalformedPayload {
        /// Short, content-free description of the structural problem.
        reason: &'static str,
    },

    /// A cryptographic operation failed for a reason other than payload
    /// authentication (e.g. Argon2 rejected the parameters as structurally
    /// invalid).
    ///
    /// AEAD authentication failures are mapped to the detail-free
    /// [`RecoveryError::Decrypt`] instead, so this variant never leaks an
    /// oracle.
    #[error("crypto operation failed")]
    Crypto(#[from] CryptoError),
}
