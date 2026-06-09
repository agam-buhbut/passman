//! Error taxonomy for `passman-hsm`.
//!
//! [`HsmError`] is mapped by `passman-core` exactly as in `architecture.md`
//! §4.3: [`HsmError::Transient`] and [`HsmError::Cancelled`] must **not** count
//! as a failed unlock attempt, while [`HsmError::PermanentlyInvalidated`] and
//! [`HsmError::HardwareAbsent`] route the user to recovery / guidance.
//!
//! No variant ever carries secret material (key bytes, plaintexts, PINs). The
//! [`HsmError::Backend`] string is for a backend's *own* non-secret diagnostic
//! (e.g. a TPM return code description); backends must never place wrapped
//! blobs, nonces, or decrypted material in it.

use thiserror::Error;

/// Errors produced by a [`crate::HardwareKeyStore`] backend.
///
/// The variants partition into "do not penalize the user" ([`Self::Transient`],
/// [`Self::Cancelled`]) and "needs user action / recovery"
/// ([`Self::HardwareAbsent`], [`Self::PermanentlyInvalidated`]); the parser
/// surface adds [`Self::MalformedBlob`] for a wrap blob that fails validation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HsmError {
    /// A retryable hardware/transport hiccup (e.g. TPM busy, transient session
    /// failure). The caller **must not** count this as a failed attempt.
    #[error("transient hardware error; retry is appropriate")]
    Transient,

    /// The user cancelled the biometric/PIN prompt. The caller **must not**
    /// count this as a failed attempt and **must not** yield key material.
    #[error("operation cancelled by the user")]
    Cancelled,

    /// The hardware backend is not available this session (no TPM, no Keystore,
    /// service down). Guide the user; do not penalize.
    #[error("hardware security backend is absent this session")]
    HardwareAbsent,

    /// The wrapping key is gone for good — biometric re-enrollment, a cleared
    /// TPM, or an account reset invalidated it. The only path back is a
    /// recovery import (§4.3, §6.6).
    #[error("hardware key permanently invalidated; recovery import required")]
    PermanentlyInvalidated,

    /// A [`crate::WrappedBlob`] (or its backend-specific payload) failed
    /// validation. `reason` is a fixed, non-secret descriptor of which check
    /// failed; it never echoes blob bytes.
    #[error("malformed wrap blob: {reason}")]
    MalformedBlob {
        /// Fixed, non-secret description of the failed validation check.
        reason: &'static str,
    },

    /// A backend-specific failure not covered by the variants above. The string
    /// is the backend's own non-secret diagnostic and must never contain key
    /// material, plaintexts, or PINs.
    #[error("hardware backend error: {0}")]
    Backend(String),
}
