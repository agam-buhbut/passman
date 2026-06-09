//! The biometric / PIN prompt callback.
//!
//! Two-phase unwrap (§6.1) lets [`crate::HardwareKeyStore::complete_unwrap`]
//! drive a native prompt at the moment the key is released; on Android even
//! `enroll` prompts (§6.4), which is why `enroll` also takes a prompter.
//!
//! The trait is implemented by the platform shell (and, across the `UniFFI`
//! boundary, by the foreign side). Per §6.5 its method takes an **owned**
//! `String` and returns a `Result` — foreign callback traits cannot take
//! references and a panic across FFI must be avoided.

use passman_crypto::SecretString;

use crate::error::HsmError;

/// Drives a platform-native authentication prompt on behalf of a backend.
///
/// Implementors block until the user responds (the core is synchronous; the
/// foreign side is responsible for calling off its main thread — §2.5).
pub trait BiometricPrompter: Send + Sync {
    /// Prompt the user, explaining why with `reason`, and report the outcome.
    ///
    /// `reason` is owned (the FFI boundary cannot pass a reference — §6.5).
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the prompt could not be presented or driven
    /// (e.g. [`HsmError::Transient`] for a transient platform failure). A user
    /// *declining* is **not** an error: it is reported as
    /// [`PromptResult::Cancelled`].
    fn prompt(&self, reason: String) -> Result<PromptResult, HsmError>;
}

/// The outcome of a [`BiometricPrompter::prompt`] call.
#[derive(Debug)]
pub enum PromptResult {
    /// The user authenticated (biometric matched / device credential accepted).
    Authenticated,
    /// The user fell back to entering a PIN, supplied here as a zeroizing
    /// secret (e.g. the optional distinct TOTP-seed PIN of §1.6).
    FallbackToPin(SecretString),
    /// The user dismissed or cancelled the prompt. The caller must treat this
    /// as [`HsmError::Cancelled`] and yield no material.
    Cancelled,
}
