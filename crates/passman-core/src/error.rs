//! Error taxonomy for `passman-core`.
//!
//! Two enums split the surface by audience:
//!
//! - [`UnlockError`] is what the unlock pipeline (`architecture.md` §4.3)
//!   returns. Its variants drive distinct UI reactions — retry, route to
//!   recovery, show a lockout timer, or report bad credentials — and the
//!   pipeline is careful about which ones touch the advisory counter (§4.9).
//! - [`CoreError`] covers everything else: construction, the single-instance
//!   lock, atomic I/O, session expiry, the export gate, and operations on an
//!   unlocked vault. The sibling-crate errors are wrapped with `#[from]` where
//!   that conversion is unambiguous.
//!
//! No message ever contains secret material (keys, plaintexts, passwords,
//! salts); the wrapped sibling errors already honour that contract.

use std::time::Duration;

use thiserror::Error;

use passman_crypto::CryptoError;
use passman_hsm::HsmError;
use passman_policy::PolicyError;
use passman_recovery::RecoveryError;
use passman_vault::VaultError;

/// Errors returned by the unlock pipeline ([`crate::App::unlock`]).
///
/// The variants partition by how the UI must react and, crucially, by whether
/// they advance the advisory lockout counter (`architecture.md` §4.9): only
/// [`Self::BadCredentials`] — a failed TOTP code or a failed probe — does.
/// HSM-transport outcomes ([`Self::Cancelled`], [`Self::Retryable`]) and the
/// recovery route ([`Self::RouteToRecovery`]) never penalize the user.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UnlockError {
    /// The user cancelled a biometric / PIN prompt. Maps from
    /// [`HsmError::Cancelled`]; the advisory counter is **not** touched.
    #[error("unlock cancelled by the user")]
    Cancelled,

    /// A transient hardware/transport hiccup occurred; retrying is appropriate.
    /// Maps from [`HsmError::Transient`]; the advisory counter is **not**
    /// touched.
    #[error("transient hardware error during unlock; retry is appropriate")]
    Retryable,

    /// The hardware key is gone or absent, so the only path back is a recovery
    /// import. Maps from [`HsmError::PermanentlyInvalidated`] /
    /// [`HsmError::HardwareAbsent`] (`architecture.md` §4.3); the advisory
    /// counter is **not** touched.
    #[error("hardware key unavailable; recovery import required")]
    RouteToRecovery,

    /// The TOTP code or the password (probe) was wrong. This is the only
    /// unlock outcome that advances the advisory lockout counter (§4.9).
    #[error("incorrect master password or TOTP code")]
    BadCredentials,

    /// The advisory lockout window is in effect; `remaining` is how long until
    /// it elapses (`architecture.md` §4.9). The real control is the HSM's
    /// native dictionary-attack protection; this is the consistent-UX layer.
    #[error("temporarily locked out; try again later")]
    LockedOut {
        /// How long until the advisory lockout window elapses.
        remaining: Duration,
    },

    /// A hardware-backend failure that is neither a cancel, a transient hiccup,
    /// nor a clean invalidation — e.g. a wrapped blob that failed its AEAD
    /// (tamper/corruption). Surfaced rather than mislabelled as a credential
    /// failure, so it does **not** advance the advisory counter.
    #[error("hardware backend error during unlock")]
    Hsm(#[source] HsmError),

    /// The on-disk vault could not be read or parsed.
    #[error("vault could not be read or parsed")]
    MalformedVault(#[source] CoreError),

    /// A software-mock backend was used without the explicit allow-software
    /// opt-in (`architecture.md` §6.2). Production builds must refuse it.
    #[error("software HSM backend refused (allow-software opt-in required)")]
    SoftwareHsmRefused,
}

/// Errors for construction, I/O, sessions, and unlocked-vault operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// Another instance already holds the single-instance advisory lock on the
    /// vault path (`architecture.md` §4.7 / D27). The UI should focus the
    /// existing instance rather than open a second one.
    #[error("another passman instance is already running for this vault")]
    AlreadyRunning,

    /// The session has expired (the 120 s hard timeout, a post-copy clamp, or
    /// an explicit lock — `architecture.md` §5.2). The vault must be unlocked
    /// again before the operation can proceed.
    #[error("session is locked")]
    Locked,

    /// The master password is not Strong enough to create a single-factor
    /// recovery export (`architecture.md` §7.5 / §8.4).
    #[error("master password is too weak to create a recovery export")]
    WeakPasswordForExport,

    /// A software-mock backend was used without the explicit allow-software
    /// opt-in (`architecture.md` §6.2).
    #[error("software HSM backend refused (allow-software opt-in required)")]
    SoftwareHsmRefused,

    /// A filesystem operation failed (open, read, write, fsync, rename, lock).
    #[error("filesystem error: {context}")]
    Io {
        /// Non-secret description of which step failed.
        context: &'static str,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A vault-format or vault-operation failure.
    #[error("vault operation failed")]
    Vault(#[from] VaultError),

    /// A hardware-key-store operation failed.
    #[error("hardware key store operation failed")]
    Hsm(#[source] HsmError),

    /// A recovery export/import operation failed.
    #[error("recovery operation failed")]
    Recovery(#[from] RecoveryError),

    /// Password generation failed (e.g. unsatisfiable policy).
    #[error("password generation failed")]
    Policy(#[from] PolicyError),

    /// A direct cryptographic-primitive failure (e.g. Argon2id rejecting the
    /// master-key derivation parameters as structurally invalid). AEAD failures
    /// surface through [`Self::Vault`] / [`Self::Recovery`] instead.
    #[error("crypto operation failed")]
    Crypto(#[from] CryptoError),
}

impl From<HsmError> for CoreError {
    fn from(err: HsmError) -> Self {
        CoreError::Hsm(err)
    }
}

impl CoreError {
    /// Wrap a [`std::io::Error`] with a fixed, non-secret context label.
    pub(crate) fn io(context: &'static str, source: std::io::Error) -> Self {
        CoreError::Io { context, source }
    }

    /// Construct an I/O-flavoured error from a shell-side failure (e.g. a
    /// [`Clipboard`](crate::Clipboard) backend that could not read or write).
    ///
    /// `CoreError` is `#[non_exhaustive]`, so a shell crate cannot build its
    /// variants directly; this is the supported way for an out-of-crate
    /// [`Clipboard`](crate::Clipboard) / I/O adapter to surface a failure. The
    /// `context` must be a fixed, non-secret label.
    #[must_use]
    pub fn shell_io(context: &'static str, source: std::io::Error) -> Self {
        CoreError::Io { context, source }
    }
}
