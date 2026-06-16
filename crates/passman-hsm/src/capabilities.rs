//! Backend capability descriptor.
//!
//! [`HsmCapabilities`] lets the UI explain platform behavior (§4.9): how many
//! attempts before a native dictionary-attack lockout, how that lockout clears,
//! and whether the optional distinct TOTP-seed PIN (§1.6) is supported. The
//! values are advisory metadata, not a security control — the control is the
//! platform HSM itself.

use std::time::Duration;

/// What a [`crate::HardwareKeyStore`] backend can do, for UX messaging.
///
/// These fields drive user-facing copy (e.g. "3 attempts before a 15-minute
/// lockout"); `passman-core` does not treat them as an enforcement mechanism.
// The four boolean flags are independent capability bits specified verbatim by
// `architecture.md` §6.1; they are not a state machine that would collapse into
// an enum, so `struct_excessive_bools` does not apply here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsmCapabilities {
    /// Whether a biometric prompt gates use of the wrapping key.
    pub biometric_supported: bool,
    /// Whether the key is backed by a discrete secure element (Android
    /// `StrongBox`); stronger than a `TEE`-only key.
    pub strongbox_backed: bool,
    /// Whether the key is bound to platform-configuration measurements (TPM
    /// PCRs). Off by default in this system (§4.10, D19).
    pub pcr_bound: bool,
    /// Native dictionary-attack lockout threshold, if the backend enforces one.
    /// `None` means no hardware DA protection (e.g. the `SecretService`
    /// fallback), where only the advisory app timer applies — documented weak.
    pub max_attempts_before_lockout: Option<u32>,
    /// How a triggered lockout is cleared.
    pub lockout_recovery: LockoutRecovery,
    /// Whether the backend can gate the TOTP-seed slot behind a distinct PIN
    /// (the optional knowledge factor of §1.6).
    pub supports_distinct_slot_pin: bool,
}

/// The backend's *current* native dictionary-attack lockout state
/// (`architecture.md` §4.3 step 3).
///
/// Distinct from [`LockoutRecovery`], which is a static capability describing
/// *how* a lockout clears; this reports whether a lockout is active **right
/// now**. `passman-core` queries it before the unwraps so the UI can warn
/// before firing a biometric prompt against an already-locked device.
///
/// This is **not** a separate security control: a real lockout already fails an
/// unlock closed via the backend's unwrap error path (e.g. the TPM2 backend maps
/// `TPM_RC_LOCKOUT` to [`crate::HsmError::Transient`]). The query is a proactive
/// UX refinement. Backends that cannot cheaply pre-query their counter inherit
/// the default [`HsmLockoutStatus::Available`] from
/// [`crate::HardwareKeyStore::lockout_status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HsmLockoutStatus {
    /// Not locked out; an unwrap may proceed.
    Available,
    /// A native DA lockout is currently active. `retry_after` is the remaining
    /// cooldown when the backend can report it (e.g. a TPM DA cooldown), else
    /// `None` (the lockout clears by some non-timed event such as a credential
    /// reset).
    LockedOut {
        /// Remaining cooldown until the lockout self-clears, if known.
        retry_after: Option<Duration>,
    },
}

/// How a triggered hardware dictionary-attack lockout is recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockoutRecovery {
    /// Clears automatically after the given duration (e.g. TPM DA cooldown).
    TimeBased {
        /// How long until the lockout self-resets.
        reset_after: Duration,
    },
    /// Only a factory reset of the secure element clears it.
    FactoryResetOnly,
    /// Clears via a user-account / credential reset (e.g. Android device
    /// credential change).
    UserAccountReset,
}
