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
