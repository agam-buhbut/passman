//! Error taxonomy for TOTP verification.

use thiserror::Error;

/// Errors produced while configuring or verifying TOTP codes.
///
/// Variants distinguish *why* a verification did not succeed so the caller
/// (`passman-core`) can react appropriately — a malformed code is a UI input
/// problem, a replay is a (logged-as-`error`) security event, and a plain
/// rejection is the expected wrong-code path. No variant carries the seed, the
/// code, or any timing detail.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpError {
    /// A configuration value was outside its permitted range (`digits` not in
    /// `6..=8`, or `period == 0`).
    #[error("invalid TOTP configuration: {0}")]
    InvalidConfig(&'static str),

    /// The supplied code was not a well-formed decimal string of the configured
    /// width (wrong length, non-digit characters, or empty).
    #[error("malformed TOTP code")]
    MalformedCode,

    /// The code matched a step at or before the last accepted step. Re-using a
    /// code within its validity window is rejected to prevent replay.
    #[error("TOTP code already used (replay)")]
    Replayed,

    /// The code did not match any step in the acceptable skew window.
    #[error("TOTP code rejected")]
    Rejected,

    /// The system clock reported a time before the Unix epoch. Only produced by
    /// [`crate::SystemClock`]; the injected clocks used in tests cannot hit this.
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
}
