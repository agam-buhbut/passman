//! TOTP configuration and validation.

use crate::error::TotpError;
use crate::hotp::TotpAlgorithm;

/// Inclusive lower bound on configurable code width.
const MIN_DIGITS: u8 = 6;
/// Inclusive upper bound on configurable code width (RFC 4226 truncation yields
/// a 31-bit value, comfortably representable in 8 decimal digits with margin).
const MAX_DIGITS: u8 = 8;

/// Parameters governing TOTP code generation and verification.
///
/// Construct via [`TotpConfig::new`] (validated) or [`TotpConfig::default`]
/// (the common authenticator profile: HMAC-SHA1, 6 digits, 30-second period,
/// ±1 step of skew). The fields are read-only after construction so a
/// [`crate::TotpVerifier`] can rely on them being valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpConfig {
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u64,
    skew_steps: u8,
}

impl TotpConfig {
    /// Build a validated configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidConfig`] if `digits` is outside `6..=8` or
    /// `period` is `0`.
    pub fn new(
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u64,
        skew_steps: u8,
    ) -> Result<Self, TotpError> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(TotpError::InvalidConfig("digits must be in 6..=8"));
        }
        if period == 0 {
            return Err(TotpError::InvalidConfig("period must be greater than 0"));
        }
        Ok(Self {
            algorithm,
            digits,
            period,
            skew_steps,
        })
    }

    /// The configured hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// The configured code width in decimal digits (always `6..=8`).
    #[must_use]
    pub const fn digits(&self) -> u8 {
        self.digits
    }

    /// The configured time step in seconds (always `> 0`).
    #[must_use]
    pub const fn period(&self) -> u64 {
        self.period
    }

    /// The number of time steps on each side of "now" that are accepted.
    #[must_use]
    pub const fn skew_steps(&self) -> u8 {
        self.skew_steps
    }
}

impl Default for TotpConfig {
    /// The standard authenticator profile: HMAC-SHA1, 6 digits, 30-second
    /// period, ±1 step of skew. These constants are in range, so the equivalent
    /// [`TotpConfig::new`] call cannot fail.
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            skew_steps: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TotpAlgorithm, TotpConfig};
    use crate::error::TotpError;

    #[test]
    fn default_is_the_standard_profile() {
        let cfg: TotpConfig = TotpConfig::default();
        assert_eq!(cfg.algorithm(), TotpAlgorithm::Sha1);
        assert_eq!(cfg.digits(), 6);
        assert_eq!(cfg.period(), 30);
        assert_eq!(cfg.skew_steps(), 1);
    }

    #[test]
    fn default_matches_equivalent_new() {
        let made: TotpConfig = TotpConfig::new(TotpAlgorithm::Sha1, 6, 30, 1).expect("valid");
        assert_eq!(made, TotpConfig::default());
    }

    #[test]
    fn rejects_too_few_digits() {
        assert_eq!(
            TotpConfig::new(TotpAlgorithm::Sha1, 5, 30, 1),
            Err(TotpError::InvalidConfig("digits must be in 6..=8")),
        );
    }

    #[test]
    fn rejects_too_many_digits() {
        assert_eq!(
            TotpConfig::new(TotpAlgorithm::Sha1, 9, 30, 1),
            Err(TotpError::InvalidConfig("digits must be in 6..=8")),
        );
    }

    #[test]
    fn accepts_digit_bounds() {
        assert!(TotpConfig::new(TotpAlgorithm::Sha256, 6, 30, 0).is_ok());
        assert!(TotpConfig::new(TotpAlgorithm::Sha512, 8, 30, 2).is_ok());
    }

    #[test]
    fn rejects_zero_period() {
        assert_eq!(
            TotpConfig::new(TotpAlgorithm::Sha1, 6, 0, 1),
            Err(TotpError::InvalidConfig("period must be greater than 0")),
        );
    }
}
