//! TOTP verification (RFC 6238) with skew tolerance and in-memory replay
//! protection.

use passman_crypto::ct_eq;

use crate::config::TotpConfig;
use crate::error::TotpError;
use crate::hotp::{format_padded, hotp_value};
use crate::time::Timestamp;

/// The time step a timestamp falls into for a given period (RFC 6238 `T`).
///
/// `period` is assumed non-zero (guaranteed by [`TotpConfig`]); callers outside
/// a validated config must ensure this themselves.
#[must_use]
pub fn current_step(ts: Timestamp, period: u64) -> u64 {
    debug_assert!(period > 0, "period must be non-zero");
    ts.as_unix_secs() / period.max(1)
}

/// Stateful TOTP verifier holding the configuration and the replay cache.
///
/// The replay cache is a single "last accepted step" value. It lives only in
/// memory and is **never** persisted (per `architecture.md` §11 row 10): the
/// guarantee is "a code cannot be used twice within one process's session". A
/// fresh `TotpVerifier` (e.g. after a restart) starts with an empty cache by
/// design — see the note returned to `passman-core` about who owns the
/// instance across unlocks.
#[derive(Debug, Clone)]
pub struct TotpVerifier {
    config: TotpConfig,
    // LIMITATION (accepted): this cache is per-process and is NOT persisted to
    // disk.  A process restart resets it, which means the same TOTP step code
    // could be accepted again within the ±skew window (up to ±1 step / 30-90 s)
    // after a restart.  Persisting the last-accepted step across restarts would
    // require writing authentication state to disk (a new attack surface and a
    // complexity cost that outweighs the narrow window of exposure).  The ±1
    // step / 30-90 s bound is the accepted residual risk; §11 row 10 documents
    // this trade-off.
    last_accepted_step: Option<u64>,
}

impl TotpVerifier {
    /// Create a verifier with the given configuration and an empty replay
    /// cache.
    #[must_use]
    pub const fn new(config: TotpConfig) -> Self {
        Self {
            config,
            last_accepted_step: None,
        }
    }

    /// The configuration this verifier was built with.
    #[must_use]
    pub const fn config(&self) -> &TotpConfig {
        &self.config
    }

    /// The most recently accepted time step, if any. Exposed for inspection and
    /// testing; not persisted.
    #[must_use]
    pub const fn last_accepted_step(&self) -> Option<u64> {
        self.last_accepted_step
    }

    /// Verify `code` against `seed` at time `now`.
    ///
    /// On success the replay cache advances to the matched step and `Ok(())` is
    /// returned. The `seed` is the raw HMAC key (any length HMAC accepts —
    /// typically 20/32/64 bytes), unwrapped by the caller from its HSM slot.
    ///
    /// # Errors
    ///
    /// - [`TotpError::MalformedCode`] — `code` is not exactly `digits` ASCII
    ///   decimal characters.
    /// - [`TotpError::Replayed`] — `code` matches a step at or before the last
    ///   accepted step (replay within the validity window).
    /// - [`TotpError::Rejected`] — `code` matches no step in the skew window.
    pub fn verify(&mut self, seed: &[u8], code: &str, now: Timestamp) -> Result<(), TotpError> {
        let digits: u8 = self.config.digits();
        let candidate: &[u8] = parse_code(code, digits)?;

        let center: u64 = current_step(now, self.config.period());
        let skew: u64 = u64::from(self.config.skew_steps());
        // Saturate the low end so step 0 with skew does not underflow.
        let first: u64 = center.saturating_sub(skew);
        let last: u64 = center.saturating_add(skew);

        // Scan every candidate step without short-circuiting, so the work (and
        // thus timing) does not depend on which step — if any — matches. We
        // record the highest matching step; with distinct per-step codes this
        // is simply "the" matching step, and on the rare cross-step collision
        // it advances the replay cache maximally (most conservative).
        let mut expected: [u8; 8] = [0; 8];
        let expected: &mut [u8] = &mut expected[..digits as usize];
        let mut matched: Option<u64> = None;
        for step in first..=last {
            let value: u32 = hotp_value(self.config.algorithm(), seed, step, digits);
            format_padded(value, digits, expected);
            if ct_eq(candidate, expected) {
                matched = Some(step);
            }
        }

        match matched {
            None => Err(TotpError::Rejected),
            Some(step) => {
                if self.last_accepted_step.is_some_and(|last| step <= last) {
                    return Err(TotpError::Replayed);
                }
                self.last_accepted_step = Some(step);
                Ok(())
            }
        }
    }
}

/// Validate that `code` is exactly `digits` ASCII decimal characters and return
/// it as bytes.
///
/// Rejecting on length/charset before the constant-time compare is safe: the
/// code's *length* and *well-formedness* are not secret (an attacker knows the
/// configured width), and a malformed code can never be a valid one.
fn parse_code(code: &str, digits: u8) -> Result<&[u8], TotpError> {
    let bytes: &[u8] = code.as_bytes();
    if bytes.len() != digits as usize {
        return Err(TotpError::MalformedCode);
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(TotpError::MalformedCode);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{current_step, TotpVerifier};
    use crate::config::TotpConfig;
    use crate::error::TotpError;
    use crate::hotp::{format_padded, hotp_value, TotpAlgorithm};
    use crate::time::Timestamp;

    const SEED: &[u8] = b"12345678901234567890";

    fn ts(secs: u64) -> Timestamp {
        Timestamp::from_unix_secs(secs)
    }

    /// Produce the valid code for `seed` at the step containing `secs`.
    fn code_at(cfg: &TotpConfig, seed: &[u8], secs: u64) -> String {
        let step: u64 = current_step(ts(secs), cfg.period());
        let value: u32 = hotp_value(cfg.algorithm(), seed, step, cfg.digits());
        let mut buf: [u8; 8] = [0; 8];
        let buf: &mut [u8] = &mut buf[..cfg.digits() as usize];
        format_padded(value, cfg.digits(), buf);
        String::from_utf8(buf.to_vec()).expect("ascii digits")
    }

    #[test]
    fn current_step_divides_by_period() {
        assert_eq!(current_step(ts(0), 30), 0);
        assert_eq!(current_step(ts(29), 30), 0);
        assert_eq!(current_step(ts(30), 30), 1);
        assert_eq!(current_step(ts(59), 30), 1);
        assert_eq!(current_step(ts(1_111_111_109), 30), 37_037_036);
    }

    #[test]
    fn accepts_current_code() {
        let cfg: TotpConfig = TotpConfig::default();
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        let code: String = code_at(&cfg, SEED, 59);
        assert_eq!(v.verify(SEED, &code, ts(59)), Ok(()));
        assert_eq!(v.last_accepted_step(), Some(1));
    }

    #[test]
    fn replay_same_step_is_rejected() {
        let cfg: TotpConfig = TotpConfig::default();
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        let code: String = code_at(&cfg, SEED, 59);
        assert_eq!(v.verify(SEED, &code, ts(59)), Ok(()));
        // Same code, still inside step 1 → replay.
        assert_eq!(v.verify(SEED, &code, ts(45)), Err(TotpError::Replayed));
        assert_eq!(v.verify(SEED, &code, ts(59)), Err(TotpError::Replayed));
    }

    #[test]
    fn later_step_after_acceptance_still_works() {
        let cfg: TotpConfig = TotpConfig::default();
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        let early: String = code_at(&cfg, SEED, 59); // step 1
        assert_eq!(v.verify(SEED, &early, ts(59)), Ok(()));

        // A genuinely later step's code (step 3, t=90..119) is accepted.
        let later: String = code_at(&cfg, SEED, 95);
        assert_eq!(v.verify(SEED, &later, ts(95)), Ok(()));
        assert_eq!(v.last_accepted_step(), Some(3));
    }

    #[test]
    fn previous_step_within_skew_verifies() {
        let cfg: TotpConfig = TotpConfig::default(); // skew_steps = 1
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        // Code from the previous step (step 1, t=59) presented now at step 2
        // (t=60) is within ±1 skew.
        let prev: String = code_at(&cfg, SEED, 59);
        assert_eq!(v.verify(SEED, &prev, ts(60)), Ok(()));
        assert_eq!(v.last_accepted_step(), Some(1));
    }

    #[test]
    fn next_step_within_skew_verifies() {
        let cfg: TotpConfig = TotpConfig::default();
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        // Code from the next step (step 2, t=60) presented at step 1 (t=59).
        let next: String = code_at(&cfg, SEED, 60);
        assert_eq!(v.verify(SEED, &next, ts(59)), Ok(()));
        assert_eq!(v.last_accepted_step(), Some(2));
    }

    #[test]
    fn two_steps_stale_is_rejected() {
        let cfg: TotpConfig = TotpConfig::default(); // skew = 1
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        // Code from step 0 (t=0..29) presented at step 2 (t=60) is 2 steps
        // stale → outside ±1 → rejected.
        let stale: String = code_at(&cfg, SEED, 0);
        assert_eq!(v.verify(SEED, &stale, ts(60)), Err(TotpError::Rejected));
        assert_eq!(v.last_accepted_step(), None);
    }

    #[test]
    fn zero_skew_rejects_neighbouring_steps() {
        let cfg: TotpConfig = TotpConfig::new(TotpAlgorithm::Sha1, 6, 30, 0).expect("valid");
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        let prev: String = code_at(&cfg, SEED, 59); // step 1
        assert_eq!(v.verify(SEED, &prev, ts(60)), Err(TotpError::Rejected));
        let cur: String = code_at(&cfg, SEED, 60); // step 2
        assert_eq!(v.verify(SEED, &cur, ts(60)), Ok(()));
    }

    #[test]
    fn malformed_codes_are_rejected() {
        let cfg: TotpConfig = TotpConfig::default(); // 6 digits
        let mut v: TotpVerifier = TotpVerifier::new(cfg);
        assert_eq!(v.verify(SEED, "", ts(59)), Err(TotpError::MalformedCode));
        assert_eq!(
            v.verify(SEED, "12345", ts(59)),
            Err(TotpError::MalformedCode)
        );
        assert_eq!(
            v.verify(SEED, "1234567", ts(59)),
            Err(TotpError::MalformedCode)
        );
        assert_eq!(
            v.verify(SEED, "12a456", ts(59)),
            Err(TotpError::MalformedCode)
        );
        assert_eq!(
            v.verify(SEED, "12 456", ts(59)),
            Err(TotpError::MalformedCode)
        );
        // Wrong code of the right shape → Rejected, not MalformedCode.
        assert_eq!(v.verify(SEED, "000000", ts(59)), Err(TotpError::Rejected));
    }

    #[test]
    fn fresh_verifier_does_not_carry_replay_state() {
        // Two independent verifiers (e.g. across a restart) each accept the
        // same code — the cache is per-instance and not persisted.
        let cfg: TotpConfig = TotpConfig::default();
        let code: String = code_at(&cfg, SEED, 59);
        let mut a: TotpVerifier = TotpVerifier::new(cfg);
        let mut b: TotpVerifier = TotpVerifier::new(cfg);
        assert_eq!(a.verify(SEED, &code, ts(59)), Ok(()));
        assert_eq!(b.verify(SEED, &code, ts(59)), Ok(()));
    }
}
