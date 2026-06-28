//! Advisory lockout (`architecture.md` §4.9) — the consistent-UX layer, **not**
//! the security control.
//!
//! The real dictionary-attack defence is the platform HSM's native lockout
//! (TPM DA, Android Keystore attempt limits, `NCrypt` anti-hammering): that is
//! state a post-unwrap attacker cannot rewrite. This module implements only the
//! app-side timer the UI shows for consistent messaging across platforms. Its
//! counter and last-failure time live in the vault header in **plaintext** (via
//! [`passman_vault::Vault::set_rate_limit`] and the matching accessors) and are
//! explicitly *not* a security boundary — an attacker with the file can roll
//! them back, which is why they are not MAC'd.
//!
//! The schedule and predicate are taken verbatim from §4.9.

use std::time::Duration;

use passman_totp::Timestamp;

/// Seconds per minute (lockout windows are specified in minutes).
const SECS_PER_MIN: u64 = 60;

/// Hard cap on the lockout window, in minutes (24 h).
const MAX_LOCKOUT_MIN: u64 = 1440;

/// The number of consecutive failures below which there is no lockout.
const FREE_ATTEMPTS: u64 = 3;

/// The failure count at or above which the lockout pins to the 24 h cap (the
/// guard that prevents the `2^(n-3)` shift from overflowing — §4.9).
const CAP_AT_ATTEMPTS: u64 = 11;

/// The advisory lockout window in **minutes** for `n` consecutive failures
/// (`architecture.md` §4.9):
///
/// ```text
/// lockout_minutes(n) = if n < 3       { 0 }
///                      else if n >= 11 { 1440 }
///                      else            { min(10 * 2^(n-3), 1440) }
/// ```
#[must_use]
pub fn lockout_minutes(counter: u64) -> u64 {
    if counter < FREE_ATTEMPTS {
        0
    } else if counter >= CAP_AT_ATTEMPTS {
        MAX_LOCKOUT_MIN
    } else {
        // `counter - 3` is in `0..=7` here, so `1u64 << (counter - 3)` is at
        // most `1 << 7 = 128` and cannot overflow; the `min` caps the product.
        let shifted = 1u64 << (counter - FREE_ATTEMPTS);
        (10 * shifted).min(MAX_LOCKOUT_MIN)
    }
}

/// The advisory rate-limit state read from / written to the vault header.
///
/// `last_failure` is Unix seconds (`0` = no recorded failure), matching the
/// vault's `rl_last_failure` encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutState {
    /// Consecutive failed-attempt counter.
    pub counter: u64,
    /// Unix-seconds timestamp of the last failure (`0` = none).
    pub last_failure: i64,
}

impl LockoutState {
    /// Construct from the vault header's advisory bytes.
    #[must_use]
    pub fn new(counter: u64, last_failure: i64) -> Self {
        Self {
            counter,
            last_failure,
        }
    }

    /// Whether a lockout is currently in effect at time `now`, and if so how
    /// long remains (`architecture.md` §4.9).
    ///
    /// Rejection predicate: reject while `now < last_failure + window`. A clock
    /// that has moved **backwards** relative to `last_failure` is clamped to
    /// "remain locked for the full window" (fail-closed), so an attacker cannot
    /// clear the timer by rewinding the system clock.
    ///
    /// Returns `None` when not locked, or `Some(remaining)` when locked.
    #[must_use]
    pub fn remaining(&self, now: Timestamp) -> Option<Duration> {
        let window_min = lockout_minutes(self.counter);
        if window_min == 0 {
            return None;
        }
        let window_secs = window_min.saturating_mul(SECS_PER_MIN);

        // `last_failure` is i64 (could in principle be negative or 0); treat any
        // non-positive value as "no recorded failure" → not locked.
        if self.last_failure <= 0 {
            return None;
        }
        let last = u64::try_from(self.last_failure).unwrap_or(0);
        let now_secs = now.as_unix_secs();

        // Unlock instant = last_failure + window.
        let unlock_at = last.saturating_add(window_secs);

        if now_secs >= unlock_at {
            // Window elapsed normally → not locked.
            None
        } else if now_secs < last {
            // Clock moved backward past the failure time: fail closed, report
            // the full window as remaining rather than letting the rewind help.
            Some(Duration::from_secs(window_secs))
        } else {
            Some(Duration::from_secs(unlock_at - now_secs))
        }
    }

    /// The state after one more recorded failure at `now`: counter incremented
    /// (saturating) and `last_failure` set to now.
    #[must_use]
    pub fn after_failure(&self, now: Timestamp) -> Self {
        let now_secs = i64::try_from(now.as_unix_secs()).unwrap_or(i64::MAX);
        Self {
            counter: self.counter.saturating_add(1),
            last_failure: now_secs,
        }
    }

    /// The reset state after a successful unlock: counter zero, no failure
    /// time.
    #[must_use]
    pub fn reset() -> Self {
        Self {
            counter: 0,
            last_failure: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{lockout_minutes, LockoutState, MAX_LOCKOUT_MIN};
    use passman_totp::Timestamp;

    #[test]
    fn schedule_matches_architecture_table() {
        // No lockout for the first three attempts.
        assert_eq!(lockout_minutes(0), 0);
        assert_eq!(lockout_minutes(1), 0);
        assert_eq!(lockout_minutes(2), 0);
        // n=3 -> 10 * 2^0 = 10; n=4 -> 20; n=5 -> 40; ...
        assert_eq!(lockout_minutes(3), 10);
        assert_eq!(lockout_minutes(4), 20);
        assert_eq!(lockout_minutes(5), 40);
        assert_eq!(lockout_minutes(6), 80);
        assert_eq!(lockout_minutes(7), 160);
        assert_eq!(lockout_minutes(8), 320);
        assert_eq!(lockout_minutes(9), 640);
        // n=10 -> 10 * 2^7 = 1280 (still under the cap).
        assert_eq!(lockout_minutes(10), 1280);
        // n>=11 pins to the 24 h cap.
        assert_eq!(lockout_minutes(11), MAX_LOCKOUT_MIN);
        assert_eq!(lockout_minutes(100), MAX_LOCKOUT_MIN);
        assert_eq!(lockout_minutes(u64::MAX), MAX_LOCKOUT_MIN);
    }

    #[test]
    fn not_locked_below_threshold() {
        let st = LockoutState::new(2, 1_000);
        assert!(st.remaining(Timestamp::from_unix_secs(1_001)).is_none());
    }

    #[test]
    fn locked_within_window() {
        // 3 failures at t=1000 → 10-minute (600 s) window.
        let st = LockoutState::new(3, 1_000);
        // At t=1300 (300 s in), 300 s remain.
        let rem = st
            .remaining(Timestamp::from_unix_secs(1_300))
            .expect("locked");
        assert_eq!(rem.as_secs(), 300);
    }

    #[test]
    fn unlocked_after_window_elapses() {
        let st = LockoutState::new(3, 1_000);
        // At t=1600 (== 1000 + 600) the window has elapsed.
        assert!(st.remaining(Timestamp::from_unix_secs(1_600)).is_none());
        assert!(st.remaining(Timestamp::from_unix_secs(2_000)).is_none());
    }

    #[test]
    fn backward_clock_stays_locked_for_full_window() {
        let st = LockoutState::new(3, 1_000);
        // Clock rewound to before the failure: fail closed, full 600 s remains.
        let rem = st
            .remaining(Timestamp::from_unix_secs(500))
            .expect("still locked");
        assert_eq!(rem.as_secs(), 600);
    }

    #[test]
    fn zero_last_failure_is_not_locked() {
        let st = LockoutState::new(5, 0);
        assert!(st.remaining(Timestamp::from_unix_secs(10_000)).is_none());
    }

    #[test]
    fn after_failure_increments_and_stamps() {
        let st = LockoutState::reset();
        let next = st.after_failure(Timestamp::from_unix_secs(42));
        assert_eq!(next.counter, 1);
        assert_eq!(next.last_failure, 42);
        let next2 = next.after_failure(Timestamp::from_unix_secs(99));
        assert_eq!(next2.counter, 2);
        assert_eq!(next2.last_failure, 99);
    }

    #[test]
    fn reset_clears_state() {
        let r = LockoutState::reset();
        assert_eq!(r.counter, 0);
        assert_eq!(r.last_failure, 0);
    }

    #[test]
    fn forward_clock_intentionally_clears_advisory_lockout() {
        // INTENT (pinned by this test): a *forward* clock jump deliberately clears
        // the advisory lockout the instant `now >= unlock_at`. Unlike the backward
        // rewind — which fails *closed* (see `backward_clock_stays_locked_for_full
        // _window`) so an attacker cannot rewind to escape — the forward direction
        // is intentionally NOT fail-closed: an attacker who can jump the clock
        // forward could clear this UX timer early. That is acceptable because the
        // advisory layer is not the security control; the HSM-native DA lockout
        // (TPM/Keystore/NCrypt) is the authoritative anti-hammering gate (§4.9) and
        // is unaffected by the system clock. Were this made fail-closed forward, a
        // benign clock correction would strand a legitimate user. This test exists
        // to make that asymmetry a deliberate, change-detected decision.
        let st = LockoutState::new(3, 1_000); // 10-minute (600 s) window
        let unlock_at = 1_000 + 600;
        // One second before the boundary: still locked.
        assert!(st.remaining(Timestamp::from_unix_secs(unlock_at - 1)).is_some());
        // Exactly at the boundary: cleared.
        assert!(st.remaining(Timestamp::from_unix_secs(unlock_at)).is_none());
        // A large forward jump well past the window: also cleared (not fail-closed).
        assert!(st
            .remaining(Timestamp::from_unix_secs(unlock_at + 10_000_000))
            .is_none());
    }
}
