//! Time abstraction.
//!
//! Verification never reads the wall clock directly; it takes a [`Timestamp`]
//! supplied by the caller (in production, from a [`Clock`]). This keeps the
//! verifier pure and the tests deterministic. [`SystemClock`] is the only thing
//! in the crate that touches `std::time`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::TotpError;

/// A point in time expressed as whole seconds since the Unix epoch
/// (1970-01-01T00:00:00Z).
///
/// The inner value is intentionally private with a single accessor, and we do
/// **not** derive `Default`: an implicit epoch (`0`) timestamp would silently
/// place every code in the very first time step, which is a footgun. Construct
/// one explicitly with [`Timestamp::from_unix_secs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Build a timestamp from whole seconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub const fn as_unix_secs(self) -> u64 {
        self.0
    }
}

/// A source of the current time.
///
/// Injected wherever "now" is needed so the time source is explicit and
/// swappable in tests. Implementations must be `Send + Sync` because the
/// verifier (and the `passman-core` session that owns it) is shared.
pub trait Clock: Send + Sync {
    /// The current time, truncated to whole seconds.
    fn now(&self) -> Timestamp;
}

/// A [`Clock`] backed by the operating system wall clock via
/// [`std::time::SystemTime`].
///
/// This is the only time-reading code in the crate. Unlike a bare `now()`, it
/// surfaces a pre-epoch clock as a typed error instead of panicking, so callers
/// can use [`SystemClock::try_now`] on untrusted system clocks; the [`Clock`]
/// impl's infallible `now()` clamps a pre-epoch clock to the epoch rather than
/// unwrapping.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// Read the wall clock, returning [`TotpError::ClockBeforeEpoch`] if the
    /// system clock is set before 1970-01-01.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::ClockBeforeEpoch`] when [`SystemTime::now`] precedes
    /// [`UNIX_EPOCH`].
    pub fn try_now(self) -> Result<Timestamp, TotpError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| Timestamp::from_unix_secs(d.as_secs()))
            .map_err(|_| TotpError::ClockBeforeEpoch)
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        // Fail-closed without panicking: a clock set before the epoch maps to
        // the epoch, which lands in step 0 and simply fails verification for any
        // real code rather than crashing the unlock pipeline.
        self.try_now().unwrap_or(Timestamp::from_unix_secs(0))
    }
}

/// A fixed-time [`Clock`] for deterministic tests.
///
/// Holds a single Unix-seconds value and returns it unchanged from every
/// [`Clock::now`] call. Public (not test-gated) so integration tests and any
/// future downstream test harness can drive verification at a known instant.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_secs(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, FixedClock, SystemClock, Timestamp};

    #[test]
    fn timestamp_round_trips_seconds() {
        let ts: Timestamp = Timestamp::from_unix_secs(1_111_111_109);
        assert_eq!(ts.as_unix_secs(), 1_111_111_109);
    }

    #[test]
    fn fixed_clock_returns_its_value() {
        let clock: FixedClock = FixedClock(59);
        assert_eq!(clock.now(), Timestamp::from_unix_secs(59));
    }

    #[test]
    fn system_clock_is_after_epoch() {
        // Not pinned to a value (it is the real clock), but it must be sane:
        // well after the epoch and not erroring on any normal system.
        let now: Timestamp = SystemClock.try_now().expect("clock after epoch");
        assert!(now.as_unix_secs() > 1_000_000_000);
        // Infallible path agrees with the fallible one here.
        assert!(SystemClock.now().as_unix_secs() > 1_000_000_000);
    }
}
