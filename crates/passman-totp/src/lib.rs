//! `passman-totp` — RFC 6238 TOTP verification.
//!
//! Verifies time-based one-time codes against a seed, with a configurable skew
//! window and an in-memory replay cache. Time is supplied through an injected
//! [`Clock`] so verification is deterministic under test. This crate performs
//! no I/O and emits no logs; the seed is supplied by the caller (unwrapped from
//! its own HSM slot — see `architecture.md` §1.6) and never persisted here.
//!
//! # Usage
//!
//! ```
//! use passman_totp::{Clock, FixedClock, TotpConfig, TotpVerifier};
//!
//! let config = TotpConfig::default(); // HMAC-SHA1, 6 digits, 30 s, ±1 step
//! let mut verifier = TotpVerifier::new(config);
//! let clock = FixedClock(59);
//! let seed: &[u8] = b"12345678901234567890";
//!
//! // `code` comes from the user's authenticator app; verify against `now`.
//! let now = clock.now();
//! let _ = verifier.verify(seed, "287082", now); // Ok for this seed/time
//! ```
//!
//! # Modules
//!
//! - [`error`] — the [`TotpError`] taxonomy.
//! - [`time`] — [`Timestamp`], the [`Clock`] trait, [`SystemClock`],
//!   [`FixedClock`].
//! - [`hotp`] — RFC 4226 HOTP core and [`TotpAlgorithm`].
//! - [`config`] — [`TotpConfig`] and its validated constructor.
//! - [`verifier`] — [`current_step`] and the [`TotpVerifier`] (replay cache).
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod hotp;
pub mod time;
pub mod verifier;

pub use config::TotpConfig;
pub use error::TotpError;
pub use hotp::TotpAlgorithm;
pub use time::{Clock, FixedClock, SystemClock, Timestamp};
pub use verifier::{current_step, TotpVerifier};
