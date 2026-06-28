//! Clipboard flow (`architecture.md` §5.3): the [`Clipboard`] trait, the
//! [`ClipboardCookie`], [`ClearOutcome`], and the clear-by-overwrite fact pool.
//!
//! # Why core never hashes
//!
//! The cookie identifies "the contents we wrote" by a SHA-256 digest, so the
//! 30-second clear only wipes the clipboard if it is *still ours*. But
//! `passman-crypto` exposes no bare SHA-256, and adding `sha2` here just for a
//! digest would widen the dependency surface. Instead the **platform
//! [`Clipboard`] implementation** computes the digest (it already links a hash
//! for its own platform code) and returns it in the [`ClipboardCookie`];
//! [`crate::UnlockedApp::clear_clipboard`] compares the current
//! [`Clipboard::read_digest`] against the stored cookie digest in constant time
//! ([`passman_crypto::ct_eq`]). Core therefore holds the digest but never
//! computes one.
//!
//! The cookie's `written_at` is stamped from the injected
//! [`passman_totp::Clock`] (process-local, never serialized), per §5.3.

use passman_totp::Timestamp;

use crate::error::CoreError;

/// A platform clipboard, implemented by each UI shell.
///
/// `Send + Sync` so the unlocked session (shared across the shell's threads)
/// can hold a reference. Every method returns a [`CoreError`] rather than
/// panicking, because clipboard access fails routinely (no display server, a
/// Wayland compositor without the data-control protocol, etc.).
pub trait Clipboard: Send + Sync {
    /// Place `secret` on the clipboard and return a cookie identifying it.
    ///
    /// The implementation computes the SHA-256 digest of exactly the bytes it
    /// writes and returns it inside the [`ClipboardCookie`] (see the module
    /// docs for why core does not hash). The implementation should also apply
    /// the platform's "exclude from history / sensitive" hint where available.
    ///
    /// # Errors
    ///
    /// [`CoreError`] if the clipboard could not be written.
    fn write(&self, secret: &passman_crypto::SecretString) -> Result<ClipboardCookie, CoreError>;

    /// The SHA-256 digest of the clipboard's *current* contents, or `None` when
    /// the clipboard is empty / unavailable / not text.
    ///
    /// Used by the clear step to decide whether the clipboard is still the
    /// value we wrote. The implementation must zeroize any transient read
    /// buffer after hashing.
    ///
    /// # Errors
    ///
    /// [`CoreError`] if the clipboard could not be read.
    fn read_digest(&self) -> Result<Option<[u8; 32]>, CoreError>;

    /// Overwrite the clipboard with `text` (used to replace a revealed secret
    /// with a fact — clear-by-overwrite, §5.3).
    ///
    /// # Errors
    ///
    /// [`CoreError`] if the clipboard could not be written.
    fn set_text(&self, text: &str) -> Result<(), CoreError>;
}

/// An opaque receipt for a clipboard write (`architecture.md` §5.3).
///
/// Carries the SHA-256 digest of what was written (computed by the
/// [`Clipboard`] impl) and the time it was written (from the injected clock).
/// Process-local; never serialized.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClipboardCookie {
    /// SHA-256 of the written bytes, supplied by the [`Clipboard`] impl.
    digest: [u8; 32],
    /// When the write happened, stamped from the injected clock.
    written_at: Timestamp,
}

/// Redacted: the SHA-256 `digest` is an offline-brute-forceable commitment to the
/// copied secret, and this cookie can cross the worker channel / `UniFFI`, so the
/// digest is never printed; only the (non-secret) `written_at` is shown. Mirrors
/// the redacted-`Debug` pattern on [`crate::SessionToken`].
impl std::fmt::Debug for ClipboardCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardCookie")
            .field("digest", &"***")
            .field("written_at", &self.written_at)
            .finish()
    }
}

impl ClipboardCookie {
    /// Construct a cookie from a digest the [`Clipboard`] impl computed and the
    /// current clock instant.
    #[must_use]
    pub fn new(digest: [u8; 32], written_at: Timestamp) -> Self {
        Self { digest, written_at }
    }

    /// The SHA-256 digest of the written contents.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// When the contents were written.
    #[must_use]
    pub fn written_at(&self) -> Timestamp {
        self.written_at
    }
}

/// The outcome of a clipboard-clear attempt (`architecture.md` §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    /// The clipboard still held our value and was overwritten with a fact.
    Cleared,
    /// The clipboard still held our value but fact-overwrite was disabled, so
    /// it was left in place (the shell may choose to empty it instead).
    StillOurs,
    /// The clipboard had been replaced by some other value; left untouched.
    Replaced,
    /// The clipboard was empty; nothing to do.
    Empty,
    /// The clipboard could not be read/written this time.
    Unavailable,
}

/// Compile-time pool of short, neutral facts used for clear-by-overwrite
/// (`architecture.md` §5.3).
///
/// Pasting one of these makes it obvious the secret is gone, and a
/// clipboard-history manager that snapshots the clipboard captures the fact
/// rather than the password. The strings are intentionally innocuous and
/// non-identifying.
pub const FACTS: &[&str] = &[
    "Honey never spoils.",
    "Octopuses have three hearts.",
    "A group of flamingos is called a flamboyance.",
    "Bananas are botanically berries.",
    "Sharks predate trees.",
    "Wombat droppings are cube-shaped.",
    "The Eiffel Tower grows taller in summer.",
    "A bolt of lightning is hotter than the Sun's surface.",
    "Sea otters hold hands while they sleep.",
    "Honeybees can recognize human faces.",
    "There are more stars than grains of sand on Earth.",
    "A day on Venus is longer than its year.",
];

/// Pick a fact from [`FACTS`] using one OS-random byte for the index.
///
/// Uses [`passman_crypto::random_secret`] (the project's only randomness
/// source) to avoid pulling in `rand` here. The pool is tiny, so a small modulo
/// bias on a 256-valued byte is irrelevant — this is cosmetic, not
/// cryptographic, selection.
#[must_use]
pub(crate) fn random_fact() -> &'static str {
    // FACTS is a non-empty compile-time constant; the modulo index is in range.
    let byte = passman_crypto::random_secret::<1>();
    let idx = (byte.expose()[0] as usize) % FACTS.len();
    FACTS[idx]
}

#[cfg(test)]
mod tests {
    use super::{random_fact, ClipboardCookie, FACTS};
    use passman_totp::Timestamp;

    #[test]
    fn facts_pool_is_non_empty() {
        assert!(!FACTS.is_empty());
        assert!(FACTS.iter().all(|f| !f.is_empty()));
    }

    #[test]
    fn random_fact_is_from_pool() {
        for _ in 0..64 {
            let f = random_fact();
            assert!(FACTS.contains(&f));
        }
    }

    #[test]
    fn cookie_exposes_its_fields() {
        let digest = [7u8; 32];
        let cookie = ClipboardCookie::new(digest, Timestamp::from_unix_secs(123));
        assert_eq!(cookie.digest(), &digest);
        assert_eq!(cookie.written_at(), Timestamp::from_unix_secs(123));
    }
}
