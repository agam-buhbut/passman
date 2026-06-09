//! Cryptographically secure randomness, sourced exclusively from [`OsRng`].
//!
//! Every random value in this crate (nonces, keys, salts, seeds) comes from
//! the operating system CSPRNG via [`rand::rngs::OsRng`]. No seeded or
//! userspace PRNG is used anywhere.
//!
//! # Failure posture
//!
//! [`OsRng`] reads the platform entropy source on every call. On the supported
//! platforms it cannot fail after boot; if the OS entropy source *does* fail
//! irrecoverably, `OsRng::fill_bytes` panics (its documented behaviour). These
//! helpers keep the infallible signatures the rest of the crate expects, so a
//! catastrophic RNG failure aborts rather than silently producing predictable
//! key material — which would be far more dangerous.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::secret::SecretArray;

/// Generate a fresh random 192-bit (24-byte) nonce for XChaCha20-Poly1305.
///
/// # Panics
///
/// Panics only if the operating system entropy source fails irrecoverably.
#[must_use]
pub fn random_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generate a fresh random `N`-byte secret (e.g. a 256-bit key, `N = 32`).
///
/// Used to mint key material such as `K_hsm`, the TOTP seed `S`, and salts.
///
/// # Panics
///
/// Panics only if the operating system entropy source fails irrecoverably.
#[must_use]
pub fn random_secret<const N: usize>() -> SecretArray<N> {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    let secret = SecretArray::new(buf);
    // `buf` is a plain array on the stack; overwrite the local copy so the only
    // surviving copy of the material lives inside the zeroizing wrapper.
    // `zeroize` (not `fill`) so the scrub is a volatile, non-elidable store.
    buf.zeroize();
    secret
}

/// Fill an arbitrary buffer with cryptographically secure random bytes.
///
/// # Panics
///
/// Panics only if the operating system entropy source fails irrecoverably.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}
