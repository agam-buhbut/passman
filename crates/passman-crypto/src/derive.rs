//! HKDF-SHA256 key derivation.
//!
//! Two operations, matching the two distinct uses in the key hierarchy:
//!
//! - [`hkdf_master`] performs a full Extract-then-Expand. Used where the input
//!   keying material is *not* uniformly random — e.g. `K_master` derived from
//!   `K_pw ‖ K_hsm`, or the recovery key. The salt feeds the Extract step.
//! - [`hkdf_expand`] performs Expand only, from an already-uniform 256-bit PRK
//!   (e.g. `K_master` → `K_index`, `K_entry`). Expand-only takes **no** salt:
//!   the PRK is already a uniform key, so re-salting would be meaningless.
//!
//! All `info` (domain-separation) strings are supplied by the caller; this
//! crate hardcodes none of them.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::secret::SecretArray;

/// Length in bytes of every derived key (256-bit).
const OUTPUT_LEN: usize = 32;

/// Full HKDF-SHA256 Extract-then-Expand.
///
/// Extracts a pseudorandom key from `ikm` (keyed by `salt`), then expands it
/// to 32 bytes under `info`. Use this when `ikm` is not already a uniform key.
///
/// The result is a zeroizing [`SecretArray<32>`].
#[must_use]
pub fn hkdf_master(salt: &[u8], ikm: &[u8], info: &[u8]) -> SecretArray<32> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; OUTPUT_LEN];
    // `expand` only errors when the requested length exceeds 255*HashLen.
    // OUTPUT_LEN is a fixed 32, so this branch is statically unreachable; we
    // still avoid `.unwrap()` by handling it explicitly.
    if hk.expand(info, &mut okm).is_err() {
        okm.zeroize();
        unreachable!("HKDF-SHA256 expand to 32 bytes cannot exceed its length limit");
    }
    let key = SecretArray::new(okm);
    okm.zeroize();
    key
}

/// HKDF-SHA256 Expand only, from an already-uniform 256-bit PRK.
///
/// No salt is taken: `prk` is already a uniform key (the contract of
/// Expand-only). Expands to 32 bytes under `info`. Use this for `K_index` and
/// per-entry keys, whose PRK is `K_master`.
///
/// The result is a zeroizing [`SecretArray<32>`].
///
/// # Panics
///
/// Never panics in practice: the PRK is exactly 32 bytes (≥ the SHA-256 output
/// size that `Hkdf::from_prk` requires) and the output length is fixed at 32.
#[must_use]
pub fn hkdf_expand(prk: &SecretArray<32>, info: &[u8]) -> SecretArray<32> {
    // `from_prk` only rejects a PRK shorter than the hash output (32 bytes).
    // `prk` is exactly 32 bytes, so this cannot fail; handle the Result without
    // `.unwrap()` to keep the no-panic contract explicit.
    let Ok(hk) = Hkdf::<Sha256>::from_prk(prk.expose_bytes()) else {
        unreachable!("PRK is exactly 32 bytes, which meets the HKDF-SHA256 minimum");
    };
    let mut okm = [0u8; OUTPUT_LEN];
    if hk.expand(info, &mut okm).is_err() {
        okm.zeroize();
        unreachable!("HKDF-SHA256 expand to 32 bytes cannot exceed its length limit");
    }
    let key = SecretArray::new(okm);
    okm.zeroize();
    key
}
