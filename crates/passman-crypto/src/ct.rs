//! Constant-time comparison helpers.
//!
//! Wraps [`subtle::ConstantTimeEq`] so secret comparisons elsewhere in the
//! crate (and in downstream crates) do not branch on secret data.

use subtle::ConstantTimeEq;

/// Compare two byte slices for equality in constant time *with respect to
/// their contents*.
///
/// Unequal lengths return `false` immediately (length is not secret here — the
/// AEAD tag length, key length, etc. are all public constants). When the
/// lengths match, the byte-by-byte comparison runs in time independent of where
/// the first difference (if any) occurs, so it does not leak a prefix-match
/// length through timing.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
