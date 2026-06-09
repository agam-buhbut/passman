//! Zeroizing secret wrappers.
//!
//! Three newtypes hold secret material and scrub it from memory on drop:
//!
//! - [`SecretString`] — a UTF-8 secret (master passwords, generated passwords).
//! - [`SecretArray<N>`] — a fixed-size byte secret (keys; `N = 32` is typical).
//! - [`SecretBytes`] — a variable-length byte secret (decrypted plaintexts).
//!
//! # Design
//!
//! These are thin newtypes over [`zeroize`] rather than wrappers around
//! `secrecy::Secret`. `zeroize` gives exactly what is needed — `Zeroize` +
//! `ZeroizeOnDrop` derived from the field types — while letting this crate own
//! the accessor names (`expose` / `expose_secret`) and keep the surface
//! minimal. In particular, `SecretArray<N>` is const-generic, which composes
//! cleanly with `zeroize`'s blanket `Zeroize for [u8; N]` impl but does not map
//! onto any `secrecy` type alias.
//!
//! # Guarantees and non-guarantees
//!
//! - Every type implements [`Zeroize`] and [`ZeroizeOnDrop`]: the backing
//!   memory is overwritten with zeros when the value is dropped.
//! - None of them implement `Clone`, `Copy`, or a leaky `Display`. Their
//!   `Debug` impls print a fixed redaction (`SecretString(***)`) and never the
//!   contents.
//! - As with all userspace zeroization, this cannot scrub copies the allocator
//!   may have left behind when a `Vec`/`String` reallocated, nor values spilled
//!   to swap. That residual risk is accepted at the architecture level.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ct::ct_eq;

/// A UTF-8 secret string (master password, generated password, PIN).
///
/// The contents are zeroized on drop. Access the inner value explicitly via
/// [`SecretString::expose`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap an owned [`String`], taking ownership of its secret contents.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    /// Borrow the secret as a `&str`.
    ///
    /// This is the single explicit escape hatch for reading the secret; every
    /// call site is therefore auditable.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Borrow the secret's UTF-8 bytes.
    ///
    /// Convenience for primitives (e.g. Argon2id) that consume `&[u8]`.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for SecretString {
    fn from(secret: String) -> Self {
        Self::new(secret)
    }
}

/// Constant-time equality over the UTF-8 bytes of the two secrets.
impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.expose_bytes(), other.expose_bytes())
    }
}

impl Eq for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

/// A fixed-size byte secret, typically a 256-bit key (`N = 32`).
///
/// The backing array is zeroized on drop. Const-generic over the length so the
/// same type serves 32-byte keys, salts, and seeds without allocation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> SecretArray<N> {
    /// Wrap a fixed-size byte array, taking ownership of its secret contents.
    #[must_use]
    pub fn new(secret: [u8; N]) -> Self {
        Self(secret)
    }

    /// Borrow the secret as a fixed-size array reference.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Borrow the secret as a byte slice.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The fixed length of this secret in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether this secret is zero-length (only possible for `SecretArray<0>`).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> From<[u8; N]> for SecretArray<N> {
    fn from(secret: [u8; N]) -> Self {
        Self::new(secret)
    }
}

/// Constant-time equality. Equal-length arrays are compared in constant time.
impl<const N: usize> PartialEq for SecretArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<const N: usize> Eq for SecretArray<N> {}

impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretArray<{N}>(***)")
    }
}

/// A variable-length byte secret, e.g. a decrypted plaintext of unknown size.
///
/// The backing `Vec` is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap an owned byte vector, taking ownership of its secret contents.
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self(secret)
    }

    /// Borrow the secret as a byte slice.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(secret: Vec<u8>) -> Self {
        Self::new(secret)
    }
}

/// Constant-time equality over the two byte buffers (length-aware).
impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretArray, SecretBytes, SecretString};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Compile-time proof that a type implements the zeroization traits. If any
    /// secret type stopped zeroizing on drop, this would fail to compile.
    fn assert_zeroizing<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn secret_types_impl_zeroize_on_drop() {
        assert_zeroizing::<SecretString>();
        assert_zeroizing::<SecretArray<32>>();
        assert_zeroizing::<SecretArray<16>>();
        assert_zeroizing::<SecretBytes>();
    }

    #[test]
    fn debug_is_redacted() {
        let s = SecretString::new("hunter2".to_owned());
        assert_eq!(format!("{s:?}"), "SecretString(***)");
        assert!(!format!("{s:?}").contains("hunter2"));

        let a = SecretArray::new([7u8; 32]);
        assert_eq!(format!("{a:?}"), "SecretArray<32>(***)");

        let b = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{b:?}"), "SecretBytes(***)");
    }

    #[test]
    fn accessors_expose_contents() {
        let s = SecretString::new("pw".to_owned());
        assert_eq!(s.expose(), "pw");
        assert_eq!(s.expose_bytes(), b"pw");

        let a = SecretArray::new([9u8; 4]);
        assert_eq!(a.expose(), &[9u8; 4]);
        assert_eq!(a.expose_bytes(), &[9u8; 4]);
        assert_eq!(a.len(), 4);
        assert!(!a.is_empty());

        let b = SecretBytes::new(vec![5, 6]);
        assert_eq!(b.expose(), &[5, 6]);
        assert_eq!(b.len(), 2);
        assert!(!b.is_empty());
    }

    #[test]
    fn constant_time_eq_impls() {
        assert_eq!(
            SecretString::new("abc".to_owned()),
            SecretString::new("abc".to_owned())
        );
        assert_ne!(
            SecretString::new("abc".to_owned()),
            SecretString::new("abd".to_owned())
        );
        assert_eq!(SecretArray::new([1u8; 8]), SecretArray::new([1u8; 8]));
        assert_ne!(SecretArray::new([1u8; 8]), SecretArray::new([2u8; 8]));
        assert_eq!(SecretBytes::new(vec![1, 2]), SecretBytes::new(vec![1, 2]));
        assert_ne!(SecretBytes::new(vec![1, 2]), SecretBytes::new(vec![1, 3]));
    }
}
