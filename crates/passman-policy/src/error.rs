//! Error taxonomy for password generation and policy resolution.

use thiserror::Error;

/// Errors that can arise while building a generation request or generating a
/// password.
///
/// Entropy estimation ([`crate::estimate_master`]) and import validation
/// ([`crate::validate`]) are deliberately infallible — a weak password is a
/// *result*, not an error — so they do not produce a `PolicyError`.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// The effective character set (selected classes minus `disallow`) has
    /// fewer than two distinct characters, so generation could not produce a
    /// meaningfully random password.
    #[error("effective character set has fewer than 2 characters")]
    EmptyCharset,

    /// The sum of the required-class minimums exceeds the requested length, so
    /// no password of that length can satisfy every minimum.
    #[error("required-class minimums ({required}) exceed requested length ({length})")]
    ImpossibleConstraints {
        /// Sum of the four class minimums.
        required: u32,
        /// Requested password length.
        length: u16,
    },

    /// A required class has a non-zero minimum but no characters of that class
    /// survive in the effective set (e.g. `min_digits > 0` while digits are
    /// disabled, or every digit is in `disallow`).
    #[error("required class {class} has minimum {minimum} but no characters available")]
    RequiredClassUnavailable {
        /// Human-readable class name (`lowercase`, `uppercase`, `digits`, `symbols`).
        class: &'static str,
        /// The unsatisfiable minimum.
        minimum: u8,
    },

    /// The requested length is outside the supported range of 16..=256.
    #[error("requested length {length} is out of range 16..=256")]
    LengthOutOfRange {
        /// The offending length.
        length: u16,
    },
}
