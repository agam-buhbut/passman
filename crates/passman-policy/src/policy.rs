//! Per-entry policy, the vault default, and the resolved generation request.
//!
//! [`EntryPolicy`] holds optional per-site overrides; merging it over the vault
//! default yields a concrete [`GenerationRequest`]. `EntryPolicy` lives inside
//! the sealed index (`architecture.md` §4.5 / §8.2), so it derives `Serialize`
//! / `Deserialize` and keeps a stable field layout.

use serde::{Deserialize, Serialize};

use crate::charset::Charset;

/// Inclusive lower bound on generated password length (`architecture.md` §8.1).
pub const MIN_LENGTH: u16 = 16;

/// Inclusive upper bound on generated password length (`architecture.md` §8.1).
pub const MAX_LENGTH: u16 = 256;

/// Default generated password length for the vault (`architecture.md` §8.6).
pub const DEFAULT_LENGTH: u16 = 40;

/// Minimum count of each character class a generated password must contain.
///
/// Serialized inside the sealed index, so the field layout is wire-stable.
/// Counts are `u8`; their sum is computed in `u32` to avoid overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredClasses {
    /// Minimum number of lowercase letters.
    pub min_lowercase: u8,
    /// Minimum number of uppercase letters.
    pub min_uppercase: u8,
    /// Minimum number of digits.
    pub min_digits: u8,
    /// Minimum number of symbols.
    pub min_symbols: u8,
}

impl RequiredClasses {
    /// One of each class — the vault default minimum (`architecture.md` §8.6).
    #[must_use]
    pub const fn one_of_each() -> Self {
        Self {
            min_lowercase: 1,
            min_uppercase: 1,
            min_digits: 1,
            min_symbols: 1,
        }
    }

    /// No class minimums.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 0,
            min_symbols: 0,
        }
    }

    /// Sum of all four minimums, computed in `u32` so four `u8::MAX` values
    /// cannot overflow.
    #[must_use]
    pub fn total(&self) -> u32 {
        u32::from(self.min_lowercase)
            + u32::from(self.min_uppercase)
            + u32::from(self.min_digits)
            + u32::from(self.min_symbols)
    }
}

/// Optional per-entry overrides applied over the vault default.
///
/// Every field is `Option`: `None` means "inherit the vault default". Stored in
/// the sealed index so a site-specific constraint (e.g. "max length 12") does
/// not fingerprint the service via the vault file (`architecture.md` §8.2).
///
/// Fields are private to keep the serialized shape stable; build via
/// [`EntryPolicy::default`] / the builder methods and read via the accessors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPolicy {
    length: Option<u16>,
    charset_override: Option<Charset>,
    required_classes_override: Option<RequiredClasses>,
    user_note: Option<String>,
}

impl EntryPolicy {
    /// Override the generated length.
    #[must_use]
    pub fn with_length(mut self, length: u16) -> Self {
        self.length = Some(length);
        self
    }

    /// Override the character set.
    #[must_use]
    pub fn with_charset(mut self, charset: Charset) -> Self {
        self.charset_override = Some(charset);
        self
    }

    /// Override the required-class minimums.
    #[must_use]
    pub fn with_required_classes(mut self, classes: RequiredClasses) -> Self {
        self.required_classes_override = Some(classes);
        self
    }

    /// Attach a free-form user note.
    #[must_use]
    pub fn with_user_note(mut self, note: String) -> Self {
        self.user_note = Some(note);
        self
    }

    /// The length override, if any.
    #[must_use]
    pub fn length(&self) -> Option<u16> {
        self.length
    }

    /// The charset override, if any.
    #[must_use]
    pub fn charset_override(&self) -> Option<&Charset> {
        self.charset_override.as_ref()
    }

    /// The required-classes override, if any.
    #[must_use]
    pub fn required_classes_override(&self) -> Option<RequiredClasses> {
        self.required_classes_override
    }

    /// The user note, if any.
    #[must_use]
    pub fn user_note(&self) -> Option<&str> {
        self.user_note.as_deref()
    }

    /// Resolve this policy over `default`, producing the effective request.
    ///
    /// Each `Some` field overrides the corresponding default; each `None`
    /// inherits it. `user_note` is metadata only and does not affect
    /// generation, so it is not carried into the request.
    ///
    /// This does not validate the result (length bounds, charset size,
    /// satisfiable minimums); those are checked by [`crate::generate`].
    #[must_use]
    pub fn resolve_over(&self, default: &GenerationRequest) -> GenerationRequest {
        GenerationRequest {
            length: self.length.unwrap_or(default.length),
            charset: self
                .charset_override
                .clone()
                .unwrap_or_else(|| default.charset.clone()),
            required_classes: self
                .required_classes_override
                .unwrap_or(default.required_classes),
        }
    }
}

/// A fully-resolved request to generate one password.
///
/// Unlike [`EntryPolicy`], every field is concrete. Build the vault default
/// with [`GenerationRequest::default_vault`], or resolve an [`EntryPolicy`] via
/// [`EntryPolicy::resolve_over`]. This type is a runtime value and is not
/// persisted, so it is intentionally not `Serialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationRequest {
    length: u16,
    charset: Charset,
    required_classes: RequiredClasses,
}

impl GenerationRequest {
    /// Construct a request from explicit parts.
    #[must_use]
    pub fn new(length: u16, charset: Charset, required_classes: RequiredClasses) -> Self {
        Self {
            length,
            charset,
            required_classes,
        }
    }

    /// The default vault generation policy (`architecture.md` §8.6): 40 chars;
    /// lower + upper + digits + full ASCII symbols; no disallow; one of each
    /// class minimum (≈ 262 bits).
    #[must_use]
    pub fn default_vault() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            charset: Charset::default_vault(),
            required_classes: RequiredClasses::one_of_each(),
        }
    }

    /// The requested length.
    #[must_use]
    pub fn length(&self) -> u16 {
        self.length
    }

    /// The resolved character set.
    #[must_use]
    pub fn charset(&self) -> &Charset {
        &self.charset
    }

    /// The resolved class minimums.
    #[must_use]
    pub fn required_classes(&self) -> RequiredClasses {
        self.required_classes
    }
}
