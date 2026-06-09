//! Character classes, symbol sets, and effective-charset construction.
//!
//! A [`Charset`] selects which character classes a generated password may draw
//! from. Resolving it against its `disallow` list yields the *effective* set —
//! the concrete characters generation samples from. See `architecture.md` §8.2.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The lowercase ASCII letters `a..=z`.
pub(crate) const LOWERCASE: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];

/// The uppercase ASCII letters `A..=Z`.
pub(crate) const UPPERCASE: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

/// The ASCII digits `0..=9`.
pub(crate) const DIGITS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

/// A small, broadly shell- and form-safe symbol subset.
///
/// Chosen to avoid characters that are commonly rejected by password forms or
/// that require shell escaping (quotes, backslash, angle brackets, etc.).
pub(crate) const BASIC_SYMBOLS: &[char] =
    &['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '=', '+'];

/// All 32 ASCII punctuation characters (`!` through `~`, the printable
/// non-alphanumeric set). Matches Rust's `char::is_ascii_punctuation`.
pub(crate) const FULL_SYMBOLS: &[char] = &[
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
    '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~',
];

/// Which symbol characters a charset may include.
///
/// Serialized inside the sealed index and the recovery payload (see
/// `architecture.md` §4.5 / §8.2), so the variant set and field layout are
/// wire-stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolSet {
    /// No symbols.
    None,
    /// A small, broadly-accepted safe subset (see [`BASIC_SYMBOLS`]).
    Basic,
    /// All 32 ASCII punctuation characters (see [`FULL_SYMBOLS`]).
    Full,
    /// A caller-supplied explicit set of symbol characters.
    Custom(BTreeSet<char>),
}

impl SymbolSet {
    /// The concrete symbol characters this set contributes, before any
    /// `disallow` filtering.
    fn chars(&self) -> Vec<char> {
        match self {
            SymbolSet::None => Vec::new(),
            SymbolSet::Basic => BASIC_SYMBOLS.to_vec(),
            SymbolSet::Full => FULL_SYMBOLS.to_vec(),
            SymbolSet::Custom(set) => set.iter().copied().collect(),
        }
    }
}

/// The character classes a generated password may draw from.
///
/// The four boolean flags select the alphanumeric classes; `symbols` selects a
/// [`SymbolSet`]. `disallow` removes specific characters from whatever the
/// flags selected (e.g. excluding visually ambiguous `O`/`0`/`l`/`1`).
///
/// Fields are private to keep the serialized shape under this crate's control;
/// construct via [`Charset::new`] or the convenience builders and read via the
/// accessors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charset {
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: SymbolSet,
    disallow: BTreeSet<char>,
}

impl Charset {
    /// Construct a charset from explicit class selections.
    #[must_use]
    pub fn new(
        lowercase: bool,
        uppercase: bool,
        digits: bool,
        symbols: SymbolSet,
        disallow: BTreeSet<char>,
    ) -> Self {
        Self {
            lowercase,
            uppercase,
            digits,
            symbols,
            disallow,
        }
    }

    /// The default vault charset: lower + upper + digits + full ASCII symbols,
    /// nothing disallowed (`architecture.md` §8.6).
    #[must_use]
    pub fn default_vault() -> Self {
        Self {
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: SymbolSet::Full,
            disallow: BTreeSet::new(),
        }
    }

    /// Whether lowercase letters are selected.
    #[must_use]
    pub fn lowercase(&self) -> bool {
        self.lowercase
    }

    /// Whether uppercase letters are selected.
    #[must_use]
    pub fn uppercase(&self) -> bool {
        self.uppercase
    }

    /// Whether digits are selected.
    #[must_use]
    pub fn digits(&self) -> bool {
        self.digits
    }

    /// The selected symbol set.
    #[must_use]
    pub fn symbols(&self) -> &SymbolSet {
        &self.symbols
    }

    /// The set of explicitly disallowed characters.
    #[must_use]
    pub fn disallow(&self) -> &BTreeSet<char> {
        &self.disallow
    }

    /// The lowercase characters surviving `disallow`.
    pub(crate) fn effective_lowercase(&self) -> Vec<char> {
        self.filter_class(self.lowercase, LOWERCASE)
    }

    /// The uppercase characters surviving `disallow`.
    pub(crate) fn effective_uppercase(&self) -> Vec<char> {
        self.filter_class(self.uppercase, UPPERCASE)
    }

    /// The digit characters surviving `disallow`.
    pub(crate) fn effective_digits(&self) -> Vec<char> {
        self.filter_class(self.digits, DIGITS)
    }

    /// The symbol characters surviving `disallow`.
    pub(crate) fn effective_symbols(&self) -> Vec<char> {
        self.symbols
            .chars()
            .into_iter()
            .filter(|c| !self.disallow.contains(c))
            .collect()
    }

    fn filter_class(&self, enabled: bool, class: &[char]) -> Vec<char> {
        if !enabled {
            return Vec::new();
        }
        class
            .iter()
            .copied()
            .filter(|c| !self.disallow.contains(c))
            .collect()
    }

    /// Build the full effective character set: the union of every selected
    /// class minus `disallow`, deduplicated and in a stable order.
    ///
    /// Custom symbol sets can overlap the alphanumeric classes, so the result
    /// is deduplicated to keep the sampling distribution uniform over distinct
    /// characters.
    pub(crate) fn effective_set(&self) -> Vec<char> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for c in self
            .effective_lowercase()
            .into_iter()
            .chain(self.effective_uppercase())
            .chain(self.effective_digits())
            .chain(self.effective_symbols())
        {
            if seen.insert(c) {
                out.push(c);
            }
        }
        out
    }
}
