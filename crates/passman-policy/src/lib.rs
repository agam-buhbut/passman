//! `passman-policy` — password generation, entropy estimation, and policy types.
//!
//! Generates high-entropy passwords with `OsRng` (rejection sampling, no modulo
//! bias), estimates master-password strength via `zxcvbn`, and defines the
//! per-entry policy model. No I/O, no logging. See `architecture.md` §8.
//!
//! # Overview
//!
//! - [`Charset`] / [`SymbolSet`] / [`RequiredClasses`] describe which
//!   characters and class minimums a generated password must satisfy.
//! - [`EntryPolicy`] holds optional per-site overrides and is `serde`-
//!   serializable because it lives inside the sealed index (`architecture.md`
//!   §4.5 / §8.2). [`EntryPolicy::resolve_over`] merges it over a
//!   [`GenerationRequest`] (typically [`GenerationRequest::default_vault`]).
//! - [`generate`] produces a zeroizing [`passman_crypto::SecretString`].
//! - [`generated_entropy_bits`], [`estimate_master`], and [`classify`] cover
//!   entropy and crack-time estimation; [`classify`] is the export-gate
//!   predicate used by `passman-core` (`architecture.md` §7.5 / §8.4).
//! - [`validate`] reports (never blocks) policy shortfalls for imported
//!   passwords (`architecture.md` §8.7).
#![forbid(unsafe_code)]

mod charset;
mod entropy;
mod error;
mod generate;
mod policy;
mod validate;

pub use charset::{Charset, SymbolSet};
pub use entropy::{
    classify, estimate_master, generated_entropy_bits, CrackEstimates, MasterEntropy, StrengthTier,
};
pub use error::PolicyError;
pub use generate::generate;
pub use policy::{
    EntryPolicy, GenerationRequest, RequiredClasses, DEFAULT_LENGTH, MAX_LENGTH, MIN_LENGTH,
};
pub use validate::{validate, ValidationReport};
