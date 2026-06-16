//! `passman-crypto` — cryptographic primitives and zeroizing secret types.
//!
//! The cryptographic foundation for passman. This crate exposes only vetted
//! primitives (Argon2id, HKDF-SHA256, XChaCha20-Poly1305) and zeroizing secret
//! wrappers. It performs no I/O, contains no platform-specific code, knows
//! nothing about the vault format, and emits no logs.
//!
//! # Modules
//!
//! - [`secret`] — zeroizing wrappers ([`SecretString`], [`SecretArray`],
//!   [`SecretBytes`]).
//! - [`key`] — role-typed key newtypes ([`MasterKey`], [`EntryKey`]).
//! - [`error`] — the [`CryptoError`] taxonomy.
//! - [`kdf`] — Argon2id password-based derivation and [`KdfParams`].
//! - [`derive`] — HKDF-SHA256 extract/expand.
//! - [`aead`] — XChaCha20-Poly1305 authenticated encryption.
//! - [`rng`] — CSPRNG helpers over `OsRng`.
//! - [`ct`] — constant-time comparison.
//!
//! All domain-separation `info` strings, nonces, and salts are supplied by the
//! caller; this crate hardcodes none of them.
#![forbid(unsafe_code)]

pub mod aead;
pub mod ct;
pub mod derive;
pub mod error;
pub mod kdf;
pub mod key;
pub mod rng;
pub mod secret;

pub use ct::ct_eq;
pub use derive::{hkdf_expand, hkdf_master};
pub use error::CryptoError;
pub use kdf::{argon2id, KdfParams, KDF_PARAMS_LEN};
pub use key::{EntryKey, MasterKey};
pub use rng::{fill_random, random_nonce, random_secret};
pub use secret::{SecretArray, SecretBytes, SecretString};
