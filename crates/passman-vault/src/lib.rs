//! `passman-vault` — the vault binary format (pure, no I/O).
//!
//! Parses and serializes the vault to and from byte buffers: per-entry sealed
//! AEAD envelopes, the sealed index (labels + per-entry policy), the
//! index↔envelope-set integrity check, advisory rate-limit bytes, and
//! metadata. Given a `K_master` it derives `K_index` and per-entry `K_entry`
//! via `passman_crypto::hkdf_expand`. It performs no filesystem or network I/O
//! (the caller owns atomic writes and locking), does not derive the master key,
//! and emits no logs. See `architecture.md` §4.4–§4.7.
//!
//! # Public surface
//!
//! - [`Vault`] — parse/serialize ([`Vault::from_bytes`] / [`Vault::to_bytes`]),
//!   create ([`Vault::create`]), probe ([`Vault::verify_probe`]), open the
//!   sealed index with the integrity check ([`Vault::open_index`]), decrypt an
//!   entry ([`Vault::decrypt_entry`]), and mutate
//!   ([`Vault::add_or_update_entry`], [`Vault::remove_entry`],
//!   [`Vault::set_metadata`], [`Vault::set_rate_limit`],
//!   [`Vault::set_hsm_blobs`]).
//! - [`EntryId`], [`EntryRecord`], [`IndexEntry`], [`Index`],
//!   [`VaultMetadata`], [`EntryEnvelope`] — the data types.
//! - [`VaultError`] — the error taxonomy.
//! - Domain-separation constants [`INDEX_INFO`] / [`ENTRY_INFO_PREFIX`] and the
//!   format constants [`FORMAT_VERSION`], [`KDF_ALGORITHM_ARGON2ID`],
//!   [`PROBE_PLAINTEXT`].
#![forbid(unsafe_code)]

mod error;
mod id;
mod index;
mod reader;
mod record;
mod vault;

pub use error::VaultError;
pub use id::{EntryId, ENTRY_ID_LEN};
pub use index::{Index, IndexEntry, ENTRY_INFO_PREFIX, INDEX_INFO};
pub use record::EntryRecord;
pub use vault::{
    EntryEnvelope, Vault, VaultMetadata, FORMAT_VERSION, KDF_ALGORITHM_ARGON2ID, PROBE_PLAINTEXT,
};
