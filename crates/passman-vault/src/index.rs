//! The sealed index: the authoritative `{id, label, policy}` list.
//!
//! The index is the only place entry labels and per-entry policies live. It is
//! serialized with `postcard` and sealed as a single AEAD blob under `K_index`
//! (`architecture.md` §4.5). Plain `String` labels are acceptable here because
//! the entire structure is encrypted — an attacker holding the vault file sees
//! only the ciphertext length, never a label.
//!
//! This module also owns the index/per-entry domain-separation strings
//! (`architecture.md` §4.6). Master/recovery `info` strings belong to other
//! crates.

use serde::{Deserialize, Serialize};

use passman_policy::EntryPolicy;

use crate::id::{EntryId, ENTRY_ID_LEN};

/// HKDF-Expand `info` for the index key: `K_index = HKDF-Expand(K_master,
/// "index-v0")` (`architecture.md` §4.6).
pub const INDEX_INFO: &[u8] = b"index-v0";

/// Fixed prefix of the per-entry HKDF-Expand `info`. The full `info` is this
/// prefix followed by the entry's 16 raw id bytes: `b"entry-v0:" ‖ id`
/// (`architecture.md` §4.6).
pub const ENTRY_INFO_PREFIX: &[u8] = b"entry-v0:";

/// Build the per-entry HKDF-Expand `info` string `b"entry-v0:" ‖ id_bytes(16)`.
///
/// Returned as a fixed-size array (prefix length + 16) so it needs no
/// allocation and its length is statically known.
#[must_use]
pub(crate) fn entry_info(id: &EntryId) -> [u8; ENTRY_INFO_PREFIX.len() + ENTRY_ID_LEN] {
    let mut info = [0u8; ENTRY_INFO_PREFIX.len() + ENTRY_ID_LEN];
    info[..ENTRY_INFO_PREFIX.len()].copy_from_slice(ENTRY_INFO_PREFIX);
    info[ENTRY_INFO_PREFIX.len()..].copy_from_slice(id.as_bytes());
    info
}

/// One row of the sealed index: an entry's identity, label, and policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Stable entry identifier (also names the matching envelope).
    pub id: EntryId,
    /// Human-readable label (lives only inside the sealed index).
    pub label: String,
    /// Per-entry generation policy (`architecture.md` §8.2).
    pub policy: EntryPolicy,
}

impl IndexEntry {
    /// Construct an index row.
    #[must_use]
    pub fn new(id: EntryId, label: String, policy: EntryPolicy) -> Self {
        Self { id, label, policy }
    }
}

/// The in-memory decrypted index: an ordered list of [`IndexEntry`].
///
/// Order is preserved across serialize/deserialize (postcard encodes the `Vec`
/// in order), which keeps round-trips and the envelope ordering deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index(Vec<IndexEntry>);

impl Index {
    /// An empty index (a freshly-created vault).
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Borrow the rows.
    #[must_use]
    pub fn entries(&self) -> &[IndexEntry] {
        &self.0
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the index has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Find a row by id.
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&IndexEntry> {
        self.0.iter().find(|e| &e.id == id)
    }

    /// Wrap an existing row vector (used by the parser / mutation path).
    #[must_use]
    pub(crate) fn from_vec(rows: Vec<IndexEntry>) -> Self {
        Self(rows)
    }

    /// Insert a new row or replace the existing row with the same id.
    ///
    /// Returns `true` if an existing row was replaced, `false` if appended.
    pub(crate) fn upsert(&mut self, entry: IndexEntry) -> bool {
        if let Some(slot) = self.0.iter_mut().find(|e| e.id == entry.id) {
            *slot = entry;
            true
        } else {
            self.0.push(entry);
            false
        }
    }

    /// Remove the row with `id`, returning whether a row was removed.
    pub(crate) fn remove(&mut self, id: &EntryId) -> bool {
        let before = self.0.len();
        self.0.retain(|e| &e.id != id);
        self.0.len() != before
    }

    /// Borrow the underlying rows for serialization.
    pub(crate) fn as_rows(&self) -> &Vec<IndexEntry> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{entry_info, Index, IndexEntry, ENTRY_INFO_PREFIX, INDEX_INFO};
    use crate::id::EntryId;
    use passman_policy::EntryPolicy;

    #[test]
    fn domain_sep_constants_are_stable() {
        assert_eq!(INDEX_INFO, b"index-v0");
        assert_eq!(ENTRY_INFO_PREFIX, b"entry-v0:");
    }

    #[test]
    fn entry_info_is_prefix_plus_id() {
        let id = EntryId::from_bytes([0xABu8; 16]);
        let info = entry_info(&id);
        assert_eq!(&info[..9], b"entry-v0:");
        assert_eq!(&info[9..], &[0xABu8; 16]);
        assert_eq!(info.len(), 9 + 16);
    }

    #[test]
    fn upsert_and_remove_behave() {
        let mut idx = Index::new();
        let id = EntryId::from_bytes([1u8; 16]);
        assert!(!idx.upsert(IndexEntry::new(id, "a".into(), EntryPolicy::default())));
        assert_eq!(idx.len(), 1);
        // Replacing the same id updates in place, does not grow.
        assert!(idx.upsert(IndexEntry::new(id, "b".into(), EntryPolicy::default())));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.get(&id).expect("row present").label, "b");
        assert!(idx.remove(&id));
        assert!(idx.is_empty());
        assert!(!idx.remove(&id));
    }
}
