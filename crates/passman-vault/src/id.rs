//! Stable 16-byte entry identifier.
//!
//! Each entry is keyed by a [`EntryId`] — a `UUIDv4` minted from the OS CSPRNG
//! (`architecture.md` §4.4). The 16 raw bytes are both the per-entry key's
//! domain-separation suffix (`b"entry-v0:" ‖ id`) and part of the per-entry
//! AEAD associated data (`format_version ‖ id`), binding an envelope to exactly
//! one identity. Two-way binding (key-from-id *and* id-in-AAD) is why an
//! envelope cannot be relocated to another id's slot.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Length of an [`EntryId`] in bytes.
pub const ENTRY_ID_LEN: usize = 16;

/// A 16-byte entry identifier (a `UUIDv4`).
///
/// `Copy` because it is small and non-secret (ids leak by design via the
/// envelope layout — `architecture.md` §4.5). Ordered so callers can keep
/// deterministic collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryId([u8; ENTRY_ID_LEN]);

impl EntryId {
    /// Generate a fresh random identifier (`UUIDv4`, OS-CSPRNG-backed).
    ///
    /// `uuid`'s `new_v4` draws from `getrandom`, i.e. the operating system
    /// entropy source — the same root as the rest of the system's randomness.
    #[must_use]
    pub fn generate() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    /// Construct from raw bytes (e.g. when parsing an envelope header).
    #[must_use]
    pub fn from_bytes(bytes: [u8; ENTRY_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 16 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ENTRY_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for EntryId {
    /// Render as the canonical hyphenated UUID form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Uuid::from_bytes(self.0), f)
    }
}

#[cfg(test)]
mod tests {
    use super::{EntryId, ENTRY_ID_LEN};

    #[test]
    fn generate_is_unique_and_round_trips_bytes() {
        let a = EntryId::generate();
        let b = EntryId::generate();
        assert_ne!(a, b, "two fresh ids must differ");
        let raw = *a.as_bytes();
        assert_eq!(EntryId::from_bytes(raw), a);
        assert_eq!(raw.len(), ENTRY_ID_LEN);
    }

    #[test]
    fn display_is_canonical_uuid() {
        let id = EntryId::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ]);
        assert_eq!(id.to_string(), "12345678-9abc-def0-1234-56789abcdef0");
    }

    #[test]
    fn v4_version_and_variant_bits_set() {
        // A generated id must have the RFC 4122 v4 version nibble and variant.
        let id = EntryId::generate();
        let bytes = id.as_bytes();
        assert_eq!(bytes[6] >> 4, 0x4, "version nibble must be 4");
        assert_eq!(bytes[8] >> 6, 0b10, "variant bits must be 10");
    }
}
