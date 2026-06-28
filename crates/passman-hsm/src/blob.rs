//! The opaque wrap-blob outer format (`architecture.md` §6.3).
//!
//! One blob per slot. The outer framing is backend-agnostic:
//!
//! ```text
//! 0   1   blob_version (= 0x00)
//! 1   1   hsm_kind     (see HsmKind wire bytes)
//! 2   2   payload_len  (u16-LE)
//! 4   N   payload      (hsm-kind-specific, opaque to everyone but the backend)
//! ```
//!
//! There is deliberately no integrity tag on the blob: integrity propagates
//! through the AEAD-probe chain (§6.3). The parser is the part that *does* see
//! attacker-controlled bytes (the blob sits on disk in the vault file), so it
//! is fully bounds-checked and panic-free — every length is validated against
//! the remaining input and trailing bytes are rejected.

use crate::error::HsmError;
use crate::slot::HsmKind;

/// The single supported outer blob version (§6.3, §4.10).
///
/// This is the **only** version field in the format: the per-backend `payload`
/// has no inner version byte of its own, so every backend-specific payload
/// layout is versioned by this *outer* `blob_version`. Consequently it MUST be
/// bumped whenever **any** backend's payload format changes (and `from_bytes`
/// taught to accept the old and new layouts), so an old on-disk blob is never
/// silently misparsed against a newer payload schema.
const BLOB_VERSION: u8 = 0x00;

/// Bytes of fixed header before the payload: version(1) + kind(1) + len(2).
const HEADER_LEN: usize = 4;

/// An opaque, length-framed hardware-wrap blob.
///
/// The `payload` is meaningful only to the backend whose [`HsmKind`] produced
/// it; this type treats it as opaque bytes and only guarantees the outer
/// framing round-trips losslessly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedBlob {
    kind: HsmKind,
    payload: Vec<u8>,
}

impl WrappedBlob {
    /// Construct a blob from a backend kind and its opaque payload.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::MalformedBlob`] if `payload` exceeds [`u16::MAX`]
    /// bytes, since `payload_len` is encoded as a `u16`.
    pub fn from_parts(kind: HsmKind, payload: Vec<u8>) -> Result<Self, HsmError> {
        if payload.len() > usize::from(u16::MAX) {
            return Err(HsmError::MalformedBlob {
                reason: "payload exceeds u16::MAX",
            });
        }
        Ok(Self { kind, payload })
    }

    /// The backend kind that produced this blob.
    #[must_use]
    pub fn kind(&self) -> HsmKind {
        self.kind
    }

    /// The opaque, backend-specific payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Serialize to the outer wire format (§6.3).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // `payload.len() <= u16::MAX` is an invariant of every constructor
        // (`from_parts` and `from_bytes` both enforce it), so `try_from` always
        // succeeds here; `unwrap_or(u16::MAX)` is a panic-free fallback that the
        // invariant means is never taken.
        let payload_len = u16::try_from(self.payload.len()).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(BLOB_VERSION);
        out.push(self.kind.to_byte());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a blob from the outer wire format (§6.3).
    ///
    /// Fully bounds-checked and panic-free: it validates the version byte, maps
    /// the kind byte, checks `payload_len` against the remaining input, and
    /// rejects any trailing bytes after the declared payload.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::MalformedBlob`] (with a fixed, non-secret reason) for
    /// a short header, an unknown version, an unknown kind byte, a `payload_len`
    /// larger than the remaining input, or trailing bytes. The blob bytes are
    /// never echoed in the error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HsmError> {
        // Header: split off exactly the fixed prefix; `get` returns None (not a
        // panic) if the input is shorter than the header.
        let header = bytes.get(..HEADER_LEN).ok_or(HsmError::MalformedBlob {
            reason: "input shorter than 4-byte header",
        })?;

        if header[0] != BLOB_VERSION {
            return Err(HsmError::MalformedBlob {
                reason: "unsupported blob_version",
            });
        }

        let kind = HsmKind::from_byte(header[1])?;

        // payload_len is the last two header bytes, little-endian.
        let payload_len = usize::from(u16::from_le_bytes([header[2], header[3]]));

        let payload = bytes.get(HEADER_LEN..).ok_or(HsmError::MalformedBlob {
            // Unreachable given the header check above, but surfaced rather
            // than indexed to keep the parser panic-free by construction.
            reason: "missing payload region",
        })?;

        if payload.len() < payload_len {
            return Err(HsmError::MalformedBlob {
                reason: "payload_len exceeds remaining input",
            });
        }
        if payload.len() > payload_len {
            return Err(HsmError::MalformedBlob {
                reason: "trailing bytes after payload",
            });
        }

        Ok(Self {
            kind,
            payload: payload.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{WrappedBlob, BLOB_VERSION, HEADER_LEN};
    use crate::error::HsmError;
    use crate::slot::HsmKind;

    #[test]
    fn round_trip_preserves_kind_and_payload() {
        for kind in [
            HsmKind::Tpm2,
            HsmKind::NCryptRsa,
            HsmKind::AndroidGcm,
            HsmKind::SecureEnclave,
            HsmKind::SecretService,
            HsmKind::SoftwareMock,
        ] {
            let payload = vec![0xAB; 37];
            let blob = WrappedBlob::from_parts(kind, payload.clone()).expect("from_parts");
            let bytes = blob.to_bytes();
            let parsed = WrappedBlob::from_bytes(&bytes).expect("from_bytes");
            assert_eq!(parsed.kind(), kind);
            assert_eq!(parsed.payload(), payload.as_slice());
            assert_eq!(parsed, blob);
        }
    }

    #[test]
    fn empty_payload_round_trips() {
        let blob = WrappedBlob::from_parts(HsmKind::SoftwareMock, Vec::new()).expect("from_parts");
        let bytes = blob.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        let parsed = WrappedBlob::from_bytes(&bytes).expect("from_bytes");
        assert!(parsed.payload().is_empty());
    }

    #[test]
    fn header_encoding_is_little_endian() {
        let blob = WrappedBlob::from_parts(HsmKind::AndroidGcm, vec![1, 2, 3]).expect("from_parts");
        let bytes = blob.to_bytes();
        assert_eq!(bytes[0], BLOB_VERSION);
        assert_eq!(bytes[1], 0x02); // AndroidGcm wire byte
        assert_eq!(bytes[2], 3); // payload_len low byte
        assert_eq!(bytes[3], 0); // payload_len high byte
    }

    #[test]
    fn rejects_payload_over_u16_max() {
        let too_big = vec![0u8; usize::from(u16::MAX) + 1];
        let err = WrappedBlob::from_parts(HsmKind::SoftwareMock, too_big).expect_err("must reject");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn accepts_max_u16_payload() {
        let max = vec![0u8; usize::from(u16::MAX)];
        let blob = WrappedBlob::from_parts(HsmKind::SoftwareMock, max).expect("from_parts");
        let bytes = blob.to_bytes();
        let parsed = WrappedBlob::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(parsed.payload().len(), usize::from(u16::MAX));
    }

    #[test]
    fn rejects_empty_input() {
        let err = WrappedBlob::from_bytes(&[]).expect_err("must reject");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn rejects_truncated_header() {
        for len in 1..HEADER_LEN {
            let truncated = vec![0u8; len];
            let err = WrappedBlob::from_bytes(&truncated).expect_err("must reject");
            assert!(matches!(err, HsmError::MalformedBlob { .. }));
        }
    }

    #[test]
    fn rejects_unknown_version() {
        // Valid kind + len=0 but version byte 0x01.
        let bytes = [0x01, HsmKind::SoftwareMock.to_byte(), 0x00, 0x00];
        let err = WrappedBlob::from_bytes(&bytes).expect_err("must reject");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn rejects_unknown_kind_byte() {
        // 0x07 is not a defined kind.
        let bytes = [BLOB_VERSION, 0x07, 0x00, 0x00];
        let err = WrappedBlob::from_bytes(&bytes).expect_err("must reject");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn rejects_payload_len_larger_than_remaining() {
        // Declares 10 payload bytes but supplies only 2.
        let bytes = [
            BLOB_VERSION,
            HsmKind::Tpm2.to_byte(),
            0x0A,
            0x00,
            0xFF,
            0xFF,
        ];
        let err = WrappedBlob::from_bytes(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "payload_len exceeds remaining input"
            }
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        // Declares 1 payload byte but supplies 3.
        let bytes = [
            BLOB_VERSION,
            HsmKind::Tpm2.to_byte(),
            0x01,
            0x00,
            0xAA,
            0xBB,
            0xCC,
        ];
        let err = WrappedBlob::from_bytes(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "trailing bytes after payload"
            }
        ));
    }

    #[test]
    fn never_panics_on_arbitrary_prefixes() {
        // Recurse over every sequence drawn from a small adversarial alphabet;
        // calling the parser is the assertion (a panic would abort the test).
        fn recurse(buf: &mut Vec<u8>, alphabet: &[u8], depth: usize) {
            let _ = WrappedBlob::from_bytes(buf);
            if depth == 0 {
                return;
            }
            for &b in alphabet {
                buf.push(b);
                recurse(buf, alphabet, depth - 1);
                buf.pop();
            }
        }

        // Exhaustively feed every 0..=5-byte sequence over the alphabet; covers
        // boundary values around the 4-byte header and the len field.
        let alphabet = [0x00u8, 0x01, 0x02, 0xFF];
        let mut buf = Vec::new();
        recurse(&mut buf, &alphabet, 5);
    }
}
