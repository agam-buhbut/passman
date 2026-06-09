//! The recovery DTOs and their zeroization-preserving payload wire form.
//!
//! These are this crate's *own* data types (`architecture.md` §2.3) — it never
//! references the vault's `EntryRecord`/`EntryId`/`EntryPolicy`. `passman-core`
//! translates between the runtime vault types and these DTOs (per-entry policy
//! crosses as opaque postcard bytes, so this crate needs no `passman-policy`
//! dependency).
//!
//! The payload is **hand-encoded** into a zeroizing [`SecretBytes`] rather than
//! routed through a serde/postcard step, because the latter would funnel every
//! secret field through plain `String`s that linger in memory after drop. On
//! import the decrypted bytes are parsed field-by-field *directly* into
//! [`SecretString`]s. There is **no inner checksum** — the AEAD tag is the sole
//! integrity control (`architecture.md` §7.3).
//!
//! # Authenticated payload layout (before AEAD, `architecture.md` §7.3)
//!
//! ```text
//! payload_version : u8 (= 0x01)
//! totp_seed       : 32 bytes
//! vault_kdf       : 9 bytes        KdfParams::to_bytes of the ORIGINAL vault params
//! entry_count     : u32-LE
//! entries[entry_count]:
//!     id          : 16 bytes
//!     label       : u32-LE len ‖ UTF-8
//!     username    : u32-LE len ‖ UTF-8
//!     password    : u32-LE len ‖ UTF-8
//!     url         : u32-LE len ‖ UTF-8
//!     notes       : u32-LE len ‖ UTF-8
//!     policy      : u32-LE len ‖ opaque bytes
//! ```

use passman_crypto::{KdfParams, SecretArray, SecretBytes, SecretString, KDF_PARAMS_LEN};

use crate::error::RecoveryError;
use crate::reader::Reader;

/// The current payload (inner) version byte (`architecture.md` §7.3).
pub const PAYLOAD_VERSION: u8 = 0x01;

/// Length of an entry id, in bytes (`UUIDv4`).
pub const ENTRY_ID_LEN: usize = 16;

/// Length of the TOTP seed `S`, in bytes.
pub const TOTP_SEED_LEN: usize = 32;

/// One exported entry.
///
/// `label` is non-secret metadata shown in the import preview; the four text
/// fields are zeroizing [`SecretString`]s. `policy` is opaque bytes
/// (postcard-encoded `EntryPolicy` supplied by `passman-core`) that this crate
/// carries through verbatim.
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryEntry {
    /// Entry id (`UUIDv4` from `OsRng`).
    pub id: [u8; ENTRY_ID_LEN],
    /// Human-readable label (metadata, shown in the import preview).
    pub label: String,
    /// Account username / login.
    pub username: SecretString,
    /// Account password.
    pub password: SecretString,
    /// Associated URL.
    pub url: SecretString,
    /// Free-form notes.
    pub notes: SecretString,
    /// Opaque per-entry policy (postcard-encoded `EntryPolicy`).
    pub policy: Vec<u8>,
}

/// The full decrypted recovery payload.
///
/// Carries the TOTP seed `S` (for authenticator re-provisioning — not a KDF
/// input), the *original vault* Argon2 params (so import can recreate the vault
/// at the same cost; distinct from the recovery KDF params in the file header),
/// and every entry.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportPayload {
    /// The TOTP seed `S` (re-provisioning only).
    pub totp_seed: SecretArray<TOTP_SEED_LEN>,
    /// The *vault's* Argon2 params (not the recovery KDF's).
    pub original_vault_kdf: KdfParams,
    /// The exported entries.
    pub entries: Vec<RecoveryEntry>,
}

/// Append a `u32-LE` length prefix followed by `body` to `buf`.
///
/// A body longer than `u32::MAX` is impossible for any realistic secret (user
/// text / opaque policy bytes), but to keep the function total it clamps the
/// prefix rather than truncating the body silently — the resulting payload
/// would then fail to round-trip and surface as a decode error, never as a
/// panic. `buf` is the zeroizing payload buffer being built.
fn push_u32_prefixed(buf: &mut Vec<u8>, body: &[u8]) {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(body);
}

/// Encode an [`ExportPayload`] into the authenticated-payload buffer
/// (`architecture.md` §7.3), ready for AEAD encryption.
///
/// The buffer is built inside a `Vec<u8>` and immediately wrapped in a
/// zeroizing [`SecretBytes`], so the plaintext that goes into the cipher is
/// scrubbed when dropped. Secret fields are written via their `expose_bytes`
/// accessors directly into this buffer; no secret is copied through a separate
/// plain `String`.
///
/// There is no inner checksum: the AEAD tag is the integrity control.
#[must_use]
pub(crate) fn encode_payload(payload: &ExportPayload) -> SecretBytes {
    // Pre-size to reduce reallocations (each realloc could leave an un-scrubbed
    // copy of secret bytes behind; sizing up-front minimizes that). This is a
    // lower bound, not exact: header + per-entry fixed bytes + field bodies.
    let mut size = 1 + TOTP_SEED_LEN + KDF_PARAMS_LEN + 4;
    for e in &payload.entries {
        size += ENTRY_ID_LEN + 6 * 4; // id + six length prefixes
        size += e.label.len()
            + e.username.expose_bytes().len()
            + e.password.expose_bytes().len()
            + e.url.expose_bytes().len()
            + e.notes.expose_bytes().len()
            + e.policy.len();
    }

    let mut buf = Vec::with_capacity(size);
    buf.push(PAYLOAD_VERSION);
    buf.extend_from_slice(payload.totp_seed.expose_bytes());
    buf.extend_from_slice(&payload.original_vault_kdf.to_bytes());

    // entry_count: clamp like every other length. An export with > u32::MAX
    // entries is not reachable in practice; clamping keeps the function total.
    let entry_count = u32::try_from(payload.entries.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&entry_count.to_le_bytes());

    for e in &payload.entries {
        buf.extend_from_slice(&e.id);
        push_u32_prefixed(&mut buf, e.label.as_bytes());
        push_u32_prefixed(&mut buf, e.username.expose_bytes());
        push_u32_prefixed(&mut buf, e.password.expose_bytes());
        push_u32_prefixed(&mut buf, e.url.expose_bytes());
        push_u32_prefixed(&mut buf, e.notes.expose_bytes());
        push_u32_prefixed(&mut buf, &e.policy);
    }

    SecretBytes::new(buf)
}

/// Decode an [`ExportPayload`] from a decrypted (authenticated) payload buffer.
///
/// Parses field-by-field through the bounds-checked [`Reader`]; every length
/// prefix is validated against the remaining plaintext before any slice or
/// allocation. Secret text fields are parsed straight into [`SecretString`]s
/// and the seed into a [`SecretArray`].
///
/// The input is authenticated by the AEAD tag before this runs, so a structural
/// problem indicates a logic/version mismatch rather than attacker input; it is
/// returned as [`RecoveryError::MalformedPayload`] rather than panicked. The
/// entry vector is *not* pre-allocated from the declared `entry_count` (which is
/// not yet validated against the available bytes); entries are pushed as they
/// parse, so a hostile count cannot drive a giant allocation.
///
/// # Errors
///
/// - [`RecoveryError::MalformedPayload`] for a bad inner version byte, a length
///   prefix that overruns the buffer, a non-UTF-8 text field, or trailing bytes
///   after the declared entries.
/// - [`RecoveryError::Truncated`] if the buffer ends mid-field (also a
///   structural defect in an authenticated payload).
pub(crate) fn decode_payload(plaintext: &SecretBytes) -> Result<ExportPayload, RecoveryError> {
    let mut r = Reader::new(plaintext.expose());

    let version = r.read_u8("payload_version")?;
    if version != PAYLOAD_VERSION {
        return Err(RecoveryError::MalformedPayload {
            reason: "unsupported payload version",
        });
    }

    let totp_seed = SecretArray::new(r.take_array::<TOTP_SEED_LEN>("totp_seed")?);
    let original_vault_kdf =
        KdfParams::from_bytes(r.take_array::<KDF_PARAMS_LEN>("original_vault_kdf")?);

    let entry_count = r.read_u32_le("entry_count")? as usize;

    // Do NOT `Vec::with_capacity(entry_count)`: the count is attacker-influenced
    // (in the import-from-tampered-file sense) and not yet validated against the
    // remaining bytes. Push as we parse; each entry's reads are bounds-checked,
    // so an inflated count simply runs out of input and errors.
    let mut entries: Vec<RecoveryEntry> = Vec::new();
    for _ in 0..entry_count {
        let id = r.take_array::<ENTRY_ID_LEN>("entry_id")?;
        let label_bytes = r.read_u32_prefixed_vec("label")?;
        let label =
            String::from_utf8(label_bytes).map_err(|_| RecoveryError::MalformedPayload {
                reason: "label is not valid UTF-8",
            })?;
        let username = r.read_u32_prefixed_secret_string("username")?;
        let password = r.read_u32_prefixed_secret_string("password")?;
        let url = r.read_u32_prefixed_secret_string("url")?;
        let notes = r.read_u32_prefixed_secret_string("notes")?;
        let policy = r.read_u32_prefixed_vec("policy")?;
        entries.push(RecoveryEntry {
            id,
            label,
            username,
            password,
            url,
            notes,
            policy,
        });
    }

    // No trailing bytes after the declared entries (fail closed).
    r.expect_eof()?;

    Ok(ExportPayload {
        totp_seed,
        original_vault_kdf,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_payload, encode_payload, ExportPayload, RecoveryEntry};
    use passman_crypto::{KdfParams, SecretArray, SecretBytes, SecretString};

    fn sample_entry(seed: u8) -> RecoveryEntry {
        RecoveryEntry {
            id: [seed; 16],
            label: format!("label-{seed}"),
            username: SecretString::new(format!("user{seed}")),
            password: SecretString::new(format!("pw!{seed}🔐")),
            url: SecretString::new("https://exämple.test".to_owned()),
            notes: SecretString::new(format!("notές {seed}")),
            policy: vec![seed, seed.wrapping_add(1), 0xAB, 0xCD],
        }
    }

    fn sample_payload(n: u8) -> ExportPayload {
        ExportPayload {
            totp_seed: SecretArray::new([0x5Au8; 32]),
            original_vault_kdf: KdfParams {
                m_kib: 1_048_576,
                t: 4,
                p: 1,
            },
            entries: (0..n).map(sample_entry).collect(),
        }
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let payload = sample_payload(3);
        let encoded = encode_payload(&payload);
        let decoded = decode_payload(&encoded).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn round_trip_empty_entries() {
        let payload = sample_payload(0);
        let encoded = encode_payload(&payload);
        let decoded = decode_payload(&encoded).expect("decode");
        assert_eq!(decoded.entries.len(), 0);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn round_trip_empty_secret_fields() {
        let payload = ExportPayload {
            totp_seed: SecretArray::new([0u8; 32]),
            original_vault_kdf: KdfParams {
                m_kib: 262_144,
                t: 4,
                p: 1,
            },
            entries: vec![RecoveryEntry {
                id: [1u8; 16],
                label: String::new(),
                username: SecretString::new(String::new()),
                password: SecretString::new(String::new()),
                url: SecretString::new(String::new()),
                notes: SecretString::new(String::new()),
                policy: Vec::new(),
            }],
        };
        let decoded = decode_payload(&encode_payload(&payload)).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes = encode_payload(&sample_payload(1)).expose().to_vec();
        bytes[0] = 0x02;
        let err = decode_payload(&SecretBytes::new(bytes)).expect_err("bad version");
        assert!(matches!(
            err,
            crate::error::RecoveryError::MalformedPayload { .. }
        ));
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let bytes = encode_payload(&sample_payload(2)).expose().to_vec();
        // Cut off mid-payload.
        let truncated = SecretBytes::new(bytes[..bytes.len() / 2].to_vec());
        assert!(decode_payload(&truncated).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode_payload(&sample_payload(1)).expose().to_vec();
        bytes.push(0x00);
        let err = decode_payload(&SecretBytes::new(bytes)).expect_err("trailing");
        assert!(matches!(
            err,
            crate::error::RecoveryError::TrailingBytes { .. }
        ));
    }

    #[test]
    fn decode_rejects_inflated_entry_count_without_panic() {
        // Build a valid 1-entry payload, then overwrite entry_count with a huge
        // value. The parser must run out of input and error, never allocate
        // gigabytes or panic.
        let mut bytes = encode_payload(&sample_payload(1)).expose().to_vec();
        // entry_count sits right after version(1) + seed(32) + kdf(9) = 42.
        let off = 1 + 32 + 9;
        bytes[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = decode_payload(&SecretBytes::new(bytes)).expect_err("inflated count");
        assert!(matches!(err, crate::error::RecoveryError::Truncated { .. }));
    }
}
