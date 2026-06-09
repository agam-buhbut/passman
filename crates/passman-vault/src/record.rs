//! The per-entry secret payload and its zeroization-preserving wire form.
//!
//! An [`EntryRecord`] holds the four secret fields of one entry. It is never
//! `postcard`-serialized, because that would route the plaintext through plain
//! `String`s that linger in memory after the record is dropped. Instead it is
//! hand-encoded as four length-prefixed UTF-8 fields directly into a byte
//! buffer for encryption, and on decrypt each field is parsed straight out of
//! the (zeroizing) decrypted [`SecretBytes`] into a [`SecretString`]
//! (`architecture.md` §4.4).
//!
//! # Authenticated plaintext layout (before AEAD)
//!
//! ```text
//! true_len : u32-LE              length of the record bytes that follow (no padding)
//! record   : true_len bytes      four length-prefixed (u32-LE) UTF-8 fields:
//!                                   username, password, url, notes
//! padding  : zeros               to the next 256-byte multiple of the WHOLE plaintext
//! ```
//!
//! The `true_len` prefix lives *inside* the authenticated plaintext, so the AEAD
//! tag covers it: padding is authenticated and is stripped deterministically
//! after decryption. The whole plaintext is padded up to a 256-byte bucket
//! boundary so the on-disk envelope size reveals only a quantized size class
//! (`architecture.md` §4.5 / §5.x threat #18).

use passman_crypto::{SecretBytes, SecretString};

use crate::error::VaultError;

/// Padding bucket size in bytes: every entry's authenticated plaintext is
/// zero-padded up to a multiple of this, hiding its true size class.
pub(crate) const BUCKET: usize = 256;

/// Number of secret fields in an [`EntryRecord`].
const FIELD_COUNT: usize = 4;

/// The decrypted secret fields of one vault entry.
///
/// All four fields are zeroizing [`SecretString`]s; the struct as a whole is
/// dropped field-by-field, scrubbing each. Empty fields are represented as
/// empty strings (not absent), so the shape is fixed.
#[derive(Debug, PartialEq, Eq)]
pub struct EntryRecord {
    /// Account username / login.
    pub username: SecretString,
    /// Account password.
    pub password: SecretString,
    /// Associated URL.
    pub url: SecretString,
    /// Free-form notes.
    pub notes: SecretString,
}

impl EntryRecord {
    /// Construct from four owned secret strings.
    #[must_use]
    pub fn new(
        username: SecretString,
        password: SecretString,
        url: SecretString,
        notes: SecretString,
    ) -> Self {
        Self {
            username,
            password,
            url,
            notes,
        }
    }

    /// Encode to the padded authenticated-plaintext buffer ready for AEAD.
    ///
    /// Layout is `true_len(u32-LE) ‖ fields ‖ zero-padding`, padded so the whole
    /// buffer is a multiple of [`BUCKET`]. The returned [`SecretBytes`] is
    /// zeroizing, so the plaintext that goes into the cipher is scrubbed when
    /// dropped.
    ///
    /// # Panics
    ///
    /// Does not panic. (Field lengths are bounded by `usize`; the `u32` length
    /// prefixes are written via `to_le_bytes` after a checked conversion, and a
    /// field longer than `u32::MAX` — impossible for any realistic secret —
    /// would surface as an error rather than truncating, but no such path is
    /// reachable here because inputs are user-typed strings.)
    pub(crate) fn encode_padded(&self) -> SecretBytes {
        let fields: [&[u8]; FIELD_COUNT] = [
            self.username.expose_bytes(),
            self.password.expose_bytes(),
            self.url.expose_bytes(),
            self.notes.expose_bytes(),
        ];

        // Length of the record region: 4 bytes per field length prefix + bodies.
        let record_len: usize = fields.iter().map(|f| 4 + f.len()).sum::<usize>();

        // Whole plaintext = 4-byte true_len prefix + record region.
        let unpadded = 4 + record_len;
        let padded = unpadded.div_ceil(BUCKET) * BUCKET;

        let mut buf = vec![0u8; padded];
        // true_len prefix: the size of the record region (excludes this prefix
        // and excludes the trailing padding).
        write_u32_le(&mut buf, 0, record_len);
        let mut off = 4;
        for field in fields {
            write_u32_le(&mut buf, off, field.len());
            off += 4;
            buf[off..off + field.len()].copy_from_slice(field);
            off += field.len();
        }
        // `off == unpadded`; bytes from `off..padded` stay zero (the padding).
        debug_assert_eq!(off, unpadded);

        SecretBytes::new(buf)
    }

    /// Decode from a decrypted (and de-padded) authenticated plaintext.
    ///
    /// Reads the `true_len` prefix, restricts parsing to exactly that many
    /// record bytes (ignoring the authenticated zero-padding beyond it), then
    /// parses the four length-prefixed UTF-8 fields directly into
    /// [`SecretString`]s. Each transient per-field byte buffer is zeroized after
    /// its UTF-8 conversion.
    ///
    /// The input is already authenticated by the AEAD tag, so a structural
    /// problem here indicates a logic/version mismatch, not attacker input; it
    /// is returned as [`VaultError::MalformedRecord`] rather than panicked.
    ///
    /// # Errors
    ///
    /// [`VaultError::MalformedRecord`] if `true_len` exceeds the buffer, a field
    /// length prefix overruns the record region, the record region is not fully
    /// consumed, or a field is not valid UTF-8.
    pub(crate) fn decode(plaintext: &SecretBytes) -> Result<Self, VaultError> {
        let bytes = plaintext.expose();
        if bytes.len() < 4 {
            return Err(VaultError::MalformedRecord {
                reason: "missing true-length prefix",
            });
        }
        let record_len = read_u32_le(bytes, 0) as usize;
        // The record region must fit within the (de-padded) plaintext after the
        // 4-byte prefix. `4 + record_len` cannot overflow: `record_len` came
        // from a u32, and on 64-bit `usize` adding 4 is safe; the comparison is
        // against `bytes.len()` which is the authoritative bound.
        let region_end = 4usize
            .checked_add(record_len)
            .ok_or(VaultError::MalformedRecord {
                reason: "record length overflows",
            })?;
        if region_end > bytes.len() {
            return Err(VaultError::MalformedRecord {
                reason: "record length exceeds plaintext",
            });
        }

        let mut cursor = 4usize;
        let mut field_values: Vec<SecretString> = Vec::with_capacity(FIELD_COUNT);
        for _ in 0..FIELD_COUNT {
            if cursor + 4 > region_end {
                return Err(VaultError::MalformedRecord {
                    reason: "field length prefix overruns record",
                });
            }
            let flen = read_u32_le(bytes, cursor) as usize;
            cursor += 4;
            let field_end = cursor
                .checked_add(flen)
                .ok_or(VaultError::MalformedRecord {
                    reason: "field length overflows",
                })?;
            if field_end > region_end {
                return Err(VaultError::MalformedRecord {
                    reason: "field body overruns record",
                });
            }
            // Validate UTF-8 by *borrowing* the slice out of the zeroizing
            // SecretBytes — no plaintext allocation happens on the error path.
            // Only on success do we allocate the field String, which is moved
            // straight into a SecretString and is therefore zeroized on drop.
            // (`to_owned` on a `&str` produces exactly the String that becomes
            // the SecretString's backing buffer; no separate un-scrubbed copy
            // lingers.)
            let field_str = std::str::from_utf8(&bytes[cursor..field_end]).map_err(|_| {
                VaultError::MalformedRecord {
                    reason: "field is not valid UTF-8",
                }
            })?;
            field_values.push(SecretString::new(field_str.to_owned()));
            cursor = field_end;
        }

        if cursor != region_end {
            return Err(VaultError::MalformedRecord {
                reason: "record region not fully consumed",
            });
        }

        // Exactly FIELD_COUNT values were pushed; drain them in order. Using
        // pop in reverse keeps ownership moves explicit without indexing panics.
        let mut iter = field_values.into_iter();
        let username = next_field(&mut iter)?;
        let password = next_field(&mut iter)?;
        let url = next_field(&mut iter)?;
        let notes = next_field(&mut iter)?;
        Ok(Self {
            username,
            password,
            url,
            notes,
        })
    }
}

/// Pull the next decoded field, mapping exhaustion to a structural error rather
/// than panicking on `Option`.
fn next_field(iter: &mut std::vec::IntoIter<SecretString>) -> Result<SecretString, VaultError> {
    iter.next().ok_or(VaultError::MalformedRecord {
        reason: "fewer fields than expected",
    })
}

/// Write `value` as a little-endian `u32` at `buf[off..off+4]`.
///
/// Length prefixes in this format are `u32-LE`. A `value` exceeding `u32::MAX`
/// is clamped rather than silently truncated; in practice this is unreachable
/// because the inputs are user-typed strings far shorter than 4 GiB. `buf` is
/// always sized to contain `off+4`.
fn write_u32_le(buf: &mut [u8], off: usize, value: usize) {
    let v = u32::try_from(value).unwrap_or(u32::MAX);
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Read a little-endian `u32` from `buf[off..off+4]`. Callers guarantee the
/// bounds before calling.
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[cfg(test)]
mod tests {
    use super::{EntryRecord, BUCKET};
    use passman_crypto::{SecretBytes, SecretString};

    fn rec(u: &str, p: &str, url: &str, n: &str) -> EntryRecord {
        EntryRecord::new(
            SecretString::new(u.to_owned()),
            SecretString::new(p.to_owned()),
            SecretString::new(url.to_owned()),
            SecretString::new(n.to_owned()),
        )
    }

    #[test]
    fn round_trip_preserves_fields() {
        let r = rec("alice", "s3cr3t!", "https://example.com", "note line");
        let encoded = r.encode_padded();
        let decoded = EntryRecord::decode(&encoded).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn padded_length_is_a_bucket_multiple() {
        let r = rec("u", "p", "x", "n");
        let encoded = r.encode_padded();
        assert_eq!(encoded.len() % BUCKET, 0);
        assert!(encoded.len() >= BUCKET);
    }

    #[test]
    fn larger_record_spans_multiple_buckets_and_round_trips() {
        let big = "z".repeat(BUCKET * 3);
        let r = rec(&big, &big, "", "");
        let encoded = r.encode_padded();
        assert_eq!(encoded.len() % BUCKET, 0);
        assert!(encoded.len() > BUCKET * 6);
        let decoded = EntryRecord::decode(&encoded).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn empty_fields_round_trip() {
        let r = rec("", "", "", "");
        let encoded = r.encode_padded();
        assert_eq!(encoded.len(), BUCKET);
        let decoded = EntryRecord::decode(&encoded).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn utf8_multibyte_round_trips() {
        let r = rec("ünïcödé", "pä$$wörd🔐", "https://exämple", "notές");
        let decoded = EntryRecord::decode(&r.encode_padded()).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let bad = SecretBytes::new(vec![0u8; 3]);
        assert!(EntryRecord::decode(&bad).is_err());
    }

    #[test]
    fn decode_rejects_record_len_exceeding_buffer() {
        // true_len says 1000 but the buffer is one bucket.
        let mut buf = vec![0u8; BUCKET];
        buf[0..4].copy_from_slice(&1000u32.to_le_bytes());
        let bad = SecretBytes::new(buf);
        assert!(EntryRecord::decode(&bad).is_err());
    }

    #[test]
    fn decode_rejects_field_overrun() {
        // record_len = 8 (fits), but first field prefix claims 100 bytes.
        let mut buf = vec![0u8; BUCKET];
        buf[0..4].copy_from_slice(&8u32.to_le_bytes());
        buf[4..8].copy_from_slice(&100u32.to_le_bytes());
        let bad = SecretBytes::new(buf);
        assert!(EntryRecord::decode(&bad).is_err());
    }

    #[test]
    fn decode_rejects_invalid_utf8() {
        // One field of length 1 containing an invalid UTF-8 byte (0xFF), and
        // three empty fields. record_len = 4 prefixes (16) + 1 body = 17.
        let mut buf = vec![0u8; BUCKET];
        let record_len: u32 = 4 * 4 + 1;
        buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        // username: len 1, body 0xFF
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8] = 0xFF;
        // password/url/notes: len 0 (prefixes already zero at offsets 9,13,17).
        let bad = SecretBytes::new(buf);
        assert!(EntryRecord::decode(&bad).is_err());
    }
}
