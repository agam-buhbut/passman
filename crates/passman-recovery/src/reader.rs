//! A panic-free, bounds-checked cursor over an input byte slice.
//!
//! Both the recovery *file* parser (attacker-controlled bytes) and the
//! *payload* parser (authenticated, but still parsed defensively) read through
//! this cursor, so every read is validated against the remaining buffer
//! *before* it happens. [`Reader`] is the single place those checks live: each
//! accessor either returns the requested bytes or a [`RecoveryError`] naming the
//! field — it can never index out of bounds and never panics.
//!
//! Two guarantees matter for fuzz-robustness:
//!
//! - Length prefixes are read as fixed-width integers and then *checked*
//!   against [`Reader::remaining`] before any slice or allocation, so a hostile
//!   length cannot drive an out-of-bounds read or a giant allocation
//!   ([`Reader::take`]).
//! - Offset arithmetic is performed on `usize` positions that only ever
//!   increase by an amount already confirmed to be `<= len`, so the cursor
//!   cannot integer-overflow.

use passman_crypto::SecretString;

use crate::error::RecoveryError;

/// A forward-only cursor over a borrowed byte slice with checked reads.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice at offset 0.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of unread bytes remaining.
    ///
    /// `self.pos` is only ever advanced by amounts already verified to be
    /// `<= buf.len()`, so `pos <= buf.len()` is an invariant and this
    /// subtraction never underflows.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Return `Err` if any unread bytes remain.
    ///
    /// Used after parsing the declared structure to reject trailing garbage,
    /// which the recovery format treats as a hard error (fail closed).
    ///
    /// # Errors
    ///
    /// [`RecoveryError::TrailingBytes`] when bytes remain after the expected
    /// end.
    pub(crate) fn expect_eof(&self) -> Result<(), RecoveryError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(RecoveryError::TrailingBytes {
                extra: self.remaining(),
            })
        }
    }

    /// Take exactly `n` bytes, advancing the cursor.
    ///
    /// The length is checked against [`Reader::remaining`] first, so an
    /// over-long `n` (e.g. an attacker-supplied length prefix) returns an error
    /// rather than panicking or reading past the end.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Truncated`] (tagged `field`) if fewer than `n` bytes
    /// remain.
    pub(crate) fn take(
        &mut self,
        n: usize,
        field: &'static str,
    ) -> Result<&'a [u8], RecoveryError> {
        if n > self.remaining() {
            return Err(RecoveryError::Truncated {
                field,
                offset: self.pos,
            });
        }
        // `self.pos + n` cannot overflow: `n <= remaining = buf.len() - pos`, so
        // `pos + n <= buf.len() <= usize::MAX`.
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..self.pos])
    }

    /// Take exactly `N` bytes into an owned fixed-size array.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Truncated`] (tagged `field`) if fewer than `N` bytes
    /// remain.
    pub(crate) fn take_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], RecoveryError> {
        let slice = self.take(N, field)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Read a single byte.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Truncated`] (tagged `field`) if no bytes remain.
    pub(crate) fn read_u8(&mut self, field: &'static str) -> Result<u8, RecoveryError> {
        Ok(self.take(1, field)?[0])
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Truncated`] (tagged `field`) if fewer than 4 bytes
    /// remain.
    pub(crate) fn read_u32_le(&mut self, field: &'static str) -> Result<u32, RecoveryError> {
        Ok(u32::from_le_bytes(self.take_array::<4>(field)?))
    }

    /// Read a `u32-LE` length prefix, then take that many bytes as an owned
    /// `Vec` (used for opaque fields such as the per-entry policy bytes).
    ///
    /// The length is validated by [`Reader::take`] before allocation. A 32-bit
    /// length cannot exceed `usize` on the 64-bit targets this project
    /// supports, and on any narrower target an over-`usize` length simply fails
    /// the `take` bounds check rather than allocating.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Truncated`] (tagged `field`) if the length prefix or the
    /// body is truncated.
    pub(crate) fn read_u32_prefixed_vec(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<u8>, RecoveryError> {
        let len = self.read_u32_le(field)? as usize;
        Ok(self.take(len, field)?.to_vec())
    }

    /// Read a `u32-LE` length prefix, then take that many bytes and parse them
    /// as a UTF-8 [`SecretString`].
    ///
    /// The body bytes are borrowed out of the underlying buffer and validated
    /// as UTF-8 *before* any owned allocation; only on success is the field
    /// `String` allocated, and it is moved straight into a [`SecretString`] (so
    /// it zeroizes on drop). On the malformed-UTF-8 path nothing is allocated.
    ///
    /// This is for secret text fields (`username`/`password`/`url`/`notes`):
    /// the decrypted payload is parsed *directly* into zeroizing
    /// [`SecretString`]s, never through a plain owned `String` that lingers.
    ///
    /// # Errors
    ///
    /// - [`RecoveryError::Truncated`] (tagged `field`) if the length prefix or
    ///   the body is truncated.
    /// - [`RecoveryError::MalformedPayload`] if the body is not valid UTF-8.
    pub(crate) fn read_u32_prefixed_secret_string(
        &mut self,
        field: &'static str,
    ) -> Result<SecretString, RecoveryError> {
        let len = self.read_u32_le(field)? as usize;
        let body = self.take(len, field)?;
        let text = core::str::from_utf8(body).map_err(|_| RecoveryError::MalformedPayload {
            reason: "text field is not valid UTF-8",
        })?;
        Ok(SecretString::new(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::error::RecoveryError;

    #[test]
    fn reads_fixed_width_in_order() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8("a").expect("u8"), 0x01);
        // bytes [0x02, 0x03, 0x04, 0x05] little-endian.
        assert_eq!(r.read_u32_le("b").expect("u32"), 0x0504_0302);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn take_rejects_overlong_request() {
        let bytes = [0u8; 4];
        let mut r = Reader::new(&bytes);
        let err = r.take(5, "field").expect_err("overlong take must fail");
        assert!(matches!(
            err,
            RecoveryError::Truncated {
                field: "field",
                offset: 0
            }
        ));
        // The cursor did not advance on failure.
        assert_eq!(r.remaining(), 4);
    }

    #[test]
    fn length_prefix_larger_than_buffer_errors_without_panic() {
        // u32 prefix = 0xFFFF_FFFF but only 4 bytes follow.
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut r = Reader::new(&bytes);
        let err = r
            .read_u32_prefixed_vec("blob")
            .expect_err("hostile length must fail");
        assert!(matches!(
            err,
            RecoveryError::Truncated { field: "blob", .. }
        ));
    }

    #[test]
    fn prefixed_secret_string_reads_exact_body() {
        // len = 3, body "abc", then a trailing byte.
        let bytes = [0x03u8, 0x00, 0x00, 0x00, b'a', b'b', b'c', 0x99];
        let mut r = Reader::new(&bytes);
        let s = r
            .read_u32_prefixed_secret_string("field")
            .expect("secret string");
        assert_eq!(s.expose(), "abc");
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn prefixed_secret_string_rejects_invalid_utf8() {
        // len = 1, body 0xFF (invalid UTF-8).
        let bytes = [0x01u8, 0x00, 0x00, 0x00, 0xFF];
        let mut r = Reader::new(&bytes);
        let err = r
            .read_u32_prefixed_secret_string("field")
            .expect_err("invalid utf8 must fail");
        assert!(matches!(err, RecoveryError::MalformedPayload { .. }));
    }

    #[test]
    fn expect_eof_detects_trailing_bytes() {
        let bytes = [0x01u8, 0x02];
        let mut r = Reader::new(&bytes);
        r.read_u8("x").expect("first byte");
        let err = r.expect_eof().expect_err("trailing byte must fail");
        assert!(matches!(err, RecoveryError::TrailingBytes { extra: 1 }));
    }

    #[test]
    fn empty_reader_take_zero_ok() {
        let bytes: [u8; 0] = [];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.take(0, "none").expect("zero take"), &[] as &[u8]);
        r.expect_eof().expect("empty reader is at eof");
    }
}
