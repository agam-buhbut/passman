//! HOTP core (RFC 4226).
//!
//! Computes the HMAC-based one-time-password value for a seed and an 8-byte
//! big-endian counter, applies the RFC 4226 §5.3 dynamic truncation, and
//! reduces modulo `10^digits`. The TOTP layer ([`crate::verifier`]) drives this
//! with the time step as the counter.

use hmac::digest::block_buffer::Eager;
use hmac::digest::consts::U256;
use hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
};
use hmac::digest::typenum::{IsLess, Le, NonZero};
use hmac::digest::{HashMarker, OutputSizeUser};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Maximum decimal width an HOTP value may be reduced to.
///
/// RFC 4226 §5.3 truncates to a 31-bit integer (`0..=2_147_483_647`), 10
/// decimal digits. Configurable widths are additionally capped at 8 (see
/// [`crate::config`]); this bounds the [`POW10`] table.
const MAX_DIGITS: usize = 10;

/// Powers of ten for reducing the truncated value: index `d` holds `10^d`.
/// Indexed only by `digits` (`1..=8`), so the overflowing `10^10` slot is never
/// read and is left as a placeholder.
const POW10: [u32; MAX_DIGITS + 1] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    0, // 10^10 overflows u32; never indexed (digits <= 8).
];

/// The hash function backing an HOTP/TOTP computation.
///
/// RFC 6238 defines TOTP over HMAC-SHA1 (the algorithm RFC 4226 and most
/// authenticator apps use) and permits SHA-256 and SHA-512. SHA-1 is the
/// default. SHA-1 appears here only because the standard mandates it for TOTP;
/// it is not used anywhere else in passman.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (RFC 4226 / RFC 6238 default).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// Compute the HOTP value for `seed` and `counter`, reduced to `digits` decimal
/// places.
///
/// `digits` must be in `1..=8`; the config layer guarantees this and this
/// function is crate-private, so it is debug-asserted rather than returning a
/// `Result`.
pub(crate) fn hotp_value(algorithm: TotpAlgorithm, seed: &[u8], counter: u64, digits: u8) -> u32 {
    debug_assert!(
        (1..=8).contains(&digits),
        "digits must be 1..=8 (enforced by TotpConfig)"
    );
    let msg: [u8; 8] = counter.to_be_bytes();
    let truncated: u32 = match algorithm {
        TotpAlgorithm::Sha1 => truncate(&keyed_hmac::<Sha1>(seed, msg)),
        TotpAlgorithm::Sha256 => truncate(&keyed_hmac::<Sha256>(seed, msg)),
        TotpAlgorithm::Sha512 => truncate(&keyed_hmac::<Sha512>(seed, msg)),
    };
    truncated % POW10[digits as usize]
}

/// Write the zero-padded ASCII form of an HOTP value into `out`.
///
/// `out` must be exactly `digits` bytes; it is filled with the decimal
/// representation of `value`, left-padded with `'0'`. Producing a fixed-width
/// byte buffer (rather than a number) lets the verifier compare candidate and
/// expected codes in constant time over the whole code space.
pub(crate) fn format_padded(value: u32, digits: u8, out: &mut [u8]) {
    debug_assert_eq!(out.len(), digits as usize);
    let mut remaining: u32 = value;
    // Fill from the least-significant digit backwards.
    for slot in out.iter_mut().rev() {
        *slot = b'0' + u8::try_from(remaining % 10).unwrap_or(0);
        remaining /= 10;
    }
}

/// RFC 4226 §5.3 dynamic truncation of an HMAC tag to a 31-bit integer.
///
/// The tag must be at least 20 bytes (true for SHA-1/256/512), so the
/// offset-selected 4-byte window is always in range.
fn truncate(tag: &[u8]) -> u32 {
    debug_assert!(tag.len() >= 20, "HMAC output too short to truncate");
    let offset: usize = (tag[tag.len() - 1] & 0x0f) as usize;
    let bytes: [u8; 4] = [
        tag[offset] & 0x7f, // mask the high bit to keep the result 31-bit
        tag[offset + 1],
        tag[offset + 2],
        tag[offset + 3],
    ];
    u32::from_be_bytes(bytes)
}

/// HMAC the 8-byte counter under `seed` with digest `D`, returning the tag.
///
/// Generic over the `RustCrypto` digest so SHA-1/256/512 share one body; the
/// bounds are the standard ones [`Hmac`] requires of a block-level digest.
fn keyed_hmac<D>(seed: &[u8], msg: [u8; 8]) -> Vec<u8>
where
    D: CoreProxy + OutputSizeUser,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + BlockSizeUser
        + Clone
        + Default,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    // HMAC accepts a key of any length (shorter keys are zero-padded, longer
    // keys are pre-hashed), so `new_from_slice` is infallible for HMAC —
    // RustCrypto's own docs use `.expect("HMAC can take key of any size")`.
    // This is the crate's single justified `unwrap_used` allow.
    #[allow(clippy::unwrap_used)] // unreachable: HMAC keys are length-agnostic.
    let mut mac: Hmac<D> =
        Hmac::<D>::new_from_slice(seed).expect("HMAC accepts keys of any length");
    mac.update(&msg);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{format_padded, hotp_value, TotpAlgorithm};

    /// RFC 4226 Appendix D: HMAC-SHA1, seed b"12345678901234567890", 6 digits,
    /// counters 0..=9.
    const RFC4226_SHA1: [u32; 10] = [
        755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871, 520_489,
    ];

    #[test]
    fn rfc4226_appendix_d_vectors() {
        let seed: &[u8] = b"12345678901234567890";
        for (counter, &expected) in RFC4226_SHA1.iter().enumerate() {
            let value: u32 = hotp_value(TotpAlgorithm::Sha1, seed, counter as u64, 6);
            assert_eq!(value, expected, "counter {counter}");
        }
    }

    #[test]
    fn format_padded_left_pads_with_zeros() {
        let mut buf: [u8; 6] = [0; 6];
        format_padded(755_224, 6, &mut buf);
        assert_eq!(&buf, b"755224");

        format_padded(1, 6, &mut buf);
        assert_eq!(&buf, b"000001");

        format_padded(0, 6, &mut buf);
        assert_eq!(&buf, b"000000");
    }

    #[test]
    fn format_padded_eight_digits() {
        let mut buf: [u8; 8] = [0; 8];
        format_padded(94_287_082, 8, &mut buf);
        assert_eq!(&buf, b"94287082");
    }

    #[test]
    fn default_algorithm_is_sha1() {
        assert_eq!(TotpAlgorithm::default(), TotpAlgorithm::Sha1);
    }
}
