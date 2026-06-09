//! RFC 6238 Appendix B test vectors, verified through the public API.
//!
//! The RFC publishes 8-digit TOTP codes at six reference times for each of the
//! three HMAC variants, using the ASCII seeds below (20/32/64 bytes for
//! SHA-1/256/512). These are the correctness anchor for the whole crate: if any
//! differs we have an HOTP/truncation/byte-order bug.
//!
//! Each vector is checked with a *fresh* [`TotpVerifier`] (so the replay cache
//! never interferes) and `skew_steps = 0` (so a code is accepted only at its
//! exact step). We also assert each code is rejected one step away, confirming
//! the verifier is locating the right time step.

use passman_totp::{Timestamp, TotpAlgorithm, TotpConfig, TotpVerifier};

/// RFC 6238 Appendix B seeds: the ASCII string truncated/repeated to the hash's
/// recommended key length.
const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// The six reference instants (Unix seconds) from Appendix B.
const TIMES: [u64; 6] = [
    59,
    1_111_111_109,
    1_111_111_111,
    1_234_567_890,
    2_000_000_000,
    20_000_000_000,
];

/// Published 8-digit codes, indexed parallel to [`TIMES`].
const CODES_SHA1: [&str; 6] = [
    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
];
const CODES_SHA256: [&str; 6] = [
    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
];
const CODES_SHA512: [&str; 6] = [
    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
];

fn check_vectors(algorithm: TotpAlgorithm, seed: &[u8], codes: &[&str; 6]) {
    let config: TotpConfig =
        TotpConfig::new(algorithm, 8, 30, 0).expect("8 digits / 30 s / 0 skew is valid");

    for (&time, &expected) in TIMES.iter().zip(codes.iter()) {
        let now: Timestamp = Timestamp::from_unix_secs(time);

        // Exact-time acceptance.
        let mut verifier: TotpVerifier = TotpVerifier::new(config);
        assert_eq!(
            verifier.verify(seed, expected, now),
            Ok(()),
            "{algorithm:?} vector at T={time} should verify code {expected}",
        );

        // One step earlier and later must be rejected (skew = 0), proving the
        // code is bound to its own step and the codes are step-distinct.
        let mut earlier: TotpVerifier = TotpVerifier::new(config);
        let t_earlier: Timestamp = Timestamp::from_unix_secs(time + 30);
        assert!(
            earlier.verify(seed, expected, t_earlier).is_err(),
            "{algorithm:?} code {expected} must not verify one step later",
        );
        if time >= 30 {
            let mut later: TotpVerifier = TotpVerifier::new(config);
            let t_later: Timestamp = Timestamp::from_unix_secs(time - 30);
            assert!(
                later.verify(seed, expected, t_later).is_err(),
                "{algorithm:?} code {expected} must not verify one step earlier",
            );
        }
    }
}

#[test]
fn rfc6238_sha1_vectors() {
    check_vectors(TotpAlgorithm::Sha1, SEED_SHA1, &CODES_SHA1);
}

#[test]
fn rfc6238_sha256_vectors() {
    check_vectors(TotpAlgorithm::Sha256, SEED_SHA256, &CODES_SHA256);
}

#[test]
fn rfc6238_sha512_vectors() {
    check_vectors(TotpAlgorithm::Sha512, SEED_SHA512, &CODES_SHA512);
}

/// The ±1 default skew accepts the immediately-adjacent steps for an SHA-1
/// vector, exercising the skew window through the public API end-to-end.
#[test]
fn rfc6238_sha1_accepts_adjacent_step_with_default_skew() {
    let config: TotpConfig = TotpConfig::new(TotpAlgorithm::Sha1, 8, 30, 1).expect("valid");
    // T=59 is step 1; present its code while "now" is step 2 (T=89).
    let mut verifier: TotpVerifier = TotpVerifier::new(config);
    let now: Timestamp = Timestamp::from_unix_secs(89);
    assert_eq!(verifier.verify(SEED_SHA1, "94287082", now), Ok(()));
}
