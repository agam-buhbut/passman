//! Known-answer and behavioural tests for `passman-crypto`.
//!
//! All vectors are pinned to published standards:
//!
//! - HKDF-SHA256: RFC 5869, Appendix A, Test Case 1 and Test Case 2.
//! - XChaCha20-Poly1305: `draft-arciszewski-xchacha-03`, Appendix A.1
//!   (the test vector common to RFC 8439 / the `XChaCha` draft).
//! - Argon2id: a fixed (password, salt, low-cost-params) triple whose 32-byte
//!   output was computed once with this crate's own `argon2id` and is asserted
//!   as a stable vector (cross-checked reproducible across runs).
//!
//! Tests are deterministic: no sleeps, no network, no filesystem.

use hex_literal::hex;

use passman_crypto::aead::{decrypt, encrypt, NONCE_LEN, TAG_LEN};
use passman_crypto::{
    argon2id, ct_eq, hkdf_expand, hkdf_master, random_nonce, random_secret, KdfParams, SecretArray,
    SecretString,
};

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869 Appendix A
// ---------------------------------------------------------------------------

// RFC 5869 Test Case 1 (basic, SHA-256).
const RFC5869_TC1_IKM: [u8; 22] = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
const RFC5869_TC1_SALT: [u8; 13] = hex!("000102030405060708090a0b0c");
const RFC5869_TC1_INFO: [u8; 10] = hex!("f0f1f2f3f4f5f6f7f8f9");
const RFC5869_TC1_PRK: [u8; 32] =
    hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
// First 32 bytes of the 42-byte OKM. HKDF-Expand output is prefix-stable, so a
// 32-byte expand equals the leading 32 bytes of the RFC's 42-byte OKM.
const RFC5869_TC1_OKM32: [u8; 32] =
    hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");

// RFC 5869 Test Case 2 (longer inputs, SHA-256).
const RFC5869_TC2_IKM: [u8; 80] = hex!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
);
const RFC5869_TC2_SALT: [u8; 80] = hex!(
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
);
const RFC5869_TC2_INFO: [u8; 80] = hex!(
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
);
// First 32 bytes of the 82-byte OKM.
const RFC5869_TC2_OKM32: [u8; 32] =
    hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c");

#[test]
fn hkdf_master_matches_rfc5869_tc1() {
    let okm = hkdf_master(&RFC5869_TC1_SALT, &RFC5869_TC1_IKM, &RFC5869_TC1_INFO);
    assert_eq!(okm.expose(), &RFC5869_TC1_OKM32);
}

#[test]
fn hkdf_master_matches_rfc5869_tc2() {
    let okm = hkdf_master(&RFC5869_TC2_SALT, &RFC5869_TC2_IKM, &RFC5869_TC2_INFO);
    assert_eq!(okm.expose(), &RFC5869_TC2_OKM32);
}

#[test]
fn hkdf_expand_matches_rfc5869_tc1_prk() {
    // Expand-only path keyed by the RFC's published PRK must reproduce the same
    // OKM prefix as the full Extract-then-Expand.
    let prk = SecretArray::new(RFC5869_TC1_PRK);
    let okm = hkdf_expand(&prk, &RFC5869_TC1_INFO);
    assert_eq!(okm.expose(), &RFC5869_TC1_OKM32);
}

#[test]
fn hkdf_distinct_info_yields_distinct_keys() {
    let prk = SecretArray::new(RFC5869_TC1_PRK);
    let a = hkdf_expand(&prk, b"index-v0");
    let b = hkdf_expand(&prk, b"entry-v0:abc");
    assert_ne!(a.expose(), b.expose());
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 — draft-arciszewski-xchacha-03 Appendix A.1
// ---------------------------------------------------------------------------

const XCHACHA_KEY: [u8; 32] =
    hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const XCHACHA_NONCE: [u8; 24] = hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
const XCHACHA_AAD: [u8; 12] = hex!("505152 53c0c1c2c3c4c5c6c7");
const XCHACHA_PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
    If I could offer you only one tip for the future, sunscreen would be it.";
// 114-byte ciphertext.
const XCHACHA_CIPHERTEXT: [u8; 114] = hex!(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
    "21f9664c97637da9768812f615c68b13b52e"
);
// 16-byte Poly1305 tag.
const XCHACHA_TAG: [u8; 16] = hex!("c0875924c1c7987947deafd8780acf49");

fn xchacha_expected_combined() -> Vec<u8> {
    let mut combined = XCHACHA_CIPHERTEXT.to_vec();
    combined.extend_from_slice(&XCHACHA_TAG);
    combined
}

#[test]
fn xchacha_encrypt_matches_draft_vector() {
    let key = SecretArray::new(XCHACHA_KEY);
    let out = encrypt(&key, &XCHACHA_NONCE, &XCHACHA_AAD, XCHACHA_PLAINTEXT)
        .expect("encryption must succeed");
    assert_eq!(out, xchacha_expected_combined());
    assert_eq!(out.len(), XCHACHA_PLAINTEXT.len() + TAG_LEN);
}

#[test]
fn xchacha_decrypt_recovers_draft_plaintext() {
    let key = SecretArray::new(XCHACHA_KEY);
    let combined = xchacha_expected_combined();
    let pt = decrypt(&key, &XCHACHA_NONCE, &XCHACHA_AAD, &combined).expect("must authenticate");
    assert_eq!(pt.expose(), XCHACHA_PLAINTEXT);
}

// ---------------------------------------------------------------------------
// Argon2id — stable self-computed vector with low params
// ---------------------------------------------------------------------------

const ARGON2ID_SALT: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
const ARGON2ID_PASSWORD: &str = "correct horse battery staple";
// Computed once via this crate's `argon2id` (m=16 KiB, t=1, p=1) and confirmed
// reproducible across runs. LOW test params keep the suite fast; the Medium/
// High presets are never run in tests.
const ARGON2ID_EXPECTED: [u8; 32] =
    hex!("ebc5590dcbd79fbf66b952eb00c1ec5d0660302d7395bf72064fe7a4fe07d7bf");

fn fast_test_params() -> KdfParams {
    KdfParams {
        m_kib: 16,
        t: 1,
        p: 1,
    }
}

#[test]
fn argon2id_matches_stable_vector() {
    let pw = SecretString::new(ARGON2ID_PASSWORD.to_owned());
    let key = argon2id(&pw, &ARGON2ID_SALT, &fast_test_params()).expect("derivation succeeds");
    assert_eq!(key.expose(), &ARGON2ID_EXPECTED);
}

#[test]
fn argon2id_is_deterministic() {
    let pw = SecretString::new(ARGON2ID_PASSWORD.to_owned());
    let a = argon2id(&pw, &ARGON2ID_SALT, &fast_test_params()).expect("a");
    let b = argon2id(&pw, &ARGON2ID_SALT, &fast_test_params()).expect("b");
    assert_eq!(a.expose(), b.expose());
}

#[test]
fn argon2id_different_salt_changes_output() {
    let pw = SecretString::new(ARGON2ID_PASSWORD.to_owned());
    let mut salt2 = ARGON2ID_SALT;
    salt2[0] ^= 0x01;
    let a = argon2id(&pw, &ARGON2ID_SALT, &fast_test_params()).expect("a");
    let b = argon2id(&pw, &salt2, &fast_test_params()).expect("b");
    assert_ne!(a.expose(), b.expose());
}

#[test]
fn argon2id_rejects_structurally_invalid_params() {
    // m_cost below the algorithm minimum (8 for p=1) must error, not panic.
    let pw = SecretString::new(ARGON2ID_PASSWORD.to_owned());
    let bad = KdfParams {
        m_kib: 1,
        t: 1,
        p: 1,
    };
    assert!(argon2id(&pw, &ARGON2ID_SALT, &bad).is_err());
}

// ---------------------------------------------------------------------------
// AEAD round-trip and tamper detection
// ---------------------------------------------------------------------------

fn rt_key() -> SecretArray<32> {
    SecretArray::new(hex!(
        "0101010101010101010101010101010101010101010101010101010101010101"
    ))
}

#[test]
fn aead_round_trip_with_aad() {
    let key = rt_key();
    let nonce = random_nonce();
    let aad = b"\x01some-associated-data";
    let plaintext = b"a master password or decrypted entry";

    let ct = encrypt(&key, &nonce, aad, plaintext).expect("encrypt");
    let pt = decrypt(&key, &nonce, aad, &ct).expect("decrypt");
    assert_eq!(pt.expose(), plaintext);
}

#[test]
fn aead_round_trip_empty_plaintext() {
    let key = rt_key();
    let nonce = random_nonce();
    let ct = encrypt(&key, &nonce, b"aad", b"").expect("encrypt");
    assert_eq!(ct.len(), TAG_LEN); // tag only
    let pt = decrypt(&key, &nonce, b"aad", &ct).expect("decrypt");
    assert!(pt.is_empty());
}

#[test]
fn aead_tamper_ciphertext_byte_fails() {
    let key = rt_key();
    let nonce = random_nonce();
    let aad = b"aad";
    let mut ct = encrypt(&key, &nonce, aad, b"plaintext payload").expect("encrypt");
    // Flip a byte inside the ciphertext region (before the tag).
    ct[0] ^= 0x01;
    let err = decrypt(&key, &nonce, aad, &ct).expect_err("must fail auth");
    assert!(matches!(err, passman_crypto::CryptoError::AeadAuth));
}

#[test]
fn aead_tamper_tag_byte_fails() {
    let key = rt_key();
    let nonce = random_nonce();
    let aad = b"aad";
    let mut ct = encrypt(&key, &nonce, aad, b"plaintext payload").expect("encrypt");
    let last = ct.len() - 1; // inside the 16-byte tag
    ct[last] ^= 0x01;
    let err = decrypt(&key, &nonce, aad, &ct).expect_err("must fail auth");
    assert!(matches!(err, passman_crypto::CryptoError::AeadAuth));
}

#[test]
fn aead_tamper_aad_byte_fails() {
    let key = rt_key();
    let nonce = random_nonce();
    let ct = encrypt(&key, &nonce, b"\x01aad", b"plaintext payload").expect("encrypt");
    // Decrypt with a different AAD: authentication must fail.
    let err = decrypt(&key, &nonce, b"\x02aad", &ct).expect_err("must fail auth");
    assert!(matches!(err, passman_crypto::CryptoError::AeadAuth));
}

#[test]
fn aead_wrong_key_fails() {
    let key = rt_key();
    let nonce = random_nonce();
    let ct = encrypt(&key, &nonce, b"aad", b"plaintext payload").expect("encrypt");
    let other = random_secret::<32>();
    let err = decrypt(&other, &nonce, b"aad", &ct).expect_err("must fail auth");
    assert!(matches!(err, passman_crypto::CryptoError::AeadAuth));
}

#[test]
fn aead_decrypt_short_input_is_invalid_length() {
    let key = rt_key();
    let nonce = random_nonce();
    let short = [0u8; TAG_LEN - 1];
    let err = decrypt(&key, &nonce, b"aad", &short).expect_err("too short");
    assert!(matches!(
        err,
        passman_crypto::CryptoError::InvalidLength { what: "ciphertext_and_tag", expected, got }
            if expected == TAG_LEN && got == TAG_LEN - 1
    ));
}

// ---------------------------------------------------------------------------
// Constant-time equality
// ---------------------------------------------------------------------------

#[test]
fn ct_eq_equal_slices_true() {
    assert!(ct_eq(b"abcdef", b"abcdef"));
    assert!(ct_eq(b"", b""));
}

#[test]
fn ct_eq_differing_slices_false() {
    assert!(!ct_eq(b"abcdef", b"abcdeg"));
}

#[test]
fn ct_eq_different_lengths_false() {
    assert!(!ct_eq(b"abc", b"abcd"));
    assert!(!ct_eq(b"abcd", b"abc"));
}

// ---------------------------------------------------------------------------
// KdfParams canonical encoding
// ---------------------------------------------------------------------------

#[test]
fn kdf_params_exact_le_layout() {
    // m=1, t=2, p=3 -> [01 00 00 00 | 02 00 00 00 | 03]
    let params = KdfParams {
        m_kib: 1,
        t: 2,
        p: 3,
    };
    assert_eq!(params.to_bytes(), hex!("01000000 02000000 03"));
}

#[test]
fn kdf_params_round_trip() {
    for params in [
        KdfParams::LOW,
        KdfParams::MEDIUM,
        KdfParams::HIGH,
        KdfParams {
            m_kib: 0xDEAD_BEEF,
            t: 0x0102_0304,
            p: 0xFF,
        },
    ] {
        assert_eq!(KdfParams::from_bytes(params.to_bytes()), params);
    }
}

#[test]
fn kdf_presets_match_architecture() {
    assert_eq!(
        KdfParams::LOW,
        KdfParams {
            m_kib: 262_144,
            t: 4,
            p: 1
        }
    );
    assert_eq!(
        KdfParams::MEDIUM,
        KdfParams {
            m_kib: 1_048_576,
            t: 4,
            p: 1
        }
    );
    assert_eq!(
        KdfParams::HIGH,
        KdfParams {
            m_kib: 4_194_304,
            t: 6,
            p: 1
        }
    );
}

// ---------------------------------------------------------------------------
// RNG sanity (non-statistical: just that fresh values differ and have shape)
// ---------------------------------------------------------------------------

#[test]
fn random_nonce_has_correct_len_and_varies() {
    let a = random_nonce();
    let b = random_nonce();
    assert_eq!(a.len(), NONCE_LEN);
    // Astronomically improbable to collide; flags a dead RNG.
    assert_ne!(a, b);
}

#[test]
fn random_secret_varies() {
    let a = random_secret::<32>();
    let b = random_secret::<32>();
    assert_ne!(a.expose(), b.expose());
}
