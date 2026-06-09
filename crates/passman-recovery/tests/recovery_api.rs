//! Integration tests over the *public* `passman-recovery` API.
//!
//! These exercise only re-exported items (`export`, `import`, the DTOs, the
//! presets, and `RecoveryError`). The full crypto round-trip through the public
//! `export` is gated `#[ignore]` because `export` enforces the 1 GiB recovery
//! Floor (`architecture.md` §7.4), which is far too slow/heavy for the default
//! run — the fast, exhaustive round-trip and tamper coverage lives in the
//! crate's inline `#[cfg(test)]` modules, which can use the `pub(crate)`
//! cheap-Argon2 seam. Here we cover everything reachable *without* running the
//! expensive KDF: the Floor gate and the panic-free parser front-end.

use passman_recovery::{
    export, import, ExportPayload, RecoveryEntry, RecoveryError, RecoveryPreset,
    KDF_ALGORITHM_ARGON2ID, MAGIC, RECOVERY_AD, SALT_LEN, TOTP_SEED_LEN,
};

use passman_crypto::{KdfParams, SecretArray, SecretString};

fn pw() -> SecretString {
    SecretString::new("a strong enough passphrase here".to_owned())
}

fn small_payload() -> ExportPayload {
    ExportPayload {
        totp_seed: SecretArray::new([0x11u8; TOTP_SEED_LEN]),
        original_vault_kdf: KdfParams {
            m_kib: 262_144,
            t: 4,
            p: 1,
        },
        entries: vec![RecoveryEntry {
            id: [0x42u8; 16],
            label: "example".to_owned(),
            username: SecretString::new("alice".to_owned()),
            password: SecretString::new("s3cr3t".to_owned()),
            url: SecretString::new("https://example.test".to_owned()),
            notes: SecretString::new(String::new()),
            policy: vec![0xDE, 0xAD],
        }],
    }
}

#[test]
fn export_refuses_below_floor() {
    // Sub-floor params (the vault Medium-ish cost) must be rejected by the
    // public `export` *before* any expensive derivation — so this is fast.
    let weak = KdfParams {
        m_kib: 262_144,
        t: 4,
        p: 1,
    };
    let err = export(&small_payload(), &pw(), &weak).expect_err("must reject sub-floor");
    match err {
        RecoveryError::WeakParams { got_m, floor_m, .. } => {
            assert_eq!(got_m, 262_144);
            assert_eq!(floor_m, RecoveryPreset::Floor.params().m_kib);
        }
        other => panic!("expected WeakParams, got {other:?}"),
    }
}

#[test]
fn import_rejects_bad_magic_without_decrypting() {
    // A file whose magic is wrong fails before any KDF work — fast.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"NOPENO"); // wrong 6-byte magic
    bytes.extend_from_slice(&[0u8; 64]);
    let err = import(&bytes, &pw()).expect_err("bad magic");
    assert!(matches!(err, RecoveryError::BadMagic));
}

#[test]
fn import_rejects_wrong_version_without_decrypting() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.push(0x99); // unsupported version
    bytes.push(KDF_ALGORITHM_ARGON2ID);
    bytes.extend_from_slice(&[0u8; 64]);
    let err = import(&bytes, &pw()).expect_err("bad version");
    assert!(matches!(
        err,
        RecoveryError::UnsupportedVersion { got: 0x99, .. }
    ));
}

#[test]
fn import_rejects_unknown_kdf_id_without_decrypting() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.push(0x01);
    bytes.push(0x07); // unknown kdf id
    bytes.extend_from_slice(&[0u8; 64]);
    let err = import(&bytes, &pw()).expect_err("bad kdf id");
    assert!(matches!(
        err,
        RecoveryError::UnsupportedKdfAlgorithm { got: 0x07 }
    ));
}

#[test]
fn import_arbitrary_bytes_never_panics() {
    // Public-API fuzz-style sweep over adversarial inputs that all fail before
    // (or at the start of) decryption, so no expensive KDF runs. The parser
    // must return an error and never panic / never index OOB.
    let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0u8], vec![0xFFu8; 1024], MAGIC.to_vec()];

    // Valid magic+version+kdf, then a header truncated at every boundary.
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(0x01);
    header.push(KDF_ALGORITHM_ARGON2ID);
    header.extend_from_slice(&8u32.to_le_bytes()); // m
    header.extend_from_slice(&1u32.to_le_bytes()); // t
    header.push(1); // p
    header.extend_from_slice(&[0u8; SALT_LEN]); // salt
    header.extend_from_slice(&[0u8; 24]); // nonce
    header.extend_from_slice(&u32::MAX.to_le_bytes()); // payload_ct_len (huge)
    for cut in 0..=header.len() {
        inputs.push(header[..cut].to_vec());
    }

    for input in &inputs {
        // Must not panic; a Result either way is fine.
        let _ = import(input, &pw());
    }
}

/// Sanity check that the public AD constant is the documented value, so a
/// downstream auditor reading the file format sees the expected tag binding.
#[test]
fn recovery_ad_constant_is_stable() {
    assert_eq!(RECOVERY_AD, b"PSMREC-v0");
    assert_eq!(MAGIC, b"PSMREC");
}

/// Full public-API round-trip through `export` (which enforces the 1 GiB
/// Floor). Ignored by default — run with `--ignored` on a machine with ≥1 GiB
/// free RAM.
#[test]
#[ignore = "public export enforces the 1 GiB Argon2 floor; too slow/heavy for the default run"]
fn public_export_import_round_trip() {
    let payload = small_payload();
    let file = export(&payload, &pw(), &RecoveryPreset::Floor.params()).expect("export");
    let got = import(&file, &pw()).expect("import");
    assert_eq!(got, payload);
}
