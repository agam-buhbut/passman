//! The recovery file framing (`architecture.md` §7.2) and the public
//! `export` / `import` entry points.
//!
//! # File layout (`architecture.md` §7.2)
//!
//! ```text
//! magic            : 6 bytes (= b"PSMREC")
//! format_version   : u8 (= 0x01)
//! kdf_algorithm_id : u8 (= 0x00, Argon2id)
//! argon2.m         : u32-LE      RECOVERY KDF memory cost (KiB)
//! argon2.t         : u32-LE      RECOVERY KDF time cost
//! argon2.p         : u8          RECOVERY KDF parallelism
//! recovery_salt    : 32 bytes
//! nonce            : 24 bytes
//! payload_ct_len   : u32-LE
//! payload          : payload_ct_len bytes (XChaCha20-Poly1305 ct ‖ tag)
//! ```
//!
//! The header Argon2 params are the *recovery* KDF cost used to derive
//! `K_recovery`. They are distinct from [`ExportPayload::original_vault_kdf`],
//! which lives *inside* the encrypted payload and records the vault's own cost.

use passman_crypto::{aead, fill_random, random_nonce, CryptoError, KdfParams, SecretString};

use crate::error::RecoveryError;
use crate::kdf::{derive_recovery_key, meets_floor, FLOOR_PARAMS};
use crate::payload::{decode_payload, encode_payload, ExportPayload};
use crate::reader::Reader;

/// The recovery file magic (`architecture.md` §7.2). Owned by this crate.
pub const MAGIC: &[u8; 6] = b"PSMREC";

/// The recovery file format version byte (`architecture.md` §7.2).
pub const FORMAT_VERSION: u8 = 0x01;

/// The `kdf_algorithm_id` byte for Argon2id (`architecture.md` §7.2).
pub const KDF_ALGORITHM_ARGON2ID: u8 = 0x00;

/// AEAD associated data for the recovery payload (`architecture.md` §7.2).
/// Binds the format/magic version into the tag so a cross-format or
/// cross-version paste fails authentication. Owned by this crate.
pub const RECOVERY_AD: &[u8] = b"PSMREC-v0";

/// Length of the recovery salt, in bytes.
pub const SALT_LEN: usize = 32;

/// Byte length of the fixed framing that precedes the AEAD ciphertext:
/// `magic(6) ‖ version(1) ‖ kdf_id(1) ‖ m(4) ‖ t(4) ‖ p(1) ‖ salt(32) ‖
/// nonce(24) ‖ payload_ct_len(4)`.
const HEADER_LEN: usize = 6 + 1 + 1 + 4 + 4 + 1 + SALT_LEN + aead::NONCE_LEN + 4;

/// Export a recovery file (`architecture.md` §7.2–§7.5, crypto path).
///
/// Validates that `recovery_params` meet the recovery Floor
/// (`architecture.md` §7.4) — refusing weaker parameters so a single-factor
/// export can never sit behind a cheap KDF — then mints a fresh random salt and
/// nonce, hand-encodes the payload into a zeroizing buffer, derives
/// `K_recovery`, AEAD-seals the payload, and assembles the §7.2 file bytes.
///
/// Returns the complete file as a `Vec<u8>` for the caller to write to disk;
/// this crate performs no I/O.
///
/// Note: the *zxcvbn* Strong-password gate (`architecture.md` §7.5 / §8.4) is
/// owned by `passman-core`, not here — recovery does not depend on
/// `passman-policy`. This function enforces only the Argon2 Floor.
///
/// # Errors
///
/// - [`RecoveryError::WeakParams`] if `recovery_params` are below the Floor.
/// - [`RecoveryError::Crypto`] if Argon2id rejects the parameters or AEAD
///   encryption fails.
pub fn export(
    payload: &ExportPayload,
    password: &SecretString,
    recovery_params: &KdfParams,
) -> Result<Vec<u8>, RecoveryError> {
    if !meets_floor(recovery_params) {
        return Err(RecoveryError::WeakParams {
            got_m: recovery_params.m_kib,
            got_t: recovery_params.t,
            got_p: recovery_params.p,
            floor_m: FLOOR_PARAMS.m_kib,
            floor_t: FLOOR_PARAMS.t,
            floor_p: FLOOR_PARAMS.p,
        });
    }
    export_with(payload, password, recovery_params)
}

/// The export work without the Floor gate.
///
/// Separated so tests can round-trip with deliberately cheap Argon2 parameters
/// (the public [`export`] always enforces the Floor, whose 1 GiB cost is far too
/// slow for unit tests). Production code must call [`export`].
///
/// # Errors
///
/// [`RecoveryError::Crypto`] if Argon2id rejects the parameters or AEAD
/// encryption fails.
pub(crate) fn export_with(
    payload: &ExportPayload,
    password: &SecretString,
    recovery_params: &KdfParams,
) -> Result<Vec<u8>, RecoveryError> {
    // Salt is not secret, but it must come from the CSPRNG; fill a plain array.
    let mut recovery_salt = [0u8; SALT_LEN];
    fill_random(&mut recovery_salt);
    let nonce = random_nonce();

    // Hand-encode into a zeroizing buffer; scrubbed on drop after encryption.
    let plaintext = encode_payload(payload);

    let k_recovery = derive_recovery_key(password, &recovery_salt, recovery_params)?;
    let ciphertext = aead::encrypt(&k_recovery, &nonce, RECOVERY_AD, plaintext.expose())?;

    // payload_ct_len: the AEAD output (ct ‖ tag) length. It cannot exceed
    // u32::MAX for any realistic vault; clamp to keep the function total (a
    // clamped value would simply fail to round-trip, never panic).
    let payload_ct_len = u32::try_from(ciphertext.len()).unwrap_or(u32::MAX);

    let mut file = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    file.extend_from_slice(MAGIC);
    file.push(FORMAT_VERSION);
    file.push(KDF_ALGORITHM_ARGON2ID);
    file.extend_from_slice(&recovery_params.m_kib.to_le_bytes());
    file.extend_from_slice(&recovery_params.t.to_le_bytes());
    file.push(recovery_params.p);
    file.extend_from_slice(&recovery_salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&payload_ct_len.to_le_bytes());
    file.extend_from_slice(&ciphertext);

    Ok(file)
}

/// Test-only export that **bypasses the recovery Floor gate** (`architecture.md`
/// §7.4) so a downstream crate's tests can build a valid recovery file with
/// cheap Argon2 parameters (the public [`export`]'s 1 GiB Floor is far too slow
/// for a normal test run).
///
/// Behind the `test-util` feature, which is **never** enabled in a production
/// build — only `passman-core`'s dev-dependencies turn it on. Production code
/// must call [`export`], which always enforces the Floor.
///
/// # Errors
///
/// [`RecoveryError::Crypto`] if Argon2id rejects the parameters or AEAD
/// encryption fails.
#[cfg(feature = "test-util")]
pub fn export_unchecked(
    payload: &ExportPayload,
    password: &SecretString,
    recovery_params: &KdfParams,
) -> Result<Vec<u8>, RecoveryError> {
    export_with(payload, password, recovery_params)
}

/// Import a recovery file (`architecture.md` §7.2–§7.6, crypto path).
///
/// A bounds-checked, panic-free parser: validates the magic, format version,
/// and KDF algorithm id; reads the header Argon2 params, salt, and nonce;
/// bounds-checks `payload_ct_len` against the remaining input; and rejects any
/// trailing bytes. It then derives `K_recovery` from the *header* params and the
/// password, AEAD-decrypts the payload, and parses the decrypted bytes
/// field-by-field into an [`ExportPayload`].
///
/// A wrong password or any tamper (ciphertext, tag, salt, or header params —
/// the params feed the key) surfaces as the detail-free
/// [`RecoveryError::Decrypt`]: there is no decryption oracle. A structural
/// problem in the *authenticated* payload surfaces as
/// [`RecoveryError::MalformedPayload`].
///
/// # Errors
///
/// - [`RecoveryError::BadMagic`] / [`RecoveryError::UnsupportedVersion`] /
///   [`RecoveryError::UnsupportedKdfAlgorithm`] for header mismatches.
/// - [`RecoveryError::Truncated`] / [`RecoveryError::TrailingBytes`] for a
///   malformed frame.
/// - [`RecoveryError::Decrypt`] for a wrong password or tampered input.
/// - [`RecoveryError::MalformedPayload`] for a structurally bad decrypted
///   payload.
pub fn import(file_bytes: &[u8], password: &SecretString) -> Result<ExportPayload, RecoveryError> {
    let mut r = Reader::new(file_bytes);

    let magic = r.take_array::<6>("magic")?;
    if &magic != MAGIC {
        return Err(RecoveryError::BadMagic);
    }

    let version = r.read_u8("format_version")?;
    if version != FORMAT_VERSION {
        return Err(RecoveryError::UnsupportedVersion {
            got: version,
            expected: FORMAT_VERSION,
        });
    }

    let kdf_id = r.read_u8("kdf_algorithm_id")?;
    if kdf_id != KDF_ALGORITHM_ARGON2ID {
        return Err(RecoveryError::UnsupportedKdfAlgorithm { got: kdf_id });
    }

    let m_kib = r.read_u32_le("argon2.m")?;
    let t = r.read_u32_le("argon2.t")?;
    let p = r.read_u8("argon2.p")?;
    let recovery_params = KdfParams { m_kib, t, p };

    // Reject an out-of-range header KDF cost BEFORE deriving: these params are
    // attacker-controlled and feed Argon2id before any authentication can fail,
    // so an absurd memory/time cost would be a pre-auth resource-exhaustion DoS
    // (OOM/hang, fatal on mobile). The strength *floor* is enforced only on the
    // export side; this is the universal anti-DoS *ceiling* on the import side.
    if !recovery_params.within_limits() {
        return Err(RecoveryError::KdfParamsOutOfRange { m_kib, t, p });
    }

    let recovery_salt = r.take_array::<SALT_LEN>("recovery_salt")?;
    let nonce = r.take_array::<{ aead::NONCE_LEN }>("nonce")?;

    let payload_ct_len = r.read_u32_le("payload_ct_len")? as usize;
    // Bounds-check the declared ciphertext length against what is actually
    // present, then require the file to end exactly there (no trailing bytes).
    let ciphertext = r.take(payload_ct_len, "payload_ct")?;
    r.expect_eof()?;

    // A ciphertext shorter than the AEAD tag cannot authenticate; fail fast
    // (detail-free, no oracle — folded into Decrypt) BEFORE the expensive
    // Argon2id derivation runs, rather than spending it to reach a guaranteed
    // InvalidLength inside aead::decrypt.
    if ciphertext.len() < aead::TAG_LEN {
        return Err(RecoveryError::Decrypt);
    }

    let k_recovery = derive_recovery_key(password, &recovery_salt, &recovery_params)?;

    // Map AEAD authentication failure to the detail-free `Decrypt` (no oracle).
    // A non-auth crypto error (none is expected on this path) still propagates
    // as `Crypto`. `InvalidLength` (ciphertext shorter than the tag) is a
    // malformed frame from the attacker's perspective, so it is also folded
    // into `Decrypt` rather than echoing lengths.
    let plaintext = match aead::decrypt(&k_recovery, &nonce, RECOVERY_AD, ciphertext) {
        Ok(pt) => pt,
        Err(CryptoError::AeadAuth | CryptoError::InvalidLength { .. }) => {
            return Err(RecoveryError::Decrypt)
        }
        Err(other) => return Err(RecoveryError::Crypto(other)),
    };

    decode_payload(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::{export, export_with, import, HEADER_LEN, MAGIC};
    use crate::error::RecoveryError;
    use crate::payload::{ExportPayload, RecoveryEntry};
    use passman_crypto::{KdfParams, SecretArray, SecretString};

    /// Deliberately cheap Argon2 params for fast tests. Far below the recovery
    /// Floor (so `export` would reject them) — used only via `export_with`.
    const TEST_PARAMS: KdfParams = KdfParams {
        m_kib: 8, // 8 KiB — minimum-ish, keeps Argon2 sub-millisecond
        t: 1,
        p: 1,
    };

    fn pw() -> SecretString {
        SecretString::new("correct horse battery staple".to_owned())
    }

    fn entry(seed: u8) -> RecoveryEntry {
        RecoveryEntry {
            id: [seed; 16],
            label: format!("acct-{seed}"),
            username: SecretString::new(format!("user{seed}")),
            password: SecretString::new(format!("pä$$🔐{seed}")),
            url: SecretString::new("https://exämple.test/login".to_owned()),
            notes: SecretString::new(format!("note line {seed}\nsecond")),
            policy: vec![0x01, 0x02, seed, 0xFF],
        }
    }

    fn payload(n: u8) -> ExportPayload {
        ExportPayload {
            totp_seed: SecretArray::new([0xABu8; 32]),
            original_vault_kdf: KdfParams {
                m_kib: 1_048_576,
                t: 4,
                p: 1,
            },
            entries: (0..n).map(entry).collect(),
        }
    }

    #[test]
    fn round_trip_recovers_payload() {
        let p = payload(3);
        let file = export_with(&p, &pw(), &TEST_PARAMS).expect("export");
        let got = import(&file, &pw()).expect("import");
        assert_eq!(got, p);
    }

    #[test]
    fn round_trip_empty_vault() {
        let p = payload(0);
        let file = export_with(&p, &pw(), &TEST_PARAMS).expect("export");
        let got = import(&file, &pw()).expect("import");
        assert_eq!(got.entries.len(), 0);
        assert_eq!(got, p);
    }

    #[test]
    fn export_rejects_sub_floor_params() {
        let err = export(&payload(1), &pw(), &TEST_PARAMS).expect_err("must reject");
        assert!(matches!(err, RecoveryError::WeakParams { .. }));
    }

    #[test]
    fn wrong_password_fails_decrypt() {
        let file = export_with(&payload(2), &pw(), &TEST_PARAMS).expect("export");
        let wrong = SecretString::new("wrong password entirely".to_owned());
        let err = import(&file, &wrong).expect_err("wrong pw");
        assert!(matches!(err, RecoveryError::Decrypt));
    }

    #[test]
    fn import_rejects_out_of_range_kdf_params() {
        // Forge a header with an absurd Argon2 memory cost (u32::MAX ~ 4 TiB).
        // import() must reject it up front — before any derivation — with the
        // typed KdfParamsOutOfRange, denying the pre-auth resource-exhaustion DoS.
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        // argon2.m occupies bytes [8..12]: magic(6) + version(1) + kdf_id(1).
        file[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = import(&file, &pw()).expect_err("must reject out-of-range cost");
        assert!(matches!(err, RecoveryError::KdfParamsOutOfRange { .. }));
    }

    #[test]
    fn tamper_ciphertext_byte_fails_decrypt() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        // Flip the last byte (inside the tag region).
        let last = file.len() - 1;
        file[last] ^= 0x01;
        let err = import(&file, &pw()).expect_err("tamper ct");
        assert!(matches!(err, RecoveryError::Decrypt));
    }

    #[test]
    fn tamper_salt_byte_fails_decrypt() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        // recovery_salt starts at offset 6+1+1+4+4+1 = 17.
        file[17] ^= 0x80;
        let err = import(&file, &pw()).expect_err("tamper salt");
        // A different salt yields a different key → AEAD auth fails.
        assert!(matches!(err, RecoveryError::Decrypt));
    }

    #[test]
    fn tamper_header_param_byte_fails_decrypt() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        // argon2.m starts at offset 8; bump its low byte so the derived key
        // changes. The new params are still structurally valid for Argon2, so
        // derivation succeeds but the key differs → AEAD auth fails.
        file[8] = file[8].wrapping_add(8);
        let err = import(&file, &pw()).expect_err("tamper param");
        assert!(matches!(
            err,
            RecoveryError::Decrypt | RecoveryError::Crypto(_)
        ));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        file[0] ^= 0xFF;
        let err = import(&file, &pw()).expect_err("bad magic");
        assert!(matches!(err, RecoveryError::BadMagic));
    }

    #[test]
    fn wrong_version_rejected() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        file[6] = 0x02; // format_version byte
        let err = import(&file, &pw()).expect_err("bad version");
        assert!(matches!(
            err,
            RecoveryError::UnsupportedVersion {
                got: 0x02,
                expected: 0x01
            }
        ));
    }

    #[test]
    fn wrong_kdf_id_rejected() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        file[7] = 0x01; // kdf_algorithm_id byte
        let err = import(&file, &pw()).expect_err("bad kdf id");
        assert!(matches!(
            err,
            RecoveryError::UnsupportedKdfAlgorithm { got: 0x01 }
        ));
    }

    #[test]
    fn truncated_header_rejected() {
        let file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        for cut in 0..HEADER_LEN {
            let err = import(&file[..cut], &pw()).expect_err("truncated header");
            // Anything short of a full header is either a magic/version/kdf
            // mismatch (if the cut lands after those bytes hold valid values it
            // can't, since we slice the real prefix) or a Truncated frame.
            assert!(
                matches!(
                    err,
                    RecoveryError::Truncated { .. } | RecoveryError::BadMagic
                ),
                "cut={cut} gave {err:?}"
            );
        }
    }

    #[test]
    fn payload_ct_len_exceeding_remaining_rejected() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        // payload_ct_len is the last 4 header bytes before the ciphertext.
        let off = HEADER_LEN - 4;
        file[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = import(&file, &pw()).expect_err("ct len too big");
        assert!(matches!(
            err,
            RecoveryError::Truncated {
                field: "payload_ct",
                ..
            }
        ));
    }

    #[test]
    fn trailing_bytes_after_payload_rejected() {
        let mut file = export_with(&payload(1), &pw(), &TEST_PARAMS).expect("export");
        file.push(0x00);
        let err = import(&file, &pw()).expect_err("trailing");
        assert!(matches!(err, RecoveryError::TrailingBytes { extra: 1 }));
    }

    #[test]
    fn arbitrary_prefix_never_panics() {
        // Sweep: every prefix of a valid file, plus a set of hand-built byte
        // patterns, must return an error (or, for the full file, decrypt) and
        // never panic / never index OOB.
        let file = export_with(&payload(2), &pw(), &TEST_PARAMS).expect("export");
        for len in 0..=file.len() {
            let _ = import(&file[..len], &pw());
        }

        // Adversarial fixed patterns of various lengths.
        let patterns: &[Vec<u8>] = &[
            vec![],
            vec![0u8; 1],
            vec![0xFFu8; HEADER_LEN],
            {
                // Valid magic + version + kdf id, then garbage of growing size.
                let mut v = Vec::new();
                v.extend_from_slice(MAGIC);
                v.push(0x01);
                v.push(0x00);
                v.extend_from_slice(&[0xAAu8; 64]);
                v
            },
            {
                // Valid header claiming a huge payload but no body.
                let mut v = Vec::new();
                v.extend_from_slice(MAGIC);
                v.push(0x01);
                v.push(0x00);
                v.extend_from_slice(&8u32.to_le_bytes()); // m
                v.extend_from_slice(&1u32.to_le_bytes()); // t
                v.push(1); // p
                v.extend_from_slice(&[0u8; 32]); // salt
                v.extend_from_slice(&[0u8; 24]); // nonce
                v.extend_from_slice(&u32::MAX.to_le_bytes()); // payload_ct_len
                v
            },
        ];
        for pat in patterns {
            let _ = import(pat, &pw());
        }
    }

    /// Real-preset round-trip. Ignored by default: the recovery Floor is 1 GiB
    /// Argon2 (~2.5 s) and the public `export` enforces it, which is far too
    /// slow and memory-hungry for the normal test run. Run explicitly with
    /// `cargo test -p passman-recovery -- --ignored` on a machine with ≥1 GiB
    /// free to exercise the full public `export` path including the Floor gate.
    #[test]
    #[ignore = "1 GiB Argon2 floor is too slow/heavy for the default test run"]
    fn real_floor_preset_round_trip() {
        use crate::kdf::RecoveryPreset;
        let p = payload(2);
        let file = export(&p, &pw(), &RecoveryPreset::Floor.params()).expect("export");
        let got = import(&file, &pw()).expect("import");
        assert_eq!(got, p);
    }
}
