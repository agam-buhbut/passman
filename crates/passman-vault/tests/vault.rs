//! Behavioural and robustness tests for `passman-vault`.
//!
//! Deterministic: no sleeps, no network, no filesystem. A fixed `K_master`,
//! fixed KDF params, and a fixed salt are used throughout so failures are
//! reproducible. Randomness (nonces, fresh entry ids) is internal to the crate
//! and does not affect the asserted invariants.
//!
//! Coverage: round-trip for 0/1/several entries, probe success/failure and
//! header-tamper detection, per-entry AEAD binding, the index↔envelope-set
//! check, bucket padding, and a battery of malformed-input parser-robustness
//! cases (each must return `Err`, never panic).

use passman_crypto::{KdfParams, MasterKey, SecretArray, SecretString};
use passman_policy::EntryPolicy;
use passman_vault::{
    EntryId, EntryRecord, IndexEntry, Vault, VaultError, VaultMetadata, FORMAT_VERSION,
    KDF_ALGORITHM_ARGON2ID, PROBE_PLAINTEXT,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn k_master() -> MasterKey {
    MasterKey::new(SecretArray::new([7u8; 32]))
}

fn other_k_master() -> MasterKey {
    MasterKey::new(SecretArray::new([9u8; 32]))
}

fn fixed_salt() -> [u8; 32] {
    [0x42u8; 32]
}

fn fixed_params() -> KdfParams {
    KdfParams::LOW
}

fn meta() -> VaultMetadata {
    VaultMetadata {
        last_password_change: 1_700_000_000,
        last_export_at: Some(1_700_500_000),
    }
}

fn record(u: &str, p: &str, url: &str, n: &str) -> EntryRecord {
    EntryRecord::new(
        SecretString::new(u.to_owned()),
        SecretString::new(p.to_owned()),
        SecretString::new(url.to_owned()),
        SecretString::new(n.to_owned()),
    )
}

/// Build an empty vault with the fixed fixtures and the two opaque HSM blobs.
fn empty_vault() -> Vault {
    Vault::create(
        fixed_params(),
        fixed_salt(),
        vec![0xAA, 0xBB, 0xCC], // opaque VaultKey wrap blob
        vec![0x01, 0x02],       // opaque TotpSeed wrap blob
        meta(),
        &k_master(),
    )
    .expect("create empty vault")
}

/// Build a vault with `n` deterministic entries, returning it plus the ids used.
fn vault_with_entries(n: usize) -> (Vault, Vec<EntryId>) {
    let km = k_master();
    let mut v = empty_vault();
    let mut ids = Vec::new();
    for i in 0..n {
        let id = EntryId::generate();
        ids.push(id);
        let r = record(
            &format!("user{i}"),
            &format!("pass-{i}-secret!"),
            &format!("https://site{i}.example"),
            &format!("notes for {i}"),
        );
        v.add_or_update_entry(&km, id, format!("label {i}"), EntryPolicy::default(), &r)
            .expect("add entry");
    }
    (v, ids)
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn round_trip_empty_vault() {
    let v = empty_vault();
    let bytes = v.to_bytes();
    let parsed = Vault::from_bytes(&bytes).expect("parse");
    assert_eq!(parsed, v);
    assert_eq!(parsed.len(), 0);
    assert!(parsed.is_empty());

    // Header fields survive.
    assert_eq!(parsed.format_version(), FORMAT_VERSION);
    assert_eq!(parsed.kdf_algorithm_id(), KDF_ALGORITHM_ARGON2ID);
    assert_eq!(parsed.kdf_params(), fixed_params());
    assert_eq!(parsed.vault_salt(), &fixed_salt());
    assert_eq!(parsed.k_hsm_wrap_blob(), &[0xAA, 0xBB, 0xCC]);
    assert_eq!(parsed.totp_seed_wrap_blob(), &[0x01, 0x02]);
    assert_eq!(parsed.metadata(), meta());

    // Empty index opens and is empty.
    let idx = parsed.open_index(&k_master()).expect("open index");
    assert!(idx.is_empty());
}

#[test]
fn round_trip_single_entry_preserves_everything() {
    let km = k_master();
    let mut v = empty_vault();
    let id = EntryId::generate();
    let r = record("alice", "hunter2!", "https://example.com", "a note");
    let policy = EntryPolicy::default().with_length(24);
    v.add_or_update_entry(&km, id, "Example".to_owned(), policy.clone(), &r)
        .expect("add");

    let parsed = Vault::from_bytes(&v.to_bytes()).expect("parse");
    assert_eq!(parsed, v);
    assert_eq!(parsed.len(), 1);

    let idx = parsed.open_index(&km).expect("open index");
    assert_eq!(idx.len(), 1);
    let row = idx.get(&id).expect("row present");
    assert_eq!(row.label, "Example");
    assert_eq!(row.policy, policy);

    let decrypted = parsed.decrypt_entry(&km, &id).expect("decrypt");
    assert_eq!(decrypted, r);
}

#[test]
fn round_trip_several_entries_labels_policies_and_records() {
    let km = k_master();
    let (v, ids) = vault_with_entries(5);

    let parsed = Vault::from_bytes(&v.to_bytes()).expect("parse");
    assert_eq!(parsed, v);
    assert_eq!(parsed.len(), 5);

    let idx = parsed.open_index(&km).expect("open index");
    assert_eq!(idx.len(), 5);
    for (i, id) in ids.iter().enumerate() {
        let row = idx.get(id).expect("row");
        assert_eq!(row.label, format!("label {i}"));

        let r = parsed.decrypt_entry(&km, id).expect("decrypt");
        assert_eq!(r.username.expose(), format!("user{i}"));
        assert_eq!(r.password.expose(), format!("pass-{i}-secret!"));
        assert_eq!(r.url.expose(), format!("https://site{i}.example"));
        assert_eq!(r.notes.expose(), format!("notes for {i}"));
    }
}

#[test]
fn update_existing_entry_replaces_in_place() {
    let km = k_master();
    let mut v = empty_vault();
    let id = EntryId::generate();
    v.add_or_update_entry(
        &km,
        id,
        "first".to_owned(),
        EntryPolicy::default(),
        &record("u1", "p1", "", ""),
    )
    .expect("add first");
    v.add_or_update_entry(
        &km,
        id,
        "second".to_owned(),
        EntryPolicy::default(),
        &record("u2", "p2", "", ""),
    )
    .expect("update to second");

    assert_eq!(v.len(), 1, "update must not grow the vault");
    let idx = v.open_index(&km).expect("open index");
    assert_eq!(idx.get(&id).expect("row present").label, "second");
    assert_eq!(
        v.decrypt_entry(&km, &id)
            .expect("decrypt")
            .username
            .expose(),
        "u2"
    );
}

#[test]
fn remove_entry_drops_envelope_and_index_row() {
    let km = k_master();
    let (mut v, ids) = vault_with_entries(3);
    v.remove_entry(&km, &ids[1]).expect("remove");
    assert_eq!(v.len(), 2);

    let idx = v.open_index(&km).expect("open index after remove");
    assert!(idx.get(&ids[1]).is_none());
    assert!(idx.get(&ids[0]).is_some());
    assert!(idx.get(&ids[2]).is_some());
    assert!(matches!(
        v.decrypt_entry(&km, &ids[1]),
        Err(VaultError::EntryNotFound)
    ));

    // Survives a round-trip with the set check intact.
    let parsed = Vault::from_bytes(&v.to_bytes()).expect("reparse");
    parsed.open_index(&km).expect("set check ok after remove");
}

#[test]
fn remove_missing_entry_is_error() {
    let km = k_master();
    let mut v = empty_vault();
    assert!(matches!(
        v.remove_entry(&km, &EntryId::generate()),
        Err(VaultError::EntryNotFound)
    ));
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

#[test]
fn probe_verifies_with_correct_key() {
    let v = empty_vault();
    v.verify_probe(&k_master()).expect("correct key verifies");
}

#[test]
fn probe_fails_with_wrong_key() {
    let v = empty_vault();
    assert!(matches!(
        v.verify_probe(&other_k_master()),
        Err(VaultError::Crypto(_))
    ));
}

#[test]
fn probe_fails_when_kdf_param_tampered() {
    // The probe AD binds the KDF params; flipping one must break verification
    // even with the correct key.
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    // m (KiB) is the u32-LE at offset 2; bump its low byte.
    bytes[2] = bytes[2].wrapping_add(1);
    let tampered = Vault::from_bytes(&bytes).expect("still parses structurally");
    assert_ne!(tampered.kdf_params(), v.kdf_params());
    assert!(matches!(
        tampered.verify_probe(&k_master()),
        Err(VaultError::Crypto(_))
    ));
}

#[test]
fn probe_fails_when_salt_tampered() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    // vault_salt starts at offset 11; flip a byte.
    bytes[11] ^= 0xFF;
    let tampered = Vault::from_bytes(&bytes).expect("parses");
    assert!(matches!(
        tampered.verify_probe(&k_master()),
        Err(VaultError::Crypto(_))
    ));
}

#[test]
fn probe_fails_when_probe_ct_tampered() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    // probe_ct starts at offset 67 (1+1+9+32+24).
    bytes[67] ^= 0x01;
    let tampered = Vault::from_bytes(&bytes).expect("parses");
    assert!(matches!(
        tampered.verify_probe(&k_master()),
        Err(VaultError::Crypto(_))
    ));
}

// ---------------------------------------------------------------------------
// Per-entry AEAD binding
// ---------------------------------------------------------------------------

#[test]
fn decrypt_entry_fails_with_wrong_key() {
    let (v, ids) = vault_with_entries(1);
    assert!(matches!(
        v.decrypt_entry(&other_k_master(), &ids[0]),
        Err(VaultError::Crypto(_))
    ));
}

#[test]
fn flipping_a_ciphertext_byte_fails_decrypt() {
    let km = k_master();
    let (v, ids) = vault_with_entries(1);
    let mut bytes = v.to_bytes();
    // Flip the very last byte (inside the only envelope's ciphertext+tag).
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = Vault::from_bytes(&bytes).expect("parses");
    assert!(matches!(
        tampered.decrypt_entry(&km, &ids[0]),
        Err(VaultError::Crypto(_))
    ));
}

#[test]
fn flipping_a_nonce_byte_fails_decrypt() {
    let km = k_master();
    let (v, ids) = vault_with_entries(1);
    let mut bytes = v.to_bytes();
    // The single envelope's nonce sits right after its 16-byte id; flipping a
    // nonce byte must make decryption fail authentication.
    let off = first_envelope_nonce_offset(&v);
    bytes[off] ^= 0x01;
    let tampered = Vault::from_bytes(&bytes).expect("parses");
    assert!(matches!(
        tampered.decrypt_entry(&km, &ids[0]),
        Err(VaultError::Crypto(_))
    ));
}

#[test]
fn envelope_moved_to_another_ids_slot_fails() {
    // Build two entries, then swap the ciphertext+nonce of envelope A into
    // envelope B's id slot. Because the key is derived from the id AND the id is
    // in the AAD, decrypting under B's id must fail.
    let km = k_master();
    let (v, ids) = vault_with_entries(2);

    // Reconstruct a tampered vault by editing the parsed structure's bytes:
    // easiest correct route is to rebuild via from_bytes after swapping the
    // two envelopes' payloads while keeping ids in place. We do it at the
    // struct level by reserializing a hand-built byte stream.
    let mut env = v.envelopes().to_vec();
    // Keep ids fixed (env[0].id, env[1].id), swap nonce + ciphertext.
    let (a_nonce, a_ct) = (env[0].nonce, env[0].ciphertext_and_tag.clone());
    env[0].nonce = env[1].nonce;
    env[0].ciphertext_and_tag = env[1].ciphertext_and_tag.clone();
    env[0].ct_len = u32::try_from(env[0].ciphertext_and_tag.len()).expect("ct len fits u32");
    env[1].nonce = a_nonce;
    env[1].ciphertext_and_tag = a_ct;
    env[1].ct_len = u32::try_from(env[1].ciphertext_and_tag.len()).expect("ct len fits u32");

    let tampered_bytes = reserialize_with_envelopes(&v, &env);
    let tampered = Vault::from_bytes(&tampered_bytes).expect("parses");
    // Now env[0] holds B's payload under A's id → must fail.
    assert!(matches!(
        tampered.decrypt_entry(&km, &ids[0]),
        Err(VaultError::Crypto(_))
    ));
    assert!(matches!(
        tampered.decrypt_entry(&km, &ids[1]),
        Err(VaultError::Crypto(_))
    ));
}

// ---------------------------------------------------------------------------
// Index <-> envelope-set check
// ---------------------------------------------------------------------------

#[test]
fn index_mismatch_when_envelope_removed_but_index_kept() {
    // Take a 2-entry vault and drop one envelope from the serialized bytes
    // (decrementing entries_count) while leaving the sealed index untouched.
    let km = k_master();
    let (v, _ids) = vault_with_entries(2);
    let bytes = drop_last_envelope(&v);
    let parsed = Vault::from_bytes(&bytes).expect("structurally valid");
    assert_eq!(parsed.len(), 1);
    assert!(matches!(
        parsed.open_index(&km),
        Err(VaultError::IndexMismatch)
    ));
}

#[test]
fn index_mismatch_when_extra_index_row_has_no_envelope() {
    // Seal an index that lists an id with no matching envelope, in an otherwise
    // empty vault.
    let km = k_master();
    let v = empty_vault();
    let phantom = IndexEntry::new(EntryId::generate(), "ghost".into(), EntryPolicy::default());
    let bytes = reseal_index_rows(&v, &[phantom]);
    let parsed = Vault::from_bytes(&bytes).expect("parses");
    assert!(matches!(
        parsed.open_index(&km),
        Err(VaultError::IndexMismatch)
    ));
}

#[test]
fn index_mismatch_on_duplicate_index_row() {
    // Two index rows share an id; one envelope exists. Lengths differ (2 vs 1)
    // and the duplicate is also caught.
    let km = k_master();
    let (v, ids) = vault_with_entries(1);
    let dup = IndexEntry::new(ids[0], "dup".into(), EntryPolicy::default());
    let row0 = IndexEntry::new(ids[0], "orig".into(), EntryPolicy::default());
    let bytes = reseal_index_rows(&v, &[row0, dup]);
    let parsed = Vault::from_bytes(&bytes).expect("parses");
    assert!(matches!(
        parsed.open_index(&km),
        Err(VaultError::IndexMismatch)
    ));
}

// ---------------------------------------------------------------------------
// Bucket padding
// ---------------------------------------------------------------------------

#[test]
fn envelope_ondisk_length_is_a_bucket_multiple() {
    // The on-disk ciphertext+tag length must be a multiple of 256 (the padded
    // plaintext length is preserved through the AEAD, which appends a 16-byte
    // tag — so ct = padded_plaintext + 16). The PADDED PLAINTEXT is the bucket
    // multiple; assert (ct_len - tag) % 256 == 0.
    const TAG: usize = 16;
    let (v, _ids) = vault_with_entries(3);
    for env in v.envelopes() {
        let ct = env.ciphertext_and_tag.len();
        assert!(ct > TAG);
        assert_eq!(
            (ct - TAG) % 256,
            0,
            "padded plaintext length must be a 256-byte multiple"
        );
        assert_eq!(env.ct_len as usize, ct, "ct_len must equal on-disk length");
    }
}

#[test]
fn padding_stripped_record_equals_original() {
    let km = k_master();
    let mut v = empty_vault();
    let id = EntryId::generate();
    // A record whose meaningful content is much smaller than a bucket.
    let r = record("u", "p", "url", "n");
    v.add_or_update_entry(&km, id, "x".into(), EntryPolicy::default(), &r)
        .expect("add entry");
    let decrypted = v.decrypt_entry(&km, &id).expect("decrypt");
    assert_eq!(decrypted, r);
}

// ---------------------------------------------------------------------------
// Sealed-index padding (threat #18 / §4.5: the sealed-index ciphertext length
// must not leak the sum of label+policy byte lengths).
// ---------------------------------------------------------------------------

/// Build a vault holding two entries with the supplied labels (fixed ids so the
/// only difference between two such vaults is the label byte lengths).
fn vault_with_labels(label_a: &str, label_b: &str) -> Vault {
    let km = k_master();
    let mut v = empty_vault();
    let id_a = EntryId::from_bytes([0x11u8; 16]);
    let id_b = EntryId::from_bytes([0x22u8; 16]);
    v.add_or_update_entry(
        &km,
        id_a,
        label_a.to_owned(),
        EntryPolicy::default(),
        &record("u", "p", "", ""),
    )
    .expect("add a");
    v.add_or_update_entry(
        &km,
        id_b,
        label_b.to_owned(),
        EntryPolicy::default(),
        &record("u", "p", "", ""),
    )
    .expect("add b");
    v
}

#[test]
fn sealed_index_ct_len_does_not_leak_label_lengths() {
    // Same entry count, vastly different total label byte length. The sealed
    // index must be padded to a bucket, so both serialize to the SAME
    // sealed-index ciphertext length (this is the property the fix delivers; it
    // FAILS before the padding change).
    let short = vault_with_labels("a", "b");
    let long = vault_with_labels(
        "a-very-long-descriptive-label-xxxxxxxx",
        "another-long-one-yyyyyyyyyy",
    );

    let short_len = sealed_index_ct_len(&short);
    let long_len = sealed_index_ct_len(&long);
    assert_eq!(
        short_len, long_len,
        "padded sealed-index ciphertext length must not reveal label-length \
         differences (short={short_len}, long={long_len})"
    );
}

#[test]
fn sealed_index_padded_format_round_trips() {
    // The new padded index must survive create -> to_bytes -> from_bytes ->
    // open_index, list entries, and reveal a field.
    let km = k_master();
    let (v, ids) = vault_with_entries(3);

    let parsed = Vault::from_bytes(&v.to_bytes()).expect("parse");
    let idx = parsed.open_index(&km).expect("open padded index");
    assert_eq!(idx.len(), 3);
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(idx.get(id).expect("row").label, format!("label {i}"));
    }
    // Reveal a field through the round-tripped vault.
    let rec0 = parsed.decrypt_entry(&km, &ids[0]).expect("decrypt");
    assert_eq!(rec0.username.expose(), "user0");
}

#[test]
fn old_unpadded_index_still_loads() {
    // Back-compat: a vault serialized in the OLD (v1, unpadded index) format
    // must still load and list correctly. We synthesize a genuine old-format
    // byte stream from a fresh vault: rewrite the version byte to v1 everywhere
    // it is AD-bound (header + probe + index AD) and re-seal the index in the
    // old unpadded form. The header version then drives the decrypt branch.
    let km = k_master();
    let (v, ids) = vault_with_entries(2);
    let old_bytes = downgrade_to_v1(&v);

    let parsed = Vault::from_bytes(&old_bytes).expect("v1 vault parses");
    assert_eq!(parsed.format_version(), 0x01);
    parsed.verify_probe(&km).expect("v1 probe verifies");
    let idx = parsed.open_index(&km).expect("v1 index opens");
    assert_eq!(idx.len(), 2);
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(idx.get(id).expect("row").label, format!("label {i}"));
    }
}

#[test]
fn mutating_a_v1_vault_does_not_corrupt_its_index() {
    // Regression (B2): a loaded legacy v1 vault must survive mutation. Before the
    // version-aware seal fix, add/remove re-sealed the index under v2 rules
    // (padded plaintext + ad=[0x02]) while the on-disk header stayed v1, so the
    // NEXT open failed the index AEAD — permanent, silent data loss. Here we load
    // a genuine v1 vault, remove one entry and add another, reload, and assert
    // the index and every surviving entry still decrypt.
    let km = k_master();
    let (v, ids) = vault_with_entries(2);
    let mut parsed = Vault::from_bytes(&downgrade_to_v1(&v)).expect("v1 parses");
    assert_eq!(parsed.format_version(), 0x01);

    parsed.remove_entry(&km, &ids[0]).expect("remove v1 entry");
    let new_id = EntryId::generate();
    parsed
        .add_or_update_entry(
            &km,
            new_id,
            "added to v1".to_owned(),
            EntryPolicy::default(),
            &record("newuser", "newpass!", "https://new.example", "n"),
        )
        .expect("add v1 entry");

    let reloaded = Vault::from_bytes(&parsed.to_bytes()).expect("mutated v1 parses");
    assert_eq!(reloaded.format_version(), 0x01, "stays v1 on disk");
    reloaded.verify_probe(&km).expect("probe still verifies");
    let idx = reloaded
        .open_index(&km)
        .expect("index opens after v1 mutation");
    assert_eq!(idx.len(), 2, "one removed, one added");
    assert!(idx.get(&ids[0]).is_none(), "removed entry is gone");
    assert!(idx.get(&new_id).is_some(), "added entry present");
    let surv = reloaded
        .decrypt_entry(&km, &ids[1])
        .expect("surviving entry decrypts");
    assert_eq!(surv.username.expose(), "user1");
    let added = reloaded
        .decrypt_entry(&km, &new_id)
        .expect("added entry decrypts");
    assert_eq!(added.username.expose(), "newuser");
}

#[test]
fn padded_index_with_oversized_true_len_is_rejected() {
    // A v2 padded index whose true_len prefix claims more bytes than the
    // (de-padded) plaintext holds must be rejected (no panic, Err). The padded
    // plaintext is INSIDE the AEAD, so we seal a malformed plaintext directly
    // with the crate's K_index and v2 AD, then assert open fails.
    let km = k_master();
    let v = empty_vault();
    let bytes = reseal_index_raw_plaintext(&v, &oversized_true_len_plaintext());
    let parsed = Vault::from_bytes(&bytes).expect("parses structurally");
    assert!(parsed.open_index(&km).is_err());
}

// ---------------------------------------------------------------------------
// Parser robustness — malformed inputs must Err, never panic
// ---------------------------------------------------------------------------

#[test]
fn empty_input_errors() {
    assert!(Vault::from_bytes(&[]).is_err());
}

#[test]
fn truncated_at_each_major_field_boundary_errors() {
    // A full valid vault; truncate it at every length and confirm none panic
    // and all (except the exact full length) error.
    let (v, _ids) = vault_with_entries(2);
    let full = v.to_bytes();
    for cut in 0..full.len() {
        let res = Vault::from_bytes(&full[..cut]);
        assert!(
            res.is_err(),
            "prefix of length {cut} unexpectedly parsed as a full vault"
        );
    }
    // The exact full buffer parses.
    assert!(Vault::from_bytes(&full).is_ok());
}

#[test]
fn wrong_version_byte_errors() {
    // 0x01 (legacy) and 0x02 (current) are both accepted; an unknown version
    // (0x03) must still be rejected. (Updated from asserting on 0x02 when the
    // index-padding change bumped the current version 0x01 -> 0x02.)
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    bytes[0] = 0x03;
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::UnsupportedVersion { got: 0x03, .. })
    ));
}

#[test]
fn wrong_kdf_algorithm_byte_errors() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    bytes[1] = 0x07;
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::UnsupportedKdfAlgorithm { got: 0x07 })
    ));
}

#[test]
fn invalid_export_present_flag_errors() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    let off = export_present_offset(&v);
    bytes[off] = 0x05; // neither 0x00 nor 0x01
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::InvalidFlag {
            field: "meta.last_export_present",
            got: 0x05
        })
    ));
}

#[test]
fn hsm_blob_length_prefix_larger_than_buffer_errors() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    // k_hsm_wrap_blob_len is the u16-LE at offset 99. Set it to a huge value.
    bytes[99] = 0xFF;
    bytes[100] = 0xFF;
    let res = Vault::from_bytes(&bytes);
    assert!(matches!(
        res,
        Err(VaultError::Truncated {
            field: "k_hsm_wrap_blob",
            ..
        })
    ));
}

#[test]
fn sealed_index_ct_len_larger_than_buffer_errors() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    let off = sealed_index_ct_len_offset(&v);
    bytes[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::Truncated {
            field: "sealed_index_ct",
            ..
        })
    ));
}

#[test]
fn entries_count_too_large_errors_without_overallocating() {
    // entries_count claims u32::MAX but no envelope bytes follow. Must error on
    // the first envelope read rather than attempting a giant allocation.
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    let off = entries_count_offset(&v);
    bytes[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let res = Vault::from_bytes(&bytes);
    assert!(matches!(res, Err(VaultError::Truncated { .. })));
}

#[test]
fn entry_ct_len_larger_than_buffer_errors() {
    // One real entry; inflate its envelope ct_len prefix.
    let (v, _ids) = vault_with_entries(1);
    let mut bytes = v.to_bytes();
    // The single envelope's ct_len u32 sits after id(16)+nonce(24) from the
    // envelope start. Find the envelope start via the helper.
    let nonce_off = first_envelope_nonce_offset(&v);
    let ct_len_off = nonce_off + 24;
    bytes[ct_len_off..ct_len_off + 4].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::Truncated {
            field: "entry.ciphertext",
            ..
        })
    ));
}

#[test]
fn trailing_garbage_after_last_envelope_errors() {
    let (v, _ids) = vault_with_entries(1);
    let mut bytes = v.to_bytes();
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::TrailingBytes { extra: 4 })
    ));
}

#[test]
fn trailing_garbage_after_empty_vault_errors() {
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    bytes.push(0x00);
    assert!(matches!(
        Vault::from_bytes(&bytes),
        Err(VaultError::TrailingBytes { extra: 1 })
    ));
}

#[test]
fn entries_count_one_but_no_envelope_errors() {
    // A structurally-empty vault whose entries_count is forced to 1.
    let v = empty_vault();
    let mut bytes = v.to_bytes();
    let off = entries_count_offset(&v);
    bytes[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
    assert!(Vault::from_bytes(&bytes).is_err());
}

// ---------------------------------------------------------------------------
// Offset/serialization helpers for the tests above.
//
// These recompute the §4.7 offsets from a vault's actual variable-length field
// sizes so the tests stay correct regardless of fixture blob lengths. They
// mirror the layout in vault.rs exactly.
// ---------------------------------------------------------------------------

/// Offset of `k_hsm_wrap_blob_len` — always 99 per §4.7.
const HSM_BLOB_LEN_OFF: usize = 99;

/// Offset just past the fixed header (the start of `k_hsm_wrap_blob_len`).
fn after_fixed_header() -> usize {
    // 1 ver + 1 kdf_id + 9 kdf_params + 32 salt + 24 probe_nonce + 32 probe_ct
    HSM_BLOB_LEN_OFF
}

/// Offset of the `rl_counter` field (just past both HSM blobs).
fn rl_counter_offset(v: &Vault) -> usize {
    let mut off = after_fixed_header();
    off += 2 + v.k_hsm_wrap_blob().len();
    off += 2 + v.totp_seed_wrap_blob().len();
    off
}

/// Offset of `meta.last_export_present`.
fn export_present_offset(v: &Vault) -> usize {
    // rl_counter(8) + rl_last_failure(8) + last_password_change(8)
    rl_counter_offset(v) + 8 + 8 + 8
}

/// Offset of `sealed_index_nonce`.
fn sealed_index_nonce_offset(v: &Vault) -> usize {
    // present(1) + last_export_at(8)
    export_present_offset(v) + 1 + 8
}

/// Offset of `sealed_index_ct_len`.
fn sealed_index_ct_len_offset(v: &Vault) -> usize {
    sealed_index_nonce_offset(v) + 24
}

/// Offset of `entries_count`.
fn entries_count_offset(v: &Vault) -> usize {
    let off = sealed_index_ct_len_offset(v);
    // ct_len(4) + sealed_index_ct
    off + 4 + sealed_index_ct_len(v)
}

/// The serialized sealed-index ciphertext length, read back from `to_bytes`.
fn sealed_index_ct_len(v: &Vault) -> usize {
    let off = sealed_index_ct_len_offset(v);
    let bytes = v.to_bytes();
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as usize
}

/// Offset of the first envelope's `nonce` (id is the 16 bytes before it).
fn first_envelope_nonce_offset(v: &Vault) -> usize {
    // entries_count(4) + id(16)
    entries_count_offset(v) + 4 + 16
}

/// Reserialize the vault but with a replacement envelope list.
fn reserialize_with_envelopes(v: &Vault, envelopes: &[passman_vault::EntryEnvelope]) -> Vec<u8> {
    let mut bytes = v.to_bytes();
    // Truncate to just after entries_count, rewrite count + envelopes.
    let count_off = entries_count_offset(v);
    bytes.truncate(count_off);
    let count = u32::try_from(envelopes.len()).expect("count fits u32");
    bytes.extend_from_slice(&count.to_le_bytes());
    for env in envelopes {
        bytes.extend_from_slice(env.id.as_bytes());
        bytes.extend_from_slice(&env.nonce);
        bytes.extend_from_slice(&env.ct_len.to_le_bytes());
        bytes.extend_from_slice(&env.ciphertext_and_tag);
    }
    bytes
}

/// Drop the last envelope and decrement `entries_count` (leaving the sealed
/// index untouched, to provoke an index↔envelope mismatch).
fn drop_last_envelope(v: &Vault) -> Vec<u8> {
    let mut env = v.envelopes().to_vec();
    env.pop();
    reserialize_with_envelopes(v, &env)
}

/// Replace the sealed-index ciphertext with a freshly-sealed encoding of
/// `rows`, keeping the rest of the vault (including envelopes) intact. The
/// public mutation path always keeps the id sets equal, so to *provoke* a
/// mismatch we encrypt arbitrary rows directly with the same `K_index` the
/// crate would derive.
///
/// The rows are wrapped in the v2 padded index encoding (`true_len` prefix +
/// zero-pad to a 256-byte bucket) so this fixture faithfully mirrors the
/// crate's own sealing; the provoked failure is then the intended
/// index↔envelope mismatch, not a padding-decode error.
fn reseal_index_rows(v: &Vault, rows: &[IndexEntry]) -> Vec<u8> {
    let postcard_bytes = postcard::to_stdvec(&rows.to_vec()).expect("serialize rows");
    reseal_index_raw_plaintext(v, &pad_index_plaintext(&postcard_bytes))
}

/// Pad an index postcard blob into the v2 authenticated-plaintext form:
/// `true_len(u32-LE) ‖ postcard_bytes ‖ zero-pad` up to a 256-byte multiple.
/// Mirrors the crate-internal `seal_index` padding so test fixtures stay in
/// lock-step with the real format.
fn pad_index_plaintext(postcard_bytes: &[u8]) -> Vec<u8> {
    const BUCKET: usize = 256;
    let unpadded = 4 + postcard_bytes.len();
    let padded = unpadded.div_ceil(BUCKET) * BUCKET;
    let mut buf = vec![0u8; padded];
    let true_len = u32::try_from(postcard_bytes.len()).expect("index fits u32");
    buf[0..4].copy_from_slice(&true_len.to_le_bytes());
    buf[4..4 + postcard_bytes.len()].copy_from_slice(postcard_bytes);
    buf
}

/// A malformed v2 padded-index plaintext whose `true_len` prefix exceeds the
/// buffer (claims 1000 bytes inside a single 256-byte bucket).
fn oversized_true_len_plaintext() -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    buf[0..4].copy_from_slice(&1000u32.to_le_bytes());
    buf
}

/// Seal `plaintext` directly under the crate's `K_index` with the v2 AD and
/// splice it into `v`'s byte stream as the sealed index (envelopes unchanged).
/// `plaintext` is the *already-padded* authenticated plaintext.
fn reseal_index_raw_plaintext(v: &Vault, plaintext: &[u8]) -> Vec<u8> {
    use passman_crypto::{aead, hkdf_expand, random_nonce};

    let key = hkdf_expand(&k_master(), passman_vault::INDEX_INFO);
    let nonce = random_nonce();
    let ad = [FORMAT_VERSION];
    let ct = aead::encrypt(&key, &nonce, &ad, plaintext).expect("seal");

    // Rebuild the byte stream from `sealed_index_nonce` onward.
    let mut bytes = v.to_bytes();
    let nonce_off = sealed_index_nonce_offset(v);
    bytes.truncate(nonce_off);
    bytes.extend_from_slice(&nonce);
    let ct_len = u32::try_from(ct.len()).expect("ct len fits u32");
    bytes.extend_from_slice(&ct_len.to_le_bytes());
    bytes.extend_from_slice(&ct);
    // Re-append entries_count + envelopes unchanged.
    let count = u32::try_from(v.envelopes().len()).expect("count fits u32");
    bytes.extend_from_slice(&count.to_le_bytes());
    for env in v.envelopes() {
        bytes.extend_from_slice(env.id.as_bytes());
        bytes.extend_from_slice(&env.nonce);
        bytes.extend_from_slice(&env.ct_len.to_le_bytes());
        bytes.extend_from_slice(&env.ciphertext_and_tag);
    }
    bytes
}

/// Synthesize a genuine OLD (v1) on-disk vault from a current (v2) vault.
///
/// The version byte is AD-bound in three places: the header probe AD, the
/// per-entry envelope AD, and the sealed-index AD. To produce a vault that the
/// v1 decrypt path accepts, we re-derive every one of those from a fresh v1
/// vault: build a brand-new vault whose header version is 0x01, re-seal its
/// index UNPADDED with `ad=[0x01]`, and re-encrypt each entry envelope with
/// `ad = 0x01 ‖ id`. We reuse `v`'s ids/labels/records so the loaded vault is
/// equivalent. This is exactly what the previous (pre-padding) code would have
/// written.
fn downgrade_to_v1(v: &Vault) -> Vec<u8> {
    use passman_crypto::{aead, hkdf_expand, random_nonce};

    let km = k_master();

    // Decrypt the current index + records so we can re-seal them under v1 AD.
    let idx = v.open_index(&km).expect("open current index");

    // 1. Re-seal the index UNPADDED with ad=[0x01] (the old format).
    let postcard_bytes = postcard::to_stdvec(&idx.entries().to_vec()).expect("serialize index");
    let index_key = hkdf_expand(&km, passman_vault::INDEX_INFO);
    let index_nonce = random_nonce();
    let index_ct =
        aead::encrypt(&index_key, &index_nonce, &[0x01u8], &postcard_bytes).expect("seal v1 index");

    // 2. Re-seal the probe under v1 AD. The probe AD binds the version, so a
    //    probe sealed under v2 will not verify once the header reads v1.
    let probe_nonce = random_nonce();
    let mut probe_ad = Vec::new();
    probe_ad.push(0x01u8); // format_version
    probe_ad.push(KDF_ALGORITHM_ARGON2ID); // kdf_algorithm_id
    probe_ad.extend_from_slice(&v.kdf_params().to_bytes());
    probe_ad.extend_from_slice(v.vault_salt());
    probe_ad.extend_from_slice(b"probe-v0");
    let probe_ct =
        aead::encrypt(&km, &probe_nonce, &probe_ad, PROBE_PLAINTEXT).expect("seal v1 probe");
    assert_eq!(
        probe_ct.len(),
        32,
        "probe ct is 16-byte payload + 16-byte tag"
    );

    // 3. Start from the v2 bytes, rewrite the header version byte to 0x01, and
    //    splice in the v1 probe (nonce at offset 43, ct at offset 67).
    let mut bytes = v.to_bytes();
    bytes[0] = 0x01;
    bytes[43..67].copy_from_slice(&probe_nonce);
    bytes[67..99].copy_from_slice(&probe_ct);

    // 4. Splice in the v1 sealed index in place of the v2 one.
    let nonce_off = sealed_index_nonce_offset(v);
    bytes.truncate(nonce_off);
    bytes.extend_from_slice(&index_nonce);
    let index_ct_len = u32::try_from(index_ct.len()).expect("ct len fits u32");
    bytes.extend_from_slice(&index_ct_len.to_le_bytes());
    bytes.extend_from_slice(&index_ct);

    // 5. Re-encrypt every envelope with ad = 0x01 ‖ id (the old per-entry AD),
    //    reusing each entry's plaintext record so the contents are preserved.
    let count = u32::try_from(v.envelopes().len()).expect("count fits u32");
    bytes.extend_from_slice(&count.to_le_bytes());
    for env in v.envelopes() {
        let id = env.id;
        let rec = v.decrypt_entry(&km, &id).expect("decrypt for re-encrypt");
        let info = entry_info_bytes(&id);
        let entry_key = passman_crypto::EntryKey::new(hkdf_expand(&km, &info));
        let padded = encode_record_padded(&rec);
        let nonce = random_nonce();
        let mut ad = [0u8; 17];
        ad[0] = 0x01;
        ad[1..].copy_from_slice(id.as_bytes());
        let ct = aead::encrypt(&entry_key, &nonce, &ad, &padded).expect("encrypt entry v1");
        let ct_len = u32::try_from(ct.len()).expect("ct len fits u32");
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ct_len.to_le_bytes());
        bytes.extend_from_slice(&ct);
    }
    bytes
}

/// Reproduce `entry-v0:` ‖ id HKDF info (the crate-internal `entry_info`).
fn entry_info_bytes(id: &EntryId) -> Vec<u8> {
    let mut info = Vec::with_capacity(9 + 16);
    info.extend_from_slice(passman_vault::ENTRY_INFO_PREFIX);
    info.extend_from_slice(id.as_bytes());
    info
}

/// Reproduce the per-entry bucket padding (`true_len ‖ four length-prefixed
/// fields ‖ zero-pad`) for the v1 re-encrypt path. The entry padding format is
/// unchanged between v1 and v2; only the index gained padding.
fn encode_record_padded(rec: &EntryRecord) -> Vec<u8> {
    const BUCKET: usize = 256;
    let fields: [&[u8]; 4] = [
        rec.username.expose().as_bytes(),
        rec.password.expose().as_bytes(),
        rec.url.expose().as_bytes(),
        rec.notes.expose().as_bytes(),
    ];
    let record_len: usize = fields.iter().map(|f| 4 + f.len()).sum();
    let unpadded = 4 + record_len;
    let padded = unpadded.div_ceil(BUCKET) * BUCKET;
    let mut buf = vec![0u8; padded];
    buf[0..4].copy_from_slice(&u32::try_from(record_len).expect("fits").to_le_bytes());
    let mut off = 4;
    for f in fields {
        buf[off..off + 4].copy_from_slice(&u32::try_from(f.len()).expect("fits").to_le_bytes());
        off += 4;
        buf[off..off + f.len()].copy_from_slice(f);
        off += f.len();
    }
    buf
}

// ---------------------------------------------------------------------------
// HSM wrap-blob u16 length bound (§4.7 / §6.3)
// ---------------------------------------------------------------------------

/// The on-disk format length-prefixes each HSM wrap blob with a `u16`, so a blob
/// at exactly `u16::MAX` bytes is the largest that can be encoded. It must
/// construct, serialize, and re-parse losslessly (no silent length clamp).
#[test]
fn max_size_hsm_blob_round_trips() {
    let blob = vec![0x5A_u8; usize::from(u16::MAX)];
    let vault = Vault::create(
        fixed_params(),
        fixed_salt(),
        blob.clone(),
        vec![0x01, 0x02],
        meta(),
        &k_master(),
    )
    .expect("create with max-size blob");

    let parsed = Vault::from_bytes(&vault.to_bytes()).expect("round-trip max-size blob");
    assert_eq!(parsed.k_hsm_wrap_blob(), blob.as_slice());
    assert_eq!(parsed.totp_seed_wrap_blob(), &[0x01, 0x02]);
}

/// A blob one byte past `u16::MAX` cannot be length-encoded; `create` must
/// reject it with `BlobTooLarge` rather than producing a vault that `to_bytes`
/// would silently corrupt.
#[test]
fn create_rejects_oversized_hsm_blob() {
    let oversized = vec![0u8; usize::from(u16::MAX) + 1];
    let err = Vault::create(
        fixed_params(),
        fixed_salt(),
        oversized,
        vec![0x01, 0x02],
        meta(),
        &k_master(),
    )
    .expect_err("oversized k_hsm blob must be rejected");
    assert!(matches!(
        err,
        VaultError::BlobTooLarge {
            which: "k_hsm_wrap_blob"
        }
    ));

    let oversized = vec![0u8; usize::from(u16::MAX) + 1];
    let err = Vault::create(
        fixed_params(),
        fixed_salt(),
        vec![0xAA, 0xBB],
        oversized,
        meta(),
        &k_master(),
    )
    .expect_err("oversized totp_seed blob must be rejected");
    assert!(matches!(
        err,
        VaultError::BlobTooLarge {
            which: "totp_seed_wrap_blob"
        }
    ));
}

/// `set_hsm_blobs` enforces the same bound and leaves the vault unchanged when a
/// blob is too large (both blobs are validated before either is stored).
#[test]
fn set_hsm_blobs_enforces_u16_bound() {
    let mut vault = empty_vault();
    let original_k_hsm = vault.k_hsm_wrap_blob().to_vec();

    let err = vault
        .set_hsm_blobs(vec![0u8; usize::from(u16::MAX) + 1], vec![0x09])
        .expect_err("oversized blob must be rejected");
    assert!(matches!(err, VaultError::BlobTooLarge { .. }));
    // Unchanged: the rejected call stored neither blob.
    assert_eq!(vault.k_hsm_wrap_blob(), original_k_hsm.as_slice());

    // A valid replacement (including the max-size boundary) succeeds.
    let max_blob = vec![0x33_u8; usize::from(u16::MAX)];
    vault
        .set_hsm_blobs(max_blob.clone(), vec![0x09])
        .expect("valid blobs accepted");
    let parsed = Vault::from_bytes(&vault.to_bytes()).expect("round-trip");
    assert_eq!(parsed.k_hsm_wrap_blob(), max_blob.as_slice());
    assert_eq!(parsed.totp_seed_wrap_blob(), &[0x09]);
}
