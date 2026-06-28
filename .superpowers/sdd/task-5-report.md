# Task 5 — Pad the sealed index (pentest finding S9, threat #18)

## Summary

The sealed index was AEAD-encrypted as raw `postcard(Vec<IndexEntry>)` with no
padding, so `sealed_index_ct_len` leaked the exact sum of all label + policy
byte lengths (and per-edit deltas across saves). The per-envelope bodies were
already bucket-padded; only the index was not. This change pads the sealed
index identically to the envelopes, closing the leak documented in §4.5
("does not learn any label") and threat #18 ("256-byte bucket padding").

## Format version bump

`crates/passman-vault/src/vault.rs`:

- `FORMAT_VERSION: 0x01 -> 0x02` (the version that tags the padded-index
  format). The version is AD-bound into every AEAD (probe, sealed index, each
  envelope) per §4.7/§4.10.
- Added `const FORMAT_VERSION_LEGACY_V1: u8 = 0x01` — still accepted on read.
- `from_bytes` now accepts `0x02` (current) **and** `0x01` (legacy); any other
  version still returns `UnsupportedVersion`. New vaults are always written as
  `0x02`.

## Padding scheme (mirrors `record.rs` exactly)

`INDEX_BUCKET = crate::record::BUCKET` (= 256) — the same constant the
envelopes use, so both quantizations are identical.

The v2 sealed-index **authenticated plaintext** (inside the AEAD) is:

```
true_len : u32-LE          length of the postcard bytes that follow
postcard : true_len bytes  postcard(Vec<IndexEntry>)
padding  : zeros           up to div_ceil(INDEX_BUCKET)*INDEX_BUCKET
```

This is byte-for-byte the same scheme as `EntryRecord::encode_padded`
(`true_len` prefix inside the authenticated plaintext + zero-pad to the bucket),
except the "record region" here is the opaque postcard blob rather than four
sub-fields. `true_len` is covered by the AEAD tag, so the padding is
authenticated.

- `seal_index` (v2 only): postcard-serialize, `pad_index_plaintext`, then
  AEAD-encrypt with `ad = [FORMAT_VERSION]` and a fresh nonce.
- `strip_index_padding`: reads `true_len`, bounds-checks `4 + true_len <=
  plaintext.len()` (with a `checked_add` overflow guard), returns the postcard
  slice. An out-of-range `true_len` returns `VaultError::MalformedRecord`,
  never panics.

## Back-compat branch

`decrypt_index` branches on the **stored** `self.format_version` (which is what
`from_bytes` read and is AD-bound, so it cannot be silently flipped without
failing the AEAD):

- `0x01` (legacy): AEAD-decrypt with `ad = [0x01]`, then postcard-parse the
  plaintext **directly** (no padding) — the original behaviour.
- `0x02` (current): AEAD-decrypt with `ad = [0x02]`, `strip_index_padding`,
  then postcard-parse.

So a vault written by the old code (`format_version = 0x01`, unpadded index)
still loads. All other invariants are unchanged: the index↔envelope-set
consistency check, per-entry AEAD AD binding (`format_version ‖ id`), fresh
nonces, fail-closed on malformed input, `#![forbid(unsafe_code)]`. The parser
bounds checks were not weakened.

## Leak-closed test (RED -> GREEN)

`sealed_index_ct_len_does_not_leak_label_lengths`: builds two 2-entry vaults
with the same ids but very different total label lengths
(`["a","b"]` vs `["a-very-long-descriptive-label-xxxxxxxx",
"another-long-one-yyyyyyyyyy"]`), serializes both, and asserts their
`sealed_index_ct_len` are EQUAL.

- **RED (before the fix):** `short=61, long=124` — the test FAILED, proving the
  leak existed.
- **GREEN (after the fix):** both round up to the same 256-byte bucket; the
  lengths are equal and the test passes.

## How back-compat was proved

`old_unpadded_index_still_loads` synthesizes a **genuine** v1 on-disk vault from
a fresh v2 vault and loads it through the public API. Because the version byte
is AD-bound in three places, the fixture re-derives all three under v1 AD:

1. Re-seals the **probe** with `ad = 0x01 ‖ kdf_id ‖ kdf_params ‖ salt ‖
   "probe-v0"` (splices the new nonce + 32-byte ct at offsets 43 / 67).
2. Re-seals the **index** UNPADDED with `ad = [0x01]` (the old format).
3. Re-encrypts each **envelope** with `ad = 0x01 ‖ id`.
4. Rewrites the header version byte to `0x01`.

The test then asserts `from_bytes` parses it, `format_version() == 0x01`,
`verify_probe` succeeds, and `open_index` lists both labels correctly. This is a
real back-compat round-trip, not just version-branch logic.

`passman-core`'s `full_round_trip_create_persist_reopen_unlock_reveal` and
`change_master_password_*` also pass, confirming the version bump is transparent
to the consumer (core never hard-codes the version on the read path).

## Negative / robustness

- `padded_index_with_oversized_true_len_is_rejected`: seals a v2 plaintext whose
  `true_len` (1000) exceeds its 256-byte buffer directly under the crate's
  `K_index`; `open_index` returns `Err` (no panic).
- The existing exhaustive negative suite still passes: truncation at every
  boundary, header/probe/envelope tamper, index↔envelope mismatch (extra row /
  duplicate row / dropped envelope), oversized length prefixes, trailing bytes.

## Test-helper / existing-test changes (flagged)

Two existing-test touches were required by the format change and are called out
explicitly (no assertion was weakened to pass):

1. `wrong_version_byte_errors` previously set `bytes[0] = 0x02` and asserted
   `UnsupportedVersion { got: 0x02 }`. Since `0x02` is now the **valid** current
   version, the test would no longer exercise an unknown version. Updated to use
   `0x03` (still unknown) — the assertion (an unknown version is rejected) is
   unchanged.
2. The test fixture `reseal_index_rows` (and the new `reseal_index_raw_plaintext`
   it now delegates to) was updated to wrap rows in the v2 padded encoding before
   sealing, so it faithfully mirrors the crate's real sealing. Without this the
   index-mismatch negative tests would trip a padding-decode error instead of
   the intended `IndexMismatch`. This keeps those tests testing the mismatch
   path; it does not change what they assert.

## Commands (all pass)

- `cargo test -p passman-vault` — 36 + 31 + 21 (integration + record + index)
  unit tests pass.
- `cargo test -p passman-core` — 18 passed, 1 ignored (the 1 GiB Argon2 floor
  test, ignored by design).
- `cargo clippy -p passman-vault -p passman-core --all-targets -- -D warnings` —
  clean.
- `cargo fmt` (vault) + `cargo fmt --check` — clean.
- `./scripts/check-boundaries.sh` — all boundary checks passed.
- `cargo build --workspace` — clean.

## Concerns

- **AD binding (verified, no concern):** the index AD is `[self.format_version]`.
  Because the stored version drives both the AD and the decode branch, a
  v1 blob decodes with `ad=[0x01]`+unpadded and a v2 blob with
  `ad=[0x02]`+padded — they cannot be confused, and flipping the version byte
  on disk fails the AEAD (the probe AD also binds it). I confirmed this is
  sound rather than relying on it.
- **One-way upgrade:** opening + saving any v1 vault rewrites it as v2 (every
  save re-seals via `seal_index`). There is no v2->v1 downgrade path, which
  matches §4.10 ("mismatch aborts loudly" for unknown versions; known prior
  versions are read, not written). If a v1-only reader must ever re-read a
  re-saved file, that is not supported — but nothing in this workspace is a
  v1-only reader.
- **No new dependencies. No public API signature changes** (`FORMAT_VERSION`'s
  value changed but its type/visibility did not).
