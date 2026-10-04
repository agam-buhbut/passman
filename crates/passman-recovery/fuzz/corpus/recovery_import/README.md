# recovery_import seed corpus

Committed seed inputs for the `recovery_import` libFuzzer target
(`fuzz_targets/recovery_import.rs`, which drives
`passman_recovery::import_within_memory` with a small memory figure, so no
input can make it run an expensive Argon2id).
Shipping seeds gives libFuzzer structurally-meaningful starting points so it
explores the recovery-file parser instead of rediscovering the framing from
scratch.

The recovery file layout (`architecture.md` §7.2, `format.rs`) is:

```
magic(6)=b"PSMREC" | format_version(1)=0x01 | kdf_algorithm_id(1)=0x00
                   | argon2.m(u32-LE) | argon2.t(u32-LE) | argon2.p(u8)
                   | recovery_salt(32) | nonce(24) | payload_ct_len(u32-LE)
                   | payload(payload_ct_len)
```

| seed | exercises |
|------|-----------|
| `empty` | zero-length input |
| `magic_only` | just the magic, then truncation |
| `bad_magic` | `BadMagic` reject path |
| `header_below_floor_truncated` | full header with a tiny KDF cost and a payload shorter than its declared length (fails fast as truncated, before Argon2) |
| `full_header_empty_payload` | self-consistent framing with an empty payload |

The KDF costs in these seeds are deliberately tiny, and every seed fails in the
structural parse (bad magic, truncation, or a payload too short to hold an AEAD
tag) before any Argon2id runs; that parsing is the part worth seeding. Import
has no Floor check: the Floor applies only to export. The seeds
were hand-crafted from the documented framing (no crate code was run). The
fuzzer mutates from them; cargo-fuzz also writes discovered inputs here at
runtime — do not commit those, only meaningful seeds.
