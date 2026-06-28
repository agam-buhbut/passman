# recovery_import seed corpus

Committed seed inputs for the `recovery_import` libFuzzer target
(`fuzz_targets/recovery_import.rs`, which drives `passman_recovery::import`).
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
| `header_below_floor_truncated` | full header with a below-floor KDF cost (fails fast at the recovery Floor gate, before Argon2) |
| `full_header_empty_payload` | self-consistent framing with an empty payload |

The KDF costs in these seeds are deliberately tiny so no seed triggers the
real (>= 1 GiB) Argon2id at corpus-load time — they fail fast at the Floor /
limit gate after the structural parse, which is the part worth seeding. They
were hand-crafted from the documented framing (no crate code was run). The
fuzzer mutates from them; cargo-fuzz also writes discovered inputs here at
runtime — do not commit those, only meaningful seeds.
