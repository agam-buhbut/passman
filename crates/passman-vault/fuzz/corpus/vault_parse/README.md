# vault_parse seed corpus

Committed seed inputs for the `vault_parse` libFuzzer target
(`fuzz_targets/vault_parse.rs`, which drives `passman_vault::Vault::from_bytes`).
Shipping seeds lets libFuzzer start from structurally-meaningful inputs instead
of an empty corpus, so coverage-guided mutation reaches the parser's interior
paths far sooner.

The vault header layout (`architecture.md` §, `vault.rs`) is:

```
format_version(1) | kdf_algorithm_id(1) | kdf_params(9) | vault_salt(32)
                  | probe_nonce(24) | probe_ct(..) | ...
```

with `FORMAT_VERSION = 0x02` (legacy `0x01` also accepted) and
`KDF_ALGORITHM_ARGON2ID = 0x00`.

| seed | exercises |
|------|-----------|
| `empty` | zero-length input (immediate truncation) |
| `one_byte_version` | version byte only, then truncation |
| `bad_version` | unsupported `format_version` reject path |
| `bad_kdf_id` | unsupported `kdf_algorithm_id` reject path |
| `header_v2_truncated` | well-formed current-version header, truncated mid-body |
| `header_v1_truncated` | accepted legacy version, truncated mid-body |

These were hand-crafted from the documented framing (no crate code was run to
generate them); they are approximate by design — the fuzzer mutates from them.
cargo-fuzz also writes newly-discovered inputs into this directory at runtime;
do not commit those, only meaningful seeds.
