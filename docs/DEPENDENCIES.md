# Dependencies

Every workspace dependency, with a one-line justification. This is the
"minimal, justified surface" referenced by `architecture.md` §9.5 and threat #8
(supply-chain compromise). The source of truth is the root `Cargo.toml`
`[workspace.dependencies]` table; exact resolved versions are pinned in the
committed `Cargo.lock`. Versions below are the conservative *requirement* floors
declared in the manifest, not the resolved patch.

Policy: prefer pure-Rust RustCrypto over FFI; keep the security core
(`passman-crypto`, `-totp`, `-policy`, `-vault`, `-recovery`, `-core`) free of
shell/platform/FFI crates; confine shell-only crates to the binary front-ends.

## Cryptographic primitives (RustCrypto)

Used by `passman-crypto` (and `passman-totp` for the HMAC/SHA path). Pure Rust,
no FFI.

| Crate | Req | Purpose |
|-------|-----|---------|
| `argon2` | 0.5 | Argon2id password key-derivation (master + recovery KDF). |
| `hkdf` | 0.12 | HKDF-SHA256 key combination/derivation (Extract + Expand split). |
| `sha2` | 0.10 | SHA-256, the hash under HKDF and HMAC. |
| `chacha20poly1305` | 0.10 | XChaCha20-Poly1305 AEAD (vault, entry, recovery encryption). |
| `hmac` | 0.12 | HMAC for RFC 6238 TOTP code generation/verification. |
| `sha1` | 0.10 | SHA-1 — **only** inside RFC-6238 TOTP, where the standard mandates it. |
| `subtle` | 2.5 | Constant-time equality for secret/tag comparisons. |
| `zeroize` | 1.7 (`derive`) | Volatile zeroization of secret buffers on drop. |
| `rand` | 0.8 | `OsRng` for nonces, salts, and password generation. |

## Library plumbing

| Crate | Req | Purpose |
|-------|-----|---------|
| `thiserror` | 1.0 | Typed error enums for the library crates (no `anyhow` in libs). |
| `zxcvbn` | 3 | Master/recovery password strength estimation (entropy gates + meter). |

## Serialization & data types

| Crate | Req | Purpose |
|-------|-----|---------|
| `serde` | 1 (`derive`) | (De)serialization of DTOs and the plaintext settings file. |
| `postcard` | 1 (`use-std`, no default features) | Compact, deterministic binary encoding (e.g. `EntryPolicy`). |
| `uuid` | 1 (`v4`, `serde`) | Random `EntryId` generation and (de)serialization. |
| `base32` | 0.5 | TOTP secret encode/decode for the `otpauth://` enrollment URI. |

## Platform shell (`passman-platform`)

Per-platform path resolution and the plaintext, non-secret `settings.toml`
(§1.5). Never pulled into the pure security core.

| Crate | Req | Purpose |
|-------|-----|---------|
| `toml` | 0.8 | Parse/emit the non-secret `settings.toml`. |
| `directories` | 5 | XDG / platform-correct config and data directories. |

## CLI shell (`passman-cli`)

Shell-only; never in the security core.

| Crate | Req | Purpose |
|-------|-----|---------|
| `clap` | 4 (`derive`) | Argument parsing and `--help`/usage (emits exit code 2). |
| `anyhow` | 1 | Binary-side error handling with context chains. |
| `rpassword` | 7 | Hidden (no-echo) master-password and TOTP prompts. |
| `arboard` | 3 | OS clipboard access for the auto-clearing copy flow. |

## GTK desktop shell (`passman-gtk`)

| Crate | Req | Purpose |
|-------|-----|---------|
| `gtk4` | 0.9 | Linux GTK4 desktop front-end. Shell-only. |

## Android binding surface (`passman-uniffi`)

| Crate | Req | Purpose |
|-------|-----|---------|
| `uniffi` | 0.28 | Kotlin/Compose FFI bindings. Pinned to 0.28 — the bindgen must match this exact line. |

## HSM backends (`passman-hsm`, Linux, optional)

Behind opt-in features; never in the default build. Pulled in as
`optional = true`.

| Crate | Req | Purpose |
|-------|-----|---------|
| `keyring` | 3 (`sync-secret-service`, `crypto-rust`) | Software-HSM fallback over Secret Service. **v3, not v4** — v4 dropped the synchronous `sync-secret-service` backend and the raw-secret API this code uses. |
| `tss-esapi` | 7 (no default features) | TPM 2.0 backend (the Linux default HSM). v7 stable, **not** the 8.0.0-alpha; bindings generated from system `libtss2` via `pkg-config`. |

## Process hardening (binary shells only)

| Crate | Req | Purpose |
|-------|-----|---------|
| `libc` | 0.2 | `prctl`/`setrlimit` to suppress core dumps at startup; signal handling for interrupt-safe clipboard clear. Already a transitive dep; declared directly for the shells. Never in the pure libraries. |

## Dev / test

| Crate | Req | Purpose |
|-------|-----|---------|
| `hex-literal` | 0.4 | Inline hex for known-answer / RFC test vectors. |
| `tempfile` | 3 | Isolated temp dirs/files for deterministic filesystem tests. |
