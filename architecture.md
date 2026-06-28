# passman — Architecture & Design

- **Status:** Revised after multi-agent review (rev 2)
- **Date:** 2026-05-28
- **Scope:** Full system design for a highly-secure, local-only password manager targeting Linux (`.deb`), Windows, and Android (sideloaded APK). iOS is deferred.

---

## 0. Revision history

**rev 2 (2026-05-28)** — incorporates a three-agent review (security/crypto, correctness/consistency, library-feasibility). Material changes:

- **Removed cleartext `label_hash`** from entry envelopes. It allowed an offline dictionary attack that recovered labels (rainbow-tableable across users), defeating the sealed-index privacy goal. Envelope identity is already bound by the `id`-derived key + `id`-in-AD, so the hash was redundant.
- **TOTP seed `S` moved to an independent HSM slot and removed from the master-key KDF.** Previously `S` was sealed in the same blob as `K_hsm` and mixed into `K_master`, which added no entropy and overstated TOTP as a co-equal cryptographic factor. `S` is now its own wrapped slot, used only for code verification.
- **Rate limiting is now HSM-native first.** The app-layer counter was forgeable by exactly the attacker it targeted (its MAC key derived from `K_hsm`; the file is rollback-able). The platform HSM's dictionary-attack protection is now the security control; the app timer is retained only for consistent cross-platform UX.
- **Recovery export gated on a Strong master password** (≥70 bits) to prevent a crackable single-factor export.
- **FFI boundary clarified** — the generic `HardwareKeyStore` trait and its `PlatformCtx` stay Rust-internal; `passman-uniffi` exposes concrete, non-generic, per-platform entry points.
- **Argon2 progress** is indeterminate (spinner + elapsed time); the RustCrypto `argon2` crate exposes no per-iteration hook.
- Numerous wire-format, error-taxonomy, concurrency, and reproducibility clarifications (see inline).

---

## 1. Overview

### 1.1 What this is

`passman` is a local-only password manager with a Rust security core and native user interfaces per platform. It generates long, high-entropy passwords, stores them encrypted at rest, and gates access behind **two cryptographic factors** — a master password and a hardware-backed key (TPM/HSM/Secure Enclave) — **plus a TOTP liveness gate** from an external authenticator app, backed by an independently-wrapped seed (see §1.6 for the honest factor analysis).

### 1.2 Goals

- **Local-only.** No sync, no cloud, no account. The vault never leaves the device except via an explicit user-initiated recovery export.
- **Expensive decryption.** Unlocking requires a deliberately costly Argon2id derivation (user-tunable, defaulting to ~2.5 s) plus a hardware-backed unwrap that cannot be parallelized off-device.
- **Hardware-rooted key protection.** The vault key is wrapped by the device's hardware security module (TPM 2.0 on Linux, Platform Crypto Provider on Windows, hardware-backed Keystore on Android). The wrapped key sits on disk; the unwrapping key never leaves the hardware.
- **Strong generation.** Default 40-character passwords over the full printable-ASCII charset (~262 bits), with per-entry policy overrides and a live entropy/crack-time meter.
- **Metadata privacy.** Per-entry encryption with a sealed index — an attacker holding the vault file cannot learn entry labels or contents. (See §4.5 for the exact, exhaustive disclosure surface.)

### 1.3 Non-goals

- No sync or multi-device replication.
- No browser extension or autofill integration in v0.
- No defense against an actively-compromised OS kernel, keylogger, or cold-boot attacker (see §3.3 — explicitly accepted out of scope).
- No iOS build in v0 (designed for, deferred).

### 1.4 Target platforms

| Platform | UI | Package |
|---|---|---|
| Linux | GTK4 (`gtk4-rs`) | `.deb` + standalone binary |
| Windows | `egui` (v0) → native later | NSIS installer + portable `.exe` |
| Android | Jetpack Compose over UniFFI | Sideloaded APK |
| iOS | (deferred) | — |

### 1.5 Vault & settings storage locations

| Platform | Vault file | Settings | Optional log |
|---|---|---|---|
| Linux | `$XDG_DATA_HOME/passman/vault.pmv` (fallback `~/.local/share/passman/`) | `$XDG_CONFIG_HOME/passman/settings.toml` | `$XDG_STATE_HOME/passman/` |
| Windows | `%APPDATA%\passman\vault.pmv` | `%APPDATA%\passman\settings.toml` | `%LOCALAPPDATA%\passman\` |
| Android | app-private internal storage `files/vault.pmv` | `files/settings.toml` | logcat (no file by default) |

Settings are **non-secret** and stored in plaintext TOML *outside* the vault (so options like `update-check` are readable before unlock). Settings never contain vault content, keys, or labels. The set of settings keys is fixed and validated on load.

### 1.6 Honest factor analysis

The system protects `K_master` with **two cryptographic factors**: the master password (something you know) and `K_hsm` (something the device's hardware holds). Both are required to derive `K_master`; neither is recoverable from the vault file alone.

TOTP is a **liveness/possession gate**, not a third cryptographic factor. The reason is fundamental: verifying a TOTP code requires the seed `S` to be present at unlock, so `S` must live on the device — which means it is, at rest, no better protected than anything else on the device. We make TOTP as strong as it can honestly be:

- `S` is stored in its **own independent HSM-wrapped slot**, separate from `K_hsm` (so it does not free-ride on the vault-key unwrap).
- The TOTP code is a **mandatory unlock gate** verified against the independently-unwrapped `S`.
- `S` is **not** mixed into the master-key KDF (it added no entropy there).

What TOTP buys you: defense against an attacker who has your master password and can drive the HSM but cannot produce a current code (e.g., they don't have your authenticator app) — *provided the seed slot is protected by something they lack*. If both HSM slots are gated by the same biometric, an attacker past that biometric obtains both `K_hsm` and `S`. To make TOTP resist a post-biometric on-device attacker, the seed slot can optionally require a **distinct PIN** (`totp.seed_pin`, a knowledge factor separate from the master password). This is offered as a setting and its security implication is documented; it is off by default.

---

## 2. Architecture

### 2.1 Workspace layout

```
passman/
├── crates/
│   ├── passman-crypto/        # Argon2id, HKDF, XChaCha20-Poly1305, secret types
│   ├── passman-totp/          # RFC 6238 verify, skew window, Clock injection
│   ├── passman-vault/         # Vault format, per-entry encryption, sealed index
│   ├── passman-recovery/      # Export/import (password-only KDF)
│   ├── passman-hsm/           # HardwareKeyStore trait + per-platform impls
│   ├── passman-policy/        # Generation, zxcvbn, per-entry overrides
│   ├── passman-core/          # Orchestration, RevealHandle, Clipboard, sessions
│   ├── passman-uniffi/        # UniFFI surface for Kotlin + Swift bindings
│   ├── passman-gtk/           # Linux GUI (gtk4-rs)
│   └── passman-win/           # Windows GUI (egui v0)
├── android/                   # Jetpack Compose UI consuming UniFFI Kotlin
├── ios/                       # (deferred)
├── packaging/                 # .deb, NSIS, signed-APK pipelines
├── ci/                        # boundary-grep, reproducible-build harness
└── architecture.md
```

### 2.2 Dependency graph (one-way, acyclic)

```
gtk / win / uniffi
        │
        ▼
       core ──► totp, vault, recovery, hsm, policy
        │
      vault ──► policy            (the sealed index stores EntryPolicy)
        │
  (every crate above) ──► crypto
```

All crates depend on `passman-crypto`. `passman-vault` additionally depends on `passman-policy` because the sealed index stores `EntryPolicy`. No crate depends on a crate above it; the graph is acyclic. Enforced in CI (§2.4).

### 2.3 Crate responsibilities

| Crate | Owns | Key types | Forbids |
|---|---|---|---|
| **passman-crypto** | Argon2id, HKDF-SHA256, XChaCha20-Poly1305 AEAD, zeroizing secret types | `KdfParams`, `MasterKey`, `EntryKey`, `SecretString`, `SecretArray<N>`, `SecretBytes` | I/O, vault knowledge, platform code |
| **passman-totp** | RFC 6238 verification, skew tolerance, replay cache, `trait Clock` | `TotpVerifier`, `Clock`, `Timestamp` | Persistence, bespoke KDF (uses crypto's HKDF only) |
| **passman-vault** | Binary format (**pure** parse/serialize to/from `&[u8]`), per-entry sealed envelopes, sealed index (incl. `EntryPolicy`), index↔envelope-set check, advisory rate-limit bytes, `VaultMetadata`, version byte; derives `K_index`/`K_entry` from a supplied `K_master` via `crypto::hkdf_expand` | `Vault`, `EntryId`, `EntryRecord`, `EntryHandle`, `VaultVersion`, `VaultMetadata` | filesystem/I/O, master-key derivation (Argon2id/HSM), recovery KDF, platform paths, logging |
| **passman-recovery** | Export/import file format, password-only Argon2id derivation, version byte | `RecoveryExport`, `ExportPayload`, `RecoveryError` | Runtime vault internals (round-trips via DTOs), HSM |
| **passman-hsm** | `HardwareKeyStore` trait, two-phase unwrap, two slots, `PlatformCtx`, `BiometricPrompter`, wrap-blob format, native DA-lockout surfacing | `HardwareKeyStore`, `WrappedBlob`, `UnwrapHandle`, `HsmError`, `HsmCapabilities`, `HsmSlot` | File I/O, vault format, cross-call caching |
| **passman-policy** | Generation (OsRng), zxcvbn entropy, crack-time estimation, per-entry policy validation | `PasswordPolicy`, `Charset`, `GenerationRequest`, `MasterEntropy` | I/O, vault |
| **passman-core** | Unlock/creation flows, master-key derivation orchestration, **atomic vault file I/O (temp+fsync+rename) and the single-instance lock**, session timer, `RevealHandle`, `Clipboard` trait, advisory lockout UX, `Clock`/`Progress`/`Spawner` plumbing, `SessionToken` | `App`, `UnlockedApp`, `RevealHandle`, `SessionToken` | Rendering, platform event loops, direct crypto primitives |
| **passman-uniffi** | Concrete, non-generic, per-platform binding surface for Kotlin + Swift | mirrors a monomorphized `passman-core` API | Logic; pure binding crate |
| **passman-gtk / passman-win** | Window, widgets, event handling | — | Reaching past `passman-core` |

### 2.4 Enforcement

- `#![forbid(unsafe_code)]` in `crypto`, `vault`, `policy`, `core`, `totp`, `recovery`.
- `clippy::disallowed_methods` blocks `std::fs`, `std::net`, `std::env` in `crypto`, `vault`, `policy`.
- `clippy::disallowed_macros` blocks `tracing::*` in `passman-crypto` (zero logging).
- CI greps for `cfg(target_*)` outside `passman-hsm` and fails the build if found elsewhere.
- `cargo audit`, `cargo deny`, and the boundary checks gate merges. Binary parsers (`passman-vault`, `passman-recovery`) are fuzzed (`cargo fuzz`) — they are the highest-risk attack surface (parsing attacker-controlled files).

### 2.5 Async posture

`passman-core` is **synchronous**. There is no async runtime in the workspace (confirmed compatible with UniFFI, which does not force async).

- Argon2id runs on a caller-supplied blocking pool via a `&dyn Spawner`. The foreign side (Kotlin/Swift) is responsible for calling unlock off its main thread.
- HSM operations take a `&dyn BiometricPrompter` so platform impls drive their native prompts using platform-native blocking.
- Long KDF operations report progress via `&dyn Progress` whose contract is **start / heartbeat / end** (a shell-owned timer drives the heartbeat) — **not** per-iteration, because the `argon2` crate exposes no incremental hook. The UI shows an indeterminate bar with elapsed time, never a deterministic `t/T` counter.
- All foreign-implemented callback trait methods (`BiometricPrompter`, `Progress`, `Spawner`) return `Result<…>` (an error in a foreign callback otherwise panics across FFI) and take **owned** parameters at the FFI boundary (UniFFI foreign traits cannot take references).

---

## 3. Threat model

### 3.1 Assets

1. Master password (`P`) — never stored.
2. Vault contents (per-entry: label, username, password, URL, notes, policy).
3. TOTP seed (`S`) — long-term shared secret with the user's authenticator app.
4. Hardware-wrapped keys (`K_hsm`, and the seed slot) — unwrappable only by the device hardware.

### 3.2 Adversary capabilities (in scope)

- Full read/write access to the vault file and recovery exports at rest (including rollback to earlier snapshots and local clock control).
- Network observation (though the default binary is network-silent — §9.6).
- Theft of the device while locked.
- A second local process / second app instance.

### 3.3 Accepted risks (explicitly out of scope)

- Active kernel-level malware on an unlocked system.
- Keyloggers capturing the master password as typed.
- Cold-boot attacks recovering RAM after power-off (no userspace RAM encryption exists on consumer hardware).
- Microarchitectural side-channels (Spectre-class) in the broader process.
- HSM hardware extraction / cloning (relies on platform hardware guarantees).
- Rooted/jailbroken mobile devices.

### 3.4 Dominant residual risk

Because verifying TOTP requires `S` on-device and because the recovery export is single-factor, the **recovery export is the dominant residual risk**: its security equals master-password strength (hence the Strong-password gate, §7.5). And once an attacker is past the HSM biometric on a stolen device, they hold `K_hsm` (and `S` unless a distinct seed PIN is set), leaving the master password as the effective barrier. These are foregrounded honestly rather than masked by a "three independent factors" claim.

---

## 4. Cryptographic design

### 4.1 Primitives (fixed — no bespoke cryptography)

| Purpose | Algorithm | Crate |
|---|---|---|
| Password KDF | Argon2id | `argon2` (RustCrypto) |
| Key combination / derivation | HKDF-SHA256 | `hkdf` (RustCrypto) |
| AEAD | XChaCha20-Poly1305 (192-bit nonce, 128-bit tag) | `chacha20poly1305` (RustCrypto) |
| RNG | `OsRng` | `rand_core` |
| Constant-time compare | `subtle::ConstantTimeEq` | `subtle` |
| TOTP inner hash | HMAC-SHA1/SHA256 (RFC 6238) | `hmac` + `sha1`/`sha2` |

Banned: SHA-1 (except inside RFC-6238 TOTP where the standard mandates it), MD5, AES-CBC, PBKDF2, any hand-rolled construction.

`KdfParams` canonical encoding (used identically in vault header and recovery header): `m: u32-LE (KiB) ‖ t: u32-LE ‖ p: u8` = 9 bytes.

### 4.2 Key hierarchy

```
P ──Argon2id(vault_salt, params)──► K_pw  ┐
                                          ├─HKDF-Extract+Expand(salt=vault_salt, info="passman-master-v0")─► K_master
HSM.unwrap(slot=VaultKey) ──► K_hsm ──────┘                                  │
                                                                             ├─HKDF-Expand("index-v0")────► K_index
                                                                             ├─HKDF-Expand("entry-v0:"+id)► K_entry(id)
                                                                             └─ probe AEAD verifies K_master

HSM.unwrap(slot=TotpSeed) ──► S   (used ONLY by passman-totp to verify the code; NOT a KDF input)
```

`S` is no longer in the master-key IKM. `K_hsm` is a full 256-bit random key — maximal for a 256-bit `K_master`.

### 4.3 Unlock pipeline

```
unlock(P, totp_code, hsm_ctx, prompter, spawner, progress) -> Result<UnlockedApp>:
    0. acquire single-instance lock on the vault path (else: refuse, focus existing)
    1. h1 ← HSM.begin_unwrap(VaultKey, k_hsm_blob, hsm_ctx)
       K_hsm ← HSM.complete_unwrap(h1, prompter)              // biometric prompt fires here
       on HsmError::{Transient,Cancelled}      → return Err WITHOUT touching counters
       on HsmError::{PermanentlyInvalidated,HardwareAbsent} → return Err RouteToRecovery
    2. h2 ← HSM.begin_unwrap(TotpSeed, totp_blob, hsm_ctx)
       S ← HSM.complete_unwrap(h2, prompter)                  // may require distinct PIN if enabled
    3. check HSM-native DA lockout status (authoritative); if locked → return Err Locked
       (advisory app-timer check is for UX messaging only — see §4.9)
    4. TOTP.verify(S, totp_code, clock.now())                 // fail-fast; on fail → Err (counts as attempt)
    5. K_pw ← Argon2id(P, vault_salt, kdf_params)             // on spawner's blocking pool; indeterminate progress
    6. K_master ← HKDF-Extract-and-Expand(
           salt = vault_salt,
           ikm  = K_pw ‖ K_hsm,
           info = "passman-master-v0", L = 32)
    7. probe ← XChaCha20-Poly1305.decrypt(
           K_master, probe_nonce, probe_ct,
           ad = format_version ‖ kdf_algorithm_id ‖ KdfParams ‖ vault_salt ‖ "probe-v0")
       require probe == b"PASSMAN_VAULT_v0"                   // wrong creds or header-tamper → AEAD fail
    8. K_index ← HKDF-Expand(K_master, "index-v0", 32)
       index   ← XChaCha20-Poly1305.decrypt(K_index, idx_nonce, idx_ct, ad = format_version)
    9. require {present envelope ids} == {ids listed in index}  // else: tamper → fail closed
    10. zeroize K_pw, K_hsm, S, and the IKM buffer
    11. return UnlockedApp { K_master, K_index, index, session_expiry = clock.now() + 120s }
```

The probe AD now authenticates the header's security-critical parameters directly (closes the rev-1 reliance on derived-key-mismatch).

### 4.4 Per-entry encryption

```
K_entry(id) = HKDF-Expand(PRK = K_master, info = b"entry-v0:" ‖ id, L = 32)
```

`id` is a fixed 16-byte UUIDv4 generated from `OsRng` (so the `info` prefix is unambiguous and ids don't collide). Each entry is its own AEAD invocation with a fresh random 192-bit nonce. **AD = `format_version ‖ id`.** Identity is bound two ways: the key itself is derived from `id`, and `id` is in the AD — so an envelope cannot be moved to another id's slot. (The rev-1 cleartext `label_hash` is removed; it was redundant for this and leaked labels.)

Passwords are decrypted **on demand** (at copy/reveal), never in bulk at unlock. Only labels (from the index) are in memory while unlocked.

### 4.5 Sealed index and exact disclosure surface

The index is a single AEAD blob under `K_index` containing the authoritative list of `{id, label, per-entry-policy}`. Labels and policies live only inside this ciphertext. On unlock the present envelope-id set must exactly equal the index id set (§4.3 step 9); any mismatch (missing/extra/duplicate) is treated as tampering and fails closed.

An attacker holding the vault file learns **exactly** this and nothing more:

- file `format_version`, `kdf_algorithm_id`, and Argon2 params (m/t/p);
- `vault_salt`, `probe_nonce`, `probe_ct`;
- the two opaque HSM wrap blobs and their lengths;
- the sealed-index ciphertext length;
- the **advisory** rate-limit counter and last-failure time (plaintext — see §4.9; explicitly *not* claimed secret);
- `last_password_change` and `last_export_at` timestamps (plaintext metadata);
- the number of entries and the bucketed (256-byte-quantized) size of each envelope.

It does **not** learn any label, any field, or which service any entry belongs to. (The timestamps and entry count are an acknowledged minor metadata leak; if a future version wants them hidden, they move inside the sealed index.)

### 4.6 Domain-separation strings (versioned)

| Use | `info` string | PRK |
|---|---|---|
| Master derivation | `passman-master-v0` | (Extract over `K_pw ‖ K_hsm`) |
| Index key | `index-v0` | `K_master` |
| Per-entry key | `entry-v0:` ‖ `id` | `K_master` |
| Recovery export key | `recovery-export-v0` | (Extract over `K_recovery_pw`) |

HKDF-**Expand** steps correctly take no salt (the PRK is already a uniform 256-bit key). This is intentional, not a missing-salt bug.

### 4.7 Vault file layout (binary, fixed-order; all offsets past 101 are computed sequentially — no absolute offset beyond 101 is valid)

```
off  size               field
0    1                  format_version            (0x01)
1    1                  kdf_algorithm_id          (0x00 = Argon2id)
2    4   u32-LE         argon2.m (KiB)
6    4   u32-LE         argon2.t
10   1                  argon2.p
11   32                 vault_salt
43   24                 probe_nonce
67   32                 probe_ct                  (16-byte payload + 16-byte tag)
99   2   u16-LE         k_hsm_wrap_blob_len
101  N                  k_hsm_wrap_blob           (opaque to vault)
‖    2   u16-LE         totp_seed_wrap_blob_len
‖    M                  totp_seed_wrap_blob       (opaque to vault)
‖    8   u64-LE         rl_counter                (advisory; NOT a security boundary)
‖    8   i64-LE         rl_last_failure           (unix seconds; 0 = none)
‖    8   i64-LE         meta.last_password_change (unix seconds)
‖    1                  meta.last_export_present  (0x00 absent / 0x01 present; else reject)
‖    8   i64-LE         meta.last_export_at       (unix seconds; 0 when absent)
‖    24                 sealed_index_nonce
‖    4   u32-LE         sealed_index_ct_len
‖    K                  sealed_index_ct + tag
‖    4   u32-LE         entries_count             (0 is valid — empty vault)
‖    …                  EntryEnvelope[entries_count]
```

`EntryEnvelope`:
```
16                      entry_id (UUIDv4 from OsRng)
24                      nonce
4   u32-LE              ct_len   (on-disk PADDED ciphertext length)
N                       ciphertext + 16-byte tag (padded to 256-byte buckets;
                        the real plaintext length is stored INSIDE the
                        authenticated plaintext and stripped after decrypt)
```

Parsing rules: read exactly `entries_count` envelopes; EOF-before-count or trailing-bytes-after-count is a hard format error (fail closed). Saves are atomic: write temp, fsync, rename over the original; every save rewrites the whole file (deletion leaves no residue; buckets hide size class). A single-instance advisory lock (`flock` / named mutex) guards against two instances racing a save.

### 4.8 Argon2id parameter presets

| Preset | m (RAM) | t | p | ~wall-time (M2 / Ryzen 7) |
|---|---|---|---|---|
| Low (floor) | 256 MiB | 4 | 1 | ~0.6 s |
| Medium (default) | 1 GiB | 4 | 1 | ~2.5 s |
| High | 4 GiB | 6 | 1 | ~12 s |

`p = 1` deliberately: memory cost is the real GPU/ASIC barrier; raising `p` mostly helps the attacker too.

**Mobile default — Low.** The Android front-end defaults vault creation to the **Low** preset (256 MiB / t = 4), labelled "Low (recommended)" in the create screen, because phones cannot spare the 1 GiB the desktop Medium default uses without OOM risk. Desktop (CLI/GTK) still defaults to Medium.

**Anti-DoS ceiling (untrusted-header guard).** Argon2 cost parameters reach `passman-crypto` from attacker-controllable on-disk headers (vault and recovery files), and the `argon2` crate itself caps `m`/`t` only near `u32::MAX`. A hostile header could therefore demand a multi-terabyte allocation or multi-hour derivation **before** authentication can fail — a pre-auth resource-exhaustion DoS (fatal on mobile). `passman-crypto` defines a universal *ceiling* — `MAX_M_KIB = 8 GiB`, `MAX_T = 24`, `MAX_P = 16` — enforced by `KdfParams::within_limits()` at **both** parser boundaries (`vault::from_bytes`, `recovery::import`) and again inside the derivation as a backstop, so no path can run an out-of-range cost. The ceiling sits at the strongest shipped preset (recovery "Paranoid" = 8 GiB / t = 12), so every legitimate configuration is still admitted. This is a **ceiling**, not a floor: the per-context strength *floor* (the recovery export floor in §7.4) is a separate, export-side caller policy.

### 4.9 Lockout: HSM-native primary, app-timer advisory

The **security control is the platform HSM's own dictionary-attack protection** — TPM 2.0 DA lockout, Android Keystore auth-bound key attempt limits, Windows NCrypt anti-hammering. These enforce state an attacker who holds `K_hsm` cannot rewrite, which is the only kind of rate-limit that binds a post-unwrap attacker. `HsmCapabilities` (§6.1) surfaces `max_attempts_before_lockout` and `lockout_recovery` so the UI can explain platform behavior.

**Backend reality — the DA lockout only engages where the key is genuinely auth-bound.** Android Keystore per-use auth (§6.4) binds it; **the shipped default Linux TPM2 backend does not.** It seals `K_hsm` and the TOTP seed as null-auth `KEYEDHASH` objects (no per-vault `authValue`), so an unseal never fails and the TPM's DA counter never increments — the hardware DA lockout therefore does **not** trigger on the default desktop. There, the throttle on online guessing is the **Argon2id work factor (§4.8 floor) plus a strong master password**, with the advisory timer below as the rest; `max_attempts_before_lockout` is reported as `None` so the UI can say so. MAC'ing the advisory counter with an HSM-derived key would **not** fix this: the in-scope attacker holds the device and can null-auth-unwrap `K_hsm`, so they could forge any HSM-keyed MAC and still roll the counter back. The genuine fix — binding a per-vault `authValue` (a PIN derived from the master password) to the TPM2 objects so wrong attempts hammer the TPM DA counter — is tracked as future work (§13).

On top of that, `passman-core` keeps an **advisory** timer implementing the schedule below, purely for **consistent cross-platform UX messaging** (and as the only (weak) backstop on the SecretService fallback, where there is no hardware DA — documented as weak there). The advisory counter/last-failure live in the vault header in plaintext. It is **explicitly not a security boundary**: an attacker with the file can roll it back or (after unwrap) ignore it. We do not HMAC it with an HSM-derived key, because doing so would falsely imply it is a control.

Advisory schedule: `lockout_minutes(n) = if n < 3 { 0 } else if n >= 11 { 1440 } else { min(10 * 2^(n-3), 1440) }` (the `n >= 11` guard prevents shift overflow). Rejection predicate: reject while `clock.now() < rl_last_failure + lockout_minutes(rl_counter) * 60`. A negative delta (clock moved backward) is clamped to "remain locked for the maximum remaining" (fail-closed). Counter resets to 0 on success.

### 4.10 Versioning

Version bytes on: vault header (`0x01`), each HSM wrap blob, recovery export (`0x01`), and every AEAD's associated data. The probe AD additionally binds the KDF algorithm id, Argon2 params, and salt. Mismatch aborts loudly. Each `v0`/`v1` suffix on a domain-separation string is a rotation hook.

---

## 5. Session lifecycle & runtime security

### 5.1 State machine

```
Locked ──unlock()──► Unlocking (HSM×2 → DA-check → TOTP → Argon2 → probe → set-check) ──► Unlocked
  ▲   ▲                    │ failure (TOTP/probe)                                            │
  │   │                    ▼                                                                 │
  │   │              advisory counter++                                                      │
  │   │              HSM-native DA may lock                                                  │
  │   └──(lockout elapsed / HSM DA cleared)── Locked-out ◄───────────────────────────────────┘
  │                                                            (on DA lock or advisory ≥3)
  └────────────────────────────────────────────────────────────────────────────────────────
        (session timer expired / explicit lock / mobile backgrounded / 30s after copy/reveal)
```

`UnlockedApp` holds `K_master`, `K_index`, decrypted index (labels only), `session_expiry`, `last_reveal_or_copy`, and a `SessionToken`. All secret material is zeroizing and zeroed on drop.

`SessionToken` is an opaque, process-local, unforgeable handle (a random 256-bit value held only in `passman-core`) that the UI presents on each privileged call to prove it is acting within the current unlocked session. It is never persisted, never crosses a network, and is invalidated on lock. Sensitive operations that must resist a hijacked session (export — §7.5) require **fresh re-authentication**, not merely a valid token.

### 5.2 Session timeout

- Hard 120 s from unlock — **no sliding**; activity does not extend it.
- After any copy/reveal: `session_expiry = min(session_expiry, last_reveal_or_copy + 30 s)`.
- Mobile backgrounding (`onPause` / `applicationWillResignActive`) triggers immediate lock.

### 5.3 Clipboard flow

```rust
pub trait Clipboard: Send + Sync {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie>;
    fn clear_if_matches(&self, cookie: &ClipboardCookie) -> Result<ClearOutcome>;
}
pub struct ClipboardCookie { digest: [u8; 32], written_at: Timestamp } // Timestamp from injected Clock; process-local, never serialized
pub enum ClearOutcome { Cleared, StillOurs, Replaced, Empty, Unavailable }
```

`copy_to_clipboard(id)`: decrypt the entry into a stack-bound `SecretString`, `write` it (returns a SHA-256 cookie), drop/zeroize the plaintext, schedule a 30 s timer (against the injected `Clock`). At 30 s, `clear_if_matches` reads the current clipboard, constant-time-compares its hash to the cookie, and clears only if still ours. The read buffer is zeroized after comparison.

**Clear-by-overwrite:** instead of writing empty, the clear writes a randomly-chosen short fact from a compile-time pool (`passman-core::clipboard::FACTS`). Pasting it shows the secret is gone; clipboard-history apps capture the fact, not the secret. Toggle `clipboard.fact_overwrite` (default `true`).

Per-platform read/clear: X11 (`XGetSelectionOwner`/empty selection), Wayland (`wl_data_device`), Windows (`GetClipboardData`/`EmptyClipboard` + exclude-from-history hint), Android (`getPrimaryClip`/`clearPrimaryClip` + `EXTRA_IS_SENSITIVE` on 13+).

**Known limitation:** third-party clipboard-history managers (`gpaste`, `clipit`, Windows Clipboard History) may capture the secret before our clear. Documented; partly mitigated by the OS exclude hints and the fact-overwrite.

### 5.4 Reveal flow

**Desktop:** `unlocked.with_revealed(id, |plaintext: &str| { … })` — plaintext lives only for the closure, then zeroized. UI sets a 10 s auto-hide; on hide, widget text is cleared (`RtlSecureZeroMemory` on Windows where we own the buffer). On Linux/GTK, the default `GtkEntryBuffer` zeroes vacated text on `delete_text` (verified in GTK source) — but note this does **not** scrub copies left by buffer *reallocation* during typing; for the master-password entry specifically, use a `GtkEntryBuffer` subclass backed by non-pageable/secure memory (GTK documents this pattern).

**Mobile (UniFFI):** `core.reveal_password(id) -> String`. UniFFI cannot represent a zeroizing string, so Kotlin/Swift hold a managed `String` for the visible duration (accepted relaxation — §12). Mitigations: reveal widget defaults to obscured (`inputType=textPassword` / `isSecureTextEntry`), tap-to-show, 10 s auto-hide, `FLAG_SECURE` to block screenshots/recording/app-switcher snapshots. The common operation (copy) never crosses the FFI with plaintext.

### 5.5 Logging policy

`tracing` everywhere; CI-enforced content restrictions:

| Crate | Levels | Never logs |
|---|---|---|
| crypto | none (compile error on `tracing::*`) | — |
| vault | `error!` (file-format only) | bytes; only offsets + error kinds |
| totp | `error!` | seeds, codes |
| recovery | `error!` | passwords, plaintexts, salts |
| policy | `debug!`/`info!` | candidate passwords |
| core | full | plaintexts, keys, salts (labels only at `debug!`) |
| hsm impls | `error!`/`info!` | wrap blobs, plaintexts |
| UI | `info!`/`warn!`/`error!` | any vault content |

Default destination stderr; file logging opt-in, rotated at 1 MiB × 5.

---

## 6. HSM / hardware-backed key storage

### 6.1 Trait

```rust
pub enum HsmSlot { VaultKey, TotpSeed }

pub trait HardwareKeyStore: Send + Sync {
    type PlatformCtx: ?Sized;                 // Rust-internal ONLY; never crosses the FFI

    fn kind(&self) -> HsmKind;
    fn capabilities(&self) -> HsmCapabilities;

    // enroll takes a prompter: on Android, per-use auth fires a biometric prompt on ENCRYPT too
    fn enroll(&self, slot: HsmSlot, material: &SecretBytes,
              ctx: &Self::PlatformCtx, prompter: &dyn BiometricPrompter)
        -> Result<WrappedBlob, HsmError>;

    fn begin_unwrap(&self, slot: HsmSlot, wrapped: &WrappedBlob, ctx: &Self::PlatformCtx)
        -> Result<UnwrapHandle, HsmError>;
    fn complete_unwrap(&self, handle: UnwrapHandle, prompter: &dyn BiometricPrompter)
        -> Result<SecretBytes, HsmError>;

    fn invalidate(&self, slot: HsmSlot, wrapped: &WrappedBlob, ctx: &Self::PlatformCtx)
        -> Result<(), HsmError>;
}

/// Opaque, Send, single-use, zeroize-on-drop. Holds the transient session state
/// between the two unwrap phases (e.g. a TPM session handle). Dropping it without
/// completing cleans up the session.
pub struct UnwrapHandle { /* opaque */ }

pub trait BiometricPrompter: Send + Sync {
    fn prompt(&self, reason: String) -> Result<PromptResult, PromptError>;  // owned param for FFI
}
pub enum PromptResult { Authenticated, FallbackToPin(SecretString), Cancelled }

pub enum HsmError {
    Transient,               // retryable; caller must NOT count as a failed attempt
    Cancelled,               // user cancelled; caller must NOT count as a failed attempt
    HardwareAbsent,          // HSM not available this session; guide user, do not penalize
    PermanentlyInvalidated,  // key gone (biometric re-enroll / TPM cleared); route to recovery import
    Backend(String),
}

pub struct HsmCapabilities {
    pub biometric_supported: bool,
    pub strongbox_backed: bool,
    pub pcr_bound: bool,
    pub max_attempts_before_lockout: Option<u32>,
    pub lockout_recovery: LockoutRecovery,
    pub supports_distinct_slot_pin: bool,      // for the optional TOTP-seed PIN (§1.6)
}
pub enum LockoutRecovery { TimeBased { reset_after: Duration }, FactoryResetOnly, UserAccountReset }
```

Two-phase unwrap lets `complete_unwrap` drive a native biometric prompt. Each slot (`VaultKey`, `TotpSeed`) is an independent wrapped blob. The error taxonomy is mapped by `passman-core` exactly as in §4.3 (transient/cancelled never penalize; permanent routes to recovery).

### 6.2 Capability discovery & fallback

| Platform | 1st choice | Fallback | Software last resort |
|---|---|---|---|
| Linux | TPM2 (`tss-esapi`) | SecretService (libsecret) | Refused unless `--allow-software-hsm` + loud warning |
| Windows | NCrypt Platform Crypto Provider | NCrypt KSP (software) | Same opt-in |
| Android | StrongBox-backed Keystore | TEE-backed Keystore | Refused (software Keystore below threshold) |
| iOS | Secure Enclave | — | — |

The user is shown the chosen backing tech at vault creation; creation aborts if nothing acceptable is available and no opt-in flag was passed. *(Hardware limitations are the user's responsibility, not the app's.)* On the SecretService fallback there is no hardware DA lockout — the advisory app timer is the only backstop and is documented as weak.

### 6.3 Wrap-blob outer format (opaque to vault; one per slot)

```
0   1   blob_version (0x00)
1   1   hsm_kind  (0=TPM2, 1=NCrypt RSA-OAEP, 2=Android AES-GCM, 3=Secure Enclave, 4=SecretService)
2   2   payload_len (u16-LE)
4   N   payload (hsm-kind-specific)
```

No HMAC on the blob — integrity propagates through the AEAD-probe chain (a tampered `VaultKey` blob yields a wrong `K_master`, failing the probe; a tampered `TotpSeed` blob fails the TOTP check). Both are fail-closed (DoS by file corruption is accepted, §11).

### 6.4 Per-platform payload specs

All variable-length names below are length-prefixed (`name_len: u16-LE`) so the platform impl can find field boundaries.

**TPM2 (`0x00`):** `pcr_policy_present(1) ‖ enrollment_uuid(16) ‖ pub_len(2,LE) ‖ TPM2B_PUBLIC ‖ priv_len(2,LE) ‖ TPM2B_PRIVATE`. Parent = SRK at persistent handle `0x81000001` (created via `create_primary` + `evict_control` using the standard TCG SRK template; handle-in-use is handled gracefully). Sealed data = `slot_tag(1) ‖` the slot's 32-byte secret — the leading slot tag is covered by the TPM sealed-object integrity, so a blob presented for the wrong slot is cryptographically rejected on unseal (the TPM-enforced form of the `HsmSlot` binding the mock and SecretService backends also provide). Optional `authValue` PIN (SHA-256-prehashed). Optional PCR policy over PCR[0,2,4,7] — **off by default** (would force re-enroll on firmware/bootloader updates). `swtpm` is used for CI.

**Windows NCrypt (`0x01`):** `name_len(2,LE) ‖ key_name(UTF-16) ‖ ct_len(2,LE) ‖ RSA-OAEP-SHA256(secret)`. 2048-bit RSA via `MS_PLATFORM_CRYPTO_PROVIDER` (TPM-backed) preferred. 64-byte-or-less payload fits with margin (OAEP-SHA256 max = 190 bytes for RSA-2048). Hello-gated via user-presence/UI-protect flags (exact `windows-rs` constant names verified at first build via `cargo doc`; raw `NCRYPT_FLAGS(value)` is the fallback). TPM RSA is slow but this is a once-per-unlock op.

**Android Keystore (`0x02`):** `name_len(2,LE) ‖ alias(UTF-8) ‖ gcm_iv(12) ‖ ct_len(2,LE) ‖ AES-256-GCM(secret)+tag`. `KeyGenParameterSpec` with `PURPOSE_ENCRYPT|DECRYPT` (not `WRAP_KEY`), `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)` (**API 30+**; pin `minSdk ≥ 30` or add the deprecated `setUserAuthenticationValidityDurationSeconds(-1)` fallback), `setIsStrongBoxBacked(true)` where available, `setInvalidatedByBiometricEnrollment(true)`. **The GCM IV is Keystore-generated and read back via `cipher.getIV()`** (a caller-supplied IV is rejected). Because per-use auth gates `Cipher.init(ENCRYPT)` too, **enrollment also fires a biometric prompt** — the `enroll` signature takes a prompter for this reason. The optional distinct TOTP-seed PIN maps to `DEVICE_CREDENTIAL`-only auth on that slot.

**Secure Enclave (`0x03`, deferred):** EC P-256 with `kSecAttrTokenIDSecureEnclave`; ECIES-style wrap; `LAContext` drives Face/Touch ID.

**SecretService (`0x04`):** payload = `vault_uuid(16)`. Key material lives in the OS keyring (collection `default`, label `passman-{slot}-{uuid}`). Trust = session-login gate; weaker, documented at creation; no hardware DA.

### 6.5 The FFI boundary (generics resolved)

UniFFI cannot export generics or an associated `PlatformCtx`. Therefore:

- The `HardwareKeyStore` trait, its associated `PlatformCtx`, and any `App::unlock<H>` generic are **Rust-internal only** and never appear in the UniFFI surface.
- `passman-uniffi` exposes a **concrete, non-generic** `App` whose methods are monomorphized for the platform the binding is compiled for (`#[cfg(target_os = …)]` selects the concrete `H`: `AndroidKeystore`, etc.).
- `PlatformCtx` (`HWND`, `&JObject`, `&TctiContext`, `&LAContext`) is **constructed inside the binding crate** from an opaque handle the foreign side passes (e.g. the Android `Activity` reference obtained via JNI). The raw platform handle never crosses the UniFFI boundary as a typed value.
- Foreign-implemented callbacks (`BiometricPrompter`, `Progress`, `Spawner`) use `#[uniffi::export(with_foreign)]`, return `Result`, and take owned parameters.

Concrete per-platform `PlatformCtx`:

| Platform | `PlatformCtx` (Rust-internal) |
|---|---|
| Linux TPM2 | `()` |
| Linux SecretService | `()` |
| Windows | `HWND` |
| Android | `&JObject` (Activity) |
| iOS | `&LAContext` |

The Linux backends take `PlatformCtx = ()`: the desktop shell injects no handle. Each self-manages its own resource — the TPM2 backend opens its own `tss-esapi` `Context` (targeting `/dev/tpmrm0` or a `TCTI` env override) per operation, and the SecretService backend opens its own D-Bus connection per `keyring::Entry` call.

### 6.6 Rotation / re-enrollment (crash-safe across two stores)

The HSM object (or keyring entry) and the vault file are separate stores, so rotation must be ordered to survive a crash:

1. Create the **new** HSM-wrapped blob(s) and ensure they are durable (TPM object persisted / keyring written).
2. Write the new vault header referencing the new blob(s) via temp-file + fsync + atomic rename.
3. Only after the rename succeeds, `invalidate` the old HSM object.

A crash before step 2 completes leaves the old blob still referenced and valid (no loss). A crash between 2 and 3 leaves a stale HSM object that is simply garbage (detectable via `enrollment_uuid`). Forced loss (TPM cleared / biometric re-enroll / account reset) makes a slot `PermanentlyInvalidated`; the **only** path back is a recovery import (§7) — by design.

---

## 7. Recovery (export / import)

### 7.1 Key hierarchy (password-only)

Recovery exists for when the HSM is gone, so it must decrypt with `P` alone — the **only** single-factor path in the system.

```
K_recovery_pw = Argon2id(P, recovery_salt, recovery_params)
K_recovery    = HKDF-Extract-and-Expand(salt=recovery_salt, ikm=K_recovery_pw, info="recovery-export-v0", L=32)
```

The TOTP seed `S` travels inside the encrypted payload so the user can re-provision their authenticator. (`S` is no longer a KDF input anywhere, so it is carried purely for re-provisioning.) Neither `K_hsm` nor any HSM material is in the export — fresh slots are enrolled on import.

### 7.2 Recovery file format

```
0   6   magic = b"PSMREC"
6   1   format_version (0x01)
7   1   kdf_algorithm_id (0x00 = Argon2id)
8   4   argon2.m (u32-LE)
12  4   argon2.t (u32-LE)
16  1   argon2.p
17  32  recovery_salt
49  24  nonce
73  4   payload_ct_len (u32-LE)
77  N   XChaCha20-Poly1305 ciphertext + tag   (AD = b"PSMREC-v0")
```

### 7.3 Encrypted payload

```
1   payload_version (0x01)
32  totp_seed S                       (for authenticator re-provisioning; NOT a KDF input)
4   original_argon2.m  (u32-LE)       mirrors §4.7 byte-for-byte
4   original_argon2.t  (u32-LE)
1   original_argon2.p
4   entry_count (u32-LE)
entries[entry_count]:
    16              entry_id
    4 u32-LE + len  label    (UTF-8)
    4 u32-LE + len  username (UTF-8)
    4 u32-LE + len  password (UTF-8)
    4 u32-LE + len  url      (UTF-8)
    4 u32-LE + len  notes    (UTF-8)
    4 u32-LE + len  policy   (postcard-encoded EntryPolicy)
```

All length prefixes are `u32-LE`. `EntryPolicy` is serialized with `postcard` (a compact, deterministic, no-std-friendly format) so it round-trips identically on import. There is **no inner checksum** — the AEAD tag already guarantees integrity bit-for-bit; a redundant hash would add nothing and was removed.

### 7.4 Recovery Argon2id presets (intentionally aggressive)

| Preset | m | t | p | ~time |
|---|---|---|---|---|
| Floor (refused below) | 1 GiB | 4 | 1 | ~2.5 s |
| Default | 4 GiB | 8 | 1 | ~15 s |
| Paranoid | 8 GiB | 12 | 1 | ~45 s |

Because the `argon2` crate has no progress hook, the UI shows an **indeterminate** progress indicator with **elapsed time** ("Deriving recovery key… 12s"), running on the blocking pool — not a deterministic step counter.

### 7.5 Export flow

Requires a fully-unlocked session **and** fresh re-authentication (master password + TOTP code + biometric) — independent of the `SessionToken`, so malware holding a session cannot export. **Export is refused unless the master password is Strong (≥55 zxcvbn-bits)** (§8.4 — `StrengthTier::allows_export`), so a single-factor export can never be weaker than its password by design. Then: walk vault → decrypt each entry into an `ExportPayload` → Argon2id(P) → HKDF → AEAD-encrypt → atomic write → zeroize buffers → show offline-storage reminder.

### 7.6 Import flow

Read header → prompt `P` → Argon2id → HKDF → AEAD-decrypt (wrong `P` → tag fail) → show content summary for confirmation → enroll **two** fresh HSM slots on the destination (`VaultKey` = new random `K_hsm`; `TotpSeed` = `S` from payload) → display `S` as an `otpauth://` QR (with `algorithm=` and `digits=` set explicitly) for re-provisioning → derive fresh `K_master` from `K_pw ‖ K_hsm` → re-encrypt every entry with fresh salts/nonces → build sealed index → write new vault. Import deletes no source file.

### 7.7 Master-password-change invalidation

`VaultMetadata { last_password_change, last_export_at }` is tracked. On password change, a modal warns that existing exports cover only historical state and offers to regenerate. If skipped, a persistent dismissable banner appears until resolved. Old exports remain cryptographically valid (we cannot revoke files on the user's media) — documented behavior. A password change that would drop below the Strong tier while an export exists prompts an extra warning.

### 7.8 What recovery does not protect

| Scenario | Outcome |
|---|---|
| Forgotten master password | Permanently unreadable (by design) |
| Lost HSM **and** no recovery file | Permanently unreadable (stern reminder at creation) |
| Export stolen + master password known/guessed | Full disclosure; the Strong-password gate (§7.5) + aggressive Argon2 (4 GiB/8) is the only barrier — this is the dominant residual risk (§3.4) |
| Forged entry inserted into export | Fails the AEAD tag (the tag is the integrity control) |
| Old export after password change | Decrypts to old contents; user warned to regenerate |

---

## 8. Password generation & policy

### 8.1 Generation algorithm (`passman-policy`)

```
generate(req) -> SecretString:
    1. effective = (lower|upper|digits|symbols) - disallow ;  assert |effective|≥2, Σmin ≤ length
    2. place required-class minimums (uniform_random_from each class ∩ effective)
    3. fill remainder uniform_random_from(effective)
    4. Fisher-Yates shuffle (OsRng)
```

`uniform_random_from` uses rejection sampling on `OsRng` to avoid modulo bias. `OsRng` only — no PRNG seeds.

### 8.2 Charset & policy model

```rust
pub struct Charset { lowercase: bool, uppercase: bool, digits: bool, symbols: SymbolSet, disallow: BTreeSet<char> }
pub enum SymbolSet { None, Basic, Full, Custom(BTreeSet<char>) }
pub struct RequiredClasses { min_lowercase: u8, min_uppercase: u8, min_digits: u8, min_symbols: u8 }
pub struct EntryPolicy {
    length: Option<u16>,
    charset_override: Option<Charset>,
    required_classes_override: Option<RequiredClasses>,
    user_note: Option<String>,
}
```

`EntryPolicy` is stored inside the sealed index (a site-specific constraint like "max length 12" would otherwise fingerprint the service). It is `postcard`-serialized in both the index and recovery payload.

### 8.3 Entropy estimation

- **Generated:** closed-form `H = length · log2(|effective_charset|)` bits.
- **Master (typed):** the maintained `zxcvbn` crate **v3**. zxcvbn's native unit is *guesses*; we define **bits ≡ log2(guesses)** (`guesses_log10 · 3.3219`) and derive crack-times from its estimates.

### 8.4 Strength tiers (master password)

| Tier | bits (= log2 guesses) | Gate |
|---|---|---|
| Dangerous | < 30 | Type `I-UNDERSTAND-THIS-IS-DANGEROUS` verbatim |
| Weak | 30–45 | Type `OVERRIDE` verbatim |
| Acceptable | 45–55 | One-click |
| Strong | 55–62 | — |
| Excellent | ≥ 62 | "overkill for most threat models" |

The thresholds are **calibrated to zxcvbn's measurable range**: zxcvbn caps its guess estimate at `u64::MAX`, so `bits = log2(guesses)` saturates at ~64 — the 70/85-bit thresholds of earlier drafts were unreachable for any typed password. Generated passwords are scored by closed-form entropy (uncapped, ~262 bits for the default policy), not zxcvbn, so they sit far above any tier.

**Export gate:** recovery export creation requires **Strong or above** (≥55 zxcvbn-bits) — see §7.5. This is safe despite being lower than a naive offline-brute-force bar because the export sits behind the 4 GiB / 8-pass recovery Argon2id (§7.4): at 55 bits, even granting an attacker a generous 10⁴ Argon2-guesses/s, cracking exceeds 10³ years. The weak-password sentinels still allow a weak password for the *vault itself* (which is HSM-gated and HSM-rate-limited), but you cannot create a single-factor export of a weakly-protected vault.

### 8.5 Crack-time display

Inline: the realistic through-KDF estimate only (`~10⁵ years (Medium preset)`). A **"What does this mean?"** expander reveals naked-GPU (10¹¹ g/s) and quantum-Grover (2× speedup) estimates with documented assumptions.

### 8.6 Default vault generation policy

40 chars; lower+upper+digits+`SymbolSet::Full`; no disallow; one of each class minimum → ≈ 262 bits/entry. Per-entry overrides handle site-specific shortening with the user in control.

### 8.7 Imported passwords

`validate(&password, &policy)` warns (never blocks) on class-minimum failures; entropy meter shown via zxcvbn.

---

## 9. Distribution, signing, build, supply chain

### 9.1 Distribution

Self-hosted over HTTPS from the project domain. No desktop app stores; Android via sideload; iOS deferred. `SHA-256SUMS` published and signed alongside artifacts.

### 9.2 Signing — minisign + GPG

Ship **both**; document **minisign as primary**. minisign (Ed25519): tiny verification surface. GPG (Ed25519): web-of-trust compatibility, signed git tags. Both keys generated air-gapped, stored offline; signing is a manual air-gapped step — **CI never holds signing keys**.

### 9.3 Android dual signature

APK Signature Scheme v3 (installer requirement; cert fingerprint published for TOFU+pinning) **plus** detached minisign+GPG over the `.apk` (download verification).

### 9.4 Reproducible builds — scoped to the core, under a fixed toolchain + environment

**What exists today.** `reproduce.sh` is a plain `cargo build --release --locked -p passman-cli` wrapped in the determinism controls that *are* implemented:

- pinned `rust-toolchain.toml` (channel `1.95.0`) → the exact compiler;
- committed `Cargo.lock` + `--locked` → the exact dependency versions;
- `--remap-path-prefix` covering the project dir **and** `$CARGO_HOME`/registry **and** `$RUSTUP_HOME` → no machine-specific absolute paths in the binary;
- `SOURCE_DATE_EPOCH` → a fixed build timestamp;
- **`codegen-units = 1`** in `[profile.release]` (without this, codegen partitioning is nondeterministic).

The CI `build-twice` job checks the repo out twice and compares the two SHA-256 hashes, so determinism is verified empirically on each push.

**Scope of the guarantee — same toolchain *and* environment.** With the same pinned toolchain, the same `Cargo.lock`, and the same build environment (in particular the same `libtss2`/`libdbus` system libraries and linker, which the CLI links dynamically), `reproduce.sh` yields a byte-identical `target/release/passman`. This is **not** a cross-machine "any host, same hash" claim: differing system libraries or a different linker can change the output. The `build-twice` job exercises exactly this same-environment case.

**Not yet implemented (PLANNED).** Vendored dependencies (`cargo vendor`), `cargo auditable` metadata embedding, and a pinned build-container image digest are *not* in the tree today. They are the path to a stronger, host-independent reproducibility guarantee and are tracked as future work — they are intentionally not claimed as current behaviour.

**Explicitly not guaranteed:** `.deb`/`.exe`/`.apk` wrappers and cross-environment system-library linkage variance. Windows reproducibility targets the GNU toolchain. The boundary is documented so a wrapper-hash match is not over-trusted.

### 9.5 Supply-chain CI

`cargo audit` (RUSTSEC) + `cargo deny` (license/banned/duplicates) + boundary greps (§2.4) + parser fuzzing gate merges; the `build-twice` reproducibility job runs on every push (§9.4). Minimal dependency surface — every workspace dependency is justified in [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md); prefer RustCrypto over FFI; review third-party `build.rs`. A CycloneDX SBOM is generated at release time by the `cargo-cyclonedx` step in `.github/workflows/release.yml` and published alongside the artifacts.

### 9.6 Update mechanism — network-silent by default

No auto-update. The default binary makes **no network connections, ever**. An optional compile-time feature `update-check` (off by default) enables a signed, read-only `version.json` fetch that verifies a minisign signature before showing a non-blocking "new version available" banner. No vault data ever egresses.

---

## 10. Testing strategy

- Unit tests inline (`#[cfg(test)]`) per crate; integration tests in `tests/` against public APIs only.
- Deterministic: injected `Clock`, `tempfile` for filesystem, no network, no sleeps.
- Known-answer tests for every crypto path (Argon2id, HKDF, XChaCha20-Poly1305, TOTP vs RFC 6238 test vectors).
- Round-trip property tests: vault save/load, recovery export/import, entry encrypt/decrypt, `postcard(EntryPolicy)`.
- Negative tests: tampered AEAD tags, wrong password, version mismatch, header-param tamper (probe AD), advisory-lockout behavior, replayed TOTP code, index↔envelope-set mismatch, truncated/over-long files, empty vault.
- **Fuzzing** (`cargo fuzz`) of `passman-vault` and `passman-recovery` parsers — the top attack surface.
- HSM impls tested against simulators (`swtpm` for TPM2) behind feature gates; Android Keystore / NCrypt behind device/integration gates.

---

## 11. Consolidated threat-coverage table

| # | Threat | Severity | Mitigation |
|---|---|---|---|
| 1 | Offline vault-file brute-force | Critical | Argon2id (≥256 MiB floor) + HSM-bound `K_hsm` + sealed labels (now genuinely sealed — `label_hash` removed) |
| 2 | Memory dump while unlocked | High | zeroize-on-drop; on-demand decrypt; ≤120 s session. Active malware: accepted |
| 3 | Keylogger captures master password | High | TOTP gate + HSM biometric. Keylogger itself: accepted |
| 4 | Clipboard scraper | Medium | 30 s clear, only-if-ours; `EXTRA_IS_SENSITIVE`; history-exclude hints |
| 5 | Screen recording / shoulder-surf | Medium | Obscured-by-default reveal; tap-to-show; 10 s auto-hide; `FLAG_SECURE` |
| 6 | Cold-boot | Low | Accepted |
| 7 | Spectre-class side-channel | Low | Constant-time primitives; broader µarch channels accepted |
| 8 | Supply-chain dependency compromise | Critical | `cargo audit`/`deny`; minimal surface (justified in `docs/DEPENDENCIES.md`); per-release CycloneDX SBOM; `build.rs` review (vendored deps: planned, §9.4) |
| 9 | Malicious update / MITM | Critical | Dual minisign+GPG; offline keys; no auto-update; signed manifest if enabled |
| 10 | TOTP replay | Medium | Last-accepted-code cache (in-memory) + ±1 step skew only |
| 11 | Vault tampering / corruption | High | AEAD tags; version + id in AD; probe AD binds header params; index↔envelope-set check; fail-closed (DoS-by-corruption accepted) |
| 12 | Nonce reuse | Critical | XChaCha20 192-bit random nonces; fresh per encryption; per-entry keys |
| 13 | Weak Argon2 params | High | 256 MiB / 0.6 s floor; warning below Medium |
| 14 | HSM extraction/cloning | Critical | Accepted (platform hardware guarantee) |
| 15 | Online guessing past the HSM | Medium | **HSM-native DA lockout** where the key is auth-bound (Android Keystore). **The default Linux TPM2 backend seals null-auth, so its DA lockout does NOT engage** (§4.9) — there the throttle is Argon2id cost + a strong master password + the advisory timer (rollback-able; not a security boundary). TPM2 `authValue` binding is future work (§13) |
| 16 | Mobile process introspection | High | `FLAG_SECURE`, snapshot suppression; rooted device accepted |
| 17 | File-format downgrade | Medium | Version in AEAD AD; probe AD binds params; mismatch aborts |
| 18 | Sealed-index size leakage | Low | 256-byte bucket padding; rewrite-on-save |
| 19 | Recovery export brute-force | Critical | Strong-password gate (≥55 zxcvbn-bits) + aggressive Argon2id (4 GiB/8); dominant residual risk, foregrounded |
| 20 | Recovery export tampering | High | AEAD tag binds payload + version + magic |
| 21 | Malware exports via unlocked session | High | Fresh re-auth (master+TOTP+biometric) required, independent of `SessionToken` |
| 22 | Recovery format downgrade | Medium | Version in AEAD AD |
| 23 | Weak master password silently accepted | High | Tiered gates; sentinel for <30 bits; export blocked unless Strong (≥55) |
| 24 | Generated-password modulo bias | Medium | Rejection sampling on `OsRng` |
| 25 | Policy metadata leak | Medium | `EntryPolicy` inside sealed index |
| 26 | Quantum brute-force on master | Low | Grover estimate surfaced; recommend ≥80 bits |
| 27 | Generated-password length fingerprint | Low | Uniform default length; overrides hidden; bucketed envelopes |
| 28 | Backdoored binary ≠ source | Critical | Reproducible core build + `codegen-units=1` + pinned container + `reproduce.sh` |
| 29 | APK swap on update | Critical | v3 key pinning + published cert fingerprint + detached sigs |
| 30 | CI compromise signs release | Critical | Air-gapped manual signing; CI cannot sign |
| 31 | Network egress leaks metadata | Medium | Network-silent default binary; update-check opt-in |
| 32 | Concurrent-instance race clobbers vault | Medium | Single-instance advisory lock on vault path |
| 33 | TOTP seed free-rides on vault-key unwrap | Medium | Seed in an independent HSM slot; optional distinct seed PIN for post-biometric independence |

---

## 12. Key decisions log

| # | Decision | Rationale |
|---|---|---|
| D1 | Local-only, no sync | User requirement |
| D2 | Rust core + native UIs | Memory-safe security core, idiomatic per-platform UX |
| D3 | Two cryptographic factors (master password + HSM key) **plus a TOTP liveness gate** | Honest model after review: TOTP can't be a true at-rest crypto factor (verifying needs the seed on-device) |
| D4 | HSM wraps the keys; vault stays on disk | TPMs have ~16–64 KB NV storage — they wrap keys, not data |
| D5 | TOTP seed in an **independent** HSM slot; **not** in the KDF | Decoupled from `K_hsm`; mixing it added no entropy; optional distinct seed PIN for real post-biometric independence (user choice) |
| D6 | Argon2id cost user-configurable at creation | User controls the security/latency trade-off |
| D7 | Per-entry encryption with sealed index; **no cleartext `label_hash`** | Metadata privacy — the rev-1 hash defeated it via offline dictionary attack |
| D8 | Sync `passman-core`, caller-supplied blocking pool, callback prompts | UniFFI-friendly; no tokio in bindings (confirmed) |
| D9 | Mobile reveal returns managed `String` (relaxation) | UniFFI cannot zeroize; clipboard path avoids FFI plaintext; obscured-by-default + `FLAG_SECURE` |
| D10 | Lockout = **HSM-native primary**, app timer advisory-only UX | App counter is forgeable/rollback-able by the post-unwrap attacker; only the HSM can bind it (user choice) |
| D11 | Session 120 s fixed, no sliding, 30 s post-copy | User choice |
| D12 | Clipboard clear-by-overwrite with crypto facts | User choice |
| D13 | Recovery default 4 GiB / 8 iter + **indeterminate** progress + elapsed time | High cost for a rare op; `argon2` has no per-iteration hook (researcher finding) |
| D14 | Fresh re-auth required at export, independent of session token | Prevents malware exfiltration via unlocked session |
| D15 | Master-password change invalidates old exports (warn + document) | Forward-secrecy expectation; cannot revoke files |
| D16 | Weak master passwords gated by typed sentinel; **export blocked unless Strong** | User choice + close the weak-export hole |
| D17 | Crack-time: realistic inline, naked/quantum behind expander | User choice |
| D18 | Vault default 40 chars, all classes, full ASCII (~262 bits) | User choice |
| D19 | TPM2 PCR binding off by default | Avoids bricking on firmware/kernel updates |
| D20 | Android refuses software-backed Keystore by default | Hardware limitations are the user's responsibility |
| D21 | Forced HSM loss → recovery import only | Prevents HSM thief from resetting to password-only |
| D22 | Update: network-silent default + opt-in `update-check` flag | Preserves "makes no network connections" claim |
| D23 | Reproducibility scoped to core binary, with `codegen-units=1` + pinned container | Honest boundary; wrappers/system-libs excluded |
| D24 | Ship minisign + GPG, minisign primary | Defense-in-depth across signing tools |
| D25 | Generic `HardwareKeyStore`/`PlatformCtx` stay Rust-internal; `passman-uniffi` exports concrete per-platform fns | Generics/associated types cannot cross the UniFFI FFI |
| D26 | Probe AD binds header params (version, kdf id, Argon2 params, salt) | Makes header tampering a clean authentication failure |
| D27 | Single-instance advisory lock on the vault path | Prevents two instances racing a save / clobbering state |

---

## 13. Open items / future work

- **TPM2 `authValue` binding for genuine hardware DA lockout:** the default Linux TPM2 backend currently seals `K_hsm`/the TOTP seed null-auth, so the TPM dictionary-attack counter never engages (§4.9). Binding a per-vault `authValue` (a PIN derived from the master password) to the sealed objects would make wrong unseals hammer the TPM DA counter — the real rate-limit against online guessing on desktop. Until then the throttle is Argon2id cost + master-password strength.
- **iOS:** full Secure Enclave implementation and SwiftUI front-end (designed for, deferred).
- **Windows native UI:** v0 uses `egui`; a native WinUI/`windows-rs` front-end is a later improvement.
- **`cargo vet` gating:** advisory in v0, hard gate later.
- **Distinct TOTP-seed PIN (§1.6):** ships as an optional setting; default off. Revisit whether it should be encouraged for high-value vaults.
- **Browser/autofill integration:** out of scope for v0.
- **Fully-reproducible packaging:** `.deb`/`.apk`/`.exe` reproducibility is a stretch goal beyond the core-binary guarantee.

---

## 14. Glossary

- **AEAD** — Authenticated Encryption with Associated Data (XChaCha20-Poly1305 here).
- **Argon2id** — memory-hard password KDF; hybrid of Argon2i and Argon2d.
- **HKDF** — HMAC-based key derivation; extract-then-expand.
- **HSM** — hardware security module; here a generic term covering TPM 2.0, Windows Platform Crypto Provider, Android hardware Keystore, Apple Secure Enclave.
- **`K_master`** — the root vault key derived from the master password and `K_hsm`.
- **`K_hsm`** — random key wrapped by the hardware; the second cryptographic factor.
- **`S`** — TOTP seed; long-term shared secret with the authenticator app, stored in its own HSM slot, used only for code verification.
- **DA lockout** — TPM dictionary-attack protection (and analogous Keystore/NCrypt anti-hammering).
- **PCR** — Platform Configuration Register (TPM measurement of boot state).
- **Sealed index** — the AEAD-encrypted list of entry labels and policies.
- **TOTP** — Time-based One-Time Password (RFC 6238).
- **TOFU** — Trust On First Use.
- **UniFFI** — Mozilla's tool generating Kotlin/Swift bindings from Rust.
