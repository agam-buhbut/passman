# Android Keystore HSM Backend — Implementation Plan (rev. 2, post-review)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.
>
> **Rev. 2 changes:** resolves D-A1 = option (ii) + **decision (A) "all-Kotlin shim"** (see below); folds in the 4-reviewer findings (security / Android-JNI / Rust-arch / verification). Net effect: **`passman-hsm` does NO JNI** — `jni`/`ndk-context` are dropped from the workspace; only `uniffi` is added. Almost the entire Rust surface is host-testable against a mock wrapper before any toolchain lands.

**Goal:** Add the `AndroidGcm` hardware backend (`passman-hsm`, wire `0x02`, architecture.md §6.4) — each 32-byte slot secret wrapped under an Android-Keystore AES-256-GCM key — plus the `passman-uniffi` binding crate exposing a concrete, monomorphized `App` to Kotlin (§6.5).

**Architecture (decision A):** `passman-hsm`'s `AndroidKeyStore` is **pure Rust, zero FFI**. It owns the `0x02` wire codec, the slot binding (it supplies `slot.tag()` as the GCM AAD), blob assembly, the §4.3 error mapping, and the *refuse-software decision*. All Keystore mechanics (keygen, wrap, unwrap, invalidate, security-level probe) live behind a plain Rust trait `KeystoreWrapper`, implemented foreign-side in a thin **Kotlin shim** (the only place `BiometricPrompt`+`CryptoObject`+`Cipher.doFinal` can live — the auth callback is an abstract class Rust can't subclass; a live `Cipher` is `!Send`; an attached-thread `FindClass` can't see `androidx.biometric.*`). `passman-uniffi` exports `KeystoreWrapper` (and the other core callbacks) via `#[uniffi::export(with_foreign)]`.

**Tech Stack:** Rust (edition 2021, rust 1.95) · `uniffi` 0.28 (the **only** new workspace dep) · `cargo-ndk` 4.1.2 · NDK r26 (API 34, `minSdk` 30) · `passman-crypto` AEAD (reused for the host mock wrapper — **no new dep**). `jni`/`ndk-context`: **not used** under decision (A).

---

## Resolved decisions (ratified via the multi-agent review + user sign-off)

- **D-A1 = option (ii) + (A):** the `BiometricPrompt`/`CryptoObject`/`Cipher` unit is a Kotlin shim; **keygen + full key-lifecycle also live in the shim** (decision A). `passman-hsm` holds only an `Arc<dyn KeystoreWrapper>` and orchestrates. No change to `HardwareKeyStore`, `BiometricPrompter`, `HsmError`, `WrappedBlob`, `HsmSlot`/`HsmKind` — `KeystoreWrapper` is **additive**.
- **PlatformCtx (Android) = `()`** (was `&JObject` in §6.5): the Kotlin shim holds whatever Android `Context`/`Activity` it needs; nothing crosses as a typed Rust handle. Same flavor of §6.5 amendment as the approved TPM2 in-seal change. (Task 12 amends §6.5.)
- **H3 accepted residual (documented):** under (A) the recovered secret `K_hsm`/`S` is produced by `Cipher.doFinal` in Kotlin and crosses back to Rust as an owned `bytes` on every unlock — **unavoidable on Android** (doFinal must be Kotlin). Recorded as an accepted residual risk parallel to the §5.4/D9 reveal-path relaxation. Mitigation: the shim scrubs every secret-bearing `byte[]` via `Arrays.fill` in a **`finally`** block; Rust copies into zeroizing `SecretBytes`.
- **Refuse-software is real, not assumed (§6.2):** the shim reports the key's hardware **security level** (`StrongBox` / `TrustedEnvironment` / `Software`) via `KeyInfo.getSecurityLevel()` (+ optional attestation challenge). **Rust** decides: `Software` → refuse (`HardwareAbsent`); `TrustedEnvironment` → accept + surface "TEE" in `capabilities()`; `StrongBox` → accept + surface "StrongBox". StrongBox absence is **surfaced, not silent** (§6.2).
- **`jni`/`ndk-context` dropped:** not needed anywhere under (A). `uniffi` is the only new dep (in `passman-uniffi`).

---

## 0. Hard invariants (stop-and-ask if a task would break one)

1. **Default build untouched.** Without `--features android-keystore`, the `android` module and the `HandleInner::Android` variant are absent; default `passman-hsm` is byte-for-byte unchanged. (Verified by: feature off → `cargo build` artifact identical; the only new dep `uniffi` lives in `passman-uniffi`, not in any default-built crate.)
2. **No settled public-API change.** `HardwareKeyStore`/`BiometricPrompter`/`HsmError`/`WrappedBlob`/`HsmSlot`/`HsmKind` unchanged. `KeystoreWrapper` is a new additive trait. (A new `HsmError` variant or a `BiometricPrompter` change is a hard stop.)
3. **`UnwrapHandle` is `Send`.** `AndroidUnwrapState` holds only `Send` plain bytes (`String`, `[u8;12]`, `Vec<u8>`, `u8`). A compile-time `assert_send::<UnwrapHandle>()` enforces it. (No JNI objects anywhere in Rust under (A), so this is trivially upheld — but assert it.)
4. **§4.3 error routing.** `Transient`/`Cancelled` never penalize; `PermanentlyInvalidated`/`HardwareAbsent` route to recovery/guidance. **Biometric lockout (incl. `ERROR_LOCKOUT_PERMANENT`) is `Transient`, NOT `PermanentlyInvalidated`** — only a genuinely invalidated *key* (`KeyPermanentlyInvalidatedException`) is permanent. The shim normalizes Java exceptions *and* `int` biometric error codes into the typed `KeystoreError` enum; Rust does the routing.
5. **Parser panic-free & non-secret.** The `0x02` payload is attacker-controlled on disk; codec is fully bounds-checked; `MalformedBlob { reason }` is a fixed `&'static str`; `Backend(String)` carries only a fixed label, never a Java message/exception text/array contents.
6. **GCM nonce safety = one Keystore key wraps exactly one secret, ever.** Each `enroll` mints a fresh random alias + fresh key; the IV is Keystore-generated (`getIV()`), never caller-supplied. **On any enroll failure after keygen, the shim/Rust deletes the just-created key** so a retry cannot reuse a key that already produced one ciphertext. Two slots never share a key.
7. **Rust owns the slot tag.** `slot.tag()` (from the *requested* slot) is passed to `KeystoreWrapper::{wrap,unwrap}` and used verbatim as GCM AAD. The shim MUST NOT read a tag from the blob or choose one. Cross-slot rejection is the GCM-enforced §6.4 binding (parity with TPM2 in-seal / mock AEAD-AD).
8. **Secrets never leak.** No secret in errors/logs; shim scrubs JVM `byte[]`s in `finally`; alias is random-only (no slot name / PII / environment entropy — it sits in cleartext on disk).
9. **Acyclic graph.** `passman-uniffi → passman-core → passman-hsm`; `uniffi` only in `passman-uniffi`; `KeystoreWrapper` defined in `passman-hsm`, foreign-implemented via `passman-uniffi`. No edge into `core`/`hsm` reversed.
10. **clippy pedantic + `unwrap_used` clean** under `-D warnings`. Java/Android type names in docs are backticked (`doc_markdown`).

---

## File structure

| Path | Create/Modify | Responsibility |
|---|---|---|
| `crates/passman-hsm/Cargo.toml` | Modify | Add `android-keystore` feature (**no new deps**). |
| `crates/passman-hsm/src/android.rs` | Create | `AndroidKeyStore` (pure-Rust orchestration) + `KeystoreWrapper` trait + `KeystoreError`/`KeystoreSecurityLevel`/`WrappedParts` types + `0x02` codec + `KeystoreError→HsmError` map + `#[cfg(test)] MockKeystoreWrapper` (real AEAD-with-AAD) + host tests. **Compiles on any target when the feature is on (no platform APIs).** |
| `crates/passman-hsm/src/lib.rs` | Modify | `#[cfg(feature="android-keystore")] mod android;` + re-export `AndroidKeyStore`, `KeystoreWrapper`, etc. Update the `dead_code` `cfg_attr` allow-list to include `android-keystore`. |
| `crates/passman-hsm/src/handle.rs` | Modify | `HandleInner::Android(AndroidUnwrapState)` + `for_android`/`into_android`, gated `#[cfg(feature="android-keystore")]` (mirror the `tpm2` pattern; gate matches the module's gate). |
| `crates/passman-uniffi/{Cargo.toml,src/lib.rs,build.rs,uniffi.toml}` | Create | New member; `uniffi`. Concrete `App` (`#[cfg(target_os="android")]` binds `H=AndroidKeyStore`, `PlatformCtx=()`); `#[uniffi::export(with_foreign)]` for `KeystoreWrapper`, `BiometricPrompter`, `Spawner`, `Progress`, `Clock`, `Clipboard`; `android_init()` (explicit, since `JNI_OnLoad` won't fire under JNA). |
| `android/` (Kotlin, outside the Rust workspace) | Create (Task 9) | The `KeystoreWrapper` shim: keygen (`KeyGenParameterSpec`), `Cipher`+`CryptoObject`+`BiometricPrompt` wrap/unwrap, `deleteEntry`, `KeyInfo.getSecurityLevel()`; normalizes exceptions + biometric `int` codes → `KeystoreError`; scrubs `byte[]` in `finally`. |
| `Cargo.toml` (root) | Modify | Add `crates/passman-uniffi` to `members`; add `uniffi = "0.28"` to `[workspace.dependencies]`. |
| `scripts/` boundary-check | Modify | Allow `cfg(target_os=…)` in `passman-uniffi` too (Task 9 introduces it there). |
| `architecture.md` | Modify | Amend §6.5 (Android `PlatformCtx=()`); note §6.4 AAD binding + the H3 residual in the disclosure/residual list. |

**Trait sketch** (the contract both the host mock and the Kotlin shim implement):
```rust
/// Foreign-implemented Android Keystore mechanics. Defined here (passman-hsm),
/// implemented host-side by MockKeystoreWrapper (tests) and Android-side by the
/// Kotlin shim (via passman-uniffi #[uniffi::export(with_foreign)]).
pub trait KeystoreWrapper: Send + Sync {
    /// Generate a fresh per-use-auth AES-256-GCM key under `alias`, then encrypt
    /// `material` with AAD = `[slot_tag]`, driving the biometric prompt. Returns
    /// the Keystore-generated IV, the ciphertext+tag, and the key's security level.
    /// On failure the impl MUST delete `alias` before returning (invariant 6).
    fn wrap(&self, alias: &str, slot_tag: u8, material: &[u8]) -> Result<WrappedParts, KeystoreError>;
    /// Decrypt `ciphertext` under `alias`'s key with AAD = `[slot_tag]` and `iv`,
    /// driving the biometric prompt. Scrubs its plaintext byte[] in `finally`.
    fn unwrap(&self, alias: &str, slot_tag: u8, iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    /// Destroy `alias`'s key (idempotent: missing alias = Ok).
    fn invalidate(&self, alias: &str) -> Result<(), KeystoreError>;
    /// Probe whether a hardware-backed key can be made + the device is secure
    /// (lock screen set). Used for the refuse-software pre-flight (§6.2).
    fn probe(&self) -> Result<KeystoreSecurityLevel, KeystoreError>;
}
pub struct WrappedParts { pub iv: [u8; 12], pub ciphertext: Vec<u8>, pub level: KeystoreSecurityLevel }
pub enum KeystoreSecurityLevel { StrongBox, TrustedEnvironment, Software }
/// Typed, non-secret failure categories the shim normalizes Java exceptions AND
/// biometric int error codes into. Carries no message strings.
pub enum KeystoreError {
    Cancelled,               // user dismissed / ERROR_USER_CANCELED / ERROR_NEGATIVE_BUTTON / ERROR_CANCELED
    Lockout,                 // ERROR_LOCKOUT / ERROR_LOCKOUT_PERMANENT / ERROR_TIMEOUT / UserNotAuthenticated → Transient
    KeyInvalidated,          // KeyPermanentlyInvalidatedException → PermanentlyInvalidated
    AuthFailed,              // AEADBadTagException / BadPaddingException → MalformedBlob (wrong slot or tamper)
    NoSecureLockOrHardware,  // KeyguardManager not secure / no Keystore → HardwareAbsent
    Backend,                 // any other Provider/KeyStoreException → Backend(fixed label)
}
```

---

## Tasks

### Task 1: `android-keystore` feature + module skeleton (no new deps)
**Files:** `crates/passman-hsm/Cargo.toml`, `src/lib.rs`, root `Cargo.toml`.
- [ ] **Step 1** — `passman-hsm/Cargo.toml`: `[features] android-keystore = []` (no `dep:` — pure Rust).
- [ ] **Step 2** — `lib.rs`: `#[cfg(feature="android-keystore")] mod android;` + re-exports; extend the `cfg_attr(... allow(dead_code))` predicate to include `feature = "android-keystore"`.
- [ ] **Step 3** — Create `src/android.rs` with module doc only.
- [ ] **Step 4** — Root `Cargo.toml`: add `uniffi = "0.28"` to `[workspace.dependencies]` (used by Task 9).
- [ ] **Step 5** — Verify: `cargo build -p passman-hsm` (default, unchanged) and `cargo build -p passman-hsm --features android-keystore` (compiles on the Linux host — no platform deps). `cargo tree -p passman-hsm` shows **no** `jni`/`ndk-context`.
- [ ] **Step 6** — Commit: `feat(hsm): scaffold android-keystore feature (pure-Rust, no JNI)`

### Task 2: `0x02` wire codec (host TDD)
Wire (§6.4): `name_len(2,LE) ‖ alias(UTF-8) ‖ gcm_iv(12) ‖ ct_len(2,LE) ‖ AES-256-GCM(secret)+tag`.
**Files:** `src/android.rs` + `#[cfg(test)]`.
- [ ] **Step 1: failing tests** — round-trip + the full `blob.rs`-bar rejection/boundary set: `payload_round_trips`, `empty_alias_round_trips`, `max_u16_alias_and_ct_round_trip`, `multibyte_utf8_alias_round_trips`, `all_zero_iv_round_trips`, `decode_rejects_trailing_bytes`, `decode_rejects_truncated_iv`, `decode_rejects_non_utf8_alias`, `decode_rejects_ct_len_over_remaining`, `decode_rejects_undersized_ciphertext` (`ct < 16`, the GCM tag floor), `encode_rejects_alias_over_u16`, `encode_rejects_ct_over_u16`.
- [ ] **Step 2: run, expect FAIL** — `cargo test -p passman-hsm --features android-keystore android::`.
- [ ] **Step 3: implement** — `encode_payload`/`decode_payload`/`ParsedPayload` (panic-free, `split_at_checked`, reuse the `read_len_prefixed` shape from `tpm2.rs:510`). `decode_payload` rejects `ciphertext.len() < 16` (`MalformedBlob{reason:"android ciphertext shorter than GCM tag"}`). `GCM_IV_LEN = 12`.
- [ ] **Step 4: run, expect PASS.**
- [ ] **Step 5: panic-fuzz** — exhaustive small-alphabet recursion (per `blob.rs:270`) **seeded with a valid `name_len`+alias prefix** so it actually reaches the IV/ct_len boundaries (not just the leading length). Run, expect PASS.
- [ ] **Step 6: Commit** — `feat(hsm): android 0x02 codec + host tests`

### Task 3: `KeystoreWrapper` trait, typed errors, state, handle variant
**Files:** `src/android.rs`, `src/handle.rs`.
- [ ] **Step 1** — Define `KeystoreWrapper`, `WrappedParts`, `KeystoreSecurityLevel`, `KeystoreError` (sketch above), and `AndroidUnwrapState { alias:String, iv:[u8;12], ciphertext:Vec<u8>, slot_tag:u8 }` (all `Send`).
- [ ] **Step 2** — Compile-time `const _: fn() = || { fn a<T:Send>(){} a::<AndroidUnwrapState>(); a::<crate::UnwrapHandle>(); };`.
- [ ] **Step 3** — `handle.rs`: `HandleInner::Android(AndroidUnwrapState)` + `for_android`/`into_android` (fallible, `Result<_,HsmError>` — mirror `into_tpm2`, NOT the infallible `into_mock`), gated `#[cfg(feature="android-keystore")]` (matches the module gate).
- [ ] **Step 4** — Build host + commit: `feat(hsm): KeystoreWrapper trait + android unwrap-state + handle variant`

### Task 4: `AndroidKeyStore` + host integration tests against a real-AEAD mock
**Files:** `src/android.rs`.
- [ ] **Step 1** — `AndroidKeyStore { wrapper: Arc<dyn KeystoreWrapper> }` + `new(wrapper)`. `impl HardwareKeyStore`:
  - `kind()` → `HsmKind::AndroidGcm`. `PlatformCtx = ()`.
  - `enroll(slot, material, _ctx, _prompter)`: mint a random alias `format!("passman-{}", hex(OsRng uuid))` (passman-crypto RNG); `wrapper.wrap(&alias, slot.tag(), material.expose())`; on `Err`, best-effort `wrapper.invalidate(&alias)` then map+return (invariant 6); on `Ok`, refuse if `level == Software` (+ invalidate); `encode_payload` → `WrappedBlob::from_parts(AndroidGcm, …)`. (The generic `prompter` is unused on this backend — the shim drives its own CryptoObject-bound prompt; document why, ref D-A1.)
  - `begin_unwrap(slot, wrapped, _ctx)`: check `kind==AndroidGcm` else `MalformedBlob`; `decode_payload`; `UnwrapHandle::for_android(AndroidUnwrapState{…, slot_tag: slot.tag()})`. No wrapper call here.
  - `complete_unwrap(handle, _prompter)`: `handle.into_android()?`; `wrapper.unwrap(&alias, slot_tag, &iv, &ct)` → `SecretBytes::new`.
  - `invalidate(slot, wrapped, _ctx)`: decode alias; `wrapper.invalidate(&alias)`.
  - `capabilities()`: from `wrapper.probe()` level (StrongBox/TEE surfaced); lockout per Keystore (pick the right `LockoutRecovery` variant — read `capabilities.rs`; biometric `ERROR_LOCKOUT_PERMANENT` clears on device-credential → not a simple `TimeBased`).
- [ ] **Step 2** — `#[cfg(test)] MockKeystoreWrapper`: real AEAD-with-AAD using `passman-crypto` (the same primitive `mock.rs` uses), AAD = `[slot_tag]`, an in-memory `alias→key` map; `wrap` returns a real `{iv, ct}`; `unwrap` fails (`AuthFailed`) on wrong `slot_tag` or flipped bytes; `invalidate` removes the key; `probe` returns `TrustedEnvironment` (and a knob to return `Software`/error for the refuse-path test).
- [ ] **Step 3** — Host integration tests (the big win — no toolchain): `enroll_then_unwrap_roundtrips_both_slots`; `cross_slot_blob_is_rejected` (VaultKey blob via TotpSeed → `MalformedBlob`); `tampered_ciphertext_is_rejected` (flip a byte → `MalformedBlob`); `repeat_unwrap_of_persisted_blob` (same blob, two fresh begin/complete cycles → identical secret, §6.6); `enroll_failure_deletes_key` (mock `wrap` errors → assert `invalidate` called); `software_level_is_refused` (`probe`→`Software` → `HardwareAbsent`); `wrong_kind_blob_rejected`. Run, expect PASS.
- [ ] **Step 4: Commit** — `feat(hsm): AndroidKeyStore orchestration + host integration tests`

### Task 5: `KeystoreError → HsmError` mapping (§4.3, host-testable)
**Files:** `src/android.rs`.
- [ ] **Step 1** — `fn map_keystore_error(e: KeystoreError) -> HsmError`: `Cancelled→Cancelled`, `Lockout→Transient`, `KeyInvalidated→PermanentlyInvalidated`, `AuthFailed→MalformedBlob{reason:"android AES-GCM authentication failed (wrong slot or tampered blob)"}`, `NoSecureLockOrHardware→HardwareAbsent`, `Backend→Backend("android keystore backend error")` (fixed label).
- [ ] **Step 2** — Host test `maps_keystore_errors_per_section_4_3` (one assert per variant), incl. the load-bearing `Lockout→Transient` (NOT `PermanentlyInvalidated`) per invariant 4.
- [ ] **Step 3** — Write a `KeystoreWrapper` doc table specifying exactly which Java exceptions + which biometric `int` codes the shim must fold into each `KeystoreError` (the shim is the only place that sees both). Commit: `feat(hsm): android error mapping + host tests`

### Task 6: slot-tag invariant guard (host)
**Files:** `src/slot.rs` tests (or `android.rs`).
- [ ] **Step 1** — Host test pinning `HsmSlot::VaultKey.tag() != HsmSlot::TotpSeed.tag()` and each equals its expected constant (protects the cross-slot binding independent of the device tier). If an equivalent test already exists, note it. Commit if added.

### Task 7: `passman-uniffi` crate
**Files:** `crates/passman-uniffi/*`, root `Cargo.toml`, boundary script.
- [ ] **Step 1** — New member; `crate-type=["cdylib","lib"]`; deps `passman-core`, `uniffi` (`[dependencies] uniffi = { workspace=true }`; `[build-dependencies] uniffi = { workspace=true, features=["build"] }`); pin the `uniffi-bindgen` at the **same** 0.28 patch.
- [ ] **Step 2** — `#[uniffi::export(with_foreign)]` for `KeystoreWrapper` (+ an adapter if uniffi can't export the hsm-defined trait directly), `BiometricPrompter`, and the core callbacks the App needs: `Spawner`, `Progress`, `Clock`, `Clipboard` (enumerate against `passman-core::App` — §2.5). Owned params, return `Result` (§6.5).
- [ ] **Step 3** — `fn android_init(...)` (`#[uniffi::export]`) the Kotlin side calls **once at startup** to wire up any global state (replaces the non-firing `JNI_OnLoad`). Assert-on-device that init ran before any backend op.
- [ ] **Step 4** — Concrete `App` wrapper holding `passman_core::App<AndroidKeyStore>`; `#[cfg(target_os="android")]` builds `AndroidKeyStore::new(foreign_wrapper)`, injects `&()` as ctx; thin forwarding methods. No generics / `PlatformCtx` / associated types on the UniFFI surface (§6.5).
- [ ] **Step 5** — `uniffi.toml` (Kotlin package/namespace, callback config); generate + compile-check Kotlin bindings against a stub. Update the boundary script to permit `cfg(target_os=…)` in `passman-uniffi`. Add `uniffi` tree to `DEPENDENCIES.md` (§9.5). Commit: `feat(uniffi): android App binding + foreign KeystoreWrapper`

### Task 8: Kotlin shim (`android/`)
**Files:** `android/…` (Jetpack, outside the Rust workspace).
- [ ] **Step 1** — Implement `KeystoreWrapper`: `wrap` = keygen (`KeyGenParameterSpec(alias, ENCRYPT|DECRYPT)`, `setBlockModes("GCM")`, `setEncryptionPaddings("NoPadding")`, `setKeySize(256)`, `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG|AUTH_DEVICE_CREDENTIAL)` [API30+, the `0` per-use is security-critical], `setInvalidatedByBiometricEnrollment(true)`, try `setIsStrongBoxBacked(true)` catch `StrongBoxUnavailableException` (around `generateKey`, ordered before `ProviderException`) → retry TEE) → `Cipher.init(ENCRYPT)`, `updateAAD([slot_tag])`, `CryptoObject` + `BiometricPrompt` (allowed authenticators via `BiometricManager.Authenticators.*`, matching the key policy), `getIV()`, `doFinal`; scrub plaintext `byte[]` in `finally`.
- [ ] **Step 2** — `unwrap` = symmetric (`init(DECRYPT, key, GCMParameterSpec(128, iv))`, `updateAAD([slot_tag])`, prompt, `doFinal`); scrub in `finally`. `invalidate` = `KeyStore.deleteEntry`. `probe` = `KeyguardManager.isDeviceSecure()` + a throwaway hardware key → `KeyInfo.getSecurityLevel()`.
- [ ] **Step 3** — Normalize exceptions + `onAuthenticationError` `int` codes → `KeystoreError` (per Task 5's table). Bridge async `BiometricPrompt` (UI thread) → the synchronous trait call (latch); propagate cancel/timeout. No secret in any thrown/returned value.

> **Shim security obligations (surfaced by the host-core security audit — the host suite CANNOT verify any of these; the Task 11 device negative-controls are the gate):**
> 1. `updateAAD([slot_tag])` on **both** encrypt *and* decrypt. A shim that omits it symmetrically still round-trips and passes every host test, while **silently voiding the cross-slot binding on-device** — Task 11's cross-slot-rejection control is the only thing that catches this. Highest-risk item.
> 2. **Delete the key on any post-keygen failure** inside `wrap` (the host orchestrator's `invalidate` only fires after `wrap` *returns*; a failure between keygen and return is the shim's to clean up). This is the real invariant-6 (GCM-nonce) enforcement.
> 3. IV strictly from `cipher.getIV()`; never a caller-supplied IV; a fresh key per `wrap`.
> 4. Normalize biometric outcomes precisely: `ERROR_LOCKOUT` / `ERROR_LOCKOUT_PERMANENT` / `ERROR_TIMEOUT` / `UserNotAuthenticated` → `Lockout` (→ `Transient`); **only** `KeyPermanentlyInvalidatedException` → `KeyInvalidated` (→ `PermanentlyInvalidated`). A swap re-introduces the destructive-recovery misroute the Rust side is careful to avoid.
> 5. Scrub every secret `byte[]` in a `finally`; never place key material, plaintext, the alias contents, or a Java message into any returned/thrown value (`KeystoreError` is data-free by design — keep it so).

### Task 9: Cross-compile link-check
- [ ] **Step 1** — `cargo ndk -t arm64-v8a -t x86_64 build -p passman-uniffi --features … ` → `libpassman_uniffi.so` per ABI (the only crate with target-specific build). `cargo ndk … clippy -- -D warnings`.
- [ ] **Step 2** — Note in the verification matrix: a green build checks Rust types/`Send`/linkage **only** — NOT uniffi/Kotlin runtime binding, classloader, or any Keystore/biometric behavior. Commit: `chore: android cross-compile green`

### Task 10: Feasibility spike (BEFORE relying on the emulator tier)
> Three assumptions the emulator tier rests on are unproven. Spike each; record the result; gate Task 11 on them.
- [ ] **Step 1** — Does `uniffi` + `android_init` correctly wire the foreign `KeystoreWrapper` from Kotlin (no `JNI_OnLoad` dependency)? Prove a trivial round-trip call Kotlin→Rust→Kotlin works.
- [ ] **Step 2** — Can a **per-use-auth `CryptoObject`** prompt be satisfied on the emulator? Try `adb emu finger touch` first; if it doesn't drive the `CryptoObject` auth, fall back to the **`DEVICE_CREDENTIAL` PIN path** (`adb shell input`/UIAutomator) and make that the primary CI path. Record which works.
- [ ] **Step 3** — Does `setInvalidatedByBiometricEnrollment(true)` + enrolling a new fingerprint actually throw `KeyPermanentlyInvalidatedException` on this emulator image? If not, mark the `PermanentlyInvalidated` behavior "physical-device-only" in the matrix (the *mapping* is already host-tested in Task 5).

### Task 11: On-device (emulator) integration — anti-vacuous-pass
> **Guard (the swtpm lesson), implemented, not just stated:** opt-in via `PASSMAN_ANDROID_EMULATOR_TEST=1`. Gate **set** + device unreachable → **`panic!`/fail** (never silent skip). Gate **unset** → `eprintln!("SKIP: …")` no-op (compile-always, runtime-gated — **never `#[ignore]`**). Positively prove the op executed: assert `KeyStore.containsAlias(alias)` true post-enroll, AND require the negative controls below to fail-closed (a no-op backend passes the happy path but fails these).
- [ ] **Step 1** — Enroll `VaultKey` + `TotpSeed` → two distinct blobs; unwrap each → original secret. Driven via the Task-10 auth path.
- [ ] **Step 2** — Negative controls: cross-slot (VaultKey blob as TotpSeed → `MalformedBlob`); single-byte ciphertext **tamper** → `MalformedBlob`; (separately) IV/tag tamper.
- [ ] **Step 3** — Repeat-unwrap the *same persisted blob* across a fresh `begin/complete` cycle (and ideally an Activity restart) → identical secret (§6.6).
- [ ] **Step 4** — `PermanentlyInvalidated` (if Task-10 Step 3 confirmed reproducible): enroll → new fingerprint → unwrap → `PermanentlyInvalidated`. `invalidate` then unwrap → key-absent. Commit: `test(android): emulator enroll/unwrap/invalidate/tamper integration`

### Task 12: Gates, docs, amendments
- [ ] **Step 1** — `cargo fmt --check`; host `cargo test` (default + `--features android-keystore`); `cargo ndk` build+clippy (Task 9); `cargo audit` (now covering the `uniffi` tree) — **merge-gated**; boundary script (updated) passes.
- [ ] **Step 2** — Amend `architecture.md` §6.5 (`PlatformCtx=()`), §6.4 (AAD binding), and the residual/disclosure list (H3 plaintext-crosses-FFI; cleartext alias). Update `android.rs` module docs to "verified against emulator …" **only after** Task 11 passes.
- [ ] **Step 3** — Update the `project_linux-verified-android-next` memory **only** to "Android: implemented; host codec/orchestration/error-map verified; device verification pending/complete per Task 10–11" — never a premature "verified". Commit: `docs: android verification notes + §6.5/§6.4 amendments`

---

## Self-review (vs architecture.md §6.4/§6.5/§4.3)
Spec coverage: `0x02` wire → T2; KeyGenParameterSpec flags → T8; IV via `getIV()` → T8; per-use `CryptoObject` auth → T8; slot binding (AAD) → T4/T5; refuse-software (§6.2) → T4 + T8 `probe`; minSdk30 → T8; §4.3 routing → T5; concrete monomorphized App / no generics on FFI → T7; `PlatformCtx` in binding crate → T7; foreign callbacks owned+Result → T7; rotation durability (§6.6) → T4 Step3 (host) + T11 Step3 (device). Placeholder scan: Kotlin API calls are named intended calls confirmed against Android docs in the review; no `TODO`s. Type consistency: `GCM_IV_LEN=12`, `slot_tag:u8`, `KeystoreWrapper`/`KeystoreError`/`WrappedParts`/`KeystoreSecurityLevel`, `AndroidUnwrapState`, `map_keystore_error` used consistently across T2–T8.

## Verification matrix (honest about what's provable when)
| Layer | How | When | Vacuous-pass guard |
|---|---|---|---|
| Wire codec | host `cargo test` | **now** | boundary + seeded panic-fuzz |
| **Orchestration: enroll/unwrap/cross-slot/tamper/repeat/refuse** | host `cargo test` vs **real-AEAD MockKeystoreWrapper** | **now** | negative controls fail-closed |
| Error routing (`KeystoreError→HsmError`) | host `cargo test` | **now** | per-variant asserts |
| `UnwrapHandle: Send`, slot-tag distinct | host compile + test | **now** | static assert |
| Rust types/Send/linkage on android | `cargo ndk build/clippy` | after NDK | compile is the assertion (Rust only) |
| uniffi↔Kotlin wiring, real Keystore/biometric, invalidation | emulator (Task 10 spike → Task 11) | after emulator | env-gated probe + hard-fail-if-unreachable + negative controls |
| StrongBox path | physical device only | later | emulator exercises TEE branch only — **not** StrongBox |

**CI reality:** host codec/orchestration/error-map tests are headless-CI-safe (no toolchain). `cargo ndk` build/clippy run in CI given an NDK. The **emulator tier needs a GUI emulator + adb auth injection → dev-box / dedicated-runner only**; managed CI (Firebase/AWS Device Farm) can't drive it. The `DEVICE_CREDENTIAL` PIN path (Task 10 Step 2) is the more CI-tractable option if pursued.
