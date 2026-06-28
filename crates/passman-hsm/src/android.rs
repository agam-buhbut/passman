//! Android hardware-`Keystore` backend (`architecture.md` §6.4, wire byte
//! `0x02`).
//!
//! Each 32-byte slot secret is wrapped under a per-enrollment, per-use-auth
//! Android `Keystore` `AES-256-GCM` key. Under decision (A) this module is
//! **pure Rust with no FFI**: every `Keystore` mechanic (keygen, the
//! `CryptoObject`-bound `BiometricPrompt`, `Cipher.doFinal`, `deleteEntry`, the
//! security-level probe) lives behind the [`KeystoreWrapper`] trait, implemented
//! foreign-side by a Kotlin shim (via `passman-uniffi`) and host-side by a test
//! mock. This file owns only the parts that are pure data: the `0x02` wire
//! codec, the slot-to-AAD binding, blob assembly, the [`KeystoreError`] to
//! [`HsmError`] routing (§4.3), and the refuse-software decision (§6.2).
//!
//! # Slot binding
//!
//! The slot is bound as the GCM **associated data** (`AAD = [slot.tag()]`),
//! recomputed from the *requested* slot on every call and never read from the
//! blob (invariant 7). A [`HsmSlot::VaultKey`] blob therefore fails
//! authentication if presented as a [`HsmSlot::TotpSeed`] — the same
//! cryptographic binding the TPM2 in-seal tag and the mock AEAD-AD provide.
//!
//! # Secrets
//!
//! On unwrap the recovered secret is produced by `Cipher.doFinal` in Kotlin and
//! crosses back as an owned `Vec<u8>` (the accepted §5.4 / H3 residual —
//! `doFinal` must be Kotlin); the orchestrator immediately copies it into a
//! zeroizing [`SecretBytes`], and the shim scrubs its own `byte[]` in a
//! `finally` block.

use std::sync::{Arc, OnceLock};

use passman_crypto::{fill_random, SecretBytes};

use crate::blob::WrappedBlob;
use crate::capabilities::{HsmCapabilities, LockoutRecovery};
use crate::error::HsmError;
use crate::handle::UnwrapHandle;
use crate::prompt::BiometricPrompter;
use crate::slot::{HsmKind, HsmSlot};
use crate::store::HardwareKeyStore;

/// Length of the GCM IV Android `Keystore` generates (`Cipher.getIV()` is always
/// 12 bytes for GCM); embedded verbatim in the `0x02` payload.
const GCM_IV_LEN: usize = 12;

/// Length of the GCM authentication tag (128-bit); the floor any stored
/// ciphertext must meet, since the tag is appended to the ciphertext.
const GCM_TAG_LEN: usize = 16;

/// Random alias entropy, in bytes (128-bit). The alias sits in cleartext on
/// disk, so it carries entropy only — no slot name, PII, or environment data
/// (invariant 8).
const ALIAS_ENTROPY_LEN: usize = 16;

/// Lowercase hex digits for rendering the random alias without a hex dependency.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The AOSP `BiometricPrompt` consecutive-failure threshold before a temporary
/// biometric lockout. **Advisory UX metadata only** (§4.9) — not a security
/// control, and not a Keystore key auth-attempt counter. After further failures
/// the lockout escalates to a credential-clearable permanent lockout; recovery
/// is conveyed by [`LockoutRecovery::UserAccountReset`], not by this count.
const BIOMETRIC_LOCKOUT_THRESHOLD: u32 = 5;

/// The hardware security level backing a `Keystore` key (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreSecurityLevel {
    /// Backed by a discrete secure element (`StrongBox`). Strongest.
    StrongBox,
    /// Backed by the TEE (Trusted Execution Environment). Accepted.
    TrustedEnvironment,
    /// Pure software (no hardware key isolation). Refused (§6.2).
    Software,
}

/// Typed, non-secret failure categories the foreign [`KeystoreWrapper`]
/// normalizes Java exceptions **and** biometric `int` error codes into.
///
/// Carries no message strings (invariant 5): the Rust side maps these to
/// [`HsmError`] via [`map_keystore_error`] following the §4.3 routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreError {
    /// User dismissed the prompt (`ERROR_USER_CANCELED` / `ERROR_NEGATIVE_BUTTON`
    /// / `ERROR_CANCELED`). Not a failed attempt.
    Cancelled,
    /// Biometric lockout (`ERROR_LOCKOUT` / `ERROR_LOCKOUT_PERMANENT` /
    /// `ERROR_TIMEOUT` / `UserNotAuthenticatedException`). **Transient** — the
    /// key is intact and re-auth with the device credential clears it
    /// (invariant 4).
    Lockout,
    /// The wrapping key was invalidated for good
    /// (`KeyPermanentlyInvalidatedException`, e.g. biometric re-enrollment under
    /// `setInvalidatedByBiometricEnrollment(true)`). Only a recovery import
    /// restores the slot.
    KeyInvalidated,
    /// GCM authentication failed (`AEADBadTagException` / `BadPaddingException`):
    /// the wrong slot (AAD) or a tampered blob.
    AuthFailed,
    /// No secure lock screen, or no usable `Keystore` / hardware on this device.
    NoSecureLockOrHardware,
    /// Any other `Provider` / `KeyStoreException` not covered above.
    Backend,
}

/// The outputs of a successful [`KeystoreWrapper::wrap`].
pub struct WrappedParts {
    /// The `Keystore`-generated 12-byte GCM IV (`Cipher.getIV()`).
    pub iv: [u8; GCM_IV_LEN],
    /// The ciphertext with the appended 16-byte GCM tag.
    pub ciphertext: Vec<u8>,
    /// The security level of the key that produced this ciphertext (§6.2).
    pub level: KeystoreSecurityLevel,
}

/// Foreign-implemented Android `Keystore` mechanics (decision A).
///
/// Defined here so the pure-Rust [`AndroidKeyStore`] can orchestrate against it;
/// implemented host-side by the test mock and Android-side by the Kotlin shim
/// (exported via `passman-uniffi`'s `#[uniffi::export(with_foreign)]`). All
/// methods take plain data and return a typed [`KeystoreError`] (never a message
/// string), so a panic never crosses the FFI boundary (§6.5).
pub trait KeystoreWrapper: Send + Sync {
    /// Generate a fresh per-use-auth `AES-256-GCM` key under `alias`, then
    /// encrypt `material` with `AAD = [slot_tag]`, driving the `CryptoObject`
    /// -bound biometric prompt. Returns the `Keystore`-generated IV, the
    /// ciphertext+tag, and the key's security level.
    ///
    /// On **any** failure after keygen the implementation MUST delete `alias`
    /// before returning, so a retry can never reuse a key that already produced
    /// a ciphertext under its IV (invariant 6 — GCM nonce safety).
    ///
    /// # Errors
    ///
    /// Returns a [`KeystoreError`] categorizing the platform failure (cancelled
    /// prompt, lockout, key invalidated, no secure hardware, or a backend fault).
    fn wrap(
        &self,
        alias: &str,
        slot_tag: u8,
        material: &[u8],
    ) -> Result<WrappedParts, KeystoreError>;

    /// Decrypt `ciphertext` under `alias`'s key with `AAD = [slot_tag]` and `iv`,
    /// driving the biometric prompt. Scrubs its plaintext `byte[]` in a `finally`
    /// block before returning.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::AuthFailed`] if the GCM tag does not verify (wrong
    /// slot or tampered blob), or another [`KeystoreError`] for a cancelled
    /// prompt, lockout, invalidated key, or backend fault.
    fn unwrap(
        &self,
        alias: &str,
        slot_tag: u8,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeystoreError>;

    /// Destroy `alias`'s key. Idempotent: a missing alias is `Ok`.
    ///
    /// # Errors
    ///
    /// Returns a [`KeystoreError`] only if the `Keystore` itself faults; a
    /// not-found alias is **not** an error.
    fn invalidate(&self, alias: &str) -> Result<(), KeystoreError>;

    /// Probe the device's hardware security posture: whether a hardware-backed
    /// key can be made and a secure lock screen is set (the §6.2 refuse-software
    /// pre-flight).
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::NoSecureLockOrHardware`] if the device has no
    /// secure lock screen or no usable `Keystore`, or another [`KeystoreError`]
    /// on a backend fault.
    fn probe(&self) -> Result<KeystoreSecurityLevel, KeystoreError>;
}

/// Transient state carried between the two unwrap phases for this backend.
///
/// Holds only `Send` plain data — the random alias, the non-secret IV, the
/// (encrypted, opaque) ciphertext, and the requested slot tag — so an
/// [`UnwrapHandle`] stays `Send` (invariant 3). No plaintext secret and no
/// foreign object is ever stored here.
#[derive(Debug)]
pub(crate) struct AndroidUnwrapState {
    /// The random `Keystore` alias whose key decrypts this blob.
    pub(crate) alias: String,
    /// The 12-byte GCM IV read from the blob.
    pub(crate) iv: [u8; GCM_IV_LEN],
    /// The ciphertext+tag to decrypt (opaque, encrypted — not a plaintext
    /// secret).
    pub(crate) ciphertext: Vec<u8>,
    /// The tag of the *requested* slot, used as the GCM AAD (invariant 7).
    pub(crate) slot_tag: u8,
}

// Compile-time proof of invariant 3: the two-phase handle (and the Android state
// it can carry) is `Send`, so `complete_unwrap` may run on a worker thread.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<AndroidUnwrapState>();
    assert_send::<UnwrapHandle>();
};

/// The Android hardware-`Keystore` backend (`HsmKind::AndroidGcm`, §6.4).
///
/// Pure-Rust orchestration over a foreign [`KeystoreWrapper`]; see the
/// [module docs](self). `PlatformCtx = ()` — the Kotlin shim holds whatever
/// Android `Context` / `Activity` it needs, so nothing crosses as a typed Rust
/// handle (the approved §6.5 amendment).
pub struct AndroidKeyStore {
    wrapper: Arc<dyn KeystoreWrapper>,
    /// The device security level, probed at most once and memoized (see
    /// [`Self::security_level`]). A device property, stable for the store's life.
    cached_level: OnceLock<KeystoreSecurityLevel>,
}

impl AndroidKeyStore {
    /// Build the backend over a concrete [`KeystoreWrapper`] (the Kotlin shim in
    /// production, a mock in host tests).
    #[must_use]
    pub fn new(wrapper: Arc<dyn KeystoreWrapper>) -> Self {
        Self {
            wrapper,
            cached_level: OnceLock::new(),
        }
    }

    /// The device's hardware security level, probed at most once then cached.
    ///
    /// `capabilities()` is advisory and may be called repeatedly (e.g. on a UI
    /// refresh); the level is a stable device property, and on a real device
    /// [`KeystoreWrapper::probe`] mints and destroys a key — so probe lazily and
    /// memoize. A probe *failure* is **not** cached: it falls back to the
    /// conservative [`KeystoreSecurityLevel::Software`] and is retried next call,
    /// so a transient failure cannot permanently mislabel the device.
    fn security_level(&self) -> KeystoreSecurityLevel {
        if let Some(level) = self.cached_level.get() {
            return *level;
        }
        match self.wrapper.probe() {
            Ok(level) => *self.cached_level.get_or_init(|| level),
            Err(_) => KeystoreSecurityLevel::Software,
        }
    }
}

impl HardwareKeyStore for AndroidKeyStore {
    type PlatformCtx = ();

    fn kind(&self) -> HsmKind {
        HsmKind::AndroidGcm
    }

    fn capabilities(&self) -> HsmCapabilities {
        // Surface the device security level (§6.2), memoized so an advisory call
        // never re-probes the hardware. A probe failure falls back conservatively
        // (see `security_level`) rather than propagating an error.
        let level = self.security_level();
        HsmCapabilities {
            // Semantics: the wrapping key is *user-auth gated* (`Keystore` keys
            // are minted `setUserAuthenticationRequired(true)`, so use requires a
            // device-credential or biometric unlock). This is **not** a guarantee
            // that a biometric is currently enrolled — the gate may be satisfied
            // by the device PIN/pattern/password. Callers must treat it as "an
            // auth prompt gates the key", not "fingerprint/face is available", and
            // must not over-trust it as proof of biometric enrollment. We report
            // `true` unconditionally rather than probing enrollment (no new
            // Android probing here).
            biometric_supported: true,
            strongbox_backed: matches!(level, KeystoreSecurityLevel::StrongBox),
            pcr_bound: false,
            // Advisory only: the biometric consecutive-failure lockout threshold
            // (see `BIOMETRIC_LOCKOUT_THRESHOLD`). Android *does* enforce a
            // hardware-backed lockout, so this is `Some`, not `None`.
            max_attempts_before_lockout: Some(BIOMETRIC_LOCKOUT_THRESHOLD),
            // A biometric lockout (including `ERROR_LOCKOUT_PERMANENT`) clears
            // when the user re-authenticates with the device credential — not a
            // timer and not a factory reset (§4.3, invariant 4).
            lockout_recovery: LockoutRecovery::UserAccountReset,
            supports_distinct_slot_pin: true,
        }
    }

    fn enroll(
        &self,
        slot: HsmSlot,
        material: &SecretBytes,
        _ctx: &Self::PlatformCtx,
        _prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError> {
        // Refuse-software pre-flight (§6.2): probe the device posture *before*
        // minting a key or prompting the user, so a software-only device is
        // rejected without a wasted keygen and biometric prompt. `security_level`
        // is memoized and falls back to `Software` on a probe failure (fail
        // closed). The post-wrap `wrapped.level` check below stays as the
        // authoritative belt-and-suspenders — `wrap` reports the key's real level.
        if matches!(self.security_level(), KeystoreSecurityLevel::Software) {
            return Err(HsmError::HardwareAbsent);
        }

        // `_prompter` is unused on Android (decision D-A1): a per-use-auth key's
        // `Cipher.doFinal` must run under a `CryptoObject` the prompt authorized,
        // which only the Kotlin shim can wire up — so the shim drives its own
        // `BiometricPrompt` inside `wrap`, and the generic prompter is moot here.
        let alias = random_alias();
        let wrapped = match self.wrapper.wrap(&alias, slot.tag(), material.expose()) {
            Ok(wrapped) => wrapped,
            Err(error) => {
                // Invariant 6: a key may exist before the failure point; delete it
                // so a retry cannot reuse a key that already produced a ciphertext.
                // Best-effort — the original failure is what we surface.
                let _ = self.wrapper.invalidate(&alias);
                return Err(map_keystore_error(error));
            }
        };

        // Refuse a software-backed key (§6.2): no TEE / `StrongBox` means no
        // hardware dictionary-attack protection, so it is not an acceptable HSM.
        // The just-created key is useless to us; remove it before refusing.
        if matches!(wrapped.level, KeystoreSecurityLevel::Software) {
            let _ = self.wrapper.invalidate(&alias);
            return Err(HsmError::HardwareAbsent);
        }

        // A real GCM ciphertext always carries the appended 16-byte tag; a
        // shorter one is a malformed wrap from the shim. Reject it (parity with
        // `decode_payload`) and delete the just-created key (invariant 6) rather
        // than durably persisting a blob that can never decrypt.
        if wrapped.ciphertext.len() < GCM_TAG_LEN {
            let _ = self.wrapper.invalidate(&alias);
            return Err(HsmError::Backend(
                "android wrap produced a ciphertext shorter than the GCM tag".to_owned(),
            ));
        }

        let payload = encode_payload(&alias, &wrapped.iv, &wrapped.ciphertext)?;
        WrappedBlob::from_parts(HsmKind::AndroidGcm, payload)
    }

    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<UnwrapHandle, HsmError> {
        if wrapped.kind() != HsmKind::AndroidGcm {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not AndroidGcm",
            });
        }
        let parsed = decode_payload(wrapped.payload())?;
        // The slot tag comes from the *requested* slot, never the blob
        // (invariant 7); it becomes the GCM AAD in `complete_unwrap`.
        Ok(UnwrapHandle::for_android(AndroidUnwrapState {
            alias: parsed.alias,
            iv: parsed.iv,
            ciphertext: parsed.ciphertext,
            slot_tag: slot.tag(),
        }))
    }

    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        _prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, HsmError> {
        // `_prompter` unused for the same reason as `enroll` (D-A1): the shim
        // drives its own `CryptoObject`-bound prompt inside `unwrap`.
        let state = handle.into_android()?;
        let plaintext = self
            .wrapper
            .unwrap(&state.alias, state.slot_tag, &state.iv, &state.ciphertext)
            .map_err(map_keystore_error)?;
        // The recovered secret crossed back from Kotlin as a plain `Vec<u8>` (the
        // accepted H3 residual); copy it into a zeroizing wrapper immediately.
        Ok(SecretBytes::new(plaintext))
    }

    fn invalidate(
        &self,
        _slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<(), HsmError> {
        if wrapped.kind() != HsmKind::AndroidGcm {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not AndroidGcm",
            });
        }
        let parsed = decode_payload(wrapped.payload())?;
        self.wrapper
            .invalidate(&parsed.alias)
            .map_err(map_keystore_error)
    }
}

/// Mint a fresh random `Keystore` alias: `passman-` followed by 128 bits of
/// `OsRng` entropy as lowercase hex. Random-only (invariant 8).
fn random_alias() -> String {
    let mut raw = [0u8; ALIAS_ENTROPY_LEN];
    fill_random(&mut raw);
    let mut alias = String::with_capacity("passman-".len() + raw.len() * 2);
    alias.push_str("passman-");
    for byte in raw {
        alias.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        alias.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    alias
}

/// Encode the §6.4 Android payload:
/// `name_len(u16-LE) ‖ alias(UTF-8) ‖ gcm_iv(12) ‖ ct_len(u16-LE) ‖
/// ciphertext+tag`.
fn encode_payload(
    alias: &str,
    iv: &[u8; GCM_IV_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HsmError> {
    let name_len = u16::try_from(alias.len()).map_err(|_| HsmError::MalformedBlob {
        reason: "android alias exceeds u16::MAX bytes",
    })?;
    let ct_len = u16::try_from(ciphertext.len()).map_err(|_| HsmError::MalformedBlob {
        reason: "android ciphertext exceeds u16::MAX bytes",
    })?;

    let mut payload = Vec::with_capacity(2 + alias.len() + GCM_IV_LEN + 2 + ciphertext.len());
    payload.extend_from_slice(&name_len.to_le_bytes());
    payload.extend_from_slice(alias.as_bytes());
    payload.extend_from_slice(iv);
    payload.extend_from_slice(&ct_len.to_le_bytes());
    payload.extend_from_slice(ciphertext);
    Ok(payload)
}

/// The parsed §6.4 Android payload. Holds only non-secret framing plus the
/// (encrypted, opaque) ciphertext, so deriving `Debug` leaks nothing.
#[derive(Debug)]
struct ParsedPayload {
    alias: String,
    iv: [u8; GCM_IV_LEN],
    ciphertext: Vec<u8>,
}

/// Parse the §6.4 Android payload. Fully bounds-checked and panic-free (the blob
/// sits on disk and is attacker-controllable): every length is validated against
/// the remaining input and trailing bytes are rejected.
fn decode_payload(payload: &[u8]) -> Result<ParsedPayload, HsmError> {
    let mut cursor = payload;

    // name_len(2) ‖ alias
    let alias_bytes = read_len_prefixed(&mut cursor)?;
    let alias = String::from_utf8(alias_bytes).map_err(|_| HsmError::MalformedBlob {
        reason: "android alias is not valid UTF-8",
    })?;

    // gcm_iv(12)
    let (iv_slice, rest) = cursor
        .split_at_checked(GCM_IV_LEN)
        .ok_or(HsmError::MalformedBlob {
            reason: "android payload truncated in gcm_iv",
        })?;
    let mut iv = [0u8; GCM_IV_LEN];
    iv.copy_from_slice(iv_slice);
    cursor = rest;

    // ct_len(2) ‖ ciphertext
    let ciphertext = read_len_prefixed(&mut cursor)?;

    if !cursor.is_empty() {
        return Err(HsmError::MalformedBlob {
            reason: "trailing bytes after android payload",
        });
    }

    // The GCM ciphertext must contain at least the 16-byte tag.
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(HsmError::MalformedBlob {
            reason: "android ciphertext shorter than GCM tag",
        });
    }

    Ok(ParsedPayload {
        alias,
        iv,
        ciphertext,
    })
}

/// Read a `u16-LE` length prefix and that many bytes, advancing `cursor`. Fully
/// bounds-checked (the blob is attacker-controllable on disk).
fn read_len_prefixed(cursor: &mut &[u8]) -> Result<Vec<u8>, HsmError> {
    let (len_bytes, rest) = cursor.split_at_checked(2).ok_or(HsmError::MalformedBlob {
        reason: "android payload truncated in a length prefix",
    })?;
    let len = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
    let (data, rest) = rest.split_at_checked(len).ok_or(HsmError::MalformedBlob {
        reason: "android length prefix exceeds remaining input",
    })?;
    *cursor = rest;
    Ok(data.to_vec())
}

/// Map a [`KeystoreError`] to the crate [`HsmError`] taxonomy per the §4.3
/// routing.
///
/// Invariant 4: a biometric lockout — **including `ERROR_LOCKOUT_PERMANENT`** —
/// is [`HsmError::Transient`], not [`HsmError::PermanentlyInvalidated`]. Only a
/// genuinely invalidated *key* ([`KeystoreError::KeyInvalidated`]) routes to the
/// destructive recovery path; a lockout leaves the key intact.
fn map_keystore_error(error: KeystoreError) -> HsmError {
    match error {
        KeystoreError::Cancelled => HsmError::Cancelled,
        KeystoreError::Lockout => HsmError::Transient,
        KeystoreError::KeyInvalidated => HsmError::PermanentlyInvalidated,
        KeystoreError::AuthFailed => HsmError::MalformedBlob {
            reason: "android AES-GCM authentication failed (wrong slot or tampered blob)",
        },
        KeystoreError::NoSecureLockOrHardware => HsmError::HardwareAbsent,
        KeystoreError::Backend => HsmError::Backend("android keystore backend error".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use passman_crypto::{aead, fill_random, random_secret, SecretArray, SecretBytes};

    use super::{
        decode_payload, encode_payload, map_keystore_error, AndroidKeyStore, KeystoreError,
        KeystoreSecurityLevel, KeystoreWrapper, WrappedParts, GCM_IV_LEN, GCM_TAG_LEN,
    };
    use crate::blob::WrappedBlob;
    use crate::capabilities::LockoutRecovery;
    use crate::error::HsmError;
    use crate::prompt::{BiometricPrompter, PromptResult};
    use crate::slot::{HsmKind, HsmSlot};
    use crate::store::HardwareKeyStore;

    // ---- Test doubles -----------------------------------------------------

    /// A no-op prompter. `AndroidKeyStore` never calls the generic prompter
    /// (D-A1), so its outcome is irrelevant; this only satisfies the signatures.
    struct NoopPrompter;
    impl BiometricPrompter for NoopPrompter {
        fn prompt(&self, _reason: String) -> Result<PromptResult, HsmError> {
            Ok(PromptResult::Authenticated)
        }
    }

    /// Test-only `KeystoreWrapper` doing **real** XChaCha20-Poly1305 AEAD with
    /// `AAD = [slot_tag]`, so the host integration tests exercise the genuine
    /// cross-slot / tamper binding rather than a no-op. Not a security backend.
    ///
    /// The `0x02` wire IV is 12 bytes (real Android GCM); the host AEAD nonce is
    /// 24 bytes. The mock derives its nonce from the stored IV by zero-extension
    /// — sound here because each mock key wraps exactly one secret, so the nonce
    /// is used once and uniqueness holds trivially.
    struct MockKeystoreWrapper {
        keys: Mutex<HashMap<String, SecretArray<32>>>,
        level: KeystoreSecurityLevel,
        // When set, `wrap` simulates "key created, then the op failed": it stores
        // the key (so the orchestrator's cleanup is observable) then returns Err.
        fail_wrap: bool,
        // When set, `wrap` returns Ok but with a ciphertext shorter than the GCM
        // tag (a malformed wrap), to exercise enroll's length guard.
        short_ciphertext: bool,
        // When set, `probe` returns an error (for the capabilities fallback test).
        fail_probe: bool,
        // Counts `probe` invocations, so the memoization test can assert
        // `capabilities()` does not re-probe the hardware on every call.
        probe_calls: AtomicUsize,
    }

    impl MockKeystoreWrapper {
        fn new() -> Self {
            Self {
                keys: Mutex::new(HashMap::new()),
                level: KeystoreSecurityLevel::TrustedEnvironment,
                fail_wrap: false,
                short_ciphertext: false,
                fail_probe: false,
                probe_calls: AtomicUsize::new(0),
            }
        }

        fn with_level(level: KeystoreSecurityLevel) -> Self {
            Self {
                level,
                ..Self::new()
            }
        }

        fn failing_wrap() -> Self {
            Self {
                fail_wrap: true,
                ..Self::new()
            }
        }

        fn short_ciphertext() -> Self {
            Self {
                short_ciphertext: true,
                ..Self::new()
            }
        }

        fn failing_probe() -> Self {
            Self {
                fail_probe: true,
                ..Self::new()
            }
        }

        fn key_count(&self) -> usize {
            self.keys.lock().expect("mock keys mutex").len()
        }

        fn probe_call_count(&self) -> usize {
            self.probe_calls.load(Ordering::Relaxed)
        }

        /// Zero-extend the 12-byte GCM IV to the 24-byte `XChaCha20` nonce.
        fn nonce_from_iv(iv: &[u8]) -> [u8; aead::NONCE_LEN] {
            let mut nonce = [0u8; aead::NONCE_LEN];
            nonce[..iv.len()].copy_from_slice(iv);
            nonce
        }
    }

    impl KeystoreWrapper for MockKeystoreWrapper {
        fn wrap(
            &self,
            alias: &str,
            slot_tag: u8,
            material: &[u8],
        ) -> Result<WrappedParts, KeystoreError> {
            let key = random_secret::<32>();
            let mut iv = [0u8; GCM_IV_LEN];
            fill_random(&mut iv);
            let nonce = Self::nonce_from_iv(&iv);
            let ciphertext = aead::encrypt(&key, &nonce, &[slot_tag], material)
                .map_err(|_| KeystoreError::Backend)?;
            self.keys
                .lock()
                .expect("mock keys mutex")
                .insert(alias.to_owned(), key);
            if self.fail_wrap {
                // Simulate a post-keygen failure: the key now exists (above), so
                // the orchestrator's invariant-6 cleanup is observable.
                return Err(KeystoreError::Backend);
            }
            if self.short_ciphertext {
                // Simulate a malformed wrap: a ciphertext shorter than the 16-byte
                // GCM tag. The key exists (above) so enroll's cleanup is observable.
                return Ok(WrappedParts {
                    iv,
                    ciphertext: vec![0u8; GCM_TAG_LEN - 1],
                    level: self.level,
                });
            }
            Ok(WrappedParts {
                iv,
                ciphertext,
                level: self.level,
            })
        }

        fn unwrap(
            &self,
            alias: &str,
            slot_tag: u8,
            iv: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, KeystoreError> {
            let keys = self.keys.lock().expect("mock keys mutex");
            // Parity with the real backend: an unknown/destroyed alias means
            // `KeyStore.getKey()` returns null, which the Kotlin shim normalizes
            // to `KeystoreError::Backend` (not `KeyInvalidated`, which is reserved
            // for a `KeyPermanentlyInvalidatedException` on an existing key).
            let key = keys.get(alias).ok_or(KeystoreError::Backend)?;
            let nonce = Self::nonce_from_iv(iv);
            let plaintext = aead::decrypt(key, &nonce, &[slot_tag], ciphertext)
                .map_err(|_| KeystoreError::AuthFailed)?;
            Ok(plaintext.expose().to_vec())
        }

        fn invalidate(&self, alias: &str) -> Result<(), KeystoreError> {
            self.keys.lock().expect("mock keys mutex").remove(alias);
            Ok(())
        }

        fn probe(&self) -> Result<KeystoreSecurityLevel, KeystoreError> {
            self.probe_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_probe {
                return Err(KeystoreError::NoSecureLockOrHardware);
            }
            Ok(self.level)
        }
    }

    fn material() -> SecretBytes {
        SecretBytes::new(vec![0x42; 32])
    }

    fn sample_iv() -> [u8; GCM_IV_LEN] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    }

    // ---- Codec (Task 2) ---------------------------------------------------

    #[test]
    fn payload_round_trips() {
        let alias = "passman-0123456789abcdef";
        let iv = sample_iv();
        let ciphertext = vec![0xAB; 48];
        let bytes = encode_payload(alias, &iv, &ciphertext).expect("encode");
        let parsed = decode_payload(&bytes).expect("decode");
        assert_eq!(parsed.alias, alias);
        assert_eq!(parsed.iv, iv);
        assert_eq!(parsed.ciphertext, ciphertext);
    }

    #[test]
    fn empty_alias_round_trips() {
        let iv = sample_iv();
        let ciphertext = vec![0u8; GCM_TAG_LEN];
        let bytes = encode_payload("", &iv, &ciphertext).expect("encode");
        let parsed = decode_payload(&bytes).expect("decode");
        assert_eq!(parsed.alias, "");
        assert_eq!(parsed.ciphertext, ciphertext);
    }

    #[test]
    fn max_u16_alias_and_ct_round_trip() {
        let alias = "a".repeat(usize::from(u16::MAX));
        let iv = sample_iv();
        let ciphertext = vec![0x5A; usize::from(u16::MAX)];
        let bytes = encode_payload(&alias, &iv, &ciphertext).expect("encode");
        let parsed = decode_payload(&bytes).expect("decode");
        assert_eq!(parsed.alias.len(), usize::from(u16::MAX));
        assert_eq!(parsed.ciphertext.len(), usize::from(u16::MAX));
    }

    #[test]
    fn multibyte_utf8_alias_round_trips() {
        let alias = "paßmañ-日本語-🔐";
        let iv = sample_iv();
        let ciphertext = vec![0u8; 20];
        let bytes = encode_payload(alias, &iv, &ciphertext).expect("encode");
        let parsed = decode_payload(&bytes).expect("decode");
        assert_eq!(parsed.alias, alias);
    }

    #[test]
    fn all_zero_iv_round_trips() {
        let iv = [0u8; GCM_IV_LEN];
        let ciphertext = vec![0x11; 32];
        let bytes = encode_payload("x", &iv, &ciphertext).expect("encode");
        let parsed = decode_payload(&bytes).expect("decode");
        assert_eq!(parsed.iv, iv);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode_payload("x", &sample_iv(), &[0u8; 16]).expect("encode");
        bytes.push(0xFF);
        let err = decode_payload(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "trailing bytes after android payload"
            }
        ));
    }

    #[test]
    fn decode_rejects_truncated_iv() {
        // name_len = 0, then only 5 bytes where 12 IV bytes are required.
        let bytes = [0x00, 0x00, 1, 2, 3, 4, 5];
        let err = decode_payload(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "android payload truncated in gcm_iv"
            }
        ));
    }

    #[test]
    fn decode_rejects_non_utf8_alias() {
        // name_len = 2, alias = 0xFF 0xFF (invalid UTF-8), then a valid IV and a
        // 16-byte ciphertext so only the UTF-8 check can fail.
        let mut bytes = vec![0x02, 0x00, 0xFF, 0xFF];
        bytes.extend_from_slice(&sample_iv());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        let err = decode_payload(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "android alias is not valid UTF-8"
            }
        ));
    }

    #[test]
    fn decode_rejects_ct_len_over_remaining() {
        // ct_len declares 100 bytes but only 20 follow.
        let mut bytes = vec![0x00, 0x00];
        bytes.extend_from_slice(&sample_iv());
        bytes.extend_from_slice(&100u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 20]);
        let err = decode_payload(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "android length prefix exceeds remaining input"
            }
        ));
    }

    #[test]
    fn decode_rejects_undersized_ciphertext() {
        // A well-framed payload whose ciphertext is shorter than the GCM tag.
        let bytes = encode_payload("x", &sample_iv(), &[0u8; GCM_TAG_LEN - 1]).expect("encode");
        let err = decode_payload(&bytes).expect_err("must reject");
        assert!(matches!(
            err,
            HsmError::MalformedBlob {
                reason: "android ciphertext shorter than GCM tag"
            }
        ));
    }

    #[test]
    fn encode_rejects_alias_over_u16() {
        let alias = "a".repeat(usize::from(u16::MAX) + 1);
        let err = encode_payload(&alias, &sample_iv(), &[0u8; 16]).expect_err("must reject");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn encode_rejects_ct_over_u16() {
        let ciphertext = vec![0u8; usize::from(u16::MAX) + 1];
        let err = encode_payload("x", &sample_iv(), &ciphertext).expect_err("must reject");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_suffixes() {
        // Calling the parser is the assertion (a panic aborts the test). Seed with
        // a valid name_len+alias prefix so recursion reaches the IV/ct boundaries.
        fn recurse(buf: &mut Vec<u8>, alphabet: &[u8], depth: usize) {
            let _ = decode_payload(buf);
            if depth == 0 {
                return;
            }
            for &b in alphabet {
                buf.push(b);
                recurse(buf, alphabet, depth - 1);
                buf.pop();
            }
        }
        let alphabet = [0x00u8, 0x01, 0x0c, 0xFF];
        let mut seeded = vec![0x03, 0x00, b'a', b'b', b'c'];
        recurse(&mut seeded, &alphabet, 6);
        let mut from_empty = Vec::new();
        recurse(&mut from_empty, &alphabet, 5);
    }

    // ---- Orchestration vs the real-AEAD mock (Task 4) ---------------------

    #[test]
    fn enroll_then_unwrap_roundtrips_both_slots() {
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock.clone());
        let prompter = NoopPrompter;

        for slot in [HsmSlot::VaultKey, HsmSlot::TotpSeed] {
            let secret = material();
            let blob = store.enroll(slot, &secret, &(), &prompter).expect("enroll");
            assert_eq!(blob.kind(), HsmKind::AndroidGcm);

            let handle = store.begin_unwrap(slot, &blob, &()).expect("begin");
            let recovered = store.complete_unwrap(handle, &prompter).expect("complete");
            assert_eq!(recovered.expose(), secret.expose());
        }
        // Two slots → two distinct keys.
        assert_eq!(mock.key_count(), 2);
    }

    #[test]
    fn cross_slot_blob_is_rejected() {
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock);
        let prompter = NoopPrompter;
        let secret = material();

        // Enrolled for VaultKey (AAD = [0x00]).
        let blob = store
            .enroll(HsmSlot::VaultKey, &secret, &(), &prompter)
            .expect("enroll");

        // begin_unwrap as TotpSeed succeeds (no slot is stored in the blob)...
        let handle = store
            .begin_unwrap(HsmSlot::TotpSeed, &blob, &())
            .expect("begin");
        // ...but completing recomputes AAD = [TotpSeed], which no longer matches
        // the sealed [VaultKey] AAD, so the GCM tag fails → MalformedBlob.
        let err = store
            .complete_unwrap(handle, &prompter)
            .expect_err("cross-slot must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock);
        let prompter = NoopPrompter;
        let secret = material();

        let blob = store
            .enroll(HsmSlot::VaultKey, &secret, &(), &prompter)
            .expect("enroll");

        // Flip the last payload byte (inside the ciphertext+tag region).
        let mut payload = blob.payload().to_vec();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        let tampered = WrappedBlob::from_parts(HsmKind::AndroidGcm, payload).expect("from_parts");

        let handle = store
            .begin_unwrap(HsmSlot::VaultKey, &tampered, &())
            .expect("begin");
        let err = store
            .complete_unwrap(handle, &prompter)
            .expect_err("tamper must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn repeat_unwrap_of_persisted_blob() {
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock);
        let prompter = NoopPrompter;
        let secret = material();

        let blob = store
            .enroll(HsmSlot::VaultKey, &secret, &(), &prompter)
            .expect("enroll");
        // Round-trip through the outer wire format to simulate on-disk persistence.
        let persisted = WrappedBlob::from_bytes(&blob.to_bytes()).expect("persist");

        for _ in 0..2 {
            let handle = store
                .begin_unwrap(HsmSlot::VaultKey, &persisted, &())
                .expect("begin");
            let recovered = store.complete_unwrap(handle, &prompter).expect("complete");
            assert_eq!(recovered.expose(), secret.expose());
        }
    }

    #[test]
    fn enroll_failure_deletes_key() {
        // Invariant 6: a wrap failure after keygen must leave no lingering key.
        let mock = Arc::new(MockKeystoreWrapper::failing_wrap());
        let store = AndroidKeyStore::new(mock.clone());
        let prompter = NoopPrompter;

        let err = store
            .enroll(HsmSlot::VaultKey, &material(), &(), &prompter)
            .expect_err("wrap failure must surface");
        assert!(matches!(err, HsmError::Backend(_)));
        assert_eq!(mock.key_count(), 0, "key must be deleted on enroll failure");
    }

    #[test]
    fn enroll_rejects_undersized_ciphertext() {
        // A wrap returning a ciphertext shorter than the 16-byte GCM tag is
        // malformed; enroll must reject it with `Backend` before persisting a
        // blob, and delete the just-created key (invariant 6).
        let mock = Arc::new(MockKeystoreWrapper::short_ciphertext());
        let store = AndroidKeyStore::new(mock.clone());
        let prompter = NoopPrompter;

        let err = store
            .enroll(HsmSlot::VaultKey, &material(), &(), &prompter)
            .expect_err("undersized ciphertext must be rejected");
        assert!(matches!(err, HsmError::Backend(_)));
        assert_eq!(mock.key_count(), 0, "rejected wrap must delete the key");
    }

    #[test]
    fn software_level_is_refused() {
        // §6.2: a software-backed key has no hardware DA protection → refuse, and
        // delete the just-created key.
        let mock = Arc::new(MockKeystoreWrapper::with_level(
            KeystoreSecurityLevel::Software,
        ));
        let store = AndroidKeyStore::new(mock.clone());
        let prompter = NoopPrompter;

        let err = store
            .enroll(HsmSlot::VaultKey, &material(), &(), &prompter)
            .expect_err("software must be refused");
        assert!(matches!(err, HsmError::HardwareAbsent));
        assert_eq!(mock.key_count(), 0, "refused software key must be deleted");
    }

    #[test]
    fn wrong_kind_blob_rejected() {
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock);

        // A SoftwareMock-kind blob must be rejected by the Android backend.
        let blob =
            WrappedBlob::from_parts(HsmKind::SoftwareMock, vec![0u8; 64]).expect("from_parts");
        let err = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect_err("wrong kind must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn invalidate_destroys_key() {
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock.clone());
        let prompter = NoopPrompter;

        let blob = store
            .enroll(HsmSlot::VaultKey, &material(), &(), &prompter)
            .expect("enroll");
        assert_eq!(mock.key_count(), 1);

        store
            .invalidate(HsmSlot::VaultKey, &blob, &())
            .expect("invalidate");
        assert_eq!(mock.key_count(), 0);

        // A subsequent unwrap of the same blob now finds no key. The real
        // backend's `getKey()` returns null for a destroyed alias, which routes
        // to `KeystoreError::Backend` -> `HsmError::Backend` (see the mock's
        // `unwrap`); `KeyInvalidated`/`PermanentlyInvalidated` is reserved for an
        // existing-but-invalidated key, not a missing one.
        let handle = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect("begin");
        let err = store
            .complete_unwrap(handle, &prompter)
            .expect_err("key gone");
        assert!(matches!(err, HsmError::Backend(_)));
    }

    // ---- Capabilities (probe surfacing) -----------------------------------

    #[test]
    fn capabilities_surface_strongbox() {
        let store = AndroidKeyStore::new(Arc::new(MockKeystoreWrapper::with_level(
            KeystoreSecurityLevel::StrongBox,
        )));
        let caps = store.capabilities();
        assert!(caps.strongbox_backed);
        assert!(caps.biometric_supported);
        assert_eq!(caps.lockout_recovery, LockoutRecovery::UserAccountReset);
    }

    #[test]
    fn capabilities_tee_is_not_strongbox() {
        let store = AndroidKeyStore::new(Arc::new(MockKeystoreWrapper::new()));
        let caps = store.capabilities();
        assert!(!caps.strongbox_backed);
    }

    #[test]
    fn capabilities_probe_failure_falls_back_conservatively() {
        let store = AndroidKeyStore::new(Arc::new(MockKeystoreWrapper::failing_probe()));
        let caps = store.capabilities();
        assert!(!caps.strongbox_backed);
    }

    #[test]
    fn capabilities_probe_is_memoized() {
        // On a real device `probe()` mints+destroys a key; `capabilities()` must
        // not re-probe on every call (review finding). Probe once, then cache.
        let mock = Arc::new(MockKeystoreWrapper::new());
        let store = AndroidKeyStore::new(mock.clone());
        for _ in 0..3 {
            let _ = store.capabilities();
        }
        assert_eq!(
            mock.probe_call_count(),
            1,
            "probe must be memoized, not called per capabilities()"
        );
    }

    // ---- Error routing (Task 5, §4.3) -------------------------------------

    #[test]
    fn maps_keystore_errors_per_section_4_3() {
        assert!(matches!(
            map_keystore_error(KeystoreError::Cancelled),
            HsmError::Cancelled
        ));
        // Load-bearing (invariant 4): a lockout is Transient, NOT Permanent.
        assert!(matches!(
            map_keystore_error(KeystoreError::Lockout),
            HsmError::Transient
        ));
        assert!(matches!(
            map_keystore_error(KeystoreError::KeyInvalidated),
            HsmError::PermanentlyInvalidated
        ));
        assert!(matches!(
            map_keystore_error(KeystoreError::AuthFailed),
            HsmError::MalformedBlob { .. }
        ));
        assert!(matches!(
            map_keystore_error(KeystoreError::NoSecureLockOrHardware),
            HsmError::HardwareAbsent
        ));
        assert!(matches!(
            map_keystore_error(KeystoreError::Backend),
            HsmError::Backend(_)
        ));
    }

    // ---- Slot-tag binding guard (Task 6) ----------------------------------

    #[test]
    fn slot_tags_are_distinct_and_pinned() {
        assert_ne!(HsmSlot::VaultKey.tag(), HsmSlot::TotpSeed.tag());
        assert_eq!(HsmSlot::VaultKey.tag(), 0x00);
        assert_eq!(HsmSlot::TotpSeed.tag(), 0x01);
    }
}
