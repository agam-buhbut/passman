//! Software mock backend — **TEST/DEV ONLY**.
//!
//! # ⚠️ No hardware protection
//!
//! [`MockKeyStore`] simulates an HSM by AEAD-wrapping slot material under an
//! **in-memory** key. That key lives in this process's heap with the same
//! protection as any other secret — i.e. **none of the hardware guarantees** a
//! real TPM / Keystore / Secure Enclave provides. It exists so `passman-core`
//! can exercise the unlock pipeline and its [`HsmError`] routing without real
//! hardware.
//!
//! **This backend must never be selected in production.** Refusing it in
//! production builds is `passman-core`'s responsibility (the equivalent of the
//! `--allow-software-hsm` opt-in, §6.2); this crate only provides the simulator.
//!
//! # What it simulates
//!
//! - `enroll` drives the prompter first (Android prompts on encrypt too, §6.4),
//!   then AEAD-encrypts the material under the mock key with a fresh random
//!   nonce, binding the [`HsmSlot`] into the associated data so a `VaultKey`
//!   blob cannot be unwrapped as a `TotpSeed`.
//! - `begin_unwrap` validates the blob (kind must be [`HsmKind::SoftwareMock`])
//!   and stashes what `complete_unwrap` needs in the [`UnwrapHandle`].
//! - `complete_unwrap` drives the prompter, then AEAD-decrypts; tamper or wrong
//!   key surfaces as [`HsmError::Backend`] with no secret leakage.
//!
//! Forced-failure constructors ([`MockKeyStore::failing`] et al.) make every
//! operation return a chosen [`HsmError`] so core can test error routing.

use std::time::Duration;

use passman_crypto::{aead, random_nonce, random_secret, SecretArray, SecretBytes};

use crate::blob::WrappedBlob;
use crate::capabilities::{HsmCapabilities, HsmLockoutStatus, LockoutRecovery};
use crate::error::HsmError;
use crate::handle::UnwrapHandle;
use crate::prompt::{BiometricPrompter, PromptResult};
use crate::slot::{HsmKind, HsmSlot};
use crate::store::HardwareKeyStore;

/// AEAD associated-data domain prefix for mock-wrapped material. The slot tag
/// is appended so the two slots are cryptographically distinct.
const MOCK_AAD_DOMAIN: &[u8] = b"passman-hsm-mock-v0";

/// Length of the XChaCha20-Poly1305 nonce embedded in the mock payload.
const NONCE_LEN: usize = 24;

/// Forced-failure configuration for [`MockKeyStore`].
///
/// A dedicated enum (rather than storing an [`HsmError`]) keeps `HsmError`
/// non-`Clone` while letting the store reproduce the chosen failure on every
/// call without interior mutability — so the store stays `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockFailure {
    /// Every op fails with [`HsmError::Transient`].
    Transient,
    /// Every op fails with [`HsmError::HardwareAbsent`].
    HardwareAbsent,
    /// Every op fails with [`HsmError::PermanentlyInvalidated`].
    PermanentlyInvalidated,
    /// Every op fails with [`HsmError::Cancelled`].
    Cancelled,
}

impl MockFailure {
    fn to_error(self) -> HsmError {
        match self {
            Self::Transient => HsmError::Transient,
            Self::HardwareAbsent => HsmError::HardwareAbsent,
            Self::PermanentlyInvalidated => HsmError::PermanentlyInvalidated,
            Self::Cancelled => HsmError::Cancelled,
        }
    }
}

/// An in-memory, software-only stand-in for a hardware key store.
///
/// See the [module docs](self) — this provides **no hardware protection** and
/// must never be selected in production.
pub struct MockKeyStore {
    /// The in-memory "hardware" wrapping key. Zeroized on drop via the type.
    key: SecretArray<32>,
    /// When set, every operation returns this failure (for testing core's
    /// error routing).
    forced_failure: Option<MockFailure>,
    /// When set, [`HardwareKeyStore::lockout_status`] reports a native lockout
    /// with this remaining cooldown (for testing core's §4.3 step-3 check). The
    /// enroll/unwrap ops are unaffected — a real device's lockout is queried
    /// separately from the wrap/unwrap path.
    lockout: Option<Duration>,
}

impl MockKeyStore {
    /// A working mock with a fresh random in-memory wrapping key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: random_secret::<32>(),
            forced_failure: None,
            lockout: None,
        }
    }

    /// A working mock that reports a native DA lockout for `retry_after` via
    /// [`HardwareKeyStore::lockout_status`] (test/dev only). `enroll` and the
    /// unwrap phases still function, so core's §4.3 step-3 short-circuit (which
    /// must fire *before* any unwrap or prompt) can be exercised.
    #[must_use]
    pub fn locked_for(retry_after: Duration) -> Self {
        Self {
            key: random_secret::<32>(),
            forced_failure: None,
            lockout: Some(retry_after),
        }
    }

    /// A mock whose every operation fails with `error`.
    ///
    /// Only the no-payload [`HsmError`] variants are forceable
    /// ([`HsmError::Transient`], [`HsmError::Cancelled`],
    /// [`HsmError::HardwareAbsent`], [`HsmError::PermanentlyInvalidated`]),
    /// which are the ones whose routing core needs to test. A
    /// [`HsmError::Backend`] / [`HsmError::MalformedBlob`] argument falls back
    /// to [`HsmError::Transient`] (those arise naturally from real inputs, not
    /// forcing).
    // Takes `HsmError` by value to mirror the documented constructor shape and
    // because the matched-over `Backend(String)` variant owns its payload;
    // requiring `&HsmError` would be a worse constructor API.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn failing(error: HsmError) -> Self {
        let failure = match error {
            HsmError::Cancelled => MockFailure::Cancelled,
            HsmError::HardwareAbsent => MockFailure::HardwareAbsent,
            HsmError::PermanentlyInvalidated => MockFailure::PermanentlyInvalidated,
            HsmError::Transient | HsmError::Backend(_) | HsmError::MalformedBlob { .. } => {
                MockFailure::Transient
            }
        };
        Self {
            key: random_secret::<32>(),
            forced_failure: Some(failure),
            lockout: None,
        }
    }

    /// A mock whose every operation fails with [`HsmError::Transient`].
    #[must_use]
    pub fn failing_transient() -> Self {
        Self::with_failure(MockFailure::Transient)
    }

    /// A mock whose every operation fails with [`HsmError::HardwareAbsent`].
    #[must_use]
    pub fn failing_hardware_absent() -> Self {
        Self::with_failure(MockFailure::HardwareAbsent)
    }

    /// A mock whose every operation fails with [`HsmError::PermanentlyInvalidated`].
    #[must_use]
    pub fn failing_permanently_invalidated() -> Self {
        Self::with_failure(MockFailure::PermanentlyInvalidated)
    }

    fn with_failure(failure: MockFailure) -> Self {
        Self {
            key: random_secret::<32>(),
            forced_failure: Some(failure),
            lockout: None,
        }
    }

    /// The associated data binding a payload to its slot: domain ‖ slot tag.
    fn aad(slot: HsmSlot) -> [u8; MOCK_AAD_DOMAIN.len() + 1] {
        let mut aad = [0u8; MOCK_AAD_DOMAIN.len() + 1];
        aad[..MOCK_AAD_DOMAIN.len()].copy_from_slice(MOCK_AAD_DOMAIN);
        aad[MOCK_AAD_DOMAIN.len()] = slot.tag();
        aad
    }

    /// Return the forced failure as an `Err`, if one is configured.
    fn check_forced(&self) -> Result<(), HsmError> {
        match self.forced_failure {
            Some(failure) => Err(failure.to_error()),
            None => Ok(()),
        }
    }
}

impl Default for MockKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareKeyStore for MockKeyStore {
    type PlatformCtx = ();

    fn kind(&self) -> HsmKind {
        HsmKind::SoftwareMock
    }

    fn capabilities(&self) -> HsmCapabilities {
        // Values chosen so core's UX code has something concrete to exercise;
        // none of it implies real protection.
        HsmCapabilities {
            biometric_supported: true,
            strongbox_backed: false,
            pcr_bound: false,
            max_attempts_before_lockout: None,
            lockout_recovery: LockoutRecovery::TimeBased {
                reset_after: Duration::from_secs(0),
            },
            supports_distinct_slot_pin: true,
        }
    }

    fn lockout_status(&self, _ctx: &Self::PlatformCtx) -> Result<HsmLockoutStatus, HsmError> {
        Ok(match self.lockout {
            Some(retry_after) => HsmLockoutStatus::LockedOut {
                retry_after: Some(retry_after),
            },
            None => HsmLockoutStatus::Available,
        })
    }

    fn enroll(
        &self,
        slot: HsmSlot,
        material: &SecretBytes,
        _ctx: &Self::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError> {
        self.check_forced()?;

        // Android prompts on encrypt too (§6.4): drive the prompt first.
        match prompter.prompt("Enroll passman key".to_owned())? {
            PromptResult::Authenticated | PromptResult::FallbackToPin(_) => {}
            PromptResult::Cancelled => return Err(HsmError::Cancelled),
        }

        let nonce = random_nonce();
        let aad = Self::aad(slot);
        let ct = aead::encrypt(&self.key, &nonce, &aad, material.expose())
            .map_err(|_| HsmError::Backend("mock AEAD encrypt failed".to_owned()))?;

        // Payload: slot_tag(1) ‖ nonce(24) ‖ ct+tag. The slot tag is redundant
        // with the AAD binding (the AAD is what enforces it) but is stored so
        // `begin_unwrap` can reconstruct the AAD without re-deriving the slot.
        let mut payload = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        payload.push(slot.tag());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ct);

        WrappedBlob::from_parts(HsmKind::SoftwareMock, payload)
    }

    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<UnwrapHandle, HsmError> {
        self.check_forced()?;

        if wrapped.kind() != HsmKind::SoftwareMock {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not SoftwareMock",
            });
        }

        let payload = wrapped.payload();
        // Minimum payload: slot tag + nonce + an empty-plaintext tag (16 bytes).
        let nonce_end = 1 + NONCE_LEN;
        let stored_tag = *payload.first().ok_or(HsmError::MalformedBlob {
            reason: "mock payload missing slot tag",
        })?;
        let nonce_slice = payload.get(1..nonce_end).ok_or(HsmError::MalformedBlob {
            reason: "mock payload truncated before nonce end",
        })?;
        let ct = payload.get(nonce_end..).ok_or(HsmError::MalformedBlob {
            reason: "mock payload missing ciphertext",
        })?;

        // The stored slot tag must match the slot we were asked to unwrap. The
        // AAD check in `complete_unwrap` is the authoritative cryptographic
        // binding; this is a fail-fast clarity check.
        if stored_tag != slot.tag() {
            return Err(HsmError::MalformedBlob {
                reason: "mock payload slot tag does not match requested slot",
            });
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);

        Ok(UnwrapHandle::for_mock(MockUnwrapState {
            slot_tag: slot.tag(),
            nonce,
            ciphertext: SecretBytes::new(ct.to_vec()),
            key: SecretArray::new(*self.key.expose()),
        }))
    }

    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, HsmError> {
        self.check_forced()?;

        // Drive the prompt before releasing any material.
        match prompter.prompt("Unlock passman key".to_owned())? {
            PromptResult::Authenticated | PromptResult::FallbackToPin(_) => {}
            PromptResult::Cancelled => return Err(HsmError::Cancelled),
        }

        // `into_mock` now fails closed (returns `Err`) if the handle was minted
        // by another backend, rather than panicking; propagate that.
        let state = handle.into_mock()?;

        // Rebuild the AAD from the stored slot tag; a tampered tag, wrong slot,
        // or wrong key all fail the AEAD with a detail-free error.
        let mut aad = [0u8; MOCK_AAD_DOMAIN.len() + 1];
        aad[..MOCK_AAD_DOMAIN.len()].copy_from_slice(MOCK_AAD_DOMAIN);
        aad[MOCK_AAD_DOMAIN.len()] = state.slot_tag;

        aead::decrypt(&state.key, &state.nonce, &aad, state.ciphertext.expose())
            .map_err(|_| HsmError::Backend("mock AEAD decrypt/verify failed".to_owned()))
    }

    fn invalidate(
        &self,
        _slot: HsmSlot,
        _wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<(), HsmError> {
        self.check_forced()?;
        // No persistent state to destroy in the mock; the in-memory key is
        // dropped (and zeroized) when the store is dropped.
        Ok(())
    }
}

/// Transient state the mock stashes in an [`UnwrapHandle`] between phases.
///
/// Holds a copy of the in-memory key and the parsed ciphertext. Both secret
/// fields are `passman-crypto` zeroizing wrappers ([`SecretArray`] /
/// [`SecretBytes`]), so dropping this struct — whether after `complete_unwrap`
/// or by abandoning the handle — scrubs the material; no `Zeroize` derive (and
/// thus no extra dependency) is needed.
pub(crate) struct MockUnwrapState {
    /// The slot tag, used to reconstruct the AEAD associated data. Not secret.
    slot_tag: u8,
    /// The XChaCha20-Poly1305 nonce read from the payload. Not secret.
    nonce: [u8; NONCE_LEN],
    /// The ciphertext+tag to decrypt, held in a zeroizing wrapper.
    ciphertext: SecretBytes,
    /// A copy of the in-memory wrapping key (zeroized on drop).
    key: SecretArray<32>,
}

/// A configurable [`BiometricPrompter`] for tests (**test/dev only**).
///
/// Returns [`PromptResult::Authenticated`] by default; construct with
/// [`MockPrompter::cancelling`] to return [`PromptResult::Cancelled`] so core
/// can exercise the cancel paths.
pub struct MockPrompter {
    outcome: MockPromptOutcome,
}

/// Which fixed outcome a [`MockPrompter`] yields. Kept separate from
/// [`PromptResult`] because that type holds a non-`Copy` secret on one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockPromptOutcome {
    Authenticated,
    Cancelled,
}

impl MockPrompter {
    /// A prompter that always reports [`PromptResult::Authenticated`].
    #[must_use]
    pub fn authenticating() -> Self {
        Self {
            outcome: MockPromptOutcome::Authenticated,
        }
    }

    /// A prompter that always reports [`PromptResult::Cancelled`].
    #[must_use]
    pub fn cancelling() -> Self {
        Self {
            outcome: MockPromptOutcome::Cancelled,
        }
    }
}

impl Default for MockPrompter {
    fn default() -> Self {
        Self::authenticating()
    }
}

impl BiometricPrompter for MockPrompter {
    fn prompt(&self, _reason: String) -> Result<PromptResult, HsmError> {
        Ok(match self.outcome {
            MockPromptOutcome::Authenticated => PromptResult::Authenticated,
            MockPromptOutcome::Cancelled => PromptResult::Cancelled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MockKeyStore, MockPrompter};
    use crate::blob::WrappedBlob;
    use crate::error::HsmError;
    use crate::handle::UnwrapHandle;
    use crate::slot::{HsmKind, HsmSlot};
    use crate::store::HardwareKeyStore;
    use passman_crypto::SecretBytes;

    fn enroll_unwrap_roundtrip(slot: HsmSlot) {
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);

        let blob = store
            .enroll(slot, &material, &(), &prompter)
            .expect("enroll");
        assert_eq!(blob.kind(), HsmKind::SoftwareMock);

        let handle = store.begin_unwrap(slot, &blob, &()).expect("begin_unwrap");
        let recovered = store
            .complete_unwrap(handle, &prompter)
            .expect("complete_unwrap");

        assert_eq!(recovered.expose(), material.expose());
    }

    #[test]
    fn roundtrip_vault_key_slot() {
        enroll_unwrap_roundtrip(HsmSlot::VaultKey);
    }

    #[test]
    fn roundtrip_totp_seed_slot() {
        enroll_unwrap_roundtrip(HsmSlot::TotpSeed);
    }

    #[test]
    fn distinct_material_per_slot_roundtrips() {
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let vault_material = SecretBytes::new(vec![0x11; 32]);
        let seed_material = SecretBytes::new(vec![0x22; 32]);

        let vault_blob = store
            .enroll(HsmSlot::VaultKey, &vault_material, &(), &prompter)
            .expect("enroll vault");
        let seed_blob = store
            .enroll(HsmSlot::TotpSeed, &seed_material, &(), &prompter)
            .expect("enroll seed");

        let vault_handle = store
            .begin_unwrap(HsmSlot::VaultKey, &vault_blob, &())
            .expect("begin vault");
        let seed_handle = store
            .begin_unwrap(HsmSlot::TotpSeed, &seed_blob, &())
            .expect("begin seed");

        assert_eq!(
            store
                .complete_unwrap(vault_handle, &prompter)
                .expect("complete vault")
                .expose(),
            vault_material.expose()
        );
        assert_eq!(
            store
                .complete_unwrap(seed_handle, &prompter)
                .expect("complete seed")
                .expose(),
            seed_material.expose()
        );
    }

    #[test]
    fn vault_blob_rejected_when_unwrapped_as_seed() {
        // A blob enrolled for VaultKey must not unwrap as TotpSeed. The stored
        // slot tag makes this fail fast at begin_unwrap.
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);

        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect("enroll");

        let err = store
            .begin_unwrap(HsmSlot::TotpSeed, &blob, &())
            .expect_err("slot mismatch must error");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn aad_binding_rejects_forged_slot_tag() {
        // Tamper the stored slot tag so begin_unwrap's fast check passes for
        // the forged slot, then confirm the AAD binding still fails the AEAD in
        // complete_unwrap (the authoritative cryptographic check).
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);

        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect("enroll");

        // Rebuild the blob payload with the slot tag flipped to TotpSeed.
        let mut payload = blob.payload().to_vec();
        payload[0] = HsmSlot::TotpSeed.tag();
        let forged = WrappedBlob::from_parts(HsmKind::SoftwareMock, payload).expect("from_parts");

        // begin_unwrap as TotpSeed now passes the tag check (tag was forged)...
        let handle = store
            .begin_unwrap(HsmSlot::TotpSeed, &forged, &())
            .expect("begin_unwrap with forged tag");
        // ...but the AEAD AAD (domain ‖ forged tag) no longer matches what was
        // sealed (domain ‖ VaultKey tag), so the tag verification fails.
        let err = store
            .complete_unwrap(handle, &prompter)
            .expect_err("AAD mismatch must fail");
        assert!(matches!(err, HsmError::Backend(_)));
    }

    #[test]
    fn tampered_ciphertext_byte_errors_without_panic() {
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);

        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect("enroll");

        // Flip the last byte of the payload (inside the ciphertext+tag region).
        let mut payload = blob.payload().to_vec();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        let tampered = WrappedBlob::from_parts(HsmKind::SoftwareMock, payload).expect("from_parts");

        let handle = store
            .begin_unwrap(HsmSlot::VaultKey, &tampered, &())
            .expect("begin_unwrap");
        let err = store
            .complete_unwrap(handle, &prompter)
            .expect_err("tamper must fail");
        assert!(matches!(err, HsmError::Backend(_)));
    }

    #[test]
    fn cancelled_prompt_blocks_enroll() {
        let store = MockKeyStore::new();
        let prompter = MockPrompter::cancelling();
        let material = SecretBytes::new(vec![0x42; 32]);

        let err = store
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect_err("cancel must block enroll");
        assert!(matches!(err, HsmError::Cancelled));
    }

    #[test]
    fn cancelled_prompt_blocks_complete_unwrap_and_yields_no_material() {
        // Enroll/begin with an authenticating prompter, then cancel at
        // complete_unwrap: it must return Cancelled and no SecretBytes.
        let store = MockKeyStore::new();
        let auth = MockPrompter::authenticating();
        let cancel = MockPrompter::cancelling();
        let material = SecretBytes::new(vec![0x42; 32]);

        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &auth)
            .expect("enroll");
        let handle = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect("begin_unwrap");

        let err = store
            .complete_unwrap(handle, &cancel)
            .expect_err("cancel must block complete_unwrap");
        assert!(matches!(err, HsmError::Cancelled));
    }

    #[test]
    fn forced_failure_constructors_surface_their_errors() {
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);

        // Each forced store surfaces its error at the first op (enroll here).
        let transient = MockKeyStore::failing_transient();
        assert!(matches!(
            transient.enroll(HsmSlot::VaultKey, &material, &(), &prompter),
            Err(HsmError::Transient)
        ));

        let absent = MockKeyStore::failing_hardware_absent();
        assert!(matches!(
            absent.enroll(HsmSlot::VaultKey, &material, &(), &prompter),
            Err(HsmError::HardwareAbsent)
        ));

        let invalidated = MockKeyStore::failing_permanently_invalidated();
        assert!(matches!(
            invalidated.enroll(HsmSlot::VaultKey, &material, &(), &prompter),
            Err(HsmError::PermanentlyInvalidated)
        ));
    }

    #[test]
    fn failing_constructor_maps_error_argument() {
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);

        let store = MockKeyStore::failing(HsmError::PermanentlyInvalidated);
        assert!(matches!(
            store.enroll(HsmSlot::VaultKey, &material, &(), &prompter),
            Err(HsmError::PermanentlyInvalidated)
        ));
    }

    #[test]
    fn forced_failure_blocks_begin_unwrap() {
        // A store that begins healthy enrolls a blob; a separate forced store
        // then refuses begin_unwrap. (Same key is not needed — we assert the
        // error fires before any crypto.)
        let healthy = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);
        let blob = healthy
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect("enroll");

        let forced = MockKeyStore::failing_transient();
        assert!(matches!(
            forced.begin_unwrap(HsmSlot::VaultKey, &blob, &()),
            Err(HsmError::Transient)
        ));
    }

    #[test]
    fn capabilities_and_kind_are_reported() {
        let store = MockKeyStore::new();
        assert_eq!(store.kind(), HsmKind::SoftwareMock);
        let caps = store.capabilities();
        assert!(caps.biometric_supported);
        assert!(caps.max_attempts_before_lockout.is_none());
    }

    #[test]
    fn invalidate_is_a_noop_ok() {
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);
        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect("enroll");
        assert!(store.invalidate(HsmSlot::VaultKey, &blob, &()).is_ok());
    }

    #[test]
    fn handle_dropped_without_completing_is_clean() {
        // Begin an unwrap and drop the handle without completing; this must not
        // panic and (via ZeroizeOnDrop) scrubs the held material. We can only
        // assert the no-panic / no-yield behavior here.
        let store = MockKeyStore::new();
        let prompter = MockPrompter::authenticating();
        let material = SecretBytes::new(vec![0x42; 32]);
        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &prompter)
            .expect("enroll");

        let handle: UnwrapHandle = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect("begin_unwrap");
        drop(handle); // no material released
    }
}
