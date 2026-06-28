//! Linux `SecretService` backend (feature `secret-service`).
//!
//! The documented weaker fallback of `architecture.md` §6.2: when no TPM is
//! available, slot material is stored in the OS keyring over D-Bus
//! (`org.freedesktop.secrets`) instead of being hardware-sealed. **There is no
//! hardware dictionary-attack lockout here** — only the advisory app timer in
//! `passman-core` applies, which §6.2/§4.9 document as weak.
//!
//! # Confidentiality boundary
//!
//! The stored secret's true confidentiality boundary is the **login session**,
//! not the passman process. Once the user's login keyring is unlocked, the
//! Secret Service hands the secret to **any process running as that user in the
//! same session** that asks for it over D-Bus — there is no per-application
//! isolation and (unlike the hardware backends) no per-use biometric/PIN gate.
//! A malicious or compromised process in the session can read `K_hsm` / the TOTP
//! seed directly. This is an accepted property of the documented weak fallback,
//! alongside the no-hardware-DA caveat above; it is *not* equivalent to a
//! hardware-sealed slot.
//!
//! # Re-enroll contract (caller must invalidate first)
//!
//! [`SecretServiceKeyStore::enroll`] mints a **fresh** enrollment uuid and
//! writes a new keyring credential every call; it does **not** invalidate any
//! previously enrolled credential for the slot. A blind re-enroll therefore
//! leaves the old secret readable in the keyring under its old uuid (an
//! orphaned credential the new blob no longer references). **The caller MUST
//! invalidate the prior blob (via [`HardwareKeyStore::invalidate`]) before
//! re-enrolling a slot**, so the superseded secret is actually removed.
//!
//! # What lives where
//!
//! The 32-byte slot secret (`K_hsm` or the TOTP seed `S`) is written into the
//! keyring as the credential's *secret*. The on-disk [`WrappedBlob`] holds only
//! the 16-byte enrollment uuid (§6.4 payload = `vault_uuid(16)`); it carries no
//! key material. To unwrap, the backend reconstructs the keyring identity from
//! the slot + uuid and reads the secret back.
//!
//! # Identity mapping (documented deviation from §6.4)
//!
//! `keyring` v3 models a credential identity as a `(service, user)` pair, not as
//! a freedesktop *collection* + *label*. This backend uses
//! `service = "passman"` and `user = "passman-{slot}-{uuid_hex}"`. That
//! reproduces the §6.4 *naming* (`passman-{slot}-{uuid}`) and round-trips
//! `get_secret`/`delete_credential`, but the underlying `dbus-secret-service`
//! backend writes to the session **default** collection and cannot pin the
//! literal collection name `default`. The intended target (the user's session
//! login collection) is reached; only the inability to assert the collection
//! name verbatim is the deviation.
//!
//! # `PlatformCtx`
//!
//! `()` — the backend opens its own D-Bus connection per `keyring::Entry`
//! operation; nothing is injected (approved §6.5 refinement).

use keyring::{Entry, Error as KeyringError};
use passman_crypto::{fill_random, SecretBytes};

use crate::blob::WrappedBlob;
use crate::capabilities::{HsmCapabilities, LockoutRecovery};
use crate::error::HsmError;
use crate::handle::UnwrapHandle;
use crate::prompt::BiometricPrompter;
use crate::slot::{HsmKind, HsmSlot};
use crate::store::HardwareKeyStore;

/// The fixed keyring service name for all passman credentials.
const KEYRING_SERVICE: &str = "passman";

/// Length of the enrollment uuid (opaque random bytes, §6.4).
const UUID_LEN: usize = 16;

/// A `SecretService`-backed key store (Linux keyring fallback).
///
/// Holds no state of its own: every operation opens a fresh [`keyring::Entry`].
/// See the [module docs](self) for the security posture (no hardware DA).
#[derive(Debug, Default)]
pub struct SecretServiceKeyStore {
    /// Zero-sized; present so the type can grow config later without an API
    /// break. Construction is via [`SecretServiceKeyStore::new`].
    _private: (),
}

impl SecretServiceKeyStore {
    /// Construct a `SecretService` backend.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// The keyring `user` for a slot + enrollment uuid: `passman-{slot}-{hex}`.
    ///
    /// `slot.tag()` is `0x00` (`VaultKey`) / `0x01` (`TotpSeed`); rendered as a
    /// single decimal digit to match the §6.4 `passman-{slot}-{uuid}` shape.
    fn keyring_user(slot: HsmSlot, uuid: &[u8; UUID_LEN]) -> String {
        const DIGITS: [char; 16] = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let mut hex = String::with_capacity(UUID_LEN * 2);
        for &byte in uuid {
            hex.push(DIGITS[usize::from(byte >> 4)]);
            hex.push(DIGITS[usize::from(byte & 0x0f)]);
        }
        format!("passman-{}-{hex}", slot.tag())
    }

    /// Open the keyring entry for a slot + uuid.
    fn entry(slot: HsmSlot, uuid: &[u8; UUID_LEN]) -> Result<Entry, HsmError> {
        let user = Self::keyring_user(slot, uuid);
        Entry::new(KEYRING_SERVICE, &user).map_err(|e| map_keyring_error(&e))
    }
}

impl HardwareKeyStore for SecretServiceKeyStore {
    type PlatformCtx = ();

    fn kind(&self) -> HsmKind {
        HsmKind::SecretService
    }

    fn capabilities(&self) -> HsmCapabilities {
        // No hardware: no biometric, no StrongBox, no PCR binding, and crucially
        // no native dictionary-attack lockout (`max_attempts_before_lockout =
        // None`, §6.2). `lockout_recovery` best-fits a session-login gate: the
        // credential becomes available once the user's login keyring is
        // unlocked, i.e. it is gated by the account credential, so
        // `UserAccountReset` is the closest fit (the others — a TPM-style time
        // cooldown or a secure-element factory reset — do not describe a
        // keyring). It is advisory UX metadata only; there is no enforcement
        // here. A distinct per-slot PIN is not supported by this backend.
        HsmCapabilities {
            biometric_supported: false,
            strongbox_backed: false,
            pcr_bound: false,
            max_attempts_before_lockout: None,
            lockout_recovery: LockoutRecovery::UserAccountReset,
            supports_distinct_slot_pin: false,
        }
    }

    fn enroll(
        &self,
        slot: HsmSlot,
        material: &SecretBytes,
        _ctx: &Self::PlatformCtx,
        _prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError> {
        // No prompt: the keyring is gated by the session login, not a per-use
        // biometric (unlike Android, §6.4).
        let mut uuid = [0u8; UUID_LEN];
        fill_random(&mut uuid);

        let entry = Self::entry(slot, &uuid)?;
        entry
            .set_secret(material.expose())
            .map_err(|e| map_keyring_error(&e))?;

        // Payload is exactly the 16-byte uuid (§6.4); no key material on disk.
        WrappedBlob::from_parts(HsmKind::SecretService, uuid.to_vec())
    }

    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<UnwrapHandle, HsmError> {
        if wrapped.kind() != HsmKind::SecretService {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not SecretService",
            });
        }

        let payload = wrapped.payload();
        let uuid: [u8; UUID_LEN] = payload.try_into().map_err(|_| HsmError::MalformedBlob {
            reason: "SecretService payload is not a 16-byte uuid",
        })?;

        // No D-Bus call and no prompt here; the fetch happens in
        // `complete_unwrap` so the two-phase contract (§6.1) is honoured.
        Ok(UnwrapHandle::for_secret_service(SecretServiceUnwrapState {
            slot,
            uuid,
        }))
    }

    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        _prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, HsmError> {
        // No prompt: see `enroll`. The keyring read itself is the only gate.
        let state = handle.into_secret_service()?;
        let entry = Self::entry(state.slot, &state.uuid)?;
        let secret = entry.get_secret().map_err(|e| map_keyring_error(&e))?;
        Ok(SecretBytes::new(secret))
    }

    fn invalidate(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<(), HsmError> {
        if wrapped.kind() != HsmKind::SecretService {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not SecretService",
            });
        }
        let payload = wrapped.payload();
        let uuid: [u8; UUID_LEN] = payload.try_into().map_err(|_| HsmError::MalformedBlob {
            reason: "SecretService payload is not a 16-byte uuid",
        })?;

        let entry = Self::entry(slot, &uuid)?;
        match entry.delete_credential() {
            // Already-gone is success for an idempotent destroy (rotation §6.6
            // may retry); anything else maps through the shared router.
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(other) => Err(map_keyring_error(&other)),
        }
    }
}

/// Map a [`keyring::Error`] to the crate [`HsmError`] taxonomy (§4.3 routing).
///
/// - [`KeyringError::NoEntry`] → [`HsmError::PermanentlyInvalidated`]: the
///   credential is gone (never set, or deleted), which §4.3 routes to recovery
///   import — the same destination as a cleared TPM.
/// - [`KeyringError::NoStorageAccess`] → [`HsmError::Transient`]: the store is
///   reachable but locked/temporarily inaccessible; retrying after the user
///   unlocks their keyring is appropriate, so this must not penalise an
///   attempt.
/// - Everything else (platform/bus failure, encoding, ambiguity, length) →
///   [`HsmError::Backend`] with a fixed, non-secret label. The keyring error's
///   own `Display` may name a service or attribute but never the secret bytes;
///   to be safe we emit only a fixed descriptor and never interpolate the
///   error, so no blob, key, or PIN can leak (per the `HsmError` contract).
fn map_keyring_error(err: &KeyringError) -> HsmError {
    match err {
        // SECURITY: `NoEntry` maps to `PermanentlyInvalidated`, which §4.3
        // routes to "recover from backup" — a serious prompt but NOT an
        // automatic destructive action; the user must confirm before any wipe.
        //
        // Residual risk: if the Secret Service backend ever returns `NoEntry`
        // for a *locked* collection (rather than a genuinely-absent entry),
        // the user would be wrongly shown a recovery prompt.  In practice
        // this is very unlikely with keyring v3: a locked collection produces
        // `Error::Locked` at the D-Bus layer, which `keyring` translates to
        // `NoStorageAccess` (see `secret_service.rs` → `no_access()`), not
        // `NoEntry`.  The `NoStorageAccess → Transient` arm below therefore
        // handles the locked-keyring case correctly.
        //
        // If a future keyring version or alternative D-Bus backend changes
        // this routing, the symptom is a false "permanently invalidated"
        // prompt (recoverable by dismissing and unlocking the keyring) — not
        // silent data loss.  No code guard is added because the keyring v3
        // API does not expose a cheap per-entry "collection is locked" check
        // that would be safe to call here without additional D-Bus round-trips.
        KeyringError::NoEntry => HsmError::PermanentlyInvalidated,
        KeyringError::NoStorageAccess(_) => HsmError::Transient,
        KeyringError::PlatformFailure(_) => {
            HsmError::Backend("SecretService platform failure".to_owned())
        }
        KeyringError::BadEncoding(_) => {
            HsmError::Backend("SecretService returned a malformed secret".to_owned())
        }
        KeyringError::TooLong(_, _) => {
            HsmError::Backend("SecretService attribute exceeded a platform limit".to_owned())
        }
        KeyringError::Invalid(_, _) => {
            HsmError::Backend("SecretService rejected an invalid attribute".to_owned())
        }
        KeyringError::Ambiguous(_) => {
            HsmError::Backend("SecretService matched multiple credentials".to_owned())
        }
        // `keyring::Error` is `#[non_exhaustive]`; a future variant routes to a
        // generic backend error rather than failing to compile.
        _ => HsmError::Backend("SecretService backend error".to_owned()),
    }
}

/// Transient state the `SecretService` backend stashes in an [`UnwrapHandle`].
///
/// Holds only the slot and the 16-byte enrollment uuid — **no key material**
/// (the secret is fetched from the keyring in `complete_unwrap`). Nothing here
/// is secret, but the type is still consumed single-use via the handle.
pub(crate) struct SecretServiceUnwrapState {
    /// Which slot this handle unwraps; selects the keyring `user`.
    slot: HsmSlot,
    /// The enrollment uuid recovered from the blob; selects the keyring `user`.
    uuid: [u8; UUID_LEN],
}

#[cfg(test)]
mod tests {
    use super::{SecretServiceKeyStore, KEYRING_SERVICE, UUID_LEN};
    use crate::blob::WrappedBlob;
    use crate::error::HsmError;
    use crate::slot::{HsmKind, HsmSlot};
    use crate::store::HardwareKeyStore;
    use keyring::Entry;
    use passman_crypto::SecretBytes;

    /// A no-op prompter for the `SecretService` backend, which never prompts.
    struct NoPrompter;
    impl crate::prompt::BiometricPrompter for NoPrompter {
        fn prompt(&self, _reason: String) -> Result<crate::prompt::PromptResult, HsmError> {
            Ok(crate::prompt::PromptResult::Authenticated)
        }
    }

    /// Probe whether a live Secret Service is reachable. Returns `true` only if
    /// a session bus is configured *and* an `Entry` round-trips a set/get/delete
    /// against it. On headless CI (no `DBUS_SESSION_BUS_ADDRESS`, or the service
    /// is absent) this returns `false` so the tests skip gracefully instead of
    /// failing — per the task's headless-CI requirement.
    fn secret_service_available() -> bool {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return false;
        }
        // Use a throwaway probe credential so we never collide with real data.
        let probe_user = "passman-selftest-probe";
        let Ok(entry) = Entry::new(KEYRING_SERVICE, probe_user) else {
            return false;
        };
        if entry.set_secret(b"probe").is_err() {
            return false;
        }
        let ok = entry.get_secret().is_ok_and(|s| s == b"probe");
        // Best-effort cleanup; ignore the result (the probe is disposable).
        let _ = entry.delete_credential();
        ok
    }

    /// Skip-or-run helper: returns the store if the service is live, else prints
    /// a skip notice to stderr and returns `None`.
    fn store_if_live(test_name: &str) -> Option<SecretServiceKeyStore> {
        if secret_service_available() {
            Some(SecretServiceKeyStore::new())
        } else {
            eprintln!(
                "SKIP {test_name}: no live Secret Service (org.freedesktop.secrets) reachable; \
                 headless environment. This is expected on CI."
            );
            None
        }
    }

    /// A fresh, collision-resistant material for a test, so parallel runs and
    /// leftover state never interfere.
    fn unique_material() -> SecretBytes {
        let mut buf = vec![0u8; 32];
        passman_crypto::fill_random(&mut buf);
        SecretBytes::new(buf)
    }

    #[test]
    fn keyring_user_matches_spec_shape() {
        // Pure (no D-Bus): the user string is `passman-{slot}-{32 hex chars}`.
        let uuid = [0xABu8; UUID_LEN];
        let user = SecretServiceKeyStore::keyring_user(HsmSlot::VaultKey, &uuid);
        assert_eq!(user, format!("passman-0-{}", "ab".repeat(UUID_LEN)));
        let user_seed = SecretServiceKeyStore::keyring_user(HsmSlot::TotpSeed, &uuid);
        assert_eq!(user_seed, format!("passman-1-{}", "ab".repeat(UUID_LEN)));
    }

    #[test]
    fn enroll_emits_uuid_only_blob_when_live() {
        let Some(store) = store_if_live("enroll_emits_uuid_only_blob_when_live") else {
            return;
        };
        let material = unique_material();
        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &NoPrompter)
            .expect("enroll");
        assert_eq!(blob.kind(), HsmKind::SecretService);
        assert_eq!(blob.payload().len(), UUID_LEN, "payload must be the uuid");

        // Clean up so we never leave a credential behind.
        store
            .invalidate(HsmSlot::VaultKey, &blob, &())
            .expect("invalidate");
    }

    #[test]
    fn enroll_unwrap_roundtrip_when_live() {
        let Some(store) = store_if_live("enroll_unwrap_roundtrip_when_live") else {
            return;
        };
        for slot in [HsmSlot::VaultKey, HsmSlot::TotpSeed] {
            let material = unique_material();
            let blob = store
                .enroll(slot, &material, &(), &NoPrompter)
                .expect("enroll");

            let handle = store.begin_unwrap(slot, &blob, &()).expect("begin_unwrap");
            let recovered = store
                .complete_unwrap(handle, &NoPrompter)
                .expect("complete_unwrap");
            assert_eq!(recovered.expose(), material.expose(), "round-trip mismatch");

            store.invalidate(slot, &blob, &()).expect("invalidate");
        }
    }

    #[test]
    fn invalidate_then_unwrap_is_permanently_invalidated_when_live() {
        let Some(store) =
            store_if_live("invalidate_then_unwrap_is_permanently_invalidated_when_live")
        else {
            return;
        };
        let material = unique_material();
        let blob = store
            .enroll(HsmSlot::VaultKey, &material, &(), &NoPrompter)
            .expect("enroll");
        store
            .invalidate(HsmSlot::VaultKey, &blob, &())
            .expect("invalidate");

        // Re-invalidate is idempotent (NoEntry -> Ok).
        store
            .invalidate(HsmSlot::VaultKey, &blob, &())
            .expect("idempotent invalidate");

        // Unwrapping a now-deleted credential surfaces PermanentlyInvalidated.
        let handle = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect("begin_unwrap");
        let err = store
            .complete_unwrap(handle, &NoPrompter)
            .expect_err("must fail after delete");
        assert!(
            matches!(err, HsmError::PermanentlyInvalidated),
            "got {err:?}"
        );
    }

    #[test]
    fn begin_unwrap_rejects_wrong_kind() {
        // Pure (no D-Bus): a non-SecretService blob is rejected without I/O.
        let store = SecretServiceKeyStore::new();
        let blob = WrappedBlob::from_parts(HsmKind::Tpm2, vec![0u8; UUID_LEN]).expect("from_parts");
        let err = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect_err("wrong kind must error");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn begin_unwrap_rejects_bad_payload_len() {
        // Pure: a payload that is not exactly 16 bytes is malformed.
        let store = SecretServiceKeyStore::new();
        let blob =
            WrappedBlob::from_parts(HsmKind::SecretService, vec![0u8; 15]).expect("from_parts");
        let err = store
            .begin_unwrap(HsmSlot::VaultKey, &blob, &())
            .expect_err("short payload must error");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn capabilities_report_no_hardware_da() {
        let store = SecretServiceKeyStore::new();
        let caps = store.capabilities();
        assert!(!caps.biometric_supported);
        assert!(!caps.strongbox_backed);
        assert!(!caps.pcr_bound);
        assert!(caps.max_attempts_before_lockout.is_none());
        assert!(!caps.supports_distinct_slot_pin);
        assert_eq!(store.kind(), HsmKind::SecretService);
    }

    // ---- map_keyring_error routing (pure, no D-Bus) --------------------------

    #[test]
    fn map_keyring_error_no_entry_routes_to_permanently_invalidated() {
        // NoEntry → PermanentlyInvalidated (§4.3 recovery route).
        // See the SECURITY comment on this arm: keyring v3 maps a locked
        // collection to NoStorageAccess (via Error::Locked), so the residual
        // risk of a locked-but-absent misroute is very low in practice.
        let err = keyring::Error::NoEntry;
        let mapped = super::map_keyring_error(&err);
        assert!(
            matches!(mapped, HsmError::PermanentlyInvalidated),
            "NoEntry must map to PermanentlyInvalidated, got {mapped:?}"
        );
    }

    #[test]
    fn map_keyring_error_no_storage_access_routes_to_transient() {
        // NoStorageAccess → Transient (keyring locked / D-Bus temporarily down).
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("locked"));
        let err = keyring::Error::NoStorageAccess(inner);
        let mapped = super::map_keyring_error(&err);
        assert!(
            matches!(mapped, HsmError::Transient),
            "NoStorageAccess must map to Transient, got {mapped:?}"
        );
    }

    #[test]
    fn map_keyring_error_platform_failure_routes_to_backend() {
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("platform"));
        let err = keyring::Error::PlatformFailure(inner);
        let mapped = super::map_keyring_error(&err);
        assert!(
            matches!(mapped, HsmError::Backend(_)),
            "PlatformFailure must map to Backend, got {mapped:?}"
        );
    }

    #[test]
    fn map_keyring_error_bad_encoding_routes_to_backend() {
        let err = keyring::Error::BadEncoding(vec![0xff, 0xfe]);
        let mapped = super::map_keyring_error(&err);
        assert!(
            matches!(mapped, HsmError::Backend(_)),
            "BadEncoding must map to Backend, got {mapped:?}"
        );
    }

    #[test]
    fn map_keyring_error_too_long_routes_to_backend() {
        let err = keyring::Error::TooLong("attr".to_owned(), 256);
        let mapped = super::map_keyring_error(&err);
        assert!(
            matches!(mapped, HsmError::Backend(_)),
            "TooLong must map to Backend, got {mapped:?}"
        );
    }
}
