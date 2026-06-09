//! The locked [`App`]: construction, vault creation, and the unlock pipeline.
//!
//! `App<H>` is generic over the [`HardwareKeyStore`] backend (`architecture.md`
//! §6.5); the associated `PlatformCtx` is threaded through `create_vault` and
//! `unlock` and never crosses an FFI boundary. The struct owns the vault path,
//! the single-instance lock, the project clock, and the long-lived
//! [`TotpVerifier`] whose in-memory replay cache must persist across attempts
//! within one process (§4.3 step 4).

use std::sync::{Arc, Mutex};

use passman_crypto::{
    argon2id, hkdf_master, random_secret, KdfParams, SecretArray, SecretBytes, SecretString,
};
use passman_hsm::{BiometricPrompter, HardwareKeyStore, HsmError, HsmKind, HsmSlot, WrappedBlob};
use passman_totp::{Clock, TotpConfig, TotpVerifier};
use passman_vault::{Vault, VaultMetadata};

use crate::error::{CoreError, UnlockError};
use crate::lockout::LockoutState;
use crate::provisioning::build_provisioning_uri;
use crate::session::SessionToken;
use crate::unlocked::UnlockedApp;

/// HKDF-Extract+Expand `info` for the master key (`architecture.md` §4.2/§4.6).
/// Owned by `passman-core`.
pub(crate) const MASTER_INFO: &[u8] = b"passman-master-v0";

/// Length of the vault salt / every 256-bit key, in bytes.
pub(crate) const KEY_LEN: usize = 32;

/// The hard session lifetime from unlock, in seconds (`architecture.md` §5.2).
pub(crate) const SESSION_SECS: u64 = 120;

/// An `otpauth://` provisioning URI for the TOTP seed, held as a
/// [`SecretString`] so it is zeroized after the shell renders its QR code
/// (`architecture.md` §7.6). It embeds the base32 seed, so it is sensitive.
pub type ProvisioningUri = SecretString;

/// The locked application handle, generic over the HSM backend.
///
/// Holds no decrypted secrets. Construction acquires the single-instance lock;
/// [`App::unlock`] / [`App::create_vault`] produce an [`UnlockedApp`].
pub struct App<H: HardwareKeyStore> {
    /// Absolute path to the vault file. Core owns this (§2.3).
    vault_path: std::path::PathBuf,
    /// The hardware-key-store backend.
    backend: H,
    /// The project clock (the `passman-totp` `Clock`, reused per the design).
    clock: Arc<dyn Clock>,
    /// The single-instance advisory lock, held for the `App`'s lifetime (D27).
    _lock: crate::storage::InstanceLock,
    /// Whether a software-mock backend is permitted (the `--allow-software-hsm`
    /// opt-in, §6.2). Off by default; tests turn it on.
    allow_software_hsm: bool,
    /// The TOTP configuration provisioned for this vault. Defaults to the
    /// standard authenticator profile at `open`; `create_vault` / import set
    /// the configuration actually enrolled.
    totp_config: Mutex<TotpConfig>,
    /// The long-lived verifier. Its replay cache must persist across unlock
    /// attempts in one process (§4.3 step 4), so it lives here behind a mutex
    /// rather than being recreated per attempt.
    verifier: Mutex<Option<TotpVerifier>>,
}

impl<H: HardwareKeyStore> App<H> {
    /// Open the application for the vault at `path`, acquiring the
    /// single-instance lock. Reads no secrets.
    ///
    /// The TOTP configuration defaults to [`TotpConfig::default`] (the standard
    /// authenticator profile) until a `create_vault` / import call records the
    /// configuration actually enrolled.
    ///
    /// # Errors
    ///
    /// - [`CoreError::AlreadyRunning`] if another instance holds the lock.
    /// - [`CoreError::Io`] if the lockfile cannot be opened/locked.
    pub fn open(
        path: impl Into<std::path::PathBuf>,
        backend: H,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, CoreError> {
        let vault_path = path.into();
        let lock = crate::storage::InstanceLock::acquire(&vault_path)?;
        Ok(Self {
            vault_path,
            backend,
            clock,
            _lock: lock,
            allow_software_hsm: false,
            totp_config: Mutex::new(TotpConfig::default()),
            verifier: Mutex::new(None),
        })
    }

    /// Like [`App::open`], but permits a software-mock HSM backend (the
    /// `--allow-software-hsm` opt-in, `architecture.md` §6.2). Tests use this;
    /// production must not unless the user passed the flag.
    ///
    /// # Errors
    ///
    /// As [`App::open`].
    pub fn open_allowing_software_hsm(
        path: impl Into<std::path::PathBuf>,
        backend: H,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, CoreError> {
        let mut app = Self::open(path, backend, clock)?;
        app.allow_software_hsm = true;
        Ok(app)
    }

    /// The vault path this app owns.
    #[must_use]
    pub fn vault_path(&self) -> &std::path::Path {
        &self.vault_path
    }

    /// Refuse a software-mock backend unless the allow-software opt-in is set
    /// (`architecture.md` §6.2).
    fn check_backend_allowed(&self) -> Result<(), CoreError> {
        if self.backend.kind() == HsmKind::SoftwareMock && !self.allow_software_hsm {
            return Err(CoreError::SoftwareHsmRefused);
        }
        Ok(())
    }

    /// Create a brand-new vault and return it unlocked plus the TOTP
    /// provisioning URI (`architecture.md` §4.2, §4.3 setup, §7.6 QR).
    ///
    /// Mints `K_hsm` and the TOTP seed `S` (both 256-bit random), enrolls each
    /// into its own HSM slot (enroll drives the prompter — Android prompts on
    /// encrypt too, §6.4), derives `K_master = HKDF(K_pw ‖ K_hsm)`, builds the
    /// vault, and atomically writes it. The returned [`ProvisioningUri`] carries
    /// the seed for the shell to render as a QR.
    ///
    /// # Errors
    ///
    /// - [`CoreError::SoftwareHsmRefused`] if the backend is the software mock
    ///   without the opt-in.
    /// - [`CoreError::Hsm`] if either slot enrollment fails (incl. a cancelled
    ///   prompt).
    /// - [`CoreError::Vault`] / [`CoreError::Io`] if building or writing the
    ///   vault fails.
    pub fn create_vault(
        &self,
        password: &SecretString,
        kdf: KdfParams,
        totp_cfg: TotpConfig,
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<(UnlockedApp<'_, H>, ProvisioningUri), CoreError> {
        self.check_backend_allowed()?;

        // Mint the hardware key and the TOTP seed. Both are zeroizing.
        let k_hsm = random_secret::<KEY_LEN>();
        let seed = random_secret::<KEY_LEN>();

        // Enroll BOTH slots. enroll takes a SecretBytes; build them from the
        // arrays (the SecretBytes copies the bytes into a zeroizing Vec).
        let k_hsm_blob = self.enroll_slot(HsmSlot::VaultKey, &k_hsm, ctx, prompter)?;
        let seed_blob = self.enroll_slot(HsmSlot::TotpSeed, &seed, ctx, prompter)?;

        // Derive K_master from K_pw ‖ K_hsm.
        let vault_salt: [u8; KEY_LEN] = *random_secret::<KEY_LEN>().expose();
        let k_master = derive_master(password, &vault_salt, &kdf, &k_hsm)?;

        // Build and persist the vault.
        let metadata = VaultMetadata::new(self.now_unix_secs());
        let vault = Vault::create(
            kdf,
            vault_salt,
            k_hsm_blob.to_bytes(),
            seed_blob.to_bytes(),
            metadata,
            &k_master,
        )?;
        crate::storage::atomic_write(&self.vault_path, &vault.to_bytes())?;

        // Record the provisioned TOTP configuration and reset the verifier so a
        // later unlock builds one against this configuration.
        self.set_totp_config(totp_cfg);

        let uri = build_provisioning_uri(&seed, totp_cfg);

        // The freshly-created vault has an empty index.
        let index = vault.open_index(&k_master)?;
        let unlocked = self.build_unlocked(k_master, index);
        Ok((unlocked, uri))
    }

    /// Unlock the vault following the `architecture.md` §4.3 pipeline exactly.
    ///
    /// The steps: read + parse the vault; unwrap `K_hsm` and `S` from their two
    /// HSM slots (routing [`HsmError`] per §4.3); run the advisory-lockout
    /// check; verify the TOTP code (a failure records an advisory failure);
    /// derive `K_master`; verify the probe (a failure records an advisory
    /// failure); open the index (which runs the index↔envelope-set check); and
    /// on success reset the advisory counter and build the session.
    ///
    /// # Errors
    ///
    /// [`UnlockError`] — see its variants. Only [`UnlockError::BadCredentials`]
    /// advances the advisory counter (TOTP or probe failure); HSM transport
    /// outcomes and the recovery route do not.
    pub fn unlock(
        &self,
        password: &SecretString,
        totp_code: &str,
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<UnlockedApp<'_, H>, UnlockError> {
        if self.backend.kind() == HsmKind::SoftwareMock && !self.allow_software_hsm {
            return Err(UnlockError::SoftwareHsmRefused);
        }

        // Step 1: read + parse the vault.
        let bytes = crate::storage::read(&self.vault_path).map_err(UnlockError::MalformedVault)?;
        let mut vault =
            Vault::from_bytes(&bytes).map_err(|e| UnlockError::MalformedVault(e.into()))?;

        // Step 2: unwrap both slots. Map HsmError per §4.3.
        let k_hsm = self.unwrap_slot(HsmSlot::VaultKey, vault.k_hsm_wrap_blob(), ctx, prompter)?;
        let seed = self.unwrap_slot(
            HsmSlot::TotpSeed,
            vault.totp_seed_wrap_blob(),
            ctx,
            prompter,
        )?;

        // Step 3: advisory-lockout check (UX layer). The HSM's native DA
        // protection is the real control (§4.9).
        let now = self.clock.now();
        let mut state = LockoutState::new(vault.rl_counter(), vault.rl_last_failure());
        if let Some(remaining) = state.remaining(now) {
            return Err(UnlockError::LockedOut { remaining });
        }

        // Step 4: verify the TOTP code against the long-lived verifier.
        if self.verify_totp(seed.expose(), totp_code).is_err() {
            self.record_failure(&mut vault, &mut state, now);
            return Err(UnlockError::BadCredentials);
        }

        // Step 5: derive K_master = HKDF(K_pw ‖ K_hsm). `k_hsm` is the raw
        // unwrapped bytes; the helper validates its length.
        let k_master =
            derive_master_from_bytes(password, vault.vault_salt(), &vault.kdf_params(), &k_hsm)
                .map_err(|_| UnlockError::BadCredentials)?;

        // Step 6: verify the probe. A wrong password (or tampered probe-AD
        // header field) fails here and counts as an advisory failure.
        if vault.verify_probe(&k_master).is_err() {
            self.record_failure(&mut vault, &mut state, now);
            return Err(UnlockError::BadCredentials);
        }

        // Step 7: open the index (also runs the index↔envelope-set check). A
        // failure here is tamper/corruption, not a credential error, so it does
        // not touch the advisory counter.
        let index = vault
            .open_index(&k_master)
            .map_err(|e| UnlockError::MalformedVault(e.into()))?;

        // Step 8: success — reset the advisory counter (persist) and build the
        // session.
        if vault.rl_counter() != 0 || vault.rl_last_failure() != 0 {
            let reset = LockoutState::reset();
            vault.set_rate_limit(reset.counter, reset.last_failure);
            // Best-effort persist of the advisory-counter reset. The advisory
            // counter is not a security boundary (the HSM's native lockout is —
            // §4.9), so a transient write failure must not fail an unlock the
            // user has already authenticated; this matches `record_failure`'s
            // best-effort posture. A stale on-disk counter only over-counts a
            // future attempt, which the success path will reset again.
            let _ = crate::storage::atomic_write(&self.vault_path, &vault.to_bytes());
        }

        Ok(self.build_unlocked(k_master, index))
    }

    /// Import a recovery file and provision a fresh vault at this app's path
    /// (`architecture.md` §7.6).
    ///
    /// Decrypts the recovery payload with `password` (wrong password → the
    /// detail-free recovery decrypt error), enrolls **two fresh** HSM slots
    /// (`VaultKey` = a new random `K_hsm`, `TotpSeed` = the payload's seed `S`),
    /// derives a fresh `K_master` under `new_kdf`, re-encrypts every entry into a
    /// new [`Vault`], atomically writes it, and returns the unlocked session
    /// plus the TOTP provisioning URI for re-provisioning the authenticator.
    ///
    /// Records `totp_cfg` as the provisioned configuration (it should match the
    /// seed's original profile so codes verify).
    ///
    /// # Errors
    ///
    /// - [`CoreError::SoftwareHsmRefused`] if the backend is the mock without
    ///   the opt-in.
    /// - [`CoreError::Recovery`] if the file is malformed or the password is
    ///   wrong.
    /// - [`CoreError::Hsm`] if either slot enrollment fails.
    /// - [`CoreError::Vault`] / [`CoreError::Io`] if building or writing fails.
    pub fn import_recovery(
        &self,
        recovery_file: &[u8],
        password: &SecretString,
        new_kdf: KdfParams,
        totp_cfg: TotpConfig,
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<(UnlockedApp<'_, H>, ProvisioningUri), CoreError> {
        self.check_backend_allowed()?;

        // Decrypt + parse the recovery payload.
        let payload = passman_recovery::import(recovery_file, password)?;

        // Enroll two FRESH slots: a new random K_hsm and the payload's seed S.
        let k_hsm = random_secret::<KEY_LEN>();
        let seed = SecretArray::<KEY_LEN>::new(*payload.totp_seed.expose());
        let k_hsm_blob = self.enroll_slot(HsmSlot::VaultKey, &k_hsm, ctx, prompter)?;
        let seed_material = SecretBytes::new(payload.totp_seed.expose().to_vec());
        let seed_blob = self
            .backend
            .enroll(HsmSlot::TotpSeed, &seed_material, ctx, prompter)
            .map_err(CoreError::Hsm)?;

        // Derive a fresh K_master under the new KDF + a fresh salt.
        let vault_salt: [u8; KEY_LEN] = *random_secret::<KEY_LEN>().expose();
        let k_master = derive_master(password, &vault_salt, &new_kdf, &k_hsm)?;

        // Build a fresh vault and re-encrypt every entry into it.
        let metadata = VaultMetadata::new(self.now_unix_secs());
        let mut vault = Vault::create(
            new_kdf,
            vault_salt,
            k_hsm_blob.to_bytes(),
            seed_blob.to_bytes(),
            metadata,
            &k_master,
        )?;
        for entry in payload.entries {
            let (id, label, policy, record) = crate::unlocked::import_entry_parts(entry)?;
            vault.add_or_update_entry(&k_master, id, label, policy, &record)?;
        }
        crate::storage::atomic_write(&self.vault_path, &vault.to_bytes())?;

        self.set_totp_config(totp_cfg);
        let uri = build_provisioning_uri(&seed, totp_cfg);
        let index = vault.open_index(&k_master)?;
        let unlocked = self.build_unlocked(k_master, index);
        Ok((unlocked, uri))
    }

    // ----- Internal helpers ----------------------------------------------------

    /// Enroll `material` into `slot`, returning the wrap blob. Maps the HSM
    /// error to [`CoreError::Hsm`].
    fn enroll_slot(
        &self,
        slot: HsmSlot,
        material: &SecretArray<KEY_LEN>,
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, CoreError> {
        let bytes = SecretBytes::new(material.expose().to_vec());
        self.backend
            .enroll(slot, &bytes, ctx, prompter)
            .map_err(CoreError::Hsm)
    }

    /// Two-phase unwrap of `slot` from the opaque `blob`, mapping [`HsmError`]
    /// to the §4.3 unlock routing.
    fn unwrap_slot(
        &self,
        slot: HsmSlot,
        blob_bytes: &[u8],
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, UnlockError> {
        let blob = WrappedBlob::from_bytes(blob_bytes).map_err(map_hsm_unlock)?;
        let handle = self
            .backend
            .begin_unwrap(slot, &blob, ctx)
            .map_err(map_hsm_unlock)?;
        self.backend
            .complete_unwrap(handle, prompter)
            .map_err(map_hsm_unlock)
    }

    /// Verify a TOTP code against the long-lived verifier, building it from the
    /// provisioned config on first use so the replay cache persists across
    /// attempts (§4.3 step 4). Returns `Ok(())` on a valid, non-replayed code.
    fn verify_totp(&self, seed: &[u8], code: &str) -> Result<(), ()> {
        let now = self.clock.now();
        let mut guard = self
            .verifier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            let cfg = *self
                .totp_config
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Some(TotpVerifier::new(cfg));
        }
        let verifier = guard.as_mut().ok_or(())?;
        verifier.verify(seed, code, now).map_err(|_| ())
    }

    /// Record one advisory failure: bump the state and persist it to the vault
    /// header (`architecture.md` §4.9). A persist failure is intentionally
    /// swallowed — the advisory counter is not a security boundary, so failing
    /// to write it must not change the (already determined) `BadCredentials`
    /// outcome, and there is no secret to leak in this path.
    fn record_failure(
        &self,
        vault: &mut Vault,
        state: &mut LockoutState,
        now: passman_totp::Timestamp,
    ) {
        *state = state.after_failure(now);
        vault.set_rate_limit(state.counter, state.last_failure);
        // Best-effort persistence; see the doc comment.
        let _ = crate::storage::atomic_write(&self.vault_path, &vault.to_bytes());
    }

    /// Build an [`UnlockedApp`] with a fresh session token and a 120 s expiry.
    fn build_unlocked(
        &self,
        k_master: SecretArray<KEY_LEN>,
        index: passman_vault::Index,
    ) -> UnlockedApp<'_, H> {
        let now = self.now_unix_secs_u64();
        UnlockedApp::new(
            self,
            k_master,
            index,
            now.saturating_add(SESSION_SECS),
            SessionToken::generate(),
        )
    }

    /// Record the provisioned TOTP configuration and clear any cached verifier
    /// so the next unlock builds one against it.
    fn set_totp_config(&self, cfg: TotpConfig) {
        *self
            .totp_config
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cfg;
        *self
            .verifier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Current time as Unix seconds (`i64`, for vault metadata).
    fn now_unix_secs(&self) -> i64 {
        i64::try_from(self.clock.now().as_unix_secs()).unwrap_or(i64::MAX)
    }

    /// Current time as Unix seconds (`u64`, for session math).
    fn now_unix_secs_u64(&self) -> u64 {
        self.clock.now().as_unix_secs()
    }

    // ----- Accessors used by `UnlockedApp` (same crate) ------------------------

    /// The project clock.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The vault path (for read/write by unlocked operations).
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.vault_path
    }

    /// Re-verify a TOTP code for fresh re-authentication (export, §7.5). Shares
    /// the same long-lived verifier (and thus replay cache).
    pub(crate) fn reverify_totp(&self, seed: &[u8], code: &str) -> Result<(), ()> {
        self.verify_totp(seed, code)
    }

    /// Unwrap a slot for an unlocked-side operation (export re-auth, password
    /// change), surfacing failures as [`CoreError`].
    pub(crate) fn unwrap_slot_core(
        &self,
        slot: HsmSlot,
        blob_bytes: &[u8],
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, CoreError> {
        let blob = WrappedBlob::from_bytes(blob_bytes)?;
        let handle = self.backend.begin_unwrap(slot, &blob, ctx)?;
        self.backend
            .complete_unwrap(handle, prompter)
            .map_err(CoreError::Hsm)
    }
}

/// Derive `K_master = HKDF-Extract+Expand(salt = vault_salt, ikm = K_pw ‖
/// K_hsm, info = MASTER_INFO)` (`architecture.md` §4.2).
///
/// The IKM concatenation lives in a zeroizing [`SecretBytes`] so the
/// `K_pw ‖ K_hsm` buffer is scrubbed when this function returns; neither input
/// is copied into any non-zeroizing buffer.
///
/// # Errors
///
/// Propagates an Argon2id parameter error from [`argon2id`].
pub(crate) fn derive_master(
    password: &SecretString,
    vault_salt: &[u8; KEY_LEN],
    kdf: &KdfParams,
    k_hsm: &SecretArray<KEY_LEN>,
) -> Result<SecretArray<KEY_LEN>, CoreError> {
    let k_pw = argon2id(password, vault_salt, kdf)?;

    // Build the IKM = K_pw ‖ K_hsm inside a zeroizing buffer.
    let mut ikm = Vec::with_capacity(k_pw.expose_bytes().len() + k_hsm.expose_bytes().len());
    ikm.extend_from_slice(k_pw.expose_bytes());
    ikm.extend_from_slice(k_hsm.expose_bytes());
    let ikm = SecretBytes::new(ikm);

    let k_master = hkdf_master(vault_salt, ikm.expose(), MASTER_INFO);
    // `ikm` and `k_pw` drop here, scrubbing K_pw and the concatenation.
    Ok(k_master)
}

/// Variant of [`derive_master`] that accepts `k_hsm` as raw [`SecretBytes`]
/// (as returned by an HSM unwrap), validating its length.
pub(crate) fn derive_master_from_bytes(
    password: &SecretString,
    vault_salt: &[u8; KEY_LEN],
    kdf: &KdfParams,
    k_hsm: &SecretBytes,
) -> Result<SecretArray<KEY_LEN>, CoreError> {
    let arr = into_key(k_hsm).ok_or(CoreError::Hsm(HsmError::MalformedBlob {
        reason: "unwrapped K_hsm is not 32 bytes",
    }))?;
    derive_master(password, vault_salt, kdf, &arr)
}

/// Copy a [`SecretBytes`] of exactly [`KEY_LEN`] into a [`SecretArray`].
fn into_key(bytes: &SecretBytes) -> Option<SecretArray<KEY_LEN>> {
    if bytes.expose().len() == KEY_LEN {
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes.expose());
        let key = SecretArray::new(arr);
        arr.fill(0);
        Some(key)
    } else {
        None
    }
}

/// Map an [`HsmError`] to the §4.3 unlock routing.
///
/// - `Cancelled` → [`UnlockError::Cancelled`] (no advisory penalty).
/// - `Transient` → [`UnlockError::Retryable`] (no advisory penalty).
/// - `PermanentlyInvalidated` / `HardwareAbsent` → [`UnlockError::RouteToRecovery`].
/// - `Backend` / `MalformedBlob` → [`UnlockError::Hsm`] (a wrapped-blob failure;
///   surfaced rather than mislabelled as a credential failure).
fn map_hsm_unlock(err: HsmError) -> UnlockError {
    match err {
        HsmError::Cancelled => UnlockError::Cancelled,
        HsmError::Transient => UnlockError::Retryable,
        HsmError::PermanentlyInvalidated | HsmError::HardwareAbsent => UnlockError::RouteToRecovery,
        other => UnlockError::Hsm(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_master, into_key, map_hsm_unlock, KEY_LEN};
    use crate::error::UnlockError;
    use passman_crypto::{random_secret, KdfParams, SecretArray, SecretBytes, SecretString};
    use passman_hsm::HsmError;

    /// Cheap Argon2 params for fast unit tests (8 KiB / 1 pass).
    const TEST_KDF: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    #[test]
    fn derive_master_is_deterministic_and_depends_on_all_inputs() {
        let pw = SecretString::new("master-pw".to_owned());
        let salt = [0x11u8; KEY_LEN];
        let k_hsm = SecretArray::new([0x22u8; KEY_LEN]);

        let base = derive_master(&pw, &salt, &TEST_KDF, &k_hsm).expect("derive base");
        let again = derive_master(&pw, &salt, &TEST_KDF, &k_hsm).expect("derive again");
        assert_eq!(base, again, "same inputs must yield same K_master");

        // Different K_hsm changes the result.
        let other_hsm = SecretArray::new([0x33u8; KEY_LEN]);
        let diff_hsm = derive_master(&pw, &salt, &TEST_KDF, &other_hsm).expect("derive diff_hsm");
        assert_ne!(base, diff_hsm);

        // Different password changes the result.
        let other_pw = SecretString::new("other-pw".to_owned());
        let diff_pw = derive_master(&other_pw, &salt, &TEST_KDF, &k_hsm).expect("derive diff_pw");
        assert_ne!(base, diff_pw);

        // Different salt changes the result.
        let diff_salt =
            derive_master(&pw, &[0x99u8; KEY_LEN], &TEST_KDF, &k_hsm).expect("derive diff_salt");
        assert_ne!(base, diff_salt);
    }

    #[test]
    fn into_key_requires_exact_length() {
        assert!(into_key(&SecretBytes::new(vec![0u8; KEY_LEN])).is_some());
        assert!(into_key(&SecretBytes::new(vec![0u8; KEY_LEN - 1])).is_none());
        assert!(into_key(&SecretBytes::new(vec![0u8; KEY_LEN + 1])).is_none());
        // Smoke the RNG path so the helper is exercised with real material.
        let _ = random_secret::<KEY_LEN>();
    }

    #[test]
    fn hsm_error_routing_matches_architecture() {
        assert!(matches!(
            map_hsm_unlock(HsmError::Cancelled),
            UnlockError::Cancelled
        ));
        assert!(matches!(
            map_hsm_unlock(HsmError::Transient),
            UnlockError::Retryable
        ));
        assert!(matches!(
            map_hsm_unlock(HsmError::PermanentlyInvalidated),
            UnlockError::RouteToRecovery
        ));
        assert!(matches!(
            map_hsm_unlock(HsmError::HardwareAbsent),
            UnlockError::RouteToRecovery
        ));
        assert!(matches!(
            map_hsm_unlock(HsmError::Backend("x".to_owned())),
            UnlockError::Hsm(_)
        ));
        assert!(matches!(
            map_hsm_unlock(HsmError::MalformedBlob { reason: "x" }),
            UnlockError::Hsm(_)
        ));
    }
}
