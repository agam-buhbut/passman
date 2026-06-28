//! The unlocked session [`UnlockedApp`] and its operations (`architecture.md`
//! §5.1–§5.4, §7.5).
//!
//! Holds `K_master`, the decrypted index (labels only), the session expiry, the
//! last copy/reveal instant, and the [`SessionToken`]. Every operation first
//! checks the session against the injected clock; an expired session returns
//! [`CoreError::Locked`]. `K_master` is a zeroizing [`SecretArray<32>`] and is
//! scrubbed when the session drops ([`UnlockedApp::lock`] forces that).
//!
//! Passwords are decrypted **on demand** (reveal / copy / export), never in
//! bulk; only labels live in memory while unlocked (§4.4).

use passman_crypto::{ct_eq, MasterKey, SecretArray, SecretString};
use passman_hsm::{BiometricPrompter, HsmSlot};
use passman_policy::{
    classify, estimate_master, generate, EntryPolicy, GenerationRequest, MasterEntropy,
};
use passman_recovery::{export, ExportPayload, RecoveryEntry, RecoveryPreset};
use passman_vault::{EntryId, EntryRecord, Index, IndexEntry, Vault};
use zeroize::Zeroize;

use crate::app::{App, KEY_LEN};
use crate::clipboard::{random_fact, ClearOutcome, Clipboard, ClipboardCookie};
use crate::error::CoreError;
use crate::progress::ProgressGuard;
use crate::session::SessionToken;

/// Seconds the session is clamped to after a copy/reveal (`architecture.md`
/// §5.2).
const POST_COPY_SECS: u64 = 30;

/// Which secret field of an entry to copy/reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealField {
    /// The account username.
    Username,
    /// The account password.
    Password,
    /// The associated URL.
    Url,
    /// The free-form notes.
    Notes,
}

/// A non-secret handle to a vault entry: its id and label, from the decrypted
/// index (`architecture.md` §4.5). Carries no secret fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHandle {
    /// Stable entry id.
    pub id: EntryId,
    /// Human-readable label.
    pub label: String,
}

/// The outcome of a master-password change (`architecture.md` §7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordChangeOutcome {
    /// Whether a recovery export already existed before the change, and is now
    /// stale. The shell should warn the user to regenerate it.
    pub existing_export_now_stale: bool,
}

/// An unlocked vault session, generic over the HSM backend.
///
/// Borrows its parent [`App`] for the backend, clock, and vault path. Dropping
/// it (or calling [`UnlockedApp::lock`]) zeroizes `K_master`.
pub struct UnlockedApp<'a, H: passman_hsm::HardwareKeyStore> {
    /// The parent locked handle (backend, clock, path).
    app: &'a App<H>,
    /// The root vault key. Zeroizing; scrubbed on drop.
    k_master: MasterKey,
    /// The decrypted index (labels + policies only).
    index: Index,
    /// Session expiry as Unix seconds (no sliding — `architecture.md` §5.2).
    session_expiry: u64,
    /// The opaque, process-local session token.
    session_token: SessionToken,
}

/// Redacted: never prints `K_master`, the index contents, or the token.
impl<H: passman_hsm::HardwareKeyStore> std::fmt::Debug for UnlockedApp<'_, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedApp")
            .field("entries", &self.index.len())
            .field("session_expiry", &self.session_expiry)
            .finish_non_exhaustive()
    }
}

impl<'a, H: passman_hsm::HardwareKeyStore> UnlockedApp<'a, H> {
    /// Construct an unlocked session. Crate-internal: only [`App`] builds these.
    pub(crate) fn new(
        app: &'a App<H>,
        k_master: MasterKey,
        index: Index,
        session_expiry: u64,
        session_token: SessionToken,
    ) -> Self {
        Self {
            app,
            k_master,
            index,
            session_expiry,
            session_token,
        }
    }

    /// The opaque session token, presented by the UI on privileged calls
    /// (`architecture.md` §5.1).
    #[must_use]
    pub fn session_token(&self) -> &SessionToken {
        &self.session_token
    }

    /// Explicitly lock the session, consuming and dropping it (which zeroizes
    /// `K_master`).
    pub fn lock(self) {
        // Dropping `self` runs `SecretArray`'s `ZeroizeOnDrop`.
        drop(self);
    }

    /// List entries as non-secret [`EntryHandle`]s (id + label), from the
    /// decrypted index — no secret fields are touched (`architecture.md` §4.5).
    ///
    /// # Errors
    ///
    /// [`CoreError::Locked`] if the session has expired.
    pub fn list_entries(&self) -> Result<Vec<EntryHandle>, CoreError> {
        self.ensure_unlocked()?;
        Ok(self
            .index
            .entries()
            .iter()
            .map(|e| EntryHandle {
                id: e.id,
                label: e.label.clone(),
            })
            .collect())
    }

    /// Decrypt the entry `id`, run `f` over the (zeroizing) [`EntryRecord`], and
    /// return `f`'s result. The record is dropped (scrubbed) after `f` returns
    /// (the desktop reveal pattern, `architecture.md` §5.4).
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Vault`] if the entry is missing or decryption fails.
    pub fn with_revealed<R>(
        &self,
        id: &EntryId,
        f: impl FnOnce(&EntryRecord) -> R,
    ) -> Result<R, CoreError> {
        self.ensure_unlocked()?;
        let vault = self.load_vault()?;
        let record = vault.decrypt_entry(&self.k_master, id)?;
        let out = f(&record);
        // `record` drops here, scrubbing the four SecretStrings.
        Ok(out)
    }

    /// Decrypt the chosen field of entry `id`, write it to the clipboard, clamp
    /// the session to `+30 s`, and return the [`ClipboardCookie`] the
    /// [`Clipboard`] impl produced (`architecture.md` §5.3). The shell schedules
    /// the 30 s clear and calls [`UnlockedApp::clear_clipboard`].
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Vault`] if the entry is missing or decryption fails.
    /// - [`CoreError`] from the clipboard write.
    pub fn copy_to_clipboard(
        &mut self,
        id: &EntryId,
        field: RevealField,
        clipboard: &dyn Clipboard,
    ) -> Result<ClipboardCookie, CoreError> {
        self.ensure_unlocked()?;
        let vault = self.load_vault()?;
        let record = vault.decrypt_entry(&self.k_master, id)?;

        // Borrow the chosen field; `write` copies it onto the clipboard and the
        // record (and its SecretStrings) drops at the end of this scope.
        let cookie = {
            let secret: &SecretString = select_field(&record, field);
            clipboard.write(secret)?
        };

        // Clamp the session: session_expiry = min(expiry, now + 30 s) (§5.2).
        let now = self.now();
        let clamp_to = now.saturating_add(POST_COPY_SECS);
        self.session_expiry = self.session_expiry.min(clamp_to);

        Ok(cookie)
    }

    /// Clear the clipboard if it still holds the value identified by `cookie`
    /// (`architecture.md` §5.3).
    ///
    /// Reads the current digest and constant-time-compares it to the cookie. If
    /// it matches, overwrites with a randomly-chosen [`crate::clipboard::FACTS`]
    /// entry when `fact_overwrite` is enabled (default), else reports
    /// [`ClearOutcome::StillOurs`] and leaves it for the shell to empty. A
    /// foreign value is left untouched.
    ///
    /// Does not require an unlocked session: the 30 s timer may fire after the
    /// session has expired, and clearing a stale secret must still work.
    #[must_use]
    pub fn clear_clipboard(
        &self,
        cookie: &ClipboardCookie,
        clipboard: &dyn Clipboard,
    ) -> ClearOutcome {
        // Intentionally ignores session state: the 30 s clear timer may fire
        // after the session has expired, and clearing a stale secret must still
        // work. Kept as a method (not a free fn) so the UI calls it on the same
        // session handle it copied from (the task's `&self` signature).
        let _ = self;
        clear_clipboard_impl(cookie, clipboard, true)
    }

    /// Like [`UnlockedApp::clear_clipboard`] but with an explicit
    /// `fact_overwrite` toggle (`clipboard.fact_overwrite`, §5.3).
    #[must_use]
    pub fn clear_clipboard_with(
        &self,
        cookie: &ClipboardCookie,
        clipboard: &dyn Clipboard,
        fact_overwrite: bool,
    ) -> ClearOutcome {
        let _ = self;
        clear_clipboard_impl(cookie, clipboard, fact_overwrite)
    }

    /// Add a new entry, then atomically persist the vault.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Vault`] / [`CoreError::Io`] on encryption or write
    ///   failure.
    pub fn add_entry(
        &mut self,
        label: String,
        policy: EntryPolicy,
        record: &EntryRecord,
    ) -> Result<EntryId, CoreError> {
        self.ensure_unlocked()?;
        let id = EntryId::generate();
        self.upsert_entry(id, label, policy, record)?;
        Ok(id)
    }

    /// Update an existing entry (by id), then atomically persist the vault.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Vault`] (incl. [`passman_vault::VaultError::EntryNotFound`])
    ///   / [`CoreError::Io`] on failure.
    pub fn update_entry(
        &mut self,
        id: EntryId,
        label: String,
        policy: EntryPolicy,
        record: &EntryRecord,
    ) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        if self.index.get(&id).is_none() {
            return Err(CoreError::Vault(passman_vault::VaultError::EntryNotFound));
        }
        self.upsert_entry(id, label, policy, record)
    }

    /// Remove an entry by id, then atomically persist the vault.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Vault`] (incl. `EntryNotFound`) / [`CoreError::Io`].
    pub fn remove_entry(&mut self, id: &EntryId) -> Result<(), CoreError> {
        self.ensure_unlocked()?;
        let mut vault = self.load_vault()?;
        vault.remove_entry(&self.k_master, id)?;
        self.persist_and_refresh(&mut vault)
    }

    /// Generate a password per `req` (delegates to [`passman_policy::generate`]).
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Policy`] if the request is unsatisfiable.
    pub fn generate_password(&self, req: &GenerationRequest) -> Result<SecretString, CoreError> {
        self.ensure_unlocked()?;
        Ok(generate(req)?)
    }

    /// Estimate a candidate master password's strength (delegates to
    /// [`passman_policy::estimate_master`]). Uses the current vault's KDF
    /// parameters for the through-KDF crack estimate.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError`] if the vault cannot be read.
    pub fn estimate_master_strength(
        &self,
        password: &str,
        user_inputs: &[&str],
    ) -> Result<MasterEntropy, CoreError> {
        self.ensure_unlocked()?;
        let vault = self.load_vault()?;
        Ok(estimate_master(password, user_inputs, &vault.kdf_params()))
    }

    /// Change the master password, re-deriving `K_master` over the **same**
    /// `K_hsm` / `S` (unwrapped fresh) and re-encrypting the vault under the new
    /// `K_master` (`architecture.md` §7.7).
    ///
    /// Verifies `old` (probe) before changing, bumps
    /// [`passman_vault::VaultMetadata`] `last_password_change`, and atomically
    /// writes. Returns whether an existing export is now stale so the shell can
    /// warn (§7.7). The live session's `K_master` is updated in place.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::Vault`] if `old` does not verify (probe failure) or
    ///   re-encryption fails.
    /// - [`CoreError::Hsm`] if unwrapping `K_hsm` fails.
    pub fn change_master_password(
        &mut self,
        old: &SecretString,
        new: &SecretString,
        kdf: passman_crypto::KdfParams,
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<PasswordChangeOutcome, CoreError> {
        self.ensure_unlocked()?;
        let vault = self.load_vault()?;

        // Unwrap K_hsm fresh (reused, not rotated).
        let k_hsm =
            self.app
                .unwrap_slot_core(HsmSlot::VaultKey, vault.k_hsm_wrap_blob(), ctx, prompter)?;

        // Bracket both Argon2id derivations (verify old + derive new) plus the
        // full re-encrypt for the progress UI (§2.5).
        let _pg = ProgressGuard::start(self.app.progress(), "Changing master password");

        // Verify the OLD password derives the current K_master (probe).
        let old_master = crate::app::derive_master_from_bytes(
            old,
            vault.vault_salt(),
            &vault.kdf_params(),
            &k_hsm,
        )?;
        vault.verify_probe(&old_master)?;

        // Re-encrypt the whole vault under a NEW K_master with fresh salt and
        // KDF params. Decrypt every entry under the old key, rebuild a fresh
        // vault under the new key, carrying the index labels/policies forward.
        let new_salt: [u8; KEY_LEN] = *passman_crypto::random_secret::<KEY_LEN>().expose();
        let new_master = crate::app::derive_master_from_bytes(new, &new_salt, &kdf, &k_hsm)?;

        let existing_export = vault.metadata().last_export_at.is_some();
        let rebuilt = self.reencrypt_vault(&vault, &new_salt, kdf, &new_master)?;
        crate::storage::atomic_write(self.app.path(), &rebuilt.to_bytes())?;

        // Update the live session to the new key + index.
        self.k_master = new_master;
        self.index = rebuilt.open_index(&self.k_master)?;

        Ok(PasswordChangeOutcome {
            existing_export_now_stale: existing_export,
        })
    }

    /// Create a single-factor recovery export (`architecture.md` §7.5).
    ///
    /// Gate: the master password must classify as Strong-or-above
    /// ([`StrengthTier::allows_export`]) else [`CoreError::WeakPasswordForExport`].
    /// Fresh re-auth: re-runs HSM unwrap + TOTP verify + probe, independent of
    /// the session token (so malware holding a session cannot export). Then
    /// decrypts every entry, translates [`EntryPolicy`] to postcard bytes for
    /// the [`RecoveryEntry`], assembles the [`ExportPayload`] (carrying the TOTP
    /// seed and the original vault KDF), and calls [`passman_recovery::export`]
    /// with the chosen preset. Returns the file bytes for the shell to write.
    ///
    /// On success the vault's `last_export_at` metadata is updated and
    /// persisted.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Locked`] if the session has expired.
    /// - [`CoreError::WeakPasswordForExport`] if the master fails the §7.5 gate.
    /// - [`CoreError::Vault`] if re-auth (probe/TOTP) or any decrypt fails.
    /// - [`CoreError::Hsm`] if unwrapping a slot fails.
    /// - [`CoreError::Recovery`] if the export (incl. the Floor gate) fails.
    pub fn export_recovery(
        &mut self,
        master_for_reauth: &SecretString,
        totp_for_reauth: &str,
        recovery_preset: RecoveryPreset,
        ctx: &H::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<Vec<u8>, CoreError> {
        self.ensure_unlocked()?;

        // §7.5 export gate: master must be Strong or above. We score it with the
        // vault's KDF params (the through-KDF estimate doesn't affect the tier).
        let vault = self.load_vault()?;
        let entropy = estimate_master(master_for_reauth.expose(), &[], &vault.kdf_params());
        if !classify(entropy.bits).allows_export() {
            return Err(CoreError::WeakPasswordForExport);
        }

        // Bracket the heavy section: the re-auth Argon2id and, dominantly, the
        // aggressive recovery-export Argon2id (≥1 GiB Floor) — one indeterminate
        // progress span for the shell (§2.5).
        let _pg = ProgressGuard::start(self.app.progress(), "Creating recovery export");

        // Fresh re-auth, independent of the session token: unwrap both slots,
        // verify TOTP against S, derive K_master from the supplied master, and
        // verify the probe.
        let k_hsm =
            self.app
                .unwrap_slot_core(HsmSlot::VaultKey, vault.k_hsm_wrap_blob(), ctx, prompter)?;
        let seed = self.app.unwrap_slot_core(
            HsmSlot::TotpSeed,
            vault.totp_seed_wrap_blob(),
            ctx,
            prompter,
        )?;
        self.app
            .reverify_totp(seed.expose(), totp_for_reauth)
            .map_err(|()| {
                CoreError::Vault(passman_vault::VaultError::Crypto(
                    passman_crypto::CryptoError::AeadAuth,
                ))
            })?;
        let reauth_master = crate::app::derive_master_from_bytes(
            master_for_reauth,
            vault.vault_salt(),
            &vault.kdf_params(),
            &k_hsm,
        )?;
        vault.verify_probe(&reauth_master)?;

        // Build the payload: decrypt each entry, translate the policy.
        let seed_arr =
            key_from_bytes(&seed).ok_or(CoreError::Hsm(passman_hsm::HsmError::MalformedBlob {
                reason: "unwrapped TOTP seed is not 32 bytes",
            }))?;
        let mut entries: Vec<RecoveryEntry> = Vec::with_capacity(self.index.len());
        for row in self.index.entries() {
            let record = vault.decrypt_entry(&reauth_master, &row.id)?;
            entries.push(recovery_entry_from(row, &record)?);
        }
        let payload = ExportPayload {
            totp_seed: seed_arr,
            original_vault_kdf: vault.kdf_params(),
            entries,
        };

        let file = export(&payload, master_for_reauth, &recovery_preset.params())?;

        // Record last_export_at and persist.
        let mut vault = vault;
        let mut meta = vault.metadata();
        meta.last_export_at = Some(self.now_i64());
        vault.set_metadata(meta);
        crate::storage::atomic_write(self.app.path(), &vault.to_bytes())?;

        Ok(file)
    }

    // ----- Internal helpers ----------------------------------------------------

    /// Re-encrypt every entry of `source` into a fresh vault under `new_master`
    /// with `new_salt` / `kdf`, carrying index labels and policies forward.
    fn reencrypt_vault(
        &self,
        source: &Vault,
        new_salt: &[u8; KEY_LEN],
        kdf: passman_crypto::KdfParams,
        new_master: &MasterKey,
    ) -> Result<Vault, CoreError> {
        let mut meta = source.metadata();
        meta.last_password_change = self.now_i64();

        let mut rebuilt = Vault::create(
            kdf,
            *new_salt,
            source.k_hsm_wrap_blob().to_vec(),
            source.totp_seed_wrap_blob().to_vec(),
            meta,
            new_master,
        )?;

        // Re-encrypt each entry under the new key (decrypt with the OLD key).
        for row in self.index.entries() {
            let record = source.decrypt_entry(&self.k_master, &row.id)?;
            rebuilt.add_or_update_entry(
                new_master,
                row.id,
                row.label.clone(),
                row.policy.clone(),
                &record,
            )?;
        }
        Ok(rebuilt)
    }

    /// Encrypt `record` into the vault under id/label/policy, persist, and
    /// refresh the in-memory index.
    fn upsert_entry(
        &mut self,
        id: EntryId,
        label: String,
        policy: EntryPolicy,
        record: &EntryRecord,
    ) -> Result<(), CoreError> {
        let mut vault = self.load_vault()?;
        vault.add_or_update_entry(&self.k_master, id, label, policy, record)?;
        self.persist_and_refresh(&mut vault)
    }

    /// Persist `vault` atomically and refresh the in-memory index from it.
    fn persist_and_refresh(&mut self, vault: &mut Vault) -> Result<(), CoreError> {
        crate::storage::atomic_write(self.app.path(), &vault.to_bytes())?;
        self.index = vault.open_index(&self.k_master)?;
        Ok(())
    }

    /// Read and parse the vault from disk.
    fn load_vault(&self) -> Result<Vault, CoreError> {
        let bytes = crate::storage::read(self.app.path())?;
        Ok(Vault::from_bytes(&bytes)?)
    }

    /// Reject the operation if the session has expired (`architecture.md`
    /// §5.2). No sliding: this only reads the clock, it never extends expiry.
    fn ensure_unlocked(&self) -> Result<(), CoreError> {
        if self.now() >= self.session_expiry {
            Err(CoreError::Locked)
        } else {
            Ok(())
        }
    }

    /// Whether the session has passed its hard expiry. Lets the worker
    /// proactively auto-lock an idle session (§5.2) without running an op.
    pub(crate) fn is_expired(&self) -> bool {
        self.now() >= self.session_expiry
    }

    /// Current time as Unix seconds (`u64`).
    fn now(&self) -> u64 {
        self.app.clock().now().as_unix_secs()
    }

    /// Current time as Unix seconds (`i64`, for metadata).
    fn now_i64(&self) -> i64 {
        i64::try_from(self.now()).unwrap_or(i64::MAX)
    }
}

/// Select the requested secret field from a decrypted record.
fn select_field(record: &EntryRecord, field: RevealField) -> &SecretString {
    match field {
        RevealField::Username => &record.username,
        RevealField::Password => &record.password,
        RevealField::Url => &record.url,
        RevealField::Notes => &record.notes,
    }
}

/// The clear-by-overwrite logic, shared by the public clear methods
/// (`architecture.md` §5.3). Free of session state — see
/// [`UnlockedApp::clear_clipboard`].
fn clear_clipboard_impl(
    cookie: &ClipboardCookie,
    clipboard: &dyn Clipboard,
    fact_overwrite: bool,
) -> ClearOutcome {
    let current = match clipboard.read_digest() {
        Ok(Some(digest)) => digest,
        Ok(None) => return ClearOutcome::Empty,
        Err(_) => return ClearOutcome::Unavailable,
    };
    // Constant-time compare against the cookie digest (§5.3).
    if !ct_eq(&current, cookie.digest()) {
        return ClearOutcome::Replaced;
    }
    if !fact_overwrite {
        return ClearOutcome::StillOurs;
    }
    match clipboard.set_text(random_fact()) {
        Ok(()) => ClearOutcome::Cleared,
        Err(_) => ClearOutcome::Unavailable,
    }
}

/// Translate a sealed-index row + decrypted record into a [`RecoveryEntry`],
/// postcard-encoding the [`EntryPolicy`] into the opaque `policy` bytes
/// (`architecture.md` §7.3).
fn recovery_entry_from(row: &IndexEntry, record: &EntryRecord) -> Result<RecoveryEntry, CoreError> {
    let policy_bytes = postcard::to_allocvec(&row.policy).map_err(|_| {
        // postcard serialization of EntryPolicy cannot realistically fail; map
        // it to a malformed-record vault error rather than panicking.
        CoreError::Vault(passman_vault::VaultError::MalformedRecord {
            reason: "failed to serialize EntryPolicy for export",
        })
    })?;
    Ok(RecoveryEntry {
        id: *row.id.as_bytes(),
        label: row.label.clone(),
        // Clone the secret fields into fresh SecretStrings (the recovery DTO
        // owns zeroizing copies; the source `record` drops at the call site).
        username: SecretString::new(record.username.expose().to_owned()),
        password: SecretString::new(record.password.expose().to_owned()),
        url: SecretString::new(record.url.expose().to_owned()),
        notes: SecretString::new(record.notes.expose().to_owned()),
        policy: policy_bytes,
    })
}

/// Copy a [`passman_crypto::SecretBytes`] of exactly [`KEY_LEN`] into a
/// [`SecretArray`].
fn key_from_bytes(bytes: &passman_crypto::SecretBytes) -> Option<SecretArray<KEY_LEN>> {
    if bytes.expose().len() == KEY_LEN {
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes.expose());
        let key = SecretArray::new(arr);
        // `arr` is `Copy` and unused hereafter, so `fill(0)` would be a dead
        // non-volatile store the optimizer may elide. `zeroize` is a volatile,
        // non-elidable write — the key copy must not survive on the stack.
        arr.zeroize();
        Some(key)
    } else {
        None
    }
}

/// Translate a [`RecoveryEntry`] back to its parts for re-encryption on import
/// (`architecture.md` §7.6): decode the opaque policy bytes to an
/// [`EntryPolicy`] and assemble an [`EntryRecord`].
///
/// # Errors
///
/// [`CoreError::Recovery`] if the policy bytes are not valid postcard.
pub(crate) fn import_entry_parts(
    entry: RecoveryEntry,
) -> Result<(EntryId, String, EntryPolicy, EntryRecord), CoreError> {
    let policy: EntryPolicy = postcard::from_bytes(&entry.policy).map_err(|_| {
        CoreError::Recovery(passman_recovery::RecoveryError::MalformedPayload {
            reason: "entry policy bytes are not valid postcard",
        })
    })?;
    let id = EntryId::from_bytes(entry.id);
    let record = EntryRecord::new(entry.username, entry.password, entry.url, entry.notes);
    Ok((id, entry.label, policy, record))
}
