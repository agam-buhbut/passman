//! `passman-uniffi` — the `UniFFI` binding surface for the Android
//! (Kotlin/Compose) front-end (`architecture.md` §6.5, Android plan Task 7).
//!
//! A **pure binding crate**: it exposes a concrete, non-generic
//! [`PassmanApp`] monomorphized over [`AndroidKeyStore`], plus the foreign
//! callback interfaces the Kotlin shim implements ([`KeystoreBridge`],
//! [`ClipboardBridge`]). All orchestration lives in `passman-core` (driven here
//! through the shared session actor [`passman_core::Session`]); generics and the
//! associated `PlatformCtx` never cross the FFI boundary.
//!
//! The biometric prompt is **not** a foreign callback: an Android per-use-auth
//! key drives its own `BiometricPrompt` inside the Kotlin `KeystoreBridge.wrap`
//! / `unwrap` (decision D-A1), so the Rust side passes a no-op prompter.

// Every `#[uniffi::export]` method and foreign-trait method takes **owned**
// parameters by necessity — UniFFI cannot pass references across the FFI
// boundary (§6.5) — so `needless_pass_by_value` does not apply. The foreign
// bridge traits document their errors collectively (each is a foreign failure),
// so per-method `# Errors` sections add no information here.
#![allow(clippy::needless_pass_by_value, clippy::missing_errors_doc)]

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, PoisonError};

use passman_core::worker::{Request, Response};
use passman_core::{App, ClipboardCookie, EntryHandle, RecoveryPreset, RevealField, Session};
use passman_crypto::{KdfParams, SecretString};
use passman_hsm::{
    AndroidKeyStore, BiometricPrompter, HsmError, KeystoreError, KeystoreSecurityLevel,
    KeystoreWrapper, PromptResult, WrappedParts,
};
use passman_totp::{Clock, SystemClock};
use passman_vault::EntryId;

uniffi::setup_scaffolding!();

/// GCM IV length (Android `Keystore` AES-GCM, §6.4); the host `WrappedParts.iv`
/// is `[u8; 12]`.
const GCM_IV_LEN: usize = 12;
/// SHA-256 clipboard cookie digest length (§5.3).
const DIGEST_LEN: usize = 32;
/// Entry id length (`UUIDv4`, §4.4).
const ENTRY_ID_LEN: usize = 16;

// ===== Foreign value types (mirrors of the host Android types) ==============

/// Hardware security level backing a `Keystore` key (§6.2).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum SecurityLevel {
    /// Discrete secure element (`StrongBox`).
    StrongBox,
    /// TEE-backed.
    TrustedEnvironment,
    /// Pure software (refused, §6.2).
    Software,
}

impl From<SecurityLevel> for KeystoreSecurityLevel {
    fn from(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::StrongBox => KeystoreSecurityLevel::StrongBox,
            SecurityLevel::TrustedEnvironment => KeystoreSecurityLevel::TrustedEnvironment,
            SecurityLevel::Software => KeystoreSecurityLevel::Software,
        }
    }
}

/// Typed, message-free `Keystore` failure categories the Kotlin shim normalizes
/// Java exceptions / biometric `int` codes into (invariant 5).
#[derive(Debug, Clone, Copy, uniffi::Error, thiserror::Error)]
pub enum KeystoreFailure {
    /// User dismissed the prompt.
    #[error("cancelled")]
    Cancelled,
    /// Biometric lockout (transient; cleared by device-credential re-auth).
    #[error("lockout")]
    Lockout,
    /// The wrapping key was permanently invalidated.
    #[error("key invalidated")]
    KeyInvalidated,
    /// GCM authentication failed (wrong slot AAD or tampered blob).
    #[error("auth failed")]
    AuthFailed,
    /// No secure lock screen / no usable hardware `Keystore`.
    #[error("no secure lock or hardware")]
    NoSecureLockOrHardware,
    /// Any other backend fault.
    #[error("backend error")]
    Backend,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeystoreFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        KeystoreFailure::Backend
    }
}

impl From<KeystoreFailure> for KeystoreError {
    fn from(f: KeystoreFailure) -> Self {
        match f {
            KeystoreFailure::Cancelled => KeystoreError::Cancelled,
            KeystoreFailure::Lockout => KeystoreError::Lockout,
            KeystoreFailure::KeyInvalidated => KeystoreError::KeyInvalidated,
            KeystoreFailure::AuthFailed => KeystoreError::AuthFailed,
            KeystoreFailure::NoSecureLockOrHardware => KeystoreError::NoSecureLockOrHardware,
            KeystoreFailure::Backend => KeystoreError::Backend,
        }
    }
}

/// The outputs of a successful [`KeystoreBridge::wrap`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct WrapOutput {
    /// The `Keystore`-generated 12-byte GCM IV (`Cipher.getIV()`).
    pub iv: Vec<u8>,
    /// The ciphertext with the appended 16-byte GCM tag.
    pub ciphertext: Vec<u8>,
    /// The security level of the key that produced this ciphertext.
    pub level: SecurityLevel,
}

/// A foreign-callback failure (clipboard bridge).
#[derive(Debug, Clone, Copy, uniffi::Error, thiserror::Error)]
pub enum CallbackError {
    /// The foreign operation failed.
    #[error("foreign callback failed")]
    Failed,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for CallbackError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        CallbackError::Failed
    }
}

// ===== Foreign callback interfaces (implemented by the Kotlin shim) =========

/// The Android `Keystore` mechanics, implemented foreign-side by the Kotlin shim
/// (Task 8). Mirrors `passman_hsm::KeystoreWrapper`; the [`KeystoreAdapter`]
/// forwards the host trait to it.
#[uniffi::export(with_foreign)]
pub trait KeystoreBridge: Send + Sync {
    /// Generate a per-use-auth AES-256-GCM key under `alias`, encrypt `material`
    /// with `AAD = [slot_tag]` (driving the `CryptoObject` prompt), and return
    /// the IV, ciphertext+tag, and security level. MUST delete `alias` on any
    /// post-keygen failure (invariant 6).
    fn wrap(
        &self,
        alias: String,
        slot_tag: u8,
        material: Vec<u8>,
    ) -> Result<WrapOutput, KeystoreFailure>;

    /// Decrypt `ciphertext` under `alias` with `AAD = [slot_tag]` and `iv`.
    fn unwrap(
        &self,
        alias: String,
        slot_tag: u8,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, KeystoreFailure>;

    /// Destroy `alias`'s key (idempotent).
    fn invalidate(&self, alias: String) -> Result<(), KeystoreFailure>;

    /// Probe the device's hardware security posture (refuse-software pre-flight).
    fn probe(&self) -> Result<SecurityLevel, KeystoreFailure>;
}

/// The OS clipboard, implemented foreign-side by the Kotlin shim (§5.3). The
/// foreign impl computes the SHA-256 digest of what it writes (core never
/// hashes).
#[uniffi::export(with_foreign)]
pub trait ClipboardBridge: Send + Sync {
    /// Place `secret` on the clipboard; return its SHA-256 digest (32 bytes).
    fn write(&self, secret: String) -> Result<Vec<u8>, CallbackError>;

    /// The SHA-256 digest of the clipboard's current contents, or `None`.
    fn read_digest(&self) -> Result<Option<Vec<u8>>, CallbackError>;

    /// Overwrite the clipboard with `text` (clear-by-overwrite).
    fn set_text(&self, text: String) -> Result<(), CallbackError>;
}

// ===== Adapters: foreign interface -> host trait ============================

/// Adapts a foreign [`KeystoreBridge`] to the host `KeystoreWrapper`.
struct KeystoreAdapter(Arc<dyn KeystoreBridge>);

impl KeystoreWrapper for KeystoreAdapter {
    fn wrap(
        &self,
        alias: &str,
        slot_tag: u8,
        material: &[u8],
    ) -> Result<WrappedParts, KeystoreError> {
        // `material.to_vec()` is a transient plaintext heap copy handed by value
        // across the FFI to the Kotlin `KeystoreBridge.wrap`. UniFFI *moves* the
        // Vec across the boundary, so it cannot be zeroized here without first
        // taking an extra, unscrubbed copy to scrub afterwards — strictly worse.
        // This is an accepted, inherent FFI residual (H3): the canonical secret
        // is the caller's zeroizing SecretBytes (still intact), the Kotlin side
        // scrubs its own copy (`material.fill(0)`), and this is the one
        // unavoidable plaintext hop between the two.
        let out = self.0.wrap(alias.to_owned(), slot_tag, material.to_vec())?;
        let iv =
            <[u8; GCM_IV_LEN]>::try_from(out.iv.as_slice()).map_err(|_| KeystoreError::Backend)?;
        Ok(WrappedParts {
            iv,
            ciphertext: out.ciphertext,
            level: out.level.into(),
        })
    }

    fn unwrap(
        &self,
        alias: &str,
        slot_tag: u8,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeystoreError> {
        Ok(self
            .0
            .unwrap(alias.to_owned(), slot_tag, iv.to_vec(), ciphertext.to_vec())?)
    }

    fn invalidate(&self, alias: &str) -> Result<(), KeystoreError> {
        Ok(self.0.invalidate(alias.to_owned())?)
    }

    fn probe(&self) -> Result<KeystoreSecurityLevel, KeystoreError> {
        Ok(self.0.probe()?.into())
    }
}

/// Adapts a foreign [`ClipboardBridge`] to the host `Clipboard`.
struct ClipboardAdapter(Arc<dyn ClipboardBridge>);

fn fixed_digest(v: Vec<u8>) -> Result<[u8; DIGEST_LEN], passman_core::CoreError> {
    <[u8; DIGEST_LEN]>::try_from(v.as_slice()).map_err(|_| {
        passman_core::CoreError::shell_io(
            "clipboard digest length",
            std::io::Error::other("digest is not 32 bytes"),
        )
    })
}

fn callback_io(_: CallbackError) -> passman_core::CoreError {
    passman_core::CoreError::shell_io(
        "clipboard bridge",
        std::io::Error::other("foreign clipboard failed"),
    )
}

impl passman_core::Clipboard for ClipboardAdapter {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie, passman_core::CoreError> {
        let digest = self
            .0
            .write(secret.expose().to_owned())
            .map_err(callback_io)?;
        Ok(ClipboardCookie::new(
            fixed_digest(digest)?,
            SystemClock.now(),
        ))
    }

    fn read_digest(&self) -> Result<Option<[u8; DIGEST_LEN]>, passman_core::CoreError> {
        match self.0.read_digest().map_err(callback_io)? {
            Some(v) => Ok(Some(fixed_digest(v)?)),
            None => Ok(None),
        }
    }

    fn set_text(&self, text: &str) -> Result<(), passman_core::CoreError> {
        self.0.set_text(text.to_owned()).map_err(callback_io)
    }
}

/// No-op prompter: the Android backend ignores it (the Kotlin shim drives the
/// `CryptoObject` prompt itself — decision D-A1).
struct NoopPrompter;

impl BiometricPrompter for NoopPrompter {
    fn prompt(&self, _reason: String) -> Result<PromptResult, HsmError> {
        Ok(PromptResult::Authenticated)
    }
}

// ===== App-facing types =====================================================

/// Which entry field to reveal/copy.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FieldKind {
    /// Username.
    Username,
    /// Password.
    Password,
    /// URL.
    Url,
    /// Notes.
    Notes,
}

impl From<FieldKind> for RevealField {
    fn from(f: FieldKind) -> Self {
        match f {
            FieldKind::Username => RevealField::Username,
            FieldKind::Password => RevealField::Password,
            FieldKind::Url => RevealField::Url,
            FieldKind::Notes => RevealField::Notes,
        }
    }
}

/// Argon2id cost preset for vault creation (§4.8).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum KdfChoice {
    /// 256 MiB / t=4 (floor).
    Low,
    /// 1 GiB / t=4 (default).
    Medium,
    /// 4 GiB / t=6.
    High,
}

impl KdfChoice {
    fn params(self) -> KdfParams {
        match self {
            KdfChoice::Low => KdfParams::LOW,
            KdfChoice::Medium => KdfParams::MEDIUM,
            KdfChoice::High => KdfParams::HIGH,
        }
    }
}

/// Recovery-export Argon2id cost preset (§7.4), mirrored for Kotlin. Maps to the
/// core/recovery [`RecoveryPreset`] (mirrors the [`KdfChoice`] pattern).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum RecoveryChoice {
    /// 1 GiB / t=4 — the minimum the recovery format permits.
    Floor,
    /// 4 GiB / t=8 — the default.
    Default,
    /// 8 GiB / t=12.
    Paranoid,
}

impl RecoveryChoice {
    fn preset(self) -> RecoveryPreset {
        match self {
            RecoveryChoice::Floor => RecoveryPreset::Floor,
            RecoveryChoice::Default => RecoveryPreset::Default,
            RecoveryChoice::Paranoid => RecoveryPreset::Paranoid,
        }
    }
}

/// A non-secret entry handle (id + label).
#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryItem {
    /// The 16-byte entry id.
    pub id: Vec<u8>,
    /// The human-readable label.
    pub label: String,
}

impl From<EntryHandle> for EntryItem {
    fn from(h: EntryHandle) -> Self {
        EntryItem {
            id: h.id.as_bytes().to_vec(),
            label: h.label,
        }
    }
}

/// Errors surfaced to the Kotlin side from [`PassmanApp`] methods.
///
/// The message field is named `detail` (not `message`) so the generated Kotlin
/// exception subclasses do not clash with `Throwable.message`.
#[derive(Debug, Clone, uniffi::Error, thiserror::Error)]
pub enum AppError {
    /// The vault could not be opened (e.g. already in use, or no hardware).
    #[error("{detail}")]
    Setup {
        /// User-facing detail.
        detail: String,
    },
    /// An operation failed (bad credentials, missing entry, …).
    #[error("{detail}")]
    Failed {
        /// User-facing detail.
        detail: String,
    },
    /// The session is locked (expired or never unlocked); unlock again.
    #[error("the session is locked")]
    SessionLocked,
}

// ===== The concrete App object ==============================================

/// Worker handle + response channel, serialized behind one mutex (a single-vault
/// app processes one request at a time).
struct Inner {
    session: Session,
    responses: Receiver<Response>,
}

/// The concrete, non-generic password-manager handle exposed to Kotlin.
#[derive(uniffi::Object)]
pub struct PassmanApp {
    inner: Mutex<Inner>,
}

#[uniffi::export]
impl PassmanApp {
    /// Open the app for the vault at `vault_path`, wiring the foreign Keystore
    /// and clipboard bridges. Acquires the single-instance lock.
    ///
    /// # Errors
    ///
    /// [`AppError::Setup`] if the vault path cannot be locked/opened.
    #[uniffi::constructor]
    pub fn open(
        vault_path: String,
        keystore: Arc<dyn KeystoreBridge>,
        clipboard: Arc<dyn ClipboardBridge>,
        fact_overwrite: bool,
    ) -> Result<Arc<Self>, AppError> {
        let backend = AndroidKeyStore::new(Arc::new(KeystoreAdapter(keystore)));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let app = App::open(&vault_path, backend, clock).map_err(|e| AppError::Setup {
            detail: format!("could not open the vault: {e}"),
        })?;
        let (session, responses) = Session::spawn(
            app,
            move || Ok(ClipboardAdapter(clipboard)),
            Box::new(NoopPrompter),
            fact_overwrite,
        );
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner { session, responses }),
        }))
    }

    /// Create a new vault; returns the `otpauth://` provisioning URI (render it
    /// as a QR — it embeds the TOTP seed) and enters the unlocked session.
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] if creation fails.
    pub fn create_vault(&self, master: String, kdf: KdfChoice) -> Result<String, AppError> {
        match self.call(Request::Create {
            master: SecretString::new(master),
            kdf: kdf.params(),
        }) {
            Response::Created {
                provisioning_uri, ..
            } => Ok(provisioning_uri.expose().to_owned()),
            Response::CreateFailed { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }

    /// Unlock the vault; returns the entry list.
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] on bad credentials or a hardware error.
    pub fn unlock(&self, master: String, code: String) -> Result<Vec<EntryItem>, AppError> {
        match self.call(Request::Unlock {
            master: SecretString::new(master),
            code,
        }) {
            Response::Unlocked { entries } => {
                Ok(entries.into_iter().map(EntryItem::from).collect())
            }
            Response::UnlockFailed { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }

    /// Re-list the entries.
    ///
    /// # Errors
    ///
    /// [`AppError::SessionLocked`] if the session expired.
    pub fn list(&self) -> Result<Vec<EntryItem>, AppError> {
        self.expect_entries(Request::Refresh)
    }

    /// Reveal one field of an entry (for display; the UI obscures by default).
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] / [`AppError::SessionLocked`].
    pub fn reveal(&self, id: Vec<u8>, field: FieldKind) -> Result<String, AppError> {
        let id = entry_id(&id)?;
        match self.call(Request::Reveal {
            id,
            field: field.into(),
        }) {
            Response::Revealed { value, .. } => Ok(value.expose().to_owned()),
            Response::Locked => Err(AppError::SessionLocked),
            Response::Error { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }

    /// Copy one field to the clipboard; returns the cookie digest (pass it to
    /// [`PassmanApp::clear_clipboard`] after the auto-clear delay).
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] / [`AppError::SessionLocked`].
    pub fn copy(&self, id: Vec<u8>, field: FieldKind) -> Result<Vec<u8>, AppError> {
        let id = entry_id(&id)?;
        match self.call(Request::Copy {
            id,
            field: field.into(),
        }) {
            Response::Copied { cookie } => Ok(cookie.digest().to_vec()),
            Response::Locked => Err(AppError::SessionLocked),
            Response::Error { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }

    /// Clear the clipboard if it still holds the value with `digest` (§5.3).
    /// Fire-and-forget.
    pub fn clear_clipboard(&self, digest: Vec<u8>) {
        if let Ok(d) = <[u8; DIGEST_LEN]>::try_from(digest.as_slice()) {
            let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            inner.session.send(Request::ClearClipboard {
                cookie: ClipboardCookie::new(d, SystemClock.now()),
            });
        }
    }

    /// Add an entry; returns the refreshed entry list.
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] / [`AppError::SessionLocked`].
    pub fn add(
        &self,
        label: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    ) -> Result<Vec<EntryItem>, AppError> {
        self.expect_entries(Request::Add {
            label,
            username: SecretString::new(username),
            password: SecretString::new(password),
            url: SecretString::new(url),
            notes: SecretString::new(notes),
        })
    }

    /// Remove an entry; returns the refreshed entry list.
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] / [`AppError::SessionLocked`].
    pub fn remove(&self, id: Vec<u8>) -> Result<Vec<EntryItem>, AppError> {
        let id = entry_id(&id)?;
        self.expect_entries(Request::Remove { id })
    }

    /// Generate a password (does not touch the vault while unlocked).
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] / [`AppError::SessionLocked`].
    pub fn generate(&self, length: u16) -> Result<String, AppError> {
        match self.call(Request::Generate { length }) {
            Response::Generated { password } => Ok(password.expose().to_owned()),
            Response::Locked => Err(AppError::SessionLocked),
            Response::Error { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }

    /// Export a single-factor recovery backup (B7, §7.5): re-enter the master
    /// password and a FRESH TOTP code (not the unlock code), run the aggressive
    /// recovery Argon2id, and return the encrypted backup bytes for the Kotlin
    /// side to write to a user-chosen location.
    ///
    /// # Errors
    ///
    /// [`AppError::Failed`] on a weak master, failed re-auth, or export error;
    /// [`AppError::SessionLocked`] if the session expired.
    pub fn export_recovery(
        &self,
        master: String,
        code: String,
        preset: RecoveryChoice,
    ) -> Result<Vec<u8>, AppError> {
        match self.call(Request::ExportRecovery {
            master: SecretString::new(master),
            code,
            preset: preset.preset(),
        }) {
            Response::RecoveryExported { file } => Ok(file),
            Response::RecoveryExportFailed { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }

    /// Confirm a TOTP `code` against the live session seed (B8 — verify right
    /// after [`PassmanApp::create_vault`] that the authenticator was provisioned
    /// correctly). Returns whether the code is currently valid.
    ///
    /// # Errors
    ///
    /// [`AppError::SessionLocked`] if the session expired.
    pub fn verify_totp(&self, code: String) -> Result<bool, AppError> {
        match self.call(Request::VerifyTotp { code }) {
            Response::TotpChecked { valid } => Ok(valid),
            other => Err(unexpected(&other)),
        }
    }

    /// Lock the session (drop the keys). **Fire-and-forget**, exactly like
    /// [`PassmanApp::clear_clipboard`]: it takes the lock only to `send`, then
    /// returns without awaiting the worker's reply.
    ///
    /// Android calls this from `ON_STOP` on the main thread; routing it through
    /// the blocking [`PassmanApp::call`] would let an in-flight op stall the UI
    /// for its full duration (an ANR), and a wedged op holding the mutex across
    /// `recv` would freeze every entrypoint. The worker's resulting
    /// `Response::Locked` becomes an unsolicited response that the drain at the
    /// top of `call` discards before the next paired request (see `call`).
    pub fn lock(&self) {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.session.send(Request::Lock);
    }
}

impl PassmanApp {
    /// Send one request and block for the worker's single matching response.
    ///
    /// # Single-worker serialization model
    ///
    /// Every foreign entrypoint that needs a reply routes through here, and
    /// `call` holds `self.inner`'s mutex across the blocking `recv`. This is by
    /// design: the worker is single-threaded, so only one operation ever runs at
    /// a time, and serializing the whole request->response pair under one lock is
    /// what keeps each `recv` aligned one-to-one with the request it just sent.
    ///
    /// The lifecycle entrypoints [`PassmanApp::lock`] and
    /// [`PassmanApp::clear_clipboard`] are intentionally non-blocking (they take
    /// the lock only to `send`, never to `recv`) so an Android `ON_STOP` /
    /// auto-clear callback never waits on an in-flight op. `lock`'s worker-side
    /// `Response::Locked` is left in the channel as an unsolicited response; the
    /// drain below discards it before the next paired request, so pairing stays
    /// one-to-one (`clear_clipboard` produces no response at all).
    ///
    /// Known limitation: a *hung* backend op — e.g. a wedged `BiometricPrompt`
    /// inside a `KeystoreBridge::unwrap` — holds this mutex until it returns, so
    /// while it is stuck every other entrypoint blocks here too. The proper fix
    /// is per-call response channels (one reply channel per request, no shared
    /// mutex held across `recv`); that is future work and deliberately not done
    /// in this change.
    fn call(&self, request: Request) -> Response {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        // Discard any unsolicited responses (notably a proactive auto-lock
        // `Locked` emitted on the §5.2 idle timeout) so our `recv` lines up
        // one-to-one with the request we are about to send. Without this, a
        // spontaneous response would desync every subsequent call.
        while inner.responses.try_recv().is_ok() {}
        inner.session.send(request);
        inner.responses.recv().unwrap_or(Response::Error {
            message: "the session worker has stopped".to_owned(),
        })
    }

    /// Drive a request expected to yield an `Entries` response.
    fn expect_entries(&self, request: Request) -> Result<Vec<EntryItem>, AppError> {
        match self.call(request) {
            Response::Entries { entries } => Ok(entries.into_iter().map(EntryItem::from).collect()),
            Response::Locked => Err(AppError::SessionLocked),
            Response::Error { message } => Err(AppError::Failed { detail: message }),
            other => Err(unexpected(&other)),
        }
    }
}

/// Map a 16-byte slice to an [`EntryId`].
fn entry_id(bytes: &[u8]) -> Result<EntryId, AppError> {
    let arr = <[u8; ENTRY_ID_LEN]>::try_from(bytes).map_err(|_| AppError::Failed {
        detail: "invalid entry id".to_owned(),
    })?;
    Ok(EntryId::from_bytes(arr))
}

/// An unexpected response for the request just sent (a logic error).
fn unexpected(response: &Response) -> AppError {
    if matches!(response, Response::Locked) {
        AppError::SessionLocked
    } else {
        AppError::Failed {
            detail: "unexpected internal response".to_owned(),
        }
    }
}

/// Called once by the Kotlin side at startup to wire any global state. A no-op
/// today (the Rust side holds no global state), but the Kotlin shim asserts it
/// ran before any backend op (Task 7 Step 3 — replaces the non-firing
/// `JNI_OnLoad`).
#[uniffi::export]
pub fn android_init() {}

/// Estimate a candidate password's strength as a coarse `0..=4` score for the
/// create screen (0 = Dangerous … 4 = Excellent). Standalone: needs no session,
/// so the Kotlin create screen can score the master password before any vault
/// exists. Routes through `passman-core` (no direct policy dependency here).
#[uniffi::export]
#[must_use]
pub fn estimate_strength(password: String) -> u8 {
    passman_core::estimate_password_strength(&SecretString::new(password))
}

#[cfg(test)]
mod tests {
    use super::{
        entry_id, estimate_strength, fixed_digest, unexpected, AppError, EntryItem, FieldKind,
        KdfChoice, KeystoreFailure, RecoveryChoice, SecurityLevel,
    };
    use passman_core::worker::Response;
    use passman_core::{EntryHandle, RecoveryPreset, RevealField};
    use passman_crypto::KdfParams;
    use passman_hsm::{KeystoreError, KeystoreSecurityLevel};
    use passman_vault::EntryId;

    #[test]
    fn entry_id_requires_exactly_16_bytes() {
        assert!(entry_id(&[0u8; 16]).is_ok());
        for bad in [0usize, 15, 17, 32] {
            assert!(
                matches!(entry_id(&vec![0u8; bad]), Err(AppError::Failed { .. })),
                "len {bad} must be rejected"
            );
        }
    }

    #[test]
    fn fixed_digest_requires_exactly_32_bytes() {
        assert!(fixed_digest(vec![0u8; 32]).is_ok());
        assert!(fixed_digest(vec![0u8; 31]).is_err());
        assert!(fixed_digest(vec![0u8; 33]).is_err());
        assert!(fixed_digest(vec![]).is_err());
    }

    #[test]
    fn kdf_choice_maps_to_the_preset_params() {
        for (choice, preset) in [
            (KdfChoice::Low, KdfParams::LOW),
            (KdfChoice::Medium, KdfParams::MEDIUM),
            (KdfChoice::High, KdfParams::HIGH),
        ] {
            let p = choice.params();
            assert_eq!((p.m_kib, p.t, p.p), (preset.m_kib, preset.t, preset.p));
        }
    }

    #[test]
    fn recovery_choice_maps_to_the_preset() {
        for (choice, preset) in [
            (RecoveryChoice::Floor, RecoveryPreset::Floor),
            (RecoveryChoice::Default, RecoveryPreset::Default),
            (RecoveryChoice::Paranoid, RecoveryPreset::Paranoid),
        ] {
            assert_eq!(choice.preset(), preset);
        }
    }

    #[test]
    fn estimate_strength_returns_a_sane_score() {
        let weak = estimate_strength("password".to_owned());
        let strong = estimate_strength("xK7#mP2$qR9vL4nB8wZ!jH3tY6&".to_owned());
        assert!(weak <= 4 && strong <= 4, "scores must be within 0..=4");
        assert!(strong > weak, "a strong password must outscore a weak one");
        assert!(strong >= 3, "a high-entropy password should reach Strong+ (>=3)");
    }

    #[test]
    fn field_kind_maps_to_reveal_field() {
        assert!(matches!(
            RevealField::from(FieldKind::Username),
            RevealField::Username
        ));
        assert!(matches!(
            RevealField::from(FieldKind::Password),
            RevealField::Password
        ));
        assert!(matches!(
            RevealField::from(FieldKind::Url),
            RevealField::Url
        ));
        assert!(matches!(
            RevealField::from(FieldKind::Notes),
            RevealField::Notes
        ));
    }

    #[test]
    fn keystore_failure_maps_to_host_error() {
        assert!(matches!(
            KeystoreError::from(KeystoreFailure::Cancelled),
            KeystoreError::Cancelled
        ));
        assert!(matches!(
            KeystoreError::from(KeystoreFailure::Lockout),
            KeystoreError::Lockout
        ));
        assert!(matches!(
            KeystoreError::from(KeystoreFailure::KeyInvalidated),
            KeystoreError::KeyInvalidated
        ));
        assert!(matches!(
            KeystoreError::from(KeystoreFailure::AuthFailed),
            KeystoreError::AuthFailed
        ));
        assert!(matches!(
            KeystoreError::from(KeystoreFailure::Backend),
            KeystoreError::Backend
        ));
    }

    #[test]
    fn security_level_maps_to_host() {
        assert!(matches!(
            KeystoreSecurityLevel::from(SecurityLevel::StrongBox),
            KeystoreSecurityLevel::StrongBox
        ));
        assert!(matches!(
            KeystoreSecurityLevel::from(SecurityLevel::TrustedEnvironment),
            KeystoreSecurityLevel::TrustedEnvironment
        ));
        assert!(matches!(
            KeystoreSecurityLevel::from(SecurityLevel::Software),
            KeystoreSecurityLevel::Software
        ));
    }

    #[test]
    fn unexpected_routes_a_locked_response_to_session_locked() {
        // Defensive: even a response that arrives out of turn must surface a
        // lock as SessionLocked, never a generic failure.
        assert!(matches!(
            unexpected(&Response::Locked),
            AppError::SessionLocked
        ));
        assert!(matches!(
            unexpected(&Response::Error {
                message: "x".to_owned()
            }),
            AppError::Failed { .. }
        ));
    }

    #[test]
    fn entry_handle_converts_to_entry_item() {
        let item = EntryItem::from(EntryHandle {
            id: EntryId::from_bytes([7u8; 16]),
            label: "GitHub".to_owned(),
        });
        assert_eq!(item.id, vec![7u8; 16]);
        assert_eq!(item.label, "GitHub");
    }
}
