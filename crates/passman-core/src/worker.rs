//! The session actor: a worker thread that owns the `App` and, while unlocked,
//! the `UnlockedApp`.
//!
//! A single-threaded shell (a GTK main loop, a `UniFFI` foreign caller) must not
//! block on the multi-second Argon2id of `unlock`. The actor solves both that
//! and a borrow problem: `UnlockedApp` borrows its `App`, so the unlocked
//! session cannot be sent back to the caller. Instead the worker owns `App` for
//! its whole life and keeps the borrowed `UnlockedApp` as a stack local in an
//! inner loop — the shell drives it by sending [`Request`]s and receiving
//! [`Response`]s over channels.
//!
//! Reused by every shell (desktop GUI, mobile binding), so it is UI-toolkit-free
//! and tested against the mock backend.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How often the unlocked loop wakes to enforce the §5.2 hard timeout when no
/// request is driving it. Small enough that an idle session locks within ~1 s of
/// its deadline; the wake is a single clock comparison, so the cost is trivial.
const EXPIRY_POLL: Duration = Duration::from_secs(1);

use crate::{
    App, Clipboard, ClipboardCookie, CoreError, EntryHandle, RevealField, UnlockError, UnlockedApp,
};
use passman_crypto::{KdfParams, SecretString};
use passman_hsm::{BiometricPrompter, HardwareKeyStore};
use passman_policy::{Charset, EntryPolicy, GenerationRequest, RequiredClasses};
use passman_recovery::RecoveryPreset;
use passman_totp::TotpConfig;
use passman_vault::{EntryId, EntryRecord};

/// A message from the UI to the session worker.
pub enum Request {
    /// Create a brand-new vault, then enter the unlocked session.
    Create {
        /// Master password for the new vault.
        master: SecretString,
        /// Argon2id parameters for the master-key derivation.
        kdf: KdfParams,
    },
    /// Attempt to unlock with the master password and a TOTP code.
    Unlock { master: SecretString, code: String },
    /// Re-list the entries (after a mutation, or on demand).
    Refresh,
    /// Decrypt one field of an entry for display (obscured-by-default reveal).
    Reveal { id: EntryId, field: RevealField },
    /// Copy one field of an entry to the clipboard.
    Copy { id: EntryId, field: RevealField },
    /// Clear the clipboard if it still holds the value identified by `cookie`.
    ClearClipboard { cookie: ClipboardCookie },
    /// Generate a password (for the add form); does not touch the vault.
    Generate { length: u16 },
    /// Add a new entry.
    Add {
        /// Entry label.
        label: String,
        /// Username field.
        username: SecretString,
        /// Password field.
        password: SecretString,
        /// URL field.
        url: SecretString,
        /// Notes field.
        notes: SecretString,
    },
    /// Remove an entry by id.
    Remove { id: EntryId },
    /// Export a single-factor recovery backup (B7, `architecture.md` §7.5). Runs
    /// fresh re-auth (HSM unwrap + TOTP + probe) and the aggressive recovery
    /// Argon2id, then returns the encrypted backup bytes for the shell to write.
    ExportRecovery {
        /// Master password, re-entered for the §7.5 fresh re-auth.
        master: SecretString,
        /// A FRESH TOTP code for the re-auth (not the one used at unlock).
        code: String,
        /// Recovery Argon2id cost preset.
        preset: RecoveryPreset,
    },
    /// Verify a TOTP code against the live session seed (B8 — confirm right after
    /// vault creation that the authenticator was provisioned correctly).
    VerifyTotp {
        /// The candidate TOTP code.
        code: String,
    },
    /// Lock the session (drop the keys); the UI returns to the unlock screen.
    Lock,
    /// Stop the worker and exit the thread.
    Quit,
}

/// A message from the session worker back to the UI.
#[derive(Debug)]
pub enum Response {
    /// Vault creation succeeded; carries the TOTP provisioning URI to render as
    /// a QR (sensitive — it embeds the seed) and the (empty) entry list.
    Created {
        /// `otpauth://` provisioning URI (zeroizing).
        provisioning_uri: SecretString,
        /// The new vault's entries (empty).
        entries: Vec<EntryHandle>,
    },
    /// Vault creation failed; carries a user-facing message.
    CreateFailed { message: String },
    /// Unlock succeeded; carries the current entry list.
    Unlocked { entries: Vec<EntryHandle> },
    /// Unlock failed; carries a user-facing message.
    UnlockFailed { message: String },
    /// The current entry list (after `Refresh` / a mutation).
    Entries { entries: Vec<EntryHandle> },
    /// A revealed field value (the UI shows it, then it is dropped/zeroized).
    Revealed {
        field: RevealField,
        value: SecretString,
    },
    /// A field was copied; the cookie lets the UI schedule the clear.
    Copied { cookie: ClipboardCookie },
    /// A generated password (for the add form).
    Generated { password: SecretString },
    /// The session locked (timeout, explicit lock, or an op found it expired).
    Locked,
    /// A recovery backup was exported; carries the encrypted file bytes (the
    /// shell writes them to a user-chosen location).
    RecoveryExported {
        /// The encrypted recovery file bytes.
        file: Vec<u8>,
    },
    /// A recovery export failed; carries a user-facing message (never a secret).
    RecoveryExportFailed { message: String },
    /// The result of a [`Request::VerifyTotp`] check.
    TotpChecked {
        /// Whether the supplied code is currently valid.
        valid: bool,
    },
    /// A non-fatal operation error to surface to the user.
    Error { message: String },
}

/// A handle to the running session worker. Dropping it tells the worker to quit
/// and joins the thread.
pub struct Session {
    tx: Sender<Request>,
    join: Option<JoinHandle<()>>,
}

impl Session {
    /// Spawn the worker thread.
    ///
    /// `make_clipboard` is run **inside** the worker thread (the OS clipboard is
    /// not `Send`); a failure leaves the clipboard unavailable (copy reports an
    /// error) but the rest of the session works. Returns the handle and the
    /// response receiver (the UI attaches it to the GTK main loop).
    pub fn spawn<H, F, C>(
        app: App<H>,
        make_clipboard: F,
        prompter: Box<dyn BiometricPrompter>,
        fact_overwrite: bool,
    ) -> (Self, Receiver<Response>)
    where
        H: HardwareKeyStore<PlatformCtx = ()> + Send + 'static,
        F: FnOnce() -> Result<C, CoreError> + Send + 'static,
        C: Clipboard,
    {
        let (req_tx, req_rx) = std::sync::mpsc::channel();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        let join = thread::spawn(move || {
            let clipboard = make_clipboard().ok();
            run_worker(app, clipboard, prompter, fact_overwrite, &req_rx, &resp_tx);
        });
        (
            Self {
                tx: req_tx,
                join: Some(join),
            },
            resp_rx,
        )
    }

    /// Send a request to the worker (best-effort; a dead worker drops it).
    pub fn send(&self, request: Request) {
        let _ = self.tx.send(request);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Tell the worker to stop, but do NOT join it. A worker stuck in a slow
        // or hung op (a multi-second Argon2 unlock, a wedged biometric prompt)
        // must not block the caller — usually the UI thread at shutdown. The
        // JoinHandle is simply dropped: the thread detaches and exits on the Quit
        // it just received (or when its current op finishes). It owns everything
        // it touches and vault writes are atomic (temp+rename), so nothing leaks
        // or corrupts. ponytail: detach over a timed join — std has no timed
        // join, and a Session's lifetime tracks the process, so there is nothing
        // left to reclaim.
        let _ = self.tx.send(Request::Quit);
        drop(self.join.take());
    }
}

/// Inner-loop control flow after handling one unlocked request.
enum Flow {
    /// Stay unlocked.
    Continue,
    /// Lock and return to the locked outer loop.
    Lock,
    /// Quit the worker entirely.
    Quit,
}

/// The worker entry point: the locked outer loop.
// The worker owns `app`/`clipboard`/`prompter` for the whole thread lifetime
// (they cannot be borrowed across the thread boundary), so by-value is required.
#[allow(clippy::needless_pass_by_value)]
fn run_worker<H, C>(
    app: App<H>,
    clipboard: Option<C>,
    prompter: Box<dyn BiometricPrompter>,
    fact_overwrite: bool,
    requests: &Receiver<Request>,
    responses: &Sender<Response>,
) where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    loop {
        match requests.recv() {
            Ok(Request::Create { master, kdf }) => {
                match app.create_vault(&master, kdf, TotpConfig::default(), &(), prompter.as_ref())
                {
                    Ok((mut unlocked, uri)) => {
                        let entries = unlocked.list_entries().unwrap_or_default();
                        let created = Response::Created {
                            provisioning_uri: uri,
                            entries,
                        };
                        if responses.send(created).is_err() {
                            return;
                        }
                        if drive_unlocked(
                            &mut unlocked,
                            clipboard.as_ref(),
                            fact_overwrite,
                            prompter.as_ref(),
                            requests,
                            responses,
                        ) {
                            return;
                        }
                    }
                    Err(e) => {
                        if responses
                            .send(Response::CreateFailed {
                                message: create_message(&e),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            Ok(Request::Unlock { master, code }) => {
                match app.unlock(&master, code.trim(), &(), prompter.as_ref()) {
                    Ok(mut unlocked) => {
                        let entries = unlocked.list_entries().unwrap_or_default();
                        if responses.send(Response::Unlocked { entries }).is_err() {
                            return;
                        }
                        if drive_unlocked(
                            &mut unlocked,
                            clipboard.as_ref(),
                            fact_overwrite,
                            prompter.as_ref(),
                            requests,
                            responses,
                        ) {
                            return;
                        }
                    }
                    Err(e) => {
                        if responses
                            .send(Response::UnlockFailed {
                                message: unlock_message(&e),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            Ok(Request::Quit) | Err(_) => return,
            // ClearClipboard is fire-and-forget — no caller awaits a response,
            // so drop it silently. Sending a response here would desync the next
            // request→response caller's recv(). (Actually wiping the clipboard
            // after a lock is a separate, low-severity improvement.)
            Ok(Request::ClearClipboard { .. }) => {}
            // Every other request needs an unlocked session and arrived via a
            // synchronous request→response caller (e.g. the UniFFI `call()`).
            // Reply `Locked` so it receives its one response instead of blocking
            // forever on recv() — the deadlock that froze the app once a lazy
            // 120 s expiry (or an explicit lock) returned the worker to this loop.
            Ok(_) => {
                let _ = responses.send(Response::Locked);
            }
        }
    }
}

/// Run the unlocked inner loop for an already-unlocked session and handle the
/// resulting [`Flow`]. Returns `true` if the worker should quit entirely.
fn drive_unlocked<H, C>(
    unlocked: &mut UnlockedApp<H>,
    clipboard: Option<&C>,
    fact_overwrite: bool,
    prompter: &dyn BiometricPrompter,
    requests: &Receiver<Request>,
    responses: &Sender<Response>,
) -> bool
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    match unlocked_loop(
        unlocked,
        clipboard,
        fact_overwrite,
        prompter,
        requests,
        responses,
    ) {
        Flow::Quit => true,
        // Lock / Continue return to the locked loop; `unlocked` drops at the call
        // site, zeroizing K_master.
        Flow::Lock | Flow::Continue => {
            let _ = responses.send(Response::Locked);
            false
        }
    }
}

/// A user-facing message for a vault-creation failure.
fn create_message(e: &CoreError) -> String {
    match e {
        CoreError::AlreadyRunning => "Another passman instance is using this vault.".to_owned(),
        CoreError::SoftwareHsmRefused => {
            "This device has no acceptable hardware key store.".to_owned()
        }
        _ => "The vault could not be created.".to_owned(),
    }
}

/// The unlocked inner loop. Returns when the session locks or the worker quits.
fn unlocked_loop<H, C>(
    unlocked: &mut UnlockedApp<H>,
    clipboard: Option<&C>,
    fact_overwrite: bool,
    prompter: &dyn BiometricPrompter,
    requests: &Receiver<Request>,
    responses: &Sender<Response>,
) -> Flow
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    // The cookie of the secret most recently copied to the clipboard, if it is
    // still believed live (a later ClearClipboard that wiped it forgets it). On
    // the lock transition we proactively wipe it: the post-lock ClearClipboard
    // the GTK shell schedules 30 s after a copy is DROPPED by the locked outer
    // loop (it is fire-and-forget), so if the session locks first — an explicit
    // Lock or the §5.2 idle auto-lock below — the secret would otherwise sit on
    // the OS clipboard indefinitely for a scraper to read (pentest S4).
    let mut live_cookie: Option<ClipboardCookie> = None;
    loop {
        match requests.recv_timeout(EXPIRY_POLL) {
            Ok(request) => {
                let flow = handle_unlocked(
                    unlocked,
                    clipboard,
                    fact_overwrite,
                    prompter,
                    request,
                    responses,
                    &mut live_cookie,
                );
                match flow {
                    Flow::Continue => {}
                    Flow::Lock => {
                        wipe_clipboard_on_exit(
                            unlocked,
                            clipboard,
                            fact_overwrite,
                            live_cookie.as_ref(),
                        );
                        return Flow::Lock;
                    }
                    // An explicit Request::Quit while unlocked: wipe a still-live
                    // clipboard secret before the UnlockedApp drops, exactly as the
                    // Lock path does — otherwise the shell's pending ClearClipboard
                    // never runs and the copied password is stranded (pentest S4).
                    Flow::Quit => {
                        wipe_clipboard_on_exit(
                            unlocked,
                            clipboard,
                            fact_overwrite,
                            live_cookie.as_ref(),
                        );
                        return Flow::Quit;
                    }
                }
            }
            // Idle tick: enforce the §5.2 hard timeout even with no request, so
            // an unlocked session can't sit resident in memory indefinitely.
            Err(RecvTimeoutError::Timeout) => {
                if unlocked.is_expired() {
                    wipe_clipboard_on_exit(
                        unlocked,
                        clipboard,
                        fact_overwrite,
                        live_cookie.as_ref(),
                    );
                    return Flow::Lock;
                }
            }
            // The request channel closed (the Session was dropped → Quit). Wipe a
            // still-live clipboard secret before the UnlockedApp drops, exactly as
            // the Lock path does (pentest S4, Quit-via-disconnect variant).
            Err(RecvTimeoutError::Disconnected) => {
                wipe_clipboard_on_exit(unlocked, clipboard, fact_overwrite, live_cookie.as_ref());
                return Flow::Quit;
            }
        }
    }
}

/// On a lock OR quit transition, proactively wipe a still-live clipboard secret
/// while we still hold the (about-to-be-dropped) `UnlockedApp`.
/// `clear_clipboard_with` is explicitly designed to run post-expiry, so calling
/// it here (where the session has just expired, been locked, or is quitting) is
/// sound. No response is sent: this is the worker's own cleanup, not a reply to
/// any request.
fn wipe_clipboard_on_exit<H, C>(
    unlocked: &UnlockedApp<H>,
    clipboard: Option<&C>,
    fact_overwrite: bool,
    live_cookie: Option<&ClipboardCookie>,
) where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    if let (Some(cookie), Some(clip)) = (live_cookie, clipboard) {
        // ClearOutcome is #[must_use]; the result is advisory (the cookie may be
        // stale or the clipboard now holds a foreign value) and there is no
        // caller to surface it to on the lock path.
        let _ = unlocked.clear_clipboard_with(cookie, clip, fact_overwrite);
    }
}

/// Handle one unlocked request, sending any response. `CoreError::Locked` from
/// an op means the 120 s session expired → lock.
fn handle_unlocked<H, C>(
    unlocked: &mut UnlockedApp<H>,
    clipboard: Option<&C>,
    fact_overwrite: bool,
    prompter: &dyn BiometricPrompter,
    request: Request,
    responses: &Sender<Response>,
    live_cookie: &mut Option<ClipboardCookie>,
) -> Flow
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    match request {
        Request::Lock => return Flow::Lock,
        Request::Quit => return Flow::Quit,
        // Already unlocked; ignore a stray create/unlock.
        Request::Create { .. } | Request::Unlock { .. } => {}
        Request::Refresh => match unlocked.list_entries() {
            Ok(entries) => send_or_lock(responses, Response::Entries { entries }),
            Err(e) => return on_op_error(&e, responses),
        },
        Request::Reveal { id, field } => {
            match unlocked.with_revealed(&id, |record| select_field(record, field)) {
                Ok(value) => send_or_lock(responses, Response::Revealed { field, value }),
                Err(e) => return on_op_error(&e, responses),
            }
        }
        Request::Copy { id, field } => match clipboard {
            Some(clip) => match unlocked.copy_to_clipboard(&id, field, clip) {
                Ok(cookie) => {
                    // Remember the live cookie so the lock transition can wipe it
                    // if the session locks before the shell's clear timer fires.
                    // ClipboardCookie is Copy, so this records a copy, not a move.
                    *live_cookie = Some(cookie);
                    send_or_lock(responses, Response::Copied { cookie });
                }
                Err(e) => return on_op_error(&e, responses),
            },
            None => send_or_lock(
                responses,
                Response::Error {
                    message: "the clipboard is unavailable".to_owned(),
                },
            ),
        },
        Request::ClearClipboard { cookie } => {
            if let Some(clip) = clipboard {
                let _ = unlocked.clear_clipboard_with(&cookie, clip, fact_overwrite);
            }
            // The shell's clear timer fired in time: forget the cookie so we don't
            // redundantly re-wipe on a later lock (and a foreign clipboard value
            // is left untouched).
            *live_cookie = None;
        }
        Request::Generate { length } => {
            let req = GenerationRequest::new(
                length,
                Charset::default_vault(),
                RequiredClasses::one_of_each(),
            );
            match unlocked.generate_password(&req) {
                Ok(password) => send_or_lock(responses, Response::Generated { password }),
                Err(e) => return on_op_error(&e, responses),
            }
        }
        Request::Add {
            label,
            username,
            password,
            url,
            notes,
        } => {
            let record = EntryRecord::new(username, password, url, notes);
            let policy = EntryPolicy::default();
            match unlocked.add_entry(label, policy, &record) {
                Ok(_) => match unlocked.list_entries() {
                    Ok(entries) => send_or_lock(responses, Response::Entries { entries }),
                    Err(e) => return on_op_error(&e, responses),
                },
                Err(e) => return on_op_error(&e, responses),
            }
        }
        Request::Remove { id } => match unlocked.remove_entry(&id) {
            Ok(()) => match unlocked.list_entries() {
                Ok(entries) => send_or_lock(responses, Response::Entries { entries }),
                Err(e) => return on_op_error(&e, responses),
            },
            Err(e) => return on_op_error(&e, responses),
        },
        Request::ExportRecovery {
            master,
            code,
            preset,
        } => match unlocked.export_recovery(&master, code.trim(), preset, &(), prompter) {
            Ok(file) => send_or_lock(responses, Response::RecoveryExported { file }),
            // A locked session locks the worker, exactly like every other op
            // (see `on_op_error`); any other failure surfaces as an
            // export-specific message via the same no-secret mapping.
            Err(CoreError::Locked) => return Flow::Lock,
            Err(e) => send_or_lock(
                responses,
                Response::RecoveryExportFailed {
                    message: operation_message(&e),
                },
            ),
        },
        Request::VerifyTotp { code } => {
            let valid = unlocked.verify_totp_code(code.trim());
            send_or_lock(responses, Response::TotpChecked { valid });
        }
    }
    Flow::Continue
}

/// Map an operation error: a locked session triggers `Flow::Lock`; anything else
/// is surfaced as a non-fatal `Error`.
fn on_op_error(e: &CoreError, responses: &Sender<Response>) -> Flow {
    if matches!(e, CoreError::Locked) {
        Flow::Lock
    } else {
        let _ = responses.send(Response::Error {
            message: operation_message(e),
        });
        Flow::Continue
    }
}

/// Send a response, downgrading a dead-channel error to a no-op (the worker will
/// exit on the next `recv`).
fn send_or_lock(responses: &Sender<Response>, response: Response) {
    let _ = responses.send(response);
}

/// Clone one field of a decrypted record into a fresh zeroizing `SecretString`.
fn select_field(record: &EntryRecord, field: RevealField) -> SecretString {
    let value = match field {
        RevealField::Username => &record.username,
        RevealField::Password => &record.password,
        RevealField::Url => &record.url,
        RevealField::Notes => &record.notes,
    };
    SecretString::new(value.expose().to_owned())
}

/// A user-facing message for an unlock failure.
fn unlock_message(e: &UnlockError) -> String {
    match e {
        UnlockError::BadCredentials => "Incorrect master password or TOTP code.".to_owned(),
        UnlockError::LockedOut { remaining } => {
            format!(
                "Locked out; try again in about {} s.",
                remaining.as_secs().max(1)
            )
        }
        UnlockError::Cancelled => "Unlock cancelled.".to_owned(),
        UnlockError::Retryable => "Transient hardware error; please retry.".to_owned(),
        UnlockError::RouteToRecovery => {
            "The hardware key is unavailable; recover from a backup.".to_owned()
        }
        UnlockError::SoftwareHsmRefused => {
            "This vault uses a software backend (run with --allow-software-hsm).".to_owned()
        }
        _ => "The vault could not be unlocked.".to_owned(),
    }
}

/// A user-facing message for an unlocked-operation failure.
fn operation_message(e: &CoreError) -> String {
    match e {
        CoreError::Vault(passman_vault::VaultError::EntryNotFound) => {
            "That entry no longer exists.".to_owned()
        }
        CoreError::WeakPasswordForExport => {
            "The master password is too weak for a recovery export.".to_owned()
        }
        _ => "The operation failed.".to_owned(),
    }
}
