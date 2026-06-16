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

use std::sync::mpsc::{Receiver, Sender};
use std::thread::{self, JoinHandle};

use crate::{
    App, Clipboard, ClipboardCookie, CoreError, EntryHandle, RevealField, UnlockError, UnlockedApp,
};
use passman_crypto::SecretString;
use passman_hsm::{BiometricPrompter, HardwareKeyStore};
use passman_policy::{Charset, EntryPolicy, GenerationRequest, RequiredClasses};
use passman_vault::{EntryId, EntryRecord};

/// A message from the UI to the session worker.
pub enum Request {
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
    /// Lock the session (drop the keys); the UI returns to the unlock screen.
    Lock,
    /// Stop the worker and exit the thread.
    Quit,
}

/// A message from the session worker back to the UI.
#[derive(Debug)]
pub enum Response {
    /// Unlock succeeded; carries the current entry list.
    Unlocked { entries: Vec<EntryHandle> },
    /// Unlock failed; carries a user-facing message.
    UnlockFailed { message: String },
    /// The current entry list (after `Refresh` / a mutation).
    Entries { entries: Vec<EntryHandle> },
    /// A revealed field value (the UI shows it, then it is dropped/zeroized).
    Revealed { field: RevealField, value: SecretString },
    /// A field was copied; the cookie lets the UI schedule the clear.
    Copied { cookie: ClipboardCookie },
    /// A generated password (for the add form).
    Generated { password: SecretString },
    /// The session locked (timeout, explicit lock, or an op found it expired).
    Locked,
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
        let _ = self.tx.send(Request::Quit);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
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
            Ok(Request::Unlock { master, code }) => {
                match app.unlock(&master, code.trim(), &(), prompter.as_ref()) {
                    Ok(mut unlocked) => {
                        let entries = unlocked.list_entries().unwrap_or_default();
                        if responses.send(Response::Unlocked { entries }).is_err() {
                            return;
                        }
                        // Unlocked inner loop: `unlocked` borrows `app` and lives
                        // only on this stack frame.
                        match unlocked_loop(
                            &mut unlocked,
                            clipboard.as_ref(),
                            fact_overwrite,
                            requests,
                            responses,
                        ) {
                            Flow::Quit => return,
                            // Lock / Continue both return to the locked loop; the
                            // unlocked session drops here, zeroizing K_master.
                            Flow::Lock | Flow::Continue => {
                                let _ = responses.send(Response::Locked);
                            }
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
            // Any other request while locked is ignored (the UI only sends them
            // while it believes the session is unlocked).
            Ok(_) => {}
        }
    }
}

/// The unlocked inner loop. Returns when the session locks or the worker quits.
fn unlocked_loop<H, C>(
    unlocked: &mut UnlockedApp<H>,
    clipboard: Option<&C>,
    fact_overwrite: bool,
    requests: &Receiver<Request>,
    responses: &Sender<Response>,
) -> Flow
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    loop {
        let Ok(request) = requests.recv() else {
            return Flow::Quit;
        };
        let flow = handle_unlocked(unlocked, clipboard, fact_overwrite, request, responses);
        match flow {
            Flow::Continue => {}
            other => return other,
        }
    }
}

/// Handle one unlocked request, sending any response. `CoreError::Locked` from
/// an op means the 120 s session expired → lock.
fn handle_unlocked<H, C>(
    unlocked: &mut UnlockedApp<H>,
    clipboard: Option<&C>,
    fact_overwrite: bool,
    request: Request,
    responses: &Sender<Response>,
) -> Flow
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    C: Clipboard,
{
    match request {
        Request::Lock => return Flow::Lock,
        Request::Quit => return Flow::Quit,
        // Already unlocked; ignore a stray unlock.
        Request::Unlock { .. } => {}
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
                Ok(cookie) => send_or_lock(responses, Response::Copied { cookie }),
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
        }
        Request::Generate { length } => {
            let req = GenerationRequest::new(length, Charset::default_vault(), RequiredClasses::one_of_each());
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
            format!("Locked out; try again in about {} s.", remaining.as_secs().max(1))
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
