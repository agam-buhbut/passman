//! `passman-core` — headless orchestration of the password manager.
//!
//! Ties the foundation crates together: the vault-creation and unlock pipelines
//! (`architecture.md` §4.3), the session lifecycle and `SessionToken` (§5.1),
//! atomic vault file I/O plus the single-instance lock, the clipboard flow with
//! clear-by-overwrite (§5.3), the on-demand reveal path (§5.4), the advisory
//! lockout UX layered on the HSM's native protection (§4.9), and the recovery
//! export/import orchestration (§7). It owns no rendering and runs no event
//! loop; blocking operations (Argon2id, HSM unwrap) are called synchronously
//! and the shell is expected to invoke them off its UI thread.
//!
//! # Public surface
//!
//! - [`App`] — the locked handle: [`App::open`] (acquires the single-instance
//!   lock), [`App::create_vault`], [`App::unlock`], [`App::import_recovery`].
//! - [`UnlockedApp`] — the session: [`UnlockedApp::list_entries`],
//!   [`UnlockedApp::with_revealed`], [`UnlockedApp::copy_to_clipboard`] /
//!   [`UnlockedApp::clear_clipboard`], entry mutation,
//!   [`UnlockedApp::generate_password`], [`UnlockedApp::change_master_password`],
//!   and [`UnlockedApp::export_recovery`].
//! - [`Clipboard`] / [`ClipboardCookie`] / [`ClearOutcome`] / [`FACTS`] — the
//!   clipboard contract (§5.3).
//! - [`Progress`] / [`NoProgress`] — the long-operation progress contract
//!   (§2.5), injected via [`App::with_progress`].
//! - [`SessionToken`], [`EntryHandle`], [`RevealField`], [`ProvisioningUri`].
//! - [`CoreError`] / [`UnlockError`] — the error taxonomy.
//!
//! The time source is the `passman-totp` [`Clock`](passman_totp::Clock); core
//! defines no clock of its own (`architecture.md` §2.5 refinement).
#![forbid(unsafe_code)]

mod app;
mod clipboard;
mod error;
mod lockout;
mod progress;
mod provisioning;
mod session;
mod storage;
mod unlocked;
pub mod worker;

pub use app::{App, ProvisioningUri};
pub use clipboard::{ClearOutcome, Clipboard, ClipboardCookie, FACTS};
pub use error::{CoreError, UnlockError};
pub use lockout::{lockout_minutes, LockoutState};
pub use progress::{NoProgress, Progress, ProgressError};
pub use session::SessionToken;
pub use storage::{atomic_write, read, InstanceLock};
pub use unlocked::{EntryHandle, PasswordChangeOutcome, RevealField, UnlockedApp};
pub use worker::{Request, Response, Session};
