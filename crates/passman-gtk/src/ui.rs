//! The GTK4 user interface: a three-page stack (unlock / vault / add) wired to
//! the [`crate::session`] worker over channels.
//!
//! All blocking work happens on the worker; the UI polls the response channel on
//! the GTK main loop (every 50 ms) and only ever touches widgets here.

use std::cell::{Cell, RefCell};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

use gtk::prelude::*;
use gtk::{gio, glib, Align, Application, ApplicationWindow, Orientation};
use gtk4 as gtk;

use passman_core::{App, EntryHandle, RecoveryPreset, RevealField};
use passman_crypto::{KdfParams, SecretString};
use passman_hsm::linux::{select_linux_backend, LinuxKeyStore};
use passman_platform::{Paths, Settings};
use passman_policy::{
    estimate_master, generate, Charset, GenerationRequest, RequiredClasses, StrengthTier,
    DEFAULT_LENGTH,
};
use passman_totp::{Clock, SystemClock};
use passman_vault::EntryId;

use crate::clipboard::SystemClipboard;
use passman_core::{Request, Response, Session};

/// GTK application id.
const APP_ID: &str = "org.passman.Gtk";
/// Obscured placeholder shown for a hidden secret (§5.4).
const OBSCURED: &str = "••••••••••";
/// Seconds a revealed secret stays visible before auto-hiding (§5.4).
const REVEAL_HIDE_SECS: u32 = 10;
/// Seconds a copied secret stays on the clipboard before the clear fires (§5.3).
const CLIPBOARD_CLEAR_SECS: u32 = 30;

/// Parsed command-line options (a tiny manual parse so GTK does not see them).
#[derive(Debug, PartialEq, Eq)]
struct Opts {
    allow_software: bool,
    vault_dir: Option<PathBuf>,
}

/// Parse our options from an argument iterator (the program name already
/// stripped). Pure, so it can be unit-tested without touching the environment.
///
/// # Errors
///
/// Returns an error if `--vault-dir` is given without a following path value.
/// An unrecognized argument is warned about on stderr and otherwise ignored.
fn parse_opts<I>(mut args: I) -> anyhow::Result<Opts>
where
    I: Iterator<Item = String>,
{
    let mut opts = Opts {
        allow_software: false,
        vault_dir: None,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-software-hsm" => opts.allow_software = true,
            "--vault-dir" => {
                let dir = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--vault-dir requires a directory path"))?;
                opts.vault_dir = Some(PathBuf::from(dir));
            }
            other => eprintln!("warning: ignoring unrecognized argument '{other}'"),
        }
    }
    Ok(opts)
}

fn parse_args() -> anyhow::Result<Opts> {
    parse_opts(std::env::args().skip(1))
}

fn resolve_paths(opts: &Opts) -> anyhow::Result<Paths> {
    match &opts.vault_dir {
        Some(dir) => Ok(Paths::under_base(dir)),
        None => Paths::discover().map_err(|e| anyhow::anyhow!("{e}")),
    }
}

/// Build the core, spawn the session worker, and run the GTK application.
///
/// # Errors
///
/// Returns an error before GTK starts if paths, settings, the backend, or the
/// single-instance lock cannot be set up.
pub fn run() -> anyhow::Result<ExitCode> {
    let opts = parse_args()?;
    let paths = resolve_paths(&opts)?;
    let settings = Settings::load(paths.settings())?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // Share the session clock with the clipboard so cookie timestamps and the
    // rest of the app read from one time source (finding S-info / §10).
    let clip_clock = Arc::clone(&clock);

    let backend = select_linux_backend(opts.allow_software).map_err(|e| match e {
        passman_hsm::HsmError::HardwareAbsent => anyhow::anyhow!(
            "no TPM 2.0 found. Pass --allow-software-hsm to use the OS keyring (weaker)."
        ),
        other => anyhow::Error::new(other).context("could not select an HSM backend"),
    })?;

    let app_core: App<LinuxKeyStore> = if opts.allow_software {
        App::open_allowing_software_hsm(paths.vault(), backend, clock)
    } else {
        App::open(paths.vault(), backend, clock)
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let vault_path = paths.vault().to_path_buf();
    let fact_overwrite = settings.clipboard_fact_overwrite;
    let (session, responses) = Session::spawn(
        app_core,
        move || Ok(SystemClipboard::new(clip_clock)),
        Box::new(crate::DesktopPrompter),
        fact_overwrite,
    );

    let application = Application::builder().application_id(APP_ID).build();
    // The session + receiver are consumed on first activation.
    let startup = Rc::new(RefCell::new(Some((session, responses, vault_path))));
    application.connect_activate(move |app| {
        if let Some((session, responses, vault_path)) = startup.borrow_mut().take() {
            build_ui(app, session, responses, vault_path);
        }
    });

    // Pass no args to GTK (we parsed our own above).
    let code = application.run_with_args::<&str>(&[]);
    Ok(if code == glib::ExitCode::SUCCESS {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Show a minimal GTK error window when startup fails (finding UX-low / §5 item 5).
///
/// This is called from `main.rs` when `run()` returns an `Err` so the user gets
/// a visible dialog instead of only a silent stderr print (e.g. when launched
/// from a desktop shortcut with no terminal).
pub fn show_startup_error(message: &str) {
    // We need a bare GTK app to own the window; no application-id so it does
    // not conflict with the real one on a re-launch.
    let app = Application::builder().build();
    let msg = message.to_owned();
    app.connect_activate(move |app| {
        let label = gtk::Label::builder()
            .label(&msg)
            .wrap(true)
            .selectable(true)
            .margin_top(16)
            .margin_bottom(8)
            .margin_start(16)
            .margin_end(16)
            .build();
        let hint = gtk::Label::builder()
            .label("Hint: if no TPM was found, relaunch with --allow-software-hsm")
            .wrap(true)
            .margin_bottom(16)
            .margin_start(16)
            .margin_end(16)
            .build();
        hint.add_css_class("dim-label");
        let ok_btn = gtk::Button::with_label("Close");
        ok_btn.set_margin_bottom(16);
        ok_btn.set_margin_start(16);
        ok_btn.set_margin_end(16);
        let vbox = gtk::Box::new(Orientation::Vertical, 0);
        vbox.append(&label);
        vbox.append(&hint);
        vbox.append(&ok_btn);
        let window = ApplicationWindow::builder()
            .application(app)
            .title("passman — startup error")
            .default_width(400)
            .default_height(180)
            .child(&vbox)
            .build();
        let win_close = window.clone();
        ok_btn.connect_clicked(move |_| win_close.close());
        window.present();
    });
    app.run_with_args::<&str>(&[]);
}

/// A pending mutation whose label we want to surface as a success confirmation.
///
/// After the user triggers Add or Remove we store the relevant label here so
/// that when `Response::Entries` arrives we can display e.g. `Added "foo"`.
#[derive(Debug, Clone)]
enum PendingMutation {
    Add(String),
    Remove(String),
}

/// The live widget set + worker handle, shared into the GTK closures via `Rc`.
struct Ui {
    stack: gtk::Stack,
    master: gtk::PasswordEntry,
    /// Second password entry for the create-vault confirm step (finding UX-medium / §5 item 3).
    create_confirm: gtk::PasswordEntry,
    /// Non-blocking strength warning shown during create (finding UX-medium / §5 item 3).
    create_strength: gtk::Label,
    totp: gtk::Entry,
    unlock_btn: gtk::Button,
    create_btn: gtk::Button,
    unlock_hint: gtk::Label,
    unlock_spinner: gtk::Spinner,
    unlock_error: gtk::Label,
    list: gtk::ListBox,
    status: gtk::Label,
    reveal: gtk::Label,
    add_label: gtk::Entry,
    add_user: gtk::Entry,
    add_pass: gtk::PasswordEntry,
    add_url: gtk::Entry,
    add_notes: gtk::Entry,
    /// The top-level window — transient parent for the export modal and the
    /// save `FileDialog` (B7).
    window: ApplicationWindow,
    /// Post-creation onboarding nudge: prompts the user to make a recovery
    /// backup now (B7). Shown by the `Created` handler, hidden otherwise.
    backup_banner: gtk::Label,
    /// Post-creation authenticator-confirm group: a fresh-TOTP entry, a confirm
    /// button, a dismiss button and a result label (B8). Shown by `Created`.
    confirm_box: gtk::Box,
    /// Fresh-TOTP entry inside [`Self::confirm_box`] (B8).
    confirm_totp: gtk::Entry,
    /// Result line for the authenticator-confirm step (B8).
    confirm_result: gtk::Label,
    session: Session,
    vault_path: PathBuf,
    entries: RefCell<Vec<EntryHandle>>,
    selected: RefCell<Option<usize>>,
    /// Set just before sending `Request::Lock`; cleared when the `Locked`
    /// response is consumed.  Distinguishes a user-initiated lock from an
    /// idle auto-lock so we can show a helpful message (finding UX-high / §5 item 2).
    user_initiated_lock: Cell<bool>,
    /// Label stored at the moment the user clicks Add or Remove, consumed when
    /// the next `Response::Entries` arrives (finding UX-medium / §5 item 6).
    pending_mutation: RefCell<Option<PendingMutation>>,
    /// Vault row-action buttons (Reveal / Copy×2 / Remove). Kept insensitive
    /// until a row is selected so they cannot silently no-op
    /// (finding UX-low / §5 item 6).
    action_buttons: Vec<gtk::Button>,
}

impl Ui {
    /// Enable or disable all row-action buttons together.
    fn set_actions_enabled(&self, enabled: bool) {
        for button in &self.action_buttons {
            button.set_sensitive(enabled);
        }
    }

    /// The id of the currently-selected entry, if any.
    fn selected_id(&self) -> Option<EntryId> {
        let idx = (*self.selected.borrow())?;
        self.entries.borrow().get(idx).map(|h| h.id)
    }

    /// The label of the currently-selected entry, if any.
    fn selected_label(&self) -> Option<String> {
        let idx = (*self.selected.borrow())?;
        self.entries.borrow().get(idx).map(|h| h.label.clone())
    }

    /// Show the unlock controls when a vault exists, else the create controls.
    fn refresh_gate(&self) {
        let exists = self.vault_path.exists();
        self.totp.set_visible(exists);
        self.unlock_btn.set_visible(exists);
        self.create_btn.set_visible(!exists);
        self.create_confirm.set_visible(!exists);
        self.create_strength.set_visible(!exists);
        self.unlock_hint.set_text(if exists {
            "Unlock your vault."
        } else {
            "Welcome — choose a master password to create your vault."
        });
        self.master.set_text("");
        self.create_confirm.set_text("");
        self.create_strength.set_text("");
        self.totp.set_text("");
        self.unlock_error.set_text("");
    }

    /// Rebuild the entry list box from `entries`.
    fn set_entries(&self, entries: Vec<EntryHandle>) {
        while let Some(child) = self.list.first_child() {
            self.list.remove(&child);
        }
        for handle in &entries {
            let row = gtk::Label::builder()
                .label(&handle.label)
                .halign(Align::Start)
                .margin_top(6)
                .margin_bottom(6)
                .margin_start(8)
                .build();
            self.list.append(&row);
        }
        *self.entries.borrow_mut() = entries;
        *self.selected.borrow_mut() = None;
        self.reveal.set_text(OBSCURED);
        // Selection was just cleared; row actions have nothing to act on
        // (finding UX-low / §5 item 6).
        self.set_actions_enabled(false);
    }
}

/// Return a human-readable tier label for a password strength tier.
///
/// Used on the create page to give non-blocking feedback (finding UX-medium / §5 item 3).
fn tier_label(tier: StrengthTier) -> &'static str {
    match tier {
        StrengthTier::Dangerous => "Strength: Dangerous — choose a longer passphrase",
        StrengthTier::Weak => "Strength: Weak — consider a longer passphrase",
        StrengthTier::Acceptable => "Strength: Acceptable",
        StrengthTier::Strong => "Strength: Strong",
        StrengthTier::Excellent => "Strength: Excellent",
    }
}

/// Whether the tier warrants a visible warning (below Strong).
fn tier_needs_warning(tier: StrengthTier) -> bool {
    !matches!(tier, StrengthTier::Strong | StrengthTier::Excellent)
}

/// Outcome of validating the create-vault form's two password fields.
#[derive(Debug, PartialEq, Eq)]
enum CreateForm {
    Ok,
    Empty,
    Mismatch,
}

/// Validate the create-vault password and its confirmation (finding UX-medium / §5 item 3).
///
/// Pure helper extracted so the branching can be unit-tested without GTK.
fn validate_create_form(master: &str, confirm: &str) -> CreateForm {
    if master.is_empty() {
        CreateForm::Empty
    } else if master != confirm {
        CreateForm::Mismatch
    } else {
        CreateForm::Ok
    }
}

/// Default filename suggested in the recovery-export save dialog (B7). The
/// `.pmrec` extension mirrors the CLI's recovery-file convention.
fn default_recovery_filename() -> &'static str {
    "passman-recovery.pmrec"
}

/// Map a recovery-preset dropdown index to a [`RecoveryPreset`] (B7).
///
/// The dropdown is built as `["Floor", "Default", "Paranoid"]`; any unexpected
/// index falls back to `Default` (the dropdown's own default selection).
fn preset_from_index(index: u32) -> RecoveryPreset {
    match index {
        0 => RecoveryPreset::Floor,
        2 => RecoveryPreset::Paranoid,
        _ => RecoveryPreset::Default,
    }
}

/// Atomically create `path` as an owner-only (0600) file and write `bytes`,
/// flushing to disk (B7). `create_new` (`O_EXCL`) makes the create fail with
/// [`io::ErrorKind::AlreadyExists`] rather than clobbering an existing file —
/// closing the check-then-write TOCTOU — and the 0600 mode keeps the recovery
/// material unreadable by other users even under a permissive umask. This
/// mirrors the CLI's `write_new_file_0600`; it is reimplemented here so the GTK
/// shell does not depend on the CLI crate.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the file already exists, cannot be
/// created with the requested mode, or the write/flush fails.
#[cfg(unix)]
fn write_new_file_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Non-Unix fallback: still create-new (no clobber, no TOCTOU); the 0600 mode is
/// Unix-only, so the platform's default ACLs apply.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the file already exists or the
/// write/flush fails.
#[cfg(not(unix))]
fn write_new_file_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Build the window and all wiring.
#[allow(clippy::too_many_lines)] // cohesive widget construction; splitting hurts clarity
fn build_ui(
    app: &Application,
    session: Session,
    responses: Receiver<Response>,
    vault_path: PathBuf,
) {
    let vault_exists = vault_path.exists();
    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::SlideLeftRight);

    // --- Unlock page ---
    let master = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Master password")
        .build();
    // Accessible names so screen readers do not rely on placeholder text alone
    // (finding a11y-low / §5 item 7).
    master.update_property(&[gtk::accessible::Property::Label("Master password")]);
    // Second entry for confirm (only shown on create, hidden on unlock).
    let create_confirm = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Confirm master password")
        .visible(!vault_exists)
        .build();
    create_confirm.update_property(&[gtk::accessible::Property::Label("Confirm master password")]);
    // Non-blocking strength label (only shown on create).
    let create_strength = gtk::Label::builder()
        .label("")
        .wrap(true)
        .visible(!vault_exists)
        .build();
    let totp = gtk::Entry::builder()
        .placeholder_text("TOTP code")
        .max_length(8)
        .build();
    totp.update_property(&[gtk::accessible::Property::Label("TOTP code")]);
    let unlock_btn = gtk::Button::with_label("Unlock");
    unlock_btn.add_css_class("suggested-action");
    let create_btn = gtk::Button::with_label("Create vault");
    create_btn.add_css_class("suggested-action");
    let unlock_spinner = gtk::Spinner::new();
    // Built via the generic object builder so we can set the construct-only
    // `accessible-role`: an Alert (assertive live) region so a screen reader
    // announces unlock/create failures (finding a11y-low / §5 item 7).
    let unlock_error: gtk::Label = glib::Object::builder()
        .property("label", "")
        .property("wrap", true)
        .property("accessible-role", gtk::AccessibleRole::Alert.to_value())
        .build();
    unlock_error.add_css_class("error");
    let unlock_hint = gtk::Label::new(Some(if vault_exists {
        "Unlock your vault."
    } else {
        "Welcome — choose a master password to create your vault."
    }));
    // Show create-vs-unlock controls depending on whether a vault exists.
    totp.set_visible(vault_exists);
    unlock_btn.set_visible(vault_exists);
    create_btn.set_visible(!vault_exists);

    let unlock_box = gtk::Box::new(Orientation::Vertical, 10);
    unlock_box.set_margin_top(24);
    unlock_box.set_margin_bottom(24);
    unlock_box.set_margin_start(24);
    unlock_box.set_margin_end(24);
    unlock_box.set_valign(Align::Center);
    let title = gtk::Label::new(Some("passman"));
    title.add_css_class("title-1");
    unlock_box.append(&title);
    unlock_box.append(&unlock_hint);
    unlock_box.append(&master);
    unlock_box.append(&create_confirm);
    unlock_box.append(&create_strength);
    unlock_box.append(&totp);
    unlock_box.append(&unlock_btn);
    unlock_box.append(&create_btn);
    unlock_box.append(&unlock_spinner);
    unlock_box.append(&unlock_error);
    stack.add_named(&unlock_box, Some("unlock"));

    // --- Vault page ---
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    let scroller = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&list)
        .build();
    // SECURITY (accepted residual): GTK has no zeroizing label/entry, so a
    // revealed secret and the seed-bearing TOTP provisioning URI linger in this
    // GtkLabel's buffer until overwritten. We minimise dwell: the label is reset
    // to OBSCURED on row selection (wire_list_selection), on list rebuild
    // (set_entries), on navigation away from the vault page (add_btn), and via
    // the 10 s auto-hide timer (finding S-low / §5 item 8).
    let reveal = gtk::Label::builder()
        .label(OBSCURED)
        .selectable(true)
        .build();
    // Status (polite live) region so a screen reader announces success/error
    // text changes (finding a11y-low / §5 item 7).
    let status: gtk::Label = glib::Object::builder()
        .property("label", "")
        .property("wrap", true)
        .property("accessible-role", gtk::AccessibleRole::Status.to_value())
        .build();

    let reveal_btn = gtk::Button::with_label("Reveal");
    let copy_pw_btn = gtk::Button::with_label("Copy password");
    let copy_user_btn = gtk::Button::with_label("Copy username");
    let remove_btn = gtk::Button::with_label("Remove");
    let actions = gtk::Box::new(Orientation::Horizontal, 6);
    actions.append(&reveal_btn);
    actions.append(&copy_pw_btn);
    actions.append(&copy_user_btn);
    actions.append(&remove_btn);

    let add_btn = gtk::Button::with_label("Add entry");
    let export_btn = gtk::Button::with_label("Back up (recovery export)");
    let lock_btn = gtk::Button::with_label("Lock");
    let header = gtk::Box::new(Orientation::Horizontal, 6);
    header.append(&add_btn);
    header.append(&export_btn);
    let header_spacer = gtk::Box::new(Orientation::Horizontal, 0);
    header_spacer.set_hexpand(true);
    header.append(&header_spacer);
    header.append(&lock_btn);

    // Onboarding nudge shown right after vault creation (B7): without a backup a
    // lost device means a lost vault. Hidden until the `Created` handler shows it.
    let backup_banner = gtk::Label::builder()
        .label(
            "Back up your vault now — use \"Back up (recovery export)\" above. \
             Without an offline backup, a lost device means a lost vault.",
        )
        .wrap(true)
        .visible(false)
        .build();
    backup_banner.add_css_class("warning");

    // Post-creation authenticator-confirm step (B8): the user scans the URI shown
    // in `reveal`, then proves the authenticator works before relying on it.
    let confirm_label = gtk::Label::builder()
        .label("Confirm your authenticator — enter a code it shows now:")
        .wrap(true)
        .halign(Align::Start)
        .build();
    let confirm_totp = gtk::Entry::builder()
        .placeholder_text("TOTP code")
        .max_length(8)
        .build();
    confirm_totp.update_property(&[gtk::accessible::Property::Label("Confirm TOTP code")]);
    let confirm_totp_btn = gtk::Button::with_label("Confirm code");
    confirm_totp_btn.add_css_class("suggested-action");
    let dismiss_btn = gtk::Button::with_label("Dismiss");
    let confirm_actions = gtk::Box::new(Orientation::Horizontal, 6);
    confirm_actions.append(&confirm_totp_btn);
    confirm_actions.append(&dismiss_btn);
    // Status (polite live) region so the pass/fail line is announced (a11y).
    let confirm_result: gtk::Label = glib::Object::builder()
        .property("label", "")
        .property("wrap", true)
        .property("accessible-role", gtk::AccessibleRole::Status.to_value())
        .build();
    let confirm_box = gtk::Box::new(Orientation::Vertical, 6);
    confirm_box.set_visible(false);
    confirm_box.append(&confirm_label);
    confirm_box.append(&confirm_totp);
    confirm_box.append(&confirm_actions);
    confirm_box.append(&confirm_result);

    let vault_box = gtk::Box::new(Orientation::Vertical, 8);
    vault_box.set_margin_top(12);
    vault_box.set_margin_bottom(12);
    vault_box.set_margin_start(12);
    vault_box.set_margin_end(12);
    vault_box.append(&header);
    vault_box.append(&backup_banner);
    vault_box.append(&scroller);
    vault_box.append(&reveal);
    vault_box.append(&confirm_box);
    vault_box.append(&actions);
    vault_box.append(&status);
    stack.add_named(&vault_box, Some("vault"));

    // --- Add page ---
    let add_label = gtk::Entry::builder().placeholder_text("Label").build();
    add_label.update_property(&[gtk::accessible::Property::Label("Entry label")]);
    let add_user = gtk::Entry::builder().placeholder_text("Username").build();
    add_user.update_property(&[gtk::accessible::Property::Label("Username")]);
    let add_pass = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Password")
        .build();
    add_pass.update_property(&[gtk::accessible::Property::Label("Password")]);
    let gen_btn = gtk::Button::with_label("Generate");
    let add_url = gtk::Entry::builder()
        .placeholder_text("URL (optional)")
        .build();
    add_url.update_property(&[gtk::accessible::Property::Label("URL (optional)")]);
    let add_notes = gtk::Entry::builder()
        .placeholder_text("Notes (optional)")
        .build();
    add_notes.update_property(&[gtk::accessible::Property::Label("Notes (optional)")]);
    let save_btn = gtk::Button::with_label("Save");
    save_btn.add_css_class("suggested-action");
    let cancel_btn = gtk::Button::with_label("Cancel");

    let pass_row = gtk::Box::new(Orientation::Horizontal, 6);
    add_pass.set_hexpand(true);
    pass_row.append(&add_pass);
    pass_row.append(&gen_btn);
    let add_actions = gtk::Box::new(Orientation::Horizontal, 6);
    add_actions.append(&save_btn);
    add_actions.append(&cancel_btn);
    let add_box = gtk::Box::new(Orientation::Vertical, 10);
    add_box.set_margin_top(16);
    add_box.set_margin_bottom(16);
    add_box.set_margin_start(16);
    add_box.set_margin_end(16);
    add_box.append(&gtk::Label::new(Some("New entry")));
    add_box.append(&add_label);
    add_box.append(&add_user);
    add_box.append(&pass_row);
    add_box.append(&add_url);
    add_box.append(&add_notes);
    add_box.append(&add_actions);
    stack.add_named(&add_box, Some("add"));

    stack.set_visible_child_name("unlock");

    let window = ApplicationWindow::builder()
        .application(app)
        .title("passman")
        .default_width(440)
        .default_height(580)
        .child(&stack)
        .build();

    let ui = Rc::new(Ui {
        stack,
        master,
        create_confirm: create_confirm.clone(),
        create_strength: create_strength.clone(),
        totp,
        unlock_btn: unlock_btn.clone(),
        create_btn: create_btn.clone(),
        unlock_hint,
        unlock_spinner,
        unlock_error,
        list: list.clone(),
        status,
        reveal,
        add_label,
        add_user,
        add_pass,
        add_url,
        add_notes,
        window: window.clone(),
        backup_banner: backup_banner.clone(),
        confirm_box: confirm_box.clone(),
        confirm_totp: confirm_totp.clone(),
        confirm_result,
        session,
        vault_path,
        entries: RefCell::new(Vec::new()),
        selected: RefCell::new(None),
        user_initiated_lock: Cell::new(false),
        pending_mutation: RefCell::new(None),
        // gtk widget `.clone()` is a GObject ref-count bump, not a deep copy.
        action_buttons: vec![
            reveal_btn.clone(),
            copy_pw_btn.clone(),
            copy_user_btn.clone(),
            remove_btn.clone(),
        ],
    });

    wire_unlock(&ui, &unlock_btn);
    wire_create(&ui, &create_btn, &create_confirm);
    wire_list_selection(&ui, &list);
    wire_vault_actions(
        &ui,
        &reveal_btn,
        &copy_pw_btn,
        &copy_user_btn,
        &remove_btn,
        &lock_btn,
        &add_btn,
    );
    wire_add_page(&ui, &gen_btn, &save_btn, &cancel_btn);
    wire_recovery_export(&ui, &export_btn);
    wire_totp_confirm(&ui, &confirm_totp_btn, &dismiss_btn);
    wire_enter_submit(&ui);
    attach_response_poll(&ui, responses);

    // Row actions start disabled until a row is selected (finding UX-low / §5 item 6).
    ui.set_actions_enabled(false);

    window.present();
    // Focus the master entry so the user can start typing immediately
    // (finding UX-medium / §5 item 3).
    ui.master.grab_focus();
}

fn wire_unlock(ui: &Rc<Ui>, unlock_btn: &gtk::Button) {
    let ui = Rc::clone(ui);
    unlock_btn.connect_clicked(move |_| {
        let master = SecretString::new(ui.master.text().to_string());
        let code = ui.totp.text().to_string();
        ui.unlock_error.set_text("");
        ui.unlock_spinner.set_spinning(true);
        ui.unlock_btn.set_sensitive(false);
        ui.session.send(Request::Unlock { master, code });
    });
}

fn wire_create(ui: &Rc<Ui>, create_btn: &gtk::Button, create_confirm: &gtk::PasswordEntry) {
    // Live strength estimate as the user types (non-blocking, finding UX-medium / §5 item 3).
    {
        let ui_strength = Rc::clone(ui);
        // Clone the widget handle out of Ui so we can borrow it for
        // `connect_changed` without also moving `ui_strength` for the method
        // call — the closure captures `ui_strength` by move.
        let master_widget = ui.master.clone();
        master_widget.connect_changed(move |entry| {
            let text = entry.text();
            if text.is_empty() {
                ui_strength.create_strength.set_text("");
                return;
            }
            // Only show strength feedback when we are on the create page
            // (create_strength is hidden during unlock).
            if !ui_strength.create_strength.is_visible() {
                return;
            }
            let est = estimate_master(text.as_str(), &[], &KdfParams::MEDIUM);
            ui_strength.create_strength.set_text(tier_label(est.tier));
            if tier_needs_warning(est.tier) {
                ui_strength.create_strength.add_css_class("warning");
            } else {
                ui_strength.create_strength.remove_css_class("warning");
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        let create_confirm = create_confirm.clone();
        create_btn.connect_clicked(move |_| {
            let master = SecretString::new(ui.master.text().to_string());
            let confirm = create_confirm.text();
            // Master must be non-empty and match its confirmation (finding UX-medium / §5 item 3).
            match validate_create_form(master.expose(), confirm.as_str()) {
                CreateForm::Empty => {
                    ui.unlock_error.set_text("Choose a master password first.");
                    return;
                }
                CreateForm::Mismatch => {
                    ui.unlock_error
                        .set_text("The passwords do not match — re-enter both.");
                    return;
                }
                CreateForm::Ok => {}
            }
            // Non-blocking weakness warning: warn but do not block creation
            // (mirrors CLI behaviour in commands.rs `warn_if_weak`).
            let est = estimate_master(master.expose(), &[], &KdfParams::MEDIUM);
            if tier_needs_warning(est.tier) {
                ui.create_strength.set_text(&format!(
                    "Warning: {} — vault will still be created.",
                    tier_label(est.tier)
                ));
                ui.create_strength.add_css_class("warning");
            }
            ui.unlock_error.set_text("");
            ui.unlock_spinner.set_spinning(true);
            ui.create_btn.set_sensitive(false);
            ui.session.send(Request::Create {
                master,
                kdf: KdfParams::MEDIUM,
            });
        });
    }
}

fn wire_list_selection(ui: &Rc<Ui>, list: &gtk::ListBox) {
    let ui = Rc::clone(ui);
    list.connect_row_selected(move |_, row| {
        *ui.selected.borrow_mut() = row.map(|r| usize::try_from(r.index()).unwrap_or(0));
        // Row actions are usable only with a selection (finding UX-low / §5 item 6).
        ui.set_actions_enabled(row.is_some());
        ui.reveal.set_text(OBSCURED);
        ui.status.set_text("");
    });
}

fn wire_vault_actions(
    ui: &Rc<Ui>,
    reveal_btn: &gtk::Button,
    copy_pw_btn: &gtk::Button,
    copy_user_btn: &gtk::Button,
    remove_btn: &gtk::Button,
    lock_btn: &gtk::Button,
    add_btn: &gtk::Button,
) {
    {
        let ui = Rc::clone(ui);
        reveal_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                ui.session.send(Request::Reveal {
                    id,
                    field: RevealField::Password,
                });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        copy_pw_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                ui.session.send(Request::Copy {
                    id,
                    field: RevealField::Password,
                });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        copy_user_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                ui.session.send(Request::Copy {
                    id,
                    field: RevealField::Username,
                });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        remove_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                // Record the label before the remove for the success confirmation
                // (finding UX-medium / §5 item 6).
                if let Some(label) = ui.selected_label() {
                    *ui.pending_mutation.borrow_mut() = Some(PendingMutation::Remove(label));
                }
                ui.session.send(Request::Remove { id });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        lock_btn.connect_clicked(move |_| {
            // Mark as user-initiated so `Response::Locked` can distinguish it
            // from an idle auto-lock (finding UX-high / §5 item 2).
            ui.user_initiated_lock.set(true);
            ui.session.send(Request::Lock);
        });
    }
    {
        let ui = Rc::clone(ui);
        add_btn.connect_clicked(move |_| {
            clear_add_form(&ui);
            // Clear any revealed secret before leaving the vault page so it does
            // not linger in the label behind another page (finding S-low / §5 item 8).
            ui.reveal.set_text(OBSCURED);
            ui.stack.set_visible_child_name("add");
        });
    }
}

fn wire_add_page(
    ui: &Rc<Ui>,
    gen_btn: &gtk::Button,
    save_btn: &gtk::Button,
    cancel_btn: &gtk::Button,
) {
    {
        let ui = Rc::clone(ui);
        gen_btn.connect_clicked(move |_| {
            // Use the shared DEFAULT_LENGTH constant so GTK and CLI generate
            // the same strength (finding UX-medium / §5 item 4).
            let req = GenerationRequest::new(
                DEFAULT_LENGTH,
                Charset::default_vault(),
                RequiredClasses::one_of_each(),
            );
            match generate(&req) {
                Ok(pw) => ui.add_pass.set_text(pw.expose()),
                // generate only errors on an impossible request (length below the
                // required-class minimums, or an empty charset); the fixed
                // default_vault/one_of_each request cannot hit that, but surface
                // the Err rather than swallow it.
                Err(e) => ui
                    .status
                    .set_text(&format!("Could not generate a password: {e}")),
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        save_btn.connect_clicked(move |_| {
            let label = ui.add_label.text().to_string();
            if label.trim().is_empty() {
                ui.status.set_text("A label is required.");
                ui.stack.set_visible_child_name("vault");
                return;
            }
            // Record the label for the success confirmation (finding UX-medium / §5 item 6).
            *ui.pending_mutation.borrow_mut() = Some(PendingMutation::Add(label.clone()));
            ui.session.send(Request::Add {
                label,
                username: SecretString::new(ui.add_user.text().to_string()),
                password: SecretString::new(ui.add_pass.text().to_string()),
                url: SecretString::new(ui.add_url.text().to_string()),
                notes: SecretString::new(ui.add_notes.text().to_string()),
            });
            // The plaintext is now copied into the SecretStrings above; wipe it
            // out of the GtkEntry/PasswordEntry buffers (finding S-medium / §5 item 1).
            clear_add_form(&ui);
            ui.stack.set_visible_child_name("vault");
        });
    }
    {
        let ui = Rc::clone(ui);
        cancel_btn.connect_clicked(move |_| {
            clear_add_form(&ui);
            ui.stack.set_visible_child_name("vault");
        });
    }
}

/// Wire the "Back up (recovery export)" button: it pops the modal export form
/// (B7).
fn wire_recovery_export(ui: &Rc<Ui>, export_btn: &gtk::Button) {
    let ui = Rc::clone(ui);
    export_btn.connect_clicked(move |_| open_export_dialog(&ui));
}

/// Build and present the modal recovery-export form (B7): master password, a
/// fresh TOTP code and a cost preset. On confirm the secrets are moved into a
/// [`SecretString`] / owned `String` immediately and the widget buffers are
/// wiped, so no plaintext lingers in the dialog after it closes.
fn open_export_dialog(ui: &Rc<Ui>) {
    let dialog = gtk::Window::builder()
        .title("Back up — recovery export")
        .modal(true)
        .transient_for(&ui.window)
        .default_width(380)
        .build();

    let intro = gtk::Label::builder()
        .label(
            "This writes a single-factor recovery backup of your vault. Store the \
             file offline (e.g. on a USB key in a safe) and never beside your vault.",
        )
        .wrap(true)
        .halign(Align::Start)
        .build();
    intro.add_css_class("dim-label");

    let master = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Master password")
        .build();
    master.update_property(&[gtk::accessible::Property::Label("Master password")]);
    let code = gtk::Entry::builder()
        .placeholder_text("Fresh TOTP code")
        .max_length(8)
        .build();
    code.update_property(&[gtk::accessible::Property::Label("Fresh TOTP code")]);

    let preset = gtk::DropDown::from_strings(&["Floor", "Default", "Paranoid"]);
    preset.set_selected(1); // Default — matches preset_from_index's fallback.
    let preset_row = gtk::Box::new(Orientation::Horizontal, 6);
    preset_row.append(&gtk::Label::new(Some("Strength:")));
    preset_row.append(&preset);

    let confirm = gtk::Button::with_label("Export backup");
    confirm.add_css_class("suggested-action");
    let cancel = gtk::Button::with_label("Cancel");
    let actions = gtk::Box::new(Orientation::Horizontal, 6);
    actions.set_halign(Align::End);
    actions.append(&cancel);
    actions.append(&confirm);

    let vbox = gtk::Box::new(Orientation::Vertical, 10);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);
    vbox.append(&intro);
    vbox.append(&master);
    vbox.append(&code);
    vbox.append(&preset_row);
    vbox.append(&actions);
    dialog.set_child(Some(&vbox));

    {
        let dialog = dialog.clone();
        cancel.connect_clicked(move |_| dialog.close());
    }
    {
        let ui = Rc::clone(ui);
        let dialog = dialog.clone();
        let master = master.clone();
        let code = code.clone();
        let preset_dd = preset.clone();
        confirm.connect_clicked(move |_| {
            // Move the secrets out of the widgets immediately.
            let master_secret = SecretString::new(master.text().to_string());
            let code_text = code.text().to_string();
            let preset = preset_from_index(preset_dd.selected());
            // Wipe the widget buffers now that the values are copied out, so no
            // plaintext is left behind (finding S-medium / §5 item 1).
            master.set_text("");
            code.set_text("");
            ui.session.send(Request::ExportRecovery {
                master: master_secret,
                code: code_text,
                preset,
            });
            ui.status.set_text("Deriving recovery key (slow)…");
            dialog.close();
        });
    }

    dialog.present();
}

/// Wire the post-creation authenticator-confirm step (B8): "Confirm code" sends
/// a [`Request::VerifyTotp`]; "Dismiss" hides the one-time URI and the group.
fn wire_totp_confirm(ui: &Rc<Ui>, confirm_btn: &gtk::Button, dismiss_btn: &gtk::Button) {
    {
        let ui = Rc::clone(ui);
        confirm_btn.connect_clicked(move |_| {
            let code = ui.confirm_totp.text().to_string();
            if code.trim().is_empty() {
                ui.confirm_result
                    .set_text("Enter the code your authenticator shows.");
                return;
            }
            ui.confirm_result.remove_css_class("error");
            ui.confirm_result.set_text("Checking…");
            ui.session.send(Request::VerifyTotp { code });
        });
    }
    {
        let ui = Rc::clone(ui);
        dismiss_btn.connect_clicked(move |_| {
            // Explicit dismiss of the one-time URI (replaces the old silent 10 s
            // auto-hide). Clear the sensitive label and the confirm group.
            ui.reveal.set_text(OBSCURED);
            ui.confirm_totp.set_text("");
            ui.confirm_result.set_text("");
            ui.confirm_box.set_visible(false);
            ui.status
                .set_text("TOTP URI hidden. If you did not save it, lock and recreate the vault.");
        });
    }
}

/// Apply the outcome of a recovery-export save dialog (B7): write the chosen
/// file owner-only (0600), or surface a non-secret status on cancel/error.
fn save_recovery_file(ui: &Rc<Ui>, result: Result<gio::File, glib::Error>, bytes: &[u8]) {
    let Ok(gfile) = result else {
        // A cancel (or any picker error) is not worth a scary message.
        ui.status.set_text("Recovery backup not saved.");
        return;
    };
    let Some(path) = gfile.path() else {
        ui.status
            .set_text("That location has no file path — choose a local file.");
        return;
    };
    match write_new_file_0600(&path, bytes) {
        Ok(()) => {
            ui.status.set_text("Recovery backup saved.");
            // They have an offline backup now; retire the onboarding nudge.
            ui.backup_banner.set_visible(false);
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            ui.status
                .set_text("A file of that name already exists — choose a new name.");
        }
        // The io::Error carries only path/OS detail, never the backup bytes.
        Err(e) => {
            ui.status
                .set_text(&format!("Could not save the recovery backup: {e}"));
        }
    }
}

/// Submit the visible unlock-page form when the user presses Enter in any of its
/// entries (finding UX-medium / §5 item 3).
///
/// `create_btn` and `unlock_btn` are mutually exclusive (see [`Ui::refresh_gate`]),
/// so we fire whichever the gate currently shows. Connecting the per-entry
/// `activate` signals avoids having to swap the window's default widget when the
/// create-vs-unlock gate flips.
fn wire_enter_submit(ui: &Rc<Ui>) {
    fn submit(ui: &Ui) {
        if ui.create_btn.is_visible() {
            ui.create_btn.emit_clicked();
        } else {
            ui.unlock_btn.emit_clicked();
        }
    }
    // Clone the widget handle out first (a GObject ref bump) so the closure can
    // move the `Rc<Ui>` without conflicting with the receiver borrow.
    {
        let ui = Rc::clone(ui);
        let master = ui.master.clone();
        master.connect_activate(move |_| submit(&ui));
    }
    {
        let ui = Rc::clone(ui);
        let confirm = ui.create_confirm.clone();
        confirm.connect_activate(move |_| submit(&ui));
    }
    {
        let ui = Rc::clone(ui);
        let totp = ui.totp.clone();
        totp.connect_activate(move |_| submit(&ui));
    }
}

fn clear_add_form(ui: &Rc<Ui>) {
    ui.add_label.set_text("");
    ui.add_user.set_text("");
    ui.add_pass.set_text("");
    ui.add_url.set_text("");
    ui.add_notes.set_text("");
}

/// Poll the worker's response channel on the GTK main loop and apply each
/// response to the widgets.
fn attach_response_poll(ui: &Rc<Ui>, responses: Receiver<Response>) {
    let ui = Rc::clone(ui);
    glib::timeout_add_local(Duration::from_millis(50), move || {
        // Drain everything currently available, then decide whether to keep the
        // timer alive based on the channel state (finding UX-medium / §5 item 2).
        loop {
            match responses.try_recv() {
                Ok(response) => handle_response(&ui, response),
                Err(TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(TryRecvError::Disconnected) => {
                    // The worker thread has exited/panicked; polling a dead
                    // channel forever would make every button silently no-op and
                    // look frozen. Surface it on both status surfaces (whichever
                    // page is showing) and stop the timer.
                    let msg = "The background worker stopped unexpectedly. \
                               Please restart passman.";
                    ui.unlock_error.set_text(msg);
                    ui.status.set_text(msg);
                    return glib::ControlFlow::Break;
                }
            }
        }
    });
}

fn handle_response(ui: &Rc<Ui>, response: Response) {
    match response {
        Response::Created {
            entries,
            provisioning_uri,
        } => {
            ui.unlock_spinner.set_spinning(false);
            ui.create_btn.set_sensitive(true);
            ui.master.set_text("");
            ui.create_confirm.set_text("");
            ui.create_strength.set_text("");
            ui.set_entries(entries);
            // Show the one-time TOTP provisioning URI so the user can scan it in
            // their authenticator app. It is sensitive (it embeds the seed). The
            // old silent 10 s auto-hide is gone (B8): the URI now stays until the
            // user confirms a code or explicitly dismisses, so it cannot vanish
            // before the authenticator has been proven to work.
            ui.reveal.set_text(provisioning_uri.expose());
            // Onboarding nudge: prompt an offline recovery backup now (B7).
            ui.backup_banner.set_visible(true);
            // Authenticator-confirm step (B8): fresh entry, cleared result.
            ui.confirm_totp.set_text("");
            ui.confirm_result.set_text("");
            ui.confirm_result.remove_css_class("error");
            ui.confirm_box.set_visible(true);
            ui.status.set_text(
                "Vault created. Scan this TOTP URI in your authenticator, then \
                 confirm a code below to prove it works.",
            );
            ui.stack.set_visible_child_name("vault");
        }
        Response::CreateFailed { message } => {
            ui.unlock_spinner.set_spinning(false);
            ui.create_btn.set_sensitive(true);
            ui.unlock_error.set_text(&message);
        }
        Response::Unlocked { entries } => {
            ui.unlock_spinner.set_spinning(false);
            ui.unlock_btn.set_sensitive(true);
            ui.master.set_text("");
            ui.totp.set_text("");
            ui.set_entries(entries);
            // The onboarding/confirm UI belongs only to a fresh create.
            ui.backup_banner.set_visible(false);
            ui.confirm_box.set_visible(false);
            ui.stack.set_visible_child_name("vault");
        }
        Response::UnlockFailed { message } => {
            ui.unlock_spinner.set_spinning(false);
            ui.unlock_btn.set_sensitive(true);
            ui.unlock_error.set_text(&message);
        }
        Response::Entries { entries } => {
            // Surface the success message for the most recent Add/Remove before
            // the list is rebuilt (finding UX-medium / §5 item 6).
            let confirmation = ui.pending_mutation.borrow_mut().take().map(|m| match m {
                PendingMutation::Add(label) => format!("Added \"{label}\"."),
                PendingMutation::Remove(label) => format!("Removed \"{label}\"."),
            });
            ui.set_entries(entries);
            if let Some(msg) = confirmation {
                ui.status.set_text(&msg);
            } else {
                ui.status.set_text("");
            }
        }
        Response::Revealed { field, value } => {
            ui.reveal.set_text(value.expose());
            let _ = field;
            // Auto-hide after 10 s (§5.4).
            let ui_hide = Rc::clone(ui);
            glib::timeout_add_seconds_local(REVEAL_HIDE_SECS, move || {
                ui_hide.reveal.set_text(OBSCURED);
                glib::ControlFlow::Break
            });
        }
        Response::Copied { cookie } => {
            ui.status.set_text(&format!(
                "Copied — auto-clears in {CLIPBOARD_CLEAR_SECS} s."
            ));
            let ui_clear = Rc::clone(ui);
            glib::timeout_add_seconds_local(CLIPBOARD_CLEAR_SECS, move || {
                ui_clear.session.send(Request::ClearClipboard { cookie });
                ui_clear.status.set_text("Clipboard cleared.");
                glib::ControlFlow::Break
            });
        }
        Response::Generated { password } => {
            ui.add_pass.set_text(password.expose());
        }
        Response::Locked => {
            let was_user_initiated = ui.user_initiated_lock.get();
            // Consume the flag before touching other UI state.
            ui.user_initiated_lock.set(false);

            ui.set_entries(Vec::new());
            ui.status.set_text("");
            // Drop any onboarding/confirm UI from a just-created vault.
            ui.backup_banner.set_visible(false);
            ui.confirm_box.set_visible(false);
            // A vault may have just been created; re-evaluate create-vs-unlock.
            ui.refresh_gate();
            ui.stack.set_visible_child_name("unlock");

            // If the lock was NOT user-initiated, it came from the 120 s idle
            // auto-lock; tell the user why they were thrown back to this screen
            // (finding UX-high / §5 item 2).
            if !was_user_initiated {
                ui.unlock_error.set_text(
                    "Locked automatically after 2 minutes of inactivity — \
                     unlock to continue.",
                );
            }
        }
        // A non-fatal op error, or a B7 export failure: both surface a worker-
        // built status string that never contains a secret.
        Response::Error { message } | Response::RecoveryExportFailed { message } => {
            ui.status.set_text(&message);
        }
        // B7 — the recovery backup bytes are ready; let the user pick a path.
        Response::RecoveryExported { file } => open_recovery_save_dialog(ui, file),
        // B8 — result of the authenticator-confirm step.
        Response::TotpChecked { valid } => apply_totp_checked(ui, valid),
    }
}

/// Pop a save dialog for the freshly-exported recovery bytes and write the
/// chosen file owner-only (0600) (B7).
fn open_recovery_save_dialog(ui: &Rc<Ui>, file: Vec<u8>) {
    let dialog = gtk::FileDialog::builder()
        .title("Save recovery backup")
        .initial_name(default_recovery_filename())
        .build();
    let ui_cb = Rc::clone(ui);
    // The save dialog is async/callback-based; it runs on the GTK main context
    // this poll already lives on.
    dialog.save(Some(&ui.window), gio::Cancellable::NONE, move |result| {
        save_recovery_file(&ui_cb, result, &file);
    });
}

/// Apply the result of the authenticator-confirm step (B8): on a match, dismiss
/// the one-time URI and the confirm group; on a miss, keep the user on the step.
fn apply_totp_checked(ui: &Rc<Ui>, valid: bool) {
    if valid {
        ui.confirm_result.remove_css_class("error");
        ui.confirm_result.set_text("Authenticator confirmed ✓");
        ui.reveal.set_text(OBSCURED);
        ui.confirm_totp.set_text("");
        ui.confirm_box.set_visible(false);
        ui.status
            .set_text("Authenticator confirmed. Back up your vault now (recovery export).");
    } else {
        ui.confirm_result.add_css_class("error");
        ui.confirm_result
            .set_text("That code didn't match — check your authenticator and try again.");
        // Clear the failed attempt so they retype a fresh code.
        ui.confirm_totp.set_text("");
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        default_recovery_filename, parse_opts, preset_from_index, tier_label, tier_needs_warning,
        validate_create_form, write_new_file_0600, CreateForm, RecoveryPreset, StrengthTier,
    };

    /// Build an owned-`String` arg iterator (program name already stripped).
    fn args(items: &[&str]) -> std::vec::IntoIter<String> {
        items
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parse_opts_defaults_to_hardware_and_no_dir() {
        let opts = parse_opts(args(&[])).expect("empty args parse");
        assert!(!opts.allow_software);
        assert_eq!(opts.vault_dir, None);
    }

    #[test]
    fn parse_opts_sets_allow_software_flag() {
        let opts = parse_opts(args(&["--allow-software-hsm"])).expect("parse");
        assert!(opts.allow_software);
        assert_eq!(opts.vault_dir, None);
    }

    #[test]
    fn parse_opts_reads_vault_dir_value() {
        let opts = parse_opts(args(&["--vault-dir", "/tmp/passman-x"])).expect("parse");
        assert_eq!(opts.vault_dir, Some(PathBuf::from("/tmp/passman-x")));
    }

    #[test]
    fn parse_opts_errors_when_vault_dir_value_missing() {
        let err = parse_opts(args(&["--vault-dir"])).expect_err("missing value should error");
        assert!(
            err.to_string().contains("--vault-dir"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_opts_ignores_unknown_flag() {
        // Unknown flags warn on stderr but must not fail the parse.
        let opts = parse_opts(args(&["--bogus", "--allow-software-hsm"])).expect("parse");
        assert!(opts.allow_software);
        assert_eq!(opts.vault_dir, None);
    }

    #[test]
    fn validate_create_form_flags_empty_and_mismatch() {
        assert_eq!(validate_create_form("", ""), CreateForm::Empty);
        assert_eq!(validate_create_form("", "anything"), CreateForm::Empty);
        assert_eq!(
            validate_create_form("a-strong-pass", "typo"),
            CreateForm::Mismatch
        );
        assert_eq!(
            validate_create_form("a-strong-pass", "a-strong-pass"),
            CreateForm::Ok
        );
    }

    #[test]
    fn tier_label_covers_all_variants() {
        // Every variant must return a non-empty string.
        for tier in [
            StrengthTier::Dangerous,
            StrengthTier::Weak,
            StrengthTier::Acceptable,
            StrengthTier::Strong,
            StrengthTier::Excellent,
        ] {
            assert!(!tier_label(tier).is_empty(), "empty label for {tier:?}");
        }
    }

    #[test]
    fn tier_needs_warning_matches_allows_export() {
        // needs_warning is true exactly when the tier is below Strong —
        // the same boundary the CLI uses for `warn_if_weak` (commands.rs).
        for tier in [
            StrengthTier::Dangerous,
            StrengthTier::Weak,
            StrengthTier::Acceptable,
        ] {
            assert!(tier_needs_warning(tier), "expected warning for {tier:?}");
        }
        for tier in [StrengthTier::Strong, StrengthTier::Excellent] {
            assert!(!tier_needs_warning(tier), "unexpected warning for {tier:?}");
        }
    }

    #[test]
    fn default_length_matches_policy_constant() {
        // The generate button uses DEFAULT_LENGTH; this pins it to 40 so
        // GTK and CLI are always aligned (finding UX-medium / §5 item 4).
        assert_eq!(super::DEFAULT_LENGTH, 40);
    }

    #[test]
    fn default_recovery_filename_has_pmrec_extension() {
        // The save-dialog default name must carry the recovery extension (B7).
        assert_eq!(default_recovery_filename(), "passman-recovery.pmrec");
    }

    #[test]
    fn preset_from_index_maps_the_dropdown_order() {
        // The dropdown is ["Floor", "Default", "Paranoid"]; out-of-range falls
        // back to Default (the dropdown's own initial selection) (B7).
        assert_eq!(preset_from_index(0), RecoveryPreset::Floor);
        assert_eq!(preset_from_index(1), RecoveryPreset::Default);
        assert_eq!(preset_from_index(2), RecoveryPreset::Paranoid);
        assert_eq!(preset_from_index(99), RecoveryPreset::Default);
        // GTK's "no selection" sentinel (INVALID_LIST_POSITION == u32::MAX) must
        // not panic and must stay safe.
        assert_eq!(preset_from_index(u32::MAX), RecoveryPreset::Default);
    }

    #[test]
    fn write_new_file_creates_then_refuses_to_clobber() {
        // Mirrors the CLI's recovery-writer test: create_new is the TOCTOU /
        // clobber guard (B7).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rec.pmrec");
        write_new_file_0600(&path, b"payload").expect("first create");
        assert_eq!(std::fs::read(&path).expect("read back"), b"payload");

        let err = write_new_file_0600(&path, b"clobber").expect_err("second create must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read back"), b"payload");
    }

    #[cfg(unix)]
    #[test]
    fn write_new_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rec.pmrec");
        write_new_file_0600(&path, b"x").expect("create");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "recovery file must be 0600, got {:o}",
            mode & 0o777
        );
    }
}
