//! The GTK4 user interface: a three-page stack (unlock / vault / add) wired to
//! the [`crate::session`] worker over channels.
//!
//! All blocking work happens on the worker; the UI polls the response channel on
//! the GTK main loop (every 50 ms) and only ever touches widgets here.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

use gtk::prelude::*;
use gtk::{glib, Align, Application, ApplicationWindow, Orientation};
use gtk4 as gtk;

use passman_core::{App, EntryHandle, RevealField};
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
struct Opts {
    allow_software: bool,
    vault_dir: Option<PathBuf>,
}

fn parse_args() -> Opts {
    let mut opts = Opts {
        allow_software: false,
        vault_dir: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-software-hsm" => opts.allow_software = true,
            "--vault-dir" => opts.vault_dir = args.next().map(PathBuf::from),
            _ => {}
        }
    }
    opts
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
    let opts = parse_args();
    let paths = resolve_paths(&opts)?;
    let settings = Settings::load(paths.settings())?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

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
        || Ok(SystemClipboard::new()),
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
}

impl Ui {
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
    // Second entry for confirm (only shown on create, hidden on unlock).
    let create_confirm = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Confirm master password")
        .visible(!vault_exists)
        .build();
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
    let unlock_btn = gtk::Button::with_label("Unlock");
    unlock_btn.add_css_class("suggested-action");
    let create_btn = gtk::Button::with_label("Create vault");
    create_btn.add_css_class("suggested-action");
    let unlock_spinner = gtk::Spinner::new();
    let unlock_error = gtk::Label::builder()
        .label("")
        .wrap(true)
        .css_classes(["error"])
        .build();
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
    let reveal = gtk::Label::builder()
        .label(OBSCURED)
        .selectable(true)
        .build();
    let status = gtk::Label::builder().label("").wrap(true).build();

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
    let lock_btn = gtk::Button::with_label("Lock");
    let header = gtk::Box::new(Orientation::Horizontal, 6);
    header.append(&add_btn);
    let header_spacer = gtk::Box::new(Orientation::Horizontal, 0);
    header_spacer.set_hexpand(true);
    header.append(&header_spacer);
    header.append(&lock_btn);

    let vault_box = gtk::Box::new(Orientation::Vertical, 8);
    vault_box.set_margin_top(12);
    vault_box.set_margin_bottom(12);
    vault_box.set_margin_start(12);
    vault_box.set_margin_end(12);
    vault_box.append(&header);
    vault_box.append(&scroller);
    vault_box.append(&reveal);
    vault_box.append(&actions);
    vault_box.append(&status);
    stack.add_named(&vault_box, Some("vault"));

    // --- Add page ---
    let add_label = gtk::Entry::builder().placeholder_text("Label").build();
    let add_user = gtk::Entry::builder().placeholder_text("Username").build();
    let add_pass = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Password")
        .build();
    let gen_btn = gtk::Button::with_label("Generate");
    let add_url = gtk::Entry::builder()
        .placeholder_text("URL (optional)")
        .build();
    let add_notes = gtk::Entry::builder()
        .placeholder_text("Notes (optional)")
        .build();
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
        session,
        vault_path,
        entries: RefCell::new(Vec::new()),
        selected: RefCell::new(None),
        user_initiated_lock: Cell::new(false),
        pending_mutation: RefCell::new(None),
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
    attach_response_poll(&ui, responses);

    window.present();
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
            if master.expose().is_empty() {
                ui.unlock_error.set_text("Choose a master password first.");
                return;
            }
            // Confirm must match (finding UX-medium / §5 item 3).
            let confirm = create_confirm.text();
            if master.expose() != confirm.as_str() {
                ui.unlock_error
                    .set_text("The passwords do not match — re-enter both.");
                return;
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
            if let Ok(pw) = generate(&req) {
                ui.add_pass.set_text(pw.expose());
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
        while let Ok(response) = responses.try_recv() {
            handle_response(&ui, response);
        }
        glib::ControlFlow::Continue
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
            // their authenticator app. It is sensitive (it embeds the seed).
            // Auto-hide on the same timer as a revealed secret (finding S7 / §5 item 1).
            ui.reveal.set_text(provisioning_uri.expose());
            ui.status.set_text(
                "Vault created. Scan this TOTP URI in your authenticator now — \
                 it hides automatically in 10 s. Click \"Done\" when saved.",
            );
            ui.stack.set_visible_child_name("vault");
            // Start the auto-hide timer (mirrors the Revealed handler, §5.4).
            let ui_hide = Rc::clone(ui);
            glib::timeout_add_seconds_local(REVEAL_HIDE_SECS, move || {
                ui_hide.reveal.set_text(OBSCURED);
                ui_hide.status.set_text(
                    "TOTP URI hidden. If you did not save it, lock and recreate the vault.",
                );
                glib::ControlFlow::Break
            });
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
        Response::Error { message } => {
            ui.status.set_text(&message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{tier_label, tier_needs_warning, StrengthTier};

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
}
