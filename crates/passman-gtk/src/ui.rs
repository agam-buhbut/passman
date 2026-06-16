//! The GTK4 user interface: a three-page stack (unlock / vault / add) wired to
//! the [`crate::session`] worker over channels.
//!
//! All blocking work happens on the worker; the UI polls the response channel on
//! the GTK main loop (every 50 ms) and only ever touches widgets here.

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

use gtk4 as gtk;
use gtk::prelude::*;
use gtk::{glib, Align, Application, ApplicationWindow, Orientation};

use passman_core::{App, EntryHandle, RevealField};
use passman_crypto::SecretString;
use passman_hsm::linux::{select_linux_backend, LinuxKeyStore};
use passman_platform::{Paths, Settings};
use passman_policy::{generate, Charset, GenerationRequest, RequiredClasses};
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

    let vault_exists = paths.vault().exists();
    let fact_overwrite = settings.clipboard_fact_overwrite;
    let (session, responses) = Session::spawn(
        app_core,
        || Ok(SystemClipboard::new()),
        Box::new(crate::DesktopPrompter),
        fact_overwrite,
    );

    let application = Application::builder().application_id(APP_ID).build();
    // The session + receiver are consumed on first activation.
    let startup = Rc::new(RefCell::new(Some((session, responses, vault_exists))));
    application.connect_activate(move |app| {
        if let Some((session, responses, vault_exists)) = startup.borrow_mut().take() {
            build_ui(app, session, responses, vault_exists);
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

/// The live widget set + worker handle, shared into the GTK closures via `Rc`.
struct Ui {
    stack: gtk::Stack,
    master: gtk::PasswordEntry,
    totp: gtk::Entry,
    unlock_btn: gtk::Button,
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
    entries: RefCell<Vec<EntryHandle>>,
    selected: RefCell<Option<usize>>,
}

impl Ui {
    /// The id of the currently-selected entry, if any.
    fn selected_id(&self) -> Option<EntryId> {
        let idx = (*self.selected.borrow())?;
        self.entries.borrow().get(idx).map(|h| h.id)
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

/// Build the window and all wiring.
#[allow(clippy::too_many_lines)] // cohesive widget construction; splitting hurts clarity
fn build_ui(app: &Application, session: Session, responses: Receiver<Response>, vault_exists: bool) {
    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::SlideLeftRight);

    // --- Unlock page ---
    let master = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Master password")
        .build();
    let totp = gtk::Entry::builder()
        .placeholder_text("TOTP code")
        .max_length(8)
        .build();
    let unlock_btn = gtk::Button::with_label("Unlock");
    unlock_btn.add_css_class("suggested-action");
    let unlock_spinner = gtk::Spinner::new();
    let unlock_error = gtk::Label::builder()
        .label("")
        .wrap(true)
        .css_classes(["error"])
        .build();
    let unlock_hint = gtk::Label::new(Some(if vault_exists {
        "Unlock your vault."
    } else {
        "No vault found. Create one with the CLI: `passman init`."
    }));

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
    unlock_box.append(&totp);
    unlock_box.append(&unlock_btn);
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
    let reveal = gtk::Label::builder().label(OBSCURED).selectable(true).build();
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
    let add_url = gtk::Entry::builder().placeholder_text("URL (optional)").build();
    let add_notes = gtk::Entry::builder().placeholder_text("Notes (optional)").build();
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
        totp,
        unlock_btn: unlock_btn.clone(),
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
        entries: RefCell::new(Vec::new()),
        selected: RefCell::new(None),
    });

    wire_unlock(&ui, &unlock_btn);
    wire_list_selection(&ui, &list);
    wire_vault_actions(&ui, &reveal_btn, &copy_pw_btn, &copy_user_btn, &remove_btn, &lock_btn, &add_btn);
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
                ui.session.send(Request::Reveal { id, field: RevealField::Password });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        copy_pw_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                ui.session.send(Request::Copy { id, field: RevealField::Password });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        copy_user_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                ui.session.send(Request::Copy { id, field: RevealField::Username });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        remove_btn.connect_clicked(move |_| {
            if let Some(id) = ui.selected_id() {
                ui.session.send(Request::Remove { id });
            }
        });
    }
    {
        let ui = Rc::clone(ui);
        lock_btn.connect_clicked(move |_| {
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

fn wire_add_page(ui: &Rc<Ui>, gen_btn: &gtk::Button, save_btn: &gtk::Button, cancel_btn: &gtk::Button) {
    {
        let ui = Rc::clone(ui);
        gen_btn.connect_clicked(move |_| {
            let req = GenerationRequest::new(24, Charset::default_vault(), RequiredClasses::one_of_each());
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
            ui.set_entries(entries);
            ui.status.set_text("");
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
            ui.status
                .set_text(&format!("Copied — auto-clears in {CLIPBOARD_CLEAR_SECS} s."));
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
            ui.set_entries(Vec::new());
            ui.status.set_text("");
            ui.stack.set_visible_child_name("unlock");
        }
        Response::Error { message } => {
            ui.status.set_text(&message);
        }
    }
}
