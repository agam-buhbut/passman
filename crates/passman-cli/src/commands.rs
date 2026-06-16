//! Command implementations, generic over the HSM backend so the integration
//! tests drive them against the mock while `main` uses the real Linux backend.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use passman_core::{App, Clipboard, UnlockError, UnlockedApp};
use passman_crypto::SecretString;
use passman_hsm::{BiometricPrompter, HardwareKeyStore};
use passman_platform::{Paths, Settings};
use passman_policy::{classify, estimate_master, EntryPolicy, GenerationRequest};
use passman_totp::Clock;
use passman_vault::{EntryId, EntryRecord};

use crate::cli::{default_length, entry_record, Command, Field, Preset, RecPreset};
use crate::io::Io;

/// Everything a command needs besides the backend-owning [`App`].
pub struct CliEnv<'a, I: Io, C: Clipboard> {
    /// System clock (shared into the `App`).
    pub clock: Arc<dyn Clock>,
    /// Biometric/PIN prompter (no-op on the desktop backends).
    pub prompter: &'a dyn BiometricPrompter,
    /// The OS clipboard.
    pub clipboard: &'a C,
    /// Terminal/clock I/O.
    pub io: &'a mut I,
    /// Non-secret settings (`clipboard_fact_overwrite`, …).
    pub settings: &'a Settings,
    /// Resolved per-platform paths.
    pub paths: &'a Paths,
    /// Whether the keyring fallback / mock is permitted (`--allow-software-hsm`).
    pub allow_software: bool,
    /// How long `get` keeps a copied secret on the clipboard before clearing it
    /// (30 s in production, 0 in tests).
    pub clipboard_clear: Duration,
    /// Test-only override for the master-key Argon2id parameters. **Production
    /// always passes `None`**, so the `--preset` flag governs; the integration
    /// tests set cheap parameters here to avoid running 256 MiB+ Argon2 per
    /// unlock. Never wired to any CLI flag.
    pub kdf_override: Option<passman_crypto::KdfParams>,
}

impl<I: Io, C: Clipboard> CliEnv<'_, I, C> {
    /// The Argon2id parameters for a key-deriving command: the test override if
    /// set, else the user's `--preset`.
    fn kdf(&self, preset: Preset) -> passman_crypto::KdfParams {
        self.kdf_override.unwrap_or_else(|| preset.params())
    }
}

/// Dispatch one command. Consumes `backend` (the `App` owns it).
///
/// # Errors
///
/// Surfaces any command failure as an [`anyhow::Error`] with a user-facing
/// message.
pub fn run<H, I, C>(command: Command, backend: H, env: &mut CliEnv<I, C>) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    // `gen` needs no vault (and so no single-instance lock); handle it first.
    if let Command::Gen { length } = command {
        return generate(length, env);
    }

    let app = open_app(backend, env)?;
    match command {
        Command::Gen { .. } => unreachable!("handled above"),
        Command::Init { preset } => cmd_init(&app, preset, env),
        Command::List => cmd_list(&app, env),
        Command::Add {
            label,
            generate,
            length,
        } => cmd_add(&app, label, generate, length, env),
        Command::Get { label, show, field } => cmd_get(&app, &label, field, show, env),
        Command::Rm { label } => cmd_rm(&app, &label, env),
        Command::Export { file, preset } => cmd_export(&app, &file, preset, env),
        Command::Import { file, preset } => cmd_import(&app, &file, preset, env),
        Command::Passwd { preset } => cmd_passwd(&app, preset, env),
    }
}

// ----- App / unlock helpers --------------------------------------------------

/// Open the locked [`App`], acquiring the single-instance lock.
fn open_app<H, I, C>(backend: H, env: &CliEnv<I, C>) -> Result<App<H>>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    let path = env.paths.vault();
    let opened = if env.allow_software {
        App::open_allowing_software_hsm(path, backend, env.clock.clone())
    } else {
        App::open(path, backend, env.clock.clone())
    };
    opened.map_err(|e| match e {
        passman_core::CoreError::AlreadyRunning => {
            anyhow!("another passman instance is already using this vault")
        }
        other => anyhow!(other).context("could not open the vault"),
    })
}

/// Prompt for the master password and a TOTP code, then unlock.
fn unlock<'a, H, I, C>(
    app: &'a App<H>,
    env: &mut CliEnv<I, C>,
) -> Result<UnlockedApp<'a, H>>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    require_vault(env.paths.vault())?;
    let master = env.io.read_secret("Master password: ")?;
    let code = env.io.read_line("TOTP code: ")?;
    app.unlock(&master, code.trim(), &(), env.prompter)
        .map_err(unlock_error)
}

/// A friendly message for each [`UnlockError`].
// By-value for `.map_err(unlock_error)` ergonomics; the match needs no field move.
#[allow(clippy::needless_pass_by_value)]
fn unlock_error(e: UnlockError) -> anyhow::Error {
    match e {
        UnlockError::BadCredentials => anyhow!("incorrect master password or TOTP code"),
        UnlockError::LockedOut { remaining } => anyhow!(
            "locked out; try again in about {} s",
            remaining.as_secs().max(1)
        ),
        UnlockError::Cancelled => anyhow!("unlock cancelled"),
        UnlockError::Retryable => anyhow!("transient hardware error during unlock; please retry"),
        UnlockError::RouteToRecovery => anyhow!(
            "the hardware key is unavailable; recover with `passman import <file>`"
        ),
        UnlockError::SoftwareHsmRefused => anyhow!(
            "this vault uses a software backend; pass --allow-software-hsm to proceed"
        ),
        UnlockError::Hsm(_) | UnlockError::MalformedVault(_) => {
            anyhow!("the vault could not be unlocked (corrupt or tampered data)")
        }
        // `UnlockError` is #[non_exhaustive]; cover any future variant.
        _ => anyhow!("unlock failed"),
    }
}

/// Resolve one entry id by its label, requiring a unique match.
fn find_entry<H>(unlocked: &UnlockedApp<H>, label: &str) -> Result<EntryId>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
{
    let mut matching = unlocked
        .list_entries()?
        .into_iter()
        .filter(|h| h.label == label);
    let first = matching
        .next()
        .ok_or_else(|| anyhow!("no entry labelled {label:?}"))?;
    if matching.next().is_some() {
        bail!("several entries are labelled {label:?}; labels must be unique to address one by name");
    }
    Ok(first.id)
}

/// Read a new password twice and require the two entries to match.
fn read_new_password<I: Io>(io: &mut I, prompt: &str) -> Result<SecretString> {
    let first = io.read_secret(prompt)?;
    let again = io.read_secret("Confirm: ")?;
    if first != again {
        bail!("the passwords do not match");
    }
    Ok(first)
}

/// Warn (on stderr) if `password` is below the Strong tier — `init`/`passwd` are
/// allowed regardless, but recovery export will be blocked until it is Strong
/// (§7.5/§8.4).
fn warn_if_weak<I: Io>(io: &mut I, password: &str, kdf: &passman_crypto::KdfParams) {
    let entropy = estimate_master(password, &[], kdf);
    if !classify(entropy.bits).allows_export() {
        io.err(&format!(
            "warning: master password is below the Strong tier (~{:.0} bits); \
             recovery export will be refused until it is stronger",
            entropy.bits
        ));
    }
}

/// Error unless a vault file exists at `path`.
fn require_vault(path: &Path) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(anyhow!(
            "no vault at {}; create one with `passman init`",
            path.display()
        ))
    }
}

// ----- Commands --------------------------------------------------------------

/// Generate a password without touching the vault (`gen`).
///
/// Public so the binary can run it **without selecting an HSM backend** (a TPM
/// is irrelevant to generation).
///
/// # Errors
///
/// [`anyhow::Error`] if the generation request is unsatisfiable.
pub fn generate<I: Io, C: Clipboard>(length: Option<u16>, env: &mut CliEnv<I, C>) -> Result<()> {
    let req = match length {
        Some(n) => GenerationRequest::new(
            n,
            passman_policy::Charset::default_vault(),
            passman_policy::RequiredClasses::one_of_each(),
        ),
        None => GenerationRequest::default_vault(),
    };
    let pw = passman_policy::generate(&req).context("password generation failed")?;
    env.io.out(pw.expose());
    Ok(())
}

/// Create a new vault (`init`).
fn cmd_init<H, I, C>(app: &App<H>, preset: Preset, env: &mut CliEnv<I, C>) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    if env.paths.vault().exists() {
        bail!(
            "a vault already exists at {}; refusing to overwrite it",
            env.paths.vault().display()
        );
    }
    env.paths
        .ensure_dirs()
        .context("could not create the vault directory")?;

    let kdf = env.kdf(preset);
    let master = read_new_password(env.io, "New master password: ")?;
    warn_if_weak(env.io, master.expose(), &kdf);

    env.io
        .err("Deriving the vault key (this is deliberately slow)…");
    let (unlocked, uri) = app
        .create_vault(
            &master,
            kdf,
            passman_totp::TotpConfig::default(),
            &(),
            env.prompter,
        )
        .context("could not create the vault")?;

    env.io.err(
        "Add this TOTP secret to your authenticator app NOW — it is shown only once:",
    );
    env.io.out(uri.expose());
    env.io.err(&format!(
        "Vault created at {}.",
        env.paths.vault().display()
    ));
    unlocked.lock();
    Ok(())
}

/// List entry labels (`list`).
fn cmd_list<H, I, C>(app: &App<H>, env: &mut CliEnv<I, C>) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    let unlocked = unlock(app, env)?;
    let mut entries = unlocked.list_entries()?;
    entries.sort_by(|a, b| a.label.cmp(&b.label));
    if entries.is_empty() {
        env.io.err("(no entries)");
    }
    for handle in entries {
        env.io.out(&handle.label);
    }
    Ok(())
}

/// Add an entry (`add`).
fn cmd_add<H, I, C>(
    app: &App<H>,
    label: String,
    generate_pw: bool,
    length: Option<u16>,
    env: &mut CliEnv<I, C>,
) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    let mut unlocked = unlock(app, env)?;
    let resolved_len = length.unwrap_or_else(default_length);

    let username = SecretString::new(env.io.read_line("Username: ")?);
    let password = if generate_pw {
        let req = GenerationRequest::new(
            resolved_len,
            passman_policy::Charset::default_vault(),
            passman_policy::RequiredClasses::one_of_each(),
        );
        let pw = unlocked.generate_password(&req)?;
        env.io.err("Generated a password for this entry.");
        pw
    } else {
        read_new_password(env.io, "Password: ")?
    };
    let url = SecretString::new(env.io.read_line("URL (optional): ")?);
    let notes = SecretString::new(env.io.read_line("Notes (optional): ")?);

    let record: EntryRecord = entry_record(username, password, url, notes);
    let policy = EntryPolicy::default().with_length(resolved_len);
    let shown = format!("Added {label:?}.");
    unlocked.add_entry(label, policy, &record)?;
    env.io.err(&shown);
    Ok(())
}

/// Reveal or copy a field (`get`).
fn cmd_get<H, I, C>(
    app: &App<H>,
    label: &str,
    field: Field,
    show: bool,
    env: &mut CliEnv<I, C>,
) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    let mut unlocked = unlock(app, env)?;
    let id = find_entry(&unlocked, label)?;

    if show {
        let value = unlocked.with_revealed(&id, |r| field_string(r, field))?;
        env.io.out(&value);
        return Ok(());
    }

    let cookie = unlocked.copy_to_clipboard(&id, field.into(), env.clipboard)?;
    let secs = env.clipboard_clear.as_secs();
    env.io.err(&format!(
        "Copied to the clipboard; it will be cleared in {secs} s."
    ));
    env.io.sleep(env.clipboard_clear);
    let outcome =
        unlocked.clear_clipboard_with(&cookie, env.clipboard, env.settings.clipboard_fact_overwrite);
    env.io.err(&format!("Clipboard cleared ({outcome:?})."));
    Ok(())
}

/// Remove an entry (`rm`).
fn cmd_rm<H, I, C>(app: &App<H>, label: &str, env: &mut CliEnv<I, C>) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    let mut unlocked = unlock(app, env)?;
    let id = find_entry(&unlocked, label)?;
    unlocked.remove_entry(&id)?;
    env.io.err(&format!("Removed {label:?}."));
    Ok(())
}

/// Write a recovery export (`export`). Requires a fresh TOTP code (the unlock
/// code is consumed by the replay cache), per the §7.5 fresh-re-auth design.
fn cmd_export<H, I, C>(
    app: &App<H>,
    file: &Path,
    preset: RecPreset,
    env: &mut CliEnv<I, C>,
) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    if file.exists() {
        bail!("{} already exists; choose a different path", file.display());
    }
    let mut unlocked = unlock(app, env)?;

    env.io.err(
        "Recovery export needs a fresh re-authentication (a NEW code, not the one you just used).",
    );
    let reauth_master = env.io.read_secret("Master password (again): ")?;
    let reauth_code = env.io.read_line("Fresh TOTP code: ")?;

    env.io
        .err("Deriving the recovery key (this is deliberately very slow)…");
    let bytes = unlocked
        .export_recovery(
            &reauth_master,
            reauth_code.trim(),
            preset.into(),
            &(),
            env.prompter,
        )
        .map_err(export_error)?;

    std::fs::write(file, &bytes)
        .with_context(|| format!("could not write {}", file.display()))?;
    env.io.err(&format!(
        "Recovery file written to {}. Store it somewhere safe.",
        file.display()
    ));
    Ok(())
}

/// A friendly message for export-specific failures.
#[allow(clippy::needless_pass_by_value)]
fn export_error(e: passman_core::CoreError) -> anyhow::Error {
    match e {
        passman_core::CoreError::WeakPasswordForExport => anyhow!(
            "the master password is not Strong enough for a recovery export; \
             change it with `passman passwd` first"
        ),
        other => anyhow!(other).context("recovery export failed (re-authentication?)"),
    }
}

/// Create a vault from a recovery export (`import`).
fn cmd_import<H, I, C>(
    app: &App<H>,
    file: &Path,
    preset: Preset,
    env: &mut CliEnv<I, C>,
) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    if env.paths.vault().exists() {
        bail!(
            "a vault already exists at {}; refusing to overwrite it on import",
            env.paths.vault().display()
        );
    }
    env.paths
        .ensure_dirs()
        .context("could not create the vault directory")?;

    let bytes = std::fs::read(file).with_context(|| format!("could not read {}", file.display()))?;
    let recovery_pw = env.io.read_secret("Recovery password: ")?;

    env.io
        .err("Deriving keys from the recovery file (this is deliberately very slow)…");
    let (unlocked, uri) = app
        .import_recovery(
            &bytes,
            &recovery_pw,
            env.kdf(preset),
            passman_totp::TotpConfig::default(),
            &(),
            env.prompter,
        )
        .context("recovery import failed (wrong password or corrupt file)")?;

    env.io
        .err("Re-provision your authenticator with this TOTP secret (shown once):");
    env.io.out(uri.expose());
    env.io.err(&format!(
        "Vault restored to {} with {} entr{}.",
        env.paths.vault().display(),
        unlocked.list_entries()?.len(),
        if unlocked.list_entries()?.len() == 1 { "y" } else { "ies" }
    ));
    unlocked.lock();
    Ok(())
}

/// Change the master password (`passwd`).
fn cmd_passwd<H, I, C>(app: &App<H>, preset: Preset, env: &mut CliEnv<I, C>) -> Result<()>
where
    H: HardwareKeyStore<PlatformCtx = ()>,
    I: Io,
    C: Clipboard,
{
    let mut unlocked = unlock(app, env)?;
    let kdf = env.kdf(preset);
    // The current master password the user just typed at unlock is not retained;
    // ask for it again explicitly as the "old" password for the change.
    let old = env.io.read_secret("Current master password: ")?;
    let new = read_new_password(env.io, "New master password: ")?;
    warn_if_weak(env.io, new.expose(), &kdf);

    env.io.err("Re-deriving and re-encrypting the vault…");
    let outcome = unlocked
        .change_master_password(&old, &new, kdf, &(), env.prompter)
        .context("could not change the master password (wrong current password?)")?;

    if outcome.existing_export_now_stale {
        env.io
            .err("note: your previous recovery export no longer works; create a new one.");
    }
    env.io.err("Master password changed.");
    Ok(())
}

/// Extract one field of a decrypted record as an owned `String` (used by
/// `get --show`).
fn field_string(record: &EntryRecord, field: Field) -> String {
    let secret = match field {
        Field::Username => &record.username,
        Field::Password => &record.password,
        Field::Url => &record.url,
        Field::Notes => &record.notes,
    };
    secret.expose().to_owned()
}
