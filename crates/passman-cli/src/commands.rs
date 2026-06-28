//! Command implementations, generic over the HSM backend so the integration
//! tests drive them against the mock while `main` uses the real Linux backend.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use passman_core::{App, ClearOutcome, Clipboard, UnlockError, UnlockedApp};
use passman_crypto::SecretString;
use passman_hsm::{BiometricPrompter, HardwareKeyStore};
use passman_platform::{Paths, Settings};
use passman_policy::{classify, estimate_master, EntryPolicy, GenerationRequest};
use passman_totp::Clock;
use passman_vault::{EntryId, EntryRecord};
use zeroize::Zeroizing;

use crate::cli::{default_length, entry_record, Command, Field, Preset, RecPreset};
use crate::io::Io;
use crate::process::{tagged, ExitClass};

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
        passman_core::CoreError::AlreadyRunning => tagged(
            ExitClass::AlreadyRunning,
            "another passman instance is already using this vault",
        ),
        other => anyhow!(other).context("could not open the vault"),
    })
}

/// Prompt for the master password and a TOTP code, then unlock.
fn unlock<'a, H, I, C>(app: &'a App<H>, env: &mut CliEnv<I, C>) -> Result<UnlockedApp<'a, H>>
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
        UnlockError::BadCredentials => tagged(
            ExitClass::AuthFailed,
            "incorrect master password or TOTP code",
        ),
        UnlockError::LockedOut { remaining } => tagged(
            ExitClass::LockedOut,
            format!(
                "locked out; try again in about {} s",
                remaining.as_secs().max(1)
            ),
        ),
        UnlockError::Cancelled => anyhow!("unlock cancelled"),
        UnlockError::Retryable => anyhow!("transient hardware error during unlock; please retry"),
        UnlockError::RouteToRecovery => {
            anyhow!("the hardware key is unavailable; recover with `passman import <file>`")
        }
        UnlockError::SoftwareHsmRefused => {
            anyhow!("this vault uses a software backend; pass --allow-software-hsm to proceed")
        }
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
        .ok_or_else(|| tagged(ExitClass::NotFound, format!("no entry labelled {label:?}")))?;
    if matching.next().is_some() {
        bail!(
            "several entries are labelled {label:?}; labels must be unique to address one by name"
        );
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

    env.io
        .err("Add this TOTP secret to your authenticator app NOW — it is shown only once:");
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
        // Hold the revealed field in a zeroizing buffer so the plaintext is
        // scrubbed the instant it leaves scope, instead of lingering in a plain
        // `String` after printing (#3). `field_string`'s allocation is moved in,
        // not copied, so this is the only heap copy and it is wiped on drop.
        let value = unlocked.with_revealed(&id, |r| Zeroizing::new(field_string(r, field)))?;
        env.io.out(value.as_str());
        return Ok(());
    }

    let cookie = unlocked.copy_to_clipboard(&id, field.into(), env.clipboard)?;
    let secs = env.clipboard_clear.as_secs();
    env.io.err(&format!(
        "Copied to the clipboard; it will be cleared in {secs} s (or on Ctrl-C)."
    ));
    // Wait in short ticks so a SIGINT/SIGTERM (whose handler only flips an atomic
    // flag — the sole async-signal-safe action) ends the wait promptly and the
    // secret is still scrubbed here, in normal code, never from the handler (#2).
    // Best-effort: a SIGKILL cannot be caught, so it can still strand the secret.
    wait_for_clear(env.io, env.clipboard_clear, &CLIPBOARD_CLEAR_REQUESTED);
    let outcome = unlocked.clear_clipboard_with(
        &cookie,
        env.clipboard,
        env.settings.clipboard_fact_overwrite,
    );
    env.io.err(clear_status_message(outcome));
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
    // Cheap advisory pre-check so the user learns the path is taken immediately,
    // rather than after re-auth + the deliberately-slow recovery derivation. The
    // authoritative guard is still the atomic create_new (O_EXCL) write below;
    // this is pure UX and losing the race there fails safely.
    if file.exists() {
        return Err(anyhow!(
            "{} already exists; choose a different path",
            file.display()
        ));
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

    // Atomic, owner-only write: `create_new` (O_EXCL) refuses to clobber and
    // closes the old check-then-write TOCTOU; 0600 keeps the recovery material
    // unreadable by other users even under a lax umask (#1).
    write_new_file_0600(file, &bytes).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            anyhow!("{} already exists; choose a different path", file.display())
        } else {
            anyhow::Error::new(e).context(format!("could not write {}", file.display()))
        }
    })?;
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

    let bytes =
        std::fs::read(file).with_context(|| format!("could not read {}", file.display()))?;
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
    let n = unlocked.list_entries()?.len();
    env.io.err(&format!(
        "Vault restored to {} with {} entr{}.",
        env.paths.vault().display(),
        n,
        if n == 1 { "y" } else { "ies" }
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
/// `get --show`). The caller wraps this in [`Zeroizing`] so the plaintext is
/// scrubbed promptly (#3).
fn field_string(record: &EntryRecord, field: Field) -> String {
    let secret = match field {
        Field::Username => &record.username,
        Field::Password => &record.password,
        Field::Url => &record.url,
        Field::Notes => &record.notes,
    };
    secret.expose().to_owned()
}

// ----- Clipboard-clear wait + signal flag (#2, #5) ---------------------------

/// How long each clipboard-clear wait tick sleeps. Short enough that a SIGINT /
/// SIGTERM is honoured within ~one tick instead of blocking the full 30 s
/// budget; long enough not to busy-spin.
const CLEAR_TICK: Duration = Duration::from_millis(200);

/// Set by the binary's SIGINT/SIGTERM handler (via [`request_clipboard_clear`])
/// so the `get` copy wait can end early and scrub the secret instead of leaving
/// it on the clipboard (#2). The handler only flips this flag; the clear itself
/// runs in normal code ([`cmd_get`]).
static CLIPBOARD_CLEAR_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Request that an in-progress `get` clipboard-clear wait end now.
///
/// Called from the binary's signal handler. Async-signal-safe: a single atomic
/// store, with no allocation, locking, or other non-reentrant work.
pub fn request_clipboard_clear() {
    CLIPBOARD_CLEAR_REQUESTED.store(true, Ordering::SeqCst);
}

/// Wait up to `budget` for the post-copy clipboard clear, returning early the
/// moment `interrupted` is set. Sleeps in [`CLEAR_TICK`] increments through the
/// injected [`Io`], so production sleeps for real while tests (zero budget)
/// return instantly. `interrupted` is a parameter (not the global directly) so
/// the tick/flag logic is unit-testable without delivering a real signal.
fn wait_for_clear<I: Io>(io: &mut I, budget: Duration, interrupted: &AtomicBool) {
    let mut waited = Duration::ZERO;
    while waited < budget {
        if interrupted.load(Ordering::SeqCst) {
            break;
        }
        let tick = CLEAR_TICK.min(budget.saturating_sub(waited));
        io.sleep(tick);
        waited += tick;
    }
}

/// A human-readable line for a clipboard-clear [`ClearOutcome`], instead of
/// printing the internal enum's `Debug` (#5).
fn clear_status_message(outcome: ClearOutcome) -> &'static str {
    match outcome {
        ClearOutcome::Cleared => "Clipboard cleared.",
        ClearOutcome::StillOurs => {
            "Clipboard left in place (fact-overwrite is disabled in settings)."
        }
        ClearOutcome::Replaced => "Clipboard left unchanged — its contents were no longer ours.",
        ClearOutcome::Empty => "Clipboard was already empty.",
        ClearOutcome::Unavailable => "Clipboard could not be accessed to clear it.",
    }
}

// ----- Atomic, owner-only recovery file write (#1) ---------------------------

/// Atomically create `path` as an owner-only (0600) file and write `bytes`,
/// flushing to disk. `create_new` (`O_EXCL`) makes the create fail with
/// [`io::ErrorKind::AlreadyExists`] rather than clobbering an existing file —
/// closing the check-then-write TOCTOU — and the 0600 mode keeps the recovery
/// material unreadable by other users even under a permissive umask (#1).
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
#[cfg(not(unix))]
fn write_new_file_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{
        clear_status_message, wait_for_clear, write_new_file_0600, ClearOutcome, Duration, Io,
    };
    use std::sync::atomic::AtomicBool;

    /// A minimal [`Io`] that only counts `sleep` calls — enough to observe the
    /// clipboard-clear tick loop without a real terminal or clock.
    struct CountIo {
        sleeps: usize,
    }

    impl Io for CountIo {
        fn read_secret(&mut self, _: &str) -> std::io::Result<passman_crypto::SecretString> {
            unreachable!("wait_for_clear never reads input")
        }
        fn read_line(&mut self, _: &str) -> std::io::Result<String> {
            unreachable!("wait_for_clear never reads input")
        }
        fn out(&mut self, _: &str) {}
        fn err(&mut self, _: &str) {}
        fn sleep(&mut self, _: Duration) {
            self.sleeps += 1;
        }
    }

    #[test]
    fn a_set_interrupt_flag_skips_the_clipboard_wait() {
        // Models a SIGINT landing before the wait: the loop must clear at once,
        // never sleeping the budget away (the injectable-flag check from #2).
        let flag = AtomicBool::new(true);
        let mut io = CountIo { sleeps: 0 };
        wait_for_clear(&mut io, Duration::from_secs(30), &flag);
        assert_eq!(io.sleeps, 0, "a set flag must short-circuit the wait");
    }

    #[test]
    fn a_clear_flag_sleeps_in_ticks_through_the_budget() {
        let flag = AtomicBool::new(false);
        let mut io = CountIo { sleeps: 0 };
        wait_for_clear(&mut io, Duration::from_millis(600), &flag);
        assert_eq!(io.sleeps, 3, "600 ms / 200 ms tick = 3 ticks");
    }

    #[test]
    fn a_zero_budget_never_sleeps() {
        let flag = AtomicBool::new(false);
        let mut io = CountIo { sleeps: 0 };
        wait_for_clear(&mut io, Duration::ZERO, &flag);
        assert_eq!(io.sleeps, 0, "tests use a zero budget and must not sleep");
    }

    #[test]
    fn clear_status_messages_are_human_sentences() {
        assert_eq!(
            clear_status_message(ClearOutcome::Cleared),
            "Clipboard cleared."
        );
        assert_eq!(
            clear_status_message(ClearOutcome::Replaced),
            "Clipboard left unchanged — its contents were no longer ours."
        );
        // No variant leaks the raw enum `Debug` form to the user.
        for outcome in [
            ClearOutcome::Cleared,
            ClearOutcome::StillOurs,
            ClearOutcome::Replaced,
            ClearOutcome::Empty,
            ClearOutcome::Unavailable,
        ] {
            assert!(
                !clear_status_message(outcome).contains("ClearOutcome"),
                "status must read as prose, not Debug"
            );
        }
    }

    #[test]
    fn write_new_file_creates_then_refuses_to_clobber() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rec.pmr");
        write_new_file_0600(&path, b"payload").expect("first create");
        assert_eq!(std::fs::read(&path).expect("read back"), b"payload");

        // A second create_new on the same path is the TOCTOU/clobber guard: it
        // must fail with AlreadyExists and leave the original intact (#1).
        let err = write_new_file_0600(&path, b"clobber").expect_err("second create must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read back"), b"payload");
    }

    #[cfg(unix)]
    #[test]
    fn write_new_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rec.pmr");
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
