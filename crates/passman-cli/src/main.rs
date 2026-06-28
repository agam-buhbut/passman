//! The `passman` binary: resolve platform paths, select the real Linux HSM
//! backend (TPM2 → `SecretService`, §6.2), and dispatch the parsed command.
//!
//! v0 targets Linux (the GTK desktop platform, §1.4); Windows/macOS shells come
//! later. All command logic lives in the (backend-generic) library so it is
//! exercised by the integration tests against the mock.

// unsafe_code is allowed in this binary entry-point to call prctl/setrlimit for
// core-dump suppression (pentest S6). The library crate (src/lib.rs) retains
// its own #![forbid(unsafe_code)] — unsafe is confined to harden_process().

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use passman_cli::{run, Cli, CliEnv, Command, DesktopPrompter, SystemClipboard, TerminalIo};
use passman_platform::{Paths, Settings};
use passman_totp::{Clock, SystemClock};

/// Seconds a copied secret stays on the clipboard before `get` clears it (§5.3).
const CLIPBOARD_CLEAR_SECS: u64 = 30;

/// Suppress core dumps so a crash while the vault is unlocked cannot spill
/// `K_master` or decrypted entries to an on-disk core file (pentest S6).
///
/// Two independent mechanisms are used so that a capability drop which blocks
/// `prctl` still hits `setrlimit`, and vice-versa:
///   1. `PR_SET_DUMPABLE 0` — tells the kernel this process is not dumpable.
///   2. `RLIMIT_CORE 0 / 0` — caps the core-file size to zero bytes.
///
/// Best-effort: a failure from either syscall is silently ignored because:
///   (a) we have no better fallback, and
///   (b) emitting a warning here risks leaking configuration info to an
///       attacker who reads stderr.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn harden_process() {
    // SAFETY: prctl/setrlimit with constant arguments and a valid stack-local
    // rlimit; no aliasing or lifetime concerns. Both calls are best-effort.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // `&raw const` avoids an implicit borrow-as-ptr (clippy::borrow_as_ptr).
        libc::setrlimit(libc::RLIMIT_CORE, &raw const zero);
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process() {}

/// Async-signal-safe SIGINT/SIGTERM handler for the `get` copy path: it does
/// nothing but flip the atomic flag the clipboard-clear loop polls — no
/// allocation, locking, or I/O — so an interrupt during the wait still scrubs
/// the secret (the clear itself runs in normal code).
#[cfg(target_os = "linux")]
extern "C" fn on_clipboard_signal(_sig: libc::c_int) {
    passman_cli::request_clipboard_clear();
}

/// Install [`on_clipboard_signal`] for SIGINT and SIGTERM. Best-effort: a failed
/// `sigaction` just leaves the default (terminate) disposition, so the only cost
/// is losing the early clipboard scrub on Ctrl-C — the 30 s timer still fires if
/// the process survives. A caught SIGINT/SIGTERM lets the wait end early; a
/// SIGKILL cannot be caught and can still strand the secret.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn install_clipboard_signal_handler() {
    // SAFETY: `action` is a fully-initialised, stack-local `sigaction`; the
    // handler is async-signal-safe (a lone atomic store) and the signal numbers
    // are constants. `&raw const` / `&raw mut` avoid an implicit borrow-as-ptr
    // (clippy::borrow_as_ptr), matching harden_process above.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        // Cast via a thin pointer first (function_casts_as_integer): the field
        // is a `size_t`-typed handler slot, set to our `extern "C"` handler.
        action.sa_sigaction = on_clipboard_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(libc::SIGINT, &raw const action, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut());
    }
}

/// Process exit codes (the binary's status contract; see `process.rs`):
///   `0` success · `1` general failure · `2` usage error (emitted by clap) ·
///   `3` entry not found · `4` auth failed · `5` locked out · `6` already running.
fn main() -> ExitCode {
    harden_process();
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `{:#}` includes the anyhow context chain; never prints secrets.
            eprintln!("error: {e:#}");
            // Map known error categories to distinct codes; everything else is 1.
            passman_cli::exit_status(&e)
        }
    }
}

#[cfg(target_os = "linux")]
fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let paths = resolve_paths(&cli)?;
    let settings = Settings::load(paths.settings())
        .with_context(|| format!("could not read {}", paths.settings().display()))?;

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let prompter = DesktopPrompter;
    let clipboard = SystemClipboard::new();
    let mut io = TerminalIo;

    let allow_software = cli.allow_software_hsm;
    let mut env = CliEnv {
        clock,
        prompter: &prompter,
        clipboard: &clipboard,
        io: &mut io,
        settings: &settings,
        paths: &paths,
        allow_software,
        clipboard_clear: Duration::from_secs(CLIPBOARD_CLEAR_SECS),
        kdf_override: None,
    };

    // `gen` needs no vault and no HSM — don't open the (possibly unavailable)
    // TPM just to print a password.
    match cli.command {
        Command::Gen { length } => passman_cli::generate(length, &mut env),
        command => {
            // Select the real Linux backend per §6.2 (TPM2 → SecretService).
            let backend =
                passman_hsm::linux::select_linux_backend(allow_software).map_err(|e| match e {
                    passman_hsm::HsmError::HardwareAbsent => {
                        anyhow::anyhow!("{}", passman_cli::hardware_absent_message())
                    }
                    other => anyhow::Error::new(other).context("could not select an HSM backend"),
                })?;
            // The copy path parks on the §5.3 clear timer; install a
            // SIGINT/SIGTERM handler so an interrupt during that wait still
            // scrubs the secret. Scoped to this command so every other command
            // keeps the default terminate-on-Ctrl-C behaviour.
            if matches!(command, Command::Get { show: false, .. }) {
                install_clipboard_signal_handler();
            }
            run(command, backend, &mut env)
        }
    }
}

/// Non-Linux builds have no backend yet (Windows/macOS shells are later work).
#[cfg(not(target_os = "linux"))]
fn real_main() -> Result<()> {
    anyhow::bail!("the passman CLI currently supports Linux only")
}

/// Resolve the vault/settings paths from `--vault-dir` or the platform defaults.
#[cfg(target_os = "linux")]
fn resolve_paths(cli: &Cli) -> Result<Paths> {
    match &cli.vault_dir {
        Some(dir) => Ok(Paths::under_base(dir)),
        None => Paths::discover()
            .context("could not determine the vault location; pass --vault-dir <DIR>"),
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(unsafe_code)]
mod harden_tests {
    use super::harden_process;

    /// Verify that `harden_process()` actually suppresses core dumps in the
    /// current process.  Runs only on Linux; deterministic (no I/O, no network).
    ///
    /// Note: `PR_GET_DUMPABLE` returns the raw `c_long` value on success (>= 0),
    /// not an errno, so we compare directly.
    #[test]
    fn harden_process_disables_core_dumps() {
        harden_process();

        // --- RLIMIT_CORE must be zeroed ---
        let mut rl = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: rl is a valid, stack-local rlimit; no aliasing concerns.
        // `&raw mut` avoids an implicit borrow-as-ptr (clippy::borrow_as_ptr).
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut rl) };
        assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) failed");
        assert_eq!(rl.rlim_cur, 0, "RLIMIT_CORE soft limit should be 0");
        assert_eq!(rl.rlim_max, 0, "RLIMIT_CORE hard limit should be 0");

        // --- PR_GET_DUMPABLE must return 0 ---
        // SAFETY: PR_GET_DUMPABLE is a read-only prctl with no pointer args.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(
            dumpable, 0,
            "PR_GET_DUMPABLE should be 0 after harden_process()"
        );
    }
}
