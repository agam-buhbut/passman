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

fn main() -> ExitCode {
    harden_process();
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `{:#}` includes the anyhow context chain; never prints secrets.
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
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
                    passman_hsm::HsmError::HardwareAbsent => anyhow::anyhow!(
                        "no TPM 2.0 found. Re-run with --allow-software-hsm to use the OS \
                         keyring instead (weaker: no hardware lockout)."
                    ),
                    other => anyhow::Error::new(other).context("could not select an HSM backend"),
                })?;
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
