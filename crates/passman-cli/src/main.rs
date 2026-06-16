//! The `passman` binary: resolve platform paths, select the real Linux HSM
//! backend (TPM2 → `SecretService`, §6.2), and dispatch the parsed command.
//!
//! v0 targets Linux (the GTK desktop platform, §1.4); Windows/macOS shells come
//! later. All command logic lives in the (backend-generic) library so it is
//! exercised by the integration tests against the mock.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use passman_cli::{run, Cli, CliEnv, DesktopPrompter, SystemClipboard, TerminalIo};
use passman_platform::{Paths, Settings};
use passman_totp::{Clock, SystemClock};

/// Seconds a copied secret stays on the clipboard before `get` clears it (§5.3).
const CLIPBOARD_CLEAR_SECS: u64 = 30;

fn main() -> ExitCode {
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

    // Select the real Linux backend per §6.2 (TPM2 → SecretService).
    let backend = passman_hsm::linux::select_linux_backend(cli.allow_software_hsm).map_err(|e| {
        match e {
            passman_hsm::HsmError::HardwareAbsent => anyhow::anyhow!(
                "no TPM 2.0 found. Re-run with --allow-software-hsm to use the OS keyring \
                 instead (weaker: no hardware lockout)."
            ),
            other => anyhow::Error::new(other).context("could not select an HSM backend"),
        }
    })?;

    let mut env = CliEnv {
        clock,
        prompter: &prompter,
        clipboard: &clipboard,
        io: &mut io,
        settings: &settings,
        paths: &paths,
        allow_software: cli.allow_software_hsm,
        clipboard_clear: Duration::from_secs(CLIPBOARD_CLEAR_SECS),
        kdf_override: None,
    };

    run(cli.command, backend, &mut env)
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
