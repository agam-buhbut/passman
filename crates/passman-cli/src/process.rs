//! The `passman` binary's process-exit-code contract.
//!
//! `main` turns a finished command's error into a process status. To keep that
//! mapping off fragile string matching, command failures that deserve a distinct
//! code are built with [`tagged`], which attaches an [`ExitClass`] to the
//! `anyhow::Error`; [`exit_status`] recovers it by downcast. Errors carrying no
//! tag fall back to [`ExitClass::General`].

use std::fmt;
use std::process::ExitCode;

/// The exit-code categories the binary distinguishes.
///
/// Process status contract (also restated at the `main` call site):
///   * `0` — success
///   * `1` — general / unspecified failure ([`ExitClass::General`])
///   * `2` — command-line usage error (emitted by clap itself, never here)
///   * `3` — requested entry not found ([`ExitClass::NotFound`])
///   * `4` — authentication failed: wrong master password or TOTP code
///     ([`ExitClass::AuthFailed`])
///   * `5` — temporarily locked out ([`ExitClass::LockedOut`])
///   * `6` — another instance already holds the vault
///     ([`ExitClass::AlreadyRunning`])
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitClass {
    General,
    NotFound,
    AuthFailed,
    LockedOut,
    AlreadyRunning,
}

/// A command error carrying the [`ExitClass`] `main` should turn into a process
/// code. Its `Display` is exactly the user-facing message (so `{:#}` prints just
/// that, with no duplicated source line), while the class rides alongside for the
/// exit-code mapping rather than being re-derived from the message text.
#[derive(Debug)]
struct Tagged {
    class: ExitClass,
    message: String,
}

impl fmt::Display for Tagged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Tagged {}

/// Build a classified command error: the user-facing `message` plus the
/// [`ExitClass`] the binary maps to a process exit code.
pub(crate) fn tagged(class: ExitClass, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Tagged {
        class,
        message: message.into(),
    })
}

/// The [`ExitClass`] for a finished-command error, defaulting to
/// [`ExitClass::General`] when the error carries no tag.
fn classify(err: &anyhow::Error) -> ExitClass {
    err.downcast_ref::<Tagged>()
        .map_or(ExitClass::General, |t| t.class)
}

/// The numeric process code for an [`ExitClass`] (the documented contract).
fn code(class: ExitClass) -> u8 {
    match class {
        ExitClass::General => 1,
        ExitClass::NotFound => 3,
        ExitClass::AuthFailed => 4,
        ExitClass::LockedOut => 5,
        ExitClass::AlreadyRunning => 6,
    }
}

/// The process [`ExitCode`] for a top-level command error (see [`ExitClass`] for
/// the contract). Usage errors (code 2) are emitted by clap before any command
/// runs, so they never reach here.
#[must_use]
pub fn exit_status(err: &anyhow::Error) -> ExitCode {
    ExitCode::from(code(classify(err)))
}

/// User-facing guidance shown when no TPM 2.0 is present. Factored out of `main`
/// so the wording lives in one place and is unit-testable.
#[must_use]
pub fn hardware_absent_message() -> &'static str {
    "no TPM 2.0 found. Re-run with --allow-software-hsm to use the OS \
     keyring instead (weaker: no hardware lockout)."
}

#[cfg(test)]
mod tests {
    use super::{classify, code, exit_status, hardware_absent_message, tagged, ExitClass};

    #[test]
    fn each_class_maps_to_its_documented_code() {
        assert_eq!(code(ExitClass::General), 1);
        assert_eq!(code(ExitClass::NotFound), 3);
        assert_eq!(code(ExitClass::AuthFailed), 4);
        assert_eq!(code(ExitClass::LockedOut), 5);
        assert_eq!(code(ExitClass::AlreadyRunning), 6);
    }

    #[test]
    fn tagged_errors_round_trip_their_class_and_message() {
        let e = tagged(ExitClass::NotFound, "no entry labelled \"x\"");
        assert_eq!(classify(&e), ExitClass::NotFound);
        // `{:#}` shows just the message (Tagged has no source), so user-facing
        // output is unchanged by the tagging.
        assert_eq!(format!("{e:#}"), "no entry labelled \"x\"");
    }

    #[test]
    fn untagged_errors_are_general() {
        assert_eq!(classify(&anyhow::anyhow!("boom")), ExitClass::General);
    }

    #[test]
    fn exit_status_maps_the_class_to_the_right_code() {
        // `ExitCode` has no `Eq`; compare via its `Debug` shape instead.
        let got = exit_status(&tagged(ExitClass::AlreadyRunning, "busy"));
        assert_eq!(
            format!("{got:?}"),
            format!("{:?}", std::process::ExitCode::from(6))
        );
        let general = exit_status(&anyhow::anyhow!("boom"));
        assert_eq!(
            format!("{general:?}"),
            format!("{:?}", std::process::ExitCode::from(1))
        );
    }

    #[test]
    fn hardware_absent_message_guides_to_the_software_flag() {
        let m = hardware_absent_message();
        assert!(m.contains("TPM"), "mentions the missing hardware");
        assert!(
            m.contains("--allow-software-hsm"),
            "points at the fallback flag"
        );
    }
}
