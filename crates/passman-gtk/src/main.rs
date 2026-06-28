//! The `passman-gtk` binary entry point.

// unsafe_code is allowed in this binary entry-point to call prctl/setrlimit for
// core-dump suppression (pentest S6). The library crate (src/lib.rs) retains
// its own #![forbid(unsafe_code)] — unsafe is confined to harden_process().

use std::process::ExitCode;

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
    match passman_gtk::run() {
        Ok(code) => code,
        Err(e) => {
            // Print to stderr for any attached terminal, then also show a
            // GTK error window so desktop-icon launches surface the failure
            // (finding UX-low / §5 item 5).
            eprintln!("error: {e:#}");
            passman_gtk::show_startup_error(&format!("{e:#}"));
            ExitCode::FAILURE
        }
    }
}
