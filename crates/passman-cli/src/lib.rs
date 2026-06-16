//! `passman-cli` — the command-line shell over `passman-core`.
//!
//! The command logic ([`run`]) is generic over the HSM backend so the
//! integration tests drive it against the in-memory mock while the `passman`
//! binary uses the real Linux backend (TPM2 → `SecretService`, §6.2). Terminal
//! I/O, the clock, the clipboard, and the post-copy wait are all injected
//! through [`CliEnv`] / the [`Io`] trait, so no test reads a real tty or sleeps.

#![forbid(unsafe_code)]

mod cli;
mod clipboard;
mod commands;
mod io;
mod prompter;

pub use cli::{Cli, Command, Field, Preset, RecPreset};
pub use clipboard::SystemClipboard;
pub use commands::{run, CliEnv};
pub use io::{Io, TerminalIo};
pub use prompter::DesktopPrompter;
