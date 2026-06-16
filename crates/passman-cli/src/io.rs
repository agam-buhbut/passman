//! Terminal input/output, abstracted so the command logic is testable.
//!
//! The [`Io`] trait isolates everything that touches a real terminal or the wall
//! clock: hidden password entry, line input, stdout (data) / stderr (status),
//! and the post-copy clipboard-clear wait. Production uses [`TerminalIo`]; the
//! integration tests use a scripted in-memory implementation, so no test ever
//! reads a real tty or sleeps.

use std::io::{self, BufRead, Write};
use std::time::Duration;

use passman_crypto::SecretString;

/// The terminal/clock surface a command needs.
///
/// Data (passwords, labels) goes to stdout via [`Io::out`]; status and prompts
/// go to stderr via [`Io::err`] / the prompt arguments (per the project's
/// stdout-is-data / stderr-is-status convention).
pub trait Io {
    /// Read a secret without echoing it (a master password, a new password).
    ///
    /// # Errors
    ///
    /// [`io::Error`] if the input could not be read.
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretString>;

    /// Read one line of (echoed) input — a label, a username, a TOTP code, or a
    /// `y/n` confirmation. The trailing newline is stripped.
    ///
    /// # Errors
    ///
    /// [`io::Error`] if the input could not be read.
    fn read_line(&mut self, prompt: &str) -> io::Result<String>;

    /// Write a line of **data** to stdout.
    fn out(&mut self, msg: &str);

    /// Write a line of **status** to stderr.
    fn err(&mut self, msg: &str);

    /// Wait `dur` (the post-copy clipboard-clear delay, §5.3). Real terminals
    /// sleep; tests return immediately.
    fn sleep(&mut self, dur: Duration);
}

/// The production [`Io`]: a real tty via `rpassword`, stdin/stdout/stderr, and
/// `std::thread::sleep`.
#[derive(Debug, Default)]
pub struct TerminalIo;

impl Io for TerminalIo {
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretString> {
        use std::io::IsTerminal;
        // Prompt on stderr, then read the secret from stdin. Interactively, use
        // `rpassword` to read with echo disabled; under piped/scripted input
        // there is no tty to control, so read a plain line (the pre-tty
        // `prompt_password`/`read_password` paths fail with ENXIO when no
        // controlling terminal exists).
        eprint!("{prompt}");
        io::stderr().flush()?;
        let stdin = io::stdin();
        if stdin.is_terminal() {
            Ok(SecretString::new(rpassword::read_password()?))
        } else {
            let mut line = String::new();
            if stdin.lock().read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of input",
                ));
            }
            Ok(SecretString::new(
                line.trim_end_matches(['\n', '\r']).to_owned(),
            ))
        }
    }

    fn read_line(&mut self, prompt: &str) -> io::Result<String> {
        // Prompt on stderr so stdout stays pure data for piping.
        eprint!("{prompt}");
        io::stderr().flush()?;
        let mut line = String::new();
        let n = io::stdin().lock().read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected end of input",
            ));
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_owned())
    }

    fn out(&mut self, msg: &str) {
        println!("{msg}");
    }

    fn err(&mut self, msg: &str) {
        eprintln!("{msg}");
    }

    fn sleep(&mut self, dur: Duration) {
        std::thread::sleep(dur);
    }
}
