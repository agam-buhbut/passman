//! The `passman-gtk` binary entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match passman_gtk::run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
