//! The OS clipboard, backed by `arboard` (`architecture.md` §5.3).
//!
//! Mirrors the CLI's adapter: the platform impl computes the SHA-256 cookie
//! digest (core never hashes), opens `arboard` lazily, and zeroizes transient
//! buffers. Created inside the session worker thread (`arboard` is not `Send`).

use std::io;
use std::sync::Mutex;

use arboard::Clipboard as Arboard;
use passman_core::{Clipboard, ClipboardCookie, CoreError};
use passman_crypto::SecretString;
use passman_totp::{Clock, SystemClock};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A `Clipboard` backed by the OS clipboard, opened on first use.
#[derive(Default)]
pub struct SystemClipboard {
    inner: Mutex<Option<Arboard>>,
}

impl SystemClipboard {
    /// Construct without opening the clipboard (deferred to first use).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    fn with<R>(
        &self,
        f: impl FnOnce(&mut Arboard) -> Result<R, arboard::Error>,
    ) -> Result<R, arboard::Error> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(Arboard::new()?);
        }
        f(guard.as_mut().expect("clipboard set above"))
    }
}

fn digest(text: &str) -> [u8; 32] {
    let mut buf = text.as_bytes().to_vec();
    let out: [u8; 32] = Sha256::digest(&buf).into();
    buf.zeroize();
    out
}

fn clip_err(context: &'static str, e: &arboard::Error) -> CoreError {
    CoreError::shell_io(context, io::Error::other(e.to_string()))
}

impl Clipboard for SystemClipboard {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie, CoreError> {
        let text = secret.expose();
        let d = digest(text);
        self.with(|c| c.set_text(text.to_owned()))
            .map_err(|e| clip_err("clipboard write", &e))?;
        Ok(ClipboardCookie::new(d, SystemClock.now()))
    }

    fn read_digest(&self) -> Result<Option<[u8; 32]>, CoreError> {
        match self.with(arboard::Clipboard::get_text) {
            Ok(mut text) => {
                let d = digest(&text);
                text.zeroize();
                Ok(Some(d))
            }
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(clip_err("clipboard read", &e)),
        }
    }

    fn set_text(&self, text: &str) -> Result<(), CoreError> {
        self.with(|c| c.set_text(text.to_owned()))
            .map_err(|e| clip_err("clipboard overwrite", &e))
    }
}
