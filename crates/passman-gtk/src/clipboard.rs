//! The OS clipboard, backed by `arboard` (`architecture.md` §5.3).
//!
//! Mirrors the CLI's adapter: the platform impl computes the SHA-256 cookie
//! digest (core never hashes), opens `arboard` lazily, and zeroizes transient
//! buffers. Created inside the session worker thread (`arboard` is not `Send`).

use std::io;
use std::sync::{Arc, Mutex};

use arboard::Clipboard as Arboard;
use passman_core::{Clipboard, ClipboardCookie, CoreError};
use passman_crypto::SecretString;
use passman_totp::Clock;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A `Clipboard` backed by the OS clipboard, opened on first use.
pub struct SystemClipboard {
    inner: Mutex<Option<Arboard>>,
    /// Shared time source for cookie timestamps — the same `Clock` the session
    /// uses, so every timestamp in the app comes from one source.
    clock: Arc<dyn Clock>,
}

impl SystemClipboard {
    /// Construct without opening the clipboard (deferred to first use).
    ///
    /// `clock` is the session's shared time source, used to stamp the clipboard
    /// cookie so it agrees with the rest of the app's notion of time.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(None),
            clock,
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
    // Hash the borrowed bytes directly: no intermediate Vec, so the secret is
    // not copied onto the heap just to be hashed.
    Sha256::digest(text.as_bytes()).into()
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
        Ok(ClipboardCookie::new(d, self.clock.now()))
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

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_matches_known_sha256_vector() {
        // SHA-256("abc") from FIPS 180-4 — pins the cookie hash to plain SHA-256.
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest("abc"), expected);
    }

    #[test]
    fn digest_of_empty_is_stable() {
        // SHA-256("") from FIPS 180-4.
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest(""), expected);
    }
}
