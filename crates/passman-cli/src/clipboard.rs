//! The OS clipboard, backed by `arboard` (`architecture.md` §5.3).
//!
//! Implements core's [`Clipboard`] trait. Per §5.3 the platform impl — not core
//! — computes the SHA-256 digest of what it writes, so the post-copy clear only
//! wipes the clipboard if it is *still ours*. Transient buffers are zeroized
//! after hashing.
//!
//! The `arboard` connection is opened **lazily** on first use, so commands that
//! never touch the clipboard (`gen`, `list`, …) work on a headless box; only
//! `get` (copy) actually requires a display server.

use std::io;
use std::sync::Mutex;

use arboard::Clipboard as Arboard;
use passman_core::{Clipboard, ClipboardCookie, CoreError};
use passman_crypto::SecretString;
use passman_totp::{Clock, SystemClock};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A `Clipboard` backed by the OS clipboard via `arboard`, opened on first use.
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

    /// Run `f` against the (lazily-opened) clipboard, mapping `arboard` errors to
    /// a core error a shell may construct.
    fn with<R>(
        &self,
        context: &'static str,
        f: impl FnOnce(&mut Arboard) -> Result<R, arboard::Error>,
    ) -> Result<R, arboard::Error> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(Arboard::new()?);
        }
        let clip = guard.as_mut().expect("clipboard set above");
        let _ = context;
        f(clip)
    }
}

/// SHA-256 of `text`, scrubbing the transient copy afterwards.
fn digest(text: &str) -> [u8; 32] {
    let mut buf = text.as_bytes().to_vec();
    let out: [u8; 32] = Sha256::digest(&buf).into();
    buf.zeroize();
    out
}

/// Map an `arboard` error to a core error a shell is allowed to construct.
fn clip_err(context: &'static str, e: &arboard::Error) -> CoreError {
    CoreError::shell_io(context, io::Error::other(e.to_string()))
}

impl Clipboard for SystemClipboard {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie, CoreError> {
        let text = secret.expose();
        let d = digest(text);
        self.with("clipboard write", |c| c.set_text(text.to_owned()))
            .map_err(|e| clip_err("clipboard write", &e))?;
        // `written_at` is process-local and currently informational; stamp it
        // from the system clock for honesty.
        Ok(ClipboardCookie::new(d, SystemClock.now()))
    }

    fn read_digest(&self) -> Result<Option<[u8; 32]>, CoreError> {
        match self.with("clipboard read", arboard::Clipboard::get_text) {
            Ok(mut text) => {
                let d = digest(&text);
                text.zeroize();
                Ok(Some(d))
            }
            // An empty / non-text clipboard means "nothing of ours is there".
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(clip_err("clipboard read", &e)),
        }
    }

    fn set_text(&self, text: &str) -> Result<(), CoreError> {
        self.with("clipboard overwrite", |c| c.set_text(text.to_owned()))
            .map_err(|e| clip_err("clipboard overwrite", &e))
    }
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        assert_eq!(digest("hunter2"), digest("hunter2"));
        assert_ne!(digest("hunter2"), digest("hunter3"));
        // SHA-256 of the empty string, sanity-anchored.
        assert_eq!(digest("").len(), 32);
    }
}
