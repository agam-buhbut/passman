//! Integration tests for the GTK app's session actor — the GTK-free worker that
//! owns the unlocked vault. Driven against the in-memory mock backend with an
//! injected clock and an inspectable clipboard; no GTK, no real hardware.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base32::Alphabet;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use passman_core::{App, Clipboard, ClipboardCookie, CoreError, RevealField};
use passman_crypto::{KdfParams, SecretString};
use passman_core::worker::{Request, Response};
use passman_core::Session;
use passman_hsm::mock::{MockKeyStore, MockPrompter};
use passman_hsm::{
    BiometricPrompter, HardwareKeyStore, HsmCapabilities, HsmError, HsmKind, HsmSlot, UnwrapHandle,
    WrappedBlob,
};
use passman_policy::EntryPolicy;
use passman_totp::{Clock, Timestamp, TotpConfig};
use passman_vault::EntryRecord;

const FAST_KDF: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
const MASTER: &str = "Str0ng-Master-Passphrase!";

fn master() -> SecretString {
    SecretString::new(MASTER.to_owned())
}

// ----- Shared-key mock (so the create App and session App share a key) -------

#[derive(Clone)]
struct SharedMock(Arc<MockKeyStore>);
impl SharedMock {
    fn new() -> Self {
        Self(Arc::new(MockKeyStore::new()))
    }
}
impl HardwareKeyStore for SharedMock {
    type PlatformCtx = ();
    fn kind(&self) -> HsmKind {
        self.0.kind()
    }
    fn capabilities(&self) -> HsmCapabilities {
        self.0.capabilities()
    }
    fn enroll(
        &self,
        slot: HsmSlot,
        material: &passman_crypto::SecretBytes,
        ctx: &(),
        prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError> {
        self.0.enroll(slot, material, ctx, prompter)
    }
    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        ctx: &(),
    ) -> Result<UnwrapHandle, HsmError> {
        self.0.begin_unwrap(slot, wrapped, ctx)
    }
    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        prompter: &dyn BiometricPrompter,
    ) -> Result<passman_crypto::SecretBytes, HsmError> {
        self.0.complete_unwrap(handle, prompter)
    }
    fn invalidate(&self, slot: HsmSlot, wrapped: &WrappedBlob, ctx: &()) -> Result<(), HsmError> {
        self.0.invalidate(slot, wrapped, ctx)
    }
}

// ----- Inspectable clipboard (shared with the test) --------------------------

#[derive(Clone, Default)]
struct SharedClipboard {
    content: Arc<Mutex<Option<String>>>,
}
fn sha256(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}
impl Clipboard for SharedClipboard {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie, CoreError> {
        let text = secret.expose().to_owned();
        let d = sha256(&text);
        *self.content.lock().expect("lock") = Some(text);
        Ok(ClipboardCookie::new(d, Timestamp::from_unix_secs(0)))
    }
    fn read_digest(&self) -> Result<Option<[u8; 32]>, CoreError> {
        Ok(self.content.lock().expect("lock").as_deref().map(sha256))
    }
    fn set_text(&self, text: &str) -> Result<(), CoreError> {
        *self.content.lock().expect("lock") = Some(text.to_owned());
        Ok(())
    }
}

// ----- Test clock + TOTP -----------------------------------------------------

struct TestClock(AtomicU64);
impl TestClock {
    fn at(secs: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(secs)))
    }
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_secs(self.0.load(Ordering::SeqCst))
    }
}
fn seed_from_uri(uri: &str) -> Vec<u8> {
    let after = uri.split("secret=").nth(1).expect("secret=");
    let b32 = after.split('&').next().expect("value");
    base32::decode(Alphabet::Rfc4648 { padding: false }, b32).expect("base32")
}
fn valid_code(seed: &[u8], now: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(seed).expect("key");
    mac.update(&(now / 30).to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let o = (tag[tag.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(tag[o] & 0x7f) << 24)
        | (u32::from(tag[o + 1]) << 16)
        | (u32::from(tag[o + 2]) << 8)
        | u32::from(tag[o + 3]);
    format!("{:06}", bin % 1_000_000)
}

// ----- Harness ---------------------------------------------------------------

struct Harness {
    _dir: tempfile::TempDir,
    backend: SharedMock,
    clock: Arc<TestClock>,
    clip: SharedClipboard,
    path: std::path::PathBuf,
}

impl Harness {
    /// Create a vault with the given entry labels, returning the harness and the
    /// TOTP seed.
    fn with_entries(labels: &[&str]) -> (Self, Vec<u8>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pmv");
        let backend = SharedMock::new();
        let clock = TestClock::at(1_700_000_000);

        let seed = {
            let app =
                App::open_allowing_software_hsm(&path, backend.clone(), clock.clone() as Arc<dyn Clock>)
                    .expect("open");
            let prompter = MockPrompter::authenticating();
            let (mut unlocked, uri) = app
                .create_vault(&master(), FAST_KDF, TotpConfig::default(), &(), &prompter)
                .expect("create");
            for label in labels {
                unlocked
                    .add_entry(
                        (*label).to_owned(),
                        EntryPolicy::default(),
                        &EntryRecord::new(
                            SecretString::new(format!("user-{label}")),
                            SecretString::new(format!("pw-{label}")),
                            SecretString::new(String::new()),
                            SecretString::new(String::new()),
                        ),
                    )
                    .expect("add");
            }
            let seed = seed_from_uri(uri.expose());
            unlocked.lock();
            seed // app drops, releasing the instance lock
        };

        (
            Self {
                _dir: dir,
                backend,
                clock,
                clip: SharedClipboard::default(),
                path,
            },
            seed,
        )
    }

    /// Spawn a session over a fresh App on the same vault (shared HSM key).
    fn spawn(&self) -> (Session, std::sync::mpsc::Receiver<Response>) {
        let app = App::open_allowing_software_hsm(
            &self.path,
            self.backend.clone(),
            self.clock.clone() as Arc<dyn Clock>,
        )
        .expect("open session app");
        let clip = self.clip.clone();
        Session::spawn(
            app,
            move || Ok(clip),
            Box::new(MockPrompter::authenticating()),
            true,
        )
    }

    fn code(&self, seed: &[u8]) -> String {
        valid_code(seed, self.clock.now_secs())
    }
}

fn recv(rx: &std::sync::mpsc::Receiver<Response>) -> Response {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("a response within 5s")
}

// ----- Tests -----------------------------------------------------------------

#[test]
fn unlock_lists_entries() {
    let (h, seed) = Harness::with_entries(&["GitHub", "Email"]);
    let (session, rx) = h.spawn();
    session.send(Request::Unlock {
        master: master(),
        code: h.code(&seed),
    });
    match recv(&rx) {
        Response::Unlocked { entries } => {
            let mut labels: Vec<_> = entries.into_iter().map(|e| e.label).collect();
            labels.sort();
            assert_eq!(labels, vec!["Email".to_owned(), "GitHub".to_owned()]);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn wrong_password_fails_unlock() {
    let (h, seed) = Harness::with_entries(&["X"]);
    let (session, rx) = h.spawn();
    session.send(Request::Unlock {
        master: SecretString::new("wrong".to_owned()),
        code: h.code(&seed),
    });
    assert!(matches!(recv(&rx), Response::UnlockFailed { .. }));
}

#[test]
fn reveal_and_copy_a_field() {
    let (h, seed) = Harness::with_entries(&["GitHub"]);
    let (session, rx) = h.spawn();
    session.send(Request::Unlock {
        master: master(),
        code: h.code(&seed),
    });
    let id = match recv(&rx) {
        Response::Unlocked { entries } => entries[0].id,
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Reveal the password.
    session.send(Request::Reveal {
        id,
        field: RevealField::Password,
    });
    match recv(&rx) {
        Response::Revealed { value, .. } => assert_eq!(value.expose(), "pw-GitHub"),
        other => panic!("expected Revealed, got {other:?}"),
    }

    // Copy the password → lands on the clipboard.
    session.send(Request::Copy {
        id,
        field: RevealField::Password,
    });
    assert!(matches!(recv(&rx), Response::Copied { .. }));
    assert_eq!(
        h.clip.content.lock().expect("lock").as_deref(),
        Some("pw-GitHub")
    );
}

#[test]
fn add_then_remove_updates_the_list() {
    let (h, seed) = Harness::with_entries(&["One"]);
    let (session, rx) = h.spawn();
    session.send(Request::Unlock {
        master: master(),
        code: h.code(&seed),
    });
    assert!(matches!(recv(&rx), Response::Unlocked { .. }));

    session.send(Request::Add {
        label: "Two".to_owned(),
        username: SecretString::new("u".to_owned()),
        password: SecretString::new("p".to_owned()),
        url: SecretString::new(String::new()),
        notes: SecretString::new(String::new()),
    });
    let id_two = match recv(&rx) {
        Response::Entries { entries } => {
            assert_eq!(entries.len(), 2);
            entries
                .into_iter()
                .find(|e| e.label == "Two")
                .expect("Two present")
                .id
        }
        other => panic!("expected Entries, got {other:?}"),
    };

    session.send(Request::Remove { id: id_two });
    match recv(&rx) {
        Response::Entries { entries } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].label, "One");
        }
        other => panic!("expected Entries, got {other:?}"),
    }
}

#[test]
fn lock_returns_to_locked_state() {
    let (h, seed) = Harness::with_entries(&["X"]);
    let (session, rx) = h.spawn();
    session.send(Request::Unlock {
        master: master(),
        code: h.code(&seed),
    });
    assert!(matches!(recv(&rx), Response::Unlocked { .. }));
    session.send(Request::Lock);
    assert!(matches!(recv(&rx), Response::Locked));
}

#[test]
fn create_makes_a_vault_and_returns_the_provisioning_uri() {
    // The in-app create path (used by the GTK and Android shells): a fresh,
    // vault-less directory, then a Create request.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.pmv");
    let backend = SharedMock::new();
    let clock = TestClock::at(1_700_000_000);
    let app = App::open_allowing_software_hsm(&path, backend, clock as Arc<dyn Clock>)
        .expect("open");
    let clip = SharedClipboard::default();
    let (session, rx) = Session::spawn(
        app,
        move || Ok(clip),
        Box::new(MockPrompter::authenticating()),
        true,
    );
    session.send(Request::Create {
        master: master(),
        kdf: FAST_KDF,
    });
    match recv(&rx) {
        Response::Created {
            entries,
            provisioning_uri,
        } => {
            assert!(entries.is_empty(), "a new vault is empty");
            assert!(provisioning_uri.expose().starts_with("otpauth://"));
        }
        other => panic!("expected Created, got {other:?}"),
    }
    assert!(path.exists(), "the vault file was written");
}
