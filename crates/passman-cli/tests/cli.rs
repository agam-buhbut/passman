//! End-to-end integration tests for the CLI command logic.
//!
//! Each test drives `passman_cli::run` — the same code path the binary uses —
//! against the in-memory mock backend, a scripted terminal, an in-memory
//! clipboard, and an injected clock. No test reads a real tty, opens a real
//! clipboard, sleeps, or runs a heavy Argon2 (a cheap KDF override is injected).
//!
//! Because each command is a one-shot `run`, the HSM key must persist across
//! invocations: [`SharedMock`] wraps one `MockKeyStore` behind an `Arc` so every
//! clone shares the same wrapping key (modelling real hardware persistence).

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base32::Alphabet;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use passman_cli::{run, CliEnv, Command, Field, Io, Preset, RecPreset};
use passman_core::{Clipboard, ClipboardCookie, CoreError};
use passman_crypto::{KdfParams, SecretString};
use passman_hsm::mock::{MockKeyStore, MockPrompter};
use passman_hsm::{
    BiometricPrompter, HardwareKeyStore, HsmCapabilities, HsmError, HsmKind, HsmSlot, UnwrapHandle,
    WrappedBlob,
};
use passman_platform::{Paths, Settings};
use passman_totp::{Clock, Timestamp};

/// Cheap Argon2 so the tests never run the real 256 MiB+ presets.
const FAST_KDF: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

const MASTER: &str = "Str0ng-Master-Passphrase!";

// ----- Shared-key mock backend ----------------------------------------------

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

// ----- Scripted terminal -----------------------------------------------------

struct ScriptIo {
    secrets: VecDeque<String>,
    lines: VecDeque<String>,
    out: Vec<String>,
    err: Vec<String>,
}

impl ScriptIo {
    fn new(secrets: &[&str], lines: &[&str]) -> Self {
        Self {
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            lines: lines.iter().map(|s| (*s).to_owned()).collect(),
            out: Vec::new(),
            err: Vec::new(),
        }
    }
    /// First stdout line beginning with `prefix`, if any.
    fn out_starting(&self, prefix: &str) -> Option<&str> {
        self.out
            .iter()
            .map(String::as_str)
            .find(|l| l.starts_with(prefix))
    }
    fn err_contains(&self, needle: &str) -> bool {
        self.err.iter().any(|l| l.contains(needle))
    }
}

impl Io for ScriptIo {
    fn read_secret(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::new(
            self.secrets.pop_front().expect("a scripted secret"),
        ))
    }
    fn read_line(&mut self, _prompt: &str) -> io::Result<String> {
        Ok(self.lines.pop_front().expect("a scripted line"))
    }
    fn out(&mut self, msg: &str) {
        self.out.push(msg.to_owned());
    }
    fn err(&mut self, msg: &str) {
        self.err.push(msg.to_owned());
    }
    fn sleep(&mut self, _dur: Duration) {}
}

// ----- In-memory clipboard ---------------------------------------------------

#[derive(Default)]
struct TestClipboard {
    content: Mutex<Option<String>>,
}

impl TestClipboard {
    fn current(&self) -> Option<String> {
        self.content.lock().expect("clipboard lock").clone()
    }
}

fn sha256(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

impl Clipboard for TestClipboard {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie, CoreError> {
        let text = secret.expose().to_owned();
        let d = sha256(&text);
        *self.content.lock().expect("clipboard lock") = Some(text);
        Ok(ClipboardCookie::new(d, Timestamp::from_unix_secs(0)))
    }
    fn read_digest(&self) -> Result<Option<[u8; 32]>, CoreError> {
        Ok(self
            .content
            .lock()
            .expect("clipboard lock")
            .as_deref()
            .map(sha256))
    }
    fn set_text(&self, text: &str) -> Result<(), CoreError> {
        *self.content.lock().expect("clipboard lock") = Some(text.to_owned());
        Ok(())
    }
}

// ----- Test clock ------------------------------------------------------------

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

// ----- TOTP code generation (RFC 4226 HOTP-SHA1) -----------------------------

fn seed_from_uri(uri: &str) -> Vec<u8> {
    let after = uri.split("secret=").nth(1).expect("secret= present");
    let b32 = after.split('&').next().expect("secret value");
    base32::decode(Alphabet::Rfc4648 { padding: false }, b32).expect("valid base32 seed")
}

fn valid_code(seed: &[u8], now: u64) -> String {
    let counter = now / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(seed).expect("hmac key any length");
    mac.update(&counter.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let offset = (tag[tag.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(tag[offset] & 0x7f) << 24)
        | (u32::from(tag[offset + 1]) << 16)
        | (u32::from(tag[offset + 2]) << 8)
        | u32::from(tag[offset + 3]);
    format!("{:06}", bin % 1_000_000)
}

// ----- Harness ---------------------------------------------------------------

/// One run-the-CLI fixture: a tempdir vault, a shared mock backend, a clock, and
/// an in-memory clipboard, reused across `run` calls within a test.
struct Fixture {
    _dir: tempfile::TempDir,
    paths: Paths,
    backend: SharedMock,
    clock: Arc<TestClock>,
    clipboard: TestClipboard,
    settings: Settings,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::under_base(dir.path());
        Self {
            _dir: dir,
            paths,
            backend: SharedMock::new(),
            clock: TestClock::at(1_700_000_000),
            clipboard: TestClipboard::default(),
            settings: Settings::default(),
        }
    }

    /// Run one command with scripted secrets/lines; returns the result and the
    /// captured terminal.
    fn run(
        &self,
        command: Command,
        secrets: &[&str],
        lines: &[&str],
    ) -> (anyhow::Result<()>, ScriptIo) {
        let prompter = MockPrompter::authenticating();
        let mut io = ScriptIo::new(secrets, lines);
        let result = {
            let mut env = CliEnv {
                clock: self.clock.clone() as Arc<dyn Clock>,
                prompter: &prompter,
                clipboard: &self.clipboard,
                io: &mut io,
                settings: &self.settings,
                paths: &self.paths,
                allow_software: true,
                clipboard_clear: Duration::ZERO,
                kdf_override: Some(FAST_KDF),
            };
            run(command, self.backend.clone(), &mut env)
        };
        (result, io)
    }

    /// Create the vault and return the TOTP seed decoded from the printed URI.
    fn init(&self) -> Vec<u8> {
        let (r, io) = self.run(
            Command::Init {
                preset: Preset::Low,
            },
            &[MASTER, MASTER],
            &[],
        );
        r.expect("init");
        let uri = io.out_starting("otpauth://").expect("provisioning URI");
        seed_from_uri(uri)
    }

    fn code(&self, seed: &[u8]) -> String {
        valid_code(seed, self.clock.now_secs())
    }
}

// ----- Tests -----------------------------------------------------------------

#[test]
fn init_creates_vault_and_lists_empty() {
    let fx = Fixture::new();
    let seed = fx.init();
    assert!(fx.paths.vault().exists(), "vault file written");

    let code = fx.code(&seed);
    let (r, io) = fx.run(Command::List, &[MASTER], &[&code]);
    r.expect("list");
    assert!(io.err_contains("no entries"));
    assert!(io.out.is_empty(), "no labels on an empty vault");
}

#[test]
fn init_refuses_to_overwrite_existing_vault() {
    let fx = Fixture::new();
    fx.init();
    let (r, _io) = fx.run(
        Command::Init {
            preset: Preset::Low,
        },
        &[MASTER, MASTER],
        &[],
    );
    assert!(r.is_err(), "second init must refuse");
    assert!(format!("{:#}", r.expect_err("must fail")).contains("already exists"));
}

#[test]
fn add_generate_then_list_and_get_show() {
    let fx = Fixture::new();
    let seed = fx.init();

    // add --generate: username + (generated password) + url + notes lines.
    let (r, io) = fx.run(
        Command::Add {
            label: "GitHub".to_owned(),
            generate: true,
            length: Some(32),
        },
        &[MASTER],
        &[&fx.code(&seed), "octocat", "https://github.com", "work"],
    );
    r.expect("add");
    assert!(io.err_contains("Added"));

    // list shows the label.
    let (r, io) = fx.run(Command::List, &[MASTER], &[&fx.code(&seed)]);
    r.expect("list");
    assert_eq!(io.out, vec!["GitHub".to_owned()]);

    // get --show prints the username (deterministic, unlike the generated pw).
    let (r, io) = fx.run(
        Command::Get {
            label: "GitHub".to_owned(),
            show: true,
            field: Field::Username,
        },
        &[MASTER],
        &[&fx.code(&seed)],
    );
    r.expect("get --show");
    assert_eq!(io.out, vec!["octocat".to_owned()]);
}

#[test]
fn add_explicit_password_then_get_copy_and_clear() {
    let fx = Fixture::new();
    let seed = fx.init();

    // add with an explicit password (entered twice).
    let (r, _io) = fx.run(
        Command::Add {
            label: "Email".to_owned(),
            generate: false,
            length: None,
        },
        &[MASTER, "s3cr3t-pw", "s3cr3t-pw"],
        &[&fx.code(&seed), "me@example.com", "", ""],
    );
    r.expect("add");

    // get (copy): the secret lands on the clipboard, then is cleared with a fact.
    let (r, io) = fx.run(
        Command::Get {
            label: "Email".to_owned(),
            show: false,
            field: Field::Password,
        },
        &[MASTER],
        &[&fx.code(&seed)],
    );
    r.expect("get --copy");
    assert!(io.err_contains("cleared"));
    let clip = fx.clipboard.current().expect("clipboard has content");
    assert_ne!(clip, "s3cr3t-pw", "secret was overwritten on clear");
    assert!(
        passman_core::FACTS.contains(&clip.as_str()),
        "cleared to a fact, got {clip:?}"
    );
}

#[test]
fn rm_removes_the_entry() {
    let fx = Fixture::new();
    let seed = fx.init();
    fx.run(
        Command::Add {
            label: "Temp".to_owned(),
            generate: true,
            length: None,
        },
        &[MASTER],
        &[&fx.code(&seed), "u", "", ""],
    )
    .0
    .expect("add");

    let (r, io) = fx.run(
        Command::Rm {
            label: "Temp".to_owned(),
        },
        &[MASTER],
        &[&fx.code(&seed)],
    );
    r.expect("rm");
    assert!(io.err_contains("Removed"));

    let (r, io) = fx.run(Command::List, &[MASTER], &[&fx.code(&seed)]);
    r.expect("list");
    assert!(io.out.is_empty(), "entry gone after rm");
}

#[test]
fn get_unknown_label_errors() {
    let fx = Fixture::new();
    let seed = fx.init();
    let (r, _io) = fx.run(
        Command::Get {
            label: "Nope".to_owned(),
            show: true,
            field: Field::Password,
        },
        &[MASTER],
        &[&fx.code(&seed)],
    );
    assert!(r.is_err());
    assert!(format!("{:#}", r.expect_err("must fail")).contains("no entry labelled"));
}

#[test]
fn wrong_master_password_fails_to_unlock() {
    let fx = Fixture::new();
    let seed = fx.init();
    let (r, _io) = fx.run(Command::List, &["wrong-password"], &[&fx.code(&seed)]);
    assert!(r.is_err());
    assert!(
        format!("{:#}", r.expect_err("must fail")).contains("incorrect master password or TOTP")
    );
}

#[test]
fn gen_prints_a_password_of_requested_length() {
    let fx = Fixture::new();
    // `gen` needs no vault; runs standalone.
    let (r, io) = fx.run(Command::Gen { length: Some(24) }, &[], &[]);
    r.expect("gen");
    assert_eq!(io.out.len(), 1);
    assert_eq!(io.out[0].chars().count(), 24);
}

#[test]
fn command_before_init_reports_missing_vault() {
    let fx = Fixture::new();
    let (r, _io) = fx.run(Command::List, &[MASTER], &["000000"]);
    assert!(r.is_err());
    assert!(format!("{:#}", r.expect_err("must fail")).contains("no vault"));
}

#[test]
fn passwd_changes_master_password() {
    let fx = Fixture::new();
    let seed = fx.init();
    let new_master = "An0ther-Str0ng-Passphrase!";

    // passwd: unlock (master + code), then current master + new (twice).
    let (r, io) = fx.run(
        Command::Passwd {
            preset: Preset::Low,
        },
        &[MASTER, MASTER, new_master, new_master],
        &[&fx.code(&seed)],
    );
    r.expect("passwd");
    assert!(io.err_contains("Master password changed"));

    // New password unlocks; old one does not.
    let (r, _io) = fx.run(Command::List, &[new_master], &[&fx.code(&seed)]);
    r.expect("unlock with new password");

    let (r, _io) = fx.run(Command::List, &[MASTER], &[&fx.code(&seed)]);
    assert!(r.is_err(), "old password must no longer unlock");
}

#[test]
fn export_refuses_weak_master_password() {
    // A weak master is allowed at init but blocks recovery export (§7.5). The
    // strength gate fires before TOTP re-auth and before the expensive recovery
    // Argon2, so this is cheap (only the cheap unlock runs a KDF).
    let fx = Fixture::new();
    let (r, io) = fx.run(
        Command::Init {
            preset: Preset::Low,
        },
        &["weak", "weak"],
        &[],
    );
    r.expect("init with weak master");
    let seed = seed_from_uri(io.out_starting("otpauth://").expect("uri"));

    let file = fx
        .paths
        .vault()
        .parent()
        .expect("vault parent")
        .join("rec.pmr");
    // secrets: unlock master, re-auth master (both "weak"). lines: valid unlock
    // code, then a dummy re-auth code (the gate rejects before it is checked).
    let (r, _io) = fx.run(
        Command::Export {
            file,
            preset: RecPreset::Floor,
        },
        &["weak", "weak"],
        &[&fx.code(&seed), "000000"],
    );
    let err = r.expect_err("weak master must block export");
    assert!(
        format!("{err:#}").contains("not Strong enough"),
        "expected the weak-export message, got: {err:#}"
    );
}

#[test]
fn import_round_trips_a_cheap_recovery_file() {
    use passman_policy::EntryPolicy;
    use passman_recovery::{export_unchecked, ExportPayload, RecoveryEntry};

    let fx = Fixture::new();

    // Build a cheap recovery file by hand (one entry).
    let policy = postcard::to_allocvec(&EntryPolicy::default()).expect("policy bytes");
    let payload = ExportPayload {
        totp_seed: passman_crypto::SecretArray::new([0x5Au8; 32]),
        original_vault_kdf: FAST_KDF,
        entries: vec![RecoveryEntry {
            id: [0x22u8; 16],
            label: "Restored".to_owned(),
            username: SecretString::new("user".to_owned()),
            password: SecretString::new("restored-pw".to_owned()),
            url: SecretString::new(String::new()),
            notes: SecretString::new(String::new()),
            policy,
        }],
    };
    let recovery_pw = "Recover-Me-Str0ng-Passphrase!";
    let file = fx
        .paths
        .vault()
        .parent()
        .expect("vault parent")
        .join("backup.pmr");
    std::fs::write(
        &file,
        export_unchecked(
            &payload,
            &SecretString::new(recovery_pw.to_owned()),
            &FAST_KDF,
        )
        .expect("export file"),
    )
    .expect("write file");

    // import: prompts for the recovery password.
    let (r, io) = fx.run(
        Command::Import {
            file,
            preset: Preset::Low,
        },
        &[recovery_pw],
        &[],
    );
    r.expect("import");
    assert!(
        io.out_starting("otpauth://").is_some(),
        "re-provisioning URI printed"
    );

    // The restored vault lists the imported entry; its seed (in the new URI)
    // unlocks it.
    let seed = seed_from_uri(io.out_starting("otpauth://").expect("uri"));
    let (r, io) = fx.run(Command::List, &[recovery_pw], &[&fx.code(&seed)]);
    r.expect("list after import");
    assert_eq!(io.out, vec!["Restored".to_owned()]);
}
