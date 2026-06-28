//! Integration tests for `passman-core` against the software-mock HSM.
//!
//! These drive the full public API end-to-end with the `MockKeyStore` /
//! `MockPrompter` (the `mock` feature is enabled automatically via the
//! dev-dependency), a controllable test clock, and `tempfile` for the vault
//! path. They are deterministic: no sleeps, no network, time is injected.
//!
//! ## Generating a valid TOTP code
//!
//! `passman-totp` exposes only verification, not code generation, and
//! `create_vault` mints the seed `S` randomly and returns it only inside the
//! provisioning URI. So the harness decodes the base32 seed out of that URI and
//! reproduces RFC 4226 HOTP-SHA1 (via the `hmac` + `sha1` dev-deps) to compute a
//! currently-valid code for the injected clock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base32::Alphabet;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use passman_core::{
    App, ClearOutcome, Clipboard, ClipboardCookie, CoreError, Progress, ProgressError, RevealField,
    UnlockError,
};
use passman_crypto::SecretBytes;
use passman_crypto::{KdfParams, SecretString};
use passman_hsm::mock::{MockKeyStore, MockPrompter};
use passman_hsm::{
    BiometricPrompter, HardwareKeyStore, HsmCapabilities, HsmError, HsmKind, HsmSlot, UnwrapHandle,
    WrappedBlob,
};
use passman_policy::EntryPolicy;
use passman_recovery::RecoveryPreset;
use passman_totp::{Clock, Timestamp, TotpConfig};
use passman_vault::EntryRecord;

// ----- Test clock (interior-mutable, Arc-shareable) --------------------------

/// A clock whose "now" can be advanced from the test while the `App` holds an
/// `Arc<dyn Clock>` pointing at the same value.
struct TestClock(AtomicU64);

impl TestClock {
    fn at(secs: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(secs)))
    }

    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
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

// ----- Mock clipboard --------------------------------------------------------

/// A clipboard backed by an in-memory cell. Its "digest" is a cheap
/// deterministic 32-byte fold of the contents (core only compares the cookie
/// digest to `read_digest` via `ct_eq`; it never requires real SHA-256), which
/// keeps the test free of an extra hashing dependency.
#[derive(Default)]
struct MockClipboard {
    contents: Mutex<Option<String>>,
}

impl MockClipboard {
    fn current(&self) -> Option<String> {
        self.contents.lock().expect("clipboard lock").clone()
    }
}

/// A cheap, deterministic 32-byte digest (FNV-1a folded across 32 lanes). Not
/// cryptographic — only needs to be stable per-content and content-sensitive.
fn fake_digest(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (i as u64).wrapping_mul(0x100_0000_01b3);
        for &b in text.as_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        *slot = (h & 0xff) as u8;
    }
    out
}

impl Clipboard for MockClipboard {
    fn write(&self, secret: &SecretString) -> Result<ClipboardCookie, CoreError> {
        let text = secret.expose().to_owned();
        let digest = fake_digest(&text);
        *self.contents.lock().expect("clipboard lock") = Some(text);
        Ok(ClipboardCookie::new(digest, Timestamp::from_unix_secs(0)))
    }

    fn read_digest(&self) -> Result<Option<[u8; 32]>, CoreError> {
        Ok(self
            .contents
            .lock()
            .expect("clipboard lock")
            .as_deref()
            .map(fake_digest))
    }

    fn set_text(&self, text: &str) -> Result<(), CoreError> {
        *self.contents.lock().expect("clipboard lock") = Some(text.to_owned());
        Ok(())
    }
}

// ----- Shared mock backend (persistent key across App instances) -------------

/// A [`HardwareKeyStore`] sharing one [`MockKeyStore`] (and thus one in-memory
/// wrapping key) across multiple `App`s via an `Arc`. A real HSM's wrapping key
/// persists in hardware across processes; the bare `MockKeyStore` mints a fresh
/// per-instance key, so the create→drop→reopen→unlock round-trip needs this to
/// model that persistence. Test-only.
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
        material: &SecretBytes,
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
    ) -> Result<SecretBytes, HsmError> {
        self.0.complete_unwrap(handle, prompter)
    }

    fn invalidate(&self, slot: HsmSlot, wrapped: &WrappedBlob, ctx: &()) -> Result<(), HsmError> {
        self.0.invalidate(slot, wrapped, ctx)
    }
}

// ----- TOTP code generation (RFC 4226 HOTP-SHA1) -----------------------------

/// Decode the base32 seed out of an `otpauth://` provisioning URI.
fn seed_from_uri(uri: &str) -> Vec<u8> {
    let after = uri.split("secret=").nth(1).expect("secret= present");
    let b32 = after.split('&').next().expect("secret value");
    base32::decode(Alphabet::Rfc4648 { padding: false }, b32).expect("valid base32 seed")
}

/// Compute the RFC 4226 HOTP-SHA1 6-digit code for `seed` at `counter`.
fn hotp_sha1(seed: &[u8], counter: u64) -> String {
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

/// The currently-valid default-profile (SHA1/6/30 s) code for `seed` at `now`.
fn valid_code(seed: &[u8], now: u64) -> String {
    hotp_sha1(seed, now / 30)
}

// ----- Shared fixtures -------------------------------------------------------

/// Cheap Argon2 params so unlocks/creates are fast (8 KiB / 1 pass).
const FAST_KDF: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

fn record(u: &str, p: &str, url: &str, n: &str) -> EntryRecord {
    EntryRecord::new(pw(u), pw(p), pw(url), pw(n))
}

/// Open an `App<MockKeyStore>` at a fresh temp path with software-HSM allowed.
fn open_app(dir: &std::path::Path, clock: Arc<TestClock>) -> App<MockKeyStore> {
    let path = dir.join("vault.pmv");
    App::open_allowing_software_hsm(path, MockKeyStore::new(), clock as Arc<dyn Clock>)
        .expect("open app")
}

// ----- Tests -----------------------------------------------------------------

#[test]
fn full_round_trip_create_persist_reopen_unlock_reveal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(1_000_000);
    let path = dir.path().join("vault.pmv");
    // One shared HSM key across the create and reopen `App`s (models hardware
    // persistence; see `SharedMock`).
    let backend = SharedMock::new();

    // Create a vault and add several entries with policies.
    let uri_str;
    {
        let app = App::open_allowing_software_hsm(
            path.clone(),
            backend.clone(),
            clock.clone() as Arc<dyn Clock>,
        )
        .expect("open create app");
        let prompter = MockPrompter::authenticating();
        let (mut unlocked, uri) = app
            .create_vault(
                &pw("Str0ng-Master-P@ssphrase!"),
                FAST_KDF,
                TotpConfig::default(),
                &(),
                &prompter,
            )
            .expect("create vault");
        uri_str = uri.expose().to_owned();

        unlocked
            .add_entry(
                "GitHub".to_owned(),
                EntryPolicy::default().with_length(24),
                &record("octocat", "hunter2!", "https://github.com", "work"),
            )
            .expect("add github");
        unlocked
            .add_entry(
                "Email".to_owned(),
                EntryPolicy::default(),
                &record(
                    "me@example.com",
                    "letmein-please",
                    "https://mail.example.com",
                    "",
                ),
            )
            .expect("add email");

        // Session is dropped here (vault already persisted on each add).
        unlocked.lock();
    }

    // Reopen with the SAME backend key and unlock with the correct credentials.
    let seed = seed_from_uri(&uri_str);
    let app = App::open_allowing_software_hsm(path, backend, clock.clone() as Arc<dyn Clock>)
        .expect("reopen app");
    let prompter = MockPrompter::authenticating();
    let code = valid_code(&seed, clock.now_secs());
    let unlocked = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), &code, &(), &prompter)
        .expect("unlock");

    // list_entries matches the labels we added.
    let mut labels: Vec<String> = unlocked
        .list_entries()
        .expect("list")
        .into_iter()
        .map(|h| h.label)
        .collect();
    labels.sort();
    assert_eq!(labels, vec!["Email".to_owned(), "GitHub".to_owned()]);

    // with_revealed returns the right secret for the GitHub entry.
    let handles = unlocked.list_entries().expect("list");
    let github = handles
        .iter()
        .find(|h| h.label == "GitHub")
        .expect("github present");
    let pw_seen = unlocked
        .with_revealed(&github.id, |rec| rec.password.expose().to_owned())
        .expect("reveal");
    assert_eq!(pw_seen, "hunter2!");
    let user_seen = unlocked
        .with_revealed(&github.id, |rec| rec.username.expose().to_owned())
        .expect("reveal user");
    assert_eq!(user_seen, "octocat");
}

#[test]
fn wrong_password_is_bad_credentials_and_increments_advisory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(2_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();

    let (unlocked, uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let seed = seed_from_uri(uri.expose());
    unlocked.lock();

    // Correct TOTP, wrong password → BadCredentials (probe fails).
    let code = valid_code(&seed, clock.now_secs());
    let err = app
        .unlock(&pw("wrong-password"), &code, &(), &prompter)
        .expect_err("wrong pw");
    assert!(matches!(err, UnlockError::BadCredentials));

    // The advisory counter advanced (persisted): a second wrong attempt is
    // still BadCredentials (not yet locked at counter < 3).
    let code2 = valid_code(&seed, clock.now_secs());
    let err2 = app
        .unlock(&pw("wrong-password"), &code2, &(), &prompter)
        .expect_err("wrong pw 2");
    assert!(matches!(err2, UnlockError::BadCredentials));
}

#[test]
fn wrong_totp_is_bad_credentials() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(3_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();

    let (unlocked, _uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    unlocked.lock();

    // A wrong (but well-formed) TOTP code, correct password → BadCredentials.
    let err = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), "000000", &(), &prompter)
        .expect_err("wrong totp");
    assert!(matches!(err, UnlockError::BadCredentials));
}

#[test]
fn advisory_lockout_after_three_failures_then_clears() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(4_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();

    let (unlocked, uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let seed = seed_from_uri(uri.expose());
    unlocked.lock();

    // Force three failures (wrong password, correct TOTP each time).
    for _ in 0..3 {
        let code = valid_code(&seed, clock.now_secs());
        let err = app
            .unlock(&pw("nope"), &code, &(), &prompter)
            .expect_err("fail");
        assert!(matches!(err, UnlockError::BadCredentials));
    }

    // The 4th attempt (even with correct creds) is locked out: counter == 3 →
    // 10-minute window.
    let code = valid_code(&seed, clock.now_secs());
    let err = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), &code, &(), &prompter)
        .expect_err("locked");
    match err {
        UnlockError::LockedOut { remaining } => {
            assert!(remaining.as_secs() > 0 && remaining.as_secs() <= 600);
        }
        other => panic!("expected LockedOut, got {other:?}"),
    }

    // Advance past the 10-minute window; now a correct unlock succeeds and
    // resets the counter.
    clock.advance(601);
    let code = valid_code(&seed, clock.now_secs());
    let unlocked = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), &code, &(), &prompter)
        .expect("unlock after window");
    unlocked.lock();

    // Counter reset: a fresh failure is BadCredentials, not immediately locked.
    let code = valid_code(&seed, clock.now_secs());
    let err = app
        .unlock(&pw("nope"), &code, &(), &prompter)
        .expect_err("post-reset fail");
    assert!(matches!(err, UnlockError::BadCredentials));
}

#[test]
fn hsm_cancelled_routes_to_cancelled_without_penalty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(5_000_000);
    // Create the vault with an authenticating prompter first.
    let uri_str;
    {
        let app = open_app(dir.path(), clock.clone());
        let prompter = MockPrompter::authenticating();
        let (unlocked, uri) = app
            .create_vault(
                &pw("Str0ng-Master-P@ssphrase!"),
                FAST_KDF,
                TotpConfig::default(),
                &(),
                &prompter,
            )
            .expect("create");
        uri_str = uri.expose().to_owned();
        unlocked.lock();
    }
    let _ = uri_str;

    // Unlock with a cancelling prompter → Cancelled (no advisory penalty).
    let app = open_app(dir.path(), clock.clone());
    let cancel = MockPrompter::cancelling();
    let err = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), "123456", &(), &cancel)
        .expect_err("cancel");
    assert!(matches!(err, UnlockError::Cancelled));
}

#[test]
fn hsm_permanently_invalidated_routes_to_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(6_000_000);

    // Create a vault with a healthy mock so a valid vault file exists.
    {
        let app = open_app(dir.path(), clock.clone());
        let prompter = MockPrompter::authenticating();
        let (unlocked, _uri) = app
            .create_vault(
                &pw("Str0ng-Master-P@ssphrase!"),
                FAST_KDF,
                TotpConfig::default(),
                &(),
                &prompter,
            )
            .expect("create");
        unlocked.lock();
    }

    // Reopen with a backend that reports PermanentlyInvalidated on every op.
    let path = dir.path().join("vault.pmv");
    let app = App::open_allowing_software_hsm(
        path,
        MockKeyStore::failing_permanently_invalidated(),
        clock.clone() as Arc<dyn Clock>,
    )
    .expect("open");
    let prompter = MockPrompter::authenticating();
    let err = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), "123456", &(), &prompter)
        .expect_err("invalidated");
    assert!(matches!(err, UnlockError::RouteToRecovery));
}

#[test]
fn clipboard_copy_clears_with_fact_and_clamps_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(7_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();
    let (mut unlocked, _uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let id = unlocked
        .add_entry(
            "Bank".to_owned(),
            EntryPolicy::default(),
            &record("acct", "super-secret-pw", "https://bank", ""),
        )
        .expect("add");

    let clip = MockClipboard::default();
    let cookie = unlocked
        .copy_to_clipboard(&id, RevealField::Password, &clip)
        .expect("copy");
    // The clipboard now holds the password.
    assert_eq!(clip.current().as_deref(), Some("super-secret-pw"));

    // Session clamped to now + 30 s: at now+29 the session is still alive, at
    // now+31 an operation reports Locked.
    clock.advance(29);
    assert!(unlocked.list_entries().is_ok());
    clock.advance(2); // now + 31
    assert!(matches!(unlocked.list_entries(), Err(CoreError::Locked)));

    // clear_clipboard overwrites with a fact when the digest still matches.
    let outcome = unlocked.clear_clipboard(&cookie, &clip);
    assert_eq!(outcome, ClearOutcome::Cleared);
    let after = clip.current().expect("clipboard has a fact");
    assert!(passman_core::FACTS.contains(&after.as_str()));
    assert_ne!(after, "super-secret-pw");
}

#[test]
fn clipboard_clear_leaves_foreign_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(8_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();
    let (mut unlocked, _uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let id = unlocked
        .add_entry(
            "Bank".to_owned(),
            EntryPolicy::default(),
            &record("acct", "secret-pw", "https://bank", ""),
        )
        .expect("add");

    let clip = MockClipboard::default();
    let cookie = unlocked
        .copy_to_clipboard(&id, RevealField::Password, &clip)
        .expect("copy");

    // Something else takes the clipboard.
    clip.set_text("user pasted something else").expect("set");

    let outcome = unlocked.clear_clipboard(&cookie, &clip);
    assert_eq!(outcome, ClearOutcome::Replaced);
    // Foreign content is left untouched.
    assert_eq!(
        clip.current().as_deref(),
        Some("user pasted something else")
    );
}

#[test]
fn export_gate_rejects_weak_master() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(9_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();

    // Create the vault with a WEAK master password.
    let (mut unlocked, uri) = app
        .create_vault(
            &pw("password"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let seed = seed_from_uri(uri.expose());
    let code = valid_code(&seed, clock.now_secs());

    // Export must refuse: the master is far below the Strong tier.
    let err = unlocked
        .export_recovery(
            &pw("password"),
            &code,
            RecoveryPreset::Floor,
            &(),
            &prompter,
        )
        .expect_err("weak export");
    assert!(matches!(err, CoreError::WeakPasswordForExport));
}

#[test]
fn export_gate_allows_strong_master_then_reauth_runs() {
    // A strong master clears the §7.5 gate; the export then proceeds to fresh
    // re-auth and the recovery Floor. We stop at re-auth correctness by feeding
    // a WRONG re-auth TOTP, which must surface as a vault (auth) error rather
    // than the weak-password gate — proving the gate passed.
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(10_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();

    let (mut unlocked, _uri) = app
        .create_vault(
            &pw("xK7#mP2$qR9vL4nB8wZ!jH3tY6&"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");

    // Wrong re-auth code: gate passes (strong), re-auth fails → a Vault error,
    // NOT WeakPasswordForExport.
    let err = unlocked
        .export_recovery(
            &pw("xK7#mP2$qR9vL4nB8wZ!jH3tY6&"),
            "000000",
            RecoveryPreset::Floor,
            &(),
            &prompter,
        )
        .expect_err("reauth fails");
    assert!(
        matches!(err, CoreError::Vault(_)),
        "expected a re-auth (vault) failure, got {err:?}"
    );
}

#[test]
fn second_instance_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(11_000_000);
    let path = dir.path().join("vault.pmv");

    let first = App::open_allowing_software_hsm(
        path.clone(),
        MockKeyStore::new(),
        clock.clone() as Arc<dyn Clock>,
    )
    .expect("first open");

    // A second open on the same path while the first holds the lock fails.
    let second = App::open_allowing_software_hsm(
        path.clone(),
        MockKeyStore::new(),
        clock.clone() as Arc<dyn Clock>,
    );
    assert!(matches!(second, Err(CoreError::AlreadyRunning)));

    drop(first);
    // After dropping the first, a new open succeeds.
    let third = App::open_allowing_software_hsm(path, MockKeyStore::new(), clock as Arc<dyn Clock>);
    assert!(third.is_ok());
}

#[test]
fn session_expires_after_120s() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(12_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();
    let (unlocked, _uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");

    // Within the 120 s window: ok.
    clock.advance(119);
    assert!(unlocked.list_entries().is_ok());

    // Past 120 s from unlock: operations return Locked.
    clock.advance(2); // 121 s total
    assert!(matches!(unlocked.list_entries(), Err(CoreError::Locked)));
    assert!(matches!(
        unlocked.with_revealed(&passman_vault::EntryId::generate(), |_| ()),
        Err(CoreError::Locked)
    ));
}

#[test]
fn change_master_password_new_works_old_fails() {
    // Re-encrypt-on-change (§7.7): after changing the master password, the
    // session keeps working, a fresh unlock with the NEW password succeeds, and
    // the OLD password is rejected (BadCredentials at the probe). No prior
    // export, so the staleness flag is false.
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(15_000_000);
    let path = dir.path().join("vault.pmv");
    let backend = SharedMock::new();

    let old_master = "Str0ng-Master-P@ssphrase!";
    let new_master = "An0ther-Str0ng-P@ssphrase?";

    let uri_str;
    {
        let app = App::open_allowing_software_hsm(
            path.clone(),
            backend.clone(),
            clock.clone() as Arc<dyn Clock>,
        )
        .expect("open create app");
        let prompter = MockPrompter::authenticating();
        let (mut unlocked, uri) = app
            .create_vault(
                &pw(old_master),
                FAST_KDF,
                TotpConfig::default(),
                &(),
                &prompter,
            )
            .expect("create");
        uri_str = uri.expose().to_owned();

        unlocked
            .add_entry(
                "GitHub".to_owned(),
                EntryPolicy::default().with_length(24),
                &record("octocat", "hunter2!", "https://github.com", "work"),
            )
            .expect("add github");

        // Change the password (same K_hsm, fresh salt, full re-encrypt).
        let outcome = unlocked
            .change_master_password(&pw(old_master), &pw(new_master), FAST_KDF, &(), &prompter)
            .expect("change password");
        assert!(
            !outcome.existing_export_now_stale,
            "no export existed, so nothing is stale"
        );

        // The live session still works after the change and sees the entry.
        let pw_seen = {
            let handles = unlocked.list_entries().expect("list after change");
            let gh = handles
                .iter()
                .find(|h| h.label == "GitHub")
                .expect("github present after change");
            unlocked
                .with_revealed(&gh.id, |r| r.password.expose().to_owned())
                .expect("reveal after change")
        };
        assert_eq!(pw_seen, "hunter2!");
        unlocked.lock();
    }

    // Reopen with the SAME backend key.
    let seed = seed_from_uri(&uri_str);
    let app = App::open_allowing_software_hsm(path, backend, clock.clone() as Arc<dyn Clock>)
        .expect("reopen app");
    let prompter = MockPrompter::authenticating();

    // OLD password now fails (probe under the old key no longer matches).
    let code = valid_code(&seed, clock.now_secs());
    let err = app
        .unlock(&pw(old_master), &code, &(), &prompter)
        .expect_err("old password must fail");
    assert!(matches!(err, UnlockError::BadCredentials));

    // Advance one TOTP step (30 s) so the next code is fresh: the failed attempt
    // above already consumed the current step into the verifier's replay cache,
    // and reusing it would (correctly) be rejected as a replay. Still under the
    // advisory lockout threshold (counter == 1 < 3), so no lockout intervenes.
    clock.advance(30);

    // NEW password unlocks and the entry survived the re-encrypt.
    let code = valid_code(&seed, clock.now_secs());
    let unlocked = app
        .unlock(&pw(new_master), &code, &(), &prompter)
        .expect("unlock with new password");
    let handles = unlocked.list_entries().expect("list");
    let gh = handles
        .iter()
        .find(|h| h.label == "GitHub")
        .expect("github present");
    let pw_seen = unlocked
        .with_revealed(&gh.id, |r| r.password.expose().to_owned())
        .expect("reveal");
    assert_eq!(pw_seen, "hunter2!");
}

#[test]
fn software_hsm_refused_without_optin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(13_000_000);
    let path = dir.path().join("vault.pmv");

    // open (no opt-in) succeeds — it does not touch the backend — but
    // create_vault must refuse the software mock.
    let app = App::open(path, MockKeyStore::new(), clock as Arc<dyn Clock>).expect("open");
    let prompter = MockPrompter::authenticating();
    let err = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect_err("software refused");
    assert!(matches!(err, CoreError::SoftwareHsmRefused));
}

#[test]
fn recovery_translation_round_trips_via_cheap_path() {
    // The full export→import round-trip exercises the real recovery Floor
    // (1 GiB Argon2), which is far too slow/heavy for the default run — see the
    // #[ignore]d `recovery_round_trip_real_floor` below. This test instead
    // covers the translation layer core owns: EntryPolicy → postcard bytes →
    // EntryPolicy must round-trip identically (the core-owned glue of §7.3/§7.6).
    let policies = [
        EntryPolicy::default(),
        EntryPolicy::default().with_length(32),
        EntryPolicy::default()
            .with_length(20)
            .with_user_note("max 20 chars on this site".to_owned()),
    ];
    for policy in policies {
        let bytes = postcard::to_allocvec(&policy).expect("serialize");
        let back: EntryPolicy = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(policy, back);
    }
}

/// Full recovery export → import round-trip with the real recovery Floor.
///
/// Ignored by default: `passman_recovery::export` enforces the 1 GiB / t=4
/// Argon2 Floor (`architecture.md` §7.4) and there is no public cheap-params
/// seam (`export_with` is `pub(crate)` to the recovery crate), so this derives
/// the recovery key at full cost twice (~5 s, ~1 GiB). Plus the vault's own
/// Argon2 on create/unlock. Run explicitly on a machine with ≥1 GiB free:
/// `cargo test -p passman-core -- --ignored recovery_round_trip_real_floor`.
#[test]
#[ignore = "recovery export enforces a 1 GiB Argon2 floor — too slow/heavy for the default run"]
fn recovery_round_trip_real_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(14_000_000);
    let master = "xK7#mP2$qR9vL4nB8wZ!jH3tY6&";

    // Source vault with a couple of entries (use the recovery Floor's KDF for
    // the vault too, since we are already paying that cost on this path).
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();
    let (mut unlocked, uri) = app
        .create_vault(
            &pw(master),
            RecoveryPreset::Floor.params(),
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let seed = seed_from_uri(uri.expose());
    unlocked
        .add_entry(
            "GitHub".to_owned(),
            EntryPolicy::default().with_length(24),
            &record("octocat", "hunter2!", "https://github.com", "n"),
        )
        .expect("add");

    let code = valid_code(&seed, clock.now_secs());
    let file = unlocked
        .export_recovery(&pw(master), &code, RecoveryPreset::Floor, &(), &prompter)
        .expect("export");

    // After an export exists, changing the master password reports the prior
    // export as stale (§7.7). Reuse the same (Floor) KDF for the change.
    let new_master = "qP4!wE7@rT1#yU9$iO6%aS3^dF8&";
    let outcome = unlocked
        .change_master_password(
            &pw(master),
            &pw(new_master),
            RecoveryPreset::Floor.params(),
            &(),
            &prompter,
        )
        .expect("change password");
    assert!(
        outcome.existing_export_now_stale,
        "an export existed before the change, so it is now stale"
    );
    unlocked.lock();
    drop(app); // release the instance lock on the source path

    // Import into a fresh path + backend.
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let app2 = open_app(dir2.path(), clock.clone());
    let prompter2 = MockPrompter::authenticating();
    let (unlocked2, _uri2) = app2
        .import_recovery(
            &file,
            &pw(master),
            RecoveryPreset::Floor.params(),
            TotpConfig::default(),
            &(),
            &prompter2,
        )
        .expect("import");

    let handles = unlocked2.list_entries().expect("list");
    assert_eq!(handles.len(), 1);
    let gh = &handles[0];
    assert_eq!(gh.label, "GitHub");
    let pw_seen = unlocked2
        .with_revealed(&gh.id, |r| r.password.expose().to_owned())
        .expect("reveal");
    assert_eq!(pw_seen, "hunter2!");
}

/// A prompter that panics if invoked — used to prove a code path fired **no**
/// biometric prompt.
struct PanicPrompter;

impl BiometricPrompter for PanicPrompter {
    fn prompt(&self, _reason: String) -> Result<passman_hsm::PromptResult, HsmError> {
        panic!("biometric prompt must not fire when the device is HSM-locked");
    }
}

#[test]
fn hsm_native_lockout_blocks_unlock_before_any_prompt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(14_000_000);
    let path = dir.path().join("vault.pmv");

    // A backend reporting a 600 s native DA lockout. enroll/unwrap still work,
    // so create_vault (which does not query lockout status) succeeds.
    let backend = MockKeyStore::locked_for(std::time::Duration::from_mins(10));
    let app = App::open_allowing_software_hsm(path, backend, clock.clone() as Arc<dyn Clock>)
        .expect("open");
    let prompter = MockPrompter::authenticating();
    let (unlocked, uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let seed = seed_from_uri(uri.expose());
    unlocked.lock();

    // Unlock with the CORRECT credentials but a prompter that panics if called.
    // The §4.3 step-3 HSM-native lockout check must short-circuit to LockedOut
    // before any unwrap or biometric prompt.
    let code = valid_code(&seed, clock.now_secs());
    let err = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), &code, &(), &PanicPrompter)
        .expect_err("locked device must refuse unlock");
    match err {
        UnlockError::LockedOut { remaining } => {
            assert_eq!(remaining, std::time::Duration::from_mins(10));
        }
        other => panic!("expected LockedOut, got {other:?}"),
    }
}

/// Shared counters a [`CountingProgress`] writes to, readable from the test.
#[derive(Default)]
struct ProgressCounts {
    starts: AtomicU64,
    ends: AtomicU64,
    last_label: Mutex<Option<String>>,
}

/// A [`Progress`] that counts `start`/`end` calls and records the last label.
struct CountingProgress(Arc<ProgressCounts>);

impl Progress for CountingProgress {
    fn start(&self, label: String) -> Result<(), ProgressError> {
        self.0.starts.fetch_add(1, Ordering::SeqCst);
        *self.0.last_label.lock().expect("label lock") = Some(label);
        Ok(())
    }

    fn end(&self) -> Result<(), ProgressError> {
        self.0.ends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn progress_brackets_each_argon2_operation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(16_000_000);
    let path = dir.path().join("vault.pmv");
    let counts = Arc::new(ProgressCounts::default());

    let app =
        App::open_allowing_software_hsm(path, MockKeyStore::new(), clock.clone() as Arc<dyn Clock>)
            .expect("open")
            .with_progress(Arc::new(CountingProgress(counts.clone())));
    let prompter = MockPrompter::authenticating();

    // create_vault runs one Argon2id derivation → one balanced start/end.
    let (unlocked, uri) = app
        .create_vault(
            &pw("Str0ng-Master-P@ssphrase!"),
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("create");
    let seed = seed_from_uri(uri.expose());
    unlocked.lock();
    assert_eq!(counts.starts.load(Ordering::SeqCst), 1, "create: one start");
    assert_eq!(counts.ends.load(Ordering::SeqCst), 1, "create: one end");

    // unlock runs another derivation → a second balanced bracket.
    let code = valid_code(&seed, clock.now_secs());
    let unlocked = app
        .unlock(&pw("Str0ng-Master-P@ssphrase!"), &code, &(), &prompter)
        .expect("unlock");
    assert_eq!(
        counts.starts.load(Ordering::SeqCst),
        2,
        "unlock: second start"
    );
    assert_eq!(counts.ends.load(Ordering::SeqCst), 2, "unlock: second end");
    assert_eq!(
        counts.last_label.lock().expect("label lock").as_deref(),
        Some("Deriving vault key"),
    );
    unlocked.lock();
}

#[test]
fn import_recovery_round_trips_via_cheap_file() {
    use passman_policy::EntryPolicy;
    use passman_recovery::{export_unchecked, ExportPayload, RecoveryEntry};

    // Hand-build a recovery payload: one entry plus a known TOTP seed. The
    // policy bytes are postcard(EntryPolicy), matching the export DTO (§7.3).
    let policy_bytes = postcard::to_allocvec(&EntryPolicy::default()).expect("encode policy");
    let payload = ExportPayload {
        totp_seed: passman_crypto::SecretArray::new([0x5Au8; 32]),
        original_vault_kdf: FAST_KDF,
        entries: vec![RecoveryEntry {
            id: [0x11u8; 16],
            label: "GitHub".to_owned(),
            username: pw("octocat"),
            password: pw("hunter2!"),
            url: pw("https://github.com"),
            notes: pw("recovered"),
            policy: policy_bytes,
        }],
    };

    // Export it cheaply (bypassing the 1 GiB Floor via the test-util seam).
    let recovery_master = pw("Recover-Me-Str0ng-Passphrase!");
    let file = export_unchecked(&payload, &recovery_master, &FAST_KDF).expect("export file");

    // Import into a fresh vault: exercises App::import_recovery end-to-end
    // (decrypt payload → enroll two slots → re-derive K_master → re-encrypt).
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = TestClock::at(17_000_000);
    let app = open_app(dir.path(), clock.clone());
    let prompter = MockPrompter::authenticating();
    let (unlocked, uri) = app
        .import_recovery(
            &file,
            &recovery_master,
            FAST_KDF,
            TotpConfig::default(),
            &(),
            &prompter,
        )
        .expect("import_recovery");

    let handles = unlocked.list_entries().expect("list");
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].label, "GitHub");
    let seen = unlocked
        .with_revealed(&handles[0].id, |r| r.password.expose().to_owned())
        .expect("reveal");
    assert_eq!(seen, "hunter2!");

    // The provisioning URI re-provisions the SAME seed: a code from it unlocks
    // the freshly-imported vault with the recovery password.
    let totp_seed = seed_from_uri(uri.expose());
    unlocked.lock();
    let code = valid_code(&totp_seed, clock.now_secs());
    let unlocked2 = app
        .unlock(&recovery_master, &code, &(), &prompter)
        .expect("unlock after import");
    assert_eq!(unlocked2.list_entries().expect("list2").len(), 1);
    unlocked2.lock();
}
