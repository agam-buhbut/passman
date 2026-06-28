# passman

A **local-only, hardware-backed password manager**. Your vault never leaves your
device — no cloud, no account, no network. Unlocking requires **two things you
control plus a one-time code**:

1. your **master password** (something you know),
2. a key held in your device's **hardware security module** — a TPM on Linux, the
   hardware-backed Keystore on Android (something your device holds), and
3. a **TOTP code** from your authenticator app at each unlock (a liveness gate).

Neither the master password nor the hardware key alone can open the vault, and
the encrypted vault file on disk reveals nothing about your entries — not even
their names.

It comes in three front-ends sharing one audited Rust core:

| App | Platform | Binary / package |
|-----|----------|------------------|
| **CLI** (`passman`) | Linux | `cargo build -p passman-cli` |
| **Desktop** (`passman-gtk`) | Linux (GTK4) | `cargo build -p passman-gtk` |
| **Mobile** | Android (Jetpack Compose) | `android/` Gradle project |

> For the full threat model and cryptographic design, see
> [`architecture.md`](architecture.md).

---

## Quickstart (CLI)

```console
$ passman init                 # create a vault; prints a TOTP setup link
New master password: ********
Confirm: ********
Add this TOTP secret to your authenticator app NOW — it is shown only once:
otpauth://totp/passman?secret=JBSWY3DPEHPK3PXP&...
Vault created at ~/.local/share/passman/vault.pmv.

$ passman add github           # add an entry (prompts for the fields)
Master password: ********
TOTP code: 042591
Username: octocat
Password: ********
…
Added "github".

$ passman list
github

$ passman get github           # copy the password to the clipboard for 30 s
Master password: ********
TOTP code: 558320
Copied to the clipboard; it will be cleared in 30 s.

$ passman gen --length 32      # generate a password (no vault needed)
```

Run `passman --help` or `passman <command> --help` for everything else
(`rm`, `export`, `import`, `passwd`, `--show`, `--field`, …).

---

## Install / build

You need **Rust ≥ 1.95** (`rustup` recommended). Everything builds from this repo.

### Quick install (Linux) — one command

```console
./install.sh              # builds + installs the CLI and the desktop app
./install.sh --cli-only   # just the `passman` command-line tool
```

`install.sh` checks for the Rust toolchain and (for the GUI) the GTK 4 libraries,
builds release binaries, installs them to `~/.local/bin` (no root), and adds a
desktop launcher. Then:

```console
passman init              # create your vault (prints a one-time TOTP setup link)
```

Prefer to build by hand, or building one component? The per-component steps
follow.

### CLI

```console
cargo build --release -p passman-cli
./target/release/passman --help
```

The CLI uses your **TPM 2.0** by default. If your user can't access the TPM
(e.g. you're not in the `tss` group) or the machine has none, add
`--allow-software-hsm` to fall back to the OS keyring (GNOME Keyring / KWallet) —
this is weaker (no hardware lockout against guessing) and is reported as such.

### Desktop (GTK4)

Build-time system libraries are required:

```console
# Debian / Ubuntu
sudo apt install libgtk-4-dev

cargo build --release -p passman-gtk
./target/release/passman-gtk            # or: passman-gtk --allow-software-hsm
```

The desktop app creates and unlocks vaults entirely in-app (no CLI needed): on
first run it shows a **Create vault** screen; afterwards it shows **Unlock**.

### Android

You need the Android SDK + NDK and [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk)
(`cargo install cargo-ndk`).

```console
# 1. Cross-compile the Rust core for the Android ABIs
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs \
    build -p passman-uniffi --release

# 2. Generate the Kotlin bindings
cargo build -p passman-uniffi
cargo run -p passman-uniffi --features bindgen --bin uniffi-bindgen -- generate \
    --library target/debug/libpassman_uniffi.so --language kotlin \
    --out-dir android/app/src/main/kotlin

# 3. Build the APK
cd android && ./gradlew :app:assembleDebug     # or: gradle :app:assembleDebug
```

The phone app stores its vault in app-private storage and shows the TOTP setup
as a **scannable QR code** on vault creation.

---

## Verify your download

Release artifacts are published with a signed checksum file. **minisign is the
primary signature**; a GPG signature is also provided. Verify before installing:

```console
# 1. minisign (primary) — uses the published public key.
minisign -Vm SHA-256SUMS -P <passman minisign public key>
# 2. GPG (secondary) — after importing the published key.
gpg --verify SHA-256SUMS.asc SHA-256SUMS
# 3. confirm your file matches the signed checksums.
sha256sum --check SHA-256SUMS
```

The core binary is also **reproducible** — run `./reproduce.sh` and compare its
SHA-256 to the published one. Full signing/verification details, key
fingerprints, and the Android APK certificate pin are in
[`docs/RELEASE.md`](docs/RELEASE.md).

---

## Where your data lives

| Platform | Vault | Settings |
|----------|-------|----------|
| Linux | `$XDG_DATA_HOME/passman/vault.pmv` (default `~/.local/share/passman/`) | `$XDG_CONFIG_HOME/passman/settings.toml` |
| Windows | `%APPDATA%\passman\vault.pmv` | `%APPDATA%\passman\settings.toml` |
| Android | app-private `files/vault.pmv` | app-private `files/settings.toml` |

`settings.toml` is plaintext and holds **no secrets** — only non-sensitive
toggles (it's readable before unlock). Pass `--vault-dir <DIR>` (CLI/GTK) to use
a custom location.

---

## Backup & recovery

The hardware key is tied to *this* device. If you lose the device (or the TPM is
cleared), restore from a **recovery export** — an encrypted backup protected by
your master password alone:

```console
$ passman export my-backup.pmr     # asks for a fresh re-authentication
$ passman import my-backup.pmr     # restore onto a new device
```

Because a recovery file is guarded by the password only (no hardware key), it is
opened behind a deliberately heavy key-derivation step and is **refused unless
your master password is strong**. Keep the file somewhere safe — anyone who has
it and your password can read your vault. Changing your master password
invalidates older exports.

---

## Security at a glance

- **Local-only.** No sync, no telemetry, no network connections.
- **Two cryptographic factors** (master password + hardware key) gate the vault
  key; a **TOTP code** is a mandatory liveness check at unlock.
- **Sealed metadata.** An attacker with your vault file learns the entry *count*
  and file sizes, but no labels, fields, or which services you use.
- **Strong generation.** Defaults to 40-character passwords over the full
  printable-ASCII set with a live strength meter.
- **On-demand decryption + short sessions.** Entries are decrypted only when
  revealed/copied; the session locks itself quickly, and copied secrets are
  wiped from the clipboard after 30 s.

See [`architecture.md`](architecture.md) for the precise disclosure surface,
threat-coverage table, and key decisions.

---

## Known limitations

- **Linux is the primary desktop target.** A Windows GUI is planned (the core and
  paths already support Windows); iOS is deferred.
- **TPM access** on Linux may require adding your user to the `tss` group, or use
  `--allow-software-hsm`.
- The recovery export uses a 1 GiB key-derivation floor, so creating one is slow
  by design (a few seconds, once).
