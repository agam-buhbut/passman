# Release & signing runbook

> **Status: PLANNED — no signed release has been published yet.**
> No public signing keys, no `SHA-256SUMS`, and no signed artifacts exist at the
> time of writing. The minisign public key, GPG identity, and Android certificate
> fingerprint shown below are **placeholders**, and the verification commands
> cannot succeed until a first signed release ships. Everything here is the
> intended procedure, recorded so the pipeline is ready — not steps a downloader
> can run today. The tag-triggered build/checksum skeleton lives in
> [`.github/workflows/release.yml`](../.github/workflows/release.yml); the
> air-gapped signing steps below are deliberately *not* automated.

How a `passman` release is built, signed, and published so downloaders can verify
it. This is the supply-chain boundary against a malicious binary or a compromised
CI (`architecture.md` §9.2–9.5, threats #28–#30).

**Signing keys never touch CI.** Building is automated; signing is a manual,
air-gapped step. CI can verify and reproduce, but it cannot sign — so a CI
compromise cannot forge a release (threat #30).

---

## 0. One-time: generate the signing keys (air-gapped)

Do this once, on an offline machine; keep the secret keys offline (e.g. on
encrypted removable media), publish only the public keys.

```console
# minisign (Ed25519) — the PRIMARY signature; tiny verification surface.
minisign -G -p passman-minisign.pub -s passman-minisign.key

# GPG (Ed25519) — web-of-trust + signed git tags.
gpg --quick-generate-key 'passman releases <releases@passman.example>' ed25519 sign
gpg --armor --export <KEYID> > passman-gpg.pub
```

Publish, on the project site over HTTPS:
- `passman-minisign.pub` (the minisign public key),
- the GPG public key + its fingerprint,
- the Android APK signing certificate's SHA-256 (for TOFU + pinning — see §3).

---

## 1. Build the artifacts (reproducibly)

```console
# The core binary, byte-reproducibly (architecture.md §9.4).
./reproduce.sh            # prints the SHA-256 to compare against the published one

# Desktop + Android as needed.
cargo build --release -p passman-gtk
# Android APK: see README "Android"; sign with the upload/release keystore (§3).
```

CI runs the `build-twice` job on every push and PR: it checks out the repo
twice into separate directories, runs `SOURCE_DATE_EPOCH=1700000000 ./reproduce.sh`
in each, and fails the job if the two SHA-256 hashes differ. The published
expected hash is compared manually at release time.

## 2. Hash and sign (air-gapped)

Collect every artifact (`passman`, `passman-gtk`, `passman-<ver>.apk`, …) in one
directory, then:

```console
# A single signed checksum file covers every artifact.
sha256sum passman passman-gtk passman-*.apk > SHA-256SUMS

# PRIMARY: minisign over the checksum file (and, if you like, each artifact).
minisign -S -s passman-minisign.key -m SHA-256SUMS

# SECONDARY: detached GPG signature over the same file.
gpg --armor --detach-sign SHA-256SUMS          # -> SHA-256SUMS.asc
```

Publish alongside the artifacts: `SHA-256SUMS`, `SHA-256SUMS.minisig`,
`SHA-256SUMS.asc`. Sign the git release tag too: `git tag -s vX.Y.Z`.

## 3. Android APK signature

The APK carries an **APK Signature Scheme v3** signature (an installer
requirement); publish the signing **certificate's SHA-256** so installs can be
pinned (TOFU). Additionally publish a detached `minisign` + `GPG` signature over
the `.apk` for download-time verification, exactly like the desktop artifacts.

---

## 4. What a downloader runs to verify

This is the section mirrored in the README so users actually do it.

```console
# 1. minisign (primary) — needs only the published public key.
minisign -Vm SHA-256SUMS -P <contents-of-passman-minisign.pub>

# 2. GPG (secondary) — after importing the published public key.
gpg --verify SHA-256SUMS.asc SHA-256SUMS

# 3. Confirm the artifact you downloaded matches the signed checksums.
sha256sum --check SHA-256SUMS

# 4. (Android) confirm the APK's signing cert matches the published fingerprint.
apksigner verify --print-certs passman-<ver>.apk | grep SHA-256
```

All four must pass. A mismatch means the download was tampered with or
incomplete — do not install it.

---

## Boundary (be honest about what is guaranteed)

- **Reproducible under a fixed toolchain *and* environment:** the core CLI binary
  that `reproduce.sh` builds (`passman`), via the pinned toolchain +
  `Cargo.lock`/`--locked` + `codegen-units=1` + path remaps + `SOURCE_DATE_EPOCH`
  (architecture.md §9.4). The "same hash" promise is scoped to that environment:
  same pinned toolchain, same `Cargo.lock`, **and** the same system libraries and
  linker. The CLI links system `libtss2` / `libdbus` dynamically, so a different
  `libtss2`/`libdbus` version or a different linker can change the bytes — this is
  *not* an unconditional "any machine, same hash" claim. The CI `build-twice` job
  verifies exactly this same-environment determinism on each push.
- **NOT bit-reproducible:** the `.deb`/`.exe`/`.apk` wrappers, and the CLI binary
  *across differing build environments* (different system-library versions or
  linker). Cross-environment, host-independent reproducibility would require
  vendored deps + a pinned build container — both **planned, not yet implemented**
  (§9.4). This is an accepted boundary, documented so a wrapper-hash match is not
  over-trusted.
