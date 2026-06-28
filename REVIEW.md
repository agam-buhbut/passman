# State of the codebase

A consolidated review of `passman` across production-readiness, security,
performance, docs, and UX. The findings below come from a full read-only audit of
every Rust/Kotlin source file, with each serious finding adversarially verified
(several were refuted or downgraded). The remediation status section tracks what
has since been fixed.

## Verdict

This is a **well-engineered, security-conscious codebase** with a genuinely
strong cryptographic core — but, at the time of the review, it was **not
production-ready** as a multi-frontend product. There is **no confidentiality
break and no broken primitive.** The blockers were at the edges:
untrusted-input handling, one data-loss bug, an Android main-thread hang, zero CI
coverage of the entire mobile surface, an unimplemented release/signing pipeline,
and frontend UX / zeroization gaps.

Totals at review time: **93 findings — 1 critical, 6 high, 20 medium, 48 low,
18 info.**

## Grades by area

| Area | Grade | One-line |
|------|-------|----------|
| Security / crypto | **C+** (core is A) | Sound primitives + zeroization discipline; let untrusted KDF cost params reach Argon2id; secret-scrub gaps at every frontend egress. |
| Prod-readiness | **D** | One data-loss bug; Android ANR; mobile entirely ungated in CI; release/signing was aspirational. |
| UX | **C** | CLI is shippable; cross-frontend product had data-loss onboarding traps and heavy re-auth friction. |
| Performance | **B+** | No measured hot paths; perf findings are all low/info (interactive scale). |
| Docs | **B** | Excellent code docs + README; some top-level docs over-promised (repro/signing/SBOM). |

## Real strengths (keep these)

- **Crypto:** XChaCha20-Poly1305 with a fresh 192-bit `OsRng` nonce per message
  (no reuse, verified at every call site); Argon2id v1.3; HKDF-SHA256 with a
  correct Extract-vs-Expand split; `subtle` constant-time compares; thorough
  `zeroize` with compile-time trait asserts; `#![forbid(unsafe_code)]`; known-
  answer tests against RFC vectors.
- **Parsers:** vault/recovery parsers are bounds-checked, panic-free,
  AEAD-AAD-bound, with no decryption oracle, fuzz targets, and arbitrary-prefix
  never-panic sweeps.
- **Concurrency:** the prior locked-loop deadlock is fixed and regression-tested;
  no lock is held across `recv()` in the worker; the clipboard is wiped on every
  exit path; poison-tolerant.
- **Storage:** `O_EXCL` temp + `0o600` + `sync_all` + rename atomic write, with
  an OS-random temp suffix.
- **Supply chain:** `deny.toml` (licenses/sources/yanked), `cargo-audit` +
  `cargo-deny`, Gradle wrapper pinned by SHA-256, no `curl | bash` install.

## Confirmed blockers (must fix before any GA)

| # | Sev | Finding | Location |
|---|-----|---------|----------|
| B1 | **critical** | `recovery::import()` ran Argon2id with attacker-controlled, **unbounded** m/t cost → pre-auth OOM/CPU DoS (fatal on Android). Same class (TOTP-gated, so medium) in vault unlock. | recovery/format.rs; crypto/kdf.rs; vault/vault.rs |
| B2 | **high** | Mutating a legacy **v0x01 vault corrupted its index** → permanently undecryptable (silent, irreversible data loss). | vault/vault.rs |
| B3 | **high** | Android `app.lock()` on `ON_STOP` blocked the **main thread** for a full in-flight op → ANR. UniFFI `call()` also held the inner mutex across the blocking `recv()`. | MainActivity.kt; uniffi/lib.rs |
| B4 | **high** | CI had **no Android build, no cross-compile, no instrumented tests** — the whole mobile/HSM/FFI surface was unverified. | .github/workflows/ci.yml |
| B5 | **high** | **No release/signing/publishing pipeline**; README "Verify your download" + RELEASE.md referenced placeholder keys and artifacts that don't exist. | RELEASE.md; README.md |
| B6 | **high** (systemic) | **Zeroization evaporated at every frontend egress**: non-volatile `arr.fill(0)`, un-zeroized UniFFI `Vec`, Kotlin `ByteArray`/`String`, GTK widget buffers. | app.rs; uniffi/lib.rs; KeystoreBridgeImpl.kt; gtk/ui.rs |
| B7 | **high** (UX) | **No recovery/backup UI** in GTK/Android and onboarding never prompted to make one → silent permanent data loss. | gtk/ui.rs; MainActivity.kt |
| B8 | **high** (UX) | **TOTP enrollment never verified** at creation; GTK auto-hid the one-time URI in 10 s and pointed at a nonexistent "Done" button. | gtk/ui.rs; MainActivity.kt |

### Refuted / over-stated by verification (no action beyond a pinning test/comment)

Lockout forward-clock "bypass" (intended, documented); tss-esapi intermediate
zeroization (already handled); HKDF `unreachable!()` panic risk (statically
sound); `estimate_master` user-inputs (works as designed); detached-worker
`K_master` residency (bounded, documented).

## Remediation status

The review's blockers and high/medium findings are being addressed on branch
**`fix/full-remediation`**, organized into the sector passes below. Summary of the
landed commits (`git log cee7f55..HEAD`):

| Commit | Sector | What landed |
|--------|--------|-------------|
| `6f8e126` | Sec 1 | Bound Argon2 cost (**B1**) + fix v0x01 index corruption (**B2**). |
| `1f634b0` | Sec 1 | Atomic `Settings::save`, directory permissions, HSM hardening. |
| `612ea2a` | Sec 1 | Volatile zeroize, redacted `ClipboardCookie` `Debug`, lockout/KDF guards (**B6**). |
| `39742a3` | Sec 2 | Gate the Android surface in CI, harden CI + supply chain (**B4**). |
| `abc580e` | Sec 3 | CLI interrupt-safe clipboard, `0600` recovery export, distinct exit codes, non-blocking lock (**B3** CLI side). |
| `da5accd` | Sec 3 | GTK: clear add-form, surface dead-channel, Enter-to-submit, accessibility, UX. |
| `b86f8a9` | Sec 3 | Android: off-main-thread lock/open (**B3**), scrub-on-throw (**B6**), mobile KDF default, QR, UX. |

Status by blocker:

- **B1, B2** — fixed (`6f8e126`); anti-DoS KDF ceiling enforced at both parser
  boundaries (see `architecture.md` §4.8).
- **B3** — fixed across CLI/Android/UniFFI (`abc580e`, `b86f8a9`).
- **B4** — fixed (`39742a3`): Android cross-compile, UniFFI bindgen check,
  `assembleDebug` + lint, and an emulator instrumented-test lane.
- **B5** — in progress: a tag-triggered build/checksum/SBOM skeleton now exists
  (`.github/workflows/release.yml`), and the docs are reconciled to mark
  verification "planned — no signed release published yet". Generating and
  publishing real signing keys remains the outstanding manual, air-gapped step.
- **B6** — addressed where feasible (`612ea2a`, `b86f8a9`); genuinely
  unavoidable JVM/FFI residuals are documented as accepted rather than claimed
  scrubbed.
- **B7, B8** (UX) — GTK/Android UX work landed in `da5accd` / `b86f8a9`; full
  recovery-backup UI and a TOTP-confirm-at-creation step across all frontends
  remain tracked follow-ups.

Docs (this pass) have been reconciled to the actual code: `architecture.md`
§9.4/§9.5, `README.md`, and `docs/RELEASE.md` no longer over-promise on
reproducibility, signing, or SBOM, and `docs/DEPENDENCIES.md` now justifies every
dependency.
