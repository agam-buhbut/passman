# passman App Shells — Implementation Plan

> **For agentic workers:** Execute task-by-task with TDD (failing test → run → implement → run → commit). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn the verified 7-crate security core into genuinely-runnable, test-verified applications: a CLI, a Linux GTK4 desktop app, and an Android app — plus the shared glue and "as-written" hardening the spec (`architecture.md`) requires.

**Architecture:** Build only on `passman-core`'s public API (no shell reaches past core, §2.3). A new `passman-platform` crate owns per-platform paths + `settings.toml` (keeping core path-agnostic). Binaries (`passman-cli`, `passman-gtk`) and the `passman-uniffi`/Android layer consume core + platform.

**Tech Stack:** Rust (existing core), `toml`/`directories` (platform), `clap`/`arboard`/`rpassword`/`anyhow` (cli), `gtk4` (gtk), `uniffi` 0.28 + Kotlin/Compose (android), `cargo-fuzz` (hardening).

**Ratified decisions (user-approved 2026-06-16):**
- **Progress** trait added (no-op `NoProgress` default, injected via new `App::open_with_progress`); `start`/`end` bracket Argon2 in core's public methods. **Spawner: dropped** — redundant in a synchronous core whose shell already off-threads `unlock` (§2.5). Conscious deviation from §2.5's literal wording; re-addable later (no format impact).
- **HSM lockout-status (§4.3 step 3):** defaulted `lockout_status() -> HsmLockoutStatus` on `HardwareKeyStore` (`Available` default); checked pre-unwrap in `unlock`; mapped to existing `UnlockError::LockedOut`. Not a new security control — a real TPM DA-lockout already fails closed via `tpm2.rs` `TPM_RC_LOCKOUT → Transient`; this is proactive UX. No TODO shipped; tpm2 inherits the `Available` default and real lockouts still surface via the unwrap path.
- **MasterKey + EntryKey newtypes (§2.3):** both added in `passman-crypto` (transparent `Deref<Target = SecretArray<32>>`); threaded through core+vault. Mechanical test edits accepted.
- Linux HSM backend selection follows §6.2: TPM2 primary → SecretService fallback → software mock refused unless opted in. This machine has `/dev/tpm0` + gnome-keyring, so both real backends are available.

---

## Phase roadmap (each phase = its own working, testable increment)

- **Phase 0 — Foundation glue** (this doc, detailed below): Progress, HSM lockout-status, MasterKey/EntryKey, recovery round-trip coverage, `passman-platform` (paths + settings.toml).
- **Phase 1 — CLI** (`passman-cli`): init/unlock/add/get/list/gen/export/import, real clipboard, hidden prompt. Integration-tested headlessly.
- **Phase 2 — Linux GTK4** (`passman-gtk`): unlock → list → reveal/copy → add/edit/gen → settings; live progress + timers. Needs `libgtk-4-dev`.
- **Phase 3 — Android** (`passman-uniffi` + `android/`): resumes the paused Android plan, Tasks 7–11.
- **Phase 4 — Hardening:** `cargo-fuzz` targets for vault+recovery parsers (§10), `cargo audit`/`deny`, CI workflow, boundary-grep gate.

Phase boundaries are review checkpoints (user's section-by-section style).

---

## Phase 0 task list

- **T0.1 — HSM lockout-status (§4.3 step 3):** `HsmLockoutStatus` enum + defaulted `lockout_status` trait method (Available default) + `pub use`; `unlock` pre-unwrap check → `UnlockError::LockedOut`; mock `locked()` ctor + core test. 0 existing tests break.
- **T0.2 — Progress (§2.5):** `passman-core/src/progress.rs` with `Progress`/`ProgressError`/`NoProgress`; `App::open_with_progress`; `progress` field; `start`/`end` bracket in `create_vault`/`unlock`/`import_recovery` and `UnlockedApp::{export_recovery, change_master_password}`; counting-mock test. 0 existing tests break.
- **T0.3 — MasterKey/EntryKey (§2.3):** newtypes in `passman-crypto`; `derive_master*` → `MasterKey`; `UnlockedApp.k_master: MasterKey`; vault `k_master: &MasterKey` on the ~11 fns; `EntryKey` at the `hkdf_expand` per-entry site in vault. Mechanical test edits.
- **T0.4 — Recovery coverage:** default-run core test of public `import_recovery` via the crate's cheap-Argon2 test seam; keep one `#[ignore]`d full create→export→import round-trip at the real Floor.
- **T0.5 — `passman-platform` crate:** XDG/APPDATA path resolution (§1.5) + `settings.toml` model with a fixed validated key set (incl. `update-check` off, `totp.seed_pin` off, `clipboard.fact_overwrite` on); load-before-unlock; never holds secrets. Full unit tests.

Self-review against §1.5/§2.5/§4.3/§6.2 performed; gaps map to T0.1–T0.5.
