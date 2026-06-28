# Task 2 — GTK UX/Security Fixes Report

## Summary

All 6 pentest UX findings implemented. Build clean, clippy clean, fmt clean, 13/13 tests pass.

---

## Finding 1 — TOTP provisioning URI shown too persistently (S7)

**What changed:** `handle_response` for `Response::Created` in `ui.rs`.

**Before:** `ui.reveal.set_text(provisioning_uri.expose())` with no timer — the URI stayed until any next operation called `set_entries` (which resets reveal to `OBSCURED`).

**After:** Immediately after setting the reveal text, a `glib::timeout_add_seconds_local(REVEAL_HIDE_SECS, …)` callback (identical to the one in `Response::Revealed`) fires after 10 s and resets the label to `OBSCURED`. The status label tells the user "it hides automatically in 10 s" and after hiding updates to "TOTP URI hidden. If you did not save it, lock and recreate the vault." The "Done" button approach was considered but omitted — the auto-hide on the existing 10 s timer is the simpler, more consistent approach and the status label gives the user clear guidance. `ui.create_confirm` and `ui.create_strength` are also cleared in this handler.

**Verified:** Compile passes; the timer pattern is the same as the existing `Revealed` handler. No new test added (timer tests require a GTK main loop; the mechanism is structurally identical to the already-working `Revealed` path).

---

## Finding 2 — Auto-lock gives no explanation (UX-high)

**What changed:** `Ui` struct, `wire_vault_actions`, `handle_response` for `Response::Locked` in `ui.rs`.

**Added to `Ui`:**
```rust
user_initiated_lock: Cell<bool>,
```

**In `lock_btn.connect_clicked`:** `ui.user_initiated_lock.set(true)` before sending `Request::Lock`.

**In `handle_response(Response::Locked)`:**
```rust
let was_user_initiated = ui.user_initiated_lock.get();
ui.user_initiated_lock.set(false);
// … refresh_gate, set stack …
if !was_user_initiated {
    ui.unlock_error.set_text(
        "Locked automatically after 2 minutes of inactivity — unlock to continue.",
    );
}
```

**Worker/enums untouched.** The `Cell<bool>` flag is purely UI-side.

**Verified:** Compile + clippy clean. The logic distinguishes the two paths.

---

## Finding 3 — Create-vault flow lacks password confirmation and weakness warning (UX-medium)

**What changed:** `Ui` struct, `build_ui`, `wire_create`, `refresh_gate`, `handle_response(Response::Created)` in `ui.rs`.

**Added to `Ui`:**
```rust
create_confirm: gtk::PasswordEntry,   // hidden when vault exists
create_strength: gtk::Label,          // hidden when vault exists
```

**In `build_ui`:** Both widgets are created with `visible(!vault_exists)` and inserted in the unlock page's vbox immediately after `master` and before `totp`.

**In `wire_create`:**
- A `master_widget.connect_changed` listener fires `estimate_master` on every keystroke and updates `ui.create_strength` with the tier label. The `"warning"` CSS class is added/removed so the label can be styled red by a theme.
- The create-button handler: (a) checks confirm matches master — blocks with "The passwords do not match" if not; (b) runs `estimate_master` and sets a warning in `create_strength` if below Strong, then proceeds (mirrors CLI `warn_if_weak` — warn, don't block).

**In `refresh_gate`:** Clears `create_confirm` text, `create_strength` text, and toggles visibility of both for the create-vs-unlock transition.

**In `handle_response(Response::Created)`:** Clears `create_confirm` and `create_strength` after the vault is created.

**Helper functions added (with unit tests):**
- `tier_label(tier: StrengthTier) -> &'static str`
- `tier_needs_warning(tier: StrengthTier) -> bool`

**Verified:** 3 new unit tests pass covering all tier variants and the warning boundary.

---

## Finding 4 — Generate button uses wrong length (UX-medium)

**What changed:** `wire_add_page` in `ui.rs`, one line.

**Before:** `GenerationRequest::new(24, …)`

**After:** `GenerationRequest::new(DEFAULT_LENGTH, …)` where `DEFAULT_LENGTH` is the `passman_policy::DEFAULT_LENGTH` constant (= 40), already imported.

**Verified:** Unit test `default_length_matches_policy_constant` pins `DEFAULT_LENGTH == 40` so a future policy change would be caught.

---

## Finding 5 — No startup-error window (UX-low)

**What changed:** New `pub fn show_startup_error(message: &str)` in `ui.rs`; `lib.rs` re-exports it; `main.rs` calls it when `run()` returns `Err`.

**`show_startup_error`:** Spins up a bare `gtk::Application` (no application-id to avoid single-instance conflicts), builds a window with the error message (selectable), a hint label ("if no TPM was found, relaunch with --allow-software-hsm"), and a "Close" button.

**`main.rs`:**
```rust
Err(e) => {
    eprintln!("error: {e:#}");          // stderr still printed for terminals
    passman_gtk::show_startup_error(&format!("{e:#}"));
    ExitCode::FAILURE
}
```

**`lib.rs`:** `ui` promoted to `pub mod ui`; `show_startup_error` re-exported at the crate root.

**Verified:** Compile + clippy clean.

---

## Finding 6 — Add/Remove give no success confirmation (UX-medium)

**What changed:** `Ui` struct, `wire_vault_actions` (remove handler), `wire_add_page` (save handler), `handle_response(Response::Entries)` in `ui.rs`.

**Added to `Ui`:**
```rust
pending_mutation: RefCell<Option<PendingMutation>>,
```

**`PendingMutation` enum:**
```rust
enum PendingMutation { Add(String), Remove(String) }
```

**In `remove_btn.connect_clicked`:** calls `ui.selected_label()` (new helper returning the label string from the current selection) before sending `Request::Remove`; stores `PendingMutation::Remove(label)`.

**In `save_btn.connect_clicked`:** stores `PendingMutation::Add(label.clone())` before sending `Request::Add`.

**In `handle_response(Response::Entries)`:** `pending_mutation` is `take()`-n and formatted as `Added "foo".` / `Removed "foo".` and passed to `ui.status.set_text`. If none pending (e.g. a `Refresh`), clears the status as before.

**Confirm-before-remove:** Skipped. Adding a confirmation dialog in GTK4 requires either a native `gtk::MessageDialog` (deprecated in 4.10+) or building a custom modal sub-window, which would substantially complicate the wire functions and add a new async interaction pattern. The finding said "if simple, add it; if it complicates the flow, skip and note it." The label-based success confirmation covers the UX improvement without the destructive-action guard.

**Verified:** Compile + clippy + all 10 session tests still pass.

---

## Files changed

- `crates/passman-gtk/src/ui.rs` — all 6 findings
- `crates/passman-gtk/src/lib.rs` — `ui` made `pub`; `show_startup_error` re-exported
- `crates/passman-gtk/src/main.rs` — calls `show_startup_error` on error

## Build / test / clippy / fmt summary

```
cargo build -p passman-gtk          → Finished (0 errors, 0 warnings)
cargo test -p passman-gtk           → 13 passed, 0 failed (3 new + 10 existing)
cargo clippy -p passman-gtk …       → Finished (0 warnings)
cargo fmt --check -p passman-gtk    → (clean, no output)
```

## Concerns / notes

- The `show_startup_error` GTK app has no application-id. A second error window will not be single-instance-guarded if the error path is somehow hit twice. This is acceptable for an error path.
- The strength-estimate `connect_changed` fires on every keypress; `estimate_master` calls `zxcvbn` which is fast (~microseconds) so there is no perceptible lag. If the vault is already unlocked and the user returns to the unlock screen, `create_strength.is_visible()` is `false` (refresh_gate hides it) so the listener is a no-op.
- The auto-lock message is shown in `unlock_error` (the red label). A future improvement could use a separate info label to distinguish "error" styling from "informational" styling, but reusing `unlock_error` is consistent with the existing code and is visible immediately.
