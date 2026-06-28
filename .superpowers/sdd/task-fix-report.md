# Pentest fix-pass — final-review follow-ups (M1, L1, L2)

Three minor items surfaced by the final review of the passman pentest fix-pass.
No commits/push (user handles git).

---

## M1 (Rust, TDD): wipe the clipboard on `Flow::Quit`, not just `Flow::Lock`

**File:** `crates/passman-core/src/worker.rs`
**Test:** `crates/passman-gtk/tests/session.rs`

### Problem
T1 added `wipe_clipboard_on_lock` and called it on the two `Flow::Lock`
transitions in `unlocked_loop` (explicit `Request::Lock` / idle 120 s auto-lock),
so a copied secret is wiped when the session locks. But the two `Flow::Quit`
transitions did **not** wipe:

1. An explicit `Request::Quit` arriving while unlocked → `handle_unlocked`
   returns `Flow::Quit` → matched in the `Ok(request)` arm (was
   `Flow::Quit => return Flow::Quit`, no wipe).
2. The request channel closing (`Session` dropped → `Drop` sends `Quit` then
   drops the receiver) → `Err(RecvTimeoutError::Disconnected) => return Flow::Quit`,
   no wipe.

If a user copies a secret and quits within the 30 s window, the GTK shell's
pending `ClearClipboard` never runs (it's dropped by the locked outer loop after
the worker exits), stranding the password on the OS clipboard (pentest S4, Quit
variant).

### RED → GREEN evidence
New test `quitting_wipes_a_still_live_clipboard_secret`:
create+unlock → `Copy` (assert clipboard holds `"pw-GitHub"`) → send
`Request::Quit` → **deterministic barrier**: drain the response channel until it
disconnects (`RecvTimeoutError::Disconnected`), which the worker triggers only
after it has fully returned — i.e. after the Quit-path wipe — so no sleeps →
assert the clipboard is no longer the secret.

RED (against current, un-fixed code):
```
thread '...' panicked at crates/passman-gtk/tests/session.rs:514:5:
assertion `left != right` failed: quitting must have wiped the still-live clipboard secret
  left: Some("pw-GitHub")
 right: Some("pw-GitHub")
test result: FAILED. 0 passed; 1 failed; ...
```
The disconnect barrier fired (no 5 s timeout panic), proving the worker exited;
the secret was simply never wiped.

GREEN (after fix): all 11 session tests pass, including the pre-existing
`locking_wipes_a_still_live_clipboard_secret` (Lock path intact).

### Implementation
- Renamed the private helper `wipe_clipboard_on_lock` → `wipe_clipboard_on_exit`
  (it now serves both Lock and Quit transitions; private to the module, no
  public-API change) and updated its doc comment to say "lock OR quit".
- Added the same `wipe_clipboard_on_exit(...)` call before **both** `Flow::Quit`
  returns in `unlocked_loop`:
  - the `Ok(request)` arm's `Flow::Quit` branch (explicit `Request::Quit`);
  - the `Err(RecvTimeoutError::Disconnected)` arm (Session dropped).
- Left untouched, as required: the locked-loop behavior, the deadlock-fix
  `Response::Locked` replies, the idle auto-lock, and the existing Lock-path wipe.

The wipe uses the still-live `live_cookie` and `unlocked.clear_clipboard_with`,
exactly as the Lock path does, while the `UnlockedApp` is still in scope.

---

## L1 (Kotlin): Compose-state (`clearJob`) mutated off the main thread in `onCopy`

**File:** `android/app/src/main/kotlin/com/passman/app/MainActivity.kt`
(cannot compile locally — no SDK; built on the remote emulator afterward)

### Problem
The `run{}` helper wraps the whole block in `withContext(Dispatchers.IO)`. Inside
`onCopy`'s block, `clearJob.value?.cancel()` and
`clearJob.value = scope.launch{...}` mutated a Compose `mutableStateOf<Job?>`
from the IO thread. Compose `MutableState` writes should happen on the main
thread.

### Fix (exact)
- `val digest = app.copy(item.id, FieldKind.PASSWORD)` still runs on the IO
  dispatcher (the digest capture is the real I/O work).
- Wrapped the `clearJob` cancel + reassignment + the `status` write in
  `withContext(Dispatchers.Main) { ... }`, so they execute on the main thread.
- The 30 s auto-clear coroutine (`scope.launch { delay(30_000);
  withContext(Dispatchers.IO){ app.clearClipboard(digest) } }`) is now created
  from the main-dispatched body — `scope.launch` defaults to `Dispatchers.Main`.
- Preserved: the 30 s `delay` + `app.clearClipboard(digest)`, the
  cancel-prior-job-on-new-copy semantics, the `"Copied — clears in 30 s"` status,
  and the `AppException.SessionLocked` handling (`app.copy` throws *before* the
  `withContext(Main)` block, so it still propagates to `run`'s catch unchanged).

### Symbol/import notes (verified against existing imports — no new imports)
- `Dispatchers.Main` — uses the already-imported `Dispatchers`
  (`import kotlinx.coroutines.Dispatchers`, line 43); `.Main` is a member of that
  object (coroutines-android is already on the classpath via Compose).
- `withContext` (line 47), `Dispatchers.IO` (43), `Job` (44), `delay` (45),
  `launch` (46) — all already imported and used elsewhere in the file.
- `clearJob` is `remember { mutableStateOf<Job?>(null) }` (line 109); `scope` is
  `rememberCoroutineScope()` (line 79); `status` is the `PassmanRoot`
  `mutableStateOf("")` (line 103). All in lexical scope of the `onCopy` lambda.
- Nested `withContext(Main)` inside `run`'s outer `withContext(IO)` is standard:
  it switches the dispatcher for its block and restores on exit.

---

## L2 (Kotlin): disable Reveal/Copy buttons while an op is in flight

**File:** `android/app/src/main/kotlin/com/passman/app/MainActivity.kt`

### Fix (exact)
In `VaultScreen`'s per-row buttons:
```
Button({ onReveal(item) }, enabled = !inFlight) { Text("Reveal") }
Button({ onCopy(item) }, enabled = !inFlight) { Text("Copy") }
```
`inFlight: Boolean` is already a `VaultScreen` parameter (line 259) and is already
used by the Add button (`enabled = !inFlight`, line 328) and the Gate buttons —
so the same form is reused; no threading change needed. Consistent with
Create/Unlock/Add (overlapping ops are a UX nit; each op is independently safe).

---

## Commands run (Rust)

- `cargo test -p passman-gtk --test session` →
  **11 passed; 0 failed** (new Quit test + 10 existing; Lock-path test still passes).
- `cargo test -p passman-core` → **31 + 18 passed; 0 failed; 1 ignored**
  (the ignored test is the 1 GiB-Argon2 recovery floor, documented as too heavy).
- `cargo clippy -p passman-core -p passman-gtk --all-targets -- -D warnings` →
  **clean (Finished, no warnings)**.
- `cargo fmt -p passman-core -p passman-gtk` then
  `cargo fmt -p passman-core -p passman-gtk --check` → **FMT-CLEAN**.

Kotlin: re-read each change; every referenced symbol/import verified present
(no new imports). Compiles on the remote emulator later.

## Scope
Only three files edited this session:
`crates/passman-core/src/worker.rs`, `crates/passman-gtk/tests/session.rs`,
`android/app/src/main/kotlin/com/passman/app/MainActivity.kt`.

## Hard stops / concerns
None. No public API changed (helper rename is module-private). No existing test
modified. No dependencies added. No files deleted. Not committed.
