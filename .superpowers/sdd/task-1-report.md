# Task 1 Report — Pentest S4: clipboard secret survives a lock

## Status: DONE

## The bug (pentest finding S4)
After a `Copy`, the GTK shell schedules a `Request::ClearClipboard` 30 s later to
wipe the copied secret (§5.3). The worker's LOCKED outer loop
(`run_worker`) handles `Ok(Request::ClearClipboard { .. }) => {}` — it drops it
silently. So if the session locks (explicit `Request::Lock`, OR the 120 s idle
auto-lock in `unlocked_loop`) BEFORE the 30 s timer fires, the worker has already
returned to the locked loop and the later `ClearClipboard` is dropped. The copied
password stays on the OS clipboard indefinitely for a clipboard scraper
(in-scope threat #4).

## The fix
Wipe the clipboard proactively ON THE LOCK TRANSITION, while we still hold the
borrowed `UnlockedApp`, instead of relying on a post-lock `ClearClipboard` the
locked loop discards.

## Files + functions changed

### `crates/passman-core/src/worker.rs`
- **`unlocked_loop`** — now owns a `let mut live_cookie: Option<ClipboardCookie>`.
  On both lock-exit paths (`Flow::Lock` returned by `handle_unlocked`, and the
  `recv_timeout` idle-tick `is_expired()` auto-lock) it calls the new
  `wipe_clipboard_on_lock(...)` BEFORE returning `Flow::Lock` (i.e. before
  `unlocked` is dropped at the `run_worker` call site). The match on the handler
  result was expanded from `Continue / other` into explicit `Continue / Lock /
  Quit` arms so the wipe runs only on `Lock`.
- **`handle_unlocked`** — gained a `live_cookie: &mut Option<ClipboardCookie>`
  parameter.
  - `Request::Copy` success: `*live_cookie = Some(cookie);` (ClipboardCookie is
    `Copy`, so the cookie is also still moved into `Response::Copied`).
  - `Request::ClearClipboard`: after the existing `clear_clipboard_with`, sets
    `*live_cookie = None;` — the shell's timer fired in time, so forget the
    cookie and don't redundantly re-wipe on a later lock.
- **`wipe_clipboard_on_lock` (new, private fn)** — if a live cookie and a
  clipboard are both present, calls
  `unlocked.clear_clipboard_with(cookie, clip, fact_overwrite)`. That method is
  explicitly documented as not requiring an unlocked session (it runs
  post-expiry), so calling it on the lock transition is sound. Result is `let _
  =` discarded (advisory `#[must_use] ClearOutcome`; no caller to surface it to,
  this is the worker's own cleanup) and NO `Response` is sent.

### `crates/passman-gtk/tests/session.rs`
- Added test **`locking_wipes_a_still_live_clipboard_secret`** (see below).

## Invariants preserved (explicitly verified, did NOT regress)
- Locked outer loop still replies `Response::Locked` to unlocked-only requests
  (deadlock fix) and still drops `ClearClipboard` with NO response
  (fire-and-forget) — `worker.rs` locked loop untouched.
  Regression test `requests_after_lock_get_a_locked_response_not_a_deadlock`
  passes.
- The 1 s `EXPIRY_POLL` recv_timeout idle auto-lock still works.
  Regression test `an_idle_session_auto_locks_after_the_timeout` passes.
- `Session::drop` detaches (does not join) — untouched.
  Test `dropping_the_session_does_not_block_on_a_stuck_worker` passes.

## Test added
```rust
#[test]
fn locking_wipes_a_still_live_clipboard_secret() {
    let (h, seed) = Harness::with_entries(&["GitHub"]);
    let (session, rx) = h.spawn();
    session.send(Request::Unlock { master: master(), code: h.code(&seed) });
    let id = match recv(&rx) {
        Response::Unlocked { entries } => entries[0].id,
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Copy → secret on the clipboard.
    session.send(Request::Copy { id, field: RevealField::Password });
    assert!(matches!(recv(&rx), Response::Copied { .. }));
    assert_eq!(h.clip.content.lock().expect("lock").as_deref(), Some("pw-GitHub"));

    // Force the 120 s idle auto-lock BEFORE any ClearClipboard.
    h.clock.advance(121);
    assert!(matches!(recv(&rx), Response::Locked));

    // The lock transition must have wiped the secret.
    assert_ne!(h.clip.content.lock().expect("lock").as_deref(), Some("pw-GitHub"));
}
```
Uses the idle auto-lock path (`advance(121)`) — the exact race the GTK 30 s timer
loses. "Cleared" is asserted as "no longer the secret" (with `fact_overwrite=true`
the content becomes a non-secret facts string), per the task note.

## RED → GREEN evidence

### RED (against current code, before the fix)
```
test locking_wipes_a_still_live_clipboard_secret ... FAILED
thread '...' panicked at crates/passman-gtk/tests/session.rs:456:5:
assertion `left != right` failed: locking must have wiped the still-live clipboard secret
  left: Some("pw-GitHub")
 right: Some("pw-GitHub")
test result: FAILED. 0 passed; 1 failed; ...
```

### GREEN (after the fix)
```
test locking_wipes_a_still_live_clipboard_secret ... ok
test result: ok. 1 passed; 0 failed; ...
```

## Command outputs

`cargo test -p passman-gtk --test session`
```
running 10 tests
test create_makes_a_vault_and_returns_the_provisioning_uri ... ok
test dropping_the_session_does_not_block_on_a_stuck_worker ... ok
test add_then_remove_updates_the_list ... ok
test lock_returns_to_locked_state ... ok
test requests_after_lock_get_a_locked_response_not_a_deadlock ... ok
test reveal_and_copy_a_field ... ok
test unlock_lists_entries ... ok
test wrong_password_fails_unlock ... ok
test an_idle_session_auto_locks_after_the_timeout ... ok
test locking_wipes_a_still_live_clipboard_secret ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo test -p passman-core`
```
test result: ok. 31 passed; 0 failed; 0 ignored  (lib unit)
test result: ok. 18 passed; 0 failed; 1 ignored  (tests/core.rs — the 1 ignore
             is the pre-existing 1 GiB Argon2 recovery-floor test, not mine)
test result: ok. 0 passed (doc-tests)
```

`cargo clippy -p passman-core -p passman-gtk --all-targets -- -D warnings`
```
Finished `dev` profile [unoptimized + debuginfo] target(s)   (clean)
```
(One iteration: an initial `clippy::ref_option` warning on
`wipe_clipboard_on_lock`'s `&Option<ClipboardCookie>` param was fixed by
switching to `Option<&ClipboardCookie>` + `live_cookie.as_ref()` at the call
sites. A `clone_on_copy` risk was avoided by relying on `ClipboardCookie: Copy`
instead of `.clone()`.)

`cargo fmt -p passman-core -p passman-gtk --check` → clean.

## Scope
Only `crates/passman-core/src/worker.rs` and
`crates/passman-gtk/tests/session.rs` were changed by this task. Other dirty
files in the working tree predate this task (the in-progress pentest-fix branch
this task continues). No existing test modified. No dependency added. No
commit/push.

## Concerns
- The fix wipes on the LOCK transition (`Flow::Lock`), per spec. It does NOT wipe
  on `Flow::Quit` (worker shutdown). If the user copies a secret and then quits
  the app within 30 s, the post-quit `ClearClipboard` (if any) is moot and the
  secret could remain on the clipboard. This was out of the task's stated scope
  ("wipe ON THE LOCK TRANSITION") so it was left unchanged — flagging as a
  possible follow-up, not fixed here.
