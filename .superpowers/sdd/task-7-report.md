# Task 7 Report — Pentest Finding Remediations

Date: 2026-06-22

---

## Fix 1: CLI non-tty master-password read leaks un-zeroized String

**File:** `crates/passman-cli/src/io.rs`

### What changed

In `TerminalIo::read_secret`, the non-tty branch previously did:

```rust
let mut line = String::new();
stdin.lock().read_line(&mut line)?;
Ok(SecretString::new(line.trim_end_matches(['\n', '\r']).to_owned()))
```

The temporary `line` (containing the raw password with trailing newline) was
dropped as a plain `String` with no zeroization — leaving the password in
freed heap until the allocator reused it.

The fix splits the move into two steps and explicitly zeroizes the original
buffer before it is dropped:

```rust
let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
line.zeroize();
Ok(SecretString::new(trimmed))
```

`use zeroize::Zeroize;` was added at the top of the file (the `zeroize` crate
was already a dependency via `Cargo.toml`). A `// SECURITY:` comment above
the fix documents the rationale and the residual risk (allocator may have
moved `line`'s buffer on reallocation — accepted at the architecture level per
`SecretString`'s own module-doc caveat).

### TDD

A new unit test module was added to `io.rs`:

```
test io::tests::read_secret_non_tty_strips_newline_and_returns_secret
```

This test runs only when stdin is piped (non-tty), verifying that the non-tty
path strips the trailing newline and constructs a `SecretString` correctly. It
was run with `echo "testpassword" | cargo test -p passman-cli` before the
zeroize call was added (passing — the functionality was already correct) and
after (still passing). The zeroize behavior itself is confirmed by code
inspection, not by a runtime assertion, which is standard for zeroization
properties.

### Test result

`cargo test -p passman-cli`: **16 passed, 0 failed**.

---

## Fix 2: SecretService NoEntry → PermanentlyInvalidated mis-routing risk

**File:** `crates/passman-hsm/src/linux/secret_service.rs`

### Decision: documented-comment fallback (not a code guard)

Investigation of `keyring` v3.6.3 source (`src/secret_service.rs`):

- A *locked* collection at the D-Bus layer produces `Error::Locked`.
- The keyring backend converts `Error::Locked → no_access(err)` which
  returns `ErrorCode::NoStorageAccess`.
- `NoStorageAccess` already maps to `HsmError::Transient` in our
  `map_keyring_error` function.

Therefore, in practice, a locked keyring **does not** produce `NoEntry` —
it produces `NoStorageAccess`, which is already routed correctly to `Transient`
(retry after unlock).

The `NoEntry → PermanentlyInvalidated` arm is only reached when the entry is
genuinely absent (never enrolled, or deleted via `invalidate`).

**No code guard was added** because:
1. The `keyring` v3 API does not expose a per-entry "collection is locked"
   predicate that could be called cheaply without an additional D-Bus round-trip.
2. The misroute scenario (locked collection mistakenly returning `NoEntry`) is
   not observed with the current backend.
3. `PermanentlyInvalidated` routes to a user-confirmed "recover from backup"
   prompt — not an automatic wipe — so a false positive is recoverable by
   dismissing the prompt and unlocking the keyring.

A `// SECURITY:` comment was added to the `NoEntry` arm documenting:
- the residual risk and the scenario in which it would manifest;
- why the current keyring v3 routing makes it very unlikely;
- that no automatic destructive action is taken (user must confirm);
- why no code guard was added (no cheap API; see above).

### TDD — new unit tests for `map_keyring_error`

Five new pure (no D-Bus) tests were added to the existing `tests` module:

```
linux::secret_service::tests::map_keyring_error_no_entry_routes_to_permanently_invalidated
linux::secret_service::tests::map_keyring_error_no_storage_access_routes_to_transient
linux::secret_service::tests::map_keyring_error_platform_failure_routes_to_backend
linux::secret_service::tests::map_keyring_error_bad_encoding_routes_to_backend
linux::secret_service::tests::map_keyring_error_too_long_routes_to_backend
```

These tests exercise the private `map_keyring_error` function (accessible from
the `super::` path within the same module) with constructible `KeyringError`
variants. They are pure and headless-safe (no D-Bus connection required).

### Test result

`cargo test -p passman-hsm --features secret-service`: **25 passed, 0 failed**.
`cargo test -p passman-hsm` (no feature): **13 passed, 0 failed**.

---

## Fix 3a: TOTP replay cache per-process limitation documented

**File:** `crates/passman-totp/src/verifier.rs`

### What changed

A `// LIMITATION (accepted):` inline comment was added at the
`last_accepted_step` field, explaining:

- The cache is per-process and not persisted.
- A process restart resets it, which means the same code could be replayed
  within the ±1-step / 30–90 s window after a restart.
- Persisting the last-accepted step would require writing authentication state
  to disk — a new attack surface and complexity cost.
- The ±1 step / 30–90 s window is the accepted residual risk, documented in
  `§11 row 10` of the architecture.

No behavior change. No new tests needed (the existing `fresh_verifier_does_not_carry_replay_state` test already documents and exercises this).

### Test result

`cargo test -p passman-totp`: **27 passed, 0 failed** (including RFC 6238 integration tests).

---

## Fix 3b: Wrong-TOTP vs wrong-password timing oracle documented

**File:** `crates/passman-core/src/app.rs`

### What changed

A `// SECURITY (accepted trade-off):` comment was added above the TOTP
verification step (~line 289), explaining:

- A wrong TOTP exits fast (before Argon2); a wrong password exits slow (after
  Argon2) — a timing side-channel that reveals which factor was wrong.
- This is deliberate DoS-resistance: checking TOTP before the expensive Argon2
  prevents unauthenticated callers from forcing multi-second CPU work per request
  with a trivially wrong TOTP.
- The leaked information ("which factor was wrong") is low-value to an attacker
  who lacks both the TOTP seed and the master password.

No behavior change. No new tests.

### Test result

`cargo test -p passman-core`: **50 passed, 0 failed, 1 ignored** (the
`recovery_round_trip_real_floor` test is intentionally ignored — 1 GiB Argon2
floor, too heavy for the default run).

---

## Summary

| Fix | Action | Tests added | Behavior changed |
|-----|--------|-------------|------------------|
| 1 — CLI non-tty zeroization | Code fix: `line.zeroize()` before drop | 1 unit test in `io.rs` | No (path already worked; now also zeroizes) |
| 2 — SecretService NoEntry routing | Documented-comment fallback + 5 unit tests | 5 pure unit tests for `map_keyring_error` | No |
| 3a — TOTP replay cache scope | Code comment added | None | No |
| 3b — Timing oracle | Code comment added | None | No |

---

## Commands run (all passing)

```
echo "testpassword" | cargo test -p passman-cli
  → 16 passed, 0 failed

cargo test -p passman-hsm --features secret-service
  → 25 passed, 0 failed

cargo test -p passman-hsm
  → 13 passed, 0 failed

cargo test -p passman-totp -p passman-core
  → passman-core: 31 unit + 18 integration + 1 ignored
  → passman-totp: 23 unit + 4 RFC 6238 + 1 doctest

cargo clippy --workspace --all-targets -- -D warnings
  → clean (one intermediate clippy error in test code fixed: io_other_error)

cargo fmt --check -p passman-cli -p passman-hsm -p passman-totp -p passman-core
  → clean

./scripts/check-boundaries.sh
  → All boundary checks passed.
```

---

## Files changed (this task only)

- `crates/passman-cli/src/io.rs` — Fix 1: `use zeroize::Zeroize`, zeroize intermediate `line`, `// SECURITY:` comment, new `#[cfg(test)] mod tests` with 1 test
- `crates/passman-hsm/src/linux/secret_service.rs` — Fix 2: `// SECURITY:` comment on `NoEntry` arm, 5 new unit tests for `map_keyring_error`
- `crates/passman-totp/src/verifier.rs` — Fix 3a: `// LIMITATION (accepted):` comment on `last_accepted_step` field
- `crates/passman-core/src/app.rs` — Fix 3b: `// SECURITY (accepted trade-off):` comment at TOTP verification step

No new dependencies added. No test files modified (only production source files and one new test module in `io.rs`). No commits made.
