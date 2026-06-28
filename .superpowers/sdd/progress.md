# Pentest fix-pass — progress ledger

Base: the uncommitted P0–P4 + fmt working tree (user handles git; implementers do NOT commit).
Decisions: S2=MAC counter+docs · S6=add libc · S9=pad index + format-version bump.

## Tasks
- [x] T1  S4   GTK clipboard wipe on lock transition — DONE, session 10/10, clippy clean, reviewed
- [x] T2  S7+UX GTK ui.rs — DONE (6 items; remove-confirm skipped: GTK4 dialog deprecation), 13/13, clippy clean
- [x] T3  S6   core-dump suppression — DONE, harden test asserts RLIMIT_CORE==0 + PR_GET_DUMPABLE==0, boundaries pass
- [x] T4  S2   DONE (docs-honesty): §4.9 expanded (TPM2-default null-auth → DA never engages; MAC won't help bc attacker has K_hsm), #15 reworded, §13 open-item. MAC NOT implemented (vindicated by existing §4.9 prose). authValue binding = §13 follow-up.
- [x] T5  S9   sealed-index padding + format 0x01→0x02 + back-compat — DONE, vault 57/core 49 pass, SECURITY REVIEW: SOUND/0 defects
- [x] T6  S8+  supply-chain — DONE: build-twice job, tools pinned (audit 0.22.2/deny 0.19.9/fuzz 0.13.2), gradle hash+validation, RELEASE.md fixed, YAML_OK
- [x] T7  lows DONE: CLI non-tty zeroize+test, secret_service documented-fallback (keyring v3 maps Locked→Transient)+5 tests, 2 accepted-risk comments; clippy clean
- [x] T8  perf REVIEWED, no change — measure-first (CLAUDE.md): no profiled bottleneck, O(n) save fine at scale, the "redundant" decrypt is an integrity check; micro-opts deferred
- [x] T9  S1+S3+S5+UX Android — DONE: 9 items; EMULATOR: Gradle BUILD SUCCESSFUL, OK(7 instrumented), app opens no crash. NOTE: new UI behaviors (clipboard 30s clear, FLAG_SECURE, lock-on-bg) are compile+open+review verified, not behaviorally auto-tested (no Compose UI test) — gap noted.

## Final-review fixes (from whole-branch review)
- [x] M1  Flow::Quit clipboard wipe (worker.rs wipe_clipboard_on_exit + Quit test) — session 11/core 49 pass
- [x] L1  Android clearJob scheduled on Dispatchers.Main (off-main-thread Compose write)
- [x] L2  Reveal/Copy buttons enabled=!inFlight

## Verify (F6) — DONE
- [x] full host suite + clippy -D warnings + boundaries + fmt (360 tests green; final count in flight)
- [x] emulator instrumented + app-open — TWICE (post-T9, post-M1/L1/L2): Gradle BUILD SUCCESSFUL, OK(7), app opens
- [x] final whole-branch review subagent — READY TO MERGE, 0 Critical/High; T5 dedicated review SOUND
## Open follow-ups: TPM2 authValue binding (§13); Compose UI behavioral tests for the new Android flows
