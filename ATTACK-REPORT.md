> **Remediation status (2026-06-28):** The one confirmed weakness, **A12**
> (pre-auth recovery-import memory-exhaustion DoS), has been **fixed and verified**
> on the real binary in commit `bc15f06` — `argon2id` now refuses, before
> allocating, any derivation whose memory cost exceeds 80% of host RAM
> (`/proc/meminfo` `MemAvailable` on Linux/Android), returning a clean typed
> error instead of OOM-killing the process. Live re-test: the 8 GiB tamper went
> from OOM-kill (rc=137) to a clean rejection in 29 ms; a legitimate 256 MiB
> derivation is still allowed through. The A4 / A6 PARTIALs remain accepted
> within the documented threat model; the preset/ceiling tuning the report
> recommends (lowering `MAX_M_KIB` / the default recovery preset) is a
> security/usability tradeoff deferred to a follow-up decision.

---

# Penetration-Test Report — `passman` TPM-Backed Password Manager
### Active attack campaign against the real TPM hardware deployment (`/dev/tpmrm0`, release binary, `sg tss`)

---

## 1. Executive Summary

`passman` was subjected to a 12-class active attack campaign run **against the real TPM, not a model or mock**: stolen-vault unlock attempts on foreign/absent TPMs, single-byte AEAD tampering, HSM slot/blob substitution, version downgrade and snapshot rollback, TOTP/lockout abuse, 100M+ parser fuzz iterations plus ~2,500 malformed files through the live binary, process/clipboard/disk inspection, concurrency races, and a full recovery-file tamper battery. Non-HOLDS verdicts were re-reproduced by two independent skeptics; HOLDS verdicts were audited for genuine effort.

**Headline result: the cryptographic and authentication core held. There was no confidentiality breach, no authentication bypass, no key extraction, no memory-corruption, and no wrong-plaintext disclosure in any of the 12 classes.** Hardware binding is sound — a stolen `vault.pmv` is cryptographically inert off its originating TPM (A1). AEAD, slot binding, parsing, input handling, on-disk permissions, process hygiene, and concurrency all fail closed (A3, A5, A7, A8, A9, A10, A11).

**One confirmed weakness was found, and it is an availability defect, not a cryptographic or authentication break:** a **pre-authentication denial-of-service in the recovery-import path (A12)**. A 4-byte edit to a recovery file's Argon2 memory parameter — *within* the code's own accepted ceiling and requiring no password — causes the importer to attempt an 8 GiB allocation that OOM-kills the process on this 3.6 GiB host (and on any mobile device). The same mis-calibrated 8 GiB ceiling also makes legitimate **default-preset (4 GiB) recovery files un-importable** on constrained devices.

Two further findings are **low-severity PARTIALs that fall squarely inside the documented threat model**: whole-file snapshot rollback (A4) and resetting the *advisory* lockout counter by patching plaintext header bytes (A6). Neither leaks a secret nor enables an offline attack; both are openly documented as "not a security boundary."

**Bottom line:** the deployment is safe to ship for its core guarantees (confidentiality, integrity, authentication, hardware binding). **A12 must be fixed before shipping if mobile or sub-8-GiB devices are in scope**, because it is both a pre-auth DoS and a correctness regression for legitimate recovery.

---

## 2. Results Table

| # | Attack | What was tried | Verdict | Severity |
|---|--------|----------------|---------|----------|
| A1 | Hardware binding | Steal `vault.pmv`; unlock with correct master+TOTP on a foreign swtpm, a dead TCTI, no-TPM, and via `--allow-software-hsm` | **HOLDS** | none |
| A2 | Pre-auth Argon2 cost DoS | Byte-patch header KDF params to absurd values (m/t/p = `0x7FFFFFFF`/`0xFF`) on vault + recovery, run under 1 GiB cap | **HOLDS** (¹) | none |
| A3 | AEAD tamper | 14–28 single-byte flips across probe, sealed index, entry envelopes, and every AD-bound header field | **HOLDS** | none |
| A4 | Rollback / downgrade | Patch the format-version byte (5 values); restore pre-delete and pre-passwd-change snapshots | **PARTIAL** | low |
| A5 | HSM slot/blob confusion | Swap, duplicate, truncate, extend the two TPM wrap blobs in `vault.pmv` | **HOLDS** | none |
| A6 | TOTP factor / lockout | Wrong/empty/stale codes; hammer to lockout across fresh processes; zero the plaintext lockout counter; replay one code | **PARTIAL** | low |
| A7 | Disk permission leak | `stat`/grep all on-disk files + live atomic-write temps under lax `umask 0002`; force dir to 0777 | **HOLDS** | none |
| A8 | Process/memory/clipboard leak | Read `/proc/<pid>/{cmdline,environ,mem,maps,limits}`; clipboard scrape on timeout, SIGINT, SIGTERM, SIGKILL | **HOLDS** | low (²) |
| A9 | Input injection | Shell metachars, `$()`/backticks, NUL, ANSI/control seqs, 4 MiB fields, RTL/combining/emoji unicode, invalid UTF-8 | **HOLDS** | none |
| A10 | Parser fuzz | ~100M in-process iterations + ~2,500 malformed vault/recovery files through the live binary | **HOLDS** | none |
| A11 | Concurrency / file lock | 24 simultaneous writers, add-during-get, `kill -9` mid-write, integrity recount | **HOLDS** | none |
| A12 | Recovery-file attack | 0600 export check, true-positive restore, 14–15 tampers, **+ in-ceiling KDF memory tamper** | **VULNERABLE (found-by-audit)** | **medium** |

(¹) A2's *scoped* defense (rejecting out-of-range params) holds, but the audit surfaced the same in-range 8 GiB OOM/SIGABRT root cause that A12 confirms as a break — see §3.1.
(²) A8 verdict HOLDS; severity low reflects the single documented, uncatchable SIGKILL clipboard residual.

---

## 3. Confirmed Weaknesses

### 3.1 A12 — Pre-auth recovery-import memory-exhaustion DoS *(VULNERABLE, medium)*

**This is the only genuine break in the campaign. It is an availability defect — there is no loss of confidentiality, integrity, or authentication.** Confidentiality and integrity of the recovery format itself held perfectly: a true-positive restore returned the exact original generated password and username; the export is `0600` with no cleartext secrets; and all 15 confidentiality/integrity tampers (bad magic, wrong version, wrong KDF id, truncation, trailing bytes, ciphertext/tag bitflips, over-ceiling params) were rejected cleanly with `rc=1`, no partial vault, no leak, no wrong-plaintext.

**The defect.** The import-side anti-DoS guard is `KdfParams::within_limits()` (`crates/passman-recovery/src/format.rs:213`), whose memory ceiling is the **fixed constant `MAX_M_KIB = 8 GiB`** (`crates/passman-crypto/src/kdf.rs:31`). It is **not bounded by available host RAM**. The prior red-teamer only probed values *above* the ceiling (`m = u32::MAX`, `m = 0`, `t = u32::MAX`), saw them rejected in ~0.02 s, and concluded "no OOM." They never tested the **within-ceiling-but-over-host-RAM** region.

A recovery file's Argon2 memory field (header offset `8..12`) is **attacker-controlled and fed to Argon2id pre-authentication**. A 4-byte edit, requiring **no password knowledge**, on a file the user can otherwise import:

- `m = 8388608 KiB` (= `MAX_M_KIB` exactly, **accepted** by `within_limits`): real `passman import` on `/dev/tpmrm0` was **OOM-killed → `rc=137` (SIGKILL)**, 20 s of swap thrash, peak RSS climbing toward 8 GiB, **no typed error** (the process was killed, not cleanly rejected). The boundary is exact: `m = MAX+1 (8388609)` is rejected in 0.018 s; `m = MAX (8388608)` OOM-kills.
- `m = 4194304 KiB` (= 4 GiB = `RecPreset::Default`, **the default export preset**): import ran the full 40 s timeout (`rc=124`), thrashing, never completing.

This violates the rules of engagement (a defense holds only if there is "no OOM/multi-second hang") and falsifies the design's own stated purpose for `within_limits` ("deny a pre-auth resource-exhaustion DoS (OOM/hang, fatal on mobile)") — the ceiling is mis-calibrated at more than 2× this host's RAM and far above any phone.

**Corroboration (A2).** The A2 audit independently hit the same root cause from the recovery path: an in-range `m = 8 GiB` recovery import (fully pre-auth) produced `exit=134` (SIGABRT, Rust `handle_alloc_error`) in 22 ms. A2's *scoped* "reject out-of-range" defense correctly holds, but the in-range ceiling is unsafe. A2 and A12 are the same defect observed via two failure modes (alloc-abort vs. OOM-kill, depending on allocator/swap state).

**Collateral correctness impact.** Because export also runs the recovery KDF and the default preset is 4 GiB, **a user creating or importing a default recovery backup on this host hits the same thrash/OOM** — i.e., the "a valid recovery file restores access" guarantee fails for default settings on constrained/mobile devices. The successful positive restore only worked with the explicit `--preset floor` (1 GiB).

**Minimal reproducer:**
```bash
# Given a valid Floor recovery file valid.pmr (header m = 1048576 KiB):
python3 -c "import struct;b=bytearray(open('valid.pmr','rb').read()); \
b[8:12]=struct.pack('<I',8388608); open('t.pmr','wb').write(bytes(b))"
printf 'any-pw\n' | sg tss -c 'passman --vault-dir $(mktemp -d) import t.pmr --preset low'
#  -> process OOM-killed (rc 137), ~20s swap thrash, NO typed rejection, no vault written
#  vs. m = 8388609 (MAX+1) -> clean rc=1 in 0.02s ("Argon2 parameters are out of range")
```
Full scripts: `/tmp/claude-1000/-home-earl-Documents-prog-passman/b7f50f11-438c-4024-b151-323c809362d5/scratchpad/attack/a12_dos_real2.sh` and `a12_dos_4gib.sh`.

**Recommended fix:**
1. **Clamp the import-side recovery KDF memory to a host-aware budget**, e.g. `m_effective = min(header.m, fraction_of_available_RAM)`, and refuse (typed `KdfParamsOutOfRange`/resource error) when the header demands more than the host can satisfy — *before* the allocation.
2. **Lower `MAX_M_KIB`** to a value survivable on the smallest supported device, or make the ceiling target-aware (a separate, lower ceiling on mobile). The current fixed 8 GiB lets a within-limits header tamper — or even a legitimate Default/Paranoid file — OOM the importer.
3. As defense-in-depth, **catch allocation failure** (fallible allocation / pre-flight RAM check) and return a clean typed error instead of letting Argon2 SIGABRT/SIGKILL the process. This also resolves the A2 in-range abort.
4. Reconsider the **default export preset (4 GiB)** for constrained targets so default-created backups remain restorable.

Source: ceiling `crates/passman-crypto/src/kdf.rs:31`; import gate `crates/passman-recovery/src/format.rs:213`; single 8 GiB allocation `crates/passman-crypto/src/kdf.rs:152-168`; default preset `crates/passman-cli/src/cli.rs:95`; uncapped recovery read `crates/passman-cli/src/commands.rs:502`.

---

### 3.2 A4 — Whole-file snapshot rollback *(PARTIAL, low — within documented threat model)*

**The claimed defense (version downgrade) holds closed.** Patching the format-version byte fails in every case with no leak and no panic: `0x01` (v2→v1) parses but the probe AEAD fails because the version is bound into the probe/index/entry associated data → `exit=4`, no `github` label shown; `0x00/0xFF/0x7F/0x42` are rejected at parse (`UnsupportedVersion`) → `exit=1`. `Vault::create` hardcodes `0x02`, so no binary path can even emit a v1 vault to coerce. A v2 vault cannot be downgraded to weaker v1 handling.

**What succeeds (the PARTIAL):** whole-file rollback by an at-rest attacker, which is **not a claimed defense**. Restoring a pre-delete snapshot resurrects a deleted entry (`get github --field username` → `octo-cat`, the later-added `gitlab` vanishes); restoring a pre-`passwd` snapshot lets the **old, rotated-away master unlock again**. Both succeed undetected.

This is explicitly **inside the threat model**: `architecture.md:160` lists "rollback to earlier snapshots" as an assumed adversary capability, and the relevant state is documented as "rollback-able; not a security boundary." Anti-rollback is never claimed, so this is an accepted limitation, not a defense bypass.

**Minimal reproducer:**
```bash
cp "$VD/vault.pmv" snap.pmv
passman --vault-dir "$VD" rm github          # delete entry (or: passwd to rotate master)
cp snap.pmv "$VD/vault.pmv"                   # roll back
passman --vault-dir "$VD" get github --field username   # -> octo-cat (resurrected)
```

**Recommended action:** Accept as documented, **or** — if rollback detection becomes in-scope — bind a **TPM NV monotonic counter** into the vault's AEAD associated data so a restored older snapshot is detected at unlock. Low priority given the explicit threat-model exclusion.

---

### 3.3 A6 — Advisory lockout reset + replay/DA residuals *(PARTIAL, low — within documented threat model)*

**The TOTP second factor and lockout-persistence both hold.** With the correct password, empty / `000000` / stale (-120 s) codes are all rejected `exit=4` with no leak; TOTP is checked before the Argon2 KDF. The advisory lockout engages after exactly 3 failures, and the 4th/5th attempts — **in fresh processes, even with a correct code** — are blocked `exit=5` *before* any credential check, with `rl_counter=3` durable on disk. Restart/kill cannot reset it.

**What succeeds (the PARTIAL):** the lockout counter (`rl_counter`, `rl_last_failure`) lives in the vault header in **plaintext and is not MAC'd / not in any AEAD AD**. Zeroing those 16 bytes immediately clears the lockout (`exit=5 → exit=0`), with all vault data intact (no self-DoS). This is exactly what the source documents: "not a security boundary … an attacker with the file can roll them back, which is why they are not MAC'd."

**Two related residuals (see §5):** the TOTP replay cache is per-process, so one valid code is reusable across separate invocations within its ~30 s window; and on the default Linux TPM2 backend there is **no HSM-native dictionary-attack lockout** (no authValue PIN, `max_attempts_before_lockout = None`, `lockout_status` defaults to `Available`), so the resettable advisory counter is the *only* `passman`-side online throttle — contradicting the design's "the real DA control is the HSM" justification on this deployment.

**Severity is low** because the reset reveals no secret, needs local write access to a user-private `0600` file, and any brute force still requires *both* a valid TOTP (checked before the KDF) and the master password; `K_hsm` remains TPM-bound, so no offline attack is enabled.

**Minimal reproducer:**
```bash
# After 3 wrong attempts have engaged the lockout (exit 5):
python3 patch_counter.py "$VD/vault.pmv" zero      # zero rl_counter/rl_last_failure (plaintext, un-MAC'd)
passman --vault-dir "$VD" get github               # exit 5 -> exit 0 : lockout cleared
```

**Recommended action:** If the lockout is meant to be a real online throttle: (a) set a TPM authValue PIN so the HSM enforces dictionary-attack lockout, **or** move the counter into TPM NV/monotonic state, **or** bind it into the AEAD AD so rollback is detected. Persist the last-accepted TOTP step (e.g., in the header) to close the cross-process replay window. At minimum, document clearly that the default Linux TPM2 config has no HSM-native DA backstop.

---

## 4. Defenses That Held (each with the proof of what was actually attempted)

### Confidentiality & cryptographic binding
- **A1 — Hardware binding.** A real-TPM vault was stolen byte-for-byte and unlocked with the *correct* master + a *valid* fresh TOTP on a foreign swtpm, a dead TCTI, with no TPM, and via `--allow-software-hsm`: every off-TPM attempt failed closed (`exit=1`, no `octo-cat`). Foreign SRK → `Esys_Load 0x1df` (TPM_RC_INTEGRITY); the control (same file on the real TPM) returned `octo-cat`, proving the failures are binding, not corruption. `K_master = HKDF(K_pw ‖ K_hsm)` cannot form without the TPM-sealed 256-bit `K_hsm`.
- **A3 — AEAD fails closed.** Up to 28 single-byte flips across the probe, sealed index, every per-entry envelope, the envelope `id`, and every AD-bound header field: all failed closed (`LEAK=0 PANIC=0 CRASH=0 HANG=0`), with `RUST_BACKTRACE=full` clean. The real username/password never appeared in any tampered output.
- **A5 — HSM slot/blob confusion.** Swap, duplicate (both directions), truncate, and extend the two TPM wrap blobs (incl. a malformed-prefix variant exercising the outer parser): all 6 variants `exit=1`, no leak, no panic. The slot tag is sealed *inside* the TPM object → `MalformedBlob` on wrong-slot, and `K_master` still depends on `K_hsm` as a second layer.

### Anti-DoS & parser/input robustness
- **A2 — Out-of-range Argon2 ceiling (scoped).** Header KDF params patched to `m/t/p = 0x7FFFFFFF/0xFF` on both vault and recovery paths, run under a 1 GiB virtual cap: rejected in 21–94 ms with no OOM, *before* derivation — the scoped "reject out-of-range" defense holds. *(Caveat: the in-range 8 GiB ceiling itself is unsafe — see §3.1.)*
- **A10 — Parser robustness.** ~100M in-process fuzz iterations (release + ~1.4M debug with overflow checks) plus ~2,515 malformed vault/recovery files driven through the live binary on the real TPM: zero panics, zero crashes, no exit code outside `{0,1,4}`, no signal, no hang. `ec=0` cases were envelope-ciphertext mutations where `list` correctly returns the authenticated label and a follow-up `get` fails closed — no wrong-plaintext.
- **A9 — Input injection.** Shell metachars, `$()`/backticks (canary dir stayed empty — no exec), NUL bytes, ANSI/OSC/control sequences, 100 KiB–4 MiB fields, RTL/combining/emoji unicode, and invalid UTF-8 via both stdin and argv: all stored/retrieved byte-exact or rejected cleanly (`rc=1`/`rc=2`); no injection, panic, corruption, or DoS.

### Local hygiene & concurrency
- **A7 — On-disk permissions.** Under `umask 0002`, a spin-watcher caught the live atomic-write temp at `0o600`; `vault.pmv`, lockfile, and recovery `.pmr` all `0600`, dir `0700`; raw grep/`strings` for the master, TOTP secret, entry password, labels, and markers found nothing. Even with the vault dir forced to `0777`, `vault.pmv` came out `0600` (explicit `mode(0o600)` is umask-independent).
- **A8 — Process/memory/clipboard.** During a copy-mode `get`, `/proc/<pid>/cmdline` showed no secret; `/proc/<pid>/{environ,mem,maps}` were all `Permission denied` to the same uid (`PR_SET_DUMPABLE=0`), core size `0/0`. The clipboard secret was scrubbed (replaced with a decoy fact, `exit 0`) on the 30 s timeout, SIGINT, and SIGTERM. Only the documented, uncatchable **SIGKILL** strands it.
- **A11 — Concurrency.** 24 simultaneous writers (6 bursts of 4) → exactly one winner per burst, the rest `exit=6` "already running"; add-during-`get` → `exit=6`; `kill -9` mid-write left no torn file, no stale temp, lock auto-released; final integrity recount matched committed entries exactly with correct plaintext. `flock(LOCK_EX|LOCK_NB)` + `O_EXCL`-temp + atomic rename.

---

## 5. Accepted Residuals / Out-of-Scope

Stated plainly; none of these is a defect against the declared threat model:

- **Whole-file snapshot rollback (A4).** Anti-rollback is not claimed; `architecture.md:160` grants the at-rest attacker snapshot rollback. Resurrecting deleted entries and undoing a master-password rotation are accepted.
- **Advisory lockout reset via plaintext header (A6).** The `rl_counter`/`rl_last_failure` fields are deliberately un-MAC'd local state ("not a security boundary"). A local attacker with the file can roll them back.
- **Per-process TOTP replay window (A6).** The replay cache is not persisted, so a captured valid code is reusable across separate processes within its ~30 s validity window.
- **No HSM-native dictionary-attack lockout on default Linux TPM2 (A6).** No authValue PIN, no PCR policy, `lockout_status = Available`. The advisory counter is the only online throttle; there is no TPM-enforced DA backstop on this deployment.
- **SIGKILL strands the clipboard secret (A8).** SIGKILL is uncatchable, so no userspace handler can scrub the clipboard on it. Documented and unavoidable.
- **TPM bus interposition / null-session sniffing (out of scope — not exercised).** This campaign did not attack the physical CPU↔TPM bus. The Linux backend seals into no-auth/no-PCR KEYEDHASH objects without an observed salted/HMAC session, so a discrete-TPM bus interposer is a standard residual the deployment does not defend against. Stated as a known limitation, not a tested finding.
- **Pre-auth Argon2 memory pressure at the *legitimate* ceiling.** Distinct from A12's tamper: even a genuine Paranoid (8 GiB) / Default (4 GiB) recovery file cannot be imported on a sub-8-GiB host. This is the same root cause as A12 and is folded into that fix; it is the cost-bound side of the same defect.

---

## 6. Bottom Line

**Is the real-hardware deployment safe to ship?**

**For its core security guarantees — yes.** Against an active attacker with the vault file, the binary, foreign/absent TPMs, and local same-uid access, `passman` did not leak a single secret, did not bypass authentication, did not surrender key material, and did not corrupt or mis-decrypt data across 11 of 12 attack classes. Hardware binding, AEAD integrity, slot binding, parser/input robustness, on-disk and process hygiene, and concurrency control all fail closed. There is **no cryptographic break and no authentication break.** The two PARTIAL findings (A4 rollback, A6 lockout reset) are low-severity, local-attacker, by-design behaviors that the architecture explicitly excludes from its security boundary.

**What must change first.**

1. **Fix A12 before shipping to mobile / constrained (sub-8-GiB) devices — blocking for those targets.** The recovery-import memory ceiling is a fixed 8 GiB, more than the host (and any phone) can satisfy. It is exploitable as a **pre-auth, no-password DoS** via a 4-byte header edit (OOM-kill / SIGKILL / hang), and it **breaks legitimate default-preset recovery** on such devices. Clamp import-side KDF memory to a host-aware budget, lower/target-scope `MAX_M_KIB`, and convert allocation failure into a clean typed error (this also fixes the A2 in-range SIGABRT). On desktops with ≥8 GiB the impact is degraded availability rather than a hard kill, but the fix is the same and cheap.

2. **Recommended, non-blocking:** harden A6's online throttle (TPM authValue PIN or TPM NV-backed counter; persist the last-accepted TOTP step) and, if rollback detection ever enters scope, bind a TPM monotonic counter into the vault AD (A4). Until then, document both as accepted limitations.

No emergency response is warranted — there is no exposure of stored credentials. Resolve A12, and the deployment is ship-ready across all targets.
