# Task 6 — CI / Supply-Chain Hardening Report

Date: 2026-06-22

---

## 1. Finding S8 — build-twice job (the over-claim)

**Problem:** `docs/RELEASE.md` stated "CI independently runs `reproduce.sh` twice and
diffs the two hashes" but no such job existed in `.github/workflows/ci.yml`.

**Fix:** Added a `build-twice` job to `ci.yml` that:

1. Checks out the repo into `$GITHUB_WORKSPACE/passman-a` using `actions/checkout@v4 path: passman-a`.
2. Installs `libtss2-dev libdbus-1-dev pkg-config` (required by passman-cli which links libtss2 + libdbus).
3. Runs `SOURCE_DATE_EPOCH=1700000000 ./reproduce.sh` from `passman-a/`; captures output with `tee /tmp/hash-a.txt`.
4. Copies the checkout minus `target/` to `/tmp/passman-b/` via `rsync -a --exclude='target/'`.
5. Runs the same `reproduce.sh` from `/tmp/passman-b/`; captures output with `tee /tmp/hash-b.txt`.
6. Compares the SHA-256 field from both files with `diff <(awk '{print $1}' ...)`. Fails with exit 1 if they differ.

The job runs on every push and PR (inherits the top-level `on: push / pull_request` trigger).

**RELEASE.md reconciliation:** Updated the paragraph in §1 to accurately describe what
the job does and that the published expected hash is compared manually at release time
(not automatically, which was never true).

---

## 2. Pinned supply-chain tool versions

**Problem:** Three `cargo install` invocations had no `--version` flag — whatever
latest existed at CI time would be installed.

**Versions sourced from crates.io API (`https://crates.io/api/v1/crates/<name>/versions`):**

| Tool | Pinned version | Source |
|------|---------------|--------|
| cargo-audit | 0.22.2 | crates.io — most recent stable; 0.22.x is the current series (0.21.x also listed for reference) |
| cargo-deny | 0.19.9 | crates.io — most recent stable in 0.19.x; 0.19.3 was yanked and is excluded |
| cargo-fuzz | 0.13.2 | crates.io — most recent stable; 0.13.x is the current series |

**Changes in `ci.yml`:**

- `cargo install cargo-audit --locked` → `cargo install cargo-audit --version 0.22.2 --locked`
- `cargo install cargo-deny --locked` → `cargo install cargo-deny --version 0.19.9 --locked`
- `cargo install cargo-fuzz --locked` → `cargo install cargo-fuzz --version 0.13.2 --locked`

`--locked` was already present in all three; adding `--version` pins the index resolution too.

---

## 3. Gradle wrapper integrity

### 3a. distributionSha256Sum

**Problem:** `gradle-wrapper.properties` had no `distributionSha256Sum` — the wrapper
jar fetches and unpacks the distribution without verifying it.

**Hash sourced:** fetched `https://services.gradle.org/distributions/gradle-8.10.2-bin.zip.sha256`
(301 → `https://downloads.gradle.org/distributions/gradle-8.10.2-bin.zip.sha256`).

Raw response (64-byte ASCII hex string):
```
31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26
```

**Change to `android/gradle/wrapper/gradle-wrapper.properties`:**
```
distributionSha256Sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26
```

Added on the line immediately after `distributionUrl`. Gradle reads this field and
aborts with an error if the downloaded zip does not match, before any unzip occurs.

### 3b. gradle-wrapper-validation job

**Problem:** The committed `gradle-wrapper.jar` is an executable binary with no CI
integrity check.

**Fix:** Added a `gradle-wrapper-validation` job to `ci.yml`:

```yaml
gradle-wrapper-validation:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: gradle/actions/wrapper-validation@v4
```

`gradle/actions/wrapper-validation@v4` is the official Gradle action; it checks
`gradle-wrapper.jar` against a maintained list of known-good checksums published
by Gradle. Any tampered or unknown jar fails the job.

---

## 4. Validation

### YAML parse
```
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo YAML_OK
```
Result: **YAML_OK**

### reproduce.sh
Not modified — `bash -n` not required.

### Gradle hash provenance
Fetched live from the Gradle CDN redirect chain:
- `https://services.gradle.org/distributions/gradle-8.10.2-bin.zip.sha256` → 301 →
- `https://downloads.gradle.org/distributions/gradle-8.10.2-bin.zip.sha256`
- Response: `31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26`

### Crate version existence evidence
All three versions confirmed present in the crates.io `/versions` API response
for each respective crate. No pre-release versions were selected.

---

## Files changed

| File | Change |
|------|--------|
| `.github/workflows/ci.yml` | Pin cargo-audit → 0.22.2, cargo-deny → 0.19.9, cargo-fuzz → 0.13.2; add `build-twice` job; add `gradle-wrapper-validation` job |
| `android/gradle/wrapper/gradle-wrapper.properties` | Add `distributionSha256Sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26` |
| `docs/RELEASE.md` | Correct the build-twice description to match what the CI job actually does |

---

## Concerns / notes

- **rust-cache scoping in build-twice:** The `Swatinem/rust-cache@v2` step is configured
  with `workspaces: passman-a -> passman-a/target`. The second build runs from
  `/tmp/passman-b/` which is outside the cache scope, so it will always do a cold
  Cargo build. This is intentional — the point is two independent builds — and means
  the job takes ~2× the compile time of a normal build. Acceptable for a gate that
  runs on every push.

- **rsync availability:** `rsync` is present on `ubuntu-latest` GitHub-hosted runners.
  If this ever changes, replace with `cp -a passman-a /tmp/passman-b && rm -rf /tmp/passman-b/target`.

- **build-twice and system-library linkage:** `reproduce.sh`'s own header notes that
  system-library linkage (`libtss2`, `libdbus`) is explicitly out of the reproducibility
  guarantee scope. The two builds here use the same runner image, so the same system
  lib versions are in play — this is the same guarantee as "two builds on the same
  machine." Cross-machine reproducibility with different distro versions of libtss2 is
  a harder problem and remains out of scope per §9.4.

- **gradle/actions/wrapper-validation@v4 is not pinned to a commit SHA.** The action
  is owned by the official `gradle` GitHub org. Pinning to a SHA would eliminate the
  remaining supply-chain risk here; left at `@v4` to match the style of the rest of
  the workflow (`actions/checkout@v4`). If the project policy changes to require
  SHA-pinned actions, all four `uses:` lines should be updated together.
