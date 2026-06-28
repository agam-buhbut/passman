#!/usr/bin/env bash
# Reproducible build of the passman CLI core binary (architecture.md §9.4).
#
# Two runs on different machines / home directories must produce a byte-identical
# binary. What pins it:
#   - rust-toolchain.toml  → the exact compiler
#   - Cargo.lock + --locked → the exact dependency versions
#   - codegen-units = 1     → deterministic codegen partitioning (release profile)
#   - the path remaps below → no machine-specific absolute paths in the binary
#   - SOURCE_DATE_EPOCH     → a fixed build timestamp
#
# Prints the SHA-256 of the artifact; compare it against the published expected
# hash (see docs/RELEASE.md). CI runs this twice and diffs the two hashes.
#
# Scope (§9.4): the GUARANTEE is the core Rust binary. The .deb/.apk/.exe
# wrappers and system-library linkage are explicitly out of scope.
set -euo pipefail
cd "$(dirname "$0")"

: "${CARGO_HOME:=$HOME/.cargo}"
: "${RUSTUP_HOME:=$HOME/.rustup}"
# A fixed timestamp: the release commit's time if available, else a constant.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct 2>/dev/null || echo 1700000000)}"

# Remap every machine-specific absolute path prefix out of the binary: the
# project dir, the cargo registry, and the rustup toolchain.
export RUSTFLAGS="--remap-path-prefix=$PWD=/build/passman --remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=$RUSTUP_HOME=/rustup ${RUSTFLAGS:-}"

echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" >&2
echo "RUSTFLAGS=$RUSTFLAGS" >&2
echo "building passman-cli (release, --locked)…" >&2

cargo build --release --locked -p passman-cli

ART="target/release/passman"
echo >&2
echo "=== reproducible artifact (compare to the published expected hash) ===" >&2
sha256sum "$ART"
