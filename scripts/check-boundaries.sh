#!/usr/bin/env bash
#
# Architectural boundary checks for the passman workspace.
#
# Enforces the invariants from architecture.md §2.2 (the one-way acyclic crate
# dependency graph) and §2.4 (pure crates do no I/O / env / logging, and carry
# `#![forbid(unsafe_code)]`). Intended to run in CI and locally. Exits non-zero
# on any violation and prints every offending location.
#
# These are deliberately greps, not clippy lints: a single workspace `clippy.toml`
# cannot scope `disallowed-methods` per-crate (passman-core legitimately uses
# std::fs), and per-crate clippy.toml files would not catch a dependency-graph
# regression. This script checks both in one place.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
err() {
    echo "BOUNDARY VIOLATION: $*" >&2
    fail=1
}

# --- 1. Dependency graph -----------------------------------------------------
#
# Each crate's [dependencies] path-deps must be a subset of its allowed set.
# The allowlist is a DAG (crypto -> {totp,policy,hsm,recovery} -> vault -> core),
# so enforcing the subset relation also guarantees the graph stays acyclic.
# Dev-dependencies are exempt by design (e.g. passman-core dev-depends on the
# passman-hsm `mock` feature).

declare -A allowed
allowed[passman-crypto]=""
allowed[passman-totp]="passman-crypto"
allowed[passman-policy]="passman-crypto"
allowed[passman-hsm]="passman-crypto"
allowed[passman-recovery]="passman-crypto"
allowed[passman-vault]="passman-crypto passman-policy"
allowed[passman-core]="passman-crypto passman-totp passman-policy passman-vault passman-hsm passman-recovery"
# passman-platform is an independent shell-support leaf (paths + settings). It
# depends on no other passman crate — the binaries compose it with passman-core.
allowed[passman-platform]=""
# passman-cli is a top-level binary shell: it composes core with the platform
# crate and the HSM backend selection, and may depend on any library crate.
allowed[passman-cli]="passman-crypto passman-totp passman-policy passman-vault passman-hsm passman-recovery passman-core passman-platform"

for dir in crates/*/; do
    name=$(awk -F\" '/^name *=/{print $2; exit}' "$dir/Cargo.toml")
    if [ -z "${allowed[$name]+set}" ]; then
        err "unknown crate '$name' is not in the boundary allowlist (update this script)"
        continue
    fi
    # Path-dependency crate names declared under [dependencies] only.
    deps=$(awk '/^\[dependencies\]/{s=1;next} /^\[/{s=0} s && /path *=/{print}' "$dir/Cargo.toml" \
        | grep -oE 'passman-[a-z]+' | sort -u || true)
    for d in $deps; do
        case " ${allowed[$name]} " in
        *" $d "*) : ;;
        *) err "$name depends on $d, not allowed by §2.2 (allowed: '${allowed[$name]}')" ;;
        esac
    done
done

# --- 2. Pure crates: no I/O, env, process, or logging ------------------------
#
# crypto/totp/policy/vault/recovery are pure (architecture.md §2.3/§2.4): all
# filesystem, network, env, process, and logging belong to passman-core (and the
# platform shells). hsm is excluded — it hosts FFI backends and is not pure.

pure="passman-crypto passman-totp passman-policy passman-vault passman-recovery"
forbidden='std::fs|std::net|std::env|std::process|tracing::|[^a-z]log::|println!|eprintln!|eprint!|[^a-z]print!|dbg!'
for c in $pure; do
    if hits=$(grep -rnE "$forbidden" "crates/$c/src/"); then
        err "$c (pure crate) uses a forbidden std/logging API:"
        echo "$hits" >&2
    fi
done

# --- 3. forbid(unsafe_code) on the pure crates + core ------------------------
#
# Matches the real inner attribute line, not a doc-comment mention of it (hsm's
# lib.rs explains in prose why it is *not* forbid-unsafe; that must not match).
# hsm is intentionally excluded (it needs `unsafe` for platform FFI).

needs_forbid="passman-crypto passman-totp passman-policy passman-vault passman-recovery passman-core passman-platform"
for c in $needs_forbid; do
    if ! grep -qE '^[[:space:]]*#!\[forbid\(unsafe_code\)\]' "crates/$c/src/lib.rs"; then
        err "$c is missing #![forbid(unsafe_code)] in src/lib.rs"
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "Boundary checks FAILED." >&2
    exit 1
fi
echo "All boundary checks passed."
