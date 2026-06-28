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
# passman-gtk is the GTK4 desktop binary shell; like the CLI it may depend on any
# library crate.
allowed[passman-gtk]="passman-crypto passman-totp passman-policy passman-vault passman-hsm passman-recovery passman-core passman-platform"
# passman-uniffi is the Android binding shell (concrete App<AndroidKeyStore> +
# foreign callbacks); it may depend on any library crate.
allowed[passman-uniffi]="passman-crypto passman-totp passman-policy passman-vault passman-hsm passman-recovery passman-core passman-platform"

# Shared edge check: is `$2` (a passman path-dep) allowed for crate `$1`?
check_edge() {
    local name="$1" d="$2"
    if [ -z "${allowed[$name]+set}" ]; then
        err "unknown crate '$name' is not in the boundary allowlist (update this script)"
        return
    fi
    case " ${allowed[$name]} " in
    *" $d "*) : ;;
    *) err "$name depends on $d, not allowed by §2.2 (allowed: '${allowed[$name]}')" ;;
    esac
}

# Primary check: derive the real dependency graph from `cargo metadata` (parsed
# with jq). Unlike the awk heuristic below it sees EVERY normal-dependency form —
# `[dependencies]`, the `[dependencies.foo]` sub-table, and
# `[target.'cfg(...)'.dependencies]` (target-specific deps carry kind=null too).
# Dev- and build-dependencies are exempt by design (kind "dev"/"build"), matching
# the original. Guarded: if cargo/jq/metadata are unavailable we fall back to the
# awk secondary signal alone rather than failing the whole check spuriously.
if command -v cargo >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 \
    && meta=$(cargo metadata --no-deps --format-version 1 2>/dev/null); then
    while read -r name d; do
        [ -n "$name" ] || continue
        check_edge "$name" "$d"
    done < <(printf '%s' "$meta" | jq -r '
        .packages[]
        | .name as $n
        | .dependencies[]
        | select(.path != null and .kind == null and (.name | startswith("passman-")))
        | "\($n) \(.name)"')
else
    echo "NOTE: cargo metadata / jq unavailable — relying on the awk heuristic only." >&2
fi

# Secondary signal: the original awk/grep heuristic over the literal
# `[dependencies]` table. Kept as defence-in-depth (it also flags any crate dir
# missing from the allowlist) and is the sole check when metadata is absent.
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
        check_edge "$name" "$d"
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

# --- 4. cfg(target_*) confined to the HSM backend + binary shells ------------
#
# §2.4: platform-conditional code (cfg(target_os/arch/family/env/vendor/...))
# belongs only in passman-hsm (per-platform FFI backends) and the binary shells
# (cli/gtk/uniffi, which select platform-specific paths/behaviour). A pure
# library crate or the core must stay platform-agnostic. `cfg(unix)` etc. are not
# matched — only the `target_*` predicates that fork on a specific platform.

platform_agnostic="passman-crypto passman-totp passman-policy passman-vault passman-recovery passman-core passman-platform"
for c in $platform_agnostic; do
    if hits=$(grep -rnE 'cfg!?\([^)]*target_(os|arch|family|env|vendor|pointer_width)' "crates/$c/src/"); then
        err "$c must stay platform-agnostic but uses cfg(target_*) (§2.4 — only hsm + binary shells may):"
        echo "$hits" >&2
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "Boundary checks FAILED." >&2
    exit 1
fi
echo "All boundary checks passed."
