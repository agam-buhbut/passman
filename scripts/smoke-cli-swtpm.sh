#!/usr/bin/env bash
# End-to-end smoke test of the real `passman` binary against an isolated swtpm
# (a software TPM in a tempdir — never touches the real /dev/tpm*). Drives the
# TPM2 backend through init -> add -> list -> get. Exits non-zero on any failure.
set -euo pipefail

BIN="${1:?usage: smoke-cli-swtpm.sh <path-to-passman-binary>}"
MASTER='Sm0ke-Test-Master-Passphrase!'

command -v swtpm >/dev/null || { echo "SKIP: swtpm not installed"; exit 0; }
command -v python3 >/dev/null || { echo "SKIP: python3 not installed"; exit 0; }

STATE_DIR="$(mktemp -d)"
VAULT_DIR="$(mktemp -d)"
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
cleanup() { kill "${SWTPM_PID:-}" 2>/dev/null || true; rm -rf "$STATE_DIR" "$VAULT_DIR"; }
trap cleanup EXIT

swtpm socket --tpm2 --tpmstate "dir=$STATE_DIR" \
  --server "type=tcp,port=$PORT,bindaddr=127.0.0.1" \
  --ctrl "type=tcp,port=$((PORT+1)),bindaddr=127.0.0.1" \
  --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWTPM_PID=$!
export TCTI="swtpm:host=127.0.0.1,port=$PORT"

# Wait for swtpm to accept connections.
for _ in $(seq 1 200); do
  python3 -c "import socket;socket.create_connection(('127.0.0.1',$PORT),0.1).close()" 2>/dev/null && break
  sleep 0.05
done

run() { "$BIN" --vault-dir "$VAULT_DIR" "$@"; }
totp() { python3 - "$1" <<'PY'
import sys, hmac, hashlib, struct, base64, time
b32 = sys.argv[1]
key = base64.b32decode(b32 + '=' * ((8 - len(b32) % 8) % 8), casefold=True)
h = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
o = h[-1] & 0x0f
print('%06d' % ((struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000))
PY
}

echo "1) init (enrolls two slots into swtpm, derives the vault key)…"
URI=$(printf '%s\n%s\n' "$MASTER" "$MASTER" | run init --preset low | grep '^otpauth://')
SECRET=$(printf '%s' "$URI" | sed -n 's/.*[?&]secret=\([^&]*\).*/\1/p')
[ -n "$SECRET" ] || { echo "FAIL: no TOTP secret in provisioning URI"; exit 1; }
[ -f "$VAULT_DIR/vault.pmv" ] || { echo "FAIL: vault file not created"; exit 1; }
echo "   vault created; TOTP secret provisioned."

echo "2) add github --generate…"
printf '%s\n%s\nocto-cat\nhttps://github.com\nwork note\n' "$MASTER" "$(totp "$SECRET")" \
  | run add github --generate --length 24 >/dev/null
echo "   added."

echo "3) list…"
LABELS=$(printf '%s\n%s\n' "$MASTER" "$(totp "$SECRET")" | run list)
[ "$LABELS" = "github" ] || { echo "FAIL: list returned '$LABELS' (want 'github')"; exit 1; }
echo "   list shows: $LABELS"

echo "4) get github --show --field username…"
GOT=$(printf '%s\n%s\n' "$MASTER" "$(totp "$SECRET")" | run get github --show --field username)
[ "$GOT" = "octo-cat" ] || { echo "FAIL: get returned '$GOT' (want 'octo-cat')"; exit 1; }
echo "   revealed username: $GOT"

echo "5) wrong password is rejected…"
if printf 'wrong-password\n%s\n' "$(totp "$SECRET")" | run list >/dev/null 2>&1; then
  echo "FAIL: wrong password unlocked the vault"; exit 1
fi
echo "   rejected as expected."

echo "ALL SMOKE CHECKS PASSED (real passman binary + swtpm TPM2 backend)."
