#!/usr/bin/env bash
# passman installer for Linux — builds the CLI and the GTK desktop app from
# source and installs them into your user profile. No root required.
#
#   ./install.sh              # CLI + desktop app
#   ./install.sh --cli-only   # just the `passman` CLI (skips GTK + its deps)
#   PREFIX=/usr/local sudo ./install.sh   # system-wide instead of ~/.local
set -euo pipefail
cd "$(dirname "$0")"

PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"
APPDIR="$PREFIX/share/applications"
cli_only=0
for a in "$@"; do
  case "$a" in
    --cli-only) cli_only=1 ;;
    -h | --help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; }

# 1. Rust toolchain.
if ! command -v cargo >/dev/null 2>&1; then
  err "Rust is not installed (needed to build passman)."
  echo "    Install it from https://rustup.rs and re-run this script." >&2
  exit 1
fi

# 2. GTK4 dev libraries (desktop app only).
if [ "$cli_only" -eq 0 ] && ! pkg-config --exists gtk4 2>/dev/null; then
  err "GTK 4 development libraries were not found (needed for the desktop app)."
  cat >&2 <<'HINT'
    Install them with your package manager, e.g.:
      Debian/Ubuntu:  sudo apt install libgtk-4-dev
      Fedora:         sudo dnf install gtk4-devel
      Arch:           sudo pacman -S gtk4
    …or run  ./install.sh --cli-only  to install just the command-line tool.
HINT
  exit 1
fi

mkdir -p "$BINDIR"

# 3. CLI.
say "Building the CLI (release)… (first build pulls dependencies; give it a minute)"
cargo build --release -p passman-cli
install -m 755 target/release/passman "$BINDIR/passman"
say "Installed $BINDIR/passman"

# 4. Desktop app + launcher.
if [ "$cli_only" -eq 0 ]; then
  say "Building the desktop app (release)…"
  cargo build --release -p passman-gtk
  install -m 755 target/release/passman-gtk "$BINDIR/passman-gtk"
  mkdir -p "$APPDIR"
  sed "s|@BIN@|$BINDIR/passman-gtk|g" packaging/passman.desktop >"$APPDIR/passman.desktop"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPDIR" 2>/dev/null || true
  say "Installed $BINDIR/passman-gtk and a desktop launcher"
fi

# 5. PATH hint.
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *)
    echo
    err "$BINDIR is not on your PATH yet."
    echo "    Add it (then open a new terminal):" >&2
    echo "      echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.profile" >&2
    ;;
esac

echo
say "Done. Next steps:"
echo "    passman init          # create your vault (prints a one-time TOTP setup link)"
echo "    passman add github    # add an entry"
echo "    passman --help        # everything else"
[ "$cli_only" -eq 0 ] && echo "    passman-gtk           # or launch the desktop app from your applications menu"
