#!/usr/bin/env bash
# eyesharvester installer for Linux / macOS.
#
# What it does:
#   1. Verifies Python 3.8+ is present.
#   2. Copies eyesharvester.py into a bin directory on your PATH.
#   3. Makes it executable, callable as `eyesharvester`.
#
# Modes:
#   Run from a cloned repo:
#       ./install.sh
#   Pipe-install from the web (public repo only):
#       curl -fsSL https://raw.githubusercontent.com/Exhunterx/eyesharvester/main/install.sh | bash
#
# Options (env vars):
#   PREFIX=$HOME/.local   install per-user, no sudo  (default if non-root)
#   PREFIX=/usr/local     install system-wide        (default if root)
#   BRANCH=main           branch to fetch when piping
#   REPO=Exhunterx/eyesharvester
#
set -euo pipefail

REPO="${REPO:-Exhunterx/eyesharvester}"
BRANCH="${BRANCH:-main}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/eyesharvester.py"

# Pick install prefix: per-user by default, /usr/local if running as root.
if [[ -z "${PREFIX:-}" ]]; then
  if [[ $EUID -eq 0 ]]; then PREFIX="/usr/local"; else PREFIX="$HOME/.local"; fi
fi
BIN_DIR="$PREFIX/bin"

say() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Python check ----------------------------------------------------------
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.8+ first."
PY_OK=$(python3 - <<'PY'
import sys
print("ok" if sys.version_info >= (3, 8) else "old")
PY
)
[[ "$PY_OK" == "ok" ]] || die "Python 3.8+ required (found $(python3 -V))."

# --- Locate or fetch eyesharvester.py --------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
SRC=""
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/eyesharvester.py" ]]; then
  SRC="$SCRIPT_DIR/eyesharvester.py"
  say "Using local source: $SRC"
else
  command -v curl >/dev/null 2>&1 || die "curl not found, and no local eyesharvester.py to install."
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  say "Downloading from $RAW_URL"
  if ! curl -fsSL "$RAW_URL" -o "$TMP/eyesharvester.py"; then
    die "Download failed. If the repo is PRIVATE, clone it first instead:
       gh repo clone $REPO && cd eyesharvester && ./install.sh"
  fi
  SRC="$TMP/eyesharvester.py"
fi

# --- Install ---------------------------------------------------------------
mkdir -p "$BIN_DIR"
DEST="$BIN_DIR/eyesharvester"
install -m 0755 "$SRC" "$DEST"
say "Installed: $DEST"

# --- PATH hint -------------------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not in your PATH. Add this to your shell rc:
       export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

# --- Verify ----------------------------------------------------------------
if "$DEST" --help >/dev/null 2>&1; then
  say "OK. Run: eyesharvester --help"
else
  die "Install completed but '$DEST --help' failed. Check Python install."
fi
