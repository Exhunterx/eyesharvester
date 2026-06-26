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
# Try several candidate interpreters. Some systems have a broken /usr/bin/python3
# (e.g. replaced by a venv-launcher wrapper whose venv has been removed), so we
# verify each candidate actually runs a real Python sanity check.
PY=""
for cand in python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
  command -v "$cand" >/dev/null 2>&1 || continue
  if ver=$("$cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null); then
    major=${ver%.*}; minor=${ver#*.}
    if [[ "$major" -ge 3 && "$minor" -ge 8 ]]; then
      PY="$cand"; PY_VER="$ver"
      break
    fi
  fi
done
if [[ -z "$PY" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    warn "python3 exists but is not a working Python 3.8+ interpreter."
    warn "Sample output: $(python3 -V 2>&1 | head -1)"
    warn "If you see a shell error like 'line N: .../python: No such file or directory',"
    warn "your /usr/bin/python3 is a broken wrapper. Restore the real interpreter:"
    warn "  sudo apt install --reinstall python3 python3-minimal     # Debian/Ubuntu"
    warn "  sudo dnf reinstall python3                              # Fedora/RHEL"
  fi
  die "No working Python 3.8+ found. Install python3 (>=3.8) and re-run."
fi
say "Using $PY ($PY_VER)"

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
# Invoke through $PY explicitly so a broken `#!/usr/bin/env python3` shebang
# doesn't fool us when the interpreter we just validated isn't the default.
if "$PY" "$DEST" --help >/dev/null 2>&1; then
  say "OK. Run: eyesharvester --help"
  if [[ "$PY" != "python3" ]]; then
    warn "Heads up: 'python3' on this system isn't $PY. The 'eyesharvester'"
    warn "shortcut uses '#!/usr/bin/env python3' - if it fails, run it as:"
    warn "    $PY $DEST --help"
  fi
else
  die "Install completed but '$PY $DEST --help' failed. Check Python install."
fi
