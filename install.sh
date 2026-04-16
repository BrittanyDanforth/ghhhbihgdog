#!/bin/bash
# Toolkit — Installer & Environment Setup
# Handles: first install, re-install, broken venv, missing packages
# Safe to run multiple times — skips what's already working
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
DIM='\033[0;90m'; BOLD='\033[1;37m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail() { echo -e "  ${RED}[x]${NC} $1"; }
dim()  { echo -e "  ${DIM}$1${NC}"; }
confirm() {
    read -p "  $1 (y/n): " -n 1 -r; echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ── Package-name → import-name mapping ─────────────────────────────────────
# pip package names differ from Python import names. This is the canonical
# mapping for every dependency we install. install.sh and the gs launcher
# both use this to verify packages are actually importable in the venv.
pkg_to_import() {
    case "$1" in
        PySocks)         echo "socks" ;;
        pycryptodomex)   echo "Cryptodome" ;;
        beautifulsoup4)  echo "bs4" ;;
        pyyaml)          echo "yaml" ;;
        aiohttp-socks)   echo "aiohttp_socks" ;;
        python-gnupg)    echo "gnupg" ;;
        *)               echo "$1" | tr 'A-Z' 'a-z' ;;
    esac
}

echo ""
echo "  Setup"
echo "  -----"

# ── Step 1: System packages ────────────────────────────────────────────────
echo "  [1/5] System packages..."
if command -v apt-get &>/dev/null; then
    NEED_PKGS=""
    for pkg in tor torsocks jq gnupg python3-pip python3-venv python3-dev curl wget build-essential; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            NEED_PKGS="$NEED_PKGS $pkg"
        fi
    done
    if [ -n "$NEED_PKGS" ]; then
        dim "Installing system dependencies..."
        sudo apt-get update -qq 2>/dev/null || true
        sudo apt-get install -y -qq $NEED_PKGS 2>/dev/null || {
            warn "Some packages need manual install. Retrying with details..."
            sudo apt-get install -y $NEED_PKGS || true
        }
        ok "System packages installed"
    else
        ok "All system packages present"
    fi
else
    warn "Not Debian/Ubuntu — install manually: tor, python3-pip, python3-venv, python3-dev, curl, build-essential"
fi

# ── Step 2: Python environment + packages ──────────────────────────────────
echo ""
echo "  [2/5] Python setup..."

PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
if [ -z "$PY" ]; then
    fail "python3 not found. Install: sudo apt install python3"
    exit 1
fi

# Detect broken venv and rebuild
if [ -d "$VENV_DIR" ]; then
    if [ ! -f "$VENV_DIR/bin/python3" ]; then
        warn "Environment broken (missing interpreter). Rebuilding..."
        rm -rf "$VENV_DIR"
    elif ! "$VENV_DIR/bin/python3" -c "import pip" 2>/dev/null; then
        warn "Environment broken (missing pip). Rebuilding..."
        rm -rf "$VENV_DIR"
    fi
fi

# Create venv if needed
if [ ! -d "$VENV_DIR" ]; then
    dim "Creating virtual environment..."
    if ! $PY -m venv "$VENV_DIR" 2>&1; then
        fail "venv creation failed. Trying with --without-pip..."
        $PY -m venv --without-pip "$VENV_DIR" || {
            fail "Cannot create virtual environment."
            fail "Install: sudo apt install python3-venv python3-dev"
            exit 1
        }
    fi
    ok "Virtual environment created"
fi

# Set interpreter paths — these are the ONLY interpreters used from here on.
# install.sh installs into VENV_PY. The gs launcher runs VENV_PY. The `run`
# script re-execs under VENV_PY. Child scripts inherit sys.executable from
# `run`. Therefore every layer uses the same interpreter and site-packages.
VENV_PY="$VENV_DIR/bin/python3"
VENV_PIP="$VENV_PY -m pip"

# Ensure pip exists in the venv
if ! "$VENV_PY" -c "import pip" 2>/dev/null; then
    dim "Installing pip into environment..."
    # Method 1: ensurepip
    "$VENV_PY" -m ensurepip --upgrade 2>/dev/null || {
        # Method 2: get-pip.py
        dim "Trying get-pip.py..."
        curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/_get_pip.py 2>/dev/null && \
        "$VENV_PY" /tmp/_get_pip.py 2>/dev/null && \
        rm -f /tmp/_get_pip.py || {
            # Method 3: copy system pip
            dim "Trying system pip..."
            $PY -m pip install --target="$VENV_DIR/lib/python3.*/site-packages/" pip 2>/dev/null || {
                fail "Cannot install pip. Try:"
                fail "  sudo apt install python3-pip python3-venv"
                fail "  rm -rf .venv && bash install.sh"
                exit 1
            }
        }
    }
fi

# Upgrade pip quietly
$VENV_PIP install --upgrade pip 2>/dev/null || true

# ── Install packages ──────────────────────────────────────────────────────
# Core deps are required. Extra deps enable optional features.
CORE_DEPS="requests PySocks tenacity stem monero psutil"
EXTRA_DEPS="cryptography pycryptodomex qrcode pyyaml beautifulsoup4 aiohttp aiohttp-socks"

dim "Installing Python packages..."

# Try batch install first (fastest). Capture pip's actual exit code instead
# of piping through tail (which swallows the real return code).
INSTALL_OK=true
INSTALL_OUTPUT=$($VENV_PIP install $CORE_DEPS $EXTRA_DEPS 2>&1) || INSTALL_OK=false

if [ "$INSTALL_OK" = true ]; then
    ok "Python packages installed"
else
    warn "Batch install had issues. Installing one by one..."
    for dep in $CORE_DEPS; do
        MOD="$(pkg_to_import "$dep")"
        if "$VENV_PY" -c "import $MOD" 2>/dev/null; then
            ok "$dep (present)"
        else
            $VENV_PIP install "$dep" 2>&1 | tail -5
            if "$VENV_PY" -c "import $MOD" 2>/dev/null; then
                ok "$dep"
            else
                fail "$dep FAILED — see error above"
            fi
        fi
    done
    dim "Installing extra packages..."
    for dep in $EXTRA_DEPS; do
        MOD="$(pkg_to_import "$dep")"
        if "$VENV_PY" -c "import $MOD" 2>/dev/null; then
            ok "$dep (present)"
        else
            $VENV_PIP install "$dep" 2>/dev/null && ok "$dep" || warn "$dep (optional, skipped)"
        fi
    done
fi

# ── Step 3: Verify ALL imports ─────────────────────────────────────────────
# This is the hard gate. Every core dependency must be importable in the
# EXACT Python interpreter that will run the toolkit. If any core dep fails,
# setup fails — no silent "it'll probably work" acceptance.
echo ""
echo "  [3/5] Verifying imports..."
IMPORT_FAILS=""

# Core deps: MUST all pass
for mod_pkg in "requests:requests" "socks:PySocks" "tenacity:tenacity" "stem:stem" "monero:monero" "psutil:psutil"; do
    mod="${mod_pkg%%:*}"
    pkg="${mod_pkg##*:}"
    if "$VENV_PY" -c "import $mod" 2>/dev/null; then
        ok "$pkg"
    else
        fail "$pkg — cannot import '$mod'"
        IMPORT_FAILS="$IMPORT_FAILS $pkg"
    fi
done

# Extra deps: warn but don't fail
EXTRA_WARNS=""
for mod_pkg in "cryptography:cryptography" "Cryptodome:pycryptodomex" "yaml:pyyaml" "bs4:beautifulsoup4" "qrcode:qrcode" "aiohttp:aiohttp" "aiohttp_socks:aiohttp-socks"; do
    mod="${mod_pkg%%:*}"
    pkg="${mod_pkg##*:}"
    if "$VENV_PY" -c "import $mod" 2>/dev/null; then
        ok "$pkg"
    else
        warn "$pkg — optional, some features unavailable"
        EXTRA_WARNS="$EXTRA_WARNS $pkg"
    fi
done

if [ -n "$IMPORT_FAILS" ]; then
    echo ""
    fail "CRITICAL: Core packages not importable:$IMPORT_FAILS"
    echo ""
    echo "  This usually means one of:"
    echo "    1. Missing build tools: sudo apt install python3-dev build-essential"
    echo "    2. Broken Python install: sudo apt install --reinstall python3 python3-venv"
    echo "    3. Network issue during pip install"
    echo ""
    echo "  Fix the issue and re-run: bash install.sh"
    echo ""
    exit 1
fi

# ── Step 4: Tor ────────────────────────────────────────────────────────────
echo ""
echo "  [4/5] Tor..."

if [ -f /etc/tor/torrc ]; then
    if ! grep -qE "^\s*ControlPort\s+9051" /etc/tor/torrc 2>/dev/null; then
        echo "" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc >/dev/null
        ok "Tor control port configured"
    else
        ok "Tor control port configured"
    fi
fi

TOR_RUNNING=false
for TOR_PORT in 9050 9150; do
    if curl -s --max-time 5 --connect-timeout 3 --socks5-hostname "127.0.0.1:${TOR_PORT}" \
       https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        ok "Tor verified (port ${TOR_PORT})"
        TOR_RUNNING=true
        break
    fi
done

if [ "$TOR_RUNNING" = false ]; then
    warn "Tor not responding. Trying to start..."
    sudo systemctl start tor 2>/dev/null || sudo service tor start 2>/dev/null || true
    sleep 3
    for TOR_PORT in 9050 9150; do
        if curl -s --max-time 10 --connect-timeout 5 --socks5-hostname "127.0.0.1:${TOR_PORT}" \
           https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
            ok "Tor started (port ${TOR_PORT})"
            TOR_RUNNING=true
            break
        fi
    done
    if [ "$TOR_RUNNING" = false ]; then
        echo ""
        fail "Tor is NOT working."
        echo "  Start Tor before using the toolkit:"
        echo "    sudo systemctl start tor"
        echo "    (or open Tor Browser for port 9150)"
        echo ""
    fi
fi

# ── Step 5: Monero tools ──────────────────────────────────────────────────
echo ""
echo "  [5/5] Monero tools..."
MONERO_OK=true
for tool in monerod monero-wallet-cli monero-wallet-rpc; do
    if command -v $tool &>/dev/null; then
        ok "$tool"
    else
        warn "$tool not found"
        MONERO_OK=false
    fi
done

if [ "$MONERO_OK" = false ]; then
    echo ""
    if confirm "Download Monero CLI tools?"; then
        cd /tmp
        wget -q --show-progress https://downloads.getmonero.org/cli/linux64 -O monero-cli.tar.bz2 && \
        tar xf monero-cli.tar.bz2 && \
        sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/ && \
        rm -rf monero-x86_64-linux-gnu-* monero-cli.tar.bz2 && \
        ok "Monero CLI installed" || \
        fail "Download failed — see https://www.getmonero.org/downloads/"
        cd - >/dev/null
    fi
fi

# ── Create launcher ───────────────────────────────────────────────────────
# The gs wrapper ensures the toolkit always runs under the venv interpreter.
# It checks ALL critical imports (not just requests) to catch partial installs.
WRAPPER="$SCRIPT_DIR/gs"
cat > "$WRAPPER" << 'LAUNCHER'
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$DIR/.venv/bin/python3"
SYS_PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null)"

# Check all critical deps, not just one. A partial install where only
# requests is present but stem/monero/socks are missing would pass the
# old single-import check, then crash at runtime.
IMPORT_CHECK="import requests, socks, tenacity, stem, monero, psutil"

if [ -f "$VENV_PY" ] && "$VENV_PY" -c "$IMPORT_CHECK" 2>/dev/null; then
    exec "$VENV_PY" "$DIR/run" "$@"
elif [ -n "$SYS_PY" ] && "$SYS_PY" -c "$IMPORT_CHECK" 2>/dev/null; then
    exec "$SYS_PY" "$DIR/run" "$@"
else
    echo "  [!] Required packages are missing or incomplete."
    echo "  [!] Run: bash install.sh"
    exit 1
fi
LAUNCHER
chmod +x "$WRAPPER"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "  ───────────────────────────"
echo "  Setup complete"
echo "  ───────────────────────────"
echo ""
echo -e "  ${GREEN}./gs${NC}       open the menu"
echo -e "  ${GREEN}./gs list${NC}  show all tools"
echo ""
if [ "$TOR_RUNNING" = false ]; then
    echo -e "  ${RED}Start Tor before using the toolkit.${NC}"
    echo ""
fi
echo "  See SETUP.md for wallet-rpc setup."
echo ""
