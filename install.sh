#!/bin/bash
# Toolkit — Installer & Environment Setup
# Handles: first install, re-install, broken venv, missing packages
# Safe to run multiple times — skips what's already working
set -e

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
        dim "Installing:$NEED_PKGS"
        sudo apt-get update -qq 2>/dev/null || true
        sudo apt-get install -y -qq $NEED_PKGS 2>/dev/null || {
            warn "apt install had errors. Trying without -qq for details..."
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
        warn "Venv broken (no python3). Rebuilding..."
        rm -rf "$VENV_DIR"
    elif ! "$VENV_DIR/bin/python3" -c "import pip" 2>/dev/null; then
        warn "Venv broken (no pip). Rebuilding..."
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

# Activate and set paths
VENV_PY="$VENV_DIR/bin/python3"
VENV_PIP="$VENV_PY -m pip"

# Ensure pip exists in the venv
if ! "$VENV_PY" -c "import pip" 2>/dev/null; then
    dim "Installing pip into venv..."
    # Method 1: ensurepip
    "$VENV_PY" -m ensurepip --upgrade 2>/dev/null || {
        # Method 2: get-pip.py
        dim "ensurepip failed, trying get-pip.py..."
        curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/_get_pip.py 2>/dev/null && \
        "$VENV_PY" /tmp/_get_pip.py 2>/dev/null && \
        rm -f /tmp/_get_pip.py || {
            # Method 3: copy system pip
            dim "get-pip.py failed, trying system pip copy..."
            $PY -m pip install --target="$VENV_DIR/lib/python3.*/site-packages/" pip 2>/dev/null || {
                fail "Cannot install pip into venv."
                fail "Try: sudo apt install python3-pip python3-venv"
                fail "Then: rm -rf .venv && bash install.sh"
                exit 1
            }
        }
    }
fi

# Upgrade pip (suppress errors — old pip versions may fail on --quiet)
$VENV_PIP install --upgrade pip 2>/dev/null || true

# Install packages — show errors, don't hide them
CORE_DEPS="requests PySocks tenacity stem monero psutil"
EXTRA_DEPS="cryptography pycryptodomex qrcode pyyaml beautifulsoup4 aiohttp aiohttp-socks"

dim "Installing Python packages..."
# Try all at once first (fastest)
if $VENV_PIP install $CORE_DEPS $EXTRA_DEPS 2>&1 | tail -20; then
    ok "Python packages installed"
else
    warn "Batch install had issues. Installing core packages one by one..."
    for dep in $CORE_DEPS; do
        if "$VENV_PY" -c "import $(echo $dep | tr 'A-Z' 'a-z' | sed 's/pysocks/socks/')" 2>/dev/null; then
            ok "$dep (already installed)"
        else
            $VENV_PIP install "$dep" 2>&1 | tail -3
            if "$VENV_PY" -c "import $(echo $dep | tr 'A-Z' 'a-z' | sed 's/pysocks/socks/')" 2>/dev/null; then
                ok "$dep"
            else
                fail "$dep FAILED — see error above"
            fi
        fi
    done
    dim "Installing extra packages..."
    for dep in $EXTRA_DEPS; do
        $VENV_PIP install "$dep" 2>/dev/null && ok "$dep" || warn "$dep (optional, skipped)"
    done
fi

# ── Step 3: Verify core imports ────────────────────────────────────────────
echo ""
echo "  [3/5] Verifying imports..."
IMPORT_FAILS=""
for mod_pkg in "requests:requests" "socks:PySocks" "tenacity:tenacity" "stem:stem" "monero:monero" "psutil:psutil"; do
    mod="${mod_pkg%%:*}"
    pkg="${mod_pkg##*:}"
    if "$VENV_PY" -c "import $mod" 2>/dev/null; then
        ok "$pkg"
    else
        fail "$pkg — cannot import"
        IMPORT_FAILS="$IMPORT_FAILS $pkg"
    fi
done

if [ -n "$IMPORT_FAILS" ]; then
    echo ""
    fail "CRITICAL: Core packages failed to install:$IMPORT_FAILS"
    echo ""
    echo "  This usually means one of:"
    echo "    1. Missing build tools: sudo apt install python3-dev build-essential"
    echo "    2. Broken Python install: sudo apt install --reinstall python3 python3-venv"
    echo "    3. Network issue during pip install"
    echo ""
    echo "  Fix and re-run: bash install.sh"
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
        ok "Added ControlPort 9051 to torrc"
    else
        ok "Tor control port configured"
    fi
fi

TOR_RUNNING=false
for TOR_PORT in 9050 9150; do
    if curl -s --max-time 5 --connect-timeout 3 --socks5-hostname "127.0.0.1:${TOR_PORT}" \
       https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        ok "Tor working on port ${TOR_PORT}"
        TOR_RUNNING=true
        break
    fi
done

if [ "$TOR_RUNNING" = false ]; then
    warn "Tor not running. Trying to start..."
    sudo systemctl start tor 2>/dev/null || sudo service tor start 2>/dev/null || true
    sleep 3
    for TOR_PORT in 9050 9150; do
        if curl -s --max-time 10 --connect-timeout 5 --socks5-hostname "127.0.0.1:${TOR_PORT}" \
           https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
            ok "Tor started on port ${TOR_PORT}"
            TOR_RUNNING=true
            break
        fi
    done
    if [ "$TOR_RUNNING" = false ]; then
        echo ""
        fail "Tor is NOT working."
        echo "  Fix: sudo systemctl start tor"
        echo "  Or open Tor Browser (port 9150)"
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
        fail "Download failed. Get it from https://www.getmonero.org/downloads/"
        cd - >/dev/null
    fi
fi

# ── Create launcher ───────────────────────────────────────────────────────
WRAPPER="$SCRIPT_DIR/gs"
cat > "$WRAPPER" << 'LAUNCHER'
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$DIR/.venv/bin/python3"
SYS_PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null)"

if [ -f "$VENV_PY" ] && "$VENV_PY" -c "import requests" 2>/dev/null; then
    exec "$VENV_PY" "$DIR/run" "$@"
elif [ -n "$SYS_PY" ] && "$SYS_PY" -c "import requests" 2>/dev/null; then
    exec "$SYS_PY" "$DIR/run" "$@"
else
    echo "  [!] Packages missing. Run: bash install.sh"
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
echo "  See SETUP.md for monero-wallet-rpc setup."
echo ""
