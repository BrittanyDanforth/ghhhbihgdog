#!/bin/bash
# Toolkit — Installer & Environment Setup
# First run: installs everything from scratch
# Later runs: checks what's missing, fixes it, skips what's already done
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[0;90m'
BOLD='\033[1;37m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail() { echo -e "  ${RED}[x]${NC} $1"; }
dim()  { echo -e "  ${DIM}$1${NC}"; }
confirm() {
    read -p "  $1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

echo ""
echo "  Setup"
echo "  -----"

# ---------- Detect if this is first run or re-run ----------
FIRST_RUN=false
if [ ! -d "$VENV_DIR" ]; then
    FIRST_RUN=true
    echo "  First time setup. This will install everything you need."
else
    echo "  Checking your setup. Already-installed stuff will be skipped."
fi
echo ""

# ---------- Step 1: System packages ----------
echo "  [1/5] System packages..."
if command -v apt-get &>/dev/null; then
    NEED_PKGS=""
    for pkg in tor torsocks jq gnupg python3-pip python3-venv curl wget; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            NEED_PKGS="$NEED_PKGS $pkg"
        fi
    done
    if [ -n "$NEED_PKGS" ]; then
        dim "Installing:$NEED_PKGS"
        sudo apt-get update -qq 2>/dev/null
        sudo apt-get install -y -qq $NEED_PKGS 2>/dev/null
        ok "System packages installed"
    else
        ok "All system packages already installed"
    fi
else
    warn "Not Debian/Ubuntu. Make sure you have: tor, jq, gnupg, python3-pip, python3-venv, curl"
fi

# ---------- Step 2: Python venv + deps ----------
echo ""
echo "  [2/5] Python setup..."

PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
    fail "python3 not found. Install: sudo apt install python3"
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    $PY -m venv "$VENV_DIR" 2>/dev/null || {
        fail "Could not create venv. Install: sudo apt install python3-venv"
        exit 1
    }
    ok "Created virtual environment"
else
    ok "Virtual environment exists"
fi

source "$VENV_DIR/bin/activate"
PY="$VENV_DIR/bin/python3"
PIP="$PY -m pip"

$PIP install --upgrade pip --quiet 2>/dev/null || true

# Install all deps in one shot (faster than one-by-one)
if [ "$FIRST_RUN" = true ]; then
    dim "Installing Python packages (this takes a minute)..."
    $PIP install --quiet \
        requests PySocks tenacity stem monero psutil \
        cryptography python-gnupg pycryptodomex qrcode pyyaml \
        beautifulsoup4 aiohttp aiohttp-socks \
        2>/dev/null && ok "All Python packages installed" || {
        warn "Some packages failed. Trying one by one..."
        for dep in requests PySocks tenacity stem monero psutil cryptography python-gnupg pycryptodomex qrcode pyyaml beautifulsoup4 aiohttp aiohttp-socks; do
            $PIP install --quiet "$dep" 2>/dev/null && ok "$dep" || warn "$dep failed"
        done
    }
else
    # Re-run: check ALL packages (same set as first-run)
    MISSING=""
    for mod_pkg in "requests:requests" "socks:PySocks" "tenacity:tenacity" "stem:stem" "monero:monero" "psutil:psutil" "Cryptodome:pycryptodomex" "cryptography:cryptography" "gnupg:python-gnupg" "qrcode:qrcode" "yaml:pyyaml" "bs4:beautifulsoup4" "aiohttp:aiohttp" "aiohttp_socks:aiohttp-socks"; do
        mod="${mod_pkg%%:*}"
        pkg="${mod_pkg##*:}"
        $PY -c "import $mod" 2>/dev/null || MISSING="$MISSING $pkg"
    done
    if [ -n "$MISSING" ]; then
        dim "Installing missing:$MISSING"
        $PIP install --quiet $MISSING 2>/dev/null || true
        ok "Missing packages installed"
    else
        ok "All Python packages present"
    fi
fi

# ---------- Step 3: Tor ----------
echo ""
echo "  [3/5] Tor..."

# Make sure Tor config has ControlPort
if [ ! -f /etc/tor/torrc ]; then
    if [ -d /etc/tor ]; then
        sudo touch /etc/tor/torrc 2>/dev/null && \
            warn "Created empty /etc/tor/torrc (Tor package may not be installed yet)" || true
    fi
fi
if [ -f /etc/tor/torrc ]; then
    if ! grep -qE "^\s*ControlPort\s+9051" /etc/tor/torrc 2>/dev/null; then
        echo "" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc >/dev/null
        ok "Added ControlPort 9051 to torrc"
    else
        ok "Tor control port configured"
    fi
else
    warn "No /etc/tor/torrc found — Tor may not be installed. Install with: sudo apt install tor"
fi

# Start Tor if not running
TOR_RUNNING=false
for TOR_PORT in 9050 9150; do
    if curl -s --max-time 5 --connect-timeout 3 --socks5-hostname "127.0.0.1:${TOR_PORT}" https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        ok "Tor working on port ${TOR_PORT}"
        TOR_RUNNING=true
        break
    fi
done

if [ "$TOR_RUNNING" = false ]; then
    warn "Tor is not running. Trying to start it..."
    sudo systemctl start tor 2>/dev/null || sudo service tor start 2>/dev/null || true
    sleep 3
    
    # Check again
    for TOR_PORT in 9050 9150; do
        if curl -s --max-time 10 --connect-timeout 5 --socks5-hostname "127.0.0.1:${TOR_PORT}" https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
            ok "Tor started and working on port ${TOR_PORT}"
            TOR_RUNNING=true
            break
        fi
    done
    
    if [ "$TOR_RUNNING" = false ]; then
        echo ""
        fail "Tor is NOT working. Fix this before using the toolkit."
        echo ""
        echo "  Common fixes:"
        echo -e "    ${BOLD}sudo systemctl start tor${NC}     <- start system Tor"
        echo -e "    ${BOLD}sudo systemctl status tor${NC}    <- check if Tor is running"
        echo -e "    ${BOLD}sudo journalctl -u tor${NC}       <- check Tor logs for errors"
        echo ""
        echo "  Or open Tor Browser (uses port 9150 instead of 9050)."
        echo ""
        echo "  If Tor keeps failing:"
        echo "    sudo apt purge tor && sudo apt install tor"
        echo "    sudo systemctl enable tor && sudo systemctl start tor"
        echo ""
    fi
fi

# ---------- Step 4: Monero CLI ----------
echo ""
echo "  [4/5] Monero tools..."
MONERO_OK=true
for tool in monerod monero-wallet-cli monero-wallet-rpc; do
    if command -v $tool &>/dev/null; then
        ok "$tool found"
    else
        warn "$tool not found"
        MONERO_OK=false
    fi
done

if [ "$MONERO_OK" = false ]; then
    echo ""
    warn "Monero tools missing. The download uses clearnet (your IP visible)."
    dim "For privacy, download via Tor Browser from getmonero.org instead."
    echo ""
    if confirm "Download Monero CLI tools now?"; then
        ARCH=$(uname -m)
        if [ "$ARCH" != "x86_64" ]; then
            warn "Your CPU is $ARCH (not x86_64). The download might not work."
        fi
        cd /tmp
        wget -q --show-progress https://downloads.getmonero.org/cli/linux64 -O monero-cli.tar.bz2 && \
        tar xf monero-cli.tar.bz2 && \
        sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/ && \
        rm -rf monero-x86_64-linux-gnu-* monero-cli.tar.bz2 && \
        ok "Monero CLI installed to /usr/local/bin/" || \
        fail "Download failed. Get it manually from https://www.getmonero.org/downloads/"
        cd - >/dev/null
    fi
fi

# ---------- Step 5: Quick import check ----------
echo ""
echo "  [5/5] Final check..."
$PY << 'PYCHECK'
fails = []
for mod, name in [
    ('requests', 'requests'), ('socks', 'PySocks'), ('tenacity', 'tenacity'),
    ('stem', 'stem'), ('monero', 'monero'), ('psutil', 'psutil'),
    ('Cryptodome', 'pycryptodomex'),
]:
    try:
        __import__(mod)
    except ImportError:
        fails.append(name)
if fails:
    print('  Missing: ' + ', '.join(fails))
    print('  Fix: .venv/bin/pip install ' + ' '.join(fails))
else:
    print('  All imports working.')
PYCHECK

# ---------- Create/update launcher ----------
WRAPPER="$SCRIPT_DIR/gs"
cat > "$WRAPPER" << 'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/.venv/bin/python3"
if [ ! -f "$PY" ]; then
    echo "Setup not done yet. Run: bash install.sh"
    exit 1
fi
exec "$PY" "$DIR/run" "$@"
EOF
chmod +x "$WRAPPER"

# ---------- Done ----------
echo ""
echo "  ----- Setup complete -----"
echo ""
echo "  Run the toolkit:"
echo -e "    ${GREEN}./gs${NC}                    opens the menu"
echo -e "    ${GREEN}./gs list${NC}               shows all tools"
echo -e "    ${GREEN}./gs paranoia --dry-run${NC}  tests cleanup"
echo ""
if [ "$TOR_RUNNING" = false ]; then
    echo -e "  ${RED}WARNING: Tor is not running. Start it before using the toolkit.${NC}"
    echo ""
fi
echo "  Before mixing, you need monero-wallet-rpc running:"
echo "    monero-wallet-rpc --rpc-bind-port 18083 \\"
echo "      --wallet-file /path/to/wallet --password 'PASS' \\"
echo "      --daemon-address 127.0.0.1:18081 --disable-rpc-login \\"
echo "      --log-level 0"
echo ""
dim "  (--log-level 0 prevents wallet-rpc from logging your operations)"
echo ""
