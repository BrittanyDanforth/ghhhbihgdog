#!/bin/bash
# GhostSpiral — One-command installer for Kali Linux / Debian
# Usage: bash install.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   GhostSpiral Toolkit — Installer         ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[0;90m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail() { echo -e "  ${RED}[✗]${NC} $1"; }
dim()  { echo -e "  ${DIM}$1${NC}"; }
confirm() {
    read -p "  $1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ---------- Step 1: System packages ----------
echo "  [1/5] System packages..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq 2>/dev/null
    sudo apt-get install -y -qq tor torsocks jq gnupg python3-pip python3-venv curl wget 2>/dev/null
    ok "System packages"
else
    warn "Not Debian/Ubuntu — install tor, jq, gnupg, python3-pip, python3-venv manually"
fi

# ---------- Step 2: Virtual environment + Python deps ----------
echo ""
echo "  [2/5] Python dependencies..."
dim "Using a virtual environment so nothing conflicts with system packages."

PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
    fail "python3 not found. Install: sudo apt install python3"
    exit 1
fi

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    $PY -m venv "$VENV_DIR" 2>/dev/null || {
        fail "Could not create venv. Install: sudo apt install python3-venv"
        exit 1
    }
    ok "Created virtual environment at .venv/"
else
    ok "Virtual environment already exists"
fi

# Activate venv for the rest of the script
source "$VENV_DIR/bin/activate"
PY="$VENV_DIR/bin/python3"
PIP="$PY -m pip"

# Upgrade pip inside the venv (silently)
$PIP install --upgrade pip --quiet 2>/dev/null || true

# Core (required)
CORE_DEPS="requests PySocks tenacity stem monero psutil"
for dep in $CORE_DEPS; do
    $PIP install --quiet "$dep" 2>/dev/null && ok "$dep" || fail "$dep — run: $PIP install $dep"
done

# Crypto / OPSEC
OPSEC_DEPS="cryptography python-gnupg pycryptodomex qrcode pyyaml"
for dep in $OPSEC_DEPS; do
    $PIP install --quiet "$dep" 2>/dev/null && ok "$dep" || warn "$dep (optional)"
done

# Intel (optional)
OPTIONAL_DEPS="beautifulsoup4 aiohttp aiohttp-socks"
for dep in $OPTIONAL_DEPS; do
    $PIP install --quiet "$dep" 2>/dev/null && ok "$dep" || warn "$dep (optional)"
done

# ---------- Step 3: Tor configuration ----------
echo ""
echo "  [3/5] Tor..."
if [ -f /etc/tor/torrc ]; then
    if ! grep -q "^ControlPort 9051" /etc/tor/torrc 2>/dev/null; then
        echo "" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc >/dev/null
        ok "ControlPort 9051 added to torrc"
    else
        ok "ControlPort already configured"
    fi
    sudo systemctl restart tor 2>/dev/null || sudo service tor restart 2>/dev/null || warn "Could not restart Tor"
    sleep 2
else
    warn "No /etc/tor/torrc found — configure Tor manually"
fi

# Check Tor SOCKS (9050 = system tor, 9150 = Tor Browser)
TOR_CHECK_OK=false
for TOR_SOCKS_PORT in 9050 9150; do
    if curl -s --max-time 15 --socks5-hostname "127.0.0.1:${TOR_SOCKS_PORT}" https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        ok "Tor SOCKS active on :${TOR_SOCKS_PORT}"
        TOR_CHECK_OK=true
        break
    fi
done
if [ "$TOR_CHECK_OK" = false ]; then
    warn "Tor not responding on :9050 or :9150 — run: sudo systemctl start tor"
fi

# ---------- Step 4: Monero CLI tools ----------
echo ""
echo "  [4/5] Monero CLI tools..."
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
    if confirm "  Download Monero CLI tools now?"; then
        echo "  Downloading from getmonero.org..."
        cd /tmp
        wget -q https://downloads.getmonero.org/cli/linux64 -O monero-cli.tar.bz2 && \
        tar xf monero-cli.tar.bz2 && \
        sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/ && \
        rm -rf monero-x86_64-linux-gnu-* monero-cli.tar.bz2 && \
        ok "Monero CLI installed" || \
        fail "Download failed — get it from https://www.getmonero.org/downloads/"
        cd - >/dev/null
    fi
fi

# ---------- Step 5: Verify imports ----------
echo ""
echo "  [5/5] Checking imports..."
$PY -c "
fails = []
for mod, name in [
    ('requests', 'requests'),
    ('socks', 'PySocks'),
    ('tenacity', 'tenacity'),
    ('stem', 'stem'),
    ('monero', 'monero'),
    ('psutil', 'psutil'),
    ('cryptography', 'cryptography'),
]:
    try:
        __import__(mod)
    except ImportError:
        fails.append(name)
if fails:
    print('  MISSING: ' + ', '.join(fails))
else:
    print('  All core imports OK!')
"

# ---------- Create launcher wrapper ----------
WRAPPER="$SCRIPT_DIR/gs"
cat > "$WRAPPER" << 'GSEOF'
#!/bin/bash
# Shortcut: runs GhostSpiral inside the venv automatically
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/python3"
if [ ! -f "$VENV" ]; then
    echo "[!] Virtual environment not found. Run: bash install.sh"
    exit 1
fi
exec "$VENV" "$SCRIPT_DIR/run" "$@"
GSEOF
chmod +x "$WRAPPER"

# ---------- Done ----------
echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   Installation complete!                  ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""
echo "  Two ways to run GhostSpiral:"
echo ""
echo "    ${GREEN}./gs${NC}                          <- easiest (uses venv automatically)"
echo "    ${GREEN}./gs list${NC}                     <- see all tools"
echo "    ${GREEN}./gs paranoia --dry-run${NC}       <- test cleanup"
echo ""
echo "  Or activate the venv yourself:"
echo ""
echo "    ${DIM}source .venv/bin/activate${NC}"
echo "    ${DIM}python3 run${NC}"
echo ""
echo "  Before using the core pipeline, start monero-wallet-rpc:"
echo "    monero-wallet-rpc --rpc-bind-port 18083 \\"
echo "      --wallet-file /path/to/wallet \\"
echo "      --password 'YOUR_PASSWORD' \\"
echo "      --daemon-address 127.0.0.1:18081 \\"
echo "      --disable-rpc-login"
echo ""
