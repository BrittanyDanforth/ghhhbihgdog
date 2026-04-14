#!/bin/bash
# GhostSpiral — One-command installer for Kali Linux / Debian
# Usage: bash install.sh
set -e

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   GhostSpiral Toolkit — Installer         ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail() { echo -e "  ${RED}[✗]${NC} $1"; }
confirm() {
    read -p "  $1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ---------- Find python3 + pip ----------
PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
    fail "python3 not found. Install it first: sudo apt install python3"
    exit 1
fi
PIP="$PY -m pip"

PY_VER=$($PY --version 2>&1)
echo "  Using: $PY ($PY_VER)"

# ---------- Step 1: System packages ----------
echo ""
echo "  [1/5] Installing system packages..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq 2>/dev/null
    sudo apt-get install -y -qq tor torsocks jq gnupg python3-pip curl wget 2>/dev/null
    ok "System packages installed"
else
    warn "Not Debian/Ubuntu — install tor, jq, gnupg, python3-pip manually"
fi

# ---------- Step 2: Python dependencies ----------
echo "  [2/5] Installing Python dependencies..."

# Upgrade pip itself first
$PIP install --upgrade pip 2>/dev/null || true

# Core (required) — install one by one so failures are clear
CORE_DEPS="requests PySocks tenacity stem monero psutil"
for dep in $CORE_DEPS; do
    $PIP install --quiet "$dep" 2>/dev/null && ok "$dep" || fail "$dep — run: $PIP install $dep"
done

# OPSEC tools
OPSEC_DEPS="python-gnupg pycryptodomex qrcode pyyaml"
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
echo "  [3/5] Configuring Tor..."
if [ -f /etc/tor/torrc ]; then
    if ! grep -q "^ControlPort 9051" /etc/tor/torrc 2>/dev/null; then
        echo "" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc >/dev/null
        echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc >/dev/null
        ok "ControlPort 9051 added to /etc/tor/torrc"
    else
        ok "ControlPort already configured"
    fi
    sudo systemctl restart tor 2>/dev/null || sudo service tor restart 2>/dev/null || warn "Could not restart Tor"
    sleep 2
else
    warn "No /etc/tor/torrc found — configure Tor manually"
fi

# Verify Tor
if curl -s --max-time 15 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
    ok "Tor is running and working"
else
    warn "Tor check failed — run: sudo systemctl start tor"
fi

# ---------- Step 4: Check Monero tools ----------
echo ""
echo "  [4/5] Checking Monero CLI tools..."
MONERO_OK=true
for tool in monerod monero-wallet-cli monero-wallet-rpc; do
    if command -v $tool &>/dev/null; then
        ok "$tool found"
    else
        warn "$tool NOT found"
        MONERO_OK=false
    fi
done
if [ "$MONERO_OK" = false ]; then
    echo ""
    if confirm "  Download and install Monero CLI tools now?"; then
        echo "  Downloading from getmonero.org..."
        cd /tmp
        wget -q https://downloads.getmonero.org/cli/linux64 -O monero-cli.tar.bz2 && \
        tar xf monero-cli.tar.bz2 && \
        sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/ && \
        rm -rf monero-x86_64-linux-gnu-* monero-cli.tar.bz2 && \
        ok "Monero CLI tools installed" || \
        fail "Monero download failed — install manually from https://www.getmonero.org/downloads/"
        cd - >/dev/null
    else
        echo "  To install manually:"
        echo "    wget https://downloads.getmonero.org/cli/linux64 -O /tmp/monero.tar.bz2"
        echo "    cd /tmp && tar xf monero.tar.bz2"
        echo "    sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/"
        echo ""
    fi
fi

# ---------- Step 5: Verify Python imports ----------
echo ""
echo "  [5/5] Verifying Python imports..."
$PY -c "
fails = []
for mod, name in [
    ('requests', 'requests'),
    ('socks', 'PySocks'),
    ('tenacity', 'tenacity'),
    ('stem', 'stem'),
    ('monero', 'monero'),
    ('psutil', 'psutil'),
]:
    try:
        __import__(mod)
    except ImportError:
        fails.append(name)
if fails:
    print('  MISSING: ' + ', '.join(fails))
    print('  Fix: $PIP install ' + ' '.join(fails))
else:
    print('  All core imports OK!')
"

# ---------- Done ----------
echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   Installation complete!                  ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""
echo "  Quick start:"
echo "    $PY run list                    # see all tools"
echo "    $PY run ghostspiral --help      # main pipeline"
echo "    $PY run paranoia --dry-run      # test cleanup"
echo ""
echo "  Before using the core pipeline, start monero-wallet-rpc:"
echo "    monero-wallet-rpc --rpc-bind-port 18083 \\"
echo "      --wallet-file /path/to/wallet \\"
echo "      --password 'pass' \\"
echo "      --daemon-address 127.0.0.1:18081 \\"
echo "      --disable-rpc-login"
echo ""
