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

# ---------- Step 1: System packages ----------
echo "  [1/5] Installing system packages..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq tor torsocks jq gnupg python3-pip curl wget >/dev/null 2>&1
    ok "System packages installed"
else
    warn "Not Debian/Ubuntu — install tor, jq, gnupg, python3-pip manually"
fi

# ---------- Step 2: Python dependencies ----------
echo "  [2/5] Installing Python dependencies..."
pip install --quiet --upgrade pip

# Core (required)
pip install --quiet \
    'requests[socks]>=2.28' \
    'PySocks>=1.7' \
    'tenacity>=8.0' \
    'stem>=1.8' \
    'monero>=1.1' \
    'psutil>=5.9'
ok "Core Python deps installed"

# OPSEC tools
pip install --quiet \
    'python-gnupg>=0.5' \
    'pycryptodomex>=3.19' \
    'qrcode>=7.0' \
    'pyyaml>=6.0' 2>/dev/null || warn "Some OPSEC deps failed (non-critical)"
ok "OPSEC Python deps installed"

# Intel/modules (optional, some may fail)
pip install --quiet \
    'beautifulsoup4>=4.12' \
    'aiohttp>=3.9' \
    'aiohttp-socks>=0.8' 2>/dev/null || warn "Some optional deps failed"
ok "Optional Python deps installed"

# ---------- Step 3: Tor configuration ----------
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
if curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
    ok "Tor is running and working"
else
    warn "Tor check failed — make sure Tor is running (sudo systemctl start tor)"
fi

# ---------- Step 4: Check Monero tools ----------
echo "  [4/5] Checking Monero CLI tools..."
MONERO_OK=true
for tool in monerod monero-wallet-cli monero-wallet-rpc; do
    if command -v $tool &>/dev/null; then
        ok "$tool found: $(command -v $tool)"
    else
        warn "$tool NOT found"
        MONERO_OK=false
    fi
done
if [ "$MONERO_OK" = false ]; then
    echo ""
    warn "Download Monero CLI from: https://www.getmonero.org/downloads/"
    echo "  Then extract and copy to /usr/local/bin/:"
    echo "    tar xf monero-linux-x64-*.tar.bz2"
    echo "    sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/"
    echo ""
fi

# ---------- Step 5: Verify Python imports ----------
echo "  [5/5] Verifying Python imports..."
VERIFY=$(python3 -c "
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
    print('MISSING: ' + ', '.join(fails))
else:
    print('OK')
" 2>&1)

if [ "$VERIFY" = "OK" ]; then
    ok "All core Python imports verified"
else
    fail "$VERIFY"
    echo "  Run: pip install $(echo $VERIFY | sed 's/MISSING: //')"
fi

# ---------- Done ----------
echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   Installation complete!                  ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""
echo "  Quick start:"
echo "    python3 run list                    # see all tools"
echo "    python3 run ghostspiral --help      # main pipeline help"
echo "    python3 run paranoia --dry-run      # test cleanup (safe)"
echo ""
echo "  Before using the core pipeline, start monero-wallet-rpc:"
echo "    monero-wallet-rpc --rpc-bind-port 18083 \\"
echo "      --wallet-file /path/to/wallet \\"
echo "      --password 'pass' \\"
echo "      --daemon-address 127.0.0.1:18081 \\"
echo "      --disable-rpc-login"
echo ""
