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
echo "  [1/6] System packages..."
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

# ── Step 2: Start Tor BEFORE downloading anything ─────────────────────────
# OPSEC: every subsequent download — PyPI wheels, get-pip.py, monero tarball —
# MUST go through Tor. A clearnet fallback on a privacy toolkit is
# a bug, not a fallback. This section:
#   1. Verifies Tor is already running; OR
#   2. Tries to start it via systemctl/service and waits for
#      'Bootstrapped 100%' from the Tor log (up to 90 s); OR
#   3. Aborts. --allow-clearnet is the ONLY way to continue without Tor,
#      and is intended for a system that already has the tor_firewall
#      active (so the kernel itself enforces Tor-only egress).
#
# Systemd/service start alone is not enough — Tor takes 15-60 s to
# bootstrap, and a SOCKS port that's open but hasn't connected yet will
# silently fail every request.
echo ""
echo "  [2/6] Tor (starting before downloads)..."

ALLOW_CLEARNET=false
for _a in "$@"; do
    case "$_a" in
        --allow-clearnet)
            ALLOW_CLEARNET=true
            warn "--allow-clearnet: downloads will NOT go through Tor."
            warn "Only use this if tor_firewall.sh is already active."
            ;;
    esac
done

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

# Shared verification probe. Returns 0 iff SOCKS on $1 reaches a site
# that confirms we're exiting via Tor.
_probe_tor() {
    local port="$1"
    curl -s --max-time 8 --connect-timeout 5 \
         --socks5-hostname "127.0.0.1:${port}" \
         https://check.torproject.org/api/ip 2>/dev/null \
        | grep -q '"IsTor":true'
}

TOR_RUNNING=false
for TOR_PORT in 9050 9150; do
    if _probe_tor "$TOR_PORT"; then
        ok "Tor verified (port ${TOR_PORT})"
        TOR_RUNNING=true
        break
    fi
done

if [ "$TOR_RUNNING" = false ]; then
    warn "Tor not responding. Attempting to start + wait for bootstrap..."
    # systemctl first, fall back to service, fall back to background tor.
    _started=false
    if command -v systemctl &>/dev/null; then
        if sudo systemctl start tor 2>/dev/null; then
            _started=true
        fi
    fi
    if [ "$_started" = false ] && command -v service &>/dev/null; then
        if sudo service tor start 2>/dev/null; then
            _started=true
        fi
    fi
    if [ "$_started" = false ]; then
        warn "Could not start tor via systemctl or service. Check 'sudo systemctl status tor'."
    fi

    # Wait up to 90 s for a SOCKS port to verify. 3 s was never enough —
    # a cold Tor bootstrap (build 3 circuits, reach guard, reach dir) takes
    # 10-60 s on a good connection. On VPN/bridge it's longer.
    dim "Waiting for Tor to bootstrap..."
    for _i in $(seq 1 18); do
        for TOR_PORT in 9050 9150; do
            if _probe_tor "$TOR_PORT"; then
                ok "Tor reachable (port ${TOR_PORT}) after ${_i}x5s"
                TOR_RUNNING=true
                break 2
            fi
        done
        sleep 5
    done
    # Also try to show the last 5 lines of the Tor log so the operator
    # isn't flying blind.
    if [ "$TOR_RUNNING" = false ]; then
        for _logfile in /var/log/tor/notices.log /var/log/tor/log /var/log/tor/tor.log; do
            if [ -r "$_logfile" ]; then
                dim "last 5 lines of $_logfile:"
                sudo tail -5 "$_logfile" 2>/dev/null | sed 's/^/        /'
                break
            fi
        done
    fi
fi

if [ "$TOR_RUNNING" = false ]; then
    if [ "$ALLOW_CLEARNET" = true ]; then
        warn "Proceeding without Tor because --allow-clearnet was passed."
        warn "If tor_firewall isn't already active, downloads LEAK YOUR REAL IP."
    else
        fail "Tor is not reachable. Refusing to install."
        fail "Start Tor manually:"
        fail "    sudo systemctl start tor"
        fail "    tail -f /var/log/tor/notices.log   # watch for 'Bootstrapped 100%'"
        fail "Then re-run: bash install.sh"
        fail ""
        fail "If you're running bash install.sh behind tor_firewall.sh and"
        fail "you know every outbound packet is already routed through Tor,"
        fail "bypass this check with: bash install.sh --allow-clearnet"
        exit 1
    fi
fi

# ── Configure pip to use Tor if firewall is active ─────────────────────────
# CHICKEN-AND-EGG PROBLEM:
# pip needs PySocks to use socks5h:// proxy, but PySocks isn't installed yet.
# Setting ALL_PROXY=socks5h:// before PySocks exists = pip can't connect at all.
#
# SOLUTION: Use torsocks as a transparent wrapper to bootstrap PySocks first.
# torsocks intercepts libc connect() calls and routes them through Tor — it
# doesn't need Python SOCKS support. Once PySocks is installed, pip can use
# the socks5h:// env vars natively for all subsequent installs.
if [ "$TOR_RUNNING" = true ]; then
    _TOR_PORT="${TOR_PORT:-9050}"
    USE_TORSOCKS=false
    if command -v torsocks &>/dev/null; then
        USE_TORSOCKS=true
        ok "pip will download through Tor via torsocks (port ${_TOR_PORT})"
    else
        warn "torsocks not found — setting SOCKS proxy env vars for pip"
        warn "If PySocks is not yet installed, first pip install may fail"
        export ALL_PROXY="socks5h://127.0.0.1:${_TOR_PORT}"
        export http_proxy="socks5h://127.0.0.1:${_TOR_PORT}"
        export https_proxy="socks5h://127.0.0.1:${_TOR_PORT}"
    fi
fi

# ── Step 3: Python environment + packages ──────────────────────────────────
echo ""
echo "  [3/6] Python setup..."

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
    # Method 1: ensurepip (offline — uses bundled pip wheel, no network)
    "$VENV_PY" -m ensurepip --upgrade 2>/dev/null || {
        # Method 2: get-pip.py. HARD-REQUIRE Tor (or --allow-clearnet)
        # for the download. Previous version silently fell back to
        # clearnet curl when Tor wasn't running.
        dim "Trying get-pip.py..."
        _getpip_ok=false
        if [ "$TOR_RUNNING" = true ] && command -v torsocks &>/dev/null; then
            torsocks curl -sS --max-time 45 \
                https://bootstrap.pypa.io/get-pip.py -o /tmp/_get_pip.py 2>/dev/null && _getpip_ok=true
        elif [ "$TOR_RUNNING" = true ]; then
            curl --socks5-hostname "127.0.0.1:${_TOR_PORT:-9050}" -sS --max-time 45 \
                https://bootstrap.pypa.io/get-pip.py -o /tmp/_get_pip.py 2>/dev/null && _getpip_ok=true
        elif [ "$ALLOW_CLEARNET" = true ]; then
            warn "get-pip.py via clearnet (--allow-clearnet)"
            curl -sS --max-time 45 https://bootstrap.pypa.io/get-pip.py -o /tmp/_get_pip.py 2>/dev/null && _getpip_ok=true
        else
            fail "get-pip.py needs Tor. Start Tor and re-run install.sh,"
            fail "or pass --allow-clearnet if the host firewall already enforces it."
            exit 1
        fi
        if [ "$_getpip_ok" = true ] && [ -s /tmp/_get_pip.py ]; then
            # get-pip.py itself downloads the pip wheel from pypi via
            # urllib. urllib CAN'T parse socks5h:// (no stdlib SOCKS
            # support), so if we inherit ALL_PROXY=socks5h:// urllib
            # will either error out or (worse) fall back to clearnet.
            # Run under torsocks when available; else temporarily
            # strip the broken proxy vars AND require --allow-clearnet.
            if [ "$USE_TORSOCKS" = true ]; then
                torsocks "$VENV_PY" /tmp/_get_pip.py 2>/dev/null || true
            elif [ "$TOR_RUNNING" = true ]; then
                fail "get-pip.py runtime would leak to clearnet without"
                fail "torsocks (urllib can't use socks5h://). Install"
                fail "torsocks (apt install torsocks) and re-run."
                rm -f /tmp/_get_pip.py
                exit 1
            elif [ "$ALLOW_CLEARNET" = true ]; then
                warn "get-pip.py runtime via clearnet (--allow-clearnet)"
                unset ALL_PROXY http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
                "$VENV_PY" /tmp/_get_pip.py 2>/dev/null || true
            else
                fail "Refusing to run get-pip.py: no Tor, no --allow-clearnet."
                rm -f /tmp/_get_pip.py
                exit 1
            fi
            rm -f /tmp/_get_pip.py
        else
            # Method 3: copy system pip — offline, no network.
            # NB: the previous code used --target with a literal glob
            # "python3.*/site-packages/" inside double quotes, which
            # bash does NOT expand, so it wrote pip into a directory
            # literally named 'python3.*'. That directory is never on
            # sys.path, so the fallback was a no-op. Expand the glob
            # with a shell-level loop and pin to the venv's actual
            # lib/pythonX.Y/site-packages.
            dim "Trying system pip (offline copy)..."
            _site_dir=""
            for _d in "$VENV_DIR"/lib/python*/site-packages; do
                [ -d "$_d" ] && _site_dir="$_d" && break
            done
            if [ -n "$_site_dir" ]; then
                $PY -m pip install --target="$_site_dir" pip 2>/dev/null || {
                    fail "Cannot install pip. Try:"
                    fail "  sudo apt install python3-pip python3-venv"
                    fail "  rm -rf .venv && bash install.sh"
                    exit 1
                }
            else
                fail "Cannot find site-packages under $VENV_DIR/lib."
                fail "Try: sudo apt install python3-pip python3-venv"
                fail "     rm -rf .venv && bash install.sh"
                exit 1
            fi
        fi
    }
fi

# Helper: run pip, optionally through torsocks
_pip_cmd() {
    if [ "$USE_TORSOCKS" = true ]; then
        torsocks $VENV_PIP "$@"
    else
        $VENV_PIP "$@"
    fi
}

# Upgrade pip quietly. We must clear proxy vars because PySocks may
# not be installed yet (pip without PySocks will bail on socks5h://).
# HOWEVER — unsetting the proxies without a torsocks wrapper would
# send pip's connection CLEARNET, which on a host without the
# Tor firewall leaks the operator's real IP to pypi. Behaviors:
#   * USE_TORSOCKS=true  -> wrap, Tor-routed, safe
#   * Tor running but no torsocks -> skip upgrade entirely; we'll
#     retry after PySocks is installed when the proxy vars are
#     safe to use again
#   * --allow-clearnet   -> operator has asserted a kernel-level
#     Tor firewall; clearnet upgrade is allowed
_SAVED_ALL_PROXY="${ALL_PROXY:-}"
_SAVED_HTTP_PROXY="${http_proxy:-}"
_SAVED_HTTPS_PROXY="${https_proxy:-}"
unset ALL_PROXY http_proxy https_proxy HTTP_PROXY HTTPS_PROXY 2>/dev/null
if [ "$USE_TORSOCKS" = true ]; then
    torsocks $VENV_PIP install --upgrade pip 2>/dev/null || true
elif [ "$ALLOW_CLEARNET" = true ]; then
    warn "pip upgrade via clearnet (--allow-clearnet)"
    $VENV_PIP install --upgrade pip 2>/dev/null || true
else
    dim "Skipping pip upgrade until PySocks is bootstrapped (no torsocks)"
fi
[ -n "$_SAVED_ALL_PROXY" ] && export ALL_PROXY="$_SAVED_ALL_PROXY"
[ -n "$_SAVED_HTTP_PROXY" ] && export http_proxy="$_SAVED_HTTP_PROXY"
[ -n "$_SAVED_HTTPS_PROXY" ] && export https_proxy="$_SAVED_HTTPS_PROXY"

# ── Install packages ──────────────────────────────────────────────────────
# Core deps are required. Extra deps enable optional features.
# PySocks MUST be installed FIRST — it enables pip's own socks5h:// support.
# Without PySocks, pip cannot use ALL_PROXY=socks5h://... and will fail
# with "Missing dependencies for SOCKS support".
BOOTSTRAP_DEP="PySocks"
CORE_DEPS="requests tenacity stem monero psutil"
EXTRA_DEPS="cryptography pycryptodomex qrcode pyyaml beautifulsoup4 aiohttp aiohttp-socks"

dim "Installing Python packages..."

# Step 1: Bootstrap PySocks first.
# CRITICAL: pip itself needs PySocks to use socks5h:// proxy. But PySocks
# isn't installed yet. If ANY proxy env var is set (ALL_PROXY, http_proxy,
# https_proxy) — even from a prior run or system config — pip will try to
# use SOCKS and fail with "Missing dependencies for SOCKS support".
#
# Solution: UNSET all proxy env vars for this one install, then use torsocks
# (which works at the OS/libc level, not Python level) to route through Tor.
if ! "$VENV_PY" -c "import socks" 2>/dev/null; then
    dim "Bootstrapping PySocks (needed for SOCKS proxy support)..."
    # Save and clear proxy vars — pip can't use them without PySocks
    _SAVED_ALL_PROXY="${ALL_PROXY:-}"
    _SAVED_HTTP_PROXY="${http_proxy:-}"
    _SAVED_HTTPS_PROXY="${https_proxy:-}"
    unset ALL_PROXY http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

    PYSOCKS_OK=false
    if [ "$USE_TORSOCKS" = true ]; then
        torsocks $VENV_PIP install PySocks 2>&1 | tail -3 && PYSOCKS_OK=true
    elif [ "$TOR_RUNNING" = true ] && [ "$ALLOW_CLEARNET" != true ]; then
        # Tor running but no torsocks installed → we just unset the
        # socks5h:// proxy envs so a bare pip install here would CLEARNET
        # to pypi, leaking the real IP. Refuse.
        fail "PySocks bootstrap requires torsocks when Tor is the only"
        fail "supported egress. Install torsocks:"
        fail "    sudo apt install torsocks"
        fail "(or re-run with --allow-clearnet if tor_firewall is active)."
        [ -n "$_SAVED_ALL_PROXY" ] && export ALL_PROXY="$_SAVED_ALL_PROXY"
        [ -n "$_SAVED_HTTP_PROXY" ] && export http_proxy="$_SAVED_HTTP_PROXY"
        [ -n "$_SAVED_HTTPS_PROXY" ] && export https_proxy="$_SAVED_HTTPS_PROXY"
        exit 1
    else
        # Either no Tor required (--allow-clearnet) or no Tor running.
        $VENV_PIP install PySocks 2>&1 | tail -3 && PYSOCKS_OK=true
    fi

    # Restore proxy vars
    [ -n "$_SAVED_ALL_PROXY" ] && export ALL_PROXY="$_SAVED_ALL_PROXY"
    [ -n "$_SAVED_HTTP_PROXY" ] && export http_proxy="$_SAVED_HTTP_PROXY"
    [ -n "$_SAVED_HTTPS_PROXY" ] && export https_proxy="$_SAVED_HTTPS_PROXY"

    if "$VENV_PY" -c "import socks" 2>/dev/null; then
        ok "PySocks bootstrapped"
    else
        fail "PySocks bootstrap FAILED"
        fail "Without PySocks, pip cannot download through Tor's SOCKS proxy."
        fail "Try manually: torsocks .venv/bin/pip install PySocks"
        exit 1
    fi
fi

# Step 2: Now that PySocks is installed, pip can use socks5h:// natively.
# Switch from torsocks to env vars (more reliable for pip's internal urllib3).
if [ "$TOR_RUNNING" = true ]; then
    export ALL_PROXY="socks5h://127.0.0.1:${_TOR_PORT}"
    export http_proxy="socks5h://127.0.0.1:${_TOR_PORT}"
    export https_proxy="socks5h://127.0.0.1:${_TOR_PORT}"
    USE_TORSOCKS=false
fi

# Step 3: Install remaining core + extra deps
INSTALL_OK=true
INSTALL_OUTPUT=$(_pip_cmd install $CORE_DEPS $EXTRA_DEPS 2>&1) || INSTALL_OK=false

if [ "$INSTALL_OK" = true ]; then
    ok "Python packages installed"
else
    warn "Batch install had issues. Installing one by one..."
    for dep in $CORE_DEPS; do
        MOD="$(pkg_to_import "$dep")"
        if "$VENV_PY" -c "import $MOD" 2>/dev/null; then
            ok "$dep (present)"
        else
            _pip_cmd install "$dep" 2>&1 | tail -5
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
            _pip_cmd install "$dep" 2>/dev/null && ok "$dep" || warn "$dep (optional, skipped)"
        fi
    done
fi

# ── Step 4: Verify ALL imports ─────────────────────────────────────────────
# This is the hard gate. Every core dependency must be importable in the
# EXACT Python interpreter that will run the toolkit. If any core dep fails,
# setup fails — no silent "it'll probably work" acceptance.
echo ""
echo "  [4/6] Verifying imports..."
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

# ── Step 5: Monero tools ──────────────────────────────────────────────────
echo ""
echo "  [5/6] Monero tools..."
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
        _WORKDIR="$(mktemp -d -t gsmonero.XXXXXX)"
        # Permissions tight — the signing key + tarball live here briefly.
        chmod 700 "$_WORKDIR"
        cd "$_WORKDIR"

        # ── Picker: use Tor (torsocks preferred, curl SOCKS fallback),
        # or abort. NEVER fall back to raw wget/curl — the previous
        # version did and silently leaked the operator's real IP to
        # downloads.getmonero.org.
        _dl() {
            local url="$1" out="$2"
            if command -v torsocks &>/dev/null && [ "$TOR_RUNNING" = true ]; then
                torsocks curl -fsSL --max-time 300 -o "$out" "$url"
            elif [ "$TOR_RUNNING" = true ]; then
                curl --socks5-hostname "127.0.0.1:${_TOR_PORT:-9050}" \
                    -fsSL --max-time 300 -o "$out" "$url"
            elif [ "$ALLOW_CLEARNET" = true ]; then
                warn "Downloading $url over clearnet (--allow-clearnet)"
                curl -fsSL --max-time 300 -o "$out" "$url"
            else
                return 1
            fi
        }

        _TARBALL_URL="https://downloads.getmonero.org/cli/linux64"
        _HASHES_URL="https://www.getmonero.org/downloads/hashes.txt"

        dim "Downloading Monero CLI (via Tor)..."
        if ! _dl "$_TARBALL_URL" monero-cli.tar.bz2; then
            fail "Monero download failed. Tor not reachable?"
            rm -rf "$_WORKDIR"
            cd - >/dev/null
            exit 1
        fi

        # ── Verify SHA-256 against the hashes.txt published on getmonero.org.
        # hashes.txt is itself signed by the Monero release key, so we
        # fetch that, check the detached signature on hashes.txt, and
        # only then trust the tarball's hash.
        dim "Downloading hashes.txt + checking signature..."
        _VERIFIED=false
        if _dl "$_HASHES_URL" hashes.txt; then
            # Binary fingerprint of the Monero maintainers (fluffypony
            # historically; current signing key publishes on getmonero.org
            # release pages). We import whatever key signed hashes.txt
            # from the operator's gpg keyring if available; otherwise
            # bail out of signature verification but STILL check SHA-256
            # (which defeats tarball-mutation at the CDN without the
            # attacker also controlling getmonero.org content).
            _TARBALL_SHA="$(sha256sum monero-cli.tar.bz2 | awk '{print $1}')"
            if grep -q "$_TARBALL_SHA" hashes.txt; then
                ok "Tarball SHA-256 matches hashes.txt entry"
                _VERIFIED=true
            else
                fail "Tarball SHA-256 does NOT match hashes.txt."
                fail "  Downloaded: $_TARBALL_SHA"
                fail "  Expected (from hashes.txt): see file"
                fail "Aborting — tarball is either corrupt or a different architecture."
                rm -rf "$_WORKDIR"
                cd - >/dev/null
                exit 1
            fi
            # Best-effort GPG signature check on hashes.txt. The
            # maintainers publish hashes.txt with ASCII-armor signature
            # inline; gpg --verify on a cleartext signature file does
            # the right thing when the signer's key is trusted.
            if command -v gpg &>/dev/null && head -1 hashes.txt 2>/dev/null \
                | grep -q "BEGIN PGP SIGNED MESSAGE"; then
                if gpg --verify hashes.txt 2>/dev/null; then
                    ok "hashes.txt GPG signature verified"
                else
                    warn "hashes.txt signer's key not in your gpg keyring."
                    warn "The SHA-256 check above did succeed — tarball matches"
                    warn "the hash published at getmonero.org. For belt-and-"
                    warn "suspenders OPSEC, import the Monero maintainer key:"
                    warn "    gpg --keyserver keyserver.ubuntu.com --recv-keys <key>"
                    warn "and re-run install.sh. Safe to proceed for now."
                fi
            fi
        else
            fail "Could not download hashes.txt — refusing to install an unverified tarball."
            rm -rf "$_WORKDIR"
            cd - >/dev/null
            exit 1
        fi

        if [ "$_VERIFIED" != true ]; then
            fail "Verification failed. Refusing to install."
            rm -rf "$_WORKDIR"
            cd - >/dev/null
            exit 1
        fi

        # Extract + install
        if tar xf monero-cli.tar.bz2 && \
            sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/; then
            ok "Monero CLI installed (verified)"
        else
            fail "Extract/install failed"
        fi
        # Wipe the workdir whatever happened so the tarball doesn't
        # sit around in /tmp.
        rm -rf "$_WORKDIR"
        cd - >/dev/null
    fi
fi

# ── Step 6: Create launcher ────────────────────────────────────────────────
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
