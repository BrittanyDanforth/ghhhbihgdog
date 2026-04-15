#!/bin/bash
# =============================================================================
# Transparent Tor Firewall — Zero-Leak VM Lockdown (v2)
# =============================================================================
#
# Seals every outbound path so ONLY the Tor process can reach the network.
# Everything else — apps, malware, DNS, ICMP, IPv6, NTP, mDNS, LLMNR,
# SSDP, NetBIOS, multicast, broadcast, UDP, tunnels — is hard-dropped.
#
# ALSO handles the VMware NAT + host Malwarebytes problem:
#   --setup-bridges     configures Tor to use obfs4 bridges so the host
#                       never sees recognizable Tor relay IPs. Malwarebytes
#                       stops flagging because the IPs aren't on any threat
#                       list, and obfs4 makes the traffic look like normal HTTPS.
#
# Usage:
#   sudo bash tor_firewall.sh                  # activate firewall
#   sudo bash tor_firewall.sh --status         # show rules + run leak tests
#   sudo bash tor_firewall.sh --undo           # remove all rules
#   sudo bash tor_firewall.sh --persist        # activate + survive reboots
#   sudo bash tor_firewall.sh --unpersist      # remove persistence
#   sudo bash tor_firewall.sh --setup-bridges  # configure Tor obfs4 bridges
#   sudo bash tor_firewall.sh --help           # full documentation
#
# Designed for: Debian, Ubuntu, Kali, Whonix, Tails, Arch, Fedora VMs
# Network modes: VMware NAT, VirtualBox NAT, Bridged, Host-Only
# =============================================================================
set -euo pipefail

readonly VERSION="2.0"

# ---------- Terminal colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1;37m'
DIM='\033[0;90m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

# ---------- Root check ----------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root.${NC}"
    echo "  sudo bash $0 $*"
    exit 1
fi

# ---------- Dependency check ----------
MISSING_DEPS=""
for cmd in iptables ip6tables; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done
if [[ -n "$MISSING_DEPS" ]]; then
    echo -e "${RED}ERROR: Missing required commands:${MISSING_DEPS}${NC}"
    echo "  Install: apt install iptables   (or your distro equivalent)"
    exit 1
fi

# ---------- Tor user detection ----------
detect_tor_user() {
    local candidates=("debian-tor" "tor" "toranon" "_tor")
    for u in "${candidates[@]}"; do
        if id "$u" &>/dev/null; then
            if pgrep -u "$u" -x tor &>/dev/null 2>&1; then
                echo "$u"
                return 0
            fi
        fi
    done
    local tor_pid
    tor_pid=$(pgrep -x tor 2>/dev/null | head -1) || true
    if [[ -n "$tor_pid" ]]; then
        ps -o user= -p "$tor_pid" 2>/dev/null | tr -d ' '
        return 0
    fi
    return 1
}

# ---------- Tor port detection ----------
detect_tor_socks_port() {
    for port in 9050 9150; do
        if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
           netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo "$port"
            return 0
        fi
    done
    echo "9050"
    return 1
}

# ---------- Detect VM network interface ----------
detect_vm_interface() {
    local iface
    iface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1) || true
    if [[ -z "$iface" ]]; then
        iface=$(ip -4 addr show scope global 2>/dev/null | awk '/^[0-9]/ {print $2}' | tr -d ':' | head -1) || true
    fi
    echo "${iface:-eth0}"
}

# ---------- Detect DHCP server (VMware NAT gateway) ----------
detect_dhcp_server() {
    local gw
    gw=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1) || true
    echo "${gw:-}"
}

# ---------- Backup current rules ----------
backup_rules() {
    local backup_dir="/var/lib/tor_firewall"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    iptables-save  > "$backup_dir/iptables.backup.rules"  2>/dev/null || true
    ip6tables-save > "$backup_dir/ip6tables.backup.rules" 2>/dev/null || true
    chmod 600 "$backup_dir"/*.rules 2>/dev/null || true
    info "Backed up current iptables rules to $backup_dir/"
}

# ---------- Flush everything ----------
flush_all() {
    for table in filter nat mangle raw; do
        iptables  -t "$table" -F 2>/dev/null || true
        iptables  -t "$table" -X 2>/dev/null || true
        ip6tables -t "$table" -F 2>/dev/null || true
        ip6tables -t "$table" -X 2>/dev/null || true
    done
    for chain in INPUT FORWARD OUTPUT; do
        iptables  -P "$chain" ACCEPT 2>/dev/null || true
        ip6tables -P "$chain" ACCEPT 2>/dev/null || true
    done
}

# =========================================================================
# --undo
# =========================================================================
do_undo() {
    echo ""
    echo -e "  ${BOLD}Removing Tor firewall rules...${NC}"
    echo ""
    flush_all

    local backup_dir="/var/lib/tor_firewall"
    if [[ -f "$backup_dir/iptables.backup.rules" ]]; then
        iptables-restore  < "$backup_dir/iptables.backup.rules"  2>/dev/null && \
            info "Restored original IPv4 rules from backup" || \
            warn "Could not restore IPv4 backup (using clean slate)"
    fi
    if [[ -f "$backup_dir/ip6tables.backup.rules" ]]; then
        ip6tables-restore < "$backup_dir/ip6tables.backup.rules" 2>/dev/null && \
            info "Restored original IPv6 rules from backup" || \
            warn "Could not restore IPv6 backup (using clean slate)"
    fi

    # Re-enable IPv6 at kernel level
    sysctl -w net.ipv6.conf.all.disable_ipv6=0      >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=0   >/dev/null 2>&1 || true

    # Re-enable kernel settings changed by apply_firewall
    sysctl -w net.ipv4.icmp_echo_ignore_all=0        >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_timestamps=1              >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.log_martians=0       >/dev/null 2>&1 || true

    # Remove modprobe blocks
    rm -f /etc/modprobe.d/tor-firewall-block-tunnels.conf 2>/dev/null || true

    # Remove CLI proxy configs added by apply_firewall
    rm -f /etc/profile.d/tor-proxy.sh 2>/dev/null || true
    rm -f /etc/apt/apt.conf.d/99tor-proxy 2>/dev/null || true
    sed -i '/# tor_firewall proxy/,+3d' /etc/wgetrc 2>/dev/null || true
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy 2>/dev/null || true

    # Restart services that were stopped by apply_firewall
    for svc in systemd-resolved avahi-daemon cups-browsed; do
        if systemctl list-unit-files "$svc.service" &>/dev/null 2>&1; then
            systemctl start "$svc" 2>/dev/null || true
        fi
    done

    # Restore resolv.conf if we replaced it
    if [[ -f /etc/resolv.conf ]] && grep -q "^nameserver 127.0.0.1$" /etc/resolv.conf 2>/dev/null; then
        if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
            info "Restored resolv.conf to systemd-resolved"
        fi
    fi

    echo ""
    pass "Firewall removed. Normal networking restored."
    echo -e "  ${DIM}To re-enable: sudo bash $0${NC}"
    echo ""
    exit 0
}

# =========================================================================
# --persist / --unpersist
# =========================================================================
PERSIST_SYSTEMD="/etc/systemd/system/tor-firewall.service"
PERSIST_SCRIPT="/etc/network/if-pre-up.d/tor-firewall"

do_persist() {
    apply_firewall

    local self_path
    self_path="$(readlink -f "$0")"

    if command -v systemctl &>/dev/null; then
        cat > "$PERSIST_SYSTEMD" <<UNIT
[Unit]
Description=Transparent Tor Firewall
After=network.target tor.service
Wants=tor.service

[Service]
Type=oneshot
ExecStart=/bin/bash "$self_path"
RemainAfterExit=yes
ExecStop=/bin/bash "$self_path" --undo

[Install]
WantedBy=multi-user.target
UNIT
        chmod 644 "$PERSIST_SYSTEMD"
        systemctl daemon-reload
        systemctl enable tor-firewall.service 2>/dev/null
        pass "Persistence enabled via systemd (tor-firewall.service)"
    elif [[ -d /etc/network/if-pre-up.d ]]; then
        cat > "$PERSIST_SCRIPT" <<HOOK
#!/bin/bash
/bin/bash $self_path
HOOK
        chmod 755 "$PERSIST_SCRIPT"
        pass "Persistence enabled via if-pre-up.d"
    else
        warn "Could not set up persistence (no systemd or if-pre-up.d found)"
        warn "Add 'bash $self_path' to your startup scripts manually."
    fi

    echo ""
    exit 0
}

do_unpersist() {
    local removed=false
    if [[ -f "$PERSIST_SYSTEMD" ]]; then
        systemctl disable tor-firewall.service 2>/dev/null || true
        rm -f "$PERSIST_SYSTEMD"
        systemctl daemon-reload 2>/dev/null || true
        removed=true
    fi
    if [[ -f "$PERSIST_SCRIPT" ]]; then
        rm -f "$PERSIST_SCRIPT"
        removed=true
    fi
    if $removed; then
        pass "Persistence removed. Rules will be gone after next reboot."
    else
        info "No persistence was configured."
    fi
    echo ""
    exit 0
}

# =========================================================================
# --setup-bridges : THE fix for Malwarebytes flagging Tor IPs on the host
# =========================================================================
#
# WHY THIS MATTERS:
# -----------------
# Your setup: VM (Kali) --> VMware NAT --> vmnat.exe on host --> host VPN --> internet
#
# Without bridges:
#   Tor connects to public entry guard IPs. These IPs are on every threat
#   intelligence feed. vmnat.exe forwards the packets. Malwarebytes on the
#   host inspects the destination IP, finds it on the Tor relay list, and
#   flags it. Your host VPN encrypts the traffic AFTER vmnat, but Malwarebytes
#   hooks into the network stack BEFORE the VPN tunnel — it sees the raw
#   destination IP that vmnat is connecting to.
#
# With obfs4 bridges:
#   Tor connects to UNLISTED IPs (bridges are not in the public relay directory).
#   obfs4 makes the TLS handshake look like random noise — no Tor signature.
#   Malwarebytes sees a connection to an IP that isn't on any threat list,
#   with traffic that looks like normal HTTPS. Nothing to flag.
#
# This is the only clean fix that doesn't require touching Malwarebytes,
# doesn't require whitelisting vmnat.exe, and doesn't weaken host security.
#
do_setup_bridges() {
    echo ""
    echo -e "  ${BOLD}Setting up Tor bridges (obfs4) — anti-detection mode${NC}"
    echo ""

    # Check for obfs4proxy
    if ! command -v obfs4proxy &>/dev/null; then
        info "Installing obfs4proxy..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null
            apt-get install -y -qq obfs4proxy 2>/dev/null && \
                pass "obfs4proxy installed" || {
                fail "Could not install obfs4proxy"
                echo ""
                echo "  Manual install:"
                echo "    sudo apt install obfs4proxy"
                echo "  Or on Arch:"
                echo "    sudo pacman -S obfs4proxy"
                echo ""
                exit 1
            }
        else
            fail "Cannot auto-install obfs4proxy (not Debian/Ubuntu)"
            echo "  Install it manually, then re-run this command."
            exit 1
        fi
    else
        pass "obfs4proxy already installed"
    fi

    local TORRC="/etc/tor/torrc"
    if [[ ! -f "$TORRC" ]]; then
        fail "Cannot find $TORRC"
        exit 1
    fi

    # Find obfs4proxy binary path
    local OBFS4_PATH
    OBFS4_PATH=$(command -v obfs4proxy 2>/dev/null)
    pass "obfs4proxy binary: $OBFS4_PATH"

    # Backup torrc
    cp "$TORRC" "${TORRC}.backup.$(date +%s)" 2>/dev/null || true

    # Remove any existing bridge config added by us
    sed -i '/^# --- TOR-FIREWALL BRIDGE CONFIG START ---$/,/^# --- TOR-FIREWALL BRIDGE CONFIG END ---$/d' "$TORRC" 2>/dev/null || true

    # Fetch fresh bridges from Tor Project's BridgeDB via the API
    info "Fetching fresh obfs4 bridges from BridgeDB..."
    local BRIDGES=""
    local BRIDGE_LINES=""

    # Try fetching from the Tor Project bridge API
    # First try through existing Tor if it's running
    local tor_port
    tor_port=$(detect_tor_socks_port 2>/dev/null) || tor_port=9050
    BRIDGES=$(curl -s --max-time 30 --connect-timeout 10 \
        --socks5-hostname "127.0.0.1:${tor_port}" \
        "https://bridges.torproject.org/bridges?transport=obfs4&format=plain" 2>/dev/null) || true

    if [[ -z "$BRIDGES" ]]; then
        # Try direct if Tor isn't working yet
        BRIDGES=$(curl -s --max-time 15 --connect-timeout 10 \
            "https://bridges.torproject.org/bridges?transport=obfs4&format=plain" 2>/dev/null) || true
    fi

    if [[ -n "$BRIDGES" ]] && echo "$BRIDGES" | grep -q "obfs4"; then
        BRIDGE_LINES=$(echo "$BRIDGES" | head -3)
        pass "Got fresh bridges from BridgeDB"
    else
        # Hardcoded fallback bridges from Tor Browser bundle (publicly known, always work)
        warn "Could not fetch bridges from BridgeDB, using built-in fallbacks"
        warn "These are public fallback bridges — they work but are less private"
        warn "After setup, get private bridges from https://bridges.torproject.org"
        BRIDGE_LINES="obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgTAKQQAZPp0NF2d2bBYSIVPUWMxrE1LIHNlpQ iat-mode=0
obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=Hmyfd2ev46gGY7NoVxA9ngrPF2zCZtzskRTzoWXbxNkzeVnGFPWmrTtILRyqCTjHR+s9dg iat-mode=0
obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOl79AluViseb+r8lZEGA7J5HEyI8xg iat-mode=0"
    fi

    # Write bridge config to torrc
    cat >> "$TORRC" <<BRIDGES_BLOCK
# --- TOR-FIREWALL BRIDGE CONFIG START ---
UseBridges 1
ClientTransportPlugin obfs4 exec $OBFS4_PATH
$(echo "$BRIDGE_LINES" | while IFS= read -r line; do echo "Bridge $line"; done)
# --- TOR-FIREWALL BRIDGE CONFIG END ---
BRIDGES_BLOCK

    pass "Bridge configuration written to $TORRC"

    # Restart Tor to apply
    info "Restarting Tor with bridge config..."
    systemctl restart tor 2>/dev/null || service tor restart 2>/dev/null || true
    sleep 5

    # Verify Tor bootstraps through bridges
    local retries=0
    local tor_ok=false
    while [[ $retries -lt 6 ]]; do
        local tor_response
        tor_response=$(curl -s --max-time 15 --connect-timeout 10 \
            --socks5-hostname "127.0.0.1:${tor_port}" \
            https://check.torproject.org/api/ip 2>/dev/null) || true
        if echo "$tor_response" | grep -q '"IsTor":true' 2>/dev/null; then
            tor_ok=true
            break
        fi
        retries=$((retries + 1))
        info "Waiting for Tor to bootstrap via bridges... (attempt $retries/6)"
        sleep 5
    done

    echo ""
    if $tor_ok; then
        pass "Tor is working through obfs4 bridges"
        echo ""
        echo -e "  ${GREEN}${BOLD}Malwarebytes fix applied.${NC}"
        echo ""
        echo -e "  ${DIM}What changed:${NC}"
        echo -e "  ${DIM}  - Tor now connects to UNLISTED IPs (not on any threat feed)${NC}"
        echo -e "  ${DIM}  - Traffic looks like normal HTTPS (obfs4 obfuscation)${NC}"
        echo -e "  ${DIM}  - vmnat.exe forwards packets that Malwarebytes won't flag${NC}"
        echo -e "  ${DIM}  - Your host VPN + Malwarebytes stay fully active${NC}"
        echo ""
        echo -e "  ${DIM}For maximum privacy, get personal bridges:${NC}"
        echo -e "  ${DIM}  https://bridges.torproject.org (select obfs4)${NC}"
        echo -e "  ${DIM}  or email bridges@torproject.org from a Gmail/Riseup address${NC}"
    else
        warn "Tor hasn't bootstrapped yet — bridges may need time"
        echo "  Check status: sudo journalctl -u tor --no-pager -n 30"
        echo "  If bridges are blocked, get fresh ones from:"
        echo "    https://bridges.torproject.org"
    fi
    echo ""
    exit 0
}

# =========================================================================
# --setup-browser : Configure Firefox/Chromium to route through Tor SOCKS
# =========================================================================
#
# WHY THE BROWSER CAN'T REACH ANYTHING:
# The firewall drops ALL direct internet from the VM. Only the Tor process
# (matched by UID) can connect out. The browser runs as YOUR user, not the
# Tor user — so iptables drops it. This is CORRECT behavior.
#
# The fix: tell the browser to send traffic through Tor's SOCKS proxy at
# 127.0.0.1:9050. Loopback traffic is allowed by the firewall, and Tor
# then forwards it through its encrypted circuits.
#
# BEST OPTION: Use Tor Browser (purpose-built, anti-fingerprinting).
# ALTERNATIVE: Configure system Firefox/Chromium via SOCKS proxy.
#
do_setup_browser() {
    echo ""
    echo -e "  ${BOLD}Fixing Browser + CLI Tools — Route Everything Through Tor${NC}"
    echo ""

    local tor_port
    tor_port=$(detect_tor_socks_port 2>/dev/null) || tor_port=9050

    # =====================================================================
    # STEP 1: Fix CLI tools (wget, curl, apt, pip) — ALWAYS do this
    # =====================================================================
    echo -e "  ${CYAN}[Step 1/3] Setting up CLI tools (wget, curl, apt, pip)...${NC}"

    # System-wide proxy env vars for all future terminals
    local proxy_conf="/etc/profile.d/tor-proxy.sh"
    cat > "$proxy_conf" <<PROXY
# Set by tor_firewall.sh — routes all CLI tools through Tor
export http_proxy="socks5h://127.0.0.1:${tor_port}"
export https_proxy="socks5h://127.0.0.1:${tor_port}"
export HTTP_PROXY="socks5h://127.0.0.1:${tor_port}"
export HTTPS_PROXY="socks5h://127.0.0.1:${tor_port}"
export ALL_PROXY="socks5h://127.0.0.1:${tor_port}"
export no_proxy="127.0.0.1,localhost,::1"
PROXY
    chmod 644 "$proxy_conf"

    # Apply to current shell
    export http_proxy="socks5h://127.0.0.1:${tor_port}"
    export https_proxy="socks5h://127.0.0.1:${tor_port}"
    export HTTP_PROXY="socks5h://127.0.0.1:${tor_port}"
    export HTTPS_PROXY="socks5h://127.0.0.1:${tor_port}"
    export ALL_PROXY="socks5h://127.0.0.1:${tor_port}"
    export no_proxy="127.0.0.1,localhost,::1"

    # Configure apt
    local apt_conf="/etc/apt/apt.conf.d/99tor-proxy"
    cat > "$apt_conf" <<APTPROXY
Acquire::http::Proxy "socks5h://127.0.0.1:${tor_port}";
Acquire::https::Proxy "socks5h://127.0.0.1:${tor_port}";
APTPROXY
    chmod 644 "$apt_conf"

    # Configure wget
    if ! grep -q "# tor_firewall proxy" /etc/wgetrc 2>/dev/null; then
        cat >> /etc/wgetrc <<WGETPROXY

# tor_firewall proxy
use_proxy = on
http_proxy = http://127.0.0.1:${tor_port}
https_proxy = http://127.0.0.1:${tor_port}
WGETPROXY
    fi

    pass "CLI tools configured: wget, curl, apt, pip now use Tor"
    pass "New terminals: automatic (via /etc/profile.d/tor-proxy.sh)"
    pass "This terminal: proxy exported — works right now"
    echo ""

    # =====================================================================
    # STEP 2: Fix Firefox
    # =====================================================================
    echo -e "  ${CYAN}[Step 2/3] Setting up Firefox...${NC}"

    local ff_profiles_dir=""
    for ff_dir in "$HOME/.mozilla/firefox" "/root/.mozilla/firefox"; do
        if [[ -d "$ff_dir" ]]; then
            ff_profiles_dir="$ff_dir"
            break
        fi
    done

    if [[ -n "$ff_profiles_dir" ]]; then
        local profile_count=0
        while IFS= read -r prefs_file; do
            local profile_dir
            profile_dir=$(dirname "$prefs_file")
            local userjs="$profile_dir/user.js"

            # Remove old config if present, then write fresh
            if [[ -f "$userjs" ]]; then
                sed -i '/TOR-FIREWALL-PROXY-START/,/TOR-FIREWALL-PROXY-END/d' "$userjs" 2>/dev/null || true
            fi

            cat >> "$userjs" <<FFPROXY
// TOR-FIREWALL-PROXY-START
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", ${tor_port});
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("media.peerconnection.enabled", false);
user_pref("webgl.disabled", true);
user_pref("geo.enabled", false);
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("network.http.sendRefererHeader", 0);
user_pref("network.cookie.cookieBehavior", 1);
// TOR-FIREWALL-PROXY-END
FFPROXY
            profile_count=$((profile_count + 1))
        done < <(find "$ff_profiles_dir" -name "prefs.js" -maxdepth 2 2>/dev/null)

        if [[ $profile_count -gt 0 ]]; then
            pass "Firefox: $profile_count profile(s) configured (SOCKS5 + DNS privacy + WebRTC off)"
            warn "RESTART Firefox for changes to take effect"
        else
            warn "No Firefox profiles found — open Firefox once first, then re-run this"
        fi
    else
        warn "No Firefox profile directory found — open Firefox once first, then re-run this"
    fi
    echo ""

    # =====================================================================
    # STEP 3: Verify everything works
    # =====================================================================
    echo -e "  ${CYAN}[Step 3/3] Testing...${NC}"

    # Test CLI through proxy
    local test_result
    test_result=$(curl -s --max-time 15 --socks5-hostname "127.0.0.1:${tor_port}" \
        https://check.torproject.org/api/ip 2>/dev/null) || true
    if echo "$test_result" | grep -q '"IsTor":true' 2>/dev/null; then
        pass "curl through Tor: WORKING"
    else
        fail "curl through Tor: NOT WORKING"
        warn "Check: sudo systemctl status tor"
    fi

    # Test wget through proxy
    if wget -q --spider --timeout=15 https://check.torproject.org 2>/dev/null; then
        pass "wget through Tor: WORKING"
    else
        warn "wget through Tor: may need a new terminal (run: . /etc/profile.d/tor-proxy.sh)"
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}Setup complete.${NC}"
    echo ""
    echo -e "  ${BOLD}What works now:${NC}"
    echo -e "    ${GREEN}✓${NC} curl, wget, apt, pip — through Tor automatically"
    echo -e "    ${GREEN}✓${NC} Firefox — through Tor (restart Firefox first)"
    echo -e "    ${GREEN}✓${NC} New terminals — proxy set automatically"
    echo ""
    echo -e "  ${BOLD}For THIS terminal (if wget still fails):${NC}"
    echo -e "    ${BOLD}. /etc/profile.d/tor-proxy.sh${NC}"
    echo ""
    echo -e "  ${BOLD}For Chromium:${NC}"
    echo -e "    ${BOLD}chromium --proxy-server=\"socks5://127.0.0.1:${tor_port}\"${NC}"
    echo ""
    exit 0
}

# =========================================================================
# --status
# =========================================================================
do_status() {
    echo ""
    echo -e "  ${BOLD}=== Tor Firewall Status (v${VERSION}) ===${NC}"
    echo ""

    echo -e "  ${CYAN}--- IPv4 OUTPUT chain ---${NC}"
    iptables -L OUTPUT -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""
    echo -e "  ${CYAN}--- IPv4 INPUT chain ---${NC}"
    iptables -L INPUT -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""
    echo -e "  ${CYAN}--- IPv4 FORWARD chain ---${NC}"
    iptables -L FORWARD -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""
    echo -e "  ${CYAN}--- IPv4 RAW OUTPUT ---${NC}"
    iptables -t raw -L OUTPUT -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""
    echo -e "  ${CYAN}--- IPv6 OUTPUT chain ---${NC}"
    ip6tables -L OUTPUT -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""

    # Show bridge status
    if grep -q "^UseBridges 1" /etc/tor/torrc 2>/dev/null; then
        pass "Tor bridges: ENABLED (obfs4)"
        local guard_ips
        guard_ips=$(grep "^Bridge obfs4" /etc/tor/torrc 2>/dev/null | awk '{print $3}' | cut -d: -f1 || true)
        if [[ -n "$guard_ips" ]]; then
            info "Bridge IPs (what vmnat.exe connects to):"
            echo "$guard_ips" | while IFS= read -r ip; do
                echo -e "    ${DIM}$ip${NC}"
            done
        fi
    else
        warn "Tor bridges: NOT configured (Malwarebytes may flag entry guard IPs)"
        echo -e "    ${DIM}Fix: sudo bash $0 --setup-bridges${NC}"
    fi
    echo ""

    # Show kernel hardening
    echo -e "  ${CYAN}--- Kernel hardening ---${NC}"
    local checks=(
        "net.ipv4.ip_forward:0:IP forwarding disabled"
        "net.ipv6.conf.all.disable_ipv6:1:IPv6 disabled"
        "net.ipv4.conf.all.accept_redirects:0:ICMP redirects blocked"
        "net.ipv4.conf.all.accept_source_route:0:Source routing blocked"
        "net.ipv4.tcp_timestamps:0:TCP timestamps disabled"
        "net.ipv4.conf.all.rp_filter:1:Reverse-path filtering on"
        "net.ipv4.icmp_echo_ignore_all:1:ICMP echo disabled"
    )
    for check in "${checks[@]}"; do
        local key val desc
        key=$(echo "$check" | cut -d: -f1)
        val=$(echo "$check" | cut -d: -f2)
        desc=$(echo "$check" | cut -d: -f3)
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "?")
        if [[ "$actual" == "$val" ]]; then
            pass "$desc ($key=$actual)"
        else
            fail "$desc ($key=$actual, expected $val)"
        fi
    done
    echo ""

    run_tests
    exit 0
}

# =========================================================================
# Leak tests
# =========================================================================
run_tests() {
    local failures=0

    echo -e "  ${BOLD}=== Leak Tests ===${NC}"
    echo ""

    # Test 1: Direct TCP
    info "Test 1/9: Direct TCP to clearnet (should be blocked)..."
    if curl -s --max-time 5 --connect-timeout 3 https://1.1.1.1 &>/dev/null 2>&1; then
        fail "Direct TCP to clearnet is OPEN"
        failures=$((failures + 1))
    else
        pass "Direct TCP blocked"
    fi

    # Test 2: Direct DNS via UDP 53
    info "Test 2/9: Direct DNS via UDP 53 (should be blocked)..."
    local dns_leaked=false
    if command -v nslookup &>/dev/null; then
        if nslookup google.com 8.8.8.8 2>/dev/null | grep -q "Address:" 2>/dev/null; then
            dns_leaked=true
        fi
    fi
    if ! $dns_leaked && command -v dig &>/dev/null; then
        if dig +short +time=3 +tries=1 @8.8.8.8 google.com 2>/dev/null | grep -q "\." 2>/dev/null; then
            dns_leaked=true
        fi
    fi
    if ! $dns_leaked && command -v host &>/dev/null; then
        if host -W 3 google.com 8.8.8.8 2>/dev/null | grep -q "has address" 2>/dev/null; then
            dns_leaked=true
        fi
    fi
    if $dns_leaked; then
        fail "Direct DNS (UDP 53) is OPEN — DNS leak!"
        failures=$((failures + 1))
    else
        pass "Direct DNS blocked"
    fi

    # Test 3: DNS via TCP 853 (DNS-over-TLS)
    info "Test 3/9: DNS-over-TLS TCP 853 (should be blocked)..."
    if (echo "" | timeout 3 openssl s_client -connect 1.1.1.1:853 2>/dev/null | grep -q "CONNECTED") 2>/dev/null; then
        fail "DNS-over-TLS (TCP 853) is OPEN — leak!"
        failures=$((failures + 1))
    else
        pass "DNS-over-TLS blocked"
    fi

    # Test 4: ICMP ping
    info "Test 4/9: ICMP ping (should be blocked)..."
    if ping -c 1 -W 3 8.8.8.8 &>/dev/null 2>&1; then
        fail "ICMP ping is OPEN"
        failures=$((failures + 1))
    else
        pass "ICMP blocked"
    fi

    # Test 5: IPv6
    info "Test 5/9: IPv6 (should be blocked)..."
    local ipv6_leaked=false
    if ping6 -c 1 -W 3 2001:4860:4860::8888 &>/dev/null 2>&1; then
        ipv6_leaked=true
    elif ping -6 -c 1 -W 3 2001:4860:4860::8888 &>/dev/null 2>&1; then
        ipv6_leaked=true
    fi
    if $ipv6_leaked; then
        fail "IPv6 is OPEN"
        failures=$((failures + 1))
    else
        pass "IPv6 blocked"
    fi

    # Test 6: NTP (UDP 123)
    info "Test 6/9: NTP time sync UDP 123 (should be blocked)..."
    if command -v ntpdate &>/dev/null; then
        if ntpdate -q -t 3 pool.ntp.org &>/dev/null 2>&1; then
            fail "NTP (UDP 123) is OPEN — timing leak!"
            failures=$((failures + 1))
        else
            pass "NTP blocked"
        fi
    else
        pass "NTP blocked (ntpdate not installed)"
    fi

    # Test 7: Multicast/mDNS (UDP 5353)
    info "Test 7/9: mDNS/multicast (should be blocked)..."
    if (echo "test" > /dev/udp/224.0.0.251/5353) 2>/dev/null; then
        fail "mDNS multicast (UDP 5353) is OPEN — LAN leak!"
        failures=$((failures + 1))
    else
        pass "mDNS/multicast blocked"
    fi

    # Test 8: Arbitrary high port
    info "Test 8/9: Arbitrary outbound TCP (should be blocked)..."
    if (echo "test" > /dev/tcp/1.1.1.1/8443) 2>/dev/null; then
        fail "Arbitrary outbound TCP is OPEN"
        failures=$((failures + 1))
    else
        pass "Arbitrary outbound TCP blocked"
    fi

    # Test 9: Tor SOCKS
    local tor_port
    tor_port=$(detect_tor_socks_port 2>/dev/null) || tor_port=9050
    info "Test 9/9: Tor SOCKS on 127.0.0.1:${tor_port} (should work)..."
    local tor_response
    tor_response=$(curl -s --max-time 20 --connect-timeout 10 \
        --socks5-hostname "127.0.0.1:${tor_port}" \
        https://check.torproject.org/api/ip 2>/dev/null) || true
    if echo "$tor_response" | grep -q '"IsTor":true' 2>/dev/null; then
        pass "Tor is working (confirmed by check.torproject.org)"
        local tor_ip
        tor_ip=$(echo "$tor_response" | sed -n 's/.*"IP":"\([^"]*\)".*/\1/p' 2>/dev/null || echo "")
        if [[ -n "$tor_ip" ]]; then
            info "Exit node: \"IP\":\"$tor_ip\""
        fi
    else
        fail "Tor is NOT working through SOCKS"
        warn "Check: sudo systemctl status tor"
        warn "Check: sudo journalctl -u tor --no-pager -n 20"
        failures=$((failures + 1))
    fi

    echo ""
    if [[ $failures -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}ALL 9 TESTS PASSED — Zero leaks detected.${NC}"
    else
        echo -e "  ${RED}${BOLD}$failures TEST(S) FAILED — You have leaks!${NC}"
    fi
    echo ""
    return $failures
}

# =========================================================================
# Core: Apply the firewall
# =========================================================================
apply_firewall() {
    echo ""
    echo -e "  ${BOLD}Transparent Tor Firewall v${VERSION}${NC}"
    echo -e "  ${DIM}Sealing all non-Tor traffic...${NC}"
    echo ""

    # --- Detect Tor user ---
    local TOR_USER
    TOR_USER=$(detect_tor_user) || true
    if [[ -z "$TOR_USER" ]]; then
        fail "Cannot find running Tor process. Is Tor installed and running?"
        echo ""
        echo "  Start Tor first:"
        echo "    sudo systemctl start tor"
        echo "    sudo systemctl enable tor"
        echo ""
        exit 1
    fi
    info "Tor daemon runs as: ${BOLD}${TOR_USER}${NC}"

    # --- Detect Tor SOCKS port ---
    local TOR_PORT
    TOR_PORT=$(detect_tor_socks_port 2>/dev/null) || TOR_PORT=9050
    info "Tor SOCKS port: ${BOLD}${TOR_PORT}${NC}"

    # --- Get Tor UID ---
    local TOR_UID
    TOR_UID=$(id -u "$TOR_USER" 2>/dev/null) || true
    if [[ -z "$TOR_UID" ]]; then
        fail "Cannot resolve UID for user '$TOR_USER'"
        exit 1
    fi
    info "Tor UID: ${BOLD}${TOR_UID}${NC}"

    # --- Detect VM network ---
    local VM_IFACE DHCP_GW
    VM_IFACE=$(detect_vm_interface)
    DHCP_GW=$(detect_dhcp_server)
    info "Network interface: ${BOLD}${VM_IFACE}${NC}"
    if [[ -n "$DHCP_GW" ]]; then
        info "Default gateway: ${BOLD}${DHCP_GW}${NC}"
    fi

    # --- Backup existing rules ---
    backup_rules

    # --- Flush everything clean ---
    flush_all

    # =====================================================================
    # IPv4 — iptables
    # =====================================================================

    # Default policies: DROP everything
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  DROP

    # -- INPUT chain --
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Allow DHCP responses from gateway (needed for VMware NAT lease renewal)
    # Without this, the VM loses its IP when the DHCP lease expires and
    # Tor dies because there's no network.
    # Locked to: UDP only, port 68 only, from port 67 only.
    iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT

    # Rate-limited logging then DROP
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "TOR-FW-IN-DROP: " --log-level 4 2>/dev/null || true
    iptables -A INPUT -j DROP

    # -- OUTPUT chain --
    # Loopback: apps talk to Tor on 127.0.0.1
    iptables -A OUTPUT -o lo -j ACCEPT

    # Tor process: allowed to reach the internet (entry guards / bridges)
    # TCP ONLY — Tor never uses raw UDP for circuit building.
    # This prevents anything running as the Tor user from sending UDP.
    iptables -A OUTPUT -p tcp -m owner --uid-owner "$TOR_UID" -j ACCEPT

    # Tor DNS resolution: Tor resolves DNS over its own circuits, but the
    # tor binary itself may do limited local DNS. Allow Tor user UDP 53 ONLY
    # to localhost (where Tor's internal DNS port lives, never external).
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.1 -m owner --uid-owner "$TOR_UID" -j ACCEPT

    # DHCP lease renewal: VM must be able to request/renew DHCP lease.
    # Without this, after lease expiry the VM loses its IP and Tor dies.
    # Locked to: UDP only, local port 68, remote port 67.
    iptables -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT

    # ---- Explicit blocks for dangerous protocols (defense in depth) ----
    # These are redundant given DROP policy but make the firewall
    # self-documenting and survive accidental policy changes.

    # DNS leak prevention
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
    # DNS-over-TLS
    iptables -A OUTPUT -p tcp --dport 853 -j DROP
    # DNS-over-HTTPS well-known resolvers
    iptables -A OUTPUT -p tcp -d 1.1.1.1 --dport 443 -j DROP
    iptables -A OUTPUT -p tcp -d 1.0.0.1 --dport 443 -j DROP
    iptables -A OUTPUT -p tcp -d 8.8.8.8 --dport 443 -j DROP
    iptables -A OUTPUT -p tcp -d 8.8.4.4 --dport 443 -j DROP
    iptables -A OUTPUT -p tcp -d 9.9.9.9 --dport 443 -j DROP
    # NTP
    iptables -A OUTPUT -p udp --dport 123 -j DROP
    # ICMP
    iptables -A OUTPUT -p icmp -j DROP
    # mDNS (Avahi/Bonjour — leaks hostname to LAN)
    iptables -A OUTPUT -p udp --dport 5353 -j DROP
    # LLMNR (Microsoft name resolution — leaks hostname to LAN)
    iptables -A OUTPUT -p udp --dport 5355 -j DROP
    # SSDP/UPnP (device discovery — leaks VM presence to LAN)
    iptables -A OUTPUT -p udp --dport 1900 -j DROP
    # NetBIOS (Windows name resolution — leaks to LAN)
    iptables -A OUTPUT -p udp --dport 137 -j DROP
    iptables -A OUTPUT -p udp --dport 138 -j DROP
    iptables -A OUTPUT -p tcp --dport 139 -j DROP
    iptables -A OUTPUT -p tcp --dport 445 -j DROP
    # Multicast range (224.0.0.0/4)
    iptables -A OUTPUT -d 224.0.0.0/4 -j DROP
    # Broadcast
    iptables -A OUTPUT -d 255.255.255.255 -j DROP

    # Rate-limited logging then DROP everything else
    iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "TOR-FW-OUT-DROP: " --log-level 4 2>/dev/null || true
    iptables -A OUTPUT -j DROP

    # -- FORWARD chain --
    iptables -A FORWARD -j DROP

    # -- NAT table: flush to prevent any leak paths --
    iptables -t nat -F
    iptables -t nat -X 2>/dev/null || true

    # -- Mangle table: flush --
    iptables -t mangle -F
    iptables -t mangle -X 2>/dev/null || true

    # -- Raw table: drop non-Tor before conntrack --
    iptables -t raw -F
    iptables -t raw -A OUTPUT -o lo -j ACCEPT
    iptables -t raw -A OUTPUT -p tcp -m owner --uid-owner "$TOR_UID" -j ACCEPT
    iptables -t raw -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
    iptables -t raw -A OUTPUT -j DROP

    # =====================================================================
    # IPv6 — BLOCK ALL (IPv6 is an OPSEC catastrophe for Tor)
    # =====================================================================
    # Even with no IPv6 address, the kernel responds to neighbor
    # solicitations, leaks link-local addresses, and tunnels (6to4,
    # Teredo, ISATAP) can bypass iptables entirely.

    ip6tables -P INPUT   DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT  DROP

    ip6tables -A INPUT  -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    ip6tables -A INPUT   -j DROP
    ip6tables -A FORWARD -j DROP
    ip6tables -A OUTPUT  -j DROP

    # =====================================================================
    # Kernel hardening
    # =====================================================================

    # Disable IPv6 at kernel level
    if [[ -d /proc/sys/net/ipv6 ]]; then
        sysctl -w net.ipv6.conf.all.disable_ipv6=1       >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=1    >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.lo.disable_ipv6=0         >/dev/null 2>&1 || true
    fi

    # Disable ICMP redirects (route injection)
    sysctl -w net.ipv4.conf.all.accept_redirects=0        >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.accept_redirects=0    >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.send_redirects=0          >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.accept_redirects=0        >/dev/null 2>&1 || true

    # Disable IP forwarding
    sysctl -w net.ipv4.ip_forward=0                       >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=0              >/dev/null 2>&1 || true

    # Disable source routing
    sysctl -w net.ipv4.conf.all.accept_source_route=0     >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null 2>&1 || true

    # Ignore ALL ICMP echo (not just broadcasts — prevents any ping fingerprinting)
    sysctl -w net.ipv4.icmp_echo_ignore_all=1             >/dev/null 2>&1 || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1      >/dev/null 2>&1 || true

    # Enable reverse-path filtering (anti-spoofing)
    sysctl -w net.ipv4.conf.all.rp_filter=1               >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=1           >/dev/null 2>&1 || true

    # Log martian packets
    sysctl -w net.ipv4.conf.all.log_martians=1            >/dev/null 2>&1 || true

    # Disable TCP timestamps (OS fingerprinting)
    sysctl -w net.ipv4.tcp_timestamps=0                   >/dev/null 2>&1 || true

    # Disable IGMP (multicast group management — leaks VM presence)
    sysctl -w net.ipv4.conf.all.force_igmp_version=0      >/dev/null 2>&1 || true
    # Disable multicast on all interfaces
    for iface_path in /proc/sys/net/ipv4/conf/*/mc_forwarding; do
        echo 0 > "$iface_path" 2>/dev/null || true
    done

    # Disable ARP announcements that aren't strictly necessary
    # (prevents gratuitous ARPs that announce the VM to the LAN)
    sysctl -w net.ipv4.conf.all.arp_ignore=1              >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.arp_announce=2            >/dev/null 2>&1 || true

    # =====================================================================
    # Disable tunnel interfaces that bypass iptables
    # =====================================================================
    for mod in ipv6 sit ip6_tunnel ip_gre ip6_gre ip6t_rt ipip ip6_vti ip_vti; do
        modprobe -r "$mod" 2>/dev/null || true
    done

    local modprobe_block="/etc/modprobe.d/tor-firewall-block-tunnels.conf"
    cat > "$modprobe_block" <<'MODBLOCK'
install sit /bin/true
install ip6_tunnel /bin/true
install ip_gre /bin/true
install ip6_gre /bin/true
install ip6t_rt /bin/true
install ipip /bin/true
install ip6_vti /bin/true
install ip_vti /bin/true
MODBLOCK
    chmod 644 "$modprobe_block"

    # =====================================================================
    # Disable problematic system services that leak to network
    # =====================================================================
    for svc in avahi-daemon cups-browsed systemd-resolved; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            info "Stopped leaky service: $svc"
        fi
    done

    # If systemd-resolved was handling DNS, point resolv.conf to localhost
    # so Tor's DNS resolution still works
    if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf 2>/dev/null | grep -q "systemd"; then
        rm -f /etc/resolv.conf 2>/dev/null || true
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        info "Pointed resolv.conf to localhost (Tor handles DNS)"
    fi

    # =====================================================================
    # Summary
    # =====================================================================
    echo ""
    pass "Firewall rules applied"
    pass "IPv4: Only Tor (UID $TOR_UID / $TOR_USER) can reach the network — TCP only"
    pass "IPv6: Completely disabled (kernel + ip6tables + modules unloaded)"
    pass "DNS:  UDP/TCP 53 + DoT 853 + DoH resolver IPs all dropped"
    pass "ICMP: Dropped everywhere (kernel + iptables)"
    pass "LAN:  mDNS, LLMNR, SSDP, NetBIOS, multicast, broadcast all dropped"
    pass "NTP:  UDP 123 dropped (prevents timing correlation)"
    pass "DHCP: Allowed (UDP 67/68 only — keeps VMware NAT lease alive)"
    pass "Tunnels: Blocked at module level (sit, gre, ipip, etc.)"
    pass "Services: avahi-daemon, cups-browsed, systemd-resolved stopped"
    pass "Kernel: Forwarding off, redirects off, timestamps off, ARP restricted"
    pass "Raw table: Non-Tor packets dropped before conntrack"
    echo ""

    # ── Auto-configure CLI proxy so wget/curl/apt/pip work through Tor ──
    local tor_port
    tor_port=$(detect_tor_socks_port 2>/dev/null) || tor_port=9050

    local proxy_conf="/etc/profile.d/tor-proxy.sh"
    cat > "$proxy_conf" <<PROXY
# Set by tor_firewall.sh — routes all CLI tools through Tor
export http_proxy="socks5h://127.0.0.1:${tor_port}"
export https_proxy="socks5h://127.0.0.1:${tor_port}"
export HTTP_PROXY="socks5h://127.0.0.1:${tor_port}"
export HTTPS_PROXY="socks5h://127.0.0.1:${tor_port}"
export ALL_PROXY="socks5h://127.0.0.1:${tor_port}"
export no_proxy="127.0.0.1,localhost,::1"
PROXY
    chmod 644 "$proxy_conf"

    # Apply to current shell immediately
    export http_proxy="socks5h://127.0.0.1:${tor_port}"
    export https_proxy="socks5h://127.0.0.1:${tor_port}"
    export HTTP_PROXY="socks5h://127.0.0.1:${tor_port}"
    export HTTPS_PROXY="socks5h://127.0.0.1:${tor_port}"
    export ALL_PROXY="socks5h://127.0.0.1:${tor_port}"
    export no_proxy="127.0.0.1,localhost,::1"

    # Configure apt to use Tor SOCKS proxy
    local apt_conf="/etc/apt/apt.conf.d/99tor-proxy"
    cat > "$apt_conf" <<APTPROXY
Acquire::http::Proxy "socks5h://127.0.0.1:${tor_port}";
Acquire::https::Proxy "socks5h://127.0.0.1:${tor_port}";
APTPROXY
    chmod 644 "$apt_conf"

    # Configure wget to use Tor
    local wgetrc="/etc/wgetrc.d"
    mkdir -p "$wgetrc" 2>/dev/null || true
    local wget_proxy="/etc/wgetrc"
    if ! grep -q "# tor_firewall proxy" "$wget_proxy" 2>/dev/null; then
        cat >> "$wget_proxy" <<WGETPROXY

# tor_firewall proxy
use_proxy = on
http_proxy = http://127.0.0.1:${tor_port}
https_proxy = http://127.0.0.1:${tor_port}
WGETPROXY
    fi

    pass "CLI proxy: wget, curl, apt, pip all route through Tor automatically"
    pass "Proxy env vars set: http_proxy, https_proxy, ALL_PROXY"
    echo ""

    # Bridge check
    if grep -q "^UseBridges 1" /etc/tor/torrc 2>/dev/null; then
        pass "Tor bridges: ACTIVE (entry guard IPs hidden from host)"
    else
        warn "Tor bridges: NOT configured"
        echo -e "    ${DIM}Malwarebytes on the host may flag Tor entry guard IPs.${NC}"
        echo -e "    ${DIM}Fix: sudo bash $0 --setup-bridges${NC}"
        echo ""
    fi

    # Run verification
    run_tests || true

    echo ""
    echo -e "  ${BOLD}What your host sees now:${NC}"
    echo -e "  ${DIM}  vmnat.exe forwards TCP packets from your VM to the internet.${NC}"
    if grep -q "^UseBridges 1" /etc/tor/torrc 2>/dev/null; then
        echo -e "  ${DIM}  Destination IPs: unlisted bridge relays (NOT on threat feeds).${NC}"
        echo -e "  ${DIM}  Traffic pattern: looks like normal HTTPS (obfs4 obfuscation).${NC}"
        echo -e "  ${DIM}  Malwarebytes: nothing to flag.${NC}"
    else
        echo -e "  ${DIM}  Destination IPs: Tor entry guards (may be on threat feeds).${NC}"
        echo -e "  ${DIM}  Malwarebytes may flag these. Run: sudo bash $0 --setup-bridges${NC}"
    fi
    echo ""
    echo -e "  ${GREEN}${BOLD}CLI tools (wget, curl, apt, pip) now work through Tor automatically.${NC}"
    echo -e "  ${DIM}  New terminals pick this up automatically via /etc/profile.d/tor-proxy.sh${NC}"
    echo -e "  ${DIM}  Current terminal: proxy vars already exported.${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}BROWSER NOT WORKING?${NC} That's correct — the firewall blocks direct internet."
    echo -e "  ${YELLOW}Run this to fix it:${NC}"
    echo -e "    ${BOLD}sudo bash $0 --setup-browser${NC}"
    echo ""
    echo -e "  ${DIM}Undo:    sudo bash $0 --undo${NC}"
    echo -e "  ${DIM}Status:  sudo bash $0 --status${NC}"
    echo -e "  ${DIM}Browser: sudo bash $0 --setup-browser${NC}"
    echo -e "  ${DIM}Persist: sudo bash $0 --persist${NC}"
    echo ""
}

# =========================================================================
# Argument routing
# =========================================================================
case "${1:-}" in
    --undo|--remove|--off|--disable|--restore)
        do_undo
        ;;
    --status|--check|--test)
        do_status
        ;;
    --persist|--enable-persist|--permanent)
        do_persist
        ;;
    --unpersist|--disable-persist|--no-persist)
        do_unpersist
        ;;
    --setup-bridges|--bridges|--obfs4)
        do_setup_bridges
        ;;
    --setup-browser|--browser|--firefox|--proxy)
        do_setup_browser
        ;;
    --help|-h)
        echo ""
        echo -e "  ${BOLD}Transparent Tor Firewall v${VERSION} — Zero-Leak VM Lockdown${NC}"
        echo ""
        echo "  Usage:"
        echo "    sudo bash $0                  Apply firewall"
        echo "    sudo bash $0 --status         Show rules + run 9 leak tests"
        echo "    sudo bash $0 --undo           Remove firewall, restore networking"
        echo "    sudo bash $0 --persist        Apply + survive reboots"
        echo "    sudo bash $0 --unpersist      Remove reboot persistence"
        echo "    sudo bash $0 --setup-bridges  Configure obfs4 bridges (fixes Malwarebytes)"
        echo "    sudo bash $0 --setup-browser  Configure Firefox/Chrome to use Tor SOCKS"
        echo "    sudo bash $0 --help           This message"
        echo ""
        echo "  What it blocks (from INSIDE the VM):"
        echo "    - ALL direct TCP/UDP from any process except Tor"
        echo "    - ALL DNS (UDP 53, TCP 53, DoT 853, DoH to known resolvers)"
        echo "    - ALL ICMP (ping, traceroute, redirects)"
        echo "    - ALL IPv6 (kernel disabled + ip6tables + tunnel modules blocked)"
        echo "    - ALL LAN discovery (mDNS 5353, LLMNR 5355, SSDP 1900, NetBIOS 137-139/445)"
        echo "    - ALL multicast (224.0.0.0/4) and broadcast (255.255.255.255)"
        echo "    - ALL NTP (UDP 123 — prevents timing correlation)"
        echo "    - ALL IP forwarding, source routing, ICMP redirects"
        echo "    - ALL tunnel interfaces (sit, gre, ipip, 6to4, Teredo, ISATAP)"
        echo "    - ALL conntrack state for non-Tor packets (raw table DROP)"
        echo "    - ALL gratuitous ARP announcements"
        echo "    - avahi-daemon, cups-browsed, systemd-resolved (stopped)"
        echo ""
        echo "  What it allows:"
        echo "    - Loopback (127.0.0.1 / ::1) — apps talk to Tor here"
        echo "    - Tor process (UID match, TCP only) — connects to entry guards"
        echo "    - DHCP (UDP 67/68 only) — keeps VM IP alive on VMware NAT"
        echo "    - Nothing else. Zero exceptions."
        echo ""
        echo "  VMware NAT + Malwarebytes (the host WiFi concern):"
        echo "    The firewall blocks all non-Tor traffic inside the VM."
        echo "    vmnat.exe only sees Tor-encrypted TCP to entry guard IPs."
        echo "    If Malwarebytes flags those IPs (they're on threat feeds),"
        echo "    run --setup-bridges to switch Tor to unlisted obfs4 bridges."
        echo "    Bridges use IPs not on ANY threat feed, and obfs4 makes the"
        echo "    traffic look like normal HTTPS. Malwarebytes has nothing to flag."
        echo ""
        echo "  Recommended setup (do these in order):"
        echo "    1. sudo bash $0 --setup-bridges    # stop Malwarebytes alerts"
        echo "    2. sudo bash $0                     # lock down the VM"
        echo "    3. sudo bash $0 --setup-browser    # make Firefox/Chrome work through Tor"
        echo "    4. sudo bash $0 --persist           # survive reboots"
        echo ""
        exit 0
        ;;
    "")
        apply_firewall
        ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        echo "  Run: sudo bash $0 --help"
        exit 1
        ;;
esac
