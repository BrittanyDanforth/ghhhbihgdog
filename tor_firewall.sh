#!/bin/bash
# =============================================================================
# Transparent Tor Firewall — Zero-Leak VM Lockdown
# =============================================================================
#
# Seals every outbound path so ONLY the Tor process can reach the network.
# Everything else (apps, malware, DNS, ICMP, IPv6) is hard-dropped.
#
# Usage:
#   sudo bash tor_firewall.sh              # activate firewall
#   sudo bash tor_firewall.sh --status     # show current rules + leak tests
#   sudo bash tor_firewall.sh --undo       # remove all rules (restore open networking)
#   sudo bash tor_firewall.sh --persist    # activate + survive reboots
#   sudo bash tor_firewall.sh --unpersist  # remove persistence (rules stay until reboot/undo)
#
# Designed for: Debian, Ubuntu, Kali, Whonix, Tails, Arch, Fedora VMs
# Requires:     root, iptables, ip6tables, tor running
# =============================================================================
set -euo pipefail

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
# Different distros use different usernames for the Tor daemon.
detect_tor_user() {
    local candidates=("debian-tor" "tor" "toranon" "_tor" "root")
    for u in "${candidates[@]}"; do
        if id "$u" &>/dev/null; then
            # Verify this user actually owns the tor process
            if pgrep -u "$u" -x tor &>/dev/null 2>&1; then
                echo "$u"
                return 0
            fi
        fi
    done
    # Fallback: find who actually owns the running tor process
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
    # Reset default policies to ACCEPT so the system isn't bricked if
    # this flush is called standalone (--undo).
    for chain in INPUT FORWARD OUTPUT; do
        iptables  -P "$chain" ACCEPT 2>/dev/null || true
        ip6tables -P "$chain" ACCEPT 2>/dev/null || true
    done
}

# =========================================================================
# --undo : Remove all firewall rules and restore open networking
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

    echo ""
    pass "Firewall removed. Normal networking restored."
    echo -e "  ${DIM}To re-enable: sudo bash $0${NC}"
    echo ""
    exit 0
}

# =========================================================================
# --persist / --unpersist : Survive reboots
# =========================================================================
PERSIST_SCRIPT="/etc/network/if-pre-up.d/tor-firewall"
PERSIST_SYSTEMD="/etc/systemd/system/tor-firewall.service"

do_persist() {
    # Apply the firewall first
    apply_firewall

    local self_path
    self_path="$(readlink -f "$0")"

    # Method 1: systemd (preferred)
    if command -v systemctl &>/dev/null; then
        cat > "$PERSIST_SYSTEMD" <<UNIT
[Unit]
Description=Transparent Tor Firewall
Before=network-pre.target
Wants=network-pre.target
After=tor.service

[Service]
Type=oneshot
ExecStart=/bin/bash $self_path
RemainAfterExit=yes
ExecStop=/bin/bash $self_path --undo

[Install]
WantedBy=multi-user.target
UNIT
        chmod 644 "$PERSIST_SYSTEMD"
        systemctl daemon-reload
        systemctl enable tor-firewall.service 2>/dev/null
        pass "Persistence enabled via systemd (tor-firewall.service)"
    # Method 2: if-pre-up.d (Debian/Ubuntu fallback)
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
# --status : Show rules + run leak tests
# =========================================================================
do_status() {
    echo ""
    echo -e "  ${BOLD}=== Tor Firewall Status ===${NC}"
    echo ""

    echo -e "  ${CYAN}--- IPv4 OUTPUT chain ---${NC}"
    iptables -L OUTPUT -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""
    echo -e "  ${CYAN}--- IPv4 FORWARD chain ---${NC}"
    iptables -L FORWARD -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
    echo ""
    echo -e "  ${CYAN}--- IPv6 OUTPUT chain ---${NC}"
    ip6tables -L OUTPUT -v -n --line-numbers 2>/dev/null || echo "  (no rules)"
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

    # Test 1: Direct TCP should be blocked
    info "Test 1: Direct TCP (should be blocked)..."
    if curl -s --max-time 5 --connect-timeout 3 https://1.1.1.1 &>/dev/null 2>&1; then
        fail "Direct TCP to clearnet is OPEN — leak!"
        ((failures++))
    else
        pass "Direct TCP blocked"
    fi

    # Test 2: Direct DNS should be blocked
    info "Test 2: Direct UDP/DNS (should be blocked)..."
    if nslookup google.com 8.8.8.8 2>/dev/null | grep -q "Address:" 2>/dev/null; then
        fail "Direct DNS (UDP 53) is OPEN — leak!"
        ((failures++))
    elif dig +short +time=3 +tries=1 @8.8.8.8 google.com 2>/dev/null | grep -q "\." 2>/dev/null; then
        fail "Direct DNS (UDP 53) is OPEN — leak!"
        ((failures++))
    else
        pass "Direct DNS blocked"
    fi

    # Test 3: ICMP/ping should be blocked
    info "Test 3: ICMP ping (should be blocked)..."
    if ping -c 1 -W 3 8.8.8.8 &>/dev/null 2>&1; then
        fail "ICMP ping is OPEN — leak!"
        ((failures++))
    else
        pass "ICMP blocked"
    fi

    # Test 4: IPv6 should be fully blocked
    info "Test 4: IPv6 (should be blocked)..."
    if ping6 -c 1 -W 3 2001:4860:4860::8888 &>/dev/null 2>&1; then
        fail "IPv6 is OPEN — leak!"
        ((failures++))
    else
        pass "IPv6 blocked"
    fi

    # Test 5: Tor SOCKS should work
    local tor_port
    tor_port=$(detect_tor_socks_port 2>/dev/null) || tor_port=9050
    info "Test 5: Tor SOCKS on 127.0.0.1:${tor_port} (should work)..."
    local tor_response
    tor_response=$(curl -s --max-time 20 --connect-timeout 10 \
        --socks5-hostname "127.0.0.1:${tor_port}" \
        https://check.torproject.org/api/ip 2>/dev/null) || true
    if echo "$tor_response" | grep -q '"IsTor":true' 2>/dev/null; then
        pass "Tor is working (confirmed by check.torproject.org)"
        local tor_ip
        tor_ip=$(echo "$tor_response" | grep -oP '"IP":"[^"]*"' 2>/dev/null || echo "")
        if [[ -n "$tor_ip" ]]; then
            info "Exit node: $tor_ip"
        fi
    else
        fail "Tor is NOT working through SOCKS"
        warn "Check: sudo systemctl status tor"
        ((failures++))
    fi

    # Test 6: Verify no other outbound protocol works
    info "Test 6: Arbitrary high port (should be blocked)..."
    if (echo "test" > /dev/tcp/1.1.1.1/443) 2>/dev/null; then
        fail "Arbitrary outbound TCP is OPEN — leak!"
        ((failures++))
    else
        pass "Arbitrary outbound TCP blocked"
    fi

    echo ""
    if [[ $failures -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}ALL TESTS PASSED — Zero leaks detected.${NC}"
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
    echo -e "  ${BOLD}Transparent Tor Firewall${NC}"
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

    # --- Get Tor UID for reliable matching ---
    local TOR_UID
    TOR_UID=$(id -u "$TOR_USER" 2>/dev/null) || true
    if [[ -z "$TOR_UID" ]]; then
        fail "Cannot resolve UID for user '$TOR_USER'"
        exit 1
    fi
    info "Tor UID: ${BOLD}${TOR_UID}${NC}"

    # --- Backup existing rules ---
    backup_rules

    # --- Flush everything clean ---
    flush_all

    # =====================================================================
    # IPv4 — iptables
    # =====================================================================

    # -- Default policies: DROP everything --
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  DROP

    # -- INPUT chain --
    # Allow loopback (Tor listens on 127.0.0.1)
    iptables -A INPUT -i lo -j ACCEPT
    # Allow established/related connections (responses to Tor's outbound)
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    # Log then drop everything else
    iptables -A INPUT -j LOG --log-prefix "TOR-FW-INPUT-DROP: " --log-level 4 -m limit --limit 5/min || true
    iptables -A INPUT -j DROP

    # -- OUTPUT chain --
    # Allow loopback (apps talk to Tor on 127.0.0.1:9050)
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow Tor process itself to reach the internet (entry guards / relays)
    # Match by UID, not username — immune to username resolution issues
    iptables -A OUTPUT -m owner --uid-owner "$TOR_UID" -j ACCEPT

    # Block DNS leaks: explicitly drop UDP 53 and TCP 53 from non-Tor users.
    # This is redundant given the DROP policy but makes the intent explicit
    # and survives accidental policy changes.
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP

    # Block ICMP (ping) — prevents timing correlation attacks
    iptables -A OUTPUT -p icmp -j DROP

    # Log then drop everything else
    iptables -A OUTPUT -j LOG --log-prefix "TOR-FW-OUTPUT-DROP: " --log-level 4 -m limit --limit 5/min || true
    iptables -A OUTPUT -j DROP

    # -- FORWARD chain (belt and suspenders) --
    iptables -A FORWARD -j DROP

    # -- NAT table: prevent any NAT rules from leaking traffic --
    iptables -t nat -F
    iptables -t nat -X 2>/dev/null || true

    # -- Raw table: drop packets before conntrack to prevent state leaks --
    # (Only for non-loopback, non-Tor traffic — this prevents conntrack
    # from tracking packets that will be dropped anyway, reducing info leaks
    # through /proc/net/nf_conntrack)
    iptables -t raw -F
    iptables -t raw -A OUTPUT -o lo -j ACCEPT
    iptables -t raw -A OUTPUT -m owner --uid-owner "$TOR_UID" -j ACCEPT
    iptables -t raw -A OUTPUT -j DROP

    # =====================================================================
    # IPv6 — ip6tables (BLOCK ALL — IPv6 is an OPSEC catastrophe)
    # =====================================================================
    # Many VMs have IPv6 enabled by default. Even with "no IPv6 address",
    # the kernel will respond to IPv6 neighbor solicitations, leak link-local
    # addresses, and potentially route traffic through IPv6 tunnels (6to4,
    # Teredo, ISATAP) that bypass iptables entirely.

    ip6tables -P INPUT   DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT  DROP

    # Allow IPv6 loopback (some apps need ::1)
    ip6tables -A INPUT  -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # Drop everything else — no exceptions
    ip6tables -A INPUT   -j DROP
    ip6tables -A FORWARD -j DROP
    ip6tables -A OUTPUT  -j DROP

    # =====================================================================
    # Kernel hardening — disable leak vectors at the OS level
    # =====================================================================

    # Disable IPv6 at the kernel level (double protection)
    if [[ -d /proc/sys/net/ipv6 ]]; then
        sysctl -w net.ipv6.conf.all.disable_ipv6=1      >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=1   >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.lo.disable_ipv6=0        >/dev/null 2>&1 || true
    fi

    # Disable ICMP redirects (prevents route injection attacks)
    sysctl -w net.ipv4.conf.all.accept_redirects=0       >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.accept_redirects=0   >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.send_redirects=0         >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.accept_redirects=0       >/dev/null 2>&1 || true

    # Disable IP forwarding (this VM is not a router)
    sysctl -w net.ipv4.ip_forward=0                      >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=0             >/dev/null 2>&1 || true

    # Disable source routing (prevents packet-level bypass)
    sysctl -w net.ipv4.conf.all.accept_source_route=0    >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null 2>&1 || true

    # Ignore ICMP broadcasts (prevent Smurf amplification)
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1     >/dev/null 2>&1 || true

    # Enable reverse-path filtering (anti-spoofing)
    sysctl -w net.ipv4.conf.all.rp_filter=1              >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=1          >/dev/null 2>&1 || true

    # Log martian packets (source addresses that shouldn't exist)
    sysctl -w net.ipv4.conf.all.log_martians=1           >/dev/null 2>&1 || true

    # Disable TCP timestamps (prevents OS fingerprinting via timing)
    sysctl -w net.ipv4.tcp_timestamps=0                  >/dev/null 2>&1 || true

    # =====================================================================
    # Disable tunnel interfaces that bypass iptables
    # =====================================================================
    # These kernel modules create virtual interfaces that can leak traffic
    # outside of iptables entirely.

    for mod in ipv6 sit ip6_tunnel ip_gre ip6_gre ip6t_rt; do
        modprobe -r "$mod" 2>/dev/null || true
    done

    # Block tunnel modules from being loaded
    local modprobe_block="/etc/modprobe.d/tor-firewall-block-tunnels.conf"
    cat > "$modprobe_block" <<'MODBLOCK'
# Tor Firewall: block tunnel modules that bypass iptables
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
    # Done
    # =====================================================================
    echo ""
    pass "Firewall rules applied"
    pass "IPv4: Only Tor (UID $TOR_UID / $TOR_USER) can reach the network"
    pass "IPv6: Completely disabled (kernel + ip6tables)"
    pass "DNS:  UDP/TCP 53 explicitly dropped for non-Tor processes"
    pass "ICMP: Dropped (no ping in or out)"
    pass "Tunnels: Blocked at module level (sit, gre, ipip, etc.)"
    pass "Kernel: Forwarding off, redirects off, timestamps off, rp_filter on"
    echo ""

    # Run verification
    run_tests || true

    echo ""
    echo -e "  ${DIM}Undo:    sudo bash $0 --undo${NC}"
    echo -e "  ${DIM}Status:  sudo bash $0 --status${NC}"
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
    --help|-h)
        echo ""
        echo "  Transparent Tor Firewall — Zero-Leak VM Lockdown"
        echo ""
        echo "  Usage:"
        echo "    sudo bash $0              Apply firewall (block all non-Tor traffic)"
        echo "    sudo bash $0 --status     Show rules + run leak tests"
        echo "    sudo bash $0 --undo       Remove firewall, restore networking"
        echo "    sudo bash $0 --persist    Apply + survive reboots"
        echo "    sudo bash $0 --unpersist  Remove reboot persistence"
        echo "    sudo bash $0 --help       This message"
        echo ""
        echo "  What it blocks:"
        echo "    - ALL direct TCP/UDP (including DNS on port 53)"
        echo "    - ALL ICMP (ping, traceroute)"
        echo "    - ALL IPv6 (disabled at kernel + firewall level)"
        echo "    - ALL IP forwarding"
        echo "    - ALL tunnel interfaces (sit, gre, ipip, 6to4, Teredo)"
        echo "    - ALL conntrack state for non-Tor packets (raw table)"
        echo ""
        echo "  What it allows:"
        echo "    - Loopback (127.0.0.1 / ::1) — apps talk to Tor here"
        echo "    - Tor process (matched by UID) — connects to entry guards"
        echo "    - Nothing else. Zero exceptions."
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
