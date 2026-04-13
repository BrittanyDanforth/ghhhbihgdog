#!/usr/bin/env python3
"""
gs_common.py - Shared OPSEC library for the GhostSpiral v10 toolchain
=====================================================================
Centralises integrity logging, Tor verification, atomic I/O, secure
file permissions, CSPRNG helpers, and timing decorrelation so that
every companion script uses battle-tested, consistent implementations.

OPSEC design principles
-----------------------
- All network I/O goes through Tor or aborts.
- Every sensitive file is written 0600 (owner-only).
- Integrity log uses SHA-256 hash-chain for tamper evidence.
- CSPRNG (secrets module) for all security-critical randomness.
- Timing jitter between operations to frustrate traffic analysis.
- Proxy format validated before first use.
- Signal handlers for graceful shutdown on SIGINT/SIGTERM.
"""
from __future__ import annotations
import hashlib, json, os, re, secrets, signal, sys, time
from decimal import Decimal
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from tenacity import retry, wait_exponential_jitter, stop_after_attempt

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

VERSION = "10.5"
CHECK_TOR_URL = "https://check.torproject.org/api/ip"
INTEGRITY_LOG = Path("integrity_chain.log")
SOCKS_RE = re.compile(r"^socks5h://[^\s:]+:\d{1,5}$")
# CRITICAL: only socks5h:// is accepted. Plain socks5:// leaks DNS locally
# because the requests library resolves hostnames BEFORE sending through
# the SOCKS proxy. With socks5h://, DNS resolution happens at the proxy.

# ---------------------------------------------------------------------------
#  Secure randomness
# ---------------------------------------------------------------------------

def secure_hex(n_bytes: int) -> str:
    """Return n_bytes of cryptographically random hex (no '0x' prefix)."""
    return secrets.token_hex(n_bytes)


def secure_delay(lo: float = 2.0, hi: float = 8.0) -> None:
    """Sleep a CSPRNG-uniform duration to decorrelate timing."""
    delay = lo + (secrets.randbelow(int((hi - lo) * 1000)) / 1000.0)
    time.sleep(delay)

# ---------------------------------------------------------------------------
#  Integrity hash-chain logger
# ---------------------------------------------------------------------------

def integrity_log(stage: str, msg: str, log_path: Path = INTEGRITY_LOG) -> str:
    """Append a SHA-256-chained line to the integrity log. Returns the hash.

    Timestamp is coarsened to 600-second (10-min) buckets to reduce the
    correlation window between the log and blockchain/network timestamps.
    An attacker with the log can only narrow the operation to a 10-min window
    instead of the exact second.

    BUG 32 FIX: The previous hash extraction was brittle — if the log file
    ended with a blank line or a corrupted line, the split would fail or
    extract the wrong value, breaking the hash chain silently. Now falls
    back to the genesis hash on any parse error.
    """
    prev = "0" * 64
    if log_path.exists():
        try:
            text = log_path.read_text()
            lines = [l for l in text.splitlines() if l.strip()]
            if lines:
                parts = lines[-1].split(" | ", 1)
                candidate = parts[0].strip()
                if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                    prev = candidate
        except (OSError, UnicodeDecodeError):
            pass
    ts = int(time.time()) // 600 * 600  # coarsen to 10-min buckets
    line = f"{ts}|{VERSION}|{stage}|{msg}"
    h = hashlib.sha256((prev + line).encode()).hexdigest()
    with log_path.open("a") as f:
        f.write(f"{h} | {line}\n")
    secure_file_perms(log_path)
    return h

# ---------------------------------------------------------------------------
#  File security
# ---------------------------------------------------------------------------

def secure_file_perms(path: Path, mode: int = 0o600) -> None:
    """Set file to owner-read/write only."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def atomic_write_json(obj, path: Path, perms: int = 0o600) -> None:
    """Write JSON atomically: tmp -> fsync -> rename. Sets secure perms.

    BUG 35 FIX: The old verify-by-reload silently swallowed parse errors
    (truncated JSON from disk-full, etc). If the reload fails, that means
    the file on disk is corrupt — we must crash loudly, not continue.
    Also fsync the parent directory to ensure the rename is durable.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    secure_file_perms(tmp, perms)
    os.replace(tmp, path)
    try:
        with open(path) as f:
            json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        sys.exit(f"[!] CRITICAL: Atomic write to {path} produced corrupt JSON: {e}")
    # fsync parent dir to make the rename durable across power loss
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def atomic_write_text(data: str, path: Path, perms: int = 0o600) -> None:
    """Write text atomically: tmp -> fsync -> rename. Sets secure perms."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    secure_file_perms(tmp, perms)
    os.replace(tmp, path)

# ---------------------------------------------------------------------------
#  Proxy validation
# ---------------------------------------------------------------------------

def validate_proxy(proxy_url: str) -> Dict[str, str]:
    """Validate and return a proxy dict, or abort if format is wrong.

    ONLY socks5h:// is accepted. Plain socks5:// resolves DNS locally,
    leaking every destination hostname to the ISP's DNS resolver.
    """
    if proxy_url.startswith("socks5://") and not proxy_url.startswith("socks5h://"):
        sys.exit(
            f"[!] CRITICAL: socks5:// leaks DNS locally!\n"
            f"    Use socks5h:// so DNS resolves through the proxy.\n"
            f"    Change: {proxy_url} -> {proxy_url.replace('socks5://', 'socks5h://')}"
        )
    if not SOCKS_RE.match(proxy_url):
        sys.exit(
            f"[!] Invalid proxy format: {proxy_url}\n"
            f"    Expected: socks5h://host:port  (NOT socks5://)"
        )
    return {"http": proxy_url, "https": proxy_url}

# ---------------------------------------------------------------------------
#  Tor verification
# ---------------------------------------------------------------------------

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=3, max=20))
def verify_tor(proxy: Dict[str, str]) -> None:
    """Verify we are exiting through Tor. Aborts on failure."""
    r = requests.get(CHECK_TOR_URL, timeout=15, proxies=proxy)
    r.raise_for_status()
    data = r.json()
    if not data.get("IsTor"):
        integrity_log("tor", "LEAK_DETECTED")
        sys.exit("[!] Tor leak detected - traffic NOT exiting via Tor. Aborting.")
    integrity_log("tor", "verified_ok")


def tor_recheck(proxy: Dict[str, str], stage: str = "recheck") -> None:
    """Re-verify Tor mid-operation. Logs but doesn't retry as aggressively."""
    try:
        r = requests.get(CHECK_TOR_URL, timeout=10, proxies=proxy)
        r.raise_for_status()
        if not r.json().get("IsTor"):
            integrity_log("tor", f"LEAK_mid_{stage}")
            sys.exit(f"[!] Tor leak detected during {stage} - aborting.")
    except requests.RequestException:
        integrity_log("tor", f"recheck_fail_{stage}")
        sys.exit(f"[!] Cannot verify Tor during {stage} - aborting for safety.")

# ---------------------------------------------------------------------------
#  NEWNYM (Tor circuit rotation)
# ---------------------------------------------------------------------------

_NEWNYM_CONSECUTIVE_FAILURES = 0
_NEWNYM_MAX_FAILURES = 3


def newnym(ctrl: str = "/var/run/tor/control", required: bool = False) -> bool:
    """Request new Tor circuit. Aborts after consecutive failures if required.

    If NEWNYM fails _NEWNYM_MAX_FAILURES times in a row and required=True,
    the process aborts to prevent all operations going over one circuit.

    BUG 34 FIX: The old code only tried the Unix socket file at
    /var/run/tor/control. Most Tor installations (especially on non-Debian
    or when installed via Tor Browser) use TCP control port 9051 instead.
    Now tries socket file first, then falls back to TCP port 9051.
    """
    global _NEWNYM_CONSECUTIVE_FAILURES
    try:
        from stem import Signal as StemSignal
        from stem.control import Controller

        c = None
        try:
            if os.path.exists(ctrl):
                c = Controller.from_socket_file(ctrl)
            else:
                c = Controller.from_port(port=9051)
            c.authenticate()
            c.signal(StemSignal.NEWNYM)
        finally:
            if c is not None:
                c.close()
        time.sleep(5)
        _NEWNYM_CONSECUTIVE_FAILURES = 0
        return True
    except Exception as e:
        _NEWNYM_CONSECUTIVE_FAILURES += 1
        integrity_log("tor", f"NEWNYM_fail:{_NEWNYM_CONSECUTIVE_FAILURES}:{str(e)[:40]}")
        if _NEWNYM_CONSECUTIVE_FAILURES >= _NEWNYM_MAX_FAILURES:
            msg = (f"[!] NEWNYM failed {_NEWNYM_MAX_FAILURES} consecutive times. "
                   f"Tor circuit rotation is NOT working.")
            if required:
                sys.exit(msg + " Aborting for OPSEC safety.")
            else:
                print(f"  {msg}")
        return False

# ---------------------------------------------------------------------------
#  Retry-wrapped HTTP
# ---------------------------------------------------------------------------

def safe_get(url: str, proxies: Dict[str, str] = None) -> dict:
    """GET with retry. Aborts if proxies is None (clearnet leak prevention).

    BUG 33 FIX: The proxy-None check must happen BEFORE the @retry decorator,
    because tenacity retries SystemExit (it inherits from BaseException), so
    the abort would be retried 4 times before propagating. Check first, then
    call the retry-wrapped inner function.
    """
    if proxies is None:
        sys.exit("[!] safe_get called without proxies — clearnet leak. Aborting.")
    return _safe_get_inner(url, proxies)


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30))
def _safe_get_inner(url: str, proxies: Dict[str, str]) -> dict:
    r = requests.get(url, timeout=20, proxies=proxies)
    r.raise_for_status()
    return r.json()


def safe_post(url: str, payload: dict, proxies: Dict[str, str] = None) -> dict:
    """POST with retry. Aborts if proxies is None (clearnet leak prevention)."""
    if proxies is None:
        sys.exit("[!] safe_post called without proxies — clearnet leak. Aborting.")
    return _safe_post_inner(url, payload, proxies)


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30))
def _safe_post_inner(url: str, payload: dict, proxies: Dict[str, str]) -> dict:
    r = requests.post(url, json=payload, timeout=25, proxies=proxies)
    r.raise_for_status()
    return r.json()

# ---------------------------------------------------------------------------
#  RPC connection (monero-wallet-rpc)
# ---------------------------------------------------------------------------

_LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}


class MoneroRPC:
    """Wrapper around monero-python that exposes both high-level Wallet
    methods and raw JSON-RPC calls via the backend.

    OPSEC: monero-python's JSONRPCWallet uses requests internally but does
    NOT support SOCKS proxy configuration. Connections to non-localhost
    hosts go clearnet, leaking the operator's IP to the Monero node.
    We enforce localhost-only, or patch the session with proxy support.
    """

    def __init__(self, url: str, proxy_url: Optional[str] = None):
        from monero.wallet import Wallet as XMRWallet
        from monero.backends.jsonrpc import JSONRPCWallet
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 18083

        if host.lower() not in _LOCALHOST_NAMES:
            if not proxy_url:
                sys.exit(
                    f"[!] RPC endpoint {host}:{port} is NOT localhost.\n"
                    f"    monero-python's JSONRPCWallet has no proxy support.\n"
                    f"    Connection would be clearnet, leaking your IP to the node.\n"
                    f"    Either: (a) use 127.0.0.1 with a local RPC, or\n"
                    f"            (b) tunnel the RPC through Tor externally (socat/ssh)."
                )
            integrity_log("rpc", f"WARN:non_local_rpc:{host}:{port}:proxy_patched")

        self._backend = JSONRPCWallet(host=host, port=port)

        if proxy_url and host.lower() not in _LOCALHOST_NAMES:
            proxies = {"http": proxy_url, "https": proxy_url}
            if hasattr(self._backend, '_session'):
                self._backend._session.proxies.update(proxies)

        self._wallet = XMRWallet(self._backend)

    @property
    def accounts(self):
        return self._wallet.accounts

    def new_account(self, **kwargs):
        return self._wallet.new_account(**kwargs)

    def raw_request(self, method: str, params: dict) -> dict:
        """Send a raw JSON-RPC request to monero-wallet-rpc."""
        return self._backend.raw_request(method, params)

    def new_subaddress(self, account_index: int = 0, label: str = "") -> str:
        """Create a new subaddress and return its string address.
        Uses monero-python's Account.new_address() which returns (Address, index)."""
        acct = self._wallet.accounts[account_index]
        addr, _idx = acct.new_address(label=label)
        return str(addr)

    def new_subaddress_indexed(self, account_index: int = 0, label: str = "") -> tuple:
        """Create a new subaddress and return (address_str, subaddress_index)."""
        acct = self._wallet.accounts[account_index]
        addr, idx = acct.new_address(label=label)
        return str(addr), idx

    def get_subaddress_balance(self, account_index: int = 0,
                               address_index: int = 0) -> tuple:
        """Return (total, unlocked) balance for a specific subaddress in atomic units."""
        res = self.raw_request("get_balance", {
            "account_index": account_index,
            "address_indices": [address_index],
        })
        per_sub = res.get("per_subaddress", [])
        if per_sub:
            entry = per_sub[0]
            return entry.get("balance", 0), entry.get("unlocked_balance", 0)
        return 0, 0


def connect_rpc(url: str, proxy_url: Optional[str] = None) -> MoneroRPC:
    """Connect to monero-wallet-rpc extracting host and port from URL.

    If the RPC host is non-localhost, proxy_url is required or the
    connection is rejected to prevent clearnet IP leaks.
    """
    return MoneroRPC(url, proxy_url=proxy_url)

# ---------------------------------------------------------------------------
#  Resource sentinel
# ---------------------------------------------------------------------------

def resource_check(min_disk_gb: float = 2.0, max_ram_pct: float = 90.0) -> bool:
    """Return True if resources are OK. False if system is stressed."""
    import psutil
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(".")
    return mem.percent < max_ram_pct and disk.free > min_disk_gb * 1024 ** 3


def require_resources(min_disk_gb: float = 2.0, max_ram_pct: float = 90.0) -> None:
    """Abort if resources are below threshold."""
    if not resource_check(min_disk_gb, max_ram_pct):
        sys.exit(f"[!] Resources low (disk<{min_disk_gb}GB or RAM>{max_ram_pct}%) - aborting.")

# ---------------------------------------------------------------------------
#  Signal handling for graceful shutdown
# ---------------------------------------------------------------------------

_SHUTDOWN_REQUESTED = False


def _shutdown_handler(signum, frame):
    global _SHUTDOWN_REQUESTED
    _SHUTDOWN_REQUESTED = True
    integrity_log("signal", f"shutdown_requested_sig={signum}")
    print(f"\n[!] Shutdown signal received ({signum}). Finishing current operation...")


def install_signal_handlers():
    """Install handlers for SIGINT and SIGTERM for graceful shutdown."""
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)


def shutdown_requested() -> bool:
    return _SHUTDOWN_REQUESTED

# ---------------------------------------------------------------------------
#  Sensitive data scrubbing
# ---------------------------------------------------------------------------

def scrub_address(addr: str, visible: int = 8) -> str:
    """Truncate an address for safe terminal display.

    BUG 36 FIX: For Monero addresses (95 chars), 8+8=16 visible chars is
    already enough to uniquely identify a subaddress on-chain. Reduce to
    6 visible chars for addresses over 40 chars (Monero), and ensure we
    never return the full address even for short inputs.
    """
    if not addr:
        return "<empty>"
    if len(addr) > 40:
        visible = min(visible, 6)
    if len(addr) <= visible * 2 + 3:
        return f"{addr[:4]}...{addr[-4:]}" if len(addr) > 11 else "****"
    return f"{addr[:visible]}...{addr[-visible:]}"
