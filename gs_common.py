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
SOCKS_RE = re.compile(r"^socks5h?://[^\s:]+:\d{1,5}$")

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
    """Append a SHA-256-chained line to the integrity log. Returns the hash."""
    prev = "0" * 64
    if log_path.exists():
        text = log_path.read_text()
        lines = text.splitlines()
        if lines:
            prev = lines[-1].split(" | ")[0].strip()
    ts = int(time.time())
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
    """Write JSON atomically: tmp -> fsync -> rename. Sets secure perms."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    secure_file_perms(tmp, perms)
    os.replace(tmp, path)
    with open(path) as f:
        json.load(f)


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
    """Validate and return a proxy dict, or abort if format is wrong."""
    if not SOCKS_RE.match(proxy_url):
        sys.exit(
            f"[!] Invalid proxy format: {proxy_url}\n"
            f"    Expected: socks5h://host:port"
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
    integrity_log("tor", f"verified_exit_ip={data.get('IP', 'unknown')[:16]}")


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

def newnym(ctrl: str = "/var/run/tor/control") -> bool:
    """Request new Tor circuit. Returns True on success."""
    try:
        from stem import Signal as StemSignal
        from stem.control import Controller
        with Controller.from_socket_file(ctrl) as c:
            c.authenticate()
            c.signal(StemSignal.NEWNYM)
        time.sleep(5)
        return True
    except Exception as e:
        integrity_log("tor", f"NEWNYM_fail:{str(e)[:60]}")
        return False

# ---------------------------------------------------------------------------
#  Retry-wrapped HTTP
# ---------------------------------------------------------------------------

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30))
def safe_get(url: str, proxies: Optional[Dict] = None) -> dict:
    r = requests.get(url, timeout=20, proxies=proxies)
    r.raise_for_status()
    return r.json()


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30))
def safe_post(url: str, payload: dict, proxies: Optional[Dict] = None) -> dict:
    r = requests.post(url, json=payload, timeout=25, proxies=proxies)
    r.raise_for_status()
    return r.json()

# ---------------------------------------------------------------------------
#  RPC connection (monero-wallet-rpc)
# ---------------------------------------------------------------------------

def connect_rpc(url: str):
    """Connect to monero-wallet-rpc extracting host and port from URL."""
    from monero.wallet import Wallet as XMRWallet
    from monero.backends.jsonrpc import JSONRPCWallet
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 18083
    return XMRWallet(JSONRPCWallet(host=host, port=port))

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
    """Truncate an address for safe terminal display."""
    if len(addr) <= visible * 2:
        return addr
    return f"{addr[:visible]}...{addr[-visible:]}"
