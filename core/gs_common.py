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
    if hi <= lo:
        time.sleep(max(lo, 0))
        return
    delay = lo + (secrets.randbelow(int((hi - lo) * 1000)) / 1000.0)
    time.sleep(delay)

# ---------------------------------------------------------------------------
#  Integrity hash-chain logger
# ---------------------------------------------------------------------------

def integrity_log(stage: str, msg: str, log_path: Path = INTEGRITY_LOG) -> str:
    """Append a SHA-256-chained line to the integrity log. Returns the hash.

    Timestamp is coarsened to 600-second (10-min) buckets to reduce the
    correlation window between the log and blockchain/network timestamps.
    """
    import fcntl
    stage = stage.replace("\n", " ").replace("\r", " ").replace("|", "_")[:64]
    msg = msg.replace("\n", " ").replace("\r", " ").replace("|", "_")[:200]

    lock_path = log_path.with_suffix(log_path.suffix + ".lock")
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
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
            ts = int(time.time()) // 600 * 600
            line = f"{ts}|{stage}|{msg}"
            h = hashlib.sha256((prev + line).encode()).hexdigest()
            with log_path.open("a") as f:
                f.write(f"{h} | {line}\n")
                f.flush()
                os.fsync(f.fileno())
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
    secure_file_perms(log_path)
    return h

# ---------------------------------------------------------------------------
#  File security
# ---------------------------------------------------------------------------

def lock_memory() -> bool:
    """Call mlockall() to prevent Python heap from being swapped to disk.

    Without this, secrets held in Python str/bytes objects (wallet passwords,
    spend keys) can be written to the swap partition and recovered forensically
    from a seized machine. Requires CAP_IPC_LOCK or root on Linux.
    Returns True if successful, False otherwise (non-fatal).

    NOTE: Even with mlockall, Python's immutable strings and garbage collector
    cannot guarantee when secret data is freed from memory. The only reliable
    mitigation for at-rest exposure is full-disk encryption (LUKS/dm-crypt)
    so that swap contents are encrypted on disk.
    """
    try:
        import ctypes
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        rc = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        if rc == 0:
            integrity_log("opsec", "mlockall_ok")
            return True
        errno = ctypes.get_errno()
        integrity_log("opsec", f"mlockall_fail:errno={errno}")
        return False
    except (OSError, AttributeError):
        integrity_log("opsec", "mlockall_unavailable")
        return False


def secure_file_perms(path: Path, mode: int = 0o600) -> None:
    """Set file to owner-read/write only."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _json_safe_default(o):
    """JSON serializer that handles Decimal but rejects dangerous types.

    BUG 75 FIX: The old `default=str` silently converted Path objects to
    strings like 'PosixPath(/home/user/...)' leaking filesystem paths.
    This only allows Decimal (common in Monero amounts) and rejects
    everything else loudly.
    """
    if isinstance(o, Decimal):
        return str(o)
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable "
                    f"(and would leak data if converted via str())")


def atomic_write_json(obj, path: Path, perms: int = 0o600) -> None:
    """Write JSON atomically: tmp -> fsync -> rename. Sets secure perms.

    BUG 35 FIX: The old verify-by-reload silently swallowed parse errors
    (truncated JSON from disk-full, etc). If the reload fails, that means
    the file on disk is corrupt — we must crash loudly, not continue.
    Also fsync the parent directory to ensure the rename is durable.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=_json_safe_default)
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
    # BUG 63 FIX: Case-insensitive check to prevent SOCKS5:// bypass
    proxy_lower = proxy_url.lower()
    if proxy_lower.startswith("socks5://") and not proxy_lower.startswith("socks5h://"):
        sys.exit(
            f"[!] CRITICAL: socks5:// leaks DNS locally!\n"
            f"    Use socks5h:// so DNS resolves through the proxy.\n"
            f"    Change: {proxy_url} -> {proxy_url.replace('socks5://', 'socks5h://')}"
        )
    if not SOCKS_RE.match(proxy_lower):
        sys.exit(
            f"[!] Invalid proxy format: {proxy_url}\n"
            f"    Expected: socks5h://host:port  (NOT socks5://)"
        )
    # Extract and validate port range
    port_str = proxy_lower.rsplit(":", 1)[-1]
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            sys.exit(f"[!] Invalid proxy port: {port}. Must be 1-65535.")
    except ValueError:
        sys.exit(f"[!] Invalid proxy port: {port_str}")
    return {"http": proxy_url, "https": proxy_url}

# ---------------------------------------------------------------------------
#  Tor verification
# ---------------------------------------------------------------------------

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=3, max=20))
def verify_tor(proxy: Dict[str, str]) -> None:
    """Verify we are exiting through Tor. Aborts on failure."""
    r = requests.get(CHECK_TOR_URL, timeout=15, proxies=proxy,
                     headers=_BROWSER_HEADERS)
    r.raise_for_status()
    data = r.json()
    if not data.get("IsTor"):
        integrity_log("tor", "LEAK_DETECTED")
        sys.exit("[!] Tor leak detected - traffic NOT exiting via Tor. Aborting.")
    integrity_log("tor", "verified_ok")


def tor_recheck(proxy: Dict[str, str], stage: str = "recheck") -> None:
    """Re-verify Tor mid-operation. Logs but doesn't retry as aggressively."""
    try:
        r = requests.get(CHECK_TOR_URL, timeout=10, proxies=proxy,
                         headers=_BROWSER_HEADERS)
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
_NEWNYM_LOCK = _threading.Lock()


def newnym(ctrl: str = "/var/run/tor/control", required: bool = False) -> bool:
    """Request new Tor circuit. Aborts after consecutive failures if required.

    If NEWNYM fails _NEWNYM_MAX_FAILURES times in a row and required=True,
    the process aborts to prevent all operations going over one circuit.

    BUG 34 FIX: The old code only tried the Unix socket file at
    /var/run/tor/control. Typical setups: Debian/system ``tor`` exposes a
    socket and/or TCP control **9051**; **Tor Browser**'s bundled tor uses
    SOCKS **9150** and control **9151** (not 9051). Order: socket if present,
    else TCP **9051**, else TCP **9151**.
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
                last_err: Optional[BaseException] = None
                for port in (9051, 9151):
                    try:
                        c = Controller.from_port(port=port)
                        break
                    except Exception as e:
                        last_err = e
                        c = None
                if c is None and last_err is not None:
                    raise last_err
            tor_pw = os.environ.get("TOR_CONTROL_PASSWORD", "")
            if tor_pw:
                c.authenticate(password=tor_pw)
            else:
                c.authenticate()
            c.signal(StemSignal.NEWNYM)
        finally:
            if c is not None:
                c.close()
        # Jittered wait for circuit establishment (fixed 5s was a timing fingerprint)
        time.sleep(3 + secrets.randbelow(5000) / 1000.0)
        with _NEWNYM_LOCK:
            _NEWNYM_CONSECUTIVE_FAILURES = 0
        return True
    except Exception as e:
        with _NEWNYM_LOCK:
            _NEWNYM_CONSECUTIVE_FAILURES += 1
            fail_count = _NEWNYM_CONSECUTIVE_FAILURES
        integrity_log("tor", f"NEWNYM_fail:{fail_count}:{str(e)[:40]}")
        if fail_count >= _NEWNYM_MAX_FAILURES:
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


def _newnym_between_retries(retry_state):
    """Called by tenacity before each retry sleep to rotate Tor circuit.
    BUG 74 FIX: Without this, all retries hit the same blocked exit node."""
    newnym()


_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"

_BROWSER_HEADERS = {
    "User-Agent": _BROWSER_UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30),
       before_sleep=_newnym_between_retries)
def _safe_get_inner(url: str, proxies: Dict[str, str]) -> dict:
    r = requests.get(url, timeout=20, proxies=proxies,
                     headers=_BROWSER_HEADERS)
    r.raise_for_status()
    return r.json()


def safe_post(url: str, payload: dict, proxies: Dict[str, str] = None,
              headers: Dict[str, str] = None) -> dict:
    """POST with retry. Aborts if proxies is None (clearnet leak prevention)."""
    if proxies is None:
        sys.exit("[!] safe_post called without proxies — clearnet leak. Aborting.")
    return _safe_post_inner(url, payload, proxies, headers or {})


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30),
       before_sleep=_newnym_between_retries)
def _safe_post_inner(url: str, payload: dict, proxies: Dict[str, str],
                     headers: Dict[str, str] = None) -> dict:
    h = dict(_BROWSER_HEADERS)
    if headers:
        h.update(headers)
    r = requests.post(url, json=payload, timeout=25, proxies=proxies, headers=h)
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
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            sys.exit(
                f"[!] Invalid RPC URL: {url}\n"
                f"    Expected format: http://host:port (e.g., http://127.0.0.1:18083)"
            )

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

        # BUG 60 FIX: Pass proxy_url directly to JSONRPCWallet constructor
        # (monero-python natively supports it). ALSO patch self.proxies
        # because raw_request() passes proxies=self.proxies to session.post(),
        # which overrides session.proxies. The old BUG 56 fix only patched
        # session.proxies but raw_request bypasses it.
        # Also extract auth credentials from URL if present.
        protocol = parsed.scheme or "http"
        user = parsed.username or ""
        password = parsed.password or ""

        backend_kwargs = {
            "host": host, "port": port, "protocol": protocol,
        }
        if user:
            backend_kwargs["user"] = user
        if password:
            backend_kwargs["password"] = password
        if proxy_url and host.lower() not in _LOCALHOST_NAMES:
            backend_kwargs["proxy_url"] = proxy_url

        try:
            self._backend = JSONRPCWallet(**backend_kwargs)
        except TypeError:
            if "proxy_url" in backend_kwargs and host.lower() not in _LOCALHOST_NAMES:
                sys.exit(
                    f"[!] monero-python does not support proxy_url for {host}:{port}.\n"
                    f"    Cannot safely connect to a non-localhost RPC without proxy.\n"
                    f"    Either: (a) use 127.0.0.1 with a local wallet-rpc, or\n"
                    f"            (b) upgrade monero-python to a version that supports proxy_url."
                )
            fallback_kwargs = {k: v for k, v in backend_kwargs.items()
                               if k != "proxy_url"}
            self._backend = JSONRPCWallet(**fallback_kwargs)

        if proxy_url and host.lower() not in _LOCALHOST_NAMES:
            proxy_dict = {"http": proxy_url, "https": proxy_url}
            # Patch self.proxies (used by raw_request's session.post call)
            if hasattr(self._backend, 'proxies'):
                self._backend.proxies = proxy_dict
            # Also patch session.proxies as belt-and-suspenders
            for attr in ('session', '_session'):
                if hasattr(self._backend, attr):
                    getattr(self._backend, attr).proxies.update(proxy_dict)
                    break

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
    try:
        import psutil
    except ImportError:
        return True  # Can't check — assume OK rather than crashing mid-operation
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

import threading as _threading

_SHUTDOWN_EVENT = _threading.Event()


def _shutdown_handler(signum, frame):
    _SHUTDOWN_EVENT.set()
    integrity_log("signal", f"shutdown_requested_sig={signum}")
    print(f"\n[!] Shutdown signal received ({signum}). Finishing current operation...")


def install_signal_handlers():
    """Install handlers for SIGINT and SIGTERM for graceful shutdown."""
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)


def shutdown_requested() -> bool:
    return _SHUTDOWN_EVENT.is_set()

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
