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
import hashlib, json, os, re, secrets, shutil, signal, stat as stat_module, sys, time
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
    """
    prev = "0" * 64
    if log_path.exists():
        text = log_path.read_text()
        lines = text.splitlines()
        if lines:
            prev = lines[-1].split(" | ")[0].strip()
    ts = int(time.time()) // 600 * 600  # coarsen to 10-min buckets
    line = f"{ts}|{VERSION}|{stage}|{msg}"
    h = hashlib.sha256((prev + line).encode()).hexdigest()
    # O_CREAT with an explicit 0600, NOT open("a") + chmod afterwards. The plain
    # append-open creates the file 0644 under the default umask, so the very
    # first log line of a run -- and this file records the wallet label, exact
    # fan-out amounts, the DAG plan and a stage timeline -- was briefly
    # world-readable, and stayed 0644 if the process died before the next call.
    # secure_write_bytes cannot be used here: it passes O_TRUNC, which would
    # destroy the hash chain this function exists to maintain.
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "a", closefd=True) as f:
            fd = -1
            f.write(f"{h} | {line}\n")
    finally:
        if fd >= 0:
            os.close(fd)
    # Narrow a log that already existed with wider perms (O_CREAT leaves an
    # existing file's mode untouched).
    secure_file_perms(log_path)
    return h

# ---------------------------------------------------------------------------
#  File security
# ---------------------------------------------------------------------------

def secure_file_perms(path: Path, mode: int = 0o600) -> None:
    """Set file to owner-read/write only.

    Prefer secure_write_bytes/secure_write_text for NEW files: chmod-after-write
    leaves a window (and, on a crash, a permanent state) where the file is
    world-readable. Use this only to fix up a file someone else created.
    """
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def secure_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create a file with owner-only perms FROM THE START, then write it.

    The `write_bytes(...)` + `secure_file_perms(...)` sequence this replaces
    creates the file at 0644 under the default umask 022 and only narrows it
    afterwards. That is not merely a short race: if the process is killed
    between the two calls the file stays 0644 PERMANENTLY -- verified, and it
    applied to tx_*.unsigned and to tx_*.signed, i.e. a fully signed,
    relayable transaction left world-readable on disk.

    os.open() applies the mode at creation time, atomically. 0o600 has no
    group/other bits, so a umask cannot widen it (a umask can only clear bits),
    which makes this umask-safe as well -- confirmed 0o600 under umask 022.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    # A pre-existing file keeps its old mode through O_CREAT, so narrow it too.
    secure_file_perms(path, mode)


def secure_write_text(path: Path, data: str, mode: int = 0o600) -> None:
    """Text wrapper over secure_write_bytes -- see there for why this exists."""
    secure_write_bytes(path, data.encode(), mode)


def secure_delete_tree(path: Path) -> bool:
    """Overwrite every file in a directory tree, then remove the tree.

    The canonical "securely delete a directory" primitive. Cleanup code across
    this toolchain kept reaching for shutil.rmtree, which only unlinks: a prior
    run's tx_staging/ holds fully signed, RELAYABLE transactions, the unsigned
    tx sets, and a manifest with unscrubbed destinations and amounts. rmtree
    leaves every byte of that recoverable, which defeats the point of wiping it
    at all.

    Symlinks inside the tree are unlinked, never followed (secure_delete_file
    enforces that), so a symlink planted in a staging dir cannot redirect the
    overwrite onto an unrelated file.

    Returns True only if every file was securely erased AND the tree was
    removed, so callers can report honestly instead of assuming success.
    """
    path = Path(path)
    if not path.is_dir():
        return False
    ok = True
    # Deepest-first so directories are empty by the time we unlink them.
    for entry in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if entry.is_symlink() or entry.is_file():
            ok = secure_delete_file(entry) and ok
    try:
        shutil.rmtree(path)
        return ok
    except OSError:
        shutil.rmtree(path, ignore_errors=True)
        return False


def check_daemon_relay_egress(daemon_url: str,
                              proxies: Optional[Dict[str, str]] = None) -> dict:
    """Inspect where a monerod would actually BROADCAST a transaction.

    This closes the last hop nobody was checking. Every request this toolchain
    makes can be perfectly Tor-proxied and the transaction can still be handed
    to a daemon that relays it to clearnet peers -- which tells those peers
    which IP originated the transaction, defeating the whole pipeline. The code
    previously only PRINTED "verify it yourself", which is not verification.

    monerod exposes no RPC reporting its --tx-proxy setting (confirmed against
    0.18.3.1: get_info has no proxy field, and get_net_stats/get_limit are not
    even available on a restricted RPC). What IS observable is the peer list
    from get_connections: a relay peer reached over Tor/I2P has a .onion/.i2p
    address, while a clearnet peer shows a raw IP. That is a direct observation
    of where traffic leaves, not an inference from configuration.

    Returns a verdict dict -- deliberately NOT a bare bool, because "cannot
    tell" is a distinct and honest outcome from "clearnet":
      verdict: "tor" | "clearnet" | "offline" | "unknown"
      onion/clear: peer counts;  detail: human-readable reason
    Never raises: a failed probe reports "unknown" rather than blocking a
    broadcast on a diagnostic.
    """
    out = {"verdict": "unknown", "onion": 0, "clear": 0, "detail": ""}
    parsed = urlparse(daemon_url)
    host = (parsed.hostname or "127.0.0.1").lower()
    use_proxies = None
    if host not in _LOCALHOST_NAMES:
        if not proxies:
            out["detail"] = "remote daemon and no proxy available to query it"
            return out
        use_proxies = proxies

    endpoint = daemon_url.rstrip("/") + "/json_rpc"
    try:
        info = requests.post(
            endpoint, json={"jsonrpc": "2.0", "id": "0", "method": "get_info"},
            timeout=20, proxies=use_proxies).json().get("result") or {}
        if info.get("offline"):
            out["verdict"] = "offline"
            out["detail"] = "daemon is running --offline; it cannot relay at all"
            return out

        conns = requests.post(
            endpoint, json={"jsonrpc": "2.0", "id": "0", "method": "get_connections"},
            timeout=20, proxies=use_proxies).json().get("result") or {}
        peers = conns.get("connections")
        if peers is None:
            out["detail"] = ("daemon did not return a peer list (restricted RPC?) -- "
                             "cannot observe where it relays")
            return out
        for c in peers:
            addr = str(c.get("address") or c.get("host") or "").lower()
            if ".onion" in addr or ".i2p" in addr:
                out["onion"] += 1
            elif addr:
                out["clear"] += 1
        if out["onion"] and not out["clear"]:
            out["verdict"] = "tor"
            out["detail"] = f"all {out['onion']} relay peer(s) are .onion/.i2p"
        elif out["clear"]:
            out["verdict"] = "clearnet"
            out["detail"] = (f"{out['clear']} clearnet peer(s) vs {out['onion']} "
                             f"anonymous -- the tx would be relayed to raw IPs")
        else:
            out["detail"] = "daemon has no peer connections yet; nothing to observe"
    except Exception as e:
        out["detail"] = f"probe failed: {str(e)[:60]}"
    return out


def secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """Create a directory owner-only, including any parents.

    plain mkdir() produces 0755 -- world-readable and traversable. The FILES
    inside are 0600 so their contents stay private, but the directory listing
    itself is a real metadata leak for this toolchain: any local user could
    enumerate a staging dir and learn how many transactions were signed, when,
    and hence that a Monero cold-signing operation ran at all. Unlinkability is
    the entire point here, so that is not acceptable even with safe file modes.

    Two details this handles that a bare mkdir(mode=...) does not:
      * With parents=True, Python applies `mode` only to the FINAL directory;
        intermediate parents are created with the default 0777 & ~umask. Each
        level is therefore chmod'ed explicitly.
      * exist_ok=True silently keeps a pre-existing directory's mode, so an
        already-0755 staging dir would stay 0755. It is narrowed too.
    """
    path = Path(path)
    created = []
    for parent in list(path.parents)[::-1]:
        if not parent.exists():
            created.append(parent)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    for d in created + [path]:
        try:
            if d.is_dir():
                os.chmod(d, mode)
        except OSError:
            pass


def atomic_write_json(obj, path: Path, perms: int = 0o600) -> None:
    """Write JSON atomically: tmp -> fsync -> rename. Sets secure perms.

    On ANY failure the partial .tmp is securely erased before the exception
    propagates. Without that, a Ctrl-C between the write and the rename left
    e.g. 'thor_pairs_batch.json.tmp' on disk holding the deposit address and
    memo in plaintext -- and paranoia's wipe pattern 'thor_pairs_*.json' does
    NOT match a '.json.tmp' suffix, so nothing ever cleaned it up. These
    scripts install SIGINT handlers, so an interrupted write is a realistic
    path, not a theoretical one. BaseException (not Exception) because
    KeyboardInterrupt is exactly the case that leaked.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        # Created 0600 up front, not chmod'ed afterwards: the tmp holds the
        # same plaintext as the final file, so a world-readable window (or a
        # crash leaving it 0644 forever) exposes exactly what the rename was
        # meant to protect.
        secure_write_bytes(tmp, json.dumps(obj, indent=2).encode(), perms)
        os.replace(tmp, path)
    except BaseException:
        secure_delete_file(tmp)
        raise
    with open(path) as f:
        json.load(f)


def atomic_write_text(data: str, path: Path, perms: int = 0o600) -> None:
    """Write text atomically: tmp -> fsync -> rename. Sets secure perms.

    Same partial-.tmp erasure as atomic_write_json -- see there for why.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        secure_write_text(tmp, data, perms)   # 0600 at creation, see above
        os.replace(tmp, path)
    except BaseException:
        secure_delete_file(tmp)
        raise

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

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=3, max=20), reraise=True)
def _verify_tor_once(proxy: Dict[str, str]) -> dict:
    r = requests.get(CHECK_TOR_URL, timeout=15, proxies=proxy)
    r.raise_for_status()
    return r.json()


def verify_tor(proxy: Dict[str, str]) -> None:
    """Verify we are exiting through Tor. Aborts on failure.

    Network errors are retried up to 4x by _verify_tor_once; reraise=True
    ensures the real requests exception (not an opaque tenacity RetryError)
    reaches this try/except once retries are exhausted, so the operator
    gets the same clear abort message as every other Tor-failure path.
    """
    try:
        data = _verify_tor_once(proxy)
    except requests.exceptions.InvalidSchema as e:
        # Not a network problem: requests cannot speak SOCKS without PySocks,
        # so EVERY socks5h:// request dies here. Reporting that as a "network
        # error" sent operators debugging their Tor daemon when the actual fix
        # is a missing dependency. Fail closed, but say what is really wrong.
        integrity_log("tor", "verify_fail:socks_support_missing")
        sys.exit(
            f"[!] SOCKS support is missing, so nothing can be routed through Tor:\n"
            f"    {str(e)[:80]}\n"
            f"    Fix: pip install PySocks   (or: pip install -r requirements.txt)\n"
            f"    Aborting rather than risk a clearnet connection."
        )
    except requests.RequestException as e:
        integrity_log("tor", f"verify_fail:{str(e)[:40]}")
        sys.exit(f"[!] Cannot verify Tor (network error): {str(e)[:80]}. Aborting for safety.")
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
    """
    global _NEWNYM_CONSECUTIVE_FAILURES
    try:
        from stem import Signal as StemSignal
        from stem.control import Controller
        with Controller.from_socket_file(ctrl) as c:
            c.authenticate()
            c.signal(StemSignal.NEWNYM)
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

@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30), reraise=True)
def safe_get(url: str, proxies: Dict[str, str] = None) -> dict:
    # `not proxies`, NOT `is None`. requests treats proxies={} exactly like no
    # proxy at all and connects DIRECTLY, so an empty dict slipped past an
    # `is None` guard and produced a real clearnet request -- confirmed by
    # observing one actually reach the target. Any falsy value must abort.
    if not proxies:
        sys.exit("[!] safe_get called without proxies — clearnet leak. Aborting.")
    r = requests.get(url, timeout=20, proxies=proxies)
    r.raise_for_status()
    return r.json()


@retry(stop=stop_after_attempt(4), wait=wait_exponential_jitter(initial=4, max=30), reraise=True)
def safe_post(url: str, payload: dict, proxies: Dict[str, str] = None) -> dict:
    if not proxies:      # proxies={} means DIRECT in requests -- see safe_get
        sys.exit("[!] safe_post called without proxies — clearnet leak. Aborting.")
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
        self._backend = JSONRPCWallet(host=host, port=port)

        if proxy_url and host.lower() not in _LOCALHOST_NAMES:
            # Only log success AFTER the patch actually applies. The old code
            # logged "proxy_patched" up front, so if the session attribute wasn't
            # present the proxy silently didn't apply yet the integrity chain
            # asserted it was patched -- a clearnet IP leak under a green log.
            proxies = {"http": proxy_url, "https": proxy_url}
            if hasattr(self._backend, "_session"):
                self._backend._session.proxies.update(proxies)
                integrity_log("rpc", f"non_local_rpc:{host}:{port}:proxy_applied")
            else:
                integrity_log("rpc", f"non_local_rpc:{host}:{port}:proxy_UNAVAILABLE")
                sys.exit(
                    f"[!] Cannot attach the proxy to monero-python's session for\n"
                    f"    non-localhost RPC {host}:{port}; the connection would be\n"
                    f"    clearnet and leak your IP. Aborting. Tunnel the RPC\n"
                    f"    externally (socat/ssh) and point at 127.0.0.1 instead."
                )

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


def daemon_fee_estimate(daemon_url: str, proxies: Optional[Dict[str, str]] = None) -> dict:
    """Return monerod's get_fee_estimate 'result' dict, or {} on any failure.

    The result carries a base per-byte 'fee' and (on modern monerod) an explicit
    per-priority 'fees' array -- callers should prefer the array so the estimate
    matches exactly what transfer_split charges at a given priority.

    get_fee_estimate is a monerod (DAEMON) json_rpc method; monero-wallet-rpc
    does NOT expose it, so callers wanting a live fee estimate must query the
    daemon endpoint (e.g. :18081), not the wallet-rpc (:18083). A localhost
    daemon is queried directly; a non-localhost daemon is queried through the
    given Tor proxies, or refused (returns {}) if none were provided, so the
    query is never leaked to a remote node over clearnet.
    """
    parsed = urlparse(daemon_url)
    host = (parsed.hostname or "127.0.0.1").lower()
    use_proxies = None
    if host not in _LOCALHOST_NAMES:
        if not proxies:
            return {}
        use_proxies = proxies
    try:
        endpoint = daemon_url.rstrip("/") + "/json_rpc"
        r = requests.post(
            endpoint,
            json={"jsonrpc": "2.0", "id": "0", "method": "get_fee_estimate"},
            timeout=20, proxies=use_proxies,
        )
        r.raise_for_status()
        return r.json().get("result", {}) or {}
    except Exception:
        return {}

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


def disable_core_dumps() -> bool:
    """Forbid this process from writing a core file. Returns True if enforced.

    A core dump is a copy of process memory written to DISK. These processes
    hold the wallet password (and, in the wallet-rpc client path, key material)
    in memory, so a crash on a machine with the common `ulimit -c unlimited`
    default would persist that secret to a file nothing here ever wipes.
    Setting RLIMIT_CORE to 0 is the standard prevention and costs nothing.

    Note this only binds THIS process and children it spawns -- it cannot
    constrain a separately-launched monerod/monero-wallet-rpc.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    except (ImportError, ValueError, OSError):
        return False


def install_signal_handlers():
    """Install handlers for SIGINT and SIGTERM, and forbid core dumps.

    Core-dump suppression lives here because every script calls this at
    startup, so it is the one hook that reliably covers them all.
    """
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    disable_core_dumps()


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


# ---------------------------------------------------------------------------
#  Real BTC bech32/bech32m checksum verification (BIP173 / BIP350)
# ---------------------------------------------------------------------------
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values) -> int:
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_checksum_ok(addr: str) -> bool:
    """Fully validate a BTC segwit address: checksum AND witness structure.

    A format regex accepts a typo'd address as long as the wrong characters stay
    in-charset; for an address we tell someone to send real BTC to, that risks
    irrecoverable funds. This runs the actual BIP173 (v0) / BIP350 (v1+ taproot)
    polymod AND enforces the witness rules, because a checksum test alone is not
    enough -- an earlier version of this function accepted three classes of
    address that Bitcoin Core rejects:
      * a v0 address carrying a bech32m checksum (and vice-versa). The checksum
        VARIANT is bound to the witness version: v0 must be bech32 (const 1),
        v1+ must be bech32m (const 0x2bc830a3). Accepting either constant for
        either version is exactly BIP350's invalid-vector list.
      * a witness program of illegal length (e.g. "bc1pw5dgrnzv"): the program
        must be 2..40 bytes, and for v0 specifically exactly 20 or 32.
      * an empty data part with no witness version byte at all.
    Sending to any of those loses the funds, so all three now return False.
    """
    if not addr or any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    if addr.lower() != addr and addr.upper() != addr:  # mixed case is invalid
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data_part = a[:pos], a[pos + 1:]
    try:
        data = [_BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        return False
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const not in (1, 0x2bc830a3):
        return False

    payload = data[:-6]          # strip the 6 checksum symbols
    if not payload:              # no witness version byte at all
        return False
    witver = payload[0]
    if witver > 16:
        return False
    # Checksum variant is BOUND to the witness version (BIP350).
    if witver == 0 and const != 1:
        return False
    if witver >= 1 and const != 0x2bc830a3:
        return False

    # Re-pack the 5-bit groups into bytes to check the program length.
    acc = bits = 0
    program = []
    for v in payload[1:]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 0xFF)
    if bits >= 5 or ((acc << (8 - bits)) & 0xFF):
        return False             # excess padding / non-zero pad bits
    if not (2 <= len(program) <= 40):
        return False
    if witver == 0 and len(program) not in (20, 32):
        return False
    return True


def secure_delete_file(path: Path) -> bool:
    """Overwrite a regular file's full extent in place (random then zeros), then
    unlink. Returns True on success. The single real wipe primitive -- callers
    that must not leave plaintext (a GPG bundle's source, paranoia_mode's
    artifact sweep) all use this one rather than keeping their own copy.

    NEVER follows a symlink. Opening the path directly would overwrite the
    LINK TARGET -- destroying a file the operator never asked to wipe -- and
    then unlink only the link, while reporting success. Since wipe callers
    expand shell globs, a symlink matching e.g. '*.json' would silently zero
    whatever it pointed at. O_NOFOLLOW makes the open fail atomically on a
    symlink (no TOCTOU gap), and we unlink the link itself instead: removing a
    symlink discloses nothing, as the link holds no file content.
    Non-regular files (fifo, device, socket) are likewise never overwritten.
    """
    path = Path(path)
    try:
        st = os.lstat(path)
    except OSError:
        return False

    if stat_module.S_ISLNK(st.st_mode):
        try:
            path.unlink()          # drop the link only; target untouched
            return True
        except OSError:
            return False
    if not stat_module.S_ISREG(st.st_mode):
        return False               # refuse fifo/device/socket/dir

    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        size = os.fstat(fd).st_size
        if size > 0:
            # "wb" matches the O_WRONLY fd. It does NOT truncate: truncation is
            # an open(2) flag (O_TRUNC) that we deliberately never pass, so the
            # original blocks stay allocated and really are overwritten. ("r+b"
            # would also work but requests read access the fd doesn't have, so
            # any future read would raise -- match the fd instead.)
            with os.fdopen(fd, "wb", closefd=True) as f:
                fd = -1            # fdopen owns it now
                for filler in (os.urandom, lambda n: b"\x00" * n):
                    f.seek(0)
                    left = size
                    while left > 0:
                        n = min(left, 1 << 20)
                        f.write(filler(n)); left -= n
                    f.flush(); os.fsync(f.fileno())
        elif fd >= 0:
            os.close(fd); fd = -1
        path.unlink()
        return True
    except (PermissionError, OSError):
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
