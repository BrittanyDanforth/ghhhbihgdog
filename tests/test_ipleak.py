#!/usr/bin/env python3
"""IP-leak defences. Every check here is about traffic escaping Tor.

None of this surface was covered before. Most of it turned out to be sound --
which is worth LOCKING IN, because a future refactor that quietly breaks any of
it produces a silent clearnet connection, the worst failure this toolchain has.

The one real bug found while writing these: PySocks was missing from
requirements.txt, so requests could not speak socks5h at all and every Tor
request died. It failed closed (safe) but reported the missing dependency as a
"network error", sending operators to debug their Tor daemon.
"""
import sys, os, importlib.util, importlib.machinery
import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                                  os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


gs = load("gs_common.py")
bcast = load("broadcast_signed_xmr")

PASS = 0; FAIL = 0; FAILURES = []
UNPROVEN = []


def unproven(name, why):
    """A check that could NOT RUN. Not a pass, not a failure -- and loud.

    These three outcomes were two. The SOCKS-routing probes below classify any
    exception without "SOCKS" in it as a CLEARNET CONNECTION, so with
    python-monero absent `ModuleNotFoundError: No module named 'monero'` was
    reported as "remote RPC with a proxy actually routes through SOCKS (got
    'clearnet')" -- a leak that did not happen, in the suite whose entire job
    is leak detection. A suite that cries wolf is how a real wolf gets ignored.

    Reported separately so it cannot be read as either: the check did not run,
    and nothing here knows whether the guarantee holds.
    """
    UNPROVEN.append(f"{name} [{why}]")
    print(f"  UNPROVEN: {name} — {why}")


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


def expect_exit(name, fn):
    try:
        fn(); check(name + " (should have aborted)", False)
    except SystemExit:
        check(name, True)


# ---------------------------------------------------------------------------
# 1. Proxy scheme validation. socks5:// resolves DNS LOCALLY -- the hostname
#    you look up leaks to your resolver/ISP even though the traffic is proxied.
#    Only socks5h:// (remote DNS) is acceptable.
# ---------------------------------------------------------------------------
check("proxy: socks5h accepted",
      gs.validate_proxy("socks5h://127.0.0.1:9050")["http"].startswith("socks5h://"))
expect_exit("proxy: socks5:// REJECTED (leaks DNS locally)",
            lambda: gs.validate_proxy("socks5://127.0.0.1:9050"))
expect_exit("proxy: http:// rejected", lambda: gs.validate_proxy("http://127.0.0.1:8118"))
expect_exit("proxy: https:// rejected", lambda: gs.validate_proxy("https://x:8080"))
expect_exit("proxy: socks4:// rejected", lambda: gs.validate_proxy("socks4://127.0.0.1:9050"))
expect_exit("proxy: empty rejected", lambda: gs.validate_proxy(""))

# ---------------------------------------------------------------------------
# 2. Nothing may go out unproxied. safe_get/safe_post/_single_post must abort
#    rather than issue a bare request.
# ---------------------------------------------------------------------------
expect_exit("safe_get: refuses to run without proxies",
            lambda: gs.safe_get("http://example.com", None))
# The empty-dict cases are the ones that actually leaked: the guards tested
# `proxies is None`, but requests treats proxies={} as NO proxy and connects
# DIRECTLY, so {} passed the check and a real clearnet request went out
# (observed reaching the target). NOTE: if these regress, the suite gets SLOW
# rather than failing instantly -- a broken guard means genuine network calls
# plus tenacity retries. Slowness here is itself the symptom.
expect_exit("safe_get: refuses EMPTY proxies dict (requests treats {} as direct)",
            lambda: gs.safe_get("http://example.com", {}))
expect_exit("safe_post: refuses to run without proxies",
            lambda: gs.safe_post("http://example.com", {}, None))
expect_exit("safe_post: refuses EMPTY proxies dict",
            lambda: gs.safe_post("http://example.com", {"a": 1}, {}))
expect_exit("broadcast._single_post: refuses EMPTY proxies dict for remote host",
            lambda: bcast._single_post("http://example.com/json_rpc", {}, {}))
expect_exit("broadcast._single_post: refuses non-localhost without proxies",
            lambda: bcast._single_post("http://example.com/json_rpc", {}, None))

# ---------------------------------------------------------------------------
# 3. Localhost detection. A non-local host mistakenly treated AS localhost
#    would skip the proxy entirely -> direct clearnet connection.
# ---------------------------------------------------------------------------
for url, expect, why in [
    ("http://127.0.0.1:18083", True, "loopback ip"),
    ("http://localhost:18083", True, "loopback name"),
    ("http://[::1]:18083", True, "ipv6 loopback"),
    ("http://127.0.0.1.evil.com:18083", False, "prefix-match spoof"),
    ("http://localhost.evil.com:18083", False, "subdomain spoof"),
    ("http://evil.com/127.0.0.1", False, "loopback only in the path"),
    ("http://127.0.0.1@evil.com/", False, "loopback as userinfo"),
    ("http://user@evil.com:18083", False, "userinfo spoof"),
    ("http://example.com:18083", False, "plain remote host"),
]:
    got = bcast._is_localhost(url)
    check(f"is_localhost: {why} -> {expect}", got == expect)

# ---------------------------------------------------------------------------
# 4. An explicit proxies= argument must win over the environment. If NO_PROXY
#    could override it, setting NO_PROXY=* would silently deanonymise every
#    request while the code still "passes proxies".
#    Proxy points at a dead port: reaching the target at all means bypass.
# ---------------------------------------------------------------------------
_DEAD = {"http": "socks5h://127.0.0.1:9", "https": "socks5h://127.0.0.1:9"}
_saved_env = {k: os.environ.get(k) for k in
              ("NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy",
               "HTTPS_PROXY", "https_proxy")}


def _went_via_proxy(url):
    """True if the request was proxied (SOCKS error), False if it bypassed."""
    try:
        requests.get(url, proxies=_DEAD, timeout=5)
        return False            # reached the target -> bypassed the dead proxy
    except requests.exceptions.InvalidSchema:
        return None             # PySocks absent; cannot judge (reported below)
    except Exception as e:
        m = str(e)
        return ("SOCKS" in m or "Socks" in m)


try:
    for env_name, env_val in [(None, None), ("NO_PROXY", "*"), ("no_proxy", "*"),
                              ("NO_PROXY", "example.com")]:
        for k in _saved_env:
            os.environ.pop(k, None)
        if env_name:
            os.environ[env_name] = env_val
        res = _went_via_proxy("http://example.com/")
        label = f"{env_name}={env_val}" if env_name else "no proxy env vars"
        if res is None:
            print(f"  (skipped NO_PROXY check [{label}]: PySocks not installed)")
        else:
            check(f"env cannot bypass explicit proxies= [{label}]", res is True)
finally:
    for k, v in _saved_env.items():
        os.environ.pop(k, None)
        if v is not None:
            os.environ[k] = v

# ---------------------------------------------------------------------------
# 5. Missing SOCKS support must fail CLOSED, and must be diagnosed as a missing
#    dependency rather than a "network error".
# ---------------------------------------------------------------------------
check("InvalidSchema is a RequestException (so the Tor guard catches it)",
      issubclass(requests.exceptions.InvalidSchema, requests.RequestException))

_real_get = gs.requests.get
try:
    gs.requests.get = lambda *a, **k: (_ for _ in ()).throw(
        requests.exceptions.InvalidSchema("Missing dependencies for SOCKS support."))
    _msg = ""
    try:
        gs.verify_tor({"http": "socks5h://127.0.0.1:9050",
                       "https": "socks5h://127.0.0.1:9050"})
        check("verify_tor: aborts when SOCKS support is missing", False)
    except SystemExit as e:
        _msg = str(e)
        check("verify_tor: aborts when SOCKS support is missing", True)
    check("verify_tor: names PySocks as the fix, not a 'network error'",
          "PySocks" in _msg and "network error" not in _msg)
finally:
    gs.requests.get = _real_get

# A genuine network failure must still abort (fail closed, not fall through).
_real_get = gs.requests.get
try:
    gs.requests.get = lambda *a, **k: (_ for _ in ()).throw(
        requests.exceptions.ConnectionError("connection refused"))
    expect_exit("verify_tor: aborts on a real network error too",
                lambda: gs.verify_tor({"http": "socks5h://127.0.0.1:9050",
                                       "https": "socks5h://127.0.0.1:9050"}))
finally:
    gs.requests.get = _real_get

# And a reachable proxy that is NOT Tor must abort rather than proceed.
_real_get = gs.requests.get
try:
    class _Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"IsTor": False, "IP": "203.0.113.9"}
    gs.requests.get = lambda *a, **k: _Resp()
    expect_exit("verify_tor: aborts when the exit is NOT Tor (IsTor=false)",
                lambda: gs.verify_tor({"http": "socks5h://127.0.0.1:9050",
                                       "https": "socks5h://127.0.0.1:9050"}))
finally:
    gs.requests.get = _real_get

# ---------------------------------------------------------------------------
# 6. PySocks must be declared, or a clean install cannot use Tor at all.
# ---------------------------------------------------------------------------
_reqs = open(os.path.join(REPO, "requirements.txt")).read().lower()
# ---- AND THE OTHER DIRECTION: NOTHING DECLARED THAT NOTHING USES ---------
#
# The check below catches a dependency that is MISSING. Nothing caught one
# that is SURPLUS, and PyYAML sat in requirements.txt with not a single
# `import yaml` anywhere in the repository -- shipped tools, suites or
# testnet drivers. On a vault holding a spend key, a package installed for
# nothing is attack surface bought for nothing.
import ast as _ast
import glob as _glob
import re as _re
_DIST_TO_MODULE = {"pysocks": "socks", "pynacl": "nacl",
                   "python-gnupg": "gnupg", "pyyaml": "yaml"}
# EXEMPTIONS ARE NAMED AND JUSTIFIED, never a blanket skip -- an exemption
# list that grows silently is the same defect as the surplus dependency.
_NOT_IMPORTED_BY_US = {
    # requests imports it to speak socks5h; we never `import socks` ourselves,
    # and without it every Tor-routed request raises InvalidSchema.
    "socks",
}
# pyflakes IS NOT EXEMPT, and the first draft of this listed it as "a dev tool
# the suite INVOKES over the shipped files, never imported". That was wrong:
# tests/test_units.py does `import pyflakes.api`. The check below caught it
# immediately, which is the whole reason the exemptions are re-verified rather
# than trusted.
_declared = []
for _l in open(os.path.join(REPO, "requirements.txt"), encoding="utf-8"):
    _l = _l.split("#")[0].strip()
    if not _l:
        continue
    _name = _re.split(r"[<>=!~\[]", _l)[0].strip().lower()
    if _name:
        _declared.append(_DIST_TO_MODULE.get(_name, _name))
_imported = set()
for _f in _glob.glob(os.path.join(REPO, "*")) + _glob.glob(os.path.join(REPO, "tests", "*.py")):
    if not os.path.isfile(_f) or _f.endswith((".md", ".log", ".lock", ".txt", ".json")):
        continue
    try:
        _t = _ast.parse(open(_f, encoding="utf-8").read())
    except Exception:                                        # noqa: BLE001
        continue
    for _n in _ast.walk(_t):
        if isinstance(_n, _ast.Import):
            _imported.update(a.name.split(".")[0] for a in _n.names)
        elif isinstance(_n, _ast.ImportFrom) and _n.module and _n.level == 0:
            _imported.add(_n.module.split(".")[0])
_surplus = sorted(set(_declared) - _imported - _NOT_IMPORTED_BY_US)
check(f"requirements.txt declares nothing that nothing imports "
      f"(surplus: {_surplus or 'none'})", _surplus == [])
# NON-VACUITY 1: the scan really did find imports, or an empty set would
# make every declaration look surplus and the check above would be inverted.
check("requirements: NON-VACUITY -- the import scan actually found modules",
      {"requests", "nacl", "monero"} <= _imported)
# NON-VACUITY 2: the declaration parse really produced names.
check("requirements: NON-VACUITY -- the file parsed into real names",
      len(_declared) >= 6 and "requests" in _declared)
# AND THE EXEMPTIONS ARE STILL TRUE. If something starts importing socks
# directly, it belongs in the ordinary set rather than the exception list.
check("requirements: the exemptions are still exemptions, not stale entries",
      all(_e not in _imported for _e in _NOT_IMPORTED_BY_US))

check("requirements.txt declares PySocks (socks5h is unusable without it)",
      "pysocks" in _reqs)

# ---------------------------------------------------------------------------
# 7. RELAY EGRESS. The last hop nobody was checking: every request can be
#    perfectly Tor-proxied and the transaction still deanonymised, because it
#    leaves via monerod's peer connections. monerod exposes no RPC reporting
#    --tx-proxy (verified against 0.18.3.1), but get_connections shows whether
#    peers are .onion/.i2p or raw IPs -- a direct observation of egress.
# ---------------------------------------------------------------------------
class _Resp:
    def __init__(self, d): self._d = d
    def json(self): return self._d
    def raise_for_status(self): pass


def _egress_verdict(info, conns):
    real = gs.requests.post
    try:
        gs.requests.post = lambda url, json=None, **k: _Resp(
            {"result": info if json.get("method") == "get_info" else conns})
        return gs.check_daemon_relay_egress("http://127.0.0.1:18081")
    finally:
        gs.requests.post = real


for name, info, conns, expect in [
    ("all peers .onion -> tor", {"offline": False},
     {"connections": [{"address": "abc.onion:18080"}, {"address": "d.onion:18080"}]}, "tor"),
    ("all peers .i2p -> tor", {"offline": False},
     {"connections": [{"address": "xyz.b32.i2p:0"}]}, "tor"),
    ("ANY clearnet peer -> clearnet", {"offline": False},
     {"connections": [{"address": "abc.onion:18080"}, {"address": "51.75.162.1:18080"}]},
     "clearnet"),
    ("all raw IPs -> clearnet", {"offline": False},
     {"connections": [{"address": "51.75.162.1:18080"}]}, "clearnet"),
    ("no peers -> unknown (not a false all-clear)", {"offline": False},
     {"connections": []}, "unknown"),
    ("restricted rpc -> unknown", {"offline": False}, {}, "unknown"),
    ("daemon --offline -> offline", {"offline": True}, {}, "offline"),
]:
    check(f"relay egress: {name}", _egress_verdict(info, conns)["verdict"] == expect)

# A mixed peer set must NOT be reported as safe: one clearnet peer is enough to
# expose the originating IP, so "mostly onion" is still clearnet.
_mixed = _egress_verdict({"offline": False},
                         {"connections": [{"address": "a.onion:1"}] * 9 +
                                          [{"address": "51.75.162.1:1"}]})
check("relay egress: 9 onion + 1 clearnet is still CLEARNET (not majority-vote)",
      _mixed["verdict"] == "clearnet")

# The probe must never raise -- a diagnostic failure must not block a broadcast.
_real_post = gs.requests.post
try:
    gs.requests.post = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    _v = gs.check_daemon_relay_egress("http://127.0.0.1:18081")
    check("relay egress: a failed probe returns 'unknown', never raises",
          _v["verdict"] == "unknown" and "probe failed" in _v["detail"])
finally:
    gs.requests.post = _real_post

# A remote daemon with no proxy must not be probed over clearnet.
check("relay egress: remote daemon without proxy is not probed in the clear",
      gs.check_daemon_relay_egress("http://example.com:18081", None)["verdict"] == "unknown")

# broadcast must ABORT on a verified-clearnet relay, and only proceed with the
# explicit override.
_EGRESS_DETAIL = {
    "clearnet": "3 clearnet peer(s) vs 0 anonymous",
    "offline": "daemon is running --offline; it cannot relay at all",
    "tor": "all 3 relay peer(s) are .onion/.i2p",
    "unknown": "daemon has no peer connections yet",
}


def _run_broadcast(extra_argv, verdict):
    b = load("broadcast_signed_xmr")
    b.verify_tor = lambda *a, **k: None
    # Detail must match the verdict: an earlier version of this test returned a
    # clearnet detail for every verdict, so the offline assertion failed on the
    # MOCK's wording rather than on the code under test.
    b.check_daemon_relay_egress = lambda *a, **k: {
        "verdict": verdict, "onion": 0, "clear": 3,
        "detail": _EGRESS_DETAIL[verdict]}
    argv = sys.argv[:]
    sys.argv = ["broadcast_signed_xmr", "/nonexistent_path",
                "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--rpc-daemon", "http://127.0.0.1:18081"] + extra_argv
    try:
        b.main(); return ""
    except SystemExit as e:
        return str(e)
    finally:
        sys.argv = argv


check("broadcast: REFUSES to relay when egress is verified clearnet",
      "Refusing to broadcast" in _run_broadcast([], "clearnet"))
check("broadcast: --allow-clearnet-relay overrides the refusal",
      "Refusing to broadcast" not in _run_broadcast(["--allow-clearnet-relay"], "clearnet"))
check("broadcast: aborts when the daemon is offline (broadcast would vanish)",
      "cannot relay" in _run_broadcast([], "offline"))


# ---------------------------------------------------------------------------
# DATA-AT-REST LEAK: the persistent integrity_chain.log must never carry a
# linkable quantity. It survives on disk, so an exact per-hop XMR amount, a
# destination address, a memo, a txid or a key recovered from it correlates
# directly against the on-chain transactions and unmixes the whole pipeline.
# GhostSpiral's stage-4 planner used to write `amt_each={fanout_amt}` and
# `amt_each={dag_hop_amt}` -- the single most linkable value there is.
# This scans every integrity_log() call in every shipped script by AST and
# fails if any interpolates a secret-looking variable.
# ---------------------------------------------------------------------------
import ast

# Names that denote a linkable VALUE (amount / address / key / etc.). This list
# had blind spots -- it caught "amount" but not "per_chunk" (a BTC amount) or
# "unlocked_bal" (the swapped XMR amount), both of which were leaking to the
# persistent integrity log until this scan was widened. Amount-ish fragments
# now included: bal, chunk, gross, net_xmr, fiat, sats, value, and the btc/xmr
# magnitude prefixes.
_SECRET_NAMES = ("amt", "amount", "addr", "address", "dest", "deposit", "memo",
                 "txid", "tx_hash", "privkey", "priv", "seed", "mnemonic",
                 "viewkey", "spendkey", "password", "secret", "balance", "mac",
                 "bal", "chunk", "gross", "fiat", "sats", "value",
                 "btc", "xmr", "picochunk")
_SHIPPED = ["GhostSpiral", "airgap_tx_signer", "broadcast_signed_xmr",
            "gs_common.py", "thor_swap_preparer", "create_receive_wallet",
            "exit_strategy_simulator", "paranoia_mode", "receive_watch"]


# Functions whose RESULT is safe to log even when a secret-named value is
# passed in: maskers (scrub_address -> first/last chars; _m -> magnitude
# masked) and COUNT wrappers (len/count -> a cardinality, not the value). A
# count of amounts is not an amount, so {len(btc_chunks)} must not flag.
_MASKERS = ("scrub_address", "scrub", "mask", "redact", "_m")
_COUNT_WRAPPERS = ("len", "count")


def _is_masked_call(node):
    """True if node is a call to a masking or count-wrapper function, e.g.
    scrub_address(addr) or len(chunks). Everything inside it is safe."""
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
    n = (name or "").lower()
    if n in _COUNT_WRAPPERS:
        return True
    return any(m == n or n.endswith("_" + m) or m in n for m in _MASKERS)


def _fstring_leaks(node):
    """Names interpolated into an f-string that look like secrets AND are not
    passed through a masking function like scrub_address()."""
    leaks = []
    for v in ast.walk(node):
        if not isinstance(v, ast.FormattedValue):
            continue
        # A masked interpolation ({scrub_address(x)}) is safe as a whole.
        if _is_masked_call(v.value):
            continue
        for n in ast.walk(v.value):
            if isinstance(n, ast.Name):
                base = n.id.lower()
                if any(s == base or base.startswith(s + "_") or base.endswith("_" + s)
                       for s in _SECRET_NAMES):
                    leaks.append(n.id)
    return leaks


def _scan_integrity_log_calls(path):
    tree = ast.parse(open(path).read())
    hits = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "integrity_log"):
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):        # an f-string arg
                    for name in _fstring_leaks(arg):
                        hits.append((getattr(node, "lineno", "?"), name))
    return hits


# ---------------------------------------------------------------------------
# A NON-LOCALHOST RPC MUST GO THROUGH THE PROXY, OR NOT GO AT ALL.
#
# The old code built the backend unproxied and then patched
# `self._backend._session.proxies`. monero-python 1.1.1 names that attribute
# `session`, so the hasattr was always False and the fail-closed branch fired
# unconditionally -- broken, but safe.
#
# Patching the SESSION would have been WORSE than the abort:
# JSONRPCWallet.raw_request passes `proxies=self.proxies` on EVERY request, and
# a per-request proxies argument overrides the Session's. Measured: with
# session.proxies set to the SOCKS URL the request still opened a plain
# HTTPConnection to the remote host -- a clearnet connection to a Monero node.
# These pin all three outcomes by the CONNECTION ACTUALLY ATTEMPTED, not by
# reading the source.
# ---------------------------------------------------------------------------
def _connect_path(url, proxy_url):
    """Return 'socks', 'clearnet', or 'abort:<msg>' for a real connection try.

    10.1.2.3 is unroutable, so the exception names the path taken:
    SOCKSHTTPConnectionPool means the proxy was used, HTTPConnectionPool means
    it was not.
    """
    try:
        gs.MoneroRPC(url, proxy_url=proxy_url)
        return "connected"
    except SystemExit as e:
        return "abort:" + str(e).splitlines()[0]
    except ImportError as e:
        # NOT "clearnet". No connection was attempted at all -- the constructor
        # never got that far. Saying "clearnet" here invents a leak.
        return "unavailable:" + str(e)
    except Exception as e:                                   # noqa: BLE001
        m = str(e)
        if "SOCKS" in m:
            return "socks"
        if "No module named" in m or isinstance(e, ModuleNotFoundError):
            return "unavailable:" + m
        return "clearnet"


_p = _connect_path("http://10.1.2.3:18083", "socks5h://127.0.0.1:9050")
if _p.startswith("unavailable:"):
    _why = "python-monero not installed: " + _p.split(":", 1)[1].strip()
    unproven("remote RPC with a proxy actually routes through SOCKS", _why)
    unproven("remote RPC with a proxy NEVER opens a direct connection", _why)
    unproven("remote RPC with NO proxy aborts instead of connecting", _why)
else:
    check("remote RPC with a proxy actually routes through SOCKS "
          f"(got {_p!r})", _p == "socks")
    check("remote RPC with a proxy NEVER opens a direct connection",
          _p != "clearnet")
    _np = _connect_path("http://10.1.2.3:18083", None)
    if _np.startswith("unavailable:"):
        unproven("remote RPC with NO proxy aborts instead of connecting",
                 "python-monero not installed")
    else:
        check("remote RPC with NO proxy aborts instead of connecting",
              _np.startswith("abort:"))

# localhost must not be wrapped: the daemon behind it already syncs over Tor,
# and sending 127.0.0.1 through SOCKS just fails.
# GUARDED. This was a bare module-level import, so with python-monero absent
# the whole file died here -- no RESULT line, no summary, and the 40 checks
# above vanished from any report that greps for one. The failure was visible
# only in a traceback nobody reads.
try:
    import monero.backends.jsonrpc.wallet as _W
except ImportError as _e:
    _W = None
    unproven("localhost RPC is not wrapped in a proxy",
             f"python-monero not installed: {_e}")
    unproven("a remote RPC IS wrapped in a proxy",
             "python-monero not installed")
_seen = {}
if _W is not None:
    _orig_init = _W.JSONRPCWallet.__init__

    def _spy(self, *a, **k):
        _seen.update(k)
        return _orig_init(self, *a, **k)

    _W.JSONRPCWallet.__init__ = _spy
    try:
        gs.MoneroRPC("http://127.0.0.1:1", proxy_url="socks5h://127.0.0.1:9050")
    except Exception:                                        # noqa: BLE001
        pass
    _W.JSONRPCWallet.__init__ = _orig_init
    check("a localhost RPC is NOT wrapped in the SOCKS proxy",
          _seen.get("proxy_url") is None)
else:
    unproven("a localhost RPC is NOT wrapped in the SOCKS proxy",
             "python-monero not installed")

# The dead attribute name must not come back -- checked over the AST, not the
# text. The comment explaining WHY _session was wrong necessarily names it, and
# a substring check cannot tell the explanation from the defect. (That false
# positive fired while writing this, for the fourth time in this codebase; it
# is the reason the checks here read code rather than source strings.)
import ast as _ast
_gtree = _ast.parse(open(os.path.join(REPO, "gs_common.py")).read())
_attrs = {n.attr for n in _ast.walk(_gtree) if isinstance(n, _ast.Attribute)}
check("gs_common no longer touches the nonexistent _session attribute",
      "_session" not in _attrs)
# and the proxy really is handed to the constructor
_ctor_kwargs = set()
for _n in _ast.walk(_gtree):
    if (isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name)
            and _n.func.id == "JSONRPCWallet"):
        _ctor_kwargs.update(k.arg for k in _n.keywords)
check("...and JSONRPCWallet is constructed with proxy_url",
      "proxy_url" in _ctor_kwargs)


# ---------------------------------------------------------------------------
# RELAY EGRESS: classify by monerod's OWN address_type, and do not raise a
# false alarm on loopback.
#
# Observed on real monerod 0.18.3.1 (two peered testnet daemons): every
# get_connections entry carries address_type -- epee's enum, 1 ipv4, 2 ipv6,
# 3 i2p, 4 tor -- alongside address/host/ip/localhost/local_ip. Matching
# ".onion" in the address string was a guess at a format; address_type is the
# daemon stating which network the connection is on.
#
# The loopback case matters for a different reason. A 127.0.0.1 peer was
# counted as clearnet, which is a false alarm -- and every false alarm pushes
# the operator toward --allow-clearnet-relay, which switches the check off for
# the case it exists to catch. It is not "tor" either: that daemon has its own
# peers and its egress is not observable from here. Unknown is the honest
# answer, and the code now says which.
# ---------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, payload): self._p = payload
    def json(self): return self._p


def _egress_with(peers, offline=False):
    """Drive the real check with a scripted get_info/get_connections pair."""
    calls = {"n": 0}

    def fake_post(url, json=None, timeout=None, proxies=None, **_kw):
        calls["n"] += 1
        if json.get("method") == "get_info":
            return _FakeResp({"result": {"offline": offline}})
        return _FakeResp({"result": {"connections": peers}})

    real = gs.requests.post
    gs.requests.post = fake_post
    try:
        return gs.check_daemon_relay_egress("http://127.0.0.1:18081")
    finally:
        gs.requests.post = real


_tor_peer = {"address": "abcd.onion:18080", "host": "abcd.onion", "address_type": 4}
_ip_peer = {"address": "8.8.8.8:18080", "host": "8.8.8.8", "address_type": 1}
_loop_peer = {"address": "127.0.0.1:18080", "host": "127.0.0.1",
              "address_type": 1, "localhost": True}
# a Tor peer whose ADDRESS STRING does not say .onion -- the case the old
# substring match would have mis-filed as clearnet
_tor_odd = {"address": "10.0.0.1:18080", "host": "10.0.0.1", "address_type": 4}

check("egress: all-Tor peers verify as anonymous",
      _egress_with([_tor_peer, _tor_peer])["verdict"] == "tor")
check("egress: a single clearnet peer is enough to refuse",
      _egress_with([_tor_peer, _ip_peer])["verdict"] == "clearnet")
check("egress: address_type 4 is trusted over the address STRING",
      _egress_with([_tor_odd])["verdict"] == "tor")
check("egress: a loopback peer is NOT reported as clearnet",
      _egress_with([_loop_peer])["verdict"] != "clearnet")
check("egress: ...it is reported as unknown, not as verified-anonymous",
      _egress_with([_loop_peer])["verdict"] == "unknown")
check("egress: ...and says why (the other daemon's egress is unobservable)",
      "cannot be observed" in _egress_with([_loop_peer])["detail"])
check("egress: loopback does not mask a real clearnet peer",
      _egress_with([_loop_peer, _ip_peer])["verdict"] == "clearnet")
check("egress: loopback alongside Tor peers still verifies anonymous",
      _egress_with([_loop_peer, _tor_peer])["verdict"] == "tor")
check("egress: an --offline daemon is called out separately",
      _egress_with([], offline=True)["verdict"] == "offline")
check("egress: no peers at all is unknown, not tor",
      _egress_with([])["verdict"] == "unknown")
# older daemons that do not report address_type must still work
check("egress: falls back to the address string when address_type is absent",
      _egress_with([{"address": "xyz.onion:18080"}])["verdict"] == "tor")

# The refusal must say what it could NOT see, or a correctly-configured
# operator (--tx-proxy set, clearnet block-sync peers) is refused with no
# explanation and reaches for --allow-clearnet-relay reflexively.
for _f in ("GhostSpiral", "broadcast_signed_xmr"):
    _txt = open(os.path.join(REPO, _f)).read()
    check(f"{_f}: the clearnet refusal admits it cannot see --tx-proxy",
          "reports its --tx-proxy setting" in _txt)
    check(f"{_f}: ...and says it read the P2P peer list instead",
          "P2P PEER LIST" in _txt or "P2P\n" in _txt or "PEER LIST" in _txt)


_total_leaks = []
for _script in _SHIPPED:
    _p = os.path.join(REPO, _script)
    if os.path.exists(_p):
        for line, name in _scan_integrity_log_calls(_p):
            _total_leaks.append(f"{_script}:{line} interpolates '{name}'")

check("no integrity_log() call interpolates a secret/linkable value",
      not _total_leaks)
if _total_leaks:
    for _l in _total_leaks:
        print("   LEAK:", _l)

# Positive control: the scanner actually detects planted leaks, so a green
# result means "scanned and clean", not "scanner is a no-op". Includes the two
# real patterns the OLD scanner missed by name (per_chunk, unlocked_bal).
def _planted_flags(src):
    t = ast.parse(src)
    out = []
    for c in ast.walk(t):
        if isinstance(c, ast.Call) and len(c.args) > 1 and isinstance(c.args[1], ast.JoinedStr):
            out += _fstring_leaks(c.args[1])
    return out


check("scanner detects a planted {fanout_amt} interpolation",
      "fanout_amt" in _planted_flags('integrity_log("x", f"a={fanout_amt}")'))
check("scanner detects a planted {per_chunk} BTC-amount interpolation",
      "per_chunk" in _planted_flags('integrity_log("x", f"btc={per_chunk}")'))
check("scanner detects a planted {unlocked_bal} XMR-amount interpolation",
      "unlocked_bal" in _planted_flags('integrity_log("x", f"u={unlocked_bal}")'))
check("scanner does NOT flag a count wrapper len(btc_chunks)",
      _planted_flags('integrity_log("x", f"n={len(btc_chunks)}")') == [])
check("scanner does NOT flag a scrubbed address",
      _planted_flags('integrity_log("x", f"a={scrub_address(addr)}")') == [])

# THREE NUMBERS, NOT TWO. An UNPROVEN check is not a pass -- the guarantee it
# names is simply unmeasured here -- and printing it as one is how a suite
# reports green while its most important checks never ran. The RESULT line
# always prints now: a bare `import monero` used to kill this file before it
# got here, so a report that greps for RESULT saw nothing at all and the 40
# checks above disappeared silently.

# ---------------------------------------------------------------------------
# ONLY socks5h:// — WIDENING THE DNS GUARANTEE.
#
# gs_common's comment on SOCKS_RE calls this CRITICAL: "only socks5h:// is
# accepted. Plain socks5:// leaks DNS locally because the requests library
# resolves hostnames BEFORE sending through the SOCKS proxy."
#
# Line 75 above already pins the headline case, and validate_proxy defends it
# TWICE — an explicit startswith() check and the regex — so removing either one
# alone changes nothing observable. Mutation showed that: each single-guard
# mutation stayed green, which reads like a coverage hole and is not one.
# Removing BOTH turns line 75 red, which is the correct behaviour and was worth
# establishing rather than assuming.
#
# What follows widens the case rather than adding a missing one: the near-miss
# spellings an operator actually types, and the shapes that could smuggle the
# right scheme past a check that matched loosely.
_DNS_OK = "socks5h://127.0.0.1:9050"
check("proxy: socks5h:// is accepted", isinstance(gs.validate_proxy(_DNS_OK), dict))
check("proxy: ...and is used for BOTH http and https",
      gs.validate_proxy(_DNS_OK) == {"http": _DNS_OK, "https": _DNS_OK})


def _refused(url):
    try:
        gs.validate_proxy(url)
        return False
    except SystemExit:
        return True
    except Exception:                                        # noqa: BLE001
        return True


# THE ONE THAT MATTERS. socks5:// differs from socks5h:// by a single letter,
# is what most documentation shows, and is what an operator types from memory.
check("proxy: plain socks5:// is REFUSED (it resolves DNS locally)",
      _refused("socks5://127.0.0.1:9050"))
check("proxy: ...and removing ONE of the two guards is not enough to break "
      "that, which is why a single-guard mutation looks green",
      _refused("socks5://127.0.0.1:9050"))
check("proxy: socks4:// is refused", _refused("socks4://127.0.0.1:9050"))
check("proxy: http:// is refused", _refused("http://127.0.0.1:8080"))
check("proxy: https:// is refused", _refused("https://127.0.0.1:8080"))
check("proxy: an empty proxy is refused", _refused(""))
check("proxy: a proxy with no port is refused", _refused("socks5h://127.0.0.1"))
check("proxy: a bare host is refused", _refused("127.0.0.1:9050"))
# Case: SOCKS5H:// is not accepted either -- requests matches the scheme
# case-sensitively, so accepting it here would hand requests a scheme it does
# not know and the connection would not be proxied at all.
check("proxy: an upper-case SOCKS5H:// is refused",
      _refused("SOCKS5H://127.0.0.1:9050"))
# ...and nothing that merely CONTAINS the right scheme sneaks through.
check("proxy: a URL that only contains socks5h:// is refused",
      _refused("http://x/?u=socks5h://127.0.0.1:9050"))
check("proxy: whitespace around a good proxy does not smuggle a bad one",
      _refused("socks5h://127.0.0.1:9050 socks5://127.0.0.1:9050"))



# ==========================================================================
# PER-STREAM CIRCUIT ISOLATION, which the toolchain could not express.
#
# Tor's SocksPort carries IsolateSOCKSAuth BY DEFAULT: streams presenting
# different SOCKS username/password go on different circuits, deterministically
# and immediately. It is the standard mechanism for exactly what newnym() is
# reaching for -- and SOCKS_RE forbade a userinfo part, so it was unreachable.
#
# newnym() alone cannot promise it, and says so: "a True here means 'Tor
# accepted the request', not 'this stream is provably on a new circuit'",
# because Tor coalesces signals sent close together. Verified against a running
# Tor 0.4.8.10: three NEWNYM signals in a row were each accepted in 0.000s,
# while Tor's internal MAX_SIGNEWNYM_RATE is 10 seconds and newnym sleeps 5.
#
# Also verified against that Tor, by raw SOCKS5 handshake: presenting
# credentials gets method 0x02 (USERNAME/PASSWORD) and auth status 0x00 (OK);
# presenting none gets method 0x00. The mechanism is really there.
#
# NOT VERIFIED HERE, and it should not be claimed: that two credentials land on
# two DIFFERENT circuits. Proving that needs a bootstrapped Tor with real
# circuits, and this sandbox intercepts TLS so Tor cannot complete its v3 link
# handshake. What is pinned below is the part that is checkable.
# ==========================================================================
print("\n=== per-stream SOCKS circuit isolation ===")

_B = "socks5h://127.0.0.1:9050"
_tags = ["quote:0", "quote:1", "quote:2", "pair:0", "veil", "exit:1"]
_ids = [gs.isolated_proxy(_B, t)["http"] for t in _tags]
check("isolation: distinct tags give distinct SOCKS identities",
      len(set(_ids)) == len(_tags))
check("isolation: the same tag is STABLE, so a retry reuses its circuit "
      "instead of burning a new one",
      gs.isolated_proxy(_B, "quote:0")["http"]
      == gs.isolated_proxy(_B, "quote:0")["http"])
# The tag must not travel in the clear: "quote:3" would tell a local observer
# of the SOCKS port how many chunks this run has -- the cardinality every other
# rule in this repo works to withhold.
check("isolation: the tag itself never reaches the proxy in the clear",
      not any(t.split(":")[0] in u for t, u in zip(_tags, _ids)))
check("isolation: ...and neither does the chunk index",
      "quote:2" not in gs.isolated_proxy(_B, "quote:2")["http"])
# An operator who configured their own credentials must keep them.
_own = "socks5h://mine:secret@127.0.0.1:9050"
check("isolation: operator-supplied credentials are not overwritten",
      gs.isolated_proxy(_own, "quote:0")["http"] == _own)
# {} AND NOT {"http": ""}: an empty-string proxy dict is TRUTHY, so it sailed
# past safe_get's `if not proxies` refusal and requests read "" as "no proxy"
# -- a direct connection out of the helper whose name promises isolation.
check("isolation: an empty proxy is {} -- falsy, so a `not proxies` guard "
      "refuses instead of connecting direct",
      gs.isolated_proxy("", "quote:0") == {})

# THE DNS-LEAK GUARD MUST SURVIVE THE WIDENED REGEX. This is the check that
# matters most here: relaxing SOCKS_RE to admit userinfo must not accidentally
# admit socks5:// (local DNS resolution, every destination hostname to the
# ISP's resolver).
for _bad in ("socks5://127.0.0.1:9050", "socks5://u:p@127.0.0.1:9050"):
    _refused = False
    try:
        gs.validate_proxy(_bad)
    except SystemExit:
        _refused = True
    check(f"isolation: {_bad} is STILL refused (DNS leak guard intact)",
          _refused)
for _good in (_B, _own):
    _ok = True
    try:
        gs.validate_proxy(_good)
    except SystemExit:
        _ok = False
    check(f"isolation: {_good.split('@')[-1]} with"
          f"{'out' if '@' not in _good else ''} credentials is accepted", _ok)
# ...and nothing else sneaks through the looser pattern.
for _bad in ("socks5h://127.0.0.1", "socks5h://:9050", "socks5h://a@b@c:9050",
             "http://127.0.0.1:9050", "socks5h://127.0.0.1:99999999"):
    check(f"isolation: {_bad!r} is still rejected by the pattern",
          not gs.SOCKS_RE.match(_bad))

# The quote loops must actually USE it -- an unused helper is not isolation.
from srcutil import code_only  # noqa: E402
_gs_src = code_only(os.path.join(REPO, "GhostSpiral"))
_th_src = code_only(os.path.join(REPO, "thor_swap_preparer"))
check("isolation: GhostSpiral's per-chunk quote loop uses a per-chunk circuit",
      'isolated_proxy(args.tor_proxy, f"quote:{i}")' in _gs_src)
check("isolation: ...and posts the quote through it, not the shared proxy",
      "safe_post(f\"{SWAPKIT_API}/v3/quote\", payload, _qproxy)" in _gs_src)
check("isolation: thor_swap_preparer's per-pair loop does the same",
      'isolated_proxy(args.tor_proxy, f"pair:{i}")' in _th_src)
# Additive, not a replacement: newnym must still run.
# The PROPERTY, not the literal. This read "newnym(required=True)" and went red
# when proxy_url= was threaded through the call -- the same trap srcutil's
# docstring names: "asserting that a particular call appears on a particular
# line does not [survive]". What matters is that a REQUIRED rotation still
# happens, whatever else the call carries.
import ast as _ast


def _required_newnyms(path):
    n = 0
    for node in _ast.walk(_ast.parse(open(path).read())):
        if isinstance(node, _ast.Call) and getattr(node.func, "id", None) == "newnym":
            if any(k.arg == "required" and getattr(k.value, "value", None) is True
                   for k in node.keywords):
                n += 1
    return n


_gs_req = _required_newnyms(os.path.join(REPO, "GhostSpiral"))
_th_req = _required_newnyms(os.path.join(REPO, "thor_swap_preparer"))
check(f"isolation: newnym is KEPT alongside it, defence in depth "
      f"(GhostSpiral {_gs_req} required rotations, thor {_th_req})",
      _gs_req > 0 and _th_req > 0)
# ...and it now names WHICH tor to rotate, or it can rotate a daemon that
# carries none of this run's traffic and report success.
check("isolation: ...and every required rotation says which tor it means",
      "proxy_url=getattr(args, \"tor_proxy\", \"\")" in _gs_src)

# EVERY FILE, NOT JUST GhostSpiral -- and this is how the real one was missed.
#
# The check above is a substring test against GhostSpiral only. broadcast_
# signed_xmr called newnym(required=True) with NO proxy_url at all, and
# newnym then falls back to its default ctrl of /var/run/tor/control and
# rotates whatever tor owns that path. On an operator running Tor Browser
# (--tor-proxy socks5h://127.0.0.1:9150 -- a setup gs_console's own detection
# offers and test_console pins) that is a DIFFERENT daemon from the one
# carrying the relay. _control_owns_socks, which exists to catch exactly that,
# is skipped as well: with no proxy_url it returns True immediately.
#
# So "NEWNYM before EVERY TX (including the first) for circuit isolation" --
# the comment sitting directly above the call -- was true of the call and
# false of the circuits, and a whole batch of transactions relayed on one.
# In the process that publishes the money.
#
# Found by RUNNING the pipeline end to end against a real chain, not by a
# test: nothing in this suite had ever executed GhostSpiral.main() far enough
# to spawn a real broadcast. AST, so it cannot be fooled by formatting, and
# every toolchain file rather than the one that happened to be looked at.
def _newnyms_missing_proxy(path):
    out = []
    for node in _ast.walk(_ast.parse(open(path).read())):
        if isinstance(node, _ast.Call) and getattr(node.func, "id", None) == "newnym":
            if not any(k.arg == "proxy_url" for k in node.keywords):
                out.append(getattr(node, "lineno", "?"))
    return out


_callers = ["GhostSpiral", "broadcast_signed_xmr", "airgap_tx_signer",
            "thor_swap_preparer", "create_receive_wallet", "receive_watch",
            "gs_console"]
_bad = {}
_total = 0
for _f in _callers:
    _fp = os.path.join(REPO, _f)
    if not os.path.exists(_fp):
        continue
    _miss = _newnyms_missing_proxy(_fp)
    _total += sum(1 for n in _ast.walk(_ast.parse(open(_fp).read()))
                  if isinstance(n, _ast.Call)
                  and getattr(n.func, "id", None) == "newnym")
    if _miss:
        _bad[_f] = _miss
check(f"isolation: EVERY newnym call in the toolchain names its tor "
      f"({_total} call(s) across {len(_callers)} files; offenders: "
      f"{_bad or 'none'})", not _bad)

# NON-VACUITY: the walker must actually be finding calls, or "no offenders"
# is just an empty search.
check("isolation: ...and the walker really found the calls it checked",
      _total >= 15)

print(f"\nRESULT: {PASS} passed, {FAIL} failed, {len(UNPROVEN)} UNPROVEN")
if UNPROVEN:
    print("UNPROVEN (these guarantees were NOT measured — do not read this "
          "suite as green):")
    for _u in UNPROVEN:
        print("   -", _u)
if FAILURES:
    print("FAILED:", FAILURES); sys.exit(1)
if UNPROVEN:
    # Exit 2: distinct from pass and from fail, so the console shows it as
    # "exit 2" rather than a tick. Install python-monero to clear it.
    sys.exit(2)
print("ALL GREEN")
