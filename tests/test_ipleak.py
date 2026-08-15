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
check("requirements.txt declares PySocks (socks5h is unusable without it)",
      "pysocks" in _reqs)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES); sys.exit(1)
print("ALL GREEN")
