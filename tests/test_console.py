#!/usr/bin/env python3
"""Executable tests for gs_console — the surface that can spend money.

Drives the real module: the real _child_env, the real live_fees, the real
action builders, and the real HTTP handler over a real socket on 127.0.0.1.
Confirmed to FAIL against the pre-fix build.
"""
import sys, os, json, time, socket, threading, subprocess, tempfile
import importlib.util, importlib.machinery
import http.client

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


def load_console(env_password=None):
    if env_password is None:
        os.environ.pop("GS_WALLET_PASSWORD", None)
    else:
        os.environ["GS_WALLET_PASSWORD"] = env_password
    loader = importlib.machinery.SourceFileLoader(
        "gs_console_t", os.path.join(REPO, "gs_console"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


SECRET = "hunter2-WALLET-SECRET"


# ==========================================================================
# 1. The wallet password must reach the pipeline child and NOTHING else.
#    The module header states this outright; before the fix every child --
#    the test suites, paranoia_mode, py_compile -- inherited it.
# ==========================================================================
def test_password_scope():
    c = load_console(SECRET)

    def child_sees(action_id):
        """Run a probe child and return what it saw, or raise if it never ran.

        The wait used to be 100 x 0.05s = 5 seconds, and on expiry it fell
        straight through to comparing whatever output existed -- usually "".
        On a loaded machine (this repo's suites run back-to-back alongside
        monero daemons) a bare interpreter start exceeds 5s, so the run
        reported 'the pipeline child DOES get the password' as FAILED.

        The direction was safe -- a timeout can only produce a mismatch, never
        a false pass -- but the message was a lie about the cause, and a
        password-scope failure is exactly the kind of thing someone drops
        everything to chase. Wait long enough for a slow host, and if it still
        has not finished, say THAT instead of pretending it is a result.
        """
        jid = c.start([sys.executable, "-c",
                       "import os;print(os.environ.get('GS_WALLET_PASSWORD'))"],
                      "probe", action_id=action_id)
        deadline = time.time() + 60
        while time.time() < deadline:
            if c.JOBS[jid]["done"]:
                return "\n".join(c.JOBS[jid]["lines"]).strip()
            time.sleep(0.05)
        raise AssertionError(
            f"probe child for action {action_id!r} did not finish within 60s "
            f"-- this is a TIMEOUT, not a password-scope result")

    check("the pipeline child DOES get the password",
          child_sees("run_pipeline") == SECRET)
    for aid in ("units", "integration", "compile", "paranoia_dry",
                "make_receive", "preflight_tor", "leakaudit"):
        check(f"'{aid}' child does NOT get the password", child_sees(aid) == "None")
    check("an unknown/None action id does not get the password",
          child_sees(None) == "None")
    check("the password is not in the console's own docstring", SECRET not in (c.__doc__ or ""))


def test_child_env_is_otherwise_intact():
    c = load_console(SECRET)
    os.environ["GS_TEST_MARKER"] = "keepme"
    try:
        env = c._child_env("units")
        check("stripping the password leaves the rest of the environment",
              env.get("GS_TEST_MARKER") == "keepme" and "PATH" in env)
        check("the real environment is not mutated",
              os.environ.get("GS_WALLET_PASSWORD") == SECRET)
    finally:
        os.environ.pop("GS_TEST_MARKER", None)


# ==========================================================================
# 2. No invented fee numbers. The console shows the daemon's estimate or none.
# ==========================================================================
def test_no_fabricated_fees():
    c = load_console()
    res = c.live_fees("http://127.0.0.1:1")          # nothing listens there
    check("an unreachable daemon yields no estimate", res["ok"] is False)
    check("an unreachable daemon yields NO numbers", res.get("xmr") is None)
    check("the operator is told why", "warning" in res and len(res["warning"]) > 20)

    # The ladder as CODE, not as prose: the docstring quotes the old constant
    # to document its removal, so grep for the expression that computed it.
    src = open(os.path.join(REPO, "gs_console")).read()
    check("the hard-coded fee ladder is gone from the code",
          "round(0.00005" not in src)

    # Both failure branches -- daemon returns nothing, and daemon lookup raises.
    c2 = load_console()

    class Boom:
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
        @staticmethod
        def daemon_fee_estimate(url, proxies=None):
            raise RuntimeError("daemon exploded")
    c2._GS_MOD = Boom
    res2 = c2.live_fees("http://127.0.0.1:18081")
    check("a raising daemon lookup also yields NO numbers", res2.get("xmr") is None)
    check("a raising daemon lookup is not marked ok", res2["ok"] is False)

    class Empty:
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
        @staticmethod
        def daemon_fee_estimate(url, proxies=None):
            return {}
    c2._GS_MOD = Empty
    check("an empty estimate yields NO numbers",
          c2.live_fees("http://127.0.0.1:18081").get("xmr") is None)


def test_real_fee_estimate_is_used_and_flagged():
    c = load_console()
    calls = []

    class FakeGs:
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}

        @staticmethod
        def daemon_fee_estimate(url, proxies=None):
            calls.append(url)
            return {"fees": [20000, 80000, 400000, 3320000]}   # piconero/byte
    c._GS_MOD = FakeGs
    res = c.live_fees("http://127.0.0.1:18081")
    check("a real fees[] array is used", res["ok"] is True and len(res["xmr"]) == 4)
    check("fees are converted to XMR per ~2 kB", res["xmr"][0] == round(20000 * 2000 / 1e12, 6))
    check("a plausible fee is not flagged", res["implausible"] is False)

    class HugeGs:
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
        @staticmethod
        def daemon_fee_estimate(url, proxies=None):
            return {"fees": [2 * 10 ** 9]}     # a fresh offline chain's absurd fee
    c._GS_MOD = HugeGs
    res2 = c.live_fees("http://127.0.0.1:18081")
    check("an absurd daemon fee IS flagged implausible", res2["implausible"] is True)
    check("the implausible warning explains it", "fresh or offline" in res2["warning"])

    class ZeroGs:
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
        @staticmethod
        def daemon_fee_estimate(url, proxies=None):
            return {"fees": [0]}
    c._GS_MOD = ZeroGs
    check("a zero fee is flagged implausible",
          c.live_fees("http://127.0.0.1:18081")["implausible"] is True)


def test_remote_daemon_fee_query_routes_through_tor():
    """A remote daemon must be queried through the Tor proxy (like the two
    preflights), and a loopback daemon queried directly. Before this the proxy
    was never threaded into live_fees, so a remote daemon behind Tor silently
    returned 'no estimate' — the half-done edge of the fee-estimate fix."""
    c = load_console()
    seen = {}

    class FakeGs:
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}

        @staticmethod
        def validate_proxy(p):
            seen["validated"] = p
            return {"http": p, "https": p}

        @staticmethod
        def daemon_fee_estimate(url, proxies=None):
            seen.setdefault("proxies", []).append(proxies)
            return {}
    c._GS_MOD = FakeGs

    c.live_fees("http://198.51.100.9:18081", "socks5h://127.0.0.1:9050")
    check("a remote daemon fee query validates the proxy", seen.get("validated"))
    check("a remote daemon fee query routes through the proxy",
          seen["proxies"][-1] == {"http": "socks5h://127.0.0.1:9050",
                                  "https": "socks5h://127.0.0.1:9050"})

    seen.clear()
    c.live_fees("http://127.0.0.1:18081", "socks5h://127.0.0.1:9050")
    check("a loopback daemon fee query stays direct (no proxy)",
          seen["proxies"][-1] is None)

    seen.clear()
    c.live_fees("http://198.51.100.9:18081", "")   # remote, no proxy configured
    check("a remote daemon with no proxy is not queried directly",
          seen.get("proxies", [None])[-1] is None)


def test_tor_port_autodetect():
    """The console must find the Tor SOCKS port itself (9050 tor.exe / 9150 Tor
    Browser) by REAL verification, not by asking the operator to know it."""
    c = load_console()
    calls = []

    class Gs:
        works = "9150"
        _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
        @staticmethod
        def validate_proxy(u):
            return {"http": u, "https": u}
        @classmethod
        def tor_recheck(cls, proxy, stage):
            calls.append(proxy["http"])
            if cls.works not in proxy["http"]:
                raise SystemExit("[!] not Tor / refused")
    c._GS_MOD = Gs

    Gs.works = "9150"
    r = c.detect_tor_proxy("")
    check("detect finds the Tor Browser port (9150)",
          r["ok"] and r["proxy"] == "socks5h://127.0.0.1:9150")
    Gs.works = "9050"
    check("detect finds the standalone tor port (9050)",
          c.detect_tor_proxy("")["proxy"] == "socks5h://127.0.0.1:9050")
    check("detect only accepts a port that ACTUALLY verifies as Tor",
          "9050" in "".join(calls) and "9150" in "".join(calls))

    Gs.works = "nope"
    r = c.detect_tor_proxy("")
    check("detect reports no proxy when Tor is not running", r["ok"] is False)
    check("detect's failure message tells the operator how to start Tor",
          "Tor Browser" in r["detail"] and "tor.exe" in r["detail"])

    src = open(os.path.join(REPO, "gs_console")).read()
    check("the page has a Detect Tor button", 'id="pfdetect"' in src)
    check("the page auto-detects Tor on load", "detectTor(true)" in src)
    check("there is a /api/detect-tor endpoint", '"/api/detect-tor"' in src)


def test_start_tor_launches_only_installed_binary():
    """Start Tor must (a) reuse a running proxy, (b) launch an installed tor and
    verify it, (c) NEVER download — a missing binary yields install guidance,
    not a fetch, and no process is spawned."""
    c = load_console()
    spawned = []
    real_popen, real_sleep = c.subprocess.Popen, c.time.sleep
    try:
        # (a) already running -> no launch
        c.detect_tor_proxy = lambda pref="": {"ok": True, "proxy": "socks5h://127.0.0.1:9150"}
        r = c.start_tor()
        check("start_tor reuses an already-running Tor (no duplicate launch)",
              r["ok"] and r["started"] is False)

        # (b) not running, no binary -> instructions, NO spawn
        c.detect_tor_proxy = lambda pref="": {"ok": False, "proxy": None}
        c._find_tor_binary = lambda: None

        def _no_spawn(*a, **k):
            spawned.append(a)
            raise AssertionError("must not spawn without a binary")
        c.subprocess.Popen = _no_spawn
        r = c.start_tor()
        check("no tor binary -> no process spawned", spawned == [])
        check("no tor binary -> actionable install guidance", r["ok"] is False
              and ("install" in r["detail"].lower() or "Tor Browser" in r["detail"]))

        # (c) binary present -> launches it, then verifies
        up = {"v": False}
        c._find_tor_binary = lambda: "/usr/bin/tor"
        c.detect_tor_proxy = (lambda pref="": {"ok": True, "proxy": "socks5h://127.0.0.1:9050"}
                              if up["v"] else {"ok": False, "proxy": None})

        class P:
            def __init__(self, *a, **k): pass
            def poll(self): return None
        c.subprocess.Popen = lambda *a, **k: P()
        c.time.sleep = lambda s: up.__setitem__("v", True)
        r = c.start_tor()
        check("an installed tor is launched and then verified",
              r["ok"] and r["started"] and r["proxy"] == "socks5h://127.0.0.1:9050")
    finally:
        c.subprocess.Popen, c.time.sleep = real_popen, real_sleep

    src = open(os.path.join(REPO, "gs_console")).read()
    check("start_tor doc says it never downloads (only launches a found binary)",
          "never downloads" in c.start_tor.__doc__.lower()
          or "never downloads" in open(os.path.join(REPO, "gs_console")).read().lower()
          or "Never downloads" in c._find_tor_binary.__doc__)
    check("the page has a Start Tor button and endpoint",
          'id="pfstart"' in src and '"/api/start-tor"' in src)


def test_wizard_structure_places_every_action():
    """The page is a 5-step wizard; every action must live in some step's
    data-acts placeholder (or it becomes unreachable), and each action id must
    appear at most once (duplicate data-id -> duplicate dot-<id> element)."""
    import re as _re
    src = open(os.path.join(REPO, "gs_console")).read()
    for s in range(1, 6):
        check(f"step {s} section exists", f'data-step="{s}"' in src)
    check("the wizard has a step navigation runner", "function showStep(" in src)
    check("steps advance via .nx/.bk buttons", "data-go=" in src)

    placed = []
    for m in _re.findall(r'data-acts="([^"]*)"', src):
        placed += [x.strip() for x in m.split(",") if x.strip()]
    c = load_console()
    for aid in c.ACTIONS:
        check(f"action '{aid}' is placed in a wizard step", aid in placed)
    check("no action is placed twice (would duplicate dot-<id>)",
          len(placed) == len(set(placed)))


def test_peel_flag_wires_through_to_argv():
    """The peeling-chain toggle must reach GhostSpiral's argv, and the peel
    preset must set it while other presets leave it off."""
    c = load_console()
    argv, _ = c.pipeline_argv({"mode": "send", "btc_entry": "bc1qxyz", "btc_amount": "0.05",
                               "tor_proxy": "socks5h://127.0.0.1:9050", "peel": True})
    check("peel=True adds --peel to the pipeline argv", "--peel" in argv)
    argv2, _ = c.pipeline_argv({"mode": "send", "btc_entry": "bc1qxyz", "btc_amount": "0.05",
                                "tor_proxy": "socks5h://127.0.0.1:9050"})
    check("no peel flag -> no --peel", "--peel" not in argv2)

    # The "Maximum safe" preset must COMPOSE both layers — peel AND dag — and
    # emit both flags, or it isn't the strongest option it claims to be.
    maxargv, _ = c.pipeline_argv({"mode": "send", "btc_entry": "bc1qxyz",
                                  "btc_amount": "0.05", "tor_proxy": "socks5h://127.0.0.1:9050",
                                  "peel": True, "dag_mixing": True})
    check("Maximum-safe params emit BOTH --peel and --dag-mixing",
          "--peel" in maxargv and "--dag-mixing" in maxargv)
    src = open(os.path.join(REPO, "gs_console")).read()
    check("the Maximum-safe preset sets peel:true AND dag_mixing:true",
          "paranoid:{wallets:10,deep:2,dag_mixing:true,peel:true" in src)
    check("the page has a peel checkbox", 'id="peel"' in src)
    check("collect() reads the peel checkbox", "peel:c('peel')" in src)
    check("there is a Peeling chain preset", 'data-p="peel"' in src and "peel:true" in src)
    check("switching presets clears peel unless the preset sets it",
          "$('#peel').checked=!!c.peel" in src)


def test_gs_common_is_loaded_once():
    """live_fees used to re-exec gs_common and grow sys.path on every poll."""
    c = load_console()
    c._GS_MOD = None
    before = len(sys.path)
    for _ in range(5):
        c.live_fees("http://127.0.0.1:1")
    check("repeated fee polls do not grow sys.path", len(sys.path) == before)
    check("gs_common is cached after the first poll", c._GS_MOD is not None)


# ==========================================================================
# 3. Preflight checks must obey the same egress rule as everything else.
# ==========================================================================
def _run_build(c, action, params, timeout=45):
    argv = c.ACTIONS[action]["build"](params)
    t = time.time()
    r = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, timeout=timeout)
    return time.time() - t, r.returncode, (r.stdout + r.stderr)


def test_wallet_preflight_refuses_remote_without_proxy():
    c = load_console()
    # 198.51.100.0/24 is TEST-NET-2: guaranteed not to route anywhere.
    el, rc, out = _run_build(c, "preflight_wallet", {"rpc_primary": "http://198.51.100.9:18083"})
    check("a remote wallet-rpc with no proxy is refused", rc != 0)
    check("it refuses INSTEAD of connecting (no connect attempt)", el < 5)
    check("the refusal explains the IP exposure", "not loopback" in out and "IP" in out)


def test_wallet_preflight_allows_loopback_direct():
    c = load_console()
    el, rc, out = _run_build(c, "preflight_wallet", {"rpc_primary": "http://127.0.0.1:1"})
    check("a loopback wallet-rpc is contacted directly", "loopback" in out and "direct" in out)
    check("an unreachable loopback rpc reports unreachable",
          "unreachable" in out and rc == 1)


def test_egress_preflight_accepts_the_proxy():
    c = load_console()
    argv = c.ACTIONS["preflight_egress"]["build"](
        {"rpc_daemon": "http://127.0.0.1:18081", "tor_proxy": "socks5h://127.0.0.1:9050"})
    check("the egress preflight is handed the Tor proxy",
          "socks5h://127.0.0.1:9050" in argv)


# ==========================================================================
# 4. HTTP surface: gates, validation, and job identity — over a real socket.
# ==========================================================================
class FakePreflightGs:
    """Stub gs_common so mandatory_preflight is deterministic and offline."""
    _LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
    tor_ok = True
    egress_verdict = "tor"

    @staticmethod
    def validate_proxy(p):
        if not p.startswith("socks5h://"):
            raise SystemExit("bad proxy")
        return {"http": p, "https": p}

    @classmethod
    def tor_recheck(cls, proxy, stage):
        if not cls.tor_ok:
            raise SystemExit("[!] Tor leak detected - traffic NOT exiting via Tor.")

    @classmethod
    def check_daemon_relay_egress(cls, d, prox):
        return {"verdict": cls.egress_verdict, "detail": f"{cls.egress_verdict} peers"}

    @staticmethod
    def integrity_log(*a, **k):
        pass

    @staticmethod
    def daemon_fee_estimate(url, proxies=None):
        return {}


class Server:
    def __init__(self, preflight_stub=False):
        self.c = load_console()
        if preflight_stub:
            self.c._GS_MOD = FakePreflightGs
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        from http.server import ThreadingHTTPServer
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), self.c.H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)

    def req(self, method, path, body=None, headers=None):
        h = {"Host": f"127.0.0.1:{self.port}"}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request(method, path, json.dumps(body) if body is not None else None, h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data

    def auth(self):
        return {"X-GS-Token": self.c.TOKEN}

    def close(self):
        self.srv.shutdown()


def test_http_gates():
    s = Server()
    try:
        st, _ = s.req("GET", "/")
        check("no token is rejected", st == 401)
        st, _ = s.req("GET", "/", headers=s.auth())
        check("a valid token loads the page", st == 200)
        st, _ = s.req("GET", "/", headers={**s.auth(), "Host": "evil.example.com"})
        check("a spoofed Host is rejected (DNS rebinding)", st == 403)
        st, _ = s.req("GET", "/", headers={**s.auth(), "Origin": "http://evil.example.com"})
        check("a cross-origin request is rejected", st == 403)
        st, _ = s.req("POST", "/run/units", {"params": {}},
                      headers={**s.auth(), "Content-Type": "text/plain"})
        check("a CORS-simple content type is rejected", st == 415)
        st, _ = s.req("POST", "/run/run_pipeline", {"params": {}}, headers=s.auth())
        check("a spending action without the arm phrase is refused", st == 403)
    finally:
        s.close()


# ==========================================================================
# 5. NON-NEGOTIABLE preflight: the pipeline cannot spend unless the OPSEC
#    preflight passes, enforced SERVER-SIDE so a crafted request can't skip it.
# ==========================================================================
_SPEND_PARAMS = {
    "mode": "send", "btc_entry": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "btc_amount": "0.05", "tor_proxy": "socks5h://127.0.0.1:9050",
    "rpc_primary": "http://127.0.0.1:18083", "rpc_daemon": "http://127.0.0.1:18081",
    "wallet_file": "w.wallet", "wallets": 10, "deep": 2, "fee_priority": 2,
    "dag_mixing": True}


def test_spend_blocked_server_side_when_tor_fails():
    s = Server(preflight_stub=True)
    FakePreflightGs.tor_ok = False
    FakePreflightGs.egress_verdict = "tor"
    try:
        st, body = s.req("POST", "/api/preflight", {"params": _SPEND_PARAMS}, headers=s.auth())
        pf = json.loads(body)
        check("preflight reports failure when Tor is down", pf["ok"] is False)
        check("preflight names Tor as the failing check", pf["checks"]["tor"]["ok"] is False)

        st, body = s.req("POST", "/run/run_pipeline",
                         {"params": _SPEND_PARAMS, "arm": "SPEND"}, headers=s.auth())
        d = json.loads(body)
        check("a spend with a valid token+arm is STILL refused when Tor fails", st == 403)
        check("the refusal cites the preflight", "Preflight FAILED" in d.get("error", ""))
        check("no job is started for a blocked spend", "jid" not in d)
    finally:
        FakePreflightGs.tor_ok = True
        s.close()


def test_spend_allowed_only_after_preflight_passes():
    s = Server(preflight_stub=True)
    FakePreflightGs.tor_ok = True
    FakePreflightGs.egress_verdict = "tor"
    try:
        st, body = s.req("POST", "/api/preflight", {"params": _SPEND_PARAMS}, headers=s.auth())
        check("preflight passes when Tor + egress are clean", json.loads(body)["ok"] is True)
        st, body = s.req("POST", "/run/run_pipeline",
                         {"params": _SPEND_PARAMS, "arm": "SPEND"}, headers=s.auth())
        d = json.loads(body)
        check("a spend launches once preflight passes", st == 200 and "jid" in d)
    finally:
        s.close()


def test_clearnet_egress_blocks_spend_unless_overridden():
    s = Server(preflight_stub=True)
    FakePreflightGs.tor_ok = True
    FakePreflightGs.egress_verdict = "clearnet"
    try:
        st, body = s.req("POST", "/run/run_pipeline",
                         {"params": _SPEND_PARAMS, "arm": "SPEND"}, headers=s.auth())
        check("a clearnet-egress spend is blocked", st == 403)
        check("the block cites egress",
              "egress" in json.loads(body).get("error", "").lower())

        over = {**_SPEND_PARAMS, "allow_clearnet_relay": True}
        st, body = s.req("POST", "/run/run_pipeline",
                         {"params": over, "arm": "SPEND"}, headers=s.auth())
        check("--allow-clearnet-relay lets the operator override the egress block",
              st == 200 and "jid" in json.loads(body))
    finally:
        FakePreflightGs.egress_verdict = "tor"
        s.close()


def test_offline_daemon_blocks_spend():
    s = Server(preflight_stub=True)
    FakePreflightGs.tor_ok = True
    FakePreflightGs.egress_verdict = "offline"
    try:
        st, body = s.req("POST", "/run/run_pipeline",
                         {"params": _SPEND_PARAMS, "arm": "SPEND"}, headers=s.auth())
        check("an offline daemon blocks the spend (broadcast would vanish)", st == 403)
    finally:
        FakePreflightGs.egress_verdict = "tor"
        s.close()


def test_preflight_does_not_gate_safe_actions():
    """The preflight gate is for spends only; a safe check must still run even
    when the (real) preflight would fail — otherwise you could never diagnose
    a broken Tor setup from the console."""
    s = Server(preflight_stub=True)
    FakePreflightGs.tor_ok = False
    try:
        st, body = s.req("POST", "/run/units", {"params": {}}, headers=s.auth())
        check("a safe action runs regardless of preflight state", st == 200)
    finally:
        FakePreflightGs.tor_ok = True
        s.close()


def test_page_wires_the_auto_preflight():
    """The page must auto-run the preflight and gate the spend button on it."""
    src = open(os.path.join(REPO, "gs_console")).read()
    check("the page defines an auto preflight runner", "async function runPreflight(" in src)
    # On load the console auto-detects Tor, then runs the preflight (detectTor
    # re-runs it on success; the fallback runs it when no Tor port is found).
    check("the preflight runs on load (after Tor auto-detect)",
          "detectTor(true).then(found=>{ if(!found) runPreflight(); })" in src)
    check("the spend button is gated on preflightOk", "armed&&preflightOk" in src)
    check("network field edits re-trigger the preflight", "schedulePreflight()" in src)
    check("the server has an /api/preflight endpoint",
          '"/api/preflight"' in src and "mandatory_preflight" in src)


def test_safe_action_rejects_bad_parameters():
    """clean() DROPS what it cannot validate; a safe action used to run anyway
    with the parameter silently missing."""
    s = Server()
    try:
        st, body = s.req("POST", "/run/preflight_wallet",
                         {"params": {"rpc_primary": "not a url"}}, headers=s.auth())
        check("a malformed parameter is refused, not dropped", st == 400)
        check("the response names the bad field",
              b"rpc primary" in body or b"rpc_primary" in body)
        st2, _ = s.req("POST", "/run/preflight_wallet",
                       {"params": {"rpc_primary": "http://127.0.0.1:18083"}},
                       headers=s.auth())
        check("a well-formed parameter still runs", st2 == 200)
    finally:
        s.close()


def test_job_ids_are_unique():
    """Two jobs started in the same millisecond used to share an id, so one
    replaced the other in JOBS and the UI polled the wrong process."""
    c = load_console()
    ids = [c.start([sys.executable, "-c", "pass"], f"j{i}", action_id="units")
           for i in range(40)]
    check("40 rapidly-started jobs get 40 distinct ids", len(set(ids)) == 40)
    check("every job is retrievable", all(i in c.JOBS for i in ids))


def test_page_escapes_untrusted_text():
    src = open(os.path.join(REPO, "gs_console")).read()
    check("an esc() helper exists", "function esc(" in src)
    check("server error text is escaped before innerHTML", "esc(res.error)" in src)
    check("the fee source is escaped", "esc(feeData.source)" in src)
    check("the fee warning is escaped", "esc(feeData.warning)" in src)
    check("the fee renderer tolerates a null estimate", "Array.isArray(feeData.xmr)" in src)


def test_receive_is_btc_to_monero():
    """The whole point of receive mode is BTC in, Monero out. Without the swap
    action the address handed to the sender is a MONERO one, so the sender must
    already hold XMR and no swap ever happens -- receive silently becomes
    XMR->XMR, which defeats the purpose of the tool."""
    c = load_console()
    src = open(os.path.join(REPO, "gs_console")).read()
    check("a BTC->XMR swap-quote action exists in the console",
          '"swap_quote"' in src)
    a = c.ACTIONS.get("swap_quote")
    check("the swap action is registered and grouped under Receive",
          a is not None and a["group"] == "Receive")
    argv = a["build"]({"swap_btc": "0.05", "receive_wallet": "w.json",
                       "tor_proxy": "socks5h://127.0.0.1:9050",
                       "pairs_file": "thor_pairs.json"})
    check("the swap action really invokes thor_swap_preparer",
          "thor_swap_preparer" in argv)
    # The amount is NOT on argv: /proc/<pid>/cmdline is world-readable (0444),
    # so the sum being swapped would be visible to any local account via ps.
    check("the swap amount is NOT on the child's argv",
          "--amounts" not in argv and "0.05" not in argv)
    check("the swap amount is handed over in the environment instead",
          c.secret_env({"swap_btc": "0.05"}).get("GS_SWAP_AMOUNTS") == "0.05")
    # The destination must come from the verified bundle, never a retyped
    # 95-char address -- a typo there is irreversible.
    check("the XMR destination is taken from the receive bundle, not retyped",
          "--dest-from-receive-wallet" in argv
          and argv[argv.index("--dest-from-receive-wallet") + 1] == "w.json")
    check("the quote is saved where the watcher will look for it",
          argv[argv.index("--outfile") + 1] == "thor_pairs.json")
    check("the swap quote is forced through Tor",
          argv[argv.index("--tor-proxy") + 1].startswith("socks5h://"))
    check("with no filename given the quote still has a default destination",
          a["build"]({"swap_btc": "0.05", "receive_wallet": "w.json",
                      "tor_proxy": "socks5h://127.0.0.1:9050"})[-1].endswith(".json"))
    check("swap_btc is in the parameter schema (unlisted keys are dropped)",
          "swap_btc" in c.SCHEMA and c.clean({"swap_btc": "0.05"})["params"]
          .get("swap_btc") == "0.05")
    check("a non-numeric BTC amount is rejected by the schema",
          c.clean({"swap_btc": "0.05; rm -rf /"})["params"].get("swap_btc") is None)
    # The receive step must present all three stages, in order.
    seg = src[src.index('id="recv-fields"'):src.index('id="recv-fields"') + 3000]
    for act in ("make_receive", "swap_quote", "watch_receive"):
        check(f"the receive step exposes {act}", f'data-acts="{act}"' in seg)
    check("the receive step says the sender pays Bitcoin",
          "sender pays Bitcoin" in seg)
    check("the receive step warns the XMR address is NOT what the sender gets",
          "not the address you give the sender" in seg)


def test_gui_never_stamps_a_tool_name_into_the_wallet():
    """The GUI must NOT label receive subaddresses.

    The page's collect() hardcoded `label:'GhostSpiral_entry'` and the
    make_receive action built its argv with
    `p.get("label", "GhostSpiral_entry")`, so the default UI -- the way this
    is actually run -- stamped the tool's own name onto every receive
    subaddress AND onto the fresh account holding it. That string lives in the
    WALLET FILE, the single artifact paranoia_mode deliberately never deletes
    because it is the operator's money. Anyone who opens that wallet learns
    which tool built the layout and which address the run entered on.

    create_receive_wallet had already been fixed to default to no label,
    OPSEC_SETUP.md documents labels as removed, and a unit test pins the CLI
    tool's default -- all three were true while the GUI kept sending the exact
    string the fix removed. Every on-chain heuristic this toolchain defeats was
    bypassed by reading a local string.
    """
    c = load_console()
    src = open(os.path.join(REPO, "gs_console")).read()

    # 1. the page must not send a label at all
    js = src[src.index("function collect()"):]
    js = js[:js.index("\n}")]
    # Strip // comments first: the explanation of WHY there is no label
    # necessarily names the string that used to be there, and a raw substring
    # check cannot tell the documentation from the defect.
    js_code = "\n".join(l.split("//")[0] for l in js.split("\n"))
    check("the collect() body was actually found (the scan is not vacuous)",
          "receive_wallet" in js_code)
    check("the page's collect() sends no hardcoded label",
          "GhostSpiral_entry" not in js_code)
    check("...and sends no label key whatsoever", "label:" not in js_code)

    # 2. the action must not invent one either
    argv = c.ACTIONS["make_receive"]["build"]({
        "rpc_primary": "http://127.0.0.1:18083",
        "tor_proxy": "socks5h://127.0.0.1:9050"})
    check("the default GUI argv carries NO --label", "--label" not in argv)
    check("...and no tool name anywhere on it",
          not any("GhostSpiral" in a for a in argv[1:]))
    check("the receive action still really invokes create_receive_wallet",
          "create_receive_wallet" in argv)
    check("...still forced through Tor",
          argv[argv.index("--tor-proxy") + 1].startswith("socks5h://"))

    # 3. an operator who deliberately asks for a label still gets one
    argv2 = c.ACTIONS["make_receive"]["build"]({
        "rpc_primary": "http://127.0.0.1:18083",
        "tor_proxy": "socks5h://127.0.0.1:9050", "label": "Savings"})
    check("a deliberate label is still passed through",
          "--label" in argv2 and argv2[argv2.index("--label") + 1] == "Savings")

    # 4. no OTHER action may smuggle the tool name onto a child's argv either
    _probe = {"rpc_primary": "http://127.0.0.1:18083",
              "tor_proxy": "socks5h://127.0.0.1:9050",
              "receive_wallet": "w.json", "wallet_file": "w",
              "swap_btc": "0.05", "btc_amount": "0.05",
              "btc_entry": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
              "split": 1, "wallets": 10, "deep": 2, "fee_priority": 1,
              "mode": "receive"}
    for name, act in c.ACTIONS.items():
        try:
            a = act["build"](_probe)
        except Exception:
            continue
        offenders = [x for x in a[1:] if isinstance(x, str) and "GhostSpiral_" in x]
        check(f"action {name} puts no tool-name label on its child's argv",
              not offenders)


def test_quote_and_watch_agree_on_the_pairs_file():
    """The GUI must not throw away the quote it just wrote.

    swap_quote defaulted a blank pairs_file to "thor_pairs.json" and wrote the
    quote there; watch_receive, reading the SAME blank field, substituted
    --any. So the default GUI flow produced a quote and then watched with no
    target at all -- discarding the expected amount, the under-delivery check
    and the shortfall report, and firing on any dust that reached the address.
    The step that reads must not silently weaken what the step that writes
    produced.
    """
    c = load_console()
    blank = {"receive_wallet": "w.json", "tor_proxy": "socks5h://127.0.0.1:9050"}
    q = c.ACTIONS["swap_quote"]["build"](blank)
    w = c.ACTIONS["watch_receive"]["build"](blank)
    check("with the field blank, the watch does NOT fall back to --any",
          "--any" not in w)
    check("...it reads the same file the quote step wrote",
          "--pairs" in w
          and w[w.index("--pairs") + 1] == q[q.index("--outfile") + 1])

    # An explicit filename must still be honoured by both.
    named = dict(blank, pairs_file="myquote.json")
    q2 = c.ACTIONS["swap_quote"]["build"](named)
    w2 = c.ACTIONS["watch_receive"]["build"](named)
    check("an explicit pairs file is used by the quote step",
          q2[q2.index("--outfile") + 1] == "myquote.json")
    check("...and by the watch step",
          w2[w2.index("--pairs") + 1] == "myquote.json")


def test_daemon_detection_fixes_no_estimate():
    """'Cannot get estimates' is nearly always 'nothing is listening where the
    daemon field points'. The console must be able to go find it."""
    c = load_console()
    src = open(os.path.join(REPO, "gs_console")).read()
    check("a daemon-detect endpoint exists", '"/api/detect-daemon"' in src)
    check("the client offers to find the daemon when there is no estimate",
          "detectDaemon" in src and "Find my daemon" in src)
    check("the probe covers the mainnet default and the common restricted port",
          18081 in c.DAEMON_PORTS and 18089 in c.DAEMON_PORTS)
    # Only the operator's configured endpoint may be remote; sweeping ports on
    # anything but this machine would be scanning someone else's host.
    def _probe_urls(preferred):
        seen = []
        real = c.live_fees
        try:
            c.live_fees = lambda u, p="": (seen.append(u),
                                           {"ok": False, "xmr": None})[1]
            c.detect_daemon(preferred, "")
        finally:
            c.live_fees = real
        return seen
    urls = _probe_urls("")
    check("every auto-probed daemon endpoint is loopback",
          all("127.0.0.1" in u for u in urls))
    check("the operator's own endpoint is tried first",
          _probe_urls("http://10.1.2.3:18081")[0] == "http://10.1.2.3:18081")

    # A fresh/offline chain quotes absurd fees. Detection must not present that
    # as a found daemon without saying so.
    real = c.live_fees
    try:
        c.live_fees = lambda u, p="": (
            {"ok": True, "xmr": [4.0, 16.0, 80.0, 664.0], "implausible": True}
            if u.endswith("28081") else {"ok": False, "xmr": None})
        r = c.detect_daemon("", "")
        check("an implausible-fee daemon is flagged, not silently accepted",
              r["ok"] and "do NOT treat these numbers as real" in r["detail"])
        # ... and a believable node must win over the implausible one.
        c.live_fees = lambda u, p="": (
            {"ok": True, "xmr": [0.00004, 0.0001, 0.0005, 0.004], "implausible": False}
            if u.endswith("18089") else
            {"ok": True, "xmr": [664.0], "implausible": True} if u.endswith("18081")
            else {"ok": False, "xmr": None})
        r = c.detect_daemon("", "")
        check("a plausible daemon is preferred over an implausible one",
              r["ok"] and r["daemon"].endswith("18089"))
    finally:
        c.live_fees = real

    # And with nothing anywhere, it must still refuse to invent numbers.
    try:
        c.live_fees = lambda u, p="": {"ok": False, "xmr": None}
        r = c.detect_daemon("", "")
        check("with no daemon at all it reports failure, inventing nothing",
              r["ok"] is False and r["daemon"] is None)
        check("the failure explains a remote node is queried over Tor",
              "through Tor" in r["detail"])
    finally:
        c.live_fees = real


def test_split_bound_is_one_number():
    """The console's --split ceiling must EQUAL gs_common.MAX_SPLIT.

    The console offered up to 20 while GhostSpiral refuses above 8, so the web
    form accepted a value the pipeline rejected -- after the operator had
    filled it in. gs_common owns the number now; SCHEMA carries a literal
    because it is built at import time and the console loads gs_common lazily.
    This is what stops the literal drifting: a comment asking two numbers to
    stay in sync is a hope, not a guarantee, and these two had already drifted.
    """
    c = load_console()
    l = importlib.machinery.SourceFileLoader(
        "gs_common_bound", os.path.join(REPO, "gs_common.py"))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name, l))
    l.exec_module(m)
    _lo, _hi = c.SCHEMA["split"][1]
    check("split bound: the console ceiling EQUALS gs_common.MAX_SPLIT",
          _hi == m.MAX_SPLIT)
    check("split bound: ...and the HTML number input offers the same maximum",
          f'id="split" type="number" min="1" max="{m.MAX_SPLIT}"'
          in open(os.path.join(REPO, "gs_console")).read())
    # Behavioural, not just the constant: clean() drops an out-of-range int.
    check("split bound: a value ABOVE it never reaches an argv",
          c.clean({"split": m.MAX_SPLIT + 1})["params"].get("split") is None)
    check("split bound: ...and the maximum itself does",
          c.clean({"split": m.MAX_SPLIT})["params"].get("split") == m.MAX_SPLIT)
    check("split bound: --split 1 (the default) is accepted",
          c.clean({"split": 1})["params"].get("split") == 1)
    check("split bound: 0 is rejected",
          c.clean({"split": 0})["params"].get("split") is None)
    # And the value actually reaches the pipeline argv when > 1.
    # pipeline_argv returns (argv, errors) -- take the argv.
    argv = c.pipeline_argv({"split": 3, "wallets": 6,
                            "tor_proxy": "socks5h://127.0.0.1:9050"})[0]
    check("split bound: a valid split is passed through to the pipeline",
          "--split" in argv and argv[argv.index("--split") + 1] == "3")
    # ...and an out-of-range one is DROPPED by clean(), which is the only way
    # params reach pipeline_argv in the server (every handler passes
    # clean(...)["params"], and the ACTIONS build lambdas are called with
    # c["params"] too). pipeline_argv itself does no range checking, so this
    # goes through the real path rather than calling it with raw input --
    # asserting on raw input would report a bug the shipped code does not have.
    _bad = c.clean({"split": m.MAX_SPLIT + 1, "wallets": 6,
                    "tor_proxy": "socks5h://127.0.0.1:9050"})
    check("split bound: an out-of-range split is dropped with a stated reason",
          "split" not in _bad["params"]
          and any("split" in e for e in _bad["errors"]))
    check("split bound: ...so it reaches no argv, and does not silently become "
          "some other number either",
          "--split" not in c.pipeline_argv(_bad["params"])[0])


def test_job_timeout_cannot_kill_a_live_pipeline():
    """The console's job timeout must exceed what GhostSpiral can legitimately take.

    It was 4 * 3600 with the comment "nothing legitimate runs longer". The
    pipeline it drives says otherwise in its own constants: the swap-arrival
    wait alone is capped at XMR_ARRIVAL_TIMEOUT (24h), the fan-out confirm adds
    FANOUT_CONFIRM_TIMEOUT, and --hop-delay accepts up to HOP_DELAY_MAX (7 days)
    PER HOP. A cross-chain BTC->XMR swap settling inside four hours is the lucky
    case, so the console was killing correct runs at the exact moment they were
    waiting on money.

    Same enforcement as the split bound above, and for the same reason: the
    console is stdlib-only and does not import GhostSpiral, so the number is a
    literal and a comment asking two numbers to agree is a hope.
    """
    c = load_console()
    l = importlib.machinery.SourceFileLoader(
        "ghost_timeout", os.path.join(REPO, "GhostSpiral"))
    g = importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name, l))
    l.exec_module(g)
    floor = g.XMR_ARRIVAL_TIMEOUT + g.FANOUT_CONFIRM_TIMEOUT + g.HOP_DELAY_MAX
    check(f"job timeout: the console allows at least the arrival wait + fan-out "
          f"confirm + one max hop delay ({floor}s)",
          c.JOB_TIMEOUT_FLOOR_S >= floor)
    check("job timeout: ...and the default is that floor, not something shorter",
          c.JOB_TIMEOUT_S >= floor)
    check("job timeout: the old 4h value would NOT have satisfied this "
          "(control: the check is not vacuous)", 4 * 3600 < floor)


def test_watchdog_lets_the_job_clean_up_before_killing_it():
    """A timed-out job must get SIGTERM first, or its secrets stay on disk.

    The watchdog sent SIGKILL, which cannot be caught, so none of the child's
    `finally` blocks ran -- and those are what erase the wallet spend-key
    password (four sites in airgap_tx_signer), the exit plan carrying
    --exit-to, the peel and change-sweep plans, and the staging trees of signed
    blobs. A run that timed out left all of it in plaintext on disk.

    Every tool installs a SIGTERM handler via gs_common.install_signal_handlers,
    and the manual stop button has always relied on that. The watchdog was the
    one path that did not -- and the only one that fires unattended.

    Driven against the REAL start() with a child that behaves like the tools do:
    it writes a secret, handles SIGTERM, and erases the secret in a finally.
    """
    c = load_console()
    d = tempfile.mkdtemp(prefix="gs_wd_")
    secret = os.path.join(d, "secret")
    child = os.path.join(d, "child.py")
    with open(child, "w") as fh:
        fh.write(
            "import signal, sys, time, pathlib\n"
            "s = pathlib.Path(sys.argv[1]); s.write_text('WALLET-PASSWORD')\n"
            "st = {'v': False}\n"
            "signal.signal(signal.SIGTERM, lambda *a: st.__setitem__('v', True))\n"
            "print('up', flush=True)\n"
            "try:\n"
            "    while not st['v']: time.sleep(0.1)\n"
            "finally:\n"
            "    s.unlink(missing_ok=True); print('cleaned', flush=True)\n")
    _saved = (c.JOB_TIMEOUT_S, c.JOB_TERM_GRACE_S)
    try:
        c.JOB_TIMEOUT_S, c.JOB_TERM_GRACE_S = 2, 15
        jid = c.start([sys.executable, child, secret], "wd-test")
        for _ in range(400):
            if c.JOBS[jid]["done"]:
                break
            time.sleep(0.25)
    finally:
        c.JOB_TIMEOUT_S, c.JOB_TERM_GRACE_S = _saved
    j = c.JOBS[jid]
    out = "\n".join(j["lines"])
    check("watchdog: the timed-out job actually ended", j["done"])
    check("watchdog: it was asked to stop (SIGTERM), not SIGKILLed outright",
          "SIGTERM" in out)
    check("watchdog: the child's cleanup RAN — this is the whole point",
          "cleaned" in out)
    check("watchdog: ...so the secret it was holding is GONE from disk "
          "(SIGKILL left the wallet password and the exit plan behind)",
          not os.path.exists(secret))
    check("watchdog: ...and it did not need the SIGKILL escalation",
          j["rc"] == 0)


def test_fee_panel_answers_the_setting_the_operator_is_changing():
    """The fee shown must move when --wallets or --deep move.

    live_fees took only (daemon_url, tor_proxy) and returned the PER-TRANSACTION
    fee, while the operator was choosing the two settings that decide how many
    transactions there are. So the panel could not change when they did, and an
    operator reported exactly that: "the fee doesn't change even if I up the
    wallets or depth".

    It is not a rounding difference. At the real priority-1 fee of 0.0024:

        3 wallets  · depth 1     6 rounds     0.0216 XMR
        20 wallets · depth 2    80 rounds     0.288  XMR
        60 wallets · depth 6   720 rounds     2.592  XMR

    a 120x span on settings picked by clicking a preset.

    compute_fee_budget is IMPORTED from GhostSpiral, not reimplemented -- the
    console has drifted from the orchestrator twice already (the --split
    ceiling, the job timeout) and both times the copy was the bug.
    """
    c = load_console()
    l = importlib.machinery.SourceFileLoader(
        "ghost_fees", os.path.join(REPO, "GhostSpiral"))
    g = importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name, l))
    l.exec_module(g)

    per = [0.0024, 0.0094, 0.038, 0.48]
    seen = {}
    for w, d in ((3, 1), (10, 2), (20, 2), (60, 6)):
        rounds, totals = c._run_totals(per, w, d)
        seen[(w, d)] = (rounds, totals)
        check(f"fee panel: {w} wallets/depth {d} produces a round count",
              rounds and rounds > 0)
    check("fee panel: the TOTAL changes when wallets/deep change "
          "(this is the whole defect)",
          len({t[1][0] for t in seen.values()}) == len(seen))
    check("fee panel: more wallets and more depth cost MORE, not less",
          seen[(3, 1)][1][0] < seen[(20, 2)][1][0] < seen[(60, 6)][1][0])
    # ...and it agrees with what the pipeline will actually reserve.
    from decimal import Decimal as _D
    _u, _f, _r = g.compute_fee_budget(_D("1000"), _D("0.0024"), 20, 2)
    check("fee panel: the total EQUALS the orchestrator's own reserve",
          abs(seen[(20, 2)][1][0] - float(_f)) < 1e-9
          and seen[(20, 2)][0] == _r)
    # Per-tx must stay per-tx: it is the number that legitimately does not move.
    check("fee panel: the per-transaction figure is unchanged by wallets/deep",
          per == [0.0024, 0.0094, 0.038, 0.48])
    # Missing/garbage settings must not invent a total.
    for bad in ((None, None), ("x", 2), (0, 2), (10, 0)):
        r_, t_ = c._run_totals(per, *bad)
        check(f"fee panel: {bad} yields no invented total", r_ is None and t_ is None)


def test_console_does_not_call_a_healthy_daemon_broken():
    """A real daemon's real fees must not be flagged as a fresh/offline chain.

    _flag_fees compares max(res["xmr"]) -- always the PRIORITY 4 figure --
    against FEE_PLAUSIBLE_MAX_XMR, which was 0.1, a priority-1 sized ceiling.
    A real monerod 0.18.3.1 returns fees = [1200000, 4700000, 19000000,
    240000000] piconero/byte = 0.0024 / 0.0094 / 0.038 / 0.48 XMR per ~2 kB tx,
    so 0.48 > 0.1 and the console announced "far above a real mainnet fee ...
    the daemon is on a fresh or offline chain. Do NOT treat these as real
    costs" -- about correct numbers from a working node.

    And GhostSpiral, the tool that actually spends, accepts them: its
    FEE_IMPLAUSIBLE_XMR is 1.0. The console warned about a fee the pipeline
    would spend against, which teaches the operator to ignore the panel.
    """
    c = load_console()
    l = importlib.machinery.SourceFileLoader(
        "ghost_imp", os.path.join(REPO, "GhostSpiral"))
    g = importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name, l))
    l.exec_module(g)
    check("fee ceiling: the console and the SPENDING tool use one number",
          float(c.FEE_PLAUSIBLE_MAX_XMR) == float(g.FEE_IMPLAUSIBLE_XMR))

    def per_tx(fees):
        return [round(f * 2000 / 1e12, 6) for f in fees]

    real = c._flag_fees({"ok": True, "xmr": per_tx(
        [1200000, 4700000, 19000000, 240000000])})
    check("fee ceiling: a REAL mainnet daemon is not called broken",
          not real.get("implausible"))
    check("fee ceiling: ...and gets no scary warning",
          not real.get("warning"))
    # The true positive must survive: a fresh/offline daemon reports ~2e9
    # piconero/byte, i.e. ~4 XMR per transaction.
    fresh = c._flag_fees({"ok": True, "xmr": per_tx([2000000000] * 4)})
    check("fee ceiling: a FRESH/offline daemon is STILL flagged "
          "(control: the check was not just switched off)",
          fresh.get("implausible") is True)
    check("fee ceiling: ...and still says why", "fresh or offline"
          in (fresh.get("warning") or ""))


def test_console_can_express_the_timing_parameter():
    """The dashboard must be able to set --hop-delay. It could not.

    SCHEMA is the whitelist -- "Anything not here cannot reach an argv" -- and
    hop_delay was absent from it, so EVERY dashboard-driven run was pinned to
    GhostSpiral's DEFAULT_HOP_DELAY of 180-720s, silently, with no control and
    no mention that it mattered.

    GhostSpiral's own --hop-delay help calls it "AN OPSEC PARAMETER" and says
    the default spends each carrier output "at roughly 11-16 blocks of age --
    close to the youngest an output can legally be spent", while Monero draws
    ring decoys from a distribution "whose bulk sits far above that" -- so the
    real output tends to be the newest member of its own ring. It recommends
    21600-86400. The CLI accepts up to HOP_DELAY_MAX (7 days). The dashboard
    offered exactly one value, the weakest, and every run from the page carried
    the same short timing signature.
    """
    c = load_console()
    l = importlib.machinery.SourceFileLoader(
        "ghost_hd", os.path.join(REPO, "GhostSpiral"))
    g = importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name, l))
    l.exec_module(g)

    check("hop delay: the console whitelist admits it at all",
          "hop_delay" in c.SCHEMA)

    def argv_for(v):
        p = {"mode": "receive", "receive_wallet": "w.json",
             "tor_proxy": "socks5h://127.0.0.1:9050",
             "rpc_daemon": "http://127.0.0.1:18081",
             "rpc_primary": "http://127.0.0.1:18083",
             "wallets": 10, "deep": 2, "fee_priority": 1}
        if v is not None:
            p["hop_delay"] = v
        cl = c.clean(p)
        a, _why = c.pipeline_argv(cl["params"])
        return a, cl["errors"]

    a, _ = argv_for("21600-86400")
    check("hop delay: a range reaches the argv",
          "--hop-delay" in a and a[a.index("--hop-delay") + 1] == "21600-86400")
    a, _ = argv_for("600")
    check("hop delay: a single value reaches the argv",
          "--hop-delay" in a and a[a.index("--hop-delay") + 1] == "600")

    # OMITTED means GhostSpiral's default, not a copy of it here. Re-declaring
    # the default in the console is how the --split ceiling and the job timeout
    # both drifted.
    a, _ = argv_for(None)
    check("hop delay: unset omits the flag, so the default lives in ONE place",
          "--hop-delay" not in a)
    a, _ = argv_for("")
    check("hop delay: ...and an empty choice does the same", "--hop-delay" not in a)

    # Garbage must not reach an argv that ends in a spend.
    for bad in ("abc", "-5", "12-9999999999", "1 2", "600;rm -rf /"):
        a, errs = argv_for(bad)
        check(f"hop delay: {bad!r} is refused and never reaches the argv",
              "--hop-delay" not in a and any("hop_delay" in e for e in errs))

    # The console regex is deliberately looser than the real cap; GhostSpiral
    # owns the bound and must still enforce it, with its own message.
    check("hop delay: the console accepts 7 digits...",
          bool(c.HOPDELAY_RE.match("9999999")))
    try:
        g.parse_hop_delay("9999999")
        check("hop delay: ...and GhostSpiral enforces HOP_DELAY_MAX", False)
    except ValueError as e:
        check("hop delay: ...and GhostSpiral enforces HOP_DELAY_MAX on it",
              str(g.HOP_DELAY_MAX) in str(e))
    # Everything the console offers must actually parse.
    import re as _re
    for opt in _re.findall(r'<option value="([^"]*)"', c.PAGE if hasattr(c, "PAGE") else ""):
        if not opt:
            continue
        if c.HOPDELAY_RE.match(opt):
            try:
                g.parse_hop_delay(opt)
                ok = True
            except ValueError:
                ok = False
            check(f"hop delay: the offered option {opt!r} is accepted by "
                  f"GhostSpiral", ok)


def test_console_can_express_the_expected_total():
    """The dashboard must be able to say how much XMR the run is waiting for.

    Same shape as the hop_delay omission above, in the place where it costs
    money rather than ring-age plausibility. SCHEMA is the whitelist --
    "Anything not here cannot reach an argv" -- and expect_total_xmr was not in
    it, so no dashboard-driven run could ever set a target.

    In RECEIVE mode that is the entire gate. GhostSpiral's stage 4 branches on
    `args.expect_total_xmr is None` and, with no target, prints "this run does
    NOT wait" and plans against whatever is on ENTRY at that instant. A
    dashboard receive run paid by four swaps therefore starts mixing on the
    first one to land: the veil sweeps it, the distribution sizes itself from
    it, and chunks two to four arrive on an ENTRY the run has already finished
    with -- unmixed, on the address the swap memo names in public. The gate
    that refuses exactly this exists, and was reachable only from the CLI.
    """
    from decimal import Decimal
    c = load_console()
    l = importlib.machinery.SourceFileLoader(
        "ghost_et", os.path.join(REPO, "GhostSpiral"))
    g = importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name, l))
    l.exec_module(g)

    check("expected total: the console whitelist admits it at all",
          "expect_total_xmr" in c.SCHEMA)

    def argv_for(extra=None, mode="receive"):
        p = {"mode": mode, "tor_proxy": "socks5h://127.0.0.1:9050",
             "wallets": 10, "deep": 2, "fee_priority": 1}
        if mode == "receive":
            p["receive_wallet"] = "w.json"
        else:
            p["btc_entry"] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
            p["btc_amount"] = "0.05"
        p.update(extra or {})
        cl = c.clean(p)
        a, _why = c.pipeline_argv(cl["params"])
        return a, cl["errors"]

    a, _ = argv_for({"expect_total_xmr": "4.0", "split": 4})
    check("expected total: it reaches the argv",
          "--expect-total-xmr" in a
          and a[a.index("--expect-total-xmr") + 1] == "4.0")

    # --split is NOT dead in receive mode: stage4 computes n_chunks as
    # `len(swap_deposits) or max(args.split, 1)`, and receive mode has no
    # deposits -- so this IS the chunk count the arrival gate keys on. It was
    # only ever emitted in the send branch.
    check("expected total: the chunk count reaches the argv in RECEIVE mode too",
          "--split" in a and a[a.index("--split") + 1] == "4")

    # Unset must behave exactly as before.
    a, _ = argv_for()
    check("expected total: unset omits the flag, so behaviour is unchanged",
          "--expect-total-xmr" not in a)
    a, _ = argv_for({"expect_total_xmr": ""})
    check("expected total: ...and an empty field does the same",
          "--expect-total-xmr" not in a)

    # Send mode gets it too -- the fallback for an unreadable quote.
    a, _ = argv_for({"expect_total_xmr": "1.25"}, mode="send")
    check("expected total: send mode can set it as well",
          "--expect-total-xmr" in a)

    # Garbage must not reach an argv that ends in a spend.
    for bad in ("abc", "4.0;rm -rf /", "1 2", "$(id)", "--wallets"):
        a, errs = argv_for({"expect_total_xmr": bad})
        check(f"expected total: {bad!r} is refused and never reaches the argv",
              "--expect-total-xmr" not in a
              and any("expect_total_xmr" in e for e in errs))

    # AND GhostSpiral MUST ACCEPT WHAT THE CONSOLE BUILDS. A flag that passes
    # the console's own validation and then dies in argparse is worse than no
    # flag at all: it fails after the operator has filled the form in.
    a, _ = argv_for({"expect_total_xmr": "4.0", "split": 4})
    ns = g.build_cli().parse_args(a[2:])
    check("expected total: GhostSpiral's parser accepts the console's argv, "
          "with the value intact",
          ns.expect_total_xmr == Decimal("4.0") and ns.split == 4)
    check("expected total: ...and it is the type stage 4 compares against",
          isinstance(ns.expect_total_xmr, Decimal))

    # The field has to exist on the page, or the schema entry is unreachable.
    _page = getattr(c, "PAGE", "")
    check("expected total: the receive step actually offers the input",
          'id="expect_total_xmr"' in _page)
    check("expected total: ...and the page collects it into the request",
          "expect_total_xmr:v('expect_total_xmr')" in _page)
    # The send form's "Split into" input lives inside #send-fields, which is
    # HIDDEN in receive mode rather than removed -- so it is still in the DOM
    # and still reads 1. A receive-side count therefore needs its own field,
    # and collect() has to prefer it, or the send input shadows it forever and
    # every receive run reports one chunk no matter what the operator typed.
    check("expected total: receive mode has its own swap-count field",
          'id="split_recv"' in _page)
    check("expected total: ...and collect() prefers it in receive mode",
          "mode==='receive' ? (+v('split_recv')||1) : (+v('split')||1)"
          in _page)
    check("expected total: ...and the receive step does not point at a field "
          "that is hidden there",
          "set Split below" not in _page)

    # THE BUNDLE, so the operator does not retype the total at all. The page
    # already collects pairs_file for the watch step and it is the same file;
    # passing it lets GhostSpiral sum the swaps itself AND keep the per-swap
    # breakdown, which a typed total cannot carry.
    a, _ = argv_for({"pairs_file": "thor_pairs.json"})
    check("expected total: the pairs bundle reaches the argv in receive mode",
          "--swap-pairs" in a
          and a[a.index("--swap-pairs") + 1] == "thor_pairs.json")
    ns = g.build_cli().parse_args(a[2:])
    check("expected total: ...and GhostSpiral's parser takes it",
          ns.swap_pairs == "thor_pairs.json")
    a, _ = argv_for()
    check("expected total: ...and no bundle means no flag, unchanged",
          "--swap-pairs" not in a)


def test_daemon_chain_is_reported_not_assumed():
    """check_daemon_relay_egress must report WHICH chain the daemon is on.

    It has always called get_info and always discarded the nettype field. The
    wallet cannot answer this: regtest uses MAINNET address prefixes, so
    validate_address on a regtest wallet returns nettype "mainnet" for its own
    addresses and for real mainnet ones alike, and gs_common.validate_xmr_address
    checks format and checksum entirely offline without ever asking the wallet.
    Driven against a real monerod --regtest, the daemon said `fakechain` while
    every address check said mainnet.
    """
    import gs_common as _gc
    check("chain: the egress probe always carries a nettype key",
          "nettype" in _gc.check_daemon_relay_egress("http://127.0.0.1:1", None))
    check("chain: an unreachable daemon reports it as unknown, not a guess",
          _gc.check_daemon_relay_egress("http://127.0.0.1:1", None)["nettype"]
          == "unknown")


def test_fee_panel_says_which_chain_the_daemon_is_on():
    """The panel must name a non-mainnet chain, not only refuse it at Run.

    check_daemon_relay_egress already returns nettype and GhostSpiral's stage 0
    now refuses a non-mainnet daemon -- but the operator only learned that after
    filling in an exit address and clicking Run.

    It is easy to land on by accident: `monerod --regtest` with no port flag
    BINDS THE MAINNET PORT (its own log: "Binding on 127.0.0.1 (IPv4):18081"),
    so detect-daemon finds a fakechain at exactly the address already in the
    field, and its fee numbers look ordinary.

    The fee heuristic is not a substitute. Measured against real daemons:
        regtest  nettype=fakechain  fees [0.0024..0.48]   implausible False
        testnet  nettype=testnet    fees [4.0..664.0]     implausible True
        stagenet nettype=stagenet   fees [4.0..664.0]     implausible True
    -- it catches a FRESH testnet/stagenet only by accident (their fees are
    absurd because the chain is empty) and cannot see regtest at all, because
    regtest's fees are genuine.
    """
    c = load_console()
    # A non-mainnet chain is called out...
    for _nt in ("fakechain", "testnet", "stagenet"):
        r = c._flag_fees({"ok": True, "xmr": [0.0024, 0.0094, 0.038, 0.48],
                          "nettype": _nt})
        check(f"chain panel: {_nt} is named on the panel",
              _nt.upper() in (r.get("nettype_warning") or ""))
        check(f"chain panel: ...and it is NOT reported as an implausible fee "
              f"({_nt} fees can be real)", not r.get("implausible"))
    # ...mainnet is not nagged about.
    r = c._flag_fees({"ok": True, "xmr": [0.0024, 0.0094, 0.038, 0.48],
                      "nettype": "mainnet"})
    check("chain panel: mainnet gets no chain warning",
          not r.get("nettype_warning"))
    r = c._flag_fees({"ok": True, "xmr": [0.0024, 0.0094, 0.038, 0.48]})
    check("chain panel: an unknown chain is not invented as a warning",
          not r.get("nettype_warning"))
    # The fee implausibility check must still work independently of it.
    r = c._flag_fees({"ok": True, "xmr": [4.0, 4.0, 4.0, 4.0],
                      "nettype": "mainnet"})
    check("chain panel: a fresh/offline daemon's absurd fee is STILL flagged",
          r.get("implausible") is True)
    # And the warning names the trap that makes this reachable at all.
    r = c._flag_fees({"ok": True, "xmr": [0.0024], "nettype": "fakechain"})
    check("chain panel: the warning names the regtest-binds-18081 trap",
          "18081" in (r.get("nettype_warning") or ""))
    check("chain panel: ...and names the flag that would allow it",
          "--allow-test-chain" in (r.get("nettype_warning") or ""))


def run_all():
    for fn in sorted([f for n, f in globals().items() if n.startswith("test_")],
                     key=lambda f: f.__name__):
        try:
            fn()
        except Exception as e:
            check(f"{fn.__name__} raised {type(e).__name__}: {str(e)[:60]}", False)
    print(f"\n  console: {PASS} passed, {FAIL} failed")
    if FAILURES:
        for f in FAILURES:
            print(f"    - {f}")
    return FAIL


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
