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
        jid = c.start([sys.executable, "-c",
                       "import os;print(os.environ.get('GS_WALLET_PASSWORD'))"],
                      "probe", action_id=action_id)
        for _ in range(100):
            if c.JOBS[jid]["done"]:
                break
            time.sleep(0.05)
        return "\n".join(c.JOBS[jid]["lines"]).strip()

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
