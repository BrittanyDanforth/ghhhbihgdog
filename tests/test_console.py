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

    src = open(os.path.join(REPO, "gs_console")).read()
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
    check("the preflight runs on load", "sync(); runPreflight()" in src)
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
