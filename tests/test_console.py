#!/usr/bin/env python3
"""Executable tests for gs_console — the surface that can spend money.

Drives the real module: the real _child_env, the real live_fees, the real
action builders, and the real HTTP handler over a real socket on 127.0.0.1.
Confirmed to FAIL against the pre-fix build.
"""
import sys, os, json, time, socket, threading, subprocess, tempfile
import contextlib, io
import re as _re_c
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
    """Strip the GS_ secrets, keep everything else.

    The marker used to be GS_TEST_MARKER, which asserted the OPPOSITE of what
    the console now does. _child_env popped only GS_WALLET_PASSWORD, so every
    other GS_ variable reached every child -- and OPSEC_SETUP.md tells the
    operator to export GS_EXIT_TO and GS_BTC_ENTRY in the shell they start the
    console from, so those were inherited by the unit suites, py_compile,
    paranoia_mode and the disk-leak audit. GhostSpiral's own _child_env already
    default-denies the whole GS_ prefix to its children for exactly this
    reason. PATH and the rest of the environment are untouched.
    """
    c = load_console(SECRET)
    os.environ["CONSOLE_TEST_MARKER"] = "keepme"
    os.environ["GS_EXIT_TO"] = "shell_exported_exit_address"
    try:
        env = c._child_env("units")
        check("stripping the secrets leaves the rest of the environment",
              env.get("CONSOLE_TEST_MARKER") == "keepme" and "PATH" in env)
        check("a GS_ value exported in the operator's own shell does NOT "
              "reach a child that has no business with it",
              "GS_EXIT_TO" not in env)
        check("...and no GS_ variable at all survives into such a child",
              not [k for k in env if k.startswith("GS_")])
        check("the pipeline child still gets the password",
              c._child_env("run_pipeline").get("GS_WALLET_PASSWORD") == SECRET)
        check("...and no GS_ variable it was not allow-listed for",
              not [k for k in c._child_env("run_pipeline")
                   if k.startswith("GS_")
                   and k not in c.ACTION_SECRETS["run_pipeline"]
                   and k != "GS_WALLET_PASSWORD"])
        check("the real environment is not mutated",
              os.environ.get("GS_WALLET_PASSWORD") == SECRET
              and os.environ.get("GS_EXIT_TO")
              == "shell_exported_exit_address")
    finally:
        os.environ.pop("CONSOLE_TEST_MARKER", None)
        os.environ.pop("GS_EXIT_TO", None)


def test_secrets_are_scoped_to_the_actions_that_need_them():
    """secret_env's values must reach ONLY the action that reads them.

    secret_env's own docstring calls the exit destination "the value with the
    most to lose" and exists to keep these four off argv -- and start() then
    did `env.update(extra_env or {})` unconditionally, so a click on "Unit
    suite", "Compile all" or "Wipe preview" handed that child the operator's
    final withdrawal address, their Bitcoin entry address and the sum being
    moved. Verified by building the environment each action would actually get.

    swap_quote's GS_EXIT_TO is deliberate: thor_swap_preparer reads it to
    refuse a swap whose destination is also the exit destination, which would
    publish that address in a Bitcoin OP_RETURN.
    """
    c = load_console()
    se = c.secret_env({"btc_entry": "bc1x", "btc_amount": "0.4",
                       "swap_btc": "0.4", "expect_total_xmr": "1.25",
                       "exit_to": ["EXIT_A", "EXIT_B"]})
    check("secret_env still produces the four values",
          set(se) == {"GS_BTC_ENTRY", "GS_BTC_AMOUNT", "GS_SWAP_AMOUNTS",
                      "GS_EXIT_TO", "GS_EXPECT_TOTAL_XMR"})

    def child_env(aid):
        env = c._child_env(aid)
        for k, v in se.items():
            if k in c.ACTION_SECRETS.get(aid, ()):
                env[k] = v
        return {k: v for k, v in env.items() if k.startswith("GS_")}

    for aid in ("units", "integration", "ipleak", "compile", "paranoia_dry",
                "leakaudit", "make_receive", "watch_receive",
                "preflight_tor", "preflight_egress", "preflight_wallet"):
        check(f"'{aid}' gets NO secret at all", child_env(aid) == {})
    _rp = child_env("run_pipeline")
    check("the pipeline gets the entry, the amount, the total and the exit",
          _rp.get("GS_EXIT_TO") == "EXIT_A EXIT_B"
          and _rp.get("GS_BTC_ENTRY") == "bc1x"
          and _rp.get("GS_BTC_AMOUNT") == "0.4"
          and _rp.get("GS_EXPECT_TOTAL_XMR") == "1.25")
    _sq = child_env("swap_quote")
    check("the swap quote gets the swap amounts, and GS_EXIT_TO only because "
          "thor_swap_preparer reads it to refuse a colliding destination",
          set(_sq) == {"GS_SWAP_AMOUNTS", "GS_EXIT_TO"})
    check("...and that really is why -- the tool reads the variable",
          "GS_EXIT_TO" in open(
              os.path.join(REPO, "thor_swap_preparer")).read())
    check("an unknown action id is denied everything", child_env(None) == {})
    check("start() filters extra_env through the allow-list rather than "
          "updating with all of it",
          "if _k in _allowed:" in open(
              os.path.join(REPO, "gs_console")).read())


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
        # A NON-ASCII TOKEN USED TO KILL THE REQUEST THREAD, BEFORE
        # AUTHENTICATION. hmac.compare_digest raises TypeError on non-ASCII str
        # operands, and this one comes straight off the wire -- so any
        # unauthenticated local process could kill a handler thread at will and
        # fill the operator's terminal with tracebacks during a run.
        # Reproduced against the running server: "curl: (52) Empty reply from
        # server" and a TypeError out of do_GET.
        st, _ = s.req("GET", "/", headers={"X-GS-Token": "\u00e9abc"})
        check("a non-ASCII token is REJECTED, not a crashed request thread",
              st == 401)
        # No astral-character case: http.client encodes headers as latin-1 and
        # refuses to send one, so a normal client cannot produce it. The
        # latin-1 range above is what actually reaches the server, and it is
        # what reproduced the crash.
        st, _ = s.req("GET", "/", headers=s.auth())
        check("...and the server is still serving afterwards", st == 200)
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

    # A SEND RUN MUST NOT INHERIT THE LAST RECEIVE RUN'S ARRIVAL TARGET.
    #
    # secret_env sends expect_total_xmr in BOTH modes, deliberately: in send
    # mode it is the fallback for an unreadable quote, and there is a check for
    # that further down this file. The INPUT, though, lived only inside
    # #recv-fields -- which is HIDDEN in send mode, not removed -- so the
    # browser kept the operator's last receive value in the DOM and collect()
    # sent it with every send run, where it becomes GS_EXPECT_TOTAL_XMR: the
    # swap arrival gate. A stale target lower than the real total opens that
    # gate with a swap still in flight and the run starts mixing, and nothing
    # on the page in send mode displayed the number.
    #
    # The fix is not to stop sending it -- that would remove a capability the
    # code has and the suite pins. It is that each mode reads its OWN visible
    # box, the rule `split` already followed.
    _js = open(os.path.join(REPO, "gs_console")).read()
    check("send mode has its own VISIBLE total-expected input, outside the "
          "receive-only block",
          'id="expect_total_xmr_send"' in _js
          and _js.index('id="expect_total_xmr_send"')
          < _js.index('id="recv-fields"'))
    check("...and collect() reads whichever box the operator can actually see, "
          "never the hidden one",
          "mode==='receive' ? v('expect_total_xmr')" in _js
          and "v('expect_total_xmr_send')" in _js)
    check("...so the receive-only input is not the source in send mode",
          "expect_total_xmr:v('expect_total_xmr')" not in _js.replace(" ", ""))

    # swap_btc, pairs_file and receive_wallet ARE sent in both modes, and that
    # is harmless rather than an oversight: ACTION_SECRETS scopes
    # GS_SWAP_AMOUNTS to the swap_quote action, and a send run is run_pipeline,
    # which never receives it. Pinned so nobody "fixes" the scoping away.
    check("GS_SWAP_AMOUNTS is scoped to swap_quote only, so a stale receive "
          "value cannot reach a send run whatever the page sends",
          "GS_SWAP_AMOUNTS" in c.ACTION_SECRETS["swap_quote"]
          and "GS_SWAP_AMOUNTS" not in c.ACTION_SECRETS["run_pipeline"])
    check("...while the arrival target IS scoped to the pipeline, which is why "
          "the visible-input rule above is the thing that protects it",
          "GS_EXPECT_TOTAL_XMR" in c.ACTION_SECRETS["run_pipeline"])

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
    # THE RUN SHAPE, not --deep. The reserve is now one fee per transaction the
    # run will actually relay, so it moves with --peel, --dag-mixing, an exit
    # destination and the chunk count -- and NOT with depth, which adds no
    # transactions. The panel listened only to wallets and deep, so turning
    # --peel on (roughly triples the transaction count) left the total stale.
    _SHAPES = [
        ("bare fan-out",   {"peel": False, "dag_mixing": False}),
        ("fan-out + DAG",  {"peel": False, "dag_mixing": True}),
        ("...with an exit", {"peel": False, "dag_mixing": True,
                             "exit_to": ["x"]}),
        ("peel + DAG + exit", {"peel": True, "dag_mixing": True,
                               "exit_to": ["x"]}),
    ]
    seen = {}
    for w in (3, 20, 60):
        for label, sh in _SHAPES:
            rounds, totals = c._run_totals(per, w, 2, sh)
            seen[(w, label)] = (rounds, totals)
            check(f"fee panel: {w} wallets, {label} produces a count",
                  rounds and rounds > 0)
    check("fee panel: the TOTAL changes when the SHAPE changes "
          "(this is the whole defect)",
          len({seen[(20, lb)][1][0] for lb, _ in
               [(x[0], x[1]) for x in _SHAPES]}) == len(_SHAPES))
    check("fee panel: more wallets cost MORE, not less",
          seen[(3, "peel + DAG + exit")][1][0]
          < seen[(20, "peel + DAG + exit")][1][0]
          < seen[(60, "peel + DAG + exit")][1][0])
    check("fee panel: a peel chain costs more than a fan-out at the same size",
          seen[(20, "peel + DAG + exit")][1][0]
          > seen[(20, "fan-out + DAG")][1][0] * 2)
    check("fee panel: --deep does NOT move it any more",
          c._run_totals(per, 20, 1, dict(_SHAPES[3][1]))[1]
          == c._run_totals(per, 20, 6, dict(_SHAPES[3][1]))[1])
    # ...and it agrees with what the pipeline will actually reserve.
    from decimal import Decimal as _D
    _u, _f, _r = g.compute_fee_budget(_D("1000"), _D("0.0024"), 20, peel=False,
                              dag_mixing=True, exit_set=False)
    check("fee panel: the total EQUALS the orchestrator's own reserve",
          abs(seen[(20, "fan-out + DAG")][1][0] - float(_f)) < 1e-9
          and seen[(20, "fan-out + DAG")][0] == _r)
    # A shape the panel is never told about must price the CHEAPEST run, not a
    # peel chain -- and the page must therefore actually send the shape.
    check("fee panel: the endpoint forwards the whole parameter set as the "
          "shape",
          'c["params"])))' in open(os.path.join(REPO, "gs_console")).read())
    # THE SET'S CONTENTS, NOT ITS FORMATTING. This matched the whole
    # `const FEE_FIELDS=new Set([...]);` line as one literal, so adding a field
    # to it -- the thing this check exists to encourage -- turned it red, and
    # so would rewrapping it. What the fee panel needs is that every field
    # which changes the run's shape is in the set; extra fields are not a
    # regression.
    _ff = _re_c.search(r"const FEE_FIELDS=new Set\(\[(.*?)\]\);",
                       c.PAGE, _re_c.S)
    _ffs = set(_re_c.findall(r"'([a-z_]+)'", _ff.group(1))) if _ff else set()
    check("fee panel: ...and the page refetches when the shape changes, not "
          "only on wallets/deep",
          {"wallets", "deep", "peel", "dag_mixing", "exit_to", "split",
           "split_recv"} <= _ffs
          and "if(FEE_FIELDS.has(el.id)) scheduleFees();" in c.PAGE)
    check("fee panel: NON-VACUITY -- the set was actually parsed out of the "
          "page, so the check above is not comparing against an empty set",
          len(_ffs) >= 7)
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


def test_every_settable_field_reaches_the_request():
    """collect() must read every SCHEMA field the page actually offers.

    --hop-delay was in SCHEMA (so the server would accept it), had a real
    dropdown (so the operator could choose one), and was set by every preset
    (so the strong ones stopped shipping the weakest value) -- and collect()
    never read the box. Every run launched from this page therefore went out at
    GhostSpiral's DEFAULT_HOP_DELAY whatever was selected.

    Three separate fixes to the same parameter, each verified at its own layer,
    and the one layer between them was checked by none of them. So this asserts
    the JOIN rather than another link: every key in SCHEMA that has an input on
    the page must appear in collect(), whatever it is.

    `output` and `label` are exempt and named here rather than pattern-matched:
    neither has a page field. label is deliberately absent -- the page used to
    hardcode 'GhostSpiral_entry', which stamped the tool's name into the wallet
    file, the one artifact paranoia_mode never deletes.
    """
    import re as _re
    c = load_console()
    _page = c.PAGE
    _collect = _page[_page.index("function collect()"):]
    _collect = _collect[:_collect.index("\n}")]
    _missing = []
    for _k in c.SCHEMA:
        if _k in ("output", "label", "mode"):
            continue
        # does the page even offer it?
        if f'id="{_k}"' not in _page:
            continue
        if _re.search(r"\b" + _re.escape(_k) + r"\s*:", _collect) is None:
            _missing.append(_k)
    check(f"collect: every SCHEMA field with an input on the page is sent "
          f"({_missing} are not)", not _missing)
    # ...and the one that was missing, by name, so the regression is legible.
    check("collect: the hop delay specifically", "hop_delay:v('hop_delay')"
          in _page)
    # NON-VACUITY: the scan must actually be looking at fields, not zero of
    # them.
    _seen = [k for k in c.SCHEMA
             if k not in ("output", "label", "mode") and f'id="{k}"' in _page]
    check(f"collect: ...and the scan really covered the page's fields "
          f"({len(_seen)} of them)", len(_seen) >= 12)


def test_every_settable_field_recomputes_the_page():
    """Editing any SCHEMA field must re-run the preview, the ETA and the fees.

    collect() sending a field is not enough: something has to CALL collect().
    The page does that from one delegated listener,

        $$('input,select,textarea').forEach(el=>el.addEventListener('input', ...

    and that selector used to read `input,select`. exit_to is the page's only
    <textarea>, so the ONE field that changes the run's size the most was the
    one field whose edits recomputed nothing. Measured by driving the shipped
    page in a browser at the "Maximum safe" preset:

        exit_to empty                35 transactions  ~2.1 days
        three exit addresses typed   35 transactions  ~2.1 days   <- the
                                     operator's view, and the line still read
                                     "(no exit destination set, so no
                                     withdrawals are counted)" with three of
                                     them in the box
        after touching any other     52 transactions  ~3.0 days   <- the truth
        control

    17 transactions and about 21 hours missing. run_eta's own docstring is
    about why that number matters: an operator told the wrong one "concludes
    the run has hung and interrupts it -- and an interrupt mid-round is the one
    failure this pipeline has no automatic recovery from". FEE_FIELDS names
    exit_to for the same reason and never fired either, so the reserved-fee
    panel was stale on the shape change that adds one transaction per withdrawn
    output.

    Same family as the hop_delay defect above, one link further along: SCHEMA
    had it, the presets set it, collect() sent it, and nothing asked collect()
    for it. So this asserts THAT join: every control carrying a SCHEMA field id
    must be a tag the listener's selector actually matches.
    """
    import re as _re
    c = load_console()
    _page = c.PAGE
    _m = _re.search(r"\$\$\('([^']+)'\)\.forEach\(el=>el\.addEventListener\('input'",
                    _page)
    check("the delegated input listener was found (the scan is not vacuous)",
          _m is not None)
    _tags = {t.strip() for t in (_m.group(1) if _m else "").split(",")}
    _unbound = []
    _controls = {}
    for _k in c.SCHEMA:
        _mm = _re.search(r"<(input|select|textarea)\b[^>]*id=\"%s\"" % _re.escape(_k),
                         _page)
        if not _mm:
            continue
        _controls[_k] = _mm.group(1)
        if _mm.group(1) not in _tags:
            _unbound.append(f"{_k} (<{_mm.group(1)}>)")
    check(f"every SCHEMA control on the page is bound to the recompute "
          f"listener ({_unbound} are not)", not _unbound)
    check(f"...and the scan really walked the page's controls "
          f"({len(_controls)} found)", len(_controls) >= 12)
    # The selector must cover the tags the page ACTUALLY uses, as a set --
    # not "textarea, because exit_to happens to be one today". Pinning the tag
    # would fail the day someone legitimately makes it a single-line input,
    # which is a refactor, not a regression.
    _used = set(_controls.values())
    check(f"the listener's selector covers every tag the page's SCHEMA "
          f"controls use ({sorted(_used - _tags)} uncovered)",
          not (_used - _tags))
    # The field that was unbound, by name, so a revert reads as itself.
    check("the exit destinations reach the recompute listener",
          "exit_to" in _controls and _controls["exit_to"] in _tags)
    # FEE_FIELDS is keyed on el.id from that same listener, so a field the
    # listener never sees can be in FEE_FIELDS and still never refresh a fee.
    check("exit_to is in FEE_FIELDS, and now actually reaches it",
          "'exit_to'" in _page and "if(FEE_FIELDS.has(el.id)) scheduleFees();"
          in _page)


def test_presets_set_the_hop_delay():
    """A preset must set the delay, and applyPreset must apply it.

    applyPreset set wallets, depth, DAG, peel, priority and clearnet, and never
    the delay -- so the preset whose note opens "MAXIMUM SAFETY" ran at the
    dropdown's own "WEAKEST" option, silently. The delay was made REACHABLE
    earlier in this audit (it was not in SCHEMA at all); this is the other
    half, because a preset that leaves it alone is what everyone who does not
    know the parameter exists actually runs.
    """
    import re as _re
    c = load_console()
    _l = importlib.machinery.SourceFileLoader(
        "ghost_pre", os.path.join(REPO, "GhostSpiral"))
    g = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(_l.name, _l))
    _l.exec_module(g)
    _pre = c.PAGE[c.PAGE.index("const PRESETS={"):]
    _pre = _pre[:_pre.index("};") + 2]
    names = _re.findall(r"\n ([a-z]+):\{", _pre)
    check("presets: the block parses into entries", len(names) >= 5)
    _missing = [n for n in names
                if not _re.search(n + r":\{[^}]*hop_delay:", _pre)]
    check(f"presets: every one names a hop_delay ({_missing} do not)",
          not _missing)
    # ...and the strong ones must not name the weak default. `fast` is allowed
    # to: it is the preset whose whole point is speed, and it says so.
    for n in ("paranoid", "peel", "balanced", "churn", "max", "lowfee"):
        m = _re.search(n + r":\{[^}]*hop_delay:'([^']*)'", _pre)
        check(f"presets: {n} sets a real delay, not the weak default",
              bool(m and m.group(1)))
        if m and m.group(1):
            try:
                g.parse_hop_delay(m.group(1))
                _ok = True
            except ValueError:
                _ok = False
            check(f"presets: ...and {n}'s value parses", _ok)
            check(f"presets: ...and {n}'s value is offered in the dropdown",
                  f'<option value="{m.group(1)}"' in c.PAGE)
    check("presets: applyPreset assigns it UNCONDITIONALLY, so switching away "
          "from a slow preset relaxes it again",
          "$('#hop_delay').value=c.hop_delay||''" in c.PAGE)


def _ghost_for_eta():
    _l = importlib.machinery.SourceFileLoader(
        "ghost_eta", os.path.join(REPO, "GhostSpiral"))
    _m = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(_l.name, _l))
    _l.exec_module(_m)
    return _m


def test_the_receive_flow_arms_its_own_arrival_gate():
    """Three actions read pairs_file. Only two defaulted it.

    swap_quote WRITES the quotes to thor_pairs.json when the box is empty and
    watch_receive WAITS against thor_pairs.json when the box is empty --
    pipeline_argv passed --swap-pairs only when the box was NOT empty. So the
    standard dashboard receive flow (click all three, type nothing) produced a
    quote file, waited on it, and then ran the mix with no target at all:
    GhostSpiral's receiver branch reads `args.expect_total_xmr is None` as
    "nothing to check", prints "this run does NOT wait", and plans against
    whatever is on ENTRY at that instant. Paid by four swaps it starts mixing
    on the first, and the other three land on an address the run has finished
    with -- unmixed, on the address the swap memo names in public.

    Adding expect_total_xmr to SCHEMA made that gate reachable. It did not arm
    it, and the page reported no problem, because nothing was missing as far as
    pipeline_argv was concerned.
    """
    c = load_console()
    base = {"mode": "receive", "receive_wallet": "w.json",
            "tor_proxy": "socks5h://127.0.0.1:9050", "wallets": 10, "deep": 2}
    a, why = c.pipeline_argv(c.clean(base)["params"])
    check("receive: the blank bundle field still reaches the run",
          "--swap-pairs" in a
          and a[a.index("--swap-pairs") + 1] == c.DEFAULT_PAIRS_FILE)
    check("receive: ...and it is the SAME default the quote and watch steps "
          "use",
          c.ACTIONS["swap_quote"]["build"](c.clean(base)["params"])[-1]
          == c.DEFAULT_PAIRS_FILE
          and c.DEFAULT_PAIRS_FILE
          in c.ACTIONS["watch_receive"]["build"](c.clean(base)["params"]))
    check("receive: an explicit bundle still wins over the default",
          c.pipeline_argv(c.clean(dict(base, pairs_file="other.json"))
                          ["params"])[0][
              c.pipeline_argv(c.clean(dict(base, pairs_file="other.json"))
                              ["params"])[0].index("--swap-pairs") + 1]
          == "other.json")
    # SEND mode must not get it: GhostSpiral prints "--swap-pairs is ignored in
    # SEND mode" and logs swap_pairs_ignored_send_mode.
    _snd = {"mode": "send", "btc_entry": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "btc_amount": "0.05", "tor_proxy": "socks5h://127.0.0.1:9050"}
    check("receive: send mode is not given a bundle it would only ignore",
          "--swap-pairs" not in c.pipeline_argv(c.clean(_snd)["params"])[0])
    # A missing bundle must stay non-fatal, or defaulting it would break every
    # run that legitimately has no quotes.
    g = _ghost_for_eta()
    _rp = g._receive_pairs_for.__doc__ or ""
    check("receive: ...and passing a bundle that is not there is NEVER FATAL",
          "NEVER FATAL" in _rp)

    # THE ADVISORY. A targetless receive run is legal, so it cannot be a
    # `problem` (those stop the spend) -- but an empty problem list reads as
    # "everything is set", which is how this stayed invisible.
    import os as _os
    _pf = _os.path.join(REPO, c.DEFAULT_PAIRS_FILE)
    _had = _os.path.exists(_pf)
    if not _had:
        _notes = c.run_notes(c.clean(base)["params"])
        check("receive: with no bundle and no total, the page SAYS the run "
              "will not wait",
              any("NOT WAIT" in n for n in _notes))
        check("receive: ...and says what to do about it",
              any("Get the BTC deposit address" in n for n in _notes))
    _notes2 = c.run_notes(c.clean(dict(base, expect_total_xmr="1.5"))["params"])
    check("receive: a typed total silences the no-target advisory",
          not any("NOT WAIT" in n for n in _notes2))
    check("receive: the advisory never blocks the run",
          not c.pipeline_argv(c.clean(base)["params"])[1])
    check("receive: the endpoint returns the notes and the page renders them",
          '"notes": run_notes(c["params"])' in open(
              _os.path.join(REPO, "gs_console")).read()
          and "$('#notes').innerHTML" in c.PAGE and 'id="notes"' in c.PAGE)
    # ...and the single-exit advisory, which the exit itself also warns about
    # far later, when it is too late to add a destination.
    _one = c.run_notes(c.clean(dict(base, exit_to=["4" + "1" * 94]))["params"])
    check("receive: one exit destination is called out here too",
          any("ONE exit destination" in n for n in _one))
    check("receive: ...and no exit destination is called out as withdrawing "
          "nothing",
          any("nothing is withdrawn" in n for n in c.run_notes(
              c.clean(base)["params"])))


def test_eta_is_computed_by_the_shipped_estimator():
    """The page must state the wall clock, and get it from the pipeline.

    The delay dropdown carried hand-written run lengths ("6 - 24 h · days")
    while --hop-delay is PER TRANSACTION: at the console's own strongest preset
    that option is 61 transactions x ~15 h, about 38 days. GhostSpiral's
    estimate_runtime docstring says an operator who is told one duration and
    then waits far longer "concludes the run has hung and interrupts it -- and
    an interrupt mid-round is the one failure this pipeline has no automatic
    recovery from".
    """
    c = load_console()
    base = {"mode": "send", "tor_proxy": "socks5h://127.0.0.1:9050",
            "wallets": 10, "deep": 2, "peel": True, "dag_mixing": True,
            "exit_to": ["4" + "1" * 94]}
    fast = c.run_eta(dict(base, hop_delay=""))
    slow = c.run_eta(dict(base, hop_delay="21600-86400"))
    check("eta: the console answers with an estimate at all", bool(fast))
    check("eta: ...and it names the transaction count, not just a duration",
          "transactions" in fast)
    check("eta: a longer delay gives a longer run", fast != slow)
    check("eta: ...and the strongest option really is measured in days",
          "day" in slow)
    check("eta: no exit destination is said to be uncounted",
          "no exit destination" in c.run_eta(
              dict(base, exit_to=[], hop_delay="")))
    # THE HIGH END OF THE DECOY RANGE, so the estimate cannot come in under the
    # run. Understating is the direction that gets a live run interrupted, and
    # it is the direction the previous estimator failed in. The fee reserve
    # assumes the same count, so the two agree about the run's size.
    _g_eta = _ghost_for_eta()
    _n = int(c.run_eta(dict(base, hop_delay="")).split("About ")[1].split()[0])
    _exp = _g_eta._runtime_terms(
        type("S", (), {"peel": True, "dag_mixing": True, "exit_to": ["x"]}),
        1, 10 + _g_eta.DECOY_MAX, 0, 0)[1]
    check(f"eta: the count assumes DECOY_MAX decoys, like the fee reserve "
          f"({_n} vs {_exp})", _n == _exp)
    check("eta: ...and the fee reserve really does assume the same",
          "DECOY_MAX" in open(os.path.join(REPO, "GhostSpiral")).read()
          .split("def compute_fee_budget")[1].split("def ")[0])
    check("eta: the endpoint returns it, so the page has something to render",
          '"eta": run_eta(c["params"])' in open(
              os.path.join(REPO, "gs_console")).read())
    check("eta: ...and the page renders it into the slot next to the delay",
          "$('#eta').textContent=r.eta" in c.PAGE
          and 'id="eta"' in c.PAGE)


def test_page_regex_is_substituted():
    """The served page must carry a real regex, not the placeholder.

    The exit box's address filter is substituted from the server's own XMR_RE
    (gs_console._js_xmr_re) so the page cannot drift from what the run will
    actually accept -- it had drifted, and was still the pre-fix pattern that
    calls every integrated address and ~1.9% of real subaddresses invalid.

    Checked by FETCHING A PAGE, because the failure mode of a missing
    substitution is not a wrong regex, it is the literal text __XMR_RE__
    reaching the browser -- a JavaScript syntax error that kills every script
    on the dashboard. A source check cannot see that; deleting the .replace()
    left the source checks in test_send_gates green.
    """
    import re as _re
    s = Server()
    try:
        st, body = s.req("GET", "/", headers=s.auth())
        check("page: it is served", st == 200)
        txt = body.decode("utf-8", "replace")
        left = sorted(set(_re.findall(r"__[A-Z_]+__", txt)))
        check(f"page: no placeholder survives into the browser (found {left})",
              not left)
        _line = [l for l in txt.splitlines() if "const bad=uniq.filter" in l]
        check("page: the exit filter is present exactly once", len(_line) == 1)
        if _line:
            _m = _re.search(r"!(/.+/)\.test\(a\)", _line[0])
            check("page: ...and it carries a real JS regex literal", bool(_m))
            if _m:
                _served = _re.compile(_m.group(1)[1:-1])
                # It must agree with the server on the shapes that mattered.
                _real_sub = ("8C8RJR1fVGsfXbztYy7YddQ4NttvZNMG4G7m96y6kpu459"
                             "GKLjJ5VuH22cSrUWP1J5gr3N2dMyyk7CAdXDPoYt7nNgYZUYc")
                _real_int = ("4EX5Xd3Lk3V2nWjns2MKiUGpv3ZiqSeHAFhcWdmNJfADcFn8"
                             "c7yw6UvZuBYp9zxuzY7exzte6SNSSNYSevFaMS3f1xmuzjRK"
                             "qxwQ4xdAsX")
                for _a, _what in ((_real_sub, "an 8C subaddress"),
                                  (_real_int, "an integrated address")):
                    check(f"page: the SERVED regex accepts {_what}, as the "
                          f"server does",
                          bool(s.c.XMR_RE.match(_a))
                          and bool(_served.match(_a)))
                check("page: ...and still rejects a non-base58 character",
                      not _served.match("4" + "0" + "1" * 93))
    finally:
        s.close()


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
    # IT REACHES THE RUN THROUGH THE ENVIRONMENT, NOT THE COMMAND LINE.
    #
    # It was composed onto argv, which is the mistake --exit-to made two fields
    # along and secret_env exists to correct: /proc/<pid>/cmdline is mode 0444,
    # so an amount there is readable by every account on the host for the whole
    # life of a run that lasts hours. GhostSpiral's own --expect-total-xmr help
    # says so and prefers GS_EXPECT_TOTAL_XMR. The console had just been taught
    # to send this value at all, and sent it the exposed way.
    check("expected total: it does NOT reach the argv",
          "--expect-total-xmr" not in a)
    check("expected total: it reaches the child as GS_EXPECT_TOTAL_XMR",
          c.secret_env({"expect_total_xmr": "4.0"}).get("GS_EXPECT_TOTAL_XMR")
          == "4.0")
    check("expected total: ...and the pipeline action is allowed to see it",
          "GS_EXPECT_TOTAL_XMR" in c.ACTION_SECRETS["run_pipeline"])
    check("expected total: ...and nothing else is",
          not [k for k, v in c.ACTION_SECRETS.items()
               if k != "run_pipeline" and "GS_EXPECT_TOTAL_XMR" in v])

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
    check("expected total: unset sets no variable either",
          c.secret_env({}) == {})
    check("expected total: ...and an empty field does the same",
          "GS_EXPECT_TOTAL_XMR" not in c.secret_env({"expect_total_xmr": ""}))

    # Send mode gets it too -- the fallback for an unreadable quote.
    check("expected total: send mode can set it as well",
          c.secret_env({"expect_total_xmr": "1.25"}).get("GS_EXPECT_TOTAL_XMR")
          == "1.25")

    # Garbage must not reach the child at all -- clean() DROPS what it cannot
    # validate, so the check is that the value never survives validation, which
    # is what secret_env is fed from.
    for bad in ("abc", "4.0;rm -rf /", "1 2", "$(id)", "--wallets"):
        a, errs = argv_for({"expect_total_xmr": bad})
        _cl = c.clean({"expect_total_xmr": bad})
        check(f"expected total: {bad!r} is refused and never reaches the child",
              "--expect-total-xmr" not in a
              and not c.secret_env(_cl["params"])
              and any("expect_total_xmr" in e for e in errs))

    # AND GhostSpiral MUST ACCEPT WHAT THE CONSOLE BUILDS. A flag that passes
    # the console's own validation and then dies in argparse is worse than no
    # flag at all: it fails after the operator has filled the form in.
    a, _ = argv_for({"expect_total_xmr": "4.0", "split": 4})
    ns = g.build_cli().parse_args(a[2:])
    check("expected total: GhostSpiral's parser accepts the console's argv",
          ns.expect_total_xmr is None and ns.split == 4)
    # ...and the value the console now sends by environment must land on the
    # same attribute, with the same type stage 4 compares against. Moving it
    # off argv is only a fix if it still arrives.
    _old = os.environ.get("GS_EXPECT_TOTAL_XMR")
    os.environ.update(c.secret_env({"expect_total_xmr": "4.0"}))
    try:
        ns2 = g.build_cli().parse_args(a[2:])
        g.resolve_swap_arrival(ns2)
        check("expected total: the environment value reaches "
              "args.expect_total_xmr", ns2.expect_total_xmr == Decimal("4.0"))
        check("expected total: ...and it is the type stage 4 compares against",
              isinstance(ns2.expect_total_xmr, Decimal))
    finally:
        if _old is None:
            os.environ.pop("GS_EXPECT_TOTAL_XMR", None)
        else:
            os.environ["GS_EXPECT_TOTAL_XMR"] = _old

    # The field has to exist on the page, or the schema entry is unreachable.
    _page = getattr(c, "PAGE", "")
    check("expected total: the receive step actually offers the input",
          'id="expect_total_xmr"' in _page)
    check("expected total: ...and send mode offers one too, because secret_env "
          "sends the value in both modes and an input that exists in only one "
          "of them means the other reads a hidden box",
          'id="expect_total_xmr_send"' in _page)
    check("expected total: ...and the page collects it from whichever box the "
          "operator can actually see",
          "mode==='receive' ? v('expect_total_xmr')" in _page
          and "v('expect_total_xmr_send')" in _page)
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
    # A BLANK FIELD NOW MEANS THE DEFAULT BUNDLE, not "no flag". This used to
    # assert the opposite, and that was the defect: swap_quote writes to
    # thor_pairs.json when the box is empty and watch_receive reads it, so
    # only the pipeline ignored the file the flow had just produced -- and ran
    # with no arrival gate. See test_the_receive_flow_arms_its_own_arrival_gate.
    a, _ = argv_for()
    check("expected total: a blank bundle field falls back to the SAME file "
          "the quote and watch steps use",
          "--swap-pairs" in a
          and a[a.index("--swap-pairs") + 1] == c.DEFAULT_PAIRS_FILE)
    check("expected total: ...and send mode still gets no bundle",
          "--swap-pairs" not in argv_for(mode="send")[0])


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


def test_job_timeout_flag_actually_does_something():
    """--job-timeout was inert for every job the page can start.

    start() is called with timeout_s=job_timeout_for(params) from the HTTP
    handler, and job_timeout_for returned max(JOB_TIMEOUT_FLOOR_S, ...) -- a
    floor that never consulted JOB_TIMEOUT_S. Measured with --job-timeout 60:
    job_timeout_for({}) -> 694800, effective 694800. The flag's own help says
    "kill a job after this long".
    """
    c = load_console()
    _saved = (c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S)
    try:
        c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S = False, 60
        _big = c.job_timeout_for({"wallets": 60, "hop_delay": "86400-259200"})
        check("unset: the per-job estimate still scales with wallets x delay, "
              "which is the reason job_timeout_for exists",
              _big > c.JOB_TIMEOUT_FLOOR_S)
        check("unset: and the default job still gets the floor",
              c.job_timeout_for({}) >= c.JOB_TIMEOUT_FLOOR_S)
        c.JOB_TIMEOUT_EXPLICIT = True
        check("set: --job-timeout 60 actually bounds a default job",
              c.job_timeout_for({}) == 60)
        check("set: ...and the biggest job too, which is the one an operator "
              "would be trying to bound", c.job_timeout_for(
                  {"wallets": 60, "hop_delay": "86400-259200"}) == 60)
    finally:
        c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S = _saved
    _src = open(os.path.join(REPO, "gs_console")).read()
    check("the flag defaults to None, so 'not given' is distinguishable from "
          "'given the default'",
          'ap.add_argument("--job-timeout", type=int, default=None' in _src)
    check("...and setting it says so, because it now overrides an estimate "
          "the operator cannot see", "applies to EVERY job" in _src)


def test_job_timeout_override_says_when_it_is_the_shorter_number():
    """Typing the flag's own advertised default cut a 361-day job to 8 days.

    The help text called JOB_TIMEOUT_FLOOR_S (694800) the "default", and with
    default=None, typing that number is NOT the same as omitting it -- it
    became an override. Measured, wallets=60, hop_delay=86400-259200:

        omitted              -> 31_194_000 s = 361 days   (per-job estimate)
        --job-timeout 694800 ->    694_800 s =   8 days   (override wins)

    and the only warning fired BELOW the floor, so 694800 -- which IS the floor
    -- said nothing. The job is SIGKILLed on day 8 of a legitimate run, and
    job_timeout_for's own reason for existing is that "killing a live run
    strands funds and leaves secrets on disk".
    """
    c = load_console()
    _saved = (c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S)
    _big = {"wallets": 60, "hop_delay": "86400-259200"}
    try:
        c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S = False, 0
        _est = c.job_timeout_for(_big)
        c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S = True, c.JOB_TIMEOUT_FLOOR_S
        _buf = io.StringIO()
        with contextlib.redirect_stdout(_buf):
            _got = c.job_timeout_for(_big)
        _said = _buf.getvalue()
        check("the override still wins -- an explicit instruction is one",
              _got == c.JOB_TIMEOUT_FLOOR_S)
        check("...but typing the advertised default is NOT silent when it is "
              "shorter than the job's own estimate", "SHORTER" in _said)
        check("...and it names both numbers, so the operator can judge",
              str(c.JOB_TIMEOUT_FLOOR_S) in _said and str(_est) in _said)
        # NON-VACUITY: it must stay quiet when the override is the longer one.
        c.JOB_TIMEOUT_S = _est * 2
        _buf2 = io.StringIO()
        with contextlib.redirect_stdout(_buf2):
            c.job_timeout_for(_big)
        check("a LONGER override says nothing -- this is a warning, not noise",
              "SHORTER" not in _buf2.getvalue())
    finally:
        c.JOB_TIMEOUT_EXPLICIT, c.JOB_TIMEOUT_S = _saved
    _src2 = open(os.path.join(REPO, "gs_console")).read()
    check("the help text no longer calls the floor the default, because it "
          "is not one any more",
          "DEFAULT: a per-job" in _src2)


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


def test_the_money_fields_finally_state_their_bounds():
    """The four amount inputs were the only fields asking for a quantity
    without saying what the bounds were.

    `split`, `wallets` and `deep` are type="number" with min and max;
    `btc_amount`, `swap_btc` and the two `expect_total_xmr` boxes were bare
    inputs behind a regex that accepts literal zero, and the server checked
    only that a value was PRESENT. So the page bounded every COUNT it asked
    for and no MONEY.
    """
    c = load_console()
    base = {"wallets": 10, "dag_mixing": True, "exit_to": ["x"]}
    note = c.limits_note(base)
    check("limits: the amount fields get a minimum at the point of asking",
          "Minimum" in note and "XMR" in note)
    check("limits: ...and it is the pipeline's own figure, not a rounder one "
          "invented for the page",
          str(c._ghost().mix_minimum_xmr(
              c._ghost().FALLBACK_FEE_XMR, 10,
              dag_mixing=True, exit_set=True)) in note)
    # THE MINIMUM MOVES, which is the whole reason it is recomputed per preview
    # rather than baked into the HTML.
    check("limits: it rises with --wallets, because every mix output reserves "
          "its own fees",
          c.limits_note({**base, "wallets": 60}) != note)
    check("limits: ...and falls without --dag-mixing, because an output that "
          "never hops reserves one transaction fewer",
          c.limits_note({**base, "dag_mixing": False}) != note)
    # THE CUT RAISES IT, and below about fifteen wallets the cut is what binds
    # -- a page showing only the mixing minimum would name a figure at which
    # the operator's own cut is uncollectable.
    _cut = c.limits_note({**base, "usage_fee": True})
    check("limits: enabling the cut raises the stated minimum", _cut != note)
    check("limits: ...and says WHY, rather than just showing a bigger number",
          "could never be spent" in _cut)
    check("limits: NON-VACUITY -- without the cut that explanation is absent",
          "could never be spent" not in note)
    # THE MAXIMUM IS REPORTED AS THE NON-ANSWER IT IS. Quoting the sanity
    # ceiling alone would tell an operator the limit is 100,000,000 XMR.
    check("limits: the maximum says what actually limits the operator instead "
          "of quoting a Decimal-overflow ceiling",
          "wallet balance" in note and "liquidity" in note
          and "100000000" not in note)
    # THE FEE ASSUMPTION IS STATED, because this runs with no socket open and
    # priority 4 is 200x the fee it assumes.
    check("limits: the fee it assumed is named, not implied",
          "fallback fee" in note and "real fee decides" in note)
    check("limits: NON-VACUITY -- a higher priority really does move the "
          "figure, so naming the assumption matters",
          c.limits_note({**base, "fee_priority": 4}) != note)
    # FAIL HONEST: no GhostSpiral, no number -- the rule live_fees and run_eta
    # both follow.
    _real = c._GHOST[0]
    try:
        c._GHOST[0] = object()          # has no mix_minimum_xmr
        check("limits: returns nothing rather than a guess when the pipeline "
              "cannot be loaded", c.limits_note(base) == "")
    finally:
        c._GHOST[0] = _real
    # AND IT REACHES THE PAGE. A note nothing renders is not a note.
    check("limits: the preview endpoint carries it",
          '"limits": limits_note(c["params"])' in _src_console())
    check("limits: ...and the page has somewhere to put it, on every money "
          "field", _src_console().count('class="d limits"') == 4)
    check("limits: ...and the JS actually renders it",
          "querySelectorAll('.limits')" in c.PAGE)


def test_the_spend_button_carries_the_three_numbers():
    """Min, max and usage fee on the button that actually spends.

    The long note lives under the amount fields, which is where an amount is
    typed. The spend button is pressed four wizard steps later, and it is the
    last surface before real transactions are signed -- so the three figures
    that decide whether the run is viable belong there too.
    """
    c = load_console()
    base = {"wallets": 10, "dag_mixing": True, "exit_to": ["x"]}
    off = c.limits_badge(base)
    on = c.limits_badge({**base, "usage_fee": True})
    for _label, _b in (("fee off", off), ("fee on", on)):
        check(f"badge: {_label} states all three -- minimum, maximum, "
              f"usage fee",
              "Min " in _b and "Max " in _b and "Usage fee" in _b)
    check("badge: the fee is named as a USAGE FEE, which is what the flags "
          "call it", "Usage fee" in on and "cut" not in on.lower())
    check("badge: with the fee off it says so rather than going blank -- a run "
          "that is not skimming should say that on the button that spends",
          "Usage fee off" in off)
    check("badge: with the fee on it states the RATE", "1.1%" in on)
    # THE RATE, NOT THE AMOUNT. The fee is a fixed fraction of the deposit, so
    # an amount rendered into the DOM puts the deposit size on the page a
    # second time, recoverable by one division. The page has no masker there.
    check("badge: it shows the percentage and never an XMR fee amount, which "
          "would put the deposit size in the DOM",
          "%" in on and " XMR" in on and on.count(" XMR") == 1)
    # The minimum on the button must be the SAME number the long note gives --
    # two surfaces disagreeing about the floor is worse than one.
    _note = c.limits_note({**base, "usage_fee": True})
    _min = c._ghost().mix_minimum_xmr(
        c._ghost().FALLBACK_FEE_XMR, 10, dag_mixing=True, exit_set=True,
        usage_pct=c._ghost().USAGE_FEE_PCT)
    check("badge: the button and the note quote the SAME minimum",
          str(_min) in on and str(_min) in _note)
    check("badge: NON-VACUITY -- enabling the fee really moves that number, so "
          "the agreement above is not two constants",
          on != off and str(_min) not in off)
    check("badge: the maximum says what actually limits the operator rather "
          "than quoting the Decimal sanity ceiling",
          "your balance" in on and "100000000" not in on)
    # Fail honest, the rule live_fees and run_eta both follow.
    _real = c._GHOST[0]
    try:
        c._GHOST[0] = object()
        check("badge: returns nothing rather than a guess when the pipeline "
              "cannot be loaded", c.limits_badge(base) == "")
    finally:
        c._GHOST[0] = _real
    # And it reaches the button.
    _src = _src_console()
    check("badge: the preview endpoint carries it",
          '"badge": limits_badge(c["params"])' in _src)
    check("badge: only the SPENDS button gets it -- a check or a preview has "
          "no amount to bound", "a.risk==='spends'?'<span class=\"ds lim\"" in _src)
    check("badge: ...and the JS fills it", "querySelectorAll('.lim')" in c.PAGE)


def test_a_rejected_address_is_not_echoed_back_at_full_length():
    """The page has no masker, and it was rendering 48 of 95 characters.

    /api/preview is bound to `input`, so it fires on every keystroke -- and
    every intermediate prefix of a CORRECT address fails the regex. That is
    not a rare error path, it is ordinary typing, and clean()'s generic "re"
    branch put 48 characters of the value into the DOM each time.

    Measured against the two things in this toolchain that already handle
    addresses: the exit list shows 16, and gs_common.scrub_address -- whose
    docstring says it "NEVER returns the full value" -- shows 16. gs_console
    has ZERO uses of scrub_address and --redact does not reach it, so 48 was
    the longest disclosure of an address on any surface here.

    btc_entry is on the same branch and is worse: a bech32 address is short
    enough that 48 characters is the WHOLE of it, and secret_env calls the
    Bitcoin entry one of "the two values that tie a run to a Bitcoin
    identity".
    """
    c = load_console()
    A = ("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5Uzqt"
         "ReoS44qo9mtmXCqY45DJ852K5Jv2684Rge")

    def echoed(field, value):
        errs = c.clean({field: value})["errors"]
        return errs[0] if errs else ""

    # MID-TYPING, not a truncated paste: this is the case that actually fires.
    _typing = echoed("usage_fee_address", A[:60])
    check("echo: a half-typed fee address is not echoed at 48 characters",
          A[:48] not in _typing and A[:17] not in _typing)
    check("echo: ...it is cut to the 16 the exit list and scrub_address use",
          A[:16] in _typing)
    check("echo: a truncated PASTE is cut the same way",
          A[:16] in echoed("usage_fee_address", A[:94])
          and A[:17] not in echoed("usage_fee_address", A[:94]))
    check("echo: the BTC entry is cut too — at 48 characters a bech32 address "
          "was echoed whole",
          A[:16] in echoed("btc_entry", A[:60])
          and A[:17] not in echoed("btc_entry", A[:60]))
    # NON-VACUITY: the rejection still HAPPENS and still names the field, so
    # this did not pass by clean() quietly dropping the problem.
    check("echo: NON-VACUITY -- the value is still rejected, and the message "
          "still names which field",
          _typing and "usage_fee_address" in _typing)
    # NON-VACUITY: a VALID address is accepted and reaches params, so the
    # branch is not refusing everything.
    _ok = c.clean({"usage_fee_address": A})
    check("echo: NON-VACUITY -- a valid address is accepted and carried",
          not _ok["errors"] and _ok["params"].get("usage_fee_address") == A)
    # NON-VACUITY: a non-address field still echoes enough to debug, so this is
    # a judgement about identity-bearing values rather than blanket truncation.
    _tor = echoed("tor_proxy", "not-a-proxy-url-that-is-long-enough-to-debug")
    check("echo: NON-VACUITY -- a non-address field still shows enough to "
          "debug, so this is not blanket truncation",
          "long-enough-to-debug" in _tor)
    # THE CLASS, NOT THE INSTANCE: no address field may sit on the generic
    # branch, or the next one added inherits the 48-character echo.
    _addr_fields = [k for k, (kind, _s) in c.SCHEMA.items()
                    if kind == "re" and ("address" in k or k == "btc_entry")]
    check("echo: no address field is left on the generic 're' branch",
          _addr_fields == [])
    check("echo: NON-VACUITY -- the addr_re kind is actually in use",
          any(kind == "addr_re" for kind, _s in c.SCHEMA.values()))


def test_the_fee_rate_never_reaches_a_command_line():
    """GS_USAGE_FEE_PCT, not --usage-fee-pct.

    The console composed `--usage-fee-pct 0.011` onto the child's argv under a
    comment claiming "the percentage is a setting, not an identifier, and it is
    already visible in the amounts". Both halves are wrong, and GhostSpiral's
    own resolve_usage_fee says so: it routes the rate through env_or_argv
    precisely because an OVERRIDE is a per-operator constant, and putting it on
    a command line publishes it to `ps` "next to amounts it divides exactly
    into".

    And a local reader of /proc/<pid>/cmdline (0444, every account on the host)
    sees argv and NOT the amounts -- those are inside RingCT and inside plan
    files under a 0700 directory. So argv was not a second copy of something
    already public; it was the only disclosure of the divisor that turns an
    observed cash-out back into a deposit size. env_or_argv was given the rate
    for this exact reason and the console handed it straight back.
    """
    c = load_console()
    p = {"btc_entry": "bc1x", "usage_fee": True, "usage_fee_pct": "0.02",
         "wallets": 10}
    # pipeline_argv returns (argv, problems); only the argv is the surface
    # /proc/<pid>/cmdline exposes.
    argv = c.pipeline_argv(p)[0]
    check("fee rate: the RATE is not on the child's command line",
          "--usage-fee-pct" not in argv and "0.02" not in argv)
    check("fee rate: ...it goes through the environment instead",
          c.secret_env(p).get("GS_USAGE_FEE_PCT") == "0.02")
    check("fee rate: ...and the pipeline is allowed to receive it",
          "GS_USAGE_FEE_PCT" in c.ACTION_SECRETS["run_pipeline"])
    # The SWITCH stays on argv: it is a boolean whose name is in the public
    # source, and GhostSpiral reads args.usage_fee to tell "skim at the default
    # rate" from "do not skim".
    check("fee rate: the switch itself is still passed, or nothing skims",
          "--usage-fee" in argv)
    # NON-VACUITY: pipeline_argv is composing a real command, so the absence
    # above is an absence from something rather than from nothing.
    check("fee rate: NON-VACUITY -- the argv this was read from is a real "
          "one, so the absences above are absences from something",
          "GhostSpiral" in argv and "--wallets" in argv)
    # THE CHECKBOX GATE, which is load-bearing rather than tidy. An env-supplied
    # rate is treated by resolve_usage_fee as "skim" -- env is the PREFERRED
    # channel, so requiring the argv flag as well would defeat having it. A rate
    # left in the field with the box unticked would therefore make a run skim
    # while the page showed no fee at all.
    _unticked = {"btc_entry": "bc1x", "usage_fee_pct": "0.02", "wallets": 10}
    check("fee rate: a rate left in the field with the box UNTICKED sets no "
          "variable — otherwise the run skims while the page says it does not",
          "GS_USAGE_FEE_PCT" not in c.secret_env(_unticked))
    check("fee rate: ...and composes no switch either",
          "--usage-fee" not in c.pipeline_argv(_unticked)[0])
    # NON-VACUITY on the gate: ticking the box with no rate is the DEFAULT-rate
    # case, which must still work and must still set no variable.
    _default = {"btc_entry": "bc1x", "usage_fee": True, "wallets": 10}
    check("fee rate: ticking the box with no rate skims at the default, with "
          "nothing to leak",
          "--usage-fee" in c.pipeline_argv(_default)[0]
          and "GS_USAGE_FEE_PCT" not in c.secret_env(_default))
    # The DESTINATION was already env-only; assert it here too so the two
    # halves of the fee's argv surface are checked in one place.
    _withaddr = {**p, "usage_fee_address": "4" + "z" * 94}
    check("fee rate: the DESTINATION is env-only as well",
          "4" + "z" * 94 not in c.pipeline_argv(_withaddr)[0]
          and c.secret_env(_withaddr).get("GS_USAGE_FEE_ADDRESS")
          == "4" + "z" * 94)


def test_sensitive_inputs_do_not_go_into_browser_history():
    """autocomplete/spellcheck on the fields that carry an identity.

    Only the arm box had autocomplete="off". btc_entry is the sender's own
    Bitcoin address, exit_to is the final destination -- the one address the
    whole pipeline exists to keep unlinked -- and the amount boxes are
    magnitudes. A browser remembers all of them in a profile that paranoia_mode
    cannot reach and a wipe does not touch.

    spellcheck matters separately: some browsers send the contents of a
    spellchecked field to a remote service. exit_to already had it off; nothing
    else did.
    """
    _src = _src_console()
    _sensitive = ["btc_entry", "usage_fee_address", "btc_amount", "swap_btc",
                  "expect_total_xmr_send", "expect_total_xmr", "usage_fee_pct",
                  "receive_wallet", "pairs_file", "wallet_file", "exit_to"]
    for _fid in _sensitive:
        _tag = _re_c.search(r'<(?:input|textarea) id="%s"[^>]*>' % _fid, _src)
        check(f"input: {_fid} is not remembered by the browser",
              bool(_tag) and 'autocomplete="off"' in _tag.group(0))
        check(f"input: ...and {_fid} is not sent to a spellchecker",
              bool(_tag) and 'spellcheck="false"' in _tag.group(0))
    for _fid in ("btc_entry", "usage_fee_address", "exit_to"):
        _tag = _re_c.search(r'<(?:input|textarea) id="%s"[^>]*>' % _fid, _src)
        check(f"input: ...and {_fid} is not autocapitalised or 'corrected', "
              f"which mangles an address",
              bool(_tag) and 'autocapitalize="off"' in _tag.group(0)
              and 'autocorrect="off"' in _tag.group(0))
    # NON-VACUITY: the fields that carry no identity are left alone, so this is
    # a judgement about sensitivity and not a blanket rewrite.
    for _fid in ("wallets", "deep", "split"):
        _tag = _re_c.search(r'<input id="%s"[^>]*>' % _fid, _src)
        check(f"input: NON-VACUITY -- {_fid} is a count and is untouched",
              bool(_tag) and 'autocomplete="off"' not in _tag.group(0))


def test_the_joinmarket_control_can_actually_run_a_tumble():
    """Ticking "JoinMarket tumble first" must not build an argv GhostSpiral refuses.

    stage1_joinmarket's second statement is `if not args.joinmarket_wallet:
    sys.exit(...)`, and no field for it existed anywhere on this page -- not in
    SCHEMA (the whitelist: "Anything not here cannot reach an argv"), not in
    the form, not in collect(). So the checkbox could only ever end the run,
    and it ended it AFTER stage0_preflight had verified Tor, opened the wallet
    and read the daemon's fee, and after a required newnym.

    Driven through the real clean() and pipeline_argv, and the resulting argv
    is handed to GhostSpiral's own parser -- a console-side field that the
    pipeline does not accept would be the same bug with the sides swapped.
    """
    c = load_console()
    _base = {"mode": "send", "wallets": 10,
             "btc_entry": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
             "btc_amount": "0.05", "tor_proxy": "socks5h://127.0.0.1:9050"}
    for _f in ("joinmarket_wallet", "joinmarket_tumbler", "joinmarket_python"):
        check(f"jm: {_f} is in SCHEMA, so it can reach an argv at all",
              _f in c.SCHEMA)
        check(f"jm: ...and the page has a box for {_f}",
              f'id="{_f}"' in _src_console())
        check(f"jm: ...and collect() actually sends it",
              f"{_f}:v('{_f}')" in _src_console())
    _bare = c.clean({**_base, "joinmarket": True})
    _argv, _why = c.pipeline_argv(_bare["params"])
    check("jm: the checkbox alone is REFUSED here rather than aborting the "
          "run at stage 1, after Tor and the wallet are already up",
          any("joinmarket" in w.lower() for w in _why))
    check("jm: ...and no half-built --joinmarket reaches the argv",
          "--joinmarket" not in _argv)
    _full = c.clean({**_base, "joinmarket": True,
                     "joinmarket_wallet": "/opt/jm/w.jmdat",
                     "joinmarket_tumbler": "/opt/jm/scripts/tumbler.py",
                     "joinmarket_python": "/opt/jmvenv/bin/python"})
    _argv, _why = c.pipeline_argv(_full["params"])
    check("jm: with the wallet supplied the run is allowed", not _why)
    for _flag, _val in (("--joinmarket-wallet", "/opt/jm/w.jmdat"),
                        ("--joinmarket-tumbler", "/opt/jm/scripts/tumbler.py"),
                        ("--joinmarket-python", "/opt/jmvenv/bin/python")):
        check(f"jm: ...and {_flag} carries the operator's value",
              _flag in _argv and _argv[_argv.index(_flag) + 1] == _val)
    # THE OPTIONAL TWO ARE OMITTED WHEN BLANK, not sent empty: GhostSpiral
    # defaults them to "tumbler.py" and "python3", and overriding a default
    # with "" is worse than leaving it alone.
    _min = c.pipeline_argv(c.clean({**_base, "joinmarket": True,
                                    "joinmarket_wallet": "w.jmdat"})["params"])[0]
    check("jm: a blank tumbler path is omitted rather than sent empty",
          "--joinmarket-tumbler" not in _min
          and "--joinmarket-python" not in _min)
    check("jm: NON-VACUITY -- the wallet flag IS there in that same argv, so "
          "the check above is not looking at an empty list",
          "--joinmarket-wallet" in _min)
    # And GhostSpiral's real parser accepts the whole thing.
    _g = c._ghost()
    _ns = _g.build_cli().parse_args(_argv[2:])
    check("jm: GhostSpiral's own parser accepts the composed argv",
          _ns.joinmarket is True
          and _ns.joinmarket_wallet == "/opt/jm/w.jmdat")
    check("jm: ...and stage1_joinmarket's own refusal no longer fires on it",
          bool(_ns.joinmarket_wallet))


def test_compile_all_compiles_all():
    """"every shipped script parses" must not mean nine of the seventeen.

    The eight it left out were the whole wake path, the delivery pair and this
    console itself -- so a syntax error in the code that runs unattended on the
    vault passed a check whose own description says otherwise.

    Checked against the DIRECTORY rather than a second list, because a second
    list is the thing that drifted.
    """
    c = load_console()
    _argv = c.ACTIONS["compile"]["build"]({})
    _named = set(_argv[3:])
    _ship = set()
    for _f in os.listdir(REPO):
        _p = os.path.join(REPO, _f)
        if not os.path.isfile(_p) or _f.startswith("test"):
            continue
        if _f.endswith(".py"):
            _ship.add(_f)
            continue
        try:
            with open(_p, "rb") as _fh:
                if _fh.read(2) == b"#!" and b"python" in open(_p, "rb").readline():
                    _ship.add(_f)
        except OSError:
            pass
    check(f"compile: every shipped script is named "
          f"(missing: {sorted(_ship - _named)})", not (_ship - _named))
    check(f"compile: ...and nothing is named that is not shipped "
          f"(extra: {sorted(_named - _ship)})", not (_named - _ship))
    check("compile: NON-VACUITY -- the directory scan really found the "
          "scripts, so 'nothing missing' is not an empty comparison",
          len(_ship) >= 15)
    for _f in ("gs_console", "gs_wake_agent", "gs_telegram_pager",
               "gs_wake_proto.py", "gs_doorbell", "gs_wake_keys",
               "gs_delivery_key", "gs_unseal"):
        check(f"compile: {_f} -- one of the eight this used to skip -- is in",
              _f in _named)
    check("compile: and the action still says what it does",
          c.ACTIONS["compile"]["desc"] == "every shipped script parses")


def test_the_minimum_moves_with_the_split():
    """--split raises the deposit floor, and both surfaces used to drop it.

    Each chunk pays its own entry-veil fee and then has to fund its own slice
    of the mix targets out of its own share (min_carrier_usable), so the
    single-chunk figure is an understatement for a split run -- and the
    shortfall only speaks at stage 4, after the swap has settled.
    """
    c = load_console()
    _g = c._ghost()
    _base = {"wallets": 10, "dag_mixing": True, "exit_to": ["x"]}
    _one = c.limits_note(_base)
    _eight = c.limits_note({**_base, "split": 8})
    check("split min: the note quotes the pipeline's split-aware figure",
          str(_g.mix_minimum_xmr(_g.FALLBACK_FEE_XMR, 10, dag_mixing=True,
                                 exit_set=True, chunks=8)) in _eight)
    check("split min: ...which is NOT the single-chunk one, so the split is "
          "really reaching the figure", _one != _eight)
    check("split min: ...and the note says how many chunks it is quoting for",
          "8 swap chunks" in _eight and "swap chunks" not in _one)
    _badge = c.limits_badge({**_base, "split": 8})
    check("split min: the spend button carries the same split-aware number",
          str(_g.mix_minimum_xmr(_g.FALLBACK_FEE_XMR, 10, dag_mixing=True,
                                 exit_set=True, chunks=8)) in _badge)
    # A SHAPE NO DEPOSIT CAN RESCUE IS SAID SO, rather than left to a stage-0
    # abort. split and wallets are independent number inputs on this page.
    _starved = c.limits_note({**_base, "wallets": _g.MIN_WALLETS, "split": 8})
    check("split min: 8 chunks at the minimum wallets is called impossible, "
          "not merely expensive",
          "cannot work" in _starved and "No deposit size fixes that" in _starved)
    check("split min: NON-VACUITY -- a workable split is NOT called impossible",
          "cannot work" not in c.limits_note({**_base, "split": 4}))
    check("split min: ...and GhostSpiral refuses the same pair before any "
          "network work, which is where the rule lives",
          _refuses_split(_g, 8, _g.MIN_WALLETS))
    check("split min: NON-VACUITY -- it does not refuse the workable pair",
          not _refuses_split(_g, 4, 10))


def _refuses_split(g, split, wallets):
    import types as _t
    try:
        g.resolve_split(_t.SimpleNamespace(split=split, wallets=wallets,
                                           peel=False))
        return False
    except SystemExit:
        return True


def _src_console():
    return open(os.path.join(REPO, "gs_console")).read()


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
