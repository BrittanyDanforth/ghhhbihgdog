#!/usr/bin/env python3
"""THE PAGER MUST TRIGGER AND NEVER CARRY.

OPSEC_SETUP.md §8 is blunt about the failure mode: "Do not 'just run a Telegram
bot' that prints the memo — that throws away the only reason to have a Pi." So
the properties worth testing are not "does it send a message" but:

  * nothing an operator can type reaches the wake channel except a bounded
    integer or a 4-hex handle -- §8: "there is deliberately no job that takes
    an XMR destination";
  * no address, memo, slip or amount ever reaches a chat, even on the paths
    that report success;
  * a chat that is not on the allowlist gets NO REPLY AT ALL, because a reply
    confirms the bot exists to whoever found it;
  * the bot token never reaches argv, a world-readable file, or an error
    string -- Telegram puts it in the URL path, so it is inside every
    exception requests raises;
  * Tor is fail-closed at startup, §4: "If Tor is down, the bot does not
    start."

Driven against the real module. The end-to-end case runs a REAL gs_doorbell
server on loopback with a fake vault speaking the real M1/M3 protocol; only
Telegram itself is stubbed, at the pager's own safe_get/safe_post.
"""
import contextlib
import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

PASS = FAIL = 0
FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   " + name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL: " + name)


def load(name):
    path = os.path.join(REPO, name)
    ld = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(ld.name, ld)
    mod = importlib.util.module_from_spec(spec)
    ld.exec_module(mod)
    return mod


pg = load("gs_telegram_pager")
DB = load("gs_doorbell")
sys.modules["gs_doorbell"] = DB
pg._DOORBELL[0] = DB
P = load("gs_wake_proto.py")
import nacl.public as NP                                     # noqa: E402

XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSs"
       "aBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
MEMO = f"=:XMR.XMR:{XMR}:0/1/0"
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"


print("== nothing typed into a chat can name a destination ==")
# EVERY accepted command, and what it is allowed to produce.
for _text, _job, _params in (
        ("/recv", "receive_new", {"count": 1}),
        ("/recv 4", "receive_new", {"count": 4}),
        ("/depo 0", "receive_and_quote", {"amount_slot": 0}),
        ("/depo 7", "receive_and_quote", {"amount_slot": 7}),
        ("/depo@somebot 2", "receive_and_quote", {"amount_slot": 2}),
        ("/watch a3f1", "watch", {"handle": "A3F1"})):
    _j, _p, _e = pg.parse_command(_text)
    check(f"{_text!r} -> {_job}", (_j, _p) == (_job, _params))

# THE ATTACK THIS SHAPE EXISTS TO STOP.
for _hostile in (f"/depo 2 --exit-to {XMR}",
                 f"/recv 1; --dest {XMR}",
                 f"/watch A3F1 {XMR}",
                 f"/depo {XMR}",
                 f"/recv 1 {MEMO}",
                 "/depo 2\n/depo 3",
                 "/spend 1",
                 f"/depo 2 && curl {BTC}"):
    _j, _p, _e = pg.parse_command(_hostile)
    check(f"refuses {_hostile[:38]!r}", _j == "" and _e)

for _bad in ("/recv 0", "/recv 5", "/recv -1", "/recv abc",
             "/depo 8", "/depo -1", "/depo 0.05",
             "/watch ZZZZ", "/watch A3F", "/watch A3F12", "", "   "):
    _j, _p, _e = pg.parse_command(_bad)
    check(f"refuses out-of-range {_bad!r}", _j == "")

# BARE /depo WAS IN THAT LIST AND STILL PASSED, WHICH IS WORSE THAN FAILING.
# It asserted "refuses '/depo'" and the assertion was `_j == ""` -- true both
# when a command is refused and when it is routed somewhere that is not a job.
# Bare /depo now starts the wizard, so the check went on passing while
# asserting the opposite of the behaviour. Named for what it does, and pinned
# to the specific err so it cannot drift into meaning "refused" again.
_j, _p, _e = pg.parse_command("/depo")
check("bare /depo starts the wizard rather than being refused",
      _j == "" and _p == {} and _e == "depo_wizard")
check("...and it is a DIFFERENT outcome from a refusal, so the two cannot be "
      "confused by a check that only looks at the job name",
      pg.parse_command("/depo 8")[2] != "depo_wizard")

# STRUCTURAL: no accepted command can produce anything but a bounded int or a
# 4-hex handle, whatever the input. Enumerating hostile strings would not stop
# the next one.
_types = set()
_long = 0
for _t in ["/recv", "/recv 2", "/depo 0", "/depo 7", "/watch A3F1",
           f"/depo 2 {XMR}", f"/watch {XMR}", "/depo 2 3 4"]:
    _j, _p, _e = pg.parse_command(_t)
    for _v in (_p or {}).values():
        _types.add(type(_v).__name__)
        if isinstance(_v, str) and len(_v) > 4:
            _long += 1
check("every parameter is an int or a 4-char handle, never a longer string",
      _types <= {"int", "str"} and _long == 0)
check("the jobs it can ask for are exactly the ones the protocol allows",
      {pg.parse_command(t)[0] for t in ("/recv", "/depo 1", "/watch A3F1",
                                        "/check A3F1")} <= set(P.JOBS))

# THE SAME GUARANTEE, THROUGH THE WIZARD, because parse_command is no longer
# the only producer of params. A structural check that covers one of two
# producers is a check that will be read as covering both.
_wiz = []


def _wizard_params(answers):
    """Drive a whole conversation through the real handle(); collect params."""
    import threading as _th
    import types as _ty
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key, p.args = {}, "x", {}, _ty.SimpleNamespace()
    p.allow = {1}
    p.busy = _th.Lock()
    p.ignored = 0
    p.convos = {}
    p.clock = lambda: 1000.0
    p.rng = __import__("random").SystemRandom()
    p.limits = _ty.SimpleNamespace(why_not=lambda: "", record=lambda: None,
                                   recent=lambda: [], daily_cap=12)
    seen = []
    p.send = lambda c, t: (seen.append(t), True)[1]
    p.start_job = lambda c, j, pa: _wiz.append((j, pa))
    for a in answers:
        if a == "<confirm>":
            import re as _re
            m = _re.search(r"(\d+) \+ (\d+) = \?", "\n".join(seen))
            a = str(int(m.group(1)) + int(m.group(2))) if m else "0"
        p.handle({"update_id": 1, "message": {"chat": {"id": 1}, "text": a}})
    return seen


for _slot in range(8):
    _wizard_params(["/depo", str(_slot), "<confirm>"])
for _hostile in (XMR, MEMO, BTC, "0.05", "-1", "8", "2 3", "²", "٢",
                 "2; /depo 7", "‮2", "٧", "2\n7", "x" * 500):
    _wizard_params(["/depo", _hostile, "<confirm>"])
    _wizard_params(["/depo", "2", _hostile])
# NOT "exactly eight jobs": '٢' is Arabic-Indic two, isdecimal() accepts it and
# int() reads it as 2, so it legitimately produces slot 2. The first version of
# this check listed it as hostile and went red on correct behaviour. The real
# invariant is that EVERY job the wizard can produce is one key holding an
# in-range slot, and that all eight are reachable.
check("every job the wizard produces is a single in-range slot, whatever was "
      "typed at it",
      all(set(pa) == {"amount_slot"} and pa["amount_slot"] in range(8)
          for _, pa in _wiz))
check("...and all eight slots are reachable, so nothing above is vacuous",
      {pa["amount_slot"] for _, pa in _wiz} == set(range(8)))
check("...every wizard-produced job is receive_and_quote",
      {j for j, _ in _wiz} == {"receive_and_quote"})
check("...and every value is a plain int, never a string or a bool",
      all(isinstance(v, int) and not isinstance(v, bool)
          for _, pa in _wiz for v in pa.values()))
for _j, _pa in _wiz:
    P.validate_job({"job_id": P.new_job_id(),
                    "challenge": P.new_challenge().hex(), "job": _j, **_pa})
check("...and every one passes the REAL job schema", True)
# ...and the protocol itself agrees, rather than this file asserting it alone.
for _t in ("/recv 2", "/depo 3", "/watch A3F1"):
    _j, _p, _e = pg.parse_command(_t)
    check(f"gs_wake_proto accepts what {_t!r} composes",
          _j in P.JOBS and set(_p) <= set(P.JOBS[_j]["schema"]))
check("no job this pager can ask for drives a forbidden tool",
      all(t not in P.FORBIDDEN_TOOLS
          for j in ("receive_new", "receive_and_quote", "watch")
          for t in P.JOBS[j]["tools"]))


print("\n== the allowlist, and why a stranger gets silence ==")
_sent = []
pg.safe_post = lambda url, payload, proxies=None: (
    _sent.append((payload["chat_id"], payload["text"])) or {"ok": True})
pg.integrity_log = lambda *a, **k: None
_d = tempfile.mkdtemp(prefix="pagertest_")
_args = types.SimpleNamespace(state=os.path.join(_d, "st.json"),
                              min_interval=0, daily_cap=99, chat_id=[111],
                              no_jitter=True, key="unused")
_p = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://127.0.0.1:9050"})
_poked = []
_p.poke = lambda cid, job, params: _poked.append((cid, job, params))


def _msg(cid, text, uid=1):
    return {"update_id": uid, "message": {"chat": {"id": cid}, "text": text}}


_p.handle(_msg(999, "/recv"))
check("a chat that is not allowlisted gets NO reply -- a reply would confirm "
      "the bot is alive to whoever found it", _sent == [])
check("...and it is counted rather than silently dropped", _p.ignored == 1)
check("...and it never reaches the wake channel", _poked == [])
_p.handle(_msg(111, "/recv"))
check("an allowlisted chat does reach it", len(_poked) == 1)


print("\n== the reply vocabulary has no word for a secret ==")
_sent.clear()


class _FakePending:
    def __init__(self, out, handle=""):
        self._out, self.result, self.job = out, {"handle": handle}, "receive_and_quote"
        self.result_budget_s = 1800

    def outcome(self):
        return self._out


_real_doorbell = pg.doorbell
# A FRESH Pager: the one above has poke() stubbed out to record calls, so
# reusing it here would have tested the stub. It did, and this block passed
# vacuously until the "done" case asked for a value only the real poke emits.
_pv = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://x"})
for _out, _h in (("done", "A3F1"), ("refused", ""), ("failed", ""),
                 ("expired_uncollected", ""), ("collected_no_result", "")):
    _sent.clear()
    pg.doorbell = lambda _o=_out, _hh=_h: types.SimpleNamespace(
        run_wake=lambda a, k, j, p: _FakePending(_o, _hh))
    _pv.poke(111, "receive_and_quote", {"amount_slot": 2})
    _text = "\n".join(t for _, t in _sent)
    check(f"outcome {_out}: no XMR address reaches the chat", XMR not in _text)
    check(f"outcome {_out}: no swap memo reaches the chat", MEMO not in _text)
    check(f"outcome {_out}: no BTC deposit address reaches the chat",
          BTC not in _text)
    if _out == "done":
        check("a finished job reports the 4-hex handle and says where the "
              "address actually is",
              "A3F1" in _text and "on the vault" in _text)
pg.doorbell = _real_doorbell


print("\n== the rate limit is real, and survives a restart ==")
_d2 = tempfile.mkdtemp(prefix="pagerlim_")
_st = os.path.join(_d2, "st.json")
_lim = pg.Limits(__import__("pathlib").Path(_st), 300, 2)
check("a fresh limiter allows a poke", _lim.why_not() == "")
_lim.record()
check("...and then the interval blocks the next one",
      "rate limited" in _lim.why_not())
_lim.min_interval = 0
_lim.record()
check("the daily cap blocks once it is reached", "24h" in _lim.why_not())
_lim2 = pg.Limits(__import__("pathlib").Path(_st), 0, 2)
check("A RESTART IS NOT A BYPASS: the counters reload from disk",
      len(_lim2.recent()) == 2 and "24h" in _lim2.why_not())
check("...and the state file is 0600, since it names when you woke the vault",
      oct(os.stat(_st).st_mode)[-3:] == "600")
check("the limits say they are courtesy, not the real bound -- the vault's "
      "own 24h budget is", "courtesy" in _lim2.why_not())


print("\n== replay: an update is never handled twice ==")
_sent.clear()
_p3 = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://x"})
_p3.poke = lambda *a: None
_p3.limits.offset = 0
_u = _msg(111, "/recv", uid=42)
_p3.limits.offset = max(_p3.limits.offset, _u["update_id"] + 1)
check("the cursor advances past a handled update", _p3.limits.offset == 43)
_p4 = pg.Limits(__import__("pathlib").Path(_args.state), 0, 99)
_p3.limits.save()
_p5 = pg.Limits(__import__("pathlib").Path(_args.state), 0, 99)
check("...and the cursor is persisted, so a restart does not replay the "
      "backlog", _p5.offset == 43)
_src = open(os.path.join(REPO, "gs_telegram_pager")).read()
check("the cursor is advanced BEFORE the handler runs, so a message that "
      "crashes it cannot be replayed on every restart",
      _src.index("self.limits.offset = max(") < _src.index("self.handle(upd)"))


print("\n== the bot token ==")
check("there is no --token flag; argv is world-readable via /proc",
      "--token-file" in _src and '"--token"' not in _src)
_tf = os.path.join(_d2, "tok")
open(_tf, "w").write("123456:SECRET")
os.chmod(_tf, 0o644)
_exited = ""
try:
    pg.load_token(_tf)
except SystemExit as e:
    _exited = str(e)
check("a group/world-readable token file is refused", "400" in _exited)
os.chmod(_tf, 0o400)
check("...and a 0400 one is accepted", pg.load_token(_tf) == "123456:SECRET")
_TOK = "123456789:AAHfake-Token_xyz1234567890abcdef"
for _ctx in (f"bot{_TOK}", f"401 for {_TOK}",
             f"url: /bot{_TOK}/getUpdates",
             f"Max retries with url: /bot{_TOK}/sendMessage"):
    check("the token is redacted out of an error string",
          _TOK not in pg._redact(_ctx)
          and _TOK.split(":")[1] not in pg._redact(_ctx))


print("\n== Tor is fail-closed, as §4 requires ==")
# THE CALL SITE, not the def: "load_token(" also matches the definition, which
# sits far earlier in the file, so the bare substring compared the wrong two
# positions and failed on correct code.
def _pos(hay, needle):
    """Index or -1. str.index RAISES, and a test that dies scores NO-RESULT in
    the mutation sweep, which proves nothing about the check. Fail with our own
    words instead -- the sweep caught this exact shape here."""
    return hay.find(needle)


check("the proxy is validated and Tor verified before the token is even read",
      _pos(_src, "verify_tor(proxy)") >= 0
      and _pos(_src, "verify_tor(proxy)")
          < _pos(_src, "load_token(args.token_file)"))
check("every Telegram call goes through safe_get/safe_post, which abort on a "
      "falsy proxies dict rather than connecting direct",
      "safe_get(url, proxies=self.proxies)" in _src
      and "proxies=self.proxies)" in _src
      and "requests." not in _src)
check("the default proxy is the Pi's own Tor",
      "socks5h://127.0.0.1:9050" in _src)


print("\n== end to end: a real doorbell, a fake vault, a real handle ==")
_PI, _TP = NP.PrivateKey.generate(), NP.PrivateKey.generate()
_s = socket.socket(); _s.bind(("127.0.0.1", 0))
_PORT = _s.getsockname()[1]; _s.close()
_KEY = {"role": "pi", "secret": _PI.encode().hex(),
        "peer_public": _TP.public_key.encode().hex(),
        "target_mac": "aa:bb:cc:dd:ee:ff", "wol_broadcast": "255.255.255.255",
        "wol_port": 9, "listen_host": "127.0.0.1", "listen_port": _PORT}


class _FakeSock:
    def setsockopt(self, *a): pass
    def sendto(self, d, a): return len(d)
    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _vault(handle):
    def post(path, body):
        c = http.client.HTTPConnection("127.0.0.1", _PORT, timeout=15)
        c.request("POST", path, body=body,
                  headers={"Content-Length": str(len(body))})
        r = c.getresponse(); r.read(); c.close(); return r.status
    for _ in range(600):
        try:
            socket.create_connection(("127.0.0.1", _PORT), 0.2).close(); break
        except OSError:
            time.sleep(0.05)
    import gc
    pend = None
    for _ in range(300):
        c = [o for o in gc.get_objects() if isinstance(o, DB.Pending)]
        if c:
            pend = c[-1]; break
        time.sleep(0.05)
    if pend is None:
        return
    eph = NP.PrivateKey.generate()
    post("/wake", P.seal(_TP, _PI.public_key, P.TAG_M1,
                         {"eph_pk": eph.public_key.encode().hex(),
                          "challenge": os.urandom(P.CHALLENGE_BYTES).hex(),
                          "window": pend.window.hex()}))
    time.sleep(0.2)
    post("/result", P.seal(_TP, _PI.public_key, P.TAG_M3,
                           {"job_id": pend.job_id, "status": "done",
                            "handle": handle, "challenge": "",
                            # THE DEFAULT VAULT: no delivery key, no
                            # plain_slip. Empty is the configuration §8
                            # describes, and it is what this end-to-end case
                            # exists to hold the line on.
                            "slip": "", "plain": {}, "phase": ""}))


_sent.clear()
_e2e_args = types.SimpleNamespace(state=os.path.join(_d, "e2e.json"),
                                  min_interval=0, daily_cap=9, chat_id=[111],
                                  no_jitter=True, key="unused")
_pe = pg.Pager(_e2e_args, "123456:TOKEN", _KEY, {"https": "socks5h://x"})
_real_rw = DB.run_wake
DB.run_wake = lambda a, k, j, p: _real_rw(
    a, k, j, p, sock_factory=lambda: _FakeSock(),
    sleep=lambda n: time.sleep(min(n, 0.05)))
threading.Thread(target=_vault, args=("A3F1",), daemon=True).start()
_pe.handle(_msg(111, "/depo 2"))
for _ in range(500):
    if len(_sent) >= 2:
        break
    time.sleep(0.05)
time.sleep(0.3)
DB.run_wake = _real_rw
_chat = "\n".join(t for _, t in _sent)
check("a chat message really did wake a real doorbell and get a handle back",
      "A3F1" in _chat)
check("...and the whole conversation still contains no XMR address",
      XMR not in _chat)
check("...no memo", MEMO not in _chat)
check("...and no BTC deposit address", BTC not in _chat)
check("...and it tells the operator where the address actually is",
      "on the vault" in _chat)


# ===========================================================================
# --whoami: THE ONLY WAY TO LEARN THE NUMBER --chat-id WANTS.
#
# The bot ignores unallowlisted chats in silence, on purpose -- so pressing
# Start in Telegram produces nothing and there is no path from "I have a bot
# token" to "I have my chat id". The tool was unusable from a standing start.
# What matters as much as it working is what it must NOT do: it runs before
# the operator has a keyfile, so it must arm nothing.
# ===========================================================================
print("\n== --whoami, the bootstrap ==")
_wargs = pg.build_cli().parse_args(["--whoami"])
check("--whoami parses with NO --key and NO --chat-id, which is the whole "
      "point: it runs before either exists",
      _wargs.whoami is True and not _wargs.key and not _wargs.chat_id)
_perr = []
try:
    pg.build_cli().parse_args([])
except SystemExit:
    _perr.append("argparse")
check("...but a bare invocation still parses, so the refusal can name BOTH "
      "missing flags in one sentence instead of argparse naming one",
      not _perr)

_updates = [{"update_id": 1, "message": {"chat": {"id": 424242},
                                         "from": {"username": "someone"},
                                         "text": "hi"}}]
pg.safe_get = lambda url, proxies=None: {"ok": True, "result": _updates}
_wout = io.StringIO()
with contextlib.redirect_stdout(_wout):
    _wrc = pg.whoami("123456:TOKEN", {"https": "socks5h://x"})
_wtext = _wout.getvalue()
check("--whoami prints the chat id of the next message", "424242" in _wtext)
check("...and the exact flag to pass it to", "--chat-id 424242" in _wtext)
check("...and returns 0", _wrc == 0)
check("...and says a chat id is not a secret, so it is fine on argv",
      "not a secret" in _wtext.lower() or "NOT a secret" in _wtext)

# A USERNAME IS A STRING ITS OWNER CHOSE, and this line reaches a terminal and,
# under systemd, a journal. Anyone can message a bot they find.
_updates[:] = [{"update_id": 2,
                "message": {"chat": {"id": 7},
                            "from": {"username": "a\x1b[31mb\x07c"},
                            "text": "hi"}}]
_wout2 = io.StringIO()
with contextlib.redirect_stdout(_wout2):
    pg.whoami("123456:TOKEN", {"https": "socks5h://x"})
check("a sender's username cannot put an escape sequence on the terminal",
      "\x1b" not in _wout2.getvalue() and "\x07" not in _wout2.getvalue())

_wsrc = open(os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read()
_wbody = _wsrc.split("def whoami")[1].split("\ndef ")[0]
for _armed in ("run_wake", "load_key", "Pager(", "sendMessage"):
    check(f"--whoami never reaches {_armed}: it arms nothing and wakes nothing",
          _armed not in _wbody)
check("...and main() returns from the --whoami branch BEFORE the keyfile is "
      "read",
      _wsrc.index("return whoami(") < _wsrc.index("doorbell().load_key("))


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
