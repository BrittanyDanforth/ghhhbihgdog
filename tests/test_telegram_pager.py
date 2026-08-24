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

#: The pager's source, read once. Several checks below read it rather than
#: driving, because the branch they are about (a job-result reply, a poll-loop
#: guard) needs a whole wake to reach.
_SRC_PG_EARLY = open(os.path.join(REPO, "gs_telegram_pager"),
                     encoding="utf-8").read()

#: The vault's real pre-job jitter, read from the protocol rather than copied,
#: so the help text's quoted round trip cannot drift away from it.
_AG_JIT = (P.VAULT_JITTER_LO_S, P.VAULT_JITTER_HI_S)

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
        # THE HANDLE IS THE WHOLE REPLY. This also required the words "on
        # the vault" -- a sentence naming the operator's own machine, sent on
        # every finished job, into the surface this design assumes is read.
        # The handle is what §8's own example carries: "depo ready · slip
        # A3F1".
        check("a finished job reports the 4-hex handle", "A3F1" in _text)
        check("...and names no machine while doing it",
              "vault" not in _text.lower())
pg.doorbell = _real_doorbell


print("\n== the rate limit is real, and survives a restart ==")
_d2 = tempfile.mkdtemp(prefix="pagerlim_")
_st = os.path.join(_d2, "st.json")
_lim = pg.Limits(__import__("pathlib").Path(_st), 300, 2)
check("a fresh limiter allows a poke", _lim.why_not() == "")
_lim.record()
check("...and then the interval blocks the next one",
      _lim.why_not() != "" and _lim.why_not().startswith("wait "))
_lim.min_interval = 0
_lim.record()
check("the daily cap blocks once it is reached",
      _lim.why_not() != "" and "limit" in _lim.why_not())
_lim2 = pg.Limits(__import__("pathlib").Path(_st), 0, 2)
check("A RESTART IS NOT A BYPASS: the counters reload from disk",
      len(_lim2.recent()) == 2 and _lim2.why_not() != "")
check("...and the state file is 0600, since it names when you woke the vault",
      oct(os.stat(_st).st_mode)[-3:] == "600")
# THE HONEST NOTE MOVED OUT OF THE CHAT. This asserted the refusal SAID it
# was a courtesy limit and that the real bound was the 24h wake budget -- true,
# useful once, and a description of the architecture written permanently into
# the readable surface, on the message an operator sees most often after a
# mistyped command. The note is still made, in the source and in
# OPSEC_SETUP.md, where it costs nothing.
check("the refusal does NOT describe the wake architecture to whoever reads "
      "this chat",
      not any(w in _lim2.why_not().lower()
              for w in ("courtesy", "vault", "24h", "budget", "real")))
check("NON-VACUITY -- the source still records that this is a courtesy limit, "
      "so the honesty was moved and not deleted",
      "courtesy" in open(os.path.join(REPO, "gs_telegram_pager"),
                         encoding="utf-8").read())


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
check("...and it names no machine to go and read it on",
      "vault" not in _chat.lower())
check("NON-VACUITY -- the reply is a real one, so the absences above are "
      "absences from a message that was actually sent",
      "ready" in _chat and "A3F1" in _chat)


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


# ===========================================================================
#  FOUR DEFECTS THAT BROKE NO EXISTING CHECK
# ===========================================================================
print("\n== the poll loop, the lock, and the digits ==")

# 1. THE BUSY LOCK, WEDGED FOREVER BY A FULL SD CARD.
#
# The release guard started at Thread.start(). limits.record() and
# integrity_log() both write to the same card and both run AFTER acquire() and
# BEFORE that try -- so a full or read-only card leaves `busy` held by nobody,
# and every later poke answers "a wake is already running" for the life of the
# process. On a headless box, with no way to wake anything and no clue why.
import threading as _th2


def _wedge_pager(fail_on):
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key = {"http": "x"}, "T", {}
    p.args = types.SimpleNamespace()
    p.allow, p.ignored, p.convos = {111}, 0, {}
    p.busy = _th2.Lock()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.burn, p.burn_after, p.burn_now = [], 0, False
    sent = []
    p.send = lambda c, t: (sent.append(t), True)[1]

    def _rec():
        if fail_on == "record":
            raise OSError(28, "No space left on device")
    p.limits = types.SimpleNamespace(why_not=lambda: "", record=_rec,
                                     recent=lambda: [], daily_cap=12,
                                     offset=0, save=lambda: None)
    return p, sent


_wp, _ws = _wedge_pager("record")
_saved_il = pg.integrity_log
# THE CALL MUST NOT ESCAPE, and catching it here is not politeness. Without
# the release guard, record() raises straight out of start_job -- so a suite
# that let it propagate would DIE with a traceback instead of reporting, and a
# mutation sweep scores a crashed suite NO-RESULT, never CAUGHT. Proven: this
# block reported NO-RESULT until the exception was caught and turned into a
# failing check with its own words.
_wp_raised = ""
try:
    pg.integrity_log = lambda *a, **k: None
    _wp.start_job(111, "receive_new", {"count": 1})
except BaseException as _e:                                  # noqa: BLE001
    _wp_raised = f"{type(_e).__name__}: {_e}"
finally:
    pg.integrity_log = _saved_il
check(f"lock: a failing state write is handled inside start_job, not raised "
      f"at the caller ({_wp_raised or 'no exception'})",
      _wp_raised == "")
check("lock: a state write that fails does NOT leave the wake lock held",
      not _wp.busy.locked())
check("lock: ...and the operator is told, rather than left guessing",
      any("could not start" in t for t in _ws))
# NON-VACUITY: the lock is really taken on the happy path, so "not locked"
# above means released and not never-acquired.
_wp2, _ws2 = _wedge_pager(None)
_started = []
_saved_thread = pg.threading.Thread
try:
    pg.integrity_log = lambda *a, **k: None
    pg.threading.Thread = lambda **k: types.SimpleNamespace(
        start=lambda: _started.append(1))
    _wp2.start_job(111, "receive_new", {"count": 1})
finally:
    pg.threading.Thread = _saved_thread
    pg.integrity_log = _saved_il
check("lock: NON-VACUITY -- a healthy poke DOES take the lock and start the "
      "worker", _wp2.busy.locked() and _started == [1])

# 2. A NON-DICT UPDATE MUST NOT KILL THE PROCESS.
#
# run() reads upd.get("update_id") in the FOR HEADER, which is outside the
# per-update try -- so one bare string in the result list raises
# AttributeError, systemd restarts, the offset was never advanced past that
# batch, and the pager crash-loops.
_up = pg.Pager.__new__(pg.Pager)
_up.proxies, _up.token = {"http": "x"}, "T"
_up.poll_failures = 0
_up.limits = types.SimpleNamespace(offset=0, save=lambda: None)
_saved_get = pg.safe_get
try:
    pg.safe_get = lambda url, proxies=None: {
        "ok": True, "result": [{"update_id": 1}, "junk", None, 7,
                               {"update_id": 2}]}
    _got = _up.updates()
finally:
    pg.safe_get = _saved_get
check("updates: a malformed element is filtered, not raised",
      _got == [{"update_id": 1}, {"update_id": 2}])
check("updates: NON-VACUITY -- the good elements still come through",
      len(_got) == 2)

# 3. AN UPDATE WITH NO USABLE id IS SKIPPED, NOT HANDLED FOREVER.
#
# The offset is what confirms an update to Telegram. One that can never
# advance the offset is redelivered on every poll -- so handling it means
# acting on one message for the life of the process.
_lp = pg.Pager.__new__(pg.Pager)
_lp.proxies, _lp.token, _lp.poll_failures = {"http": "x"}, "T", 0
_lp.ignored = 0
_lp.limits = types.SimpleNamespace(offset=0, save=lambda: None)
_handled = []
_lp.handle = lambda u: _handled.append(u)
_ticks = [0]


def _one_batch(url, proxies=None):
    _ticks[0] += 1
    if _ticks[0] > 1:
        raise KeyboardInterrupt
    return {"ok": True, "result": [{"update_id": "NaN", "message": {}},
                                   {"update_id": True, "message": {}},
                                   {"update_id": 5, "message": {}}]}


try:
    pg.safe_get = _one_batch
    pg.integrity_log = lambda *a, **k: None
    _b = _lp.updates()
    for _u in _b:
        _uid = _u.get("update_id")
        if isinstance(_uid, int) and not isinstance(_uid, bool):
            _lp.limits.offset = max(_lp.limits.offset, _uid + 1)
        else:
            _lp.ignored += 1
            continue
        _lp.handle(_u)
finally:
    pg.safe_get = _saved_get
    pg.integrity_log = _saved_il
check("updates: an update with a non-int id is skipped, not handled",
      [u["update_id"] for u in _handled] == [5])
check("updates: ...and True is not accepted as an id (True == 1 would move "
      "the cursor to 2)", _lp.ignored == 2 and _lp.limits.offset == 6)
# The source-level half, because the loop above is a paraphrase of run():
check("updates: run() itself excludes bool from the id check",
      "isinstance(uid, int) and not isinstance(uid, bool)" in _SRC_PG_EARLY)

# 4. isdecimal, NOT isdigit -- the bug the wizard documents as fixed and
#    parse_command never got. "²".isdigit() is True and int("²") RAISES, so a
#    typo escaped parse_command as a ValueError: handle() is inside run()'s
#    per-update try, so the operator got NO reply and it was counted as a
#    dropped update.
for _sup in ("/recv ²", "/depo ²", "/recv ³", "/depo ½"):
    _raised = False
    try:
        _j, _p, _e = pg.parse_command(_sup)
    except Exception:                                        # noqa: BLE001
        _raised = True
    check(f"digits: {_sup!r} is REFUSED, not raised",
          not _raised and _j == "" and _e)
# NON-VACUITY: ordinary digits still work, and so does the Arabic-Indic form
# the wizard's own test says legitimately reads as a slot.
check("digits: NON-VACUITY -- plain digits still parse",
      pg.parse_command("/recv 4")[1] == {"count": 4}
      and pg.parse_command("/depo 3")[1] == {"amount_slot": 3})
check("digits: NON-VACUITY -- Arabic-Indic digits still parse, as the wizard "
      "already decided they legitimately do",
      pg.parse_command("/depo ٢")[1] == {"amount_slot": 2})
# CODE, NOT PROSE. A substring ban punishes the comments that explain the
# fix -- the same trap the addr_index guard fell into. Every remaining mention
# of isdigit in this file is a note saying why isdecimal is used instead.
import ast as _ast_pg
_pg_calls = {n.func.attr for n in _ast_pg.walk(_ast_pg.parse(_SRC_PG_EARLY))
             if isinstance(n, _ast_pg.Call)
             and isinstance(n.func, _ast_pg.Attribute)}
check("digits: no isdigit() is CALLED anywhere — that predicate is wider than "
      "int() accepts",
      "isdigit" not in _pg_calls)
check("digits: NON-VACUITY -- isdecimal() IS called, so the guard exists",
      "isdecimal" in _pg_calls)
check("digits: NON-VACUITY -- and the prose still explains why, which a "
      "substring ban would have forbidden",
      "isdigit" in _SRC_PG_EARLY)


# ===========================================================================
#  THREE MORE THINGS THE CHAT DID NOT NEED TO SAY
# ===========================================================================
print("\n== /status, the manual, and the machine's own job names ==")
import types as _ty3
import threading as _th3


def _plain_pager(busy=False, why=""):
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key = {"http": "x"}, "T", {}
    p.args = _ty3.SimpleNamespace()
    p.allow, p.ignored, p.convos = {111}, 4, {}
    p.busy = _th3.Lock()
    if busy:
        p.busy.acquire()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.burn, p.burn_after, p.burn_now = [], 0, False
    p.limits = _ty3.SimpleNamespace(why_not=lambda: why, record=lambda: None,
                                    recent=lambda: [1, 2, 3], daily_cap=12,
                                    offset=0, save=lambda: None)
    seen = []
    p.send = lambda c, t: (seen.append(t), True)[1]
    return p, seen


# 1. /status printed the poke COUNT for the last 24h and busy True/False.
#    The count is how many deposits were started today. `busy` is whether the
#    machine is powered on AT THIS MOMENT -- the single most useful fact to
#    anyone deciding when to knock on a door -- and both sat permanently in the
#    transcript, on a command that exists to answer "can I send one".
_sp, _ss = _plain_pager()
_sp.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                        "message_id": 1, "text": "/status"}})
check("status: an idle pager answers 'ready'", _ss == ["ready"])
_sp2, _ss2 = _plain_pager(busy=True)
_sp2.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                         "message_id": 1, "text": "/status"}})
check("status: a busy one says wait, not that the machine is powered on",
      _ss2 == ["wait"])
check("status: neither answer carries a poke count or a power state",
      not any(w in " ".join(_ss + _ss2).lower()
              for w in ("24h", "poke", "busy", "true", "false", "/12")))
# NON-VACUITY: the two states really are distinguishable, so this is not one
# constant string.
check("status: NON-VACUITY -- idle and busy give DIFFERENT answers",
      _ss != _ss2)
# ...and a rate limit still wins, because that is the more actionable answer.
_sp3, _ss3 = _plain_pager(why="wait 42s")
_sp3.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                         "message_id": 1, "text": "/status"}})
check("status: a rate limit is reported over 'ready'", _ss3 == ["wait 42s"])

# 2. THE WHOLE MANUAL ON EVERY TYPO. f"no: {err}\n\n{HELP}" put the full
#    command list -- including the memo line -- back into the chat on each
#    mistake.
_hp, _hs = _plain_pager()
_hp.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                        "message_id": 1, "text": "/nope"}})
check("help: a typo is answered with the error alone",
      len(_hs) == 1 and _hs[0].startswith("no:"))
check("help: ...and does not reprint the command list",
      "OP_RETURN" not in _hs[0] and "/watch" not in _hs[0])
# NON-VACUITY: /help itself still prints it, once, on request.
_hp2, _hs2 = _plain_pager()
_hp2.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                         "message_id": 1, "text": "/help"}})
check("help: NON-VACUITY -- /help still prints the command list on request",
      any("/watch" in t for t in _hs2))

# 3. THE MACHINE'S OWN JOB NAME. OPSEC_SETUP section 5 step 5 specifies
#    "depo ready · slip A3F1"; the code sent "receive_and_quote ready".
check("names: the chat name for the quote job is the short one the doc "
      "specifies", pg.chat_name("receive_and_quote") == "depo")
check("names: ...and every job the protocol has HAS a chat name",
      all(j in pg.CHAT_NAME for j in P.JOBS))
check("names: NON-VACUITY -- an unknown job falls back to its own name "
      "rather than raising on the reply that says a wake landed",
      pg.chat_name("something_new") == "something_new")
check("names: no reply interpolates the raw job identifier any more",
      'f"{job}' not in _SRC_PG_EARLY)

# 4. THE HELP MUST DESCRIBE WHAT THE COMMANDS ACTUALLY DO.
#    "/status counters" survived the change that stopped it printing counters,
#    and "/check ~5 min" quoted the probe's own three-minute window while every
#    wake first serves a random 5-20 minutes of jitter before the job starts --
#    understating the round trip by two to seven times, on the command an
#    operator reaches for when money has not appeared.
check("help: /status is described as what it now answers, not as counters",
      "counters" not in pg.HELP)
check("help: /check's quoted time includes the wake jitter it always waits",
      "10-25 min" in pg.HELP)
_jit_lo, _jit_hi = _AG_JIT
check(f"help: ...and that figure is consistent with the real jitter "
      f"({_jit_lo // 60}-{_jit_hi // 60} min) plus the 3-minute probe",
      _jit_lo // 60 + 3 <= 10 and 25 >= _jit_hi // 60 + 3)
# NON-VACUITY: the help still lists the commands, so this is not passing on an
# emptied string.
check("help: NON-VACUITY -- every command is still listed",
      all(c in pg.HELP for c in ("/depo", "/recv", "/check", "/watch",
                                 "/cancel", "/status")))


# ===========================================================================
#  CHAT TEXT THAT ARRIVES THROUGH A VARIABLE
# ===========================================================================
print("\n== text that reaches the chat without being a literal at send() ==")
#
# A source scan for string literals at self.send() call sites cannot see a
# string that arrives in a variable. Two did, and both said things the
# transcript should not carry:
#
#   * Limits.why_not() -- sent verbatim as f"no: {why}" -- named the operator's
#     machine AND described the wake budget protecting it ("the vault's own 24h
#     budget is the real one"). That is a sentence about the architecture, on
#     the message an operator sees most often after a mistyped command.
#   * gs_doorbell refuses a bind with the Pi's own listen host and port in the
#     text, and poke() forwards that exception straight to Telegram.
_vlim = pg.Limits.__new__(pg.Limits)
_vlim.min_interval, _vlim.daily_cap = 300, 12
_vlim.last_poke, _vlim.pokes = __import__("time").time(), []
_why = _vlim.why_not()
check("varchat: the rate-limit reply says what to do and nothing else",
      _why.startswith("wait ") and _why.endswith("s"))
check("varchat: ...and names no machine and no budget architecture",
      not any(w in _why.lower()
              for w in ("vault", "24h", "budget", "courtesy", "real one")))
_vlim2 = pg.Limits.__new__(pg.Limits)
_vlim2.min_interval, _vlim2.daily_cap = 0, 2
_vlim2.last_poke = 0
_vlim2.pokes = [__import__("time").time()] * 5
_why2 = _vlim2.why_not()
check("varchat: the daily-cap reply is the same shape",
      _why2 and "vault" not in _why2.lower() and "courtesy" not in _why2.lower())
# NON-VACUITY: it still REFUSES, and still says something. A why_not() that
# returned "" would pass every check above and would also remove the limit.
check("varchat: NON-VACUITY -- both are still refusals with a reason",
      bool(_why) and bool(_why2))
_vlim3 = pg.Limits.__new__(pg.Limits)
_vlim3.min_interval, _vlim3.daily_cap = 300, 12
_vlim3.last_poke, _vlim3.pokes = 0, []
check("varchat: NON-VACUITY -- an allowed poke returns '' rather than a "
      "reason, so the two are distinguishable", _vlim3.why_not() == "")

# THE DOORBELL'S BIND REFUSAL, forwarded to the chat by poke(). _redact runs
# over it, and until now it stripped only token-shaped text.
for _host in ("192.168.1.50:9999", "0.0.0.0:41234", "10.0.0.5:18081",
              "pi.local:9999"):
    _msg = f"cannot listen on {_host} (Address already in use)"
    _red = pg._redact(_msg)
    check(f"varchat: {_host} does not survive into the chat",
          _host not in _red and "<host:port>" in _red)
# NON-VACUITY: the operator still learns what went wrong.
check("varchat: NON-VACUITY -- the reason survives, only the address goes",
      "already in use" in pg._redact("cannot listen on 1.2.3.4:9 (Address "
                                     "already in use)"))
# NON-VACUITY: ordinary replies are not mangled by the new rule.
for _plain in ("burned 3/7.", "pokes in last 24h: 3/12", "wait 30s",
               "A3F1: landed and spendable. The swap is done."):
    check(f"varchat: NON-VACUITY -- {_plain!r} passes through untouched",
          pg._redact(_plain) == _plain)
# ...and the token rule still works, which the new one sits beside.
check("varchat: NON-VACUITY -- a bot token is still stripped",
      pg._redact("bot123456789:AAEEabcdefghijklmnopqrstuvwxyz01")
      == "bot<token>")


# ===========================================================================
#  BURN AFTER READING
# ===========================================================================
print("\n== the chat can be emptied, and only from the host ==")
#
# The transcript is assumed read. Making the replies boring was the first half;
# removing them afterwards is the second. Neither replaces the other -- a
# message that says nothing is safe whether or not the delete lands.
#
# THE TRIGGER IS NOT A CHAT COMMAND, and that is the design rather than an
# omission. "/wipe" would put the word into the very transcript it empties -- a
# line in the operator's own hand saying there was something here worth
# deleting -- and would hand a stolen phone the power to destroy the operator's
# own record of what that phone did.
import signal as _sig
import types as _ty2


class _BurnPager:
    """A Pager with the network replaced, so deletes are counted not sent."""

    def __init__(self, burn_after=0, refuse=()):
        p = pg.Pager.__new__(pg.Pager)
        p.proxies, p.token, p.key = {"http": "x"}, "T", {}
        p.args = _ty2.SimpleNamespace()
        p.allow = {111}
        p.busy = __import__("threading").Lock()
        p.ignored = 0
        p.convos = {}
        p.clock = lambda: 0.0
        p.rng = __import__("random").SystemRandom()
        p.limits = _ty2.SimpleNamespace(why_not=lambda: "", record=lambda: None,
                                        recent=lambda: [], daily_cap=12,
                                        offset=0, save=lambda: None)
        p.burn, p.burn_after, p.burn_now = [], burn_after, False
        self.deleted = []
        self.refuse = set(refuse)
        p.delete_message = self._del
        self.p = p

    def _del(self, cid, mid):
        if mid in self.refuse:
            return False
        self.deleted.append((cid, mid))
        return True


# 1. THE OPERATOR'S OWN COMMANDS ARE TRACKED, and they are the half that
#    matters: the replies are boring by design, but "/depo 2" at 03:12 is not.
_b = _BurnPager()
_b.p.send = lambda c, t: True
_b.p.handle({"update_id": 1,
             "message": {"chat": {"id": 111}, "message_id": 900,
                         "text": "/status"}})
check("burn: the operator's own command message is tracked for deletion",
      any(m == 900 for _c, m, _t in _b.p.burn))
# NON-VACUITY: a chat that is NOT allowlisted must not be tracked -- deleting
# there is an action taken for somebody who was refused.
_b2 = _BurnPager()
_b2.p.send = lambda c, t: True
_b2.p.handle({"update_id": 1,
              "message": {"chat": {"id": 999}, "message_id": 901,
                          "text": "/status"}})
check("burn: NON-VACUITY -- a chat that is not allowlisted is not tracked",
      _b2.p.burn == [] and _b2.p.ignored == 1)

# 2. THE BOT'S OWN REPLIES ARE TRACKED, from whatever Telegram answers with.
_b3 = _BurnPager()
_sent_ids = [4242]
pg_saved_post = pg.safe_post
try:
    pg.safe_post = lambda url, payload, proxies=None: {
        "ok": True, "result": {"message_id": _sent_ids[0]}}
    _ok = _b3.p.send(111, "hello")
finally:
    pg.safe_post = pg_saved_post
check("burn: a reply that landed is tracked by its message_id",
      _ok and any(m == 4242 for _c, m, _t in _b3.p.burn))
# NON-VACUITY: a malformed answer must not raise -- the reply DID land, and
# turning that into a failure is the more expensive direction.
_b4 = _BurnPager()
try:
    pg.safe_post = lambda url, payload, proxies=None: {"ok": True}
    _ok2 = _b4.p.send(111, "hello")
    _raised = False
except Exception:
    _raised = True
finally:
    pg.safe_post = pg_saved_post
check("burn: NON-VACUITY -- an answer with no message_id costs the delete, "
      "not the reply", _ok2 and not _raised and _b4.p.burn == [])

# 3. EXPIRY. Old messages go, recent ones stay.
_b5 = _BurnPager(burn_after=60)
_now = __import__("time").time()
_b5.p.burn = [(111, 1, _now - 3600), (111, 2, _now - 5), (111, 3, _now - 120)]
_gone = _b5.p.burn_expired(60)
check("burn: messages past the deadline are deleted", _gone == 2
      and sorted(m for _c, m in _b5.deleted) == [1, 3])
check("burn: ...and one inside it is kept",
      [m for _c, m, _t in _b5.p.burn] == [2])
# NON-VACUITY: with the feature off, nothing is deleted however old.
_b6 = _BurnPager(burn_after=0)
_b6.p.burn = [(111, 1, _now - 999999)]
check("burn: NON-VACUITY -- with --burn-after 0 nothing is deleted at all",
      _b6.p.burn_expired(0) == 0 and _b6.deleted == []
      and len(_b6.p.burn) == 1)

# 4. A REFUSED DELETE IS DROPPED, NOT RETRIED FOREVER. Telegram refuses past
#    48h and that refusal is permanent; retrying every tick would turn one
#    refusal into a permanent stream of requests over Tor.
_b7 = _BurnPager(burn_after=1, refuse={7})
_b7.p.burn = [(111, 7, _now - 99), (111, 8, _now - 99)]
_b7.p.burn_expired(1)
check("burn: a refused delete is dropped rather than retried on every tick",
      _b7.p.burn == [] and _b7.deleted == [(111, 8)])

# 5. THE SIGNAL. It sets a flag and does no I/O -- a handler runs between
#    bytecodes and can arrive inside safe_post.
_b8 = _BurnPager()
_b8.p.burn = [(111, 11, _now), (111, 12, _now)]
check("burn: SIGUSR1 does not delete anything itself", not _b8.p.burn_now)
_b8.p.arm_burn(_sig.SIGUSR1, None)
check("burn: ...it sets a flag the loop reads", _b8.p.burn_now
      and _b8.deleted == [])
_g, _t = _b8.p.burn_all()
check("burn: ...and burn_all then deletes everything tracked",
      (_g, _t) == (2, 2) and _b8.p.burn == [])
# HONEST ARITHMETIC: gone and tried differ when Telegram refuses, and the
# operator needs both numbers rather than the word "wiped".
_b9 = _BurnPager(refuse={21})
_b9.p.burn = [(111, 21, _now), (111, 22, _now)]
check("burn: burn_all reports gone AND tried, because they differ",
      _b9.p.burn_all() == (1, 2))
# ONE CHAT ONLY when a chat is named: burning another chat's history is an
# action on a conversation the caller is not in.
_b10 = _BurnPager()
_b10.p.burn = [(111, 31, _now), (222, 32, _now)]
_b10.p.burn_all(111)
check("burn: burning one chat leaves another chat's messages alone",
      _b10.deleted == [(111, 31)]
      and [m for _c, m, _t in _b10.p.burn] == [32])

# 6. NO CHAT COMMAND DOES THIS. The word must not exist in the parser.
for _w in ("/wipe", "/burn", "/delete", "/destruct"):
    _j, _p, _e = pg.parse_command(_w)
    check(f"burn: {_w} is not a command", _j == "" and _e not in
          ("wipe", "burn", "delete"))
_SRC_PG = open(os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read()
check("burn: ...and the source has no chat-command branch for it either",
      '"/wipe"' not in _SRC_PG and '"/burn"' not in _SRC_PG)

# 7. NOTHING NEW REACHES THE SD CARD. The message list is a log of exactly
#    when the operator was active, which is the thing the card must not hold.
check("control: Limits.save exists, so the check below reads a real function",
      "def save" in _SRC_PG)
check("burn: the tracked-message list is never written to state",
      "burn" not in _SRC_PG.split("def save")[1].split("\n    def ")[0])
# NON-VACUITY: save DOES write something, so this is not passing on an empty
# function body.
check("burn: NON-VACUITY -- save really does persist the cursor and counters",
      "offset" in _SRC_PG.split("def save")[1].split("\n    def ")[0])

# 8. A --burn-after past Telegram's window is REFUSED, not clamped: it would
#    never fire, and the chat would look like it was being emptied.
_rc = None
try:
    pg.main(["--chat-id", "1", "--burn-after", str(pg.TG_DELETE_WINDOW_S + 1)])
except SystemExit as _e:
    _rc = str(_e)
check("burn: a --burn-after past the 48h window is refused with the reason",
      _rc and "deletion window" in _rc)
_rc2 = None
try:
    pg.main(["--chat-id", "1", "--burn-after", "-5"])
except SystemExit as _e:
    _rc2 = str(_e)
check("burn: ...and a negative one is refused too",
      _rc2 and "negative" in _rc2)
# NON-VACUITY: a value INSIDE the window must get past this gate. It still
# exits -- there is no Tor here -- but for a different reason, which proves the
# two refusals above are about --burn-after and not about main() always dying.
_rc3 = None
try:
    pg.main(["--chat-id", "1", "--burn-after", "600"])
except SystemExit as _e:
    _rc3 = str(_e)
except Exception as _e:                                      # noqa: BLE001
    _rc3 = f"{type(_e).__name__}: {_e}"
check("burn: NON-VACUITY -- a value inside the window passes this gate and "
      f"fails later for its own reason ({str(_rc3)[:40]!r})",
      _rc3 is not None and "deletion window" not in str(_rc3)
      and "negative" not in str(_rc3))


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
