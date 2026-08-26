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
import re
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

def _confirm_answer(sent):
    """Read the wizard's arithmetic back off the chat and solve it."""
    import re as _re_c
    m = _re_c.search(r"(\d+) \+ (\d+) = \?",
                     "\n".join(t for _c, t in sent))
    return int(m.group(1)) + int(m.group(2)) if m else 0


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
        ("/watch a3f1", "watch", {"handle": "A3F1"}),
        ("/check A3F1", "swap_status", {"handle": "A3F1"})):
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
# /depo is not in this list any more: it produces NO job directly, only the
# wizard, which is the point. The wizard's own output is checked below.
check("the jobs it can ask for are exactly the ones the protocol allows",
      {pg.parse_command(t)[0] for t in ("/watch A3F1",
                                        "/check A3F1")} <= set(P.JOBS))
check("...and /depo produces no job of its own at all, in either form",
      pg.parse_command("/depo")[0] == ""
      and pg.parse_command("/depo 2")[0] == "")

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
    p.allow_users = set()
    p.handle_owner = {}
    p.handle_job = {}
    p._chain = None
    p._chain_leg = 0
    p._status_at = None
    p.spenders = 1
    p.busy = _th.Lock()
    p.ignored = 0
    p.convos = {}
    p.clock = lambda: 1000.0
    p.rng = __import__("random").SystemRandom()
    p.limits = _ty.SimpleNamespace(why_not=lambda: "", record=lambda: None,
                                   recent=lambda: [], daily_cap=12)
    seen = []
    p.send = lambda c, t, buttons=None: (seen.append(t), True)[1]
    p.start_job = lambda c, j, pa: _wiz.append((j, pa))
    for a in answers:
        if a == "<confirm>":
            import re as _re
            m = _re.search(r"(\d+) \+ (\d+) = \?", "\n".join(seen))
            a = str(int(m.group(1)) + int(m.group(2))) if m else "0"
        p.handle({"update_id": 1, "message": {"chat": {"id": 1}, "text": a}})
    return seen


_LEGAL = {"0.0001": 10_000, "0.05": 5_000_000, "1": 100_000_000,
          "2.5": 250_000_000, "100": 10_000_000_000}
for _typed in _LEGAL:
    _wizard_params(["/depo", _typed, "<confirm>"])
for _hostile in (XMR, MEMO, BTC, "-1", "1e9", "0.05 0.05", "²", "٢",
                 "0.05; /depo 7", "‮2", "٧", "0.05\n7", "x" * 500,
                 "0,05", "0.000000001", "999999", "١٢٣", "１"):
    _wizard_params(["/depo", _hostile, "<confirm>"])
    _wizard_params(["/depo", "0.05", _hostile])
# EXACTLY THE LEGAL SET, and '٢' is now on the hostile side of that line.
#
# This check used to say the opposite in as many words: "NOT 'exactly eight
# jobs': '٢' is Arabic-Indic two, isdecimal() accepts it and int() reads it as
# 2, so it legitimately produces slot 2." That was a correct reading of the
# code and a defensible call while the parameter was a LADDER INDEX -- picking
# rung 2 by an unusual keystroke is a curiosity, not a loss.
#
# It stopped being defensible when the parameter became money. The same
# property that made "٢" a harmless way to say slot 2 made "１" a way to say
# ONE WHOLE BITCOIN through a character that renders as a slightly wide 1 --
# and Python's \d, str.isdecimal(), int(), float() and Decimal() all agree
# with it. So the amount parser is pinned to [0-9] and every one of the 455
# non-ASCII decimal digits is refused here.
check("every job the wizard produces is a single in-range satoshi count, "
      "whatever was typed at it",
      all(set(pa) == {"amount_sat"}
          and P.DEPOSIT_MIN_SAT <= pa["amount_sat"] <= P.DEPOSIT_MAX_SAT
          for _, pa in _wiz))
check("...and the amounts produced are EXACTLY the legal ones typed, so no "
      "hostile string reached the wire as a number",
      {pa["amount_sat"] for _, pa in _wiz} == set(_LEGAL.values()))
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
for _t in ("/watch A3F1", "/check A3F1"):
    _j, _p, _e = pg.parse_command(_t)
    check(f"gs_wake_proto accepts what {_t!r} composes",
          _j in P.JOBS and set(_p) <= set(P.JOBS[_j]["schema"]))
check("no job this pager can ask for drives a forbidden tool",
      all(t not in P.FORBIDDEN_TOOLS
          for j in ("receive_and_quote", "watch")
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


_p.handle(_msg(999, "/check A3F1"))
check("a chat that is not allowlisted gets NO reply -- a reply would confirm "
      "the bot is alive to whoever found it", _sent == [])
check("...and it is counted rather than silently dropped", _p.ignored == 1)
check("...and it never reaches the wake channel", _poked == [])
_p.handle(_msg(111, "/check A3F1"))
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
        run_wake=lambda a, k, j, p, on_event=None: _FakePending(_o, _hh))
    _pv.poke(111, "receive_and_quote", {"amount_sat": 5000000})
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
    if _out == "refused":
        # "TRY /status, THEN AGAIN" WAS WRONG HALF THE TIME, and wrong in the
        # direction that costs the operator the thing it told them to spend.
        #
        # Refusals have two shapes and the reason is deliberately not on the
        # wire, so this end cannot tell them apart. The wake budget clears by
        # itself. The ACCOUNT CEILING does not: once the wallet holds its
        # limit, minting is refused every single time, so /deposit and
        # /address are dead until somebody is physically at the machine -- and
        # the old message told the operator to keep trying, spending a wake on
        # each identical refusal.
        check("refused: it no longer tells the operator to just try again",
              "then again" not in _text)
        check("refused: ...it gives the rule that is right for both kinds, "
              "and needs no reason from the wire",
              "a second try is refused" in _text and "stop" in _text)
        check("refused: ...and says some refusals need somebody at the machine",
              "somebody at the machine" in _text)
        check("refused: ...and says retrying is not free",
              "daily allowance" in _text)
        check("refused: ...while still naming no machine and no reason",
              "vault" not in _text.lower() and "ceiling" not in _text.lower()
              and "budget" not in _text.lower())
        # THE RENDERED MESSAGE, not the literals it is built from. The ceiling
        # in test_depo_wizard measures string constants, and this reply is
        # several joined with `+` -- so a paragraph can be added there in
        # pieces that each pass. Measured here as the operator receives it.
        check(f"refused: ...and the whole rendered reply stays short "
              f"({len(_text)} chars)", len(_text) <= 420)
pg.doorbell = _real_doorbell

# ---- THE DOORBELL SAW SOMETHING AND ONLY THE TERMINAL WAS TOLD ----------
#
# gs_doorbell collects `events` and _report_events prints the two that change
# what the operator should believe -- under a docstring saying `events` "was
# collected and never read by anything ... and worse here, because the one
# event that means 'your job did not go where you think' was among the ones
# being thrown away." It was fixed for the CLI and left unfixed for the
# surface the feature exists for: grep for `events` in the pager found one
# hit, inside a comment.
#
# The case that matters: a replayed M1 collects the job, the real vault's M1
# is then refused, and events are ['job_collected', 'm1_second_ephemeral'].
# The CLI prints "the job went to a boot that cannot read it, and nothing
# ran". The chat got "I do NOT know whether the funds moved. ... Do not run
# /withdraw again until you have checked" -- forbidding the retry that is in
# fact the right move.
print("\n== what the doorbell saw, told to the operator ==")


class _EventPending:
    def __init__(self, events, out="collected_no_result"):
        self.events = list(events)
        self.result = None
        self._out = out

    def outcome(self):
        return self._out


_ep = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://x"})
_eps = []
_ep.send = lambda cid, t, buttons=None: (_eps.append(t), True)[1]
pg.doorbell = lambda: types.SimpleNamespace(
    run_wake=lambda a, k, j, p, on_event=None:
        _EventPending(["job_collected", "m1_second_ephemeral"]))
try:
    _ep.poke(111, "withdraw", {"exit_to": ["4" + "1" * 94], "depth": 1})
finally:
    pg.doorbell = _real_doorbell
_eptext = "\n".join(_eps)
check("events: a second signed request for the job reaches the CHAT, not just "
      "a terminal", "second signed request" in _eptext)
check("events: ...and says what it means for what follows",
      "nothing ran" in _eptext and "Check before assuming" in _eptext)
check("events: ...before the outcome, since it changes how that reads",
      _eps and "second signed request" in _eps[0])
check("events: ...and the outcome still arrives after it",
      len(_eps) >= 2 and "never reported" in _eptext.lower())
# A CLOSED VOCABULARY, so the vault gains no free-text channel into a chat:
# this box renders its OWN sentence for a word the doorbell chose from a set
# it also fixes. Same rule as PHASE_LINES.
_ep2 = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://x"})
_eps2 = []
_ep2.send = lambda cid, t, buttons=None: (_eps2.append(t), True)[1]
pg.doorbell = lambda: types.SimpleNamespace(
    run_wake=lambda a, k, j, p, on_event=None:
        _EventPending(["job_collected", "; DROP TABLE --", "m1_retry"]))
try:
    _ep2.poke(111, "receive_and_quote", {"amount_sat": 5000000})
finally:
    pg.doorbell = _real_doorbell
check("events: a word this box has no sentence for is not rendered at all",
      "DROP TABLE" not in "\n".join(_eps2))
check("events: ...and neither is bookkeeping nobody can act on",
      "m1_retry" not in "\n".join(_eps2))
check("events: NON-VACUITY -- an ordinary run with nothing to report says "
      "nothing extra",
      not any("second signed request" in _t for _t in _eps2))
# THE VOCABULARY IS A REAL SUBSET of what the doorbell can record, or this is
# a filter that lets everything through.
_dbsrc_ev = open(os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read()
check("events: every word rendered is one the doorbell actually records",
      all(f'"{_w}"' in _dbsrc_ev for _w in pg.EVENT_VOCAB))
check("events: ...and it is a subset, not everything the doorbell records",
      len(pg.EVENT_VOCAB) < len(set(re.findall(
          r'events\.append\("([a-z0-9_]+)"\)', _dbsrc_ev))))

# ---- "YOUR FUNDS ARE EXACTLY WHERE THEY WERE" -- SAID BY A BOX WITH NO -----
# ---- IDEA WHERE THEY ARE --------------------------------------------------
#
# The pager knows one true thing when a job expires uncollected: it was never
# handed over, so THIS attempt cannot have started anything. It converted that
# into a claim about the WALLET, and there is nothing behind it. This box has
# never been told a balance, and it keeps no record that a wake is in flight:
# `busy` is process memory and the shipped unit has Restart=on-failure.
#
# So the reachable false case is ordinary: the pager dies during a withdrawal
# and comes back, the vault is still mixing, the next magic packet lands on a
# machine that is already up and nothing collects it. The operator is told
# their funds are exactly where they were, and invited to try again -- which,
# on the one job that spends, is an invitation to spend it twice.
#
# The `refused` branch gets this right and defends itself as "THE ONE ENDING
# WHERE 'NOTHING RAN' IS CERTAIN". It is certain there because the vault said
# so. Here nobody said anything at all.
print("\n== an expired withdrawal, and what the pager cannot know ==")
_xp = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://x"})
_xsent = []
_xp.send = lambda cid, t, buttons=None: (_xsent.append(t), True)[1]
pg.doorbell = lambda: types.SimpleNamespace(
    run_wake=lambda a, k, j, p, on_event=None:
        _FakePending("expired_uncollected", ""))
try:
    _xp.poke(111, "withdraw", {"exit_to": ["4" + "1" * 94], "depth": 1})
    _xt = "\n".join(_xsent)
finally:
    pg.doorbell = _real_doorbell
check("expired: it no longer makes a claim about the wallet",
      "exactly where they were" not in _xt
      and "NOTHING WAS SPENT" not in _xt)
check("expired: ...and scopes what it says to THIS attempt, which is the only "
      "thing it actually knows",
      "THIS attempt" in _xt)
check("expired: ...and says outright that it keeps no record of an earlier one",
      "no record" in _xt.lower())
check("expired: ...and sends them to the balance before a second withdrawal, "
      "rather than inviting one",
      "check the balance" in _xt.lower())
check("expired: ...while still saying the one thing that IS certain — this "
      "attempt handed nothing over",
      "never picked up" in _xt and "spent nothing" in _xt)
# NON-VACUITY: a DEPOSIT that expires still just says try again, because
# nothing about a deposit can have been spent and there is no second reading.
_dxp = pg.Pager(_args, "123456:TOKEN", {}, {"https": "socks5h://x"})
_dxs = []
_dxp.send = lambda cid, t, buttons=None: (_dxs.append(t), True)[1]
pg.doorbell = lambda: types.SimpleNamespace(
    run_wake=lambda a, k, j, p, on_event=None:
        _FakePending("expired_uncollected", ""))
try:
    _dxp.poke(111, "receive_and_quote", {"amount_sat": 5000000})
finally:
    pg.doorbell = _real_doorbell
check("expired: NON-VACUITY -- a deposit that expires still simply says to "
      "try again, so this is a branch and not a blanket hedge",
      "Try again." in "\n".join(_dxs)
      and "check the balance" not in "\n".join(_dxs).lower())




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
DB.run_wake = lambda a, k, j, p, on_event=None: _real_rw(
    a, k, j, p, sock_factory=lambda: _FakeSock(),
    sleep=lambda n: time.sleep(min(n, 0.05)), on_event=on_event)
threading.Thread(target=_vault, args=("A3F1",), daemon=True).start()
# THROUGH THE WIZARD, because that is the only path to a wake now. The
# end-to-end drive used the one-shot form, which is refused.
_pe.handle(_msg(111, "/depo"))
_pe.handle(_msg(111, "2"))
_pe.handle(_msg(111, str(_confirm_answer(_sent))))
# WAIT FOR THE HANDLE, NOT FOR A MESSAGE COUNT. The old loop waited for
# len(_sent) >= 2 -- which the wizard already satisfies before the wake even
# starts (the slot prompt and the confirm question), so it fell straight
# through and read a chat that had no handle in it yet.
for _ in range(500):
    if any("A3F1" in t for _c, t in _sent):
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
      "quoted" in _chat and "A3F1" in _chat)


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
    p.allow_users, p.handle_owner, p.handle_job = set(), {}, {}
    p._chain = None
    p._chain_leg = 0
    p._status_at = None
    p.spenders = 1
    p.busy = _th2.Lock()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.burn, p.burn_after, p.burn_now = [], 0, False
    sent = []
    p.send = lambda c, t, buttons=None: (sent.append(t), True)[1]

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
    _wp.start_job(111, "receive_and_quote", {"amount_sat": 5000000})
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
    _wp2.start_job(111, "receive_and_quote", {"amount_sat": 5000000})
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

# 4. THE POLL-FAILURE EXIT MUST NOT KILL A WAKE THAT IS IN FLIGHT.
#
# THE MOST EXPENSIVE BUG THIS FILE HAS HELD, and every suite was green through
# it. safe_get times out at 20 s and the failure path sleeps 5, so
# MAX_POLL_FAILURES is reached after roughly five minutes of Tor being
# unreachable -- routine on Tor over WireGuard. The worker that runs a wake is
# a DAEMON thread, so SystemExit on the polling thread tears the interpreter
# down without joining it, and the in-process doorbell server dies with its
# socket closed.
#
# End to end: a withdrawal the vault already collected keeps running ON THE
# VAULT for up to 16.75 h, spends real money, and POSTs its result to a port
# nothing is bound to. gs_wake_agent.report_back catches that, writes
# `result_undeliverable`, and the vault powers off. The mix happened. The
# operator's last message was "working" and nothing ever follows it.
_saved_sleep = pg.time.sleep
pg.time.sleep = lambda _s: None


def _drive_polls(busy_held, ticks):
    """Run updates() through `ticks` dead polls. True if it called sys.exit."""
    _q = pg.Pager.__new__(pg.Pager)
    _q.proxies, _q.token, _q.poll_failures = {"http": "x"}, "T", 0
    _q.busy = threading.Lock()
    _q.limits = types.SimpleNamespace(offset=0, save=lambda: None)
    if busy_held:
        _q.busy.acquire()
    for _ in range(ticks):
        try:
            _q.updates()
        except SystemExit:
            return True, _q
    return False, _q


try:
    pg.safe_get = lambda url, proxies=None: (_ for _ in ()).throw(
        OSError("SOCKS connect failed"))
    pg.integrity_log = lambda *a, **k: None
    _exited_busy, _qb = _drive_polls(True, pg.MAX_POLL_FAILURES + 8)
    _exited_idle, _qi = _drive_polls(False, pg.MAX_POLL_FAILURES + 8)
    # AND IT STILL STOPS once the wake is done, or the narrowing became a
    # permanent licence to run deaf.
    _qb.busy.release()
    try:
        _qb.updates()
        _stops_after = False
    except SystemExit:
        _stops_after = True
finally:
    pg.safe_get = _saved_get
    pg.integrity_log = _saved_il
    pg.time.sleep = _saved_sleep

check("polls: a wake in flight is NOT killed by Telegram being unreachable",
      not _exited_busy)
check("polls: ...and the failure counter still climbed, so it is not merely "
      "not counting", _qb.poll_failures > pg.MAX_POLL_FAILURES)
check("polls: NON-VACUITY -- with nothing running it DOES still stop, which "
      "is the original rule", _exited_idle)
check("polls: ...and it stops on the next poll once the wake finishes, so "
      "this is a delay and not a licence to run deaf", _stops_after)

# 4b. EVERY COMMAND THAT WORKS IS PUBLISHED, AND EVERY PUBLISHED ONE WORKS.
#
# /receive, /fee, /speed and /exit were all handled in parse_command, all had
# answers, and NONE of them was in BOT_COMMANDS -- so setMyCommands never
# published them and HELP (built from that same list) never mentioned them.
# The operator had to already know they existed and how they were spelled,
# which publish_commands' own docstring calls "indistinguishable from a bot
# that does not work". A four-command blind spot survived a green suite.
_HANDLED_ERRS = {"depo_wizard", "withdraw_wizard", "settings", "fee", "speed",
                 "exit", "cancel", "help", "welcome", "status"}
_unresolved = []
for _c, _desc in pg.BOT_COMMANDS:
    _job, _params, _err = pg.parse_command(f"/{_c}")
    # A command "resolves" if it starts a job, opens a wizard, or is one of
    # the answers handle() dispatches on. "handle must be 4 hex characters" is
    # a resolved command asking for its argument, not an unknown one.
    if not (_job or _err in _HANDLED_ERRS or "handle" in _err):
        _unresolved.append(_c)
check(f"menu: every published command resolves in parse_command "
      f"({len(pg.BOT_COMMANDS)} of them)", _unresolved == [])
# AND THE OTHER DIRECTION, which is the one that was broken. Aliases are
# deliberately unpublished -- one spelling in the menu, several accepted --
# so they are named here rather than inferred.
# THE PUBLISHED SPELLINGS CHANGED, AND SO DID WHICH SIDE OF THIS LINE THEY SIT
# ON. /receive read as "receive my money" and meant "mint me an address" --
# opposite ends of the pipeline -- and the command that actually pays the
# operator was /send, which does not say a direction at all. The menu now
# offers /address and /withdraw; /receive, /recv and /send are accepted
# forever, for the reason this file gives about /depo.
# "recv", "receive", "addr" and "address" are ANSWERED, not handled: the
# command is gone and parse_command returns a sentence saying so, rather than
# "unknown command", because an operator with the word in their fingers should
# be told it moved and not that the bot is broken.
_ALIASES = {"depo", "dep", "recv", "receive", "addr", "address", "send",
            "stop", "watch"}
_pub = {c for c, _ in pg.BOT_COMMANDS}
_handled = set(re.findall(r'cmd (?:==|in) \(?"/([a-z]+)"', _SRC_PG_EARLY))
_handled |= set(re.findall(r'"/([a-z]+)"[,)]',
                           _SRC_PG_EARLY.split("def parse_command")[1]
                           .split("\ndef ")[0]))
check("menu: every command parse_command handles is published or a named alias",
      sorted(_handled - _pub - _ALIASES) == [])
# NON-VACUITY: the scrape really did find the commands, so this is not two
# empty sets agreeing.
check("menu: NON-VACUITY -- the handled set was actually populated",
      len(_handled) >= 12 and "fee" in _handled and "settings" in _handled)
# AND THE ANSWERS POINT AT PUBLISHED SPELLINGS. EXIT_ANSWER said "see
# /withdraw", which parse_command accepts but the menu never offers.
for _name, _txt in (("EXIT_ANSWER", pg.EXIT_ANSWER),
                    ("SPEED_ANSWER", pg.SPEED_ANSWER),
                    ("FEE_ANSWER", pg.FEE_ANSWER)):
    _pointed = set(re.findall(r"/([a-z]+)", _txt))
    check(f"menu: {_name} points only at published commands "
          f"({sorted(_pointed) or 'none'})", _pointed <= _pub)

# 5. "WORKING. THIS TAKES A WHILE." IS NOT A NUMBER ANYONE CAN WAIT OUT.
#
# That was the message for EVERY job, and the jobs are not alike: a status
# probe is minutes, a withdrawal holds `busy` -- every command, not just
# another wake -- for the better part of a day. An operator told "a while" and
# then answered "a wake is already running" for sixteen hours concludes the
# bot is broken, which is the report this whole channel exists not to produce.
_said = []
_wp = pg.Pager.__new__(pg.Pager)
_wp.args = types.SimpleNamespace(no_jitter=False)
_wp.spenders = 1
_wp.limits = types.SimpleNamespace(why_not=lambda: "", record=lambda: None)
_wp.send = lambda cid, t, buttons=None: (_said.append((cid, t)), True)[1]
_saved_thread = threading.Thread
try:
    pg.integrity_log = lambda *a, **k: None
    threading.Thread = lambda **kw: types.SimpleNamespace(start=lambda: None)
    _durations = {}
    for _j in sorted(P.JOBS):
        _said.clear()
        _wp.busy = threading.Lock() if False else _th2.Lock()
        _wp.start_job(1, _j, {})
        _durations[_j] = _said[0][1] if _said else ""
finally:
    threading.Thread = _saved_thread
    pg.integrity_log = _saved_il

check("working: every job says how long it will hold the pager",
      all(re.search(r"up to \d+\s*(h|min)", _t)
          for _t in _durations.values()))
check("working: ...and says that nothing else can run meanwhile, which is "
      "what `busy` actually means",
      all("Nothing else" in _t for _t in _durations.values()))
# THE FIGURES ARE NOT ALL THE SAME, or one message is being printed for five
# very different waits and the number is decoration.
check("working: NON-VACUITY -- the durations actually differ per job",
      len({re.search(r"up to (\d+\s*(?:h|min))", _t).group(1)
           for _t in _durations.values()}) > 1)
# AND THE SPENDING JOB IS THE LONG ONE, stated in hours rather than minutes.
check("working: the withdrawal is reported in HOURS, not 'a while'",
      "h." in _durations["withdraw"] or re.search(r"up to \d+h",
                                                  _durations["withdraw"]))
# DERIVED, NOT TYPED. The figure must track result_budget_s, or it becomes the
# next 9900 -- a hand-copied duration that stopped being true when a job was
# added and that nothing noticed.
#
# AND IT IS THREE TERMS, NOT TWO. This summed result_budget_s and the pre-WOL
# ceiling. The window actually held is PRE_WOL_MAX_S, then the doorbell's
# FETCH_WINDOW_S while it waits to be collected, and only THEN result_budget_s
# from collected_at -- Pending.finished() is false while fetch_open() holds,
# so the three are strictly sequential. Hour-rounding hid the missing term on
# the long jobs and not on the short ones: /deposit was quoted 50 minutes
# against a real 60, /check 40 against 50. What an operator does in that gap
# is send another command and be told something is already running, which is
# the experience this message exists to prevent.
_want_h = (P.result_budget_s("withdraw") + DB.FETCH_WINDOW_S
           + DB.PRE_WOL_MAX_S) // 3600 + 1
check(f"working: the withdrawal figure is derived from result_budget_s "
      f"({_want_h}h)", f"up to {_want_h}h" in _durations["withdraw"])
# THE SHORT JOBS ARE WHERE IT SHOWED, so they are what pins it: no rounding to
# absorb the missing ten minutes.
for _sj in ("swap_status", "receive_and_quote"):
    _want_s = (P.result_budget_s(_sj) + DB.FETCH_WINDOW_S + DB.PRE_WOL_MAX_S)
    _txt = (f"up to {_want_s // 3600 + 1}h" if _want_s >= 3600
            else f"up to {max(1, _want_s // 60)} min")
    check(f"working: {_sj} quotes the whole window it holds, fetch window "
          f"included ({_txt})", _txt in _durations[_sj])
# NON-VACUITY: the fetch window is a real, non-zero term, so the checks above
# are about something rather than about adding zero.
check("working: NON-VACUITY -- the fetch window is minutes, not nothing",
      DB.FETCH_WINDOW_S >= 300)
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
for _sup in ("/recv ²", "/recv ³", "/recv ½", "/recv ٩٩٩"):
    _raised = False
    try:
        _j, _p, _e = pg.parse_command(_sup)
    except Exception:                                        # noqa: BLE001
        _raised = True
    check(f"digits: {_sup!r} is REFUSED, not raised",
          not _raised and _j == "" and _e)
# NON-VACUITY: ordinary digits still work, and so does the Arabic-Indic form
# the wizard's own test says legitimately reads as a slot.
# NON-VACUITY moved to the commands that still take an argument: /recv is
# gone, so the digit path it used to exercise is /check and /wait's handle.
check("digits: NON-VACUITY -- a real handle still parses",
      pg.parse_command("/check A3F1")[1] == {"handle": "A3F1"})
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


def _plain_pager(busy=False, why="", spenders=1):
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key = {"http": "x"}, "T", {}
    p.args = _ty3.SimpleNamespace()
    p.allow, p.ignored, p.convos = {111}, 4, {}
    p.allow_users, p.handle_owner, p.handle_job = set(), {}, {}
    p._chain = None
    p._chain_leg = 0
    p._status_at = None
    p.spenders = spenders
    p.busy = _th3.Lock()
    if busy:
        p.busy.acquire()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.burn, p.burn_after, p.burn_now = [], 0, False
    p.limits = _ty3.SimpleNamespace(why_not=lambda: why, record=lambda: None,
                                    recent=lambda: [1, 2, 3], daily_cap=12,
                                    offset=0, save=lambda: None)
    seen = []
    p.send = lambda c, t, buttons=None: (seen.append(t), True)[1]
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
# ...AND SO DOES THE GATE THAT NEVER CLEARS ON ITS OWN.
#
# start_job refuses on THREE things and this answer read two of them. The
# third -- more than one person allowlisted against one wallet -- refuses
# EVERY job unconditionally and cannot time out, so a bot configured that way
# answered "ready" to "can I start one right now" and then refused every
# single command that followed. Confidently wrong about the one gate nobody
# can wait out.
_sp4, _ss4 = _plain_pager(spenders=2)
_sp4.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                         "message_id": 1, "text": "/status"}})
check("status: a bot allowlisted for two people does not answer 'ready' to "
      "'can I start one'",
      len(_ss4) == 1 and _ss4[0] != "ready"
      and _ss4[0].startswith("not ready"))
check("status: ...and says which of the three gates it is, since this is the "
      "one that needs a person to fix it",
      "one wallet" in _ss4[0] and "allowlisted" in _ss4[0])
# THE SAME PAGER REALLY DOES REFUSE THE WORK, so this is not a warning about
# a condition that would have been fine.
_sp4.send = lambda c, t, buttons=None: (_ss4.append(t), True)[1]
_sp4.start_job(111, "receive_and_quote", {"amount_sat": 5000000})
check("status: NON-VACUITY -- and start_job on that same pager refuses too, "
      "so the answer matched what would actually have happened",
      "one wallet" in _ss4[-1] and len(_ss4) == 2)
# NON-VACUITY: one spender and everything else equal still answers ready, so
# this reads the count and not something else.
_sp5, _ss5 = _plain_pager(spenders=1)
_sp5.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                         "message_id": 1, "text": "/status"}})
check("status: NON-VACUITY -- one spender still answers 'ready'",
      _ss5 == ["ready"])

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
      any("/wait" in t for t in _hs2))

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
# ...AND THEN THE FIGURE ITSELF BECAME THE PROBLEM, one layer up.
#
# "10-25 min" was TYPED here, and start_job computes the real hold on every
# run from result_budget_s plus the doorbell's pre-WOL ceiling and its fetch
# window -- and says it. Two numbers for one wait, and the typed one was the
# smaller: the menu promised 10-25 minutes and the bot answered "up to 55 min"
# one tap later, on the command an operator reaches for when money has not
# appeared.
#
# A published list cannot derive that figure: BOT_COMMANDS is a module
# constant and the windows live in gs_doorbell, which is loaded by path at
# call time. So the list stops quoting a duration it cannot keep true, and the
# derived one -- which every job already prints -- is the only one.
check("help: the command list quotes no duration it cannot derive",
      not re.search(r"\d+\s*-\s*\d+\s*min|up to \d+\s*(min|h)\b", pg.HELP))
_jit_lo, _jit_hi = _AG_JIT
check(f"help: ...and the derived one covers the jitter it always waits "
      f"({_jit_lo // 60}-{_jit_hi // 60} min), which is what the typed figure "
      f"was added for",
      P.result_budget_s("swap_status") > _jit_hi)
# THE ARGUMENT IS NAMED INSTEAD, which is the thing the list CAN say and the
# thing an operator cannot guess: both refuse without a 4-hex label, in a word
# ("handle") the chat uses nowhere else.
_cmds = dict(pg.BOT_COMMANDS)
check("help: /check and /wait show the argument they refuse without",
      "/check A3F1" in _cmds["check"] and "/wait A3F1" in _cmds["wait"])
check("help: NON-VACUITY -- they really do refuse without one, in a word the "
      "chat never otherwise uses",
      pg.parse_command("/check")[2] == "handle must be 4 hex characters"
      and pg.parse_command("/wait")[2] == "handle must be 4 hex characters")
# NON-VACUITY: the help still lists the commands, so this is not passing on an
# emptied string.
# THE ADVERTISED NAMES, which are now words rather than abbreviations: "depo"
# and "slot 0-7" meant nothing to anyone who had not read the source. The old
# spellings still WORK -- parse_command takes both -- but the menu and the help
# offer the ones a stranger could guess.
check("help: NON-VACUITY -- every advertised command is listed",
      all(c in pg.HELP for c in ("/deposit", "/check", "/wait", "/withdraw",
                                 "/settings", "/cancel", "/status")))
# AND THE DIRECTION IS ON THE LINE, not left to the verb. This is the whole
# of the rename: an operator waiting to be paid must not be able to read the
# list and pick the wrong one.
# ONE WAY IN AND ONE WAY OUT, since /address went. The direction still has to
# be on the line rather than left to the verb: that is the whole of the rename,
# and an operator waiting to be paid must not read the list and pick the wrong
# one.
check("help: the money-in command says MONEY IN and the money-out one says "
      "MONEY OUT",
      pg.HELP.count("MONEY IN") == 1 and pg.HELP.count("MONEY OUT") == 1)
for _c, _d in pg.BOT_COMMANDS:
    if _c in ("deposit", "address"):
        check(f"help: /{_c} is marked MONEY IN", _d.startswith("MONEY IN"))
    if _c == "withdraw":
        check(f"help: /{_c} is marked MONEY OUT", _d.startswith("MONEY OUT"))
# ONE LIST, so the "/" menu Telegram renders and the help cannot disagree.
check("help: the help is BUILT from the command list, not kept beside it",
      all(f"/{_c}" in pg.HELP for _c, _d in pg.BOT_COMMANDS)
      and all(_d in pg.HELP for _c, _d in pg.BOT_COMMANDS))
# ...and the old spellings still answer, so an operator's muscle memory is not
# met with "unknown command" by a bot that looks broken.
for _old, _want in (("/depo", "depo_wizard"), ("/withdraw", "withdraw_wizard"),
                    ("/watch A3F1", "watch")):
    _j, _p2, _e = pg.parse_command(_old)
    check(f"help: the old spelling {_old!r} still works",
          _j == _want or _e == _want)
# /recv and /address are ANSWERED rather than routed: the job is gone, and a
# sentence saying so beats "unknown command", which reads as a broken bot.
for _gone in ("/recv", "/receive", "/address", "/addr"):
    check(f"help: {_gone!r} is answered with a reason rather than routed",
          pg.parse_command(_gone)[0] == ""
          and "gone" in pg.parse_command(_gone)[2].lower())


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
#  THE COMMAND MENU TELEGRAM RENDERS
# ===========================================================================
print("\n== the bot stops looking dead ==")
#
# Telegram builds the "/" autocomplete, the blue Menu button and the command
# descriptions from setMyCommands -- and this never called it. So a correctly
# working pager, over Tor, with a valid token, presented as an empty chat with
# no menu and no hint that typing anything would do something. The operator had
# to already know every command and its exact spelling. That is
# indistinguishable from a bot that does not work.
def _flat_src(fn):
    """A function's source with runs of whitespace collapsed, so a check does
    not depend on how the line happened to wrap."""
    import inspect
    return " ".join(inspect.getsource(fn).split())


_pub = []


class _PubPager:
    """The real publish_commands with only the HTTP call replaced."""

    def __init__(self, answer):
        self.proxies = {}
        self.token = "123456:TOKEN"
        self._answer = answer

    _url = pg.Pager._url
    publish_commands = pg.Pager.publish_commands


_saved_post = pg.safe_post
try:
    pg.safe_post = lambda url, data, **k: (_pub.append((url, data)),
                                           {"ok": True})[1]
    _ok = _PubPager(True).publish_commands()
    check("menu: the pager publishes its command list on start", _ok)
    _url, _data = _pub[0]
    check("menu: ...to setMyCommands", _url.endswith("/setMyCommands"))
    _cmds = json.loads(_data["commands"])
    check("menu: ...carrying every command it advertises",
          {c["command"] for c in _cmds}
          == {c for c, _d in pg.BOT_COMMANDS})
    check("menu: ...each with a description a stranger could act on",
          all(c["description"] and len(c["description"]) > 8 for c in _cmds))
    # NO LEADING SLASH: Telegram rejects the whole call if one is sent, and
    # the failure is silent from the operator's side -- the menu just never
    # appears, which is the symptom this exists to fix.
    check("menu: ...and none of them carries a leading slash, which Telegram "
          "rejects", not any(c["command"].startswith("/") for c in _cmds))
    # AN AMOUNT, NOT A RATE. This refused any decimal at all, which caught
    # "the 1.1% usage fee this service keeps" -- a RATE, published in the
    # source as USAGE_FEE_PCT and the one number a newcomer most needs before
    # they use the thing. The rule is about MAGNITUDES: what the menu must
    # never carry is how much money anybody has. A percentage says nothing
    # about that, so the check now excludes a decimal that is a percentage and
    # keeps refusing every other one.
    check("menu: ...and none names a machine or an amount (a RATE is not an "
          "amount)",
          not any("vault" in c["description"].lower()
                  or re.search(r"\d+\.\d(?!\s*%)", c["description"])
                  for c in _cmds))
    check("menu: NON-VACUITY -- a real amount in a description WOULD be "
          "caught",
          re.search(r"\d+\.\d(?!\s*%)", "sends 0.05 BTC") is not None
          and re.search(r"\d+\.\d(?!\s*%)", "the 1.1% usage fee") is None)
    # NOT FATAL. A pager that could not publish its menu still answers every
    # command; refusing to start over cosmetics is the wrong trade on the box
    # whose whole job is to be reachable.
    _pub.clear()
    pg.safe_post = lambda url, data, **k: {"ok": False}
    _out = io.StringIO()
    with contextlib.redirect_stdout(_out):
        _bad = _PubPager(False).publish_commands()
    check("menu: a failed publish is reported and NOT fatal",
          _bad is False and "still answers" in _out.getvalue())
    pg.safe_post = lambda url, data, **k: (_ for _ in ()).throw(OSError("tor"))
    with contextlib.redirect_stdout(io.StringIO()):
        check("menu: ...and a raising transport is not fatal either",
              _PubPager(False).publish_commands() is False)
finally:
    pg.safe_post = _saved_post

# AND run() MUST ACTUALLY CALL IT. The checks above drive publish_commands
# directly, so they are structurally unable to see the menu never being
# published at all -- a mutation removing the call from run() SURVIVED them.
# The producer being correct is not the pipeline being wired.
_run_src = _flat_src(pg.Pager.run)
check("menu: run() publishes the menu on start",
      "self.publish_commands()" in _run_src)
# .find, NOT .index. index() RAISES when the call is absent, and a check that
# raises kills the suite -- which mutation_sweep scores NO-RESULT, i.e. no
# verdict at all, rather than the red line this is for. Driven: removing the
# call turned a CAUGHT into a NO-RESULT.
_i_pub, _i_up = _run_src.find("publish_commands"), _run_src.find("Pager up")
check("menu: ...before it announces itself, so a failure is on screen above "
      "the 'Pager up' line rather than below it",
      _i_pub != -1 and _i_up != -1 and _i_pub < _i_up)


# ===========================================================================
#  THE ONE FILE THE PAGER PERSISTS
# ===========================================================================
print("\n== what the state file says about when you were awake ==")
#
# It held a float per poke: the exact second the operator asked for a quote,
# for every quote in the last 24 hours, on the SD card of the box that is
# supposed to hold nothing. Anyone who images the card reads a timetable of
# when its owner was moving money, to the microsecond.
#
# Five minutes is coarser than anything the file is FOR -- the interval gate
# defaults to 300 s and the cap counts a 24-hour window -- so a stamp good to
# five minutes still answers both questions the file exists to answer.
_stdir = tempfile.mkdtemp(prefix="stamps_")
_stp = os.path.join(_stdir, "state.json")
_sl = pg.Limits(__import__("pathlib").Path(_stp), 300, 12)
_t_odd = 1755900123.456789
_sl.last_poke = _t_odd
_sl.pokes = [_t_odd, _t_odd + 7, _t_odd + 61]
_sl.save()
_on_disk = json.loads(open(_stp, encoding="utf-8").read())
check("stamps: no exact second reaches the card",
      _t_odd not in _on_disk["pokes"]
      and _on_disk["last_poke"] != _t_odd)
check("stamps: every stamp is a whole multiple of the bucket",
      all(float(x) % pg.Limits.STAMP_BUCKET_S == 0
          for x in _on_disk["pokes"] + [_on_disk["last_poke"]]))
check("stamps: ...and no stamp moved into the FUTURE, which would make the "
      "interval gate refuse for longer than it should",
      all(float(x) <= _t_odd + 61 for x in _on_disk["pokes"])
      and float(_on_disk["last_poke"]) <= _t_odd)
# NON-VACUITY: the file still records the pokes it is for, and the cursor.
check("stamps: NON-VACUITY -- the pokes are still there to be counted",
      len(_on_disk["pokes"]) == 3 and "offset" in _on_disk)
# NON-VACUITY: the limiter still WORKS on the coarsened values -- rounding a
# rate limit into uselessness would be the wrong fix.
# A LIVE STAMP for the reload check: recent() prunes anything older than 24h,
# so the fixed 2025 value above is correctly dropped and would make this pass
# for the wrong reason.
_sl_live = pg.Limits(__import__("pathlib").Path(_stp), 300, 2)
_now_live = time.time()
_sl_live.last_poke = _now_live
_sl_live.pokes = [_now_live - 10, _now_live - 400, _now_live]
_sl_live.save()
_sl2 = pg.Limits(__import__("pathlib").Path(_stp), 300, 2)
check("stamps: NON-VACUITY -- a restart still reloads them and still refuses",
      len(_sl2.recent()) >= 2 and _sl2.why_not() != "")
check("stamps: ...and those live ones were coarsened on the way to disk too",
      all(float(x) % pg.Limits.STAMP_BUCKET_S == 0
          for x in json.loads(open(_stp, encoding="utf-8").read())["pokes"]))
check("stamps: ...and the file is still 0600, which is what makes the "
      "coarsening a second line rather than the only one",
      oct(os.stat(_stp).st_mode)[-3:] == "600")
# 0 IS NOT A TIME. A never-poked limiter must not have its zero turned into a
# bucket boundary that reads as a real stamp.
check("stamps: a zero stays zero rather than becoming a timestamp",
      pg._bucket(0, 300) == 0 and pg._bucket(0.0, 300) == 0)


# ===========================================================================
#  WHAT THE Pi's OWN CARD SAYS ABOUT WHAT THE Pi IS FOR
# ===========================================================================
print("\n== the SD card must not be a map of the operation ==")
#
# The Pi is the box that is supposed to hold nothing. Its unit files carried
# ninety lines each explaining what the pager is, what a stolen token gets,
# which keyfile decides what comes back, and what the wake budget is -- so
# anyone who imaged that card read the design out of the comments without
# running a thing. `systemctl status` printed the toolchain's name too.
#
# The reasoning belongs in OPSEC_SETUP.md and in the tools' own docstrings, on
# the machine that has the source.
_UNITS = {}
for _u in ("gs-telegram-pager.service.example", "gs-doorbell.service.example"):
    _up = os.path.join(REPO, "systemd", _u)
    _UNITS[_u] = open(_up, encoding="utf-8").read() if os.path.exists(_up) else ""
check("card: both Pi-side unit examples exist, so the checks below read "
      "something", all(_UNITS.values()))

for _u, _txt in _UNITS.items():
    _desc = [l for l in _txt.splitlines() if l.startswith("Description=")]
    check(f"card: {_u} has exactly one Description", len(_desc) == 1)
    check(f"card: {_u}'s Description names no tool and no toolchain — "
          f"systemctl prints it to anyone who can read the unit",
          not any(w in _desc[0].lower()
                  for w in ("ghostspiral", "gs_", "pager", "doorbell",
                            "telegram", "wake", "vault")))
    # A CEILING, because the drift was length rather than a forbidden word.
    check(f"card: {_u} is under 110 lines ({len(_txt.splitlines())})",
          len(_txt.splitlines()) <= 110)
    check(f"card: {_u} does not restate the wake budget or the threat model",
          not any(w in _txt.lower()
                  for w in ("24 h wake", "24h wake", "wake budget",
                            "account ceiling", "stolen phone",
                            "throws away the only reason")))
    check(f"card: {_u} sets a UMask, so nothing it writes is world-readable",
          "UMask=" in _txt)
    check(f"card: {_u} still keeps the journal empty",
          "StandardOutput=null" in _txt and "StandardError=null" in _txt)
    check(f"card: {_u} still forbids core dumps, which hold the token",
          "LimitCORE=0" in _txt)
# NON-VACUITY: the units still say the things an installer cannot do without.
_pgu = _UNITS["gs-telegram-pager.service.example"]
check("card: NON-VACUITY -- the pager unit still says the token goes in the "
      "environment and never on argv",
      "never on argv" in _pgu.lower() or "NEVER ON ARGV" in _pgu)
check("card: NON-VACUITY -- and still tells the operator to find their chat "
      "id first", "--whoami" in _pgu)
check("card: NON-VACUITY -- and documents the burn switch it now has",
      "--burn-after" in _pgu and "USR1" in _pgu)

# ---- THE PAGER COULD NOT START AT ALL, SILENTLY, EVERY 30 SECONDS -------
#
# systemd starts a unit with cwd=/ . gs_common's chain is
# Path("integrity_chain.log") -- RELATIVE, resolved against cwd when it is
# opened -- and this unit sets ProtectSystem=strict with ReadWritePaths=
# /var/lib/gs and had no WorkingDirectory. So the chain resolved to
# /integrity_chain.log on a read-only filesystem, and the first bookkeeping
# line the pager ever writes raised an unhandled OSError.
#
# With StandardError=null that traceback went nowhere, and Restart=on-failure
# with RestartSec=30 retried it forever. The one box whose entire job is being
# reachable was unreachable, in a loop, with no message anywhere.
#
# gs-wake-agent.service already carries this reasoning and fixes it there; this
# unit copied the hardening and not the fix.
check("card: the pager unit says where it runs, because a relative chain path "
      "and cwd=/ under ProtectSystem=strict is a silent restart loop",
      "WorkingDirectory=" in _pgu)
check("card: ...and points it at the one directory the unit may write",
      any(_l.strip() == "WorkingDirectory=/var/lib/gs"
          for _l in _pgu.splitlines())
      and "ReadWritePaths=/var/lib/gs" in _pgu)
# NON-VACUITY on the premise: the hardening that makes cwd read-only is really
# there, so this is a fix for a live combination and not a precaution.
check("card: NON-VACUITY -- the unit really does make everything outside "
      "ReadWritePaths read-only, and really does swallow stderr",
      "ProtectSystem=strict" in _pgu and "StandardError=null" in _pgu
      and "Restart=on-failure" in _pgu)
# AND THE TOOL SURVIVES A UNIT THAT FORGETS. The example's own header says
# "read every line, then write your own", so an operator's unit may have no
# WorkingDirectory at all -- and a full or read-only card would do the same on
# one that does. A pager that answers is worth more than a chain line about a
# pager that did not start.
_ml_src = _SRC_PG_EARLY.split("def main(")[1]
check("pager: the startup chain line cannot stop the bot from starting",
      "try:\n        integrity_log(\"pager\", \"start\")" in _ml_src)
check("pager: ...and says so on stdout rather than dying into a null stderr",
      "integrity chain unavailable" in _ml_src)
_dbu = _UNITS["gs-doorbell.service.example"]
check("card: NON-VACUITY -- the doorbell unit still keeps the job off argv, "
      "which is the defect its own comment records",
      "StandardInput=file:" in _dbu and "--job" in _dbu)


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
        p.allow_users, p.handle_owner, p.handle_job = set(), {}, {}
        p._chain = None
        p._chain_leg = 0
        p._status_at = None
        p.spenders = 1
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
_b.p.send = lambda c, t, buttons=None: True
_b.p.handle({"update_id": 1,
             "message": {"chat": {"id": 111}, "message_id": 900,
                         "text": "/status"}})
check("burn: the operator's own command message is tracked for deletion",
      any(m == 900 for _c, m, _t in _b.p.burn))
# NON-VACUITY: a chat that is NOT allowlisted must not be tracked -- deleting
# there is an action taken for somebody who was refused.
_b2 = _BurnPager()
_b2.p.send = lambda c, t, buttons=None: True
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


# ===========================================================================
#  THE ALLOWLIST GATED THE ROOM, NOT THE PERSON
#
#  handle() read msg["chat"]["id"] and checked it against --chat-id. It never
#  read msg["from"] at all. In a PRIVATE chat those are the same number, so it
#  worked and every test here passed. In a GROUP they are not: every member's
#  message carries the group's chat id, so `--chat-id <negative>` allowlisted
#  the whole room -- for /send, which spends.
# ===========================================================================
print("\n== the allowlist: which id is actually checked ==")
import types as _ty4
import threading as _th4


def _room_pager(allow, users):
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key = {"http": "x"}, "T", {}
    p.args = _ty4.SimpleNamespace()
    p.allow, p.ignored, p.convos = set(allow), 0, {}
    p.allow_users, p.handle_owner, p.handle_job = set(users), {}, {}
    p._chain = None
    p._chain_leg = 0
    p._status_at = None
    p.spenders = len(p.allow_users) or len(p.allow)
    p.burn_after = 0
    p.busy = _th4.Lock()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.burn, p.burn_after, p.burn_now = [], 0, False
    p.limits = _ty4.SimpleNamespace(why_not=lambda: "", record=lambda: None,
                                    recent=lambda: [], daily_cap=12,
                                    offset=0, save=lambda: None)
    seen = []
    p.send = lambda c, t, buttons=None: (seen.append(t), True)[1]
    return p, seen


def _msg(chat, frm, text="/status"):
    m = {"chat": {"id": chat}, "message_id": 1, "text": text}
    if frm is not None:
        m["from"] = {"id": frm}
    return {"update_id": 1, "message": m}


_ROOM = -1001234567890
_ME, _THEM = 4242, 777001

_gp, _gs_ = _room_pager([_ROOM], [_ME])
_gp.handle(_msg(_ROOM, _ME))
check("allowlist: in a group, the allowlisted SENDER is answered",
      _gs_ == ["ready"])
_gp2, _gs2 = _room_pager([_ROOM], [_ME])
_gp2.handle(_msg(_ROOM, _THEM))
check("allowlist: ...and another member of that same room is NOT — before "
      "this, the room id was the whole check and they were",
      _gs2 == [] and _gp2.ignored == 1)

# SILENTLY. A reply confirms the bot is alive to whoever found it, which is
# the same reason an unlisted chat gets nothing.
check("allowlist: a rejected sender gets no reply at all, not a refusal",
      _gs2 == [])

# The shapes Telegram can put in `from`, and the one Python lies about:
# True is an int, and `True in {1}` is True.
for _bad, _what in ((None, "no from field at all (a channel post)"),
                    ("4242", "a string id"),
                    (True, "a bool, which Python counts as int 1")):
    _bp, _bs = _room_pager([_ROOM], [1])
    _bp.handle(_msg(_ROOM, _bad))
    check(f"allowlist: {_what} is refused, not coerced", _bs == [])

# NON-VACUITY: with no --user-id the gate is off, which is what keeps every
# private-chat operator working exactly as before.
_pp, _ps = _room_pager([111], [])
_pp.handle(_msg(111, 999))
check("allowlist: NON-VACUITY -- with no --user-id a private chat still "
      "answers, whoever the from field claims to be (chat.id IS the user "
      "there, so the room is the person)", _ps == ["ready"])

# ...and the startup refusal, so nobody can be in that state by accident.
_saved_main = (pg.validate_proxy, pg.verify_tor, pg.isolated_proxy,
               pg.load_token)
pg.validate_proxy = lambda u: "socks5h://x"
pg.verify_tor = lambda p: None
pg.isolated_proxy = lambda u, tag: {"https": "socks5h://x"}
pg.load_token = lambda f: "123456:TOKEN"
try:
    _grc = None
    try:
        pg.main(["--key", "/nonexistent.key", "--chat-id", str(_ROOM)])
    except SystemExit as _e:
        _grc = str(_e)
    except Exception as _e:                                  # noqa: BLE001
        _grc = f"{type(_e).__name__}: {_e}"
    check("allowlist: a GROUP --chat-id with no --user-id is REFUSED at "
          "startup, not warned about",
          _grc and "GROUP" in _grc and "--user-id" in _grc)
    check("allowlist: ...and the refusal says WHY it matters (a group message "
          "carries the room's id, and /send spends)",
          _grc and "SPENDS" in _grc)
    # NON-VACUITY: the same group id WITH --user-id gets past this gate and
    # fails later for its own reason (there is no keyfile here).
    _grc2 = None
    try:
        pg.main(["--key", "/nonexistent.key", "--chat-id", str(_ROOM),
                 "--user-id", str(_ME)])
    except SystemExit as _e:
        _grc2 = str(_e)
    except Exception as _e:                                  # noqa: BLE001
        _grc2 = f"{type(_e).__name__}: {_e}"
    check(f"allowlist: NON-VACUITY -- the same group WITH --user-id passes "
          f"this gate ({str(_grc2)[:44]!r})",
          _grc2 is not None and "GROUP" not in str(_grc2))
    # ...and a PRIVATE chat id never has to supply one.
    _grc3 = None
    try:
        pg.main(["--key", "/nonexistent.key", "--chat-id", "111"])
    except SystemExit as _e:
        _grc3 = str(_e)
    except Exception as _e:                                  # noqa: BLE001
        _grc3 = f"{type(_e).__name__}: {_e}"
    check("allowlist: a PRIVATE chat id still needs no --user-id",
          _grc3 is not None and "GROUP" not in str(_grc3))
finally:
    (pg.validate_proxy, pg.verify_tor, pg.isolated_proxy,
     pg.load_token) = _saved_main

# --whoami has to be the thing that TELLS them, because it is the only place
# an operator ever learns an id. It printed the chat id and "Start the pager
# with --chat-id {cid}", which in a group is an instruction to allowlist the
# whole room.
_wupd = [{"update_id": 9, "message": {"chat": {"id": _ROOM, "title": "grp"},
                                      "from": {"id": _ME, "username": "op"},
                                      "text": "hi"}}]
pg.safe_get = lambda url, proxies=None: {"ok": True, "result": _wupd}
_gout = io.StringIO()
with contextlib.redirect_stdout(_gout):
    pg.whoami("123456:TOKEN", {"https": "socks5h://x"})
_gtext = _gout.getvalue()
check("whoami: a GROUP is named as a group, not reported as a chat id",
      "GROUP" in _gtext)
check("whoami: ...and it prints the SENDER's id too, which is the one the "
      "group needs", str(_ME) in _gtext)
check("whoami: ...and the command it hands over carries both",
      f"--chat-id {_ROOM} --user-id {_ME}" in _gtext)
_wupd[:] = [{"update_id": 10, "message": {"chat": {"id": 111},
                                          "from": {"id": 111, "username": "op"},
                                          "text": "hi"}}]
_pout = io.StringIO()
with contextlib.redirect_stdout(_pout):
    pg.whoami("123456:TOKEN", {"https": "socks5h://x"})
_ptext = _pout.getvalue()
check("whoami: NON-VACUITY -- a PRIVATE chat is told it needs no --user-id, "
      "so the group advice is not printed at everyone",
      "PRIVATE" in _ptext and "GROUP" not in _ptext
      and "--chat-id 111 --user-id" not in _ptext)


# ===========================================================================
#  A HANDLE WAS A BEARER TOKEN WITH NO OWNER
#
#  The vault has no notion of a chat -- deliberately -- so it answers /check
#  and /wait for ANY handle in its file. Driven against the real functions:
#  a second chat asking /check <somebody else's handle> got their deposit
#  address, amount and memo in the clear, and the memo names the destination
#  XMR address in full.
# ===========================================================================
print("\n== a handle belongs to the chat that made it ==")
_hp3, _hs3 = _room_pager([111, 222], [])
_hp3.start_job = lambda cid, job, params: _hs3.append(("JOB", cid, params))

# chat 111 makes one
_hp3.handle_owner["A3F1"] = 111
_hp3.handle({"update_id": 1, "message": {"chat": {"id": 111},
                                         "message_id": 1,
                                         "text": "/check A3F1"}})
check("handles: the chat that made a handle can still check it",
      any(x[0] == "JOB" for x in _hs3 if isinstance(x, tuple)))

_hs3.clear()
_hp3.handle({"update_id": 2, "message": {"chat": {"id": 222},
                                         "message_id": 1,
                                         "text": "/check A3F1"}})
check("handles: another allowlisted chat asking for it is REFUSED — no wake, "
      "so no slip and no deposit address",
      not any(isinstance(x, tuple) and x[0] == "JOB" for x in _hs3))
check("handles: ...and the refusal does not confirm the handle exists",
      _hs3 and all("somebody" not in str(t).lower()
                   and "else" not in str(t).lower() for t in _hs3))

# The honest bound: the map is process memory, so a restart empties it, and
# refusing an UNKNOWN handle would lock an operator out of their own swap on
# the one box whose job is to be reachable.
_hs3.clear()
_hp3.handle({"update_id": 3, "message": {"chat": {"id": 222},
                                         "message_id": 1,
                                         "text": "/check B7C2"}})
check("handles: a handle this process has never seen is still allowed — the "
      "map is process memory and a restart must not lock anyone out",
      any(isinstance(x, tuple) and x[0] == "JOB" for x in _hs3))

# ...and the map really is filled in by the code path that mints one, not
# only by tests writing to it by hand.
check("handles: poke() records the owner when a wake comes back with one",
      "self.handle_owner[h] = chat_id" in _SRC_PG)
check("handles: ...and the map never reaches the SD card",
      "handle_owner" not in _SRC_PG.split("def save")[1].split("\n    def ")[0])



# ===========================================================================
#  EVERYTHING WAS TYPED. NOTHING WAS TAPPABLE.
#
#  Every answer this bot gave was a paragraph ending in an instruction to
#  type something -- "Reply with one:", "start again with /send", "/cancel to
#  stop" -- on a surface whose entire client is a touchscreen. An operator
#  standing in a street with one thumb had to spell /withdraw correctly, then
#  a depth, then a three-digit confirm, with a Tor round trip between each.
#
#  A tap is now the SAME command, not a second one: parse_callback maps
#  callback data to the exact text the typed path takes, and handle_callback
#  feeds it through the same handler -- same allowlist, same sender check,
#  same rate limit, same one-job lock, same handle ownership.
# ===========================================================================
print("\n== a tap is the same command as typing it ==")


def _tap(p, data, chat=111, frm=111, cb_id="cbq1"):
    p.handle({"callback_query": {"id": cb_id, "data": data,
                                 "from": {"id": frm},
                                 "message": {"chat": {"id": chat},
                                             "message_id": 9}}})


def _tapper(allow=(111,), users=()):
    """A pager that records (text, buttons) rather than text alone."""
    p, _ = _room_pager(allow, users)
    seen, toasts, jobs = [], [], []
    p.send = lambda c, t, buttons=None: (seen.append((t, buttons)), True)[1]
    p.answer_callback = lambda i, text="": toasts.append(text)
    p.start_job = lambda cid, job, params: jobs.append((cid, job, params))
    return p, seen, toasts, jobs


for _data, _text in (("m:status", "/status"), ("m:help", "/help"),
                     ("m:fee", "/fee"), ("m:speed", "/speed"),
                     ("m:exit", "/exit"), ("m:settings", "/settings"),
                     ("m:depo", "/deposit"),
                     ("m:send", "/send"), ("m:cancel", "/cancel")):
    _a, _sa, _, _ja = _tapper()
    _tap(_a, _data)
    _b, _sb, _, _jb = _tapper()
    _b.handle(_msg(111, 111, _text))
    check(f"tap: {_data} does exactly what typing {_text} does",
          _sa == _sb and _ja == _jb)

# ...and the table is CLOSED, read the way the doorbell reads a phase name.
for _bad, _label in (("m:nope", "a button not in the table"),
                     ("d:9", "a depth the vault does not offer"),
                     ("c:ZZZZ", "a mangled handle"),
                     ("", "empty callback data"),
                     ("m:depo ; rm -rf /", "anything with an argument")):
    _p, _s, _t, _j = _tapper()
    _tap(_p, _bad)
    check(f"tap: {_label} is refused — no job, no message in the chat",
          _j == [] and _s == [])
    check(f"tap: ...and answered as a TOAST, which reaches the tapper's "
          f"screen and not the transcript ({_t[:1]})",
          len(_t) == 1 and _t[0].startswith("no:"))

# THE MENU IS ON THE TWO MESSAGES SOMEBODY WITHOUT A PLAN ARRIVES AT.
_mp, _ms, _, _ = _tapper()
_mp.handle(_msg(111, 111, "/help"))
_labels = [l for _row in (_ms[0][1] or []) for l, _d in _row]
check("tap: /help carries the menu",
      any("Bitcoin in" in l for l in _labels)
      and any("Withdraw" in l for l in _labels))
# THE LABELS SAY WHICH WAY THE MONEY GOES. "Fresh address" sat next to
# "Withdraw" and gave no clue which of them pays the operator -- the same
# confusion as the command name it was drawn from.
check("tap: the money-in button and the money-out button are marked with "
      "different arrows, so the direction is readable without the words",
      any("\u2b07" in l and "Bitcoin in" in l for l in _labels)
      and any("\u2b06" in l and "Withdraw" in l for l in _labels))
# AND THE DIRECTION IS IN THE WORDS TOO, not only in the arrow. An arrow is a
# glyph a client may render as a box, and a label that then reads "Monero
# address" beside "Deposit Bitcoin" is the confusion the arrow was covering
# for: an address is both a thing you are given and a thing you send to, so it
# named a third direction this tool does not have.
_lbl = [l for _row in pg.MENU_BUTTONS for l, _d in _row]
check("tap: ...and each money button says its direction in words, so it "
      "survives a client that does not render the arrow",
      sum(l.endswith(" in") for l in _lbl) == 1
      and any(l.startswith("\u2b06") and "pays you" in l for l in _lbl))
# "WITHDRAW" ALONE HAS NO OBJECT for somebody who has deposited nothing yet,
# which is precisely who is looking at this menu under the welcome.
check("tap: ...and the money-out button says who it pays, which is the "
      "question the old command name got wrong",
      any("pays you" in l for l in _lbl))
# THE BUTTON THAT PROMISED AN OVERVIEW OPENED A SETTINGS TABLE.
check("tap: ...and no button promises an overview it does not open",
      not any("What this does" in l for l in _lbl)
      and any("What a run does" in l for l in _lbl))
check("tap: ...and every button on it maps to a real command",
      all(pg.parse_callback(_d)[1] == ""
          for _row in (_ms[0][1] or []) for _l, _d in _row))

# ---- THE DEPTH GATE AND THE DEPTH STEP AGREE ON WHAT A DIGIT IS ----------
#
# parse_callback returned "the text the typed path would have received" -- and
# for a depth that is a bare digit, which _depth_from then re-reads. The two
# used DIFFERENT predicates: parse_callback took str.isdecimal(), True for all
# 455 Unicode decimal digits, and _depth_from takes "0123456789" only. So
# "d:１" -- FULLWIDTH DIGIT ONE, which a CJK keyboard emits unasked, and which
# a modified client can put in callback data directly -- passed the gate, came
# back verbatim as the text, and was read as None one layer down: the tap did
# nothing, the question repeated, and nothing told the operator why the button
# they had just been handed was not accepted.
for _d, _want in (("d:3", "3"), ("d:20", "20")):
    check(f"depth tap: {_d!r} still selects a depth",
          pg.parse_callback(_d) == (_want, ""))
# ...AND THE BUTTON CARRIES HOPS, NOT THE WIRE'S KEY. parse_callback returns
# "the text the typed path would have received" and the typed path reads hops
# now, so a button carrying the key taps to a number the step then refuses.
for _bad in ("d:１", "d:٣", "d:²", "d:½", "d:٣٣", "d:", "d:99", "d:-1",
             "d:3.0", "d: 3", "d:0x3", "d:1", "d:2"):
    _t, _e = pg.parse_callback(_bad)
    check(f"depth tap: {_bad!r} is refused at the gate, not passed on as text",
          _t == "" and _e != "")
# ...AND THE PREDICATE IS THE ONE THE STEP USES, not a paraphrase of it: every
# string this gate accepts must survive _depth_from, or the tap is a no-op.
_dpz = pg.Pager.__new__(pg.Pager)
check("depth tap: NON-VACUITY -- everything the gate accepts, the step reads",
      all(_dpz._depth_from(pg.parse_callback(f"d:{_h}")[0]) == _d
          for _h, _d in P.WITHDRAW_HOPS.items()))
# ---- "3" MEANS THREE HOPS, WHICH IS WHAT IT LOOKS LIKE IT MEANS ----------
#
# The question listed the wire's KEY beside the hop count -- "1  3 hops",
# "3  20 hops" -- so one character carried both vocabularies at once and 3 was
# in both. Somebody who read the first line and typed 3 got the THIRD option:
# twenty hops, more than twice the runtime, the highest minimum balance of the
# three, and a run that dies at stage 0 if their balance sits between the two
# minimums -- after they have confirmed something else. Nothing on screen was
# wrong and nothing on the wire was wrong.
check("depth: typing 3 selects THREE hops, not the third row",
      _dpz._depth_from("3") == P.WITHDRAW_HOPS[3]
      and P.WITHDRAW_DEPTHS[_dpz._depth_from("3")][0] == 3)
check("depth: ...and every hop count the menu prints is accepted",
      all(P.WITHDRAW_DEPTHS[_dpz._depth_from(str(_h))][0] == _h
          for _h in P.WITHDRAW_HOPS))
# THE OLD KEYS ARE REFUSED, NOT REINTERPRETED. An operator who had memorised
# "2" for ten hops gets a refusal and asks again; the alternative is being
# handed a different depth without being told, which is the defect itself.
check("depth: ...and a bare wire key is refused rather than silently meaning "
      "something else",
      _dpz._depth_from("1") is None and _dpz._depth_from("2") is None)
check("depth: NON-VACUITY -- the question prints hop counts and no key column",
      all(f"  {_h} hops" in _dpz._depth_question()
          for _h in P.WITHDRAW_HOPS)
      and "  1  " not in _dpz._depth_question())

# ---- A DEPTH BUTTON IS ONLY A DEPTH WHILE SOMETHING IS ASKING FOR ONE ----
#
# parse_callback turns a tap into "the text the typed path would have
# received", which is what makes taps and typing identical everywhere else.
# For the depth menu that text is a BARE DIGIT -- and a bare digit means
# whatever the live conversation is currently reading digits as.
#
# Telegram keyboards do not expire; the menu stays under its message forever.
# So: /withdraw, address given, depth menu drawn, abandoned; /deposit typed;
# the operator scrolls up and taps "20 hops". Driven before the gate existed,
# the reply was "Deposit 3 BTC" and a confirm sum -- a deposit two orders of
# magnitude out, with the operator primed to answer because they had just
# tapped a button and a question appeared.
# ---- STOPPING MID-WAKE WAS ANNOUNCED WHERE NOBODY READS IT --------------
#
# The code names the cost itself: the worker is a daemon thread, so returning
# from run() tears down the in-process doorbell server, and a vault that is
# mid-withdrawal reports back to a closed port hours later. Its comment says
# the defect being fixed is that "the operator was never told" -- and then
# told them with print(), on a unit that sets StandardOutput=null and
# StandardError=null.
#
# `systemctl restart`, a package upgrade, a Pi reboot, Restart=on-failure or
# an operator stopping the unit all land here, during the up-to-16 h window a
# withdrawal holds `busy`. The operator is left with "working" as the last
# thing they ever heard about a spend.
print("\n== stopping while something is still running ==")
_sd, _sds = _room_pager([111, 222], [])
_sdsent = []
_sd.send = lambda cid, t, buttons=None: (_sdsent.append((cid, t)), True)[1]
_sd.busy.acquire()
# The branch lives in run()'s tail rather than in a helper, so what is checked
# below is the shipped source of that branch, sliced on the one integrity line
# only it writes. The behavioural half -- that send() works with `busy` held
# and no worker thread -- is driven at the end.
# SLICED ON THE BRANCH, NOT ON THE FIRST OCCURRENCE. `if self.busy.locked():`
# appears four times in this file; the shutdown one is identified by the
# integrity line only it writes.
_sd_src = _SRC_PG_EARLY.split(
    'integrity_log("pager", "shutdown_with_wake_in_flight")')[1] \
    .split("return 1")[0]
check("shutdown: the mid-wake branch also tells the CHAT, not only a stdout "
      "the shipped unit sets to null",
      "self.send(_cid," in _sd_src)
check("shutdown: ...to every allowlisted chat, since nothing here records "
      "which one started the job", "for _cid in sorted(self.allow):" in _sd_src)
check("shutdown: ...and says the job keeps going but its result is lost",
      "keeps going" in _sd_src and "not be told how it" in _sd_src)
check("shutdown: ...and sends them to the machine rather than to a retry",
      "CHECK AT THE MACHINE" in _sd_src)
check("shutdown: ...inside a bare except, so a dead circuit at shutdown does "
      "not turn stopping into a traceback",
      "except Exception:" in _sd_src and _sd_src.index("try:")
      < _sd_src.index("for _cid in sorted(self.allow):"))
check("shutdown: NON-VACUITY -- the prints are kept for the by-hand case, "
      "which is the one surface that DOES show them",
      "Shutdown requested WHILE A WAKE IS IN FLIGHT" in _sd_src)
# AND IT REALLY REACHES send(): driven, not grepped.
_sd2, _ = _room_pager([111, 222], [])
_sd2sent = []
_sd2.send = lambda cid, t, buttons=None: (_sd2sent.append((cid, t)), True)[1]
_sd2.busy.acquire()
try:
    for _c in sorted(_sd2.allow):
        _sd2.send(_c, "probe")
finally:
    _sd2.busy.release()
check("shutdown: ...and send() needs neither the busy lock nor the worker "
      "thread, which is why this branch can use it at all",
      len(_sd2sent) == 2)

# ---- /status WAS THE ONE COMMAND WITH NO COST TO SEND -------------------
#
# start_job charges the rate limit, and /status never reaches it. It wakes
# nothing, so it cannot spend the vault's budget -- what it spends is one
# Telegram POST over Tor per tap, on a Pi with 1 GB of RAM and Tor resident,
# from a button that sits under almost every message this bot sends. A thumb
# resting on it is a Tor circuit per second.
#
# A COOLDOWN, NOT A BUDGET: the honest answer cannot change faster than this,
# so a repeat inside the window would return the same word anyway. Silent,
# because a "slow down" line is itself a message, which is the thing being
# rationed.
# ---- ONE /withdraw DRAINS EVERYTHING, AS N SEPARATE MIXES ---------------
#
# _funded_entry takes the LARGEST SINGLE unlocked output and never sums:
# spending inputs from two subaddresses in one transaction is permanent public
# proof they share an owner. So a run empties ONE arrival, and that is not
# negotiable.
#
# What WAS wrong is that the operator was left to notice and drive the rest by
# hand, with no idea how many remained -- so being paid a third of what they
# put in read as the tool shortchanging them. The vault answers that question
# now (phase "more_left", set only on a run that actually finished) and the
# pager keeps going.
print("\n== a withdrawal that drains everything ==")


def _chain_run(arrivals):
    """A vault holding `arrivals` separate arrivals. Returns (legs, messages)."""
    _cp, _cs, _, _ = _tapper()
    _cp.start_job = pg.Pager.start_job.__get__(_cp, pg.Pager)
    _left = [arrivals]
    _legs = [0]

    class _Leg:
        def __init__(self):
            _legs[0] += 1
            _left[0] -= 1
            self.result = {"status": "done", "handle": "", "slip": "",
                           "plain": {},
                           "phase": "more_left" if _left[0] > 0 else ""}
            self.events = []

        def outcome(self):
            return "done"

    _saved = pg._DOORBELL[0]
    _saved_retry, pg.SLIP_RETRY_S = pg.SLIP_RETRY_S, 0
    try:
        pg._DOORBELL[0] = types.SimpleNamespace(
            run_wake=lambda *a, **k: _Leg())
        _cp.start_job(111, "withdraw",
                      {"exit_to": ["4" + "8" * 94], "depth": 2})
        for _ in range(600):
            if not _cp.busy.locked() and _cp._chain is None:
                break
            time.sleep(0.02)
    finally:
        pg._DOORBELL[0] = _saved
        pg.SLIP_RETRY_S = _saved_retry
    return _legs[0], [t for t, _b in _cs]


_n1, _m1 = _chain_run(1)
check("chain: one arrival runs one mix", _n1 == 1)
check("chain: ...and says there is nothing left, so the operator is not left "
      "wondering whether they were paid in full",
      any("last one here" in t and "nothing left" in t for t in _m1))
check("chain: ...and does not announce a next leg that is not coming",
      not any("starting the next" in t for t in _m1))

_n3, _m3 = _chain_run(3)
check("chain: three arrivals run three mixes off ONE /withdraw", _n3 == 3)
check("chain: ...each announced before it starts, so the operator is never "
      "left watching silence",
      sum("starting the next" in t for t in _m3) == 2)
check("chain: ...numbered, so a long chain is followable",
      any("(2 of at most" in t for t in _m3)
      and any("(3 of at most" in t for t in _m3))
check("chain: ...and the reason they go separately is given once they matter",
      any("all yours" in t for t in _m3))
check("chain: ...and the last leg still says nothing is left",
      any("last one here" in t for t in _m3))

# THE CAP. The daily wake budget bounds this anyway; the cap is what stops a
# wallet reporting "more left" forever -- a stuck scan, or dust that can never
# clear the mix minimum -- turning one command into an unbounded run of spends.
_n9, _m9 = _chain_run(9)
check(f"chain: a wallet with nine arrivals stops at the cap "
      f"({_n9} of {pg.Pager.MAX_CHAIN_LEGS})",
      _n9 == pg.Pager.MAX_CHAIN_LEGS)
check("chain: ...and says so, rather than stopping silently mid-drain",
      any("Stopping after" in t and "still more here" in t for t in _m9))
check("chain: ...and hands it back to the operator rather than to a retry loop",
      any("send /withdraw again" in t for t in _m9))

# THROUGH start_job, WHICH IS WHERE EVERY BOUND LIVES. A chain that called
# _worker directly would be a second path to a wake with no rate limit, no
# one-spender check and no busy lock.
_CH_END = 'integrity_log("pager", "chain_start_failed")'
_ch_src = _SRC_PG_EARLY.split("_next, self._chain = self._chain, None")[1]
# Window it to the handover block itself. Slicing to end-of-file would drag in
# every later mention of _worker and fail for reasons that have nothing to do
# with the chain.
check("chain: the handover block ends where the test thinks it does",
      _CH_END in _ch_src)
_ch_src = _ch_src.split(_CH_END)[0]
check("chain: the next leg goes through start_job like everything else",
      "self.start_job(_cid" in _ch_src and "_worker" not in _ch_src)
# THE LEG COUNT SURVIVES THE HANDOVER. The first version read it out of the
# slot, which _worker clears before the next poke runs -- so it was 0 on every
# leg, the message said "2 of at most 6" forever, and the cap never fired.
# Driven with nine arrivals: nine mixes ran.
check("chain: the leg number is carried by start_job, not by the slot the "
      "handover clears",
      "def start_job(self, cid: int, job: str, params: dict, leg: int = 0)"
      in _SRC_PG_EARLY
      and "self._chain_leg = int(leg)" in _SRC_PG_EARLY)
# AND IT IS ARMED ONLY AFTER THE REPORT LANDS. If the completion could not be
# delivered, the operator does not know a leg finished -- and starting another
# one silently is the worst thing this could do.
_arm = _SRC_PG_EARLY.split('integrity_log("pager", "withdraw_result_undelivered")')[1]
check("chain: the next leg is armed below the report, not instead of it",
      _arm.index("self._chain = (chat_id") > 0)


print("\n== /status cannot be leaned on ==")
_stp, _sts, _, _ = _tapper()
_stclock = [500.0]
_stp.clock = lambda: _stclock[0]
for _ in range(10):
    _stp.handle(_msg(111, 111, "/status"))
check(f"status: ten taps in the same second answer once ({len(_sts)})",
      len(_sts) == 1)
check("status: ...and the answer is still the one word",
      _sts[0][0] in ("ready", "wait"))
_stclock[0] += pg.Pager.STATUS_COOLDOWN_S + 1
_stp.handle(_msg(111, 111, "/status"))
check("status: ...and it answers again once the window passes", len(_sts) == 2)
# THE FIRST TAP AFTER A RESTART MUST ANSWER, and the first version of this
# swallowed it. It initialised the marker to 0.0 and compared clock() - 0.0 --
# self.clock is time.monotonic, which counts from an arbitrary point, so on a
# freshly booted Pi that difference is inside the cooldown. "Never answered" is
# a different state from "answered at time zero".
for _t0, _lbl in ((0.0, "a Pi that has just booted"),
                  (604800.0, "a Pi up for a week")):
    _bp, _bs, _, _ = _tapper()
    _bp.clock = lambda _v=_t0: _v
    _bp.handle(_msg(111, 111, "/status"))
    check(f"status: the first tap answers on {_lbl}", len(_bs) == 1)
check("status: ...because 'never' is spelled differently from 'at zero'",
      pg.Pager(_args, "123456:TOKEN", {}, {"https": "x"})._status_at is None)
# NON-VACUITY: the throttle is /status's alone. It must not swallow the
# commands that do something.
_np, _ns, _, _nj = _tapper()
_np.clock = lambda: 500.0
_np.handle(_msg(111, 111, "/status"))
_np.handle(_msg(111, 111, "/fee"))
_np.handle(_msg(111, 111, "/help"))
check("status: NON-VACUITY -- other commands in the same second still answer",
      len(_ns) == 3)



print("\n== a button from an earlier question ==")
_dp, _ds, _dt, _dj = _tapper()
_dp.handle(_msg(111, 111, "/withdraw"))
_dp.handle(_msg(111, 111, "4" + "1" * 94))
_dp.handle(_msg(111, 111, "/deposit"))
_ds.clear()
_dt.clear()
_dj.clear()
_tap(_dp, "d:20")
check("stale tap: it starts nothing", _dj == [])
check("stale tap: ...and writes nothing to the transcript", _ds == [])
check("stale tap: ...and says so on the tapper's own screen instead",
      len(_dt) == 1 and "earlier question" in _dt[0])
check("stale tap: ...and the live conversation is untouched — still the "
      "deposit wizard, still waiting for its amount",
      _dp.convos.get(111) is not None
      and _dp.convos[111].kind == "depo"
      and _dp.convos[111].amount is None)
# NON-VACUITY, and it is the half that matters: the gate must not break the
# button it is guarding.
_dp2, _ds2, _dt2, _dj2 = _tapper()
_dp2.handle(_msg(111, 111, "/withdraw"))
_dp2.handle(_msg(111, 111, "4" + "1" * 94))
_ds2.clear()
_tap(_dp2, "d:20")
check("stale tap: NON-VACUITY -- the same tap while a depth IS being asked "
      "for still answers it",
      _dp2.convos.get(111) is not None and _dp2.convos[111].depth == 3)
# ...AND WITH NO CONVERSATION AT ALL, which is the other way to arrive here:
# the wizard timed out, or was answered hours ago, and the keyboard is still
# on screen.
_dp3, _ds3, _dt3, _dj3 = _tapper()
_tap(_dp3, "d:20")
check("stale tap: ...and a depth tapped with nothing running at all is "
      "refused the same way", _dj3 == [] and _ds3 == [] and len(_dt3) == 1)

# ---- A COMMAND ABANDONS THE CONVERSATION, AND NOW SAYS SO ---------------
#
# The rule is right and the silence around it was the whole problem. Driven
# end to end before the notice existed:
#
#     /deposit  -> "How much? Reply with the BTC amount..."
#     /status   -> "ready"                (the wizard is now gone)
#     0.05      -> "no: unknown command"
#
# The operator answered the question they were asked and was told their answer
# is not a command. Nothing in that sequence says a command cancelled the thing
# that was asking.
print("\n== a command cancels the wizard, out loud ==")
_ap, _as, _, _ = _tapper()
_ap.handle(_msg(111, 111, "/deposit"))
_as.clear()
_ap.handle(_msg(111, 111, "/status"))
_atext = "\n".join(t for t, _b in _as)
check("abandon: a command mid-wizard says what it dropped",
      "dropped the /deposit" in _atext)
check("abandon: ...and that any command does it, so it is a rule and not a "
      "glitch", "any command does" in _atext)
check("abandon: ...and that nothing was sent",
      "Nothing was sent" in _atext)
check("abandon: ...and the command still answers, after the notice",
      _as[-1][0] in ("ready", "wait"))
check("abandon: ...and the conversation really is gone",
      _ap.convos.get(111) is None)
# /withdraw NAMES ITSELF, not "/deposit": the notice is built from the kind.
_wp, _ws, _, _ = _tapper()
_wp.handle(_msg(111, 111, "/withdraw"))
_ws.clear()
_wp.handle(_msg(111, 111, "/help"))
check("abandon: ...and it names the wizard that was actually running",
      "dropped the /withdraw" in "\n".join(t for t, _b in _ws))
# /cancel MUST NOT SAY IT TWICE. Asked of parse_command rather than matched in
# the branch: that branch has already been the place a second cancel
# vocabulary got written and then disagreed with the first one.
_cp, _cs, _, _ = _tapper()
_cp.handle(_msg(111, 111, "/deposit"))
_cs.clear()
_cp.handle(_msg(111, 111, "/cancel"))
_ctext = "\n".join(t for t, _b in _cs)
check("abandon: /cancel says it once, in its own words, not twice",
      "dropped the" not in _ctext and "cancelled" in _ctext.lower())
# THE SAME COMMAND AGAIN IS A RESTART, NOT AN INTERRUPTION. "That dropped the
# /deposit you were part-way through", printed immediately before re-asking
# "How much?", reads as an error report about the thing the operator just
# deliberately did -- they typed it again BECAUSE they wanted to start over.
for _c1, _c2, _lbl in (("/deposit", "/deposit", "the same command"),
                       ("/deposit", "/depo", "an alias of it"),
                       ("/withdraw", "/send", "the withdraw alias")):
    _rp, _rs, _, _ = _tapper()
    _rp.handle(_msg(111, 111, _c1))
    _rs.clear()
    _rp.handle(_msg(111, 111, _c2))
    check(f"abandon: {_c1} then {_lbl} says it is starting over, not that "
          f"something was dropped",
          _rs[0][0] == "(starting that over.)")
    check(f"abandon: ...and the wizard really did restart",
          _rp.convos.get(111) is not None)
# ...AND A DIFFERENT COMMAND STILL GETS THE DROP NOTICE, so this is a branch
# and not a way of making the notice disappear.
_xp, _xs, _, _ = _tapper()
_xp.handle(_msg(111, 111, "/deposit"))
_xs.clear()
_xp.handle(_msg(111, 111, "/withdraw"))
check("abandon: NON-VACUITY -- a DIFFERENT wizard still says what it dropped",
      "dropped the /deposit" in _xs[0][0])

# AND NO SPURIOUS NOTICE when there was nothing to drop.
_np, _ns, _, _ = _tapper()
_np.handle(_msg(111, 111, "/status"))
check("abandon: ...and a command with no wizard running says nothing about "
      "dropping one",
      "dropped the" not in "\n".join(t for t, _b in _ns))

# ---- AND THE ANSWER THAT ARRIVES AFTER IT --------------------------------
#
# handle() routes text to a live conversation first, so a bare message
# reaching parse_command has no question waiting for it. "unknown command"
# describes a mistyped command; it does not describe an amount or a pasted
# address, which is what actually arrives here.
_up, _us, _, _ = _tapper()
_up.handle(_msg(111, 111, "0.05"))
_utext = "\n".join(t for t, _b in _us)
check("orphan answer: a bare amount is not called an unknown command",
      "unknown command" not in _utext)
check("orphan answer: ...it says nothing is waiting, and what to type",
      "waiting for an answer" in _utext
      and "/deposit" in _utext and "/withdraw" in _utext)
check("orphan answer: ...and does not echo what they typed back into the "
      "transcript, which may be an amount or an address",
      "0.05" not in _utext)
check("orphan answer: NON-VACUITY -- a mistyped COMMAND still gets the "
      "command answer", pg.parse_command("/nope")[2] == "unknown command")
_sp, _ss, _, _ = _tapper()
_sp.handle(_msg(111, 111, "/status"))
check("tap: /status carries it too — it is the command an operator sends in "
      "order to decide what to do next",
      _ss and _ss[0][1])
check("tap: ...and the ANSWER is still one word, so the buttons added "
      "nothing to the transcript",
      _ss[0][0] in ("ready", "wait"))

# EVERY LABEL IS A COMMAND THAT EXISTS. A button wired to nothing is worse
# than no button.
for _d in pg.CALLBACK_TEXT.values():
    _job, _prm, _err = pg.parse_command(_d)
    check(f"tap: the menu's {_d} is a command parse_command knows",
          _err != "unknown command")

# THE DEPTH MENU comes from the PROTOCOL's table, like the text beside it, so
# a depth cannot be offered as a button and not as a line, or the reverse.
_dp, _ds, _, _ = _tapper()
_dp.handle(_msg(111, 111, "/send"))
_dp.handle(_msg(111, 111, "4" + "1" * 94))
_depth_rows = _ds[-1][1] or []
_depth_data = [_d for _row in _depth_rows for _l, _d in _row]
check("tap: the depth question is tappable",
      all(f"d:{_h}" in _depth_data for _h in P.WITHDRAW_HOPS))
check("tap: ...with exactly the depths the protocol offers and no others",
      sorted(_d for _d in _depth_data if _d.startswith("d:"))
      == sorted(f"d:{_h}" for _h in P.WITHDRAW_HOPS))
check("tap: ...and a way out, since the message says '/cancel to stop'",
      "m:cancel" in _depth_data)
check("tap: ...and every depth line in the TEXT has a button",
      all(f"{_h} hops" in _ds[-1][0] for _h in P.WITHDRAW_HOPS))

# AND THE CONFIRM DOES NOT GET ONE. CONFIRM_NOTE: this gate "stops a
# pocket-dial and a message pasted into the wrong chat" -- and a tap IS a
# pocket-dial. A Yes button would put a spend one accidental touch away and
# leave that sentence claiming a protection that no longer existed.
_dp.handle({"update_id": 1, "message": {"chat": {"id": 111}, "message_id": 1,
                                        "from": {"id": 111}, "text": "10"}})
check("tap: the CONFIRM question carries NO buttons — a tap is exactly the "
      "pocket-dial that gate exists to stop",
      _ds[-1][1] is None and "SPENDS" in _ds[-1][0])
# NON-VACUITY: that same wizard DID get buttons one step earlier, so this is
# not "the wizard has no buttons".
check("tap: NON-VACUITY -- the step before it was tappable",
      _depth_rows != [])

# A HANDLE'S REPLY CARRIES ITS OWN NEXT STEP. /check and /wait both needed a
# four-character hex label retyped off the screen above, correctly, or the
# wake was spent on unknown_handle.
_hp, _hs, _, _hj = _tapper()
check("tap: a minted handle gets check/wait buttons",
      [_d for _row in (_hp._handle_buttons("A3F1") or [])
       for _l, _d in _row] == ["c:A3F1", "w:A3F1"])
check("tap: ...and a non-handle gets none rather than a broken button",
      _hp._handle_buttons("") is None
      and _hp._handle_buttons("ZZZZ") is None
      and _hp._handle_buttons(None) is None)
_hp.handle_owner["A3F1"] = 111
_tap(_hp, "c:A3F1")
check("tap: tapping it starts the same job /check A3F1 starts",
      _hj == [(111, "swap_status", {"handle": "A3F1"})])
# ...AND THE OWNERSHIP RULE APPLIES TO A TAP. The button is a convenience,
# never a bypass.
_op, _os, _, _oj = _tapper()
_op.handle_owner["A3F1"] = 222
_tap(_op, "c:A3F1")
check("tap: a handle belonging to another chat is refused through a button "
      "exactly as it is through a typed command",
      _oj == [] and _os and "no record" in _os[0][0])

# IN A GROUP THE BUTTON IS IN FRONT OF EVERYONE, which is where the sender
# check earns its keep: a callback_query carries the room's chat id and a
# `from` that is the thumb.
_gp, _gsx, _gt, _gj = _tapper([_ROOM], [_ME])
_tap(_gp, "m:send", chat=_ROOM, frm=_ME)
check("tap: in a group, the allowlisted operator's tap works",
      len(_gsx) == 1)
_gp2, _gs2, _gt2, _gj2 = _tapper([_ROOM], [_ME])
_tap(_gp2, "m:send", chat=_ROOM, frm=_THEM)
check("tap: ...and another member tapping the SAME button starts nothing",
      _gj2 == [] and _gs2 == [] and _gp2.ignored == 1)
check("tap: ...and is told so as a toast — they can see the button, so "
      "saying no discloses nothing, and a silent tap spins for 30s",
      _gt2 == ["Not for you."])
# A CHAT THAT IS NOT ALLOWLISTED GETS NOTHING AT ALL, including no
# acknowledgement: answering confirms the bot is alive to whoever found it.
_up, _us, _ut, _uj = _tapper([111], [])
_tap(_up, "m:status", chat=999, frm=999)
check("tap: an unlisted chat gets no reply AND no acknowledgement",
      _us == [] and _ut == [] and _uj == [] and _up.ignored == 1)

# THE POLL HAS TO ASK FOR THEM. A getUpdates without callback_query in
# allowed_updates never receives one, so every button would spin and do
# nothing -- worse than having no buttons.
check("tap: getUpdates asks for callback_query as well as message",
      "callback_query" in _SRC_PG.split("def updates")[1].split("def ")[0])
# ...and the spinner is closed. An unanswered callback_query holds the
# client's spinner for about thirty seconds.
check("tap: the pager answers the callback so the spinner closes",
      "answerCallbackQuery" in _SRC_PG)
check("tap: ...and acknowledges BEFORE starting the job, which can hold the "
      "thread longer than the spinner lives",
      _SRC_PG.split("def handle_callback")[1].index("self.answer_callback(_id)")
      < _SRC_PG.split("def handle_callback")[1].index("self.handle({"))
# NOTHING IS REACHABLE ONLY BY TAPPING. A chat with no keyboard support, an
# old client, or a burned message must all still work by typing.
check("tap: buttons are optional on send(), so every reply still works "
      "without one", "buttons=None" in _SRC_PG.split("def send")[1][:400])
check("tap: ...and no callback maps to anything the typed vocabulary does "
      "not already have",
      all(pg.parse_command(_t)[2] != "unknown command"
          for _t in pg.CALLBACK_TEXT.values()))


# ===========================================================================
#  ONE WALLET, AND THE ALLOWLIST DOES NOT DIVIDE IT
#
#  Driven against the shipped _funded_entry with two piles on one wallet: it
#  returns the LARGEST single unlocked output and takes no chat argument --
#  gs_wake_agent, gs_wake_proto and gs_doorbell contain no chat_id at all, on
#  purpose. So with two allowlisted people, the second one taps Withdraw and
#  the vault hands them the first one's money, correctly, by its own rules.
#
#  There is no fix for that inside the pager: dividing the pot needs a
#  persistent chat-to-account ledger on the vault -- the record this design
#  refuses to keep -- and a chat identifier on a wire that deliberately
#  carries none. So the operator is made to say they know.
# ===========================================================================
# ===========================================================================
#  "THE FEE" IS TWO DIFFERENT THINGS AND THE BOT NAMED NEITHER
#
#  The operator's USAGE FEE is 1.1% of a withdrawal and is what this service
#  keeps. The Monero NETWORK fee is charged per transaction by the network, a
#  mix is many transactions, and none of it comes here -- so it is the larger
#  of the two. Conflating them costs in both directions: read as the mixing
#  cost, the operator thinks they were overcharged; read as the network fee,
#  they think the service is free.
#
#  Before this, /fee said "1.1% usage fee." and nothing else in the bot
#  mentioned a fee at all -- not the welcome, not /settings, not the confirm
#  where it is actually charged. A newcomer met the rate only by guessing that
#  a command called /fee existed.
# ===========================================================================
print("\n== the usage fee, and the fee it is not ==")
check("fee: the RATE is the one pinned to GhostSpiral's own constant, not a "
      "literal retyped per surface",
      pg.USAGE_FEE_LABEL in pg.WELCOME and pg.USAGE_FEE_LABEL in pg.FEE_ANSWER)
# THE FIRST SCREEN. This is the whole of the user's request: somebody seeing
# the bot for the first time must be told the rate without hunting for it.
check("fee: the WELCOME states the usage fee on first sight",
      "USAGE FEE" in pg.WELCOME and pg.USAGE_FEE_LABEL in pg.WELCOME)
check("fee: ...and says it is what the SERVICE keeps",
      "this service keeps" in pg.WELCOME)
check("fee: ...and says which amount it comes out of",
      "what you withdraw" in pg.WELCOME)
# WHERE THE EXPLANATION LIVES, AND WHERE ONLY THE DISTINCTION DOES.
#
# A first draft put the full two-paragraph explanation on /fee as well, and it
# failed test_depo_wizard's ceiling on that answer -- 40 characters, naming no
# machine, tool or file. That ceiling is not decoration: the reasoning it
# guards is in that file, and it is that /fee is asked REPEATEDLY, so anything
# it says sits in the readable surface once per asking.
#
# The two requirements are not in conflict once the surfaces are separated:
#
#   * The WELCOME is sent ONCE, on /start, to somebody who has never seen the
#     bot. That is the "first time seeing it" the explanation is for, and it
#     is where the whole of it goes.
#   * /fee is the lookup. One line, the rate, and the single clause that stops
#     it being read as the mixing cost.
#
# So the deep checks below run on the welcome, and /fee gets the narrow one.
check("fee: the welcome distinguishes it from the NETWORK fee",
      "network fee" in pg.WELCOME.lower())
check("fee: ...and says the network fee is not received here",
      "none of that comes here" in pg.WELCOME.lower())
check("fee: ...and that a mix is many transactions, which is why the network "
      "fee is the larger one",
      "many transactions" in pg.WELCOME.lower())
check("fee: ...and says outright that the total leaving is more than the "
      "usage fee alone, which is the number an operator will actually check",
      "more than the usage fee" in pg.WELCOME.lower())
# /fee CARRIES THE DISTINCTION IN ITS ONE LINE, or the answer is worse than
# nothing: "1.1% usage fee." alone is what an operator reads as the cost of
# mixing, and then a much larger amount leaves.
check(f"fee: /fee says which fee it is NOT, in its one line ({pg.FEE_ANSWER!r})",
      "not the network fee" in pg.FEE_ANSWER.lower())
# AND IT STAYS UNDER THE OTHER SUITE'S CEILING, checked here too so a change
# made in this file fails in this file rather than three suites away.
check(f"fee: ...and stays one short line ({len(pg.FEE_ANSWER)} chars)",
      len(pg.FEE_ANSWER) <= 40)
# THE COMMAND LIST has to say which fee /fee is about, or the newcomer has no
# reason to tap it -- and must NOT carry the rate, because HELP is built from
# this list and test_depo_wizard pins the rate to /fee and nowhere else.
# .get, NOT [], AND THAT IS NOT DEFENSIVENESS FOR ITS OWN SAKE. The mutation
# sweep's entry for this guarantee DELETES the ("fee", ...) row from
# BOT_COMMANDS -- and a bare subscript then raises KeyError, which kills the
# whole suite before it reports. The sweep scores that NO-RESULT, i.e. "the
# suite crashed, which proves nothing about its checks", and it is right to:
# a crash is indistinguishable from the suite having no opinion. A missing row
# has to FAIL here, loudly and specifically, not take the process with it.
_feedesc = dict(pg.BOT_COMMANDS).get("fee", "")
check("fee: /fee is published in the command list at all — an answer nobody "
      "can find is an answer that is not built",
      "fee" in dict(pg.BOT_COMMANDS))
check(f"fee: the menu entry says whose fee it is ({_feedesc!r})",
      "usage fee" in _feedesc and "not the network fee" in _feedesc)
check("fee: ...and does not put the rate in the published command list, "
      "which HELP is built from",
      pg.USAGE_FEE_LABEL not in _feedesc)

# AND AT THE MOMENT IT IS CHARGED. A cost disclosed only somewhere else is a
# cost the person paying it can miss.
_fp, _fs = _room_pager([111], [])
_fp.start_job = lambda *a: None
_fp.handle(_msg(111, 111, "/withdraw"))
_fp.handle(_msg(111, 111, "4" + "1" * 94))
_fp.handle(_msg(111, 111, "10"))
check("fee: the withdraw CONFIRM names the usage fee, where the money moves",
      pg.USAGE_FEE_LABEL in _fs[-1] and "usage fee" in _fs[-1])
check("fee: ...and names the network fee beside it, so the operator is not "
      "surprised by the larger one",
      "network fee" in _fs[-1].lower())
# NO ARITHMETIC. This box has never been told a balance -- /settings refuses
# to fetch one -- so it may state the RATE and must not state a figure.
check("fee: ...and quotes NO amount, because this box has no balance to "
      "compute one from",
      not re.search(r"\d+\.\d{3,}", _fs[-1]))
check("fee: NON-VACUITY -- it is still the confirm question",
      "SPENDS" in _fs[-1] and "= ?" in _fs[-1])

# ...AND THE PHONE PATH REALLY IS CHARGED THAT RATE. GS_USAGE_FEE_PCT would
# override it, and run_child strips every GS_ variable and re-adds only what
# the dispatcher puts in env_extra -- which never includes the rate. So the
# number this bot quotes is the number GhostSpiral's own constant charges.
_ag_src = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("fee: the vault never passes a rate override, so the quoted rate is "
      "the one actually charged",
      "GS_USAGE_FEE_PCT" not in _ag_src)


# ===========================================================================
#  BOOKKEEPING MUST NOT PRE-EMPT THE REPORT
#
#  poke() writes the integrity chain ABOVE every reply branch, and
#  integrity_log re-raises an OSError. _worker was try/finally with no except,
#  so a full or read-only SD card at the moment a 16.5-hour withdrawal
#  reported back killed the thread silently: busy released by the finally, the
#  pager still answering "ready", and under the shipped unit's
#  StandardOutput=null the traceback going nowhere.
#
#  Driven: messages received [], busy released True, thread alive False --
#  after the job that spends everything.
# ===========================================================================
print("\n== the report survives the bookkeeping ==")


class _DoneFin:
    result = {"status": "done", "handle": "----", "slip": "", "plain": {},
              "phase": ""}

    def outcome(self):
        return "done"


def _chain_dead(job="withdraw"):
    _p, _s = _room_pager([111], [])
    _saved_il, _saved_db = pg.integrity_log, pg._DOORBELL[0]
    pg._DOORBELL[0] = types.SimpleNamespace(
        run_wake=lambda a, k, j, pa, on_event=None: _DoneFin())
    pg.integrity_log = lambda *a, **k: (_ for _ in ()).throw(
        OSError(28, "No space left on device"))
    _p.busy.acquire()
    _th = threading.Thread(target=_p._worker, args=(111, job, {}), daemon=True)
    _err = []
    _saved_hook = threading.excepthook
    threading.excepthook = lambda a: _err.append(a.exc_type.__name__)
    try:
        _th.start()
        _th.join(5)
    finally:
        threading.excepthook = _saved_hook
        pg.integrity_log, pg._DOORBELL[0] = _saved_il, _saved_db
    return _p, _s


_cp, _cs = _chain_dead()
check("chain: a chain write that fails does NOT cost the completion message "
      "— the message IS what happened, as far as the operator is concerned",
      _cs != [])
check("chain: ...and the message that lands is the real completion one",
      any("withdraw: sent" in t for t in _cs))
check("chain: ...and busy is still released, so the pager is not wedged",
      not _cp.busy.locked())

# AND IF poke() ITSELF DIES, the operator is still told something -- and told
# honestly, because this box cannot know whether the wake ran.
_wp3, _ws3 = _room_pager([111], [])
_wp3.busy.acquire()
_saved_db3 = pg._DOORBELL[0]
pg._DOORBELL[0] = types.SimpleNamespace(
    run_wake=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
_saved_poke = pg.Pager.poke
pg.Pager.poke = lambda self, c, j, p_: (_ for _ in ()).throw(
    OSError(28, "No space left on device"))
_th3 = threading.Thread(target=_wp3._worker, args=(111, "withdraw", {}),
                        daemon=True)
_saved_hook3 = threading.excepthook
threading.excepthook = lambda a: None
try:
    _th3.start()
    _th3.join(5)
finally:
    threading.excepthook = _saved_hook3
    pg.Pager.poke = _saved_poke
    pg._DOORBELL[0] = _saved_db3
check("chain: a worker that dies for ANY reason still tells the operator "
      "something", _ws3 != [])
check("chain: ...and does not claim it finished, because this box cannot know",
      _ws3 and "cannot tell you whether" in _ws3[-1])
check("chain: ...and does not imply the money is safe either",
      _ws3 and "nothing was spent" not in _ws3[-1].lower())
check("chain: ...and busy is released, so the pager keeps working",
      not _wp3.busy.locked())

# ...AND THE UPDATE CURSOR CANNOT KILL THE PROCESS. limits.save() sat outside
# the per-update try, and the doorbell's HTTP server runs IN THIS PROCESS: a
# card fault plus any incoming update -- including one from a stranger the
# allowlist would ignore a line later -- tore the interpreter down mid-wake
# and took the socket with it. updates() carries a long note about exactly
# that outcome; this line walked around it.
_src_run = _SRC_PG.split("def run(")[1].split("\n    def ")[0]
# TO THE END OF THE BRANCH, not a fixed window. The comment above the code is
# longer than any slice guessed by eye, and a window that misses the line
# reads as a failure while the code is right -- which is exactly the mistake
# this check would otherwise be reporting.
_save_line = _src_run.split("self.limits.offset = max(")[1].split(
    "                else:")[0]
check("cursor: limits.save() in the poll loop is guarded",
      "try:" in _save_line and "self.limits.save()" in _save_line)
check("cursor: ...and the failure is reported rather than swallowed",
      "could not persist the update cursor" in _save_line)
check("cursor: ...and the in-memory offset is advanced BEFORE the write, so a "
      "failed save does not replay the batch inside this process",
      _src_run.index("self.limits.offset = max(")
      < _src_run.index("self.limits.save()"))


print("\n== one wallet, several people ==")
_saved_m = (pg.validate_proxy, pg.verify_tor, pg.isolated_proxy, pg.load_token)
pg.validate_proxy = lambda u: "socks5h://x"
pg.verify_tor = lambda p: None
pg.isolated_proxy = lambda u, tag: {"https": "socks5h://x"}
pg.load_token = lambda f: "123456:TOKEN"
try:
    def _boot(argv):
        try:
            pg.main(argv)
            return ""
        except SystemExit as _e:
            return str(_e)
        except Exception as _e:                              # noqa: BLE001
            return f"{type(_e).__name__}: {_e}"

    _K = ["--key", "/nonexistent.key"]
    _two = _boot(_K + ["--chat-id", "111", "--chat-id", "222"])
    check("pot: two allowlisted people is REFUSED at startup",
          "spend from ONE wallet" in _two)
    check("pot: ...and the refusal names what actually happens — the largest "
          "balance, whoever put it there",
          "LARGEST unlocked balance" in _two)
    check("pot: ...with the driven figures, not an abstraction",
          "1000 XMR" in _two and "300" in _two)
    # THE REFUSAL IS UNCONDITIONAL, AND THAT IS THE FINDING.
    #
    # The first version of this offered --shared-funds: an acknowledgement the
    # operator passes to say they understand. Wrong shape for a consent gate.
    # The person who types the flag is the OPERATOR; the person who loses
    # money is the other user, who never saw it, was never asked, and cannot
    # find out it was passed. Consent by one party to a harm landing on a
    # second party is not consent, it is a switch for silencing a warning.
    check("pot: there is NO override flag — an operator cannot consent on "
          "another person's behalf",
          "--shared-funds" not in _two and "shared_funds" not in _two)
    check("pot: ...and the refusal says so, rather than leaving the operator "
          "hunting for the flag that turns it off",
          "NO FLAG TO OVERRIDE" in _two)
    check("pot: ...and says what to do instead",
          "own vault" in _two and "own bot" in _two)
    # AND THE "SEVERAL DEVICES" JUSTIFICATION IS CORRECTED, because it was
    # never true: Telegram gives one ACCOUNT one chat with a given bot,
    # whatever it is signed in on. A second --chat-id is a second account.
    check("pot: ...and corrects the several-devices reasoning that used to "
          "justify a second chat id",
          "one account one" in _two.replace("\n", " ").replace("  ", " "))
    # SENDERS, NOT CHATS. With --user-id the people are the senders.
    _grp = _boot(_K + ["--chat-id", "-100123", "--user-id", "4242",
                       "--user-id", "777001"])
    check("pot: two allowlisted SENDERS in one group is refused too",
          "spend from ONE wallet" in _grp)
    # THE FLAG IS GONE FROM THE PARSER, not merely ignored -- an operator who
    # learned it must be told, not silently allowed.
    _opts = {a for _act in pg.build_cli()._actions
             for a in _act.option_strings}
    check("pot: the old override is not even a recognised argument",
          "--shared-funds" not in _opts)
    _flagged = []
    try:
        pg.build_cli().parse_args(["--chat-id", "111", "--shared-funds"])
    except SystemExit:
        _flagged.append("refused")
    check("pot: ...so an operator who learned it is TOLD, not silently "
          "allowed", _flagged == ["refused"])
    # NON-VACUITY: every legitimate shape still starts. They fail later on the
    # missing keyfile, which is the proof they got past this gate.
    for _argv, _label in (
            (_K + ["--chat-id", "111"], "one private chat"),
            (_K + ["--chat-id", "111", "--chat-id", "111"],
             "the same chat id twice — one person, deduplicated"),
            (_K + ["--chat-id", "-100123", "--user-id", "4242"],
             "a group with one allowlisted sender")):
        check(f"pot: NON-VACUITY -- {_label} still starts",
              "spend from ONE wallet" not in _boot(_argv))
finally:
    (pg.validate_proxy, pg.verify_tor, pg.isolated_proxy,
     pg.load_token) = _saved_m

# AND THE SAME RULE AT THE OTHER END. start_job is the ONLY path to a wake and
# a wake is what moves money, so a Pager built some other way -- a future
# caller, an edit that skips main() -- must not reach the wire with an
# allowlist main() would have rejected. Defence in depth is worth it here
# specifically because the harm is not the operator's.
_mp1, _ms1 = _room_pager([111], [])
_mp1.spenders = 2
_mj1 = []
_mp1.start_job(111, "withdraw", {"exit_to": ["4" + "1" * 94], "depth": 1})
check("pot: start_job REFUSES a multi-person allowlist, at the last line "
      "before the wake",
      _ms1 and "more than one person" in _ms1[-1])
check("pot: ...and says every job is refused until it is fixed, not just "
      "this one", "every job" in _ms1[-1])
check("pot: ...and nothing was woken", not _mp1.busy.locked())
# NON-VACUITY: one person gets past it and reaches the real machinery.
_mp2, _ms2 = _room_pager([111], [])
_mp2.spenders = 1
_mp2.limits = types.SimpleNamespace(
    why_not=lambda: "rate limited", record=lambda: None,
    recent=lambda: [], daily_cap=12, offset=0, save=lambda: None)
_mp2.start_job(111, "withdraw", {"exit_to": ["4" + "1" * 94], "depth": 1})
check("pot: NON-VACUITY -- one person gets past that gate and is refused by "
      "the NEXT one, so the check is not simply 'refuse everything'",
      _ms2 and "rate limited" in _ms2[-1])


# ===========================================================================
#  /address MINTED AN ADDRESS AND SENT "READY" WITHOUT IT
#
#  receive_new produces a Monero subaddress and no quote, so there is no
#  thor_pairs file -- and both delivery paths are keyed on one. Driven with
#  plain_slip ON and a delivery key configured: seal_slip_for_delivery
#  returned "", plain_slip_for_chat returned {}, and the chat got
#  "address ready · slip B7C2". The command whose whole purpose is to hand
#  over an address handed over none, and called it ready.
# ===========================================================================
print("\n== /address is gone, and says so ==")
#
# It minted a Monero subaddress to be paid into directly -- an entry point for
# somebody who already holds XMR. Nothing in this repository swaps XMR to BTC;
# every path is BTC to XMR. So it was half a feature: it could take money in
# and had no way to say where.
#
# Both slip builders returned empty on it BY CONSTRUCTION -- no quote, so no
# thor_pairs file to build one from -- which meant the command whose entire
# purpose was to hand the operator an address delivered no address, on every
# configuration. Both watching jobs refused its handle for the same reason, so
# /check and /wait on one spent a magic packet, a boot and a 5-20 minute
# jitter to be told no.
check("address: the job is off the wire", "receive_new" not in P.JOBS)
check("address: ...and the pager cannot compose it either",
      "receive_new" not in pg.CHAT_NAME)
# ANSWERED, NOT IGNORED. An operator with the word in their fingers gets a
# sentence; "unknown command" reads as a broken bot.
for _old in ("/address", "/addr", "/receive", "/recv"):
    _j, _p, _e = pg.parse_command(_old)
    check(f"address: {_old} is answered with a reason, not a job",
          _j == "" and _p == {} and "gone" in _e.lower())
    check(f"address: ...and points at the way in that exists",
          "/deposit" in _e)
check("address: ...and says WHY, since 'gone' alone invites asking for it back",
      "swaps Monero to Bitcoin" in pg.parse_command("/address")[2])
# NOTHING OFFERS IT ANY MORE.
check("address: it is off the published command list",
      "address" not in dict(pg.BOT_COMMANDS))
check("address: ...off the keyboard",
      not any("Monero in" in _l for _row in pg.MENU_BUTTONS for _l, _d in _row))
check("address: ...and out of the welcome",
      "/address" not in pg.WELCOME)
check("address: ...and no callback maps to it",
      not any(_v in ("/address", "/receive", "/recv")
              for _v in pg.CALLBACK_TEXT.values()))
# NON-VACUITY: the way in that remains is still there and still advertised.
check("address: NON-VACUITY -- /deposit is still the way in, on the list and "
      "on the keyboard",
      "deposit" in dict(pg.BOT_COMMANDS)
      and any("Bitcoin in" in _l
              for _row in pg.MENU_BUTTONS for _l, _d in _row))


print("\n== the welcome ==")
check("welcome: /start is its own answer, not an alias of /help",
      pg.parse_command("/start")[2] == "welcome"
      and pg.parse_command("/help")[2] == "help")
check("welcome: ...and they really are different text",
      pg.WELCOME != pg.HELP)
# A DEEP-LINK PAYLOAD MUST NOT BREAK IT. Telegram sends "/start <payload>"
# when a user arrives through a t.me link, so `arg` is non-empty on the one
# command that must never fail.
check("welcome: /start with a deep-link payload still welcomes",
      pg.parse_command("/start abc123")[2] == "welcome")
check("welcome: ...and the group form does too",
      pg.parse_command("/start@mybot")[2] == "welcome")

_wp, _wsn = _room_pager([111], [])
_wp.burn_after = 0
_wp.handle(_msg(111, 111, "/start"))
check("welcome: an allowlisted chat gets it", _wsn == [pg.WELCOME])
# ...rendered against THIS pager's setting, not the module default.
_wp2, _wsn2 = _room_pager([111], [])
_wp2.burn_after = 7200
_wp2.handle(_msg(111, 111, "/start"))
check("welcome: ...and it reflects the burn setting the pager is running with",
      _wsn2 == [pg.welcome_text(7200)] and "deleted after 2h" in _wsn2[0])
# ...AND A STRANGER STILL GETS NOTHING. A welcome is a reply, and a reply to
# an unlisted chat confirms the bot is alive to whoever found it.
_sp2, _ss2 = _room_pager([111], [])
_sp2.handle(_msg(999, 999, "/start"))
check("welcome: a chat that is not allowlisted gets NO welcome — a reply is "
      "still a reply", _ss2 == [] and _sp2.ignored == 1)

# WHAT IT SAYS. Three things, in the order somebody needs them.
check("welcome: it says which way each command moves money",
      "MONEY IN" in pg.WELCOME and "MONEY OUT" in pg.WELCOME)
check("welcome: ...and names the way in and the way out",
      "/withdraw" in pg.WELCOME and "/deposit" in pg.WELCOME)
check("welcome: ...and says outright which one pays them, since that is the "
      "question the old names got wrong",
      "the one that pays YOU" in pg.WELCOME)
# ...AND WHAT IT SWEEPS UP, WHICH IS ALL OF IT.
#
# _funded_entry takes the LARGEST SINGLE unlocked output and never sums,
# because summing would spend inputs from several subaddresses in one
# transaction -- permanent public proof they share an owner. That is a
# property of a RUN and it is not changing. It was also, for two turns, the
# promise the welcome made about the COMMAND: "it mixes ONE arrival", leaving
# an operator with money in three places to notice and drive the other two by
# hand. Being paid a third of what went in does not read as an OPSEC property.
# The pager chains the legs itself now, so the command promises the balance
# and the sentence explains why it arrives in pieces.
check("welcome: ...and that a withdrawal sends back everything that is here, "
      "which is what the operator actually wants to know",
      "everything that is here" in pg.WELCOME)
check("welcome: ...and that it arrives as separate sends, so several "
      "transactions are not a malfunction",
      "separate mixes" in pg.WELCOME and "one per arrival" in pg.WELCOME)
check("welcome: ...and WHY, because otherwise it reads as a limitation "
      "somebody should have fixed",
      "prove they are all yours" in pg.WELCOME)
# ...AND THE OLD PROMISE IS GONE FROM BOTH SURFACES. A published command list
# that still says "ONE arrival" is the same wrong answer in the place a
# newcomer reads first.
# ...AND THE DEPOSIT ENTRY DOES NOT PROMISE THE ADDRESS IN THE CHAT EITHER.
# It said "send Bitcoin, get an address and a memo" -- what the JOB produces,
# not what this surface hands over. The pair is minted inside the job and the
# reply says to read it on the machine, so a list promising a payload the
# reply then withholds reads as the reply having failed.
check("welcome: the command list does not promise an address the chat never "
      "sends",
      "get an address" not in dict(pg.BOT_COMMANDS)["deposit"]
      and "label" in dict(pg.BOT_COMMANDS)["deposit"])
check("welcome: ...and the deposit reply is the surface that says where it "
      "actually is",
      "ON THE MACHINE" in pg.WELCOME)
check("welcome: ...and the published command list says the same thing",
      "send it all back" in dict(pg.BOT_COMMANDS)["withdraw"]
      and "ONE arrival" not in dict(pg.BOT_COMMANDS)["withdraw"])
check("welcome: ...and neither surface still promises only one",
      "mixes what is here" not in pg.WELCOME
      and "ONE arrival" not in pg.WELCOME)
# THE RENAME NOTE IS IN /help, NOT HERE, and that is the point of this pair.
#
# The welcome is read by somebody who has never used this bot. A sentence
# about a command spelling that no longer exists is, to that reader, a fact
# about a thing they have never seen -- it makes the shortest surface longer
# and answers a question they cannot have. The reader it IS for is the one
# with the old word already in their fingers, and that reader types /help.
check("welcome: the removed command is not explained to a first-time reader",
      "receive" not in pg.WELCOME.lower() and "/address" not in pg.WELCOME)
# ...BUT AN OPERATOR WITH THE OLD WORD IS STILL ANSWERED, in parse_command
# rather than in the welcome: the welcome is read by somebody who has never
# used this bot, and a sentence about a command that no longer exists is a
# fact about a thing they have never seen.
check("welcome: ...but the old spellings are still answered somewhere, so an "
      "operator who learned them is not left guessing",
      all("gone" in pg.parse_command(_c)[2].lower()
          for _c in ("/address", "/addr", "/receive", "/recv")))
check("welcome: ...and the aliases /help DOES name really are accepted",
      all(pg.parse_command(_c)[0] == _j or pg.parse_command(_c)[2] == _j
          for _c, _j in (("/send", "withdraw_wizard"),
                         ("/depo", "depo_wizard"))))
check("welcome: ...and that this chat should be assumed readable",
      "read by somebody who is not you" in pg.WELCOME)
# AND IT SAYS SO WITHOUT THE WORD "TRANSCRIPT", which is on the banned list in
# test_depo_wizard for a reason this welcome originally walked straight into:
# the sentence explaining that the omissions are deliberate because the
# transcript is assumed read is itself a description of the arrangement. The
# advice survives; the word that turns it into a disclosure does not.
check("welcome: ...without naming the thing being read",
      "transcript" not in pg.WELCOME.lower())

# WHAT IT MUST NOT SAY, AND THE FIRST DRAFT SAID ALL OF IT.
#
# That draft opened "This is a doorbell, not a wallet. Nothing here holds a
# key, and it cannot move money on its own -- it asks a machine that is
# switched off most of the time, and that machine decides." Every clause is
# true, and together they say: there is a second machine, it is normally
# powered down, this chat is what wakes it, and the keys are not here. That is
# the shape of the operation, written into the surface this file is built on
# the assumption that somebody else reads.
#
# The same rule already cut /settings and FEE_ANSWER back from paragraphs --
# "a reader who has the transcript and nothing else learns the shape of the
# operation from the explanations, not from the answers." A welcome is the
# LONGEST message this bot sends, so it is where that rule matters most.
_ARCH = ("doorbell", "switched off", "powered", "holds a key", "holds no key",
         "another machine", "that machine", "second machine", "wakes",
         "wake ", "offline", "air gap", "air-gapped", "ThinkPad", "Raspberry",
         "systemd", "vault", "gs_", "127.0.0.1", "socks5", "Tor",
         "ThorChain", ".key", "keyfile", "wallet file", "server", "LAN")
for _leak in _ARCH:
    check(f"welcome: describes no part of the setup — no {_leak.strip()!r}",
          _leak.lower() not in pg.WELCOME.lower())
# NON-VACUITY on that sweep: the welcome is not empty, and it DOES contain the
# service words -- so this is a filter that lets the right things through.
check("welcome: NON-VACUITY -- it still says what the service does",
      "Monero" in pg.WELCOME and "/deposit" in pg.WELCOME
      and len(pg.WELCOME) > 300)

# THE DELETION PROMISE IS CONDITIONAL, because --burn-after 0 disables it and
# a welcome promising deletion on an install that does not delete is the class
# of confident false statement this repo keeps removing.
check("welcome: an install with no --burn-after does not promise deletion",
      "deleted" not in pg.welcome_text(0))
check("welcome: ...and one with it says so, with the hours it is set to",
      "deleted after 2h" in pg.welcome_text(7200))
check("welcome: ...reading the real setting rather than a literal",
      "deleted after 13h" in pg.welcome_text(13 * 3600))
check("welcome: ...and a malformed value is treated as off, not as a crash",
      "deleted" not in pg.welcome_text(None)
      and "deleted" not in pg.welcome_text("x"))
# OP_RETURN IS IN IT NOW, DELIBERATELY. It is not an address, a memo or an
# amount -- it is the reason a phone cannot complete the payment, and an
# operator who does not know that tries from the phone and fails. What must
# stay out is anything that names a destination or a figure.
check("welcome: no address, amount or memo is in it",
      not re.search(r"[48][0-9A-Za-z]{50,}", pg.WELCOME)
      and not re.search(r"\d+\.\d{4,}", pg.WELCOME))
check("welcome: ...and it does say what stops a phone paying, which is the "
      "one mechanism word worth the room",
      "OP_RETURN" in pg.WELCOME and "desktop wallet" in pg.WELCOME)
# ...and it is short enough to read on a phone without scrolling past the
# buttons. Telegram's own limit is 4096; the constraint here is a thumb.
check(f"welcome: it fits on a screen ({len(pg.WELCOME)} chars, "
      f"{pg.WELCOME.count(chr(10)) + 1} lines)",
      len(pg.WELCOME) < 1200 and pg.WELCOME.count("\n") < 30)

# AND THE BUTTONS COME WITH IT, which is the whole point of answering /start
# with something other than a list of things to type.
_bp, _bs, _, _ = _tapper()
_bp.handle(_msg(111, 111, "/start"))
check("welcome: the menu is under it",
      _bs and _bs[0][1] == pg.MENU_BUTTONS)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
