#!/usr/bin/env python3
"""THE /depo WIZARD: conversation state that cannot become a liability.

`/depo 2` works and always will. The wizard exists because "2" is a number
whose meaning has to be remembered, and the one command that spends the wake
budget and quotes real money should not be a single unconfirmed keystroke.

Adding conversation state to this program is the risky part, not the asking.
Everything here is a bound on it:

  * WHAT REACHES THE WIRE IS UNCHANGED. After all the conversation, the job is
    byte-identical to what `/depo 2` emits. No new job, no schema field, no
    keyfile field, so no re-pairing and no half-upgraded pair.
  * IT CANNOT NAME AN AMOUNT. Not "does not" -- cannot. The ladder lives in
    the vault's keyfile; the Pi's holds secret, peer_public, target_mac,
    wol_broadcast, wol_port, listen_host, listen_port. There is nothing on
    this box an amount could be read from.
  * IN MEMORY, BOUNDED, EXPIRING. The --state file sits on the same SD card as
    the sealed keyfile and a half-finished /depo does not belong there.
  * IT HOLDS NO LOCK AND SPENDS NO BUDGET. A conversation that reserved the
    one-job channel, or charged a poke on the way in, would be a way to wedge
    the pager by starting conversations and walking away.
  * ONE PATH TO A WAKE. The wizard and `/depo 2` go through the same
    start_job, so the rate limit cannot apply to one and not the other.

AND THE CONFIRM GATE IS LABELLED HONESTLY. It stops a pocket-dial and a
message pasted into the wrong chat. Anyone holding the phone can read "3 + 5"
and answer it. The suite asserts the code SAYS that rather than implying it is
a security control -- the bounds that matter are the vault's 24h wake budget
and account ceiling, which need physical access to change.
"""
import importlib.machinery
import importlib.util
import os
import re
import sys
import threading
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(ld.name, ld)
    mod = importlib.util.module_from_spec(spec)
    ld.exec_module(mod)
    return mod


import gs_wake_proto as P                                    # noqa: E402
from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILURES),
                                 "test_depo_wizard")

DB = load("gs_doorbell")
sys.modules["gs_doorbell"] = DB
pg = load("gs_telegram_pager")
pg.integrity_log = lambda *a, **k: None

CLOCK = [1000.0]


class Fake:
    """A Pager with the wake replaced, so nothing below start_job runs."""

    def __init__(self, allow=(111, 222)):
        p = pg.Pager.__new__(pg.Pager)
        p.proxies, p.token, p.key = {}, "x", {}
        p.args = types.SimpleNamespace()
        p.allow = set(allow)
        p.busy = threading.Lock()
        p.ignored = 0
        p.convos = {}
        p.clock = lambda: CLOCK[0]
        p.rng = __import__("random").SystemRandom()
        self.limited = [""]
        self.recorded = []
        p.limits = types.SimpleNamespace(
            why_not=lambda: self.limited[0],
            record=lambda: self.recorded.append(1),
            recent=lambda: [], daily_cap=12)
        self.sent = []
        self.pokes = []
        p.send = lambda cid, t: (self.sent.append((cid, t)), True)[1]
        self._real_start = pg.Pager.start_job.__get__(p, pg.Pager)
        p.start_job = lambda cid, job, params: self.pokes.append(
            (cid, job, params))
        self.p = p

    def say(self, text, cid=111):
        self.p.handle({"update_id": 1,
                       "message": {"chat": {"id": cid}, "text": text}})

    def text(self):
        return "\n".join(t for _, t in self.sent)

    def answer_confirm(self, cid=111):
        """Read the arithmetic back off the chat and answer it correctly."""
        m = re.search(r"(\d+) \+ (\d+) = \?", self.text())
        if not m:
            return None
        a = int(m.group(1)) + int(m.group(2))
        self.say(str(a), cid=cid)
        return a


# ===========================================================================
# 1. THE JOB THAT REACHES THE WIRE IS UNCHANGED.
# ===========================================================================
print("\n-- the wizard emits exactly what /depo 2 emits --")
f = Fake()
f.say("/depo")
check("/depo with no argument starts a conversation", 111 in f.p.convos)
f.say("2")
check("...and asks a confirm question", "= ?" in f.text())
f.answer_confirm()
check("answering correctly pokes the wake",
      f.pokes == [(111, "receive_and_quote", {"amount_slot": 2})])

g = Fake()
g.say("/depo 2")
check("...and /depo 2 in one shot produces the IDENTICAL job",
      g.pokes == f.pokes)
check("the conversation is gone once it has poked", 111 not in f.p.convos)

# THE INVARIANT, checked against the protocol rather than by eye: whatever the
# conversation collected, what reaches the wire is a job name plus bounded
# integers that the real schema accepts.
_job, _params = f.pokes[0][1], f.pokes[0][2]
check("the emitted job is one the protocol has", _job in P.JOBS)
# THE REAL SCHEMA, through validate_job, with the job_id and challenge an M2
# actually carries -- so this is the same gate the vault applies, not a
# paraphrase of it.
_ok = True
try:
    P.validate_job({"job_id": P.new_job_id(),
                    "challenge": P.new_challenge().hex(),
                    "job": _job, **_params})
except P.WakeError:
    _ok = False
check("...and the emitted params pass the REAL job schema", _ok)
check("...and carry nothing but the declared keys",
      set(_params) == set(P.JOBS[_job]["schema"]))
check("nothing in the emitted params is a string",
      all(isinstance(v, int) and not isinstance(v, bool)
          for v in _params.values()))

# ===========================================================================
# 2. IT CANNOT NAME AN AMOUNT. Structural, not behavioural.
# ===========================================================================
print("\n-- it cannot show an amount, because it has none to show --")
_SRC = open(os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read()
check("the pager never reads an amount ladder",
      '"amount_ladder"' not in _SRC and "'amount_ladder'" not in _SRC)
f2 = Fake()
f2.say("/depo")
f2.say("2")
check("the slot prompt and the confirm never print a decimal amount",
      not re.search(r"\d+\.\d{2,}", f2.text()))
check("...and the wizard says WHY it can only offer slots",
      "ladder lives on the vault" in f2.text()
      or "has never held it" in f2.text())

# ===========================================================================
# 3. IN MEMORY, NEVER ON THE CARD.
# ===========================================================================
print("\n-- a half-finished /depo never reaches the SD card --")
check("Convo has __slots__, so a field cannot be added by accident",
      hasattr(pg.Convo, "__slots__"))
check("...and holds only slot, expect, deadline",
      set(pg.Convo.__slots__) == {"slot", "expect", "deadline"})
# NO STRING FIELD AT ALL, which is the enforceable form of the SD-card rule:
# a struct with no string cannot hold an address, a memo, a slip or an amount
# however the prompts around it are later edited. `step` used to be a string
# and is now DERIVED from `slot is None`, which also makes "at the confirm
# step with no slot" unrepresentable rather than merely untested.
check("...and not one of them is a string field",
      all(isinstance(getattr(pg.Convo(lambda: 0.0), f), (int, float, type(None)))
          for f in pg.Convo.__slots__))
check("...so `step` is derived, not stored", "step" not in pg.Convo.__slots__)
_save = pg.Limits.save.__doc__ or ""
_lsrc = _SRC.split("class Limits")[1].split("\nclass ")[0]
check("Limits.save writes only the cursor and the counters",
      '"offset"' in _lsrc and '"pokes"' in _lsrc and "convo" not in _lsrc)
check("nothing writes convos to disk",
      "atomic_write_json" not in _SRC.split("def begin_convo")[1]
      .split("def send")[0])
f3 = Fake()
f3.say("/depo")
f3.say("3")
_c = f3.p.convos[111]
check("a live conversation holds an int slot, not text",
      isinstance(_c.slot, int) and _c.slot == 3)
for _bad in ("address", "memo", "amount", "btc", "xmr"):
    check(f"...and nothing named like {_bad}", _bad not in pg.Convo.__slots__)

# ===========================================================================
# 4. BOUNDED AND EXPIRING.
# ===========================================================================
print("\n-- bounded, on a 1 GB box --")
f4 = Fake(allow=range(1, 200))
for c in range(1, 200):
    f4.say("/depo", cid=c)
check(f"live conversations are capped at MAX_CONVOS ({pg.MAX_CONVOS})",
      len(f4.p.convos) <= pg.MAX_CONVOS)
check("...and the chat at the cap is told, not silently ignored",
      "too many conversations" in f4.text())

f5 = Fake()
f5.say("/depo")
CLOCK[0] += pg.CONVO_TTL_S + 1
f5.sent.clear()
f5.say("2")
check("an answer after the TTL wakes nothing", f5.pokes == [])
check("...the conversation is reaped", 111 not in f5.p.convos)
check("...and the operator is told it expired rather than 'unknown command', "
      "because walking away and coming back is the ordinary case",
      "expired" in f5.text())
CLOCK[0] = 1000.0

f6 = Fake()
f6.say("/depo")
f6.say("2")
CLOCK[0] += pg.CONVO_TTL_S - 5
f6.sent.clear()
check("NON-VACUITY: inside the TTL it is still live", 111 in f6.p.convos)
CLOCK[0] = 1000.0

# ===========================================================================
# 5. NO LOCK, NO BUDGET, UNTIL THE POKE.
# ===========================================================================
print("\n-- a conversation reserves nothing --")
f7 = Fake()
f7.say("/depo")
check("starting a conversation does not take the one-job lock",
      not f7.p.busy.locked())
f7.say("2")
check("...nor does answering the slot", not f7.p.busy.locked())
check("...and no poke has been charged against the daily budget",
      f7.recorded == [])

# A CONVERSATION MUST NOT BLOCK OTHER COMMANDS.
f8 = Fake()
f8.say("/depo")
f8.sent.clear()
f8.say("/check A3F1")
check("a real command mid-conversation is NOT eaten by the wizard",
      f8.pokes == [(111, "swap_status", {"handle": "A3F1"})])
check("...and the abandoned conversation is dropped rather than left live",
      111 not in f8.p.convos)

# THE RATE LIMIT APPLIES TO BOTH PATHS, which is the point of one start_job.
f9 = Fake()
f9.p.start_job = f9._real_start
f9.limited[0] = "rate limited, 42s left"
f9.say("/depo 2")
check("the rate limit refuses the one-shot form",
      "rate limited" in f9.text())
f9.sent.clear()
f9.say("/depo")
f9.say("2")
f9.answer_confirm()
check("...and refuses the WIZARD too, at the same gate",
      "rate limited" in f9.text())
check("...and neither path started a wake", not f9.p.busy.locked())

# ===========================================================================
# 6. THE CONFIRM GATE.
# ===========================================================================
print("\n-- the confirm gate, and what it honestly is --")
fa = Fake()
fa.say("/depo")
fa.say("4")
_q = fa.text()
check("the confirm repeats the slot before waking anything", "slot 4" in _q)
check("...and says plainly that this wakes the vault", "WAKE THE VAULT" in _q)
# FREE-FORM, NOT MULTIPLE CHOICE. Three buttons meant a pocket-dial cleared
# the gate one time in three; typing a sum is no harder for the operator and
# is not guessable. The expected value is therefore never rendered anywhere.
check("the confirm is free-form, not a list of options to pick from",
      "reply with the answer" in _q and "one of:" not in _q)
check("the expected answer is never printed in the question",
      str(fa.p.convos[111].expect) not in _q.split("= ?")[1])
fa.sent.clear()
fa.say(str(fa.p.convos[111].expect + 1))
check("a wrong answer wakes nothing", fa.pokes == [])
check("...and cancels rather than re-asking, so three choices means three "
      "choices and not unlimited guesses", 111 not in fa.p.convos)

fb = Fake()
fb.say("/depo")
fb.say("4")
fb.sent.clear()
for _ in range(5):
    fb.say("99")
check("repeated guessing cannot reach the wake", fb.pokes == [])

check("the code labels the gate as NOT a security control",
      "NOT a security control" in pg.CONFIRM_NOTE)
check("...and names what the real bound is",
      "wake budget" in pg.CONFIRM_NOTE and "physical access" in pg.CONFIRM_NOTE)
check("the confirm value comes from SystemRandom, not the predictable stream",
      "SystemRandom" in _SRC)

# ===========================================================================
# 7. A BAD SLOT NEVER BECOMES A JOB.
# ===========================================================================
print("\n-- nothing but 0-7 gets through --")
for _bad in ("9", "8", "-1", "0.05", "two", "", "٢", "0x2", "1e1", " 2 ",
             "2; /depo 7", "2\n7", "7" * 40, "²", "½", "٩", "07", "+2"):
    fc = Fake()
    fc.say("/depo")
    fc.say(_bad)
    if fc.p.convos.get(111) and not fc.p.convos[111].awaiting_slot():
        fc.answer_confirm()
    ok = (fc.pokes == []
          or fc.pokes[0][2]["amount_slot"] in range(8))
    check(f"slot {_bad!r} cannot produce an out-of-range job", ok)
    check(f"...and leaves no conversation live and armed for {_bad!r}",
          111 not in fc.p.convos)

# THE MESSAGE MATTERS TOO, and it is what the range check uniquely provides.
#
# Found by the mutation sweep: deleting the 0-7 bound left the guarantee
# intact -- commit_convo re-composes "/depo 9", parse_command refuses it, and
# the equality check stops the poke -- so nothing out of range ever reaches
# the wire either way. What changes is what the operator is told: "internal
# check failed" instead of "a slot is 0-7", two screens later, for a typo.
# Defence in depth is why the first check survived; it is not a reason to let
# the outer one rot.
for _oob in ("8", "9", "70"):
    fd = Fake()
    fd.say("/depo")
    fd.sent.clear()
    fd.say(_oob)
    check(f"...and {_oob!r} is refused with the REASON, at the step the "
          f"operator typed it", "a slot is 0-7" in fd.text())

# A SUPERSCRIPT DIGIT IS THE isdigit/isdecimal TRAP, and it is here because it
# was a real reproduced bug: "²".isdigit() is True and int("²") raises, so a
# slot step guarded by isdigit let a ValueError escape -- no reply sent AND
# the conversation left live, so the operator's next unrelated message was
# eaten as a slot answer. The try/except in step_convo now contains any escape,
# so the CONTAINMENT is not what distinguishes the two predicates -- the
# message is. isdecimal gets the plain "a slot is 0-7"; isdigit gets an error.
for _sup in ("²", "³", "¹"):
    fe2 = Fake()
    fe2.say("/depo")
    fe2.sent.clear()
    fe2.say(_sup)
    check(f"{_sup!r} is refused as a bad slot, not as an internal error",
          "a slot is 0-7" in fe2.text()
          and "went wrong" not in fe2.text())

# AND THE LADDER'S OWN BOUND, at the vault, checked from both ends. The wizard
# cannot produce a negative slot -- but the check that would catch one if
# anything ever did was `slot >= len(ladder)`, which a negative slot walks
# straight past into ladder[-1], the LARGEST rung.
_AG = load("gs_wake_agent")
_lkey = {"tor_proxy": "socks5h://127.0.0.1:9050",
         "rpc_primary": "http://127.0.0.1:18083",
         "amount_ladder": ["0.01", "0.02", "0.05"]}
for _slot, _want_refusal in ((-1, True), (-3, True), (3, True), (0, False),
                             (2, False)):
    try:
        _AG.build_argv("receive_and_quote", {"amount_slot": _slot}, _lkey,
                       __import__("pathlib").Path("/tmp/bay"))
        _refused = False
    except _AG.Refused:
        _refused = True
    check(f"amount slot {_slot} is "
          f"{'refused' if _want_refusal else 'accepted'} by the vault",
          _refused == _want_refusal)

# And the whole space that IS legal, end to end.
for _n in range(8):
    fd = Fake()
    fd.say("/depo")
    fd.say(str(_n))
    fd.answer_confirm()
    check(f"slot {_n} completes and emits amount_slot={_n}",
          fd.pokes == [(111, "receive_and_quote", {"amount_slot": _n})])

# ===========================================================================
# 8. /cancel, AND THE THREE QUESTIONS THAT ARE NOT KNOBS.
# ===========================================================================
print("\n-- cancel, and the answers that are not settings --")
fe = Fake()
fe.say("/depo")
fe.say("/cancel")
check("/cancel drops a live conversation", 111 not in fe.p.convos)
check("...and says nothing was woken", "Nothing was woken" in fe.text())
fe.sent.clear()
fe.say("/cancel")
check("/cancel with nothing running says so rather than lying",
      "nothing to cancel" in fe.text())

# THEY ANSWER "WHERE", AND DELIBERATELY NAME NO IDENTIFIER.
#
# An earlier draft answered each by naming the environment variable, the CLI
# flag, the tool and the memo field it lives in. Accurate, useful to somebody
# standing at the vault with the source open -- and a map of the vault's
# control surface typed into a transcript this whole feature assumes will
# leak. The operator on a phone needs to know it is not settable here and
# where it is; the rest is in OPSEC_SETUP.md, on the machine that has it.
for _cmd, _where in (("/fee", "sending wallet"), ("/speed", "not settable"),
                     ("/exit", "at the vault")):
    ff = Fake()
    ff.say(_cmd)
    check(f"{_cmd} says where it is really decided ({_where!r})",
          _where in ff.text())
    check(f"...and {_cmd} wakes nothing", ff.pokes == [])
for _leak in ("GS_EXIT_TO", "max-slippage", "thor_swap_preparer",
              "interval", "quantity", "gs_wake_agent", "amount_ladder",
              "run_pipeline", "GS_SWAP_AMOUNTS"):
    fh = Fake()
    for _c in ("/fee", "/speed", "/exit", "/help"):
        fh.say(_c)
    check(f"...and no reply hands {_leak} to whoever holds the phone",
          _leak not in fh.text())

# THE ANSWERS MUST BE TRUE. Checked against the code they describe, not just
# present -- a confident sentence about a knob that quietly appeared later is
# the drift this repo keeps catching.
_thor = open(os.path.join(REPO, "thor_swap_preparer"), encoding="utf-8").read()
check("/speed's claim holds: thor_swap_preparer requests no streaming",
      "interval" not in _thor and "streaming" not in _thor)
check("/fee's claim holds: --max-slippage exists and is a vault-side flag",
      '"--max-slippage"' in _thor)
check("...and is NOT reachable from the pager",
      "max-slippage" not in _SRC.split("SPEED_ANSWER")[0]
      .split("FEE_ANSWER")[0])
check("/exit's claim holds: no job schema takes a destination",
      not any("dest" in k or "exit" in k or "addr" in k
              for s in P.JOBS.values() for k in s["schema"]))

# ===========================================================================
# 9. AN UNALLOWLISTED CHAT CANNOT START ONE.
# ===========================================================================
print("\n-- the allowlist still comes first --")
fg = Fake()
fg.say("/depo", cid=999)
check("a chat that is not allowlisted starts no conversation", not fg.p.convos)
check("...and gets no reply at all", fg.sent == [])
check("...and is counted", fg.p.ignored == 1)

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
