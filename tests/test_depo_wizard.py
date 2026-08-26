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


#: Fixed rather than random so a label can be written into a check and stay
#: true from one run to the next.
PAIR_KEY = {"secret": "11" * 32}


class Fake:
    """A Pager with the wake replaced, so nothing below start_job runs."""

    def __init__(self, allow=(111, 222)):
        p = pg.Pager.__new__(pg.Pager)
        # A REAL PAIRING SECRET: /check takes a confirmation number, which is
        # a MAC over (chat, handle) keyed from one, and a Pager that cannot
        # build one is refused at startup.
        p.proxies, p.token, p.key = {}, "x", dict(PAIR_KEY)
        p.args = types.SimpleNamespace()
        p.allow = set(allow)
        p.allow_users = set()
        p.handle_owner = {}
        p.handle_job = {}
        p._chain = None
        p._chain_leg = 0
        p._status_at = {}
        p.spenders = 1
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
        #: The inline keyboard each reply carried, index-aligned with `sent`.
        #: None where a reply had none, which is most of them.
        self.keyboards = []
        p.send = lambda cid, t, buttons=None: (
            self.sent.append((cid, t)), self.keyboards.append(buttons),
            True)[2]
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
print("\n-- the wizard emits the amount that was typed at it --")
f = Fake()
f.say("/depo")
check("/depo with no argument starts a conversation", 111 in f.p.convos)
f.say("0.05")
check("...and asks a confirm question", "= ?" in f.text())
f.answer_confirm()
# EXACT SATOSHIS, and the point of asserting the number rather than "some
# int": 0.05 BTC is 5000000 sat and float(0.05) * 1e8 is 4999999.999999999.
# A conversion that went through a float would land here, once, on a live
# deposit, and this is the check that would say so.
check("answering correctly pokes the wake, carrying the exact amount",
      f.pokes == [(111, "receive_and_quote", {"amount_sat": 5_000_000})])

# THE ONE-SHOT FORM IS GONE, and this check is inverted rather than deleted.
#
# `/depo 2` was one keystroke from a wake and a real quote -- which makes the
# confirm the wizard exists for optional, and optional is the same as absent.
# It also put the digit in the transcript ATTACHED to the word, on one line,
# permanently; the wizard's answer is a bare "2" that says nothing alone.
#
# An argument is REFUSED, not ignored: silently dropping it would run a
# different slot from the one typed.
g = Fake()
g.say("/depo 2")
check("/depo with an argument wakes nothing", g.pokes == [])
check("...and says to use the wizard instead of failing silently",
      "just /depo" in g.text())
check("...and starts no conversation either, so the digit is not half-used",
      111 not in g.p.convos)
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
# 1b. /withdraw: THE ONE JOB THAT SPENDS, AND THE ONLY FREE TEXT ON THE WIRE
# ===========================================================================
print("\n-- the withdraw wizard, driven end to end --")
#
# Every other command is a bounded int or a label this bot issued. This one
# takes an address the operator types, because the alternative is a phone that
# cannot move its owner's money and a documented cycle that ends with the
# funds sitting on an address the Bitcoin chain already published.
_WA = "4" + "Ad" * 47


def _wjob_ok(params):
    """Does the wire really accept this withdraw note? Asked of the real gate."""
    try:
        P.validate_job({"job_id": P.new_job_id(),
                        "challenge": P.new_challenge().hex(),
                        "job": "withdraw", **params})
        return True
    except P.WakeError:
        return False


w = Fake()
w.say("/withdraw")
check("wd: /withdraw starts a conversation", 111 in w.p.convos)
# STRAIGHT TO THE ADDRESS. It used to ask for a 4-character handle first --
# the label of a bundle a /depo had minted -- so a withdrawal was only
# possible for money that arrived through this tool's own deposit flow, and
# the operator had to remember which label named which pile. The vault finds
# its own funded output now.
check("wd: ...and asks ONLY for the address, with no handle to remember",
      "address" in w.sent[-1][1].lower()
      and "handle" not in w.sent[-1][1].lower())
w.say(_WA)
# THEN THE DEPTH, and it is not a confirm yet. A hard-coded depth is what made
# this job refuse most real deposits: GhostSpiral's mix floor rises with the
# hop count (0.1784 XMR at 3 wallets, 0.2972 at 10), so the single pinned
# WITHDRAW_WALLETS = 10 was a floor on what could be withdrawn AT ALL.
# HOPS, NOT THE WIRE'S KEY. The question used to print both -- "1  3 hops",
# "3  20 hops" -- so 3 was the key for twenty hops AND the hop count on the
# first line, and somebody who read the menu and typed what they wanted got
# the slowest option with the highest minimum balance.
check("wd: ...then asks how deep, offering every depth the protocol has",
      all(f"{_h} hops" in w.sent[-1][1] for _h in P.WITHDRAW_HOPS)
      and "SPENDS" not in w.sent[-1][1])
w.say("10")
check("wd: ...then confirms, saying plainly that this one SPENDS",
      "SPENDS" in w.sent[-1][1] and "= ?" in w.sent[-1][1])
# NEITHER THE ADDRESS NOR AN AMOUNT in the confirm: the address is already in
# the transcript once, and this box has never been told a balance.
check("wd: ...and the confirm repeats neither the address nor an amount",
      _WA not in w.sent[-1][1]
      and not re.search(r"\d+\.\d{2,}", w.sent[-1][1]))
w.answer_confirm()
# A LIST, EVEN FOR ONE ADDRESS. The exit relays one transaction per mixed
# output, so a single destination collects every arrival the run spent hours
# separating -- and the wire used to have room for exactly one, which meant the
# phone had no choice about it. exit_to carries 1..MAX_WAKE_EXIT_DESTS now and
# always comes back as a list, so gs_wake_agent's " ".join into GS_EXIT_TO is
# total and there is one shape for every caller to handle.
check("wd: answering correctly pokes exactly one withdraw job, carrying the "
      "destination and the chosen depth",
      w.pokes == [(111, "withdraw", {"exit_to": [_WA], "depth": 2})])
check("wd: ...and the conversation is gone", 111 not in w.p.convos)
_wok = True
try:
    P.validate_job({"job_id": P.new_job_id(),
                    "challenge": P.new_challenge().hex(),
                    "job": "withdraw", **w.pokes[0][2]})
except P.WakeError:
    _wok = False
check("wd: ...and what it emits passes the REAL job schema", _wok)
check("wd: THREE MESSAGES from /withdraw to a spend -- address, depth, "
      "confirm", len([t for _c, t in w.sent]) == 3)

for _msgs, _label, _want in (
        (["/withdraw", "notanaddress"], "a bad address", "bad address"),
        (["/withdraw", "-" + _WA[1:]], "an address shaped like a flag",
         "bad address"),
        (["/withdraw", _WA[:94]], "an address one character short",
         "bad address"),
        (["/withdraw", _WA, "10", "999"], "a wrong confirm", "wrong answer"),
        (["/withdraw", _WA, "0"], "a depth below the table",
         "did not recognise"),
        (["/withdraw", _WA, "4"], "a depth above the table",
         "did not recognise"),
        # THE WIRE'S OWN KEYS, WHICH THE CHAT NO LONGER SPEAKS. "1" and "2"
        # used to mean three and ten hops; the menu printed them beside the
        # hop counts, so "3" meant twenty hops on one line and three hops on
        # another. Refusing them is the safe half of that fix -- an operator
        # who had memorised "2" asks again rather than being handed a
        # different depth without being told.
        (["/withdraw", _WA, "1"], "the old wire key for three hops",
         "did not recognise"),
        (["/withdraw", _WA, "2"], "the old wire key for ten hops",
         "did not recognise"),
        # FULLWIDTH DIGIT ONE. str.isdecimal() is True for it and int()
        # converts it, which is how the first version of _depth_from accepted
        # it -- and how the amount parser accepted "1️" shaped input as a
        # whole bitcoin before _BTC_RE was pinned to [0-9].
        (["/withdraw", _WA, "１"], "a fullwidth digit as a depth",
         "did not recognise"),
        (["/withdraw " + _WA], "the address on the command line",
         "just /withdraw")):
    _g = Fake()
    for _m in _msgs:
        _g.say(_m)
    check(f"wd: {_label} wakes nothing", _g.pokes == [])
    check(f"wd: ...and says why ({_want!r})", _want in _g.text())
    check(f"wd: ...and leaves no conversation armed", 111 not in _g.p.convos)
_ge = Fake()
_ge.say("/withdraw")
_ge.say(_WA[:60])
check("wd: a rejected address is NOT echoed back into the chat",
      _WA[:60] not in _ge.text() and _WA[:16] not in _ge.text())
# NON-VACUITY: the good path really does carry the address, so the check above
# is about the REJECTED value and not about a bot that never says addresses.
check("wd: NON-VACUITY -- the accepted address really does reach the job",
      w.pokes[0][2]["exit_to"] == [_WA])

# ===========================================================================
# 1b-ii. IT TAKES MORE THAN ONE DESTINATION, AND SAYS WHY THAT MATTERS
# ===========================================================================
#
# THE EXIT SENDS ONE TRANSACTION PER MIXED OUTPUT. A withdrawal funds
# `wallets + randint(DECOY_MIN, DECOY_MAX)` of them, so the floor is 5, 12 and
# 22 arrivals at the three depths -- and with a single destination every one of
# them lands on the same address, minutes apart, from a wallet that just spent
# hours making sure they could not be grouped.
#
# resolve_exit_destinations warns about exactly that, and says it is a warning
# rather than a refusal because "one destination is a legitimate choice ... The
# operator has to be told what it costs, not overruled." It prints onto the
# vault's stdout, which the unit diverts to a 0600 file on a machine that
# powers off -- so on the phone path nobody has ever read it, and the wire took
# one address, so the wizard could not have offered a second even if they had.
print("\n-- the withdrawal can be spread, and the chat says what one costs --")
_WB = "4" + "Ad" * 46 + "Ae"
_WC = "4" + "Ad" * 46 + "Af"

_m = Fake()
_m.say("/withdraw")
_ask = _m.sent[-1][1]
check("wd/spread: the question offers more than one address",
      str(P.MAX_WAKE_EXIT_DESTS) in _ask and "several" in _ask.lower())
check("wd/spread: ...and states the arrival count that makes it matter",
      str(P.exit_arrivals_floor(min(P.WITHDRAW_DEPTHS))) in _ask)
# "ONE ADDRESS IS FINE" WAS TWO SENTENCES OF REASSURANCE nobody needed: the
# question already accepts one, so an operator with one address types it. What
# is worth the room is the reason SEVERAL is better, which is the part they
# cannot work out for themselves.
check("wd/spread: ...and says why several is better, which is the part the "
      "operator cannot work out alone",
      "group them" in _ask.lower())
check(f"wd/spread: ...in one short screen ({len(_ask)} chars)",
      len(_ask) <= 260)
_m.say(f"{_WA} {_WB} {_WC}")
_m.say("20")
_conf = _m.sent[-1][1]
check("wd/spread: three addresses are accepted in one message",
      "= ?" in _conf)
check("wd/spread: the confirm says how many separate transactions there will "
      "be, at the depth just chosen",
      str(P.exit_arrivals_floor(3)) in _conf)
check("wd/spread: ...and how many places they land in",
      "across 3 addresses" in _conf)
# THE ADDRESSES ARE STILL NOT REPEATED. A count is not a destination: it says
# nothing about where the money goes, and the transcript has no masker.
check("wd/spread: the confirm still repeats no address",
      _WA not in _conf and _WB not in _conf and _WC not in _conf)
_m.answer_confirm()
check("wd/spread: all three reach the job, in order",
      _m.pokes[0][2]["exit_to"] == [_WA, _WB, _WC])
check("wd/spread: ...and the wire accepts that note",
      _wjob_ok(_m.pokes[0][2]))

# ...AND "3" MEANS THREE HOPS, WHICH IS WHAT IT LOOKS LIKE IT MEANS.
#
# The one character both vocabularies claimed. Under the old numbering it
# selected the THIRD row -- twenty hops, ~13h instead of ~6h, the highest
# minimum balance of the three -- for somebody who had read "3 hops" off the
# first line and typed it. Driven end to end, because a mapping test would
# not have caught the question printing one thing and the step reading
# another.
_h3 = Fake()
_h3.say("/withdraw"); _h3.say(_WA); _h3.say("3")
_h3conf = _h3.sent[-1][1]
_h3.answer_confirm()
check("wd/hops: typing 3 runs THREE hops, not the third row",
      len(_h3.pokes) == 1
      and P.WITHDRAW_DEPTHS[_h3.pokes[0][2]["depth"]][0] == 3)
check("wd/hops: ...and the confirm it agreed to said three hops too, so the "
      "screen and the job match",
      "3 hops" in _h3conf and "20 hops" not in _h3conf)
# EVERY NUMBER THE MENU PRINTS IS A NUMBER THE STEP READS, and this is the
# check that would have caught the collision on its own. The question used to
# print two number columns -- the wire's key and the hop count -- so half the
# numbers on screen meant one thing to the reader and another to the step.
_dq = Fake()
_dq.say("/withdraw"); _dq.say(_WA)
_dqtext = _dq.sent[-1][1]
_dqnums = [int(n) for n in re.findall(r"^\s+(\d+)", _dqtext, re.M)]
check(f"wd/hops: the question prints one number per row ({_dqnums})",
      len(_dqnums) == len(P.WITHDRAW_DEPTHS))
check("wd/hops: ...and every one of them is a hop count the step accepts, so "
      "nothing on screen means something else to the code",
      _dqnums and all(_dq.p._depth_from(str(_n)) is not None
                      for _n in _dqnums)
      and sorted(_dqnums) == sorted(P.WITHDRAW_HOPS))

# NON-VACUITY: the deepest option is still reachable, by the number the menu
# prints for it.
_h20 = Fake()
_h20.say("/withdraw"); _h20.say(_WA); _h20.say("20")
_h20.answer_confirm()
check("wd/hops: NON-VACUITY -- 20 still runs twenty hops",
      P.WITHDRAW_DEPTHS[_h20.pokes[0][2]["depth"]][0] == 20)

# ONE DESTINATION GETS THE SENTENCE, because that is the case where the count
# is the bad news. NON-VACUITY for the branch above: the two differ.
_o = Fake()
_o.say("/withdraw"); _o.say(_WA); _o.say("20")
_oc = _o.sent[-1][1]
check("wd/spread: one address is told what it costs, at the confirm",
      "ONE address" in _oc and "group" in _oc)
check("wd/spread: NON-VACUITY -- the three-address confirm says no such thing",
      "ONE address" not in _conf)
check("wd/spread: both confirms quote the SAME arrival floor for the same "
      "depth, so the number is about the depth and not about the spread",
      str(P.exit_arrivals_floor(3)) in _oc)

# THE CAP AND THE DUPLICATE RULE ARE THE WIRE'S, enforced where the operator
# is typing rather than after a wake has been spent.
_c = Fake()
_c.say("/withdraw")
_c.say(" ".join("4" + "Ad" * 46 + "A" + c
                for c in "bcdefghijklmnop"[:P.MAX_WAKE_EXIT_DESTS + 1]))
check("wd/spread: one more than the cap is refused here, not at the vault",
      "no:" in _c.sent[-1][1].lower() and 111 not in _c.p.convos)
_d2 = Fake()
_d2.say("/withdraw"); _d2.say(f"{_WA} {_WA}")
check("wd/spread: the same address twice is refused -- repeating one spreads "
      "nothing", "no:" in _d2.sent[-1][1].lower() and 111 not in _d2.p.convos)
# NON-VACUITY: exactly the cap still works, so the two refusals above are a
# ceiling and a duplicate rule, not a blanket refusal of several addresses.
_f = Fake()
_f.say("/withdraw")
_f.say(" ".join("4" + "Ad" * 46 + "A" + c
                for c in "bcdefghijklmnop"[:P.MAX_WAKE_EXIT_DESTS]))
_f.say("3")
check("wd/spread: NON-VACUITY -- exactly the cap is accepted",
      "= ?" in _f.sent[-1][1])
_f.answer_confirm()
check("wd/spread: ...and all of them reach the job",
      len(_f.pokes[0][2]["exit_to"]) == P.MAX_WAKE_EXIT_DESTS)
check("wd/spread: ...and the wire carries a note at the cap",
      _wjob_ok(_f.pokes[0][2]))

# ===========================================================================
# 1c. IT ASKS FOR THE AMOUNT, AND ONLY ACCEPTS ONE
# ===========================================================================
print("\n-- it asks how much, in the operator's own figures --")
#
# This section used to be "nobody knows what slot 0 to 7 is", and it tested a
# menu of LABELS -- "small", "medium", "large" -- that named rungs of a ladder
# of amounts held in the vault's keyfile. The labels solved the cosmetic half
# of the problem (a number nobody could decode) and left the real half: a rung
# is the amount being sent only if that amount was foreseen at pairing time.
# The ladder is gone; the wizard asks for the figure.
_a = Fake()
_a.say("/deposit")
_q = _a.sent[-1][1]
check("amount: the question asks for a BTC amount, not a position in a list",
      "btc" in _q.lower() and "slot" not in _q.lower()
      and "position" not in _q.lower())
# THE BOUNDS MOVED TO THE REFUSAL. Listing them in the QUESTION makes every
# operator read two numbers that constrain almost nobody; listing them in the
# refusal reaches exactly the operator who got it wrong.
check("amount: ...and does not spend the question on bounds that constrain "
      "almost nobody",
      P.btc_display(P.DEPOSIT_MAX_SAT) not in _q)
_a.say("0.05")
check("amount: the confirm says the figure back, so it is what gets confirmed",
      "0.05" in _a.sent[-1][1])
_a.answer_confirm()
check("amount: ...and it reaches the wire as exact satoshis",
      _a.pokes == [(111, "receive_and_quote", {"amount_sat": 5_000_000})])

# EXACTNESS IS THE PROPERTY, not "it parsed". Every one of these is a figure
# whose float conversion is wrong in the last place, and a deposit quoted for
# 4999999.999999999 satoshis is a deposit quoted for the wrong number.
for _typed, _want in (("0.05", 5_000_000), ("0.07", 7_000_000),
                      ("0.1", 10_000_000), ("1.1", 110_000_000),
                      ("2.675", 267_500_000), ("0.00010000", 10_000),
                      ("100", 10_000_000_000)):
    _e = Fake()
    _e.say("/deposit"); _e.say(_typed); _e.answer_confirm()
    check(f"amount: {_typed} BTC is exactly {_want} sat",
          _e.pokes == [(111, "receive_and_quote", {"amount_sat": _want})])
    check(f"amount: NON-VACUITY -- float would have got {_typed} wrong",
          int(float(_typed) * 1e8) == _want
          or _e.pokes[0][2]["amount_sat"] == _want)

# WHAT IS REFUSED, and each of these is a way a string looks like one number
# and parses as another.
for _typed, _why in (
        ("0.00009", "under the floor"),
        ("101", "over the ceiling"),
        ("0", "zero"),
        ("-1", "negative"),
        ("+1", "signed"),
        ("1e9", "exponent"),
        ("1,5", "a comma as the separator"),
        ("0.123456789", "nine decimal places, which bitcoin does not have"),
        (".5", "a bare leading dot"),
        ("1.", "a trailing dot"),
        ("abc", "not a number at all"),
        # THE ONE THAT WAS ACTUALLY ACCEPTED. "１" is FULLWIDTH DIGIT ONE:
        # str.isdecimal() is True for it, int() converts it, and Python's \d
        # matches it -- so the first version of _BTC_RE took it for one whole
        # bitcoin. Driven before the fix. There are 455 such characters.
        ("１", "a fullwidth digit that renders as 1"),
        ("٥", "an Arabic-Indic digit that Decimal() would accept as 5")):
    _r = Fake()
    _r.say("/deposit"); _r.say(_typed)
    check(f"amount: {_why} is refused ({_typed!r})", _r.pokes == [])
    check(f"amount: ...and no conversation is left armed ({_typed!r})",
          111 not in _r.p.convos)

# NOT ECHOED. A rejected figure in the transcript is an amount written down
# for a deposit that is not going to happen.
_re_ = Fake()
_re_.say("/deposit"); _re_.say("123.456")
check("amount: a rejected figure is NOT echoed back into the chat",
      "123.456" not in _re_.text())

# ROUND TRIP. What the operator confirmed and what the vault will quote are
# the same number, expressed by the two functions that must agree.
_rt = True
for _sat in (P.DEPOSIT_MIN_SAT, 5_000_000, 123_456_789, P.DEPOSIT_MAX_SAT):
    if P.btc_to_sat(P.sat_to_btc(_sat)) != _sat:
        _rt = False
check("amount: sat_to_btc and btc_to_sat round-trip exactly", _rt)
check("amount: NON-VACUITY -- sat_to_btc really does produce a parseable "
      "figure", P.sat_to_btc(5_000_000) == "0.05000000")

# ===========================================================================
# 1d. /settings — WHAT A RUN DOES, AND WHO DECIDES IT
# ===========================================================================
print("\n-- the settings the dashboard had and the chat did not --")
_st = Fake()
_st.say("/settings")
_stx = _st.sent[-1][1]
# ---- A TYPO GUARD PRESENTED AS AN OPERATING RANGE STRANDS MONEY ---------
#
# gs_wake_proto says it at the constants: "THESE ARE TYPO GUARDS AND NOT
# PROTOCOL MINIMUMS". The chat said "Anything from 0.0001 to 100", which is how
# an operator reads an operating range -- and a careful first-timer testing
# with the smallest number the bot named strands the money, because every
# /withdraw at every depth then fails against a mix minimum two orders of
# magnitude higher.
#
# AND THEN THE FIX ITSELF WAS THE NEXT PROBLEM. The first version spent four
# lines explaining what a typo guard is, what the real floor is, and that this
# box cannot compute it -- 391 characters, on the first question a newcomer is
# ever asked. The operator only ever needed the last clause. The bounds are
# still enforced and still named in the REFUSAL, which is where a number is
# actually useful; the question keeps the one instruction that changes what
# they type.
print("\n-- the deposit floor, in as few words as it takes --")
_aq = Fake()
_aq.say("/deposit")
_aqt = _aq.text()
check("deposit: the question says which way to err, which is the only part "
      "the operator can act on",
      "Too little" in _aqt and "send more" in _aqt)
check(f"deposit: ...and says it in one short screen ({len(_aqt)} chars)",
      len(_aqt) <= 180)
check("deposit: ...and does not lecture about what a typo guard is",
      "TYPO GUARD" not in _aqt and "real floor" not in _aqt)
# THE BOUNDS ARE STILL ENFORCED, and still named where a number helps: the
# refusal. A question that lists them makes every operator read them; a
# refusal that lists them reaches only the operator who got it wrong.
_ob = Fake()
_ob.say("/deposit")
_ob.say("500")
check("deposit: an out-of-range amount is still refused",
      "no:" in _ob.text().lower())
check("deposit: ...and the refusal names the bound, so it is not a guessing "
      "game",
      P.btc_display(P.DEPOSIT_MAX_SAT) in _ob.text()
      or "100" in _ob.text())

check("settings: it says the operator picks the deposit amount",
      "deposit amount" in _stx.lower())
check("settings: ...and offers every mixing depth the protocol has",
      all(str(_d) in _stx for _d in P.WITHDRAW_DEPTHS))
# "WAKE BUDGET" WAS THE WORD, AND THE WELCOME IS TESTED FOR NOT CONTAINING
# IT. "wake" says there is a machine that is normally off and that this chat
# switches it on -- the shape of the operation, on the longest reply this bot
# sends. The test was written for the welcome and the word was left standing
# in thirteen replies that predate it, /settings among them. What the
# operator needs from this line is the number and that it is a daily one.
check("settings: ...and the daily allowance, which is counted on THIS end",
      "12" in _stx and "allowance" in _stx.lower())
check("settings: ...and does not name what is being woken to do it",
      not re.search(r"\\bwoken?\\b|\\bwakes?\\b", _stx, re.I))
# THE MEANING, NOT ONE PHRASE. This tested for the literal "not here", which
# the reply happened to contain; the reply now separates "set on the machine"
# from "fixed in the software" because the old version claimed the hop delay
# was a machine setting when it is settable NOWHERE. Both headings have to be
# there, or one of those groups has gone back to being a single vague bucket.
check("settings: ...and says plainly which parts are decided elsewhere, "
      "separating what a person can change from what nobody can",
      "set on the machine" in _stx.lower()
      and "fixed in the software" in _stx.lower())
check("settings: ...and does not claim the hop delay is a machine setting, "
      "because there is no keyfile field for it and no --hop-delay composed",
      "delay" in _stx.lower()
      and _stx.lower().index("fixed in the software")
      < _stx.lower().index("the delay between hops"))
check("settings: ...and why they are not settable from a chat",
      "turn the mixing down" in _stx)
check("settings: it wakes nothing to answer", _st.pokes == [])
# NOTHING OPERATIONAL LEAKS. It is a reply on the surface this design assumes
# is read: no machine names, no amounts, no addresses.
check("settings: it names no machine",
      "vault" not in _stx.lower() and "thinkpad" not in _stx.lower()
      and "pi" not in _stx.lower().split())
# STILL NO DECIMAL, and this one survived the change rather than being
# relaxed to fit it. An earlier draft of the new /settings printed the deposit
# bounds here and would have failed this; the bounds moved to /deposit, which
# is where they are actually needed.
check("settings: and no amount", not re.search(r"\d+\.\d", _stx))

# ===========================================================================
# 2. IT CANNOT NAME A DESTINATION FOR A DEPOSIT. Structural, not behavioural.
# ===========================================================================
print("\n-- it cannot name where a deposit lands, because it mints nothing --")
#
# THIS SECTION USED TO SAY "IT CANNOT NAME AN AMOUNT", and that is no longer
# true or wanted: the wizard asks for the figure, because a quote for a rung
# off a preset list is a quote for a number that is not the number being sent.
# The half of the old property that was actually load-bearing survives intact
# and is what is tested here -- the Pi cannot say WHERE a deposit goes. The
# receive subaddress is minted inside the job, on the vault, by
# create_receive_wallet; nothing on this box can name, select or influence it.
# That is the one that turns "they can wake and spam quotes" into "they can
# redirect your money", and it is unchanged.
_SRC = open(os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read()
check("the pager has no amount ladder to read, and no longer pretends to",
      '"amount_ladder"' not in _SRC and "'amount_ladder'" not in _SRC
      and '"amount_labels"' not in _SRC)
# THE DEPOSIT JOB CARRIES ONE KEY, and it is not an address.
_dj = Fake()
_dj.say("/deposit"); _dj.say("0.05"); _dj.answer_confirm()
check("a deposit job carries the amount and nothing else",
      set(_dj.pokes[0][2]) == {"amount_sat"})
check("...and the protocol agrees that is the whole schema",
      set(P.JOBS["receive_and_quote"]["schema"]) == {"amount_sat"})
# NON-VACUITY: the OTHER job really can carry an address, so this is a fact
# about the deposit path and not about a bot that never sends addresses.
check("NON-VACUITY -- withdraw really can carry a destination, so the "
      "deposit path's silence is a property and not an incapacity",
      "exit_to" in P.JOBS["withdraw"]["schema"])

f2 = Fake()
f2.say("/depo")
f2.say("0.05")
# AND IT EXPLAINS NOTHING. The prompt used to say why it could only offer
# slots -- that the ladder lived on the other machine and this box had never
# held it. True, and a description of the arrangement written permanently into
# the surface this design assumes gets read, in exchange for telling the
# operator something they learn once. The reasoning stayed in the source.
check("the prompt does not describe the setup to whoever reads this chat",
      "ladder" not in f2.text().lower()
      and "vault" not in f2.text().lower()
      and "subaddress" not in f2.text().lower())
check("NON-VACUITY -- it still asks the question and still says how to stop",
      "How much" in f2.text() and "/cancel" in f2.text())
# THE ONLY DECIMALS IN THE TRANSCRIPT ARE THE BOUNDS AND THE OPERATOR'S OWN
# FIGURE. Both are things they typed or things every install of this public
# repository shares; neither says anything about this operator's money that
# they did not just say themselves.
import re as _re2
_decimals = set(_re2.findall(r"\d+\.\d+", f2.text()))
check("every figure in the chat is either a bound or what the operator typed",
      _decimals <= {P.btc_display(P.DEPOSIT_MIN_SAT),
                    P.btc_display(P.DEPOSIT_MAX_SAT), "0.05"})

# ===========================================================================
# 3. IN MEMORY, NEVER ON THE CARD.
# ===========================================================================
print("\n-- a half-finished /depo never reaches the SD card --")
check("Convo has __slots__, so a field cannot be added by accident",
      hasattr(pg.Convo, "__slots__"))
check("...and holds only the seven fields the two wizards need",
      set(pg.Convo.__slots__) == {"kind", "amount", "depth", "handle",
                                  "exit_to", "expect", "deadline"})
# THE RULE NARROWED. It used to be "no string field at all" -- a struct that
# cannot hold an address however the prompts are later edited. /withdraw has to
# hold one, because the operator types their destination into the chat and it
# must survive until the confirm.
#
# So the rule becomes the narrower thing it was always FOR: exactly ONE free
# text field, named, and nothing here reaching disk. The second half was always
# the real invariant; the first was the cheap way to enforce it, and it is
# still enforced for every other field.
_c_fresh = pg.Convo(lambda: 0.0)
check("...and every field starts empty, so a fresh Convo holds nothing",
      all(getattr(_c_fresh, f) in (None, "depo")
          or isinstance(getattr(_c_fresh, f), float)
          for f in pg.Convo.__slots__))
_c_full = pg.Convo(lambda: 0.0, kind="withdraw")
_c_full.handle, _c_full.exit_to, _c_full.expect = "A3F1", "4" + "Ad" * 47, 9
_str_fields = [f for f in pg.Convo.__slots__
               if isinstance(getattr(_c_full, f), str)]
check("...and a FULL withdraw conversation holds exactly three strings: its "
      "kind, the handle this bot issued, and the one address",
      sorted(_str_fields) == ["exit_to", "handle", "kind"])
check("...and no field can hold a memo, a slip or an amount — nothing else is "
      "text at all",
      all(not isinstance(getattr(_c_full, f), str)
          for f in pg.Convo.__slots__
          if f not in ("kind", "handle", "exit_to")))
# AND THE ADDRESS IS SET IN EXACTLY ONE PLACE, from a value the protocol's own
# gate has already accepted. A second writer is how a checked field becomes an
# unchecked one.
check("...and exit_to is assigned in exactly one place in the source",
      _SRC.count("c.exit_to = ") == 1)
check("...and that place is guarded by the protocol's address gate",
      'proto.JOBS["withdraw"]["schema"]["exit_to"](_a)' in _SRC)
check("...so `step` is derived, not stored", "step" not in pg.Convo.__slots__)
_save = pg.Limits.save.__doc__ or ""
# THE WINDOW IS THE CLASS, taken from the parse tree rather than from the next
# occurrence of the word "class".
#
# This read _SRC.split("class Limits")[1].split("\nclass ")[0], and there is no
# class between Limits and Convo -- so the "window" was Limits PLUS every
# module-level function defined after it, parse_command included. The check
# below then fails or passes on words written in functions it is not about: it
# fired on the word "conversation" in parse_command's refusal, which has
# nothing to do with what Limits.save writes. A window that drifts is a check
# whose subject drifts with it.
import ast as _ast_l                                          # noqa: E402
_lsrc = next(_ast_l.get_source_segment(_SRC, _n)
             for _n in _ast_l.parse(_SRC).body
             if isinstance(_n, _ast_l.ClassDef) and _n.name == "Limits")
check("the window really is just that class and not everything after it",
      _lsrc.startswith("class Limits") and "def parse_command" not in _lsrc)
check("Limits.save writes only the cursor and the counters",
      '"offset"' in _lsrc and '"pokes"' in _lsrc and "convo" not in _lsrc)
check("nothing writes convos to disk",
      "atomic_write_json" not in _SRC.split("def begin_convo")[1]
      .split("def send")[0])
f3 = Fake()
f3.say("/depo")
f3.say("0.03")
_c = f3.p.convos[111]
# AN INT, NOT THE TEXT THAT WAS TYPED. The parse happens once, at the step
# that reads it, and what survives into the struct is a satoshi count -- so
# "0.03", a locale comma, an exponent or a fullwidth digit cannot live here
# waiting to be re-parsed by something else later.
check("a live conversation holds an int amount in satoshis, not the text",
      isinstance(_c.amount, int) and not isinstance(_c.amount, bool)
      and _c.amount == 3_000_000)
_c3 = Fake()
_c3.say("/withdraw"); _c3.say(_WA); _c3.say("20")
check("...and a withdraw conversation holds an int depth the same way",
      isinstance(_c3.p.convos[111].depth, int)
      and _c3.p.convos[111].depth == 3)
# NAMES THAT WOULD BE FREE TEXT. `amount` is deliberately NOT in this list
# any more: the struct holds one now, as an int, and the rule it was standing
# in for is the one below -- exactly one STRING field, and it is the exit
# address. A name-based check cannot tell an int from a memo; the type check
# can, so that is the one that carries the invariant.
for _bad in ("address", "memo", "btc", "xmr", "text", "note"):
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
f8.say(f"/check {pg.confirmation_number(PAIR_KEY, 111, 'A3F1')}")
check("a real command mid-conversation is NOT eaten by the wizard",
      f8.pokes == [(111, "swap_status", {"handle": "A3F1"})])
check("...and the abandoned conversation is dropped rather than left live",
      111 not in f8.p.convos)

# THE RATE LIMIT IS ON THE ONE PATH THERE IS. It used to be checked on both
# the wizard and the one-shot form, because the point of a single start_job is
# that a limit cannot apply to one and not the other. The one-shot form is
# gone, so the wizard is the only producer -- and the gate still has to be on
# it, which is what this now proves.
f9 = Fake()
f9.p.start_job = f9._real_start
f9.limited[0] = "wait 42s"
f9.say("/depo 2")
check("an argument to /depo wakes nothing even before the limit is consulted",
      not f9.p.busy.locked() and "just /depo" in f9.text())
f9.sent.clear()
f9.say("/depo")
f9.say("2")
f9.answer_confirm()
check("the rate limit refuses the WIZARD, which is the only path to a wake",
      "wait 42s" in f9.text())
check("...and no wake was started", not f9.p.busy.locked())
# NON-VACUITY: with the limit lifted, the SAME drive does reach a wake -- so
# the refusal above is the limit and not the wizard being broken.
f9b = Fake()
f9b.p.start_job = f9b._real_start
f9b.limited[0] = ""
f9b.say("/depo")
f9b.say("2")
f9b.answer_confirm()
check("NON-VACUITY -- with no limit the same drive DOES reach start_job",
      f9b.recorded == [1])

# ===========================================================================
# 6. THE CONFIRM GATE.
# ===========================================================================
print("\n-- the confirm gate, and what it honestly is --")
fa = Fake()
fa.say("/depo")
fa.say("0.4")
_q = fa.text()
# THE CONFIRM NAMES WHAT WAS CHOSEN, and now that is the figure itself. It
# used to be the operator's word for a ladder rung ("medium"), or "#4" when
# they had paired no words -- a number nobody could check against anything.
check("the confirm names what was chosen before waking anything",
      "Deposit 0.4 BTC" in _q)
check("...and names no machine while doing it", "vault" not in _q.lower())
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
# 7. A BAD AMOUNT NEVER BECOMES A JOB.
# ===========================================================================
print("\n-- nothing but a real BTC figure gets through --")
#
# This was "nothing but 0-7 gets through" and tested a ladder index. The
# parameter changed; the discipline did not, and most of the hostile strings
# below are the SAME ones, because they are ways a value looks like a number
# and is not one.
for _bad in ("9e9", "-1", "two", "", "٢", "0x2", "1e1", "2; /depo 7", "2\n7",
             "7" * 40, "²", "½", "٩", "+2", "0.05.1", "0,05", "١٢٣",
             "0.000000001", "1000000", "nan", "inf", "0"):
    fc = Fake()
    fc.say("/depo")
    fc.say(_bad)
    if fc.p.convos.get(111) and not fc.p.convos[111].awaiting_amount():
        fc.answer_confirm()
    ok = (fc.pokes == []
          or (P.DEPOSIT_MIN_SAT <= fc.pokes[0][2]["amount_sat"]
              <= P.DEPOSIT_MAX_SAT))
    check(f"amount {_bad!r} cannot produce an out-of-range job", ok)
    check(f"...and leaves no conversation live and armed for {_bad!r}",
          111 not in fc.p.convos)

# THE MESSAGE MATTERS TOO, and it is what the range check uniquely provides.
#
# Found by the mutation sweep on the predecessor of this section: deleting the
# bound left the guarantee intact, because a later equality check stopped the
# poke anyway -- so nothing out of range reached the wire either way. What
# changed was what the operator was TOLD: "internal check failed" instead of a
# reason, two screens later, for a typo. Defence in depth is why the inner
# check survives; it is not a reason to let the outer one rot.
for _oob, _why in (("1000", "over"), ("0.000001", "under")):
    fd = Fake()
    fd.say("/depo")
    fd.sent.clear()
    fd.say(_oob)
    check(f"...and {_oob!r} is refused with the REASON ({_why} the bound), "
          f"at the step the operator typed it",
          "expected between" in fd.text())
for _shape in ("1e9", "two", "0,05"):
    fd = Fake()
    fd.say("/depo")
    fd.sent.clear()
    fd.say(_shape)
    check(f"...and {_shape!r} is refused for its SHAPE, not its size",
          "plain BTC amount" in fd.text())

# A SUPERSCRIPT DIGIT IS THE isdigit/isdecimal TRAP, and it is here because it
# was a real reproduced bug: "²".isdigit() is True and int("²") raises, so a
# step guarded by isdigit let a ValueError escape -- no reply sent AND the
# conversation left live, so the operator's next unrelated message was eaten
# as an answer. The try/except in step_convo contains any escape now, so
# CONTAINMENT is not what distinguishes the predicates -- the message is.
for _sup in ("²", "³", "¹"):
    fe2 = Fake()
    fe2.say("/depo")
    fe2.sent.clear()
    fe2.say(_sup)
    check(f"{_sup!r} is refused as a bad amount, not as an internal error",
          "plain BTC amount" in fe2.text() and "went wrong" not in fe2.text())

# THE FULLWIDTH FAMILY, WHICH IS THE SAME TRAP WEARING A DISGUISE THAT WORKS.
# "²" raises in int() and is caught. "１" does NOT: str.isdecimal() is True,
# int() returns 1, Decimal() returns 1 and Python's \d matches it. There are
# 455 such characters and the first version of _BTC_RE took every one of them.
# Driven: "１" was accepted as 100,000,000 satoshis -- one whole bitcoin.
_leaked = []
for _c in ("１", "٥", "৩", "๗", "９"):
    ff = Fake()
    ff.say("/depo")
    ff.say(_c)
    if ff.pokes:
        _leaked.append(_c)
check("no non-ASCII digit is accepted as an amount, however it renders",
      _leaked == [])
# NON-VACUITY: int() really would have taken them, so this is a fact about
# the guard and not about characters Python rejects anyway.
check("NON-VACUITY -- int() accepts every one of those characters",
      all(int(_c) > 0 for _c in ("１", "٥", "৩", "๗", "９")))

# AND THE VAULT'S OWN BOUND, checked from both ends. The predecessor of this
# check caught a real defect: the vault read `slot >= len(ladder)`, one end
# only, so a NEGATIVE slot indexed from the far end into ladder[-1] -- the
# LARGEST rung -- and the refusal never fired. The ladder is gone; the lesson
# is that the box holding the money bounds the number itself, at both ends.
_AG = load("gs_wake_agent")
_lkey = {"tor_proxy": "socks5h://127.0.0.1:9050",
         "rpc_primary": "http://127.0.0.1:18083"}
for _sat, _want_refusal in ((-1, True), (0, True), (P.DEPOSIT_MIN_SAT - 1, True),
                            (P.DEPOSIT_MAX_SAT + 1, True), (10 ** 18, True),
                            (P.DEPOSIT_MIN_SAT, False), (5_000_000, False),
                            (P.DEPOSIT_MAX_SAT, False)):
    try:
        _AG.build_argv("receive_and_quote", {"amount_sat": _sat}, _lkey,
                       __import__("pathlib").Path("/tmp/bay"))
        _refused = False
    except _AG.Refused:
        _refused = True
    check(f"amount {_sat} sat is "
          f"{'refused' if _want_refusal else 'accepted'} by the vault",
          _refused == _want_refusal)

# THE AMOUNT REACHES THE CHILD AS BITCOIN, NOT AS SATOSHIS. A str() here
# instead of sat_to_btc would quote a swap for a hundred million times the
# intended figure, and every other check in this file would still pass.
check("NON-VACUITY -- sat_to_btc is what stands between 0.05 and 5000000 BTC",
      P.sat_to_btc(5_000_000) == "0.05000000" and str(5_000_000) != "0.05000000")

# And a spread of the space that IS legal, end to end.
for _typed, _sat in (("0.0001", 10_000), ("0.05", 5_000_000),
                     ("1", 100_000_000), ("2.5", 250_000_000),
                     ("100", 10_000_000_000)):
    fd = Fake()
    fd.say("/depo")
    fd.say(_typed)
    fd.answer_confirm()
    check(f"{_typed} BTC completes and emits amount_sat={_sat}",
          fd.pokes == [(111, "receive_and_quote", {"amount_sat": _sat})])

# ===========================================================================
# 8. /cancel, AND THE THREE QUESTIONS THAT ARE NOT KNOBS.
# ===========================================================================
print("\n-- cancel, and the answers that are not settings --")
fe = Fake()
fe.say("/depo")
fe.say("/cancel")
check("/cancel drops a live conversation", 111 not in fe.p.convos)
check("...and says nothing was started", "Nothing was started" in fe.text())
fe.sent.clear()
fe.say("/cancel")
check("/cancel with nothing running says so rather than lying",
      "nothing to cancel" in fe.text())

# AND THE THIRD STATE, WHICH IS THE ONE AN OPERATOR IS MOST LIKELY IN.
#
# /cancel had two answers for three states. With no half-typed conversation
# but a WAKE IN FLIGHT it said "nothing to cancel." -- while a withdrawal held
# `busy` for up to sixteen hours and every other command was being refused
# with "a wake is already running". The bot told the operator nothing was
# happening and then refused them because something was. That flat
# self-contradiction is the thing that reads as broken software.
#
# A wake genuinely cannot be cancelled: the vault has collected the job and is
# running it on a machine nothing here can reach. So the fix is not a cancel,
# it is an honest answer.
_cb = Fake()
_cb.p.busy.acquire()                       # a wake is running, no conversation
_cb.say("/cancel")
_cbt = _cb.text()
check("/cancel with a WAKE running does not claim there is nothing to cancel",
      "nothing to cancel." not in _cbt)
check("...and says something is running instead",
      "something is running" in _cbt.lower()
      or "something IS running" in _cbt)
check("...and says plainly that it cannot be stopped from here, rather than "
      "implying it was", "cannot be stopped" in _cbt.lower())
check("...and explains why everything else is being refused",
      "refused" in _cbt.lower())
check("...and wakes nothing itself", _cb.pokes == [])
# A HALF-TYPED CONVERSATION IS STILL CANCELLABLE WHILE A WAKE RUNS -- and
# building that state took a correction. The obvious construction (hold
# `busy`, then /depo) does not produce it: begin_convo REFUSES to start a
# conversation while a wake runs, deliberately, because a wake outlives
# CONVO_TTL_S and the operator would walk the whole wizard to be refused at
# the end. So a live conversation can only coexist with a wake if it was
# started FIRST -- which happens for real whenever two chats are allowlisted
# and the other one pokes.
_cc = Fake()
_cc.say("/depo")
check("/cancel: the state exists -- a conversation started before the wake",
      111 in _cc.p.convos)
_cc.p.busy.acquire()                       # now the other chat's wake begins
_cc.sent.clear()
_cc.say("/cancel")
check("/cancel still cancels a half-typed wizard while a job runs",
      "Nothing was started" in _cc.text() and 111 not in _cc.p.convos)
# AND THE GUARD THAT MADE THE FIRST VERSION OF THIS CHECK WRONG IS ITSELF
# WORTH PINNING: a wizard cannot be STARTED during a wake.
_ce = Fake()
_ce.p.busy.acquire()
_ce.say("/depo")
check("/cancel: ...and a wizard cannot be started during a wake at all",
      111 not in _ce.p.convos
      and "already running" in _ce.text())
# NON-VACUITY: with nothing running at all the plain answer is unchanged, so
# the new branch is about `busy` and not a rewrite of every cancel.
_cd = Fake()
_cd.say("/cancel")
check("/cancel: NON-VACUITY -- idle still answers 'nothing to cancel.'",
      "nothing to cancel." in _cd.text())

# THEY ANSWER "WHERE", AND DELIBERATELY NAME NO IDENTIFIER.
#
# THE ANSWER, AND NOTHING AROUND IT.
#
# Two drafts got this wrong in the same direction. The first named the
# environment variable, the CLI flag, the tool and the memo field each knob
# lives in. The second dropped the names but kept the paragraphs: where it is
# really decided, why it is not settable, what loosening it would cost, and --
# worst -- a sentence explaining that the omission was deliberate because the
# transcript is assumed read. Every one of those is a description of the
# arrangement, sitting permanently in the readable surface, bought by telling
# the operator something they already know.
#
# So the test is now a CEILING, not a needle: the reply is short, and it names
# nothing. A needle check cannot fail on a paragraph that grows around it,
# which is exactly how the second draft passed.
_ANSWER_MAX = 40
for _cmd in ("/fee", "/speed", "/exit"):
    ff = Fake()
    ff.say(_cmd)
    _r = ff.text().strip()
    check(f"{_cmd} answers in one short line ({len(_r)} chars)",
          0 < len(_r) <= _ANSWER_MAX)
    check(f"...and {_cmd} names no machine, tool or file",
          not any(w in _r.lower() for w in
                  ("vault", "thinkpad", "keyfile", "gs_", "thorchain",
                   "opsec", "deliberate", "transcript", "cash-out",
                   "deposit", "swap", "mix")))
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
# /exit's CLAIM CHANGED WITH THE CODE. It used to say "not settable here" and
# the check proved no job schema took a destination. /withdraw takes one now,
# by reply, per withdrawal -- so the old check would have kept a FALSE answer
# green, which is the drift this file exists to catch.
# BY THE PUBLISHED NAME, WHICHEVER THAT IS. This asserted the literal "/send"
# -- correct while /send was the published spelling and wrong the moment the
# menu started offering /withdraw instead, which is the same drift in the
# other direction. Checked against BOT_COMMANDS rather than against a
# spelling, so the answer and the menu cannot disagree whatever they are
# called next.
_EXIT_POINTS = set(re.findall(r"/([a-z]+)", pg.EXIT_ANSWER))
check("/exit points at the command that does set it, by its PUBLISHED name",
      _EXIT_POINTS and _EXIT_POINTS <= {_c for _c, _d in pg.BOT_COMMANDS}
      and "not settable" not in pg.EXIT_ANSWER.lower())
check("/exit: ...and that command is the one that takes a destination",
      "withdraw" in _EXIT_POINTS)
check("...and exactly one job schema takes a destination, not several",
      [j for j in P.JOBS
       if any("exit" in k or "dest" in k or "addr" in k
              for k in P.JOBS[j]["schema"])] == ["withdraw"])
check("...and no OTHER job gained one, which is what /exit's answer would "
      "stop being true about first",
      not any("dest" in k or "exit" in k or "addr" in k
              for j, sp in P.JOBS.items() if j != "withdraw"
              for k in sp["schema"]))

# THE USAGE FEE IS NAMED ONLY TO SAY IT IS NOT HERE.
#
# "/fee" predates --usage-fee and answers about the BITCOIN network fee and the
# swap's slippage floor. Now that a thing called a usage fee exists, someone
# typing /fee to ask about theirs gets a confident answer about something else,
# and silence about their own reads as "not built".
_fh = Fake()
_fh.say("/fee")
_fee_reply = _fh.text().strip()
# "1.1% usage fee." WAS THE WHOLE ANSWER, and it was ambiguous in the one way
# that costs money to be wrong about. Two different things are called "the
# fee": this service's cut, and what the network charges to carry each
# transaction. A mix is many transactions, so the network's is the LARGER of
# the two -- and the operator reading "1.1% usage fee." concludes that 1.1% is
# what mixing costs, watches a bigger number leave, and reads it as theft.
#
# The four extra words say which fee it is not. They are still inside the
# 40-character ceiling above, still name no machine, tool or file, and the
# equality is kept exact so the paragraph cannot creep back in behind them.
# The full explanation lives on the welcome, which is sent once.
check("/fee names the usage fee, its rate, and which fee it is NOT",
      _fee_reply == f"{pg.USAGE_FEE_LABEL} usage fee. Not the network fee.")
# THE RATE IS THE ONE NUMBER THIS CHANNEL MAY CARRY, and it is a decision
# rather than an oversight: the operator asked for it, having been told what it
# costs (an observed cash-out divided by the rate is the deposit behind it).
# So the test asserts it appears HERE and nowhere else, which is the part that
# is enforceable.
check("...and the rate it prints is the rate GhostSpiral actually charges, "
      "not a copy that has drifted",
      pg.USAGE_FEE_LABEL
      == f"{(load('GhostSpiral').USAGE_FEE_PCT * 100).normalize()}%")
# AND THE CLAIM MUST BE TRUE BY CONSTRUCTION, not by policy: gs_wake_agent's
# argv table decides what can run at all, and GhostSpiral is not in it -- so no
# usage-fee line can reach this channel however the pager behaves.
_agent = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
# /fee's CLAIM ALSO CHANGED. The agent CAN spawn GhostSpiral now, for exactly
# one keyfile-gated job -- so "its output can never reach this chat" is no
# longer true by construction and has to be true by what is SENT instead.
check("/fee's claim holds: the agent spawns the mix only for the spending job",
      _agent.count('_tool("GhostSpiral")') == 1
      and 'if job == "withdraw":' in _agent)
check("...and that job is refused unless this machine's own keyfile allows it",
      'if not key.get("allow_withdraw"):' in _agent)
# AND THE OLD CHECK HERE IS GONE, DELIBERATELY. It asserted the fee RATE never
# reached the chat, on the reasoning that the rate divides an observed cash-out
# back into a deposit size. That was true and worth guarding while the chat
# carried no destination. /withdraw carries one now, by reply, by design -- and
# a transcript holding the destination makes guarding the rate beside it
# theatre. Keeping a check that guards the smaller of two values while the
# larger goes past it is worse than having none: it reads as coverage.
#
# What still matters is that the fee is not SETTABLE from here, because a
# stolen phone changing the rate is a different thing from reading it.
check("/fee is an answer, not a control: no chat message sets a rate",
      not any("usage_fee" in k or "fee_pct" in k
              for sp in P.JOBS.values() for k in sp["schema"]))
check("...and no job drives a tool that could set one",
      "GhostSpiral" not in [t for j, sp in P.JOBS.items()
                            if j not in P.SPENDING_JOBS
                            for t in sp["tools"]])
check("NON-VACUITY -- the agent DOES spawn other tools by that same helper, so "
      "the absence above is an absence from a real table",
      '_tool("receive_watch")' in _agent
      and '_tool("thor_swap_preparer")' in _agent)
# ...and NO OTHER command carries the rate. /fee is the one place it may
# appear, so a rate that turns up in /help or a job reply is a second copy
# nobody asked for.
for _c in ("/help", "/status", "/speed", "/exit"):
    _fr = Fake()
    _fr.say(_c)
    check(f"{_c} does not repeat the fee rate",
          pg.USAGE_FEE_LABEL not in _fr.text() and "0.011" not in _fr.text())
check("NON-VACUITY -- /fee DOES carry it, so the checks above are about the "
      "other commands and not about a rate that is never printed",
      pg.USAGE_FEE_LABEL in _fee_reply)

# ===========================================================================
# 8b. EVERY STRING THIS BOT CAN SEND, NOT JUST THE ONES A TEST HAPPENS TO DRIVE.
# ===========================================================================
#
# The checks above drive commands and read the replies. That covers what they
# drive and nothing else -- and the verbose drafts this suite kept re-catching
# were never in the commands under test, they were in the JOB-RESULT branches
# (refused, failed, expired, undelivered) which need a whole wake to reach.
#
# So this reads the SOURCE instead: every string literal passed to self.send(),
# plus the constants that are sent whole. A word that has no business in a
# transcript is a word the operator can never accidentally publish.
print("\n-- what it is capable of saying, read from the source --")
import ast as _ast

# WORD BOUNDARIES, not substrings. "tor" inside "history" or "storage" would
# fail a future message that is perfectly fine, and a check that cries wolf is
# a check someone deletes.
#
# OP_RETURN is deliberately NOT on this list. It is the one mechanism word the
# operator needs at the moment they send, and leaving it out costs the payment
# rather than costing privacy: without the memo attached the transfer is
# unroutable and the funds do not come back.
_BANNED = ("vault", "thinkpad", "keyfile", "gs_unseal", "thorchain",
           "subpoena", "deliberate", "transcript", "cash-out", "ladder",
           "ghostspiral", "monero", "xmr", "wallet-rpc", "tor")
_BANNED_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in _BANNED) + r")\b", re.I)
_pg_tree = _ast.parse(_SRC)


def _sent_strings(tree):
    """Every literal the bot can put on the wire, with its line."""
    out = []
    for n in _ast.walk(tree):
        if isinstance(n, _ast.Call) and getattr(n.func, "attr", "") == "send":
            for arg in n.args[1:2]:
                for x in _ast.walk(arg):
                    if isinstance(x, _ast.Constant) and isinstance(x.value, str):
                        out.append((n.lineno, x.value))
    for name in ("HELP", "FEE_ANSWER", "SPEED_ANSWER", "EXIT_ANSWER",
                 "BUSY_ANSWER"):
        for n in tree.body:
            if isinstance(n, _ast.Assign) and getattr(
                    n.targets[0], "id", "") == name:
                for x in _ast.walk(n.value):
                    if isinstance(x, _ast.Constant) and isinstance(x.value, str):
                        out.append((n.lineno, x.value))
    return out


# AND THE TEXT THAT LIVES IN ANOTHER FILE. The first version of this scan read
# gs_telegram_pager and stopped there -- which missed PHASE_LINES entirely.
# Those live in gs_wake_proto and the pager sends them verbatim
# (`f"{h}: {proto.PHASE_LINES.get(phase, phase)}"`), and two of them named the
# operator's own machine on the two answers most likely to be asked for when
# something has gone wrong. A scan scoped to one file reads as covering the
# reply vocabulary and covers the part of it that happens to be local.
_all_sent = _sent_strings(_pg_tree)
_all_sent += [(0, v) for v in P.PHASE_LINES.values()]

# AND THE REPLIES THAT ARE BUILT, NOT WRITTEN -- the same lesson as PHASE_LINES
# above, learned a second time and this time closed properly.
#
# _sent_strings walks `self.send(cid, <expr>)` and collects the string
# CONSTANTS inside <expr>. Five of this bot's replies have no constant there at
# all: they are `self._settings_text()`, `welcome_text(self.burn_after)`, and
# the three wizard questions. Every one of them was invisible to this scan, and
# they are between them the LONGEST things the bot says -- /settings and the
# welcome are the top two.
#
# That was not theoretical. The welcome shipped the sentence "Assume this
# transcript can be read by somebody who is not you", and /settings shipped
# "Monero's own, per transaction" -- a banned word each, in the two longest
# replies, past a check whose printed name claims to cover "every string this
# bot can send". A scan that reads as complete and covers the literals is worse
# than one that admits its scope.
_cs = Fake()
_cs.p.burn_after = 0
_COMPOSED = [
    ("welcome_text", pg.welcome_text(0)),
    # BOTH RENDERINGS. The deposit line follows the keyfile's delivery mode --
    # "on the machine" with none set, "arrives HERE" with plain_slip -- and
    # only one of them was ever scanned, so the sentence the phone-only
    # operator actually reads went unchecked for banned words and for the
    # currency ceiling below.
    ("welcome_text_plain", pg.welcome_text(0, {"deposit_in_chat": True})),
    ("_settings_text", pg.Pager._settings_text(_cs.p)),
    ("_amount_question", pg.Pager._amount_question(_cs.p)),
    ("_exit_question", pg.Pager._exit_question(_cs.p)),
    ("_depth_question", pg.Pager._depth_question(_cs.p)),
]
check(f"the scan now also drives the {len(_COMPOSED)} replies that are "
      f"BUILT rather than written, which it used to miss entirely",
      all(len(t) > 40 for _n, t in _COMPOSED))

# AND IT STAYS CLOSED. A sixth composed reply added later would slip past the
# list above exactly the way these five slipped past the walk -- so the table
# is checked against the source instead of trusted. Every `send()` whose text
# argument carries no literal at all must be one this file knows about: either
# a composed reply driven above, one of the module constants already walked, or
# a RUNTIME value (a slip from the vault, a minted address, a memo) which is
# not authored text and cannot be read from source by anyone.
_RUNTIME_SENDS = {"slip", "_msg", "memo"}
_COVERED_SENDS = ({"self." + n + "()" for n, _t in _COMPOSED if n[0] == "_"}
                  | {"welcome_text(self.burn_after, self.key)"}
                  | {"HELP", "FEE_ANSWER", "SPEED_ANSWER", "EXIT_ANSWER",
                     "BUSY_ANSWER"}
                  | _RUNTIME_SENDS)
_uncovered = sorted(
    {_ast.unparse(a) for n in _ast.walk(_pg_tree)
     if isinstance(n, _ast.Call) and getattr(n.func, "attr", "") == "send"
     for a in n.args[1:2]
     if not any(isinstance(x, _ast.Constant) and isinstance(x.value, str)
                for x in _ast.walk(a))} - _COVERED_SENDS)
check(f"...and no OTHER reply is composed out of the scan's reach "
      f"({_uncovered})", _uncovered == [])

# THE CURRENCY IS THE WELCOME'S ONE EXEMPTION, and it is bounded rather than
# waved through. A welcome that will not say what the service deals in is not a
# welcome; every other reply still may not say it, and the welcome may not turn
# it into a running commentary. Two mentions: what this is, and which of the
# two ways in applies to the reader.
_CURRENCY_RE = re.compile(r"\b(monero|xmr)\b", re.I)
_wc = len(_CURRENCY_RE.findall(pg.WELCOME))
check(f"the welcome names the currency, because a service that will not say "
      f"what it deals in cannot onboard anybody ({_wc} mentions)", _wc >= 1)
check("...and no more than twice, so it stays a naming and not a description",
      _wc <= 2)
# THE EXEMPTION IS COUNTED ACROSS EVERY SURFACE IT COVERS, not per surface.
# Scrubbing the currency out before the banned-word scan is what lets the
# welcome and the button labels name it at all; without a total, that scrub
# is an open door and each new exempt surface widens it by however much it
# likes. The cap is checked after the labels are collected, below.
# Line -1 marks "composed, not a literal": the ceiling below is per
# surface and reads that marker to tell the two groups apart.
# THE WITHDRAW QUESTION GOES IN SCRUBBED, like the welcome, because it is the
# one place the reader has to be told WHICH KIND of address to paste -- "Send
# a Monero address" plus an example. Its mention is counted in the ceiling
# above rather than exempted quietly.
_all_sent += [(-1, t) for n, t in _COMPOSED
              if n not in ("welcome_text", "welcome_text_plain",
                           "_exit_question")]
_all_sent += [(-1, _CURRENCY_RE.sub("", t)) for n, t in _COMPOSED
              if n == "_exit_question"]
# The two welcomes go in with the currency names scrubbed, like the default
# one below, because "Monero mixing, from your phone" is the headline and the
# exemption for it is counted rather than hidden.
_all_sent += [(-1, _CURRENCY_RE.sub("", t)) for n, t in _COMPOSED
              if n == "welcome_text_plain"]
_all_sent += [(-1, _CURRENCY_RE.sub("", pg.WELCOME))]

# AND THE BUTTON LABELS, which were the third surface out of reach.
#
# _sent_strings reads `send(cid, <text>)` and stops at the text. Every label on
# every inline keyboard is a string that lands in the chat, sits under the
# message permanently, and was never looked at -- so "⬇ Monero address", the
# label a newcomer could least place, was also a currency name nothing checked.
_LABELS = [l for _t in (pg.MENU_BUTTONS,) for _row in _t for l, _d in _row]
_LABELS += [l for _row in pg.Pager._depth_buttons(
    types.SimpleNamespace()) for l, _d in _row]
# BOTH SHAPES, because _handle_buttons returns a different keyboard for a
# label nothing can watch: an /address handle gets the menu instead of two
# buttons that would each spend a wake to be refused.
_LABELS += [l for _row in pg.Pager._handle_buttons(
    types.SimpleNamespace(UNWATCHABLE_JOBS=pg.Pager.UNWATCHABLE_JOBS),
    "A3F1", "receive_and_quote") for l, _d in _row]
_LABELS += [l for _row in pg.Pager._handle_buttons(
    types.SimpleNamespace(UNWATCHABLE_JOBS=("some_future_job",)),
    "A3F1", "some_future_job") for l, _d in _row]
# ...AND THE STATUS ANSWER'S KEYBOARD, which is the fourth table and the one
# an operator sees most, because waiting is what this tool mostly does. Every
# phase, including one a newer vault might invent: the fallback is a real
# keyboard, so it is a real surface.
#
# DE-DUPLICATED against what is already here. _phase_buttons composes the
# other three rather than writing labels of its own -- which is the point of
# it -- so appending its output raw would scan the same string twice and count
# the menu's one currency mention twice against the ceiling below.
_PHZ = types.SimpleNamespace(UNWATCHABLE_JOBS=pg.Pager.UNWATCHABLE_JOBS)
_PHZ._handle_buttons = pg.Pager._handle_buttons.__get__(_PHZ)
_PHZ._label = pg.Pager._label.__get__(_PHZ)
_PHZ.key = dict(PAIR_KEY)
_PHASE_LABELS = [
    l for _w in ("not_yet", "arriving", "landed", "short", "stuck",
                 "more_left", "a-phase-from-a-newer-vault")
    for _row in (pg.Pager._phase_buttons(_PHZ, _w, "A3F1", "swap_status")
                 or [])
    for l, _d in _row]
check("the scan reaches the status answer's keyboard, the fourth table and "
      "the one an operator sees most often",
      len(_PHASE_LABELS) >= 6)
_LABELS += [l for l in dict.fromkeys(_PHASE_LABELS) if l not in _LABELS]
check(f"the scan reaches the button labels too ({len(_LABELS)} of them), "
      f"which land in the chat and stay under the message",
      len(_LABELS) >= 8)
_all_sent += [(-1, _CURRENCY_RE.sub("", l)) for l in _LABELS]
#: The deposit instructions name the currency too ("Expected out: ~1.2 XMR"),
#: and the ceiling below is a TOTAL across every surface the scrub covers --
#: so this has to be in it before it is checked, or the scrub would let a
#: whole extra surface name the currency for free.
_PLAIN_SAMPLE = {"b": "0.05000000", "d": "bc1qexample", "x": "1.23",
                 "h": "A3F1", "m": "=:XMR.XMR:4example:0/1/0"}
_plain_authored = [
    _l for _l in P.plain_lines(_PLAIN_SAMPLE, label="A3F1-9C2B7E")
    if _l and _l != _PLAIN_SAMPLE["m"]]
#: AND THE WITHDRAW QUESTION, which is the one place the reader has to know
#: WHICH KIND of address to paste. "Send a Monero address" plus an example is
#: the fastest this can be; the alternative is three sentences of reasoning
#: and no example, which is what it was.
_EXIT_Q = dict(_COMPOSED)["_exit_question"]
_exempt_total = (_wc
                 + sum(len(_CURRENCY_RE.findall(l)) for l in _LABELS)
                 + sum(len(_CURRENCY_RE.findall(l)) for l in _plain_authored)
                 + len(_CURRENCY_RE.findall(_EXIT_Q)))
# THE EXEMPTION SHRANK WHEN /address WENT. "⬇ Monero in" was the second
# mention; with the command gone the welcome's headline is the only one left,
# which is the smallest the exemption can be while the service still says what
# it deals in.
check(f"the currency exemption stays bounded across every surface it covers "
      f"({_exempt_total} mentions across the welcome, the button labels, the "
      f"deposit instructions and the withdraw question)",
      _exempt_total <= 4)
# NON-VACUITY on the scrub: it is what lets those surfaces through, so it has
# to actually be doing something, or the cap above is guarding nothing.
check("NON-VACUITY -- the surfaces the scrub covers really do name it",
      _exempt_total >= 1)
# ---- AND THE DEPOSIT INSTRUCTIONS, WHICH LIVE IN ANOTHER FILE -----------
#
# THE DEFECT THIS FOUND. gs_wake_proto.plain_lines builds the message the chat
# sends with --deposit-in-chat on, and the pager forwards it verbatim. It said
#
#     "A payment without it is one ThorChain cannot route."
#
# THORCHAIN IS ON THE BANNED LIST above -- the same list that keeps "vault",
# "keyfile" and "ghostspiral" out of every reply -- and it reached the chat
# anyway, because _sent_strings reads literals in gs_telegram_pager and these
# are in gs_wake_proto. That is the identical defect already recorded for
# PHASE_LINES, on the one surface that carries an address and an amount.
#
# THE AUTHORED TEXT, NOT THE VALUES. The address, the amount and the memo are
# runtime values off a quote -- nobody wrote them and no scan can read them
# from source. What is authored is the labels and the OP_RETURN sentence, and
# that is what a banned word can hide in.
check(f"the scan reaches the deposit instructions too, which live in "
      f"gs_wake_proto and are sent verbatim ({len(_plain_authored)} lines)",
      len(_plain_authored) >= 5)
_all_sent += [(-1, _CURRENCY_RE.sub("", _l)) for _l in _plain_authored]
# NON-VACUITY: the line the defect was in really is among them, so this is
# scanning the thing it was written for.
# THE MEMO INSTRUCTION IS GONE ENTIRELY, along with the memo. What is left is
# the one thing a reader can get wrong and lose the payment for.
check("...including the line that replaced the OP_RETURN instruction",
      any("phone wallet" in _l for _l in _plain_authored))
check("...and nothing there names the service that routes the swap, or the "
      "field it routes on",
      not any(re.search(r"thorchain|OP_RETURN", _l, re.I)
              for _l in _plain_authored))
check("...and the memo itself is not among the lines at all",
      not any("XMR.XMR" in _l or _l.startswith("=:")
              for _l in _plain_authored))
# BOTH RENDERINGS. plain_lines takes a label for the chat and prints the bare
# handle without one, for the machine's own terminal -- two outputs, and only
# one of them was being looked at.
_all_sent += [(-1, _CURRENCY_RE.sub("", _l))
              for _l in P.plain_lines(_PLAIN_SAMPLE)
              if _l and _l != _PLAIN_SAMPLE["m"]
              and _l not in _plain_authored]

# EVERY BUTTON TABLE, not the one the menu happens to use. A `buttons=` that
# named a fifth table would be a keyboard nothing above reads.
#
# THE CALLEE, NOT THE WHOLE EXPRESSION. This compared unparsed source text --
# "self._handle_buttons(h, job)" -- against a set of literal strings, so
# threading one more argument through a builder failed a check about which
# TABLES exist. What has to be true is that a keyboard comes from a known
# builder; how many arguments that builder takes is not this check's business,
# and pinning it here means every signature change reads as a leak.
def _btn_source(node):
    if isinstance(node, _ast.Call):
        return getattr(node.func, "attr", None) or getattr(
            node.func, "id", "<call>")
    if isinstance(node, _ast.Name):
        return node.id
    if isinstance(node, (_ast.List, _ast.Tuple)):
        return "<literal>"
    if isinstance(node, _ast.Constant) and node.value is None:
        return "<none>"
    return _ast.unparse(node)


_BTN_TABLES = {"MENU_BUTTONS", "_depth_buttons", "_handle_buttons",
               "_phase_buttons", "<literal>"}
_btn_seen = {_btn_source(_kw.value) for _n in _ast.walk(_pg_tree)
             if isinstance(_n, _ast.Call)
             and getattr(_n.func, "attr", "") == "send"
             for _kw in _n.keywords if _kw.arg == "buttons"}
check(f"...and every keyboard this bot attaches comes from one of them "
      f"({sorted(_btn_seen - _BTN_TABLES)})",
      _btn_seen <= _BTN_TABLES)
# NON-VACUITY: the scan really did find the builders, so the subset test above
# is not passing on an empty set.
check(f"...and it found them all ({sorted(_btn_seen)})",
      {"MENU_BUTTONS", "_handle_buttons", "_phase_buttons"} <= _btn_seen)
check("control: the scan reaches the phase lines too, which live in another "
      "file and are sent verbatim",
      any(t in P.PHASE_LINES.values() for _l, t in _all_sent))
check(f"control: the scan found the bot's reply vocabulary "
      f"({len(_all_sent)} literals), so the checks below read something",
      len(_all_sent) >= 30)
_hits = [(ln, _BANNED_RE.search(t).group(0), t[:60])
         for ln, t in _all_sent if _BANNED_RE.search(t)]
check(f"no reply this bot can send names a machine, a tool or the operation "
      f"({_hits})", _hits == [])
# ---- AND THE WORDS THE WELCOME IS TESTED FOR NOT CONTAINING -------------
#
# test_telegram_pager sweeps the welcome for ~25 words that describe the SETUP
# rather than the service -- "doorbell", "switched off", "wakes", "another
# machine" -- on the reasoning that together they say: there is a second
# machine, it is normally powered down, and this chat is what switches it on.
#
# That sweep was written for the welcome, because the welcome is where the
# words were newly typed. It was never pointed at the replies that predate it,
# and thirteen of them carried "wake" or "woken": "no: a wake is already
# running", "cancelled. Nothing was woken.", "This wakes the machine.", and
# /settings' own "wake budget" line. An operator's transcript said the thing
# the welcome is forbidden from saying, on the messages they see most.
#
# The information survives the edit in every case, because none of those
# replies was ABOUT waking: "nothing was started" is what the operator needed
# to know, and "something is already running" is the one that is actually
# actionable.
_ARCH_REPLY = ("wake", "wakes", "woken", "waking", "doorbell", "switched off",
               "powered down", "air gap", "air-gapped", "second machine",
               "another machine")
_ARCH_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in _ARCH_REPLY) + r")\b", re.I)
_arch_hits = [(ln, _ARCH_RE.search(t).group(0), t[:60])
              for ln, t in _all_sent if _ARCH_RE.search(t)]
check(f"no reply describes the arrangement it runs on, which is the rule the "
      f"welcome is already held to ({_arch_hits})", _arch_hits == [])
# NON-VACUITY, both ways. The list catches what it is for...
check("NON-VACUITY -- the arrangement sweep fires on the reply it was written "
      "for", bool(_ARCH_RE.search("no: a wake is already running")))
# ...and does not fire on the vocabulary these replies legitimately use. "the
# machine" stays: /settings has to say which settings need physical access, and
# the operator knows which machine is theirs. It is the OFF-ness and the
# switching-on that are the disclosure, not the noun.
check("NON-VACUITY -- ...and not on 'the machine', which the replies may say",
      not _ARCH_RE.search("Set on the machine, with physical access"))

# NON-VACUITY: the scanner really does catch these words -- proven on a string
# built here, not hoped for.
_synth = _ast.parse('def f():\n    self.send(1, "read it on the vault")\n')
check("NON-VACUITY -- the scan flags a banned word when one is present",
      any(_BANNED_RE.search(t) for _l, t in _sent_strings(_synth)))
# NON-VACUITY on the boundaries: an innocent word that merely CONTAINS a
# banned one must pass, or the check starts failing on messages that are fine.
check("NON-VACUITY -- ...and does not fire on 'history' or 'storage', which "
      "merely contain one",
      not _BANNED_RE.search("check your history and storage"))
# A CEILING, because the drafts did not add banned words, they added
# paragraphs. The longest legitimate reply is /help.
#
# THE CEILING IS PER SURFACE, not one number over everything, and that split is
# the honest version rather than a loosening. Two of these replies are whole
# screens by design and always were -- /settings is a table of what a run does,
# the welcome is the one-time introduction -- so a single 400-char rule over
# the lot either fails on them forever or gets raised to their size and stops
# constraining the 90 literals it was written for. Each surface is pinned near
# what it is now, so a paragraph added to ANY of them fails here.
_longest = max((len(t), ln, t[:50]) for ln, t in _all_sent if ln != -1)
check(f"no single reply literal runs past 400 characters "
      f"(longest {_longest[0]} at line {_longest[1]})",
      _longest[0] <= 400)
for _cname, _climit in (("welcome_text", 1400), ("_settings_text", 1200),
                        ("_amount_question", 400), ("_exit_question", 600),
                        ("_depth_question", 400)):
    _ctext = dict(_COMPOSED)[_cname]
    check(f"...and the composed {_cname} stays under {_climit} "
          f"({len(_ctext)} chars)", len(_ctext) <= _climit)
# AND THE TWO LONG ONES STILL FIT A PHONE SCREEN, which is the constraint the
# character count is standing in for. A 1400-character wall of text is read by
# nobody, and a welcome nobody reads is a welcome that has not told them the
# usage fee.
for _cname, _lines in (("welcome_text", 26), ("_settings_text", 30)):
    _n = dict(_COMPOSED)[_cname].count("\n") + 1
    check(f"...and {_cname} stays under {_lines} lines ({_n})", _n <= _lines)

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
