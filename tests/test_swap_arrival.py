#!/usr/bin/env python3
"""THE ARRIVAL WAIT: has ALL of the swapped XMR landed, or just some of it?

The defect these tests exist for (G6). Stage 4's wait was:

    while unlocked_bal <= DUST_XMR and waited < XMR_ARRIVAL_TIMEOUT:

-- the right test for exactly one swap, and wrong for every other case. With
--split N the operator makes N separate BTC deposits, ThorChain settles them
independently, and their XMR lands on ENTRY minutes to hours apart. That gate
opens on chunk 1 of N.

Everything downstream then sizes itself from that fraction: the entry veil
sweeps it, the distribution spreads it, and chunks 2..N arrive on an ENTRY the
run has already finished with. Nothing mixes them. The exit finds them sitting
there and sweeps them out -- one transaction each, from the address the
ThorChain memo names IN PUBLIC, straight to --exit-to. The majority of the
money took a raw swap -> destination link, in the pipeline's final step,
whenever --split was used.

So: the gate is the SUMMED target, a shortfall stops the run rather than
being inherited silently, and a chunk that lands late is not withdrawn by the
exit (that half is in test_exit_withdraw.py).

Every check drives the real functions with a synthetic clock.

On "confirmed to fail against the pre-fix build": the honest version of that
claim is below, not in this docstring. The pre-fix source has no
wait_for_swap_arrival at all, so running this file against it raises
AttributeError on import -- red, but a demonstration of nothing. The OLD GATE
section reproduces the old loop condition verbatim and drives it down the same
timeline the fix is tested on, so the defect is shown rather than asserted.
"""
import importlib.machinery, importlib.util, io, os, sys, contextlib, types
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

_ld = importlib.machinery.SourceFileLoader("GhostSpiral",
                                           os.path.join(REPO, "GhostSpiral"))
ghost = importlib.util.module_from_spec(
    importlib.util.spec_from_loader(_ld.name, _ld))
_ld.exec_module(ghost)

PASS = 0
FAIL = 0
FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  ", name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL:", name)


D = Decimal


def quote(expected):
    """One deposit instruction, as stage2_get_swap_quotes returns it."""
    return {"chunk": 0, "btc_amount": "0.1", "deposit_address": "bc1q",
            "memo": "=:XMR.XMR:4...", "expected_xmr": str(expected)}


class Timeline:
    """A synthetic clock plus a scripted balance history.

    `steps` is [(total, unlocked), ...] -- one entry consumed per poll. The
    last entry repeats forever, which is what a swap that never completes
    actually looks like: the balance simply stops changing.
    """

    def __init__(self, steps, poll=30):
        self.steps = [(D(str(t)), D(str(u))) for t, u in steps]
        self.poll = poll
        self.now = 0.0
        self.polls = 0

    def balance(self):
        i = min(self.polls, len(self.steps) - 1)
        self.polls += 1
        return self.steps[i]

    def sleep(self, _s):
        self.now += self.poll

    def clock(self):
        return self.now


def run(steps, floor_, chunks=3, stall_s=7200, timeout_s=86400, poll=30):
    tl = Timeline(steps, poll)
    with contextlib.redirect_stdout(io.StringIO()):
        res = ghost.wait_for_swap_arrival(
            tl.balance, D(str(floor_)), chunks, stall_s=stall_s,
            timeout_s=timeout_s, poll_s=poll,
            sleep_fn=tl.sleep, clock=tl.clock, echo=lambda *a, **k: None)
    return res, tl


# ---- the target: every chunk, not the first one -------------------------
_tot, _bad, _amts = ghost.swap_expected_total([quote("1.0")] * 3)
check("target: sums the quoted output of EVERY chunk, not just the first",
      _tot == D("3.0") and _bad == 0)
check("target: no quotes at all is no target (manual mode)",
      ghost.swap_expected_total([]) == (D(0), 0, []))

# An unreadable quote deflates the target, which would let the wait finish
# while a third of the money is still in flight. It must be COUNTED so the
# caller can say so -- receive_watch.expected_total learned this the same way.
_tot, _bad, _amts = ghost.swap_expected_total([quote("3.0"), quote("junk"), quote("0")])
check("target: an unreadable quote contributes nothing...", _tot == D("3.0"))
check("target: ...and is counted, so the caller can say the target is partial",
      _bad == 2)
check("target: a missing expected_xmr key counts as unreadable",
      ghost.swap_expected_total([{"chunk": 0}]) == (D(0), 1, []))

# The gate sits a tolerance below the quotes: swaps never pay to the digit.
check("gate: the floor is the summed target less the tolerance",
      ghost.accept_floor(D("3.0"), D("0.10")) == D("2.7"))


# ---- THE OLD GATE, on the timeline the fix is tested against ------------
#
# Reproduced verbatim from the pre-fix stage 4, so this file demonstrates the
# defect instead of asserting it happened:
#
#     while unlocked_bal <= DUST_XMR and waited < XMR_ARRIVAL_TIMEOUT:
#
# Same 3-chunk timeline as the checks below. The old condition is false the
# moment chunk 1 unlocks, so the loop exits with 1 XMR of a 3 XMR swap and
# stage 4 plans against a third of the money -- the other two chunks land on
# ENTRY afterwards and are never mixed by anything.
_SPLIT_TIMELINE = [(0, 0), (1, 0), (1, 1), (1, 1)]


def _old_gate(steps):
    """The pre-fix loop. Returns what it would have handed stage 4."""
    total_bal = unlocked_bal = D(0)
    waited = 0
    for total_bal, unlocked_bal in steps:
        total_bal, unlocked_bal = D(str(total_bal)), D(str(unlocked_bal))
        if not (unlocked_bal <= ghost.DUST_XMR
                and waited < ghost.XMR_ARRIVAL_TIMEOUT):
            break
        waited += ghost.XMR_ARRIVAL_POLL
    return unlocked_bal


check("OLD GATE: the pre-fix condition opens on chunk 1 of 3 (the defect)",
      _old_gate(_SPLIT_TIMELINE) == D("1"))
check("OLD GATE: ...i.e. it would have planned against a third of the swap",
      _old_gate(_SPLIT_TIMELINE) < ghost.accept_floor(D("3.0"), D("0.10")))


# ---- THE FIX: the wait must not return on the first chunk ---------------
#
# 3 chunks of 1 XMR quoted, floor 2.7. Chunk 1 lands and unlocks; nothing
# else ever comes.
_res, _tl = run(_SPLIT_TIMELINE, "2.7", stall_s=300)
check("SPLIT: one chunk of three does NOT satisfy the wait",
      _res["state"] != "funded")
check("SPLIT: ...it is reported as stalled, with what actually arrived",
      _res["state"] == "stalled" and _res["unlocked"] == D("1"))

# ...and the same timeline WITH the rest arriving completes normally.
_res, _tl = run([(0, 0), (1, 0), (1, 1), (2, 1), (3, 1), (3, 3)], "2.7",
                stall_s=300)
check("SPLIT: the wait completes once ALL the chunks have landed and unlocked",
      _res["state"] == "funded" and _res["unlocked"] == D("3"))

# A swap paying slightly under its quote is normal, not a shortfall.
_res, _ = run([(0, 0), (2.8, 2.8)], "2.7", stall_s=300)
check("SPLIT: a delivery inside the slippage tolerance counts as complete",
      _res["state"] == "funded")
_res, _ = run([(0, 0), (2.6, 2.6)], "2.7", stall_s=300)
check("SPLIT: ...and one below it does not", _res["state"] == "stalled")

# Locked-but-arrived is not arrived: sizing a plan off a balance that cannot
# be spent yet is how a run builds transactions against money it has not got.
_res, _ = run([(0, 0), (3, 0), (3, 0)], "2.7", stall_s=300)
check("SPLIT: money that has arrived but not UNLOCKED is not 'funded'",
      _res["state"] != "funded")


# ---- THE TOLERANCE MUST NOT BE WORTH A WHOLE CHUNK ----------------------
#
# The first version of this fix took the slippage tolerance off the SUMMED
# target and opened at `unlocked >= total * (1 - tolerance)`. The tolerance is
# meant to absorb the slippage on ONE swap; charged against the whole pot it
# absorbs an entire chunk the moment a chunk is worth less than it:
#
#     --split 12, 1 XMR each, tolerance 0.10 -> floor 10.8
#     11 chunks arrive IN FULL = 11.0 >= 10.8 -> "the swap has arrived"
#
# So at --split 10 or more, on DEFAULT flags and with no operator mistake, the
# gate opened with a whole chunk still in flight -- G6 rebuilt inside the fix
# for G6. Found by driving the shipped loop, not by reading it.
_SPLITS = (3, 5, 10, 12, 20, 50)


def _floor_for(n, amounts=None, chunks=None, tol="0.10"):
    amts = amounts if amounts is not None else [D(1)] * n
    total = sum(amts) if amts else D(n)
    return ghost.swap_arrival_floor(total, D(tol), amts,
                                    chunks if chunks is not None else n)[0]


for _n in _SPLITS:
    _flr = _floor_for(_n)                            # N chunks of 1 XMR
    check(f"CHUNK GATE: at --split {_n}, {_n - 1} full chunks do NOT satisfy "
          f"the gate", D(_n - 1) < _flr)
check("CHUNK GATE: ...while the full delivery still does",
      all(D(_n) >= _floor_for(_n) for _n in _SPLITS))

# Non-vacuity: the UNCAPPED tolerance really does admit a missing chunk, or
# every check above would pass against a gate that never had the defect.
check("control: the UNCAPPED tolerance admits a whole missing chunk at N=12",
      D(11) >= ghost.accept_floor(D(12), D("0.10")))

check("CHUNK GATE: a single chunk leaves the plain tolerance floor",
      ghost.swap_arrival_floor(D(1), D("0.10"), [D(1)], 1)
      == (ghost.accept_floor(D(1), D("0.10")), False))
check("CHUNK GATE: a tolerance already tighter than the guard is left alone",
      ghost.swap_arrival_floor(D(12), D("0.01"), [D(1)] * 12, 12)
      == (ghost.accept_floor(D(12), D("0.01")), False))

# UNEQUAL CHUNKS. The count-based cap assumed every chunk was worth 1/N of the
# pot; --joinmarket sets btc_chunks = jm_utxos, the tumbler's own outputs,
# which are nothing of the kind. Reproduced: 0.50/0.30/0.15/0.05 under a 10%
# tolerance gave floor 0.90, so the 0.05 chunk could be absent and 0.95 opened
# the gate.
_UNEQ = [D("0.50"), D("0.30"), D("0.15"), D("0.05")]
_uf, _ut = ghost.swap_arrival_floor(sum(_UNEQ), D("0.10"), _UNEQ, len(_UNEQ))
check("UNEQUAL: the gate is keyed on the SMALLEST chunk, not the count", _ut)
for _m in _UNEQ:
    check(f"UNEQUAL: a missing {_m} chunk does NOT satisfy the gate",
          sum(_UNEQ) - _m < _uf)
check("UNEQUAL: ...and the complete delivery still does", sum(_UNEQ) >= _uf)
check("control: the count-keyed floor DID admit the smallest chunk",
      sum(_UNEQ) - min(_UNEQ) >= ghost.accept_floor(sum(_UNEQ), D("0.10")))

# MANUAL MODE. swap_deposits is empty, so n_chunks falls back to --split --
# which is 1 by default and does nothing else in manual mode. Twelve real
# swaps with --expect-total-xmr 12 gave floor 10.8 and opened at 11.0.
_mf, _mt = ghost.swap_arrival_floor(D(12), D("0.10"), [], 1)
check("MANUAL: with no chunk count the gate cannot detect a missing swap",
      D(11) >= _mf and not _mt)
_mf12, _mt12 = ghost.swap_arrival_floor(D(12), D("0.10"), [], 12)
check("MANUAL: ...and passing --split 12 restores the guarantee",
      D(11) < _mf12 and _mt12)
check("MANUAL: ...while a full delivery still passes", D(12) >= _mf12)

# ...and through the REAL loop, on the timeline that used to pass it.
_f12 = _floor_for(12)
_res, _ = run([(0, 0)] + [(i, i) for i in range(1, 12)] + [(11, 11)] * 30,
              _f12, chunks=12, stall_s=300)
check("CHUNK GATE: the real loop HOLDS at 11 of 12 chunks",
      _res["state"] != "funded" and _res["unlocked"] == D("11"))
_res, _ = run([(0, 0)] + [(i, i) for i in range(1, 13)] + [(12, 12)] * 5,
              _f12, chunks=12, stall_s=300)
check("CHUNK GATE: ...and completes when the twelfth lands",
      _res["state"] == "funded")


# ---- Infinity and NaN, straight off the quote JSON ----------------------
#
# expected_xmr comes off the network. Decimal("NaN") > 0 RAISES rather than
# returning False, so a NaN quote escaped swap_expected_total instead of being
# counted unreadable -- the one thing its docstring promises. Infinity converts
# cleanly, compares greater than zero and becomes a target no balance can ever
# reach: the run waits out its whole timeout and blames the swap.
check("quotes: a NaN expected_xmr is counted UNREADABLE, not raised",
      ghost.swap_expected_total([quote("NaN"), quote("1.0")])
      == (D("1.0"), 1, [D("1.0")]))
check("quotes: an Infinity expected_xmr is counted UNREADABLE, not summed",
      ghost.swap_expected_total([quote("Infinity"), quote("1.0")])
      == (D("1.0"), 1, [D("1.0")]))
check("quotes: -Infinity too",
      ghost.swap_expected_total([quote("-Infinity")]) == (D(0), 1, []))


# ---- a transient balance DROP must not raise the bar --------------------
#
# `marked` only ever moved up, so one low reading -- a wallet mid-rescan, a
# reorg, an RPC answering from a stale cache -- permanently raised what counted
# as the next arrival, and the run stalled out with money still landing.
# receive_watch's loop has carried the re-anchor branch for the same reason.
_res, _ = run([(0, 0), (5, 5), (0, 0), (5, 5), (8, 8), (11, 11), (12, 12)],
              _f12, chunks=12, stall_s=300)
check("DROP: a transient drop to zero does not strand the wait",
      _res["state"] == "funded")


# ---- the two clocks -----------------------------------------------------
#
# The stall clock restarts on every real arrival, which is what lets N chunks
# land over an afternoon without anyone predicting N x (settle time) up front.
_slow = [(0, 0)] * 5 + [(1, 1)] * 5 + [(2, 2)] * 5 + [(3, 3)]
_res, _tl = run(_slow, "2.7", stall_s=180, poll=30)
check("clocks: chunks arriving slowly keep the wait alive (the stall clock "
      "restarts on each arrival)", _res["state"] == "funded")

# ...but a swap that is never sent at all fails in ONE stall window rather
# than holding the run for the whole absolute cap.
_res, _tl = run([(0, 0)], "2.7", stall_s=180, timeout_s=86400, poll=30)
check("clocks: nothing arriving at all stalls out in one stall window",
      _res["state"] == "stalled" and _tl.now < 86400)

# The absolute cap is the backstop when arrivals keep trickling but never
# reach the target.
_forever = [(D("0.001") * i, D("0.001") * i) for i in range(1, 400)]
_res, _tl = run(_forever, "2.7", stall_s=3600, timeout_s=600, poll=30)
check("clocks: the absolute cap bounds a wait that never reaches the target",
      _res["state"] == "timeout")


# ---- the drip ----------------------------------------------------------
#
# ENTRY is not a secret: the swap memo names it in plaintext and the sender
# puts that memo in a Bitcoin OP_RETURN. Anyone reading the BTC chain can pay
# it. Without a floor on what counts as an arrival, a piconero every poll
# would hold the stall clock open forever and the run would sit at stage 4
# believing more of its own money was on the way.
_drip = [(D("1") + D("0.0000000001") * i, D("1")) for i in range(400)]
_res, _tl = run(_drip, "2.7", stall_s=300, timeout_s=86400, poll=30)
check("drip: sub-threshold dust does NOT hold the stall clock open",
      _res["state"] == "stalled")

# ...while genuine increments BELOW the step still add up. The step for a 2.7
# floor is max(dust, 2.7 * 0.001) = 0.0027, so the increments here must be
# smaller than that or the check cannot distinguish "compares against the last
# MARKED total" (correct) from "compares against the previous tick" (the hole
# `marked` exists to close). An earlier version of this check used 0.05 -- 18x
# the step -- so it passed either way and proved nothing.
_STEP = ghost.swap_arrival_step(D("2.7"))
_CREEP = D("0.001")
check("drip: (the creep increment really is below the arrival step)",
      _CREEP < _STEP)
_creep = [(_CREEP * i, _CREEP * i) for i in range(1, 2800)]
_res, _ = run(_creep, "2.7", stall_s=300, timeout_s=10 ** 7, poll=30)
check("drip: ...but sub-step increments that ACCUMULATE past it do count",
      _res["state"] == "funded")

check("drip: the arrival step scales with the target (0.1%)",
      ghost.swap_arrival_step(D("1000")) == D("1.000"))
check("drip: ...and never falls below the dust threshold",
      ghost.swap_arrival_step(D("0.001")) == ghost.DUST_XMR)
check("drip: no target -> the dust threshold",
      ghost.swap_arrival_step(D(0)) == ghost.DUST_XMR)


# ---- no target at all (manual mode) -------------------------------------
#
# With no quotes there is no number to compare against, so the old dust gate
# is all that is available. It still has to WORK -- the caller is the one that
# warns the operator this cannot tell chunk 1 from chunk N.
_res, _ = run([(0, 0), (1, 1)], "0", chunks=1, stall_s=300)
check("manual: with no target, any balance above dust is the arrival",
      _res["state"] == "funded" and _res["unlocked"] == D("1"))
_res, _ = run([(0, 0), (D("0.00001"), D("0.00001"))], "0", chunks=1,
              stall_s=300)
check("manual: ...but dust alone is not", _res["state"] != "funded")


# ---- interruption and RPC hiccups ---------------------------------------
_saved = ghost.shutdown_requested
try:
    ghost.shutdown_requested = lambda: True
    _res, _ = run([(0, 0)], "2.7", stall_s=300)
finally:
    ghost.shutdown_requested = _saved
check("shutdown: a requested shutdown ends the wait as 'interrupted', not "
      "'funded'", _res["state"] == "interrupted")


class Flaky:
    """A wallet that refuses a couple of polls mid-wait. Normal across hours."""

    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        if self.n in (2, 3):
            raise RuntimeError("wallet is busy")
        return (D("3"), D("3")) if self.n > 3 else (D(0), D(0))


_flaky = Flaky()
_tl = Timeline([(0, 0)], 30)
_saved_log = ghost.integrity_log
try:
    ghost.integrity_log = lambda *a, **k: None
    with contextlib.redirect_stdout(io.StringIO()):
        _res = ghost.wait_for_swap_arrival(
            _flaky, D("2.7"), 3, stall_s=3600, timeout_s=86400, poll_s=30,
            sleep_fn=_tl.sleep, clock=_tl.clock, echo=lambda *a, **k: None)
finally:
    ghost.integrity_log = _saved_log
check("rpc: a transient wallet-rpc failure does not abandon the wait",
      _res["state"] == "funded")


# ---- the flags that size the gate ---------------------------------------
import types  # noqa: E402

def _resolve(**kw):
    ns = types.SimpleNamespace(swap_tolerance=ghost.SWAP_TOLERANCE_DEFAULT,
                               expect_total_xmr=None,
                               accept_partial_swap=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.resolve_swap_arrival(ns)
    except SystemExit:
        return "exit"
    return "ok"


check("flags: the default tolerance is accepted", _resolve() == "ok")
check("flags: tolerance 0 (exact quote) is accepted",
      _resolve(swap_tolerance=D(0)) == "ok")
# A tolerance of 1 or more computes a NEGATIVE floor, which no balance can
# fail to clear -- the gate would open on the first piconero and the run would
# be silently back to the defect this path exists to fix.
check("flags: a tolerance of 1 is refused (it would disable the gate)",
      _resolve(swap_tolerance=D(1)) == "exit")
check("flags: a tolerance above 1 is refused",
      _resolve(swap_tolerance=D("1.5")) == "exit")
check("flags: a negative tolerance is refused",
      _resolve(swap_tolerance=D("-0.1")) == "exit")
check("flags: a non-positive --expect-total-xmr is refused (it is no target)",
      _resolve(expect_total_xmr=D(0)) == "exit"
      and _resolve(expect_total_xmr=D("-1")) == "exit")
check("flags: a real --expect-total-xmr is accepted",
      _resolve(expect_total_xmr=D("3.0")) == "ok")

# The bounds are checked UP FRONT, next to the other syntactic validation --
# not at stage 4, which is after the accounts are made, the quotes are fetched
# and the operator has already sent BTC.
from srcutil import code_only                                    # noqa: E402
_code = code_only(os.path.join(REPO, "GhostSpiral"))
_main_at = _code.index("def main(")
_resolve_at = _code.index("resolve_swap_arrival(args)", _main_at)
_stage4_at = _code.index("stage4_await_swap(", _resolve_at)
check("flags: the bounds check runs before the wait it sizes",
      _resolve_at < _stage4_at)
# ...and the wait is reached from main() at all. The block was extracted to a
# module-level helper to keep main() under the decomposition limit, which is
# exactly the kind of move that can leave a well-tested function with no
# caller.
check("wiring: main() actually calls the arrival wait",
      "stage4_await_swap(" in _code[_main_at:])
check("wiring: ...and the helper is the only thing driving the wait loop",
      callable(getattr(ghost, "stage4_await_swap", None)))


# ---- stage4_await_swap: the orchestration, EXECUTED ---------------------
#
# Everything above drives the pure functions. That is not enough, and a
# mutation sweep proved it: stage4_await_swap -- which contains this whole
# path's headline guarantee, "a shortfall EXITS rather than being inherited
# silently" -- was reached by nothing. Deleting the sys.exit outright, or
# skipping the wait altogether, left this file at 36 passed / 0 failed. The
# checks that mentioned it searched source text and asked `callable(...)`,
# which is the "214 warning/abort lines no test executes" hole in miniature.
#
# So: call it. Only xmr_balance and the clock are faked.
print()


def drive_stage4(steps, deposits=None, receive_mode=False, expect=None,
                 tolerance=None, accept_partial=False, split=1,
                 unlocked_now=D(0), total_now=D(0)):
    """Run the REAL stage4_await_swap. Returns (result, stdout, exited)."""
    tl = Timeline(steps, 30)
    saved = (ghost.xmr_balance, ghost.integrity_log, ghost.time,
             ghost.XMR_ARRIVAL_STALL)
    out = io.StringIO()
    exited = None
    res = None
    try:
        ghost.xmr_balance = lambda rpc, acct, idx: tl.balance()
        ghost.integrity_log = lambda *a, **k: None
        # A clock the wait can actually advance, and a stall short enough that
        # a missing chunk resolves inside the test rather than in two hours.
        ghost.time = types.SimpleNamespace(sleep=tl.sleep,
                                           monotonic=tl.clock)
        ghost.XMR_ARRIVAL_STALL = 300
        args = types.SimpleNamespace(
            split=split,
            expect_total_xmr=expect,
            swap_tolerance=(tolerance if tolerance is not None
                            else ghost.SWAP_TOLERANCE_DEFAULT),
            accept_partial_swap=accept_partial,
            entry_veil=True)
        with contextlib.redirect_stdout(out):
            try:
                res = ghost.stage4_await_swap(
                    args, object(), 3, 1, "4" + "A" * 94, deposits or [],
                    receive_mode, total_now, unlocked_now)
            except SystemExit as e:
                exited = e
    finally:
        (ghost.xmr_balance, ghost.integrity_log, ghost.time,
         ghost.XMR_ARRIVAL_STALL) = saved
    return res, out.getvalue(), exited


_Q3 = [quote("1.0")] * 3          # 3 chunks, 3 XMR quoted

# THE HEADLINE GUARANTEE. Two of three chunks land and stop.
_res, _out, _exit = drive_stage4([(0, 0), (1, 1), (2, 2)], deposits=_Q3)
check("STAGE4: a shortfall EXITS rather than being inherited silently",
      _exit is not None)
check("STAGE4: ...and the message says what arrived and what was expected",
      "NOT fully arrived" in str(_exit) and "NOTHING HAS BEEN SPENT" in str(_exit))
check("STAGE4: ...and does not tell the operator to re-run first, which would "
      "strand what did arrive",
      "BEFORE re-running" in str(_exit))

# The full delivery proceeds, and returns the balance the plan is sized from.
_res, _out, _exit = drive_stage4([(0, 0), (1, 1), (2, 2), (3, 3)], deposits=_Q3)
check("STAGE4: a complete arrival returns normally", _exit is None)
check("STAGE4: ...with the full balance, not the first chunk's",
      _res == (D(3), D(3)))

# --accept-partial-swap is the ONLY way past a shortfall, and it must say so.
_res, _out, _exit = drive_stage4([(0, 0), (1, 1), (2, 2)], deposits=_Q3,
                                 accept_partial=True)
check("STAGE4: --accept-partial-swap proceeds instead of exiting",
      _exit is None and _res == (D(2), D(2)))
check("STAGE4: ...and warns that later arrivals are never mixed",
      "NOT mixed by this run" in _out)
check("STAGE4: ...and that the exit will not withdraw them",
      "will NOT withdraw" in _out)

# Receiver mode: nothing to wait for -- but the flags must not be swallowed.
_res, _out, _exit = drive_stage4([(9, 9)], deposits=_Q3, receive_mode=True,
                                 unlocked_now=D(9), total_now=D(9),
                                 expect=D("5.0"))
check("STAGE4: receiver mode returns the balance it was given",
      _exit is None and _res == (D(9), D(9)))
check("STAGE4: ...and SAYS the arrival flags are ignored rather than "
      "discarding them in silence",
      "NO EFFECT in receiver mode" in _out)

# Manual mode: no quotes, so no target. The warning must not be conditional on
# --split, which does nothing in manual mode.
_res, _out, _exit = drive_stage4([(0, 0), (1, 1)], deposits=[], split=1)
check("STAGE4: manual mode warns that the wait cannot tell one chunk from all",
      "NO EXPECTED TOTAL" in _out)
check("STAGE4: ...even at the default --split 1, where the old warning was "
      "silent", "--expect-total-xmr" in _out)

# The chunk-safe cap must be announced, not applied behind the operator's back.
_res, _out, _exit = drive_stage4(
    [(0, 0)] + [(i, i) for i in range(1, 13)] + [(12, 12)] * 3,
    deposits=[quote("1.0")] * 12)
check("STAGE4: the tightened gate is announced", "tightened" in _out)
check("STAGE4: ...and with real quotes it says the SMALLEST QUOTED chunk, "
      "a fact it actually has", "smallest quoted chunk" in _out.lower())
check("STAGE4: ...and the run still completes on a full delivery",
      _exit is None and _res == (D(12), D(12)))

# ...and at --split 12 a missing chunk must NOT pass, through the real
# orchestration rather than the pure floor arithmetic.
_res, _out, _exit = drive_stage4(
    [(0, 0)] + [(i, i) for i in range(1, 12)] + [(11, 11)] * 20,
    deposits=[quote("1.0")] * 12)
check("STAGE4: 11 of 12 chunks exits, through the real orchestration",
      _exit is not None)

# An explicit target below the quotes lowers the bar -- say so.
_res, _out, _exit = drive_stage4([(0, 0), (1, 1), (2, 2)], deposits=_Q3,
                                 expect=D("2.0"))
check("STAGE4: an --expect-total-xmr below the quoted sum is called out",
      "BELOW" in _out)

# The manual-mode hole, driven end to end: a total with no chunk count cannot
# detect a missing swap, and the run must SAY that rather than pass it off as
# a checked arrival.
_res, _out, _exit = drive_stage4([(0, 0), (12, 12)], deposits=[],
                                 expect=D(12), split=1)
check("STAGE4: a target with no chunk count warns that a missing swap is "
      "undetectable", "number of swaps is UNKNOWN" in _out)
check("STAGE4: ...and names the flag that fixes it", "--split" in _out)
_res, _out, _exit = drive_stage4([(0, 0), (12, 12)], deposits=[],
                                 expect=D(12), split=12)
check("STAGE4: ...and does NOT warn once --split says how many",
      "number of swaps is UNKNOWN" not in _out)
_res, _out, _exit = drive_stage4([(0, 0)] + [(11, 11)] * 20, deposits=[],
                                 expect=D(12), split=12)
check("STAGE4: 11 of 12 manual swaps exits once --split is given",
      _exit is not None)


# ---- ONE SUMMER, TWO CALLERS, AND THEY MUST NOT DRIFT -------------------
#
# receive_watch.expected_total and GhostSpiral.swap_expected_total were the
# same function written twice. GhostSpiral's was fixed for NaN and Infinity;
# receive_watch's was not, and nothing noticed, because test_receive_watch.py
# contained no NaN, no Infinity and no is_finite check anywhere -- the word
# does not appear in the file. A NaN quote RAISED InvalidOperation straight out
# of it, and its pairs come from thor_pairs*.json, a file on disk.
#
# Both now call gs_common.sum_quoted_xmr. These checks drive BOTH and compare,
# so the next divergence fails here rather than in a run.
import importlib.machinery as _im, importlib.util as _iu
_rwld = _im.SourceFileLoader("receive_watch", os.path.join(REPO, "receive_watch"))
_rw = _iu.module_from_spec(_iu.spec_from_loader(_rwld.name, _rwld))
_rwld.exec_module(_rw)
import gs_common as _gsc

_HOSTILE = [
    ("a NaN quote",            "NaN"),
    ("an Infinity quote",      "Infinity"),
    ("a -Infinity quote",      "-Infinity"),
    ("an absurd finite quote", "1e20"),
    ("a negative quote",       "-5"),
    ("a non-numeric quote",    "junk"),
    ("an empty quote",         ""),
]
for _label, _v in _HOSTILE:
    _pairs = [{"expected_xmr": _v}, {"expected_xmr": "1.0"}]
    # GhostSpiral
    try:
        _g_tot, _g_bad, _g_amt = ghost.swap_expected_total(_pairs)
        _g = (_g_tot, _g_bad)
    except Exception as _e:                                  # noqa: BLE001
        _g = f"RAISED {type(_e).__name__}"
    # receive_watch
    try:
        _r = _rw.expected_total(_pairs)
    except Exception as _e:                                  # noqa: BLE001
        _r = f"RAISED {type(_e).__name__}"
    check(f"SUMMER: {_label} is counted unreadable, not raised (GhostSpiral)",
          _g == (D("1.0"), 1))
    check(f"SUMMER: ...and receive_watch agrees exactly", _r == _g)

# The absurd-value bound exists because accept_floor RAISES past ~1.7e16, and
# the caller has no reason to guard a logging helper. Without it a hostile or
# broken quote produced a traceback hours into a run.
check("SUMMER: an absurd quote cannot reach accept_floor at all",
      ghost.swap_expected_total([{"expected_xmr": "1e20"}])[0] == D(0))
_big = _gsc.XMR_ABSURD_TOTAL
check("SUMMER: the bound sits far above any real amount and far below the "
      "precision cliff", D("18400000") < _big < D("1e15"))
check("SUMMER: a large-but-real amount is still accepted",
      ghost.swap_expected_total([{"expected_xmr": "1000000"}])[0] == D("1000000"))

# Non-vacuity: the pre-fix body really did raise, so these are not passing on
# a case that was never broken.
def _prefix_expected_total(pairs):
    """receive_watch's body as it shipped, verbatim."""
    tot, unreadable = D(0), 0
    for p in pairs:
        try:
            v = D(str(p.get("expected_xmr") or "0"))
        except Exception:                                    # noqa: BLE001
            v = D(0)
        if v > 0:                    # <-- outside the try: NaN raises here
            tot += v
        else:
            unreadable += 1
    return tot, unreadable


_raised = False
try:
    _prefix_expected_total([{"expected_xmr": "NaN"}])
except Exception:                                            # noqa: BLE001
    _raised = True
check("control: the pre-fix body DID raise on a NaN quote", _raised)
check("control: ...and DID sum an Infinity quote as readable",
      _prefix_expected_total([{"expected_xmr": "Infinity"}])[1] == 0)



# ---- receive_watch's gate is the SAME gate, wired end to end -------------
#
# receive_watch's arrival gate kept the pre-G6 floor (plain accept_floor) after
# GhostSpiral's was hardened, and nothing noticed because they were two gates
# rather than one. On the same 4-chunk swap (0.50/0.30/0.15/0.05, 10%
# tolerance) GhostSpiral waited while receive_watch reported PAID with the 0.05
# chunk still in flight; on twelve equal chunks it reported PAID at eleven.
# That is the worse copy: GhostSpiral's gate decides what a run plans against,
# this one is what TELLS THE OPERATOR the money has landed.
#
# Driven as a SUBPROCESS against the real argv, not grepped for and not
# unit-called: the defect was in main()'s wiring, so only running main() proves
# the wiring. It aborts at the Tor check a moment later, which is fine -- the
# gate is announced first.
import json as _json, subprocess as _sp, tempfile as _tf, os as _os

_RW_ADDR = ("83Ss8Wx9CmH4EaWkan3bdGhAybs7r3xgHZnMeWMNgwwdW3BJc6nfjTbFL9V4"
            "Go9LxZjUvDCX9H416cHR68m8aLc6FUZFVRJ")


def _run_receive_watch(quotes, tolerance="0.10"):
    """Run the shipped receive_watch on a pairs file. Returns its stdout."""
    d = _tf.mkdtemp(prefix="rw_gate_")
    pairs = _os.path.join(d, "pairs.json")
    bundle = _os.path.join(d, "bundle.json")
    with open(pairs, "w") as fh:
        _json.dump([{"schema": "thor_pairs_v1", "dest_xmr": _RW_ADDR,
                     "expected_xmr": q} for q in quotes], fh)
    with open(bundle, "w") as fh:
        _json.dump({"schema": "gs_receive_wallet_v1", "address": _RW_ADDR,
                    "account_index": 3, "subaddress_index": 1,
                    "wallet_file": "w", "nettype": "mainnet",
                    "created": "2026-01-01T00:00:00Z"}, fh)
    p = _sp.run([sys.executable, os.path.join(REPO, "receive_watch"),
                 "--receive-wallet", bundle, "--pairs", pairs,
                 "--tolerance", tolerance,
                 "--tor-proxy", "socks5h://127.0.0.1:9050"],
                capture_output=True, text=True, timeout=120, cwd=d)
    return p.stdout + p.stderr


_UNEQ_Q = ["0.50", "0.30", "0.15", "0.05"]
_out = _run_receive_watch(_UNEQ_Q)
_want, _ = ghost.swap_arrival_floor(D("1.00"), D("0.10"),
                                    [D(q) for q in _UNEQ_Q], 4)
check("RW GATE: receive_watch tightens the gate for an unequal split swap",
      "tightened" in _out)
check("RW GATE: ...to exactly the floor the shared helper computes",
      str(_want) in _out)
check("RW GATE: ...and the announced floor really does hold back the "
      "smallest chunk", D("0.95") < _want)

# CONTROL: equal chunks where the tolerance is already safe must NOT tighten,
# or the check above would pass on a gate that tightens unconditionally.
_out2 = _run_receive_watch(["1.0", "1.0"])
check("RW GATE control: an equal 2-chunk swap is NOT tightened "
      "(so the check above is not vacuous)", "tightened" not in _out2)

# ...and the gate it uses is the shared one, so GhostSpiral and receive_watch
# cannot disagree about whether the same swap has arrived.
for _qs in (["0.50", "0.30", "0.15", "0.05"], ["1.0"] * 12, ["2.5", "2.5"]):
    _amts = [D(q) for q in _qs]
    _tot = sum(_amts)
    check(f"RW GATE: both tools compute one floor for {len(_qs)} chunks",
          ghost.swap_arrival_floor(_tot, D("0.10"), _amts, len(_amts))
          == _gsc.swap_arrival_floor(_tot, D("0.10"), _amts, len(_amts)))



# ---- STAGE 4 WITH UNEQUAL CHUNKS ---------------------------------------
#
# Every stage4 check above uses EQUAL chunks, and that is why a one-line
# regression survived a green suite: `chunk_amounts = []` whenever
# --expect-total-xmr was set threw away the per-chunk breakdown, so the
# unequal-chunk gate reverted to the plain tolerance at the exact moment the
# operator supplied the total this tool asks them for. With equal chunks the
# two floors are close enough that nothing noticed.
#
# --joinmarket is the path that produces unequal chunks: btc_chunks becomes
# jm_utxos, the tumbler's own outputs.
_UQ = ["0.50", "0.30", "0.15", "0.05"]        # total 1.00, smallest is 5%


def _uq_quotes():
    return [quote(x) for x in _UQ]


# ...with quotes alone: the smallest chunk must hold the gate.
_res, _out, _exit = drive_stage4(
    [(0, 0), (D("0.50"), D("0.50")), (D("0.80"), D("0.80")),
     (D("0.95"), D("0.95"))] + [(D("0.95"), D("0.95"))] * 20,
    deposits=_uq_quotes())
check("UNEQUAL STAGE4: 0.95 of a 1.00 swap EXITS when the missing 0.05 is a "
      "whole chunk", _exit is not None)
_res, _out, _exit = drive_stage4(
    [(0, 0), (D("0.50"), D("0.50")), (D("0.95"), D("0.95")),
     (D("1.00"), D("1.00"))], deposits=_uq_quotes())
check("UNEQUAL STAGE4: ...and the complete delivery proceeds",
      _exit is None and _res == (D("1.00"), D("1.00")))

# THE REGRESSION. Supplying the true total must not weaken the gate: the total
# corrects the magnitude, the quotes still describe the proportions.
_res, _out, _exit = drive_stage4(
    [(0, 0), (D("1.90"), D("1.90"))] + [(D("1.90"), D("1.90"))] * 20,
    deposits=_uq_quotes(), expect=D("2.00"))
check("UNEQUAL STAGE4: --expect-total-xmr does NOT discard the per-chunk "
      "breakdown (1.90 of 2.00 with a 0.10 chunk missing still exits)",
      _exit is not None)
_res, _out, _exit = drive_stage4(
    [(0, 0), (D("1.90"), D("1.90")), (D("2.00"), D("2.00"))],
    deposits=_uq_quotes(), expect=D("2.00"))
check("UNEQUAL STAGE4: ...and the full rescaled delivery still proceeds",
      _exit is None and _res == (D("2.00"), D("2.00")))

# Non-vacuity: on the SAME timeline the plain tolerance would have opened, so
# these checks are about the breakdown and not about the numbers happening to
# line up.
check("control: the plain tolerance alone WOULD have accepted 1.90 of 2.00",
      D("1.90") >= ghost.accept_floor(D("2.00"), D("0.10")))



# ---- the floor must always be REACHABLE ---------------------------------
#
# swap_arrival_floor raises the floor to just above "everything except the
# smallest chunk". A chunk smaller than one piconero -- a quote can carry one,
# Decimal("0.0000000000001") is finite and positive and sum_quoted_xmr accepts
# it -- pushed that above the TOTAL, so no arrival could ever satisfy the gate
# and the run waited out its whole timeout and reported the swap short.
_TINY = [D("1.0"), D("0.0000000000001")]
_tf_, _tt_ = ghost.swap_arrival_floor(sum(_TINY), D("0.10"), _TINY, 2)
check("FLOOR: a sub-piconero chunk cannot make the gate unreachable",
      _tf_ <= sum(_TINY))
check("FLOOR: ...and it falls back to the plain tolerance rather than "
      "tightening to something impossible", not _tt_)

# The floor is never above the total for any shape, checked over the sizes and
# spreads this pipeline actually produces.
_shapes = [[D(1)] * n for n in (1, 2, 3, 12, 20)] + [
    [D("0.5"), D("0.3"), D("0.15"), D("0.05")],
    [D("0.9999"), D("0.0001")],
    [D("100"), D("0.01")],
    [D("0.0001")] * 5,
]
for _sh in _shapes:
    _t = sum(_sh)
    for _tol in (D("0"), D("0.01"), D("0.10"), D("0.5"), D("0.99")):
        _f, _ = ghost.swap_arrival_floor(_t, _tol, _sh, len(_sh))
        if _f > _t:
            check(f"FLOOR: unreachable for {[str(x) for x in _sh]} @ {_tol}",
                  False)
            break
else:
    check(f"FLOOR: never exceeds the total, over {len(_shapes)} shapes x 5 "
          f"tolerances", True)

check("FLOOR: a zero or negative total yields no floor at all",
      ghost.swap_arrival_floor(D(0), D("0.10"), [], 3) == (D(0), False)
      and ghost.swap_arrival_floor(D(-1), D("0.10"), [], 3) == (D(0), False))



# ---- the gate must not assert what it does not know ---------------------
#
# With a total and a count but no quotes, "the smallest chunk is worth less
# than that tolerance" is not a measurement — the sizes are ASSUMED EQUAL. The
# message stated it as fact, which is the same class of defect as the rest of
# this audit: a claim the code never established.
_res, _out, _exit = drive_stage4(
    [(0, 0)] + [(D(i), D(i)) for i in range(1, 13)] + [(D(12), D(12))] * 3,
    deposits=[], expect=D(12), split=12)
check("MANUAL CLAIM: with no quotes the gate says the sizes are ASSUMED equal",
      "assumes your" in _out and "EQUAL" in _out)
check("MANUAL CLAIM: ...and does not claim to know the smallest chunk",
      "smallest quoted chunk" not in _out.lower())
check("MANUAL CLAIM: ...and warns the real smallest may be smaller",
      "may be smaller" in _out)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
