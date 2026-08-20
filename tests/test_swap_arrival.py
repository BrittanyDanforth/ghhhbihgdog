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
import importlib.machinery, importlib.util, io, itertools, os, sys, contextlib, types
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
    saved = (ghost.entry_balance_reader, ghost.integrity_log, ghost.time,
             ghost.XMR_ARRIVAL_STALL)
    out = io.StringIO()
    exited = None
    res = None
    try:
        # entry_balance_reader, not entry_set_balance and not xmr_balance.
        #
        # The gate sums across the whole entry set, because --split N lands the
        # chunks on N different subaddresses -- so faking the SUM is what the
        # wait actually consumes. That used to be entry_set_balance, and this
        # stub named it. Stage 4 now builds its balance_fn with
        # entry_balance_reader (which needs the PER-PAIR read outcomes, not
        # just the sum, so it can tell "the wallet says zero" from "the wallet
        # said nothing"), and a stub on the old name is simply not called any
        # more -- the nine drive_stage4 checks below all failed the moment the
        # production seam moved, which is what a seam-shaped stub is for.
        ghost.entry_balance_reader = lambda rpc, pairs, echo=print: tl.balance
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
                    args, object(), [(3, 1)] * max(1, split),
                    ["4" + "A" * 94] * max(1, split), deposits or [],
                    receive_mode, total_now, unlocked_now)
            except SystemExit as e:
                exited = e
    finally:
        (ghost.entry_balance_reader, ghost.integrity_log, ghost.time,
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

# Receiver mode WITH the target already satisfied: 9 XMR on ENTRY against an
# expected 5.0, so there is genuinely nothing to wait for and it returns at
# once. This used to assert the opposite intent -- that the flags were IGNORED
# and said so ("NO EFFECT in receiver mode") -- which was the defect, not the
# contract: the flags are now honoured, and the receiver section further down
# drives the case where the money has NOT all arrived.
_res, _out, _exit = drive_stage4([(9, 9)], deposits=_Q3, receive_mode=True,
                                 unlocked_now=D(9), total_now=D(9),
                                 expect=D("5.0"))
check("STAGE4: receiver mode returns the balance it was given when the "
      "expected total is already there",
      _exit is None and _res == (D(9), D(9)))
check("STAGE4: ...and no longer claims the arrival flags have NO EFFECT",
      "NO EFFECT in receiver mode" not in _out)

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

# THE RESCALE ITSELF, which the two checks above cannot see.
#
# stage4 computed `_scale = args.expect_total_xmr / quoted` -- AFTER the block
# above had already assigned `quoted = args.expect_total_xmr`. So the
# expression was x/x, _scale was exactly 1, and the block commented "RESCALE
# the breakdown; do not throw it away" left the breakdown at the quotes' raw
# magnitudes while `quoted` carried the operator's total. Asserting _scale == 1
# in the shipped code runs four times in this file and never fires.
#
# The checks above miss it because _UQ's smallest chunk is 5% of the total and
# the tolerance there is 5% too, so the chunk floor and the tolerance floor sit
# on top of each other and both versions agree. Seeing it needs a smallest
# chunk well BELOW the tolerance, and a total BELOW the quotes' sum -- the case
# stage4 prints a dedicated warning for, so it is an expected input.
#
# Quotes 0.60/0.30/0.08/0.02 (sum 1.00, smallest 2%), --expect-total-xmr 0.1,
# tolerance 5%. Correctly scaled the smallest is 0.002 and the floor is
# 0.098000000001; unscaled it is 0.02, the chunk term drops below the tolerance
# term and the floor collapses to 0.095. A balance of 0.098 is exactly "every
# chunk but the smallest", so the broken gate calls it ARRIVED and the run
# plans against a fraction.
_SKEW = [quote(x) for x in ("0.60", "0.30", "0.08", "0.02")]
_res, _out, _exit = drive_stage4(
    [(0, 0), (D("0.098"), D("0.098"))] + [(D("0.098"), D("0.098"))] * 20,
    deposits=_SKEW, expect=D("0.1"), tolerance=D("0.05"))
check("UNEQUAL STAGE4: --expect-total-xmr RESCALES the breakdown onto the new "
      "total — 0.098 of 0.1 with the smallest chunk in flight still EXITS "
      "(unscaled, the floor collapses to the bare tolerance and it proceeds)",
      _exit is not None)
# ...and the fully-arrived swap on the same quotes still goes through, so the
# fix is not just "refuse more".
_res, _out, _exit = drive_stage4(
    [(0, 0), (D("0.098"), D("0.098")), (D("0.1"), D("0.1"))],
    deposits=_SKEW, expect=D("0.1"), tolerance=D("0.05"))
check("UNEQUAL STAGE4: ...and the full 0.1 still proceeds",
      _exit is None and _res == (D("0.1"), D("0.1")))
# Non-vacuity: the plain tolerance would have opened at 0.098, so this check is
# about the rescaled breakdown and not about the numbers lining up.
check("control: the plain tolerance alone WOULD have accepted 0.098 of 0.1",
      D("0.098") >= ghost.accept_floor(D("0.1"), D("0.05")))
# And the floor really does move when the breakdown is scaled -- the property
# stated directly against the shipped helper, independent of the drive.
check("control: scaling the breakdown onto the operator's total RAISES the "
      "floor above the bare tolerance",
      _gsc.swap_arrival_floor(D("0.1"), D("0.05"),
                             [D(x) * (D("0.1") / D("1.00"))
                              for x in ("0.60", "0.30", "0.08", "0.02")], 4)[0]
      > _gsc.swap_arrival_floor(D("0.1"), D("0.05"),
                               [D(x) for x in ("0.60", "0.30", "0.08", "0.02")],
                               4)[0])



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


# ==========================================================================
# THE GATE SUMS ACROSS THE WHOLE ENTRY SET.
#
# --split N lands the chunks on N DIFFERENT subaddresses (create_entry_set),
# minutes to hours apart. "Has the swap arrived" is therefore a question about
# the SUM -- watching any one of them finishes the moment that chunk lands,
# which is the first-chunk defect this whole file exists to close, reopened
# one level up.
#
# entry_set_balance is what stage 4 calls, so drive THAT with a fake wallet
# rather than asserting on the closure's shape.
# ==========================================================================
print("\n=== the arrival gate sums across N entry addresses ===")


class _MultiBalRPC:
    """A wallet holding a different balance on each entry subaddress."""

    def __init__(self, per_sub):
        self.per_sub = per_sub          # {(acct, idx): (total, unlocked)}
        self.asked = []

    def raw_request(self, method, params=None):
        if method == "refresh":
            return {}
        raise AssertionError(method)

    def get_subaddress_balance(self, account_index=0, address_index=0):
        self.asked.append((account_index, address_index))
        return self.per_sub.get((account_index, address_index), (0, 0))


_PAIRS = [(10, 1), (11, 1), (12, 1)]
_M = _MultiBalRPC({(10, 1): (2 * 10**12, 2 * 10**12),
                   (11, 1): (3 * 10**12, 1 * 10**12),
                   (12, 1): (5 * 10**12, 5 * 10**12)})
_tot, _unl = ghost.entry_set_balance(_M, _PAIRS)
check("multi: the total is the SUM over every entry address, not one of them",
      _tot == D("10"))
check("multi: ...and so is the unlocked figure", _unl == D("8"))
check("multi: EVERY entry address is polled, not just the first",
      sorted(set(_M.asked)) == sorted(_PAIRS))

# The breakdown the distribution needs.
_rows = ghost.entry_set_balances(_M, _PAIRS)
check("multi: the per-entry breakdown keeps chunk order",
      [u for _t, u in _rows] == [D("2"), D("1"), D("5")])


class _HalfDeadRPC(_MultiBalRPC):
    def get_subaddress_balance(self, account_index=0, address_index=0):
        if account_index == 11:
            raise RuntimeError("rpc hiccup")
        return super().get_subaddress_balance(account_index, address_index)


_tot2, _unl2 = ghost.entry_set_balance(_HalfDeadRPC(_M.per_sub), _PAIRS)
check("multi: an unreadable entry reads as ZERO — under-reporting makes the "
      "gate stricter, and a poll loop must survive an RPC hiccup",
      _unl2 == D("7"))

# NON-VACUITY: one entry behaves exactly as it did before.
_one_rpc = _MultiBalRPC({(10, 1): (4 * 10**12, 4 * 10**12)})
check("control: with ONE entry the sum is that entry's balance, unchanged",
      ghost.entry_set_balance(_one_rpc, [(10, 1)]) == (D("4"), D("4")))
check("control: ...and a balance elsewhere in the wallet is NOT counted",
      ghost.entry_set_balance(
          _MultiBalRPC({(10, 1): (4 * 10**12, 4 * 10**12),
                        (99, 1): (99 * 10**12, 99 * 10**12)}),
          [(10, 1)]) == (D("4"), D("4")))

# And the gate itself: three chunks, two landed. It must NOT fire.
_res3, _out3, _exit3 = drive_stage4(
    [(D("1"), D("1")), (D("2"), D("2")), (D("2"), D("2")), (D("2"), D("2"))],
    deposits=_Q3, split=3)
check("multi: with 3 chunks quoted at 1 XMR each, 2 XMR summed across the set "
      "does NOT satisfy the gate", _exit3 is not None)
check("multi: ...and the shortfall names what is missing",
      _exit3 and "short by" in str(_exit3.code))



# ==========================================================================
# THE WAIT MUST SAY IT IS ALIVE, not only when something changes.
#
# Every reporting branch in wait_for_swap_arrival fires on a CHANGE. While a
# cross-chain swap is still settling -- the entire purpose of this wait, and
# routinely hours -- nothing changes, so the loop printed NOTHING at all, for
# up to XMR_ARRIVAL_TIMEOUT (24h). Driven on the pre-fix code: a 60-minute wait
# with no arrival produced ZERO lines. An operator who had just sent real BTC
# saw a console pane that had not moved since the run started, with no way to
# tell "waiting" from "hung" -- which is exactly what "it just went nowhere"
# looks like from the outside.
#
# receive_watch answers the same question and has always echoed progress_line
# on every poll; gs_console even documents tuning its output buffering around
# that cadence. Stage 4 was the waiter that stayed silent.
# ==========================================================================
print("\n=== the arrival wait reports that it is alive ===")


class _HBClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, n):
        self.t += n


_hb_lines = []
_hbc = _HBClock()
_hb = ghost.wait_for_swap_arrival(
    lambda: (D(0), D(0)), D("2.0"), 4, stall_s=3600, timeout_s=7200,
    poll_s=30, sleep_fn=_hbc.sleep, clock=_hbc, echo=_hb_lines.append)
check("heartbeat: a swap that has not landed still reports progress "
      f"(got {len(_hb_lines)} lines across {int(_hbc.t // 60)} min; the "
      f"pre-fix loop printed 0)", len(_hb_lines) >= 5)
check("heartbeat: ...and says what it is waiting for",
      any("still waiting for the swap" in l for l in _hb_lines))
check("heartbeat: ...and how long it has been waiting, so a stuck run is "
      "visible", any("min elapsed" in l for l in _hb_lines))
# Cadence: bounded, so a 24h wait cannot flood the console's line buffer and
# push the run's real events out of it.
check(f"heartbeat: paced at ARRIVAL_HEARTBEAT_S, not every poll "
      f"({ghost.ARRIVAL_HEARTBEAT_S}s)",
      len(_hb_lines) <= int(_hbc.t / ghost.ARRIVAL_HEARTBEAT_S) + 1)

# It must carry the REAL figures, not a fixed string -- a heartbeat that always
# says the same thing cannot distinguish a stalled swap from a partial one.
_hb2 = []
_hbc2 = _HBClock()
_state = {"n": 0}


def _partial():
    _state["n"] += 1
    return (D("1.2"), D("0.5")) if _state["n"] > 3 else (D(0), D(0))


ghost.wait_for_swap_arrival(_partial, D("2.0"), 4, stall_s=1800,
                            timeout_s=3600, poll_s=30, sleep_fn=_hbc2.sleep,
                            clock=_hbc2, echo=_hb2.append)
_beats = [l for l in _hb2 if "still waiting for the swap" in l]
check("heartbeat: reports what has UNLOCKED so far",
      any("unlocked 0.5 XMR" in l for l in _beats))
check("heartbeat: ...what is still confirming",
      any("still confirming" in l for l in _beats))
check("heartbeat: ...and how far from the target, as a percentage",
      any("to go (25.0%)" in l for l in _beats))
# ...and the shared helper really is shared, so the two waiters cannot drift
# into describing the same balance differently.
check("heartbeat: GhostSpiral and receive_watch use ONE progress_line",
      ghost.progress_line is _gsc.progress_line)



# ==========================================================================
# RECEIVER MODE MUST WAIT TOO, WHEN IT HAS BEEN TOLD WHAT TO WAIT FOR.
#
# This branch returned immediately and printed that --expect-total-xmr,
# --swap-tolerance and --accept-partial-swap "have NO EFFECT in receiver mode:
# the XMR is already on the entry address, so there is no arrival to wait for."
#
# The XMR gets to that entry address from a swap the operator arranged, and a
# --split N swap lands N chunks minutes to hours apart -- the same staggered
# arrival the send-mode wait exists for. Nothing forces a receive_watch run
# first and nothing checked that one happened.
#
# Driven on the old code: receiver mode, --expect-total-xmr 4.0, 1.0 XMR on
# ENTRY -> returned (1.0, 1.0) immediately and the run planned against a
# QUARTER of the money. The dust guard downstream cannot see it: 1.0 XMR is
# four orders of magnitude above DUST_XMR. Chunks 2-4 then land on an ENTRY the
# run has finished with -- veil swept, distribution sized -- and the exit
# correctly refuses to sweep ENTRY, so they sit on the one address the public
# ThorChain memo names.
# ==========================================================================
print("\n=== receiver mode waits for the total it was given ===")


class _RClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, n):
        self.t += n


_r_real = ghost.wait_for_swap_arrival


def _r_fast(bf, f, c, **kw):
    cl = _RClock()
    return _r_real(bf, f, c, stall_s=3600, timeout_s=7200, poll_s=30,
                   sleep_fn=cl.sleep, clock=cl, echo=lambda *a, **k: None)


def _recv(landed, expect, accept_partial=False, target=True, later=None):
    seq = {"n": 0}

    def _bal():
        seq["n"] += 1
        v = D(str(later)) if (later and seq["n"] > 3) else D(str(landed))
        return (v, v)

    _saved = (ghost.wait_for_swap_arrival, ghost.entry_balance_reader,
              ghost.integrity_log)
    ghost.wait_for_swap_arrival = _r_fast
    ghost.entry_balance_reader = lambda rpc, pairs, echo=print: _bal
    ghost.integrity_log = lambda *a, **k: None
    a = types.SimpleNamespace(
        expect_total_xmr=(D(str(expect)) if target else None),
        accept_partial_swap=accept_partial,
        swap_tolerance=ghost.SWAP_TOLERANCE_DEFAULT, split=4)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return ("ok", ghost.stage4_await_swap(
                a, None, [(3, 1)], ["8" + "A" * 94], [], True,
                D(str(landed)), D(str(landed))))
    except SystemExit as e:
        return ("exit", str(e))
    finally:
        (ghost.wait_for_swap_arrival, ghost.entry_balance_reader,
         ghost.integrity_log) = _saved


_st, _r = _recv(1.0, 4.0)
check("receiver: 1.0 of an expected 4.0 XMR REFUSES instead of planning "
      "against a quarter of the money", _st == "exit")
check("receiver: ...and says the rest would stay on ENTRY unmixed",
      _st == "exit" and "UNMIXED" in _r)
check("receiver: ...and names the escape hatch rather than only refusing",
      _st == "exit" and "--accept-partial-swap" in _r)

_st, _r = _recv(4.0, 4.0)
check("receiver: the full amount proceeds", _st == "ok" and _r[1] == D("4.0"))

# THE POINT OF WAITING: the rest turns up while it waits and the run continues
# on its own, which is what "detect it and then just do it" means.
_st, _r = _recv(1.0, 4.0, later=4.0)
check("receiver: the rest arriving DURING the wait proceeds automatically "
      "with the full amount", _st == "ok" and _r[1] == D("4.0"))

_st, _r = _recv(1.0, 4.0, accept_partial=True)
check("receiver: --accept-partial-swap still plans against what is there",
      _st == "ok" and _r[1] == D("1.0"))

# Unchanged where there is nothing to check against.
_st, _r = _recv(1.0, 4.0, target=False)
check("receiver: with no --expect-total-xmr the behaviour is unchanged",
      _st == "ok" and _r[1] == D("1.0"))
# code_only: the fix's own comment QUOTES the removed sentence to record why
# it went, and a raw read cannot tell a defect from its own post-mortem. That
# is the fourth time this session a literal source check has caught prose.
from srcutil import code_only as _code_only_sa                # noqa: E402
check("receiver: ...and the old 'NO EFFECT' claim is gone from the CODE",
      "have NO EFFECT in receiver mode" not in
      _code_only_sa(os.path.join(REPO, "GhostSpiral")))


# ==========================================================================
# "READ AS ZERO" IS NOT "IS ZERO".
#
# entry_set_balances deliberately reports an unreadable subaddress as zero, so
# the arrival gate can never open on a guess. Nothing carried the FACT of the
# failure out, and two things read that zero as truth:
#
#   * the arrival wait, where a wallet-rpc answering nothing at all was
#     indistinguishable from a swap that never settled -- five-minute
#     heartbeats reading "unlocked 0 XMR . 0.0%" for up to a day, then a
#     verdict blaming ThorChain for money that was sitting on ENTRY;
#   * the one-shot read feeding select_funded_entries, where one dropped poll
#     drops a FULLY FUNDED chunk out of the distribution, announces "1 of 4
#     swap chunk(s) have NOT arrived", and leaves that quarter unmixed on the
#     address the swap memo names in public.
#
# Driven with an RPC that raises, which is what a dropped socket, a wallet
# mid-rescan or a wrong --rpc-primary port actually looks like.
# ==========================================================================
print("\n=== an unreadable wallet is not an empty one ===")

_BP = [(10, 1), (11, 1), (12, 1)]
_BFULL = {(10, 1): (2 * 10**12, 2 * 10**12),
          (11, 1): (3 * 10**12, 3 * 10**12),
          (12, 1): (5 * 10**12, 5 * 10**12)}


class _BlindRPC:
    """A wallet-rpc that is reachable in some ways and not others."""

    def __init__(self, per, dead=(), refresh_ok=True):
        self.per, self.dead, self.refresh_ok = per, set(dead), refresh_ok

    def raw_request(self, method, params=None):
        if method == "refresh" and not self.refresh_ok:
            raise RuntimeError("no daemon")
        return {}

    def get_subaddress_balance(self, account_index=0, address_index=0):
        if (account_index, address_index) in self.dead:
            raise RuntimeError("Connection refused")
        return self.per.get((account_index, address_index), (0, 0))


_b_saved_il = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
try:
    # Non-vacuity first: a healthy wallet reads exactly as before and says
    # nothing extra.
    _bl = []
    check("blind: a healthy wallet reads the full sum through the reader",
          ghost.entry_balance_reader(_BlindRPC(_BFULL), _BP,
                                     echo=_bl.append)() == (D("10"), D("10")))
    check("blind: ...and prints nothing", _bl == [])

    # TOTAL blindness must RAISE, so wait_for_swap_arrival's own
    # "wallet-rpc did not answer this tick" branch fires. That branch existed
    # all along and was unreachable, because the swallow happened below it.
    _rd = ghost.entry_balance_reader(_BlindRPC(_BFULL, dead=_BP), _BP,
                                     echo=lambda _s: None)
    try:
        _rd()
        _raised = False
    except Exception:                                        # noqa: BLE001
        _raised = True
    check("blind: every entry address unreadable RAISES rather than "
          "reporting an authoritative zero", _raised)

    # And end to end through the real wait.
    _bclock = itertools.count(0, 30)
    _blines = []
    _bres = ghost.wait_for_swap_arrival(
        ghost.entry_balance_reader(_BlindRPC(_BFULL, dead=_BP), _BP,
                                   echo=_blines.append),
        D("4.0"), 3, stall_s=600, timeout_s=3600, poll_s=30,
        sleep_fn=lambda _s: None, clock=lambda: next(_bclock),
        echo=_blines.append)
    check("blind: the wait against a dead wallet TELLS the operator the "
          "wallet is the problem",
          any("did not answer" in _l for _l in _blines))
    check("blind: ...naming the real reason, not a truncated empty paren",
          any("Connection refused" in _l for _l in _blines))
    check("blind: ...and the verdict carries how many polls failed",
          _bres.get("poll_errors", 0) > 0
          and _bres["poll_errors"] == _bres["polls"])
    # The flood this replaced: one line per poll across the stall window.
    check("blind: ...rate-limited, not one line per poll",
          sum(1 for _l in _blines if "did not answer" in _l) < _bres["polls"])
    check("blind: ...so the operator is not told the swap is short",
          "THE WALLET WAS NOT READABLE"
          in ghost.arrival_blindness_note(_bres))

    # PARTIAL blindness: the sum stays low (the gate must stay strict) and the
    # operator is told the shortfall may be the socket.
    _plines = []
    _psum = ghost.entry_balance_reader(_BlindRPC(_BFULL, dead=[(11, 1)]), _BP,
                                       echo=_plines.append)()
    check("blind: a partly readable wallet still UNDER-reports, keeping the "
          "gate strict", _psum == (D("7"), D("7")))
    check("blind: ...and says the total may be lower than the truth",
          any("could NOT be read" in _l for _l in _plines))

    # A wallet that will not refresh is reachable but STALE -- no arrival can
    # ever be seen, and the balances it does return are from before the swap.
    _slines = []
    _ssum = ghost.entry_balance_reader(_BlindRPC(_BFULL, refresh_ok=False),
                                       _BP, echo=_slines.append)()
    check("blind: a wallet that will not refresh still reports its balances",
          _ssum == (D("10"), D("10")))
    check("blind: ...and warns they may be stale",
          any("stale" in _l for _l in _slines))

    # The one-shot read is a DECISION, and must fail closed.
    check("blind: the strict read returns normally on a healthy wallet",
          [u for _t, u in ghost.read_entry_balances_strict(
              _BlindRPC(_BFULL), _BP, "test")] == [D("2"), D("3"), D("5")])
    _sx = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.read_entry_balances_strict(
                _BlindRPC(_BFULL, dead=[(11, 1)]), _BP, "sizing",
                sleep_fn=lambda _s: None)
    except SystemExit as _e:
        _sx = str(_e)
    check("blind: one unreadable address ABORTS the run rather than letting "
          "select_funded_entries drop a funded chunk", _sx is not None)
    check("blind: ...saying nothing has been spent", "NOTHING HAS BEEN SPENT"
          in (_sx or ""))
    # The whole point: it must NOT quietly become a 'chunk never arrived'.
    check("blind: ...and never claims the chunk did not arrive",
          "have NOT arrived" not in (_sx or ""))

    # Non-vacuity for the abort: a chunk that is GENUINELY empty is still
    # allowed through, because that is a real swap shortfall and
    # select_funded_entries is meant to handle it.
    _genuine = dict(_BFULL)
    _genuine[(11, 1)] = (0, 0)
    check("blind: a genuinely EMPTY entry is not an error — it reads zero and "
          "the run goes on to drop that chunk",
          [u for _t, u in ghost.read_entry_balances_strict(
              _BlindRPC(_genuine), _BP, "test")] == [D("2"), D("0"), D("5")])
    check("blind: ...and select_funded_entries does drop exactly it",
          ghost.select_funded_entries(["a", "b", "c"],
                                      [D("2"), D("0"), D("5")])[0]
          == ["a", "c"])
finally:
    ghost.integrity_log = _b_saved_il

# The production seam. drive_stage4 stubs entry_balance_reader because that is
# what stage 4 builds its balance_fn from; if a later edit puts a bare
# `lambda: entry_set_balance(...)` back, the nine drive_stage4 checks go green
# again while the blindness handling is gone. This is the check that does not.
check("blind: stage 4 builds its waits from entry_balance_reader, NOT from a "
      "bare entry_set_balance lambda",
      _code_only_sa(os.path.join(REPO, "GhostSpiral")).count(
          "entry_balance_reader(rpc, entry_pair_list)") == 2
      and "lambda: entry_set_balance(rpc, entry_pair_list)"
      not in _code_only_sa(os.path.join(REPO, "GhostSpiral")))
# THIS CHECK WAS FALSE HOPE ON ITS FIRST WRITING, and the mutation that
# proved it is the whole reason for the shape below. It read
#
#     "read_entry_balances_strict(" in code_only(GhostSpiral)
#
# which the function's own `def` line satisfies. Reverting the CALL SITE back
# to the best-effort entry_set_balances -- the actual defect, one funded chunk
# silently dropped from the distribution -- left the suite ALL GREEN.
#
# So: whitespace-normalised, so it survives reformatting, and it names the
# ARGUMENTS. And the negative half matters as much as the positive one: the
# call has to be strict AND the old best-effort call must be gone, or a stray
# duplicate read puts the defect back beside the fix.
_norm_gs = " ".join(_code_only_sa(os.path.join(REPO, "GhostSpiral")).split())
check("blind: ...and the distribution's sizing read is the STRICT one",
      "read_entry_balances_strict( rpc_primary, ENTRY_PAIRS" in _norm_gs)
check("blind: ...with the best-effort read gone from that decision",
      "entry_set_balances( rpc_primary, ENTRY_PAIRS)" not in _norm_gs)


# ==========================================================================
# RECEIVER MODE CAN READ ITS OWN QUOTES NOW.
#
# stage4's receiver branch said in its own comment that "the only thing
# receiver mode genuinely lacks is quotes to derive the total FROM". Until
# --swap-pairs there was no way to supply them, so the target had to be retyped
# into --expect-total-xmr by hand -- a decimal whose failure is silent in the
# direction that costs money: a dropped digit makes the target smaller, the
# gate opens early, and the run plans against part of the swap.
#
# And a typed total cannot carry the PER-SWAP breakdown. On 0.50/0.30/0.15/0.05
# the gate tightens to 0.95 XMR with the breakdown and only reaches 0.90
# without it -- and at 0.90 the 0.05 swap can be missing entirely while the run
# starts mixing.
# ==========================================================================
print("\n=== receiver mode reads the swap quotes itself ===")

import json as _sp_json, tempfile as _sp_tmp, os as _sp_os      # noqa: E402

_SPD = "4" + "A" * 94
_SPO = "8" + "B" * 94
_sp_dir = _sp_tmp.mkdtemp(prefix="gs_pairs_")


def _sp_bundle(name, rows, schema="thor_pairs_v1"):
    _p = _sp_os.path.join(_sp_dir, name)
    with open(_p, "w") as _f:
        _sp_json.dump([{"schema": schema, "btc_in": "0.01", "deposit": "bc1x",
                        "memo": "=:XMR.XMR:" + _d, "dest_xmr": _d,
                        "expected_xmr": _a, "ts": 0} for _d, _a in rows], _f)
    return _p


def _sp_read(path):
    _o = io.StringIO()
    with contextlib.redirect_stdout(_o):
        _r = ghost._receive_pairs_for(types.SimpleNamespace(swap_pairs=path),
                                      _SPD)
    return _r, _o.getvalue()


_sp_saved_il = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
try:
    _good = _sp_bundle("good.json", [(_SPD, "0.5"), (_SPD, "0.3"),
                                     (_SPD, "0.15"), (_SPD, "0.05")])
    _rows, _out = _sp_read(_good)
    check("pairs: every swap routed to this address is read", len(_rows) == 4)
    _tot, _unread, _amts = ghost.swap_expected_total(_rows)
    check("pairs: ...and their quotes sum to the target",
          _tot == D("1.00") and _unread == 0)
    check("pairs: ...keeping the PER-SWAP breakdown, which a typed total cannot",
          [str(a) for a in _amts] == ["0.5", "0.3", "0.15", "0.05"])

    # THE POINT OF THE BREAKDOWN.
    _with = ghost.swap_arrival_floor(_tot, D("0.1"), _amts, len(_rows))
    _without = ghost.swap_arrival_floor(_tot, D("0.1"), [], len(_rows))
    check("pairs: the breakdown TIGHTENS the gate past the flat tolerance",
          _with[0] > _without[0] and _with[1] is True)
    check("pairs: ...and the smallest swap could hide under the loose figure",
          D("0.05") < _tot - _without[0])
    check("pairs: ...but not under the tight one", D("0.05") > _tot - _with[0])

    # A bundle for someone else must NOT become this run's target.
    _wrong = _sp_bundle("wrong.json", [(_SPO, "4.0")])
    _rows, _out = _sp_read(_wrong)
    check("pairs: a bundle routed elsewhere contributes NOTHING", _rows == [])
    check("pairs: ...and says so, because the operator supplied it and "
          "reasonably believes the run is gated",
          "NONE of them describe this run\'s money" in _out
          and "are routed to this receive address" in _out)

    # NEVER FATAL: this is a convenience over --expect-total-xmr.
    for _bad, _why in ((_sp_os.path.join(_sp_dir, "nope.json"), "missing"),
                       (_sp_bundle("badschema.json", [(_SPD, "1.0")],
                                   schema="nope_v9"), "wrong schema")):
        _rows, _out = _sp_read(_bad)
        check(f"pairs: a {_why} bundle warns and returns [] rather than "
              f"killing the run", _rows == [] and "[!]" in _out)
    check("pairs: no --swap-pairs at all is silent and unchanged",
          _sp_read(None) == ([], ""))

    # An unreadable quote is COUNTED, not dropped -- a silently deflated target
    # is how a gate reports arrival on a fraction.
    _nan = _sp_bundle("nan.json", [(_SPD, "1.0"), (_SPD, "NaN")])
    _rows, _out = _sp_read(_nan)
    check("pairs: a NaN quote does not kill the read", len(_rows) == 2)
    check("pairs: ...and the operator is told it contributes nothing",
          "contribute NOTHING" in _out)
finally:
    ghost.integrity_log = _sp_saved_il

# THE TWO SIDES MUST AGREE ON THE STRING, or the filter matches nothing and
# every bundle looks like "routed elsewhere" -- which fails SAFE (no target)
# but silently throws the whole feature away.
#
# thor_swap_preparer writes dest_xmr from load_receive_bundle(path)["address"];
# GhostSpiral's ENTRY in receiver mode is load_receive_bundle(path)["address"]
# too. Same loader, same key -- driven here through the real shared loader
# rather than asserted from reading, because "they both use the same key" is
# the kind of claim that stays true right up until one side normalises.
_rb_dir = _sp_tmp.mkdtemp(prefix="gs_bundle_")
_rb_path = _sp_os.path.join(_rb_dir, "wallet_test.json")
with open(_rb_path, "w") as _f:
    _sp_json.dump({"schema": "gs_receive_wallet_v1", "address": _SPD,
                   "account_index": 7, "subaddress_index": 3,
                   "rpc_endpoint": "http://127.0.0.1:18083"}, _f)
from gs_common import load_receive_bundle as _rb_load             # noqa: E402
_rb = _rb_load(_rb_path)
# What thor_swap_preparer puts in dest_xmr...
_thor_dest = _rb["address"]
# ...and what GhostSpiral resolves ENTRY to in receiver mode.
_gs_entry = _rb["address"]
_rb_bundle = _sp_bundle("roundtrip.json", [(_thor_dest, "2.5")])
_rb_saved = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
try:
    _o = io.StringIO()
    with contextlib.redirect_stdout(_o):
        _rb_rows = ghost._receive_pairs_for(
            types.SimpleNamespace(swap_pairs=_rb_bundle), _gs_entry)
finally:
    ghost.integrity_log = _rb_saved
check("pairs: a pairs entry written from a real receive bundle is matched by "
      "the ENTRY that same bundle produces", len(_rb_rows) == 1)
check("pairs: ...and its quote becomes the target",
      ghost.swap_expected_total(_rb_rows)[0] == D("2.5"))

# A FLAG THAT DOES NOTHING MUST SAY SO. Send mode fetches its own quotes and
# takes the target from those, so a bundle handed in there is genuinely unused
# -- and an operator who passed one believes the run is gated by it. This file
# has already shipped two "NO EFFECT" messages that were wrong about their own
# code; a third flag dropped in silence is the same defect with no message at
# all.
_ig_out = io.StringIO()
_ig_saved = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
try:
    _ig_args = types.SimpleNamespace(
        receive_wallet=None, swap_pairs="thor_pairs.json", joinmarket=False,
        btc_entry="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    try:
        with contextlib.redirect_stdout(_ig_out):
            ghost.resolve_entry_mode(_ig_args)
    except SystemExit:
        pass
finally:
    ghost.integrity_log = _ig_saved
check("pairs: --swap-pairs in SEND mode is reported as ignored, not dropped "
      "in silence", "ignored in SEND mode" in _ig_out.getvalue())

# ...and stays quiet when it was not passed.
_ig_out2 = io.StringIO()
_ig_saved = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
try:
    try:
        with contextlib.redirect_stdout(_ig_out2):
            ghost.resolve_entry_mode(types.SimpleNamespace(
                receive_wallet=None, swap_pairs=None, joinmarket=False,
                btc_entry="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
    except SystemExit:
        pass
finally:
    ghost.integrity_log = _ig_saved
check("pairs: ...and says nothing when it was not passed",
      "swap-pairs" not in _ig_out2.getvalue())

# The flag has to exist and reach stage 4's decision.
check("pairs: --swap-pairs is a real flag",
      "--swap-pairs" in (ghost.build_cli().format_help()))
_sp_src = " ".join(_code_only_sa(os.path.join(REPO, "GhostSpiral")).split())
check("pairs: main() fills swap_deposits from the bundle in receive mode",
      "swap_deposits = _receive_pairs_for(args, ENTRY)" in _sp_src)
check("pairs: stage 4 falls back to the quoted sum when no explicit total",
      "else (quoted if quoted > 0 else None)" in _sp_src)
check("pairs: stage 4 feeds the REAL chunk amounts to the receiver gate, "
      "not []",
      "_rtarget, args.swap_tolerance, chunk_amounts, n_chunks" in _sp_src)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
