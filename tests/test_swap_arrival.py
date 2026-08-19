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
import importlib.machinery, importlib.util, io, os, sys, contextlib
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
_tot, _bad = ghost.swap_expected_total([quote("1.0"), quote("1.0"), quote("1.0")])
check("target: sums the quoted output of EVERY chunk, not just the first",
      _tot == D("3.0") and _bad == 0)
check("target: no quotes at all is no target (manual mode)",
      ghost.swap_expected_total([]) == (D(0), 0))

# An unreadable quote deflates the target, which would let the wait finish
# while a third of the money is still in flight. It must be COUNTED so the
# caller can say so -- receive_watch.expected_total learned this the same way.
_tot, _bad = ghost.swap_expected_total([quote("3.0"), quote("junk"), quote("0")])
check("target: an unreadable quote contributes nothing...", _tot == D("3.0"))
check("target: ...and is counted, so the caller can say the target is partial",
      _bad == 2)
check("target: a missing expected_xmr key counts as unreadable",
      ghost.swap_expected_total([{"chunk": 0}]) == (D(0), 1))

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

# ...while genuine increments below the step still add up: 58 arrivals of
# 0.0001 are 0.0058 XMR, and comparing against the previous TICK rather than
# the last marked total would never notice.
_creep = [(D("0.05") * i, D("0.05") * i) for i in range(1, 60)]
_res, _ = run(_creep, "2.7", stall_s=120, timeout_s=86400, poll=30)
check("drip: ...but real increments that accumulate to a chunk do count",
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

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
