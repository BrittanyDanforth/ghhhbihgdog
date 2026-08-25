#!/usr/bin/env python3
"""ENTRY MUST NEVER RECEIVE A HOP.

ENTRY is the address the ThorChain memo names, in plaintext, in a Bitcoin
OP_RETURN -- so anyone who reads the BTC chain has it. build_entry_veil calls
the output sitting on it "THE ONE OUTPUT AN ANALYST GETS FOR FREE", and the
veil's entire premise is that ENTRY is spent ONCE, into a fresh carrier, and
then abandoned. Every transaction after that spends an output no outsider can
enumerate.

The hop graph broke that. `dag` was built over all of `subs`, which contains
ENTRY, and assign_hop_destinations prefers a source's own adjacency
(`dag.get(s, mix_targets)`), falling back to the ENTRY-free `mix_targets` only
when the adjacency is exhausted. So the exclusion was written, and the primary
path went around it: a MIXED output was paid back to the publicly-named address
in roughly nine runs out of ten, at every size measured.

That also made the exit's ENTRY hold fire on the wrong thing. The hold exists
to stop a late swap chunk being swept from ENTRY straight to --exit-to; with
the hop graph feeding ENTRY, what it actually caught, most of the time, was
mixed value that had been sent home.

Driven, not read: these checks build the real adjacency and run the real
assignment. A source grep would pass on a graph that excluded ENTRY from the
keys but not the values.
"""
import importlib.machinery
import importlib.util
import os
import re
import types
import io
import contextlib
import ast as _ast
import secrets
import secrets as _secretsmod
import sys
from decimal import Decimal, ROUND_UP
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

_ld = importlib.machinery.SourceFileLoader("GhostSpiral",
                                           os.path.join(REPO, "GhostSpiral"))
ghost = importlib.util.module_from_spec(
    importlib.util.spec_from_loader(_ld.name, _ld))
_ld.exec_module(ghost)

PASS = 0
FAIL = 0
FAILS = []
import sys as _sys_cg, os as _os_cg
_sys_cg.path.insert(0, _os_cg.path.dirname(_os_cg.path.abspath(__file__)))
from srcutil import fail_loudly_on_crash              # noqa: E402

# ARMED HERE, NOT AT THE END. A crash never reaches the bottom of the file --
# that is what makes it a crash -- so the guard is registered as soon as the
# counters exist. Whatever kills this suite, the RESULT line still prints and
# the crash counts as a failure.
#
# Without it, a mutation that makes the file DIE is scored NO-RESULT by
# mutation_sweep, which its own header says is not a catch. That has already
# turned one genuinely-caught mutation into a recorded survivor, and it has
# hit three separate call sites in this repo. Guarding the outcome beats
# guarding each call.
_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS), "test_dag_entry.py")



def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  ", name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL:", name)


RNG = secrets


def plan(wallets, deep, decoys=3, build=None):
    """One planning run. Returns (ENTRY, mix_targets, dag, assignment)."""
    subs = [f"addr{i:03d}" for i in range(wallets + decoys)]
    entry = subs[0]
    secrets.SystemRandom().shuffle(subs)
    mix_targets = [s for s in subs if s != entry]
    dag = (build or ghost.build_dag_adjacency)(subs, entry, deep, RNG)
    assigned = ghost.assign_hop_destinations(mix_targets, dag, mix_targets, RNG)
    return entry, mix_targets, dag, assigned


def _old_build(subs, entry_addr, deep, rng):
    """The pre-fix adjacency, verbatim: every sub is a candidate, ENTRY too."""
    dag = {}
    for a in subs:
        others = [b for b in subs if b != a]
        max_k = len(others)
        k = min((rng.randbelow(3) + 1) * deep, max_k)
        k = max(k, 1)
        chosen, pool = [], list(others)
        for _ in range(k):
            chosen.append(pool.pop(rng.randbelow(len(pool))))
        dag[a] = chosen
    return dag


SIZES = ((10, 2), (6, 2), (20, 3))
RUNS = 400

print("=== ENTRY never appears in the hop graph ===")
for wallets, deep in SIZES:
    leaked = 0
    for _ in range(RUNS):
        entry, _mt, dag, _asg = plan(wallets, deep)
        if any(entry in dests for dests in dag.values()):
            leaked += 1
    check(f"adjacency: wallets={wallets} deep={deep}: ENTRY is in no "
          f"destination list ({RUNS} runs)", leaked == 0)

print("\n=== ...so no hop is ever ASSIGNED to it ===")
for wallets, deep in SIZES:
    leaked = 0
    for _ in range(RUNS):
        entry, _mt, _dag, assigned = plan(wallets, deep)
        if entry in assigned.values():
            leaked += 1
    check(f"assignment: wallets={wallets} deep={deep}: 0/{RUNS} runs pay a "
          f"hop to ENTRY", leaked == 0)

# NON-VACUITY. The same harness on the PRE-FIX adjacency must show the defect,
# or every check above would pass against a pipeline that never had it -- and
# "all tests green" would again be worth nothing.
print("\n=== control: the pre-fix adjacency really did leak ===")
for wallets, deep in SIZES:
    leaked = 0
    for _ in range(RUNS):
        entry, _mt, _dag, assigned = plan(wallets, deep, build=_old_build)
        if entry in assigned.values():
            leaked += 1
    pct = 100.0 * leaked / RUNS
    check(f"control: wallets={wallets} deep={deep}: the OLD graph paid ENTRY "
          f"in {leaked}/{RUNS} runs ({pct:.1f}%)", leaked > RUNS // 2)

print("\n=== the graph is still a usable graph ===")
for wallets, deep in SIZES:
    entry, mix_targets, dag, assigned = plan(wallets, deep)
    check(f"usable: wallets={wallets} deep={deep}: every mix target still "
          f"gets a destination",
          len(assigned) == len(mix_targets))
    check(f"usable: wallets={wallets} deep={deep}: no destination is used "
          f"twice (the no-merge invariant)",
          len(set(assigned.values())) == len(assigned))
    check(f"usable: wallets={wallets} deep={deep}: nothing hops to itself",
          all(s != d for s, d in assigned.items()))
    check(f"usable: wallets={wallets} deep={deep}: every source has a "
          f"non-empty adjacency",
          all(dag[s] for s in mix_targets))

# The degenerate sizes: two subs (ENTRY + one) leaves ENTRY with no legal
# destination at all. randbelow(0) raises ValueError, so this must return an
# empty adjacency rather than crash a run that has already made the accounts.
_deg = ghost.build_dag_adjacency(["E", "a"], "E", 2, RNG)
# The empty one is "a", not ENTRY: ENTRY may still POINT at things (it is a
# key, just never a funded source), while "a" has nothing legal left once
# ENTRY is excluded. Getting this backwards is what the check caught first.
check("degenerate: the sub whose only neighbour was ENTRY gets an empty "
      "adjacency, not a crash", _deg["a"] == [])
check("degenerate: ...and ENTRY, which may still point outward, keeps one",
      _deg["E"] == ["a"])
_one = ghost.build_dag_adjacency(["E"], "E", 2, RNG)
check("degenerate: a single sub yields an empty adjacency", _one == {"E": []})

# ENTRY may still be a KEY. It is never funded by the fan-out (mix_targets
# excludes it) so it is never a hop source in practice, and dropping the key
# would only make the structure lie about which addresses exist.
_e, _mt, _dag, _asg = plan(10, 2)
check("ENTRY is still present as a source key (it is simply never funded)",
      _e in _dag)
check("...and is not among the sources the assignment was asked to place",
      _e not in _mt)


# ==========================================================================
# G7: THE SWEPT CHANGE DOES NOT HOP, AND NOTHING MAY SAY IT DOES
# ==========================================================================
print("\n=== swept change is not in the hop graph ===")
#
# _run_change_sweep's summary line said "Sweep ONE change location into the
# mix", and two operator messages plus the caller repeated it. The destination
# is a subaddress of an account created moments earlier, so it is not in
# `subs`, not in `mix_targets`, not in `fanout_dests`, not in `hop_sources`,
# and build_dag_adjacency has never heard of it. The swept change moves once
# and rests.
#
# It cannot currently do more: the DAG plan is built and SIGNED before the
# destination exists, and the change amount is not known until the
# distribution has executed and paid its fee, so a hop out of it cannot be
# sized in a pre-signed plan. The defect was the claim, not the behaviour —
# and an operator who believes the remainder went through the mix treats it as
# though it did.
_g7_subs = [f"mix{_i:02d}" for _i in range(12)]
_g7_entry = _g7_subs[0]
_g7_mix = [x for x in _g7_subs if x != _g7_entry]
_g7_fan, _g7_hops = ghost.select_fanout_targets(_g7_mix, set(), 8, 3)
_g7_change = "change_sweep_destination_created_later"

check("G7: the change destination is not a fan-out destination",
      _g7_change not in _g7_fan)
check("G7: ...not a hop source", _g7_change not in _g7_hops)
check("G7: ...not in mix_targets at all", _g7_change not in _g7_mix)
check("G7: ...and the hop graph does not contain it",
      _g7_change not in ghost.build_dag_adjacency(_g7_subs, _g7_entry, 2, RNG))

# Non-vacuity: a REAL mix output is in all of those, so the checks above are
# about this address and not about the harness.
check("control: a real mix output IS a hop source", _g7_mix[1] in _g7_hops)
check("control: ...and is in the hop graph",
      _g7_mix[1] in ghost.build_dag_adjacency(_g7_subs, _g7_entry, 2, RNG))

# THE CLAIM. Adjacent string literals joined first, so a message split across
# source lines is still found — the wrap that made an earlier check report a
# missing warning that was right there.
_g7_src = re.sub(r"\s+", " ", Path(REPO, "GhostSpiral").read_text())
_g7_src = re.sub(r'"\s*f?"', "", _g7_src)
check("G7: nothing claims the change is swept 'into the mix' any more",
      "into the mix" not in _g7_src)
check("G7: ...and the success message says it moves once and rests",
      "moves once and rests" in _g7_src)
check("G7: ...and the docstring states WHY it cannot hop (the plan is "
      "pre-signed and the amount is not known until execution)",
      "BUILT AND SIGNED before this destination exists" in _g7_src)



# ==========================================================================
# G5: THE VEIL'S PREMISE IS ONE INPUT, AND NOTHING CHECKED
# ==========================================================================
print("\n=== the entry veil's input count ===")
#
# build_entry_veil argues its case entirely from transaction SHAPE: a 1-in/2-out
# sweep is "the shape most of the network is making", so the distribution should
# run from the carrier instead of advertising itself as 1-in/7-out. Every word
# of that holds only while ENTRY carries exactly ONE output — sweep_all
# (airgap_tx_signer:442, subaddr_indices=[src_index]) spends them all in one
# transaction, so N outputs means N inputs.
#
# N inputs is worse than the shape it replaced: each ring contains an output the
# public swap memo names, so intersecting them identifies this transaction and
# therefore the carrier. The veil stops being protection and becomes the thing
# that gives the carrier away.
#
# `--split N` guaranteed it (all N chunks to one address) and is refused now.
# What remains is not the operator's doing: a swap settling in several payments,
# a receive address already paid, or ANYONE sending dust to an address the memo
# publishes.


class _XferRPC:
    def __init__(self, transfers, fail=False):
        self._t = transfers
        self._fail = fail

    def raw_request(self, method, params=None):
        if self._fail:
            raise RuntimeError("rpc down")
        if method == "incoming_transfers":
            return {"transfers": self._t}
        return {}

    def new_subaddress_indexed(self, account_index=0, **k):
        # PER ACCOUNT, like a real wallet. A fake that answers with one
        # constant address made three carriers look identical, which hid the
        # fact that nothing verified they were distinct -- see the carrier
        # check in build_entry_veils, which this fixture's honesty produced.
        return ("8" + "A" * 93 + str(account_index % 10), 1)


def _veil_out(transfers, fail=False, n=1):
    _saved = ghost.create_fresh_account
    try:
        _acct = [40]

        def _fresh(rpc, label=""):
            _acct[0] += 1
            return _acct[0]
        ghost.create_fresh_account = _fresh
        buf = io.StringIO()
        entries = [(f"ENTRY{i}", 3 + i, 1) for i in range(n)]
        with contextlib.redirect_stdout(buf):
            ghost.build_entry_veils(_XferRPC(transfers, fail), entries)
        return buf.getvalue()
    finally:
        ghost.create_fresh_account = _saved


_one = [{"amount": 1000, "spent": False}]
_four = [{"amount": 1000, "spent": False} for _ in range(4)]

check("G5: counts outputs, not balance — 4 outputs is 4 inputs",
      ghost.entry_output_count(_XferRPC(_four), 3, 1) == 4)
check("G5: a SPENT output is not an input", ghost.entry_output_count(
    _XferRPC(_four + [{"amount": 9, "spent": True}]), 3, 1) == 4)
check("G5: a zero-amount output is not an input", ghost.entry_output_count(
    _XferRPC(_four + [{"amount": 0, "spent": False}]), 3, 1) == 4)
check("G5: an unreachable RPC returns None, not a guess",
      ghost.entry_output_count(_XferRPC([], fail=True), 3, 1) is None)

check("G5: with ONE output the veil says nothing (its premise holds)",
      _veil_out(_one).strip() == "")
_m = _veil_out(_four)
check("G5: with FOUR it says the veil will be a 4-INPUT transaction",
      "4-INPUT" in _m)
check("G5: ...and that the rings can be intersected to find the carrier",
      "intersect" in _m and "carrier" in _m)

# THE TWO CASES ARE NOT THE SAME, and the message has to say which is which.
# Two publicly-known swap outputs give an analyst two candidate sets to
# intersect; one swap output plus a stranger's dust gives him nothing to
# intersect against. Reporting them identically overstates the second and
# understates the first.
check("G5: ...it names the SERIOUS case — more than one swap on one address",
      "two swaps" in _m or "two payments" in _m)
check("G5: ...and separately the MILD one — dust sent by somebody else",
      "dust" in _m and "milder" in _m)
check("G5: ...and admits it cannot tell them apart from here",
      "tell the two apart" in _m)
_u = _veil_out([], fail=True)
check("G5: an unknown count is reported as unknown, not as fine",
      "not known whether" in _u)

# The veil still WORKS in every case — this reports, it does not block. A run
# that refuses to veil would spend ENTRY directly, which is strictly worse.
_saved_cfa = ghost.create_fresh_account
try:
    ghost.create_fresh_account = lambda rpc, label="": 41
    with contextlib.redirect_stdout(io.StringIO()):
        _plan, _carriers = ghost.build_entry_veils(
            _XferRPC(_four), [("ENTRY", 3, 1)])
    check("G5: ...and the veil is still built (reporting, not blocking)",
          len(_plan) == 1 and _plan[0]["sweep"] is True)
finally:
    ghost.create_fresh_account = _saved_cfa


# ==========================================================================
# G5, THE REAL FIX: one entry address per chunk, and NO CONVERGENCE.
#
# --split N used to be refused because every chunk was routed to one address.
# It is supported now, and what makes it safe is not "the veil has one input"
# but the stronger invariant build_entry_veils states:
#
#     NO TRANSACTION EVER SPENDS VALUE FROM TWO DIFFERENT SWAP CHUNKS.
#
# One input per veil is not sufficient on its own: veil the chunks separately
# into a SHARED carrier and the distribution becomes the convergence instead,
# and the analyst intersects there. So the test is on the whole plan, not on
# the veil.
# ==========================================================================
print("\n=== G5: N chunks, N entries, no convergence ===")


class _EntrySetRPC:
    """A wallet that numbers accounts and addresses like the real one."""

    def __init__(self):
        self.acct = 0
        self.made = []

    def raw_request(self, method, params=None):
        if method == "create_account":
            self.acct += 1
            self.made.append(self.acct)
            return {"account_index": self.acct}
        if method == "incoming_transfers":
            return {"transfers": [{"amount": 1000, "spent": False}]}
        raise AssertionError(method)

    def new_subaddress_indexed(self, account_index=0, label=""):
        return (f"ADDR_{account_index}", 1)


_es = ghost.create_entry_set(_EntrySetRPC(), 4)
check("split: --split 4 mints FOUR entry addresses", len(_es) == 4)
check("split: ...all distinct", len({a for a, _, _ in _es}) == 4)
check("split: ...each in its OWN account, so no transaction can spend two",
      len({c for _, c, _ in _es}) == 4)
check("split: ...and none of them is account 0 (the wallet's primary)",
      all(c != 0 for _, c, _ in _es))


class _DupEntryRPC(_EntrySetRPC):
    def new_subaddress_indexed(self, account_index=0, label=""):
        return ("SAME", 1)


_dup = None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        ghost.create_entry_set(_DupEntryRPC(), 3)
except SystemExit as _e:
    _dup = str(_e.code)
check("split: a wallet handing out the same entry address twice is REFUSED",
      _dup is not None)
check("split: ...and the refusal says what it would have cost",
      _dup and "linkage" in _dup)


class _DupAcctRPC(_EntrySetRPC):
    def raw_request(self, method, params=None):
        if method == "create_account":
            return {"account_index": 7}
        return super().raw_request(method, params)

    def new_subaddress_indexed(self, account_index=0, label=""):
        _DupAcctRPC._n = getattr(_DupAcctRPC, "_n", 0) + 1
        return (f"A{_DupAcctRPC._n}", 1)


_dupa = None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        ghost.create_entry_set(_DupAcctRPC(), 3)
except SystemExit as _e:
    _dupa = str(_e.code)
check("split: two entries in ONE account is REFUSED — a transaction CAN "
      "spend two subaddresses of one account", _dupa is not None)

# -- N veils, N carriers, and never a shared one ---------------------------
_saved_cfa = ghost.create_fresh_account
try:
    _c = [50]

    def _fresh2(rpc, label=""):
        _c[0] += 1
        return _c[0]
    ghost.create_fresh_account = _fresh2
    with contextlib.redirect_stdout(io.StringIO()):
        _vplan, _vcar = ghost.build_entry_veils(
            _XferRPC(_one), [("E0", 10, 1), ("E1", 11, 1), ("E2", 12, 1)])
finally:
    ghost.create_fresh_account = _saved_cfa

check("split: three entries produce THREE veil transactions", len(_vplan) == 3)
check("split: each veil spends exactly ONE entry, naming its own account",
      [(t["src"], t["account_index"], t["src_index"]) for t in _vplan]
      == [("E0", 10, 1), ("E1", 11, 1), ("E2", 12, 1)])
check("split: every veil is a sweep (whole balance, zero change)",
      all(t.get("sweep") is True for t in _vplan))
check("split: THREE SEPARATE CARRIERS — a shared one would just move the "
      "convergence to the distribution, where the same intersection works",
      len({a for a, _, _ in _vcar}) == 3
      and len({d for _, _, d in _vcar}) == 3)
# THE VEILS ARE NOT A TIMING CLUSTER, and they never were.
#
# This briefly widened the delay window in proportion to the chunk count, to
# stop "N veils landing inside the window meant for one". Reading
# broadcast_signed_xmr killed that premise: it relays a plan file with one
# `for item in items:` loop that SLEEPS item.delay before each submit, so the
# delays are CUMULATIVE. N veils already span N full gaps. The widening also
# scaled the round as N-squared -- measured at N=8, 1.0h became 6.6h -- for a
# property already held. Reverted; this pins that it stays reverted.
_sv2 = _saved_cfa
try:
    _cc2 = [80]

    def _f5(rpc, label=""):
        _cc2[0] += 1
        return _cc2[0]
    ghost.create_fresh_account = _f5
    _delays = []
    for _t in range(80):
        with contextlib.redirect_stdout(io.StringIO()):
            _pl, _ = ghost.build_entry_veils(
                _XferRPC(_one), [("E0", 10, 1), ("E1", 11, 1), ("E2", 12, 1)])
        _delays += [t["delay"] for t in _pl]
finally:
    ghost.create_fresh_account = _sv2
_lo, _hi = ghost.DEFAULT_HOP_DELAY
check("split: every veil delay stays inside the ORDINARY --hop-delay window, "
      "however many chunks there are — the relay loop is sequential, so N "
      "veils already span N gaps",
      _delays and all(_lo <= d <= _hi for d in _delays))
check("split: ...and the window is not silently multiplied by the chunk count "
      "(which scaled the round as N-squared, 1.0h to 6.6h at N=8)",
      max(_delays) <= _hi)
check("split: ...the delays are still jittered, not a constant",
      len(set(_delays)) > 3)


# ==========================================================================
# HOW LONG THE RUN WILL TAKE, SAID BEFORE IT STARTS.
#
# --dag-mixing's help promised "a run takes ~20+ min longer", counting only
# the on-chain confirmation wait. The DAG round relays ONE transaction per
# funded output and broadcast_signed_xmr sleeps that transaction's --hop-delay
# before each submit, sequentially -- so with the defaults it is about two and
# a half HOURS, not twenty minutes.
#
# An operator told "20 minutes" who sees two hours of silence concludes the
# run has hung and interrupts it, and an interrupt mid-round is the one
# failure this pipeline cannot recover from automatically.
# ==========================================================================
print("\n=== the runtime estimate ===")

_A = types.SimpleNamespace
_plain = _A(peel=False, dag_mixing=False, exit_to=None)
_dag = _A(peel=False, dag_mixing=True, exit_to=None)
_dagexit = _A(peel=False, dag_mixing=True, exit_to=["x"])


def _mins(s):
    """Parse the estimate back into minutes."""
    return (float(s.strip("~h")) * 60 if s.endswith("h")
            else float(s.split()[0].lstrip("~")))


check("runtime: --dag-mixing is estimated in HOURS, not the ~20 minutes the "
      "help used to claim",
      _mins(ghost.estimate_runtime(_dag, 1, 15, None)) > 120)
check("runtime: ...and it is the DELAYS that dominate, so it scales with the "
      "number of mix outputs",
      _mins(ghost.estimate_runtime(_dag, 1, 30, None))
      > _mins(ghost.estimate_runtime(_dag, 1, 15, None)) * 1.5)
check("runtime: a plain run (no dag, no exit) is much shorter",
      _mins(ghost.estimate_runtime(_plain, 1, 15, None))
      < _mins(ghost.estimate_runtime(_dag, 1, 15, None)) / 3)
check("runtime: --exit-to adds one delayed withdrawal per output",
      _mins(ghost.estimate_runtime(_dagexit, 1, 15, None))
      > _mins(ghost.estimate_runtime(_dag, 1, 15, None)))
check("runtime: more chunks means more veils and more fan-outs",
      _mins(ghost.estimate_runtime(_dag, 8, 15, None))
      > _mins(ghost.estimate_runtime(_dag, 1, 15, None)))
check("runtime: a longer --hop-delay makes the estimate longer — it is not a "
      "constant",
      _mins(ghost.estimate_runtime(_dag, 1, 15, (3600, 7200)))
      > _mins(ghost.estimate_runtime(_dag, 1, 15, None)) * 4)

# THE COUNT, AGAINST TWO MEASURED RUNS. The estimate is only as honest as the
# number of delayed transactions behind it, and that number was wrong: the
# change sweeps were not counted at all, and the exit was counted as
# mix_outputs when it withdraws the mix outputs AND the change-sweep
# destinations. On a full --peel --dag-mixing run with one chunk and seven mix
# outputs the chain recorded 36 sends; the old terms summed to 22.
_MEAN = (Decimal(180) + Decimal(720)) / 2
_CONF = Decimal(ghost.FANOUT_CONFIRM_POLL_ESTIMATE)
_peelexit = _A(peel=True, dag_mixing=True, exit_to=["x"])
# 22, NOT 36. The measured 36-transaction run was veil 1 + peels 7 + hops 7 +
# change sweeps 7 + exits 14. The peel leaves no change now (it consumes each
# carrier exactly and the last hop sweeps), so the 7 change sweeps are gone and
# the exit has 7 fewer destinations to withdraw: veil 1 + peels 7 + hops 7 +
# exits 7.
check("runtime: a zero-change peel+DAG+exit run of 7 outputs is 22 delayed "
      "transactions, down from the 36 the chain recorded before",
      ghost._runtime_terms(_peelexit, 1, 7, _MEAN, _CONF)[1] == 22)
_fanexit = _A(peel=False, dag_mixing=False, exit_to=["x"])
check("runtime: ...and a fan-out run of 7 outputs is 11, likewise measured",
      ghost._runtime_terms(_fanexit, 1, 7, _MEAN, _CONF)[1] == 11)
# The two phases that were missing, isolated.
check("runtime: a peel run has NO change sweeps to count",
      ghost._runtime_terms(_A(peel=True, dag_mixing=False, exit_to=None),
                           1, 7, _MEAN, _CONF)[1] == 1 + 7)
check("runtime: ...and one per chunk otherwise",
      ghost._runtime_terms(_A(peel=False, dag_mixing=False, exit_to=None),
                           1, 7, _MEAN, _CONF)[1] == 1 + 1 + 1)
check("runtime: the exit withdraws one output per mix subaddress and nothing "
      "else, because a peel run leaves no change destinations",
      ghost._runtime_terms(_peelexit, 1, 7, _MEAN, _CONF)[1]
      - ghost._runtime_terms(_A(peel=True, dag_mixing=True, exit_to=None),
                             1, 7, _MEAN, _CONF)[1] == 7)
# ...and a FAN-OUT still has its one change location, so the exit is
# mix_outputs + 1 there. The two shapes must not be conflated.
check("runtime: a fan-out still has its change sweep and its extra withdrawal",
      ghost._runtime_terms(_A(peel=False, dag_mixing=False, exit_to=["x"]),
                           1, 7, _MEAN, _CONF)[1] == 1 + 1 + 1 + 8)
# A run measured in weeks must not be reported as "~900.0h".
check("runtime: a very long run is reported in days, not three-digit hours",
      "day" in ghost.estimate_runtime(_peelexit, 1, 12, (21600, 86400)))
check("runtime: ...and a short one is still minutes",
      "min" in ghost.estimate_runtime(
          _A(peel=False, dag_mixing=False, exit_to=None), 1, 1, (1, 2)))
check("runtime: --peel is estimated as sequential confirmation-gated hops",
      _mins(ghost.estimate_runtime(_A(peel=True, dag_mixing=False,
                                      exit_to=None), 1, 7, None)) > 120)

# ...and the help no longer makes the claim that was wrong.
_help = open(os.path.join(REPO, "GhostSpiral")).read()
_dagh = _help[_help.index('"--dag-mixing"'):]
_dagh = _dagh[:_dagh.index("cli.add_argument", 10)]
check("runtime: the --dag-mixing help no longer says '~20+ min longer'",
      "20+ min longer" not in _dagh)
check("runtime: ...and says what actually dominates",
      "hop-delay" in _dagh.lower() and "HOURS" in _dagh)

check("split: no veil pays a carrier another veil also pays",
      len({t["dst"] for t in _vplan}) == 3)

# ...and that is ENFORCED, not merely true of this fixture. A wallet that
# handed out one carrier address twice would merge two chunks into one output
# and nothing downstream would notice: the distribution would see one funded
# source instead of two and the run would report success.
class _OneCarrierRPC(_XferRPC):
    def new_subaddress_indexed(self, account_index=0, **k):
        return ("8" + "C" * 94, 1)


_merged = None
_saved_cfa2 = ghost.create_fresh_account
try:
    _c2 = [60]

    def _fresh3(rpc, label=""):
        _c2[0] += 1
        return _c2[0]
    ghost.create_fresh_account = _fresh3
    with contextlib.redirect_stdout(io.StringIO()):
        ghost.build_entry_veils(_OneCarrierRPC(_one),
                                [("E0", 10, 1), ("E1", 11, 1)])
except SystemExit as _e:
    _merged = str(_e.code)
finally:
    ghost.create_fresh_account = _saved_cfa2
check("split: two veils paying ONE carrier is REFUSED, not silently merged",
      _merged is not None)
check("split: ...and the refusal names it as the convergence it is",
      _merged and "convergence" in _merged)

# THE SAME CHECK, ON THE TWO LOOPS THAT DID NOT MAKE IT.
#
# create_fresh_account validates the SHAPE of one answer and has no memory
# across calls, so nothing in it can notice a wallet handing back an index it
# already gave. Three loops close that themselves -- create_subs,
# create_entry_set and build_entry_veils, each aborting with a message naming
# the merge. Two minted the same way from the same RPC and never looked.


class _DupTargetRPC:
    """A wallet that hands back the SAME subaddress every time."""

    def __init__(self, dup_addr=True, dup_acct=False):
        self.n = 200
        self.dup_addr = dup_addr
        self.dup_acct = dup_acct

    def raw_request(self, method, params=None):
        if method == "create_account":
            if self.dup_acct:
                return {"account_index": 777}
            self.n += 1
            return {"account_index": self.n}
        raise AssertionError(method)

    def new_subaddress_indexed(self, account_index=0, label=""):
        if self.dup_addr:
            return ("SHARED_TARGET", 1)
        return (f"T{account_index}", 1)


# --- change-sweep destinations -------------------------------------------
# Each change location holds ONE chunk's distribution remainder, so two jobs
# sharing a destination put two swap chunks on one address -- and the exit
# sweeps a subaddress in ONE transaction, spending both together. Before this
# check, three jobs came back all pointing at the same address, silently.
for _lbl, _rpc in [("address", _DupTargetRPC(dup_addr=True)),
                   ("account", _DupTargetRPC(dup_addr=False, dup_acct=True))]:
    _csdup = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.build_change_sweep_jobs(_rpc, {}, [11, 22, 33])
    except SystemExit as _e:
        _csdup = str(_e.code)
    check(f"changesweep: a wallet reusing one {_lbl} for two change sweep "
          f"destinations is REFUSED", _csdup is not None)
    check(f"changesweep: ...and the refusal ({_lbl}) says it would merge two "
          f"chunks the exit then spends together",
          _csdup and "two chunks" in _csdup and "ONE" in _csdup)

_csok = None
with contextlib.redirect_stdout(io.StringIO()):
    _csok = ghost.build_change_sweep_jobs(
        _DupTargetRPC(dup_addr=False), {}, [11, 22, 33])
check("control: distinct change-sweep destinations are accepted",
      len(_csok) == 3 and len({j[2] for j in _csok}) == 3)

# --- peel carriers and hop accounts --------------------------------------
# build_peel_stage_plan's own docstring dies twice on a duplicate: ROTATING
# CARRIERS ("no address is ever spent twice") and ONE ACCOUNT PER HOP (two
# peels' change on one subaddress 0 makes the collecting sweep a 2-input
# transaction). Measured before the check: a duplicate address gave 4 peels
# spending only 2 distinct sources; a duplicate account gave 4 peels with 2
# change accounts.
_PD = [f"P{i}" for i in range(4)]
_PBY = {a: Decimal("1") for a in _PD}
for _lbl, _rpc in [("carrier address", _DupTargetRPC(dup_addr=True)),
                   ("hop account", _DupTargetRPC(dup_addr=False, dup_acct=True))]:
    _pdup = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.build_peel_stage_plan(_rpc, {}, 9, "PENTRY", 1, _PD, _PBY,
                                        Decimal("0.0024"), delay_window=(0, 0))
    except SystemExit as _e:
        _pdup = str(_e.code)
    check(f"peel: a wallet reusing one {_lbl} across hops is REFUSED",
          _pdup is not None)
    check(f"peel: ...and the refusal ({_lbl}) names BOTH costs — the "
          f"twice-spent address and the 2-input change sweep",
          _pdup and "twice" in _pdup and "2-input" in _pdup)

_pai = {}
with contextlib.redirect_stdout(io.StringIO()):
    _pok, _paccts = ghost.build_peel_stage_plan(
        _DupTargetRPC(dup_addr=False), _pai, 9, "PENTRY", 1, _PD, _PBY,
        Decimal("0.0024"), delay_window=(0, 0))
check("control: distinct peel carriers are accepted",
      len(_pok) == 4 and len({t["src"] for t in _pok}) == 4)
# NO CHANGE ACCOUNTS. The hops each still run in their own account -- that is
# what the duplicate check above enforces -- but none of them ends up holding
# change, so the run mints no sweep destinations and issues no sweeps.
check("control: ...and a zero-change chain reports no change locations",
      _paccts == [])
check("control: ...while every carrier is still registered for the exit to "
      "look at, in case a fee moves between the signer's two build passes",
      all(t["consume_to"] in _pai for t in _pok[:-1]))

# -- the distribution is N transactions, one per carrier -------------------
_VA2 = types.SimpleNamespace


def _dist(sources, slices, by_addr, peel=False, bal=None, usable=None):
    """Drive the real planner. bal/usable are REQUIRED by the planner now --
    the peel branch runs the affordability gate with them, and defaulting them
    to None is what let that gate be skipped. Default here to a balance that
    comfortably covers these tiny fixtures, so the fan-out cases read as before
    and the peel cases exercise the gate rather than trip over it."""
    _args = _VA2(peel=peel, dag_mixing=False)
    _ai = {a: (c, i) for a, c, i in sources}
    _tot = sum(by_addr.values(), Decimal(0))
    _bal = bal if bal is not None else _tot * Decimal("50") + Decimal("10")
    _use = usable if usable is not None else _bal * Decimal("0.9")
    with contextlib.redirect_stdout(io.StringIO()):
        _r = ghost.build_distribution_plan(
            _args, None, _ai, sources, [d for sl in slices for d in sl],
            by_addr, slices, Decimal("0.0024"), sources[0][1],
            sum(len(sl) for sl in slices), (0, 0), _secretsmod, _bal, _use)
        # (plan, change_accounts, mode) -- the 4th element is the amounts the
        # planner actually used, checked separately below.
        return _r[:3]


_SRC = [("C0", 20, 1), ("C1", 21, 1), ("C2", 22, 1)]
_SLICES = [["m0", "m1"], ["m2", "m3"], ["m4", "m5"]]
_BY = {f"m{i}": Decimal("1") for i in range(6)}
_plan, _chg, _mode = _dist(_SRC, _SLICES, _BY)
check("split: the distribution is THREE transactions, one per chunk",
      len(_plan) == 3 and _mode == "fanout")
check("split: each spends its OWN carrier",
      [t["src"] for t in _plan] == ["C0", "C1", "C2"])
check("split: ...naming that carrier's own account, not a shared one",
      [t["account_index"] for t in _plan] == [20, 21, 22])
check("split: each fan-out pays only ITS slice of the mix targets",
      [[d["address"] for d in t["destinations"]] for t in _plan] == _SLICES)

# THE INVARIANT, checked on the plan as a whole rather than tx by tx: trace
# every destination back to the chunk that funded it and confirm no two chunks
# ever meet in one transaction.
_owner = {}
for _i, _t in enumerate(_plan):
    for _d in _t["destinations"]:
        _owner.setdefault(_d["address"], set()).add(_i)
check("split: NO mix subaddress is funded by two different chunks — the "
      "invariant, checked over the whole plan",
      all(len(v) == 1 for v in _owner.values()))
check("split: every change location is its own carrier's account, so no "
      "change sweep merges two chunks either",
      sorted(_chg) == [20, 21, 22])

# CONTROL: with one chunk this is exactly the old single fan-out.
_p1, _c1, _m1 = _dist([("C0", 20, 1)], [["m0", "m1", "m2"]],
                      {f"m{i}": Decimal("1") for i in range(3)})
check("control: ONE chunk is still ONE fan-out transaction", len(_p1) == 1)
check("control: ...over all of the targets", 
      [d["address"] for d in _p1[0]["destinations"]] == ["m0", "m1", "m2"])
check("control: ...with one change location", _c1 == [20])

# -- --split with --peel is refused, and says why --------------------------
# AT PARSE TIME, which is the whole point: refusing this at the distribution
# means refusing after the quotes are fetched and the deposit instructions
# printed — possibly after the operator has already sent Bitcoin, at which
# point "refused" means their money is mid-swap with no run to receive it.
_early = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=3, peel=True))
except SystemExit as _e:
    _early = str(_e.code)
check("split: --split with --peel is refused at FLAG-PARSE time, before any "
      "quote is fetched or any BTC is sent", _early is not None)
check("split: ...naming the convergence as the reason", _early and "convergence" in _early)
check("split: ...and the time cost of N sequential chains",
      _early and "20 minutes" in _early)
_ok_peel = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=1, peel=True))
except SystemExit as _e:
    _ok_peel = str(_e.code)
check("control: --peel with ONE chunk is not refused", _ok_peel is None)
_ok_split = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=3, peel=False))
except SystemExit as _e:
    _ok_split = str(_e.code)
check("control: --split without --peel is not refused", _ok_split is None)

# ...and the distribution keeps its own backstop for a caller that gets there
# another way.
_peel_msg = None
try:
    _dist(_SRC, _SLICES, _BY, peel=True)
except SystemExit as _e:
    _peel_msg = str(_e.code)
check("split: the distribution still refuses it as a backstop",
      _peel_msg is not None)
check("split: ...because merging the chains would re-create the convergence",
      _peel_msg and "convergence" in _peel_msg)
check("split: ...and N sequential chains is the time cost, stated",
      _peel_msg and "20 minutes" in _peel_msg)
check("control: ONE chunk with --peel is NOT refused by that check",
      "convergence" not in str(
          (lambda: [_dist([("C0", 20, 1)], [["m0"]], {"m0": Decimal("1")},
                          peel=True)] and "")() or ""))

# -- ...AND THE OTHER DOOR INTO THE SAME REFUSAL --------------------------
#
# The parse-time gate above reads --split. The chunk count is not --split: it
# is planned_chunk_count, whose first line is "JoinMarket first, because when
# it ran its UTXOs ARE the chunks and --split is not consulted". So
# `--peel --joinmarket` with a tumbler that produced two or more UTXOs walked
# past resolve_split and landed on the stage-4 backstop -- after the tumble,
# after the entry set, after the quotes, after the deposit instructions and
# after the swap had arrived, which is precisely the situation the comment
# above says the early gate exists to prevent. The message it landed on read
# "--split 3 with --peel is not supported" and told the operator to "use
# --split with the fan-out distribution", naming a flag they never passed.
_jm_args = types.SimpleNamespace(split=1, peel=True, joinmarket=True)
_jm_msg = None
_jm_buf = io.StringIO()
with contextlib.redirect_stdout(_jm_buf):
    try:
        ghost.refuse_peel_multichunk(_jm_args, [Decimal("0.1")] * 3)
    except SystemExit as _e:
        _jm_msg = str(_e.code)
check("split: --peel with a MULTI-UTXO JoinMarket tumble is refused, even "
      "though --split is 1", _jm_msg is not None)
check("split: ...naming JoinMarket's UTXOs rather than a --split the "
      "operator never passed",
      _jm_msg and "JoinMarket" in _jm_msg.splitlines()[0]
      and "--split" not in _jm_msg.splitlines()[0])
check("split: ...and saying the swap has NOT happened, which is the whole "
      "value of refusing here",
      _jm_msg and "NOTHING HAS BEEN SWAPPED" in _jm_msg)
check("split: ...still naming the convergence and the time cost",
      _jm_msg and "convergence" in _jm_msg and "20 minutes" in _jm_msg)

# The controls: one chunk is the supported shape, and no --peel means the
# chunk count is none of this gate's business.
_jm_ctrl = []
for _lbl, _a, _u in (
        ("one JoinMarket UTXO", types.SimpleNamespace(split=1, peel=True,
                                                      joinmarket=True),
         [Decimal("0.1")]),
        ("no JoinMarket at all", types.SimpleNamespace(split=1, peel=True,
                                                       joinmarket=False), []),
        ("three chunks without --peel",
         types.SimpleNamespace(split=1, peel=False, joinmarket=True),
         [Decimal("0.1")] * 3)):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.refuse_peel_multichunk(_a, _u)
        _jm_ctrl.append(None)
    except SystemExit as _e:
        _jm_ctrl.append(f"{_lbl}: {_e.code}")
check("control: the gate refuses none of the supported shapes",
      _jm_ctrl == [None, None, None])

# AND IT HAS TO BE CALLED BEFORE THE SWAP. Nothing executes main(), so the
# ordering is asserted against its source: the gate must appear before the
# entry set is minted and before the quotes are fetched, or it is the stage-4
# backstop again under a new name.
_pm_tree = _ast.parse(Path(REPO, "GhostSpiral").read_text())
_pm_main = [n for n in _pm_tree.body
            if isinstance(n, _ast.FunctionDef) and n.name == "main"]
_pm_lines = {}
for _n in _ast.walk(_pm_main[0] if _pm_main else _ast.Module(body=[],
                                                             type_ignores=[])):
    if isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name):
        _pm_lines.setdefault(_n.func.id, _n.lineno)
check("split: main() calls refuse_peel_multichunk at all",
      "refuse_peel_multichunk" in _pm_lines)
check("split: ...after stage1_joinmarket, which is where the UTXO count "
      "becomes known",
      _pm_lines.get("refuse_peel_multichunk", 0)
      > _pm_lines.get("stage1_joinmarket", 10 ** 9))
check("split: ...and BEFORE the entry set is minted",
      _pm_lines.get("refuse_peel_multichunk", 10 ** 9)
      < _pm_lines.get("establish_entry_set", 0))
check("split: ...and before stage 2 runs at all",
      _pm_lines.get("refuse_peel_multichunk", 10 ** 9)
      < _pm_lines.get("resolve_swap_deposits", 0))

# -- AND THE FEE'S HALF OF EXACTLY THE SAME GATE --------------------------
#
# _refuse_fee_combinations refuses `--usage-fee --split N` at parse time, and
# its reason is entirely about the CHUNK COUNT: "the spendability floor is
# checked against the TOTAL while the operator receives N separate outputs --
# each of which can be individually below the fee to move it, which is the
# exact uncollectable output the floor exists to prevent." It reads args.split.
# The chunk count is not args.split, for the same reason the peel gate above
# had to be added -- and the fee's half was never added. Driven through the
# shipped functions with a tumble of three UTXOs and --split at its default:
# planned_chunk_count -> 3, and the fee gate passed.
_fee_args = types.SimpleNamespace(split=1, peel=False, joinmarket=True,
                                  usage_fee=True,
                                  usage_fee_pct=Decimal("0.011"))
_fee_msg = None
with contextlib.redirect_stdout(io.StringIO()):
    try:
        ghost.refuse_fee_multichunk(_fee_args, [Decimal("0.1")] * 3)
    except SystemExit as _e:
        _fee_msg = str(_e.code)
check("fee: --usage-fee with a MULTI-UTXO JoinMarket tumble is refused, even "
      "though --split is 1", _fee_msg is not None)
check("fee: ...naming JoinMarket's UTXOs rather than a --split the operator "
      "never passed",
      _fee_msg and "JoinMarket" in _fee_msg.splitlines()[0]
      and "--split" not in _fee_msg.splitlines()[0])
check("fee: ...and saying the swap has NOT happened",
      _fee_msg and "NOTHING HAS BEEN SWAPPED" in _fee_msg)
check("fee: ...still naming the reason the parse-time gate gives — an output "
      "per chunk, each possibly worth less than the fee to move it",
      _fee_msg and "one output per chunk" in _fee_msg)

# The controls, matching the peel gate's: one chunk is the supported shape,
# and no --usage-fee makes the chunk count none of this gate's business.
_fee_ctrl = []
for _lbl, _a, _u in (
        ("one JoinMarket UTXO",
         types.SimpleNamespace(split=1, peel=False, usage_fee=True,
                               usage_fee_pct=Decimal("0.011")),
         [Decimal("0.1")]),
        ("no JoinMarket at all",
         types.SimpleNamespace(split=1, peel=False, usage_fee=True,
                               usage_fee_pct=Decimal("0.011")), []),
        ("three chunks with no usage fee",
         types.SimpleNamespace(split=1, peel=False, usage_fee=False,
                               usage_fee_pct=None),
         [Decimal("0.1")] * 3)):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.refuse_fee_multichunk(_a, _u)
        _fee_ctrl.append(None)
    except SystemExit as _e:
        _fee_ctrl.append(f"{_lbl}: {_e.code}")
check("control: the fee gate refuses none of the supported shapes",
      _fee_ctrl == [None, None, None])

check("fee: main() calls refuse_fee_multichunk at all",
      "refuse_fee_multichunk" in _pm_lines)
check("fee: ...after stage1_joinmarket, which is where the UTXO count "
      "becomes known",
      _pm_lines.get("refuse_fee_multichunk", 0)
      > _pm_lines.get("stage1_joinmarket", 10 ** 9))
check("fee: ...and BEFORE the entry set is minted",
      _pm_lines.get("refuse_fee_multichunk", 10 ** 9)
      < _pm_lines.get("establish_entry_set", 0))
check("fee: ...and before stage 2 runs at all",
      _pm_lines.get("refuse_fee_multichunk", 10 ** 9)
      < _pm_lines.get("resolve_swap_deposits", 0))
# ...and it asks planned_chunk_count rather than re-deriving the count, so
# this gate and the entry set cannot answer differently.
_fee_src = Path(REPO, "GhostSpiral").read_text().split(
    "def refuse_fee_multichunk")[1].split("\ndef ")[0]
check("fee: the gate asks planned_chunk_count rather than re-deriving it",
      "planned_chunk_count(args, jm_utxos)" in _fee_src)

# -- FEWER MIX OUTPUTS THAN CHUNKS, refused before the swap too -----------
#
# split_by_weight returns an EMPTY slice for every chunk it has no destination
# left for, and stage 4 answers that with sys.exit: "N swap chunk(s) would have
# no mix subaddress to distribute into ... Use more --wallets, or fewer --split
# chunks." Both are flags, and the counts they decide are known one screen
# after create_subs draws the decoys -- but that exit is reached only after
# stage4_await_swap has watched the XMR land, so the operator is told to change
# a flag with the money already on entry addresses a public memo names.
#
# --wallets 3 --split 8 reaches it whenever the random decoy draw is low:
# fanout_count is wallets + decoys, so 3 + 2 = 5 destinations for 8 chunks.
_tm_sl = ghost.split_by_weight([f"m{_i}" for _i in range(5)], [Decimal(1)] * 8)
check("split: control — split_by_weight really does leave chunks with no "
      "destination", sum(1 for _x in _tm_sl if not _x) == 3)


def _thin(n_subs, wallets, decoys, chunks):
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            ghost.refuse_thin_mix([f"m{_i}" for _i in range(n_subs)],
                                  [f"e{_i}" for _i in range(chunks)],
                                  set(), wallets, decoys, chunks)
            return None
        except SystemExit as _e:
            return str(_e.code)


_tm_msg = _thin(5, 3, 2, 8)
check("split: 8 chunks into 5 mix subaddresses is refused before the swap",
      _tm_msg is not None)
check("split: ...naming both counts, so the operator can see the arithmetic",
      _tm_msg and "8 swap chunks" in _tm_msg and "only 5 mix" in _tm_msg)
check("split: ...and saying the swap has NOT happened",
      _tm_msg and "NOTHING HAS BEEN SWAPPED" in _tm_msg)
check("split: ...with a remedy that is a flag, not a recovery procedure",
      _tm_msg and "--wallets 8 or more" in _tm_msg)

# EXACT, not conservative: the decoys are already drawn when this runs, so a
# high draw that DOES fit must not be refused. Refusing it would deny a shape
# that works, which is the failure mode a bound would have.
check("control: the same flags with a HIGH decoy draw are not refused",
      _thin(10, 3, 7, 8) is None)
check("control: the default shape is not refused", _thin(17, 10, 7, 8) is None)
check("control: one chunk is never refused, however thin the mix",
      _thin(5, 3, 2, 1) is None)
# It must ask select_fanout_targets rather than count `subs`, or it disagrees
# with stage 4 the moment either changes: 20 subs but --wallets 2 + 3 decoys is
# 5 fan-out destinations, not 20.
check("split: the count comes from select_fanout_targets, not from len(subs)",
      _thin(20, 2, 3, 8) is not None)

_pm_lines2 = {}
for _n in _ast.walk(_pm_main[0]):
    if isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name):
        _pm_lines2.setdefault(_n.func.id, _n.lineno)
check("split: main() calls refuse_thin_mix", "refuse_thin_mix" in _pm_lines2)
check("split: ...after create_subs and establish_entry_set, which is what "
      "makes both counts exact",
      _pm_lines2.get("refuse_thin_mix", 0) > _pm_lines2.get("create_subs", 10 ** 9)
      and _pm_lines2.get("refuse_thin_mix", 0)
      > _pm_lines2.get("establish_entry_set", 10 ** 9))
check("split: ...and before stage 2 runs at all",
      _pm_lines2.get("refuse_thin_mix", 10 ** 9)
      < _pm_lines2.get("resolve_swap_deposits", 0))

# ...and "stage 2" has to still MEAN the quotes and the deposit instructions,
# or both orderings above are satisfied by a call that does neither. Asserted
# against resolve_swap_deposits itself rather than trusting the name: the two
# gates were written against a main() that inlined this, and a move is exactly
# what turns an ordering check into a check on nothing.
_rsd = [n for n in _pm_tree.body
        if isinstance(n, _ast.FunctionDef) and n.name == "resolve_swap_deposits"]
_rsd_calls = {n.func.id for n in _ast.walk(_rsd[0])
              if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)} \
    if _rsd else set()
check("split: ...and stage 2 is what fetches the quotes and prints the "
      "deposit instructions",
      {"stage2_get_swap_quotes", "print_sender_instructions"} <= _rsd_calls)
check("split: ...and main() no longer does either itself",
      "stage2_get_swap_quotes" not in _pm_lines2
      and "print_sender_instructions" not in _pm_lines2)


# ==========================================================================
# STAGE 2 EXECUTION, NOW THAT IT IS CALLABLE.
#
# resolve_swap_deposits was 86 lines inline in main(), so none of its
# branching had ever been executed by a test -- including two guards that
# refuse before any BTC is sent. It is the code that decides how much BTC goes
# to how many swaps and WHICH ENTRY ADDRESS each one names, which is the
# binding the whole --split invariant rests on.
# ==========================================================================
print("\n== stage 2 execution: chunks, quotes and the entry binding ==")

_S2A = [f"8{_c * 94}" for _c in "XYZ"]
_S2SET = [(_a, 30 + _i, 1) for _i, _a in enumerate(_S2A)]


def _dep(i, dest):
    """The shape stage2_get_swap_quotes really returns -- every key
    print_sender_instructions and swap_expected_total read."""
    return {"chunk": i, "btc_amount": "0.1", "deposit_address": "bc1qdeposit",
            "memo": "=:XMR.XMR:x", "expected_xmr": "1.0", "quote_id": "q",
            "xmr_dest": dest}


def _s2(args, jm=(), receive=False, quotes=None, pairs=None):
    """Drive the real resolve_swap_deposits; only the network edges are stubbed."""
    _sv = (ghost.stage2_get_swap_quotes, ghost._receive_pairs_for,
           ghost.integrity_log)
    _seen = {}

    def _q(a, proxy, chunks, dests):
        _seen["chunks"] = list(chunks)
        _seen["dests"] = list(dests)
        return (quotes if quotes is not None else
                [_dep(_i, d) for _i, d in enumerate(dests)])

    try:
        ghost.stage2_get_swap_quotes = _q
        ghost._receive_pairs_for = lambda a, e: (pairs if pairs is not None
                                                 else [{"xmr_dest": e}])
        ghost.integrity_log = lambda *a, **k: None
        _b = io.StringIO()
        with contextlib.redirect_stdout(_b):
            try:
                _r = ghost.resolve_swap_deposits(args, {"http": "x"}, list(jm),
                                                 receive, _S2A[0], _S2A, _S2SET)
                return _r, _b.getvalue(), None, _seen
            except SystemExit as _e:
                return None, _b.getvalue(), str(_e.code), _seen
    finally:
        (ghost.stage2_get_swap_quotes, ghost._receive_pairs_for,
         ghost.integrity_log) = _sv


_S2ARGS = lambda **k: types.SimpleNamespace(
    **{**dict(btc_amount=None, split=3, tor_proxy="socks5h://127.0.0.1:9050"), **k})

# Receiver mode takes the --swap-pairs bundle and asks for no quote at all.
_r, _o, _x, _seen = _s2(_S2ARGS(), receive=True)
check("stage2: receiver mode skips the swap and uses the --swap-pairs bundle",
      _x is None and _r == [{"xmr_dest": _S2A[0]}] and "chunks" not in _seen)

# JoinMarket's UTXOs ARE the chunks -- they are not re-split by --split.
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("1")),
                        jm=[Decimal("0.4"), Decimal("0.6")])
check("stage2: JoinMarket's UTXOs are the chunks, not --btc-amount re-split",
      _x is None and _seen.get("chunks") == [Decimal("0.4"), Decimal("0.6")])
check("stage2: ...and each chunk is quoted to its OWN entry address, in order",
      _seen.get("dests") == _S2A)

# --btc-amount is split into --split UNEQUAL chunks, and each still gets its
# own address.
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("0.3")))
check("stage2: --btc-amount is split into --split chunks",
      _x is None and len(_seen.get("chunks") or []) == 3
      and sum(_seen["chunks"]) == Decimal("0.3"))
check("stage2: ...unequal, because equal deposits minutes apart are a cluster",
      len(set(_seen.get("chunks") or [])) == 3)
check("stage2: ...and the deposit instructions are printed",
      "deposit instruction" in _o)

# A NON-POSITIVE --btc-amount is refused rather than falling through to the
# manual-mode branch, which used to tell the operator "No --btc-amount
# specified" for an amount they had plainly specified.
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("0")))
check("stage2: --btc-amount 0 is REFUSED, not read as 'no amount given'",
      _x is not None and "must be positive" in _x)
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("-1")))
check("stage2: ...and so is a negative one",
      _x is not None and "must be positive" in _x)

# Manual mode names EVERY entry address on the thor_swap_preparer line.
# Printing only the first would be the merge the entry set exists to stop,
# issued as an instruction.
_r, _o, _x, _seen = _s2(_S2ARGS())
check("stage2: manual mode returns no deposits and asks for none",
      _x is None and _r == [] and "chunks" not in _seen)
check("stage2: ...and its --dests line names EVERY entry address",
      all(ghost.scrub_address(_a) in _o for _a in _S2A))
check("stage2: ...saying one per swap, never the same one twice",
      "never the same one twice" in _o)

# THE BINDING ITSELF. A quote fetched against another chunk's address routes
# two swaps to one entry, which links them at the aggregator and merges them
# on-chain -- so it is refused before any deposit instruction is printed.
_bad = [_dep(0, _S2A[1]), _dep(1, _S2A[0]), _dep(2, _S2A[2])]
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("0.3")), quotes=_bad)
check("stage2: quotes fetched against the WRONG entry addresses are refused",
      _x is not None and "not fetched against this run's entry addresses" in _x)
check("stage2: ...before any deposit instruction is printed",
      "deposit instruction" not in _o)
_short = [_dep(0, _S2A[0])]
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("0.3")), quotes=_short)
check("stage2: ...and a SHORT quote list is accepted only if it is a prefix",
      _x is None)
_wrongshort = [_dep(0, _S2A[1])]
_r, _o, _x, _seen = _s2(_S2ARGS(btc_amount=Decimal("0.3")), quotes=_wrongshort)
check("stage2: ...a short list that is NOT a prefix is still refused",
      _x is not None)

# ==========================================================================
# THE SINGLE-SOURCE PEEL PLANNER, DRIVEN WITH THE OBJECT PRODUCTION PASSES.
#
# Every peel test above either has SEVERAL sources -- which hits the
# "--split with --peel" refusal before the planner runs -- or ONE source with
# ONE destination, which needs zero carriers and so returns before touching
# the rng. So the single-source, many-destination peel plan, the one a real
# run builds, had NO offline coverage at all.
#
# That gap let a live crash through. build_distribution_plan receives
# `_secrets`, which main() sets with `import secrets as _secrets` -- the
# MODULE, not a generator. Every other user in that function writes
# `_secrets.SystemRandom()` first. Code that called rng.random() on it died
# with "module 'secrets' has no attribute 'random'" on the first peel of a
# real chain, while every offline test passed, because the tests inject a real
# SystemRandom or a stub.
#
# So this passes the MODULE, exactly as main() does.
import secrets as _peel_secmod                                   # noqa: E402


class _PeelRpc:
    """Enough wallet for build_peel_stage_plan: fresh accounts and fresh
    subaddresses, in the shapes gs_common's helpers actually require."""

    def __init__(self):
        self.n = 100

    def raw_request(self, method, params=None):
        if method == "create_account":
            self.n += 1
            return {"account_index": self.n,
                    "address": f"ACCT{self.n}ADDR"}
        return {}

    def new_subaddress_indexed(self, account_index, label=""):
        self.n += 1
        return (f"CARRIER{self.n}", self.n)


_pl_dests = [f"pm{i}" for i in range(6)]
_pl_by = {d: Decimal("1") for d in _pl_dests}
_pl_args = types.SimpleNamespace(peel=True, dag_mixing=True)
_pl_err = None
_pl_plan = _pl_mode = None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _pl_plan, _pl_chg, _pl_mode, _pl_amts = ghost.build_distribution_plan(
            _pl_args, _PeelRpc(), {"PC0": (20, 1)}, [("PC0", 20, 1)],
            _pl_dests, _pl_by, [_pl_dests], Decimal("0.0024"), 20,
            len(_pl_dests), (0, 0), _peel_secmod, Decimal("50"),
            Decimal("45"))
except BaseException as _e:                                      # noqa: BLE001
    _pl_err = f"{type(_e).__name__}: {_e}"
check(f"peel planner: a single-source chain builds with the secrets MODULE, "
      f"which is what main() passes ({_pl_err or 'no error'})",
      _pl_err is None)
check("peel planner: ...and produces one transaction per destination",
      _pl_plan is not None and len(_pl_plan) == len(_pl_dests))
check("peel planner: ...in peel mode", _pl_mode == "peel")

# AND THE SHRINK PATH, which is the other half of the same hazard.
#
# fit_peel_distribution only touches the rng when the default distribution
# does NOT fit: it then calls compute_fanout_amounts for a smaller fraction,
# and that calls rng.random(). A comfortable balance never reaches it, so a
# test that only covers the affordable case leaves the module hazard live on
# exactly the runs that are tight enough to need shrinking. Verified: a
# mutation restoring the module on the fit call alone survived until this
# existed.
#
# The balance here is chosen from the arithmetic, not by eye: six 1 XMR
# destinations need 6 + 5*headroom = 6.14400, and a 6.10 balance leaves a cap
# of 6.07120, so the default distribution CANNOT fit and the shrink branch has
# to run. A first attempt used 6.2, whose cap is 6.17120 -- it fits, the shrink
# never ran, and the mutation this check exists for survived.
_pl_tight_err = None
_pl_tight_mode = None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _pt_plan, _pt_chg, _pl_tight_mode, _pt_amts = ghost.build_distribution_plan(
            _pl_args, _PeelRpc(), {"PC0": (20, 1)}, [("PC0", 20, 1)],
            _pl_dests, _pl_by, [_pl_dests], Decimal("0.0024"), 20,
            len(_pl_dests), (0, 0), _peel_secmod,
            Decimal("6.10"), Decimal("6.0"))
except SystemExit:
    # A clean refusal is a legitimate outcome for a tight balance; what must
    # not happen is an AttributeError from the rng.
    _pl_tight_mode = "refused"
except BaseException as _e:                                      # noqa: BLE001
    _pl_tight_err = f"{type(_e).__name__}: {_e}"
check(f"peel planner: the SHRINK path also survives the secrets module "
      f"({_pl_tight_err or 'no error'})", _pl_tight_err is None)
check("peel planner: ...and it either built or refused, never crashed",
      _pl_tight_mode in ("peel", "refused"))

# THE AMOUNTS THE PLANNER RETURNS MUST BE THE AMOUNTS THE PLAN PAYS.
#
# fanout_by_addr is a PARAMETER of build_distribution_plan, and the peel branch
# rebinds it when fit_peel_distribution shrinks the distribution. That rebind
# used to stay inside the function: main() went on to hand build_dag_plan the
# PRE-shrink dict, so the hop planner sized its fundability check from amounts
# no mix subaddress ever received. It happened to be harmless -- every amount
# compute_fanout_amounts produces clears min_hop_fundable, so both the stale
# and the real number answer hop_is_fundable the same way -- but that is the
# floor being the only question anyone asks, not the dict being right.
#
# Checked against the PLAN rather than against the input, so it holds whether
# or not a shrink happened: every non-final peel names its destination and
# amount explicitly, and those must be the returned numbers to the piconero.
def _amounts_agree(plan, by_addr):
    for _t in plan:
        for _d in _t.get("destinations", ()):
            if Decimal(str(_d["amount"])) != Decimal(str(by_addr[_d["address"]])):
                return False
    return True


check("peel planner: the returned amounts are the ones the plan pays",
      _pl_plan is not None and _amounts_agree(_pl_plan, _pl_amts))

# AND ON THE SHRINK PATH, which is the only one where the dict changes. Search
# for a balance that actually shrinks rather than guessing one: the fixture
# that merely refuses, or merely fits, leaves this unexercised -- which is how
# the stale dict survived in the first place.
_shrunk_plan = _shrunk_amts = None
# Six 1 XMR destinations need 6.018 with the headroom, so anything at or
# below 6.00 forces the 0.80 fraction. Walked rather than pinned to one
# number, because the reserve constants are the kind that get retuned.
for _bal_try in ("6.00", "5.75", "5.50", "5.00", "4.50", "4.00", "3.00"):
    _buf_sh = io.StringIO()
    try:
        with contextlib.redirect_stdout(_buf_sh):
            _sp, _sc, _sm, _sa = ghost.build_distribution_plan(
                _pl_args, _PeelRpc(), {"PC0": (20, 1)}, [("PC0", 20, 1)],
                _pl_dests, dict(_pl_by), [_pl_dests], Decimal("0.0024"), 20,
                len(_pl_dests), (0, 0), _peel_secmod,
                Decimal(_bal_try), Decimal(_bal_try) * Decimal("0.98"))
    except SystemExit:
        continue
    if "could not carry the full distribution" in _buf_sh.getvalue():
        _shrunk_plan, _shrunk_amts = _sp, _sa
        break
check("peel planner: a shrinking balance was found, so the path below ran",
      _shrunk_plan is not None)
check("peel planner: a SHRUNK distribution returns the shrunk amounts",
      _shrunk_plan is not None
      and any(Decimal(str(_shrunk_amts[_d])) != _pl_by[_d] for _d in _pl_dests))
check("peel planner: ...and they still match what the plan pays",
      _shrunk_plan is not None and _amounts_agree(_shrunk_plan, _shrunk_amts))

# The call site has to USE the fourth value. A caller that unpacks three and
# keeps its own dict is the defect back, with the function fixed.
_bdp_txt = Path(REPO, "GhostSpiral").read_text()
check("peel planner: main() rebinds fanout_by_addr from the return",
      "fanout_by_addr) = build_distribution_plan(" in _bdp_txt)
check("peel planner: ...and build_dag_plan is still handed that same name",
      "build_dag_plan(args, fee_xmr, hop_sources_real, fanout_by_addr,"
      in _bdp_txt)

# -- the budget follows the money -----------------------------------------
_slices, _su, _amts, _bad = ghost.size_distribution(
    ["m0", "m1", "m2", "m3"], [Decimal("3"), Decimal("1")], Decimal("8"),
    Decimal("0.0024"), False, _secretsmod.SystemRandom())
check("split: a fundable distribution names no unfundable chunk", _bad is None)
check("split: destinations are sliced by each chunk's OWN arrived balance, "
      "not equally — chunks are not equal",
      [len(x) for x in _slices] == [3, 1])
check("split: ...and each slice's budget is that chunk's share of usable",
      _su[0] > _su[1] * 2)
check("split: ...so the amounts sum to no more than the chunk can spend",
      sum(_amts[:3]) <= _su[0] and sum(_amts[3:]) <= _su[1])
check("split: a chunk with NO destinations comes back empty rather than "
      "silently dropped",
      ghost.size_distribution(["m0"], [Decimal("1"), Decimal("1")],
                              Decimal("8"), Decimal("0.0024"), False,
                              _secretsmod.SystemRandom())[2] == [])
# A chunk that arrives above dust but too small to fund even ONE mix output is
# NAMED, so the caller can drop that chunk and re-size instead of losing the
# whole run to it. It used to abort everything under a message about the
# wallet balance being too small — which it was not; every other chunk was fine.
_tiny_res = ghost.size_distribution(
    ["m0", "m1", "m2", "m3"], [Decimal("10"), Decimal("0.0002")],
    Decimal("9"), Decimal("0.0024"), False, _secretsmod.SystemRandom())
check("split: an under-funded chunk is IDENTIFIED, not returned as a bare "
      "failure", _tiny_res[3] is not None and _tiny_res[2] == [])
check("split: ...and it is the small one that is named, not chunk 0",
      _tiny_res[3] == 1)

# EACH CARRIER CAN PAY ITS OWN SLICE, mapped BY ADDRESS.
#
# The check above reads `sum(_amts[:3]) <= _su[0]`, which slices the amounts
# POSITIONALLY -- it assumes concat(slices) == fanout_dests, the same
# assumption the code used to make. A test written that way stays green under
# exactly the change that breaks the code, so the real property is asserted
# here instead: for every slice, the amounts belonging to THAT SLICE'S
# ADDRESSES fit THAT slice's budget. True for any partition, in any order.
_dests4 = ["m0", "m1", "m2", "m3"]
_sl4, _su4, _am4, _bad4 = ghost.size_distribution(
    _dests4, [Decimal("3"), Decimal("1")], Decimal("8"),
    Decimal("0.0024"), False, _secretsmod.SystemRandom())
_by4 = dict(zip(_dests4, _am4))       # exactly what main() does
check("split: every destination gets an amount", len(_by4) == len(_dests4))
check("split: each carrier is asked for no more than ITS OWN budget "
      "(by address, not by position)",
      all(sum(_by4[a] for a in sl) <= bud
          for sl, bud in zip(_sl4, _su4)))

# THE PARTITION ORDER MUST NOT MATTER. split_by_weight's docstring names
# round-robin as the equivalent alternative to contiguous slices, so that is
# the edit its own comment invites. Under the old positional concatenation it
# asked a carrier holding 0.75 XMR to pay 3.12 -- and the fan-out dies "not
# enough money" AFTER the veils have relayed and paid their fees.
_saved_sbw = ghost.split_by_weight
try:
    def _round_robin(items, weights):
        n = len(weights)
        out = [[] for _ in range(n)]
        for i, it in enumerate(items):
            out[i % n].append(it)
        return out
    ghost.split_by_weight = _round_robin
    _dests9 = [f"m{i}" for i in range(9)]
    _slR, _suR, _amR, _badR = ghost.size_distribution(
        _dests9, [Decimal("4"), Decimal("3"), Decimal("1")], Decimal("6"),
        Decimal("0.0002"), False, _secretsmod.SystemRandom())
    _byR = dict(zip(_dests9, _amR))
    check("split: a NON-CONTIGUOUS partition still funds every destination",
          _badR is None and len(_byR) == len(_dests9))
    check("split: ...and each carrier is STILL only asked for its own budget "
          "— the amounts follow the address, not the list position",
          all(sum(_byR[a] for a in sl) <= bud
              for sl, bud in zip(_slR, _suR)))

    # A partition that does not COVER every destination must stop the run at
    # plan time, not hand back a short list for the caller to zip against.
    def _drops_one(items, weights):
        out = _round_robin(items, weights)
        out[-1] = out[-1][:-1] if len(out[-1]) > 1 else out[-1]
        return out
    ghost.split_by_weight = _drops_one
    _raised = ""
    try:
        ghost.size_distribution(_dests9, [Decimal("4"), Decimal("3"),
                                          Decimal("1")], Decimal("6"),
                                Decimal("0.0002"), False,
                                _secretsmod.SystemRandom())
    except RuntimeError as _e:
        _raised = str(_e)
    check("split: a partition that leaves a destination in NO slice is "
          "refused, not silently misaligned", "no slice" in _raised)
    check("split: ...and the refusal says the destinations would go unfunded",
          "unfunded" in _raised)
finally:
    ghost.split_by_weight = _saved_sbw

# -- --split bounds --------------------------------------------------------
# THE UPPER BOUND IS NO LONGER --split ALONE. A chunk with no mix subaddress to
# distribute into is fatal at stage 4, and the fan-out funds
# `wallets + randint(DECOY_MIN, DECOY_MAX)` targets, so `wallets + DECOY_MIN`
# is the only count that holds for every draw. These cases therefore carry a
# --wallets that can actually feed them; the refusal below drives the pair that
# cannot.
for _ok in (1, 2, 8, None):
    _r = None
    try:
        ghost.resolve_split(types.SimpleNamespace(split=_ok, wallets=10))
    except SystemExit as _e:
        _r = str(_e.code)
    check(f"split: --split {_ok!r} is allowed at --wallets 10", _r is None)
_starved = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=8, wallets=ghost.MIN_WALLETS))
except SystemExit as _e:
    _starved = str(_e.code)
check("split: --split 8 at the minimum --wallets is refused BEFORE the swap — "
      "every decoy draw leaves a chunk with nowhere to distribute",
      _starved is not None)
check("split: ...and the refusal names both numbers the operator can change",
      _starved and "--wallets" in _starved and "--split" in _starved)
check("split: ...and says it cannot work on ANY run, not that it might",
      _starved and "cannot work on any run" in _starved)
check("split: NON-VACUITY -- one more than the borderline chunk count really "
      "is the boundary, so the refusal is not refusing everything",
      ghost.resolve_split(types.SimpleNamespace(
          split=ghost.MIN_WALLETS + ghost.DECOY_MIN,
          wallets=ghost.MIN_WALLETS)) is None)
# WALLETS MISSING IS TREATED AS THE SMALLEST, not as the CLI default. main()
# always sets it, so this only decides what an incomplete namespace gets: the
# conservative answer refuses a shape it cannot vouch for rather than letting
# it through to a stage-4 abort after the money has moved.
_noswallets = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=ghost.MAX_SPLIT))
except SystemExit as _e:
    _noswallets = str(_e.code)
check("split: a namespace with no --wallets is judged at MIN_WALLETS, so the "
      "refusal fails closed",
      _noswallets is not None
      and f"--wallets {ghost.MIN_WALLETS}" in _noswallets)

# THE STAGE-1 HALF, for the count --split cannot see. planned_chunk_count's
# own first line is "JoinMarket first, because when it ran its UTXOs ARE the
# chunks and --split is not consulted", so `--joinmarket --wallets 3` with a
# six-output tumble walks past the parse-time gate above -- the exact walk
# refuse_peel_multichunk exists for, one refusal along.


def _starved_jm(n_utxos, wallets):
    _ns = types.SimpleNamespace(split=1, wallets=wallets, peel=False)
    try:
        ghost.refuse_starved_chunks(_ns, ["u"] * n_utxos)
        return ""
    except SystemExit as _e:
        return str(_e.code)


def _refused_split(ns):
    try:
        ghost.resolve_split(ns)
        return False
    except SystemExit:
        return True


_jm6 = _starved_jm(6, ghost.MIN_WALLETS)
check("split: a JoinMarket tumble with more UTXOs than the mix has targets is "
      "refused at STAGE 1 — before the entry set, the quotes and the swap",
      bool(_jm6))
check("split: NON-VACUITY -- resolve_split alone does NOT catch it, because "
      "--split is still 1 on that command line",
      not _refused_split(types.SimpleNamespace(split=1,
                                               wallets=ghost.MIN_WALLETS,
                                               peel=False)))
check("split: ...and the refusal names the TUMBLER, not a --split the "
      "operator never passed",
      "JoinMarket" in _jm6 and "UTXO" in _jm6 and "--split" not in _jm6)
check("split: ...and its remedy is one the operator can act on",
      "fewer output addresses" in _jm6)
check("split: NON-VACUITY -- a tumble the mix CAN feed is left alone",
      not _starved_jm(ghost.MIN_WALLETS + ghost.DECOY_MIN, ghost.MIN_WALLETS)
      and not _starved_jm(ghost.MAX_SPLIT, 10))
check("split: the two gates share one rule, so they cannot drift into "
      "disagreeing about the same shape",
      ghost.starved_chunk_refusal(ghost.MIN_WALLETS, ghost.MAX_SPLIT) != ""
      and ghost.starved_chunk_refusal(10, ghost.MAX_SPLIT) == "")
_rsc_src = open(os.path.join(REPO, "GhostSpiral")).read()
_rsc_body = _rsc_src[_rsc_src.index("def refuse_starved_chunks"):][:900]
check("split: ...and the stage-1 gate asks planned_chunk_count rather than "
      "re-deriving the count, so it and the entry set cannot disagree",
      "planned_chunk_count(args, jm_utxos)" in _rsc_body)
check("split: NON-VACUITY -- it does NOT read --split there, which is the "
      "flag that cannot see a JoinMarket tumble",
      '"split"' not in _rsc_body)
# AND main() HAS TO CALL IT. A gate nothing invokes is the same as no gate,
# and the checks above all call refuse_starved_chunks directly -- so deleting
# the one line in main() left every one of them green. Read out of the parsed
# tree rather than grepped, so a mention in a comment cannot stand in for a
# call, and asserted alongside its sibling: these two answer the same question
# at the same moment and neither is complete on its own.
_main_calls = set()
for _fn in _ast.walk(_ast.parse(_rsc_src)):
    if isinstance(_fn, _ast.FunctionDef) and _fn.name == "main":
        for _nd in _ast.walk(_fn):
            if isinstance(_nd, _ast.Call) and isinstance(_nd.func, _ast.Name):
                _main_calls.add(_nd.func.id)
check("split: main() actually calls the stage-1 gate — a refusal nothing "
      "invokes is not a refusal",
      "refuse_starved_chunks" in _main_calls)
check("split: ...beside refuse_peel_multichunk, which asks the same question "
      "at the same moment",
      "refuse_peel_multichunk" in _main_calls)
check("split: NON-VACUITY -- the walk really read main()'s calls, so the two "
      "checks above are not both reading an empty set",
      "stage1_joinmarket" in _main_calls and len(_main_calls) > 20)
_too_many = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=99))
except SystemExit as _e:
    _too_many = str(_e.code)
check("split: --split 99 is refused (fees, veils and the offline wallet's "
      "account lookahead all scale with it)", _too_many is not None)
check("split: ...and the refusal names the lookahead, which is the "
      "measured limit", _too_many and "accounts" in _too_many)
_neg = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=0))
except SystemExit as _e:
    _neg = str(_e.code)
check("split: --split 0 is refused", _neg is not None)

# -- a chunk that never arrived is dropped, not left to sink the run -------
#
# The arrival gate compares the SUM against the target, so a chunk can be
# missing while the total clears: one swap overshooting its quote covers
# another that has not landed, and --accept-partial-swap allows a shortfall
# outright. Before this, that chunk's empty entry made size_distribution return
# no amounts, which main() reported as "usable balance too small to fan out ...
# use fewer wallets, or fund the wallet more" — wrong in every particular.
_ES3 = [("E0", 10, 1), ("E1", 11, 1), ("E2", 12, 1)]
with contextlib.redirect_stdout(io.StringIO()) as _fb:
    _fe, _fu = ghost.select_funded_entries(
        _ES3, [Decimal("2"), Decimal("0"), Decimal("3")])
check("unfunded: the chunk that never arrived is dropped",
      [a for a, _c, _i in _fe] == ["E0", "E2"])
check("unfunded: ...and its weight goes with it, so the slices stay aligned",
      _fu == [Decimal("2"), Decimal("3")])

_fb2 = io.StringIO()
with contextlib.redirect_stdout(_fb2):
    ghost.select_funded_entries(_ES3, [Decimal("2"), Decimal("0"), Decimal("3")])
_msg = _fb2.getvalue()
check("unfunded: the operator is told a SWAP has not arrived — not that their "
      "balance is too small or that they should use fewer wallets",
      "NOT arrived" in _msg and "wallets" not in _msg)
check("unfunded: ...and that the missing value is not mixed by this run",
      "NOT mixed by this run" in _msg)
check("unfunded: ...and that its address is held back from the exit, which is "
      "what stops a late chunk leaving in one hop",
      "held back from the exit" in _msg)
check("unfunded: ...and how to mix it afterwards",
      "--receive-wallet" in _msg)

# Dust is not an arrival. Somebody can send a piconero to an address the swap
# memo publishes, and that must not count as the chunk landing.
with contextlib.redirect_stdout(io.StringIO()):
    _fe2, _ = ghost.select_funded_entries(_ES3, [Decimal("2"), ghost.DUST_XMR,
                                                 Decimal("3")])
check("unfunded: a DUST balance is not an arrival",
      [a for a, _c, _i in _fe2] == ["E0", "E2"])

# Nothing at all is the caller's decision, signalled by an empty return.
with contextlib.redirect_stdout(io.StringIO()):
    check("unfunded: when NOTHING arrived it returns empty for the caller to "
          "make fatal", ghost.select_funded_entries(
              _ES3, [Decimal(0)] * 3) == ([], []))

# CONTROL: the ordinary run is untouched — same list back, and SILENT.
_fb3 = io.StringIO()
with contextlib.redirect_stdout(_fb3):
    _ok = ghost.select_funded_entries(_ES3, [Decimal("1")] * 3)
check("control: with every chunk funded nothing is dropped",
      _ok == (_ES3, [Decimal("1")] * 3))
check("control: ...and nothing is printed — no warning on a healthy run",
      _fb3.getvalue() == "")

# -- the entry set is sized before the quotes, from the same three inputs ---
check("split: JoinMarket's UTXOs are the chunk count when it ran",
      ghost.planned_chunk_count(types.SimpleNamespace(split=1),
                                ["u1", "u2", "u3"]) == 3)
check("split: otherwise --split is", 
      ghost.planned_chunk_count(types.SimpleNamespace(split=4), []) == 4)
check("split: and it is never zero",
      ghost.planned_chunk_count(types.SimpleNamespace(split=None), []) == 1)


# ==========================================================================
# A HOP NEVER CROSSES SWAP CHUNKS.
#
# The entry set stops two chunks meeting at the veil or the distribution. The
# DAG round could still put them on one subaddress, by a route that has
# nothing to do with the entry addresses:
#
#   the round is a permutation, so a target that hops its OWN output away ends
#   holding exactly one output and whose it is does not matter. But two kinds
#   of target do NOT hop and are still eligible to RECEIVE one -- a source
#   whose hop amount lands at or below dust, and a source that could not be
#   given a destination. Such a target keeps its original output AND takes
#   delivery of the incoming hop, and the exit's per-subaddress sweep_all then
#   spends BOTH IN ONE TRANSACTION.
#
# With one chunk that is harmless: both outputs are the same money. With N it
# is the convergence the whole change exists to prevent.
#
# Found by tracing the round by hand. It needs a small-enough fan-out output
# or an exhausted candidate pool, so it is occasional rather than reliable --
# which is worse than reliable, not better.
# ==========================================================================
print("\n=== DAG hops stay inside their own chunk ===")

_HA = types.SimpleNamespace(dag_mixing=True, deep=2)
_CHUNK_A = [f"A{i}" for i in range(4)]
_CHUNK_B = [f"B{i}" for i in range(4)]
_ALL = _CHUNK_A + _CHUNK_B
_AI = {a: (70 + i, 1) for i, a in enumerate(_ALL)}


def _hop_plan(by_addr, slices):
    _dag = ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod)
    with contextlib.redirect_stdout(io.StringIO()):
        return ghost.build_dag_plan(
            _HA, Decimal("0.0024"), list(_ALL), by_addr, _dag, _ALL, _AI,
            _secretsmod, dest_slices=slices)


# Every output comfortably fundable: a clean permutation.
_BY_OK = {a: Decimal("1") for a in _ALL}
_chunk_of = {a: ("A" if a in _CHUNK_A else "B") for a in _ALL}
for _trial in range(25):
    _p = _hop_plan(_BY_OK, [_CHUNK_A, _CHUNK_B])
    _cross = [(t["src"], t["dst"]) for t in _p
              if _chunk_of[t["src"]] != _chunk_of[t["dst"]]]
    if _cross:
        break
check("hop: over 25 plans, NO hop ever crosses from one chunk's slice to the "
      "other's", not _cross)
check("hop: ...and the round still hops (this is not vacuously empty)",
      len(_p) > 0)
check("hop: ...one destination each, never used twice",
      len({t["dst"] for t in _p}) == len(_p))

# THE FAILING SHAPE. One output in chunk A is too small to fund a hop, so it
# does not hop -- and would previously have been a legal destination for a
# chunk-B source, leaving A-dust and B-value on one subaddress.
_BY_DUST = dict(_BY_OK)
_BY_DUST["A0"] = Decimal("0.0001")          # hop amount lands under dust
_saw_nonhopper_as_dest = False
_saw_cross = False
for _trial in range(40):
    _p2 = _hop_plan(_BY_DUST, [_CHUNK_A, _CHUNK_B])
    _srcs = {t["src"] for t in _p2}
    for t in _p2:
        if _chunk_of[t["src"]] != _chunk_of[t["dst"]]:
            _saw_cross = True
        # a destination that is NOT itself a source keeps its own output too
        if t["dst"] not in _srcs and _chunk_of[t["dst"]] != _chunk_of[t["src"]]:
            _saw_nonhopper_as_dest = True
check("hop: A0 cannot fund a hop, and over 40 plans it is never paid by the "
      "OTHER chunk — which is the merge",
      not _saw_cross and not _saw_nonhopper_as_dest)
check("hop: ...and A0 really is unfundable (the fixture bites)",
      ghost.compute_hop_amount(Decimal("0.0001"), Decimal("0.0024"))
      <= ghost.DUST_XMR)

# ...AND THE SAME-CHUNK MERGE, which the assertion above deliberately did not
# cover and which the docstring called "harmless -- both outputs are the same
# money". It is not harmless under --peel: a peeling chain creates its outputs
# in SEPARATE transactions precisely so no public transaction groups them, and
# one merged exit sweep groups two of them again.
#
# A hop is a sweep_all and the whole round is CREATED before any of it is
# broadcast, so a target that hops ends holding exactly the output it received.
# A target that does NOT hop keeps its own AND takes delivery -- two outputs on
# one subaddress, which _funded_subaddresses returns as one row and the exit
# sweeps in ONE multi-input transaction.
#
# Driven before the fix, single chunk, one unfundable output among ten:
# 275 of 300 planned rounds routed a hop onto it. 0 of 300 with every output
# fundable, which is what makes it this defect and not noise.
def _merges(by_addr, slices, trials=60):
    _bad = 0
    for _ in range(trials):
        _pl = _hop_plan(by_addr, slices)
        _hs = {t["src"] for t in _pl}          # these sweep themselves empty
        if any(t["dst"] not in _hs for t in _pl):
            _bad += 1
    return _bad

_ONE = [list(_ALL)]
check("hop: an output that cannot fund a hop is never PAID one either — it "
      "would keep its own output and hold two",
      _merges(_BY_DUST, _ONE) == 0)
_BY_D3 = dict(_BY_OK)
for _d in _ALL[:3]:
    _BY_D3[_d] = Decimal("0.0001")
check("hop: ...still true with three of them", _merges(_BY_D3, _ONE) == 0)
check("hop: ...and inside one chunk of a split run",
      _merges(_BY_DUST, [_CHUNK_A, _CHUNK_B]) == 0)
check("hop: control — every output fundable, no merge either",
      _merges(_BY_OK, _ONE) == 0)
# NON-VACUITY: the fixture must actually make an output unhoppable, or the
# checks above pass because nothing was ever at risk.
check("hop: ...and the dust fixture really does remove a source from the round",
      len(_hop_plan(_BY_DUST, _ONE)) == len(_ALL) - 1
      and len(_hop_plan(_BY_OK, _ONE)) == len(_ALL))

# THE MECHANISM, on its own. close_hop_cycles turns every path into a cycle, so
# every address that receives also sends. Tested directly because the planner
# only reaches some of its shapes by chance.
_paths = {"a": "b", "b": "c", "c": "d"}          # one path, tail d
_cl = ghost.close_hop_cycles(_paths, {"a", "b", "c", "d"})
check("close_hop_cycles: a path becomes a cycle, so its tail hops too",
      _cl == {"a": "b", "b": "c", "c": "d", "d": "a"})
check("close_hop_cycles: ...and every destination is also a source",
      all(_v in _cl for _v in _cl.values()))
_cyc = {"a": "b", "b": "a"}
check("close_hop_cycles: an existing cycle is left alone",
      ghost.close_hop_cycles(_cyc, {"a", "b"}) == _cyc)
check("close_hop_cycles: a tail that holds NOTHING is not made a source — its "
      "sweep would be built before its only output arrives",
      ghost.close_hop_cycles({"a": "b"}, {"a"}) == {"a": "b"})
check("close_hop_cycles: two separate paths both close",
      ghost.close_hop_cycles({"a": "b", "c": "d"}, set("abcd"))
      == {"a": "b", "b": "a", "c": "d", "d": "c"})
check("close_hop_cycles: it never gives an address two incoming hops",
      len(set(ghost.close_hop_cycles(
          {"a": "b", "b": "c", "d": "e"}, set("abcde")).values())) == 5)
check("close_hop_cycles: nothing is dropped — closing only ADDS hops",
      len(ghost.close_hop_cycles({"a": "b", "b": "c"}, set("abc"))) == 3)

# THE OTHER DOOR: OVERLAPPING SLICES. dest_slices arrives as a parameter and
# this function does not verify it partitions, so two groups can pick the same
# address; the cross-call dedupe then DROPS one hop, and its source is left
# holding its own output while somebody else is already hopping onto it.
#
# That is the same merge by a different route, and it needs no dust at all.
# Driven with close_hop_cycles disabled: 62 of 150 plans merged.
_OV = [_CHUNK_A + _CHUNK_B[:1], _CHUNK_B]        # one address in both slices
_ov_merge = 0
_ov_min = 99
for _trial in range(60):
    _po = _hop_plan(_BY_OK, _OV)
    _ohs = {t["src"] for t in _po}
    if any(t["dst"] not in _ohs for t in _po):
        _ov_merge += 1
    _ov_min = min(_ov_min, len(_po))
check(f"hop: overlapping slices never leave a hop paying a non-hopper "
      f"({_ov_merge} of 60 plans)", _ov_merge == 0)
# ...and the repair is CLOSING the paths, not dropping the hops. With cycle
# closing disabled the same fixture keeps as few as 4 of 8; with it, 7 or 8.
check(f"hop: ...and it repairs them by closing the chain, not by dropping "
      f"hops (worst plan kept {_ov_min} of {len(_ALL)})",
      _ov_min >= len(_ALL) - 1)

# THE BACKSTOP, exercised on its own. close_hop_cycles and the destination-pool
# filter each close this independently, so a single-point mutation of either is
# invisible -- which is what defence in depth means and also how a layer gets
# quietly deleted. Neutering the repair here forces the backstop to be the one
# holding the invariant.
_real_close = ghost.close_hop_cycles
ghost.close_hop_cycles = lambda d, m: dict(d)
try:
    _bs_merge = 0
    _bs_fired = 0
    for _trial in range(60):
        _bo = io.StringIO()
        with contextlib.redirect_stdout(_bo):
            _pb = ghost.build_dag_plan(
                _HA, Decimal("0.0024"), list(_ALL), _BY_OK,
                ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod),
                _ALL, _AI, _secretsmod, dest_slices=_OV)
        _bhs = {t["src"] for t in _pb}
        if any(t["dst"] not in _bhs for t in _pb):
            _bs_merge += 1
        if "is not sweeping its own output away" in _bo.getvalue():
            _bs_fired += 1
finally:
    ghost.close_hop_cycles = _real_close
check(f"hop: with the path repair disabled the BACKSTOP still admits no merge "
      f"({_bs_merge} of 60)", _bs_merge == 0)
check(f"hop: ...and it says so rather than dropping hops silently "
      f"(reported in {_bs_fired} of 60)", _bs_fired > 0)

# ORPHANS AND A DUST HOLDER TOGETHER. A source that belongs to no slice falls
# to the orphan pass, whose pool is drawn from mix_targets directly -- so the
# unfundable holder has to be filtered out there too, not only in the per-group
# pools.
_ORPH = list(_ALL) + ["Z0", "Z1"]
_orph_ai2 = dict(_AI); _orph_ai2.update({"Z0": (91, 1), "Z1": (92, 1)})
_orph_by2 = {a: Decimal("1") for a in _ORPH}
_orph_by2[_ALL[0]] = Decimal("0.0001")           # a holder that cannot hop
_od_merge = 0
for _trial in range(40):
    _dagj = ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod)
    _dagj.update({"Z0": list(_ALL), "Z1": list(_ALL)})
    with contextlib.redirect_stdout(io.StringIO()):
        _pod = ghost.build_dag_plan(_HA, Decimal("0.0024"), _ORPH, _orph_by2,
                                    _dagj, _ALL, _orph_ai2, _secretsmod,
                                    dest_slices=[list(_ALL)])
    _ohs2 = {t["src"] for t in _pod}
    if any((t["dst"] in set(_ORPH) and t["dst"] not in _ohs2) for t in _pod):
        _od_merge += 1
check(f"hop: an orphan is never handed the one target that cannot hop "
      f"({_od_merge} of 40)", _od_merge == 0)

# EACH LAYER IS PINNED IN SOURCE. The three are individually redundant, so no
# single-point mutation of any one of them changes an observable -- which is
# exactly how one gets deleted as "dead". Named here so the deletion is a test
# failure and the next reader has to argue with this comment first.
from srcutil import code_only as _code_only_hp              # noqa: E402
_dp_src = " ".join(_code_only_hp(os.path.join(REPO, "GhostSpiral")).split())
check("hop: layer 1 — the per-group destination pool excludes unfundable "
      "holders",
      "_grp_pool = [d for d in _grp if d in _safe_dsts]" in _dp_src)
check("hop: layer 1b — and so does the orphan pool",
      "if d in _safe_dsts and d not in set(_dsts.values())]" in _dp_src)
check("hop: layer 2 — paths are closed into cycles",
      "_dsts = close_hop_cycles(_dsts, _holds_output & _fundable_set)"
      in _dp_src)
check("hop: layer 3 — the backstop runs to a FIXED POINT, because dropping "
      "one hop can create the next merge",
      "for _ in range(len(_dsts) + 1):" in _dp_src
      and "if not _merge_dsts:" in _dp_src)

# A SLICE OF ONE CANNOT HOP, and with several chunks and few wallets that is
# most of them: a hop must leave its source and stay inside its chunk, so a
# chunk holding one mix subaddress has nowhere legal to send it. The run must
# say so rather than reporting "could not be given a destination" as if it were
# bad luck.
_thin_out = io.StringIO()
with contextlib.redirect_stdout(_thin_out):
    ghost.build_dag_plan(_HA, Decimal("0.0024"), list(_ALL), _BY_OK,
                         ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod),
                         _ALL, _AI, _secretsmod,
                         dest_slices=[["A0"], ["A1"], _CHUNK_B + _CHUNK_A[2:]])
_tm = _thin_out.getvalue()
check("hop: a chunk with fewer than two mix subaddresses is REPORTED, not "
      "silently left unhopped", "nowhere to hop" in _tm)
check("hop: ...explaining that a hop cannot leave its own chunk",
      "cannot leave its own chunk" in _tm)
check("hop: ...and saying how many --wallets would fix it",
      "--wallets" in _tm)
_fat_out = io.StringIO()
with contextlib.redirect_stdout(_fat_out):
    ghost.build_dag_plan(_HA, Decimal("0.0024"), list(_ALL), _BY_OK,
                         ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod),
                         _ALL, _AI, _secretsmod,
                         dest_slices=[_CHUNK_A, _CHUNK_B])
check("control: slices with room to hop produce NO such warning",
      "nowhere to hop" not in _fat_out.getvalue())

# CONTROL: with ONE chunk the slice is every target and the round is unchanged
# -- hops range over the whole mix, exactly as before.
_p3 = _hop_plan(_BY_OK, [list(_ALL)])
check("control: with one chunk hops range over every mix subaddress",
      len(_p3) > 0 and len({t["dst"] for t in _p3}) == len(_p3))

# NO DESTINATION TWICE, ACROSS EVERY assign_hop_destinations CALL.
#
# That function guarantees "no destination used twice" only WITHIN ONE CALL,
# and build_dag_plan calls it once per chunk group PLUS once for orphans, then
# merges with _dsts.update() — which merges by SOURCE and never looked at the
# destinations. The per-group calls are safe only because the groups are
# disjoint, which nothing checked; the orphan call passed the FULL mix_targets
# and re-picked addresses the group calls had already taken.
#
# Two hops onto one address put value from two swap chunks on it, and the exit
# issues ONE sweep_all per funded subaddress — so both leave in a single
# multi-input transaction. That is the merge the whole split exists to prevent,
# produced by the branch written as a safety net, and it contradicted the
# policy this same function prints: "a missed hop costs mixing depth, sharing a
# destination would cost the no-merge guarantee."
#
# Driven directly, both doors, before the fix: TRUE-ORPHAN 200/200 plans shared
# a destination, OVERLAPPING slices 180/200.

# DOOR 1: sources outside mix_targets entirely, so they reach the orphan pass.
_orph_srcs = list(_ALL) + ["Z0", "Z1"]
_orph_by = {a: Decimal("1") for a in _orph_srcs}
_orph_ai = dict(_AI); _orph_ai.update({"Z0": (91, 1), "Z1": (92, 1)})
_orph_dup = 0
for _trial in range(40):
    _dagj = ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod)
    _dagj.update({"Z0": list(_ALL), "Z1": list(_ALL)})
    with contextlib.redirect_stdout(io.StringIO()):
        _po = ghost.build_dag_plan(_HA, Decimal("0.0024"), _orph_srcs, _orph_by,
                                   _dagj, _ALL, _orph_ai, _secretsmod,
                                   dest_slices=[_CHUNK_A, _CHUNK_B])
    _d = [t["dst"] for t in _po]
    if len(set(_d)) != len(_d):
        _orph_dup += 1
check("hop: a source belonging to NO chunk group never takes a destination "
      "another hop already has — over 40 plans", _orph_dup == 0)

# ...AND IT STILL GETS TO HOP WHEN THERE IS SOMEWHERE FREE TO GO.
#
# Two defences sit here and they do different jobs. The cross-call check below
# keeps the INVARIANT: a duplicate destination is dropped. Restricting the
# orphan pass to unclaimed destinations keeps the MIXING DEPTH: without it the
# orphan picks from the full pool, collides with a destination a group already
# took, and is then dropped by that check — so the invariant holds and the hop
# is lost for no reason. A test that only looked for collisions would call that
# a pass.
#
# Eight targets, four group sources, so four destinations are still free when
# the orphans are assigned. They must take them.
_SLACK = [f"S{i}" for i in range(8)]
_slack_ai = {a: (80 + i, 1) for i, a in enumerate(_SLACK)}
_slack_ai.update({"Y0": (95, 1), "Y1": (96, 1)})
_slack_srcs = [_SLACK[0], _SLACK[1], _SLACK[4], _SLACK[5], "Y0", "Y1"]
_slack_by = {a: Decimal("1") for a in _slack_srcs}
_orph_hopped = 0
for _trial in range(40):
    _dslack = ghost.build_dag_adjacency(_SLACK, [], 2, _secretsmod)
    _dslack.update({"Y0": list(_SLACK), "Y1": list(_SLACK)})
    with contextlib.redirect_stdout(io.StringIO()):
        _ps = ghost.build_dag_plan(_HA, Decimal("0.0024"), _slack_srcs,
                                   _slack_by, _dslack, _SLACK, _slack_ai,
                                   _secretsmod,
                                   dest_slices=[_SLACK[0:4], _SLACK[4:8]])
    if {t["src"] for t in _ps} >= {"Y0", "Y1"}:
        _orph_hopped += 1
check("hop: an orphan is offered the destinations nothing has claimed, so it "
      "still hops when one is free — dropping it would cost mixing depth for "
      "no gain", _orph_hopped == 40)

# DOOR 2: overlapping slices. build_dag_plan takes dest_slices as a parameter
# and never verifies they partition, so this is a second way in.
_ov_dup = 0
for _trial in range(40):
    with contextlib.redirect_stdout(io.StringIO()):
        _pv = _hop_plan(_BY_OK, [_ALL[0:5], _ALL[3:8]])
    _d = [t["dst"] for t in _pv]
    if len(set(_d)) != len(_d):
        _ov_dup += 1
check("hop: OVERLAPPING slices cannot merge two chunks onto one address "
      "either — the collision is checked, not assumed away", _ov_dup == 0)

# ...and a dropped hop is REPORTED, because losing mixing depth silently is
# the failure mode this project keeps finding.
_drop_out = io.StringIO()
with contextlib.redirect_stdout(_drop_out):
    _dagj2 = ghost.build_dag_adjacency(_ALL, [], 2, _secretsmod)
    _dagj2.update({"Z0": list(_ALL), "Z1": list(_ALL)})
    ghost.build_dag_plan(_HA, Decimal("0.0024"), _orph_srcs, _orph_by,
                         _dagj2, _ALL, _orph_ai, _secretsmod,
                         dest_slices=[_CHUNK_A, _CHUNK_B])
_dt = _drop_out.getvalue()
check("hop: a hop that could not get its OWN destination is reported, not "
      "silently missing", "could not be given a hop destination" in _dt
      or "DROPPED" in _dt)

# CONTROL: the ordinary split path is untouched — every source still hops and
# every destination is still distinct.
_p_norm = _hop_plan(_BY_OK, [_CHUNK_A, _CHUNK_B])
check("control: the ordinary two-chunk round still hops every output",
      len(_p_norm) == len(_ALL))
check("control: ...each to its own destination",
      len({t["dst"] for t in _p_norm}) == len(_p_norm))
_spans = False
for _trial in range(25):
    _p4 = _hop_plan(_BY_OK, [list(_ALL)])
    if any(_chunk_of[t["src"]] != _chunk_of[t["dst"]] for t in _p4):
        _spans = True
        break
check("control: ...and it DOES cross what would have been slice boundaries, "
      "so the restriction above is doing real work rather than being the "
      "only thing that could happen", _spans)

# ...and passing no slices at all behaves like one slice (back-compatible).
_p5 = _hop_plan(_BY_OK, None)
check("control: dest_slices=None falls back to the whole target list",
      len(_p5) > 0)


# ==========================================================================
# EQUAL BTC CHUNKS UNDO THE SPLIT ON THE BITCOIN SIDE.
#
# The Monero side of --split is careful: one entry address per chunk, one veil
# each, one distribution each, no transaction spending two chunks. None of it
# helps if the BITCOIN chain hands an observer the grouping for free. This was
#
#     per_chunk = (total / n).quantize(SATOSHI)
#     btc_chunks = [per_chunk] * n
#
# so a --split 4 run told the operator to make four deposits of an IDENTICAL
# amount, within minutes, to the same vault — one cluster, and the OP_RETURNs
# then read out all four Monero destinations.
# ==========================================================================
print("\n=== the BTC chunks are unequal ===")

_R = _secretsmod.SystemRandom()


class _FlatRNG:
    """Every weight identical, so every chunk starts out equal.

    split_btc_amount draws its jitter from randrange(0, 2001); returning the
    midpoint gives weight exactly 1 for every chunk. That is the worst case for
    the distinctness construction and the one a random RNG almost never
    produces, which is why the old probabilistic check missed a repair that
    could not handle it.
    """

    def randrange(self, a, b=None):
        return 1000 if b == 2001 else 0

    def random(self):
        return 0.5


def _split_or_none(total, n, rng):
    """split_btc_amount, but a refusal is a RED CHECK rather than a traceback.

    It raises ValueError when it cannot produce n distinct positive chunks. A
    test that let that escape would kill this file, print no RESULT line, and
    score NO-RESULT in the mutation sweep -- which the sweep's own header warns
    is not a catch. Returning None instead makes the checks below fail with
    their own words.
    """
    try:
        return ghost.split_btc_amount(total, n, rng)
    except ValueError:
        return None


for _total, _n in [(Decimal("0.08"), 4), (Decimal("0.5"), 2),
                   (Decimal("1"), 8), (Decimal("0.13"), 3)]:
    _a = _split_or_none(_total, _n, _R) or []
    check(f"btc: {_total}/{_n} produces {_n} chunks", len(_a) == _n)
    check(f"btc: {_total}/{_n} sums EXACTLY to the total (no satoshi lost or "
          f"invented)", sum(_a, Decimal(0)) == _total)
    # DETERMINISTIC, not 120 hopeful draws. This used to draw repeatedly and
    # assert the last one was distinct -- and natural collisions run at 0.085%
    # for 4 chunks and 0.585% for 8, so 120 draws caught a broken repair only
    # about 60% of the time. It let a real defect through a full mutation
    # sweep: the sweep reported "two BTC chunks may be equal" as SURVIVED on
    # one run and CAUGHT on another, which is the signature of a check that is
    # really a coin flip.
    #
    # _FlatRNG makes every weight identical, so EVERY chunk collides and the
    # repair has to do its whole job. The old repair returned 3 distinct
    # values out of 8 here: it always took its satoshi from the LARGEST chunk,
    # which is the one it had just incremented, so it handed the satoshi
    # straight back and oscillated until its pass budget ran out.
    _ax = _split_or_none(_total, _n, _FlatRNG())
    check(f"btc: {_total}/{_n} chunks are DISTINCT even when every weight is "
          f"identical — a repeated deposit amount is the tell this exists to "
          f"remove", _ax is not None and len(set(_ax)) == _n)
    check(f"btc: {_total}/{_n} ...and the repair did not break the total",
          _ax is not None and sum(_ax, Decimal(0)) == _total
          and all(x > 0 for x in _ax))
    # ...and still distinct on ordinary random draws.
    _rand_dups = 0
    for _rep in range(200):
        _rx = _split_or_none(_total, _n, _R)
        if _rx is None or len(set(_rx)) != _n:
            _rand_dups += 1
    check(f"btc: {_total}/{_n} ...and distinct on 200 random draws too",
          _rand_dups == 0)
    check(f"btc: {_total}/{_n} every chunk is positive", all(x > 0 for x in _a))
    _share = _total / Decimal(_n)
    # THE DERIVED BOUND, not the naive one. Each chunk is total * w_i/sum(w)
    # with w_i in [1-j, 1+j], so it lands between (1-j)/(1+j) and (1+j)/(1-j)
    # of the equal share -- normalising (which is what keeps the sum exact)
    # widens the band beyond +/-j. Asserting +/-j here failed, correctly, and
    # the answer was to state the real bound rather than loosen it to whatever
    # happened to pass.
    _j = ghost.SPLIT_JITTER
    _lo = _share * (Decimal(1) - _j) / (Decimal(1) + _j)
    _hi = _share * (Decimal(1) + _j) / (Decimal(1) - _j)
    check(f"btc: {_total}/{_n} no chunk is conspicuous — every one inside the "
          f"derived band, so none is obviously the big or the small one",
          all(_lo <= x <= _hi for x in _a))

# NOT A FIXED PATTERN. Two runs of the same amount must not produce the same
# chunk sizes, or the "unequal" split is just a different constant.
_s1 = _split_or_none(Decimal("0.4"), 4, _R) or []
_s2 = _split_or_none(Decimal("0.4"), 4, _R) or []
check("btc: two runs of the same amount give DIFFERENT chunk sizes",
      _s1 != _s2)

# The quantisation drift must not always land on chunk 0, or "the one that is
# not a round fraction" identifies it in every run.
_firsts = set()
for _ in range(40):
    _x = _split_or_none(Decimal("0.07"), 3, _R) or []
    if _x:
        _firsts.add(_x[0])
check("btc: the remainder is not always put on chunk 0", len(_firsts) > 1)

# CONTROL: one chunk is the whole amount, untouched — a default run is not
# jittered into a different number than the operator typed.
check("control: --split 1 hands over exactly what was asked for",
      _split_or_none(Decimal("0.123456"), 1, _R) == [Decimal("0.123456")])

# DEGENERATE AMOUNTS MUST NEVER PRODUCE A NEGATIVE INSTRUCTION.
#
# The first fallback here divided equally and put the difference on chunk 0,
# so 1 satoshi across 3 chunks came out as [-1, 1, 1] satoshis — an
# instruction to send less than nothing, which summed correctly and passed
# every other check on its way to the operator.
#
# THE BOUND IS 1+2+...+n SATOSHIS, NOT n. n distinct positive amounts need that
# many, and the old bound of n let through totals whose only possible answer
# was repeated deposit amounts -- the Bitcoin-side cluster the split exists to
# remove, returned silently. These totals are all at or above the real
# minimum, so they must come back positive, exact AND distinct.
for _t, _n in [("0.00000006", 3), ("0.00000036", 8), ("0.0000001", 3),
               ("0.00000040", 8)]:
    for _rep in range(60):
        _tiny = _split_or_none(Decimal(_t), _n, _R)
        if _tiny is None or not (all(x > 0 for x in _tiny)
                                 and sum(_tiny, Decimal(0)) == Decimal(_t)):
            break
    check(f"btc: {_t} across {_n} chunks is positive and exact, every time",
          _tiny is not None and all(x > 0 for x in _tiny)
          and sum(_tiny, Decimal(0)) == Decimal(_t))
    check(f"btc: {_t} across {_n} chunks is DISTINCT at the boundary too",
          _tiny is not None and len(set(_tiny)) == _n)

# Below n satoshis there is no correct answer, so it is refused up front
# rather than invented.
_imposs = None
try:
    ghost.resolve_btc_amount(types.SimpleNamespace(
        btc_amount=Decimal("0.00000001"), split=3))
except SystemExit as _e:
    _imposs = str(_e.code)
check("btc: --btc-amount below one satoshi per chunk is REFUSED", _imposs is not None)
check("btc: ...naming the real minimum, which is 1+2+...+n satoshis and not n",
      _imposs and "0.00000006" in _imposs)
check("btc: ...and saying WHY — equal chunks are the Bitcoin-side cluster",
      _imposs and "identical" in _imposs and "deposits" in _imposs)
# THE RANGE THE OLD BOUND LET THROUGH. 4 satoshis across 3 chunks clears "one
# satoshi each" and still cannot be split into three DISTINCT positive amounts
# (that needs 6), so it used to reach split_btc_amount, which returned repeats.
_between = None
try:
    ghost.resolve_btc_amount(types.SimpleNamespace(
        btc_amount=Decimal("0.00000004"), split=3))
except SystemExit as _e:
    _between = str(_e.code)
check("btc: a total with a satoshi per chunk but no DISTINCT split is refused "
      "too — the old bound accepted it and the chunks came back equal",
      _between is not None)

# THE "TOTAL IS EXACT" PROMISE HOLDS FOR EVERY INPUT split_btc_amount ACCEPTS.
#
# It works in integer satoshis, so a sub-satoshi total would come back
# QUANTISED — 0.1234567891 BTC summing to 0.12345679 — silently breaking the
# guarantee its own docstring makes. (The nudge loop this replaced kept the sum
# by putting the sub-satoshi remainder on one chunk, which is the other half of
# the same problem: a chunk that is not a whole number of satoshis and cannot
# be sent.) resolve_btc_amount refuses these at parse time; refusing here too
# means the promise holds for every input the function takes, not merely for
# every input the caller happened to filter.
_subsat = None
try:
    ghost.split_btc_amount(Decimal("0.1234567891"), 3, _R)
except ValueError as _e:
    _subsat = str(_e)
check("btc: a sub-satoshi total is REFUSED rather than silently rounded",
      _subsat is not None)
check("btc: ...and says the total cannot be split into whole satoshis",
      _subsat and "finer than one satoshi" in _subsat)

# ==========================================================================
# DISTINCT IS NOT THE SAME AS DIFFERENT, and the suite could not tell.
#
# mutation_sweep [12] -- "the BTC chunks are all equal again", which zeroes
# SPLIT_JITTER -- SURVIVED the whole suite. Every distinctness check above went
# green, because with the jitter gone the chunks are still technically
# distinct: the exact-total repair spreads the quantisation remainder a satoshi
# at a time, so a four-way split of 0.05 comes back as
#
#     0.01250002  0.01250003  0.01249994  0.01250001
#
# Four different numbers, `len(set(c)) == len(c)`, test passes. And to anyone
# reading the Bitcoin chain that is four payments of the same size -- exactly
# the cluster the jitter exists to break, since the whole point of --split is
# that the deposits should not look like one operator's split of one amount.
#
# So the property has to be about the SPREAD, not about inequality. The
# docstring already states the real bound: each chunk lands between about 0.70x
# and 1.44x of the equal share at j = 0.18.
#
# Measured, as (max - min) / mean, median over 200 draws:
#     real     0.219 - 0.224 across seeds
#     mutated  0.0000072, and identical for every seed
# Four orders of magnitude apart, so 0.02 is nowhere near either.
#
# MEDIAN over many draws, not a per-split floor: the jitter is random, so a
# single split legitimately comes out near-equal sometimes (the minimum
# observed over 400 real draws was 0.00084). A per-split assertion would be a
# flake. A SEEDED rng rather than SystemRandom makes it exactly reproducible
# while still driving the shipped function.
import random as _sprand                                          # noqa: E402
import statistics as _spstat                                      # noqa: E402


def _chunk_spread(total, n, seed=1234, draws=200):
    """Median of (max-min)/mean over `draws` splits. 0 means "all equal".

    _split_or_none, NOT split_btc_amount directly. It raises ValueError when it
    cannot produce n distinct positive chunks, and the first version of this
    helper let that escape -- so mutation [17], which routes every split into
    that raise, KILLED this file instead of failing a check. No RESULT line,
    scored NO-RESULT, and the sweep's own header says that is not a catch. The
    helper twenty lines up exists for exactly this and was written after the
    same mistake. Returning None makes the checks below go red in their own
    words.
    """
    _r = _sprand.Random(seed)
    out = []
    for _ in range(draws):
        _raw = _split_or_none(Decimal(total), n, _r)
        if _raw is None:
            return None
        _c = [float(x) for x in _raw]
        out.append((max(_c) - min(_c)) / (sum(_c) / len(_c)))
    return _spstat.median(out)


for _tot, _n in (("0.05", 4), ("1.0", 3), ("0.5", 8), ("0.01", 2)):
    _sp = _chunk_spread(_tot, _n)
    check(f"btc: {_n} chunks of {_tot} BTC are MEANINGFULLY different, not "
          f"merely non-identical (median spread "
          f"{'REFUSED' if _sp is None else format(_sp, '.3f')}, jitterless is "
          f"~0.00001)", _sp is not None and _sp > 0.02)

# The bound the docstring states, so the spread above cannot come from a jitter
# that has quietly grown into "one chunk carries almost everything".
_r_ext = _sprand.Random(99)
_lo, _hi = 9.9, 0.0
_band_ok = True
for _ in range(300):
    _raw = _split_or_none(Decimal("1.0"), 4, _r_ext)
    if _raw is None:
        _band_ok = False
        break
    _c = [float(x) for x in _raw]
    _mean = sum(_c) / len(_c)
    _lo = min(_lo, min(_c) / _mean)
    _hi = max(_hi, max(_c) / _mean)
check(f"btc: ...and still inside the stated 0.70x-1.44x band "
      f"(saw {_lo:.3f}x-{_hi:.3f}x)",
      _band_ok and 0.68 <= _lo and _hi <= 1.46)

# NON-VACUITY: the measure must actually report ~0 for a genuinely equal split,
# or `> 0.02` is passing for some other reason.
_equal = [1.0, 1.0, 1.0, 1.0]
check("btc: ...and the spread measure reports 0 for a truly equal split",
      (max(_equal) - min(_equal)) / (sum(_equal) / len(_equal)) == 0.0)
check("control: a satoshi-exact total of the same size is accepted and EXACT",
      sum(_split_or_none(Decimal("0.12345679"), 3, _R) or [], Decimal(0))
      == Decimal("0.12345679"))
# AS A NUMBER THE OPERATOR CAN TYPE. Decimal renders small values in
# scientific notation, so this message read "3 chunks need at least 3E-8 BTC"
# — not a figure anyone can enter into a wallet, describing a payment.
check("btc: ...in fixed notation, not scientific", "E-" not in _imposs)
for _v, _want in [("3E-8", "0.00000003"), ("0.5", "0.5"), ("1", "1"),
                  ("1E-7", "0.0000001"), ("0.123456789", "0.12345679")]:
    check(f"btc: fmt_btc({_v}) is typeable -> {_want}",
          ghost.fmt_btc(Decimal(_v)) == _want)
check("control: exactly 1+2+...+n satoshis IS allowed — the bound refuses "
      "below the minimum, it does not refuse the minimum",
      ghost.resolve_btc_amount(types.SimpleNamespace(
          btc_amount=Decimal("0.00000006"), split=3)) is None)
check("control: --split 1 has no such minimum",
      ghost.resolve_btc_amount(types.SimpleNamespace(
          btc_amount=Decimal("0.00000001"), split=1)) is None)
# ...and the splitter itself refuses rather than inventing, if reached directly.
_raised = False
try:
    ghost.split_btc_amount(Decimal("0.00000001"), 3, _R)
except ValueError:
    _raised = True
check("btc: the splitter RAISES on an impossible split rather than returning "
      "a negative amount", _raised)

# JUST BELOW THE FLOOR IT MUST RAISE, NOT RETURN A TIED PAIR.
#
# 2 satoshis across 2 chunks, and 3 across 3, clear "one satoshi each" but sit
# below 1+2+...+n, so no distinct positive split exists. The construction
# leaves the smallest chunk at zero there, and the positivity repair moves a
# satoshi onto it FROM THE LARGEST -- which lands both on the same value. The
# splitter used to return [1, 1] on roughly half the draws and raise on the
# rest: distinct in the branch that promises it, tied in the branch that fixes
# positivity, with nothing between them to notice. resolve_btc_amount refuses
# these totals, so the CLI never reaches them -- but the raise-branch's own
# comment says reaching the splitter means that gate was bypassed, and there it
# must raise EVERY time, never hand back a repeated deposit amount.
#
# Hammered, because the old behaviour was a coin flip: a single draw caught it
# only half the time, which is exactly how the earlier distinctness check let a
# broken repair through a full mutation sweep.
for _bt, _bn in [(2, 2), (3, 3)]:
    _tot = ghost.SATOSHI_BTC * Decimal(_bt)
    _tied = _slipped = 0
    for _rep in range(400):
        try:
            _bx = ghost.split_btc_amount(_tot, _bn, _R)
            _slipped += 1
            if len(set(_bx)) != _bn:
                _tied += 1
        except ValueError:
            pass
    check(f"btc: {_bt} satoshis across {_bn} chunks is REFUSED every time, "
          f"never returned as a repeated deposit amount",
          _slipped == 0 and _tied == 0)

# THE CHUNK ORDER MUST CARRY NO INFORMATION, at every total and not merely at
# convenient ones.
#
# The distinctness construction sorts the chunks, walks the sorted order adding
# +1 to force a strict staircase, then writes back to the ORIGINAL indices --
# and the docstring says that write-back is what stops chunk 0 being
# systematically the smallest. It is not sufficient, because sorted() is
# STABLE: keying on the satoshi value alone puts TIED chunks in original index
# order, so within any tied group the lowest index always received the lowest
# amount. The tell was reintroduced by the sort, one step before the write-back
# that was supposed to remove it.
#
# The earlier check for this counted how often the result came out fully sorted
# and found 1/n!, which is correct -- at 1 BTC, where two chunks essentially
# never tie. The statistic has to be measured where ties are COMMON.
#
# P(chunk[i] < chunk[j]) over all i<j is 0.5 for an unbiased split. Measured on
# the stable-tiebreak version it tracked the tie rate all the way up: 0.501 at
# 1 BTC, 0.514 at 0.00001 BTC, 0.551 at 0.000002, 0.659 at 36 satoshis, 0.688
# at 10 satoshis across 4. Randomising the tie-break returns every one of those
# to ~0.50.
#
# Checked at a DUST total, because that is where ties are guaranteed and so
# where a regression is visible. The band is generous enough not to flake: at
# 8000 ordered pairs the standard error is ~0.006, and the defect this catches
# sat 0.16 away from centre.
_pairs = _conc = 0
for _rep in range(1000):
    _o = _split_or_none(ghost.SATOSHI_BTC * Decimal(60), 8, _R)
    if _o is None:
        continue
    for _i in range(8):
        for _j in range(_i + 1, 8):
            _pairs += 1
            if _o[_i] < _o[_j]:
                _conc += 1
_ratio = (_conc / _pairs) if _pairs else 0
check(f"btc: chunk INDEX carries no information about chunk SIZE even where "
      f"ties are certain — P(a[i]<a[j])={_ratio:.3f}, unbiased is 0.5 "
      f"(a stable sort tie-break made this 0.62)",
      _pairs > 0 and 0.46 <= _ratio <= 0.54)

# Every chunk is a whole number of satoshis — an unsendable amount would be an
# instruction the operator cannot follow. This holds because the TOTAL is
# satoshi-exact: resolve_btc_amount refuses anything finer, which is what makes
# the property true rather than approximately true. Asserting it against a
# sub-satoshi total is how that gap was found.
for _tot in ("0.33333333", "1", "0.07", "0.00012345"):
    _sat = _split_or_none(Decimal(_tot), 3, _R) or []
    check(f"btc: every chunk of {_tot} is a whole number of satoshis",
          all(x == x.quantize(ghost.SATOSHI_BTC) for x in _sat))

_sub = None
try:
    ghost.resolve_btc_amount(types.SimpleNamespace(
        btc_amount=Decimal("0.123456789")))
except SystemExit as _e:
    _sub = str(_e.code)
check("btc: a --btc-amount finer than a satoshi is REFUSED", _sub is not None)
check("btc: ...and refused rather than rounded, because rounding would swap a "
      "different amount than was asked for",
      _sub and "rather than rounding" in _sub)
check("btc: ...and it names both payable amounts either side",
      _sub and "0.12345678" in _sub and "0.12345679" in _sub)
for _ok_amt in ("0.1", "0.00000001", "1", "0.12345678"):
    _r = None
    try:
        ghost.resolve_btc_amount(types.SimpleNamespace(
            btc_amount=Decimal(_ok_amt)))
    except SystemExit as _e:
        _r = str(_e.code)
    check(f"control: --btc-amount {_ok_amt} is payable and allowed", _r is None)
check("control: no --btc-amount at all is fine (manual and receive modes)",
      ghost.resolve_btc_amount(types.SimpleNamespace(btc_amount=None)) is None)


# ==========================================================================
# GAPS FOUND BY MUTATION, NOT BY READING.
#
# A 29-mutation sweep over the guarantees this file claims to protect found
# EIGHT that no test noticed: break them and every suite stayed green. Each
# check below turns exactly one of those red. They are grouped here rather
# than scattered because the thing they have in common is how they were
# found -- reading the code did not surface any of them.
# ==========================================================================
def _addr(seed):
    """A syntactically valid 95-char Monero address, distinct per seed."""
    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    tail = "".join(b58[(seed * (i + 7) + i) % len(b58)] for i in range(93))
    return "4" + b58[seed % 2] + tail


print("\n=== gaps the mutation sweep found ===")

# -- [2][3] the quote loop's two refusals ---------------------------------
# Nothing drove stage2_get_swap_quotes with a bad destination list, so
# deleting either guard changed nothing.
def _quotes(chunks, dests):
    """Run the REAL stage2_get_swap_quotes with the network stubbed."""
    saved = (ghost.safe_post, ghost.btc_per_xmr_oracle, ghost.newnym,
             ghost.secure_delay, ghost.integrity_log)
    try:
        ghost.btc_per_xmr_oracle = lambda *a, **k: None
        ghost.newnym = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        ghost.safe_post = lambda url, payload, proxy: {"routes": [{
            "expectedOutput": "1.0",
            "transaction": {
                "memo": "=:XMR.XMR:" + payload["destinationAddress"] + ":0/1/0::0",
                "depositAddress": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}}]}
        _a = types.SimpleNamespace(allow_unbound_memo=False)
        with contextlib.redirect_stdout(io.StringIO()):
            return ghost.stage2_get_swap_quotes(_a, None, chunks, dests), None
    except SystemExit as e:
        return None, str(e.code)
    except Exception as e:                                   # noqa: BLE001
        # A CRASH IS NOT A PASS AND IT IS NOT A CATCH EITHER.
        #
        # Without the length guard, xmr_dests[i] raises IndexError on the
        # third chunk -- so this helper died and took the whole FILE with it,
        # printing a traceback and no RESULT line. A mutation sweep scores
        # that as NO-RESULT, correctly: a suite that crashed proves nothing
        # about its checks, and a reader sees a broken test rather than a
        # broken guarantee.
        #
        # Returned as an error string instead, so the check below FAILS with
        # its own words. The same pathology bit test_ipleak earlier in this
        # audit; it is the reason that convention exists.
        return None, f"{type(e).__name__}: {e}"
    finally:
        (ghost.safe_post, ghost.btc_per_xmr_oracle, ghost.newnym,
         ghost.secure_delay, ghost.integrity_log) = saved


_E1, _E2, _E3 = _addr(9001), _addr(9002), _addr(9003)
_CH = [Decimal("0.01")] * 3

_r, _m = _quotes(_CH, [_E1, _E2])
check("gap: THREE chunks with TWO destinations is REFUSED — a short list "
      "would re-use an address for the rest, which is the linkage the split "
      "removes", _m is not None)
check("gap: ...and it refuses DELIBERATELY, with a reason — not by crashing "
      "on an index it never checked",
      _m is not None and "Refusing to quote" in _m
      and "IndexError" not in _m)

_r, _m = _quotes(_CH, [_E1, _E2, _E1])
check("gap: two chunks sharing a destination is REFUSED", _m is not None)
check("gap: ...naming the aggregator link as the reason",
      _m and "aggregator" in _m)

_r, _m = _quotes(_CH, [_E1, _E2, _E3])
check("control: three chunks with three distinct destinations is accepted",
      _m is None and _r is not None and len(_r) == 3)

# A MEMO NAMING ANOTHER CHUNK'S ADDRESS MUST BE REFUSED.
#
# The memo is what tells ThorChain where to deliver the XMR, and the deposit
# address is a SHARED inbound vault -- so a memo naming the wrong address
# delivers that chunk's money somewhere else. With one entry there was no
# "wrong address" to name but a stranger's; with N there is now a way for the
# swap to be routed to ANOTHER CHUNK OF THE SAME RUN, which would put two
# chunks on one entry and rebuild the exact linkage the split removes --
# without anything on this side being wrong.
#
# The end-to-end drive in test_send_gates cannot see this: its fake builds
# each memo FROM the payload's own destination, so the memo always matches by
# construction. This drives the guard with a memo that does not.
def _quotes_memo(dests, memo_for):
    """Run the real quote loop where chunk i's memo names memo_for(i)."""
    saved = (ghost.safe_post, ghost.btc_per_xmr_oracle, ghost.newnym,
             ghost.secure_delay, ghost.integrity_log)
    try:
        ghost.btc_per_xmr_oracle = lambda *a, **k: None
        ghost.newnym = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        _n = [0]

        def _post(url, payload, proxy):
            i = _n[0]
            _n[0] += 1
            return {"routes": [{"expectedOutput": "1.0", "transaction": {
                "memo": "=:XMR.XMR:" + memo_for(i) + ":0/1/0::0",
                "depositAddress":
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}}]}
        ghost.safe_post = _post
        _a = types.SimpleNamespace(allow_unbound_memo=False)
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.stage2_get_swap_quotes(_a, None, _CH, dests)
        return None
    except SystemExit as e:
        return str(e.code)
    finally:
        (ghost.safe_post, ghost.btc_per_xmr_oracle, ghost.newnym,
         ghost.secure_delay, ghost.integrity_log) = saved


_E3L = [_E1, _E2, _E3]
check("gap: a memo naming ANOTHER CHUNK's entry address is REFUSED — it would "
      "route two chunks to one entry and rebuild the linkage the split removes",
      _quotes_memo(_E3L, lambda i: _E1) is not None)
check("gap: a memo naming a STRANGER's address is refused",
      _quotes_memo(_E3L, lambda i: _addr(9990)) is not None)
check("control: a memo naming THIS chunk's own address is accepted",
      _quotes_memo(_E3L, lambda i: _E3L[i]) is None)
check("control: ...and each deposit records its own destination",
      _r and [d["xmr_dest"] for d in _r] == [_E1, _E2, _E3])


# -- [20] the exit must hold EVERY entry address --------------------------
# `_addrs[:1]` survived: no test called _exit_hold_list with more than one
# entry. This is the guard that stops a late swap chunk being swept to
# --exit-to in one hop from an address the swap names in public.
_ha = types.SimpleNamespace(entry_veil=True)
_hai = {_E1: (11, 1), _E2: (12, 1), _E3: (13, 1), "mix": (20, 1)}
_hold3 = ghost._exit_hold_list(_ha, _hai, [_E1, _E2, _E3])
check("gap: the exit holds EVERY entry address, not just the first",
      sorted(_hold3) == [(11, 1), (12, 1), (13, 1)])
check("gap: ...and holds nothing else",
      (20, 1) not in _hold3)
check("control: a single entry still yields exactly its own pair",
      ghost._exit_hold_list(_ha, _hai, [_E2]) == [(12, 1)])
check("control: a bare string is still accepted (the one-chunk call shape)",
      ghost._exit_hold_list(_ha, _hai, _E2) == [(12, 1)])
check("control: an entry the wallet does not know is skipped, not crashed on",
      ghost._exit_hold_list(_ha, _hai, [_E1, "unknown"]) == [(11, 1)])


# -- [24] JoinMarket's UTXO count is bounded too ---------------------------
# Nothing drove the JoinMarket path, so removing its cap changed nothing --
# and a tumbler decides its own UTXO count, unlike --split.
_jm = None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        ghost.planned_chunk_count(types.SimpleNamespace(split=1),
                                  ["u"] * (ghost.MAX_SPLIT + 1))
except SystemExit as _e:
    _jm = str(_e.code)
check("gap: more JoinMarket UTXOs than MAX_SPLIT is REFUSED — a tumbler picks "
      "its own count, and past the cap chunks would share entry addresses",
      _jm is not None)
check("gap: ...naming the offline wallet's account limit as the reason",
      _jm and "accounts" in _jm)
check("control: exactly MAX_SPLIT UTXOs is allowed",
      ghost.planned_chunk_count(types.SimpleNamespace(split=1),
                                ["u"] * ghost.MAX_SPLIT) == ghost.MAX_SPLIT)


# -- [26] EVERY entry address is excluded from hop destinations ------------
# `b not in _entry_set` -> `b != list(_entry_set)[0]` survived. The
# adjacency docstring measured 87.5% of runs paying a hop back to an
# unexcluded entry, so this is the guard that measurement produced.
_subs_e = ["m0", "m1", "m2", "m3"]
_entries_e = ["E_a", "E_b"]
_adj = ghost.build_dag_adjacency(_subs_e + _entries_e, _entries_e, 2,
                                 _secretsmod)
_all_dsts = {d for v in _adj.values() for d in v}
check("gap: NO entry address is reachable as a hop destination — not just the "
      "first one", not (_all_dsts & set(_entries_e)))
_leaked = False
for _ in range(60):
    _a2 = ghost.build_dag_adjacency(_subs_e + _entries_e, _entries_e, 2,
                                    _secretsmod)
    if {d for v in _a2.values() for d in v} & set(_entries_e):
        _leaked = True
        break
check("gap: ...over 60 draws, so this is not one lucky shuffle", not _leaked)
check("control: ordinary mix targets ARE reachable, so the exclusion is not "
      "excluding everything", bool(_all_dsts & set(_subs_e)))


# -- [27] the holdings report names EVERY funded entry account ------------
class _HoldRPC:
    """Answers get_balance per account, the way report_holdings asks."""

    def raw_request(self, method, params=None):
        if method == "get_balance":
            return {"balance": 1_000_000_000_000,
                    "unlocked_balance": 1_000_000_000_000}
        if method == "refresh":
            return {}
        raise AssertionError(method)


_hb = io.StringIO()
with contextlib.redirect_stdout(_hb):
    ghost.report_holdings(_HoldRPC(), [11, 12, 13, 20],
                          entry_account=[11, 12, 13])
_ht = _hb.getvalue()
# Anchor on the WARNING, not on "ACCOUNT" -- the listing header above it is
# "ACCOUNTS:", which matched and made this look for the numbers in the wrong
# block entirely.
_i = _ht.index("SWAP ENTRY") if "SWAP ENTRY" in _ht else -1
_warn_line = _ht[max(0, _i - 120):_i + 60] if _i >= 0 else ""
check("gap: the holdings report names EVERY entry account, not just the first",
      _i >= 0 and all(str(a) in _warn_line for a in (11, 12, 13)))
check("gap: ...and warns not to spend them with the rest",
      "Do NOT spend" in _ht)
_hb2 = io.StringIO()
with contextlib.redirect_stdout(_hb2):
    ghost.report_holdings(_HoldRPC(), [11, 12, 13, 20], entry_account=None)
check("control: with no entry account there is no such warning",
      "SWAP ENTRY" not in _hb2.getvalue())


# ==========================================================================
# NOTHING WRITES tx_extra, AND NOTHING MAY START.
#
# Every plan entry used to carry `"extra": secure_hex(16)` -- sixteen
# cryptographically random bytes, at six sites, sitting right next to
# build_entry_veils' measurements of tx_extra SIZE as a fingerprinting vector
# (44 / 131 / 259 bytes). It read exactly like tx_extra randomisation and was
# INERT: airgap_tx_signer never forwarded it to any RPC, and its
# _canonical_plan says so outright, which is also why the signing fingerprint
# never covered it.
#
# It was worse than dead weight. A standard Monero transaction's tx_extra is
# the transaction public key and little else -- the 44 bytes measured there.
# Appending sixteen random bytes would give every transaction this tool makes
# a size no ordinary wallet emits: a unique fingerprint on EVERY hop, not a
# defence on any. So the field is gone rather than "completed", and this is
# what stops the next reader finishing the job.
# ==========================================================================
print("\n=== no plan carries tx_extra ===")

import ast as _ast
_tree = _ast.parse(open(os.path.join(REPO, "GhostSpiral")).read())
_extra_keys = [k.lineno for n in _ast.walk(_tree) if isinstance(n, _ast.Dict)
               for k in n.keys
               if isinstance(k, _ast.Constant) and k.value == "extra"]
check("tx_extra: NO plan-building dict in GhostSpiral carries an 'extra' key",
      not _extra_keys)

# ...and the signer would ignore it anyway, so a re-added field would be
# silently inert rather than loudly wrong. Both halves stated.
_ag_src = open(os.path.join(REPO, "airgap_tx_signer")).read()
check("tx_extra: the signer still documents that it never forwards 'extra', "
      "so re-adding the field would be inert, not effective",
      "never forwards" in _ag_src)

# The real plans this suite builds must not carry it either -- an AST check
# alone would miss a field added by dict-update or **kwargs.
_saved_cfa3 = ghost.create_fresh_account
try:
    _c3 = [90]

    def _f6(rpc, label=""):
        _c3[0] += 1
        return _c3[0]
    ghost.create_fresh_account = _f6
    with contextlib.redirect_stdout(io.StringIO()):
        _vp3, _ = ghost.build_entry_veils(_XferRPC(_one), [("E0", 10, 1)])
finally:
    ghost.create_fresh_account = _saved_cfa3
_dp3 = _hop_plan(_BY_OK, [list(_ALL)])
_fp3, _, _ = _dist([("C0", 20, 1)], [["m0", "m1"]],
                   {"m0": Decimal("1"), "m1": Decimal("1")})
for _lbl, _plan3 in (("veil", _vp3), ("DAG hop", _dp3), ("fan-out", _fp3)):
    check(f"tx_extra: a real {_lbl} plan entry carries no 'extra' field",
          all("extra" not in t for t in _plan3))


# ==========================================================================
# --deep BUYS NO TRANSACTIONS, and it no longer costs anything either.
#
# `rounds = wallets * 2 * deep` read as "one transaction per round", with
# `deep` sitting in it as though depth meant more hop ROUNDS. It does not:
# --deep multiplies the DAG adjacency's out-degree, assign_hop_destinations
# still gives every source exactly ONE destination, and _stage5_run runs
# exactly one DAG round. The knob scaled the fee reserve linearly while the
# transaction count stayed put, and the difference was not distributed -- it
# became change, swept once, reported UNMIXED.
#
# That was left standing as a deliberate safety margin, on the argument that a
# live chain's real fee could not be measured from here. It can now: the
# reserve is one fee per transaction _runtime_terms counts, and that count
# reproduces two measured runs exactly. So `deep` is gone from the fee math
# and the RUN SHAPE is what drives it.
# ==========================================================================
print("\n=== the fee reserve follows the shape, not --deep ===")

_ufan, _ffan, _rfan = ghost.compute_fee_budget(
    Decimal("10"), Decimal("0.0024"), 12,
    peel=False, dag_mixing=True, exit_set=False)
_upeel, _fpeel, _rpeel = ghost.compute_fee_budget(
    Decimal("10"), Decimal("0.0024"), 12,
    peel=True, dag_mixing=True, exit_set=True)
check("shape: a peel chain with an exit reserves more than a bare fan-out",
      _fpeel > _ffan and _rpeel > _rfan)
check("shape: ...so less of the balance is distributed under --peel",
      _upeel < _ufan)
check("shape: the reserve is exactly one hop_fee_reserve per counted "
      "transaction",
      _fpeel == ghost.hop_fee_reserve(Decimal("0.0024")) * _rpeel)
check("shape: --deep cannot change it -- it is not a parameter any more",
      "deep" not in __import__("inspect").signature(
          ghost.compute_fee_budget).parameters)
# THE MEASURED RUN. --wallets 4 --deep 2 --peel --dag-mixing relayed 36
# transactions and paid 0.072714 XMR; the old formula reserved 0.05760.
_mu, _mf, _mr = ghost.compute_fee_budget(
    Decimal("12"), Decimal("0.0024"), 4,
    peel=True, dag_mixing=True, exit_set=True)
check(f"shape: the measured peel+DAG run's reserve ({_mf}) now covers the "
      f"0.072714 XMR it actually spent", _mf > Decimal("0.072714"))
check("shape: ...and the formula it replaced did not",
      Decimal("0.0024") * ghost.FEE_SAFETY_MARGIN * 4 * 2 * 2
      < Decimal("0.072714"))

# The transaction count does NOT move with --deep. Same sources, same targets,
# one destination each, whatever the adjacency out-degree.
_subs_d = [f"m{i}" for i in range(8)]
_ai_d = {a: (50 + i, 1) for i, a in enumerate(_subs_d)}
_by_d = {a: Decimal("1") for a in _subs_d}
_counts = []
for _deep in (1, 2, 6):
    _adj = ghost.build_dag_adjacency(_subs_d, [], _deep, _secretsmod)
    with contextlib.redirect_stdout(io.StringIO()):
        _pl = ghost.build_dag_plan(
            types.SimpleNamespace(dag_mixing=True, deep=_deep),
            Decimal("0.0024"), list(_subs_d), _by_d, _adj, _subs_d, _ai_d,
            _secretsmod, dest_slices=[list(_subs_d)])
    _counts.append(len(_pl))
check(f"deep: the DAG round makes the SAME number of hops at --deep 1/2/6 "
      f"{_counts} — the knob buys no transactions",
      len(set(_counts)) == 1 and _counts[0] > 0)

# ...and the help says all of that, so an operator is not turning a knob that
# quietly moves their money out of the mix.
_gs_help = open(os.path.join(REPO, "GhostSpiral")).read()
_dh = _gs_help[_gs_help.index('"--deep"'):]
_dh = _dh[:_dh.index("cli.add_argument", 10)]
# JOIN THE ADJACENT LITERALS FIRST. Help text is wrapped across concatenated
# f-strings, so a phrase that reads continuously to an operator ("unmixed
# change") is split by `" ... "\n f"` in the source and a plain substring
# search misses it. Searching the raw source for operator-facing wording is a
# check that fails for the wrong reason -- or passes for one.
_dh = re.sub(r'"\s*\n\s*f?"', "", _dh)
check("deep: the help no longer calls it a 'depth multiplier' full stop",
      "does NOT add hop rounds" in _dh)
check("deep: ...and says the fee reserve no longer follows it",
      "fee reserve" in _dh and "no longer costs anything" in _dh)
check("deep: ...and no longer claims it pushes money out of the mix, "
      "because it does not",
      "unmixed change" not in _dh)



# ==========================================================================
# THE ONE TRANSACTION THAT LOOKS DIFFERENT.
#
# --dag-mixing announces itself when it is OFF. --peel does not, and its
# absence is the one that shows up on the chain.
#
# Measured on a completed run against a real chain: eleven transactions
# relayed, ten of them 1-input / 2-output / 44-byte tx_extra / ~0.0018 XMR fee
# -- the shape of an ordinary Monero payment. The fan-out was the eleventh:
# 8 outputs, a 291-byte tx_extra, and a 0.0045 XMR fee. All three are public
# and all three scale with the output count.
#
# And the entry veil's notice, printed moments earlier, says the transaction
# spending the swap output is "an ordinary 2-output send rather than one an
# analyst can pick out by shape" -- true of the veil, and the only thing it is
# true of. Read alone it suggests shape has been handled.
# ==========================================================================
print("\n=== the distribution says what shape it leaves ===")

_sh_saved = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
try:
    def _shape(peel, n, fee_out=False):
        _o = io.StringIO()
        with contextlib.redirect_stdout(_o):
            ghost.announce_distribution_shape(
                types.SimpleNamespace(peel=peel), n, fee_out=fee_out)
        return _o.getvalue()

    _d = _shape(False, 8)
    check("shape: the default fan-out announces itself",
          "ONE fan-out transaction creating 8 outputs" in _d)
    # THE COUNT MUST MATCH WHAT AN ANALYST WILL COUNT. This paragraph's whole
    # subject is that the output count is public, and it quoted the MIX count
    # while --usage-fee builds one more output than that. Off by one is the
    # one wrong number the operator has nothing to check against.
    _dfee = _shape(False, 8, fee_out=True)
    check("shape/fee: with a usage fee the announced count is the REAL one, "
          "not the mix count",
          "creating 9 outputs" in _dfee
          and "creating 8 outputs" not in _dfee)
    check("shape/fee: ...and says which output the extra one is",
          "8 of those are the mix" in _dfee and "usage fee" in _dfee)
    check("shape/fee: ...and why it is not a shape of its own — the mix count "
          "is already randomised over a wider range than one output",
          "decoys drawn at run time" in _dfee)
    check("shape/fee: ...and does not send the operator to a --peel run that "
          "will be refused",
          "refused together" in _dfee)
    # NON-VACUITY: without the fee, none of that is printed, so the lines above
    # are the fee branch's and not boilerplate on every run.
    check("shape/fee: NON-VACUITY -- a run with no fee says none of it",
          "of those are the mix" not in _d and "refused together" not in _d)
    check("shape: ...naming all three public tells, not just the output count",
          "output count" in _d and "tx_extra" in _d and "fee" in _d)
    check("shape: ...correcting the veil notice rather than repeating it",
          "does not make it ordinary" in _d)
    check("shape: ...and naming the flag that removes it, with its real cost",
          "--peel" in _d and "8 * 20 min" in _d)
    check("shape: the count is the run's own, not a fixed example",
          "25 outputs" in _shape(False, 25))

    # SILENT WHEN PEELING. A notice that fires on the run that already made
    # the stronger choice is noise, and noise is what gets tuned out.
    check("shape: --peel says nothing, because there is nothing to warn about",
          _shape(True, 8) == "")
finally:
    ghost.integrity_log = _sh_saved

# It has to be REACHED. Announcing correctly from a function nothing calls is
# the same as not announcing.
from srcutil import code_only as _code_only_dg                  # noqa: E402
_sh_src = " ".join(_code_only_dg(os.path.join(REPO, "GhostSpiral")).split())
check("shape: build_distribution_plan calls it where the mode is decided, "
      "and tells it whether this run carries a fee output",
      'distribution_mode = "peel" if args.peel else "fanout" '
      "announce_distribution_shape(args, fanout_count, "
      "fee_out=bool(fee_addr and fee_amt > 0))" in _sh_src)
# Symmetry with the notice it was modelled on: both must exist, or the pair
# reads as "DAG matters, peel does not".
check("shape: ...and the DAG-off notice it mirrors is still there",
      "Run with --dag-mixing to" in _sh_src)


# ===========================================================================
#  min_fanout_usable: a minimum an operator can actually be TOLD
# ===========================================================================
#
# compute_fanout_amounts draws random weights, so its exact threshold moves
# seed to seed. A UI that shows "minimum X" is making a promise, and a figure
# that happens to work for one draw is not one. These checks hold the helper to
# "funds on EVERY draw", and pin the margin it pays for that.
print("\n-- the minimum a UI is allowed to display --")
_MFU_FEE = ghost.FALLBACK_FEE_XMR
_mfu_rng = secrets.SystemRandom()
_MFU_N = (3, 5, 10, 20, 40, 60)          # 3 = MIN_WALLETS, 60 = the CLI's max


def _mfu_funds(usable, n, draws=150):
    """How many of `draws` real SystemRandom plans this usable actually funds."""
    return sum(1 for _ in range(draws)
               if len(ghost.compute_fanout_amounts(
                   usable, n, _MFU_FEE, True, rng=_mfu_rng)) == n)


for _n in _MFU_N:
    _m = ghost.min_fanout_usable(_n, _MFU_FEE, True)
    check(f"min: --wallets {_n} at {_m} XMR funds the fan-out on every draw",
          _mfu_funds(_m, _n) == 150)

# NON-VACUITY (a): the bound must be a BOUND, not a number so large that any
# value passes. One DUST tick below it, the smallest step the grid allows, the
# plan must still be fundable -- i.e. the helper is not wildly over-reserving.
for _n in (10, 60):
    _m = ghost.min_fanout_usable(_n, _MFU_FEE, True)
    check(f"min: NON-VACUITY -- --wallets {_n} is not over-reserved; one tick "
          f"below still funds, so the margin is small",
          _mfu_funds(_m - ghost.DUST_XMR, _n, draws=60) == 60)

# NON-VACUITY (b): well below the bound it must FAIL, or "funds on every draw"
# is a claim about a function that never refuses anything.
for _n in (10, 60):
    _m = ghost.min_fanout_usable(_n, _MFU_FEE, True)
    check(f"min: NON-VACUITY -- --wallets {_n} at HALF the bound is refused",
          _mfu_funds(_m / 2, _n, draws=40) == 0)

# THE DISTINCTNESS STAIRCASE IS THE CONSTRAINT THAT BITES, and a bound derived
# from the fundability floor alone is wrong in the dangerous direction. At
# --wallets 60 the staircase needs 60*59/2 = 1770 DUST ticks = 0.177 XMR, more
# than min_exit_fundable asks for. This pins that the helper accounts for it.
_floor_only = (ghost.min_exit_fundable(_MFU_FEE, True) * Decimal(60)
               / ghost.FANOUT_SPEND_FRACTION)
check("min: the bound exceeds the fundability floor alone, because the "
      "distinctness staircase costs more than the floor at 60 wallets",
      ghost.min_fanout_usable(60, _MFU_FEE, True) > _floor_only)
check("min: NON-VACUITY -- the floor-only figure really is insufficient, so "
      "the line above is not a tautology",
      _mfu_funds(_floor_only.quantize(ghost.DUST_XMR), 60, draws=40) == 0)

# Degenerate inputs must not raise -- a UI may ask before the operator has
# chosen a wallet count.
check("min: a zero/negative wallet count returns 0 rather than raising",
      ghost.min_fanout_usable(0, _MFU_FEE, True) == 0
      and ghost.min_fanout_usable(-5, _MFU_FEE, True) == 0)
# ...and the DAG-off branch is a real, smaller floor, not the same number.
check("min: --dag-mixing off has its OWN smaller floor, since an output that "
      "never hops reserves one fewer transaction",
      ghost.min_fanout_usable(10, _MFU_FEE, False)
      < ghost.min_fanout_usable(10, _MFU_FEE, True))
check("min: NON-VACUITY -- the dag-off bound still funds a dag-off plan",
      sum(1 for _ in range(60)
          if len(ghost.compute_fanout_amounts(
              ghost.min_fanout_usable(10, _MFU_FEE, False), 10, _MFU_FEE,
              False, rng=_mfu_rng)) == 10) == 60)

# ===========================================================================
#  mix_minimum_xmr: the figure a UI is allowed to print, cut included
# ===========================================================================
print("\n-- the balance minimum, decoys and the operator's cut included --")
_MM_CUT = Decimal("0.011")               # the shipped operator cut

# THE ASSUMPTION THE WHOLE HELPER RESTS ON. mix_minimum_xmr reads the fee
# reserve out of compute_fee_budget at an arbitrary balance, which is only
# legitimate because total_fees does not depend on the balance. Pinned here
# rather than believed, because every figure below is wrong if it stops holding.
#
# WHAT IT DOES NOT SAY is that the run's usable equals its balance minus this
# reserve. compute_fee_budget's own return does; the PATH does not, because
# size_and_prune_chunks takes the entry veils' fee off first. Reading the two
# checks below as one statement about the run is exactly the mistake that put
# a short minimum in front of operators -- see _mm_survives.
_mm_fees = {b: ghost.compute_fee_budget(Decimal(b), _MFU_FEE, 10, peel=False,
                                        dag_mixing=True, exit_set=True)[1]
            for b in ("0.3", "1", "10", "1000")}
check("min: total_fees does not depend on the balance, which is what lets the "
      "helper read the reserve out at any balance",
      len(set(_mm_fees.values())) == 1)
check("min: ...and usable is exactly balance minus that reserve",
      all(ghost.compute_fee_budget(Decimal(b), _MFU_FEE, 10, peel=False,
                                   dag_mixing=True, exit_set=True)[0]
          == Decimal(b) - _mm_fees[b] for b in _mm_fees))

# DECOYS. The fan-out funds wallets + randint(DECOY_MIN, DECOY_MAX), drawn at
# run time, so a minimum computed from `wallets` alone is short by up to
# DECOY_MAX outputs and survives only a lucky draw.
check("min: the balance minimum accounts for the decoys the operator does not "
      "choose, so it exceeds one computed from --wallets alone",
      ghost.mix_minimum_xmr(_MFU_FEE, 10)
      > ghost.min_fanout_usable(10, _MFU_FEE, True))
check("min: NON-VACUITY -- the decoy count is really drawn above zero, so the "
      "line above is not comparing a number to itself",
      ghost.DECOY_MIN >= 1 and ghost.DECOY_MAX > ghost.DECOY_MIN)


class _MMArgs:
    """The three fields size_and_prune_chunks reads off `args`."""

    peel = False
    dag_mixing = True
    exit_veil = True
    entry_veil = True

    def __init__(self, wallets):
        self.wallets = wallets
        self.exit_to = ["x"]


def _mm_survives(bal, wallets, cut=None, draws=120, chunks=1):
    """Drive THE SHIPPED PATH at `bal` and count the draws that plan.

    THIS USED TO RE-DERIVE THE BUDGET INSTEAD OF CALLING IT, and that is why it
    stayed green through a real shortfall. It computed

        _usable = bal - _fees - _cut

    which is mix_minimum_xmr's docstring premise, not the code. The shipped
    stage-4 path is size_and_prune_chunks, and its FIRST act is to take the
    entry veils' fee reserve off the balance -- one hop_fee_reserve per chunk
    -- BEFORE compute_fee_budget ever sees it. The published minimum was short
    by exactly that, so a deposit of precisely the advertised figure planned
    fine in this test and failed on the vault, at stage 4, after the swap had
    settled on an address the swap memo names publicly.

    So this now calls size_and_prune_chunks itself, over the real chunk splits
    split_btc_amount produces and the real decoy draw, and asks the one
    question that matters: did every mix target get an amount?
    """
    _n = wallets + ghost.DECOY_MAX
    _dests = ["d%d" % i for i in range(_n)]
    _ok = 0
    # STDOUT SUPPRESSED, because the non-vacuity draws below are MEANT to fail
    # and each failure prints the operator's chunk-dropped warning. Left on,
    # the suite's own result scrolls past a thousand lines of correct output
    # from a check that is asserting the failure happened.
    import contextlib as _ctx_mm
    import io as _io_mm
    with _ctx_mm.redirect_stdout(_io_mm.StringIO()):
        for _ in range(draws):
            _bal = bal - ((bal * cut).quantize(ghost.DUST_XMR) if cut
                          else Decimal(0))
            _weights = ghost.split_btc_amount(Decimal(1), chunks, _mfu_rng)
            _unlocked = [_bal * _wt for _wt in _weights]
            _entries = [("a%d" % i, i) for i in range(chunks)]
            try:
                _r = ghost.size_and_prune_chunks(
                    _MMArgs(wallets), _entries, _unlocked, _dests, _bal,
                    _MFU_FEE, _mfu_rng)
            except SystemExit:
                continue
            # (entries, unlocked, bal, usable, slices, slice_usable, amounts)
            if (len(_r[6]) == _n and all(_sl for _sl in _r[4])
                    and len(_r[0]) == chunks):
                _ok += 1
    return _ok


for _w in (3, 10, 20, 60):
    _b = ghost.mix_minimum_xmr(_MFU_FEE, _w, usage_pct=_MM_CUT)
    check(f"min: --wallets {_w} at {_b} XMR still funds the fan-out on every "
          f"draw AFTER the 1.1% cut is taken",
          _mm_survives(_b, _w, _MM_CUT) == 120)
    check(f"min: ...and the cut it yields ({(_b * _MM_CUT).quantize(ghost.DUST_XMR)}) "
          f"is worth more than the fee to spend it",
          (_b * _MM_CUT).quantize(ghost.DUST_XMR)
          > ghost.hop_fee_reserve(_MFU_FEE))

# THE ENTRY VEIL'S FEE, WHICH THE PUBLISHED MINIMUM USED TO OMIT.
#
# size_and_prune_chunks subtracts hop_fee_reserve per chunk before it budgets,
# so a figure that only covered min_fanout_usable + total_fees was short by
# exactly one reserve on a single-chunk run. On a decoy draw of DECOY_MAX --
# one run in six -- that shortfall took every plan with it. Driven WITHOUT the
# cut, because the cut's own floor is larger below ~15 wallets and would hide
# the mixing shortfall behind it.
for _w in (3, 10, 20, 60):
    for _dag in (True, False):
        _b = ghost.mix_minimum_xmr(_MFU_FEE, _w, dag_mixing=_dag)
        _MMArgs.dag_mixing = _dag
        check(f"min: --wallets {_w} dag={_dag} at {_b} XMR plans through the "
              f"real size_and_prune_chunks on every draw, veil fee included",
              _mm_survives(_b, _w) == 120)
        check(f"min: NON-VACUITY -- one hop_fee_reserve less than {_b} does "
              f"NOT plan on every draw, so the reserve is what carries it",
              _mm_survives(_b - ghost.hop_fee_reserve(_MFU_FEE), _w) < 120)
_MMArgs.dag_mixing = True

# EVERY CARRIER, NOT THE SUM OF THEM. With --split N the money lands on N entry
# addresses and each one funds its own slice out of its own share, so a global
# figure that clears min_fanout_usable can still leave the poorest chunk unable
# to pay for its outputs -- which drops that chunk, strands its value on an
# address the exit holds back, and can then shortfall the rest of the run.
#
# BOTH VALUES OF --dag-mixing, and the second one is not padding. The first
# version of this ran dag=True only, and the shapes where the per-chunk veil
# reserve is load-bearing are mostly dag=False: an output that never hops
# reserves one transaction fewer, so the whole budget is tighter and a missing
# veil fee has less margin to hide in. A mutation that counted the reserve once
# however many chunks survived the dag=True grid untouched.
#
# AND THE SMALL WALLET COUNTS, which is where a split bites hardest: the same
# chunk count over fewer mix targets means each carrier's slice is a larger
# share of a smaller budget. Shapes resolve_split refuses outright are skipped
# rather than driven -- they cannot reach this code at all.
for _c in (2, 4, 6, 8):
    for _dag in (True, False):
        _MMArgs.dag_mixing = _dag
        for _w in (4, 6, 10, 20, 60):
            if _c > _w + ghost.DECOY_MIN:
                continue
            _b = ghost.mix_minimum_xmr(_MFU_FEE, _w, dag_mixing=_dag,
                                       chunks=_c)
            check(f"min: --split {_c} --wallets {_w} dag={_dag} at {_b} XMR "
                  f"plans on every draw, every carrier funding its own slice",
                  _mm_survives(_b, _w, chunks=_c) == 120)
    _MMArgs.dag_mixing = True
    check(f"min: NON-VACUITY -- the single-chunk figure does NOT survive "
          f"--split {_c}, so wiring the chunk count is doing real work",
          _mm_survives(ghost.mix_minimum_xmr(_MFU_FEE, 10), 10,
                       chunks=_c) < 120)
    check(f"min: ...and --split {_c} therefore asks for strictly more than "
          f"one chunk does",
          ghost.mix_minimum_xmr(_MFU_FEE, 10, chunks=_c)
          > ghost.mix_minimum_xmr(_MFU_FEE, 10))

# ONE VEIL FEE PER CHUNK, DRIVEN AT A SHAPE WHERE IT ACTUALLY BINDS.
#
# Every entry address gets its own veil transaction and its own fee, so the
# reserve is hop_fee_reserve * chunks. Counting it ONCE looks harmless -- the
# figure only drops by (chunks-1) fees, and min_carrier_usable's margin
# absorbs that at most shapes. It does not absorb it everywhere: driven over
# every fee priority, chunk count, wallet count and dag/exit setting, the
# once-counted figure failed at 235 of them, concentrated at six chunks and up
# and at dag=False.
#
# The shape pinned here is the one that fails HARDEST, not a convenient one:
# --split 7 --wallets 6 with DAG mixing off, at the fallback fee, failed 218
# of 300 draws when the veil reserve was counted once. Picking a shape that
# only fails a few draws in a hundred would make this check flaky, which is
# its own kind of untrue.
_MMArgs.dag_mixing = False
_v_full = ghost.mix_minimum_xmr(_MFU_FEE, 6, dag_mixing=False, chunks=7)
_v_once = _v_full - 6 * ghost.hop_fee_reserve(_MFU_FEE)
check("min: --split 7 --wallets 6 without DAG mixing plans on every draw at "
      "the published figure",
      _mm_survives(_v_full, 6, chunks=7) == 120)
check("min: NON-VACUITY -- the same figure with ONE veil fee instead of seven "
      "does NOT, so the per-chunk reserve is load-bearing and not margin",
      _mm_survives(_v_once, 6, chunks=7) < 120)
_MMArgs.dag_mixing = True

# --print-limits IS THE ONLY WAY A CALLER THAT CANNOT IMPORT THIS FILE GETS A
# MINIMUM, and its own tiny parser has to carry every flag the figure depends
# on. It parses with parse_known_args, so a flag it does not declare is not an
# error -- it is silently dropped, limits_report's getattr falls back to one
# chunk, and a split run is quoted the single-chunk floor. Driven through the
# real entry point rather than by reading the parser.
import json as _json_pl                                       # noqa: E402
_pl_saved = sys.argv[:]
try:
    def _pl(argv):
        sys.argv = ["GhostSpiral"] + argv
        _buf = io.StringIO()
        with contextlib.redirect_stdout(_buf):
            _done = ghost.maybe_print_limits()
        return _done, _json_pl.loads(_buf.getvalue())

    _d1, _r1 = _pl(["--print-limits", "--wallets", "10", "--dag-mixing",
                    "--exit-to", "x"])
    _d8, _r8 = _pl(["--print-limits", "--wallets", "10", "--dag-mixing",
                    "--exit-to", "x", "--split", "8"])
    check("limits: --print-limits handles the run and stops main()",
          _d1 is True and _d8 is True)
    check("limits: it reports the chunk count it computed for, so a reader "
          "can tell which question was answered",
          _r1.get("split") == 1 and _r8.get("split") == 8)
    check("limits: ...and --split really reaches the figure, rather than "
          "being dropped by parse_known_args",
          _r8["by_wallets"]["10"]["min_xmr"] != _r1["by_wallets"]["10"]["min_xmr"])
    check("limits: ...to exactly the split-aware minimum the pipeline uses",
          _r8["by_wallets"]["10"]["min_xmr"]
          == str(ghost.mix_minimum_xmr(
              ghost.FALLBACK_FEE_BY_PRIORITY[1], 10, dag_mixing=True,
              exit_set=True, chunks=8)))
    check("limits: ...and the cut row is split-aware too",
          _r8["by_wallets"]["10"]["min_xmr_with_cut"]
          != _r1["by_wallets"]["10"]["min_xmr_with_cut"])
    check("limits: the payload says the minimum is per-run and rises with "
          "--split, so a page cannot quote it as a fixed floor",
          "split" in _r8.get("split_note", ""))
    check("limits: NON-VACUITY -- every wallet count the CLI accepts has a "
          "row, so the checks above are not reading a one-row table",
          len(_r8["by_wallets"]) == ghost.MAX_WALLETS - ghost.MIN_WALLETS + 1)
finally:
    sys.argv = _pl_saved

# min_carrier_usable's own two bounds, stated as the code states them.
check("min: min_carrier_usable is min_fanout_usable exactly at one chunk, so "
      "the split-aware bound cannot move the single-chunk figure",
      ghost.min_carrier_usable(17, 1, _MFU_FEE, True)
      == ghost.min_fanout_usable(17, _MFU_FEE, True))
check("min: ...and is never below it at any chunk count, wallet count or "
      "fee priority",
      all(ghost.min_carrier_usable(_n, _c, _f, _d)
          >= ghost.min_fanout_usable(_n, _f, _d)
          for _f in ghost.FALLBACK_FEE_BY_PRIORITY.values()
          for _n in (5, 10, 17, 27, 67)
          for _c in range(1, ghost.MAX_SPLIT + 1)
          for _d in (True, False)))
# NOT MONOTONIC IN THE CHUNK COUNT, AND THE RUN IS NOT EITHER. Splitting one
# more way gives each carrier a poorer share AND a smaller slice, and
# min_fanout_usable is superlinear in the slice, so the second can outweigh the
# first. Pinned as an observation rather than left to surprise a reader who
# "fixes" it with a running max: bisecting the REAL size_and_prune_chunks for
# the 100%-success floor at --wallets 3 --dag-mixing gives 0.2699 XMR at
# --split 4 and 0.2666 at --split 5. The dip is in the pipeline, not in the
# bound, and forcing the published figure to rise would be inventing a rule the
# code does not have.
check("min: NON-VACUITY -- the chunk count really moves the figure, so the "
      "bound above is not constant in it",
      len({ghost.min_carrier_usable(17, _c, _MFU_FEE, True)
           for _c in range(1, ghost.MAX_SPLIT + 1)}) >= ghost.MAX_SPLIT - 1)

# THE SLICE-COUNT BOUND min_carrier_usable IS DERIVED FROM. An earlier version
# assumed a carrier never holds more than ceil(n * share) + 1 targets; at 67
# targets split_by_weight really hands out five more than that, and the
# minimum built on it was short at --wallets 60. The bound that replaced it is
# stated in two halves, and both are driven here against the real function over
# weight vectors far wider than split_btc_amount's jitter band.
_sbw_bad = 0
for _ in range(4000):
    _c = _mfu_rng.randint(2, ghost.MAX_SPLIT)
    _n = _mfu_rng.randint(_c, ghost.MAX_WALLETS + ghost.DECOY_MAX)
    _wts = [Decimal(_mfu_rng.randint(1, 1000)) for _ in range(_c)]
    _tot = sum(_wts)
    for _i, _part in enumerate(ghost.split_by_weight(list(range(_n)), _wts)):
        _bound = max(max(1, int(Decimal(_n) * _wts[_i] / _tot)), _n // _c + 1)
        if len(_part) > _bound:
            _sbw_bad += 1
check("min: split_by_weight never gives a carrier more than "
      "max(floor(n*share), n//chunks + 1) targets -- the bound "
      "min_carrier_usable inverts",
      _sbw_bad == 0)
check("min: NON-VACUITY -- the loop above really ran over many slices",
      _sbw_bad == 0 and ghost.MAX_SPLIT >= 2)

# THE CUT IS THE BINDING CONSTRAINT AT A DEFAULT RUN, and that is the finding
# worth pinning: an operator reading only the mixing minimum would be told a
# figure at which their own cut is uncollectable.
check("min: enabling the cut RAISES the minimum at the default --wallets 10",
      ghost.mix_minimum_xmr(_MFU_FEE, 10, usage_pct=_MM_CUT)
      > ghost.mix_minimum_xmr(_MFU_FEE, 10))
check("min: ...and at --wallets 10 it is the CUT that binds, not the mix -- "
      "the raised figure is the spendability floor, not the mixing one",
      ghost.mix_minimum_xmr(_MFU_FEE, 10, usage_pct=_MM_CUT)
      == ((ghost.hop_fee_reserve(_MFU_FEE) + ghost.DUST_XMR)
          / _MM_CUT).quantize(ghost.DUST_XMR, rounding=ROUND_UP))
# NON-VACUITY: at a LARGE wallet count the mix binds again, so the max() is a
# real choice between two constraints rather than one that always wins.
check("min: NON-VACUITY -- at --wallets 60 the MIX binds instead, so the "
      "helper is choosing between two constraints",
      ghost.mix_minimum_xmr(_MFU_FEE, 60, usage_pct=_MM_CUT)
      > ((ghost.hop_fee_reserve(_MFU_FEE) + ghost.DUST_XMR)
         / _MM_CUT).quantize(ghost.DUST_XMR, rounding=ROUND_UP))
# NON-VACUITY: well below the minimum the cut really is uncollectable, or
# "spendable at the minimum" is a claim about a threshold that never bites.
check("min: NON-VACUITY -- at a balance below the minimum the cut is worth "
      "less than the fee to move it, which is why the floor exists",
      (Decimal("0.2") * _MM_CUT).quantize(ghost.DUST_XMR)
      < ghost.hop_fee_reserve(_MFU_FEE))
check("min: a cut of zero or None leaves the mixing minimum untouched",
      ghost.mix_minimum_xmr(_MFU_FEE, 10, usage_pct=Decimal(0))
      == ghost.mix_minimum_xmr(_MFU_FEE, 10, usage_pct=None)
      == ghost.mix_minimum_xmr(_MFU_FEE, 10))

# ===========================================================================
#  THE OPERATOR'S USAGE FEE
# ===========================================================================
print("\n-- the operator's usage fee --")
import contextlib as _ctx_c                                  # noqa: E402
_FEE_A1 = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
_FEE_A2 = "43ZYYZBkwxZJNJFo6rGHf5KREAGR3LizKKXN3aPDCHYj1AAfkqEipXs4x9nnrTq2FuaqXMqLrVtED1kV2Z77b6NGE6FFTCm"


class _FeeArgs:
    pass


def _fee_args(**kw):
    a = _FeeArgs()
    a.usage_fee = True
    a.usage_fee_pct = None
    a.usage_fee_address = None
    a.exit_to = None
    a.btc_entry = None
    a.wallets = 10
    a.dag_mixing = True
    a.peel = False
    a.split = 1
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def _resolve_fee(a):
    """resolve_usage_fee with the chain silenced. Returns "" or the refusal."""
    _old = ghost.integrity_log
    ghost.integrity_log = lambda *x, **y: None
    for _v in ("GS_USAGE_FEE_ADDRESS", "GS_USAGE_FEE_PCT"):
        os.environ.pop(_v, None)
    try:
        with _ctx_c.redirect_stdout(io.StringIO()):
            ghost.resolve_usage_fee(a)
        return ""
    except SystemExit as e:
        return str(e)
    finally:
        ghost.integrity_log = _old


# OFF BY DEFAULT. A run that was not asked to skim must not skim, and this is
# the check that a future default flip has to walk past.
check("fee: no cut is taken unless it is asked for",
      _resolve_fee(_fee_args(usage_fee=False)) == ""
      and _fee_args(usage_fee=False).usage_fee_pct is None)
_a = _fee_args()
check("fee: --usage-fee alone takes the shipped default",
      _resolve_fee(_a) == "" and _a.usage_fee_pct == ghost.USAGE_FEE_PCT)
check("fee: NON-VACUITY -- the shipped default really is 1.1%",
      ghost.USAGE_FEE_PCT == Decimal("0.011"))

# THE TWO COMBINATIONS THAT CHARGE AND NEVER PAY. Both were real: the peel
# branch of build_distribution_plan has no cut destination while the deduction
# is unconditional, and a split cut is checked against the total but paid as N
# separate outputs. Refused, not patched -- the same answer --split N --peel
# already gets.
check("fee: --peel is REFUSED, because only the fan-out branch pays a cut and "
      "the deduction is unconditional",
      "--usage-fee with --peel is refused" in _resolve_fee(_fee_args(peel=True)))
check("fee: --split > 1 is REFUSED, because a partial relay pays a partial "
      "cut and each chunk's share can be individually unspendable",
      "is refused" in _resolve_fee(_fee_args(split=4)))
# NON-VACUITY: both flags must still work on their own, or the refusals are
# just disabling features.
check("fee: NON-VACUITY -- --peel without a cut is untouched",
      _resolve_fee(_fee_args(usage_fee=False, peel=True)) == "")
check("fee: NON-VACUITY -- --split 4 without a cut is untouched",
      _resolve_fee(_fee_args(usage_fee=False, split=4)) == "")
check("fee: NON-VACUITY -- --usage-fee on a --split 1 run is allowed",
      _resolve_fee(_fee_args(split=1)) == "")

# THE ADDRESS REFUSALS.
check("fee: an address with no --usage-fee is refused rather than guessed at",
      "was given but --usage-fee was not"
      in _resolve_fee(_fee_args(usage_fee=False, usage_fee_address=_FEE_A1)))
check("fee: a cut address that is ALSO an exit destination is refused -- then "
      "it is not a cut, it is a transaction paying you your own money",
      "also an --exit-to destination"
      in _resolve_fee(_fee_args(usage_fee_address=_FEE_A1, exit_to=[_FEE_A1])))
check("fee: NON-VACUITY -- a cut address with a DIFFERENT exit is accepted",
      _resolve_fee(_fee_args(usage_fee_address=_FEE_A1,
                             exit_to=[_FEE_A2])) == "")
check("fee: a malformed cut address is refused",
      "Bad --usage-fee-address"
      in _resolve_fee(_fee_args(usage_fee_address="nope")))
for _bad, _why in ((Decimal("0"), "zero"), (Decimal("-0.1"), "negative"),
                   (ghost.USAGE_FEE_PCT_MAX + Decimal("0.01"), "above the ceiling")):
    check(f"fee: a {_why} fraction is refused",
          _resolve_fee(_fee_args(usage_fee_pct=_bad)) != "")
check("fee: NON-VACUITY -- a fraction AT the ceiling is accepted, so the bound "
      "is not off by one",
      _resolve_fee(_fee_args(usage_fee_pct=ghost.USAGE_FEE_PCT_MAX)) == "")

# THE RATE TRAVELS LIKE THE ADDRESS. An override is a per-operator constant and
# argv is world-readable; the address went through env_or_argv and the rate did
# not.
_gsrc = open(os.path.join(REPO, "GhostSpiral")).read()
check("fee: the fraction goes through env_or_argv, like every other value "
      "argv would publish to ps",
      'env_or_argv("GS_USAGE_FEE_PCT"' in _gsrc)
check("fee: ...and so does the destination",
      'env_or_argv("GS_USAGE_FEE_ADDRESS"' in _gsrc)


class _CutRPC:
    def new_subaddress_indexed(self, account_index=0, label=""):
        return ("4" + "z" * 94, 3)


def _plan_fee(bal, _mint=None, **kw):
    """plan_usage_fee with a stub wallet. Returns (addr, amt, printed, pair).

    `_mint` replaces create_fresh_account, so a caller can make the mint FAIL
    the way a real wallet-rpc does -- that path aborted the whole run after the
    swap had settled, and nothing exercised it.
    """
    _old_log, _old_acct = ghost.integrity_log, ghost.create_fresh_account
    ghost.integrity_log = lambda *x, **y: None
    ghost.create_fresh_account = _mint or (lambda rpc, label="": 7)
    a = _fee_args(**kw)
    # `or` would swallow an explicit Decimal(0) -- which is the one value this
    # helper is asked for when checking that "no cut" really mints nothing.
    a.usage_fee_pct = (kw["usage_fee_pct"] if "usage_fee_pct" in kw
                     else ghost.USAGE_FEE_PCT)
    _b = io.StringIO()
    try:
        with _ctx_c.redirect_stdout(_b):
            _addr, _amt, _pair = ghost.plan_usage_fee(
                _CutRPC(), a, bal, ghost.FALLBACK_FEE_XMR)
        return _addr, _amt, _b.getvalue(), _pair
    finally:
        ghost.integrity_log, ghost.create_fresh_account = _old_log, _old_acct


_addr, _amt, _out, _pair = _plan_fee(Decimal("1"))
check("fee: a 1 XMR deposit yields exactly 1.1%", _amt == Decimal("0.0110"))
check("fee: ...paid to a FRESHLY MINTED account, not a reused address -- the "
      "reuse this toolchain refuses in three other places",
      bool(_addr) and "freshly minted" in _out)
check("fee: ...and the operator is TOLD the account and the amount, because "
      "the wallet is the only authoritative record that they were paid",
      "account 7" in _out and "0.0110" in _out)

# BELOW THE SPENDABILITY FLOOR: WAIVE, NEVER ABORT. This ran after the swap, so
# "nothing has been spent" was false of the deposit -- the BTC is through
# ThorChain and the XMR sits on an address the memo names in a public
# OP_RETURN. Aborting to protect a fee strands it.
_addr2, _amt2, _out2, _pair2 = _plan_fee(Decimal("0.30"))
check("fee: below the spendability floor the cut is WAIVED and the mix goes "
      "ahead", _addr2 is None and _amt2 == 0)
check("fee: ...and the operator is told why, with the figure that would have "
      "worked", "NO USAGE FEE TAKEN" in _out2 and "at least" in _out2)
check("fee: ...and it does NOT claim nothing has been spent, which is false "
      "of the deposit by the time this runs",
      "Nothing has been spent" not in _out2)
# NON-VACUITY: the floor must actually bite somewhere, or "waived" is a branch
# that never runs.
check("fee: NON-VACUITY -- the waive is a real threshold, not a dead branch",
      _plan_fee(Decimal("1"))[0] is not None
      and _plan_fee(Decimal("0.30"))[0] is None)
check("fee: no cut asked for means no cut and no minting",
      _plan_fee(Decimal("1"), usage_fee=False, usage_fee_pct=Decimal(0))[0] is None)

# ROUND_DOWN, so the operator never takes more than the fraction they named.
_, _amt3, _, _ = _plan_fee(Decimal("0.33333333333"))
check("fee: the cut is rounded DOWN, so it never exceeds the stated fraction",
      _amt3 <= Decimal("0.33333333333") * ghost.USAGE_FEE_PCT)

# A STATIC ADDRESS IS ACCEPTED AND WARNED ABOUT, because it is the operator's
# choice and the cost is theirs -- but it is stated where it happens.
_addr4, _amt4, _out4, _pair4 = _plan_fee(Decimal("1"),
                                         usage_fee_address=_FEE_A1)
check("fee: a static address is used as given", _addr4 == _FEE_A1)
check("fee: ...and the reuse it causes is stated at the moment it happens",
      "collect from every run" in _out4)
check("fee: NON-VACUITY -- the freshly minted path does NOT print that warning",
      "collect from every run" not in _out)

# ---- A STATIC ADDRESS INSIDE THIS WALLET IS THE ONE THE EXIT SWEEPS -------
#
# This branch used to return with the note "the exit only ever enumerates
# accounts THIS RUN made, and a fixed external address is in none of them".
# False, and the counter-example is the likeliest paste of all:
# _exit_account_list returns addr_index's accounts PLUS change_accounts PLUS
# bal_account, and bal_account is `receive_account_index if receive_mode else
# 0` -- account 0, the wallet's pre-existing primary account, which the run did
# not make. _funded_subaddresses then walks EVERY subaddress of it.
#
# So the fee would go to --exit-to: unmixed value, sized at a fixed fraction of
# the deposit, landing beside the mixed outputs. On subaddress 0 of that
# account it is worse -- that is where the fan-out's change lands, so the
# change sweep moves it to a fresh address which build_change_sweep_jobs puts
# in addr_index, and out it goes with everything else.
print("\n-- a static fee address that belongs to this wallet --")


class _OwnedRPC:
    """A wallet that recognises the address as its own account 0."""

    def raw_request(self, method, params=None):
        if method == "get_address_index":
            return {"index": {"major": 0, "minor": 0}}
        raise AssertionError(method)

    def new_subaddress_indexed(self, account_index=0, label=""):
        raise AssertionError("must not mint: the fee is waived")


class _ForeignRPC:
    """A real wallet's answer for an address it does not hold keys to:
    get_address_index ERRORS. That is the EXPECTED case for a correct
    external destination, which is why an error means 'not ours'."""

    def raw_request(self, method, params=None):
        raise RuntimeError("Address doesn't belong to the wallet")

    def new_subaddress_indexed(self, account_index=0, label=""):
        raise AssertionError("must not mint: a static address was given")


def _plan_static(rpc, **kw):
    _ol, _oa = ghost.integrity_log, ghost.create_fresh_account
    ghost.integrity_log = lambda *x, **y: None
    ghost.create_fresh_account = lambda r, label="": 7
    try:
        a = _fee_args(usage_fee_address=_FEE_A1, **kw)
        a.usage_fee_pct = ghost.USAGE_FEE_PCT
        _b = io.StringIO()
        with _ctx_c.redirect_stdout(_b):
            _r = ghost.plan_usage_fee(rpc, a, Decimal("1"),
                                      ghost.FALLBACK_FEE_XMR)
        return _r + (_b.getvalue(),)
    finally:
        ghost.integrity_log, ghost.create_fresh_account = _ol, _oa


_oa, _oamt, _opair, _oout = _plan_static(_OwnedRPC())
check("fee/own: a static fee address inside THIS wallet takes no fee at all",
      _oa is None and _oamt == 0 and _opair is None)
check("fee/own: ...and says which account and subaddress it resolved to, so "
      "the operator can see what they pasted",
      "account 0, subaddress 0" in _oout)
check("fee/own: ...and names the actual consequence — the exit would have "
      "swept it to the operator's destination",
      "swept the fee to your --exit-to" in _oout)
check("fee/own: ...and WAIVES rather than aborting: the swap has settled by "
      "the time this runs",
      "NO USAGE FEE TAKEN" in _oout and "going ahead in full" in _oout)
# NON-VACUITY, and this is the check that matters: the SAME address with a
# wallet that does not know it is used as given. Without this the waive above
# would pass just as well if the branch refused every static address.
_fa, _famt2, _fpair2, _fout2 = _plan_static(_ForeignRPC())
check("fee/own: NON-VACUITY -- an address the wallet does NOT hold keys to is "
      "used exactly as given, which is the ordinary case",
      _fa == _FEE_A1 and _famt2 > 0 and _fpair2 is None)
check("fee/own: NON-VACUITY -- ...and gets the reuse warning, not the "
      "in-wallet one",
      "collect from every run" in _fout2 and "THIS WALLET" not in _fout2)
# ONE STATEMENT PER RUN. The refusal used to print AFTER the reuse warning, so
# a waived run said "the usage fee goes to a FIXED address you supplied" and
# then, four lines later, "NO USAGE FEE TAKEN" -- two claims about the same run
# that cannot both be true, leaving the operator to work out which won. Found
# by reading every branch's real output side by side rather than one at a time.
check("fee/own: a waived in-wallet address does NOT also get the reuse "
      "warning — the run would be making two contradictory statements",
      "collect from every run" not in _oout)
# AN ERROR IS THE EXPECTED ANSWER FOR A FOREIGN ADDRESS. monero-wallet-rpc
# answers get_address_index for an address it does not own with an ERROR, not
# with a null result -- so treating "unknown" as "ours" would waive the fee on
# every correct configuration.
check("fee/own: the lookup treats an RPC error as 'not ours', because that is "
      "what a real wallet answers for a foreign address",
      ghost._wallet_owns_address(_ForeignRPC(), _FEE_A1) is None)
check("fee/own: ...and a successful lookup as 'ours'",
      ghost._wallet_owns_address(_OwnedRPC(), _FEE_A1) == (0, 0))


class _JunkRPC:
    def raw_request(self, method, params=None):
        return {"index": {"major": "zero", "minor": None}}


check("fee/own: a lookup that succeeds without a usable index is 'not ours' — "
      "the address is already format-validated, so guessing 'ours' would "
      "waive a fee that was fine",
      ghost._wallet_owns_address(_JunkRPC(), _FEE_A1) is None)
check("fee/own: ...and a bare True is not an index either (True == 1)",
      ghost._wallet_owns_address(
          type("R", (), {"raw_request": lambda s, m, p=None: {
              "index": {"major": True, "minor": True}}})(), _FEE_A1) is None)
# THE CLAIM THE FIX RESTS ON, driven rather than asserted: bal_account really
# is in the exit's account list, and _funded_subaddresses really does walk it.
check("fee/own: NON-VACUITY -- account 0 (bal_account in send mode) IS in the "
      "exit's account list, which is why an in-wallet fee address is exposed",
      0 in ghost._exit_account_list({f"4{'m' * 94}": (5, 1)}, [], 0))

# ---- AND THE FEE ADDRESS ITSELF IS NEVER PRINTED --------------------------
#
# It is off the terminal today only because plan_usage_fee CHOSE to print
# "account N, subaddress M" instead -- strictly better than a scrubbed address,
# since indices disclose nothing outside the operator's own wallet. But that is
# one function's discipline, not a barrier, and the most plausible benign next
# edit is "print the address so I can check it in a block explorer". That puts
# 95 characters into gs_console's in-memory job buffer and into the DOM, on a
# page with NO masker (zero uses of scrub_address) that --redact does not
# reach. scrub_address is tested for what it RETURNS and never for whether it
# is used.
print("\n-- the fee address never reaches a pane with no masker --")
_GTREE_P = _ast.parse(Path(REPO, "GhostSpiral").read_text())


def _gfn_p(name):
    return [n for n in _ast.walk(_GTREE_P)
            if isinstance(n, _ast.FunctionDef) and n.name == name][0]


def _bare_address_prints(fn):
    """f-string prints in `fn` that interpolate an address name RAW.

    Wrapped in scrub_address is fine -- that is the contract. What this finds
    is the bare name inside an f-string that goes to print().
    """
    _names = {"addr", "fee_addr", "_fee_addr", "usage_fee_address"}
    _bad = []
    for _n in _ast.walk(fn):
        if not (isinstance(_n, _ast.Call)
                and isinstance(_n.func, _ast.Name) and _n.func.id == "print"):
            continue
        for _a in _ast.walk(_n):
            if not isinstance(_a, _ast.FormattedValue):
                continue
            _v = _a.value
            # scrub_address(x) / gs_common.scrub_address(x) -> allowed.
            if isinstance(_v, _ast.Call):
                _f = _v.func
                _fn_name = (_f.id if isinstance(_f, _ast.Name)
                            else getattr(_f, "attr", ""))
                if _fn_name in ("scrub_address", "chain_safe"):
                    continue
            for _x in _ast.walk(_v):
                if isinstance(_x, _ast.Name) and _x.id in _names:
                    _bad.append(_ast.unparse(_v))
    return _bad


for _fname in ("plan_usage_fee", "resolve_usage_fee",
               "_wallet_owns_address"):
    check(f"fee/print: {_fname} prints no fee address unscrubbed",
          _bare_address_prints(_gfn_p(_fname)) == [])
# NON-VACUITY 1: the checker CAN see a bare interpolation. Built here rather
# than hoped for, so a walker that silently matches nothing cannot pass.
_synth = _ast.parse('def f():\n    print(f"{fee_addr}")\n').body[0]
check("fee/print: NON-VACUITY -- the checker flags a bare address print when "
      "there is one",
      _bare_address_prints(_synth) == ["fee_addr"])
# NON-VACUITY 2: ...and does NOT flag the wrapped form, so it distinguishes
# the two rather than banning the word.
_synth_ok = _ast.parse(
    'def f():\n    print(f"{scrub_address(fee_addr)}")\n').body[0]
check("fee/print: NON-VACUITY -- ...and passes the scrub_address-wrapped form",
      _bare_address_prints(_synth_ok) == [])
# NON-VACUITY 3: the one place in the pipeline that legitimately shows a fee
# address to the operator does wrap it, so the contract is live in the source
# and not merely unexercised.
check("fee/print: NON-VACUITY -- resolve_usage_fee's own refusal DOES name the "
      "address, through scrub_address",
      "scrub_address(_d)" in _ast.unparse(_gfn_p("resolve_usage_fee")))

# ===========================================================================
#  THE TRAP: the exit must never sweep the usage fee back to --exit-to
# ===========================================================================
#
# _exit_account_list is built from addr_index.values() + change_accounts +
# [bal_account], and create_carriers adds its accounts to addr_index with the
# comment "SO THE EXIT CAN SEE IT". plan_usage_fee deliberately does NOT --
# the fee is already at its destination and must stay there.
#
# That makes the obvious next change a money bug: adding the fee account to
# addr_index so report_holdings can list it would hand the operator's fee
# straight to --exit-to, which is usually somewhere else entirely. Nothing
# about that change looks wrong, so it is pinned here.
print("\n-- the exit does not sweep the usage fee --")
_FEE_ACCT = 99


class _FeeRPC:
    def new_subaddress_indexed(self, account_index=0, label=""):
        return ("4" + "q" * 94, 5)


def _fee_and_exit_accounts():
    """Take a fee, then ask the exit which accounts it would empty."""
    _old_log, _old_acct = ghost.integrity_log, ghost.create_fresh_account
    ghost.integrity_log = lambda *x, **y: None
    ghost.create_fresh_account = lambda rpc, label="": _FEE_ACCT
    a = _fee_args()
    a.usage_fee_pct = ghost.USAGE_FEE_PCT
    # A realistic addr_index: three mix subaddresses on their own accounts.
    _ai = {f"4{'m' * 94}{i}": (i, 1) for i in range(3)}
    try:
        with _ctx_c.redirect_stdout(io.StringIO()):
            _addr, _amt, _pair = ghost.plan_usage_fee(
                _FeeRPC(), a, Decimal("1"), ghost.FALLBACK_FEE_XMR)
        return (_addr, _amt, _ai, ghost._exit_account_list(_ai, [], 0),
                _pair)
    finally:
        ghost.integrity_log, ghost.create_fresh_account = _old_log, _old_acct


_faddr, _famt, _ai, _exit_accts, _fpair = _fee_and_exit_accounts()
check("fee/exit: the fee was actually taken, so the check below is about a "
      "real payment", bool(_faddr) and _famt > 0)
check("fee/exit: the fee ACCOUNT is not in the exit's sweep list -- the exit "
      "would send it to --exit-to, which is not where the fee goes",
      _FEE_ACCT not in _exit_accts)
check("fee/exit: ...and the fee ADDRESS never entered addr_index, which is "
      "what keeps it out",
      _faddr not in _ai)
# NON-VACUITY: the mix accounts ARE in the list, so this is not a function
# that returns nothing.
check("fee/exit: NON-VACUITY -- the mix accounts ARE swept, so the exit list "
      "is real", all(_i in _exit_accts for _i in range(3)))
# NON-VACUITY: putting the fee account in addr_index really would sweep it --
# i.e. the trap is a live one, not a hypothetical.
check("fee/exit: NON-VACUITY -- adding the fee account to addr_index WOULD "
      "sweep it, which is why plan_usage_fee must not",
      _FEE_ACCT in ghost._exit_account_list(
          {**_ai, _faddr: (_FEE_ACCT, 5)}, [], 0))
# ...and the source-level guard, so the trap is caught by reading too.
_GTREE = _ast.parse(Path(REPO, "GhostSpiral").read_text())


def _gfn(name):
    return [n for n in _ast.walk(_GTREE)
            if isinstance(n, _ast.FunctionDef) and n.name == name][0]


def _touches(fn, name):
    """Does this function actually USE `name` -- as a variable, an argument,
    an attribute or a keyword?

    NOT `name in ast.dump(fn)`, which was the first version and which reads
    the DOCSTRING too. The docstring of plan_usage_fee now explains at length
    why the fee is kept out of addr_index, so the substring test started
    failing on the comment that documents the very property it checks. A test
    that forbids naming the thing is a test that punishes explaining it.
    """
    for n in _ast.walk(fn):
        if isinstance(n, _ast.Name) and n.id == name:
            return True
        if isinstance(n, _ast.arg) and n.arg == name:
            return True
        if isinstance(n, _ast.Attribute) and n.attr == name:
            return True
        if isinstance(n, _ast.keyword) and n.arg == name:
            return True
    return False


_pf_fn = _gfn("plan_usage_fee")
check("fee/exit: plan_usage_fee never touches addr_index in CODE",
      not _touches(_pf_fn, "addr_index"))
check("fee/exit: NON-VACUITY -- build_peel_stage_plan DOES touch it (its "
      "own comment says \"SO THE EXIT CAN SEE IT\"), so the check above "
      "distinguishes the two",
      _touches(_gfn("build_peel_stage_plan"), "addr_index"))
# NON-VACUITY on the reader itself: it must not be a function that says "no"
# to everything, and it must not be fooled by prose. plan_usage_fee's
# docstring names addr_index repeatedly and its code does not -- which is
# exactly the pair `in ast.dump()` could not tell apart.
check("fee/exit: NON-VACUITY -- _touches finds a name plan_usage_fee DOES use",
      _touches(_pf_fn, "cut") and _touches(_pf_fn, "integrity_log"))
check("fee/exit: NON-VACUITY -- and the docstring alone does not fool it: "
      "plan_usage_fee's prose names addr_index while its code does not",
      "addr_index" in (_ast.get_docstring(_pf_fn) or ""))

# ---- THE SECOND LOCK: the pair the exit is told to refuse -----------------
#
# Everything above proves the fee is safe BY OMISSION -- nothing puts it in
# addr_index, so nothing enumerates it. That is a guard made of absence, and
# absence is what a later change deletes without noticing: one line adding the
# fee account to addr_index (to make report_holdings list it, say) puts the
# operator's own cut in exit_accounts and sweeps it to --exit-to in silence.
#
# So plan_usage_fee also HANDS BACK the pair, main() passes it to _stage5_run
# as exit_fee_hold, and _run_exit_withdrawals refuses it by name. Inert while
# the omission holds. Loud the day it does not.
check("fee/hold: the minted cut reports the (account, subaddress) it landed on",
      _pair == (7, 3))
check("fee/hold: ...and it is the same account the operator was told about",
      f"account {_pair[0]}" in _out and f"subaddress {_pair[1]}" in _out)
check("fee/hold: a static address reports NO pair — this run did not create "
      "it, so it can name no account, and the exit never enumerates it anyway",
      _pair4 is None and _addr4 == _FEE_A1)
check("fee/hold: a waived cut reports no pair either", _pair2 is None)
check("fee/hold: and no cut at all reports no pair",
      _plan_fee(Decimal("1"), usage_fee=False,
                usage_fee_pct=Decimal(0))[3] is None)
# THE WIRING, read from the source: a producer and a consumer that are each
# correct in isolation is not a wired pipeline -- the ENTRY hold learned that
# the expensive way (emptying it at either call site restored the exact sweep
# it exists to prevent, and both test files stayed green).
_S5_SRC = Path(REPO, "GhostSpiral").read_text()
check("fee/hold: main() passes the pair on to _stage5_run",
      "exit_fee_hold=([_fee_pair] if _fee_pair" in _S5_SRC)
check("fee/hold: _stage5_run folds it into the hold the exit honours",
      "for _fp in (exit_fee_hold or ()):" in _S5_SRC
      and "fee_pairs=list(exit_fee_hold or ())" in _S5_SRC)
check("fee/hold: _run_exit_withdrawals takes fee_pairs as its own kind, not "
      "folded into entry_pairs — every ENTRY remedy is wrong for the fee",
      "fee_pairs=()" in _S5_SRC and '"usagefee": "YOUR OWN USAGE FEE"' in _S5_SRC)
# AND THE SAME PAIR REACHES THE FINAL REPORT, which is the only durable record
# of where the operator's own money went: the fee account is out of addr_index
# (so report_holdings never lists it), the plan file has no index, and a
# completed run wipes that plan.
check("fee/hold: main() also hands the pair to the end-of-run report",
      "fee_pair=_fee_pair," in _S5_SRC)

# ---- THE MINT CAN FAIL, AND THE SWAP HAS ALREADY SETTLED ------------------
#
# create_fresh_account RAISES rather than defaulting to account 0, and
# new_subaddress_indexed validates its answer the same way. Uncaught, either
# takes main() down with a traceback at stage 4 -- which is AFTER
# stage4_await_swap, so the BTC is through ThorChain and the XMR is sitting on
# an address a public OP_RETURN names. That is the exact outcome the
# below-floor branch stopped doing; this door was left open beside it.
print("\n-- a wallet that will not mint the fee account --")


def _boom(rpc, label=""):
    raise RuntimeError("wallet refused create_account")


_maddr, _mamt, _mout, _mpair = _plan_fee(Decimal("1"), _mint=_boom)
check("fee/mint: a wallet that will not mint the fee account WAIVES the cut",
      _maddr is None and _mamt == 0 and _mpair is None)
check("fee/mint: ...and does not raise, because the swap has already settled "
      "by the time this runs",
      "NO USAGE FEE TAKEN" in _mout)
check("fee/mint: ...and says the mix is going ahead, so the operator does not "
      "kill a run that is still fine",
      "going ahead in full" in _mout)
check("fee/mint: ...and reports the wallet's own reason rather than swallowing "
      "it", "refused create_account" in _mout)
# NON-VACUITY: the same call with a working wallet DOES take the fee, so the
# waive is a response to the failure and not the helper's normal answer.
check("fee/mint: NON-VACUITY -- the same deposit with a working wallet takes "
      "the cut", _addr is not None and _amt > 0)


class _BadSubRPC:
    """Mints the account, then refuses the subaddress. The second half of the
    same failure, and it is a different call with its own validation."""

    def new_subaddress_indexed(self, account_index=0, label=""):
        raise RuntimeError("create_address returned no address_index")


_old_l, _old_a = ghost.integrity_log, ghost.create_fresh_account
ghost.integrity_log = lambda *x, **y: None
ghost.create_fresh_account = lambda rpc, label="": 7
try:
    _sa = _fee_args()
    _sa.usage_fee_pct = ghost.USAGE_FEE_PCT
    _sb = io.StringIO()
    with _ctx_c.redirect_stdout(_sb):
        _s_addr, _s_amt, _s_pair = ghost.plan_usage_fee(
            _BadSubRPC(), _sa, Decimal("1"), ghost.FALLBACK_FEE_XMR)
    _sout = _sb.getvalue()
finally:
    ghost.integrity_log, ghost.create_fresh_account = _old_l, _old_a
check("fee/mint: a wallet that mints the account but refuses the SUBADDRESS "
      "waives too — the account exists but is empty and unreferenced",
      _s_addr is None and _s_amt == 0 and _s_pair is None)
check("fee/mint: ...and says so rather than raising",
      "NO USAGE FEE TAKEN" in _sout)

# ---- SPEND HYGIENE, ON THE ACCOUNTS NOTHING ELSE COVERS -------------------
#
# report_holdings prints "SPEND THEM ONE ACCOUNT AT A TIME" over the run's
# accounts -- and the fee account is deliberately not one of them, so the
# accounts that accumulate run after run were the only ones the warning never
# reached. They are also the ones where merging costs most: every mixed output
# is an arbitrary amount, but each of these is a FIXED FRACTION of one deposit,
# so spending two together does not merely link the fees, it measures the runs
# behind them.
check("fee/hygiene: the minted disclosure says to spend the fee on its own",
      "SPEND IT ON ITS OWN" in _out)
check("fee/hygiene: ...and gives the reason that is specific to a fee — the "
      "fixed rate divides back to the deposit",
      "divide by the rate" in _out and "share an owner" in _out)
check("fee/hygiene: ...and says not to send it where the mixed output goes",
      "same" in _out and "destination as your mixed output" in _out)
# NON-VACUITY: the waived branch mints nothing, so it must NOT print advice
# about an account that does not exist.
check("fee/hygiene: NON-VACUITY -- a waived cut prints no such advice, so the "
      "line above is the minting branch's and not boilerplate",
      "SPEND IT ON ITS OWN" not in _out2)

# ---- NOTHING IS LABELLED, because labels are written into the wallet file --
#
# paranoia_mode deliberately never deletes the wallet file -- it is the only
# thing that can still spend the money -- so anything written INTO it outlives
# every artifact wipe the toolchain performs. An account labelled "usage fee"
# or "cut 1.1%" would survive a seizure that erases the plans, the logs and the
# staging directory, and it would do the analyst's arithmetic for them: it
# names which account is the operator's revenue and, with the rate in the
# label, what the deposit was.
#
# Both mints, because there are two: the account and the subaddress inside it.
_LABELS = {"acct": None, "sub": None}


class _LabelRPC:
    def new_subaddress_indexed(self, account_index=0, label=""):
        _LABELS["sub"] = label
        return ("4" + "z" * 94, 3)


_old_l2, _old_a2 = ghost.integrity_log, ghost.create_fresh_account
ghost.integrity_log = lambda *x, **y: None


def _label_acct(rpc, label=""):
    _LABELS["acct"] = label
    return 7


ghost.create_fresh_account = _label_acct
try:
    _la = _fee_args()
    _la.usage_fee_pct = ghost.USAGE_FEE_PCT
    with _ctx_c.redirect_stdout(io.StringIO()):
        ghost.plan_usage_fee(_LabelRPC(), _la, Decimal("1"),
                             ghost.FALLBACK_FEE_XMR)
finally:
    ghost.integrity_log, ghost.create_fresh_account = _old_l2, _old_a2
check("fee/label: the fee ACCOUNT is minted with an empty label — a label is "
      "written into the wallet file, which paranoia_mode never deletes",
      _LABELS["acct"] == "")
check("fee/label: ...and so is the SUBADDRESS inside it", _LABELS["sub"] == "")
# NON-VACUITY: the recorder really did see both calls, so an empty string is
# an observed label and not an un-run stub.
check("fee/label: NON-VACUITY -- both mints were actually reached, so the "
      "empty labels are observed and not defaults of a call that never "
      "happened",
      _LABELS["acct"] is not None and _LABELS["sub"] is not None)
# ...and at the source level, so the property is also readable: neither call
# may pass a label expression at all.
check("fee/label: neither mint passes anything but a literal empty label",
      all(isinstance(_k.value, _ast.Constant) and _k.value.value == ""
          for _n in _ast.walk(_pf_fn) if isinstance(_n, _ast.Call)
          for _k in _n.keywords if _k.arg == "label"))
check("fee/label: NON-VACUITY -- there ARE label= keywords in plan_usage_fee "
      "for that check to have read",
      len([_k for _n in _ast.walk(_pf_fn) if isinstance(_n, _ast.Call)
           for _k in _n.keywords if _k.arg == "label"]) == 2)

# WHAT REACHES THE PERSISTENT CHAIN. The fee is a fixed fraction of the
# deposit, so an amount on the chain is the deposit on the chain.
# ITS OWN TAG. "fee" was already taken -- by the DAEMON's network fee
# (daemon_fee:*, using_fallback_fee, IMPLAUSIBLE_daemon_fee). Two unrelated
# meanings under one chain tag is a reader's problem, and this test found it.
_fee_chain = re.findall(r'integrity_log\w*\("usagefee",\s*(?:f?")([^"]*)"',
                        Path(REPO, "GhostSpiral").read_text())
check(f"fee/chain: the usage fee has its own chain tag, not the daemon's "
      f"({len(_fee_chain)} payloads)", len(_fee_chain) >= 4)
check("fee/chain: NON-VACUITY -- the daemon's own fee tag still exists and is "
      "a different one",
      bool(re.findall(r'integrity_log\w*\("fee",',
                      Path(REPO, "GhostSpiral").read_text())))
check(f"fee/chain: no usage-fee payload interpolates anything but a COUNT "
      f"({_fee_chain})",
      all("{" not in _p or "len(" in _p for _p in _fee_chain))
# THE INTERPOLATED EXPRESSIONS, not the payload NAMES. A first version of this
# looked for the substring "addr" and flagged `address_validated` -- a constant
# string that carries no address at all. What matters is what gets substituted
# IN, so that is what is read.
_fee_interp = [_e for _p in _fee_chain
               for _e in re.findall(r"\{([^}]*)\}", _p)]
check(f"fee/chain: every interpolated value is a COUNT, never an address or "
      f"an amount ({_fee_interp or 'nothing is interpolated'})",
      all(_e.startswith("len(") for _e in _fee_interp))
check("fee/chain: NON-VACUITY -- the extractor really does find the one "
      "interpolation there is, so the check is not scanning an empty list",
      len(_fee_interp) == 1)
_gsc_mod = __import__("gs_common")
for _p in ("on_fanout:4_chunks", "subaddress_minted"):
    check(f"fee/chain: chain_safe leaves {_p!r} carrying no digit",
          not any(_c.isdigit() for _c in _gsc_mod.chain_safe(_p)))

_finished()
# ---- THE PREFERRED CHANNEL FOR THE FEE RATE WAS THE UNVALIDATED ONE -----
#
# --usage-fee-pct is type=decimal_arg. GS_USAGE_FEE_PCT went straight into
# Decimal(str(...)) at both assignment sites in resolve_usage_fee -- and
# OPSEC_SETUP lists it among the values that must travel by environment, so
# the channel the document recommends is the one with no gate on it. That is
# the exact defect decimal_env's own docstring was written for; this variable
# was added after it and did not get one.
#
# Two values got through, and the second is the one that costs money:
#
#   * "1.1%" -- the natural typo, since the help and the docs both write the
#     rate as "0.011 = 1.1%" -- raised a raw decimal.InvalidOperation.
#   * "1e-400" was ACCEPTED. It is positive and under the ceiling, so
#     _check_fee_pct passed it; the cut then quantizes to zero and the run
#     takes the WAIVER path, whose message calls
#     mix_minimum_xmr(usage_pct=1E-400) -- and the
#     (hop_fee_reserve + DUST_XMR)/usage_pct term in there is about 3.7E+397
#     and cannot be quantized in a 28-digit context. That raise lands AFTER
#     stage4_await_swap: after the BTC is gone, which is the one outcome the
#     waive-rather-than-abort design exists to prevent.
print("\n-- the fee rate, and the channel it arrives on --")
import os as _os_fee


def _resolve_pct(_v, _env=True):
    """resolve_usage_fee's verdict on one value. Returns ('ok', p) or ('no',)."""
    if _env:
        _os_fee.environ["GS_USAGE_FEE_PCT"] = _v
    _a = types.SimpleNamespace(usage_fee_pct=None if _env else _v,
                               usage_fee=True, usage_fee_address=None,
                               exit_to=[], split=1, peel=False, btc_entry=None)
    try:
        ghost.resolve_usage_fee(_a)
        return ("ok", _a.usage_fee_pct)
    except SystemExit:
        return ("no",)
    finally:
        _os_fee.environ.pop("GS_USAGE_FEE_PCT", None)


check("feepct: the rate written the way the docs write it is refused, not "
      "raised", _resolve_pct("1.1%") == ("no",))
check("feepct: ...and so are the two words that parse as Decimals",
      _resolve_pct("NaN") == ("no",) and _resolve_pct("Infinity") == ("no",))
check("feepct: ...and a rate above the ceiling", _resolve_pct("0.5") == ("no",))
check("feepct: ...and a negative one", _resolve_pct("-0.01") == ("no",))
# THE FLOOR IS THE HALF THAT CRASHED. "> 0" admits denormals.
check("feepct: a denormal rate is refused at parse time, not discovered after "
      "the swap has settled", _resolve_pct("1e-400") == ("no",))
check("feepct: ...and the floor is about representability -- a Monero atomic "
      "unit is 1e-12 XMR, so below it a cut cannot become an output at all",
      ghost.USAGE_FEE_PCT_MIN > 0
      and _resolve_pct(str(ghost.USAGE_FEE_PCT_MIN / 10)) == ("no",))
check("feepct: NON-VACUITY -- the real rate is still accepted, by env and by "
      "flag alike",
      _resolve_pct("0.011") == ("ok", Decimal("0.011"))
      and _resolve_pct(Decimal("0.011"), _env=False)[0] == "ok")
check("feepct: ...and the floor itself is accepted, so the band is closed at "
      "both ends rather than shifted",
      _resolve_pct(str(ghost.USAGE_FEE_PCT_MIN)) == ("ok", ghost.USAGE_FEE_PCT_MIN))
# AND THE CRASH IT AVOIDS IS REAL, not theoretical: driven against the shipped
# function with the value the old gate let through.
_mm_raised = False
try:
    ghost.mix_minimum_xmr(Decimal("0.0002"), 20, usage_pct=Decimal("1e-400"))
except Exception:                                            # noqa: BLE001
    _mm_raised = True
check("feepct: NON-VACUITY -- that value really does make mix_minimum_xmr "
      "raise, which is what the waiver path calls after the swap",
      _mm_raised)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
