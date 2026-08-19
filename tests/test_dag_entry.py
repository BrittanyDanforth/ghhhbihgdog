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
import secrets
import sys
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

    def new_subaddress_indexed(self, **k):
        return ("8" + "A" * 94, 1)


def _veil_out(transfers, fail=False):
    _saved = ghost.create_fresh_account
    try:
        ghost.create_fresh_account = lambda rpc, label="": 41
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ghost.build_entry_veil(_XferRPC(transfers, fail), "ENTRY", 3, 1)
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
check("G5: ...and does not claim the veil still delivers",
      "cannot deliver its premise" in _m)
_u = _veil_out([], fail=True)
check("G5: an unknown count is reported as unknown, not as fine",
      "not known whether" in _u)

# The veil still WORKS in every case — this reports, it does not block. A run
# that refuses to veil would spend ENTRY directly, which is strictly worse.
_saved_cfa = ghost.create_fresh_account
try:
    ghost.create_fresh_account = lambda rpc, label="": 41
    with contextlib.redirect_stdout(io.StringIO()):
        _plan, _carrier = ghost.build_entry_veil(_XferRPC(_four), "ENTRY", 3, 1)
    check("G5: ...and the veil is still built (reporting, not blocking)",
          len(_plan) == 1 and _plan[0]["sweep"] is True)
finally:
    ghost.create_fresh_account = _saved_cfa

# --split is refused outright, which is the one case the operator controls.
_split_msg = None
try:
    ghost.resolve_split(types.SimpleNamespace(split=4))
except SystemExit as _e:
    _split_msg = str(_e.code)
check("G5: --split above 1 is REFUSED", _split_msg is not None)
check("G5: ...naming the aggregator linkage", _split_msg and "links them" in _split_msg)
check("G5: ...the newnym theatre", _split_msg and "theatre" in _split_msg)
check("G5: ...the N-input veil", _split_msg and "input transaction" in _split_msg)
check("G5: ...and the supported alternative",
      _split_msg and "create_receive_wallet --count" in _split_msg)
for _ok in (1, 0, None):
    _r = None
    try:
        ghost.resolve_split(types.SimpleNamespace(split=_ok))
    except SystemExit as _e:
        _r = str(_e.code)
    check(f"G5: --split {_ok!r} is allowed through", _r is None)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
