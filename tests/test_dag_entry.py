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
import secrets as _secretsmod
import sys
from decimal import Decimal
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
            ghost.build_peel_stage_plan(_rpc, 9, "PENTRY", 1, _PD, _PBY,
                                        Decimal("0.0024"), delay_window=(0, 0))
    except SystemExit as _e:
        _pdup = str(_e.code)
    check(f"peel: a wallet reusing one {_lbl} across hops is REFUSED",
          _pdup is not None)
    check(f"peel: ...and the refusal ({_lbl}) names BOTH costs — the "
          f"twice-spent address and the 2-input change sweep",
          _pdup and "twice" in _pdup and "2-input" in _pdup)

with contextlib.redirect_stdout(io.StringIO()):
    _pok, _paccts = ghost.build_peel_stage_plan(
        _DupTargetRPC(dup_addr=False), 9, "PENTRY", 1, _PD, _PBY,
        Decimal("0.0024"), delay_window=(0, 0))
check("control: distinct peel carriers are accepted",
      len(_pok) == 4 and len({t["src"] for t in _pok}) == 4)
check("control: ...each hop leaving its change on its OWN account",
      len(set(_paccts)) == len(_paccts))

# -- the distribution is N transactions, one per carrier -------------------
_VA2 = types.SimpleNamespace


def _dist(sources, slices, by_addr, peel=False):
    _args = _VA2(peel=peel, dag_mixing=False)
    _ai = {a: (c, i) for a, c, i in sources}
    with contextlib.redirect_stdout(io.StringIO()):
        return ghost.build_distribution_plan(
            _args, None, _ai, sources, [d for sl in slices for d in sl],
            by_addr, slices, Decimal("0.0024"), sources[0][1],
            sum(len(sl) for sl in slices), (0, 0), _secretsmod)


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
for _ok in (1, 2, 8, None):
    _r = None
    try:
        ghost.resolve_split(types.SimpleNamespace(split=_ok))
    except SystemExit as _e:
        _r = str(_e.code)
    check(f"split: --split {_ok!r} is allowed", _r is None)
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
# --deep COSTS MONEY AND BUYS NO TRANSACTIONS, and the help now says so.
#
# `rounds = wallets * 2 * deep` reads as "one transaction per round", with
# `deep` sitting in it as though depth meant more hop ROUNDS. It does not:
# --deep multiplies the DAG adjacency's out-degree, assign_hop_destinations
# still gives every source exactly ONE destination, and _stage5_run runs
# exactly one DAG round. So the knob scales the fee reserve linearly while the
# transaction count stays put, and the difference is not distributed -- it
# becomes change, swept once, reported UNMIXED.
#
# Left conservative on purpose: under-reserving fails on the LAST hop after
# the funds are already split, and a live chain's real fee cannot be measured
# from here. Made VISIBLE instead, which is what this pins.
# ==========================================================================
print("\n=== --deep is honest about its cost ===")

_u1, _f1, _r1 = ghost.compute_fee_budget(Decimal("10"), Decimal("0.0024"), 12, 1)
_u6, _f6, _r6 = ghost.compute_fee_budget(Decimal("10"), Decimal("0.0024"), 12, 6)
check("deep: raising --deep really does hold back more of the balance",
      _f6 > _f1 * 5)
check("deep: ...so less is distributed into the mix",
      _u6 < _u1)
check("deep: ...and the reserve is linear in it, as the formula says",
      _r6 == _r1 * 6)

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
check("deep: ...and states that it scales the fee reserve",
      "fee reserve" in _dh)
check("deep: ...and that the difference becomes unmixed change",
      "unmixed change" in _dh)



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
    def _shape(peel, n):
        _o = io.StringIO()
        with contextlib.redirect_stdout(_o):
            ghost.announce_distribution_shape(
                types.SimpleNamespace(peel=peel), n)
        return _o.getvalue()

    _d = _shape(False, 8)
    check("shape: the default fan-out announces itself",
          "ONE fan-out transaction creating 8 outputs" in _d)
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
check("shape: build_distribution_plan calls it where the mode is decided",
      'distribution_mode = "peel" if args.peel else "fanout" '
      "announce_distribution_shape(args, fanout_count)" in _sh_src)
# Symmetry with the notice it was modelled on: both must exist, or the pair
# reads as "DAG matters, peel does not".
check("shape: ...and the DAG-off notice it mirrors is still there",
      "Run with --dag-mixing to" in _sh_src)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
