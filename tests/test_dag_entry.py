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
_peel_msg = None
try:
    _dist(_SRC, _SLICES, _BY, peel=True)
except SystemExit as _e:
    _peel_msg = str(_e.code)
check("split: --split with --peel is REFUSED", _peel_msg is not None)
check("split: ...because merging the chains would re-create the convergence",
      _peel_msg and "convergence" in _peel_msg)
check("split: ...and N sequential chains is the time cost, stated",
      _peel_msg and "20 minutes" in _peel_msg)
check("control: ONE chunk with --peel is NOT refused by that check",
      "convergence" not in str(
          (lambda: [_dist([("C0", 20, 1)], [["m0"]], {"m0": Decimal("1")},
                          peel=True)] and "")() or ""))

# -- the budget follows the money -----------------------------------------
_slices, _su, _amts = ghost.size_distribution(
    ["m0", "m1", "m2", "m3"], [Decimal("3"), Decimal("1")], Decimal("8"),
    Decimal("0.0024"), False, _secretsmod.SystemRandom())
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


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
