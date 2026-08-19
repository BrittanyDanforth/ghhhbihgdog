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
# N VEILS IN ONE ROUND ARE A JOINT TIMING CONSTRAINT unless they are spread.
# With the ordinary 3-12 minute jitter, N veils land inside the window meant
# for one — so an analyst holding N known swap outputs keeps only the N-tuples
# of candidate transactions that all fall in one short window, which is a
# handle the single-veil design never gave him.
check("split: a ONE-chunk run keeps the ordinary delay window untouched",
      ghost._veil_window(None, 1) == ghost.DEFAULT_HOP_DELAY)
check("split: with N chunks the window is widened, so N veils are not "
      "compressed into the space of one",
      ghost._veil_window(None, 4)[1] > ghost.DEFAULT_HOP_DELAY[1])
check("split: ...in proportion to the chunk count, keeping the expected gap "
      "between consecutive veils about what a single veil gets",
      ghost._veil_window(None, 4)[1] == ghost.DEFAULT_HOP_DELAY[1] * 4)
check("split: ...and it respects a custom --hop-delay rather than overriding it",
      ghost._veil_window((60, 120), 3) == (60, 360))
# ...and the plan actually USES it: the delays of a 3-veil plan must be able to
# exceed what a single veil could ever draw.
_saw_beyond = False
for _t in range(60):
    _sv = _saved_cfa
    try:
        _cc = [80]

        def _f4(rpc, label=""):
            _cc[0] += 1
            return _cc[0]
        ghost.create_fresh_account = _f4
        with contextlib.redirect_stdout(io.StringIO()):
            _pl, _ = ghost.build_entry_veils(
                _XferRPC(_one), [("E0", 10, 1), ("E1", 11, 1), ("E2", 12, 1)])
    finally:
        ghost.create_fresh_account = _sv
    if any(t["delay"] > ghost.DEFAULT_HOP_DELAY[1] for t in _pl):
        _saw_beyond = True
        break
check("split: a multi-veil plan really draws delays beyond the single-veil "
      "ceiling — the wider window reaches the plan, not just the helper",
      _saw_beyond)

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

for _total, _n in [(Decimal("0.08"), 4), (Decimal("0.5"), 2),
                   (Decimal("1"), 8), (Decimal("0.13"), 3)]:
    _a = ghost.split_btc_amount(_total, _n, _R)
    check(f"btc: {_total}/{_n} produces {_n} chunks", len(_a) == _n)
    check(f"btc: {_total}/{_n} sums EXACTLY to the total (no satoshi lost or "
          f"invented)", sum(_a, Decimal(0)) == _total)
    check(f"btc: {_total}/{_n} chunks are DISTINCT — the whole point",
          len(set(_a)) == _n)
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
_s1 = ghost.split_btc_amount(Decimal("0.4"), 4, _R)
_s2 = ghost.split_btc_amount(Decimal("0.4"), 4, _R)
check("btc: two runs of the same amount give DIFFERENT chunk sizes",
      _s1 != _s2)

# The quantisation drift must not always land on chunk 0, or "the one that is
# not a round fraction" identifies it in every run.
_firsts = set()
for _ in range(40):
    _x = ghost.split_btc_amount(Decimal("0.07"), 3, _R)
    _firsts.add(_x[0])
check("btc: the remainder is not always put on chunk 0", len(_firsts) > 1)

# CONTROL: one chunk is the whole amount, untouched — a default run is not
# jittered into a different number than the operator typed.
check("control: --split 1 hands over exactly what was asked for",
      ghost.split_btc_amount(Decimal("0.123456"), 1, _R) == [Decimal("0.123456")])

# DEGENERATE AMOUNTS MUST NEVER PRODUCE A NEGATIVE INSTRUCTION.
#
# The first fallback here divided equally and put the difference on chunk 0,
# so 1 satoshi across 3 chunks came out as [-1, 1, 1] satoshis — an
# instruction to send less than nothing, which summed correctly and passed
# every other check on its way to the operator. At (or just above) n satoshis
# every chunk must be exactly one satoshi and there is no room to jitter, so
# the boundary is repaired rather than approximated.
for _t, _n in [("0.00000003", 3), ("0.00000008", 8), ("0.0000001", 3),
               ("0.0000001", 8)]:
    for _rep in range(60):
        _tiny = ghost.split_btc_amount(Decimal(_t), _n, _R)
        if not (all(x > 0 for x in _tiny)
                and sum(_tiny, Decimal(0)) == Decimal(_t)):
            break
    check(f"btc: {_t} across {_n} chunks is positive and exact, every time",
          all(x > 0 for x in _tiny) and sum(_tiny, Decimal(0)) == Decimal(_t))

# Below n satoshis there is no correct answer, so it is refused up front
# rather than invented.
_imposs = None
try:
    ghost.resolve_btc_amount(types.SimpleNamespace(
        btc_amount=Decimal("0.00000001"), split=3))
except SystemExit as _e:
    _imposs = str(_e.code)
check("btc: --btc-amount below one satoshi per chunk is REFUSED", _imposs is not None)
check("btc: ...naming the real minimum", _imposs and "0.00000003" in _imposs)
# AS A NUMBER THE OPERATOR CAN TYPE. Decimal renders small values in
# scientific notation, so this message read "3 chunks need at least 3E-8 BTC"
# — not a figure anyone can enter into a wallet, describing a payment.
check("btc: ...in fixed notation, not scientific", "E-" not in _imposs)
for _v, _want in [("3E-8", "0.00000003"), ("0.5", "0.5"), ("1", "1"),
                  ("1E-7", "0.0000001"), ("0.123456789", "0.12345679")]:
    check(f"btc: fmt_btc({_v}) is typeable -> {_want}",
          ghost.fmt_btc(Decimal(_v)) == _want)
check("control: exactly one satoshi per chunk is allowed",
      ghost.resolve_btc_amount(types.SimpleNamespace(
          btc_amount=Decimal("0.00000003"), split=3)) is None)
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

# Every chunk is a whole number of satoshis — an unsendable amount would be an
# instruction the operator cannot follow. This holds because the TOTAL is
# satoshi-exact: resolve_btc_amount refuses anything finer, which is what makes
# the property true rather than approximately true. Asserting it against a
# sub-satoshi total is how that gap was found.
for _tot in ("0.33333333", "1", "0.07", "0.00012345"):
    _sat = ghost.split_btc_amount(Decimal(_tot), 3, _R)
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


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
