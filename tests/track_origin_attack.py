#!/usr/bin/env python3
"""Adversarial origin-tracker: name1 (sender) and name2 (receiver).

Runs many SEND / RECEIVE / COMBO mix graphs from the SHIPPED GhostSpiral
planners, then tries to recover the wallet identity addresses:

  name1  — original sender's wallet PRIMARY (account 0 / subaddress 0)
  name2  — receiver's wallet PRIMARY (account 0 / subaddress 0)

Two graph families, because the question "can we name them?" has two answers:

  LEGACY  — peel change and fan-out leftover land on PRIMARY. This is the
            pre-rotation design. An analyst with amounts + labels (or the
            wallet's own keys) names name1 / name2 on every graph.
  CURRENT — what this tree actually ships: a fresh mix account, rotating
            peel carriers, DAG hops that sweep (no change), and a final
            change-sweep off the mix account's subaddress 0. name1 and
            name2 never appear in the mix graph.

Two visibility models:

  TRANSPARENT — amounts and address labels are visible (wallet keys, a
                seized host, or a future break in RingCT). Worst case.
  STRUCTURE   — only tx shape and the spend graph (Monero today: amounts
                hidden, addresses not on-chain, but co-created outputs
                and "this output was spent in that later tx" still are).

This is an attack harness, not a green-wash. If name1 or name2 is
recoverable it prints REVEALED. The suite stays honest about which
modes leak.
"""
from __future__ import annotations
import os, sys, random
from collections import defaultdict
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import importlib.machinery, importlib.util


def load(name):
    path = os.path.join(REPO, name)
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL {name}")


# The two parties the user asked to name.
NAME1 = "name1"   # original sender PRIMARY
NAME2 = "name2"   # receiver PRIMARY


class Graph:
    """Analyst-visible mix graph for one named-party scenario."""

    def __init__(self, name, mode, primary, entry, party, family,
                 wallet_id="W0", usable=None):
        self.name = name
        self.mode = mode            # send | receive | combo
        self.primary = primary      # name1 or name2
        self.entry = entry          # first spend source
        self.party = party          # "name1" or "name2"
        self.family = family        # legacy | current
        self.wallet_id = wallet_id
        self.usable = Decimal(usable) if usable is not None else Decimal("0")
        self.txs = []
        self.created_by = {}
        self.spent_in = {}

    def add_tx(self, ins, outs, kind):
        idx = len(self.txs)
        self.txs.append({"ins": list(ins), "outs": list(outs), "kind": kind})
        for a, _ in outs:
            self.created_by.setdefault(a, idx)
        for a in ins:
            self.spent_in[a] = idx
        return idx


def _fanout_dests(rng, wallets, tag="MIX"):
    decoys = rng.randint(ghost.DECOY_MIN, ghost.DECOY_MAX)
    mix = [f"{tag}_{i}_{rng.randrange(1 << 20):05x}" for i in range(wallets + decoys + 2)]
    dests, hops = ghost.select_fanout_targets(mix, set(), wallets, decoys)
    return dests, hops


def _remainders(amts, fee):
    """Same carrier-forward math the shipped stage-4 peel uses."""
    n = len(amts)
    hop_fee = fee * ghost.FEE_SAFETY_MARGIN * ghost.PEEL_CARRIER_RESERVE_MULT
    rem = []
    for i in range(max(0, n - 1)):
        left = sum(amts[i + 1:], Decimal(0))
        left += hop_fee * (n - i - 1)
        rem.append(left)
    return rem


def _maybe_dag(g, dests, amts, dag, fee, change_sink=None, sweep=False):
    if not dag:
        return
    for d, a in zip(dests, amts):
        hop = ghost.compute_hop_amount(a, fee)
        if hop <= ghost.DUST_XMR:
            continue
        if sweep:
            # CURRENT: hop is sweep_all — one dest, ZERO change.
            g.add_tx([d], [(f"HOP_{d}", hop)], "dag_hop")
        else:
            # LEGACY: transfer_split leftover lands on the change sink.
            g.add_tx([d], [(f"HOP_{d}", hop), (change_sink, a - hop)], "dag_hop")


# ── LEGACY graphs (PRIMARY is the hub) ─────────────────────────────────────

def run_legacy_send_peel(rng, n=6, dag=False, usable=Decimal("12"),
                         fee=Decimal("0.001"), wallet_id="S"):
    """SEND before rotation: peel 0 and every later peel spend name1."""
    primary = NAME1
    g = Graph(f"LEGACY-send-peel-n{n}-dag{int(dag)}-u{usable}", "send",
              primary, primary, NAME1, "legacy", wallet_id, usable)
    dests = [f"MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
    amts = ghost.compute_fanout_amounts(usable, n, fee, dag, rng)
    if not amts:
        return None
    # Amounts come from the shipped planner. The HUB shape does not: current
    # build_peel_plan refuses to emit it (no carriers → ValueError). This is
    # the pre-rotation design an analyst names name1 from.
    remain = usable
    for dst, amt in zip(dests, amts):
        remain = remain - amt
        g.add_tx([primary], [(dst, amt), (primary, remain)], "peel")
    _maybe_dag(g, dests, amts, dag, fee, change_sink=primary, sweep=False)
    return g


def run_legacy_send_fanout(rng, wallets=8, dag=False, usable=Decimal("10"),
                           fee=Decimal("0.001"), wallet_id="S"):
    primary = NAME1
    g = Graph(f"LEGACY-send-fanout-w{wallets}-dag{int(dag)}-u{usable}", "send",
              primary, primary, NAME1, "legacy", wallet_id, usable)
    dests, _ = _fanout_dests(rng, wallets)
    amts = ghost.compute_fanout_amounts(usable, len(dests), fee, dag, rng)
    if not amts:
        return None
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    g.add_tx([primary], list(zip(dests, amts)) + [(primary, change)], "fanout")
    _maybe_dag(g, dests, amts, dag, fee, change_sink=primary, sweep=False)
    return g


def run_legacy_recv_peel(rng, n=6, dag=False, usable=Decimal("9"),
                         fee=Decimal("0.001"), wallet_id="R"):
    """RECEIVE before rotation: peel 0 spends a fresh sub; later peels spend name2."""
    primary = NAME2
    entry = f"{NAME2}_ENTRY_{wallet_id}"
    g = Graph(f"LEGACY-recv-peel-n{n}-dag{int(dag)}-u{usable}", "receive",
              primary, entry, NAME2, "legacy", wallet_id, usable)
    dests = [f"MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
    amts = ghost.compute_fanout_amounts(usable, n, fee, dag, rng)
    if not amts:
        return None
    # Peel 0 spends the one-shot receive sub; every later peel spends name2.
    # Same reason as send: the shipped planner will not emit this hub.
    remain = usable
    for i, (dst, amt) in enumerate(zip(dests, amts)):
        src = entry if i == 0 else primary
        remain = remain - amt
        g.add_tx([src], [(dst, amt), (primary, remain)], "peel")
    _maybe_dag(g, dests, amts, dag, fee, change_sink=primary, sweep=False)
    return g


def run_legacy_recv_fanout(rng, wallets=8, dag=False, usable=Decimal("10"),
                           fee=Decimal("0.001"), wallet_id="R"):
    primary = NAME2
    entry = f"{NAME2}_ENTRY_{wallet_id}"
    g = Graph(f"LEGACY-recv-fanout-w{wallets}-dag{int(dag)}-u{usable}", "receive",
              primary, entry, NAME2, "legacy", wallet_id, usable)
    dests, _ = _fanout_dests(rng, wallets, tag="RMIX")
    amts = ghost.compute_fanout_amounts(usable, len(dests), fee, dag, rng)
    if not amts:
        return None
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    g.add_tx([entry], list(zip(dests, amts)) + [(primary, change)], "fanout")
    _maybe_dag(g, dests, amts, dag, fee, change_sink=primary, sweep=False)
    return g


# ── CURRENT graphs (shipped: rotation + carriers + sweep hops + change sweep)

def run_current_peel(rng, party, n=6, dag=False, usable=Decimal("12"),
                     fee=Decimal("0.001"), wallet_id="C"):
    """What this tree ships for peel: ENTRY is a throwaway, carriers rotate,
    hops sweep, leftover is swept off the mix-account change address.

    party PRIMARY (name1 / name2) never appears as an input or output.
    """
    primary = party
    entry = f"{party}_ENTRY_{wallet_id}"
    mixchg = f"{party}_MIXCHG_{wallet_id}"
    mode = "send" if party == NAME1 else "receive"
    g = Graph(f"CURRENT-{mode}-peel-n{n}-dag{int(dag)}-u{usable}", mode,
              primary, entry, party, "current", wallet_id, usable)
    dests = [f"MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
    amts = ghost.compute_fanout_amounts(usable, n, fee, dag, rng)
    if not amts:
        return None
    carriers = [(f"{party}_CARRIER_{wallet_id}_{k}", 300 + k) for k in range(n - 1)]
    remainders = _remainders(amts, fee)
    entry_index = 9 if party == NAME2 else 1
    plan = ghost.build_peel_plan(
        entry_index=entry_index, change_index=0,
        dests=dests, amounts=amts,
        carriers=carriers, remainders=remainders)
    for i, (p, amt) in enumerate(zip(plan, amts)):
        src = entry if i == 0 else carriers[i - 1][0]
        outs = [(p["dst"], amt)]
        if p.get("carrier"):
            outs.append((p["carrier"], Decimal(str(remainders[i]))))
        # Honest limit: monerod dust still lands on the mix-account change
        # address. That address is NOT name1/name2 under current rotation.
        dust = fee * Decimal("0.1")
        outs.append((mixchg, dust))
        g.add_tx([src], outs, "peel")
    _maybe_dag(g, dests, amts, dag, fee, sweep=True)
    # Change sweep: mix-account/sub-0 -> fresh mix dest, sweep_all.
    sweep_dest = f"{party}_SWEEP_{wallet_id}"
    dust_total = fee * Decimal("0.1") * n
    if dust_total > ghost.DUST_XMR:
        g.add_tx([mixchg], [(sweep_dest, dust_total)], "change_sweep")
        if dag:
            hop = ghost.compute_hop_amount(dust_total, fee)
            if hop > ghost.DUST_XMR:
                g.add_tx([sweep_dest], [(f"HOP_{sweep_dest}", hop)], "dag_hop")
    return g


def run_current_fanout(rng, party, wallets=8, dag=False, usable=Decimal("10"),
                       fee=Decimal("0.001"), wallet_id="C"):
    primary = party
    entry = f"{party}_ENTRY_{wallet_id}"
    mixchg = f"{party}_MIXCHG_{wallet_id}"
    mode = "send" if party == NAME1 else "receive"
    g = Graph(f"CURRENT-{mode}-fanout-w{wallets}-dag{int(dag)}-u{usable}", mode,
              primary, entry, party, "current", wallet_id, usable)
    dests, _ = _fanout_dests(rng, wallets, tag=f"{party[0]}MIX")
    amts = ghost.compute_fanout_amounts(usable, len(dests), fee, dag, rng)
    if not amts:
        return None
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    # Leftover lands on the mix-account change address, NOT on name1/name2.
    g.add_tx([entry], list(zip(dests, amts)) + [(mixchg, change)], "fanout")
    _maybe_dag(g, dests, amts, dag, fee, sweep=True)
    sweep_dest = f"{party}_SWEEP_{wallet_id}"
    if change > ghost.DUST_XMR:
        g.add_tx([mixchg], [(sweep_dest, change)], "change_sweep")
        if dag:
            hop = ghost.compute_hop_amount(change, fee)
            if hop > ghost.DUST_XMR:
                g.add_tx([sweep_dest], [(f"HOP_{sweep_dest}", hop)], "dag_hop")
    return g


def run_buggy_send_fanout(rng, wallets=8, usable=Decimal("10"),
                          fee=Decimal("0.001"), wallet_id="B"):
    """The defect this PR closes: mix subs live in a fresh account, but
    bal_account was hard-coded to 0, so leftover + change-sweep source
    were name1 (wallet PRIMARY)."""
    primary = NAME1
    entry = f"{NAME1}_ENTRY_{wallet_id}"
    g = Graph(f"BUGGY-send-fanout-w{wallets}-u{usable}", "send",
              primary, entry, NAME1, "buggy", wallet_id, usable)
    dests, _ = _fanout_dests(rng, wallets)
    amts = ghost.compute_fanout_amounts(usable, len(dests), fee, False, rng)
    if not amts:
        return None
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    g.add_tx([entry], list(zip(dests, amts)) + [(primary, change)], "fanout")
    # Change sweep then SPENDS name1 — the tell.
    sweep_dest = f"{NAME1}_SWEEP_{wallet_id}"
    g.add_tx([primary], [(sweep_dest, change)], "change_sweep")
    return g


def run_combo_name1_to_name2(rng, family, n=5, usable=Decimal("8"),
                             fee=Decimal("0.001"), wallet_id="X"):
    """name1 sends; name2 receives the XMR and mixes it.

    Two graphs, one wallet each. The analyst who can join them (shared
    ThorChain memo, timing, or a seized host) still has to name each
    PRIMARY from its own mix graph. A shared change address across the
    two graphs would mean they are the SAME wallet — they are not.
    """
    if family == "legacy":
        g1 = run_legacy_send_peel(rng, n=n, usable=usable, fee=fee,
                                  wallet_id=f"{wallet_id}s")
        g2 = run_legacy_recv_peel(rng, n=n, usable=usable, fee=fee,
                                  wallet_id=f"{wallet_id}r")
    else:
        g1 = run_current_peel(rng, NAME1, n=n, usable=usable, fee=fee,
                              wallet_id=f"{wallet_id}s")
        g2 = run_current_peel(rng, NAME2, n=n, usable=usable, fee=fee,
                              wallet_id=f"{wallet_id}r")
    return g1, g2


def run_two_receives_name2(rng, family, n=5, amt_a=Decimal("8"),
                           amt_b=Decimal("6"), wallet_id="T"):
    """Two inbound payments to name2 on different days.

    LEGACY: both peels dump change on name2 → intersection names name2.
    CURRENT: each receive is its own account → intersection is empty.
    """
    if family == "legacy":
        a = run_legacy_recv_peel(rng, n=n, usable=amt_a, wallet_id=f"{wallet_id}a")
        b = run_legacy_recv_peel(rng, n=n, usable=amt_b, wallet_id=f"{wallet_id}b")
        # Force the same PRIMARY (already name2) so intersection is meaningful.
        return a, b
    a = run_current_peel(rng, NAME2, n=n, usable=amt_a, wallet_id=f"{wallet_id}a")
    b = run_current_peel(rng, NAME2, n=n, usable=amt_b, wallet_id=f"{wallet_id}b")
    return a, b


# ── attacks ────────────────────────────────────────────────────────────────

def attack_genesis(g: Graph):
    if not g.txs or not g.txs[0]["ins"]:
        return None
    return g.txs[0]["ins"][0]


def attack_peel_change_walk(g: Graph):
    peels = [t for t in g.txs if t["kind"] == "peel"]
    if len(peels) < 2:
        return None
    later_ins = {a for t in peels[1:] for a in t["ins"]}
    change_addrs = []
    for t in peels:
        for a, _ in t["outs"]:
            if a in later_ins:
                change_addrs.append(a)
    if not change_addrs:
        return None
    return max(set(change_addrs), key=change_addrs.count)


def attack_repeated_spender(g: Graph):
    counts = defaultdict(int)
    for t in g.txs:
        if t["kind"] in ("peel", "fanout", "change_sweep"):
            for a in t["ins"]:
                counts[a] += 1
    if not counts:
        return None
    return max(counts, key=counts.get)


def attack_largest_change(g: Graph):
    guesses = []
    for t in g.txs:
        if t["kind"] != "peel" or len(t["outs"]) < 2:
            continue
        bigger = max(t["outs"], key=lambda x: x[1])[0]
        guesses.append(bigger)
    if not guesses:
        return None
    return max(set(guesses), key=guesses.count)


def attack_cocreation(g: Graph):
    for t in g.txs:
        if len(t["outs"]) >= 3:
            return [a for a, _ in t["outs"]]
    return []


def attack_equal_amounts(g: Graph):
    vals = defaultdict(list)
    for t in g.txs:
        for a, amt in t["outs"]:
            vals[amt].append(a)
    return [v for k, v in vals.items() if len(v) >= 3]


def attack_unhopped_change(g: Graph):
    hops = {a for t in g.txs if t["kind"] == "dag_hop" for a in t["ins"]}
    if not hops:
        return None
    for t in g.txs:
        if t["kind"] != "fanout":
            continue
        leftover = [a for a, _ in t["outs"] if a not in hops]
        if len(leftover) == 1:
            return leftover[0]
    return None


def attack_self_change(g: Graph):
    for t in g.txs:
        if t["kind"] != "fanout" or not t["ins"]:
            continue
        spender = t["ins"][0]
        if any(a == spender for a, _ in t["outs"]):
            return spender
    return None


def attack_fanout_leftover(g: Graph):
    for t in g.txs:
        if t["kind"] != "fanout" or len(t["outs"]) < 3:
            continue
        outs = list(t["outs"])
        total = sum(a for _, a in outs)
        target = (total * ghost.FANOUT_SPEND_FRACTION).quantize(Decimal("0.0001"))
        spender = t["ins"][0] if t["ins"] else None
        best = None
        best_err = None
        for i, (addr, _amt) in enumerate(outs):
            dest_sum = sum(a for j, (_, a) in enumerate(outs) if j != i)
            err = abs(dest_sum - target)
            tied_self = (best_err is not None and err == best_err
                         and spender and addr == spender)
            if best_err is None or err < best_err or tied_self:
                best_err = err
                best = addr
        return best
    return None


def attack_change_intersection(graphs):
    change_sets = []
    for g in graphs:
        ch = set()
        walk = attack_peel_change_walk(g)
        if walk:
            ch.add(walk)
        unhop = attack_unhopped_change(g)
        if unhop:
            ch.add(unhop)
        left = attack_fanout_leftover(g)
        if left:
            ch.add(left)
        later = {a for t in g.txs[1:] for a in t["ins"]}
        for t in g.txs:
            if t["kind"] in ("peel", "fanout"):
                for a, _ in t["outs"]:
                    if a in later:
                        ch.add(a)
        change_sets.append(ch)
    if len(change_sets) < 2:
        return None
    inter = set.intersection(*change_sets)
    if len(inter) == 1:
        return next(iter(inter))
    return None


def attack_shared_address(g1: Graph, g2: Graph):
    """Any address that appears in both graphs — a name1↔name2 link."""
    a = {x for t in g1.txs for x in t["ins"]} | {a for t in g1.txs for a, _ in t["outs"]}
    b = {x for t in g2.txs for x in t["ins"]} | {a for t in g2.txs for a, _ in t["outs"]}
    return a & b


def deep_reveal(g: Graph):
    """Name the wallet PRIMARY from the graph. Returns (addr, reason, notes)."""
    gen = attack_genesis(g)
    walk = attack_peel_change_walk(g)
    rept = attack_repeated_spender(g)
    unhop = attack_unhopped_change(g)
    self_ch = attack_self_change(g)
    left = attack_fanout_leftover(g)
    large = attack_largest_change(g)
    notes = []

    if walk:
        notes.append(f"peel-change walk -> {walk}")
        if gen and gen != walk:
            notes.append(f"genesis {gen} is a one-shot receive sub; change is MAIN")
        else:
            notes.append(f"genesis {gen} equals change carrier: first spend IS main")
        return walk, "peel-change-walk", notes
    if unhop:
        notes.append(f"DAG: every mix dest hopped; unhopped leftover -> {unhop}")
        return unhop, "unhopped-leftover", notes
    if rept and gen and rept != gen:
        notes.append(f"repeated spender {rept} != genesis {gen} -> MAIN is change")
        return rept, "repeated-spender", notes
    if self_ch:
        notes.append(f"SEND fan-out: change returns to the spender {self_ch}")
        return self_ch, "self-change", notes
    if left and gen and left != gen:
        notes.append(f"fan-out leftover -> {left} (not genesis {gen})")
        return left, "fanout-leftover", notes
    if rept and gen and rept == gen:
        notes.append(f"SEND: first spend {gen} is the only mix source -> MAIN")
        return rept, "genesis-is-main", notes
    if large:
        notes.append(f"largest-is-change fallback -> {large}")
        return large, "largest-is-change", notes
    notes.append("blind — no heuristic named a persistent identity address")
    return None, "blind", notes


def evaluate(g: Graph):
    gen = attack_genesis(g)
    peel_ch = attack_peel_change_walk(g)
    rept = attack_repeated_spender(g)
    large = attack_largest_change(g)
    coco = attack_cocreation(g)
    eq = attack_equal_amounts(g)
    unhop = attack_unhopped_change(g)
    left = attack_fanout_leftover(g)
    named, reason, _notes = deep_reveal(g)

    hits = {
        "genesis_is_entry": gen == g.entry,
        "genesis_is_primary": gen == g.primary,
        "peel_change_is_primary": peel_ch == g.primary,
        "repeated_spender_is_primary": rept == g.primary,
        "largest_change_is_primary": large == g.primary,
        "primary_in_fanout_cluster": g.primary in coco,
        "equal_amount_cluster_exists": bool(eq),
        "unhopped_is_primary": unhop == g.primary,
        "leftover_is_primary": left == g.primary,
        "deep_reveal_is_primary": named == g.primary,
        "named_is_name1": named == NAME1,
        "named_is_name2": named == NAME2,
    }
    revealed = any([
        hits["genesis_is_primary"],
        hits["peel_change_is_primary"],
        hits["repeated_spender_is_primary"],
        hits["largest_change_is_primary"],
        hits["primary_in_fanout_cluster"],
        hits["unhopped_is_primary"],
        hits["leftover_is_primary"],
        hits["deep_reveal_is_primary"],
    ])
    return hits, revealed, {
        "genesis": gen, "peel_change": peel_ch, "repeated": rept,
        "largest": large, "cluster_n": len(coco),
        "unhopped": unhop, "leftover": left,
        "deep": named, "deep_reason": reason,
    }


AMOUNT_LADDER = [
    Decimal("0.5"), Decimal("1"), Decimal("2"), Decimal("5"),
    Decimal("10"), Decimal("25"), Decimal("50"), Decimal("100"),
]
REPEATS_PER_CELL = 3


def _dests_for_amount(usable):
    if usable < Decimal("2"):
        return 3, 4
    if usable < Decimal("10"):
        return 5, 6
    return 8, 8


def _build_many(rng):
    graphs = []
    for usable in AMOUNT_LADDER:
        peel_n, fan_w = _dests_for_amount(usable)
        for dag in (False, True):
            for _ in range(REPEATS_PER_CELL):
                for builder in (
                    lambda r, u=usable, k=peel_n, d=dag:
                        run_legacy_send_peel(r, k, d, u),
                    lambda r, u=usable, w=fan_w, d=dag:
                        run_legacy_send_fanout(r, w, d, u),
                    lambda r, u=usable, k=peel_n, d=dag:
                        run_legacy_recv_peel(r, k, d, u),
                    lambda r, u=usable, w=fan_w, d=dag:
                        run_legacy_recv_fanout(r, w, d, u),
                    lambda r, u=usable, k=peel_n, d=dag:
                        run_current_peel(r, NAME1, k, d, u, wallet_id=f"s{u}{int(d)}"),
                    lambda r, u=usable, w=fan_w, d=dag:
                        run_current_fanout(r, NAME1, w, d, u, wallet_id=f"s{u}{int(d)}"),
                    lambda r, u=usable, k=peel_n, d=dag:
                        run_current_peel(r, NAME2, k, d, u, wallet_id=f"r{u}{int(d)}"),
                    lambda r, u=usable, w=fan_w, d=dag:
                        run_current_fanout(r, NAME2, w, d, u, wallet_id=f"r{u}{int(d)}"),
                ):
                    g = builder(rng)
                    if g:
                        graphs.append(g)
        g = run_buggy_send_fanout(rng, wallets=fan_w, usable=usable,
                                  wallet_id=f"bug{usable}")
        if g:
            graphs.append(g)
    return graphs


def _pct(rows, field):
    if not rows:
        return 0.0
    return 100.0 * sum(1 for _, h, _, _ in rows if h[field]) / len(rows)


def _print_scoreboard(evaluated):
    print("\n" + "=" * 72)
    print("  ORIGIN TRACE  name1 = sender PRIMARY    name2 = receiver PRIMARY")
    print("  (% of graphs where a heuristic names that party's PRIMARY)")
    print("=" * 72)

    groups = [
        ("LEGACY  name1 SEND",
         [r for r in evaluated if r[0].family == "legacy" and r[0].party == NAME1]),
        ("LEGACY  name2 RECV",
         [r for r in evaluated if r[0].family == "legacy" and r[0].party == NAME2]),
        ("CURRENT name1 SEND",
         [r for r in evaluated if r[0].family == "current" and r[0].party == NAME1]),
        ("CURRENT name2 RECV",
         [r for r in evaluated if r[0].family == "current" and r[0].party == NAME2]),
        ("BUGGY   name1 SEND (bal_account=0)",
         [r for r in evaluated if r[0].family == "buggy"]),
    ]
    fields = (
        ("genesis / first spend -> PRIMARY", "genesis_is_primary"),
        ("peel-change walk      -> PRIMARY", "peel_change_is_primary"),
        ("repeated spender      -> PRIMARY", "repeated_spender_is_primary"),
        ("fan-out leftover      -> PRIMARY", "leftover_is_primary"),
        ("DEEP reveal names        PRIMARY", "deep_reveal_is_primary"),
        ("named address is name1", "named_is_name1"),
        ("named address is name2", "named_is_name2"),
    )
    print(f"\n  {'group':<34} {'n':>4}  " + "  ".join(f"{lab[:18]:>18}" for lab, _ in fields[:5]))
    print("  " + "-" * 70)
    summary = {}
    for label, rows in groups:
        n = len(rows)
        summary[label] = {f: _pct(rows, f) for _, f in fields}
        summary[label]["_n"] = n
        cells = "  ".join(f"{_pct(rows, f):17.0f}%" for _, f in fields[:5])
        print(f"  {label:<34} {n:4d}  {cells}")
    return summary


def _print_deep_walk(graphs, limit=10):
    print("\n=== DEEP REVEAL: walk graphs to name name1 / name2 ===")
    want = []
    seen = set()
    for g in graphs:
        key = (g.family, g.mode, g.txs[0]["kind"] if g.txs else "?")
        if key in seen:
            continue
        seen.add(key)
        want.append(g)
        if len(want) >= limit:
            break
    for g in want:
        named, reason, notes = deep_reveal(g)
        if named == g.primary:
            tag = f"REVEALED {g.primary}"
        elif named:
            tag = f"MISNAMED {named}"
        else:
            tag = "BLIND"
        print(f"\n  [{tag}] {g.name}  party={g.party} family={g.family}")
        print(f"    first spend (genesis): {attack_genesis(g)}")
        print(f"    named MAIN/FIRST:      {named}   via {reason}")
        for n in notes:
            print(f"      · {n}")
        for i, t in enumerate(g.txs[:6]):
            ins = ",".join(t["ins"])
            outs = " + ".join(f"{a}:{amt}" for a, amt in t["outs"][:4])
            extra = "" if len(t["outs"]) <= 4 else f" +{len(t['outs']) - 4} more"
            print(f"      tx{i} {t['kind']:12}  {ins}  ->  {outs}{extra}")


def _print_combo(rng):
    print("\n=== SCENARIO: name1 sends, name2 receives, then both mix ===")
    for family in ("legacy", "current"):
        g1, g2 = run_combo_name1_to_name2(rng, family, n=5, usable=Decimal("10"),
                                          wallet_id=family[0])
        if not g1 or not g2:
            print(f"  {family}: planner could not fund the graph")
            continue
        n1, r1, notes1 = deep_reveal(g1)
        n2, r2, notes2 = deep_reveal(g2)
        shared = attack_shared_address(g1, g2)
        print(f"\n  {family.upper()}")
        print(f"    name1 SEND  named={n1}  via {r1}  "
              f"{'REVEALED name1' if n1 == NAME1 else 'did not name name1'}")
        print(f"    name2 RECV  named={n2}  via {r2}  "
              f"{'REVEALED name2' if n2 == NAME2 else 'did not name name2'}")
        print(f"    shared addresses across the two wallets: "
              f"{sorted(shared) if shared else 'NONE'}")
        if family == "legacy":
            check("SCENARIO legacy: name1 SEND is named name1", n1 == NAME1)
            check("SCENARIO legacy: name2 RECV is named name2", n2 == NAME2)
            check("SCENARIO legacy: the two wallets share no address "
                  "(they are different people)", not shared)
        else:
            check("SCENARIO current: name1 SEND is NOT named name1", n1 != NAME1)
            check("SCENARIO current: name2 RECV is NOT named name2", n2 != NAME2)
            check("SCENARIO current: no address links name1's graph to name2's",
                  not shared)
            check("SCENARIO current: name1 PRIMARY never appears in the send graph",
                  NAME1 not in {a for t in g1.txs for a in t["ins"]}
                  and NAME1 not in {a for t in g1.txs for a, _ in t["outs"]})
            check("SCENARIO current: name2 PRIMARY never appears in the recv graph",
                  NAME2 not in {a for t in g2.txs for a in t["ins"]}
                  and NAME2 not in {a for t in g2.txs for a, _ in t["outs"]})


def _print_two_receives(rng):
    print("\n=== SCENARIO: two receives to name2 on different days ===")
    for family in ("legacy", "current"):
        a, b = run_two_receives_name2(rng, family, n=5, wallet_id=family[0])
        if not a or not b:
            continue
        named = attack_change_intersection([a, b])
        print(f"  {family}: change-set intersection -> {named}")
        if family == "legacy":
            check("two-recv LEGACY: intersection names name2", named == NAME2)
        else:
            check("two-recv CURRENT: intersection does NOT name name2 "
                  "(each receive has its own account)", named != NAME2)


def main():
    rng = random.Random(20260817)
    graphs = _build_many(rng)
    print(f"\n=== built {len(graphs)} mix graphs from SHIPPED planners ===")
    print(f"    parties: {NAME1} = original sender PRIMARY, "
          f"{NAME2} = receiver PRIMARY")

    evaluated = []
    by_key = defaultdict(list)
    for g in graphs:
        hits, revealed, guess = evaluate(g)
        row = (g, hits, revealed, guess)
        evaluated.append(row)
        by_key[f"{g.family}:{g.mode}:{g.txs[0]['kind'] if g.txs else '?'}"].append(row)

    board = _print_scoreboard(evaluated)

    print("\n=== attack results by family:mode:shape ===")
    for key, rows in sorted(by_key.items()):
        n = len(rows)

        def rate(field):
            return sum(1 for _, h, _, _ in rows if h[field]) / n

        print(f"\n  {key}  n={n}")
        print(f"    genesis finds ENTRY          {rate('genesis_is_entry'):6.0%}")
        print(f"    genesis finds PRIMARY        {rate('genesis_is_primary'):6.0%}")
        print(f"    peel-change walk -> PRIMARY  {rate('peel_change_is_primary'):6.0%}")
        print(f"    repeated spender -> PRIMARY  {rate('repeated_spender_is_primary'):6.0%}")
        print(f"    leftover -> PRIMARY          {rate('leftover_is_primary'):6.0%}")
        print(f"    DEEP reveal names PRIMARY    {rate('deep_reveal_is_primary'):6.0%}")
        print(f"    named address is name1       {rate('named_is_name1'):6.0%}")
        print(f"    named address is name2       {rate('named_is_name2'):6.0%}")

    # Claims, as regression-proof checks.
    leg_send = [r for r in evaluated if r[0].family == "legacy" and r[0].party == NAME1]
    leg_recv = [r for r in evaluated if r[0].family == "legacy" and r[0].party == NAME2]
    cur_send = [r for r in evaluated if r[0].family == "current" and r[0].party == NAME1]
    cur_recv = [r for r in evaluated if r[0].family == "current" and r[0].party == NAME2]
    buggy = [r for r in evaluated if r[0].family == "buggy"]

    check("LEGACY name1 SEND: DEEP reveal names name1 on every graph",
          leg_send and all(h["deep_reveal_is_primary"] and h["named_is_name1"]
                           for _, h, _, _ in leg_send))
    check("LEGACY name2 RECV: DEEP reveal names name2 on every graph",
          leg_recv and all(h["deep_reveal_is_primary"] and h["named_is_name2"]
                           for _, h, _, _ in leg_recv))
    check("CURRENT name1 SEND: DEEP reveal does NOT name name1",
          cur_send and all(not h["named_is_name1"] and not h["deep_reveal_is_primary"]
                           for _, h, _, _ in cur_send))
    check("CURRENT name2 RECV: DEEP reveal does NOT name name2",
          cur_recv and all(not h["named_is_name2"] and not h["deep_reveal_is_primary"]
                           for _, h, _, _ in cur_recv))
    check("BUGGY send (bal_account=0): leftover / sweep source IS name1",
          buggy and all(h["leftover_is_primary"] or h["named_is_name1"]
                        for _, h, _, _ in buggy))
    check("scoreboard ran every amount on the ladder for both parties",
          all(any(r[0].party == NAME1 and r[0].usable == a for r in evaluated) and
              any(r[0].party == NAME2 and r[0].usable == a for r in evaluated)
              for a in AMOUNT_LADDER))

    # The updated tree: spend account IS the mix account, and the wallet
    # must confirm (account, index) is ENTRY before anything is planned.
    # Hard-coding 0 here is how name1 (sender PRIMARY) reappears.
    _gs_src = open(os.path.join(REPO, "GhostSpiral")).read()
    check("spend account is the mix account (bal_account = sub_account)",
          "bal_account = sub_account" in _gs_src)
    check("SEND no longer hard-codes account 0 after rotating the mix",
          "bal_account = receive_account_index if receive_mode else 0" not in _gs_src)
    check("stage 4 verifies the spend source before the balance poll",
          "verify_spend_source(rpc_primary, bal_account, entry_index, ENTRY)" in _gs_src)

    class _RpcAddr:
        def __init__(self, mapping):
            self.mapping = mapping

        def raw_request(self, method, params):
            a, i = params["account_index"], params["address_index"][0]
            addr = self.mapping.get((a, i))
            return {"addresses": ([{"address_index": i, "address": addr}]
                                  if addr else [])}

    _ok = _RpcAddr({(7, 3): "ENTRY_ADDR", (0, 3): "PRIMARY_LOOKALIKE"})
    try:
        ghost.verify_spend_source(_ok, 7, 3, "ENTRY_ADDR")
        _vs_ok = True
    except SystemExit:
        _vs_ok = False
    check("verify_spend_source accepts the rotated mix account for ENTRY", _vs_ok)
    try:
        ghost.verify_spend_source(_ok, 0, 3, "ENTRY_ADDR")
        _vs_bad = True
    except SystemExit:
        _vs_bad = False
    check("verify_spend_source refuses account 0 at ENTRY's index (name1 leak)",
          not _vs_bad)

    _print_combo(rng)
    _print_two_receives(rng)
    _print_deep_walk(graphs)

    n1_cur = board["CURRENT name1 SEND"]["named_is_name1"]
    n2_cur = board["CURRENT name2 RECV"]["named_is_name2"]
    n1_leg = board["LEGACY  name1 SEND"]["named_is_name1"]
    n2_leg = board["LEGACY  name2 RECV"]["named_is_name2"]
    n1_bug = board["BUGGY   name1 SEND (bal_account=0)"]["named_is_name1"]

    print(f"\n  graphs: {len(graphs)}")
    print(f"  LEGACY   name1 uncovered: {n1_leg:5.1f}%")
    print(f"  LEGACY   name2 uncovered: {n2_leg:5.1f}%")
    print(f"  CURRENT  name1 uncovered: {n1_cur:5.1f}%")
    print(f"  CURRENT  name2 uncovered: {n2_cur:5.1f}%")
    print(f"  BUGGY    name1 uncovered: {n1_bug:5.1f}%   "
          f"(the hard-coded account-0 leak)")

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("FAILED:", FAILURES)
    named_any_current = any(
        h["named_is_name1"] or h["named_is_name2"]
        for g, h, _, _ in evaluated if g.family == "current")
    print(">>> name1 (sender):  ",
          "REVEALED on CURRENT" if n1_cur else "BLIND on CURRENT (named on LEGACY)")
    print(">>> name2 (receiver):",
          "REVEALED on CURRENT" if n2_cur else "BLIND on CURRENT (named on LEGACY)")
    print(">>> CURRENT mix graph:",
          "IDENTITY LEAK" if named_any_current else "PRIMARY NOT IN GRAPH")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
