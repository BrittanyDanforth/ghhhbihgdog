#!/usr/bin/env python3
"""Adversarial origin-tracker: run many SEND/RECEIVE mix graphs, then try to
find the wallet's PRIMARY (subaddress 0) from what a chain analyst can see.

Drives the SHIPPED GhostSpiral planners (compute_fanout_amounts, build_peel_plan,
select_fanout_targets, compute_hop_amount). Does not reimplement the money math.

Two visibility models, because they give different answers:

  TRANSPARENT — amounts and address labels are visible (Bitcoin-like, or a
    future break in RingCT). Worst case for the operator.
  STRUCTURE   — only tx shape and the spend graph of outputs (Monero today:
    amounts hidden, addresses not on-chain, but co-created outputs and
    "this output was spent in that later tx" are still visible).

Attacks (all public, Kerckhoffs):
  1. Co-creation cluster — every output of a multi-dest tx is the same wallet.
  2. Genesis / first-spender — the input that never arrived from a prior mix tx.
  3. Peel-change walk — 2-out txs where one output is spent next = change;
     walking back reaches peel 0's input.
  4. Equal-amount cluster — identical values across outputs (jitter should stop this).
  5. Change-is-largest — on a 2-out peel, the bigger leftover is change.
  6. Repeated-spender — the address that keeps showing up as a later-peel source
     is the account change address, which IS primary (subaddr 0).
  7. Unhopped leftover — when DAG hops every mix dest, the fan-out output that
     never hops is change = PRIMARY.
  8. Wallet intersection — two receives (or a receive then a send) from the
     same wallet share exactly one change address: PRIMARY.

Deep reveal (the "name MAIN/FIRST" pass):
  SEND:     first spend IS primary.
  RECEIVE:  first spend is a fresh subaddr; change still returns to subaddr 0.
  COMBO:    receive-then-send, or two receives: intersection names PRIMARY.

This is an attack harness, not a green-wash: if PRIMARY is recoverable it
prints REVEALED. The suite stays honest about which modes leak.
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
REVEALS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL {name}")


class Graph:
    """Analyst-visible mix graph for one scenario."""

    def __init__(self, name, mode, primary, entry, wallet_id="W0", usable=None):
        self.name = name
        self.mode = mode          # send | receive | combo
        self.primary = primary    # wallet subaddr 0
        self.entry = entry        # first spend source (primary on send, receive-sub on receive)
        self.wallet_id = wallet_id
        self.usable = Decimal(usable) if usable is not None else Decimal("0")
        self.txs = []             # list of {ins, outs: [(addr, amt)], kind}
        self.created_by = {}      # addr -> tx index that created it
        self.spent_in = {}        # addr -> tx index that spent it

    def add_tx(self, ins, outs, kind):
        idx = len(self.txs)
        self.txs.append({"ins": list(ins), "outs": list(outs), "kind": kind})
        for a, _ in outs:
            self.created_by.setdefault(a, idx)
        for a in ins:
            self.spent_in[a] = idx
        return idx


def _fanout_dests(rng, wallets):
    decoys = rng.randint(ghost.DECOY_MIN, ghost.DECOY_MAX)
    mix = [f"MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(wallets + decoys + 2)]
    dests, hops = ghost.select_fanout_targets(mix, set(), wallets, decoys)
    return dests, hops


def _maybe_dag(g, dests, amts, dag, fee):
    if not dag:
        return
    for d, a in zip(dests, amts):
        hop = ghost.compute_hop_amount(a, fee)
        if hop <= ghost.DUST_XMR:
            continue
        g.add_tx([d], [(f"HOP_{d}", hop), (d, a - hop)], "dag_hop")


def run_send_fanout(rng, wallets=8, dag=False, usable=Decimal("10"), fee=Decimal("0.001"),
                    wallet_id="W0"):
    primary = "PRIMARY"
    entry = primary
    g = Graph(f"send-fanout-w{wallets}-dag{int(dag)}-u{usable}", "send",
              primary, entry, wallet_id, usable=usable)
    dests, _hops = _fanout_dests(rng, wallets)
    amts = ghost.compute_fanout_amounts(usable, len(dests), fee, dag, rng)
    if not amts:
        return None
    # ENTRY (primary) spends into N mix outputs in ONE tx. Change stays on ENTRY.
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    outs = list(zip(dests, amts)) + [(entry, change)]
    g.add_tx([entry], outs, "fanout")
    _maybe_dag(g, dests, amts, dag, fee)
    return g


def run_send_peel(rng, n=6, dag=False, usable=Decimal("12"), fee=Decimal("0.001"),
                  wallet_id="W0"):
    primary = "PRIMARY"
    entry = primary
    g = Graph(f"send-peel-n{n}-dag{int(dag)}-u{usable}", "send",
              primary, entry, wallet_id, usable=usable)
    dests = [f"MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
    amts = ghost.compute_fanout_amounts(usable, n, fee, dag, rng)
    if not amts:
        return None
    plan = ghost.build_peel_plan(entry_index=0, change_index=0, dests=dests, amounts=amts)
    remain = usable
    for p, amt in zip(plan, amts):
        src = entry if p["src_index"] == 0 and p["peel_num"] == 0 else primary
        # After peel 0, change lives on subaddr 0 = PRIMARY (monerod behaviour).
        remain = remain - amt
        g.add_tx([src], [(p["dst"], amt), (primary, remain)], "peel")
    _maybe_dag(g, dests, amts, dag, fee)
    return g


def run_receive_peel(rng, n=6, dag=False, usable=Decimal("9"), fee=Decimal("0.001"),
                     entry_index=7, wallet_id="W0", entry=None):
    """Receive mode: ENTRY is a fresh subaddress, NOT primary.

    Peel 0 spends the receive subaddr. Peels 1..N spend change_index 0 —
    the wallet PRIMARY. That is the tell this attack is hunting.
    """
    primary = "PRIMARY"
    entry = entry or "RECV_SUB"
    g = Graph(f"recv-peel-n{n}-dag{int(dag)}-u{usable}", "receive",
              primary, entry, wallet_id, usable=usable)
    dests = [f"MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
    amts = ghost.compute_fanout_amounts(usable, n, fee, dag, rng)
    if not amts:
        return None
    # entry_index is the receive sub (not 0); change_index is 0 (PRIMARY).
    plan = ghost.build_peel_plan(entry_index=entry_index, change_index=0,
                                 dests=dests, amounts=amts)
    remain = usable
    for p, amt in zip(plan, amts):
        src = entry if p["src_index"] == entry_index else primary
        remain = remain - amt
        g.add_tx([src], [(p["dst"], amt), (primary, remain)], "peel")
    _maybe_dag(g, dests, amts, dag, fee)
    return g


def run_receive_fanout(rng, wallets=8, dag=False, usable=Decimal("10"),
                       fee=Decimal("0.001"), wallet_id="W0", entry=None):
    primary = "PRIMARY"
    entry = entry or "RECV_SUB"
    g = Graph(f"recv-fanout-w{wallets}-dag{int(dag)}-u{usable}", "receive",
              primary, entry, wallet_id, usable=usable)
    dests, _hops = _fanout_dests(rng, wallets)
    amts = ghost.compute_fanout_amounts(usable, len(dests), fee, dag, rng)
    if not amts:
        return None
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    # Fan-out change returns to the account change address = PRIMARY.
    g.add_tx([entry], list(zip(dests, amts)) + [(primary, change)], "fanout")
    _maybe_dag(g, dests, amts, dag, fee)
    return g


def run_recv_then_send(rng, recv_kind="peel", send_kind="peel", n=5, wallets=6,
                       dag=False, recv_amt=Decimal("9"), send_amt=Decimal("4"),
                       wallet_id="W0"):
    """Most realistic operator path: receive to a fresh sub, mix, then later
    send from the leftover that landed on PRIMARY."""
    primary = "PRIMARY"
    entry = f"RECV_SUB_{wallet_id}"
    g = Graph(f"combo-{recv_kind}>{send_kind}-n{n}-dag{int(dag)}-u{recv_amt}", "combo",
              primary, entry, wallet_id, usable=recv_amt)
    fee = Decimal("0.001")
    if recv_kind == "peel":
        dests = [f"RMIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
        amts = ghost.compute_fanout_amounts(recv_amt, n, fee, dag, rng)
        if not amts:
            return None
        plan = ghost.build_peel_plan(entry_index=7, change_index=0,
                                     dests=dests, amounts=amts)
        remain = recv_amt
        for p, amt in zip(plan, amts):
            src = entry if p["src_index"] == 7 else primary
            remain = remain - amt
            g.add_tx([src], [(p["dst"], amt), (primary, remain)], "peel")
        leftover = remain
        _maybe_dag(g, dests, amts, dag, fee)
    else:
        dests, _ = _fanout_dests(rng, wallets)
        amts = ghost.compute_fanout_amounts(recv_amt, len(dests), fee, dag, rng)
        if not amts:
            return None
        leftover = (recv_amt - sum(amts)).quantize(Decimal("0.0001"))
        g.add_tx([entry], list(zip(dests, amts)) + [(primary, leftover)], "fanout")
        _maybe_dag(g, dests, amts, dag, fee)

    # Later send spends PRIMARY (the leftover / change carrier).
    spend = min(send_amt, leftover) if leftover > ghost.DUST_XMR * 4 else send_amt
    if spend <= ghost.DUST_XMR * 4:
        spend = Decimal("3")
    if send_kind == "peel":
        dests2 = [f"SMIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(max(3, n - 1))]
        amts2 = ghost.compute_fanout_amounts(spend, len(dests2), fee, False, rng)
        if not amts2:
            return g
        plan2 = ghost.build_peel_plan(entry_index=0, change_index=0,
                                      dests=dests2, amounts=amts2)
        remain = spend
        for p, amt in zip(plan2, amts2):
            remain = remain - amt
            g.add_tx([primary], [(p["dst"], amt), (primary, remain)], "peel")
    else:
        dests2, _ = _fanout_dests(rng, max(4, wallets - 2))
        amts2 = ghost.compute_fanout_amounts(spend, len(dests2), fee, False, rng)
        if not amts2:
            return g
        ch = (spend - sum(amts2)).quantize(Decimal("0.0001"))
        g.add_tx([primary], list(zip(dests2, amts2)) + [(primary, ch)], "fanout")
    return g


def run_two_receives(rng, n=5, dag=False, wallet_id="W0",
                     amt_a=Decimal("8"), amt_b=Decimal("6")):
    """Two inbound payments to two fresh subaddrs of the SAME wallet.

    Change of both peels lands on PRIMARY. Intersection of the two change
    sets is the main address — the deep 'reveal first' tell.
    """
    primary = "PRIMARY"
    a = f"RECV_A_{wallet_id}"
    b = f"RECV_B_{wallet_id}"
    total = amt_a + amt_b
    g = Graph(f"two-recv-n{n}-dag{int(dag)}-u{total}", "combo", primary, a, wallet_id,
              usable=total)
    fee = Decimal("0.001")
    for entry, idx, usable, tag in (
        (a, 7, amt_a, "A"),
        (b, 11, amt_b, "B"),
    ):
        dests = [f"{tag}MIX_{i}_{rng.randrange(1 << 20):05x}" for i in range(n)]
        amts = ghost.compute_fanout_amounts(usable, n, fee, dag, rng)
        if not amts:
            return None
        plan = ghost.build_peel_plan(entry_index=idx, change_index=0,
                                     dests=dests, amounts=amts)
        remain = usable
        for p, amt in zip(plan, amts):
            src = entry if p["src_index"] == idx else primary
            remain = remain - amt
            g.add_tx([src], [(p["dst"], amt), (primary, remain)], "peel")
        _maybe_dag(g, dests, amts, dag, fee)
    return g


# ── attacks ────────────────────────────────────────────────────────────────

def attack_genesis(g: Graph):
    """First input of the first mix tx — the opening spend.

    Self-change (ENTRY paying itself the leftover) puts ENTRY in created_by
    of that same tx, so "never created by a prior tx" is the wrong test:
    the analyst just reads the first spend.
    """
    if not g.txs or not g.txs[0]["ins"]:
        return None
    return g.txs[0]["ins"][0]


def attack_peel_change_walk(g: Graph):
    """Walk 2-out peels: the output that is spent in the next peel is change.
    The input of peel 0 is the first spend; the repeated change address is primary."""
    peels = [t for t in g.txs if t["kind"] == "peel"]
    if len(peels) < 2:
        return None
    # Change = the out that appears as an in of a later peel.
    later_ins = {a for t in peels[1:] for a in t["ins"]}
    change_addrs = []
    for t in peels:
        for a, _ in t["outs"]:
            if a in later_ins:
                change_addrs.append(a)
    if not change_addrs:
        return None
    # Most frequent change address.
    return max(set(change_addrs), key=change_addrs.count)


def attack_repeated_spender(g: Graph):
    """Address that spends in the most mix txs (the change carrier)."""
    counts = defaultdict(int)
    for t in g.txs:
        if t["kind"] in ("peel", "fanout"):
            for a in t["ins"]:
                counts[a] += 1
    if not counts:
        return None
    return max(counts, key=counts.get)


def attack_largest_change(g: Graph):
    """On each 2-out peel, guess the larger output is change; take the mode."""
    guesses = []
    for t in g.txs:
        if t["kind"] != "peel" or len(t["outs"]) != 2:
            continue
        bigger = max(t["outs"], key=lambda x: x[1])[0]
        guesses.append(bigger)
    if not guesses:
        return None
    return max(set(guesses), key=guesses.count)


def attack_cocreation(g: Graph):
    """Outputs of the first multi-out tx — the mix cluster. Does not name PRIMARY
    unless PRIMARY is one of those outputs (the change output of a fan-out)."""
    for t in g.txs:
        if len(t["outs"]) >= 3:
            return [a for a, _ in t["outs"]]
    return []


def attack_equal_amounts(g: Graph):
    vals = defaultdict(list)
    for t in g.txs:
        for a, amt in t["outs"]:
            vals[amt].append(a)
    clusters = [v for k, v in vals.items() if len(v) >= 3]
    return clusters


def attack_unhopped_change(g: Graph):
    """When every mix dest hops, the fan-out output that never hops is change.

    Kerckhoffs: the shipped rule is hop_sources == fanout_dests. Change is
    the leftover that stays on subaddr 0 and is NOT in that hop set.
    """
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
    """SEND fan-out: change returns to the same address that spent (PRIMARY).

    RECEIVE fan-out never does this — the spender is the one-shot sub, change
    lands on subaddr 0. So a self-change output names MAIN on send only.
    """
    for t in g.txs:
        if t["kind"] != "fanout" or not t["ins"]:
            continue
        spender = t["ins"][0]
        if any(a == spender for a, _ in t["outs"]):
            return spender
    return None


def attack_fanout_leftover(g: Graph):
    """Transparent leftover: dests sum to ~FANOUT_SPEND_FRACTION of usable;
    the remaining output is change = PRIMARY."""
    for t in g.txs:
        if t["kind"] != "fanout" or len(t["outs"]) < 3:
            continue
        outs = list(t["outs"])
        total = sum(a for _, a in outs)
        # Analyst: pick the output whose removal leaves a dest set summing
        # to ~90% of (dests+change). A dest that happens to equal the leftover
        # amount ties — prefer the self-change output (SEND) when present.
        target = (total * ghost.FANOUT_SPEND_FRACTION).quantize(Decimal("0.0001"))
        spender = t["ins"][0] if t["ins"] else None
        best = None
        best_err = None
        for i, (addr, _amt) in enumerate(outs):
            dest_sum = sum(a for j, (_, a) in enumerate(outs) if j != i)
            err = abs(dest_sum - target)
            tied_self = best_err is not None and err == best_err and spender and addr == spender
            if best_err is None or err < best_err or tied_self:
                best_err = err
                best = addr
        return best
    return None


def attack_change_intersection(graphs):
    """Same wallet, two inbound mixes: the only shared change address is PRIMARY."""
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
        # Every peel/fanout leftover output that is later spent.
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


def deep_reveal_main(g: Graph):
    """Name the wallet's MAIN/FIRST address from the graph.

    Order of evidence (strongest structural first):
      1. Peel-change walk — later peels spend the leftover.
      2. Unhopped leftover — DAG hops every mix dest; change stays.
      3. Repeated spender that is NOT the one-shot genesis (receive tell).
      4. Fan-out leftover (~10% remainder under FANOUT_SPEND_FRACTION).
      5. Genesis, only when it equals the change carrier (send tell).

    Returns (named_addr, reason, path_notes).
    """
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
        notes.append(f"SEND fan-out: change returns to the spender {self_ch} -> first IS main")
        return self_ch, "self-change", notes
    if left and gen and left != gen:
        notes.append(f"fan-out leftover (~{float(1 - ghost.FANOUT_SPEND_FRACTION):.0%} remainder) -> {left}")
        notes.append(f"RECEIVE: leftover returns to {left}, not genesis {gen}")
        return left, "fanout-leftover", notes
    if rept and gen and rept == gen:
        notes.append(f"SEND: first spend {gen} is the only mix source -> MAIN")
        return rept, "genesis-is-main", notes
    if large:
        notes.append(f"largest-is-change fallback -> {large}")
        return large, "largest-is-change", notes
    notes.append("blind")
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
    named, reason, _notes = deep_reveal_main(g)

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


# Amount ladder: dust-adjacent up through large. Higher XMR makes leftover /
# largest-is-change easier (the ~10% remainder is a bigger, more distinct chunk;
# peel remain stays > dest for more steps). Equal-amount clusters go the other
# way — 0.0001 quantisation collides more when the pot is small.
AMOUNT_LADDER = [
    Decimal("0.5"), Decimal("1"), Decimal("2"), Decimal("5"),
    Decimal("10"), Decimal("25"), Decimal("50"), Decimal("100"),
]
REPEATS_PER_CELL = 4


def _dests_for_amount(usable):
    """Fewer dests at tiny pots so the shipped planner can still fund them."""
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
                    lambda r, u=usable, k=peel_n, d=dag: run_send_peel(r, k, d, u),
                    lambda r, u=usable, w=fan_w, d=dag: run_send_fanout(r, w, d, u),
                    lambda r, u=usable, k=peel_n, d=dag: run_receive_peel(r, k, d, u),
                    lambda r, u=usable, w=fan_w, d=dag: run_receive_fanout(r, w, d, u),
                ):
                    g = builder(rng)
                    if g:
                        graphs.append(g)
        # Receive-then-send at this inbound amount (later send spends leftover).
        send_amt = (usable * Decimal("0.4")).quantize(Decimal("0.0001"))
        if send_amt < Decimal("0.2"):
            send_amt = Decimal("0.2")
        for recv_k, send_k, dag in (
            ("peel", "peel", False),
            ("fanout", "fanout", False),
            ("peel", "fanout", True),
        ):
            g = run_recv_then_send(
                rng, recv_k, send_k, n=peel_n, wallets=fan_w, dag=dag,
                recv_amt=usable, send_amt=send_amt,
                wallet_id=f"C{usable}{recv_k[0]}{send_k[0]}{int(dag)}")
            if g:
                graphs.append(g)
        half = (usable / 2).quantize(Decimal("0.0001"))
        other = usable - half
        g = run_two_receives(rng, n=peel_n, dag=False, wallet_id=f"T{usable}",
                             amt_a=half, amt_b=other)
        if g:
            graphs.append(g)
    return graphs


def _pct(hits, n):
    return (100.0 * hits / n) if n else 0.0


def _print_scoreboard(evaluated):
    """% of actual SENDER / RECEIVER uncovered, by amount.

    SENDER   = send-mode graph: first spend is the operator's PRIMARY.
    RECEIVER inbound = receive/combo: genesis is the published receive sub.
    RECEIVER main    = receive/combo: deep reveal names PRIMARY anyway.
    Amount-heuristics (largest / leftover) are the ones that get easier as
    the pot grows; structural walks do not care about the XMR figure.
    """
    print("\n=== SCENARIOS RUN (amount · role · uncovered?) ===")
    print(f"  {'amount':>10}  {'role':<16}  {'kind':<8}  {'uncovered':<10}  "
          f"{'named':<10}  via")
    for g, hits, _rev, guess in evaluated:
        if g.mode == "send":
            role = "SENDER"
            uncovered = hits["deep_reveal_is_primary"]
        elif g.mode == "receive":
            role = "RECEIVER"
            uncovered = hits["deep_reveal_is_primary"]
        else:
            role = "RECV+SEND"
            uncovered = hits["deep_reveal_is_primary"]
        kind = g.txs[0]["kind"] if g.txs else "?"
        print(f"  {g.usable.quantize(Decimal('0.0001')):>8} XMR  {role:<16}  {kind:<8}  "
              f"{'YES' if uncovered else 'NO':<10}  "
              f"{str(guess['deep'] or '-'):<10}  {guess['deep_reason']}")

    def bucket(rows, pred):
        n = len(rows)
        h = sum(1 for r in rows if pred(r))
        return h, n, _pct(h, n)

    send = [r for r in evaluated if r[0].mode == "send"]
    recv = [r for r in evaluated if r[0].mode == "receive"]
    combo = [r for r in evaluated if r[0].mode == "combo"]

    print("\n=== UNCOVER % — actual SENDER vs actual RECEIVER ===")
    sh, sn, sp = bucket(send, lambda r: r[1]["deep_reveal_is_primary"])
    print(f"  SENDER   (send-mode PRIMARY / first spend)     "
          f"{sh}/{sn}  {sp:5.1f}% uncovered")
    rh, rn, rp = bucket(recv, lambda r: r[1]["genesis_is_entry"])
    print(f"  RECEIVER inbound sub (published RECV_SUB)      "
          f"{rh}/{rn}  {rp:5.1f}% found as first spend")
    rph, rpn, rpp = bucket(recv, lambda r: r[1]["deep_reveal_is_primary"])
    print(f"  RECEIVER main/first  (PRIMARY behind inbound)  "
          f"{rph}/{rpn}  {rpp:5.1f}% uncovered")
    ch, cn, cp = bucket(combo, lambda r: r[1]["deep_reveal_is_primary"])
    print(f"  RECV+SEND combo      (PRIMARY after inbound)   "
          f"{ch}/{cn}  {cp:5.1f}% uncovered")

    # By exact amount — this is the table the operator asked for.
    print("\n=== UNCOVER % by amount (higher XMR → amount-heuristics get easier) ===")
    hdr = (f"  {'amount':>10}  {'n':>4}  {'sender%':>8}  {'recv_in%':>8}  "
           f"{'recv_main%':>10}  {'largest%':>9}  {'leftover%':>10}  {'equal%':>7}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    by_amt = defaultdict(list)
    for row in evaluated:
        by_amt[row[0].usable].append(row)
    low_amt_large = None
    high_amt_large = None
    low_amt_left = None
    high_amt_left = None
    for amt in sorted(by_amt):
        rows = by_amt[amt]
        srows = [r for r in rows if r[0].mode == "send"]
        rrows = [r for r in rows if r[0].mode == "receive"]
        peels = [r for r in rows if r[0].txs and r[0].txs[0]["kind"] == "peel"]
        fans = [r for r in rows if r[0].txs and r[0].txs[0]["kind"] == "fanout"]
        _, _, sender_p = bucket(srows, lambda r: r[1]["deep_reveal_is_primary"])
        _, _, rin_p = bucket(rrows, lambda r: r[1]["genesis_is_entry"])
        _, _, rmain_p = bucket(rrows, lambda r: r[1]["deep_reveal_is_primary"])
        # Amount-heuristics only apply to the shape they fit — don't dilute
        # leftover% with peels (which have no leftover) or largest% with fan-outs.
        _, _, lp = bucket(peels, lambda r: r[1]["largest_change_is_primary"])
        _, _, kp = bucket(fans, lambda r: r[1]["leftover_is_primary"])
        _, _, ep = bucket(rows, lambda r: r[1]["equal_amount_cluster_exists"])
        print(f"  {amt.quantize(Decimal('0.0001')):>8} XMR  {len(rows):>4}  "
              f"{sender_p:7.1f}%  {rin_p:7.1f}%  "
              f"{rmain_p:9.1f}%  {lp:8.1f}%  {kp:9.1f}%  {ep:6.1f}%")
        if amt == Decimal("0.5"):
            low_amt_large, low_amt_left = lp, kp
        if amt == Decimal("100"):
            high_amt_large, high_amt_left = lp, kp

    print("\n  largest% = peel graphs only (2-out leftover). leftover% = fan-out graphs only.")
    print("  sender% / recv_main% = structural (change → subaddr 0); amount does not save you.")
    print("  equal% = jitter failures; MORE common at small pots (0.0001 quantisation).")
    return {
        "sender": (sh, sn, sp),
        "recv_inbound": (rh, rn, rp),
        "recv_main": (rph, rpn, rpp),
        "combo": (ch, cn, cp),
        "low_largest": low_amt_large,
        "high_largest": high_amt_large,
        "low_leftover": low_amt_left,
        "high_leftover": high_amt_left,
        "by_amt": by_amt,
    }


def _print_deep_walk(graphs, limit=12):
    print("\n=== DEEP REVEAL: walk graphs to name MAIN/FIRST ===")
    shown = 0
    # Prefer one of each family.
    want = []
    seen_fam = set()
    for g in graphs:
        fam = g.name.split("-u")[0] if "-u" in g.name else g.name.rsplit("-", 1)[0]
        fam = "-".join(g.name.split("-")[:3])
        if fam in seen_fam:
            continue
        seen_fam.add(fam)
        want.append(g)
        if len(want) >= limit:
            break
    for g in want:
        named, reason, notes = deep_reveal_main(g)
        tag = "REVEALED" if named == g.primary else "MISSED"
        print(f"\n  [{tag}] {g.name}  mode={g.mode}")
        print(f"    first spend (genesis): {attack_genesis(g)}")
        print(f"    named MAIN/FIRST:      {named}   via {reason}")
        for n in notes:
            print(f"      · {n}")
        # Compact path of the first few mix txs.
        for i, t in enumerate(g.txs[:6]):
            ins = ",".join(t["ins"])
            outs = " + ".join(f"{a}:{amt}" for a, amt in t["outs"][:4])
            extra = "" if len(t["outs"]) <= 4 else f" +{len(t['outs']) - 4} more"
            print(f"      tx{i} {t['kind']:8}  {ins}  ->  {outs}{extra}")
        shown += 1
    return shown


def main():
    rng = random.Random(20260816)
    graphs = _build_many(rng)

    print(f"\n=== built {len(graphs)} mix graphs from SHIPPED planners ===")
    by_mode = defaultdict(list)
    evaluated = []
    for g in graphs:
        hits, revealed, guess = evaluate(g)
        row = (g, hits, revealed, guess)
        evaluated.append(row)
        key = g.mode + ":" + g.txs[0]["kind"]
        by_mode[key].append(row)
        if revealed:
            REVEALS.append((g.name, guess))

    board = _print_scoreboard(evaluated)

    # Honest tallies
    print("\n=== attack results (PRIMARY = wallet subaddr 0) ===")
    for key, rows in sorted(by_mode.items()):
        n = len(rows)

        def rate(field):
            return sum(1 for _, h, _, _ in rows if h[field]) / n

        print(f"\n  {key}  n={n}")
        print(f"    genesis finds ENTRY          {rate('genesis_is_entry'):6.0%}")
        print(f"    genesis finds PRIMARY        {rate('genesis_is_primary'):6.0%}")
        print(f"    peel-change walk -> PRIMARY  {rate('peel_change_is_primary'):6.0%}")
        print(f"    repeated spender -> PRIMARY  {rate('repeated_spender_is_primary'):6.0%}")
        print(f"    largest-is-change -> PRIMARY {rate('largest_change_is_primary'):6.0%}")
        print(f"    PRIMARY sits in fan-out set  {rate('primary_in_fanout_cluster'):6.0%}")
        print(f"    unhopped leftover -> PRIMARY {rate('unhopped_is_primary'):6.0%}")
        print(f"    fan-out leftover -> PRIMARY  {rate('leftover_is_primary'):6.0%}")
        print(f"    DEEP reveal names PRIMARY    {rate('deep_reveal_is_primary'):6.0%}")
        print(f"    equal-amount cluster exists  {rate('equal_amount_cluster_exists'):6.0%}")

    send_fan = by_mode.get("send:fanout", [])
    recv_fan = by_mode.get("receive:fanout", [])
    send_peel = by_mode.get("send:peel", [])
    recv_peel = by_mode.get("receive:peel", [])
    combo_peel = by_mode.get("combo:peel", [])
    combo_fan = by_mode.get("combo:fanout", [])

    print("\n=== what the attacks prove about the shipped modes ===")
    if send_fan:
        check("SEND fan-out: genesis is PRIMARY (the first spend IS the main addr)",
              all(h["genesis_is_primary"] for _, h, _, _ in send_fan))
        check("SEND fan-out: PRIMARY is in the co-created output set (change)",
              all(h["primary_in_fanout_cluster"] for _, h, _, _ in send_fan))
        eq_rate = sum(1 for _, h, _, _ in send_fan if h["equal_amount_cluster_exists"]) / len(send_fan)
        check("SEND fan-out: jitter is not a complete defense (equal clusters still happen)",
              eq_rate < 1.0)
        print(f"         (equal-amount cluster rate under jitter: {eq_rate:.0%})")
        dag_fan = [(g, h) for g, h, _, _ in send_fan
                   if any(t["kind"] == "dag_hop" for t in g.txs)]
        if dag_fan:
            check("SEND fan-out + DAG: unhopped leftover is PRIMARY",
                  all(h["unhopped_is_primary"] for _, h in dag_fan))
    if recv_fan:
        check("RECEIVE fan-out: genesis is the receive sub, NOT primary",
              all(h["genesis_is_entry"] and not h["genesis_is_primary"]
                  for _, h, _, _ in recv_fan))
        check("RECEIVE fan-out: PRIMARY still appears as the change output",
              all(h["primary_in_fanout_cluster"] for _, h, _, _ in recv_fan))
        check("RECEIVE fan-out: leftover heuristic names PRIMARY",
              all(h["leftover_is_primary"] for _, h, _, _ in recv_fan))
        dag_rf = [(g, h) for g, h, _, _ in recv_fan
                  if any(t["kind"] == "dag_hop" for t in g.txs)]
        if dag_rf:
            check("RECEIVE fan-out + DAG: unhopped leftover is PRIMARY (structure, no labels)",
                  all(h["unhopped_is_primary"] for _, h in dag_rf))
    if send_peel:
        check("SEND peel: peel-change walk recovers PRIMARY every time",
              all(h["peel_change_is_primary"] for _, h, _, _ in send_peel))
        check("SEND peel: no 3+ output co-creation cluster (the peel point)",
              all(gss["cluster_n"] < 3 for _, _, _, gss in send_peel))
        check("SEND peel: first spend is PRIMARY",
              all(h["genesis_is_primary"] for _, h, _, _ in send_peel))
    if recv_peel:
        check("RECEIVE peel: genesis is RECV_SUB, not PRIMARY (peel 0 is clean)",
              all(h["genesis_is_entry"] and not h["genesis_is_primary"]
                  for _, h, _, _ in recv_peel))
        check("RECEIVE peel: change-walk STILL recovers PRIMARY (peels 2..N spend subaddr 0)",
              all(h["peel_change_is_primary"] for _, h, _, _ in recv_peel))
        check("RECEIVE peel: repeated-spender STILL recovers PRIMARY",
              all(h["repeated_spender_is_primary"] for _, h, _, _ in recv_peel))
    if combo_peel or combo_fan:
        combo = combo_peel + combo_fan
        check("COMBO receive-then-send / two-recv: DEEP reveal names PRIMARY",
              all(h["deep_reveal_is_primary"] for _, h, _, _ in combo))
        check("COMBO: first spend is the receive sub, not PRIMARY",
              all(h["genesis_is_entry"] and not h["genesis_is_primary"]
                  for _, h, _, _ in combo))

    # Pair two independent receive graphs as if they were the same wallet
    # observed on two different days — intersection of change sets.
    recv_pairs = [g for g in graphs if g.mode == "receive" and g.txs[0]["kind"] == "peel"]
    pair_hits = 0
    pair_n = 0
    for i in range(0, len(recv_pairs) - 1, 2):
        named = attack_change_intersection([recv_pairs[i], recv_pairs[i + 1]])
        pair_n += 1
        if named == "PRIMARY":
            pair_hits += 1
    if pair_n:
        print(f"\n  two-receive intersection: {pair_hits}/{pair_n} named PRIMARY")
        check("two independent RECEIVE peels: change-set intersection is PRIMARY",
              pair_hits == pair_n)

    _print_deep_walk(graphs)

    # The deep finding, stated as a test so it cannot silently regress:
    check("FINDING: every peel/fan-out path that returns change to subaddr 0 "
          "lets an analyst name PRIMARY",
          all(h["peel_change_is_primary"] or h["primary_in_fanout_cluster"]
              or h["repeated_spender_is_primary"] or h["deep_reveal_is_primary"]
              for rows in by_mode.values() for _, h, _, _ in rows))
    check("DEEP REVEAL names PRIMARY on every built graph",
          all(h["deep_reveal_is_primary"]
              for rows in by_mode.values() for _, h, _, _ in rows))
    check("scoreboard ran every amount on the ladder for both send and receive",
          all(any(r[0].mode == "send" and r[0].usable == a for r in evaluated) and
              any(r[0].mode == "receive" and r[0].usable == a for r in evaluated)
              for a in AMOUNT_LADDER))
    sh, sn, sp = board["sender"]
    rph, rpn, rpp = board["recv_main"]
    check(f"SENDER uncover is total, not a sample ({sh}/{sn})",
          sn > 0 and sh == sn)
    check(f"RECEIVER main uncover is total, not a sample ({rph}/{rpn})",
          rpn > 0 and rph == rpn)
    if board["low_leftover"] is not None and board["high_leftover"] is not None:
        check("leftover heuristic is at least as easy at 100 XMR as at 0.5 XMR",
              board["high_leftover"] >= board["low_leftover"])

    print(f"\n  graphs: {len(graphs)}  reveals: {len(REVEALS)}/{len(graphs)}")
    print(f"  SENDER uncovered:        {sp:5.1f}%  ({sh}/{sn})")
    print(f"  RECEIVER main uncovered: {rpp:5.1f}%  ({rph}/{rpn})")
    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("FAILED:", FAILURES)
    print(">>> ORIGIN TRACKER:", "PRIMARY RECOVERABLE" if REVEALS else "BLIND")
    print(">>> MAIN/FIRST:", "REVEALED" if FAIL == 0 and REVEALS else "NOT NAMED")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
