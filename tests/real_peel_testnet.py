#!/usr/bin/env python3
"""Prove the PEELING CHAIN works on-chain, and that nothing it does afterwards
gives the chain back.

A fan-out's weakness is that its N outputs are co-created in one transaction.
A peeling chain sends to ONE mix subaddress per transaction, so the N outputs
appear in N SEPARATE transactions with rotating carriers and no repeated
spender.

That was already asserted here and passed -- while the run still ended with a
single change sweep spending all N peels' change together. A transaction's
INPUTS are public: spending N outputs in one transaction is permanent proof
that those N outputs have one owner, needing no ring analysis at all, and
those N outputs were the change of the N peels. The chain was undone by its
own tidy-up.

The previous version of this file printed that change accumulating and
excused it -- "change dust; never spent... what matters is that it is never
SPENT, so it cannot be walked" -- which reasons past the defect rather than
catching it. The danger was never that a peel spends subaddress 0. It was the
sweep that came later. So the measurement this suite exists for is now:

    NO transaction in the whole run may spend more than ONE input.

Runs on `monerod --regtest` (hard fork v16 from height 1: RingCT, ring 16,
current fee rules) via tests/monerolab.py, NOT on `--testnet --offline`, which
is a pre-RingCT chain where output counts, ring sizes and fees are all
different -- see monerolab's docstring.

SKIPs (exit 0) if the monero binaries aren't installed.
"""
import importlib.machinery
import importlib.util
import os
import random
import shutil
import sys
import tempfile
from decimal import Decimal

for _b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(_b) is None:
        print(f"SKIP: {_b} not on PATH")
        sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, REPO)
from monerolab import MoneroLab                              # noqa: E402


def load(name):
    ld = importlib.machinery.SourceFileLoader(
        name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")

ATOMIC = 10 ** 12
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


class LabRpc:
    """The two methods the shipped peel planner asks a wallet for."""

    def __init__(self, lab):
        self.lab = lab

    def raw_request(self, method, params=None):
        r = self.lab.wj(method, params)
        if "error" in r:
            raise RuntimeError(r["error"].get("message", "rpc error"))
        return r.get("result")

    def new_subaddress_indexed(self, account_index=0, label=""):
        r = self.raw_request("create_address", {"account_index": account_index,
                                                "label": label})
        return r["address"], r["address_index"]


BASE = tempfile.mkdtemp(prefix="peel_")
lab = MoneroLab(BASE, 30161, 30163)
result = "FAILED"
try:
    lab.start()
    hf = lab.dj("hard_fork_info")["result"]
    print(f"chain: hard fork v{hf['version']} (enabled={hf['enabled']}) "
          f"-- RingCT, ring 16, current fee rules")

    lab.wj("create_wallet", {"filename": "w", "password": "", "language": "English"})
    primary = lab.wj("get_address", {"account_index": 0})["result"]["address"]
    lab.gen(primary, 120)
    fee_xmr = Decimal(lab.fee_estimate(1)) / ATOMIC
    print(f"daemon priority-1 fee estimate: {fee_xmr} XMR")

    def subbal(acct, idx):
        b = lab.wj("get_balance", {"account_index": acct,
                                   "address_indices": [idx]})["result"]
        per = [s for s in b["per_subaddress"] if s["address_index"] == idx]
        return ((int(per[0]["balance"]), int(per[0]["unlocked_balance"]))
                if per else (0, 0))

    # The mix runs in its OWN account, as the pipeline does -- account 0's
    # subaddress 0 is the wallet's primary address and is never involved.
    MIX = lab.wj("create_account", {"label": ""})["result"]["account_index"]
    entry = lab.wj("create_address", {"account_index": MIX})["result"]
    E = entry["address_index"]
    lab.wj("transfer_split", {"destinations": [{"amount": int(6 * ATOMIC),
                                                "address": entry["address"]}],
                              "account_index": 0, "priority": 1})
    lab.gen(primary, 15)
    print(f"ENTRY is account {MIX} subaddr {E}, funded "
          f"{subbal(MIX, E)[0] / ATOMIC} XMR")

    # SHIPPED sizing, SHIPPED planner. Nothing hand-rolled: a test that
    # reimplements the reserve rule cannot fail when the shipped one is wrong.
    N = 3
    mix = [lab.wj("create_address", {"account_index": MIX})["result"]
           for _ in range(N)]
    bal = Decimal(subbal(MIX, E)[1]) / ATOMIC
    usable, _fees, _rounds = ghost.compute_fee_budget(bal, fee_xmr, N, peel=True, dag_mixing=False,
                                                   exit_set=False)
    amounts = ghost.compute_fanout_amounts(usable, N, fee_xmr, False,
                                           random.Random(99))
    hop_fee = fee_xmr * ghost.FEE_SAFETY_MARGIN * ghost.PEEL_CARRIER_RESERVE_MULT
    amounts, frac, _pex = ghost.fit_peel_distribution(amounts, bal, usable, N, fee_xmr,
                                                False, random.Random(99), hop_fee)
    check("the shipped planner funds this chain at the default distribution",
          frac is None)
    plan, change_accounts = ghost.build_peel_stage_plan(
        LabRpc(lab), MIX, entry["address"], E, [m["address"] for m in mix],
        dict(zip([m["address"] for m in mix], amounts)), hop_fee)

    check("shipped build_peel_stage_plan produced N peels", len(plan) == N)
    check("peel 0 spends ENTRY", plan[0]["src_index"] == E)
    check("no peel spends a subaddress 0 -- the hub is gone",
          all(p["src_index"] != 0 for p in plan))
    check("each peel spends a DISTINCT address (no repeated spender)",
          len({(p["account_index"], p["src_index"]) for p in plan}) == N)
    check("each peel runs in its OWN account, so its change is its own",
          len({p["account_index"] for p in plan}) == N)
    check("one change location is reported per hop",
          sorted(change_accounts) == sorted(p["account_index"] for p in plan))
    print("peel amounts (XMR):", [str(a) for a in amounts])

    planned = {m["address_index"]: int((a * ATOMIC).to_integral_value())
               for m, a in zip(mix, amounts)}
    txids = []
    spent = []
    for i, p in enumerate(plan):
        acct, src = p["account_index"], p["src_index"]
        dests = p.get("destinations") or [{"address": p["dst"], "amount": p["amt"]}]
        need = sum((Decimal(str(d["amount"])) for d in dests), Decimal(0))
        if i > 0:
            for _ in range(60):
                lab.wj("refresh")
                if Decimal(subbal(acct, src)[1]) / ATOMIC >= need:
                    break
                lab.gen(primary, 2)
            check(f"peel {i}: rotating carrier (acct {acct} subaddr {src}) "
                  f"confirmed+unlocked",
                  Decimal(subbal(acct, src)[1]) / ATOMIC >= need)
        r = lab.wj("transfer_split", {
            "destinations": [{"amount": int((Decimal(str(d["amount"])) * ATOMIC)
                                            .to_integral_value()),
                              "address": d["address"]} for d in dests],
            "account_index": acct, "subaddr_indices": [src], "priority": 1})
        ths = (r.get("result") or {}).get("tx_hash_list") or []
        if not ths:
            print(f"  peel {i} error:", str(r.get("error") or r)[:200])
        check(f"peel {i + 1}/{N} relayed as its own transaction", bool(ths))
        assert ths
        txids += ths
        spent.append((acct, src))
        lab.gen(primary, 12)

    check("every peel was a DISTINCT transaction (not one fan-out)",
          len(set(txids)) == N)
    got = {m["address_index"]: subbal(MIX, m["address_index"])[0] for m in mix}
    for k in planned:
        print(f"    mix subaddr {k}: planned {planned[k] / ATOMIC:.4f}  "
              f"got {got[k] / ATOMIC:.4f}  "
              f"{'OK' if got[k] == planned[k] else 'MISMATCH'}")
    check("each mix subaddress received its own peeled amount on-chain",
          all(got[k] == planned[k] for k in planned))
    check("ENTRY was drained by peel 0", subbal(MIX, E)[0] < ATOMIC // 2)
    check("no address was spent more than once", len(set(spent)) == len(spent))

    # -- the tidy-up, which is where this used to come apart ---------------
    sweeps = []
    had_change = []
    for acct in change_accounts:
        left = subbal(acct, 0)[0]
        if left == 0:
            continue
        had_change.append(acct)
        dst = lab.wj("create_address", {"account_index": MIX})["result"]["address"]
        r = lab.wj("sweep_all", {"address": dst, "account_index": acct,
                                 "subaddr_indices": [0], "get_tx_keys": False})
        h = (r.get("result") or {}).get("tx_hash_list") or []
        if not h:
            print(f"  change sweep on account {acct} failed: "
                  f"{str(r.get('error') or r)[:160]}")
        sweeps += h
        lab.gen(primary, 3)
    check("every hop's change was swept",
          all(subbal(a, 0)[0] == 0 for a in change_accounts))
    # Every hop leaves (headroom - real fee) behind, so every hop must have had
    # change to sweep. If one did not, the reserve arithmetic changed and this
    # suite should say so rather than quietly sweeping fewer accounts.
    check("every hop actually left change on its own account",
          len(had_change) == len(change_accounts))
    check("the change was swept in SEPARATE transactions, exactly one per hop",
          len(sweeps) == len(change_accounts))

    # -- THE MEASUREMENT ---------------------------------------------------
    shapes = lab.tx_shapes(txids + sweeps)
    print("\n  ON-CHAIN SHAPES (what an analyst reads, no wallet involved):")
    for s in shapes:
        print(f"    {s['hash'][:12]}  {s['n_in']}-in / {s['n_out']}-out  "
              f"extra={s['extra_len']}  rings={sorted(set(s['ring_sizes']))}  "
              f"fee={Decimal(s['fee']) / ATOMIC}")
    check("the chain really is running current consensus (ring size 16)",
          all(all(r == 16 for r in s["ring_sizes"]) for s in shapes))
    worst = max((s["n_in"] for s in shapes), default=0)
    check("NO transaction spends more than ONE input -- nothing publicly "
          f"proves two of these outputs share an owner (worst: {worst})",
          worst <= 1)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    lab.stop()
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
print(f">>> SHIPPED PEELING CHAIN AGAINST REAL BINARIES: {result}")
sys.exit(0 if FAIL == 0 else 1)
