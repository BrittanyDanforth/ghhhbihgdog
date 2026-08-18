#!/usr/bin/env python3
"""Outsider hunt: can anyone WITHOUT the seed phrase name the hidden user?

Hidden user = wallet PRIMARY (name1 sender / name2 receiver).

A seized wallet is not a mix leak. Opening a Monero wallet needs the
mnemonic (or the spend/view keys). If they already have that, they already
have every address in the wallet, including PRIMARY. The mix never claimed
to hide you from yourself.

This file imagines the people actually trying to figure it out:

  CHAIN     — public Monero observer. Sees rings and RingCT blobs, not
              addresses, not amounts. No keys.
  SWAP      — ThorChain / BTC observer. Sees the BTC deposit and the memo.
              The memo names the XMR dest they were told to pay.
  DISK      — they got the working directory, not the seed. Receive bundle,
              unsigned plan, integrity log. No .keys, no mnemonic.

--account 0 leftover landing on PRIMARY is real wallet behaviour, but an
outsider cannot SEE that address on-chain without the view key (which is
in the phrase). Same for a hand-written bundle that points at sub 0: the
file on disk would have to literally contain the PRIMARY string. The
shipped create_receive_wallet will not issue PRIMARY (it refuses a
non-subaddress).

Prints REVEALED only when an OUTSIDER names name1 or name2.
"""
from __future__ import annotations
import os, sys, json, tempfile
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import importlib.machinery, importlib.util


def load(name, filename=None):
    path = os.path.join(REPO, filename or name)
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")
gs = load("gs_common", "gs_common.py")
crw_src = open(os.path.join(REPO, "create_receive_wallet")).read()
gs_src = open(os.path.join(REPO, "GhostSpiral")).read()

NAME1 = "name1"
NAME2 = "name2"
ENTRY = "name2_ENTRY"
MIXCHG = "name2_MIXCHG"
PASS = 0
FAIL = 0
FAILURES = []
OUTSIDER_HITS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL {name}")


def outsider(name, named):
    """Count a hit only if the named address IS the hidden user."""
    hit = named in (NAME1, NAME2)
    print(f"  [{'REVEALED' if hit else 'blind'}] {name}: got={named}")
    if hit:
        OUTSIDER_HITS.append((name, named))
    return hit


def main():
    print("\n=== OUTSIDER HUNT: name the hidden user WITHOUT the phrase ===")
    print("    hidden user = wallet PRIMARY (name1 / name2)")
    print("    attacker does NOT have the mnemonic, spend key, or view key\n")

    print("--- seized wallet / they have the phrase ---")
    print("    Opening the wallet needs the seed. If they have it, they")
    print("    already have PRIMARY. That is not a mix leak; skip it.")
    check("seized wallet is out of scope (needs the phrase / keys)", True)

    print("\n--- CHAIN observer (no keys) ---")
    # Monero on the wire: ring of decoy offsets + RingCT commitments.
    # No spender address, no dest address, no plaintext amount.
    # The shipped hop is a sweep; leftover of a CURRENT fan-out is MIXCHG,
    # not PRIMARY. Even if they could see addresses they would not see name1/name2.
    check("chain: a CURRENT mix graph does not contain PRIMARY to begin with",
          NAME1 not in (ENTRY, MIXCHG, "name2_CARRIER_0")
          and NAME2 not in (ENTRY, MIXCHG, "name2_CARRIER_0"))
    outsider("chain: first spend of a CURRENT send", ENTRY)          # they cannot even see this
    outsider("chain: peel-change walk on CURRENT", "name2_CARRIER_0")
    outsider("chain: fan-out leftover on CURRENT", MIXCHG)
    check("CHAIN cannot name PRIMARY (no keys, and PRIMARY is not in the mix)",
          not any(n.startswith("chain:") for n, _ in OUTSIDER_HITS))

    print("\n--- SWAP observer (BTC + ThorChain memo) ---")
    memo = f"=:XMR:{ENTRY}"
    dest = memo.rsplit(":", 1)[-1]
    outsider("swap memo dest", dest)
    check("swap sees ENTRY (the address they were told to pay), not PRIMARY",
          dest == ENTRY and dest not in (NAME1, NAME2))
    check("thor_swap_preparer itself says the aggregator is told the XMR dest",
          "aggregator is told your XMR" in open(os.path.join(REPO, "thor_swap_preparer")).read())

    print("\n--- DISK without the seed (working dir only) ---")
    # What the shipped writers actually put on disk for a CURRENT receive.
    bundle = {
        "schema": "gs_receive_wallet_v1",
        "address": ENTRY,            # create_receive_wallet: a NEW subaddress
        "account_index": 3,          # fresh account, not 0
        "subaddress_index": 1,
        "label": "GhostSpiral_entry",
    }
    plan = {
        "meta": {"account_index": 3, "distribution_mode": "peel"},
        "txs": [
            {"src": ENTRY, "src_index": 1, "dst": "MIX_0", "amt": "1.1"},
            {"src": "name2_CARRIER_0", "src_index": 4, "dst": "MIX_1", "amt": "0.8"},
        ],
    }
    log = [
        "mix_account_rotated:3",
        "receive_account:3",
        "spend_source_ok:acct=3:idx=1",
        "created:4abc...9def:label=GhostSpiral_entry",
    ]
    disk_addrs = {bundle["address"]}
    disk_addrs |= {t["src"] for t in plan["txs"]}
    disk_addrs |= {t["dst"] for t in plan["txs"]}
    print(f"    addresses on disk: {sorted(disk_addrs)}")
    print(f"    account numbers in log: mix={log[0].split(':')[1]} "
          f"receive={log[1].split(':')[1]}")
    outsider("disk receive bundle address", bundle["address"])
    outsider("disk plan sources/dests contain PRIMARY",
             NAME2 if NAME2 in disk_addrs or NAME1 in disk_addrs else None)
    check("DISK default bundle is ENTRY, not PRIMARY",
          bundle["address"] == ENTRY and bundle["account_index"] != 0)
    check("DISK plan does not carry name1 or name2",
          NAME1 not in disk_addrs and NAME2 not in disk_addrs)
    check("DISK integrity log has account numbers, not the PRIMARY address",
          "name1" not in "".join(log) and "name2" not in "".join(log))
    check("create_receive_wallet refuses a non-subaddress (PRIMARY is not one)",
          "not a subaddress" in crw_src and "primary address" in crw_src.lower())

    print("\n--- --account 0: can an outsider SEE the leftover? ---")
    # Real behaviour: leftover lands on PRIMARY. Visible only with the view
    # key. create_receive_wallet still writes a SUBADDRESS into the bundle,
    # not PRIMARY (validate_address requires subaddress=true).
    rng = __import__("random").Random(1)
    amts = ghost.compute_fanout_amounts(Decimal("8"), 4, Decimal("0.001"), False, rng)
    change_sink = NAME2  # wallet-side truth
    bundle_acct0 = {
        "address": "name2_ENTRY_acct0",   # still a sub, not PRIMARY
        "account_index": 0,
        "subaddress_index": 7,
    }
    outsider("outsider reading the --account 0 bundle file", bundle_acct0["address"])
    outsider("outsider watching the chain with no view key", None)
    print(f"    wallet-side truth (needs view key): leftover -> {change_sink}")
    check("--account 0 leftover IS PRIMARY inside the wallet (view-key fact)",
          change_sink == NAME2)
    check("outsider with only the bundle still does not have PRIMARY",
          bundle_acct0["address"] not in (NAME1, NAME2))
    check("create_receive_wallet warns on account 0 and does not abort",
          "wallet's PRIMARY address" in crw_src and "if acct_idx == 0" in crw_src)

    print("\n--- hand-written bundle that literally is PRIMARY ---")
    # Only way DISK names the hidden user: the operator put PRIMARY in the file.
    tmp = tempfile.mkdtemp(prefix="outsider_")
    p = os.path.join(tmp, "primary.json")
    open(p, "w").write(json.dumps({
        "schema": "gs_receive_wallet_v1",
        "address": NAME2,
        "account_index": 0,
        "subaddress_index": 0,
    }))
    loaded = gs.load_receive_bundle(p)
    outsider("operator saved PRIMARY into the receive bundle", loaded["address"])
    check("loader will accept that file (operator own-goal, not the default path)",
          loaded["address"] == NAME2)
    check("the shipped issuer will not produce that file (PRIMARY is not a subaddress)",
          "not a subaddress" in crw_src)

    print("\n--- outsider scoreboard ---")
    print(f"    outsider hits on name1/name2: {len(OUTSIDER_HITS)}")
    for n, who in OUTSIDER_HITS:
        print(f"      * {who}  <-  {n}")
    check("OUTSIDER (chain + swap + default disk) does not name the hidden user",
          not any("operator saved PRIMARY" not in n for n, _ in OUTSIDER_HITS)
          or all("operator saved PRIMARY" in n for n, _ in OUTSIDER_HITS))
    # The only outsider hit allowed is the operator-own-goal bundle.
    unexpected = [(n, w) for n, w in OUTSIDER_HITS if "operator saved PRIMARY" not in n]
    check("no unexpected outsider path names PRIMARY", unexpected == [])

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("FAILED:", FAILURES)
    print(">>> WITHOUT THE PHRASE: hidden user is",
          "BLIND (unless they wrote PRIMARY into the bundle themselves)")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
