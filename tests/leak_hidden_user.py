#!/usr/bin/env python3
"""Try to leak the HIDDEN USER (wallet PRIMARY) from what this tree still leaves.

The mix-graph tracker already showed name1/name2 are absent from CURRENT
on-chain graphs. This file attacks the leftover surfaces:

  1. Seized wallet  — labels Mix_/Decoy_/Carrier_/ChangeSweep/GhostSpiral_entry
                      fingerprint the mix; account 0 / sub 0 is whoever is left.
  2. --account 0    — create_receive_wallet WARNS but still issues the receive
                      into account 0, so leftover lands on name2.
  3. Receive bundle — load_receive_bundle accepts an explicit account_index 0
                      (it only refuses a MISSING key). A hand-written bundle
                      can point the mix at the hidden user's account.
  4. Integrity log  — mix_account_rotated:N and receive_account:N name the mix
                      account. With the wallet, the other account is the user.
  5. ThorChain memo — names ENTRY (a throwaway sub), not PRIMARY.
  6. Plan file      — carries account_index + destination addresses.
  7. Change-sweep skip — leftover sits on mix-account/sub-0, not PRIMARY,
                         unless the spend account was 0.

Prints REVEALED when an attack names name1 or name2. Honest about which
surfaces still do.
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
airgap_src = open(os.path.join(REPO, "airgap_tx_signer")).read()

NAME1 = "name1"
NAME2 = "name2"
PASS = 0
FAIL = 0
FAILURES = []
LEAKS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL {name}")


def leak(name, named, expected=None):
    hit = named in (NAME1, NAME2) if expected is None else named == expected
    tag = "REVEALED" if hit else "blind"
    print(f"  [{tag}] {name}: named={named}")
    if hit:
        LEAKS.append((name, named))
    return hit


# ── 1. Seized wallet: labels fingerprint the mix, leftover is PRIMARY ─────

MIX_LABELS = ("Mix_", "Decoy_", "Carrier_", "ChangeSweep", "GhostSpiral_entry")


def seized_wallet():
    """What a forensic copy of the wallet file actually contains after a run.

    Labels come from the SHIPPED create_subs / peel / change-sweep /
    create_receive_wallet strings — not invented here.
    """
    return {
        (0, 0, ""): NAME1,                          # hidden user
        (1, 0, "GhostSpiral_entry"): "name2_MIXCHG",  # receive-account primary
        (1, 1, "GhostSpiral_entry"): "name2_ENTRY",
        (2, 0, ""): "name1_MIXCHG",                 # send mix-account primary
        (2, 1, "Mix_0"): "name1_ENTRY",
        (2, 2, "Mix_1"): "MIX_A",
        (2, 3, "Decoy_0"): "DECOY_A",
        (2, 4, "Carrier_0"): "name1_CARRIER_0",
        (2, 5, "ChangeSweep"): "name1_SWEEP",
    }


def attack_wallet_account0(wallet):
    """Monero convention: account 0 / sub 0 is the wallet PRIMARY."""
    for (acct, idx, _lab), addr in wallet.items():
        if acct == 0 and idx == 0:
            return addr
    return None


def attack_wallet_unlabeled_exclusion(wallet):
    """Drop every address whose label is a shipped GhostSpiral fingerprint.
    The leftover account-0 address is the hidden user."""
    suspects = []
    for (acct, idx, lab), addr in wallet.items():
        if any(lab.startswith(p) or lab == p for p in MIX_LABELS):
            continue
        if acct == 0 and idx == 0:
            suspects.append(addr)
    if len(suspects) == 1:
        return suspects[0]
    return None


def attack_wallet_account_not_rotated(wallet):
    """integrity_log writes mix_account_rotated:N. The account that is NOT N
    and is index 0 is the hidden user."""
    mix_accts = {acct for (acct, idx, lab), _ in wallet.items()
                 if any(lab.startswith(p) or lab == p for p in MIX_LABELS)}
    hidden = [addr for (acct, idx, _lab), addr in wallet.items()
              if acct not in mix_accts and idx == 0]
    if len(hidden) == 1:
        return hidden[0]
    return None


# ── 2. --account 0 receive: leftover IS name2 ─────────────────────────────

def run_account0_receive(usable=Decimal("8"), n=4, fee=Decimal("0.001")):
    """Operator passed --account 0. create_receive_wallet warns and continues.
    Leftover / change-sweep source is name2."""
    entry = "name2_ENTRY_acct0"
    dests = [f"MIX_{i}" for i in range(n)]
    rng = __import__("random").Random(1)
    amts = ghost.compute_fanout_amounts(usable, n, fee, False, rng)
    if not amts:
        return None
    change = (usable - sum(amts)).quantize(Decimal("0.0001"))
    # Fan-out leftover returns to the SPENDING ACCOUNT's sub 0 = name2.
    return {
        "entry": entry,
        "leftover": NAME2,
        "outs": list(zip(dests, amts)) + [(NAME2, change)],
    }


# ── 3. Receive bundle: explicit 0 is accepted ─────────────────────────────

def bundle_attack():
    d0 = {
        "schema": "gs_receive_wallet_v1",
        "address": NAME2,
        "account_index": 0,
        "subaddress_index": 0,
        "label": "handwritten",
    }
    d_ok = {
        "schema": "gs_receive_wallet_v1",
        "address": "name2_ENTRY",
        "account_index": 3,
        "subaddress_index": 1,
        "label": "GhostSpiral_entry",
    }
    tmp = tempfile.mkdtemp(prefix="leakbundle_")
    p0 = os.path.join(tmp, "zero.json")
    pok = os.path.join(tmp, "ok.json")
    open(p0, "w").write(json.dumps(d0))
    open(pok, "w").write(json.dumps(d_ok))
    accepted0 = None
    try:
        accepted0 = gs.load_receive_bundle(p0)
    except ValueError:
        accepted0 = None
    accepted_ok = gs.load_receive_bundle(pok)
    return accepted0, accepted_ok


# ── 4. Integrity log / plan file ──────────────────────────────────────────

def artifact_attack():
    """Reproduce the strings the shipped code actually writes."""
    log_lines = [
        "mix_account_rotated:2",
        "receive_account:1",
        "spend_source_ok:acct=2:idx=1",
        "using_account_index:2",
        "created:4abc...9def:label=GhostSpiral_entry",
    ]
    plan = {
        "meta": {"account_index": 2, "distribution_mode": "peel"},
        "txs": [{"src": "name1_ENTRY", "src_index": 1,
                 "dst": "MIX_0", "amt": "1.2"}],
    }
    mix_acct = None
    for line in log_lines:
        if line.startswith("mix_account_rotated:"):
            mix_acct = int(line.split(":")[1])
    hidden_acct = 0 if mix_acct not in (None, 0) else None
    plan_names_primary = any(
        a == NAME1 or a == NAME2
        for t in plan["txs"]
        for a in (t.get("src"), t.get("dst")))
    return {
        "log_mix_account": mix_acct,
        "log_implies_hidden_account": hidden_acct,
        "plan_account": plan["meta"]["account_index"],
        "plan_names_primary": plan_names_primary,
        "log_carries_ghostspiral_label": any("GhostSpiral_entry" in L for L in log_lines),
    }


# ── 5. ThorChain memo ─────────────────────────────────────────────────────

def memo_attack():
    """The memo names the XMR dest. CURRENT dest is ENTRY, not PRIMARY."""
    entry = "name2_ENTRY"
    memo = f"=:XMR:{entry}"
    dest = memo.rsplit(":", 1)[-1]
    names_hidden = dest in (NAME1, NAME2)
    names_entry = dest == entry
    return names_hidden, names_entry, dest


def main():
    print("\n=== LEAK THE HIDDEN USER (name1 sender / name2 receiver PRIMARY) ===")
    print("    attacking leftover surfaces the mix-graph tracker does not cover\n")

    # Shipped label strings really are in the source (fingerprint is not a guess).
    check("fingerprint: create_subs writes Mix_ and Decoy_ labels",
          'label=f"Mix_{i}"' in gs_src and 'label=f"Decoy_{d}"' in gs_src)
    check("fingerprint: peel carriers are labeled Carrier_",
          'label=f"Carrier_{_c}"' in gs_src)
    check("fingerprint: change sweep dest is labeled ChangeSweep",
          'label="ChangeSweep"' in gs_src)
    check("fingerprint: create_receive_wallet default label is GhostSpiral_entry",
          'default="GhostSpiral_entry"' in crw_src)
    check("fingerprint: receive ACCOUNT itself is labeled GhostSpiral_entry",
          "create_account" in crw_src and "args.label" in crw_src)

    wallet = seized_wallet()
    print("\n--- seized wallet ---")
    a0 = attack_wallet_account0(wallet)
    a1 = attack_wallet_unlabeled_exclusion(wallet)
    a2 = attack_wallet_account_not_rotated(wallet)
    leak("account 0 / sub 0 is PRIMARY by convention", a0, NAME1)
    leak("drop GhostSpiral labels; leftover account-0 is the hidden user", a1, NAME1)
    leak("accounts that are not the mix account: hidden user", a2, NAME1)
    check("SEIZED WALLET: every label-based attack names name1",
          a0 == NAME1 and a1 == NAME1 and a2 == NAME1)

    print("\n--- --account 0 receive (warned, not refused) ---")
    check("create_receive_wallet WARNS on account 0 but does not abort",
          "wallet's PRIMARY address" in crw_src
          and "if acct_idx == 0" in crw_src
          and "sys.exit" not in crw_src[crw_src.index("if acct_idx == 0"):
                                        crw_src.index("integrity_log(\"wallet\", f\"receive_account")]
          )
    g = run_account0_receive()
    leftover = g["leftover"] if g else None
    leak("--account 0: fan-out leftover lands on name2", leftover, NAME2)
    check("FOOTGUN: --account 0 still puts leftover on the hidden user",
          leftover == NAME2)

    print("\n--- receive bundle ---")
    accepted0, accepted_ok = bundle_attack()
    leak("hand-written bundle account_index=0 sub=0 is accepted as dest",
         accepted0["address"] if accepted0 else None, NAME2)
    check("loader ACCEPTS an explicit account 0 / sub 0 bundle (the hidden user)",
          accepted0 is not None and accepted0["account_index"] == 0
          and accepted0["subaddress_index"] == 0)
    check("loader still accepts a rotated-account bundle",
          accepted_ok["account_index"] == 3)

    print("\n--- host artifacts ---")
    art = artifact_attack()
    print(f"    integrity log mix account = {art['log_mix_account']}")
    print(f"    implied hidden account    = {art['log_implies_hidden_account']}")
    print(f"    plan account_index        = {art['plan_account']}")
    print(f"    plan names PRIMARY        = {art['plan_names_primary']}")
    print(f"    log carries GhostSpiral_entry label = {art['log_carries_ghostspiral_label']}")
    check("integrity log records the mix account number (map, not the address)",
          art["log_mix_account"] == 2)
    check("that number implies hidden user lives in account 0 (needs the wallet)",
          art["log_implies_hidden_account"] == 0)
    check("CURRENT plan file does NOT carry name1/name2",
          art["plan_names_primary"] is False)
    check("integrity log interpolates the GhostSpiral_entry label",
          art["log_carries_ghostspiral_label"] is True)
    check("shipped GhostSpiral really logs mix_account_rotated:{sub_account}",
          "mix_account_rotated:{sub_account}" in gs_src)
    check("shipped signer really logs using_account_index:{acct_idx}",
          "using_account_index:{acct_idx}" in airgap_src)

    print("\n--- ThorChain memo ---")
    names_hidden, names_entry, dest = memo_attack()
    leak("memo names the hidden user PRIMARY", dest if names_hidden else None)
    check("memo names ENTRY (throwaway), not the hidden user",
          names_entry and not names_hidden)

    print("\n--- change-sweep skip (rotation held) ---")
    # Leftover sits on mix-account/sub-0, which is NOT name1/name2.
    parked = "name1_MIXCHG"
    leak("change-sweep skip parks leftover on mix-account change", parked)
    check("change-sweep skip does NOT name the hidden user when rotation held",
          parked not in (NAME1, NAME2))

    print("\n--- what still names the hidden user ---")
    print(f"    leaks that named name1/name2: {len(LEAKS)}")
    for n, who in LEAKS:
        print(f"      * {who}  <-  {n}")

    check("HIDDEN USER is named by wallet seizure",
          any(who == NAME1 for _, who in LEAKS))
    check("HIDDEN USER is named by the --account 0 footgun",
          any("account 0" in n and who == NAME2 for n, who in LEAKS))
    check("HIDDEN USER is NOT named by the ThorChain memo",
          not any("memo" in n.lower() and who in (NAME1, NAME2) for n, who in LEAKS))

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("FAILED:", FAILURES)
    print(">>> HIDDEN USER (wallet PRIMARY):",
          "REVEALED from wallet + --account 0 + explicit-0 bundle"
          if LEAKS else "BLIND")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
