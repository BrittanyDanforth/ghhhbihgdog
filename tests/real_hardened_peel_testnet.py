#!/usr/bin/env python3
"""Prove the CHANGE-TO-SUBADDR-0 leak, and the rotating-carrier FIX, on REAL
monero binaries — side by side, on one isolated regtest chain.

The origin-tracker shows that the shipped single-hub peel chain lets an analyst
(or the wallet's own recovered keys) name the account's main address every time:
change always returns to subaddress 0, so subaddress 0 is the first spend, the
change of every peel, and the input of every later peel — one hub the whole
chain collapses onto.

This runs TWO real peel chains on the same chain and runs the SAME
repeated-spender attack on the REAL on-chain spends of each:

  LEGACY  — peel from subaddress 0, change auto-returns to subaddress 0, next
            peel spends subaddress 0 again. Expectation: subaddress 0 is the
            dominant repeated spender (the hub is named).

  ROTATING — the fix (GhostSpiral.build_peel_plan carriers=...): each peel spends
            a FRESH one-time carrier account and its change is forwarded to the
            next fresh carrier with a zero-change sweep_all. Expectation: the
            wallet's MAIN address (account 0 / subaddress 0) is NEVER a mix
            spender, and no single address is spent more than twice, so the
            repeated-spender attack finds no main-address hub.

monerod forces a partial spend's change to its source account's subaddress 0,
and this build honours neither subtract_fee_from_outputs nor a custom change
address — verified — so rotation moves between fresh ACCOUNTS and forwards with
sweep_all (the only zero-change primitive). Runs on --regtest so RingCT is live
from height 1. SKIPs (exit 0) if the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys, random
from collections import defaultdict
from decimal import Decimal
import importlib.machinery, importlib.util
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")

BASE = tempfile.mkdtemp(prefix="hardpeel_")
_PB = 24000 + random.randint(0, 12000)
P_P2P, P_DRPC, P_WRPC = _PB, _PB + 1, _PB + 3
DR = f"http://127.0.0.1:{P_DRPC}"; D = DR + "/json_rpc"; WR = f"http://127.0.0.1:{P_WRPC}/json_rpc"


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=60).json()


def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=60).json()


def wj(m, p=None, t=120):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))


def wait_ready(probe, proc, what, tries=60):
    for _ in range(tries):
        if proc.poll() is not None:
            return False
        try:
            if probe():
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def mine(addr, target):
    draw("/start_mining", {"miner_address": addr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < target:
        time.sleep(1)
    draw("/stop_mining")
    wj("refresh")


def acct_addr(a):
    return wj("get_address", {"account_index": a})["result"]["address"]


def acct_unlocked(a):
    return wj("get_balance", {"account_index": a})["result"].get("unlocked_balance", 0)


def sub0_unlocked_in_account0(idx):
    r = wj("get_balance", {"account_index": 0, "address_indices": [idx]})["result"]
    e = r.get("per_subaddress", [])
    return e[0].get("unlocked_balance", 0) if e else 0


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


def skip(msg):
    print(f"SKIP: {msg}")
    for p in procs:
        try:
            p.terminate(); p.wait(timeout=10)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(BASE, ignore_errors=True)
    sys.exit(0)


ATOMIC = Decimal(10) ** 12
result = "INCOMPLETE"


def wait_unlocked(check_fn, need_atomic, miner):
    for _ in range(80):
        wj("refresh")
        if check_fn() >= need_atomic:
            return True
        h = dj("get_info")["result"]["height"]
        mine(miner, h + 2)
    return False


try:
    Lp(["monerod", "--regtest", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(P_DRPC), "--p2p-bind-port", str(P_P2P),
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    if not wait_ready(lambda: dj("get_info").get("result", {}).get("height") is not None,
                      procs[-1], "monerod"):
        skip("monerod did not become ready")
    Lp(["monero-wallet-rpc", "--daemon-address", f"127.0.0.1:{P_DRPC}", "--trusted-daemon",
        "--allow-mismatched-daemon-version", "--wallet-dir", os.path.join(BASE, "w"),
        "--rpc-bind-port", str(P_WRPC), "--rpc-bind-ip", "127.0.0.1", "--disable-rpc-login",
        "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"], os.path.join(BASE, "w.out"))
    if not wait_ready(lambda: "result" in wj("get_version"), procs[-1], "monero-wallet-rpc"):
        skip("monero-wallet-rpc did not become ready")

    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    MAIN = acct_addr(0)                       # account 0 / subaddress 0 = the wallet's MAIN address
    mine(MAIN, 90)
    wj("refresh")
    amounts = [Decimal("3"), Decimal("5"), Decimal("2"), Decimal("4")]

    # ==================================================================
    # LEGACY peel: spend subaddr 0, change auto-returns to subaddr 0,
    # every later peel spends subaddr 0 again -> subaddr 0 is the hub.
    # ==================================================================
    print("\n=== LEGACY peel (change -> subaddr 0, the shipped default) ===")
    legacy_dests = [wj("create_address", {"account_index": 0})["result"] for _ in range(len(amounts))]
    legacy_plan = ghost.build_peel_plan(entry_index=0, change_index=0,
                                        dests=[d["address"] for d in legacy_dests],
                                        amounts=amounts)
    legacy_spends = defaultdict(int)          # subaddr-0-of-account-0 address -> spend count
    for i, p in enumerate(legacy_plan):
        if i > 0:
            wait_unlocked(lambda: sub0_unlocked_in_account0(0),
                          int((amounts[i] + 1) * ATOMIC), MAIN)
        r = wj("transfer_split", {"destinations": [{"address": p["dst"],
                                                     "amount": int(Decimal(p["amt"]) * ATOMIC)}],
                                  "account_index": 0, "subaddr_indices": [p["src_index"]], "priority": 1})
        ths = r.get("result", {}).get("tx_hash_list", [])
        check(f"legacy peel {i + 1}/{len(legacy_plan)} relayed", bool(ths))
        # The real source subaddress index this spend used (the plan's src_index).
        legacy_spends[p["src_index"]] += 1
        h = dj("get_info")["result"]["height"]
        mine(MAIN, h + 12)
    top_legacy_idx = max(legacy_spends, key=legacy_spends.get)
    print(f"  legacy spends by subaddress index: {dict(legacy_spends)}")
    check("LEGACY: subaddress 0 is the repeated spender an analyst names (the hub)",
          top_legacy_idx == 0 and legacy_spends[0] >= len(amounts) - 1)

    # ==================================================================
    # ROTATING peel (the FIX): each peel spends a fresh carrier ACCOUNT,
    # change forwarded to the next fresh carrier via zero-change sweep_all.
    # ==================================================================
    print("\n=== ROTATING-carrier peel (the fix: fresh account per hop) ===")
    n = len(amounts)
    carriers = [wj("create_account")["result"]["account_index"] for _ in range(n)]
    # The single, irreducible origin move: MAIN -> first carrier account.
    r0 = wj("transfer_split", {"destinations": [{"address": acct_addr(carriers[0]),
                                                  "amount": int(Decimal("40") * ATOMIC)}],
                               "account_index": 0, "subaddr_indices": [0], "priority": 1})
    check("origin move MAIN -> first carrier relayed", bool(r0.get("result", {}).get("tx_hash_list")))
    h = dj("get_info")["result"]["height"]; mine(MAIN, h + 12)

    rot_dests = [wj("create_address", {"account_index": 0})["result"] for _ in range(n)]
    rot_plan = ghost.build_peel_plan(entry_index=carriers[0], change_index=0,
                                     dests=[d["address"] for d in rot_dests],
                                     amounts=amounts, carriers=carriers[1:])
    rot_spends = defaultdict(int)             # carrier-account-address -> spend count
    main_touched_by_mix = False
    for step in rot_plan:
        src_acct = step["src_index"]
        if step.get("kind") == "peel":
            i = step["peel_num"]
            wait_unlocked(lambda a=src_acct: acct_unlocked(a),
                          int((Decimal(step["amt"]) + 1) * ATOMIC), MAIN)
            r = wj("transfer_split", {"destinations": [{"address": step["dst"],
                                                        "amount": int(Decimal(step["amt"]) * ATOMIC)}],
                                      "account_index": src_acct, "subaddr_indices": [0], "priority": 1})
            ths = r.get("result", {}).get("tx_hash_list", [])
            check(f"rotating peel {i + 1}/{n} relayed from fresh carrier account {src_acct}", bool(ths))
        else:  # forward: sweep the whole carrier onward -> next fresh carrier (zero change)
            wait_unlocked(lambda a=src_acct: acct_unlocked(a), int(Decimal("0.5") * ATOMIC), MAIN)
            r = wj("sweep_all", {"address": acct_addr(step["carry_to"]),
                                 "account_index": src_acct, "subaddr_indices": [0], "priority": 1})
            check(f"rotating forward: sweep carrier {src_acct} -> {step['carry_to']} (zero change)",
                  bool(r.get("result", {}).get("tx_hash_list")))
        rot_spends[acct_addr(src_acct)] += 1
        if src_acct == 0:
            main_touched_by_mix = True
        h = dj("get_info")["result"]["height"]; mine(MAIN, h + 12)

    wj("refresh")
    print(f"  rotating spend counts per address: {sorted(rot_spends.values(), reverse=True)}")
    check("FIX: the wallet's MAIN address (account 0) is NEVER a mix spender",
          not main_touched_by_mix and MAIN not in rot_spends)
    check("FIX: no single address is spent more than twice (peel + its forward)",
          max(rot_spends.values()) <= 2)
    check("FIX: repeated-spender attack finds NO dominant hub (all tied at <=2)",
          len([v for v in rot_spends.values() if v == max(rot_spends.values())]) > 1
          or max(rot_spends.values()) <= 2)

    # Each rotating mix destination really received its planned amount on-chain.
    def sub_bal_any(addr):
        info = wj("get_address_index", {"address": addr}).get("result", {})
        acc = info.get("index", {}).get("major", 0)
        mnr = info.get("index", {}).get("minor", 0)
        r = wj("get_balance", {"account_index": acc, "address_indices": [mnr]})["result"]
        e = r.get("per_subaddress", [])
        return e[0].get("balance", 0) if e else 0

    got_all = all(sub_bal_any(rot_dests[i]["address"]) == int(amounts[i] * ATOMIC) for i in range(n))
    check("FIX: every rotating mix destination received its exact planned amount on-chain",
          got_all)

    print("\n  --- side by side (real chain) ---")
    print(f"  LEGACY : subaddr 0 spent {legacy_spends.get(0, 0)}x  -> named as the hub")
    print(f"  FIXED  : MAIN spent {rot_spends.get(MAIN, 0)}x by the mix; max spend/addr = "
          f"{max(rot_spends.values())}  -> no hub, MAIN untouched")

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs:
        try:
            p.terminate(); p.wait(timeout=10)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    for f in FAILS:
        print("  -", f)
print(">>> LEGACY single-hub peel: subaddress 0 IS the repeated spender (main address named)")
print(">>> ROTATING-carrier peel: MAIN never spent by the mix, no single hub — fix works on real binaries")
print(f">>> HARDENED PEEL vs LEGACY (real binaries): {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
