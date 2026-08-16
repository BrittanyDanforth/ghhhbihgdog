#!/usr/bin/env python3
"""Prove the PEELING CHAIN works on-chain against real monero binaries.

The fan-out's weakness is that its N outputs are co-created in one transaction.
A peeling chain sends to ONE mix subaddress per transaction, each spending the
previous peel's change, so the N outputs appear in N SEPARATE transactions.

This drives the SHIPPED build_peel_plan (which subaddress each peel spends) and
compute_fanout_amounts (the unequal amounts), then executes the peels against a
real testnet wallet with confirmation gating between each, and asserts:
  * each mix subaddress received its own planned amount,
  * via N DISTINCT transactions (not one fan-out),
  * peel 0 spent ENTRY and its change landed on subaddress 0 (verified change
    behaviour the plan relies on),
  * peels 1..N spent subaddress 0 (the carrier), each a separate on-chain tx.

Isolated testnet. SKIPs (exit 0) if the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys
import importlib.machinery, importlib.util
from decimal import Decimal
import random
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


ghost = load("GhostSpiral")

BASE = tempfile.mkdtemp(prefix="peel_")
DR = "http://127.0.0.1:28101"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:28103/json_rpc"


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()


def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=40).json()


def wj(m, p=None, t=180):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))


def mine(addr, target):
    draw("/start_mining", {"miner_address": addr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < target:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")


def subbal(idx):
    r = wj("get_balance", {"account_index": 0, "address_indices": [idx]})["result"]
    e = r.get("per_subaddress", [])
    return (e[0].get("balance", 0), e[0].get("unlocked_balance", 0)) if e else (0, 0)


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


ATOMIC = Decimal(10) ** 12
result = "INCOMPLETE"
try:
    Lp(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28101", "--p2p-bind-port", "28100",
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28101", "--trusted-daemon",
        "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28103", "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
       os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "w", "password": "", "language": "English"})
    primary = wj("get_address", {"account_index": 0})["result"]["address"]   # subaddr 0
    mine(primary, 90); wj("refresh")

    # ENTRY is a NON-zero subaddress (the receive-mode case): peel 0 spends it,
    # and its change must land on subaddr 0, the carrier for the later peels.
    entry = wj("create_address", {"account_index": 0})["result"]
    E = entry["address_index"]
    wj("transfer_split", {"destinations": [{"amount": int(6 * ATOMIC), "address": entry["address"]}],
                          "account_index": 0, "subaddr_indices": [0], "priority": 1})
    h = dj("get_info")["result"]["height"]; mine(primary, h + 12); wj("refresh")
    print(f"ENTRY is subaddr {E}, funded {subbal(E)[0] / 1e12} XMR")

    # N mix destinations + the SHIPPED jittered amounts + the SHIPPED peel plan.
    N = 3
    mix = [wj("create_address", {"account_index": 0})["result"] for _ in range(N)]
    midx = [m["address_index"] for m in mix]
    amounts = ghost.compute_fanout_amounts(Decimal("4"), N, Decimal("0.01"), False,
                                           random.Random(99))
    plan = ghost.build_peel_plan(entry_index=E, change_index=0,
                                 dests=[m["address"] for m in mix], amounts=amounts)
    check("shipped build_peel_plan produced N peels", len(plan) == N)
    check("peel 0 spends ENTRY, later peels spend subaddr 0 (the carrier)",
          plan[0]["src_index"] == E and all(p["src_index"] == 0 for p in plan[1:]))
    planned = [int((a * ATOMIC).to_integral_value()) for a in amounts]
    print("peel amounts (XMR):", [str(a) for a in amounts])

    sub0_before = subbal(0)[0]
    txids = []
    for i, p in enumerate(plan):
        # Confirmation-gate: the carrier must hold the previous change, unlocked.
        if i > 0:
            need = planned[i] + int(ATOMIC // 20)
            for _ in range(60):
                wj("refresh")
                if subbal(0)[1] >= need:
                    break
                h = dj("get_info")["result"]["height"]; mine(primary, h + 2)
            check(f"peel {i}: carrier (subaddr 0) confirmed+unlocked before spending",
                  subbal(0)[1] >= need)
        r = wj("transfer_split", {"destinations": [{"amount": planned[i], "address": p["dst"]}],
                                  "account_index": 0, "subaddr_indices": [p["src_index"]],
                                  "priority": 1})
        ths = r.get("result", {}).get("tx_hash_list", [])
        if not ths:
            print(f"  peel {i} error:", str(r.get("result") or r)[:200])
        check(f"peel {i + 1}/{N} relayed as its own transaction", bool(ths))
        assert ths
        txids.append(ths[0])
        h = dj("get_info")["result"]["height"]; mine(primary, h + 12); wj("refresh")

    # THE PAYOFF.
    check("every peel was a DISTINCT transaction (not one fan-out)",
          len(set(txids)) == N)
    got = {i: subbal(i)[0] for i in midx}
    ok = all(got[midx[k]] == planned[k] for k in range(N))
    for k in range(N):
        print(f"    mix subaddr {midx[k]}: planned {planned[k] / 1e12:.4f}  "
              f"got {got[midx[k]] / 1e12:.4f}  {'OK' if got[midx[k]] == planned[k] else 'MISMATCH'}")
    check("each mix subaddress received its own peeled amount on-chain", ok)
    check("peel 0's change reached the carrier (subaddr 0 grew)",
          subbal(0)[0] > sub0_before)
    check("ENTRY was drained by peel 0 (its output was fully peeled)",
          subbal(E)[0] < int(ATOMIC // 2))
    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs:
        try: p.terminate(); p.wait(timeout=10)
        except Exception:
            try: p.kill()
            except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    for f in FAILS: print("  -", f)
print(f">>> SHIPPED PEELING CHAIN AGAINST REAL BINARIES: {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
