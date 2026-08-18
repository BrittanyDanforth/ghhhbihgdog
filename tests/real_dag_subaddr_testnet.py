#!/usr/bin/env python3
"""Prove the DAG-mixing CORE against real monero binaries: that
subaddr_indices=[i] makes transfer_split spend from EXACTLY subaddress i (real
per-hop mixing) and not pool from the whole account. Funds a full wallet on an
isolated testnet, fans out to 3 subaddresses, confirms/unlocks them, then does
a hop constrained to ONE subaddress and checks only that subaddress's balance
moved. SKIPs (exit 0) if the monero binaries aren't installed."""
import subprocess, time, os, signal, shutil, tempfile, sys
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

BASE = tempfile.mkdtemp(prefix="dag_")
DR = "http://127.0.0.1:28061"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:28063/json_rpc"
def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()
def draw(path, body=None): return requests.post(DR + path, json=body or {}, timeout=40).json()
def wj(m, p=None, t=120):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()
procs = []
def Lp(cmd, log): procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))
def mine(addr, target):
    draw("/start_mining", {"miner_address": addr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < target: time.sleep(2)
    draw("/stop_mining"); wj("refresh")
def sub_bal(idxs):
    r = wj("get_balance", {"account_index": 0, "address_indices": idxs})["result"]
    return {e["address_index"]: e.get("unlocked_balance", 0) for e in r.get("per_subaddress", [])}

PASS = 0; FAIL = 0; FAILS = []
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)

try:
    Lp(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28061", "--p2p-bind-port", "28060",
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28061", "--trusted-daemon",
        "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28063", "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"], os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "w", "password": "", "language": "English"})
    primary = wj("get_address", {"account_index": 0})["result"]["address"]
    mine(primary, 85)

    # 3 fresh subaddresses in account 0
    subs = [wj("create_address", {"account_index": 0})["result"] for _ in range(3)]
    idxs = [s["address_index"] for s in subs]
    print("subaddress indices:", idxs)

    # fan-out from ENTRY (subaddr 0) to the 3 subaddresses, restricted to [0]
    fo = wj("transfer_split", {"destinations": [{"amount": 5000000000000, "address": s["address"]} for s in subs],
                               "account_index": 0, "subaddr_indices": [0], "priority": 1})
    check("fan-out relayed", bool(fo.get("result", {}).get("tx_hash_list")))
    h = dj("get_info")["result"]["height"]
    mine(primary, h + 15)   # confirm + unlock (10-block lock)

    before = sub_bal(idxs)
    print("after fan-out, unlocked per subaddr:", {k: v/1e12 for k, v in before.items()})
    check("all 3 subaddrs funded+unlocked", all(before.get(i, 0) > 0 for i in idxs))

    # THE CORE CHECK: hop constrained to ONE subaddress (idxs[1]) must spend
    # ONLY from that subaddress, leaving the other two untouched.
    src = idxs[1]
    hop = wj("transfer_split", {"destinations": [{"amount": 3000000000000, "address": primary}],
                                "account_index": 0, "subaddr_indices": [src], "priority": 1})
    check("hop relayed", bool(hop.get("result", {}).get("tx_hash_list")))
    h = dj("get_info")["result"]["height"]
    mine(primary, h + 3)
    after = sub_bal(idxs)
    print("after hop, unlocked per subaddr:", {k: v/1e12 for k, v in after.items()})

    moved = [i for i in idxs if after.get(i, 0) != before.get(i, 0)]
    check(f"ONLY subaddr {src} moved (subaddr_indices restricted the spend)", moved == [src])
    check("the two non-source subaddrs are byte-identical before/after",
          after.get(idxs[0]) == before.get(idxs[0]) and after.get(idxs[2]) == before.get(idxs[2]))
    check(f"source subaddr {src} balance decreased", after.get(src, 0) < before.get(src, 0))
    print(f"  -> subaddr {src}: {before.get(src,0)/1e12} -> {after.get(src,0)/1e12} XMR")
finally:
    for pr in procs:
        try: pr.send_signal(signal.SIGTERM); pr.wait(timeout=8)
        except Exception:
            try: pr.kill()
            except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS: print("FAILED:", FAILS); sys.exit(1)
print("ALL GREEN — subaddr_indices makes per-hop mixing REAL")
