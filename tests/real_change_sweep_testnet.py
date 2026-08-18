#!/usr/bin/env python3
"""sweep_all cannot spend LOCKED outputs — and the change sweep depends on it.

This is the fact _run_change_sweep rests on, so it is asserted against the real
binary rather than assumed.

WHY IT MATTERS. A fan-out is one transaction, so it leaves exactly one change
output and "wait for some unlocked change" and "wait for all the change" mean
the same thing. A PEELING CHAIN leaves one change output PER PEEL, all on the
same subaddress. The old wait asked only for DUST_XMR to be unlocked there,
which peel 0's change satisfies long before the last peel's change has
confirmed — so the sweep ran early, swept what happened to be unlocked,
silently abandoned the rest, and the pipeline printed "nothing is parked on the
change address".

Two things are proven here:
  1. the primitive: sweep_all moves only the unlocked balance and leaves a
     still-locked output sitting exactly where it was;
  2. the guard: _wait_for_change_settled does not return while any balance on
     that subaddress is still confirming.

Isolated testnet (monerod --offline --fixed-difficulty 1). SKIPs if absent.
"""
import subprocess, time, os, shutil, tempfile, sys, types
import importlib.machinery, importlib.util
from decimal import Decimal
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


import gs_common
DPORT, WPORT = 30260, 30263
DR = f"http://127.0.0.1:{DPORT}"
WR = f"http://127.0.0.1:{WPORT}/json_rpc"
BASE = tempfile.mkdtemp(prefix="chsweep_")
procs = []
PASS = 0; FAIL = 0; FAILS = []
A = 10 ** 12


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


def wj(m, p=None, t=240):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    if p is not None: b["params"] = p
    return requests.post(WR, json=b, timeout=t).json()


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    if p is not None: b["params"] = p
    return requests.post(DR + "/json_rpc", json=b, timeout=60).json()


def height():
    return dj("get_info")["result"]["height"]


def mine_to(target, addr):
    """Tight poll: fixed-difficulty blocks arrive faster than a 2s sleep, and
    overshooting by dozens of blocks silently unlocks the output this test
    needs to keep LOCKED (which is how the first attempt at this came out
    inconclusive)."""
    requests.post(DR + "/start_mining", json={
        "miner_address": addr, "threads_count": 1,
        "do_background_mining": False, "ignore_battery": True}, timeout=40)
    while height() < target:
        time.sleep(0.02)
    requests.post(DR + "/stop_mining", json={}, timeout=40)
    wj("refresh")


result = "INCOMPLETE"
try:
    procs.append(subprocess.Popen(
        ["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
         "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(DPORT),
         "--p2p-bind-port", str(DPORT - 1), "--no-igd", "--hide-my-port",
         "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
         "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"],
        stdout=open(os.path.join(BASE, "d.out"), "w"), stderr=subprocess.STDOUT))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    procs.append(subprocess.Popen(
        ["monero-wallet-rpc", "--testnet", "--daemon-address", f"127.0.0.1:{DPORT}",
         "--trusted-daemon", "--wallet-dir", os.path.join(BASE, "w"),
         "--rpc-bind-port", str(WPORT), "--rpc-bind-ip", "127.0.0.1",
         "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"),
         "--log-level", "0"],
        stdout=open(os.path.join(BASE, "w.out"), "w"), stderr=subprocess.STDOUT))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "c", "password": "", "language": "English"})
    P = wj("get_address", {"account_index": 0})["result"]["address"]
    sub = wj("create_address", {"account_index": 0})["result"]
    S, SI = sub["address"], sub["address_index"]
    DST = wj("create_address", {"account_index": 0})["result"]["address"]
    mine_to(height() + 60, P)

    # Two payments to ONE subaddress, at different depths -- the exact shape a
    # peel chain leaves on the change address.
    wj("transfer", {"destinations": [{"amount": 2 * A, "address": S}],
                    "account_index": 0, "get_tx_key": False})
    mine_to(height() + 14, P)          # this one is well past the 10-block unlock
    wj("transfer", {"destinations": [{"amount": 3 * A, "address": S}],
                    "account_index": 0, "get_tx_key": False})
    mine_to(height() + 2, P)           # this one is only ~2 blocks deep

    b = wj("get_balance", {"account_index": 0,
                           "address_indices": [SI]})["result"]["per_subaddress"][0]
    tot, unl = int(b["balance"]), int(b["unlocked_balance"])
    print(f"  change subaddress: total={Decimal(tot)/A} unlocked={Decimal(unl)/A} "
          f"blocks_to_unlock={b.get('blocks_to_unlock')}")
    if tot == unl:
        print("  SKIP: could not create the locked condition (mining overshot)")
        result = "SKIPPED"
        raise SystemExit
    check("precondition: the subaddress holds both an unlocked and a LOCKED output",
          tot > unl > 0)

    # ---- the GUARD: it must refuse to sweep while anything is confirming ----
    args = types.SimpleNamespace(rpc_primary=f"http://127.0.0.1:{WPORT}",
                                 tor_proxy=None)
    ghost = load("GhostSpiral")
    ghost.FANOUT_CONFIRM_TIMEOUT = 6      # fail fast instead of waiting 30 min
    ghost.FANOUT_CONFIRM_POLL = 2
    ok, _seen = ghost._wait_for_change_settled(args, 0, SI, None, "guard")
    check("the settle guard REFUSES while change is still confirming", not ok)

    # ---- the PRIMITIVE: sweep_all leaves the locked output behind ----------
    r = wj("sweep_all", {"address": DST, "account_index": 0,
                         "subaddr_indices": [SI], "get_tx_hex": False})
    check("sweep_all was accepted", bool(r.get("result")))
    mine_to(height() + 14, P)
    b2 = wj("get_balance", {"account_index": 0,
                            "address_indices": [SI]})["result"]["per_subaddress"][0]
    left = int(b2["balance"])
    print(f"  after sweep_all: {Decimal(left)/A} XMR still on the change subaddress")
    check("sweep_all moved only the UNLOCKED balance", left > 0)
    check("...and what it left behind is exactly the output that was locked",
          left == tot - unl)

    # ---- and once everything has settled, the guard lets it through --------
    ok2, seen2 = ghost._wait_for_change_settled(args, 0, SI, None, "guard")
    check("the settle guard passes once nothing is confirming", ok2)
    check("...reporting the full settled balance", seen2 == left)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
except SystemExit:
    pass
finally:
    for p in procs:
        try: p.terminate()
        except Exception: pass
    time.sleep(1)
    for p in procs:
        try: p.kill()
        except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS: print("FAILED:", FAILS)
print(f">>> CHANGE SWEEP vs LOCKED OUTPUTS (REAL BINARIES): {result}")
sys.exit(0 if result in ("SUCCESS", "SKIPPED") else 1)
