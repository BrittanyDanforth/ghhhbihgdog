#!/usr/bin/env python3
"""Prove receive_watch tells "the swap paid short" apart from "my wallet
stopped looking" -- against a REAL wallet whose daemon is actually killed.

WHY THIS CANNOT BE A UNIT TEST: the whole finding is about what real
monero-wallet-rpc does when it loses its daemon. It does NOT start raising --
get_balance keeps answering, successfully, with the last scanned figure, so
watch()'s transient-error path never fires. Only get_height stops advancing.
A fake RPC cannot establish that; it can only encode whatever the test author
already believed. (A stale-cache IndexError in the shipped RPC wrapper
survived this repo's entire offline suite for exactly that reason.)

What the old code did with that state: reported 'stalled' and told the
operator "That usually means the swap under-delivered ... re-run with --any to
accept it" -- a false cause whose recommended remedy is to accept less money
than may already be on-chain.

This test funds a subaddress for real, kills monerod, and asserts the SHIPPED
watch() returns 'not_syncing' rather than 'stalled'.

Isolated testnet (monerod --offline --fixed-difficulty 1). SKIPs (exit 0) if
the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys, signal
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


rw = load("receive_watch")
import gs_common

BASE = tempfile.mkdtemp(prefix="wdesync_")
DPORT, WPORT = 31681, 31683
DR = f"http://127.0.0.1:{DPORT}"
WR = f"http://127.0.0.1:{WPORT}/json_rpc"
procs = {}


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(DR + "/json_rpc", json=b, timeout=40).json()


def wj(m, p=None, t=180):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


result = "INCOMPLETE"
try:
    procs["d"] = subprocess.Popen(
        ["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
         "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(DPORT),
         "--p2p-bind-port", str(DPORT - 1), "--no-igd", "--hide-my-port",
         "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
         "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"],
        stdout=open(os.path.join(BASE, "d.out"), "w"), stderr=subprocess.STDOUT)
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass

    procs["w"] = subprocess.Popen(
        ["monero-wallet-rpc", "--testnet", "--daemon-address", f"127.0.0.1:{DPORT}",
         "--trusted-daemon", "--wallet-dir", os.path.join(BASE, "w"),
         "--rpc-bind-port", str(WPORT), "--rpc-bind-ip", "127.0.0.1",
         "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"),
         "--log-level", "0"],
        stdout=open(os.path.join(BASE, "w.out"), "w"), stderr=subprocess.STDOUT)
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "d", "password": "", "language": "English"})
    PRIMARY = wj("get_address", {"account_index": 0})["result"]["address"]
    sub = wj("create_address", {"account_index": 0})["result"]
    RECV, RIDX = sub["address"], sub["address_index"]

    # Mine so the wallet has a real balance and a real, advancing scan height.
    target = dj("get_info")["result"]["height"] + 80
    requests.post(DR + "/start_mining", json={
        "miner_address": PRIMARY, "threads_count": 2,
        "do_background_mining": False, "ignore_battery": True}, timeout=40)
    while dj("get_info")["result"]["height"] < target:
        time.sleep(2)
    requests.post(DR + "/stop_mining", json={}, timeout=40)
    wj("refresh")

    # Pay the watched subaddress a small, deliberately SHORT amount, so the
    # watch is genuinely below its floor either way and the only thing that can
    # change the verdict is whether the wallet keeps scanning.
    wj("transfer", {"destinations": [{"amount": int(Decimal("0.5") * 10**12),
                                      "address": RECV}],
                    "account_index": 0, "get_tx_key": False}, t=240)
    tgt = dj("get_info")["result"]["height"] + 15
    requests.post(DR + "/start_mining", json={
        "miner_address": PRIMARY, "threads_count": 2,
        "do_background_mining": False, "ignore_battery": True}, timeout=40)
    while dj("get_info")["result"]["height"] < tgt:
        time.sleep(2)
    requests.post(DR + "/stop_mining", json={}, timeout=40)
    wj("refresh")

    rpc = gs_common.connect_rpc(f"http://127.0.0.1:{WPORT}")
    tot, unl = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    print(f"  watched subaddress holds {Decimal(unl) / 10**12} XMR unlocked")
    check("the short payment really landed and unlocked", unl > 0)

    h_live = rw.wallet_height(rpc)
    check("wallet_height reads a real height from wallet-rpc",
          isinstance(h_live, int) and h_live > 0)

    # ---- (A) daemon ALIVE, balance short and static -> a REAL shortfall -----
    # Mine in the background so the wallet's height genuinely advances during
    # the watch, exactly as it would on a live chain.
    requests.post(DR + "/start_mining", json={
        "miner_address": PRIMARY, "threads_count": 1,
        "do_background_mining": False, "ignore_battery": True}, timeout=40)
    clk = Clock()

    def sleep_a(_s):
        clk.t += 600            # jump the virtual clock past the stall window
        time.sleep(2)           # real time, so blocks actually get mined
        try: wj("refresh")
        except Exception: pass

    r_alive = rw.watch(rpc, 0, RIDX, Decimal("5.0"),
                       timeout_s=100_000, stall_s=900,
                       sleep_fn=sleep_a, clock=clk, echo=lambda *a, **k: None)
    requests.post(DR + "/stop_mining", json={}, timeout=40)
    print(f"  daemon ALIVE -> {r_alive['state']} (sync={r_alive.get('sync')})")
    check("A: with the wallet still scanning, a short payment reports 'stalled'",
          r_alive["state"] == "stalled")
    check("A: ...and records that the sync was VERIFIED, not assumed",
          r_alive.get("sync") == "ok")

    # ---- (B) daemon KILLED mid-watch -> NOT a shortfall --------------------
    procs["d"].terminate()
    try: procs["d"].wait(timeout=20)
    except Exception: procs["d"].kill()
    time.sleep(6)

    # The premise of the whole finding, asserted against the real binary.
    ok_bal = True
    try:
        t2, u2 = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    except Exception:
        ok_bal = False
    check("PREMISE: with the daemon dead, get_balance still ANSWERS "
          "(so the transient-error path never fires)", ok_bal)
    h1 = rw.wallet_height(rpc); time.sleep(4)
    try: wj("refresh", t=20)
    except Exception: pass
    h2 = rw.wallet_height(rpc)
    check("PREMISE: ...while the scan height stops advancing",
          h1 is not None and h2 is not None and h2 == h1)

    clk2 = Clock()

    def sleep_b(_s):
        clk2.t += 600
        time.sleep(1)

    r_dead = rw.watch(rpc, 0, RIDX, Decimal("5.0"),
                      timeout_s=100_000, stall_s=900,
                      sleep_fn=sleep_b, clock=clk2, echo=lambda *a, **k: None)
    print(f"  daemon DEAD  -> {r_dead['state']} (sync={r_dead.get('sync')})")
    check("B: with the wallet frozen, the SHIPPED watch reports 'not_syncing'",
          r_dead["state"] == "not_syncing")
    check("B: ...and NEVER calls it a shortfall", r_dead["state"] != "stalled")
    check("B: ...flagging the sync as stuck", r_dead.get("sync") == "stuck")

    # The point: identical balances, opposite verdicts, decided only by whether
    # the wallet kept scanning.
    check("the two runs saw the SAME balance and returned DIFFERENT verdicts",
          r_alive["unlocked"] == r_dead["unlocked"]
          and r_alive["state"] != r_dead["state"])

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs.values():
        try: p.terminate()
        except Exception: pass
    time.sleep(1)
    for p in procs.values():
        try: p.kill()
        except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS: print("FAILED:", FAILS)
print(f">>> WATCH DESYNC AGAINST REAL BINARIES: {result}")
sys.exit(0 if result == "SUCCESS" else 1)
