#!/usr/bin/env python3
"""Send REAL dust to a REAL receive subaddress and prove it decides nothing.

The receive address is not a secret. thor_swap_preparer builds the memo
`=:XMR.XMR:<dest>` and both tools instruct the sender to put it in the Bitcoin
transaction's OP_RETURN, so the swap provider — and anyone reading the BTC
chain — knows exactly where to send. Before this fix that was enough to steer
the tool for the price of one transaction fee:

  * one piconero set seen_any, so a balance that never moved again was reported
    as "the swap paid short" when nothing had arrived;
  * one piconero every 25 minutes reset the no-more-is-coming timer, and one
    permanently-locked piconero pinned still_confirming — either of which held
    the shortfall verdict off for the full 24 hours.

A fake RPC can only encode what the test author already believed about how a
wallet reports a 1-piconero output. This sends one, on a real chain, through a
real wallet, and drives the SHIPPED watch() against the result.

Isolated testnet (monerod --offline --fixed-difficulty 1). SKIPs if absent.
"""
import subprocess, time, os, shutil, tempfile, sys
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

BASE = tempfile.mkdtemp(prefix="dust_")
DPORT, WPORT = 30250, 30253
DR = f"http://127.0.0.1:{DPORT}"
WR = f"http://127.0.0.1:{WPORT}/json_rpc"
procs = []
PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(DR + "/json_rpc", json=b, timeout=40).json()


def wj(m, p=None, t=240):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


def mine(addr, n):
    tgt = dj("get_info")["result"]["height"] + n
    requests.post(DR + "/start_mining", json={
        "miner_address": addr, "threads_count": 2,
        "do_background_mining": False, "ignore_battery": True}, timeout=40)
    while dj("get_info")["result"]["height"] < tgt:
        time.sleep(2)
    requests.post(DR + "/stop_mining", json={}, timeout=40)
    wj("refresh")


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


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

    wj("create_wallet", {"filename": "d", "password": "", "language": "English"})
    PRIMARY = wj("get_address", {"account_index": 0})["result"]["address"]
    sub = wj("create_address", {"account_index": 0})["result"]
    RECV, RIDX = sub["address"], sub["address_index"]
    mine(PRIMARY, 80)

    # THE DUST: one piconero, the smallest amount Monero can represent, to the
    # receive subaddress — exactly what anyone who has read the swap memo can do.
    PICO = 1
    tx = wj("transfer", {"destinations": [{"amount": PICO, "address": RECV}],
                         "account_index": 0, "get_tx_key": False})
    check("the chain ACCEPTED a 1-piconero transfer (the attack is real)",
          "result" in tx and tx["result"].get("tx_hash"))
    mine(PRIMARY, 15)

    rpc = gs_common.connect_rpc(f"http://127.0.0.1:{WPORT}")
    tot, unl = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    print(f"  subaddress now holds {tot} piconero ({Decimal(tot) / 10**12} XMR)")
    check("the wallet reports the dust as a real, unlocked balance",
          tot == PICO and unl == PICO)

    TARGET = Decimal("3.0")
    FLOOR = Decimal("2.7")
    MIN_ARR = rw.arrival_floor(TARGET)
    print(f"  target {TARGET} XMR -> arrival floor {MIN_ARR} XMR")

    def drive(min_arrival, stall_s=1800, timeout_s=20000):
        """Drive the SHIPPED watch() while the chain keeps advancing.

        The virtual clock jumps a minute per tick so the stall window is
        reached quickly, but real blocks must still be produced: watch()'s
        liveness check reads the wallet's scan height, and on an --offline
        testnet with mining stopped that height is genuinely frozen, so the
        run correctly returns not_syncing before any balance reasoning
        happens. That is the code behaving properly and the harness lying --
        mine during the sleep so the wallet is actually following a live chain.
        """
        clk = Clock()

        def _sleep(_s):
            clk.t += 60
            requests.post(DR + "/start_mining", json={
                "miner_address": PRIMARY, "threads_count": 1,
                "do_background_mining": False, "ignore_battery": True}, timeout=40)
            time.sleep(1.5)
            requests.post(DR + "/stop_mining", json={}, timeout=40)
            try:
                wj("refresh", t=60)
            except Exception:
                pass

        return rw.watch(rpc, 0, RIDX, FLOOR, timeout_s=timeout_s, stall_s=stall_s,
                        sleep_fn=_sleep, clock=clk, echo=lambda *a, **k: None,
                        min_arrival=min_arrival)

    # WITH the floor: the dust must decide nothing.
    r = drive(MIN_ARR, stall_s=600, timeout_s=1800)
    print(f"  with the arrival floor -> {r['state']}")
    check("REAL dust does NOT produce a 'swap paid short' verdict",
          r["state"] != "stalled")
    check("...the watch keeps waiting instead", r["state"] == "timeout")

    # WITHOUT it (min_arrival=0 restores the old behaviour) the same on-chain
    # dust DOES flip the verdict -- so the check above is not vacuous.
    r0 = drive(Decimal(0), stall_s=600, timeout_s=1800)
    print(f"  with min_arrival=0 (old behaviour) -> {r0['state']}")
    check("control: the SAME on-chain dust flips the verdict when the floor is "
          "removed, so the fix is what is doing the work",
          r0["state"] == "stalled")

    # Now a REAL payment must still work, on the same address.
    wj("transfer", {"destinations": [{"amount": int(Decimal("3.0") * 10**12),
                                      "address": RECV}],
                    "account_index": 0, "get_tx_key": False})
    mine(PRIMARY, 15)
    tot2, unl2 = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    print(f"  after the real payment: {Decimal(unl2) / 10**12} XMR unlocked")
    r2 = drive(MIN_ARR, stall_s=600, timeout_s=1800)
    check("a REAL 3.0 XMR payment to the same address still funds",
          r2["state"] == "funded")
    check("...and the dust is included in the reported total, not discarded",
          r2["unlocked"] > Decimal("3.0"))

    result = "SUCCESS" if FAIL == 0 else "FAILED"
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
print(f">>> DUST CANNOT STEER THE WATCH (REAL BINARIES): {result}")
sys.exit(0 if result == "SUCCESS" else 1)
