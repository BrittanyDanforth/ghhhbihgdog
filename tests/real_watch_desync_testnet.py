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

import os as _os, sys as _sys                              # noqa: E402
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
from monerolab import MoneroLab                              # noqa: E402

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
lab = MoneroLab(BASE, DPORT, WPORT)
DR = lab.DR
WR = lab.WR
procs = {}


# The suite's helpers, pointed at the lab. Assertions unchanged.
dj = lab.dj
wj = lab.wj



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
    lab.start()
    procs["d"] = lab.daemon_proc

    wj("create_wallet", {"filename": "d", "password": "", "language": "English"})
    PRIMARY = wj("get_address", {"account_index": 0})["result"]["address"]
    sub = wj("create_address", {"account_index": 0})["result"]
    RECV, RIDX = sub["address"], sub["address_index"]

    # Mine so the wallet has a real balance and a real, advancing scan height.
    # generateblocks, not start_mining: /stop_mining is asynchronous, so blocks
    # keep landing after it returns -- and this suite's whole subject is a scan
    # height that STOPS. A chain still producing blocks in the background is
    # the one thing that would make it prove nothing.
    lab.gen(PRIMARY, 100)

    # Pay the watched subaddress a small, deliberately SHORT amount, so the
    # watch is genuinely below its floor either way and the only thing that can
    # change the verdict is whether the wallet keeps scanning.
    _fund = int(wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"])
    if _fund <= 0:
        raise SystemExit(f"[!] setup: nothing unlocked after mining 100 blocks "
                         f"(coinbase lock is 60). Cannot fund the watch.")
    _pay = wj("transfer", {"destinations": [{"amount": int(Decimal("0.5") * 10**12),
                                             "address": RECV}],
                           "account_index": 0, "get_tx_key": False}, t=240)
    if "error" in _pay:
        raise SystemExit(f"[!] setup: the short payment failed: {_pay['error']}. "
                         f"The suite would otherwise run against a zero balance "
                         f"and report which verdict it got, proving nothing.")
    lab.gen(PRIMARY, 15)

    rpc = gs_common.connect_rpc(f"http://127.0.0.1:{WPORT}")
    tot, unl = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    print(f"  watched subaddress holds {Decimal(unl) / 10**12} XMR unlocked")
    check("the short payment really landed and unlocked", unl > 0)

    h_live = rw.wallet_height(rpc)
    check("wallet_height reads a real height from wallet-rpc",
          isinstance(h_live, int) and h_live > 0)

    # ---- (A) daemon ALIVE, balance short and static -> a REAL shortfall -----
    # The wallet's height must genuinely advance during the watch, exactly as
    # it would on a live chain -- that is the ONLY difference between run A and
    # run B, so if it does not happen this suite proves nothing.
    #
    # This used background start_mining plus a real 2s sleep per tick and hoped
    # blocks landed. Generating one block per tick makes the premise a fact
    # rather than a race, which matters here more than anywhere: the premises
    # are asserted below, and a flaky premise turns a real regression into an
    # intermittent one.
    clk = Clock()

    def sleep_a(_s):
        clk.t += 600            # jump the virtual clock past the stall window
        lab.gen(PRIMARY, 1)     # ...and the chain really advances
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
