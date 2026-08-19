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


import gs_common
DPORT, WPORT = 30260, 30263
DR = f"http://127.0.0.1:{DPORT}"
WR = f"http://127.0.0.1:{WPORT}/json_rpc"
BASE = tempfile.mkdtemp(prefix="chsweep_")
lab = MoneroLab(BASE, 30260, 30263)
procs = []
PASS = 0; FAIL = 0; FAILS = []
A = 10 ** 12


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


wj = lab.wj

dj = lab.dj

def height():
    return dj("get_info")["result"]["height"]


def mine_to(target, addr):
    """Mine to EXACTLY `target`. This used start_mining and polled every 20ms,
    because fixed-difficulty blocks arrive faster than a 2s sleep and
    overshooting by dozens of blocks silently unlocks the output this test
    needs to keep LOCKED -- which is how the first attempt at this came out
    inconclusive. A tight poll narrows that race; it does not close it, and
    /stop_mining is asynchronous so blocks keep landing after it returns.
    generateblocks produces exactly the number asked for and none after.
    """
    lab.mine(addr, target)


result = "INCOMPLETE"
try:
    lab.start()
    wj("create_wallet", {"filename": "c", "password": "", "language": "English"})
    P = wj("get_address", {"account_index": 0})["result"]["address"]
    sub = wj("create_address", {"account_index": 0})["result"]
    S, SI = sub["address"], sub["address_index"]
    DST = wj("create_address", {"account_index": 0})["result"]["address"]
    # A coinbase output is locked for 60 blocks, so 60 blocks of mining leaves
    # NOTHING spendable. This said `height() + 60` and worked only because
    # start_mining overshot it by however many blocks landed before
    # /stop_mining took effect -- the test was funded by the same
    # non-determinism it complains about in mine_to. Mine enough that early
    # coinbases have actually matured.
    mine_to(height() + 100, P)
    _funded = int(wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"])
    if _funded < 10 * A:
        raise SystemExit(f"[!] setup: only {Decimal(_funded)/A} XMR unlocked after "
                         f"mining; the coinbase lock is 60 blocks. Refusing to run "
                         f"a test whose preconditions were never established.")

    # Two payments to ONE subaddress, at different depths -- the exact shape a
    # peel chain leaves on the change address.
    _r1 = wj("transfer", {"destinations": [{"amount": 2 * A, "address": S}],
                          "account_index": 0, "get_tx_key": False})
    if "error" in _r1:
        raise SystemExit(f"[!] setup: first payment failed: {_r1['error']}")
    mine_to(height() + 14, P)          # this one is well past the 10-block unlock
    _r2 = wj("transfer", {"destinations": [{"amount": 3 * A, "address": S}],
                          "account_index": 0, "get_tx_key": False})
    if "error" in _r2:
        raise SystemExit(f"[!] setup: second payment failed: {_r2['error']}")
    mine_to(height() + 2, P)           # this one is only ~2 blocks deep

    b = wj("get_balance", {"account_index": 0,
                           "address_indices": [SI]})["result"]["per_subaddress"][0]
    tot, unl = int(b["balance"]), int(b["unlocked_balance"])
    print(f"  change subaddress: total={Decimal(tot)/A} unlocked={Decimal(unl)/A} "
          f"blocks_to_unlock={b.get('blocks_to_unlock')}")
    if tot == unl:
        # Was a SKIP, which reported SUCCESS-adjacent output while proving
        # nothing. With exact block generation there is no overshoot left to
        # blame, so a missing locked output means the setup is wrong.
        raise SystemExit(f"[!] setup: wanted an unlocked AND a locked output, got "
                         f"total={Decimal(tot)/A} unlocked={Decimal(unl)/A}. "
                         f"Block generation is exact now, so this is not overshoot.")
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
    lab.stop()
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS: print("FAILED:", FAILS)
print(f">>> CHANGE SWEEP vs LOCKED OUTPUTS (REAL BINARIES): {result}")
sys.exit(0 if result in ("SUCCESS", "SKIPPED") else 1)
