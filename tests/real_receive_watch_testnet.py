#!/usr/bin/env python3
"""Prove receive_watch detects a REAL payment on real monero binaries.

WHY THIS NEEDS REAL BINARIES: the whole tool rests on one claim —
gs_common.MoneroRPC.get_subaddress_balance(account, index) reports the balance
of THAT SUBADDRESS. If it actually returned the ACCOUNT balance, every unit
test with a fake RPC would still pass while the shipped tool declared "you have
been paid" the instant any unrelated balance existed anywhere in the wallet.
Only a real wallet-rpc can settle that, so this test deliberately funds the
account's primary address with a large amount and pays the watched subaddress a
small one, then asserts the watch reports the SMALL number.

It also proves the confirm/unlock gate is real: funds are asserted invisible to
the watch until they have actually unlocked on-chain.

Isolated testnet (monerod --offline --fixed-difficulty 1). SKIPs (exit 0) if
the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys
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


rw = load("receive_watch")           # the SHIPPED watch loop
import gs_common                     # the SHIPPED rpc wrapper

BASE = tempfile.mkdtemp(prefix="recvw_")
lab = MoneroLab(BASE, 30201, 30203)
DR = "http://127.0.0.1:30201"; D = DR + "/json_rpc"
WPORT = 30203
WR = f"http://127.0.0.1:{WPORT}/json_rpc"


dj = lab.dj

draw = lab.draw

wj = lab.wj

procs = []


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))


mine = lab.gen

PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


def fast_watch(rpc, acct, idx, floor_, timeout_s=240, stall_s=10 ** 9):
    """The SHIPPED watch loop, with only the sleep shortened so the test is not
    a 90-second-per-tick wait. Everything else is the real code path."""
    return rw.watch(rpc, acct, idx, Decimal(str(floor_)),
                    timeout_s=timeout_s, stall_s=stall_s,
                    sleep_fn=lambda _s: time.sleep(2))


result = "INCOMPLETE"
try:
    lab.start()
    # 1. A wallet whose PRIMARY address will hold a large mined balance.
    wj("create_wallet", {"filename": "recv", "password": "", "language": "English"})
    PRIMARY = wj("get_address", {"account_index": 0})["result"]["address"]

    # 2. The receive subaddress — what create_receive_wallet produces.
    sub = wj("create_address", {"account_index": 0, "label": "GhostSpiral_entry"})["result"]
    RECV, RIDX = sub["address"], sub["address_index"]
    print(f"  primary funded addr = ...{PRIMARY[-8:]}")
    print(f"  watched subaddress  = ...{RECV[-8:]} (index {RIDX})")
    check("the receive subaddress is NOT index 0 (that is the change carrier)", RIDX != 0)

    # 3. Fund the PRIMARY heavily. The watched subaddress still has nothing.
    mine(PRIMARY, 80)
    wj("refresh")
    acct_unlocked = wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"]
    print(f"  account unlocked = {acct_unlocked / 1e12:.4f} XMR (all on the PRIMARY)")
    check("the account is now richly funded", acct_unlocked > 100 * 10 ** 12)

    # The real shipped RPC wrapper, against the real wallet-rpc.
    rpc = gs_common.connect_rpc(f"http://127.0.0.1:{WPORT}")

    bal, unl = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    check("REAL RPC: the watched subaddress reads 0 while the ACCOUNT holds a fortune",
          bal == 0 and unl == 0)
    check("REAL RPC: get_subaddress_balance is per-subaddress, NOT the account total",
          unl != acct_unlocked)

    # 4. A watch with a target must NOT fire on the account's unrelated balance.
    r = fast_watch(rpc, 0, RIDX, floor_=1, timeout_s=12)
    check("watch: does NOT declare payment from an unrelated account balance",
          r["state"] == "timeout" and r["unlocked"] == Decimal(0))

    # 5. Pay the watched subaddress a SMALL, specific amount.
    PAY = 3 * 10 ** 12                      # 3 XMR
    tx = wj("transfer", {"destinations": [{"address": RECV, "amount": PAY}],
                         "account_index": 0, "priority": 1,
                         "get_tx_key": True}, t=300)
    check("a real transfer to the receive subaddress was relayed",
          "result" in tx and tx["result"].get("tx_hash"))

    # 6. Before it confirms/unlocks, the watch must still refuse to call it paid.
    wj("refresh")
    bal, unl = rpc.get_subaddress_balance(account_index=0, address_index=RIDX)
    print(f"  pre-confirm: balance={bal / 1e12} unlocked={unl / 1e12}")
    check("REAL RPC: the payment shows as balance but is NOT yet unlocked",
          bal > 0 and unl < bal)
    r = fast_watch(rpc, 0, RIDX, floor_=Decimal("2.9"), timeout_s=12)
    check("watch: a confirmed-but-LOCKED payment is not yet 'paid'",
          r["state"] == "timeout")

    # 7. Unlock it (regular outputs need 10 blocks) and watch it land.
    mine(PRIMARY, 15)
    wj("refresh")
    r = fast_watch(rpc, 0, RIDX, floor_=Decimal("2.9"), timeout_s=180)
    print(f"  watch result: {r['state']} unlocked={r['unlocked']}")
    check("watch: reports FUNDED once the real payment confirms and unlocks",
          r["state"] == "funded")
    check("watch: reports the SUBADDRESS amount (3 XMR), not the account fortune",
          r["unlocked"] == Decimal("3.000000000000"))

    # 8. The end-to-end shape an operator actually gets: bundle -> target -> menu.
    import json
    bundle_path = os.path.join(BASE, "wallet_real.json")
    json.dump({"schema": "gs_receive_wallet_v1", "address": RECV,
               "account_index": 0, "subaddress_index": RIDX,
               "rpc_endpoint": f"http://127.0.0.1:{WPORT}"}, open(bundle_path, "w"))
    b = rw.load_receive_bundle(bundle_path)
    check("the shipped loader accepts a bundle describing this real subaddress",
          b["address"] == RECV and b["subaddress_index"] == RIDX)

    pairs = [{"schema": "thor_pairs_v1", "btc_in": "0.02",
              "deposit": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
              "memo": f"=:XMR.XMR:{RECV}", "dest_xmr": RECV,
              "expected_xmr": "3.2", "ts": 1700000000}]
    # expected_total returns (total, n_unreadable): an unreadable quote used to
    # vanish into a smaller target with no mention, so the count comes back for
    # the caller to surface.
    target, _unreadable = rw.expected_total(rw.pairs_for_dest(pairs, RECV))
    check("every quote in the pairs file was readable", _unreadable == 0)
    floor_ = rw.accept_floor(target, Decimal("0.10"))
    check("a 3.2 XMR quote with 10% tolerance accepts the 3.0 that really arrived",
          target == Decimal("3.2") and floor_ <= Decimal("3.0"))
    r = fast_watch(rpc, 0, RIDX, floor_=floor_, timeout_s=60)
    check("watch: the real 3 XMR satisfies the real quote's tolerance floor",
          r["state"] == "funded")

    argv = rw.build_mix_command(rw.choice_by_key("1"), bundle_path,
                                "socks5h://127.0.0.1:9050")
    check("the printed next command is a real GhostSpiral peel+DAG invocation",
          "--peel" in argv and "--dag-mixing" in argv
          and argv[argv.index("--receive-wallet") + 1] == bundle_path)

    result = "DONE"
finally:
    lab.stop()
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\n{result}: {PASS} passed, {FAIL} failed")
for f in FAILS:
    print("  - " + f)
sys.exit(1 if FAIL or result != "DONE" else 0)
