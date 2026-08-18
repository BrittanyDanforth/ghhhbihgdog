#!/usr/bin/env python3
"""Cold signing must survive the account indices that output isolation creates.

THE DEFECT THIS PINS. A Monero wallet derives subaddresses for a bounded
LOOKAHEAD of accounts -- 50 major by default -- and that bound is fixed when
the wallet is CREATED: wallet-cli refuses --subaddress-lookahead alongside
--wallet-file, so an existing offline wallet cannot be told a bigger number.

GhostSpiral now gives every output its own account, because a transaction
cannot spend across accounts and that is what stops one transaction merging the
mix. It costs roughly twenty accounts per run, so the ONLINE wallet passes 50
accounts during the second run. From then on the offline wallet cannot derive
the keys for the exported outputs:

    import_outputs -> "Failed to generate key image"
    sign_transfer  -> "Loaded 1 transactions", and no signed file

Nothing warns, nothing is lost, and the round simply cannot be signed. Measured
before the fix: an offline wallet at the default lookahead could not sign a
spend from account 120; after 122 x `account new` the same import reported
"147 outputs imported" and the signature succeeded.

So phase_create records the online wallet's account count and phase_sign tops
the offline wallet up to match. This suite drives the SHIPPED functions, and
includes the NEGATIVE CONTROL -- the same round with the count marker removed
must FAIL -- because otherwise it would pass on a wallet that never needed the
fix at all.

Runs on `monerod --regtest` (current consensus) via tests/monerolab.py.
SKIPs (exit 0) if the monero binaries aren't installed.
"""
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
from decimal import Decimal

import requests

for _b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(_b) is None:
        print(f"SKIP: {_b} not on PATH")
        sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, REPO)
from monerolab import MoneroLab                              # noqa: E402


def load(name):
    ld = importlib.machinery.SourceFileLoader(
        name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


airgap = load("airgap_tx_signer")

A = 10 ** 12
#: Comfortably past the default 50-major lookahead, and past it by enough that
#: an off-by-a-few in the top-up still shows as a failure rather than a pass.
TARGET_ACCOUNT = 70
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


BASE = tempfile.mkdtemp(prefix="coldla_")
lab = MoneroLab(BASE, 30271, 30273)
VW = "http://127.0.0.1:30276/json_rpc"
view_proc = None
result = "FAILED"


def vj(method, params=None):
    body = {"jsonrpc": "2.0", "id": "0", "method": method}
    if params is not None:
        body["params"] = params
    return requests.post(VW, json=body, timeout=900).json()


try:
    lab.start()
    lab.wj("create_wallet", {"filename": "full", "password": "",
                             "language": "English"})
    primary = lab.wj("get_address", {"account_index": 0})["result"]["address"]
    lab.gen(primary, 130)
    viewkey = lab.wj("query_key", {"key_type": "view_key"})["result"]["key"]

    # The ONLINE machine: a view-only wallet, and the only one that creates
    # accounts. The offline spend wallet never sees those calls.
    os.makedirs(os.path.join(BASE, "v"), exist_ok=True)
    view_proc = subprocess.Popen(
        ["monero-wallet-rpc", "--daemon-address", f"127.0.0.1:{lab.dp}",
         "--trusted-daemon", "--wallet-dir", os.path.join(BASE, "v"),
         "--rpc-bind-port", "30276", "--rpc-bind-ip", "127.0.0.1",
         "--disable-rpc-login", "--allow-mismatched-daemon-version",
         "--log-file", os.path.join(BASE, "v.log"), "--log-level", "0"],
        stdout=open(os.path.join(BASE, "v.out"), "w"), stderr=subprocess.STDOUT)
    for _ in range(90):
        time.sleep(1)
        try:
            if "result" in vj("get_version"):
                break
        except Exception:                                    # noqa: BLE001
            pass
    vj("generate_from_keys", {"restore_height": 0, "filename": "view",
                              "address": primary, "viewkey": viewkey,
                              "password": ""})
    vj("refresh")

    acct = 0
    while acct < TARGET_ACCOUNT:
        acct = vj("create_account", {"label": ""})["result"]["account_index"]
    sub = vj("create_address", {"account_index": acct})["result"]
    print(f"spending account {acct} / subaddr {sub['address_index']}, created "
          f"only on the view-only wallet (default lookahead is 50)")

    lab.wj("transfer", {"destinations": [{"amount": int(2 * A),
                                          "address": sub["address"]}],
                        "account_index": 0, "get_tx_key": False})
    lab.gen(primary, 15)
    vj("refresh")
    dest = vj("create_address", {"account_index": 0})["result"]["address"]
    lab.wj("close_wallet")          # release the .keys file for wallet-cli

    shim = os.path.join(BASE, "wcli")
    open(shim, "w").write('#!/bin/sh\nexec monero-wallet-cli --offline "$@"\n')
    os.chmod(shim, 0o755)

    class RpcShim:
        def raw_request(self, method, params=None):
            r = vj(method, params)
            if "error" in r:
                raise RuntimeError(str(r["error"])[:160])
            return r.get("result", {})

    airgap.verify_tor = lambda *a, **k: None
    airgap.connect_rpc = lambda *a, **k: RpcShim()
    os.chdir(BASE)

    class Args:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    plan = [{"src": "HIGH", "src_index": sub["address_index"],
             "account_index": acct, "dst": dest, "amt": "1", "delay": 0}]
    wallet_file = os.path.join(BASE, "w", "full")

    def run_round(stage, drop_marker):
        airgap.phase_create(
            Args(tor_proxy="socks5h://127.0.0.1:9050",
                 rpc=VW.replace("/json_rpc", ""), outdir=stage, fee_priority=1),
            plan, {"account_index": acct})
        made = os.path.exists(os.path.join(stage, "tx_0.unsigned"))
        marker = os.path.join(stage, airgap.ACCOUNTS_COUNT_NAME)
        seen = os.path.exists(marker)
        if drop_marker and seen:
            os.remove(marker)
        try:
            airgap.phase_sign(
                Args(outdir=stage, wallet_file=wallet_file, wallet_password="",
                     wallet_cli=shim), plan)
        except SystemExit:
            # phase_sign aborts the run when a round signs partially, which is
            # correct behaviour and exactly what the control expects to see.
            pass
        return made, seen, os.path.exists(os.path.join(stage, "signed", "tx_0.signed"))

    # NEGATIVE CONTROL FIRST, on a pristine offline wallet: without the account
    # count the top-up cannot run, and the round must fail. Run it first
    # because the fix is persistent -- once the accounts exist, they exist.
    made0, seen0, signed0 = run_round(os.path.join(BASE, "stage_ctrl"), True)
    check("control: phase_create built the unsigned tx", made0)
    check("control: phase_create recorded the online wallet's account count",
          seen0)
    check("control: WITHOUT that count the offline wallet cannot sign a spend "
          "above its lookahead -- so this suite is testing something",
          not signed0)

    made1, seen1, signed1 = run_round(os.path.join(BASE, "stage_fix"), False)
    check("phase_create recorded the account count again", seen1)
    check("WITH the count, the shipped signer tops the offline wallet up and "
          f"cold-signs a spend from account {acct}", signed1)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    if view_proc:
        try:
            view_proc.terminate()
        except Exception:                                    # noqa: BLE001
            pass
    lab.stop()
    os.chdir("/")
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
print(f">>> COLD SIGNING ABOVE THE SUBADDRESS LOOKAHEAD: {result}")
sys.exit(0 if FAIL == 0 else 1)
