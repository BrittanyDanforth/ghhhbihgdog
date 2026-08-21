#!/usr/bin/env python3
"""Real-binary tests of pipeline transaction SHAPES and flags on isolated testnet:
  - fee-priority 1..4 are accepted and the fee scales;
  - the multi-destination FAN-OUT tx (one transfer_split, N outputs) round-trips
    end to end (view-only unsigned -> sign_transfer -> submit_transfer -> mined);
  - a PASSWORD-PROTECTED wallet signs via the password-first stdin.
SKIPs (exit 0) if the monero binaries are not installed."""
import subprocess, time, os, signal, shutil, tempfile, json, sys
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

import os as _os, sys as _sys                              # noqa: E402
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
from monerolab import MoneroLab                              # noqa: E402

BASE = tempfile.mkdtemp(prefix="rf_")
lab = MoneroLab(BASE, 30131, 30133)
DR = "http://127.0.0.1:30131"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:30133/json_rpc"
PW = "s3cret"   # non-empty wallet password, exercised through sign_transfer

def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()
def draw(path, body=None): return requests.post(DR + path, json=body or {}, timeout=40).json()
wj = lab.wj

procs = []
def L(cmd, log): procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))
def step(s): print("\n===", s, "===")
PASS = 0; FAIL = 0; FAILS = []
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)

try:
    lab.start()
    step("fund PASSWORD-PROTECTED full wallet")
    wj("create_wallet", {"filename": "full", "password": PW, "language": "English"})
    faddr = wj("get_address", {"account_index": 0})["result"]["address"]
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < 85:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    print("funded unlocked:", wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"])
    wj("close_wallet")

    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": faddr, "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages: wj("import_key_images", {"signed_key_images": kimages})

    step("fee-priority 1..4 accepted, fee scales")
    fees = {}
    for pr in (1, 2, 3, 4):
        r = wj("transfer_split", {"destinations": [{"amount": 100000000000, "address": faddr}],
                                  "account_index": 0, "priority": pr, "get_tx_hex": False, "do_not_relay": True})
        rr = r.get("result", {})
        uts = rr.get("unsigned_txset", ""); fee = (rr.get("fee_list") or [0])[0]
        fees[pr] = fee
        print(f"  priority {pr}: unsigned_txset len {len(uts)}, fee {fee}")
        check(f"fp{pr}:unsigned_txset", bool(uts))
    # Fee behaviour is FORK-dependent, and this suite used to run on a chain at
    # hard fork v1, where the per-priority fees are not monotonic (observed
    # 2/4/6/2). The assertion was weakened to ">=2 distinct fees" to survive
    # that -- i.e. the environment was wrong and the test was relaxed to match
    # it, which is the wrong way round.
    #
    # On current consensus they ARE monotonic (measured here: 2.6M / 10.2M /
    # 41.2M / 521M), so assert what the pipeline actually depends on:
    # fee_priority selects a strictly higher fee. fetch_fee_from_daemon reads
    # the daemon's fees[] rather than a fixed multiplier table, and this is the
    # property that makes that reading meaningful.
    _ordered = [fees[k] for k in sorted(fees)]
    check("fee-priority yields >=2 distinct fees", len(set(fees.values())) >= 2)
    check("fee-priority is STRICTLY MONOTONIC on current consensus "
          f"({'/'.join(str(f) for f in _ordered)})",
          all(_ordered[i] < _ordered[i + 1] for i in range(len(_ordered) - 1)))

    step("MULTI-DEST FAN-OUT round-trip (3 outputs) with password-protected signing")
    dests = [wj("create_address", {"account_index": 0})["result"]["address"] for _ in range(3)]
    r = wj("transfer_split", {"destinations": [{"amount": 100000000000, "address": a} for a in dests],
                              "account_index": 0, "priority": 1, "get_tx_hex": False, "do_not_relay": True})
    uts = r.get("result", {}).get("unsigned_txset", "")
    check("fanout:unsigned_txset", bool(uts))
    print("  fan-out unsigned_txset len:", len(uts), "err:", r.get("error"))

    work = os.path.join(BASE, "work"); os.makedirs(work, exist_ok=True)
    open(os.path.join(work, "unsigned_monero_tx"), "wb").write(bytes.fromhex(uts))
    # phase_sign with a NON-EMPTY password: password-first stdin
    p = subprocess.run(
        ["monero-wallet-cli", "--offline", "--wallet-file", os.path.join(BASE, "w", "full"),
         "--password", PW, "--command", "sign_transfer"],
        input=f"{PW}\n" + "y\n" * 3, capture_output=True, text=True, timeout=90, cwd=work)
    signed = os.path.join(work, "signed_monero_tx")
    check("fanout:signed (pw-protected)", os.path.exists(signed))
    print("  sign rc", p.returncode, "signed:", os.path.exists(signed))
    if os.path.exists(signed):
        sr = wj("submit_transfer", {"tx_data_hex": open(signed, "rb").read().hex()})
        txids = sr.get("result", {}).get("tx_hash_list", [])
        check("fanout:relayed", bool(txids))
        print("  submit ->", json.dumps(sr)[:160])
        if txids:
            draw("/start_mining", {"miner_address": faddr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
            time.sleep(4); draw("/stop_mining")
            tx = requests.post(DR + "/get_transactions", json={"txs_hashes": [txids[0]]}, timeout=30).json()
            on_chain = bool(tx.get("txs")); in_pool = tx.get("txs", [{}])[0].get("in_pool") if on_chain else None
            # a fan-out tx creates 3 named outputs -> outputs count >= 4 (3 + change)
            print("  fan-out tx on-chain:", on_chain, "in_pool:", in_pool)
            check("fanout:confirmed", on_chain and in_pool is False)
finally:
    for pr in procs:
        try: pr.send_signal(signal.SIGTERM); pr.wait(timeout=8)
        except Exception:
            try: pr.kill()
            except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS: print("FAILED:", FAILS); sys.exit(1)
print("ALL GREEN")
