#!/usr/bin/env python3
"""Prove the SEND fan-out actually works end to end, with the shipped UNEQUAL
(jittered) amounts, against real monero binaries via the COLD-SIGNING path.

WHY: GhostSpiral's send distributes the entry balance across N mix subaddresses
in one fan-out transaction, now with deliberately unequal per-destination
amounts (compute_fanout_amounts) so a chain analyst has no single value to
cluster on. This test proves that:
  * the amounts the SHIPPED compute_fanout_amounts produces are valid and
    relayable (unequal outputs do not break the transaction),
  * the fan-out survives the real cold-signing round trip (view-only wallet ->
    unsigned_txset -> monero-wallet-cli sign_transfer -> submit_transfer), and
  * each mix subaddress receives its OWN specific amount on-chain, so the send
    delivers exactly the planned distribution — not an approximation.

Isolated testnet (monerod --offline --fixed-difficulty 1). SKIPs (exit 0) if
the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys, hashlib, json
import importlib.machinery, importlib.util
from decimal import Decimal
import random
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


ghost = load("GhostSpiral")          # the SHIPPED jitter function

BASE = tempfile.mkdtemp(prefix="send_")
DR = "http://127.0.0.1:30221"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:30223/json_rpc"


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


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


ATOMIC = Decimal(10) ** 12
result = "INCOMPLETE"
try:
    Lp(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "30221", "--p2p-bind-port", "30220",
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:30221", "--trusted-daemon",
        "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "30223", "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
       os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    # 1. Fund a FULL wallet; ENTRY is its primary address (account 0, index 0).
    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    ENTRY = wj("get_address", {"account_index": 0})["result"]["address"]
    mine(ENTRY, 90)
    wj("refresh")
    unlocked = wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"]
    print("ENTRY unlocked:", unlocked / 1e12, "XMR")

    # 2. Create N mix subaddresses (the fan-out destinations).
    N = 6
    subs = [wj("create_address", {"account_index": 0})["result"] for _ in range(N)]
    idxs = [s["address_index"] for s in subs]

    # 3. THE SHIPPED jitter function decides the per-destination amounts.
    #    A modest total keeps the fan-out to a couple of coinbase inputs (a
    #    685-XMR send would need ~30 inputs and blow the tx size); the jitter
    #    logic under test is identical at any scale.
    usable = Decimal("5")
    fee = Decimal("0.001")
    amounts = ghost.compute_fanout_amounts(usable, N, fee, True, random.Random(1234))
    check("shipped compute_fanout_amounts returned N amounts", len(amounts) == N)
    check("the fan-out amounts are UNEQUAL (anti-clustering)", len(set(amounts)) == N)
    assert amounts
    planned = {s["address"]: int((a * ATOMIC).to_integral_value()) for s, a in zip(subs, amounts)}
    print("planned per-subaddr (XMR):", [str(a) for a in amounts])

    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")

    # 4. Build the fan-out as ONE transfer_split (ENTRY -> N subs, unequal
    #    amounts), do_not_relay, on a VIEW-ONLY wallet -> unsigned_txset.
    wj("close_wallet")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": ENTRY,
                              "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})
    dests = [{"address": a, "amount": amt} for a, amt in planned.items()]
    r = wj("transfer_split", {"destinations": dests, "account_index": 0,
                              "subaddr_indices": [0], "priority": 1,
                              "get_tx_hex": False, "do_not_relay": True})
    uts = r.get("result", {}).get("unsigned_txset", "")
    if not uts:
        print("  transfer_split response:", json.dumps(r)[:300])
    check("view-only produced an unsigned fan-out txset", bool(uts))
    assert uts

    # 5. Cold-sign with monero-wallet-cli sign_transfer (the shipped protocol:
    #    unsigned_monero_tx in cwd, password-first stdin + confirmations).
    work = os.path.join(BASE, "sign"); os.makedirs(work, exist_ok=True)
    open(os.path.join(work, "unsigned_monero_tx"), "wb").write(bytes.fromhex(uts))
    subprocess.run(
        ["monero-wallet-cli", "--testnet", "--offline", "--wallet-file",
         os.path.join(BASE, "w", "full"), "--password", "", "--command", "sign_transfer"],
        input="\n" + "y\n" * 6, cwd=work, capture_output=True, text=True, timeout=120)
    signed_path = os.path.join(work, "signed_monero_tx")
    check("wallet-cli signed the fan-out", os.path.exists(signed_path))
    assert os.path.exists(signed_path)

    # 6. Relay via the view-only wallet's submit_transfer, mine, confirm.
    signed_hex = open(signed_path, "rb").read().hex()
    sr = wj("submit_transfer", {"tx_data_hex": signed_hex})
    txids = sr.get("result", {}).get("tx_hash_list", [])
    check("submit_transfer relayed the cold-signed fan-out", bool(txids))
    assert txids
    h = dj("get_info")["result"]["height"]
    mine(ENTRY, h + 15)                       # confirm + unlock
    wj("refresh")

    # 7. THE PAYOFF: each mix subaddress received its OWN planned amount.
    bal = wj("get_balance", {"account_index": 0, "address_indices": idxs})["result"]
    got = {e["address_index"]: e.get("balance", 0) for e in bal.get("per_subaddress", [])}
    planned_by_idx = {s["address_index"]: planned[s["address"]] for s in subs}
    all_match = True
    for i in idxs:
        exp = planned_by_idx[i]; act = got.get(i, 0)
        ok = act == exp
        all_match = all_match and ok
        print(f"    subaddr {i}: planned {exp/1e12:.4f}  got {act/1e12:.4f}  {'OK' if ok else 'MISMATCH'}")
    check("every mix subaddr received its EXACT planned (unequal) amount", all_match)
    check("all N subaddresses are funded (the send delivered)",
          all(got.get(i, 0) > 0 for i in idxs))
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
print(f">>> SHIPPED jittered SEND fan-out AGAINST REAL BINARIES: {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
