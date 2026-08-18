#!/usr/bin/env python3
"""REAL end-to-end cold-signing round-trip against actual monero binaries on an
isolated testnet (checkpoint-free, instant mining, wallet fork-table matches).

Exercises the pipeline's ACTUAL logic, no mocks:
  view-only transfer_split(do_not_relay) -> unsigned_txset (hex)
  -> phase_sign's bytes.fromhex + wallet-cli sign_transfer (password-first stdin)
  -> signed_monero_tx (binary) -> hex -> broadcast's submit_transfer -> relay
  -> mine 1 block -> confirm the tx is on-chain.

Requires monerod, monero-wallet-rpc, monero-wallet-cli on PATH (e.g.
`apt-get install monero`). SKIPS (exit 0) if they are not installed.

Note: an isolated testnet sits at an early fork (small ring size); the cold-
signing MECHANISM this validates (hex<->binary tx-set, sign_transfer prompts,
submit_transfer relay) is identical across forks -- the pipeline code touches
none of the ring/RingCT specifics.
"""
import subprocess, time, os, signal, shutil, tempfile, json, sys
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH (install monero to run this real round-trip test)")
        sys.exit(0)

BASE = tempfile.mkdtemp(prefix="rt_")
DR = "http://127.0.0.1:28081"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:28083/json_rpc"

def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()
def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=40).json()
def wj(m, p=None, t=120):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()

procs = []
def L(cmd, log):
    p = subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT); procs.append(p); return p
def step(s): print("\n===", s, "===")

result = "INCOMPLETE"
try:
    L(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "node"),
       "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28081", "--p2p-bind-port", "28080",
       "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
       "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    L(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28081", "--trusted-daemon",
       "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28083", "--rpc-bind-ip", "127.0.0.1",
       "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"], os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    step("1. create + fund FULL wallet (mine on isolated testnet)")
    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    faddr = wj("get_address", {"account_index": 0})["result"]["address"]
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < 80:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    print("full unlocked:", wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"])
    wj("close_wallet")

    step("2. VIEW-ONLY wallet: import key images, transfer_split(do_not_relay) -> unsigned_txset")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": faddr, "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})
    r = wj("transfer_split", {"destinations": [{"amount": 300000000000, "address": faddr}],
                              "account_index": 0, "priority": 1, "get_tx_hex": False, "do_not_relay": True})
    uts = r.get("result", {}).get("unsigned_txset", "")
    print("unsigned_txset hex len:", len(uts), "err:", r.get("error"))
    assert uts, "view-only transfer_split returned no unsigned_txset"

    step("3. phase_sign logic: bytes.fromhex -> wallet-cli sign_transfer (password-first stdin)")
    work = os.path.join(BASE, "work"); os.makedirs(work, exist_ok=True)
    # EXACTLY as airgap_tx_signer.phase_sign writes it:
    open(os.path.join(work, "unsigned_monero_tx"), "wb").write(bytes.fromhex(uts))
    password = ""
    p = subprocess.run(
        ["monero-wallet-cli", "--testnet", "--offline", "--wallet-file", os.path.join(BASE, "w", "full"),
         "--password", password, "--command", "sign_transfer"],
        input=f"{password}\n" + "y\n" * 3,   # phase_sign's password-first fix
        capture_output=True, text=True, timeout=90, cwd=work)
    signed_path = os.path.join(work, "signed_monero_tx")
    print("wallet-cli rc", p.returncode, "| signed_monero_tx produced:", os.path.exists(signed_path))
    assert os.path.exists(signed_path), "sign_transfer produced no signed_monero_tx"
    signed_hex = open(signed_path, "rb").read().hex()   # broadcast: raw_data.hex()

    step("4. broadcast logic: submit_transfer(tx_data_hex) via view-only wallet-rpc")
    sr = wj("submit_transfer", {"tx_data_hex": signed_hex})
    txids = sr.get("result", {}).get("tx_hash_list", [])
    print("submit_transfer ->", json.dumps(sr)[:200])
    assert txids, "submit_transfer returned no tx_hash_list"
    txid = txids[0]

    step("5. mine 1 block, confirm tx on-chain")
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
    time.sleep(4); draw("/stop_mining")
    tx = requests.post(DR + "/get_transactions", json={"txs_hashes": [txid]}, timeout=30).json()
    on_chain = bool(tx.get("txs"))
    in_pool = tx.get("txs", [{}])[0].get("in_pool", None) if on_chain else None
    print("tx on daemon:", on_chain, "| in_pool:", in_pool)
    assert on_chain and in_pool is False, "tx not confirmed on-chain"
    result = "SUCCESS"
finally:
    for p in procs:
        try: p.send_signal(signal.SIGTERM); p.wait(timeout=8)
        except Exception:
            try: p.kill()
            except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print("\n>>> REAL COLD-SIGNING ROUND-TRIP:", result)
sys.exit(0 if result == "SUCCESS" else 1)
