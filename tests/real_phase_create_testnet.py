#!/usr/bin/env python3
"""Drive the SHIPPED phase_create() -> phase_sign() chain against real binaries.

WHAT GAP THIS CLOSES: tests/test_integration.py already calls the shipped
phase_create, but against a FAKE RPC that returns whatever the test hands it.
That proves the REQUEST SHAPE (destinations, subaddr_indices, priority,
do_not_relay) is built correctly -- it cannot prove a real monero-wallet-rpc
ACCEPTS that shape or returns a usable unsigned_txset. If a param name were
wrong or an invalid combination were sent, the fake-RPC test would still pass.

So this test:
  1. calls the shipped phase_create against a REAL monero-wallet-rpc,
  2. feeds the manifest IT wrote to the shipped phase_sign (no hand-built
     manifest -- the real handoff between the two shipped functions), and
  3. relays the result to a real daemon and confirms it on-chain.

Both a DAG-hop (single destination) and a fan-out (one input -> many outputs)
plan are exercised, since those are the two TX shapes phase_create builds.

Only verify_tor/validate_proxy are stubbed -- Tor is not what is under test
here and is covered separately; the RPC endpoint is a real local wallet-rpc.

Requires monerod, monero-wallet-rpc, monero-wallet-cli on PATH. SKIPS if absent.
"""
import subprocess, time, os, signal, shutil, tempfile, json, sys
import importlib.machinery, importlib.util
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH (install monero to run this test)")
        sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


airgap = load("airgap_tx_signer")           # the SHIPPED module

BASE = tempfile.mkdtemp(prefix="pc_")
DR = "http://127.0.0.1:30171"; D = DR + "/json_rpc"
WPORT = 30173
WR = f"http://127.0.0.1:{WPORT}/json_rpc"

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL {name}")


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()


def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=40).json()


def wj(m, p=None, t=120):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def L(cmd, log):
    p = subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT)
    procs.append(p); return p


def step(s):
    print("\n===", s, "===")


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


result = "INCOMPLETE"
cwd0 = os.getcwd()
try:
    L(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "node"),
       "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "30171", "--p2p-bind-port", "30170",
       "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
       "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None:
                break
        except Exception:
            pass
    L(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:30171", "--trusted-daemon",
       "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", str(WPORT), "--rpc-bind-ip", "127.0.0.1",
       "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
      os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"):
                break
        except Exception:
            pass

    step("1. fund a FULL wallet and make real subaddresses")
    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    faddr = wj("get_address", {"account_index": 0})["result"]["address"]
    subs = []
    for i in range(3):
        r = wj("create_address", {"account_index": 0, "label": f"mix{i}"})["result"]
        subs.append(r["address"])
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < 80:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    wj("close_wallet")

    step("2. view-only wallet (what phase_create talks to in production)")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": faddr,
                              "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})

    # Tor is not under test; the RPC below is a real local wallet-rpc.
    airgap.verify_tor = lambda *a, **k: None
    airgap.validate_proxy = lambda u: {"http": u, "https": u}

    step("3. SHIPPED phase_create -> REAL wallet-rpc (DAG-hop shape, single dest)")
    outdir = os.path.join(BASE, "staging_hop")
    os.chdir(BASE)
    plan_hop = [{"src": faddr, "src_index": 0, "dst": subs[0], "amt": "0.3", "delay": 0}]
    args = Args(tor_proxy="socks5h://127.0.0.1:9050", rpc=f"http://127.0.0.1:{WPORT}",
                outdir=outdir, fee_priority=1)
    airgap.phase_create(args, plan_hop, {"account_index": 0})   # sys.exit(1) if any TX failed

    mani_path = os.path.join(outdir, "unsigned_manifest.json")
    check("phase_create wrote unsigned_manifest.json", os.path.exists(mani_path))
    mani = json.load(open(mani_path))
    check("manifest has exactly 1 entry", len(mani.get("entries", [])) == 1)
    ent = mani["entries"][0]
    check("unsigned tx file exists on disk", os.path.exists(ent["file"]))
    blob = open(ent["file"]).read()
    check("REAL wallet-rpc returned a non-empty unsigned_txset", len(blob) > 100)
    check("unsigned_txset is hex (phase_sign fromhex's it)",
          all(c in "0123456789abcdefABCDEF" for c in blob.strip()))
    check("unsigned tx decodes to monero unsigned-txset magic",
          bytes.fromhex(blob.strip())[:22].startswith(b"Monero unsigned tx set"))

    step("4. SHIPPED phase_sign consumes the manifest phase_create just wrote")
    shim = os.path.join(BASE, "wcli-testnet")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\nexec monero-wallet-cli --testnet --offline "$@"\n')
    os.chmod(shim, 0o755)
    sargs = Args(outdir=outdir, wallet_cli=shim,
                 wallet_file=os.path.join(BASE, "w", "full"), wallet_password="")
    # Same plan object -> the fingerprint phase_create stored must validate here.
    airgap.phase_sign(sargs, plan_hop)
    signed = os.path.join(outdir, "signed", "tx_0.signed")
    check("phase_sign accepted phase_create's fingerprint + hash", os.path.exists(signed))
    assert os.path.exists(signed)
    raw = open(signed, "rb").read()
    check("signed blob has monero signed-txset magic",
          raw[:20].startswith(b"Monero signed tx set"))

    step("5. real daemon relays the shipped chain's output")
    sr = wj("submit_transfer", {"tx_data_hex": raw.hex()})
    txids = sr.get("result", {}).get("tx_hash_list", [])
    print("  submit_transfer ->", json.dumps(sr)[:170])
    check("submit_transfer relayed it", bool(txids))
    if txids:
        draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                               "do_background_mining": False, "ignore_battery": True})
        time.sleep(4); draw("/stop_mining")
        tx = requests.post(DR + "/get_transactions",
                           json={"txs_hashes": [txids[0]]}, timeout=30).json()
        on_chain = bool(tx.get("txs"))
        in_pool = tx.get("txs", [{}])[0].get("in_pool", None) if on_chain else None
        check("chain output confirmed on-chain", on_chain and in_pool is False)

    step("6. SHIPPED phase_create with a FAN-OUT plan (1 input -> 3 outputs)")
    wj("refresh")
    time.sleep(2)
    outdir2 = os.path.join(BASE, "staging_fan")
    plan_fan = [{
        "src": faddr, "src_index": 0,
        "destinations": [{"address": a, "amount": "0.2"} for a in subs],
        "delay": 0,
    }]
    args2 = Args(tor_proxy="socks5h://127.0.0.1:9050", rpc=f"http://127.0.0.1:{WPORT}",
                 outdir=outdir2, fee_priority=1)
    airgap.phase_create(args2, plan_fan, {"account_index": 0})
    mani2 = json.load(open(os.path.join(outdir2, "unsigned_manifest.json")))
    check("fan-out: manifest has 1 entry (ONE tx, many outputs)",
          len(mani2.get("entries", [])) == 1)
    check("fan-out: manifest summarizes as N_dests",
          mani2["entries"][0]["dst"] == "3_dests")
    check("fan-out: manifest total amt = 0.6", mani2["entries"][0]["amt"] == "0.6")
    fan_blob = open(mani2["entries"][0]["file"]).read()
    check("fan-out: REAL wallet-rpc accepted the multi-dest params",
          len(fan_blob) > 100)
    check("fan-out: decodes to a real unsigned tx set",
          bytes.fromhex(fan_blob.strip())[:22].startswith(b"Monero unsigned tx set"))

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    os.chdir(cwd0)
    for p in procs:
        try:
            p.send_signal(signal.SIGTERM); p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
print(">>> SHIPPED phase_create -> phase_sign AGAINST REAL BINARIES:", result)
sys.exit(0 if result == "SUCCESS" else 1)
