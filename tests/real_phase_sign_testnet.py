#!/usr/bin/env python3
"""Drive the SHIPPED airgap_tx_signer.phase_sign() against real monero binaries.

WHY THIS EXISTS: real_roundtrip_testnet.py proves the cold-signing PROTOCOL
works, but it reimplements the sequence inline ("EXACTLY as phase_sign writes
it"). A hand-copied parallel implementation cannot catch drift -- if phase_sign
regressed, that test would still pass. This test imports airgap_tx_signer and
calls phase_sign(args, plan) directly, so the shipped code path is what runs:
its manifest load, plan-fingerprint check, sha256 verify, hex->binary decode,
password-first stdin protocol, signed-file collection, and partial-sign abort.

The signed blob is then submitted to a real daemon, which is the only way to
prove phase_sign emitted a genuinely valid signed tx set rather than any file.

Requires monerod, monero-wallet-rpc, monero-wallet-cli on PATH. SKIPS (exit 0)
if absent.
"""
import subprocess, time, os, signal, shutil, tempfile, json, sys, hashlib
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


airgap = load("airgap_tx_signer")          # <-- the SHIPPED module, not a copy

BASE = tempfile.mkdtemp(prefix="ps_")
DR = "http://127.0.0.1:28091"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:28093/json_rpc"

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
    """Stand-in for argparse's namespace -- the exact attributes phase_sign reads."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


result = "INCOMPLETE"
cwd0 = os.getcwd()
try:
    L(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "node"),
       "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28091", "--p2p-bind-port", "28090",
       "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
       "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None:
                break
        except Exception:
            pass
    L(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28091", "--trusted-daemon",
       "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28093", "--rpc-bind-ip", "127.0.0.1",
       "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
      os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"):
                break
        except Exception:
            pass

    step("1. fund a FULL wallet on the isolated testnet")
    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    faddr = wj("get_address", {"account_index": 0})["result"]["address"]
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < 80:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    wj("close_wallet")

    step("2. view-only wallet -> real unsigned_txset")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": faddr,
                              "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})
    r = wj("transfer_split", {"destinations": [{"amount": 300000000000, "address": faddr}],
                              "account_index": 0, "priority": 1,
                              "get_tx_hex": False, "do_not_relay": True})
    uts = r.get("result", {}).get("unsigned_txset", "")
    check("view-only produced an unsigned_txset", bool(uts))
    assert uts

    step("3. build the on-disk state phase_sign consumes (manifest + unsigned file)")
    outdir = os.path.join(BASE, "staging")
    os.makedirs(outdir, exist_ok=True)
    tx_file = os.path.join(outdir, "tx_0.unsigned")
    with open(tx_file, "w") as f:
        f.write(uts)
    # phase_sign verifies sha256 over the file's TEXT, exactly as phase_create wrote it.
    tx_hash = hashlib.sha256(open(tx_file).read().encode()).hexdigest()
    plan = [{"src": faddr, "dst": faddr, "amt": "0.3", "delay": 0}]
    manifest = {
        # Computed with the SHIPPED fingerprint fn, so a real mismatch would fail
        # the test rather than being papered over by a hand-written constant.
        "plan_fingerprint": airgap._compute_plan_fingerprint(plan),
        "phase": "unsigned",
        "entries": [{"idx": 0, "file": tx_file, "hash": tx_hash,
                     "dst": faddr, "amt": "0.3", "delay": 0}],
    }
    with open(os.path.join(outdir, "unsigned_manifest.json"), "w") as f:
        json.dump(manifest, f)

    # phase_sign builds its wallet-cli argv WITHOUT --testnet/--offline (correct
    # for mainnet air-gapped use). A shim supplies those two flags so the real
    # phase_sign code -- its stdin protocol, decode and collection logic -- is
    # what executes against a testnet wallet.
    shim = os.path.join(BASE, "wcli-testnet")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\nexec monero-wallet-cli --testnet --offline "$@"\n')
    os.chmod(shim, 0o755)

    step("4. CALL THE SHIPPED airgap_tx_signer.phase_sign()")
    os.chdir(BASE)          # integrity_chain.log lands in the scratch dir
    args = Args(outdir=outdir, wallet_cli=shim,
                wallet_file=os.path.join(BASE, "w", "full"), wallet_password="")
    airgap.phase_sign(args, plan)      # sys.exit()s if it signs fewer than all

    signed_blob = os.path.join(outdir, "signed", "tx_0.signed")
    check("phase_sign produced signed/tx_0.signed", os.path.exists(signed_blob))
    assert os.path.exists(signed_blob)
    raw = open(signed_blob, "rb").read()
    check("signed blob is non-trivial", len(raw) > 100)
    check("signed blob has monero signed-txset magic",
          raw[:20].startswith(b"Monero signed tx set"))
    smf = os.path.join(outdir, "signed", "signed_manifest_v1.json")
    check("phase_sign wrote its signed manifest", os.path.exists(smf))
    if os.path.exists(smf):
        entries = json.load(open(smf))
        check("signed manifest records the tx with a sha256",
              len(entries) == 1 and len(entries[0].get("hash", "")) == 64)

    step("5. daemon accepts what phase_sign produced (proves real validity)")
    sr = wj("submit_transfer", {"tx_data_hex": raw.hex()})
    txids = sr.get("result", {}).get("tx_hash_list", [])
    print("submit_transfer ->", json.dumps(sr)[:180])
    check("submit_transfer relayed phase_sign's blob", bool(txids))
    assert txids
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    time.sleep(4); draw("/stop_mining")
    tx = requests.post(DR + "/get_transactions", json={"txs_hashes": [txids[0]]}, timeout=30).json()
    on_chain = bool(tx.get("txs"))
    in_pool = tx.get("txs", [{}])[0].get("in_pool", None) if on_chain else None
    check("phase_sign's tx confirmed on-chain", on_chain and in_pool is False)

    step("6. tamper detection: a corrupted unsigned file must NOT be signed")
    outdir2 = os.path.join(BASE, "staging2")
    os.makedirs(os.path.join(outdir2), exist_ok=True)
    tx2 = os.path.join(outdir2, "tx_0.unsigned")
    with open(tx2, "w") as f:
        f.write(uts)
    bad_manifest = {
        "plan_fingerprint": airgap._compute_plan_fingerprint(plan),
        "phase": "unsigned",
        # hash of DIFFERENT content -> phase_sign must refuse this entry
        "entries": [{"idx": 0, "file": tx2, "hash": hashlib.sha256(b"not-this").hexdigest(),
                     "dst": faddr, "amt": "0.3", "delay": 0}],
    }
    with open(os.path.join(outdir2, "unsigned_manifest.json"), "w") as f:
        json.dump(bad_manifest, f)
    args2 = Args(outdir=outdir2, wallet_cli=shim,
                 wallet_file=os.path.join(BASE, "w", "full"), wallet_password="")
    try:
        airgap.phase_sign(args2, plan)
        check("hash mismatch aborts (should have exited)", False)
    except SystemExit:
        check("hash mismatch -> phase_sign aborts, signs nothing", True)
    check("no signed blob written for tampered input",
          not os.path.exists(os.path.join(outdir2, "signed", "tx_0.signed")))

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
print(">>> SHIPPED phase_sign() AGAINST REAL BINARIES:", result)
sys.exit(0 if result == "SUCCESS" else 1)
