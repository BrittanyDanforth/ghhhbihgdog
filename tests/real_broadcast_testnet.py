#!/usr/bin/env python3
"""Drive the SHIPPED broadcast_signed_xmr.main() against real monero binaries.

WHY THIS EXISTS: tests/test_broadcast.py stubs the RPC, so it proves the relay
loop's control flow but not that the loop still relays a genuinely valid
transaction to a real daemon. This test signs a real testnet transaction with
the shipped signer, then hands the staging directory to the shipped
broadcast main() -- with only Tor/NEWNYM stubbed (there is no Tor on an
isolated testnet) and the RPC left REAL, so submit_transfer actually crosses
the wire to monero-wallet-rpc.

It then proves the three relay-loop guarantees end to end, against the daemon:

  A. a shutdown during the planned delay relays NOTHING (the tx pool stays
     empty, and the daemon is the witness -- not a mock)
  B. a --resume of that run relays the tx for real and it confirms on-chain
  C. a blob swapped DURING the planned delay is refused at submit time and
     never reaches the daemon

Requires monerod, monero-wallet-rpc, monero-wallet-cli on PATH. SKIPS (exit 0)
if absent.
"""
import subprocess, time, os, shutil, tempfile, json, sys, hashlib, threading
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


airgap = load("airgap_tx_signer")
bcast = load("broadcast_signed_xmr")       # <-- the SHIPPED relay loop

BASE = tempfile.mkdtemp(prefix="rb_")
DR = "http://127.0.0.1:28191"; D = DR + "/json_rpc"
WBASE = "http://127.0.0.1:28193"; WR = WBASE + "/json_rpc"

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


def pool_size():
    r = draw("/get_transaction_pool")
    return len(r.get("transactions") or [])


procs = []


def L(cmd, log):
    p = subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT)
    procs.append(p); return p


def step(s):
    print("\n===", s, "===")


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


# ---- stub ONLY the anonymity layer; the RPC stays real ---------------------
_shutdown_calls = [0]
_shutdown_mode = ["never"]


def _shutdown_requested():
    _shutdown_calls[0] += 1
    if _shutdown_mode[0] == "never":
        return False
    # "in_delay": False for the loop's own gate, True on the first check made
    # from inside the planned-delay sleep.
    return _shutdown_calls[0] > 1


for _stub in ("verify_tor", "tor_recheck", "newnym", "secure_delay",
              "install_signal_handlers"):
    setattr(bcast, _stub, lambda *a, **k: None)
bcast.check_daemon_relay_egress = lambda *a, **k: {"verdict": "tor",
                                                   "detail": "isolated testnet"}
bcast.shutdown_requested = _shutdown_requested


def run_broadcast(path, progfile, extra=()):
    sys.argv = ["broadcast_signed_xmr", str(path),
                "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--rpc", WBASE, "--resume", str(progfile),
                "--rebroadcast", "2", *extra]
    try:
        bcast.main(); return 0, ""
    except SystemExit as e:
        return (e.code if isinstance(e.code, int) else 1), str(e.code or "")


result = "INCOMPLETE"
try:
    L(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "node"),
       "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28191", "--p2p-bind-port", "28190",
       "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
       "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None:
                break
        except Exception:
            pass
    L(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28191", "--trusted-daemon",
       "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28193", "--rpc-bind-ip", "127.0.0.1",
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

    step("3. sign it with the SHIPPED phase_sign()")
    outdir = os.path.join(BASE, "staging")
    os.makedirs(outdir, exist_ok=True)
    tx_file = os.path.join(outdir, "tx_0.unsigned")
    with open(tx_file, "w") as f:
        f.write(uts)
    tx_hash = hashlib.sha256(open(tx_file).read().encode()).hexdigest()
    plan = [{"src": faddr, "dst": faddr, "amt": "0.3", "delay": 0}]
    with open(os.path.join(outdir, "unsigned_manifest.json"), "w") as f:
        json.dump({"plan_fingerprint": airgap._compute_plan_fingerprint(plan),
                   "phase": "unsigned",
                   "entries": [{"idx": 0, "file": tx_file, "hash": tx_hash,
                                "dst": faddr, "amt": "0.3", "delay": 0}]}, f)
    shim = os.path.join(BASE, "wcli-testnet")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\nexec monero-wallet-cli --testnet --offline "$@"\n')
    os.chmod(shim, 0o755)
    os.chdir(BASE)
    airgap.phase_sign(Args(outdir=outdir, wallet_cli=shim,
                           wallet_file=os.path.join(BASE, "w", "full"),
                           wallet_password=""), plan)
    signed_dir = os.path.join(outdir, "signed")
    blob = os.path.join(signed_dir, "tx_0.signed")
    check("phase_sign produced a signed blob", os.path.exists(blob))
    assert os.path.exists(blob)

    # Give the manifest a planned delay so the delay-path guarantees are the
    # ones under test, not the zero-delay fast path.
    smf = os.path.join(signed_dir, "signed_manifest_v1.json")
    entries = json.load(open(smf))
    entries[0]["delay"] = 6
    with open(smf, "w") as f:
        json.dump(entries, f)
    good_bytes = open(blob, "rb").read()

    check("daemon tx pool starts empty", pool_size() == 0)

    step("A. shutdown DURING the planned delay must relay nothing")
    prog = os.path.join(BASE, "progA.json")
    _shutdown_mode[0] = "in_delay"; _shutdown_calls[0] = 0
    codeA, msgA = run_broadcast(signed_dir, prog)
    check("A: run exits nonzero", codeA != 0)
    check("A: operator stop is reported", "stopped by operator" in msgA)
    check("A: THE DAEMON SAW NOTHING (pool still empty)", pool_size() == 0)
    pA = json.load(open(prog))
    check("A: nothing recorded as relayed", pA["relayed"] == [])
    check("A: not marked permanently failed (resume can retry)", pA["failed_perm"] == [])
    check("A: progress is name-keyed v2", pA.get("schema") == "broadcast_progress_v2")

    step("C. a blob swapped DURING the delay must be refused at submit time")
    progC = os.path.join(BASE, "progC.json")
    _shutdown_mode[0] = "never"; _shutdown_calls[0] = 0

    def _swap():
        with open(blob, "wb") as f:
            f.write(b"Monero signed tx set\x04" + b"\x00" * 400)   # plausible, wrong
    t = threading.Timer(2.0, _swap); t.start()
    codeC, msgC = run_broadcast(signed_dir, progC)
    t.join()
    check("C: run exits nonzero", codeC != 0)
    check("C: refusal names the on-disk change",
          "changed on disk" in msgC or "not trustworthy" in msgC)
    check("C: THE DAEMON SAW NOTHING (pool still empty)", pool_size() == 0)
    with open(blob, "wb") as f:                     # restore the real blob
        f.write(good_bytes)

    step("B. --resume of run A relays for real and confirms on-chain")
    _shutdown_mode[0] = "never"; _shutdown_calls[0] = 0
    codeB, msgB = run_broadcast(signed_dir, prog)
    check("B: resume completes with exit 0", codeB == 0)
    pB = json.load(open(prog))
    check("B: the blob is recorded relayed by NAME",
          pB["relayed"] == ["tx_0.signed"])
    check("B: A REAL DAEMON ACCEPTED IT (tx now in the pool)", pool_size() == 1)
    txid = [e for e in pB["log"] if e.get("sent")][-1]["txid"]
    check("B: a real txid was recorded", len(txid) >= 64)

    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    time.sleep(5); draw("/stop_mining")
    tx = requests.post(DR + "/get_transactions",
                       json={"txs_hashes": [txid.split(",")[0]]}, timeout=30).json()
    on_chain = bool(tx.get("txs")) and not tx["txs"][0].get("in_pool", True)
    check("B: the relayed tx confirmed on-chain", on_chain)

    step("D. re-running a completed batch relays nothing again")
    before = pool_size()
    codeD, _ = run_broadcast(signed_dir, prog)
    check("D: completed batch exits 0 without re-broadcasting",
          codeD == 0 and pool_size() == before)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    os.chdir("/")
    for p in procs:
        try:
            p.terminate(); p.wait(timeout=10)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    for f in FAILURES:
        print("  -", f)
print(f">>> SHIPPED broadcast main() AGAINST REAL BINARIES: {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
