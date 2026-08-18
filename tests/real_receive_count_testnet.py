#!/usr/bin/env python3
"""Prove --count mints INDEPENDENT receives on a real wallet, and that the
swap preparer refuses to reuse one across a batch.

WHY REAL BINARIES: the claim under test is about monero-wallet-rpc's account
model, and a fake RPC cannot settle it. create_receive_wallet gives each
receive its OWN account because change is returned to the SPENDING ACCOUNT's
subaddress 0 -- so two receives sharing an account pool their leftovers onto
one address. This asserts, against a real wallet:

  * --count N creates N accounts, none of them account 0 (whose subaddress 0
    IS the wallet's primary address),
  * each receive's subaddress belongs to its own account and the wallet
    resolves the index back to the same string the tool printed,
  * every account's subaddress 0 is DISTINCT, i.e. the change sinks really
    are separate rather than nominally so,
  * no label is written unless one is asked for -- the wallet file is the one
    artifact paranoia_mode never deletes,
  * thor_swap_preparer accepts exactly the N bundles this produced, and
    refuses the batch the old code would have built (one address, N amounts).

Isolated testnet (monerod --offline --fixed-difficulty 1). SKIPs (exit 0) if
the monero binaries aren't installed.
"""
import subprocess, time, os, json, shutil, tempfile, sys, types
import importlib.machinery, importlib.util
from decimal import Decimal
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


crw = load("create_receive_wallet")      # the SHIPPED minter
thor = load("thor_swap_preparer")        # the SHIPPED resolver
import gs_common

BASE = tempfile.mkdtemp(prefix="recvcnt_")
DR = "http://127.0.0.1:28281"
WPORT = 28283
WR = f"http://127.0.0.1:{WPORT}/json_rpc"
procs = []


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(DR + "/json_rpc", json=b, timeout=40).json()


def wj(m, p=None, t=180):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"),
                                  stderr=subprocess.STDOUT))


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


result = "INCOMPLETE"
try:
    Lp(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28281",
        "--p2p-bind-port", "28280", "--no-igd", "--hide-my-port",
        "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"],
       os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass

    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28281",
        "--trusted-daemon", "--wallet-dir", os.path.join(BASE, "w"),
        "--rpc-bind-port", str(WPORT), "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"),
        "--log-level", "0"], os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "rc", "password": "", "language": "English"})
    PRIMARY = wj("get_address", {"account_index": 0})["result"]["address"]
    print(f"  wallet primary = ...{PRIMARY[-8:]}")

    # The SHIPPED RPC wrapper, pointed at the real wallet-rpc, no Tor (this
    # daemon is a local isolated testnet).
    rpc = gs_common.connect_rpc(f"http://127.0.0.1:{WPORT}")

    # Silence only the network-side hooks; mint_one_receive itself is real.
    crw.newnym = lambda *a, **k: None

    N = 3
    outdir = os.path.join(BASE, "bundles")
    args = types.SimpleNamespace(account=None, label="", count=N,
                                 rpc=f"http://127.0.0.1:{WPORT}",
                                 output_dir=outdir)

    print(f"\n=== mint {N} receives through the SHIPPED mint_one_receive ===")
    bundles = [crw.mint_one_receive(rpc, args) for _ in range(N)]

    loaded = [gs_common.load_receive_bundle(str(f)) for _, f in bundles]
    accts = [b["account_index"] for b in loaded]
    addrs = [b["address"] for b in loaded]

    check(f"--count {N} wrote {N} bundles", len(bundles) == N)
    check("every bundle loads under the strict loader", len(loaded) == N)
    check("each receive got its OWN account (no shared change sink)",
          len(set(accts)) == N)
    check("no receive landed in account 0 (the wallet PRIMARY)",
          0 not in accts)
    check("the addresses are all distinct", len(set(addrs)) == N)
    check("no receive address IS the wallet primary", PRIMARY not in addrs)

    print("\n=== the REAL wallet agrees with every bundle ===")
    for b in loaded:
        r = wj("get_address", {"account_index": b["account_index"],
                               "address_index": [b["subaddress_index"]]})["result"]
        got = r["addresses"][0]["address"]
        check(f"acct {b['account_index']} idx {b['subaddress_index']} resolves "
              f"to the address the tool wrote", got == b["address"])
        v = wj("validate_address", {"address": b["address"],
                                    "any_net_type": False})["result"]
        check(f"...and the wallet calls it a real subaddress",
              v.get("valid") and v.get("subaddress") and not v.get("integrated"))

    # THE POINT of a fresh account: separate change sinks. Change lands on the
    # SPENDING account's subaddress 0, so those must be distinct addresses.
    sinks = []
    for a in accts:
        sinks.append(wj("get_address", {"account_index": a,
                                        "address_index": [0]})["result"]["addresses"][0]["address"])
    check("each account's subaddress 0 (its CHANGE SINK) is distinct",
          len(set(sinks)) == N)
    check("no change sink is the wallet's primary address",
          PRIMARY not in sinks)

    print("\n=== the wallet file carries NO label ===")
    accounts = wj("get_accounts")["result"]["subaddress_accounts"]
    labels = [a.get("label", "") for a in accounts if a["account_index"] in accts]
    check("no account created by this run is labelled",
          all(not l for l in labels))
    tagged = [l for l in labels if "GhostSpiral" in l or "Mix" in l]
    check("...and nothing names the tool in the wallet file", not tagged)

    print("\n=== the swap preparer accepts these and refuses reuse ===")
    paths = [str(f) for _, f in bundles]
    amounts = [Decimal("0.01"), Decimal("0.02"), Decimal("0.03")]
    got = thor.resolve_destinations(amounts, [], paths)
    check("thor accepts the N bundles --count produced", got == addrs)
    check("...resolving each to a DISTINCT destination", len(set(got)) == N)

    def refused(fn):
        try:
            fn(); return False
        except SystemExit:
            return True

    # exactly what the old code built: one bundle, N amounts
    check("thor REFUSES one bundle spread across N amounts",
          refused(lambda: thor.resolve_destinations(amounts, [], [paths[0]])))
    check("thor REFUSES an explicit repeat of a real address",
          refused(lambda: thor.resolve_destinations(
              amounts, [addrs[0], addrs[1], addrs[0]], [])))

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs:
        try: p.terminate()
        except Exception: pass
    time.sleep(1)
    for p in procs:
        try: p.kill()
        except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
print(f">>> --count RECEIVES AGAINST REAL BINARIES: {result}")
sys.exit(0 if result == "SUCCESS" else 1)
