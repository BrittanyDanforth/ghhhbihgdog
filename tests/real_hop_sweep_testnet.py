#!/usr/bin/env python3
"""Prove a DAG hop leaves NO change, through the real cold-signing path.

WHY THIS EXISTS: a hop used to be a transfer_split for a fixed amount. The
amount has to be chosen before the fee is known, so the transaction always
left a remainder, and monerod returns a remainder to the ACCOUNT'S SUBADDRESS
0. At wallets=10 deep=2 that is 40 hops each depositing dust on one address --
the run's own convergence point, and something no amount of jittering hides,
because it is structural rather than statistical.

sweep_all is the correct primitive for a hop ("move everything from here to
there") and produces no change output at all. The claim can only be settled by
a real daemon, and only end-to-end: the online wallet is VIEW-ONLY, so the
sweep must survive being built there, signed on an air-gapped wallet by
monero-wallet-cli, and relayed back.

Drives the SHIPPED airgap_tx_signer.phase_create/phase_sign and the SHIPPED
GhostSpiral.build_dag_plan. Isolated testnet; SKIPs if binaries are absent.
"""
import subprocess, time, os, shutil, tempfile, sys, secrets as _pysecrets
import importlib.machinery, importlib.util
from decimal import Decimal
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


ghost = load("GhostSpiral")
airgap = load("airgap_tx_signer")

BASE = tempfile.mkdtemp(prefix="hopsweep_")
DR = "http://127.0.0.1:30141"; D = DR + "/json_rpc"; WP = 30143
WR = f"http://127.0.0.1:{WP}/json_rpc"
A = Decimal(10) ** 12


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=60).json()


def draw(p, b=None):
    return requests.post(DR + p, json=b or {}, timeout=60).json()


def wj(m, p=None, t=300):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def Lp(c, l):
    procs.append(subprocess.Popen(c, stdout=open(l, "w"), stderr=subprocess.STDOUT))


def mine(a, n):
    t = dj("get_info")["result"]["height"] + n
    draw("/start_mining", {"miner_address": a, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < t:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


class A_:
    def __init__(self, **kw): self.__dict__.update(kw)


result = "INCOMPLETE"
try:
    Lp(["monerod", "--testnet", "--offline", "--data-dir", BASE + "/n",
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "30141",
        "--p2p-bind-port", "30140", "--no-igd", "--hide-my-port",
        "--fixed-difficulty", "1", "--non-interactive", "--no-zmq",
        "--log-file", BASE + "/d.log", "--log-level", "0"], BASE + "/d.out")
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:30141",
        "--trusted-daemon", "--wallet-dir", BASE + "/w", "--rpc-bind-port", str(WP),
        "--rpc-bind-ip", "127.0.0.1", "--disable-rpc-login",
        "--log-file", BASE + "/w.log", "--log-level", "0"], BASE + "/w.out")
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    primary = wj("get_address", {"account_index": 0})["result"]["address"]
    mine(primary, 90)

    # The mix runs in a ROTATED account, as resolve_mix_account now arranges.
    ACC = wj("create_account", {"label": ""})["result"]["account_index"]
    check("mix runs in a rotated account (not the wallet's account 0)", ACC != 0)

    # Two fan-out outputs that will hop, and two hop targets.
    srcs = [wj("create_address", {"account_index": ACC})["result"] for _ in range(2)]
    tgts = [wj("create_address", {"account_index": ACC})["result"] for _ in range(2)]
    for s in srcs:
        wj("transfer_split", {"destinations": [{"amount": int(3 * A),
                                                "address": s["address"]}],
                              "account_index": 0, "subaddr_indices": [0], "priority": 1})
    mine(primary, 12)

    def bal(acc, idx):
        r = wj("get_balance", {"account_index": acc, "address_indices": [idx]})["result"]
        e = r.get("per_subaddress", [])
        return (e[0].get("balance", 0), e[0].get("unlocked_balance", 0)) if e else (0, 0)

    for s in srcs:
        print(f"  hop source acct{ACC}/sub{s['address_index']} = "
              f"{bal(ACC, s['address_index'])[0]/1e12} XMR")

    # THE SHIPPED PLANNER decides the hop shape.
    addr_index = {s["address"]: s["address_index"] for s in srcs}
    addr_index.update({t["address"]: t["address_index"] for t in tgts})
    hops = ghost.build_dag_plan(
        A_(dag_mixing=True), Decimal("0.0024"),
        [s["address"] for s in srcs],
        {s["address"]: Decimal("3") for s in srcs},
        {s["address"]: [t["address"] for t in tgts] for s in srcs},
        [t["address"] for t in tgts], addr_index, _pysecrets)
    check("the shipped planner produced a hop per source", len(hops) == 2)
    check("every planned hop is a SWEEP (no fixed amount)",
          all(h.get("sweep") is True and "amt" not in h for h in hops))

    # Go VIEW-ONLY: this is what the pipeline's online machine actually runs.
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    wj("close_wallet")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view",
                              "address": primary, "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})
    check("the view-only wallet still sees the hop sources",
          all(bal(ACC, s["address_index"])[1] > 0 for s in srcs))

    # Point the SHIPPED signer at this testnet.
    shim = os.path.join(BASE, "wcli-testnet")
    open(shim, "w").write('#!/bin/sh\nexec monero-wallet-cli --testnet --offline "$@"\n')
    os.chmod(shim, 0o755)

    class RpcShim:
        def raw_request(self, method, params):
            r = wj(method, params)
            if "error" in r:
                raise RuntimeError(str(r["error"])[:160])
            return r.get("result", {})

    airgap.verify_tor = lambda *a, **k: None
    airgap.connect_rpc = lambda *a, **k: RpcShim()
    os.chdir(BASE)

    relayed = []
    for i, hop in enumerate(hops):
        stage = os.path.join(BASE, f"hop{i}")
        args = A_(tor_proxy="socks5h://127.0.0.1:9050",
                  rpc=WR.replace("/json_rpc", ""), outdir=stage, fee_priority=1,
                  wallet_file=os.path.join(BASE, "w", "full"), wallet_password="",
                  wallet_cli=shim)
        # SHIPPED phase_create -- must take the sweep branch (sweep_all).
        airgap.phase_create(args, [hop], {"account_index": ACC})
        check(f"hop {i}: SHIPPED phase_create built the unsigned sweep",
              os.path.exists(os.path.join(stage, "tx_0.unsigned")))
        # SHIPPED phase_sign -- the air-gapped wallet signs a sweep.
        airgap.phase_sign(args, [hop])
        sp = os.path.join(stage, "signed", "tx_0.signed")
        check(f"hop {i}: SHIPPED phase_sign COLD-SIGNED the sweep",
              os.path.exists(sp))
        assert os.path.exists(sp)
        blob = open(sp, "rb").read().hex()
        sr = wj("submit_transfer", {"tx_data_hex": blob})
        hs = (sr.get("result") or {}).get("tx_hash_list", [])
        check(f"hop {i}: relayed to the daemon", bool(hs))
        assert hs
        relayed.append(hs[0])
        mine(primary, 12)

    # ---- THE MEASUREMENT --------------------------------------------------
    print()
    total_change = 0
    for i, txid in enumerate(relayed):
        tr = wj("get_transfer_by_txid", {"txid": txid, "account_index": ACC})
        ins = [t for t in (tr.get("result", {}).get("transfers") or [])
               if t.get("type") == "in"]
        back_to_0 = [t for t in ins if t.get("subaddr_index", {}).get("minor") == 0]
        total_change += sum(t.get("amount", 0) for t in back_to_0)
        print(f"  hop {i}: outputs returned to this account = "
              f"{[(t['subaddr_index']['minor'], t['amount']/1e12) for t in ins]}")

    check("ON-CHAIN: NO hop returned any change to the account's subaddress 0",
          total_change == 0)
    check("ON-CHAIN: every hop source was fully drained (a sweep leaves nothing)",
          all(bal(ACC, s["address_index"])[0] == 0 for s in srcs))
    moved = sum(bal(ACC, t["address_index"])[0] for t in tgts)
    check("ON-CHAIN: the swept value arrived at the hop targets",
          moved > int(Decimal("5.5") * A))
    print(f"  swept {moved/1e12} XMR onward; change to subaddr 0 across all hops: "
          f"{total_change/1e12} XMR")

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs:
        try: p.terminate(); p.wait(timeout=10)
        except Exception:
            try: p.kill()
            except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
for f in FAILS:
    print("  - " + f)
print(f">>> ZERO-CHANGE DAG HOPS AGAINST REAL BINARIES: {result}")
sys.exit(1 if FAIL or result != "SUCCESS" else 0)
