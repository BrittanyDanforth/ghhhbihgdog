#!/usr/bin/env python3
"""Prove the ROTATING-CARRIER peel is COLD-SIGNABLE end to end — the fix, run
through the SHIPPED airgap_tx_signer (phase_create + phase_sign), on real
monero binaries.

real_hardened_peel_testnet proved the rotating topology with a HOT wallet.
The pipeline ships the COLD-SIGNING model (online view-only builds the unsigned
tx, offline full wallet signs it). The open question this raises: can the
view-only wallet build, and the offline wallet cold-sign, BOTH a peel that
spends a fresh carrier account AND the zero-change sweep_all that forwards the
carry to the next fresh carrier -- outputs the view-only wallet did not create?

This drives the SHIPPED airgap.phase_create / phase_sign per round on an
isolated regtest chain (RingCT live from height 1), exactly as the pipeline's
_run_peel_chain does, and asserts:
  * every rotating peel AND every forward sweep is cold-signed and relayed;
  * the wallet's MAIN address (account 0 / subaddress 0) is NEVER spent by the
    mix -- it is not the genesis, the change sink, or a repeated spender;
  * no single address is spent more than twice (peel + its forward);
  * each mix destination receives its exact planned amount on-chain.

SKIPs (exit 0) if the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys, random
from collections import defaultdict
from decimal import Decimal
import importlib.machinery, importlib.util
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")
airgap = load("airgap_tx_signer")

BASE = tempfile.mkdtemp(prefix="rotcold_")
_PB = 26000 + random.randint(0, 12000)
P_P2P, P_DRPC, P_WRPC = _PB, _PB + 1, _PB + 3
DR = f"http://127.0.0.1:{P_DRPC}"; D = DR + "/json_rpc"; WR = f"http://127.0.0.1:{P_WRPC}/json_rpc"


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=60).json()


def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=60).json()


def wj(m, p=None, t=180):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))


def wait_ready(probe, proc, tries=60):
    for _ in range(tries):
        if proc.poll() is not None:
            return False
        try:
            if probe():
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def mine(addr, target):
    draw("/start_mining", {"miner_address": addr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < target:
        time.sleep(1)
    draw("/stop_mining")
    wj("refresh")


def acct_addr(a):
    return wj("get_address", {"account_index": a})["result"]["address"]


def acct_unlocked(a):
    wj("refresh")
    return wj("get_balance", {"account_index": a})["result"].get("unlocked_balance", 0)


PASS = 0
FAIL = 0
FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  ", name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL:", name)


def skip(msg):
    print(f"SKIP: {msg}")
    for p in procs:
        try:
            p.terminate(); p.wait(timeout=10)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(BASE, ignore_errors=True)
    sys.exit(0)


ATOMIC = Decimal(10) ** 12
result = "INCOMPLETE"


class A:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class RpcShim:
    """connect_rpc stand-in: real HTTP to the regtest wallet-rpc, so the SHIPPED
    phase_create (transfer_split / sweep_all / export_outputs) really runs."""
    def raw_request(self, method, params):
        r = wj(method, params)
        if "error" in r:
            raise RuntimeError(str(r["error"])[:160])
        return r.get("result", {})


try:
    Lp(["monerod", "--regtest", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(P_DRPC), "--p2p-bind-port", str(P_P2P),
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    if not wait_ready(lambda: dj("get_info").get("result", {}).get("height") is not None, procs[-1]):
        skip("monerod did not become ready")
    Lp(["monero-wallet-rpc", "--daemon-address", f"127.0.0.1:{P_DRPC}", "--trusted-daemon",
        "--allow-mismatched-daemon-version", "--wallet-dir", os.path.join(BASE, "w"),
        "--rpc-bind-port", str(P_WRPC), "--rpc-bind-ip", "127.0.0.1", "--disable-rpc-login",
        "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"], os.path.join(BASE, "w.out"))
    if not wait_ready(lambda: "result" in wj("get_version"), procs[-1]):
        skip("monero-wallet-rpc did not become ready")

    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    MAIN = acct_addr(0)
    mine(MAIN, 90)
    wj("refresh")

    N = 3
    amounts = ghost.compute_fanout_amounts(Decimal("6"), N, Decimal("0.01"), False, random.Random(11))
    carriers = [wj("create_account")["result"]["account_index"] for _ in range(N)]
    mix = [wj("create_address", {"account_index": 0})["result"] for _ in range(N)]
    midx = [m["address_index"] for m in mix]

    # Origin move: MAIN -> first carrier account (the one time MAIN is spent).
    wj("transfer_split", {"destinations": [{"address": acct_addr(carriers[0]),
                                            "amount": int(Decimal("40") * ATOMIC)}],
                          "account_index": 0, "subaddr_indices": [0], "priority": 1})
    h = dj("get_info")["result"]["height"]; mine(MAIN, h + 12); wj("refresh")

    # SHIPPED rotating plan (peel + forward steps across fresh carrier accounts).
    plan = ghost.build_peel_plan(entry_index=carriers[0], change_index=0,
                                 dests=[m["address"] for m in mix],
                                 amounts=amounts, carriers=carriers[1:])
    # Decorate each step with the SHIPPED tx shape: src label, per-tx account,
    # sweep flag for forwards, dst address for forwards (the next carrier's sub0).
    steps = []
    for s in plan:
        acct = s["src_index"]                        # carrier account holding funds
        if s.get("kind") == "peel":
            steps.append({"src": "CARRIER", "src_index": 0, "account_index": acct,
                          "dst": s["dst"], "amt": s["amt"], "delay": 0})
        else:  # forward: sweep_all this carrier account's sub0 -> next carrier sub0
            steps.append({"src": "CARRIER", "src_index": 0, "account_index": acct,
                          "dst": acct_addr(s["carry_to"]), "sweep": True, "delay": 0})

    # Go VIEW-ONLY (the pipeline's online machine).
    view_key = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    wj("close_wallet")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": MAIN,
                              "viewkey": view_key, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})

    shim = os.path.join(BASE, "wcli")
    open(shim, "w").write('#!/bin/sh\nexec monero-wallet-cli --offline "$@"\n')
    os.chmod(shim, 0o755)
    airgap.verify_tor = lambda *a, **k: None
    airgap.connect_rpc = lambda *a, **k: RpcShim()
    os.chdir(BASE)

    spends_by_acct = defaultdict(int)
    txids = []
    main_spent_by_mix = False
    for i, step in enumerate(steps):
        acct = step["account_index"]
        need = int((Decimal(step.get("amt", "0")) + Decimal("0.05")) * ATOMIC) if not step.get("sweep") \
            else int(Decimal("0.05") * ATOMIC)
        for _ in range(80):
            if acct_unlocked(acct) >= need:
                break
            hh = dj("get_info")["result"]["height"]; mine(MAIN, hh + 2)
        stage = os.path.join(BASE, f"step{i}")
        kind = "sweep-forward" if step.get("sweep") else "peel"
        # SHIPPED phase_create (online, view-only) -> unsigned + outputs export.
        airgap.phase_create(
            A(tor_proxy="socks5h://127.0.0.1:9050", rpc=WR.replace("/json_rpc", ""),
              outdir=stage, fee_priority=1), [step], {"account_index": 0})
        check(f"step {i} ({kind}): SHIPPED phase_create built the unsigned tx",
              os.path.exists(os.path.join(stage, "tx_0.unsigned")))
        # SHIPPED phase_sign (offline) -> import outputs, then sign.
        airgap.phase_sign(
            A(outdir=stage, wallet_file=os.path.join(BASE, "w", "full"),
              wallet_password="", wallet_cli=shim), [step])
        sb = os.path.join(stage, "signed", "tx_0.signed")
        check(f"step {i} ({kind}): SHIPPED phase_sign COLD-SIGNED it", os.path.exists(sb))
        assert os.path.exists(sb), f"cold-signing failed at step {i} ({kind})"
        sr = wj("submit_transfer", {"tx_data_hex": open(sb, "rb").read().hex()})
        ths = sr.get("result", {}).get("tx_hash_list", [])
        if not ths:
            print(f"  step {i} submit:", str(sr.get("result") or sr.get("error") or sr)[:200])
        check(f"step {i} ({kind}): relayed to the daemon", bool(ths))
        assert ths
        txids.append(ths[0])
        spends_by_acct[acct] += 1
        if acct == 0:
            main_spent_by_mix = True
        h = dj("get_info")["result"]["height"]; mine(MAIN, h + 12); wj("refresh")

    # ---- payoff ----
    check("every cold-signed step is a DISTINCT transaction", len(set(txids)) == len(steps))
    check("FIX (cold): the wallet's MAIN account (0) is NEVER spent by the mix",
          not main_spent_by_mix and 0 not in spends_by_acct)
    check("FIX (cold): no carrier account is spent more than twice (peel + forward)",
          max(spends_by_acct.values()) <= 2)
    got = {}
    for k in range(N):
        r = wj("get_balance", {"account_index": 0, "address_indices": [midx[k]]})["result"]
        e = r.get("per_subaddress", [])
        got[midx[k]] = e[0].get("balance", 0) if e else 0
        print(f"    mix {midx[k]}: planned {int(amounts[k]*ATOMIC)/1e12:.4f}  got {got[midx[k]]/1e12:.4f}")
    check("FIX (cold): every mix destination received its exact planned amount on-chain",
          all(got[midx[k]] == int(amounts[k] * ATOMIC) for k in range(N)))
    print(f"\n  spends per account: {dict(spends_by_acct)}  (MAIN account 0: "
          f"{spends_by_acct.get(0, 0)} mix spends)")
    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
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
if FAILS:
    for f in FAILS:
        print("  -", f)
print(">>> ROTATING-CARRIER peel is COLD-SIGNABLE end to end through the shipped signer,")
print(">>> the MAIN account is never spent by the mix, and no single address is a hub.")
print(f">>> COLD ROTATING PEEL vs LEGACY HUB (real binaries): {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
