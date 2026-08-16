#!/usr/bin/env python3
"""Origin-tracker against REAL monero binaries — not a simulation.

track_origin_attack.py builds a Python model of the mix graph and always
finds PRIMARY. That is honest about being a worst-case TRANSPARENT model
(see its own docstring) but it never touches a real blockchain, so a
skeptic can reasonably ask whether the "100%" is real.

This script drives the SAME shipped planners (compute_fanout_amounts,
build_peel_plan) against an isolated real monerod + monero-wallet-rpc
chain: real transactions, real confirmations, real balances. It measures
the origin-tracking attack TWO ways, both from REAL data, never a model:

  1. WITH THE WALLET'S OWN KEYS (operator self-view, forensic seizure, a
     compromised host, or a wallet file recovered later). Every "ins" and
     "outs" in the reconstructed graph below is a REAL measured balance
     delta or a REAL destination echoed back by a real transfer_split
     call against the real chain we just built — not assumed math. The
     attack functions imported from track_origin_attack.py run on this
     REAL graph.

  2. AS A PASSIVE CHAIN OBSERVER WITH NO KEYS — the actual Monero threat
     model. Runs on --regtest (hard fork v16 active from height 1, so
     RingCT/CLSAG/view-tags are real from the first block — reaching that
     hard fork on a fresh --testnet chain would need ~625,000 mined
     blocks, which isn't practical here). This script pulls the RAW bytes
     of a real relayed peel tx straight from the daemon
     (get_transactions, decode_as_json) and checks what is actually on
     the wire: a real ring of decoy key_offsets (not a spender address)
     and real RingCT commitments (not a plaintext amount). That is the
     real reason the "100%" figure does NOT transfer to an external
     observer on real Monero.

SKIPs (exit 0) if the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys, json
import importlib.machinery, importlib.util
from decimal import Decimal
import random
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name, filename=None):
    path = os.path.join(REPO, filename or name)
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")
tracker = load("track_origin_attack", os.path.join("tests", "track_origin_attack.py"))

BASE = tempfile.mkdtemp(prefix="realtrack_")
DR = "http://127.0.0.1:28301"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:28303/json_rpc"


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()


def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=40).json()


def wj(m, p=None, t=180):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))


def mine(addr, target):
    draw("/start_mining", {"miner_address": addr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < target:
        time.sleep(1)
    draw("/stop_mining")
    wj("refresh")


def subbal(idx):
    r = wj("get_balance", {"account_index": 0, "address_indices": [idx]})["result"]
    e = r.get("per_subaddress", [])
    return (e[0].get("balance", 0), e[0].get("unlocked_balance", 0)) if e else (0, 0)


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


ATOMIC = Decimal(10) ** 12
result = "INCOMPLETE"
ring_size = None
REAL_TXIDS = []                      # every real txid we relay, in order
GRAPH_LABEL = {}                     # real address -> symbolic label for printing


def real_peel_round(rgraph, entry_addr, entry_idx, change_idx, dests, amounts,
                    primary_addr, entry_label, carrier_label):
    """Execute a real peel plan: N real transfer_split calls, confirmation-
    gated between each exactly like the shipped orchestrator does. Every
    number that goes into rgraph is a REAL measured value: the destination
    amount is what the real transfer_split call actually requested and the
    daemon actually relayed, and the change amount is the REAL observed
    balance delta of the carrier subaddress after the tx confirmed."""
    dest_addrs = [d["address"] for d in dests]
    plan = ghost.build_peel_plan(entry_index=entry_idx, change_index=change_idx,
                                 dests=dest_addrs, amounts=amounts)
    txids = []
    for i, (p, amt) in enumerate(zip(plan, amounts)):
        planned_atomic = int((amt * ATOMIC).to_integral_value())
        src_label = entry_label if i == 0 else carrier_label
        if i > 0:
            need = planned_atomic + int(ATOMIC // 20)
            for _ in range(60):
                wj("refresh")
                if subbal(change_idx)[1] >= need:
                    break
                h = dj("get_info")["result"]["height"]
                mine(primary_addr, h + 2)
        carrier_before, _ = subbal(change_idx)
        dst_idx = next(d["address_index"] for d in dests if d["address"] == p["dst"])
        dst_before, _ = subbal(dst_idx)
        r = wj("transfer_split", {
            "destinations": [{"amount": planned_atomic, "address": p["dst"]}],
            "account_index": 0, "subaddr_indices": [p["src_index"]], "priority": 1,
        })
        ths = r.get("result", {}).get("tx_hash_list", [])
        if not ths:
            print(f"    peel {i} error:", str(r.get("result") or r)[:200])
        check(f"peel {i + 1}/{len(plan)} relayed as its own real transaction", bool(ths))
        if not ths:
            continue
        txids.append(ths[0])
        REAL_TXIDS.append(ths[0])
        h = dj("get_info")["result"]["height"]
        mine(primary_addr, h + 12)
        wj("refresh")
        dst_after, _ = subbal(dst_idx)
        carrier_after, _ = subbal(change_idx)
        real_dst_amt = Decimal(dst_after - dst_before) / ATOMIC
        real_change_amt = Decimal(carrier_after - carrier_before) / ATOMIC
        check(f"peel {i + 1}: destination REALLY received the exact planned atomic amount",
              (dst_after - dst_before) == planned_atomic)
        outs = [(f"MIX_{dst_idx}", real_dst_amt)]
        if real_change_amt > 0:
            outs.append((carrier_label, real_change_amt))
        rgraph.add_tx([src_label], outs, "peel")
    return txids


try:
    Lp(["monerod", "--regtest", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28301", "--p2p-bind-port", "28300",
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None:
                break
        except Exception:
            pass
    hf = dj("hard_fork_info").get("result", {})
    print(f"regtest hard fork version active from height 1: v{hf.get('version')} "
          f"(RingCT/CLSAG/view-tags active immediately, no ~625k-block mine needed)")

    Lp(["monero-wallet-rpc", "--daemon-address", "127.0.0.1:28301", "--trusted-daemon",
        "--allow-mismatched-daemon-version",
        "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28303", "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
       os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"):
                break
        except Exception:
            pass

    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    PRIMARY = wj("get_address", {"account_index": 0})["result"]["address"]
    GRAPH_LABEL[PRIMARY] = "PRIMARY"
    mine(PRIMARY, 90)
    wj("refresh")
    print(f"ENTRY/PRIMARY funded: {subbal(0)[0] / 1e12} XMR (unlocked {subbal(0)[1] / 1e12})")

    RGRAPH = tracker.Graph("real-chain", "mixed", "PRIMARY", "SEND/RECV", usable=Decimal("0"))

    # ------------------------------------------------------------------
    # Scenario 1: SEND peel. Real transfer_split calls, PRIMARY -> mix,
    # change confirmed back to subaddr 0 each round -- on a REAL chain.
    # ------------------------------------------------------------------
    print("\n=== REAL send-mode peel (PRIMARY -> mix, real regtest chain) ===")
    n_send = 4
    send_dests = [wj("create_address", {"account_index": 0})["result"] for _ in range(n_send)]
    send_amounts = ghost.compute_fanout_amounts(Decimal("6"), n_send, Decimal("0.0024"),
                                                False, random.Random(1))
    check("shipped compute_fanout_amounts funded the real send peel", bool(send_amounts))
    send_txids = real_peel_round(RGRAPH, PRIMARY, 0, 0, send_dests, send_amounts,
                                 PRIMARY, "PRIMARY", "PRIMARY")
    check("SEND peel produced one real txid per destination", len(send_txids) == n_send)

    # ------------------------------------------------------------------
    # Scenario 2: RECEIVE peel. Fund a FRESH subaddress with a real inbound
    # transfer (the operator's receive step), then peel FROM it; per shipped
    # build_peel_plan, change_index=0 -- so peels 1..N spend PRIMARY too.
    # ------------------------------------------------------------------
    print("\n=== REAL receive-mode peel (fresh sub -> mix, real regtest chain) ===")
    recv_sub = wj("create_address", {"account_index": 0})["result"]
    GRAPH_LABEL[recv_sub["address"]] = "RECV_SUB"
    recv_idx = recv_sub["address_index"]
    fund_r = wj("transfer_split", {
        "destinations": [{"amount": int(Decimal("5") * ATOMIC), "address": recv_sub["address"]}],
        "account_index": 0, "subaddr_indices": [0], "priority": 1,
    })
    fund_txids = fund_r.get("result", {}).get("tx_hash_list", [])
    check("real inbound payment to the fresh receive subaddress relayed", bool(fund_txids))
    if fund_txids:
        REAL_TXIDS.append(fund_txids[0])
    h = dj("get_info")["result"]["height"]
    mine(PRIMARY, h + 12)
    wj("refresh")
    check("receive subaddress is really funded on-chain (not simulated)",
          subbal(recv_idx)[0] > 0)

    n_recv = 4
    recv_dests = [wj("create_address", {"account_index": 0})["result"] for _ in range(n_recv)]
    recv_amounts = ghost.compute_fanout_amounts(Decimal("4.5"), n_recv, Decimal("0.0024"),
                                                False, random.Random(2))
    check("shipped compute_fanout_amounts funded the real receive peel", bool(recv_amounts))
    recv_txids = real_peel_round(RGRAPH, recv_sub["address"], recv_idx, 0, recv_dests,
                                 recv_amounts, PRIMARY, "RECV_SUB", "PRIMARY")
    check("RECEIVE peel produced one real txid per destination", len(recv_txids) == n_recv)

    # ------------------------------------------------------------------
    # WITH-KEYS attack on the REAL graph (real destinations, real measured
    # change deltas -- no Python-modelled amounts).
    # ------------------------------------------------------------------
    print("\n=== attacking the REAL on-chain graph (with wallet keys) ===")
    print(f"  real txs recorded: {len(RGRAPH.txs)}")
    for i, t in enumerate(RGRAPH.txs):
        outs = " + ".join(f"{a}:{amt:.4f}" for a, amt in t["outs"])
        print(f"    tx{i} {t['kind']:6} {','.join(t['ins'])} -> {outs}")

    real_gen = tracker.attack_genesis(RGRAPH)
    real_walk = tracker.attack_peel_change_walk(RGRAPH)
    real_rept = tracker.attack_repeated_spender(RGRAPH)
    print(f"\n  first real spend (genesis):     {real_gen}")
    print(f"  peel-change walk on REAL data:   {real_walk}")
    print(f"  repeated spender on REAL data:   {real_rept}")
    check("WITH KEYS: peel-change walk on REAL on-chain data names PRIMARY",
          real_walk == "PRIMARY")
    check("WITH KEYS: repeated spender on REAL on-chain data names PRIMARY",
          real_rept == "PRIMARY")
    check("WITH KEYS: the real SEND peel's first spend really is PRIMARY",
          RGRAPH.txs[0]["ins"] == ["PRIMARY"])
    check("WITH KEYS: the real RECEIVE peel's first spend really is RECV_SUB, not PRIMARY",
          any(t["ins"] == ["RECV_SUB"] for t in RGRAPH.txs))

    # ------------------------------------------------------------------
    # WITHOUT-KEYS attack: what a passive chain observer actually sees.
    # Pull the RAW transaction from the DAEMON (no wallet keys at all) for
    # one real relayed peel tx and check what is really on the wire.
    # ------------------------------------------------------------------
    print("\n=== what a KEYLESS chain observer sees on the SAME real tx (daemon only) ===")
    sample_txid = send_txids[0] if send_txids else REAL_TXIDS[0]
    raw_resp = requests.post(DR + "/get_transactions", json={
        "txs_hashes": [sample_txid], "decode_as_json": True,
    }, timeout=40).json()
    txs = raw_resp.get("txs", [])
    check("daemon returned the real relayed transaction", bool(txs))
    decoded = {}
    if txs:
        as_json = txs[0].get("as_json", "")
        decoded = json.loads(as_json) if as_json else {}
    vin = decoded.get("vin", [])
    vout = decoded.get("vout", [])
    rct_present = "rct_signatures" in decoded

    has_ring_offsets = any("key" in v and "key_offsets" in v.get("key", {}) for v in vin)
    has_spender_address = any(
        isinstance(v, dict) and any(
            isinstance(vv, dict) and "address" in vv for vv in v.values()
        ) for v in vin
    )
    has_plaintext_amount_out = any(
        isinstance(v, dict) and v.get("amount", 0) not in (0, None) for v in vout
    )
    ring_sizes = [len(v.get("key", {}).get("key_offsets", [])) for v in vin]
    print(f"  sample real txid: {sample_txid}  (tx version {decoded.get('version')})")
    print(f"  vin entries: {len(vin)}  ring size per input (key_offsets len): {ring_sizes}")
    print(f"  vout entries: {len(vout)}  rct/RingCT signature block present: {rct_present}")
    print(f"  does any vin carry a plaintext SPENDER ADDRESS?          {has_spender_address}")
    print(f"  does any vout carry a plaintext, non-zero AMOUNT field?  {has_plaintext_amount_out}")
    if rct_present:
        print(f"  rct_signatures fields (real commitments, not amounts): "
              f"{list(decoded.get('rct_signatures', {}).keys())}")

    check("REAL raw tx: inputs are ring signatures (key_offsets), never a spender address",
          has_ring_offsets and not has_spender_address)
    check("REAL raw tx: outputs carry NO plaintext amount (RingCT hides it)",
          not has_plaintext_amount_out)
    check("REAL raw tx: an RCT signature block is present (amounts are commitments, not values)",
          rct_present)
    check("REAL raw tx: ring size is Monero's real multi-decoy ring (>1), not a bare pointer",
          bool(ring_sizes) and min(ring_sizes) > 1)

    ring_size = max(ring_sizes) if ring_sizes else 1
    guess_rate = (100.0 / ring_size) if ring_size else 100.0
    print(f"\n  ring size on this real tx: {ring_size}")
    print(f"  a keyless observer's best blind guess at the true spender: "
          f"~{guess_rate:.1f}% (1-in-{ring_size}), vs 100% with the wallet's own keys")

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=10)
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
print(f"\n>>> WITH THE WALLET'S OWN KEYS (self-view / seized wallet): PRIMARY recovered "
      f"from REAL on-chain data — {'YES' if FAIL == 0 else 'INCOMPLETE'}")
print(f">>> AS A PASSIVE CHAIN OBSERVER (no keys, real ring size {ring_size or '?'} "
      f"+ real RingCT): spender and amount are NOT recoverable from the raw tx alone")
print(f">>> REAL-BINARY ORIGIN TRACKER: {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
