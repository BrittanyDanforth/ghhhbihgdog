#!/usr/bin/env python3
"""Origin-tracker against REAL monero binaries — not a simulation.

track_origin_attack.py builds a Python model of the mix graph and always
finds PRIMARY. That is honest about being a worst-case TRANSPARENT model
(see its own docstring) but it never touches a real blockchain, so a
skeptic can reasonably ask whether the "100%" is real.

This script drives the SAME shipped planners (compute_fanout_amounts,
build_peel_plan, select_fanout_targets, compute_hop_amount) against an
isolated real monerod + monero-wallet-rpc chain: real transactions, real
confirmations, real balances, real decoys, a real DAG hop round, a real
COLD-SIGNING round (the documented "decent opsec" workflow — spend key
air-gapped), and a real paranoia_mode artifact wipe. It measures the
origin-tracking attack from REAL data only, never a model:

  1. WITH THE WALLET'S OWN KEYS (operator self-view, forensic seizure, a
     compromised host, or a wallet file recovered later). Every "ins" and
     "outs" in the reconstructed graph below is a REAL measured balance
     delta or a REAL destination echoed back by a real transfer_split
     call against the real chain we just built — not assumed math. The
     attack functions imported from track_origin_attack.py run on this
     REAL graph.

  2. WITH "DECENT OPSEC" (cold-signing, spend key never on the online
     host). Runs the SHIPPED cold-signing protocol for real: full wallet
     exports view key + key images, closes; a VIEW-ONLY wallet (no spend
     key, ever) builds the unsigned txset; monero-wallet-cli signs
     air-gapped; the view-only wallet relays it. Then asks ONLY that
     view-only wallet, never reopening the spend key, whether the mix
     graph is still visible. It is — keeping the spend key offline
     protects against theft, not against an analyst reading the online
     wallet's own transaction records.

  3. AFTER A REAL paranoia_mode ARTIFACT WIPE. Seeds a scratch "operator
     working directory" with real GhostSpiral artifact files plus a real
     copy of the wallet files, runs paranoia_mode's actual
     wipe_gs_artifacts() (real secure-delete, not a dry run) against it,
     then opens a FRESH monero-wallet-rpc on the SURVIVING files to prove
     the wallet itself — and the whole mix graph — is still intact.
     (Only the artifact-wipe phase is exercised this way; MAC-spoofing,
     journal/log wiping and shell-history erasure need root and would
     modify this shared sandbox host, so they are out of scope here —
     they are also orthogonal to the on-chain finding either way.)

  4. AS A PASSIVE CHAIN OBSERVER WITH NO KEYS — the actual Monero threat
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

Out of scope, honestly: JoinMarket (needs a real counterparty market, not
fabricable here) and Tor/network-origin privacy (orthogonal to the
on-chain graph this script measures — this whole test only ever talks to
its own loopback daemon anyway).

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
# Randomise the port block per run so a lingering daemon/wallet from a previous
# run (or a back-to-back invocation) can't cause a bind collision -- the exact
# "connection refused" flake that a fixed port block produced.
_PB = 20000 + random.randint(0, 15000)
P_P2P, P_DRPC, P_WRPC, P_WRPC3 = _PB, _PB + 1, _PB + 3, _PB + 5
DR = f"http://127.0.0.1:{P_DRPC}"; D = DR + "/json_rpc"
WR = f"http://127.0.0.1:{P_WRPC}/json_rpc"


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


def wait_ready(probe, proc, what, tries=60):
    """Poll `probe` until it succeeds, aborting cleanly if the process dies.

    A daemon/wallet that never binds (a transient startup race, or a port
    still held by a previous run) used to sail past the old poll loop and
    then blow up with a raw ConnectionError traceback deep in mining. This
    turns that into an honest SKIP: environment flake, not a code failure.
    """
    for _ in range(tries):
        if proc.poll() is not None:
            return False, f"{what} process exited during startup (code {proc.returncode})"
        try:
            if probe():
                return True, ""
        except Exception:
            pass
        time.sleep(1)
    return False, f"{what} did not become ready within {tries}s"


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


try:
    Lp(["monerod", "--regtest", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(P_DRPC), "--p2p-bind-port", str(P_P2P),
        "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    ok, why = wait_ready(lambda: dj("get_info").get("result", {}).get("height") is not None,
                         procs[-1], "monerod")
    if not ok:
        skip(why)
    hf = dj("hard_fork_info").get("result", {})
    print(f"regtest hard fork version active from height 1: v{hf.get('version')} "
          f"(RingCT/CLSAG/view-tags active immediately, no ~625k-block mine needed)")

    Lp(["monero-wallet-rpc", "--daemon-address", f"127.0.0.1:{P_DRPC}", "--trusted-daemon",
        "--allow-mismatched-daemon-version",
        "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", str(P_WRPC), "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
       os.path.join(BASE, "w.out"))
    ok, why = wait_ready(lambda: "result" in wj("get_version"), procs[-1], "monero-wallet-rpc")
    if not ok:
        skip(why)

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
    # Scenario 1b: SEND fan-out + a REAL DAG hop round, WITH real decoys.
    # select_fanout_targets decides the decoy count and which outputs hop
    # (all of them -- no dead-end tell); compute_hop_amount decides the
    # real hop amount reserving the real fee. This is the "Maximum safe"
    # preset's second layer, executed for real.
    # ------------------------------------------------------------------
    print("\n=== REAL send fan-out + DAG hop round (with real decoys, real chain) ===")
    wallets_n = 4
    mix_pool = [wj("create_address", {"account_index": 0})["result"] for _ in range(wallets_n + ghost.DECOY_MAX + 2)]
    mix_addrs = [m["address"] for m in mix_pool]
    fanout_dests, hop_sources = ghost.select_fanout_targets(mix_addrs, set(), wallets_n,
                                                            random.Random(3).randint(ghost.DECOY_MIN, ghost.DECOY_MAX))
    n_decoys_used = len(fanout_dests) - wallets_n
    check("select_fanout_targets padded with real decoys beyond `wallets`",
          len(fanout_dests) > wallets_n)
    check("select_fanout_targets: every fan-out output is a hop source (no dead-end tell)",
          sorted(hop_sources) == sorted(fanout_dests))
    fanout_amounts = ghost.compute_fanout_amounts(Decimal("5"), len(fanout_dests),
                                                  Decimal("0.0024"), True, random.Random(4))
    check("shipped compute_fanout_amounts funded the real fan-out+DAG round", bool(fanout_amounts))
    fanout_by_addr = dict(zip(fanout_dests, fanout_amounts))
    fanout_idx = {m["address"]: m["address_index"] for m in mix_pool}
    fanout_atomic = [{"address": a, "amount": int((amt * ATOMIC).to_integral_value())}
                     for a, amt in fanout_by_addr.items()]
    r = wj("transfer_split", {"destinations": fanout_atomic, "account_index": 0,
                              "subaddr_indices": [0], "priority": 1})
    fanout_txids = r.get("result", {}).get("tx_hash_list", [])
    check("real fan-out with real decoys relayed as ONE transaction", bool(fanout_txids))
    if fanout_txids:
        REAL_TXIDS.append(fanout_txids[0])
    h = dj("get_info")["result"]["height"]
    mine(PRIMARY, h + 12)
    wj("refresh")
    fanout_outs = [(f"MIX_{fanout_idx[a]}", amt) for a, amt in fanout_by_addr.items()]
    RGRAPH.add_tx(["PRIMARY"], fanout_outs, "fanout")
    check("every real fan-out destination (including decoys) is really funded",
          all(subbal(fanout_idx[a])[0] > 0 for a in fanout_dests))

    hop_dst = wj("create_address", {"account_index": 0})["result"]["address"]
    hopped = 0
    unhopped = []
    for src_addr in hop_sources:
        src_idx = fanout_idx[src_addr]
        hop_amt = ghost.compute_hop_amount(fanout_by_addr[src_addr], Decimal("0.0024"))
        if hop_amt <= ghost.DUST_XMR:
            unhopped.append(src_addr)
            continue
        hop_atomic = int((hop_amt * ATOMIC).to_integral_value())
        rh = wj("transfer_split", {"destinations": [{"address": hop_dst, "amount": hop_atomic}],
                                   "account_index": 0, "subaddr_indices": [src_idx], "priority": 1})
        ths = rh.get("result", {}).get("tx_hash_list", [])
        if ths:
            hopped += 1
            REAL_TXIDS.append(ths[0])
            RGRAPH.add_tx([f"MIX_{src_idx}"],
                          [(f"HOP_{src_idx}", hop_amt),
                           (f"MIX_{src_idx}", fanout_by_addr[src_addr] - hop_amt)], "dag_hop")
    check("real DAG hop round: every fundable fan-out output (including decoys) hopped",
          hopped == len(hop_sources) - len(unhopped) and hopped > 0)
    print(f"  {len(fanout_dests)} fan-out outputs ({n_decoys_used} decoys beyond `wallets`), "
          f"{hopped} really hopped, {len(unhopped)} too small to hop")

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
    # "Decent opsec" check: the SHIPPED cold-signing protocol, executed
    # for real. The spend key never touches the online host again after
    # this point -- only view_key + exported key images do. If the mix
    # graph is STILL visible afterwards, cold-signing protected the FUNDS
    # (nobody can spend without the air-gapped key) but did NOT protect
    # the HISTORY (whoever holds the online view-only wallet sees it all).
    # ------------------------------------------------------------------
    print("\n=== REAL cold-signing round ('decent opsec': spend key goes air-gapped) ===")
    cold_dest = wj("create_address", {"account_index": 0})["result"]
    view_key = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    check("real export_key_images returned signed key images from the full wallet", bool(kimages))
    primary_before_cold, _ = subbal(0)

    wj("close_wallet")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": PRIMARY,
                              "viewkey": view_key, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})
    cold_amt = Decimal("0.8")
    cold_atomic = int((cold_amt * ATOMIC).to_integral_value())
    r = wj("transfer_split", {"destinations": [{"address": cold_dest["address"], "amount": cold_atomic}],
                              "account_index": 0, "subaddr_indices": [0], "priority": 1,
                              "get_tx_hex": False, "do_not_relay": True})
    uts = r.get("result", {}).get("unsigned_txset", "")
    check("VIEW-ONLY wallet (no spend key present) built the unsigned cold-sign txset", bool(uts))

    work = os.path.join(BASE, "coldsign")
    os.makedirs(work, exist_ok=True)
    if uts:
        open(os.path.join(work, "unsigned_monero_tx"), "wb").write(bytes.fromhex(uts))
    subprocess.run(
        ["monero-wallet-cli", "--offline", "--wallet-file", os.path.join(BASE, "w", "full"),
         "--password", "", "--command", "sign_transfer"],
        input="\n" + "y\n" * 6, cwd=work, capture_output=True, text=True, timeout=120)
    signed_path = os.path.join(work, "signed_monero_tx")
    check("monero-wallet-cli (spend key, offline/air-gapped) signed the cold TX",
          os.path.exists(signed_path))
    cold_txids = []
    if os.path.exists(signed_path):
        signed_hex = open(signed_path, "rb").read().hex()
        sr = wj("submit_transfer", {"tx_data_hex": signed_hex})
        cold_txids = sr.get("result", {}).get("tx_hash_list", [])
    check("the VIEW-ONLY wallet relayed the cold-signed tx (spend key never touched again)",
          bool(cold_txids))
    if cold_txids:
        REAL_TXIDS.append(cold_txids[0])
        h = dj("get_info")["result"]["height"]
        mine(PRIMARY, h + 12)
        wj("refresh")

    gt_cold = wj("get_transfer_by_txid", {"txid": cold_txids[0]}) if cold_txids else {}
    cold_dests = (gt_cold.get("result", {}).get("transfer") or {}).get("destinations") or []
    primary_after_cold, _ = subbal(0)
    print(f"  cold-signed tx's destination (read from the VIEW-ONLY wallet's OWN record, "
          f"no spend key present): {cold_dests}")
    print(f"  PRIMARY subaddr0 balance, read by the view-only wallet, before/after: "
          f"{primary_before_cold / 1e12:.4f} -> {primary_after_cold / 1e12:.4f} XMR")
    check("VIEW-ONLY wallet alone still reports the real cold-sign destination address+amount",
          bool(cold_dests) and cold_dests[0].get("address") == cold_dest["address"])
    check("VIEW-ONLY wallet alone still shows the real change landing back on subaddr 0",
          primary_after_cold != primary_before_cold)
    check("DECENT-OPSEC FINDING: air-gapping the spend key protects the FUNDS, not the GRAPH -- "
          "the online view-only wallet still reveals it",
          bool(cold_dests))

    # ------------------------------------------------------------------
    # REAL paranoia_mode artifact wipe. Seed a scratch "operator working
    # directory" with real GhostSpiral artifact filenames PLUS a real copy
    # of the wallet files, run the SHIPPED wipe_gs_artifacts() for real
    # (secure-delete, not --dry-run), then open a fresh wallet-rpc on
    # whatever survives to prove the wallet -- and the mix graph -- is
    # still there. MAC-spoofing / journal / shell-history phases need root
    # and would touch this shared sandbox host, so only the artifact-wipe
    # phase (paranoia_mode's own module function) runs here; that is also
    # the only phase that could plausibly destroy chain-graph evidence.
    # ------------------------------------------------------------------
    print("\n=== REAL paranoia_mode artifact wipe: does it also erase the wallet? ===")
    # Snapshot durable, per-subaddress evidence BEFORE the wipe: this is what
    # get_balance derives from the wallet's own output scan (baked into the
    # cache file), unlike get_transfer_by_txid's "destinations" annotation,
    # which this wallet-rpc build does not persist across a process restart --
    # a real, useful thing to have learned by actually testing it instead of
    # assuming it. Per-subaddress balances are the durable evidence a forensic
    # reader of the SAME wallet file would actually rely on.
    mix_check_idx = send_dests[0]["address_index"]
    primary_bal_pre_wipe, _ = subbal(0)
    mix_bal_pre_wipe, _ = subbal(mix_check_idx)
    check("snapshot: PRIMARY (subaddr 0) really holds accumulated change before the wipe",
          primary_bal_pre_wipe > 0)
    check("snapshot: the real send peel's first MIX destination really holds its planned amount",
          mix_bal_pre_wipe > 0)

    para = load("paranoia_mode")
    scratch = os.path.join(BASE, "opdir")
    os.makedirs(os.path.join(scratch, "unsigned"), exist_ok=True)
    artifact_files = {
        "unsigned_v1.json": "sensitive fan-out plan",
        "integrity_chain.log": "hash-chained action log",
        "monero-wallet-rpc.log": "wallet-rpc log",
        "wallet_meta.json": "GhostSpiral wallet metadata",
        "signed_manifest_v1.json": "signed manifest",
    }
    for fn, content in artifact_files.items():
        with open(os.path.join(scratch, fn), "w") as f:
            f.write(content)
    with open(os.path.join(scratch, "unsigned", "plan.json"), "w") as f:
        f.write("nested artifact under a wiped dir pattern")

    wallet_dir_real = os.path.join(BASE, "w")
    copied_wallet_files = []
    for fn in os.listdir(wallet_dir_real):
        if fn.startswith("full") or fn.startswith("view"):
            shutil.copy(os.path.join(wallet_dir_real, fn), os.path.join(scratch, fn))
            copied_wallet_files.append(fn)
    check("scratch operator dir seeded with real wallet files to wipe alongside artifacts",
          bool(copied_wallet_files))

    # CONFINE THE REAL WIPE. wipe_gs_artifacts hard-codes its search roots as
    # Path("."), Path.home() and ~/ghostspiral, ~/GhostSpiral, then adds
    # extra_dirs. Called naively from the repo it will really secure-delete any
    # matching artifact in the CWD and home dir -- and it did: an earlier run
    # of this test deleted the repo's own `renamethis1` fixture, which is in
    # paranoia_mode's pattern list. Point "." and "~" at throwaway empty dirs
    # for the duration of the call so the ONLY real root is our scratch sandbox.
    safe_home = os.path.join(BASE, "safe_home")
    safe_cwd = os.path.join(BASE, "safe_cwd")
    os.makedirs(safe_home, exist_ok=True)
    os.makedirs(safe_cwd, exist_ok=True)
    _prev_cwd = os.getcwd()
    _prev_home = os.environ.get("HOME")
    try:
        os.chdir(safe_cwd)
        os.environ["HOME"] = safe_home
        wipe_failures = para.wipe_gs_artifacts(False, extra_dirs=[scratch])
    finally:
        os.chdir(_prev_cwd)
        if _prev_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = _prev_home
    check("paranoia_mode's REAL artifact wipe (secure-delete, not dry-run) reported no failures",
          wipe_failures == 0)
    check("the confined wipe did NOT touch anything outside its sandbox "
          "(safe_cwd/safe_home stayed empty)",
          not os.listdir(safe_cwd) and not os.listdir(safe_home))

    remaining = set(os.listdir(scratch)) | {
        os.path.join("unsigned", f) for f in
        (os.listdir(os.path.join(scratch, "unsigned")) if os.path.isdir(os.path.join(scratch, "unsigned")) else [])
    }
    artifacts_survived = [fn for fn in artifact_files if fn in remaining]
    nested_survived = os.path.isdir(os.path.join(scratch, "unsigned"))
    wallet_survived = [fn for fn in copied_wallet_files if fn in remaining]
    print(f"  artifact files before wipe: {sorted(artifact_files)}")
    print(f"  artifact files still present after the REAL wipe: {artifacts_survived or 'none'}")
    print(f"  nested 'unsigned/' dir still present after the wipe: {nested_survived}")
    print(f"  wallet files still present after the REAL wipe: {sorted(wallet_survived)}")
    check("REAL wipe actually deleted every seeded GhostSpiral artifact file",
          not artifacts_survived)
    check("REAL wipe actually deleted the nested 'unsigned/' plan directory",
          not nested_survived)
    check("REAL wipe did NOT touch the wallet files (paranoia_mode's own pattern list "
          "never matches a Monero wallet filename)",
          sorted(wallet_survived) == sorted(copied_wallet_files))

    WR3 = f"http://127.0.0.1:{P_WRPC3}/json_rpc"
    def wj3(m, p=None, t=180):
        b = {"jsonrpc": "2.0", "id": "0", "method": m}
        b.update({"params": p} if p is not None else {})
        return requests.post(WR3, json=b, timeout=t).json()

    Lp(["monero-wallet-rpc", "--daemon-address", f"127.0.0.1:{P_DRPC}", "--trusted-daemon",
        "--allow-mismatched-daemon-version",
        "--wallet-dir", scratch, "--rpc-bind-port", str(P_WRPC3), "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w3.log"), "--log-level", "0"],
       os.path.join(BASE, "w3.out"))
    ok3, _why3 = wait_ready(lambda: "result" in wj3("get_version"), procs[-1],
                            "post-wipe monero-wallet-rpc")
    check("a fresh wallet-rpc process started against the POST-WIPE scratch dir", ok3)
    ro = wj3("open_wallet", {"filename": "full", "password": ""})
    check("post-wipe wallet-rpc opened the SURVIVING wallet file (it was never touched)",
          "result" in ro)
    wj3("refresh")
    bal3 = wj3("get_balance", {"account_index": 0}).get("result", {})
    check("the surviving wallet file's balance is fully intact after the REAL artifact wipe",
          bal3.get("balance", 0) > 0)
    def subbal3(idx):
        r = wj3("get_balance", {"account_index": 0, "address_indices": [idx]}).get("result", {})
        e = r.get("per_subaddress", [])
        return (e[0].get("balance", 0), e[0].get("unlocked_balance", 0)) if e else (0, 0)

    primary_bal_post_wipe, _ = subbal3(0)
    mix_bal_post_wipe, _ = subbal3(mix_check_idx)
    txids_known = wj3("get_transfers", {"out": True}).get("result", {}).get("out", [])
    txid_survived = send_txids[0] in {t.get("txid") for t in txids_known} if send_txids else False
    print(f"  post-wipe wallet balance: {bal3.get('balance', 0) / 1e12:.4f} XMR")
    print(f"  PRIMARY (subaddr 0) balance, before wipe -> after wipe: "
          f"{primary_bal_pre_wipe / 1e12:.4f} -> {primary_bal_post_wipe / 1e12:.4f} XMR")
    print(f"  MIX subaddr {mix_check_idx} balance, before wipe -> after wipe: "
          f"{mix_bal_pre_wipe / 1e12:.4f} -> {mix_bal_post_wipe / 1e12:.4f} XMR")
    print(f"  the first real send peel's txid is still in the reopened wallet's own history: "
          f"{txid_survived}")
    check("PARANOIA-MODE FINDING: PRIMARY's real accumulated-change balance survives the wipe "
          "byte-for-byte (durable evidence, from the wallet's own output scan)",
          primary_bal_post_wipe == primary_bal_pre_wipe)
    check("PARANOIA-MODE FINDING: the MIX destination's real balance survives the wipe too",
          mix_bal_post_wipe == mix_bal_pre_wipe)
    check("PARANOIA-MODE FINDING: the reopened wallet still lists the exact same real txid",
          txid_survived)

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
print(f">>> WITH 'DECENT OPSEC' (spend key air-gapped, cold-signed for real): the mix graph "
      f"is STILL visible from the online view-only wallet alone")
print(f">>> AFTER A REAL paranoia_mode ARTIFACT WIPE: the wallet file survives (by design) "
      f"and still reveals the SAME mix graph")
print(f">>> AS A PASSIVE CHAIN OBSERVER (no keys, real ring size {ring_size or '?'} "
      f"+ real RingCT): spender and amount are NOT recoverable from the raw tx alone")
print(f">>> REAL-BINARY ORIGIN TRACKER: {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
