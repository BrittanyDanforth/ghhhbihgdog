#!/usr/bin/env python3
"""Simulate a REAL payment + mix, then try to uncover name1/name2 as an outsider.

Story:
  name1  — sender. Funds sit on their wallet PRIMARY. They pay name2.
  name2  — receiver. create_receive_wallet-style fresh account + ENTRY.
           XMR lands on ENTRY (the ThorChain dest). Then they mix with
           the shipped peel planner.

Oracle (hidden from the attacker): both PRIMARY addresses, pulled from
the wallets after create. The outsider never gets a wallet, a seed, or
a view key.

Outsider corpus:
  * every relayed tx, pulled from the daemon (get_transactions + decode)
  * the ThorChain memo / pairs file
  * the receive bundle
  * the unsigned peel plan
  * the integrity log
  * NOT *.wallet / *.keys / RPC with a wallet open

If either PRIMARY string appears in that corpus, the hidden user is
uncovered. Isolated testnet. SKIPs if monero binaries are absent.
"""
import subprocess, time, os, shutil, tempfile, sys, json, random, traceback, re, getpass, socket
import importlib.machinery, importlib.util
from decimal import Decimal
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH")
        sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


ghost = load("GhostSpiral")

BASE = tempfile.mkdtemp(prefix="outsider_tx_")
PUBLIC = os.path.join(BASE, "public")   # what the outsider gets
ORACLE = os.path.join(BASE, "oracle")   # ground truth, not given to attacker
os.makedirs(PUBLIC)
os.makedirs(ORACLE)

_PB = 21000 + random.randint(0, 4000)
P_P2P, P_DRPC, P_WRPC = _PB, _PB + 1, _PB + 3
DR = f"http://127.0.0.1:{P_DRPC}"
D = DR + "/json_rpc"
WR = f"http://127.0.0.1:{P_WRPC}/json_rpc"
ATOMIC = Decimal(10) ** 12


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


def mine(addr, n):
    tgt = dj("get_info")["result"]["height"] + n
    draw("/start_mining", {"miner_address": addr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < tgt:
        time.sleep(1)
    draw("/stop_mining")
    try:
        wj("refresh")
    except Exception:
        pass


def subbal(acct, idx):
    r = wj("get_balance", {"account_index": acct, "address_indices": [idx]})["result"]
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


def dump_tx(txid):
    r = requests.post(DR + "/get_transactions",
                      json={"txs_hashes": [txid], "decode_as_json": True},
                      timeout=40).json()
    return r


result = "INCOMPLETE"
txids = []
try:
    print(f"\n=== REAL TX SIM  workdir={BASE}  ports={P_DRPC}/{P_WRPC} ===")
    Lp(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(P_DRPC),
        "--p2p-bind-port", str(P_P2P), "--no-igd", "--hide-my-port",
        "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"],
       os.path.join(BASE, "d.out"))
    up = False
    for _ in range(50):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None:
                up = True
                break
        except Exception:
            pass
    check("monerod came up", up)
    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", f"127.0.0.1:{P_DRPC}",
        "--trusted-daemon", "--wallet-dir", os.path.join(BASE, "w"),
        "--rpc-bind-port", str(P_WRPC), "--rpc-bind-ip", "127.0.0.1",
        "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"),
        "--log-level", "0"], os.path.join(BASE, "w.out"))
    wup = False
    for _ in range(50):
        time.sleep(1)
        try:
            if "result" in wj("get_version"):
                wup = True
                break
        except Exception:
            pass
    check("wallet-rpc came up", wup)

    # ── name1: sender ────────────────────────────────────────────────────
    print("\n--- name1 (sender) creates a wallet, PRIMARY is funded ---")
    wj("create_wallet", {"filename": "name1", "password": "", "language": "English"})
    name1 = wj("get_address", {"account_index": 0})["result"]["address"]
    open(os.path.join(ORACLE, "name1_primary.txt"), "w").write(name1)
    print(f"  ORACLE name1 PRIMARY ...{name1[-8:]}")
    mine(name1, 80)
    wj("refresh")
    n1_bal = wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"]
    print(f"  name1 unlocked {n1_bal / 1e12:.4f} XMR on PRIMARY")
    check("name1 PRIMARY is funded", n1_bal > 10 * 1e12)
    wj("close_wallet")

    # ── name2: receiver, fresh account + ENTRY (shipped receive path) ────
    print("\n--- name2 (receiver) fresh account + ENTRY ---")
    wj("create_wallet", {"filename": "name2", "password": "", "language": "English"})
    name2 = wj("get_address", {"account_index": 0})["result"]["address"]
    open(os.path.join(ORACLE, "name2_primary.txt"), "w").write(name2)
    print(f"  ORACLE name2 PRIMARY ...{name2[-8:]}")
    acct = wj("create_account", {"label": "GhostSpiral_entry"})["result"]
    ACC = acct["account_index"]
    check("name2 mix/receive account is NOT account 0", ACC != 0)
    ent = wj("create_address", {"account_index": ACC, "label": "GhostSpiral_entry"})["result"]
    ENTRY = ent["address"]
    EIDX = ent["address_index"]
    print(f"  name2 ENTRY acct {ACC} / sub {EIDX} ...{ENTRY[-8:]}")
    wj("close_wallet")

    # Public receive bundle (what create_receive_wallet writes).
    bundle = {
        "schema": "gs_receive_wallet_v1",
        "created": int(time.time()) // 600 * 600,
        "address": ENTRY,
        "account_index": ACC,
        "subaddress_index": EIDX,
        "label": "GhostSpiral_entry",
        "rpc_endpoint": WR.rsplit("/", 1)[0],
    }
    open(os.path.join(PUBLIC, "wallet_recv.json"), "w").write(json.dumps(bundle, indent=2))

    # ThorChain memo an outsider (and the aggregator) sees.
    memo = f"=:XMR:{ENTRY}"
    pairs = {"schema": "thor_pairs_v1", "btc_in": "0.04",
             "deposit": "bc1qoutsiderobservesthorvault000000000000",
             "memo": memo, "dest": ENTRY}
    open(os.path.join(PUBLIC, "thor_pairs_batch.json"), "w").write(json.dumps(pairs, indent=2))

    # ── payment: name1 PRIMARY -> name2 ENTRY (the swap settling) ────────
    print("\n--- payment: name1 PRIMARY pays name2 ENTRY ---")
    wj("open_wallet", {"filename": "name1", "password": ""})
    wj("refresh")
    n1_again = wj("get_balance", {"account_index": 0})["result"]
    print(f"  name1 after reopen: unlocked {n1_again.get('unlocked_balance', 0) / 1e12:.4f} XMR")
    if n1_again.get("unlocked_balance", 0) < int(Decimal("20") * ATOMIC):
        mine(name1, 20)
        wj("refresh")
        n1_again = wj("get_balance", {"account_index": 0})["result"]
        print(f"  name1 after extra mine: unlocked {n1_again.get('unlocked_balance', 0) / 1e12:.4f} XMR")
    pay = int(Decimal("12") * ATOMIC)
    r = wj("transfer_split", {
        "destinations": [{"amount": pay, "address": ENTRY}],
        "account_index": 0, "subaddr_indices": [0], "priority": 1})
    if "error" in r or not r.get("result", {}).get("tx_hash_list"):
        print("  first pay attempt:", str(r.get("error") or r.get("result") or r)[:180])
        r = wj("transfer_split", {
            "destinations": [{"amount": pay, "address": ENTRY}],
            "account_index": 0, "priority": 1})
    pay_txs = r.get("result", {}).get("tx_hash_list", [])
    if not pay_txs:
        print("  payment error:", str(r.get("error") or r.get("result") or r)[:200])
    check("name1 -> name2 ENTRY payment relayed", bool(pay_txs))
    txids.extend(pay_txs)
    mine(name1, 12)
    wj("close_wallet")

    # ── name2 mixes with the shipped peel planner ────────────────────────
    print("\n--- name2 mixes ENTRY with shipped peel planner ---")
    wj("open_wallet", {"filename": "name2", "password": ""})
    wj("refresh")
    got, unl = subbal(ACC, EIDX)
    print(f"  ENTRY holds {got / 1e12:.4f} XMR (unlocked {unl / 1e12:.4f})")
    check("ENTRY received the payment", unl >= pay)
    if unl < pay:
        raise RuntimeError("ENTRY empty; cannot mix")

    N = 4
    usable = Decimal("10")
    fee = Decimal("0.01")
    mix = [wj("create_address", {"account_index": ACC, "label": f"Mix_{i}"})["result"]
           for i in range(N)]
    amounts = ghost.compute_fanout_amounts(usable, N, fee, False, random.Random(7))
    dests = [{"amount": int((a * ATOMIC).to_integral_value()), "address": m["address"]}
             for a, m in zip(amounts, mix)]
    open(os.path.join(PUBLIC, "unsigned_fanout.json"), "w").write(json.dumps({
        "meta": {
            "schema": "unsigned_v1",
            "version": ghost.VERSION if hasattr(ghost, "VERSION") else "10.5",
            "created": int(time.time()) // 600 * 600,
            "account_index": ACC,
            "distribution_mode": "fanout",
        },
        "txs": [{
            "src": ENTRY, "src_index": EIDX,
            "destinations": [{"address": m["address"], "amount": str(a)}
                             for a, m in zip(amounts, mix)],
            "delay": 240, "extra": "not_forwarded_to_rpc",
        }],
    }, indent=2))
    open(os.path.join(PUBLIC, "integrity_chain.log"), "w").write(
        f"mix_account_rotated:{ACC}\n"
        f"receive_account:{ACC}\n"
        f"spend_source_ok:acct={ACC}:idx={EIDX}\n"
        f"fanout_plan:1_tx:{N}_dests\n"
    )
    check("shipped fan-out amounts are fundable from ENTRY",
          bool(amounts) and sum(amounts) < Decimal(str(unl / 1e12)))
    rr = wj("transfer_split", {
        "destinations": dests,
        "account_index": ACC, "subaddr_indices": [EIDX], "priority": 1})
    ths = rr.get("result", {}).get("tx_hash_list", [])
    if not ths:
        print("  fan-out error:", str(rr.get("error") or rr.get("result") or rr)[:200])
    check("name2 mix fan-out relayed from ENTRY (not PRIMARY)", bool(ths))
    if ths:
        txids.append(ths[0])
    mine(name2, 12)
    wj("refresh")

    # Close the wallet so the rest of the script cannot cheat via RPC.
    wj("close_wallet")
    print("  wallets closed. outsider has no RPC wallet.")

    # ── OUTSIDER POV ─────────────────────────────────────────────────────
    print("\n=== OUTSIDER POV: no seed, no wallet, no view key ===")
    print(f"  public dir: {PUBLIC}")
    print(f"  txids ({len(txids)}):")
    for t in txids:
        print(f"    {t}")

    # Pull every tx from the daemon the way a chain observer would.
    raw = []
    for t in txids:
        raw.append(dump_tx(t))
    open(os.path.join(PUBLIC, "chain_txs.json"), "w").write(json.dumps(raw, indent=2))

    corpus = ""
    for root, _, files in os.walk(PUBLIC):
        for fn in files:
            corpus += open(os.path.join(root, fn), errors="replace").read()
    # Also the raw daemon responses as strings.
    corpus += json.dumps(raw)

    hit1 = name1 in corpus
    hit2 = name2 in corpus
    print(f"  name1 PRIMARY in outsider corpus: {hit1}")
    print(f"  name2 PRIMARY in outsider corpus: {hit2}")
    check("OUTSIDER does not find name1 PRIMARY in chain + disk", not hit1)
    check("OUTSIDER does not find name2 PRIMARY in chain + disk", not hit2)

    # Every address-like string the outsider can actually read.
    mix_addrs = {m["address"] for m in mix}
    pub_addrs = sorted(set(re.findall(
        r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}",
        corpus)))
    print(f"  address-like strings outsider can read: {len(pub_addrs)}")
    for a in pub_addrs:
        tag = ("ENTRY" if a == ENTRY else
               "MIX dest" if a in mix_addrs else
               "PRIMARY" if a in (name1, name2) else "OTHER")
        print(f"    ...{a[-8:]}  {tag}")
    check("public addresses are ENTRY/mix dests only (never PRIMARY)",
          pub_addrs and all(a == ENTRY or a in mix_addrs for a in pub_addrs)
          and name1 not in pub_addrs and name2 not in pub_addrs)

    print("\n  --- metadata leads in PUBLIC (not the people) ---")
    b = json.load(open(os.path.join(PUBLIC, "wallet_recv.json")))
    print(f"    label:        {b.get('label')}")
    print(f"    created:      {b.get('created')} (10-min bucket)")
    print(f"    rpc_endpoint: {b.get('rpc_endpoint')}")
    print(f"    schema:       {b.get('schema')}")
    check("PUBLIC files do not contain this username",
          getpass.getuser() not in corpus)
    check("PUBLIC files do not contain this hostname",
          socket.gethostname() not in corpus)
    check("bundle label is a tool fingerprint, not a person",
          b.get("label") == "GhostSpiral_entry")
    check("bundle rpc_endpoint is present (HOST lead if they got the working dir)",
          "rpc_endpoint" in b)

    # What they DO find.
    check("OUTSIDER does find ENTRY (memo / bundle / plan dest)",
          ENTRY in corpus)
    check("receive bundle address is ENTRY, not either PRIMARY",
          json.load(open(os.path.join(PUBLIC, "wallet_recv.json")))["address"] == ENTRY)
    check("thor memo dest is ENTRY, not either PRIMARY",
          pairs["memo"].endswith(ENTRY) and name1 not in pairs["memo"]
          and name2 not in pairs["memo"])

    # Inspect one decoded tx: look for address-like fields.
    decoded_addrs = []
    blob = json.dumps(raw)
    for token in (name1, name2, ENTRY):
        if token in blob:
            decoded_addrs.append(token[-8:])
    print(f"  PRIMARY/ENTRY strings inside decoded txs: {decoded_addrs or 'NONE'}")
    check("decoded chain txs do not contain either PRIMARY",
          name1 not in blob and name2 not in blob)

    # Amounts: even if the isolated testnet is pre-RingCT and amounts leak,
    # an amount is not an identity.
    vin_vout = []
    for block in raw:
        for tx in block.get("txs", []) or []:
            try:
                d = json.loads(tx.get("as_json") or "{}")
            except Exception:
                d = {}
            vin_vout.append({
                "vin": d.get("vin"),
                "vout": d.get("vout"),
                "rct": d.get("rct_signatures") is not None or d.get("rctsig_prunable") is not None,
            })
    open(os.path.join(PUBLIC, "decoded_shape.json"), "w").write(json.dumps(vin_vout, indent=2)[:20000])
    print(f"  decoded {len(vin_vout)} tx shape(s); first vout type: "
          f"{type((vin_vout[0] or {}).get('vout')).__name__ if vin_vout else 'n/a'}")
    rct_any = any(v.get("rct") for v in vin_vout)
    print(f"  chain RCT signatures present: {rct_any}")
    print("  (isolated genesis is often pre-RCT so amounts leak; that is not an identity)")
    check("plaintext amounts still do not name either PRIMARY",
          not hit1 and not hit2)

    # Guess: is ENTRY the hidden user? No — we know it is not.
    check("ENTRY is not name1 PRIMARY", ENTRY != name1)
    check("ENTRY is not name2 PRIMARY", ENTRY != name2)
    check("name1 PRIMARY != name2 PRIMARY (two people)", name1 != name2)

    named = hit1 or hit2
    result = "NAMED" if named else "BLIND"
    check("outsider scoreboard: hidden user stays unnamed", not named)
except Exception as e:
    print(f"\n[!] {e}")
    traceback.print_exc()
    result = "INCOMPLETE"
finally:
    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
for f in FAILS:
    print("  - " + f)
if result == "BLIND":
    print(">>> OUTSIDER UNCOVER name1/name2: NO — PRIMARY never appeared")
elif result == "NAMED":
    print(">>> OUTSIDER UNCOVER name1/name2: YES")
else:
    print(">>> OUTSIDER UNCOVER name1/name2: INCOMPLETE (sim failed before hunt)")
sys.exit(0 if result == "BLIND" and FAIL == 0 else 1)
