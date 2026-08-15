#!/usr/bin/env python3
"""Collect REAL pipeline verification data into JSON for the dashboard.
Runs the actual test suites and a live testnet cold-signing round-trip against
real monero binaries, and records real metrics -- nothing is fabricated.

Usage: python3 tests/collect_dashboard_data.py [out.json]
"""
import subprocess, os, sys, re, time, json, tempfile, shutil, signal
import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "tests", "dashboard_data.json")

def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, **kw)

data = {"generated_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "suites": [], "roundtrip": {}, "fee_estimate": {}, "env": {}, "fake_to_real": []}

# ---- environment / provenance --------------------------------------------
data["env"]["monero"] = (sh(["monerod", "--version"]).stdout.strip().splitlines() or ["(absent)"])[0]
data["env"]["commit"] = sh(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
data["env"]["branch"] = sh(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
data["env"]["commits_this_branch"] = sh(["git", "rev-list", "--count", "98313a2..HEAD"]).stdout.strip()
data["env"]["files_changed"] = len(sh(["git", "diff", "--name-only", "98313a2..HEAD"]).stdout.split())

# ---- run the fast test suites --------------------------------------------
for suite in ("test_units.py", "test_integration.py", "test_realfns.py", "test_cli_flags.py"):
    p = sh([sys.executable, os.path.join("tests", suite)], timeout=180)
    m = re.search(r"RESULT:\s*(\d+)\s*passed,\s*(\d+)\s*failed", p.stdout)
    passed, failed = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    data["suites"].append({"name": suite, "passed": passed, "failed": failed,
                           "kind": "mock" if suite != "test_cli_flags.py" else "cli",
                           "ok": failed == 0 and m is not None})

# ---- live testnet cold-signing round-trip (real binaries) ----------------
def _round_trip():
    if shutil.which("monerod") is None:
        return {"skipped": True}
    BASE = tempfile.mkdtemp(prefix="dash_")
    DR = "http://127.0.0.1:28071"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:28073/json_rpc"
    def dj(m, p=None):
        b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
        return requests.post(D, json=b, timeout=40).json()
    def draw(path, body=None): return requests.post(DR + path, json=body or {}, timeout=40).json()
    def wj(m, p=None, t=120):
        b = {"jsonrpc": "2.0", "id": "0", "method": m}; b.update({"params": p} if p is not None else {})
        return requests.post(WR, json=b, timeout=t).json()
    procs = []
    def Lp(cmd, log): procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))
    r = {"skipped": False, "steps": []}
    t_all = time.time()
    try:
        Lp(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "n"),
            "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28071", "--p2p-bind-port", "28070",
            "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
            "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
        for _ in range(45):
            time.sleep(1)
            try:
                if dj("get_info").get("result", {}).get("height") is not None: break
            except Exception: pass
        Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28071", "--trusted-daemon",
            "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", "28073", "--rpc-bind-ip", "127.0.0.1",
            "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"], os.path.join(BASE, "w.out"))
        for _ in range(45):
            time.sleep(1)
            try:
                if "result" in wj("get_version"): break
            except Exception: pass

        t = time.time()
        wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
        faddr = wj("get_address", {"account_index": 0})["result"]["address"]
        draw("/start_mining", {"miner_address": faddr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
        while dj("get_info")["result"]["height"] < 85: time.sleep(2)
        draw("/stop_mining"); wj("refresh")
        r["mine_seconds"] = round(time.time() - t, 1)
        r["blocks_mined"] = dj("get_info")["result"]["height"]
        r["funded_atomic"] = int(wj("get_balance", {"account_index": 0})["result"]["unlocked_balance"])
        r["steps"].append({"k": "fund", "ok": r["funded_atomic"] > 0, "detail": f'{r["funded_atomic"]/1e12:.4f} XMR unlocked'})
        # real per-priority fees[] from the daemon
        fe = dj("get_fee_estimate").get("result", {})
        data["fee_estimate"] = {"fee": fe.get("fee"), "fees": fe.get("fees")}
        vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
        kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
        wj("close_wallet")

        wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": faddr, "viewkey": vk, "password": ""})
        wj("refresh")
        if kimages: wj("import_key_images", {"signed_key_images": kimages})
        # multi-destination fan-out (the real Stage-4 shape): 3 outputs
        dests = [wj("create_address", {"account_index": 0})["result"]["address"] for _ in range(3)]
        tr = wj("transfer_split", {"destinations": [{"amount": 100000000000, "address": a} for a in dests],
                                   "account_index": 0, "priority": 1, "get_tx_hex": False, "do_not_relay": True})
        uts = tr.get("result", {}).get("unsigned_txset", "")
        r["unsigned_txset_hexlen"] = len(uts)
        r["fanout_outputs"] = len(dests)
        r["steps"].append({"k": "transfer_split", "ok": bool(uts), "detail": f"{len(dests)} dests -> unsigned_txset {len(uts)} hex"})

        work = os.path.join(BASE, "work"); os.makedirs(work, exist_ok=True)
        open(os.path.join(work, "unsigned_monero_tx"), "wb").write(bytes.fromhex(uts))   # phase_sign hex->binary
        sp = subprocess.run(["monero-wallet-cli", "--testnet", "--offline", "--wallet-file", os.path.join(BASE, "w", "full"),
                             "--password", "", "--command", "sign_transfer"],
                            input="\n" + "y\n" * 3, capture_output=True, text=True, timeout=90, cwd=work)  # password-first
        signed = os.path.join(work, "signed_monero_tx")
        r["signed_bytes"] = os.path.getsize(signed) if os.path.exists(signed) else 0
        r["steps"].append({"k": "sign_transfer", "ok": os.path.exists(signed), "detail": f"signed_monero_tx {r['signed_bytes']} bytes"})
        if os.path.exists(signed):
            sr = wj("submit_transfer", {"tx_data_hex": open(signed, "rb").read().hex()})   # broadcast submit
            txids = sr.get("result", {}).get("tx_hash_list", [])
            r["txid"] = txids[0] if txids else None
            r["steps"].append({"k": "submit_transfer", "ok": bool(txids), "detail": (txids[0][:24] + "...") if txids else "no tx_hash_list"})
            if txids:
                draw("/start_mining", {"miner_address": faddr, "threads_count": 2, "do_background_mining": False, "ignore_battery": True})
                time.sleep(4); draw("/stop_mining")
                tx = requests.post(DR + "/get_transactions", json={"txs_hashes": [txids[0]]}, timeout=30).json()
                on = bool(tx.get("txs")); inpool = tx.get("txs", [{}])[0].get("in_pool") if on else None
                r["confirmed"] = bool(on and inpool is False)
                r["steps"].append({"k": "confirm", "ok": r["confirmed"], "detail": "mined into a block" if r["confirmed"] else "not confirmed"})
        r["total_seconds"] = round(time.time() - t_all, 1)
        r["success"] = all(s["ok"] for s in r["steps"])
    finally:
        for pr in procs:
            try: pr.send_signal(signal.SIGTERM); pr.wait(timeout=8)
            except Exception:
                try: pr.kill()
                except Exception: pass
        shutil.rmtree(BASE, ignore_errors=True)
    return r

data["roundtrip"] = _round_trip()

# ---- fake-to-real ledger (what stopped being fake) -----------------------
data["fake_to_real"] = [
    {"was": "sign_transfer stdin fed 'y' as the password", "now": "password-first stdin; verified end-to-end signing", "proof": "roundtrip sign_transfer"},
    {"was": "broadcast posted to daemon /sendrawtransaction (rejected)", "now": "wallet-rpc submit_transfer relays the signed tx-set", "proof": "roundtrip submit_transfer + confirm"},
    {"was": "unsigned hex written verbatim to wallet-cli (unparseable)", "now": "bytes.fromhex -> binary unsigned_monero_tx", "proof": "roundtrip sign_transfer"},
    {"was": "fee estimate on wallet-rpc (always fell back to a constant)", "now": "daemon get_fee_estimate per-priority fees[]", "proof": "fee_estimate fees[]"},
    {"was": "JoinMarket tumble output ignored (TODO, silent return [])", "now": "parse_jm_amounts parses outputs or fails loudly", "proof": "test_units jm:*"},
]

with open(OUT, "w") as f:
    json.dump(data, f, indent=2)
print("wrote", OUT)
print(json.dumps({"suites": data["suites"], "roundtrip_success": data["roundtrip"].get("success"),
                  "txid": data["roundtrip"].get("txid"), "fees": data["fee_estimate"]}, indent=2))
