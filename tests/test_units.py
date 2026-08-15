#!/usr/bin/env python3
"""Executable tests for the pure-Python (non-Monero-stack) logic I changed.
Loads the real extensionless scripts as modules and asserts real behavior."""
import sys, os, tempfile, importlib.util, importlib.machinery
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

# Run side-effecting file writes (integrity_chain.log) in a temp dir.
_scratch = tempfile.mkdtemp(prefix="gs_test_")
gs = load("gs_common.py")
airgap = load("airgap_tx_signer")
ghost = load("GhostSpiral")
bcast = load("broadcast_signed_xmr")
os.chdir(_scratch)

PASS = 0; FAIL = 0; FAILURES = []
def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")

def expect_exit(name, fn):
    """Assert fn() raises SystemExit (validation abort)."""
    try:
        fn(); check(name + " (should have exited)", False)
    except SystemExit:
        check(name, True)
    except Exception as e:
        check(name + f" (wrong exc {type(e).__name__}: {e})", False)

# ---------------------------------------------------------------------------
# airgap _validate_plan: new multi-dest + old single-dest + rejections
# ---------------------------------------------------------------------------
single = {"src": "A", "src_index": 0, "dst": "B", "amt": "1.5"}
multi = {"src": "A", "src_index": 0,
         "destinations": [{"address": "B", "amount": "0.5"},
                          {"address": "C", "amount": "0.5"}]}
try:
    airgap._validate_plan([single]); check("validate: single-dest ok", True)
except SystemExit:
    check("validate: single-dest ok", False)
try:
    airgap._validate_plan([multi]); check("validate: multi-dest ok", True)
except SystemExit:
    check("validate: multi-dest ok", False)
try:
    airgap._validate_plan([single, multi]); check("validate: mixed plan ok", True)
except SystemExit:
    check("validate: mixed plan ok", False)

expect_exit("validate: empty plan rejected", lambda: airgap._validate_plan([]))
expect_exit("validate: missing src rejected",
            lambda: airgap._validate_plan([{"dst": "B", "amt": "1"}]))
expect_exit("validate: missing dst/amt rejected",
            lambda: airgap._validate_plan([{"src": "A"}]))
expect_exit("validate: negative amt rejected",
            lambda: airgap._validate_plan([{"src": "A", "dst": "B", "amt": "-1"}]))
expect_exit("validate: unparsable amt rejected",
            lambda: airgap._validate_plan([{"src": "A", "dst": "B", "amt": "xyz"}]))
expect_exit("validate: empty destinations rejected",
            lambda: airgap._validate_plan([{"src": "A", "destinations": []}]))
expect_exit("validate: dest missing address rejected",
            lambda: airgap._validate_plan([{"src": "A", "destinations": [{"amount": "1"}]}]))
expect_exit("validate: dest zero amount rejected",
            lambda: airgap._validate_plan([{"src": "A", "destinations": [{"address": "B", "amount": "0"}]}]))

# ---------------------------------------------------------------------------
# airgap _compute_plan_fingerprint: consistent, format-aware, discriminating
# ---------------------------------------------------------------------------
fp1 = airgap._compute_plan_fingerprint([single, multi])
fp2 = airgap._compute_plan_fingerprint([single, multi])
check("fingerprint: deterministic", fp1 == fp2)
fp3 = airgap._compute_plan_fingerprint([single])
check("fingerprint: differs by content", fp1 != fp3)
# changing a destination amount must change the fingerprint (tamper detection)
multi_b = {"src": "A", "destinations": [{"address": "B", "amount": "0.5"},
                                        {"address": "C", "amount": "0.6"}]}
check("fingerprint: multi-dest tamper detected",
      airgap._compute_plan_fingerprint([multi]) != airgap._compute_plan_fingerprint([multi_b]))

# ---------------------------------------------------------------------------
# airgap _load_unsigned: dict-with-txs, bare list, error formats
# ---------------------------------------------------------------------------
import json
from pathlib import Path
p = Path(_scratch) / "u1.json"
p.write_text(json.dumps({"meta": {"account_index": 3}, "txs": [single]}))
txs, meta = airgap._load_unsigned(p)
check("load_unsigned: dict txs", txs == [single] and meta.get("account_index") == 3)
p.write_text(json.dumps([single, multi]))
txs, meta = airgap._load_unsigned(p)
check("load_unsigned: bare list", txs == [single, multi] and meta == {})

# ---------------------------------------------------------------------------
# Replicate phase_create's dests construction to verify the multi-dest branch
# produces correct atomic-unit RPC destinations (the create<->plan contract)
# ---------------------------------------------------------------------------
def build_dests(tx):
    if tx.get("destinations"):
        return [{"amount": int(Decimal(str(d["amount"])) * Decimal(10 ** 12)),
                 "address": d["address"]} for d in tx["destinations"]]
    return [{"amount": int(Decimal(tx["amt"]) * Decimal(10 ** 12)), "address": tx["dst"]}]
d_single = build_dests(single)
d_multi = build_dests(multi)
check("dests: single -> 1 dest atomic", d_single == [{"amount": 1_500_000_000_000, "address": "B"}])
check("dests: multi -> 2 dests atomic",
      d_multi == [{"amount": 500_000_000_000, "address": "B"},
                  {"amount": 500_000_000_000, "address": "C"}])

# ---------------------------------------------------------------------------
# GhostSpiral fetch_fee_from_daemon: per-priority array > base*mult > fallback
# ---------------------------------------------------------------------------
def with_estimate(est):
    ghost.daemon_fee_estimate = lambda *a, **k: est
    return ghost.fetch_fee_from_daemon("http://127.0.0.1:18081", None, 3)
# per-priority fees[] path: priority 3 -> fees[2] = 8000 per byte, *2000 bytes
fee = with_estimate({"fee": 1000, "fees": [1000, 4000, 8000, 20000]})
check("fee: uses per-priority fees[2]", fee == Decimal(8000 * 2000) / Decimal(10**12))
# base-only path: priority 3 -> base 1000 * multiplier(20) * 2000
fee = with_estimate({"fee": 1000})
check("fee: base x multiplier when no fees[]",
      fee == (Decimal(1000 * 2000) / Decimal(10**12)) * Decimal(20))
# empty -> fallback * multiplier
fee = with_estimate({})
check("fee: fallback when empty",
      fee == ghost.FALLBACK_FEE_XMR * Decimal(20))
# fees[] too short for priority -> falls back to base path
fee = with_estimate({"fee": 1000, "fees": [1000, 4000]})
check("fee: short fees[] falls through to base",
      fee == (Decimal(1000 * 2000) / Decimal(10**12)) * Decimal(20))

# ---------------------------------------------------------------------------
# gs_common daemon_fee_estimate: refuse non-localhost without proxy (no net)
# ---------------------------------------------------------------------------
check("daemon_fee_estimate: non-localhost + no proxy -> {}",
      gs.daemon_fee_estimate("http://1.2.3.4:18081", None) == {})

# ---------------------------------------------------------------------------
# GhostSpiral.parse_jm_amounts: real JoinMarket-output parser (de-stubbed)
# ---------------------------------------------------------------------------
DEST = "bc1qdestaddr000"
check("jm: parse BTC amount on dest line",
      ghost.parse_jm_amounts(f"Sending 0.50000000 BTC to {DEST} now", DEST) == [Decimal("0.50000000")])
check("jm: parse satoshi amount on dest line",
      ghost.parse_jm_amounts(f"sending 12345678 sats to {DEST}", DEST) == [Decimal("0.12345678")])
check("jm: ignores lines without dest",
      ghost.parse_jm_amounts("Sending 9.9 BTC to bc1qOTHER", DEST) == [])
check("jm: empty when nothing parseable",
      ghost.parse_jm_amounts(f"tumble complete for {DEST}", DEST) == [])
check("jm: dedups repeated amount",
      ghost.parse_jm_amounts(f"0.25 BTC to {DEST}\nsummary: 0.25 BTC to {DEST}", DEST) == [Decimal("0.25")])
check("jm: multiple distinct outputs",
      ghost.parse_jm_amounts(f"0.1 BTC to {DEST}\n0.2 BTC to {DEST}", DEST) == [Decimal("0.1"), Decimal("0.2")])

# ---------------------------------------------------------------------------
# gs_common.bech32_checksum_ok: REAL BTC checksum validation (not just charset)
# ---------------------------------------------------------------------------
check("bech32: valid mainnet passes", gs.bech32_checksum_ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
check("bech32: valid testnet passes", gs.bech32_checksum_ok("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"))
check("bech32: corrupted checksum fails", not gs.bech32_checksum_ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"))
check("bech32: legacy 1-addr fails", not gs.bech32_checksum_ok("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
check("bech32: mixed case fails", not gs.bech32_checksum_ok("bc1qw508D6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
check("bech32: empty fails", not gs.bech32_checksum_ok(""))
# Witness-structure rules (BIP350). A checksum test ALONE accepted all three of
# these; Bitcoin Core rejects them and BTC sent to them is unrecoverable.
check("bech32: v1 taproot (bech32m) passes",
      gs.bech32_checksum_ok("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))
check("bech32: v0 addr with bech32m checksum REJECTED",
      not gs.bech32_checksum_ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"))
check("bech32: v1 addr with bech32 checksum REJECTED",
      not gs.bech32_checksum_ok("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4"))
check("bech32: witness program too short REJECTED",
      not gs.bech32_checksum_ok("bc1pw5dgrnzv"))
check("bech32: empty witness program REJECTED",
      not gs.bech32_checksum_ok("bc1gmk9yu"))

# ---------------------------------------------------------------------------
# gs_common misc: validate_proxy, scrub_address, secure_hex
# ---------------------------------------------------------------------------
check("validate_proxy: socks5h ok",
      gs.validate_proxy("socks5h://127.0.0.1:9050") == {"http": "socks5h://127.0.0.1:9050",
                                                        "https": "socks5h://127.0.0.1:9050"})
expect_exit("validate_proxy: socks5 (no h) rejected",
            lambda: gs.validate_proxy("socks5://127.0.0.1:9050"))
expect_exit("validate_proxy: garbage rejected",
            lambda: gs.validate_proxy("http://x"))
check("scrub_address: truncates", gs.scrub_address("A" * 95).count(".") == 3)
check("scrub_address: short passthrough", gs.scrub_address("short") == "short")
check("secure_hex: length", len(gs.secure_hex(16)) == 32)

# ---------------------------------------------------------------------------
# gs_common integrity_log: real SHA-256 hash chain links prev->next
# ---------------------------------------------------------------------------
logp = Path(_scratch) / "chain.log"
h1 = gs.integrity_log("t", "one", log_path=logp)
h2 = gs.integrity_log("t", "two", log_path=logp)
lines = logp.read_text().splitlines()
check("integrity_log: two lines", len(lines) == 2)
check("integrity_log: line1 hash matches", lines[0].split(" | ")[0] == h1)
check("integrity_log: line2 hash matches", lines[1].split(" | ")[0] == h2)
# recompute the chain to prove tamper-evidence
import hashlib
prev = "0" * 64
recomputed_ok = True
for ln in lines:
    stored_hash, body = ln.split(" | ", 1)
    if hashlib.sha256((prev + body).encode()).hexdigest() != stored_hash:
        recomputed_ok = False; break
    prev = stored_hash
check("integrity_log: chain verifies", recomputed_ok)

# ---------------------------------------------------------------------------
# broadcast helpers: _is_localhost, _blob_sort_key
# ---------------------------------------------------------------------------
check("is_localhost: 127.0.0.1", bcast._is_localhost("http://127.0.0.1:18083/json_rpc"))
check("is_localhost: localhost", bcast._is_localhost("http://localhost:18083"))
check("is_localhost: ::1", bcast._is_localhost("http://[::1]:18083"))
check("is_localhost: remote false", not bcast._is_localhost("http://example.com:18083"))
check("is_localhost: onion false", not bcast._is_localhost("http://abc.onion:18083"))
check("blob_sort_key: tx_15", bcast._blob_sort_key(Path("tx_15.signed")) == 15)
check("blob_sort_key: tx_0", bcast._blob_sort_key(Path("tx_0.signed")) == 0)
check("blob_sort_key: malformed -> sentinel", bcast._blob_sort_key(Path("garbage.signed")) == 999999)

# ---------------------------------------------------------------------------
# null-safety pattern (mirrors GhostSpiral stage2 / thor route parsing):
# present-but-null keys must collapse to safe fallbacks, not crash
# ---------------------------------------------------------------------------
def parse_route(route):
    expected = route.get("expectedOutput") or "0"
    tx_info = route.get("transaction") or route.get("calldata") or {}
    dep = tx_info.get("depositAddress") or tx_info.get("to") or ""
    return expected, dep, Decimal(str(expected))
check("nullsafe: null transaction no crash",
      parse_route({"transaction": None, "expectedOutput": None})[1] == "")
check("nullsafe: null expectedOutput -> 0",
      parse_route({"transaction": {"to": "X"}, "expectedOutput": None})[2] == Decimal(0))
check("nullsafe: calldata fallback",
      parse_route({"transaction": None, "calldata": {"depositAddress": "Y"}, "expectedOutput": "1.2"})[1] == "Y")

# ---------------------------------------------------------------------------
# exit_strategy_simulator Bisq fallback: EUR must NOT be fabricated from the
# USD rate. If Bisq only quoted USD, the returned dict must have no xmr_eur/
# btc_eur keys (so main() refuses --currency eur instead of lying).
# ---------------------------------------------------------------------------
exitsim = load("exit_strategy_simulator")

def _fake_bisq(data_entries):
    """Monkeypatch safe_get to return a Bisq-shaped payload, run fetch_prices."""
    orig = exitsim.safe_get
    exitsim.safe_get = lambda url, proxy=None: (_ for _ in ()).throw(Exception("cg down")) \
        if "coingecko" in url else {"data": data_entries}
    try:
        return exitsim.fetch_prices(None)
    finally:
        exitsim.safe_get = orig

_usd_only = _fake_bisq([
    {"currencyCode": "XMR", "price": 0.004},
    {"currencyCode": "USD", "price": 60000},
])
check("exitsim: bisq usd-only has xmr_usd", "xmr_usd" in _usd_only)
check("exitsim: bisq usd-only OMITS xmr_eur (no fabrication)", "xmr_eur" not in _usd_only)
check("exitsim: bisq usd-only OMITS btc_eur", "btc_eur" not in _usd_only)
check("exitsim: bisq usd_val = 0.004*60000 = 240", _usd_only["xmr_usd"] == Decimal("240.00"))

_with_eur = _fake_bisq([
    {"currencyCode": "XMR", "price": 0.004},
    {"currencyCode": "USD", "price": 60000},
    {"currencyCode": "EUR", "price": 55000},
])
check("exitsim: bisq w/eur has xmr_eur", "xmr_eur" in _with_eur)
check("exitsim: bisq eur = 0.004*55000 = 220 (real EUR rate, not USD)",
      _with_eur["xmr_eur"] == Decimal("220.00"))
check("exitsim: bisq eur != usd (proves not fabricated)",
      _with_eur["xmr_eur"] != _with_eur["xmr_usd"])

# ---------------------------------------------------------------------------
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
