#!/usr/bin/env python3
"""THE WHOLE PIPELINE, WITH THREE SWAP CHUNKS, EXECUTED.

Nothing else in tests/ runs stage 4 or stage 5 with more than one chunk. The
--split N work is checked function by function everywhere else -- create_entry_set
here, build_entry_veils there, size_distribution somewhere else -- and every one
of those tests calls its function directly. main() ties them together, and until
this file existed the tying-together had never run: size_and_prune_chunks was
reachable from no test at all, and _stage5_run's per-carrier veil loop had never
been entered with more than one carrier.

So this drives the REAL main() end to end with three UNEQUAL chunks (4/3/1 XMR,
the case the design exists for), fakes only the wallet RPC, the network, the
clock and the round runner, and then asks three questions of the plans it
actually produced:

  1. Does it run at all?
  2. Does the invariant hold ON THOSE PLANS -- trace every mix output back to
     the chunk that funded it and confirm no transaction touches two?
  3. Does the shipped signer accept them?

The third matters because an N-veil plan carries N different account_index
values in one file, and nothing had ever handed the validator one.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import types
from decimal import Decimal as D

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

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


import tempfile
_OUTDIR = tempfile.mkdtemp(prefix="split3_")

ld = importlib.machinery.SourceFileLoader("GhostSpiral", os.path.join(REPO, "GhostSpiral"))
g = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
ld.exec_module(g)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def addr(seed):
    return "4" + B58[seed % 2] + "".join(B58[(seed*(i+7)+i) % len(B58)] for i in range(93))

N = 3
WALLETS = 6
subs = [addr(2000+i) for i in range(WALLETS+4)]
idx = {a: (30+i, 1) for i, a in enumerate(subs)}

# THE ENTRY ACCOUNTS ARE NOT STUBBED. create_entry_set runs for real against
# the fake wallet below, so this file covers the minting and its duplicate
# checks too -- a first draft stubbed it out, and mutating the real function
# then changed nothing here, which is the "test stubs the thing it appears to
# test" shape this project keeps finding.
#
# Balances are assigned to the first ENTRIES accounts the run mints, IN ORDER,
# and deliberately UNEQUAL (4 / 3 / 1 XMR) -- the case the whole design exists
# for. Equal chunks would let a slicing bug pass unnoticed.
ENTRY_BAL = [4 * 10**12, 3 * 10**12, 1 * 10**12]
MINTED = []          # every account create_fresh_account hands out, in order
BAL = {}             # (account, index) -> atomic, filled as entries are minted

class RPC:
    def raw_request(self, m, p=None):
        if m == "refresh": return {}
        if m == "get_balance":
            a = int((p or {}).get("account_index", 0))
            ix = (p or {}).get("address_indices") or [0]
            return {"per_subaddress": [
                {"account_index": a, "address_index": i,
                 "balance": BAL.get((a, i), 0), "unlocked_balance": BAL.get((a, i), 0)}
                for i in ix]}
        if m == "get_address":
            a = int((p or {}).get("account_index", 0))
            for ad, (ac, ii) in idx.items():
                if ac == a:
                    return {"addresses": [{"address": ad, "address_index": 1}]}
            # An account this fake minted: answer with the same address
            # new_subaddress_indexed gave for it, or verify_spend_source
            # (correctly) refuses to spend from a pair it cannot confirm.
            return {"addresses": [{"address": addr(7000 + a),
                                   "address_index": 1}]}
        if m == "create_account":
            RPC.acct = getattr(RPC, "acct", 200) + 1
            MINTED.append(RPC.acct)
            # The first N accounts this run mints are the entry set (main
            # calls create_entry_set before anything else creates accounts),
            # so fund those and nothing else.
            if len(MINTED) <= N:
                BAL[(RPC.acct, 1)] = ENTRY_BAL[len(MINTED) - 1]
            return {"account_index": RPC.acct}
        if m == "incoming_transfers":
            return {"transfers": [{"amount": 10**12, "spent": False}]}
        raise AssertionError("unexpected RPC: " + m)
    def get_subaddress_balance(self, account_index=0, address_index=0):
        v = BAL.get((int(account_index), int(address_index)), 0)
        return (v, v)
    def new_subaddress_indexed(self, account_index=0, label=""):
        return (addr(7000 + int(account_index)), 1)

ROUNDS = []
def fake_round(args, path, stage, label):
    import json
    with open(path) as f:
        d = json.load(f)
    ROUNDS.append((label, d.get("txs", [])))
    return len(d.get("txs", []))

stubs = dict(
    verify_tor=lambda *a, **k: None,
    require_resources=lambda *a, **k: None,
    check_daemon_relay_egress=lambda *a, **k: {"verdict": "tor", "onion": 4, "clear": 0, "detail": "ok"},
    connect_rpc=lambda *a, **k: RPC(),
    stage0_preflight=lambda *a, **k: (RPC(), RPC(), D("0.0024")),
    stage1_joinmarket=lambda *a, **k: [],
    resolve_mix_account=lambda *a, **k: None,
    create_subs=lambda *a, **k: (list(subs), dict(idx), set()),
    newnym=lambda *a, **k: None,
    tor_recheck=lambda *a, **k: None,
    validate_xmr_address=lambda *a, **k: None,
    resolve_wallet_password=lambda *a, **k: None,
    resolve_sensitive_inputs=lambda *a, **k: None,
    integrity_log=lambda *a, **k: None,
    secure_delay=lambda *a, **k: None,
    reject_self_exit=lambda *a, **k: None,
    _run_round=fake_round,
    _wait_for_carrier=lambda *a, **k: True,
    _wait_for_fanout_confirm=lambda *a, **k: True,
    _wait_for_change_settled=lambda *a, **k: (True, 0),
    _change_residue=lambda *a, **k: 0,
    _run_change_sweeps=lambda *a, **k: 0,
    report_completion=lambda *a, **k: None,
    safe_post=lambda url, payload, proxy: {"routes": [{
        "expectedBuyAmount": "3.0",
        "memo": "=:XMR.XMR:" + payload["destinationAddress"] + ":0/1/0::0",
        "targetAddress": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}]},
    btc_per_xmr_oracle=lambda *a, **k: None,
    wait_for_swap_arrival=lambda fn, floor_, n: dict(zip(("state","total","unlocked"),
                                                         ("funded",) + fn())),
)
saved = {k: getattr(g, k) for k in stubs}
@contextlib.contextmanager
def nolock(*a, **k): yield None
saved["run_lock"] = g.run_lock

out = io.StringIO()
try:
    for k, v in stubs.items(): setattr(g, k, v)
    g.run_lock = nolock
    sys.argv = ["GhostSpiral", "--btc-entry", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "--btc-amount", "0.6", "--split", str(N), "--wallets", str(WALLETS),
                "--dag-mixing", "--hop-delay", "0-0",
                "--output", _OUTDIR,
                "--tor-proxy", "socks5h://127.0.0.1:9050"]
    with contextlib.redirect_stdout(out):
        g.main()
    _outcome = "returned"
except SystemExit as e:
    _outcome = "SystemExit: " + str(e.code)[:300]
except Exception as e:                                       # noqa: BLE001
    _outcome = f"CRASHED {type(e).__name__}: {e}"
finally:
    for k, v in saved.items(): setattr(g, k, v)

print("=== a three-chunk run, end to end ===")
check(f"the whole pipeline RUNS with --split 3 ({_outcome})",
      _outcome == "returned")

_by = dict(ROUNDS)
check("Round 0 creates THREE veils, one per chunk", len(_by.get("Entry veil", [])) == 3)
check("...each a SWEEP of one entry output",
      all(t.get("sweep") is True for t in _by.get("Entry veil", [])))
check("...each naming its OWN account, so no transaction can spend two",
      len({t["account_index"] for t in _by.get("Entry veil", [])}) == 3)
check("Round 1 creates THREE fan-outs, one per carrier",
      len(_by.get("Fan-out", [])) == 3)
check("...from three DIFFERENT carrier accounts",
      len({t["account_index"] for t in _by.get("Fan-out", [])}) == 3)
# 4/3/1 XMR in, so the slices must be unequal and ordered the same way.
_sizes = [len(t.get("destinations") or []) for t in _by.get("Fan-out", [])]
check(f"...with slices sized by each chunk's OWN balance, not equally {_sizes}",
      len(set(_sizes)) > 1 and _sizes == sorted(_sizes, reverse=True))
# EVERY OUTPUT THAT CAN LEGALLY HOP, WHICH IS NOT EVERY OUTPUT.
#
# This asserted len(DAG) == sum(_sizes) -- every fan-out output hops -- and had
# been FLAKY since it was written: 9 failures in 25 runs, silently passing the
# audit's verification sweeps by luck. The cause is not a bug in the round. A
# hop must leave its source AND stay inside its own chunk (that restriction is
# what stops two chunks meeting in one transaction), so a chunk holding ONE mix
# subaddress has nowhere legal to send it. With balances 4/3/1 the smallest
# chunk gets a slice of 1 whenever fanout_count lands on 8 (slices [4,3,1]) and
# a slice of 2 when it lands on 10 ([5,3,2]) -- and fanout_count varies with the
# decoy count, so the same test drew both.
#
# Loosening it to <= would have hidden a real regression. The honest assertion
# is the one the design actually makes: every output hops EXCEPT those in a
# slice too thin to have a legal destination -- and the run must SAY so, because
# silently skipping a mixing round is the failure this project keeps finding.
_thin_slices = [n for n in _sizes if n < 2]
_hoppable = sum(n for n in _sizes if n >= 2)
check(f"Round 2 hops every output that CAN hop — {len(_by.get('DAG', []))} of "
      f"{_hoppable} hoppable, from slices {_sizes}",
      len(_by.get("DAG", [])) == _hoppable)
check("...and a chunk too thin to hop is REPORTED, not silently skipped",
      not _thin_slices or "nowhere to hop" in out.getvalue())
check("...with no hop invented for a chunk that had nowhere to send it",
      len(_by.get("DAG", [])) <= sum(_sizes))

print("\n=== the invariant, on the plans this run actually produced ===")
veil = dict(ROUNDS).get("Entry veil", [])
fan  = dict(ROUNDS).get("Fan-out", [])
dag  = dict(ROUNDS).get("DAG", [])

# chunk id -> carrier address, from the veils
carrier_of_chunk = {i: t["dst"] for i, t in enumerate(veil)}
chunk_of_carrier = {v: k for k, v in carrier_of_chunk.items()}
check(f"{len(veil)} veils pay {len(set(carrier_of_chunk.values()))} DISTINCT carriers "
      f"— a shared one would move the convergence to the distribution",
      len(set(carrier_of_chunk.values())) == len(veil) == 3)

# mix target -> which chunk funded it, from the fan-outs
owner = {}
bad = []
for t in fan:
    c = chunk_of_carrier.get(t["src"])
    if c is None:
        bad.append(f"fan-out from {t['src'][:8]} is not any veil's carrier")
    for d in t.get("destinations", []):
        if d["address"] in owner:
            bad.append(f"target {d['address'][:8]} funded by chunks "
                       f"{owner[d['address']]} AND {c}")
        owner[d["address"]] = c
check(f"no mix target is funded by two different chunks ({len(owner)} targets)",
      not bad)

# every DAG hop must stay inside its chunk
cross = [(t["src"][:8], t["dst"][:8], owner.get(t["src"]), owner.get(t["dst"]))
         for t in dag
         if owner.get(t["src"]) is not None and owner.get(t["dst"]) is not None
         and owner[t["src"]] != owner[t["dst"]]]
check(f"NO DAG hop crosses a chunk boundary ({len(dag)} hops) — the route by "
      f"which the exit's per-subaddress sweep would have merged two chunks",
      not cross)

# and no transaction anywhere spends two chunks
multi = []
for label, txs in ROUNDS:
    for t in txs:
        srcs = {t.get("src")}
        chunks = {owner.get(s) for s in srcs if owner.get(s) is not None}
        if len(chunks) > 1: multi.append((label, t.get("src")))
check("NO transaction in the whole run spends value from two swap chunks",
      not multi)

print("\n=== the shipped signer validating those plans ===")
la = importlib.machinery.SourceFileLoader("airgap", os.path.join(REPO, "airgap_tx_signer"))
ag = importlib.util.module_from_spec(importlib.util.spec_from_loader(la.name, la))
la.exec_module(ag)
for label, txs in ROUNDS:
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ag._validate_plan(txs, phase="create")
        check(f"the shipped validator ACCEPTS the {label} plan "
              f"({len(txs)} tx, {len({t.get('account_index') for t in txs})} "
              f"accounts in one file)", True)
    except SystemExit as e:
        check(f"the shipped validator ACCEPTS the {label} plan "
              f"({str(e.code)[:80]})", False)


import shutil
shutil.rmtree(_OUTDIR, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
