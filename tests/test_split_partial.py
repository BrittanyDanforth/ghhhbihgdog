#!/usr/bin/env python3
"""A SPLIT RUN IN WHICH ONE SWAP CHUNK NEVER ARRIVES.

test_split_pipeline drives three chunks that all land. This drives the case the
arrival gate deliberately allows through: the SUM clears the target while one
individual chunk is still empty -- one swap overshooting its quote covers
another that has not settled, and --accept-partial-swap permits a shortfall
outright. select_funded_entries then drops the empty chunk and the run
continues on the rest.

That path is reasoned about in three docstrings and had never been executed.
It matters because of what it claims:

  "The dropped entries keep their addresses, and _exit_hold_list still takes
   the FULL set -- so a chunk that lands later is held back from the exit
   rather than swept to the operator's destination in one hop from an address
   the swap publicly names."

If ENTRY_ADDRS were ever narrowed to the funded subset -- the obvious edit,
since every other consumer wants the funded one -- that sentence stays in the
file and stops being true, and the failure is invisible: the run reports
success, and the late chunk leaves in one hop from the address the OP_RETURN
memo names in public. So the hold list is asserted here against the FULL set,
by driving the real main().

Chunk 1 arrives EMPTY (4 / 0 / 1 XMR).
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
_OUTDIR = tempfile.mkdtemp(prefix="splitpartial_")

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
ENTRY_BAL = [4 * 10**12, 0, 1 * 10**12]      # chunk 1 never arrived
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
HOLD = {}            # what the exit is told to refuse to withdraw
ENTRIES_SEEN = {}    # the full entry set, before any pruning

_real_hold = g._exit_hold_list
def spy_hold(args, addr_index, entry_addr):
    out = _real_hold(args, addr_index, entry_addr)
    HOLD["list"] = list(out)
    HOLD["entry_arg"] = list(entry_addr) if isinstance(entry_addr, (list, tuple)) else [entry_addr]
    return out

_real_establish = g.establish_entry_set
def spy_establish(*a, **k):
    es, ea = _real_establish(*a, **k)
    ENTRIES_SEEN["set"] = list(es)
    ENTRIES_SEEN["addrs"] = list(ea)
    return es, ea

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
    _exit_hold_list=spy_hold,
    establish_entry_set=spy_establish,
    _wait_for_carrier=lambda *a, **k: True,
    _wait_for_fanout_confirm=lambda *a, **k: True,
    _wait_for_change_settled=lambda *a, **k: (True, 0),
    _change_residue=lambda *a, **k: 0,
    _run_change_sweeps=lambda *a, **k: 0,
    report_completion=lambda *a, **k: None,
    safe_post=lambda url, payload, proxy: {"routes": [{
        "expectedOutput": "3.0",
        "transaction": {"memo": "=:XMR.XMR:" + payload["destinationAddress"] + ":0/1/0::0",
                        "depositAddress": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}}]},
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
                "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--exit-to", addr(4242)]
    with contextlib.redirect_stdout(out):
        g.main()
    _outcome = "returned"
except SystemExit as e:
    _outcome = "SystemExit: " + str(e.code)[:300]
except Exception as e:                                       # noqa: BLE001
    _outcome = f"CRASHED {type(e).__name__}: {e}"
finally:
    for k, v in saved.items(): setattr(g, k, v)


print("=== a three-chunk run in which chunk 1 never arrived ===")
check(f"the run COMPLETES rather than dying on the empty chunk ({_outcome})",
      _outcome == "returned")

_by = dict(ROUNDS)
_veils = _by.get("Entry veil", [])
_fans = _by.get("Fan-out", [])
check(f"only the TWO funded chunks are veiled, not three ({len(_veils)})",
      len(_veils) == 2)
check(f"...and only two are distributed ({len(_fans)})", len(_fans) == 2)
check("...each still from its OWN account — dropping a chunk must not merge "
      "the survivors",
      len({t["account_index"] for t in _fans}) == len(_fans))

print("\n=== the claim: the DROPPED chunk is still held back from the exit ===")
_all_entries = ENTRIES_SEEN.get("addrs") or []
check(f"the run minted {N} entry addresses before pruning",
      len(_all_entries) == N)
# The dropped chunk is the one with no balance. Its address is the one that
# appears in NO veil.
_veiled_srcs = {t.get("src") for t in _veils}
_dropped = [a for a in _all_entries if a not in _veiled_srcs]
check(f"exactly one entry address was left undistributed ({len(_dropped)})",
      len(_dropped) == 1)
check("_exit_hold_list was given the FULL entry set, not the funded subset",
      len(HOLD.get("entry_arg") or []) == N)
_held = {h[0] if isinstance(h, (list, tuple)) else h for h in (HOLD.get("list") or [])}
_hold_pairs = set()
for _h in (HOLD.get("list") or []):
    if isinstance(_h, (list, tuple)) and len(_h) >= 2:
        _hold_pairs.add((int(_h[0]), int(_h[1])))
_idxmap = {a: (ac, ix) for a, (ac, ix) in
           [(a, ENTRIES_SEEN["set"][i][1:]) for i, a in enumerate(_all_entries)]}
check("the DROPPED chunk's entry output is in the exit's hold list — it is "
      "NOT swept to --exit-to in one hop from the address the swap memo names",
      all(_idxmap[a] in _hold_pairs for a in _dropped))
check("...and so is every entry address that DID arrive",
      all(_idxmap[a] in _hold_pairs for a in _all_entries))

print("\n=== the invariant still holds on the surviving chunks ===")
_dag = _by.get("DAG", [])
_carrier_of = {i: t["dst"] for i, t in enumerate(_veils)}
_chunk_of = {v: k for k, v in _carrier_of.items()}
owner = {}
for t in _fans:
    c = _chunk_of.get(t["src"])
    for d in (t.get("destinations") or []):
        owner[d["address"]] = c
for t in _fans:
    owner[t["src"]] = _chunk_of.get(t["src"])
_cross = [(t["src"][:8], t["dst"][:8]) for t in _dag
          if owner.get(t["src"]) is not None and owner.get(t["dst"]) is not None
          and owner[t["src"]] != owner[t["dst"]]]
check(f"NO DAG hop crosses a chunk boundary ({len(_dag)} hops)", not _cross)
check(f"{len(_veils)} veils pay {len(set(_carrier_of.values()))} DISTINCT carriers",
      len(set(_carrier_of.values())) == len(_veils))

print("\n=== the shipped signer validating those plans ===")
la = importlib.machinery.SourceFileLoader("airgap", os.path.join(REPO, "airgap_tx_signer"))
ag = importlib.util.module_from_spec(importlib.util.spec_from_loader(la.name, la))
la.exec_module(ag)
for label, txs in ROUNDS:
    if not txs:
        continue
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ag._validate_plan(txs, phase="create")
        check(f"the shipped validator ACCEPTS the {label} plan ({len(txs)} tx)", True)
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
