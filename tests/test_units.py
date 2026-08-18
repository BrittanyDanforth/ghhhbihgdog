#!/usr/bin/env python3
"""Executable tests for the pure-Python (non-Monero-stack) logic I changed.
Loads the real extensionless scripts as modules and asserts real behavior."""
import ast
import re
import sys, os, shutil, tempfile, importlib.util, importlib.machinery
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tests"))
from srcutil import code_only
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

# Implausible fee (fresh/offline daemon) must ABORT, not size a plan. A fresh
# monerod returns base=2e9 piconero/byte, which this conversion turns into 4 XMR
# per tx. The sibling console flags it; the spending tool must refuse it.
def _fee_exits(est, prio=1):
    ghost.daemon_fee_estimate = lambda *a, **k: est
    try:
        ghost.fetch_fee_from_daemon("http://127.0.0.1:18081", None, prio)
        return False
    except SystemExit:
        return True
check("fee: fresh-chain base fee (2e9/byte -> 4 XMR) is refused",
      _fee_exits({"fee": 2000000000}))
check("fee: implausible per-priority fees[] entry is refused",
      _fee_exits({"fees": [2000000000, 2000000000, 2000000000, 2000000000]}))
# A real fee -- even a high-priority one worth a fraction of an XMR -- must pass.
# 100000 piconero/byte * 2000 = 0.0002 XMR; priority 4 real values stay well
# under the 1-XMR ceiling.
check("fee: a real sub-XMR fee is NOT rejected",
      with_estimate({"fees": [100000, 400000, 800000, 2000000]}) < ghost.FEE_IMPLAUSIBLE_XMR)
check("fee: a real fee just under the ceiling is accepted",
      _fee_exits({"fee": int(Decimal("0.9") * Decimal(10**12) / 2000)}) is False)
# The fee that fed the old confusing "insufficient balance: 240 XMR fees" bug.
check("fee: the 4-XMR fresh-chain value that mis-sized the plan is caught",
      _fee_exits({"fee": 2000000000}, prio=1))

# ---------------------------------------------------------------------------
# GhostSpiral.compute_fanout_amounts: UNEQUAL jittered fan-out (anti-clustering)
# ---------------------------------------------------------------------------
import random as _rnd
_fee = Decimal("0.0005")
_bud = Decimal("10") * ghost.FANOUT_SPEND_FRACTION
_amts = ghost.compute_fanout_amounts(Decimal("10"), 8, _fee, True, _rnd.Random(1))
check("fanout: returns one amount per destination", len(_amts) == 8)
check("fanout: amounts are UNEQUAL (defeats equal-value clustering)",
      len(set(_amts)) == 8)
check("fanout: sum never exceeds the spend budget",
      sum(_amts) <= _bud)
check("fanout: every amount reserves its own hop fee (DAG on)",
      min(_amts) >= ghost.hop_fee_reserve(_fee))
check("fanout: a seeded rng is deterministic (same seed -> same split)",
      ghost.compute_fanout_amounts(Decimal("10"), 8, _fee, True, _rnd.Random(1)) == _amts)
check("fanout: a different seed gives a different split",
      ghost.compute_fanout_amounts(Decimal("10"), 8, _fee, True, _rnd.Random(2)) != _amts)
check("fanout: an unfundable budget returns [] (caller aborts, no bad plan)",
      ghost.compute_fanout_amounts(Decimal("0.001"), 8, _fee, True, _rnd.Random(1)) == [])
check("fanout: zero/negative count returns []",
      ghost.compute_fanout_amounts(Decimal("10"), 0, _fee, True, _rnd.Random(1)) == [])
# DAG off needs only a dust margin, so a smaller balance can still fan out.
_amts_off = ghost.compute_fanout_amounts(Decimal("0.01"), 5, _fee, False, _rnd.Random(3))
check("fanout: DAG-off floor is only a dust margin (funds smaller balances)",
      len(_amts_off) == 5 and all(a >= Decimal("0.0002") for a in _amts_off))
check("fanout: DAG-off sum still within budget",
      sum(_amts_off) <= Decimal("0.01") * ghost.FANOUT_SPEND_FRACTION)

# ---------------------------------------------------------------------------
# GhostSpiral.select_fanout_targets: EVERY output hops (Kerckhoffs — no output
# has a behavioural tell an analyst could use even with the full source).
# ---------------------------------------------------------------------------
_mix = ["M0", "M1", "M2", "D0", "D1"]          # 3 real + 2 extra (pre-shuffled)
_decoys = {"D0", "D1"}
_fd, _hs = ghost.select_fanout_targets(_mix, _decoys, wallets=3, num_decoys=2)
check("fanout: funds wallets + extra outputs (padded output count)",
      len(_fd) == 5 and all(d in _fd for d in _decoys))
check("fanout: EVERY output hops — no dead-end class a public-code analyst can filter",
      sorted(_hs) == sorted(_fd))
check("fanout: the extra ('decoy') outputs hop exactly like the rest",
      all(d in _hs for d in _decoys))
check("fanout: hop count == fan-out count (no output-vs-hop discrepancy to exploit)",
      len(_hs) == len(_fd))
# num_decoys=0 => exactly `wallets` wide.
_fd_bug, _ = ghost.select_fanout_targets(_mix, _decoys, wallets=3, num_decoys=0)
check("fanout: num_decoys=0 gives exactly `wallets` outputs",
      len(_fd_bug) == 3)
# Never exceeds what actually exists, and those still all hop.
_fd_cap, _hs_cap = ghost.select_fanout_targets(["M0", "D0"], {"D0"}, wallets=10, num_decoys=4)
check("fanout: never exceeds available subaddresses; all still hop",
      _fd_cap == ["M0", "D0"] and sorted(_hs_cap) == ["D0", "M0"])
check("fanout: extra-output count is a RANGE, not a fixed fingerprint",
      ghost.DECOY_MIN >= 1 and ghost.DECOY_MAX > ghost.DECOY_MIN)

# ---------------------------------------------------------------------------
# main() DECOMPOSITION. It was 869 lines with five closures inside it, so its
# stages could not be called, inspected or tested except by running a whole
# money pipeline -- which is exactly how a swap path with no memo check stayed
# invisible. These are the extracted pieces, driven directly.
# ---------------------------------------------------------------------------
_cli = ghost.build_cli()
_opts = {a.option_strings[0]: a for a in _cli._actions if a.option_strings}

check("cli: build_cli returns a real parser", hasattr(_cli, "parse_args"))
check("cli: --tor-proxy is REQUIRED (fail closed, never optional)",
      _opts["--tor-proxy"].required is True)
# The two entry modes are mutually exclusive AND one is mandatory: a run with
# neither has no source of funds, a run with both is ambiguous about which.
_groups = [g for g in _cli._mutually_exclusive_groups]
check("cli: exactly one mutually exclusive entry-mode group exists", len(_groups) == 1)
# The group is deliberately NOT argparse-required: the BTC entry may arrive in
# GS_BTC_ENTRY, because an address on argv is world-readable via
# /proc/<pid>/cmdline. The "exactly one mode" contract moved into
# resolve_sensitive_inputs, and must still be enforced there.
check("cli: the entry-mode group is NOT argparse-required (env may supply it)",
      _groups[0].required is False)
_gs_env = open(os.path.join(REPO, "GhostSpiral")).read()
check("cli: the exactly-one-mode contract is enforced in code instead",
      "No entry mode" in _gs_env and "not both" in _gs_env)
check("cli: GS_BTC_ENTRY and GS_BTC_AMOUNT are the supported env inputs",
      "GS_BTC_ENTRY" in _gs_env and "GS_BTC_AMOUNT" in _gs_env)
check("cli: that group is --btc-entry vs --receive-wallet",
      sorted(a.option_strings[0] for a in _groups[0]._group_actions)
      == ["--btc-entry", "--receive-wallet"])
check("cli: --max-slippage defaults to the same 0.25 as thor_swap_preparer",
      _opts["--max-slippage"].default == Decimal("0.25"))
# Every "allow" flag widens exposure, so each must default OFF. A preset or a
# stray default flipping one of these on is a silent downgrade.
for _f in ("--allow-clearnet-relay", "--allow-unbound-memo"):
    check(f"cli: {_f} defaults OFF (widening exposure is always explicit)",
          _opts[_f].default is False)
check("cli: --peel and --dag-mixing both default OFF",
      _opts["--peel"].default is False and _opts["--dag-mixing"].default is False)
_p = _cli.parse_args(["--receive-wallet", "w.json", "--tor-proxy",
                      "socks5h://127.0.0.1:9050"])
check("cli: a minimal receive invocation parses", _p.receive_wallet == "w.json")
check("cli: --fee-priority is constrained to 1-4",
      _opts["--fee-priority"].choices == [1, 2, 3, 4])


class _A:                                   # a stand-in for parsed args
    def __init__(self, **kw):
        self.wallet_password = ""
        self.__dict__.update(kw)


# resolve_wallet_password: env beats argv, and argv warns.
_a = _A(wallet_password="from-argv")
os.environ["GS_WALLET_PASSWORD"] = "from-env"
ghost.resolve_wallet_password(_a)
check("password: the environment wins over argv", _a.wallet_password == "from-env")
os.environ.pop("GS_WALLET_PASSWORD", None)
_a2 = _A(wallet_password="from-argv")
ghost.resolve_wallet_password(_a2)
check("password: argv is still honoured when no env var is set",
      _a2.wallet_password == "from-argv")
# An empty env var is a DELIBERATE empty password (an unencrypted wallet), not
# "unset" -- collapsing the two would silently fall back to the argv value.
os.environ["GS_WALLET_PASSWORD"] = ""
_a3 = _A(wallet_password="from-argv")
ghost.resolve_wallet_password(_a3)
check("password: an EMPTY env var means empty, not 'fall back to argv'",
      _a3.wallet_password == "")
os.environ.pop("GS_WALLET_PASSWORD", None)


# compute_fee_budget: pure money math, now callable without a pipeline.
_u, _tf, _r = ghost.compute_fee_budget(Decimal("10"), Decimal("0.001"), 10, 2)
check("budget: rounds = wallets * 2 * deep", _r == 40)
check("budget: the fee reserve carries the safety margin",
      _tf == Decimal("0.001") * ghost.FEE_SAFETY_MARGIN * 40)
check("budget: usable is the balance minus the whole reserve",
      _u == Decimal("10") - _tf)
# The reserve must scale with the work, or a deep run under-reserves and dies
# on its LAST hop, after the funds are already scattered across subaddresses.
_u2, _tf2, _r2 = ghost.compute_fee_budget(Decimal("10"), Decimal("0.001"), 10, 6)
check("budget: a deeper run reserves strictly more", _tf2 > _tf and _r2 > _r)
check("budget: usable shrinks as depth grows", _u2 < _u)
# It must report an unaffordable plan rather than abort: "cannot afford this"
# is an answer the caller acts on, not an error.
_u3, _, _ = ghost.compute_fee_budget(Decimal("0.0001"), Decimal("1"), 10, 2)
check("budget: an unaffordable plan returns a non-positive usable, not an exit",
      _u3 <= 0)
check("budget: it never returns more than the balance",
      all(ghost.compute_fee_budget(Decimal(b), Decimal("0.001"), w, d)[0] <= Decimal(b)
          for b in ("1", "10", "100") for w in (3, 10, 40) for d in (1, 3, 6)))


# The five extracted stage helpers must be module-level and callable.
for _fn in ("stage1_joinmarket", "stage2_get_swap_quotes", "create_subs",
            "xmr_balance", "_src_index", "stage0_preflight", "build_cli",
            "resolve_entry_mode", "resolve_wallet_password", "compute_fee_budget"):
    check(f"decomp: {_fn} is a module-level function, not a closure",
          callable(getattr(ghost, _fn, None)))
_main = [n for n in ast.walk(ast.parse(open(os.path.join(REPO, "GhostSpiral")).read()))
         if isinstance(n, ast.FunctionDef) and n.name == "main"][0]
check("decomp: main() has NO nested function definitions left",
      not [c for c in _main.body if isinstance(c, ast.FunctionDef)])
check("decomp: main() is under 500 lines (was 869)",
      _main.end_lineno - _main.lineno < 500)

# The stale docstring that WAS the trace recipe must stay gone.
_cs_doc = ghost.create_subs.__doc__ or ""
check("decomp: create_subs no longer claims decoys 'never hop' (that was the filter)",
      "never hop" not in _cs_doc or "used to say" in _cs_doc)


# ---------------------------------------------------------------------------
# THE SWAP MEMO IS THE ONLY THING BINDING A BTC DEPOSIT TO YOUR XMR ADDRESS.
# The BTC a sender pays goes to a SHARED ThorChain inbound vault, so a memo
# naming a different address delivers the money to whoever owns it.
# thor_swap_preparer refused to print such instructions. GhostSpiral's own
# stage 2, fetching the same quotes from the same API, checked the deposit
# address and then printed "Send N BTC to <addr> with memo <memo>" having never
# looked at the memo at all -- and did not abort on an EMPTY memo either.
# ---------------------------------------------------------------------------
_MDEST = "8" + "A" + "1" * 93
_MOTHER = "8" + "B" + "2" * 93
# A real mainnet bech32 address (valid BIP173 checksum).
_MDEP = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def _route_rejected(deposit, memo, dest=_MDEST, allow=False):
    try:
        ghost.validate_swap_route(deposit, memo, dest, 0, allow_unbound_memo=allow)
        return False
    except SystemExit:
        return True


check("swap: a memo naming YOUR address is accepted",
      not _route_rejected(_MDEP, f"=:XMR.XMR:{_MDEST}:0/1/0"))
# The bug, stated as a test: this exact quote used to reach the operator as
# "send real bitcoin to this address with this memo".
check("swap: a memo naming SOMEONE ELSE'S address is REFUSED",
      _route_rejected(_MDEP, f"=:XMR.XMR:{_MOTHER}:0/1/0"))
check("swap: an EMPTY memo is refused (a swap is routed entirely by the memo)",
      _route_rejected(_MDEP, ""))
check("swap: a None memo is refused", _route_rejected(_MDEP, None))
check("swap: a missing deposit address is refused", _route_rejected("", f"=:XMR.XMR:{_MDEST}"))
check("swap: a deposit address failing bech32 checksum is refused",
      _route_rejected("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                      f"=:XMR.XMR:{_MDEST}"))
check("swap: a non-BTC deposit string is refused",
      _route_rejected("not-an-address", f"=:XMR.XMR:{_MDEST}"))
# Aggregators may hex-encode the memo for the OP_RETURN; that must still bind.
check("swap: a HEX-encoded memo binding your address is accepted",
      not _route_rejected(_MDEP, f"=:XMR.XMR:{_MDEST}".encode().hex()))
check("swap: a hex-encoded memo naming someone else is still refused",
      _route_rejected(_MDEP, f"=:XMR.XMR:{_MOTHER}".encode().hex()))
# The override exists, but must be explicit and must not weaken the others.
check("swap: --allow-unbound-memo lets an unbound memo through deliberately",
      not _route_rejected(_MDEP, f"=:XMR.XMR:{_MOTHER}", allow=True))
check("swap: --allow-unbound-memo does NOT excuse a missing memo",
      _route_rejected(_MDEP, "", allow=True))
check("swap: --allow-unbound-memo does NOT excuse a bad deposit address",
      _route_rejected("not-an-address", f"=:XMR.XMR:{_MDEST}", allow=True))

# Both swap paths must enforce the identical rule from one implementation.
import gs_common as _gsc0
check("swap: the memo check lives in gs_common (shared, audited once)",
      hasattr(_gsc0, "memo_binds_destination"))
_th_s = open(os.path.join(REPO, "thor_swap_preparer")).read()
_gs_s = open(os.path.join(REPO, "GhostSpiral")).read()
check("swap: thor_swap_preparer uses the shared memo check",
      "memo_binds_destination" in _th_s and "import" in _th_s)
check("swap: GhostSpiral's own stage 2 now validates the route",
      "validate_swap_route(" in _gs_s)
# Structural, not textual: find the stage-2 quote loop and prove the guard is
# actually CALLED there, before any deposit instruction is built.
_gs_ast = ast.parse(_gs_s)
_calls_guard = [n for n in ast.walk(_gs_ast)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "validate_swap_route"]
check("swap: GhostSpiral actually CALLS the route guard (not just defines it)",
      len(_calls_guard) == 1)
check("swap: the guard is called with the operator's own xmr_dest",
      _calls_guard and any(isinstance(a, ast.Name) and a.id == "xmr_dest"
                           for a in _calls_guard[0].args))
# thor and GhostSpiral must agree on every case, not merely both have a check.
for _m, _d in ((f"=:XMR.XMR:{_MDEST}", True), (f"=:XMR.XMR:{_MOTHER}", False),
               ("", False), (f"=:XMR.XMR:{_MDEST}".encode().hex(), True)):
    check(f"swap: both paths agree on memo {_m[:24]!r}",
          _gsc0.memo_binds_destination(_m, _MDEST) is _d)


# ---------------------------------------------------------------------------
# ONE receive-bundle loader. This describes WHERE MONEY LANDS and used to be
# parsed inline in three places with three different strictnesses; the weakest
# won. GhostSpiral did `rw_data.get("subaddress_index") or 0`, so a bundle
# missing the index silently became subaddress 0 -- the account's primary AND
# change address -- and the pipeline used the change carrier as its entry with
# no error at all.
# ---------------------------------------------------------------------------
import gs_common as _gsc
import tempfile as _tf, json as _js, os as _os

_bd = _tf.mkdtemp(prefix="gs_bundle_")


def _wb(name, obj):
    p = _os.path.join(_bd, name)
    with open(p, "w") as fh:
        _js.dump(obj, fh)
    return p


_DESTA = "8" + "A" + "1" * 93


def _bundle_ok(**over):
    d = {"schema": "gs_receive_wallet_v1", "address": _DESTA,
         "account_index": 0, "subaddress_index": 7}
    d.update(over)
    return d


def _refused(obj_or_path):
    path = obj_or_path if isinstance(obj_or_path, str) else _wb("t.json", obj_or_path)
    try:
        _gsc.load_receive_bundle(path)
        return False
    except ValueError:
        return True


check("bundle: a well-formed receive bundle loads",
      _gsc.load_receive_bundle(_wb("g.json", _bundle_ok()))["subaddress_index"] == 7)
# THE BUG: absence must never become 0.
check("bundle: a MISSING subaddress_index is refused, never defaulted to 0",
      _refused({"schema": "gs_receive_wallet_v1", "address": _DESTA, "account_index": 0}))
check("bundle: a MISSING account_index is refused too",
      _refused({"schema": "gs_receive_wallet_v1", "address": _DESTA, "subaddress_index": 7}))
check("bundle: a present-but-null index is refused (not coerced to 0)",
      _refused(_bundle_ok(subaddress_index=None)))
# `or 0` also collapsed a legitimate 0 with absence; an explicit 0 must work.
check("bundle: an EXPLICIT subaddress_index of 0 is still accepted",
      _gsc.load_receive_bundle(_wb("z.json", _bundle_ok(subaddress_index=0)))
      ["subaddress_index"] == 0)
# bool is an int subclass, so True would sneak through a naive isinstance check
# and become index 1 -- a different subaddress than any bundle intended.
check("bundle: a boolean index is refused (True is an int, and would mean 1)",
      _refused(_bundle_ok(subaddress_index=True)))
check("bundle: a negative index is refused", _refused(_bundle_ok(subaddress_index=-1)))
check("bundle: a non-integer index is refused", _refused(_bundle_ok(subaddress_index="7")))
check("bundle: the wrong schema is refused", _refused(_bundle_ok(schema="thor_pairs_v1")))
check("bundle: no address is refused",
      _refused({"schema": "gs_receive_wallet_v1", "account_index": 0,
                "subaddress_index": 7}))
check("bundle: a non-string address is refused", _refused(_bundle_ok(address=12345)))
check("bundle: a JSON list is refused", _refused(_wb("l.json", [_DESTA])))
check("bundle: a missing file is refused", _refused(_os.path.join(_bd, "nope.json")))

# What create_receive_wallet actually writes must satisfy the loader, or the
# tool that produces bundles and the tools that consume them disagree.
check("bundle: create_receive_wallet's own output shape loads cleanly",
      _gsc.load_receive_bundle(_wb("real.json", {
          "schema": "gs_receive_wallet_v1", "created": 1700000000,
          "address": _DESTA, "account_index": 0, "subaddress_index": 3,
          "label": "GhostSpiral_entry",
          "rpc_endpoint": "http://127.0.0.1:18083"}))["address"] == _DESTA)

# No consumer may keep a private, laxer parse of this format.
_gs_src = open(os.path.join(REPO, "GhostSpiral")).read()
_rw_src = open(os.path.join(REPO, "receive_watch")).read()
_th_src = open(os.path.join(REPO, "thor_swap_preparer")).read()
def _code_only(src):
    """Strip comments and docstrings: these files quote the old buggy line in
    prose to record why it is gone, and a scan that reads prose as code would
    fail on the very comment documenting the fix."""
    import io as _io, tokenize as _tok
    out = []
    try:
        for tk in _tok.generate_tokens(_io.StringIO(src).readline):
            if tk.type in (_tok.COMMENT, _tok.NL):
                continue
            if tk.type == _tok.STRING and tk.line.strip().startswith(tk.string[:1] * 3):
                continue                      # a bare triple-quoted docstring
            out.append(tk.string)
    except Exception:                         # noqa: BLE001
        return src
    return "\n".join(out)


for _n, _s in (("GhostSpiral", _gs_src), ("receive_watch", _rw_src),
               ("thor_swap_preparer", _th_src)):
    _code = _code_only(_s)
    check(f"bundle: {_n} uses the shared loader",
          "load_receive_bundle" in _code)
    check(f"bundle: {_n} has no private `or 0` index default in CODE",
          'get("subaddress_index") or 0' not in _code
          and 'get("account_index") or 0' not in _code
          and "get('subaddress_index') or 0" not in _code)
    check(f"bundle: {_n} does not re-check the schema string itself",
          '"gs_receive_wallet_v1"' not in _code)


# ---------------------------------------------------------------------------
# peel + DAG COMPOSE (the "Maximum safe" preset): the peeled outputs are
# exactly the DAG hop sources, and each peeled amount can fund its later hop.
# This is what makes running --peel AND --dag-mixing a real two-layer mix
# rather than two unrelated settings.
# ---------------------------------------------------------------------------
_cd = ["A", "B", "C", "D"]
_ca = [Decimal("1.0"), Decimal("0.6"), Decimal("2.1"), Decimal("0.9")]
_ccar = [(f"CarrierAddr{i}", 200 + i) for i in range(len(_cd) - 1)]
_crem = [Decimal("3.6"), Decimal("3.0"), Decimal("0.9")]
_cpeels = ghost.build_peel_plan(9, 0, _cd, _ca, carriers=_ccar, remainders=_crem)
_cfd, _chop = ghost.select_fanout_targets(_cd, set(), wallets=4, num_decoys=0)
check("peel+dag: the peeled destinations ARE the DAG hop sources (same outputs)",
      sorted(p["dst"] for p in _cpeels) == sorted(_chop))
_cby = dict(zip(_cd, _ca))
check("peel+dag: every peeled output can fund its later DAG hop",
      all(ghost.compute_hop_amount(_cby[d], Decimal("0.01")) > ghost.DUST_XMR
          for d in _chop))
check("peel+dag: the DAG hop amount is derived from THAT output's peeled amount",
      ghost.compute_hop_amount(_cby["C"], Decimal("0.01"))
      > ghost.compute_hop_amount(_cby["B"], Decimal("0.01")))   # C peeled more than B

# ---------------------------------------------------------------------------
# NOTHING THAT IDENTIFIES THE OPERATOR GOES ON A COMMAND LINE.
#
# /proc/<pid>/cmdline is mode 0444 -- every account on the host can read a
# child's argv for as long as it runs -- while /proc/<pid>/environ is 0400.
# The rule was written once for the wallet password and then not applied to
# the off-ramp amount, the BTC entry ADDRESS, or the swap amounts. Those are
# the values that tie a run to a Bitcoin identity, and the same toolchain
# strips them from the integrity chain for exactly that reason.
#
# gs_common.env_or_argv is the single implementation so the next caller cannot
# half-apply it again.
# ---------------------------------------------------------------------------
check("argv: gs_common owns one env-over-argv helper", hasattr(gs, "env_or_argv"))
os.environ.pop("GS_T_SECRET", None)
check("argv: with no env var the argv value is used",
      gs.env_or_argv("GS_T_SECRET", "from-argv", "x") == "from-argv")
os.environ["GS_T_SECRET"] = "from-env"
check("argv: the environment WINS over argv",
      gs.env_or_argv("GS_T_SECRET", "from-argv", "x") == "from-env")
check("argv: a cast is applied to the env value",
      gs.env_or_argv("GS_T_SECRET", None, "x", cast=str.upper) == "FROM-ENV")
os.environ["GS_T_SECRET"] = ""
check("argv: an EMPTY env var falls through to argv, not to a blank secret",
      gs.env_or_argv("GS_T_SECRET", "from-argv", "x") == "from-argv")
os.environ.pop("GS_T_SECRET", None)
check("argv: neither source yields None for the caller to decide on",
      gs.env_or_argv("GS_T_SECRET", None, "x") is None)

_gsx = open(os.path.join(REPO, "GhostSpiral")).read()
_thx = open(os.path.join(REPO, "thor_swap_preparer")).read()
_cnx = open(os.path.join(REPO, "gs_console")).read()
# The three values, and the tools that must read them from the environment.
check("argv: GhostSpiral reads the BTC entry from the environment",
      "GS_BTC_ENTRY" in _gsx and "env_or_argv" in _gsx)
check("argv: GhostSpiral reads the BTC amount from the environment",
      "GS_BTC_AMOUNT" in _gsx)
check("argv: thor reads the swap amounts from the environment",
      "GS_SWAP_AMOUNTS" in _thx and "env_or_argv" in _thx)
# THE CONSOLE IS THE CALLER THAT LEAKED. It must not put them back on argv.
check("argv: the console no longer appends --btc-entry to a child's argv",
      '"--btc-entry", p["btc_entry"]' not in _cnx)
check("argv: the console no longer appends --btc-amount",
      '"--btc-amount", p["btc_amount"]' not in _cnx)
check("argv: the console no longer appends --amounts for the swap",
      '"--amounts", p.get("swap_btc"' not in _cnx)
check("argv: the console has one place that decides what is env-only",
      "def secret_env(" in _cnx)
# And the preview the page renders is the real argv, so secrets stay off it.
check("argv: keeping them off argv keeps them out of the command preview",
      "command PREVIEW" in _cnx or "preview" in _cnx)

# Every network call must refuse a falsy proxies dict. requests treats
# proxies={} as NO proxy and connects directly -- the defect safe_get records
# having observed reach a real target. verify/recheck were the two calls the
# guard was never added to.
for _bad in ({}, None):
    for _fn, _nm in ((gs._verify_tor_once, "_verify_tor_once"),
                     (gs.tor_recheck, "tor_recheck")):
        try:
            _fn(_bad); _ok = False
        except SystemExit as _e:
            _ok = "clearnet" in str(_e)
        except Exception:
            _ok = False
        check(f"noleak: {_nm}({_bad!r}) aborts instead of connecting clearnet", _ok)


# ---------------------------------------------------------------------------
# WHAT SURVIVES THE WIPE, AND WHAT A COMMAND LINE PUBLISHES.
#
# Audit of exit_strategy_simulator and paranoia_mode, hunting the operator
# rather than the transaction graph.
# ---------------------------------------------------------------------------
_exit_src = open(os.path.join(REPO, "exit_strategy_simulator")).read()
_par_src = open(os.path.join(REPO, "paranoia_mode")).read()
_gs_a = open(os.path.join(REPO, "GhostSpiral")).read()
_crw_a = open(os.path.join(REPO, "create_receive_wallet")).read()
_bc_a = open(os.path.join(REPO, "broadcast_signed_xmr")).read()

# 1. THE AMOUNT ON ARGV. /proc/<pid>/cmdline is mode 0444 -- world-readable by
#    every account on the host -- while /proc/<pid>/environ is 0400. The
#    pipeline passed the off-ramp total as a positional argument, so any local
#    user could read the size of the holding off `ps`. This repo already
#    refuses argv for the wallet password, and strips amounts from the
#    integrity chain, for exactly that reason.
check("exit: the pipeline no longer puts the amount on the child's argv",
      '"exit_strategy_simulator", str(spendable_amount)' not in _gs_a)
check("exit: the amount is handed over in the environment instead",
      'GS_EXIT_AMOUNT' in _gs_a and 'GS_EXIT_AMOUNT' in _exit_src)
check("exit: the positional amount is optional, so argv need never carry it",
      'nargs="?"' in _exit_src)
# Asserted by DRIVING the tool, not by grepping for a literal. The old check
# looked for the string "warn:amount_on_argv" inside exit_strategy_simulator;
# when the three hand-rolled env/argv copies were retired in favour of the
# shared gs_common.env_or_argv, that literal moved and the check went red while
# the behaviour was correct. A test that pins where a string lives fails on
# refactors and passes on regressions -- the wrong way round.
def _drive_exit(env_amount, argv_amount):
    """Run the real main() and report (warned?, chained?)."""
    import io as _io, contextlib as _ctx, types as _ty
    esm = load("exit_strategy_simulator")
    esm.verify_tor = lambda p: None
    esm.validate_proxy = lambda p: {"http": p}
    esm.install_signal_handlers = lambda: None
    esm.shutdown_requested = lambda: False
    esm.fetch_prices = lambda p: {"xmr_usd": Decimal("150"),
                                  "btc_usd": Decimal("60000"), "source": "stub"}
    chained = []
    esm.integrity_log = lambda st, m, **k: chained.append(f"{st}:{m}")
    import gs_common as _g
    _real = _g.integrity_log
    _g.integrity_log = lambda st, m, **k: chained.append(f"{st}:{m}")
    _prev = os.environ.get("GS_EXIT_AMOUNT")
    _d = tempfile.mkdtemp(prefix="gs_exitwarn_")
    _cwd = os.getcwd()
    try:
        os.chdir(_d)
        if env_amount is None:
            os.environ.pop("GS_EXIT_AMOUNT", None)
        else:
            os.environ["GS_EXIT_AMOUNT"] = env_amount
        sys.argv = (["exit_strategy_simulator"]
                    + ([argv_amount] if argv_amount else [])
                    + ["--method", "bisq", "--tor-proxy", "socks5h://127.0.0.1:9050",
                       "--outfile", "p.json"])
        buf = _io.StringIO()
        try:
            with _ctx.redirect_stdout(buf):
                esm.main()
        except SystemExit:
            pass
        out = buf.getvalue()
    finally:
        os.chdir(_cwd)
        _g.integrity_log = _real
        if _prev is None:
            os.environ.pop("GS_EXIT_AMOUNT", None)
        else:
            os.environ["GS_EXIT_AMOUNT"] = _prev
        shutil.rmtree(_d, ignore_errors=True)
    return ("command line" in out,
            any("on_argv" in c for c in chained),
            out)


_w, _c, _ = _drive_exit(None, "200")
check("exit: an argv amount still WARNS rather than passing silently", _w)
check("exit: ...and the warning reaches the integrity chain", _c)
_w2, _c2, _ = _drive_exit("200", None)
check("exit: the environment path stays quiet (nothing is on argv)", not _w2)
# The case all three hand-rolled copies got wrong: BOTH supplied. The env wins,
# but the argv copy is still in /proc/<pid>/cmdline and must be called out.
_w3, _c3, _out3 = _drive_exit("200", "900")
check("exit: env AND argv together still warns (the old `elif` went silent)", _w3)
check("exit: ...and says the two values disagree", "DISAGREE" in _out3)
check("exit: ...and the environment value is the one used",
      "200 XMR" in _out3 and "900 XMR" not in _out3)
check("exit: with neither source it refuses instead of guessing",
      "No amount. Set GS_EXIT_AMOUNT" in _exit_src)

# 2. WALLET-FILE LABELS. paranoia_mode deliberately never deletes the wallet,
#    so anything written into it survives every wipe. Labels naming each
#    address's ROLE hand a reader the answer with no analysis: which outputs
#    are decoys, which are carriers and in what order, which is the change
#    sweep -- and "GhostSpiral_entry" names the tool. Every on-chain heuristic
#    this pipeline defeats is bypassed by reading a string.
for _bad in ('label=f"Mix_', 'label=f"Decoy_', 'label=f"Carrier_',
             'label="ChangeSweep"'):
    check(f"labels: the wallet no longer records {_bad.split('=')[1][:14]}…",
          _bad not in _gs_a)
check("labels: subaddresses are created with an EMPTY label",
      _gs_a.count('label=""') >= 4)
check("labels: create_receive_wallet no longer defaults to a tool-naming label",
      'default="GhostSpiral_entry"' not in _crw_a)
check("labels: and it says why the default is empty",
      "never deletes" in _crw_a and "names the tool" in _crw_a)
# Nothing may start depending on a label, or the fix regresses into a bug.
check("labels: no code reads a label back (they were write-only decoration)",
      '.get("label")' not in _gs_a and '["label"]' not in _gs_a)

# 3. BLOCK HEIGHT vs the log's own timestamp coarsening. integrity_log buckets
#    its timestamp to 600s specifically to widen the correlation window against
#    blockchain timestamps -- and one line then wrote an exact height, which
#    pins the run to a single ~2-minute block and defeats the bucketing 5x.
check("chain: the sync height is coarsened, not exact",
      'rpc_sync_ok:height={h1}' not in _gs_a
      and "height~" in _gs_a)

# 4. THE RELAY SCHEDULE. The per-TX delays are the mechanism that stops a batch
#    relaying as one timing cluster. Writing their LENGTHS into a persistent,
#    index-keyed file hands a reader the exact schedule -- the correlation the
#    delays exist to destroy.
check("chain: the delay LENGTH is not written to the integrity chain",
      'delay:idx={real_idx}:secs={item.delay}' not in _bc_a)
check("chain: that a delay happened is still chained",
      'f"delay:idx={real_idx}"' in _bc_a)

# 5. WHAT paranoia_mode CANNOT DO. "Every phase reported success" reads as
#    "this host is clean of the run". The wallet is untouched by design -- it
#    is the money -- and it holds the balances, the history and every
#    subaddress the run created. Silence about that is a false-hope leak.
check("paranoia: the summary states the wallet survives the wipe",
      "THE WALLET IS STILL HERE" in _par_src)
check("paranoia: it explains the wallet holds the whole mix graph",
      "mix graph" in _par_src)
check("paranoia: it points at the real mitigation instead of implying none",
      "OPSEC_SETUP.md" in _par_src)
# It must not have quietly started deleting the wallet to make that true.
check("paranoia: it still does NOT delete wallet keys (that is the money)",
      "*.keys" not in _par_src)
# And the artifacts it DOES claim must really be covered.
for _pat in ("exitplan_*.json", "monero-wallet-rpc.log", "outputs_export.hex",
             "integrity_chain.log"):
    check(f"paranoia: {_pat} is in the wipe patterns", _pat in _par_src)


# ---------------------------------------------------------------------------
# THE SPEND ACCOUNT MUST BE THE MIX ACCOUNT.
#
# resolve_mix_account creates a fresh account and create_subs puts ENTRY and
# every mix subaddress in it -- and then stage 4 said
# `bal_account = receive_account_index if receive_mode else 0`, hard-coding 0
# for send. That one variable drives the balance poll, the peel carriers, the
# PLAN's account_index, the change-sweep destination, and change_target.
#
# So in send mode the rotation was theatre: the fresh account held the
# subaddresses while account 0 / subaddress 0 -- the wallet PRIMARY -- did
# every spend and received all the change, which the sweep then SPENT. It was
# also functionally wrong: the balance was polled from account 0 at ENTRY's
# index, a different subaddress entirely.
#
# Nothing failed. That is why it needs a test AND a runtime guard.
# ---------------------------------------------------------------------------
# code_only: the docstrings in this area QUOTE the buggy lines they replaced
# ("bal_account = receive_account_index if receive_mode else 0"), so a raw
# source search matches its own post-mortem and passes on the defect.
_gs_src3 = code_only(os.path.join(REPO, "GhostSpiral"))
check("spend account: send mode no longer hard-codes account 0",
      "bal_account = receive_account_index if receive_mode else 0" not in _gs_src3)
check("spend account: it is READ BACK from ENTRY, not assigned from a branch",
      "_src_account(addr_index, entry_addr)" in _gs_src3)
check("spend account: no branch assigns it from a shared mix account",
      "bal_account = sub_account" not in _gs_src3)
check("spend account: main() gets the pair from the resolver, not a literal",
      "bal_account, entry_index = resolve_entry_account(" in _gs_src3)
# The confirmation-wait must watch the same place the plan spends from. Each
# address now carries its OWN account, so this is per-address, not one shared
# value -- drive create_subs rather than grepping for a variable name.
class _FakeAcctRpc:
    """A wallet that hands out accounts and subaddresses like the real one:
    account 0 pre-exists, every create_account returns the next index."""
    def __init__(self): self.acct = 0; self.subs = {}
    def raw_request(self, method, params=None):
        if method == "create_account":
            self.acct += 1
            return {"account_index": self.acct}
        raise AssertionError(f"unexpected RPC {method}")
    def new_subaddress_indexed(self, account_index=0, label=""):
        self.subs[account_index] = self.subs.get(account_index, 0) + 1
        return (f"ADDR_{account_index}_{self.subs[account_index]}",
                self.subs[account_index])

_far = _FakeAcctRpc()
_subs, _ai2, _dec = ghost.create_subs(_far, 5, 3)
check("spend account: create_subs makes one subaddress per output", len(_subs) == 8)
check("spend account: EVERY output gets its OWN account -- a transaction "
      "cannot spend across accounts, so they can never be merged",
      len({_ai2[a][0] for a in _subs}) == len(_subs))
check("spend account: no output lands in account 0 (its subaddr 0 is the PRIMARY)",
      all(_ai2[a][0] != 0 for a in _subs))
check("spend account: decoys are isolated too -- they are funded fan-out "
      "outputs, so an unmergeable decoy is the point as much as a real one",
      len(_dec) == 3 and all(_ai2[a][0] != 0 for a in _dec))
check("spend account: _src_account and _src_index round-trip every address",
      all((ghost._src_account(_ai2, a), ghost._src_index(_ai2, a)) == _ai2[a]
          for a in _subs))
# An index alone stopped identifying an output: index 1 exists in every
# account, so resolving one without its account would spend the wrong money.
check("spend account: the same subaddress index recurs across accounts, so "
      "an index alone is no longer an identity",
      len({ghost._src_index(_ai2, a) for a in _subs}) < len(_subs))

# The runtime guard, driven directly.
class _RpcAddr:
    def __init__(self, mapping): self.mapping = mapping
    def raw_request(self, method, params):
        a, i = params["account_index"], params["address_index"][0]
        addr = self.mapping.get((a, i))
        return {"addresses": ([{"address_index": i, "address": addr}] if addr else [])}


_ok_rpc = _RpcAddr({(7, 3): "ENTRY_ADDR", (0, 3): "SOMEONE_ELSES_SUBADDR"})
try:
    ghost.verify_spend_source(_ok_rpc, 7, 3, "ENTRY_ADDR"); _vs_ok = True
except SystemExit:
    _vs_ok = False
check("spend guard: the correct (account, index) for ENTRY is accepted", _vs_ok)


def _vs_rejects(acct, idx, expect, rpc=_ok_rpc):
    try:
        ghost.verify_spend_source(rpc, acct, idx, expect); return False
    except SystemExit:
        return True


# THE EXACT BUG: the mix is in account 7, the spend says account 0. Account 0
# has a subaddress at that index too -- it is simply the wrong one.
check("spend guard: account 0 at ENTRY's index is REJECTED (the shipped bug)",
      _vs_rejects(0, 3, "ENTRY_ADDR"))
check("spend guard: an index the account does not have is rejected",
      _vs_rejects(7, 99, "ENTRY_ADDR"))


class _BoomRpc:
    def raw_request(self, *a, **k): raise RuntimeError("rpc down")


check("spend guard: an unverifiable source fails CLOSED, never assumed",
      _vs_rejects(7, 3, "ENTRY_ADDR", rpc=_BoomRpc()))
# DRIVE the resolver: it must verify the pair before handing it back, and it
# must refuse a bundle that disagrees with the wallet. A source search for the
# call site stopped meaning anything once the block moved into a function.
_calls = []
class _EntryRpc:
    def raw_request(self, method, params=None):
        if method == "get_address":
            return {"addresses": [{"address": "ENTRY_ADDR"}]}
        raise AssertionError(method)
_real_vss = ghost.verify_spend_source
try:
    ghost.verify_spend_source = lambda rpc, a, i, addr: _calls.append((a, i, addr))
    _ai3 = {"ENTRY_ADDR": (9, 4)}
    _got = ghost.resolve_entry_account(_EntryRpc(), _ai3, "ENTRY_ADDR", None)
    check("spend guard: the resolver returns ENTRY's own (account, index)",
          _got == (9, 4))
    check("spend guard: it verifies that exact pair before returning it",
          _calls == [(9, 4, "ENTRY_ADDR")])
    _got2 = ghost.resolve_entry_account(_EntryRpc(), _ai3, "ENTRY_ADDR", 9)
    check("spend guard: a bundle that AGREES with the wallet is accepted",
          _got2 == (9, 4))
    try:
        ghost.resolve_entry_account(_EntryRpc(), _ai3, "ENTRY_ADDR", 3)
        check("spend guard: a bundle that DISAGREES with the wallet aborts", False)
    except SystemExit:
        check("spend guard: a bundle that DISAGREES with the wallet aborts", True)
finally:
    ghost.verify_spend_source = _real_vss
# It must verify BEFORE the balance is read, or a wrong account still sizes a
# plan. The resolver owns both the verify and the return, and main() reads the
# balance from what it returned, so ordering is structural now rather than a
# question of which line comes first.
check("spend guard: the balance is read from the resolver's answer",
      "xmr_balance(rpc_primary, bal_account, entry_index)" in _gs_src3
      and _gs_src3.index("bal_account, entry_index = resolve_entry_account(")
      < _gs_src3.index("xmr_balance(rpc_primary, bal_account, entry_index)"))


# ---------------------------------------------------------------------------
# THE CHANGE SWEEP. A distribution cannot allocate its input exactly, so a
# remainder always comes back as change on the mix account's subaddress 0.
# Rotating the account moved that off the wallet's primary address, and
# rotating the peel carriers stopped it being SPENT -- but the value was still
# parked there: unmixed, and the one output of the fan-out that never moves.
#
# Two problems, not one. The OPSEC problem is the tell. The correctness
# problem is that roughly a tenth of the operator's balance was never mixed at
# all while the run reported success.
# ---------------------------------------------------------------------------
_gs_src2 = open(os.path.join(REPO, "GhostSpiral")).read()
check("changesweep: a _run_change_sweep helper exists",
      "def _run_change_sweep(" in _gs_src2)
# code_only(): these are substring checks over a function body, and this
# suite has been bitten six times by matching a phrase that lived only in a
# comment explaining the OLD defect.
_gs_code = code_only(os.path.join(REPO, "GhostSpiral"))
_cs_fn = _gs_code[_gs_code.index("def _run_change_sweep("):
                  _gs_code.index("def _stage5_run(")]
check("changesweep: it issues a SWEEP (whole balance, zero change of its own)",
      '"sweep": True' in _cs_fn)
check("changesweep: it carries no amount (a sweep has none)",
      '"amt"' not in _cs_fn)
check("changesweep: it spends the CHANGE index, not a guessed 0",
      '"src_index": change_index' in _cs_fn)
# It must wait for ALL the change, not merely for some. sweep_all can only
# spend UNLOCKED outputs -- proven on a real chain: a subaddress holding 2 XMR
# unlocked and 3 XMR still locked swept the 2 and LEFT THE 3. A peel chain
# makes one change output PER PEEL on this same subaddress, so the old
# "_wait_for_carrier(..., DUST_XMR, ...)" was satisfied by peel 0's change long
# before the last peel's had confirmed: the sweep ran early, took what had
# unlocked, abandoned the rest, and the caller printed "nothing is parked on
# the change address". A fan-out has one distribution tx, so the two conditions
# were identical there -- they stopped being identical when peel mode landed.
check("changesweep: it waits for ALL the change to settle, not just some",
      "_wait_for_change_settled(" in _cs_fn)
check("changesweep: ...and the settle condition is 'nothing still confirming'",
      "tot == unlk" in code_only(os.path.join(REPO, "GhostSpiral")))
# The success message must be VERIFIED, not asserted.
check("changesweep: it re-reads the balance instead of claiming success",
      "_change_residue(" in _cs_fn)
check("changesweep: a residual is reported honestly",
      "STILL on account" in _cs_fn)
check("changesweep: the clean case says the result was verified",
      "verified nothing is parked" in _cs_fn)
check("changesweep: a timeout is reported honestly, not silently swallowed",
      "NOT swept" in _cs_fn and "UNMIXED" in _cs_fn)
check("changesweep: the plan file is wiped after the round",
      "secure_delete_file(path)" in _cs_fn)

# The entry it builds must satisfy the signer's own validator.
_cs_entry = {"src": "change", "src_index": 0, "dst": "D", "sweep": True,
             "delay": 300, "extra": "ab" * 8}
try:
    airgap._validate_plan([_cs_entry]); _cs_ok = True
except SystemExit:
    _cs_ok = False
check("changesweep: the entry it builds passes the shipped signer's validator",
      _cs_ok)

# BOTH distribution modes must sweep. The peel chain forwards its remainder at
# every hop, which removed the spend hub -- but each peel still leaves
# (carrier reserve - real fee) as change, so an N-peel chain makes N deposits.
# Rotation stopped an address being spent, not being a sink.
_s5 = _gs_code[_gs_code.index("def _stage5_run("):]
_s5 = _s5[:_s5.index("\ndef ")] if "\ndef " in _s5[10:] else _s5
check("changesweep: the FAN-OUT path sweeps its change",
      _s5.count("_run_change_sweeps(") >= 1)
check("changesweep: the PEEL path sweeps its change too",
      _s5.count("_run_change_sweeps(") == 2)
check("changesweep: a failed sweep is reported in the run's incomplete list",
      _s5.count("incomplete.append") >= 3 and "unmixed" in _s5)
check("changesweep: stage 5 takes the sweep jobs as a parameter",
      "change_sweep_jobs=None" in _gs_code)
# The destinations must be provisioned BEFORE the spend, or a sweep has
# nowhere to go at the moment it is needed.
_prov = _gs_code[_gs_code.index("change_sweep_jobs = []"):
                 _gs_code.index("incomplete = _stage5_run(")]
check("changesweep: the destinations are created before the distribution runs",
      "new_subaddress_indexed(" in _prov)
check("changesweep: failing to create one warns that the change stays unmixed",
      "UNMIXED" in _prov)
check("changesweep: one destination is created per change location",
      "for _acct in change_accounts" in _prov)

# THE POINT OF THE SPLIT. N change outputs must be swept in N transactions,
# never collected into one: a transaction's inputs are public, so spending N
# outputs together is permanent proof that all N share an owner -- and in a
# peel chain those N outputs are the change of the N peels, so one tidy sweep
# publishes exactly the link the chain spent hours hiding. Measured on a chain
# running current consensus: six change outputs swept together produced ONE
# 6-input transaction; swept separately, six 1-in/2-out transactions.
#
# DRIVE it. A source grep would have passed on a loop that swept the same
# account N times, or on one that stopped after the first failure.
import io as _io, contextlib as _ctx
_swept = []
_real_cs = ghost._run_change_sweep
try:
    ghost._run_change_sweep = (lambda args, account, change_index, dest_addr,
                               dest_index, staging_dir, proxy, meta,
                               label="change sweep", seq=0, delay_window=None:
                               _swept.append((account, change_index, dest_addr,
                                              seq)) or account != 99)
    _jobs = [(5, 0, "DST5", 50), (6, 0, "DST6", 60), (99, 0, "DSTX", 70),
             (8, 0, "DST8", 80)]
    _buf = _io.StringIO()
    with _ctx.redirect_stdout(_buf):
        _failed = ghost._run_change_sweeps(None, _jobs, "stg", None, {})
    check("changesweep: one sweep per change location, never one collecting sweep",
          len(_swept) == len(_jobs))
    check("changesweep: each sweep names a DIFFERENT account",
          len({a for a, _, _, _ in _swept}) == len(_jobs))
    check("changesweep: each sweep goes to a DIFFERENT destination",
          len({d for _, _, d, _ in _swept}) == len(_jobs))
    check("changesweep: each sweep gets its own staging sequence number",
          len({q for _, _, _, q in _swept}) == len(_jobs))
    check("changesweep: a failing sweep is counted, not swallowed", _failed == 1)
    check("changesweep: ...and the remaining locations are still swept, "
          "not abandoned",
          [a for a, _, _, _ in _swept] == [5, 6, 99, 8])
    check("changesweep: the operator is told the sweeps were kept separate",
          "SEPARATE" in _buf.getvalue())
finally:
    ghost._run_change_sweep = _real_cs



# ---------------------------------------------------------------------------
# DAG HOPS ARE SWEEPS. A hop means "move everything from this subaddress to
# that one", and sweep_all is exactly that -- and, unlike transfer_split, it
# produces NO CHANGE OUTPUT. transfer_split has to choose the amount before
# the fee is known, so it always leaves a remainder that monerod returns to
# the account's subaddress 0: at wallets=10 deep=2 that was 40 hops each
# depositing dust on ONE address, the run's own convergence point.
# ---------------------------------------------------------------------------
_sweep = {"src": "A", "src_index": 4, "dst": "B", "sweep": True}
try:
    airgap._validate_plan([_sweep]); _sw_ok = True
except SystemExit:
    _sw_ok = False
check("sweep: a sweep entry validates without an amount", _sw_ok)


def _sweep_rejected(tx):
    try:
        airgap._validate_plan([tx]); return False
    except SystemExit:
        return True


# An amount on a sweep would be silently ignored while looking authoritative.
check("sweep: a sweep carrying 'amt' is REJECTED, not silently ignored",
      _sweep_rejected({"src": "A", "src_index": 4, "dst": "B", "sweep": True,
                       "amt": "1.0"}))
check("sweep: a sweep with 'destinations' is rejected (it has ONE destination)",
      _sweep_rejected({"src": "A", "src_index": 4, "dst": "B", "sweep": True,
                       "destinations": [{"address": "C", "amount": "1"}]}))
check("sweep: a sweep with no dst is rejected",
      _sweep_rejected({"src": "A", "src_index": 4, "sweep": True}))
check("sweep: a NON-sweep still requires dst+amt (the old rule is intact)",
      _sweep_rejected({"src": "A", "src_index": 4, "dst": "B"}))

# THE TAMPER CASE. Flipping `sweep` turns a fixed-amount hop into "send
# everything" from the same src_index to the same dst. If the fingerprint did
# not cover it, that manifest would still verify and the offline signer would
# authorise a completely different spend.
_fixed = {"src": "A", "src_index": 4, "dst": "B", "amt": "1.0", "delay": 5}
_swept = {"src": "A", "src_index": 4, "dst": "B", "sweep": True, "delay": 5}
check("sweep: flipping 'sweep' CHANGES the plan fingerprint (tamper detected)",
      airgap._compute_plan_fingerprint([_fixed])
      != airgap._compute_plan_fingerprint([_swept]))
check("sweep: the fingerprint is still deterministic for a sweep",
      airgap._compute_plan_fingerprint([_swept])
      == airgap._compute_plan_fingerprint([_swept]))
check("sweep: two sweeps to DIFFERENT destinations differ",
      airgap._compute_plan_fingerprint([_swept])
      != airgap._compute_plan_fingerprint(
          [{"src": "A", "src_index": 4, "dst": "Z", "sweep": True, "delay": 5}]))

# phase_create must actually call sweep_all, not transfer_split, for a sweep.
_ag_src = open(os.path.join(REPO, "airgap_tx_signer")).read()
check("sweep: phase_create calls sweep_all for a sweep entry",
      'raw_request("sweep_all"' in _ag_src)
check("sweep: sweep_all is called with no amount (it sends the balance)",
      "sweep_all" in _ag_src and '"address": tx["dst"]' in _ag_src)

# build_dag_plan must emit sweeps, and must NOT carry an amount on them.
_hops = ghost.build_dag_plan(
    _A(dag_mixing=True), Decimal("0.0024"), ["s1", "s2"],
    {"s1": Decimal("5"), "s2": Decimal("5")},
    {"s1": ["t1"], "s2": ["t2"]}, ["t1", "t2"],
    {"s1": (21, 11), "s2": (22, 12), "t1": (23, 13), "t2": (24, 14)},
    __import__("secrets"))
check("sweep: the DAG round plans one hop per fundable source", len(_hops) == 2)
# Each hop source lives in its own account, so the hop has to name it: index 1
# exists in every account, and spending the right index in the wrong account
# is silent.
check("sweep: every DAG hop names the account it spends from",
      sorted(h.get("account_index") for h in _hops) == [21, 22])
# The account and the index are separate fields and must not be confused:
# every hop source sits in its own account, so index 11 in account 21 and
# index 11 in account 22 are different money.
check("sweep: the account and the index are carried independently",
      sorted((h["account_index"], h["src_index"]) for h in _hops)
      == [(21, 11), (22, 12)])
check("sweep: every DAG hop is a sweep", all(h.get("sweep") is True for h in _hops))
check("sweep: no DAG hop carries an amount", all("amt" not in h for h in _hops))
check("sweep: each hop still names its own source index",
      sorted(h["src_index"] for h in _hops) == [11, 12])
check("sweep: a hop never targets its own source",
      all(h["dst"] != h["src"] for h in _hops))
# Every planned hop must survive the validator the signer will run on it.
try:
    airgap._validate_plan(_hops); _hops_ok = True
except SystemExit:
    _hops_ok = False
check("sweep: the shipped DAG plan passes the shipped signer's validator",
      _hops_ok)
# Dust sources are still filtered out rather than planned and failing later.
_dust = ghost.build_dag_plan(
    _A(dag_mixing=True), Decimal("0.0024"), ["s1"],
    {"s1": Decimal("0.00001")}, {"s1": ["t1"]}, ["t1"],
    {"s1": 11, "t1": 12}, __import__("secrets"))
check("sweep: a source too small to cover its own fee is not planned",
      _dust == [])
check("sweep: DAG mixing off plans nothing",
      ghost.build_dag_plan(_A(dag_mixing=False), Decimal("0.0024"), ["s1"],
                           {"s1": Decimal("5")}, {"s1": ["t1"]}, ["t1"],
                           {"s1": 11, "t1": 12}, __import__("secrets")) == [])


# ---------------------------------------------------------------------------
# WHICH ACCOUNT THE MIX RUNS IN decides where every leftover comes to rest.
#
# Verified against real monerod 0.18 (tests/real_fanout_change_testnet.py):
# change is returned to the SPENDING ACCOUNT's subaddress 0, not to the
# wallet's account 0. Running the mix in account 0 therefore sends the
# fan-out's unallocated remainder AND the dust from every DAG hop to the
# wallet's own primary address -- the same address on every run, so two runs
# share a change sink and are trivially the same wallet.
# ---------------------------------------------------------------------------
class _RpcAcct:
    def __init__(self, idx=7, boom=False):
        self.idx = idx; self.boom = boom; self.calls = []

    def raw_request(self, method, params):
        self.calls.append(method)
        if self.boom:
            raise RuntimeError("wallet is read-only")
        return {"account_index": self.idx}


_ra = _RpcAcct(idx=7)
# SEND mode no longer rotates HERE, and that is not a weakening. create_subs
# gives EVERY output its own fresh account, so ENTRY already lands in one and
# already never in account 0. A second account on top, that nothing spends and
# nothing receives, announced as "the mix account", would be the theatre this
# function's own docstring objects to.
check("mix account: SEND mode returns None rather than inventing an account",
      ghost.resolve_mix_account(_A(), _ra, False, 0) is None)
check("mix account: ...and creates nothing to leave orphaned in the wallet",
      "create_account" not in _ra.calls)
# Receive mode must NOT rotate: the money is already sitting in the bundle's
# account, so a new account here would point the pipeline at an empty one.
_rb = _RpcAcct(idx=7)
check("mix account: RECEIVE mode uses the bundle's account, unchanged",
      ghost.resolve_mix_account(_A(), _rb, True, 3) == 3)
check("mix account: RECEIVE mode does not create an account at all",
      "create_account" not in _rb.calls)
# FAIL CLOSED. Falling back to account 0 would put the run's change on the
# wallet's identity address while the operator believed it had been rotated
# away -- worse than not having the feature, because the belief is acted on.
# FAIL CLOSED, now enforced where the accounts are actually made. A wallet
# that cannot create one must stop the run, not hand back account 0 -- whose
# subaddress 0 is the wallet's PRIMARY address -- while the operator believes
# the outputs were isolated.
try:
    ghost.create_subs(_RpcAcct(boom=True), 3, 1)
    _rot_ok = False
except Exception:
    _rot_ok = True
check("mix account: create_subs ABORTS if an account cannot be made", _rot_ok)
class _ZeroAcctRpc:
    """A wallet answering create_account with 0 -- which cannot have happened,
    account 0 always pre-exists, and 0 is the one value that would hurt."""
    def raw_request(self, m, p=None): return {"account_index": 0}
    def new_subaddress_indexed(self, account_index=0, label=""): return ("A", 1)
try:
    ghost.create_subs(_ZeroAcctRpc(), 2, 0)
    _zero_ok = False
except Exception:
    _zero_ok = True
check("mix account: an output is never placed in account 0, even if the "
      "wallet claims it made one", _zero_ok)

_crw_src = open(os.path.join(REPO, "create_receive_wallet")).read()

# Asserted by BEHAVIOUR, not by grepping for a call that has since moved into
# gs_common.create_fresh_account. Both callers used to inline
#     int((acct or {}).get("account_index", 0))
# so a create_account that SUCCEEDED with an unexpected shape -- a dict with no
# account_index, a None result, an older or proxied wallet-rpc -- silently
# became account 0, whose subaddress 0 IS the wallet's primary address. The
# try/except around it only caught exceptions, and GhostSpiral then printed
# "Mix runs in a fresh account (0); the run's change stays off the wallet's
# primary address", which is the exact opposite of what had happened.
class _AcctRPC:
    def __init__(self, resp): self.resp = resp
    def raw_request(self, m, p=None): return self.resp


check("mix account: a well-formed create_account is accepted",
      gs.create_fresh_account(_AcctRPC({"account_index": 4})) == 4)
for _resp, _why in [
    ({}, "no account_index (absent is not zero)"),
    (None, "a None result"),
    ({"account_index": 0}, "index 0 — a NEW account is never 0, and 0 is the "
                           "primary-address account"),
    ({"account_index": True}, "a bool (True == 1 in Python)"),
    ({"account_index": "2"}, "a string"),
    ({"account_index": -1}, "a negative index"),
]:
    _refused = False
    try:
        gs.create_fresh_account(_AcctRPC(_resp))
    except RuntimeError:
        _refused = True
    check(f"mix account: REFUSES {_why}", _refused)

# ...and both callers must go through it rather than keeping a private copy.
# Source-text checks go through code_only(), which blanks comments and
# docstrings. Six checks in this suite have gone red because they matched a
# string that appeared only in a COMMENT explaining the old defect -- a search
# cannot tell a bug from its own post-mortem, and that failure mode is the
# wrong way round: noisy on refactors, silent on regressions.
check("mix account: create_receive_wallet uses the shared fail-closed helper",
      "create_fresh_account(" in code_only(os.path.join(REPO, "create_receive_wallet"))
      and 'get("account_index", 0)' not in code_only(
          os.path.join(REPO, "create_receive_wallet")))
check("mix account: GhostSpiral uses it too",
      "create_fresh_account(" in code_only(os.path.join(REPO, "GhostSpiral"))
      and 'get("account_index", 0)' not in code_only(
          os.path.join(REPO, "GhostSpiral")))
# ...and the stripper itself must actually work, or the two checks above are
# just weaker versions of the greps they replaced.
# Self-contained: this used to assert against a sentinel that happened to
# appear in a GhostSpiral comment, and went red the day that comment was
# deleted -- a test of the stripper that depended on unrelated prose.
_co_probe = os.path.join(_scratch, "co_probe.py")
open(_co_probe, "w").write(
    '# SENTINEL_IN_COMMENT = 1\n'
    'def f():\n'
    '    """SENTINEL_IN_DOCSTRING"""\n'
    '    s = "SENTINEL_IN_STRING"\n'
    '    SENTINEL_IN_CODE = 2\n'
    '    return s, SENTINEL_IN_CODE\n')
_co = code_only(_co_probe)
check("code_only(): a pattern present ONLY in a comment does not match",
      "SENTINEL_IN_COMMENT" not in _co)
check("code_only(): a pattern present ONLY in a docstring does not match",
      "SENTINEL_IN_DOCSTRING" not in _co)
check("code_only(): a string literal the code USES is kept",
      "SENTINEL_IN_STRING" in _co)
check("code_only(): real code is kept", "SENTINEL_IN_CODE" in _co)
check("code_only(): line numbers are preserved, so offsets still line up",
      len(_co.split(chr(10))) == len(open(_co_probe).read().split(chr(10))))
check("code_only(): real code is still visible",
      "create_fresh_account(" in code_only(os.path.join(REPO, "GhostSpiral")))
check("code_only(): string literals the tool uses are kept",
      "GS_WALLET_PASSWORD" in code_only(os.path.join(REPO, "GhostSpiral")))
check("mix account: it verifies the address in the account it actually used",
      "acct_idx" in _crw_src and "int(acct_idx), \"address_index\"" in _crw_src)
check("mix account: the bundle records the real account, not a hard-coded 0",
      '"account_index": acct_idx,' in _crw_src)
check("mix account: an operator forced into account 0 is warned",
      "wallet's PRIMARY address" in _crw_src)


# ---------------------------------------------------------------------------
# build_peel_plan: ROTATING CARRIERS.
#
# The previous design let monerod's change land where it always lands -- the
# account's subaddress 0 -- and spent THAT for every peel after the first. For
# an 8-destination chain that is subaddress 0 spent 7 times. Against anyone
# holding the view key that is not a probabilistic weakness but a walk: follow
# any peel's change input backwards and every hop lands on the same address
# until you reach the entry. A repeated spender is also the most reliable
# change heuristic there is, so the same address was labelled "this wallet's
# change" for free. The peel mode existed to beat fan-out clustering, and it
# did -- while building a cleaner signal in its place.
# ---------------------------------------------------------------------------
_pdests = ["Ma", "Mb", "Mc", "Md"]
_pamts = [Decimal("1.1"), Decimal("0.7"), Decimal("2.3"), Decimal("0.4")]
_pcar = [(f"Carrier{i}", 300 + i) for i in range(3)]
_prem = [Decimal("3.4"), Decimal("2.7"), Decimal("0.4")]
_peel = ghost.build_peel_plan(entry_index=9, change_index=0, dests=_pdests,
                              amounts=_pamts, carriers=_pcar, remainders=_prem)
check("peel: one peel per destination", len(_peel) == 4)
check("peel: peel 0 spends ENTRY (entry_index)", _peel[0]["src_index"] == 9)

from collections import Counter as _Ctr
_spent = _Ctr(p["src_index"] for p in _peel)
# The three properties the rotation exists to create.
check("peel: MAIN (subaddress 0) is spent ZERO times",
      _spent.get(0, 0) == 0)
check("peel: no address is spent more than twice",
      max(_spent.values()) <= 2)
check("peel: every peel spends a DISTINCT address (no repeated spender)",
      len(_spent) == len(_peel))
check("peel: peels 1..N spend the fresh carrier the previous peel paid",
      [p["src_index"] for p in _peel[1:]] == [c[1] for c in _pcar])
# The remainder is carried FORWARD as an explicit output, not left as change.
check("peel: every peel but the last pays its remainder to the next carrier",
      all("destinations" in p for p in _peel[:-1]))
check("peel: the last peel has no carrier output (nothing left to carry)",
      "destinations" not in _peel[-1])
check("peel: a carrier output names the next carrier's address",
      all(_peel[i]["destinations"][1]["address"] == _pcar[i][0] for i in range(3)))
check("peel: the carrier output carries the planned remainder",
      all(_peel[i]["destinations"][1]["amount"] == str(_prem[i]) for i in range(3)))
check("peel: the mix destination is still paid in the same tx",
      all(_peel[i]["destinations"][0]["address"] == _pdests[i] for i in range(3)))

check("peel: each peel targets ONE mix destination in order",
      [p["dst"] for p in _peel] == _pdests)
check("peel: each peel carries its own (unequal) amount",
      [p["amt"] for p in _peel] == [str(a) for a in _pamts])
check("peel: peel_num is sequential 0..N-1",
      [p["peel_num"] for p in _peel] == [0, 1, 2, 3])
check("peel: empty dests -> empty plan", ghost.build_peel_plan(9, 0, [], []) == [])

# A single-destination chain needs no carrier at all.
check("peel: a 1-peel chain needs no carrier and spends only ENTRY",
      ghost.build_peel_plan(9, 0, ["X"], [Decimal("1")])[0]["src_index"] == 9)

# THE REGRESSION GUARD. Falling back to subaddress 0 when carriers run out
# would silently rebuild the exact hub this design removes, and it would look
# like a working plan. It must raise instead.
def _no_carrier_raises(nc):
    try:
        ghost.build_peel_plan(9, 0, ["a", "b", "c"], [Decimal("1")] * 3,
                              carriers=[(f"C{i}", 400 + i) for i in range(nc)],
                              remainders=[Decimal("1")] * nc)
        return False
    except ValueError as e:
        return "hub" in str(e)


check("peel: NO carriers -> refuses, never falls back to subaddr 0",
      _no_carrier_raises(0))
check("peel: too FEW carriers -> refuses rather than reuse one",
      _no_carrier_raises(1))
check("peel: exactly enough carriers is accepted", not _no_carrier_raises(2))

# Ragged inputs never index out of range: zips to the shorter.
check("peel: mismatched dests/amounts zips to the shorter length",
      len(ghost.build_peel_plan(9, 0, ["a", "b", "c"], [Decimal("1")])) == 1)

# The whole-chain property, at the size the presets actually use.
_bigd = [f"d{i}" for i in range(10)]
_bigc = [(f"c{i}", 500 + i) for i in range(9)]
_big = ghost.build_peel_plan(7, 0, _bigd, [Decimal("1")] * 10,
                             carriers=_bigc, remainders=[Decimal("5")] * 9)
_bs = _Ctr(p["src_index"] for p in _big)
check("peel: a 10-peel chain still spends MAIN zero times", _bs.get(0, 0) == 0)
check("peel: a 10-peel chain has 10 distinct spenders", len(_bs) == 10)

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
# This assertion used to read `scrub_address("short") == "short"`, i.e. it
# LOCKED IN the fail-open: a value <=16 chars was returned whole by the one
# function callers rely on to withhold. The test was codifying the bug, so
# fixing the bug turned it red -- exactly as it should have from the start.
check("scrub_address: a 5-char value is masked, not passed through",
      gs.scrub_address("short") != "short")
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
# null-safety pattern: SwapKit routinely returns keys PRESENT-BUT-NULL, so
# .get("k", default) returns None (not default) and downstream .get() raises
# AttributeError. Drives the REAL GhostSpiral.parse_swap_route so a regression
# to `.get(k, {})` there is caught here. The previous version asserted on a
# local reimplementation of the parser, so reverting the shipped one would not
# have turned the test red -- exactly the "vacuous test" pattern the audit hit.
# The parser must NOT crash on null values -- an uncaught AttributeError in
# stage2 would abort the run after real BTC has already moved. Wrap in a
# helper that turns any raise into a FAIL, so a regression to
# `.get("transaction", {})` (which would raise on a null value) reports a
# clean failure instead of aborting the whole suite mid-run.
def _try_parse(route):
    try:
        return ghost.parse_swap_route(route)
    except Exception as e:
        return ("__RAISED__" + type(e).__name__, "", "")

check("nullsafe (real): null transaction returns empty deposit, no crash",
      _try_parse({"transaction": None, "expectedOutput": None})[0] == "")
check("nullsafe (real): null expectedOutput -> '0' fallback",
      _try_parse({"transaction": {"to": "X"}, "expectedOutput": None})[2] == "0")
check("nullsafe (real): calldata fallback when transaction is null",
      _try_parse({"transaction": None, "calldata": {"depositAddress": "Y"},
                  "expectedOutput": "1.2"})[0] == "Y")
check("nullsafe (real): memo picked up from tx_info",
      _try_parse({"transaction": {"depositAddress": "A", "memo": "SWAP:XMR"},
                  "expectedOutput": "1"})[1] == "SWAP:XMR")
check("nullsafe (real): calldata.data used as memo fallback",
      _try_parse({"calldata": {"to": "A", "data": "0xdeadbeef"},
                  "expectedOutput": "1"})[1] == "0xdeadbeef")

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
# ITEM 2 (audit-workflow): airgap_tx_signer._validate_plan MUST require
# src_index. A missing key defaulting to 0 spent from the wallet's primary
# subaddress instead of the mix subaddress the plan named.
# ---------------------------------------------------------------------------
airgap = load("airgap_tx_signer")

def expect_signer_reject(name, plan, phase="create"):
    try:
        airgap._validate_plan(plan, phase)
        check(f"src_index[{phase}]: {name} (should reject)", False)
    except SystemExit:
        check(f"src_index[{phase}]: {name} -> rejected", True)

expect_signer_reject("missing src_index",
                     [{"src": "A", "dst": "B", "amt": "0.4"}])
expect_signer_reject("src_index = None",
                     [{"src": "A", "src_index": None, "dst": "B", "amt": "0.4"}])
expect_signer_reject("src_index = -1",
                     [{"src": "A", "src_index": -1, "dst": "B", "amt": "0.4"}])
expect_signer_reject("src_index = 'seven' (string)",
                     [{"src": "A", "src_index": "seven", "dst": "B", "amt": "0.4"}])
expect_signer_reject("src_index = True (bool sneak)",
                     [{"src": "A", "src_index": True, "dst": "B", "amt": "0.4"}])
# Legitimate plans must still pass.
try:
    airgap._validate_plan([{"src": "A", "src_index": 0, "dst": "B", "amt": "0.4"}])
    check("src_index = 0 accepted (primary is legitimate for ENTRY case)", True)
except SystemExit:
    check("src_index = 0 accepted", False)
try:
    airgap._validate_plan([{"src": "A", "src_index": 7,
                            "destinations": [{"address": "X", "amount": "0.1"}]}])
    check("src_index = 7 with fan-out accepted", True)
except SystemExit:
    check("src_index = 7 with fan-out accepted", False)

# PHASE-AWARE: only phase_create consumes src_index (it becomes subaddr_indices).
# phase_sign signs already-built tx sets where the source is fixed, so requiring
# it there rejected legitimate sign-only runs for no security benefit.
try:
    airgap._validate_plan([{"src": "A", "dst": "B", "amt": "0.4"}], "sign")
    check("src_index[sign]: absent is ACCEPTED (phase_sign never reads it)", True)
except SystemExit:
    check("src_index[sign]: absent is ACCEPTED (phase_sign never reads it)", False)
# but a present-yet-invalid value is still rejected, in either phase
expect_signer_reject("present-but-invalid (-1)",
                     [{"src": "A", "src_index": -1, "dst": "B", "amt": "0.4"}], "sign")

# ---------------------------------------------------------------------------
# The plan FINGERPRINT must cover src_index. It is the field that decides which
# output is spent, so two plans differing only in it are NOT the same plan --
# yet they used to hash identically, leaving the create->sign guard blind to a
# swapped spend source.
# ---------------------------------------------------------------------------
_fp = airgap._compute_plan_fingerprint
_p7 = [{"src": "A", "src_index": 7, "dst": "B", "amt": "0.4"}]
_p0 = [{"src": "A", "src_index": 0, "dst": "B", "amt": "0.4"}]
_pN = [{"src": "A", "dst": "B", "amt": "0.4"}]
check("fingerprint: differing src_index -> DIFFERENT fingerprint", _fp(_p7) != _fp(_p0))
check("fingerprint: explicit 0 distinguishable from absent", _fp(_p0) != _fp(_pN))
check("fingerprint: still deterministic for an identical plan", _fp(_p7) == _fp(_p7))
check("fingerprint: still sensitive to destination",
      _fp(_p7) != _fp([{"src": "A", "src_index": 7, "dst": "OTHER", "amt": "0.4"}]))
check("fingerprint: still sensitive to amount",
      _fp(_p7) != _fp([{"src": "A", "src_index": 7, "dst": "B", "amt": "0.5"}]))

# COLLISIONS the old raw-concatenation scheme allowed. It hashed
# f"{dst}:{amt}" per TX into one stream with no record boundaries, so
# structurally different plans produced identical bytes. Each of these was
# verified to collide under the old scheme.
check("fingerprint: 2 single-dest TXs != 1 TX with 2 destinations "
      "(structurally different on-chain, used to collide)",
      _fp([{"src_index": 0, "dst": "X", "amt": "1"},
           {"src_index": 0, "dst": "Y", "amt": "2"}]) !=
      _fp([{"src_index": 0, "destinations": [{"address": "X", "amount": "1"},
                                             {"address": "Y", "amount": "2"}]}]))
check("fingerprint: per-TX broadcast delay is part of identity "
      "(swapped relay timing is an OPSEC change; used to collide)",
      _fp([{"src_index": 0, "dst": "B", "amt": "0.4", "delay": 60}]) !=
      _fp([{"src_index": 0, "dst": "B", "amt": "0.4", "delay": 9999}]))
check("fingerprint: destination ORDER is significant",
      _fp([{"src_index": 0, "destinations": [{"address": "X", "amount": "1"},
                                             {"address": "Y", "amount": "2"}]}]) !=
      _fp([{"src_index": 0, "destinations": [{"address": "Y", "amount": "2"},
                                             {"address": "X", "amount": "1"}]}]))
# Cosmetic fields must NOT invalidate a manifest: 'src' is a label read nowhere,
# and 'extra' is never forwarded to the RPC.
check("fingerprint: cosmetic 'src' label change does NOT change identity",
      _fp(_p7) == _fp([{**_p7[0], "src": "a-different-label"}]))
check("fingerprint: numeric and string amounts normalise identically",
      _fp([{"src_index": 0, "dst": "B", "amt": "0.4"}]) ==
      _fp([{"src_index": 0, "dst": "B", "amt": 0.4}]))

# ---------------------------------------------------------------------------
# MONEY PATH: the DAG hop must reserve the ACTUAL fee, not a percentage.
# The old formula was fanout_amt * 0.85, i.e. a 15% reserve -- but the fee is
# an ABSOLUTE amount, so the reserve shrinks with the hop while the fee does
# not. With a real daemon fee (~0.0024 XMR) every fanout_amt below ~0.016 XMR
# reserved LESS than the fee: the plan passed the dust guard and then failed
# "not enough money" inside transfer_split, AFTER the fan-out had already
# executed on-chain. Model both formulas and assert the new one is fundable.
# ---------------------------------------------------------------------------
from decimal import ROUND_DOWN as _RD
_REAL_FEE = Decimal(1200000 * 2000) / Decimal(10 ** 12)   # real monerod 0.18.3.1
_RESERVE = _REAL_FEE * Decimal("1.5")
_DUST = Decimal("0.0001")


def _hop_old(fanout):
    """The OLD shipped formula, kept only to demonstrate the band it broke."""
    return (fanout * Decimal("0.85")).quantize(Decimal("0.0001"))


def _hop_new(fanout):
    """Drives the REAL shipped function -- not a model of it. A formula
    reimplemented in the test cannot catch a regression in the original, which
    is exactly the vacuous-test pattern this suite keeps producing."""
    return ghost.compute_hop_amount(fanout, _REAL_FEE)


# The band where the OLD formula silently produced an unfundable hop.
_broken_old = [f for f in ["0.005", "0.01", "0.0141"]
               if _hop_old(Decimal(f)) > _DUST
               and (Decimal(f) - _hop_old(Decimal(f))) < _REAL_FEE]
check(f"money: the OLD 0.85 formula WAS unfundable for small fan-outs "
      f"(reproduced at {_broken_old})", len(_broken_old) == 3)

for _f in ["0.005", "0.01", "0.0141", "0.016", "0.02", "0.05", "1.0"]:
    _fan = Decimal(_f)
    _hop = _hop_new(_fan)
    if _hop <= _DUST:
        check(f"money: fanout={_f} -> hop skipped as unfundable (correct)", True)
    else:
        check(f"money: fanout={_f} -> hop {_hop} leaves >= the real fee for the TX",
              (_fan - _hop) >= _REAL_FEE)

check("money: hop never exceeds what the subaddress received",
      all(_hop_new(Decimal(f)) < Decimal(f) for f in ["0.005", "0.02", "1.0"]))
check("money: ROUND_DOWN quantise never rounds the hop UP past the output",
      _hop_new(Decimal("0.019999")) <= Decimal("0.019999") - _RESERVE)

# ---------------------------------------------------------------------------
# scrub_address exists to WITHHOLD. The old guard returned the whole string
# for anything <= 16 chars, i.e. it failed open in the one function every
# caller trusts to be safe in print()/integrity_log().
# ---------------------------------------------------------------------------
for _v in ["short", "sixteen_chars_16", "a" * 17, "4AdUnd" + "X" * 89]:
    check(f"scrub_address: len {len(_v)} is NOT returned verbatim",
          gs.scrub_address(_v) != _v)
check("scrub_address: masks a short value proportionally rather than exposing it",
      gs.scrub_address("sixteen_chars_16").count(".") == 3)
check("scrub_address: long address keeps head+tail only",
      gs.scrub_address("4AdUnd" + "X" * 89) == "4AdUndXX...XXXXXXXX")
check("scrub_address: values too short to identify anything pass through",
      gs.scrub_address("n/a") == "n/a")
check("scrub_address: None does not crash", gs.scrub_address(None) == "(none)")

# ---------------------------------------------------------------------------
# secure_delay: secrets.randbelow() raises on a non-positive bound, so the old
# body crashed whenever hi == lo or hi < lo. Callers pass valid ranges today,
# so this was a latent abort in the middle of a pipeline run.
# ---------------------------------------------------------------------------
for _lo, _hi in [(0, 0), (0.001, 0.001), (0.002, 0.001)]:
    try:
        gs.secure_delay(_lo, _hi)
        check(f"secure_delay({_lo},{_hi}) does not raise", True)
    except Exception as _e:
        check(f"secure_delay({_lo},{_hi}) does not raise ({type(_e).__name__})", False)

# ---------------------------------------------------------------------------
# The resource sentinel must not answer "fine" for a check it never ran.
# ---------------------------------------------------------------------------
check("resource_check raises a named error when psutil is missing (never "
      "silently returns True)",
      hasattr(gs, "ResourceCheckUnavailable") and
      issubclass(gs.ResourceCheckUnavailable, RuntimeError))
_real_rc = gs.resource_check
try:
    gs.resource_check = lambda *a, **k: (_ for _ in ()).throw(
        gs.ResourceCheckUnavailable("no psutil"))
    gs.require_resources()          # must warn and continue, not crash or exit
    check("require_resources survives a missing psutil (warns, continues)", True)
except BaseException as _e:
    check(f"require_resources survives a missing psutil ({type(_e).__name__})", False)
finally:
    gs.resource_check = _real_rc

# The fee margin must have ONE definition. It was written inline in three
# places (stage-4 budget, hop reserve, and the message reporting the reserve),
# so a changed margin would have made the printed number disagree with the
# arithmetic that actually ran.
check("money: hop_fee_reserve uses the shared FEE_SAFETY_MARGIN constant",
      ghost.hop_fee_reserve(_REAL_FEE) == _REAL_FEE * ghost.FEE_SAFETY_MARGIN)
check("money: the reserve the message reports IS the reserve the hop used",
      ghost.compute_hop_amount(Decimal("1.0"), _REAL_FEE) ==
      (Decimal("1.0") - ghost.hop_fee_reserve(_REAL_FEE)).quantize(
          Decimal("0.0001"), rounding=_RD))

# FAN-OUT must also be able to pay its own fee -- the same question the hop
# failed. It passes because the stage-4 budget already subtracts total_fees AND
# only FANOUT_SPEND_FRACTION of what remains is distributed. Driven through the
# REAL function so a regression in it is caught here.
_fo_bad = []
for _bal_s in ["0.05", "0.06", "0.1", "0.3", "1", "10"]:
    for _w in [3, 5, 10, 25]:
        for _d in [1, 2]:
            _bal = Decimal(_bal_s)
            _usable = _bal - (_REAL_FEE * ghost.FEE_SAFETY_MARGIN * (_w * 2 * _d))
            if _usable <= Decimal("0.0001"):
                continue
            _fa = ghost.compute_fanout_amount(_usable, _w)
            if _fa <= Decimal("0.0001"):
                continue
            if (_bal - _fa * _w) < _REAL_FEE:      # nothing left to pay the fee
                _fo_bad.append((_bal_s, _w, _d))
check(f"money: fan-out always leaves enough for its own fee "
      f"(unfundable combos: {_fo_bad})", not _fo_bad)
check("money: fan-out total never exceeds the spend fraction it derives from",
      ghost.compute_fanout_amount(Decimal("1.0"), 7) * 7 <=
      Decimal("1.0") * ghost.FANOUT_SPEND_FRACTION)
check("money: compute_fanout_amount rounds DOWN (never up past the budget)",
      ghost.compute_fanout_amount(Decimal("0.9999999"), 3) * 3 <=
      Decimal("0.9999999") * ghost.FANOUT_SPEND_FRACTION)

# ---------------------------------------------------------------------------
# ITEM 5: --btc-entry checksum. bech32_checksum_ok used across the codebase;
# GhostSpiral's BTC_RE-only check was the odd one out.
# ---------------------------------------------------------------------------
# A charset-valid, checksum-broken bech32 (last char flipped).
_typo = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"
check("btc-entry regression: format regex STILL matches the typo (proves the "
      "regex alone is not sufficient)", bool(ghost.BTC_RE.match(_typo)))
check("btc-entry regression: bech32_checksum_ok REJECTS the same typo",
      not gs.bech32_checksum_ok(_typo))

# ---------------------------------------------------------------------------
# ITEM 3b: thor_swap_preparer._btc_per_xmr must fail closed (return None), not
# silently fabricate 0.003 BTC/XMR as the slippage baseline.
# ---------------------------------------------------------------------------
thor = load("thor_swap_preparer")
_real_safe_get = thor.safe_get
try:
    thor.safe_get = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("oracle down"))
    _rate = thor._btc_per_xmr(None)
    check("thor: oracle failure -> _btc_per_xmr returns None (not fabricated 0.003)",
          _rate is None)
finally:
    thor.safe_get = _real_safe_get

# ---------------------------------------------------------------------------
# redact_addresses -- for output this toolchain did NOT write.
#
# monero-wallet-cli prints "Opened wallet: <95-char primary address>" on EVERY
# invocation at the default log level (measured on 0.18.3.1: no --log-level
# needed). The signer prints slices of that output when a step fails, so the
# operator can see why -- result.stdout[:200] and the tail of the combined
# streams. Measured on the real binary the address sits at offset 333 and lands
# in NEITHER window, so nothing leaked. But that safety is a byte count in
# someone else's startup banner, not a property of this code: one warning line
# fewer, a longer wallet path, or a trimmed help block slides the primary
# address -- the value that ties the operator to every subaddress in the mix --
# straight into a slice we print. These pin the structural version.
# ---------------------------------------------------------------------------
_REAL_PRIMARY = ("A2feEzqiMBDbMn1vnGj8pCeAMZzEoBBFTW4AR8AbSQGK1puUDwKKv2y1fzcu"
                 "yZgNqe4kxigJLCzZnbZXrMpEe3oz3ri7mh6")   # real testnet wallet
check("redact: a 95-char address is 95 chars", len(_REAL_PRIMARY) == 95)

_banner = ("Monero 'Fluorine Fermi' (v0.18.3.1-unknown)\n"
           f"Opened wallet: {_REAL_PRIMARY}\n"
           "Error: Failed to import outputs: Bad magic from outputs\n")
_red = gs.redact_addresses(_banner)
check("redact: the primary address is gone from wallet-cli output",
      _REAL_PRIMARY not in _red)
check("redact: no 90+ char base58 run survives anywhere in the result",
      not re.search(r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{90,}",
                    _red))
check("redact: the surrounding diagnostic text is preserved",
      "Bad magic from outputs" in _red and "Fluorine Fermi" in _red)
check("redact: what remains is the same masked form used everywhere else",
      gs.scrub_address(_REAL_PRIMARY) in _red)

# Every address form Monero produces, not just the standard one.
_SUBADDR = "8" + _REAL_PRIMARY[1:]                    # subaddress: also 95
_INTEGRATED = _REAL_PRIMARY + "0123456789ab"          # integrated: 106
for _label, _a in (("subaddress", _SUBADDR), ("integrated", _INTEGRATED)):
    check(f"redact: a {_label} address is masked too",
          _a not in gs.redact_addresses(f"Opened wallet: {_a}\n"))

# TWO addresses in one blob -- a sub() must catch every occurrence, not the
# first. This is the case a search-and-replace-once implementation fails.
_two = f"from {_REAL_PRIMARY} to {_SUBADDR}"
_red2 = gs.redact_addresses(_two)
check("redact: every address in the text is masked, not just the first",
      _REAL_PRIMARY not in _red2 and _SUBADDR not in _red2)

# Must NOT eat ordinary output. A txid is 64 hex chars, a sha256 digest is 64:
# both are below the 90-char floor and are legitimately printed by this
# toolchain, so redaction that swallowed them would destroy real diagnostics.
_txid = "a" * 64
check("redact: a 64-char txid/sha256 is left intact",
      gs.redact_addresses(f"relayed {_txid}") == f"relayed {_txid}")
check("redact: ordinary prose is unchanged",
      gs.redact_addresses("Error: fee too low") == "Error: fee too low")
check("redact: empty and None are safe",
      gs.redact_addresses("") == "" and gs.redact_addresses(None) is None)

# The signer must actually USE it on wallet-cli output, not merely import it.
_signer_src = open(os.path.join(REPO, "airgap_tx_signer")).read()
check("signer: redacts wallet-cli stdout before printing it",
      "redact_addresses(result.stdout)" in _signer_src)
check("signer: redacts wallet-cli stderr before printing it",
      "redact_addresses(result.stderr)" in _signer_src)
check("signer: redacts the import_outputs output tail before printing it",
      "redact_addresses(_txt" in _signer_src)
# ...and no raw slice of captured output survives anywhere in the file
check("signer: no unredacted slice of captured wallet-cli output is printed",
      "result.stdout[:" not in _signer_src and "result.stderr[:" not in _signer_src)

# The relayer prints the NODE's error text on every retry, and its `or res`
# fallback stringifies the WHOLE RPC response when there is no message field.
_bcast_src = open(os.path.join(REPO, "broadcast_signed_xmr")).read()
check("broadcast: redacts the node's error text before printing it",
      "redact_addresses(str(err.get(" in _bcast_src)
check("broadcast: redacts an exception message before it reaches the "
      "integrity chain ON DISK",
      "_emsg = redact_addresses(str(e))" in _bcast_src)
check("broadcast: no raw str(e) slice is logged or printed",
      "str(e)[:40]" not in _bcast_src and "str(e)[:80]" not in _bcast_src)


# ---------------------------------------------------------------------------
# MoneroRPC.new_subaddress_indexed must not use python-monero's CACHED account
# list. That list is a snapshot from Wallet construction; every other call here
# goes through raw_request, so an account created afterwards is invisible to
# it. create_receive_wallet does exactly that, one line earlier:
#     rpc.raw_request("create_account")  -> account_index 1
#     rpc.new_subaddress_indexed(account_index=1)   # accounts == [0]
# -> IndexError on real monero-wallet-rpc 0.18.3.1 (reproduced). So the DEFAULT
# receive path -- fresh account per receive, the thing keeping a run's change
# off the wallet primary -- crashed on every real wallet, while every offline
# suite passed because they all stub this method. The tests exercised the
# caller and never the call.
# ---------------------------------------------------------------------------
class _FakeBackend:
    def __init__(self, resp): self.resp = resp; self.calls = []
    def raw_request(self, method, params):
        self.calls.append((method, params))
        return self.resp


def _rpc_with(resp):
    r = gs.MoneroRPC.__new__(gs.MoneroRPC)
    r._backend = _FakeBackend(resp)
    # deliberately NOT set: a wallet object with a stale accounts list. If the
    # implementation reaches for self._wallet at all, this raises instead of
    # silently working on a fake.
    return r


_r = _rpc_with({"address": "8" + "Z" * 94, "address_index": 7})
_addr, _idx = _r.new_subaddress_indexed(account_index=3, label="")
check("new_subaddress_indexed goes through create_address, not the cache",
      _r._backend.calls[0][0] == "create_address")
check("...forwarding the account index it was asked for",
      _r._backend.calls[0][1]["account_index"] == 3)
check("...and returns the wallet's own address + index", _addr.startswith("8") and _idx == 7)
check("...without touching a cached wallet object",
      not hasattr(_r, "_wallet"))

# new_subaddress had its OWN copy of the stale lookup -- one of the pair could
# be fixed while the other stayed broken. It must share the implementation.
_r2 = _rpc_with({"address": "8" + "Y" * 94, "address_index": 2})
check("new_subaddress shares that implementation",
      _r2.new_subaddress(account_index=1) == "8" + "Y" * 94
      and _r2._backend.calls[0][0] == "create_address")

# The index is written into the receive bundle and is what the watcher polls,
# so an unusable one must raise rather than default to 0 -- polling index 0 of
# a fresh account watches its CHANGE SINK, which would report the wrong money.
for _bad, _why in [({"address": "8" + "Z" * 94}, "missing index"),
                   ({"address": "8" + "Z" * 94, "address_index": None}, "null index"),
                   ({"address": "8" + "Z" * 94, "address_index": -1}, "negative index"),
                   ({"address": "8" + "Z" * 94, "address_index": True}, "bool index"),
                   ({"address": "", "address_index": 1}, "empty address"),
                   ({}, "empty response")]:
    _raised = False
    try:
        _rpc_with(_bad).new_subaddress_indexed(account_index=1)
    except RuntimeError:
        _raised = True
    check(f"a create_address response with a {_why} raises, never defaults", _raised)

# explicit 0 IS valid and must be accepted (account 0's first subaddress)
_ok0 = _rpc_with({"address": "8" + "Q" * 94, "address_index": 0})
check("address_index 0 is accepted (it is a real index, not 'missing')",
      _ok0.new_subaddress_indexed(account_index=0)[1] == 0)


# ---------------------------------------------------------------------------
# get_subaddress_balance must not trust per_subaddress POSITIONALLY.
# The answer is reported as "the balance of the address you are watching" --
# receive_watch prints PAID on it, GhostSpiral plans a spend from it -- and it
# was read out of per_sub[0] without ever checking the entry's own indices.
# Measured on real wallet-rpc 0.18.3.1: asking about an index the wallet does
# NOT have returns HTTP 200 with a synthesised zero entry carrying that index,
# so the reply's shape is not self-evidently trustworthy.
# ---------------------------------------------------------------------------
class _Bk:
    def __init__(self, per): self.per = per
    def raw_request(self, m, p): return {"per_subaddress": self.per}


def _bal(per, acct=0, idx=7):
    r = gs.MoneroRPC.__new__(gs.MoneroRPC)
    r._backend = _Bk(per)
    return r.get_subaddress_balance(account_index=acct, address_index=idx)


check("the matching entry's balance is returned",
      _bal([{"account_index": 0, "address_index": 7,
             "balance": 5, "unlocked_balance": 4}]) == (5, 4))
check("...found by INDEX even when it is not first in the list",
      _bal([{"account_index": 0, "address_index": 3, "balance": 999,
             "unlocked_balance": 999},
            {"account_index": 0, "address_index": 7, "balance": 5,
             "unlocked_balance": 4}]) == (5, 4))
for _per, _why in [
    ([{"account_index": 0, "address_index": 3, "balance": 999,
       "unlocked_balance": 999}], "a DIFFERENT subaddress"),
    ([{"account_index": 9, "address_index": 7, "balance": 999,
       "unlocked_balance": 999}], "the right index in the WRONG account"),
    ([{"balance": 999, "unlocked_balance": 999}], "an entry with no index"),
]:
    _raised = False
    try:
        _bal(_per)
    except RuntimeError:
        _raised = True
    check(f"a reply describing {_why} is REFUSED, not reported as ours", _raised)
check("an empty per_subaddress is still a clean zero", _bal([]) == (0, 0))


# ---------------------------------------------------------------------------
# env_or_argv: the environment WINNING does not make argv safe.
# The old shape was `if env: return / elif argv: warn`, so supplying both
# skipped the warning AND the integrity-chain entry -- while the value sat in
# /proc/<pid>/cmdline (0444) all the same -- and silently discarded the
# operator's typed value with no mention that the two disagreed.
# ---------------------------------------------------------------------------
import io as _io, contextlib as _ctx
_seen_logs = []
_real_ilog = gs.integrity_log
gs.integrity_log = lambda st, m, **k: _seen_logs.append(f"{st}:{m}")
try:
    os.environ["GS_TEST_BOTH"] = "111"
    _buf = _io.StringIO()
    with _ctx.redirect_stdout(_buf):
        _v = gs.env_or_argv("GS_TEST_BOTH", "222", "The test value")
    _out = _buf.getvalue()
    check("the environment value still wins", str(_v) == "111")
    check("...but the operator IS warned that argv also carried it",
          "command line" in _out)
    check("...and the disagreement is surfaced", "DISAGREE" in _out)
    check("...and it reaches the integrity chain",
          any("on_argv_and_env" in l for l in _seen_logs))

    _buf = _io.StringIO()
    with _ctx.redirect_stdout(_buf):
        _v = gs.env_or_argv("GS_TEST_BOTH", None, "The test value")
    check("env alone stays quiet", _buf.getvalue().strip() == "")
    os.environ.pop("GS_TEST_BOTH", None)
    _buf = _io.StringIO()
    with _ctx.redirect_stdout(_buf):
        _v = gs.env_or_argv("GS_TEST_BOTH", "222", "The test value")
    check("argv alone still warns and is returned",
          str(_v) == "222" and "command line" in _buf.getvalue())
finally:
    gs.integrity_log = _real_ilog
    os.environ.pop("GS_TEST_BOTH", None)


# ---------------------------------------------------------------------------
# Peel-chain solvency arithmetic.
#
# The failure these exist for is not a crash: a peel chain that under-reserves
# runs several hops successfully, then fails "not enough money" with the whole
# remaining balance sitting on a carrier subaddress and no auto-resume. It was
# only ever caught by executing a chain on a real daemon, so the arithmetic
# that decides it is asserted directly here.
# ---------------------------------------------------------------------------
_HR = Decimal("0.0036")          # one hop's headroom
_AMTS = [Decimal(x) for x in ("1.5", "2.25", "0.8", "3.1", "1.05", "0.6")]

_res = ghost.peel_carrier_reserves(_AMTS, _HR)
check("peel_carrier_reserves: one reserve per carrier (n-1)",
      len(_res) == len(_AMTS) - 1)
check("peel_carrier_reserves: strictly decreasing down the chain",
      all(_res[i] > _res[i + 1] for i in range(len(_res) - 1)))
check("peel_carrier_reserves: last carrier still keeps a full headroom",
      _res[-1] == _HR)
check("peel_carrier_reserves: consecutive reserves differ by exactly one headroom",
      all(_res[i] - _res[i + 1] == _HR for i in range(len(_res) - 1)))
check("peel_carrier_reserves: no carriers for a single destination",
      ghost.peel_carrier_reserves([Decimal("1")], _HR) == [])
check("peel_carrier_reserves: empty plan is empty, not an IndexError",
      ghost.peel_carrier_reserves([], _HR) == [])
check("peel_entry_requirement: everything distributed plus carrier 0's reserve",
      ghost.peel_entry_requirement(_AMTS, _res) == sum(_AMTS, Decimal(0)) + _res[0])
check("peel_entry_requirement: empty plan needs nothing",
      ghost.peel_entry_requirement([], []) == Decimal(0))
check("peel_entry_requirement: a lone destination needs only itself",
      ghost.peel_entry_requirement([Decimal("2")], []) == Decimal("2"))

# THE INVARIANT. Walk the chain the way the daemon will and assert every hop
# is constructible: each carrier must receive at least what its peel spends
# PLUS one headroom, or that peel cannot be built and the funds stop there.
_fwd = ghost.peel_forward_amounts(_AMTS, _HR)
check("peel_forward_amounts: one forward per carrier",
      len(_fwd) == len(_AMTS) - 1)
_leftovers = []
for _i in range(len(_AMTS) - 1):
    _spend = _AMTS[_i + 1] + (_fwd[_i + 1] if _i + 1 < len(_fwd) else Decimal(0))
    _leftovers.append(_fwd[_i] - _spend)
check("peel chain: every hop keeps a full headroom after paying its way",
      all(x >= _HR for x in _leftovers))
# Tighter than solvency: the reserve schedule should leave each hop EXACTLY
# its own fee, so nothing accumulates on a carrier and nothing is over-held.
# The final hop is included -- it keeps one headroom, which is its fee, not a
# stranded remainder.
check("peel chain: every hop keeps exactly one headroom, no more and no less",
      all(x == _HR for x in _leftovers))

# A one-fee-per-hop reserve -- what shipped, and what died on peel 2 -- must
# FAIL this same invariant, or the test proves nothing.
_flat = [sum(_AMTS[i + 1:], Decimal(0)) + _HR for i in range(len(_AMTS) - 1)]
_flat_ok = True
for _i in range(len(_AMTS) - 1):
    _spend = _AMTS[_i + 1] + (_flat[_i + 1] if _i + 1 < len(_flat) else Decimal(0))
    if _flat[_i] - _spend < _HR:
        _flat_ok = False
check("peel chain: a flat one-headroom-per-carrier reserve is caught as insolvent",
      not _flat_ok)

# fit_peel_distribution
class _R:
    """Deterministic stand-in for SystemRandom in compute_fanout_amounts."""
    def randbelow(self, n): return n // 2
    def random(self): return 0.5
    def shuffle(self, seq): pass
    def randint(self, a, b): return (a + b) // 2

_usable = Decimal("9.5")
_base = ghost.compute_fanout_amounts(_usable, 6, Decimal("0.0024"), False, _R())
_fit, _frac = ghost.fit_peel_distribution(
    _base, Decimal("10"), _usable, 6, Decimal("0.0024"), False, _R(), _HR)
check("fit_peel_distribution: a fundable chain is left at the default fraction",
      _frac is None and _fit == _base)
check("fit_peel_distribution: ...and the result really is affordable",
      ghost.peel_entry_requirement(_fit, ghost.peel_carrier_reserves(_fit, _HR))
      <= Decimal("10") - _HR)

# A headroom large enough to make the default distribution unaffordable must
# shrink it rather than hand back a plan that strands funds.
_big = Decimal("0.4")
_fit2, _frac2 = ghost.fit_peel_distribution(
    _base, Decimal("10"), _usable, 6, Decimal("0.0024"), False, _R(), _big)
check("fit_peel_distribution: an expensive chain is shrunk, not accepted",
      _frac2 is not None and sum(_fit2, Decimal(0)) < sum(_base, Decimal(0)))
check("fit_peel_distribution: ...and the shrunk plan is affordable",
      ghost.peel_entry_requirement(_fit2, ghost.peel_carrier_reserves(_fit2, _big))
      <= Decimal("10") - _big)
check("fit_peel_distribution: the fraction it reports is one it actually offers",
      _frac2 in ghost.PEEL_BUDGET_FRACTIONS)

try:
    ghost.fit_peel_distribution(_base, Decimal("10"), _usable, 6,
                                Decimal("0.0024"), False, _R(), Decimal("5"))
    check("fit_peel_distribution: an unfundable chain raises before money moves",
          False)
except ghost.PeelBudgetError as _e:
    check("fit_peel_distribution: an unfundable chain raises before money moves",
          _e.hops == 5 and _e.hop_headroom == Decimal("5"))

# The reserve multiplier is a MEASURED quantity; a change to it should be a
# deliberate re-measurement, not a drive-by nudge. Guard the band it was
# measured into rather than the exact value.
check("PEEL_CARRIER_RESERVE_MULT covers the worst measured input count",
      ghost.PEEL_CARRIER_RESERVE_MULT * ghost.FEE_SAFETY_MARGIN >= Decimal("10"))
check("PEEL_CARRIER_RESERVE_MULT is not the pre-RingCT artifact value",
      ghost.PEEL_CARRIER_RESERVE_MULT < Decimal("50"))


# build_peel_stage_plan is the only peel code that touches the wallet, so it
# is the piece a pure-arithmetic test cannot reach. It shipped once with a
# NameError on a module-vs-local alias that every other test passed straight
# through, so DRIVE it against a fake wallet rather than reading the source.
class _FakeSubRpc:
    def __init__(self): self.next = 40; self.calls = []
    def new_subaddress_indexed(self, account_index, label=""):
        self.next += 1
        self.calls.append((account_index, label))
        return (f"SUB{self.next}", self.next)

_fr = _FakeSubRpc()
_dests = [f"MIX{i}" for i in range(5)]
_by = {a: Decimal("1.0") for a in _dests}
_real_cfa0 = ghost.create_fresh_account
try:
    _seq0 = iter(range(11, 99))
    ghost.create_fresh_account = lambda rpc, label="": next(_seq0)
    _plan, _chg0 = ghost.build_peel_stage_plan(
        _fr, 3, "ENTRYADDR", 7, _dests, _by, _HR)
finally:
    ghost.create_fresh_account = _real_cfa0
check("build_peel_stage_plan: one peel per destination", len(_plan) == len(_dests))
check("build_peel_stage_plan: peel 0 spends ENTRY",
      _plan[0]["src"] == "ENTRYADDR" and _plan[0]["src_index"] == 7)
check("build_peel_stage_plan: provisions one carrier per hop, not per destination",
      len(_fr.calls) == len(_dests) - 1)
check("build_peel_stage_plan: each carrier is created in its OWN fresh account",
      len({a for a, _ in _fr.calls}) == len(_dests) - 1)
check("build_peel_stage_plan: carriers are created UNLABELLED",
      all(l == "" for _, l in _fr.calls))
check("build_peel_stage_plan: no hop ever spends subaddress 0",
      all(p["src_index"] != 0 for p in _plan))
check("build_peel_stage_plan: each later peel spends the previous carrier",
      all(_plan[i]["src"] == f"SUB{40 + i}" for i in range(1, len(_plan))))
check("build_peel_stage_plan: every peel but the last also pays a carrier",
      all(len(p.get("destinations") or []) == 2 for p in _plan[:-1]))
check("build_peel_stage_plan: the last peel pays only its destination",
      not _plan[-1].get("destinations") or len(_plan[-1]["destinations"]) == 1)
check("build_peel_stage_plan: every peel carries an inter-hop delay",
      all(isinstance(p["delay"], int) and p["delay"] >= 180 for p in _plan))
check("build_peel_stage_plan: peels are numbered in order",
      [p["peel_num"] for p in _plan] == list(range(len(_dests))))
check("build_peel_stage_plan: the destinations are the mix addresses, in order",
      [p["dst"] for p in _plan] == _dests)

# A peel plan must therefore name a DIFFERENT account per hop, or the change
# all lands on one subaddress 0 and no amount of separate sweeping helps.
_fr2 = _FakeSubRpc()
_real_cfa = ghost.create_fresh_account
try:
    _acct_seq = iter(range(11, 99))
    ghost.create_fresh_account = lambda rpc, label="": next(_acct_seq)
    _plan2, _chg = ghost.build_peel_stage_plan(
        _fr2, 3, "ENTRYADDR", 7, [f"M{i}" for i in range(5)],
        {f"M{i}": Decimal("1.0") for i in range(5)}, _HR)
finally:
    ghost.create_fresh_account = _real_cfa
check("peel accounts: every hop names an account",
      all(isinstance(p.get("account_index"), int) for p in _plan2))
check("peel accounts: every hop runs in a DIFFERENT account",
      len({p["account_index"] for p in _plan2}) == len(_plan2))
check("peel accounts: peel 0 spends the mix account, not a fresh one",
      _plan2[0]["account_index"] == 3)
check("peel accounts: no hop runs in account 0 (its subaddr 0 is the PRIMARY)",
      all(p["account_index"] != 0 for p in _plan2))
check("peel accounts: one change location reported per hop",
      len(_chg) == len(_plan2))
check("peel accounts: the change locations are exactly the hops' accounts",
      sorted(_chg) == sorted(p["account_index"] for p in _plan2))
check("peel accounts: the signer's validator accepts a per-hop account",
      (lambda: (airgap._validate_plan(_plan2), True)[1])())


# ---------------------------------------------------------------------------
# WHERE the run lock sits, checked structurally.
#
# It was once taken 400 lines below the balance read, under a comment claiming
# "locking before the read is the point of locking at all". Everything it was
# supposed to guard -- the account rotation, the balance read, every mix
# subaddress, every peel carrier and per-hop account -- happened above it, and
# nothing noticed because no test knew where the lock was meant to be.
#
# AST, not grep: the comment that describes this defect names every one of
# these functions, so a source search matches its own post-mortem.
# ---------------------------------------------------------------------------
import ast as _ast
_gtree = _ast.parse(open(os.path.join(REPO, "GhostSpiral")).read())
_main_fn = next(n for n in _gtree.body
                if isinstance(n, _ast.FunctionDef) and n.name == "main")
_locks = [n for n in _ast.walk(_main_fn) if isinstance(n, _ast.With)
          and any(isinstance(i.context_expr, _ast.Call)
                  and getattr(i.context_expr.func, "id", "") == "run_lock"
                  for i in n.items)]
check("main() takes the run lock exactly once", len(_locks) == 1)
if _locks:
    _lk = _locks[0]
    _guarded = range(_lk.body[0].lineno, (_lk.end_lineno or _lk.body[-1].lineno) + 1)
    # Everything that mutates the wallet or reads the balance the plan is
    # sized against. A losing concurrent run must not get as far as any of it.
    _MUST_GUARD = {"resolve_mix_account", "create_subs", "xmr_balance",
                   "new_subaddress_indexed", "create_fresh_account",
                   "build_peel_stage_plan", "compute_fee_budget",
                   "fit_peel_distribution", "_stage5_run"}
    _outside = []
    for _n in _ast.walk(_main_fn):
        if isinstance(_n, _ast.Call):
            _nm = getattr(_n.func, "id", None) or getattr(_n.func, "attr", None)
            if _nm in _MUST_GUARD and _n.lineno not in _guarded:
                _outside.append((_nm, _n.lineno))
    check(f"every wallet mutation and balance read is INSIDE the run lock "
          f"(outside: {_outside})", not _outside)
    # ...and it is not so late that it only covers the tail of the run.
    _body_lines = _main_fn.end_lineno - _main_fn.lineno
    _guard_lines = (_lk.end_lineno or _lk.body[-1].lineno) - _lk.lineno
    check("the lock covers the bulk of main(), not just its tail",
          _guard_lines > _body_lines * 0.7)


# ---------------------------------------------------------------------------
# Per-TX broadcast delay: one source of truth, and operator-controllable.
# ---------------------------------------------------------------------------
check("hop delay: the default window is a named constant, not four literals",
      ghost.DEFAULT_HOP_DELAY == (180, 720))
# The literal appeared inline in four separate places, which is the same
# drift risk FEE_SAFETY_MARGIN was extracted for. code_only() so the comment
# that records the defect does not satisfy the check.
check("hop delay: no inline randbelow(540) + 180 survives in the code",
      "randbelow(540) + 180" not in _gs_code)

check("hop delay: no spec means the default", ghost.parse_hop_delay(None) == (180, 720))
check("hop delay: empty spec means the default", ghost.parse_hop_delay("") == (180, 720))
check("hop delay: a single number is a fixed delay, not a range",
      ghost.parse_hop_delay("600") == (600, 600))
check("hop delay: MIN-MAX parses", ghost.parse_hop_delay("21600-86400") == (21600, 86400))
for _bad, _why in (("abc", "not a number"), ("5-x", "half a number"),
                   ("-5", "negative"), ("900-100", "backwards"),
                   ("700000000", "past the broadcaster's 7-day cap")):
    try:
        ghost.parse_hop_delay(_bad)
        check(f"hop delay: {_why} is rejected ({_bad!r})", False)
    except ValueError:
        check(f"hop delay: {_why} is rejected ({_bad!r})", True)

import secrets as _sec
_dv = [ghost.hop_delay((100, 200)) for _ in range(300)]
check("hop delay: every draw is inside the window",
      all(100 <= v < 200 for v in _dv))
check("hop delay: the window is actually sampled, not pinned to one value",
      len(set(_dv)) > 20)
check("hop delay: a degenerate window returns that value, not a ZeroDivision "
      "or a randbelow(0)", ghost.hop_delay((300, 300)) == 300)
check("hop delay: the default window is used when none is given",
      180 <= ghost.hop_delay() < 720)

# It has to reach the plan, or the flag is decoration.
_fr3 = _FakeSubRpc()
_real_cfa3 = ghost.create_fresh_account
try:
    _sq = iter(range(21, 99))
    ghost.create_fresh_account = lambda rpc, label="": next(_sq)
    _p3, _ = ghost.build_peel_stage_plan(
        _fr3, 3, "ENTRYADDR", 7, [f"D{i}" for i in range(4)],
        {f"D{i}": Decimal("1.0") for i in range(4)}, _HR,
        delay_window=(9000, 9001))
finally:
    ghost.create_fresh_account = _real_cfa3
check("hop delay: the window reaches every peel in the plan",
      all(p["delay"] == 9000 for p in _p3))


# ---------------------------------------------------------------------------
# THE HOLDINGS REPORT. The other half of isolating every output.
#
# Isolation stops one transaction merging the mix, but it also means the run no
# longer ends with "the mix account" holding everything -- it ends with a dozen
# accounts holding a slice each. An operator who does not know that has traded
# a privacy win for forgotten money, which is the worse outcome.
# ---------------------------------------------------------------------------
class _BalRpc:
    def __init__(self, balances): self.balances = balances; self.asked = []
    def raw_request(self, method, params=None):
        assert method == "get_balance"
        a = params["account_index"]
        self.asked.append(a)
        return {"balance": self.balances.get(a, 0)}

_br = _BalRpc({4: 1_400_000_000_000, 5: 0, 6: 2_100_000_000_000, 7: 0})
_buf2 = _io.StringIO()
with _ctx.redirect_stdout(_buf2):
    _funded = ghost.report_holdings(_br, [4, 5, 6, 7, 6])
_out2 = _buf2.getvalue()
check("holdings: only accounts that actually hold money are listed",
      _funded == [(4, 1_400_000_000_000), (6, 2_100_000_000_000)])
check("holdings: a repeated account is asked about once, not twice",
      sorted(_br.asked) == [4, 5, 6, 7])
check("holdings: the operator is told how many accounts hold the run",
      "2 SEPARATE ACCOUNTS" in _out2)
check("holdings: each account number and balance is shown",
      "account    4" in _out2 and "1.4" in _out2
      and "account    6" in _out2 and "2.1" in _out2)
check("holdings: the total is shown, so nothing looks missing",
      "3.5" in _out2)
check("holdings: the RULE is stated, not just the list",
      "ONE ACCOUNT AT A TIME" in _out2)
check("holdings: it explains WHY (inputs are public), not just what to do",
      "inputs are public" in _out2)
check("holdings: the exchange-side link is named as unfixable here",
      "exchange" in _out2 and "not on-chain" in _out2)

# NOTHING ON DISK. create_subs stopped labelling subaddresses because labels
# live in the wallet file and hand a reader the run's structure; a file naming
# this run's accounts is the same disclosure renamed. The grouping is the only
# part the wallet does not already show.
_before = set(os.listdir("."))
_buf3 = _io.StringIO()
with _ctx.redirect_stdout(_buf3):
    ghost.report_holdings(_BalRpc({9: 5_000_000_000_000}), [9])
check("holdings: writes no file -- the grouping is what an adversary lacks",
      set(os.listdir(".")) == _before)
check("holdings: and says so, so the absence reads as deliberate",
      "Not written to disk" in _buf3.getvalue())

# The integrity chain may record that a report happened, never WHICH accounts:
# that file persists and the account numbers are the grouping.
_hl = []
_real_il2 = ghost.integrity_log
try:
    ghost.integrity_log = lambda st, msg: _hl.append(msg)
    with _ctx.redirect_stdout(_io.StringIO()):
        ghost.report_holdings(_BalRpc({11: 1, 12: 2}), [11, 12])
finally:
    ghost.integrity_log = _real_il2
check("holdings: the integrity chain records a COUNT, not the account numbers",
      _hl == ["holdings:2_accounts"])

# An empty run reports nothing rather than an empty banner.
_buf4 = _io.StringIO()
with _ctx.redirect_stdout(_buf4):
    _none = ghost.report_holdings(_BalRpc({}), [1, 2])
check("holdings: no funded accounts means no report at all",
      _none == [] and _buf4.getvalue().strip() == "")

# An unreadable account must not abort the report -- the other balances are
# still the operator's only map to their own money.
class _FlakyBal(_BalRpc):
    def raw_request(self, method, params=None):
        if params["account_index"] == 5:
            raise RuntimeError("rpc blew up")
        return super().raw_request(method, params)
with _ctx.redirect_stdout(_io.StringIO()):
    _f2 = ghost.report_holdings(_FlakyBal({4: 7, 5: 9, 6: 8}), [4, 5, 6])
check("holdings: one unreadable account does not lose the whole report",
      _f2 == [(4, 7), (6, 8)])

# report_completion must not print holdings for a half-executed run: the value
# is mid-flight on carriers, and a balance table would read as the result.
_buf5 = _io.StringIO()
try:
    with _ctx.redirect_stdout(_buf5):
        ghost.report_completion(_BalRpc({4: 1}), ["peel chain relayed 2/6"], [4])
    check("holdings: an incomplete run exits non-zero", False)
except SystemExit as _se:
    check("holdings: an incomplete run exits non-zero", _se.code == 1)
check("holdings: an incomplete run reports the shortfall, not a balance table",
      "NOT what was planned" in _buf5.getvalue()
      and "SEPARATE ACCOUNTS" not in _buf5.getvalue())


# ---------------------------------------------------------------------------
# THE ENTRY VEIL. A ThorChain memo is public, so the output that funded the run
# is the one thing an analyst gets for free. Ring signatures hide which
# transaction spent it only for as long as that transaction looks like the rest
# of the network. Measured on a chain running current consensus:
#
#     fan-out spending ENTRY directly :  1-in / 7-out, extra 259
#     peel 0 spending ENTRY directly  :  1-in / 3-out, extra 131
#     an ordinary sweep               :  1-in / 2-out, extra  44
#
# Two outputs is what most of the network makes. Seven is not, so an analyst
# holding the swap output lists the transactions referencing it and keeps the
# odd-shaped one.
# ---------------------------------------------------------------------------
class _VeilRpc:
    def __init__(self): self.acct = 40; self.made = []
    def raw_request(self, method, params=None):
        assert method == "create_account"
        self.acct += 1
        self.made.append(self.acct)
        return {"account_index": self.acct}
    def new_subaddress_indexed(self, account_index=0, label=""):
        return (f"VEIL_{account_index}", 1)

_vr = _VeilRpc()
_vplan, (_va, _vi, _vaddr) = ghost.build_entry_veil(_vr, "ENTRY_ADDR", 3, 7,
                                                    (100, 101))
check("veil: it is a SWEEP -- whole balance, zero change, two outputs",
      len(_vplan) == 1 and _vplan[0].get("sweep") is True)
check("veil: a sweep carries no amount (that is what makes it zero-change)",
      "amt" not in _vplan[0])
check("veil: it spends ENTRY, naming both its account and its index",
      _vplan[0]["src"] == "ENTRY_ADDR" and _vplan[0]["src_index"] == 7
      and _vplan[0]["account_index"] == 3)
check("veil: the carrier is a FRESH account, not ENTRY's",
      _va != 3 and _va in _vr.made)
check("veil: it pays that carrier", _vplan[0]["dst"] == _vaddr)
check("veil: it honours --hop-delay, which matters most here -- it is the one "
      "hop where an analyst knows both endpoints of the wait",
      _vplan[0]["delay"] == 100)
check("veil: the entry it builds passes the shipped signer's validator",
      (lambda: (airgap._validate_plan(_vplan), True)[1])())

# resolve_entry_veil decides what the distribution actually spends. Both paths
# must return the same shape or they drift.
class _VA:
    def __init__(self, **kw): self.__dict__.update(kw)

_ai4 = {"ENTRY_ADDR": (3, 7)}
_buf6 = _io.StringIO()
with _ctx.redirect_stdout(_buf6):
    _p, _sa, _ac, _ix, _b = ghost.resolve_entry_veil(
        _VeilRpc(), _VA(entry_veil=True), _ai4, "ENTRY_ADDR", 3, 7,
        Decimal("10"), Decimal("0.0024"), (100, 101))
check("veil: ON -- the distribution spends the CARRIER, not ENTRY",
      _sa != "ENTRY_ADDR" and (_ac, _ix) == (41, 1))
check("veil: ON -- the carrier is registered so its account can be resolved",
      _ai4.get(_sa) == (41, 1))
check("veil: ON -- the balance is reduced by the sweep's fee reserve",
      _b == Decimal("10") - ghost.hop_fee_reserve(Decimal("0.0024")))
check("veil: ON -- a plan is produced", len(_p) == 1)

_ai5 = {"ENTRY_ADDR": (3, 7)}
_buf7 = _io.StringIO()
with _ctx.redirect_stdout(_buf7):
    _p2, _sa2, _ac2, _ix2, _b2 = ghost.resolve_entry_veil(
        _VeilRpc(), _VA(entry_veil=False), _ai5, "ENTRY_ADDR", 3, 7,
        Decimal("10"), Decimal("0.0024"), (100, 101))
check("veil: OFF -- the distribution spends ENTRY unchanged",
      (_p2, _sa2, _ac2, _ix2, _b2) == ([], "ENTRY_ADDR", 3, 7, Decimal("10")))
check("veil: OFF -- and the operator is told what that costs them",
      "DIRECTLY" in _buf7.getvalue() and "memo is public" in _buf7.getvalue())
check("veil: OFF -- no carrier is registered",
      _ai5 == {"ENTRY_ADDR": (3, 7)})

# Stage 5 must WAIT for the veil to unlock: the distribution spends its output.
_s5v = _gs_code[_gs_code.index("def _stage5_run("):]
_s5v = _s5v[:_s5v.index(chr(10) + "def ")] if (chr(10) + "def ") in _s5v[10:] else _s5v
check("veil: stage 5 runs it as its own round, before the distribution",
      _s5v.index("veil_file") < _s5v.index("distribution_mode ==")
      if "distribution_mode ==" in _s5v else True)
check("veil: stage 5 waits for the carrier to confirm and unlock",
      "_wait_for_carrier(args, _vacct, _vidx, veil_need" in _s5v)
check("veil: a veil that never confirms stops the run instead of distributing",
      "nothing was distributed" in _s5v)


# ---------------------------------------------------------------------------
# _run_change_sweep must actually BUILD its sweep entry.
#
# It shipped with `secrets.SystemRandom().randbelow(540) + 180` from the commit
# that introduced it. randbelow is a MODULE function; SystemRandom has no such
# method, so every change sweep raised AttributeError while building its own
# plan -- the feature added to stop value being left parked could never run.
#
# Nothing caught it because every test that touches the change sweep STUBS
# this function. So drive it: stub only what talks to the outside world and let
# the entry get built for real.
# ---------------------------------------------------------------------------
_built = {}
_r_settle = ghost._wait_for_change_settled
_r_round = ghost._run_round
_r_res = ghost._change_residue
_r_sdf = ghost.secure_delete_file
_r_awj = ghost.atomic_write_json
try:
    ghost._wait_for_change_settled = lambda *a, **k: (True, 5_000_000_000)
    ghost._run_round = lambda *a, **k: None
    ghost._change_residue = lambda *a, **k: 0
    ghost.secure_delete_file = lambda *a, **k: True
    ghost.atomic_write_json = lambda payload, path: _built.update(payload)
    with _ctx.redirect_stdout(_io.StringIO()):
        _ok_cs = ghost._run_change_sweep(
            _VA(rpc_primary="http://127.0.0.1:1", tor_proxy=None),
            5, 0, "DEST_ADDR", 9, "stg", None, {"account_index": 5},
            label="change sweep 1/3", seq=1, delay_window=(600, 601))
    _tx = (_built.get("txs") or [{}])[0]
    check("changesweep: it builds its entry without raising", _ok_cs is True)
    check("changesweep: the entry is a sweep of the change subaddress",
          _tx.get("sweep") is True and _tx.get("src_index") == 0)
    check("changesweep: it names the account it sweeps, not meta's",
          _tx.get("account_index") == 5)
    check("changesweep: it pays the destination it was given",
          _tx.get("dst") == "DEST_ADDR")
    check("changesweep: the delay comes from the run's window",
          _tx.get("delay") == 600)
    check("changesweep: the entry passes the shipped signer's validator",
          (lambda: (airgap._validate_plan([_tx]), True)[1])())
finally:
    ghost._wait_for_change_settled = _r_settle
    ghost._run_round = _r_round
    ghost._change_residue = _r_res
    ghost.secure_delete_file = _r_sdf
    ghost.atomic_write_json = _r_awj

# The delay helper takes NO rng, so the wrong one cannot be handed to it again.
import inspect as _insp
check("hop delay: takes no rng parameter -- there is one right CSPRNG and "
      "offering the choice is what shipped the bug above",
      list(_insp.signature(ghost.hop_delay).parameters) == ["window"])
check("hop delay: no caller passes SystemRandom().randbelow anywhere",
      "SystemRandom().randbelow" not in _gs_code)


# ---------------------------------------------------------------------------
# _stage5_cleanup erases the PREVIOUS run's plans and must not touch THIS
# run's. It took (fanout_file, dag_file) by name, so the entry veil -- a third
# plan file -- was securely deleted between stage 4 writing it and stage 5
# running it. Variadic now, and driven here rather than read.
# ---------------------------------------------------------------------------
_cl = tempfile.mkdtemp(prefix="gs_clean_")
_keep = [Path(_cl) / n for n in ("unsigned_fanout_a.json", "unsigned_dag_a.json",
                                 "unsigned_veil_a.json")]
_stale = [Path(_cl) / n for n in ("unsigned_fanout_OLD.json",
                                  "unsigned_veil_OLD.json")]
for _f in _keep + _stale:
    _f.write_text("{}")
_cwd0 = os.getcwd()
try:
    os.chdir(_cl)
    ghost._stage5_cleanup(Path(_cl), *_keep)
finally:
    os.chdir(_cwd0)
check("cleanup: this run's plan files all survive",
      all(f.exists() for f in _keep))
check("cleanup: ...including the entry veil, which a named-parameter version "
      "erased before stage 5 could run it",
      (Path(_cl) / "unsigned_veil_a.json").exists())
check("cleanup: the previous run's plans are gone",
      not any(f.exists() for f in _stale))

# A None (no DAG round planned) must not become a KeyError or keep everything.
for _f in _stale:
    _f.write_text("{}")
_cwd0 = os.getcwd()
try:
    os.chdir(_cl)
    ghost._stage5_cleanup(Path(_cl), _keep[0], None, _keep[2])
finally:
    os.chdir(_cwd0)
check("cleanup: a skipped round passed as None is simply dropped",
      _keep[0].exists() and _keep[2].exists()
      and not any(f.exists() for f in _stale))
check("cleanup: ...and a file NOT named as current is still erased",
      not _keep[1].exists())
shutil.rmtree(_cl, ignore_errors=True)


# ---------------------------------------------------------------------------
# The veil's STAGE-5 wiring, driven. Source assertions are what let
# `secrets.SystemRandom().randbelow(540)` sit in the change sweep from the day
# it was written: reading a call site does not run it.
# ---------------------------------------------------------------------------
_seq5 = []
_r_rr, _r_wc, _r_rpc2 = ghost._run_round, ghost._wait_for_carrier, ghost._run_peel_chain
_r_nn, _r_tr, _r_cs = ghost.newnym, ghost.tor_recheck, ghost._run_change_sweeps
try:
    ghost._run_round = lambda a, f, sd, label: _seq5.append(("round", label))
    ghost._wait_for_carrier = lambda a, acct, idx, need, p, label: (
        _seq5.append(("wait", acct, idx, str(need))) or True)
    ghost._run_peel_chain = lambda *a, **k: (_seq5.append(("peels",)) or 3)
    ghost._run_change_sweeps = lambda *a, **k: 0
    ghost.newnym = lambda **k: None
    ghost.tor_recheck = lambda *a, **k: None
    _pf = Path(_scratch) / "plan.json"
    _pf.write_text(json.dumps({"meta": {"account_index": 1},
                               "txs": [{}, {}, {}]}))
    _vf = Path(_scratch) / "veil.json"
    _vf.write_text(json.dumps({"meta": {}, "txs": [{}]}))
    with _ctx.redirect_stdout(_io.StringIO()):
        ghost._stage5_run(_VA(dag_mixing=False), _pf, None, [], "stg", None,
                          Decimal("9"), distribution_mode="peel",
                          change_target=(4, 0), change_sweep_jobs=[],
                          veil_file=_vf, veil_target=(7, 2),
                          veil_need=Decimal("8.5"))
finally:
    (ghost._run_round, ghost._wait_for_carrier, ghost._run_peel_chain,
     ghost.newnym, ghost.tor_recheck, ghost._run_change_sweeps) = (
        _r_rr, _r_wc, _r_rpc2, _r_nn, _r_tr, _r_cs)

check("veil wiring: the veil round runs, and runs FIRST",
      _seq5 and _seq5[0] == ("round", "Entry veil"))
check("veil wiring: it waits for the veil carrier before distributing",
      _seq5[1][0] == "wait" and _seq5[1][1:3] == (7, 2))
check("veil wiring: it waits on the CARRIER's account, not the entry's",
      _seq5[1][1] == 7)
check("veil wiring: it waits for the amount the distribution needs",
      _seq5[1][3] == "8.5")
check("veil wiring: only then does the distribution run",
      ("peels",) in _seq5 and _seq5.index(("peels",)) > 1)

# A veil that never confirms must STOP, not distribute from an entry the plan
# no longer describes.
_seq6 = []
try:
    ghost._run_round = lambda a, f, sd, label: _seq6.append(("round", label))
    ghost._wait_for_carrier = lambda *a, **k: False
    ghost._run_peel_chain = lambda *a, **k: (_seq6.append(("peels",)) or 3)
    ghost.newnym = lambda **k: None
    ghost.tor_recheck = lambda *a, **k: None
    with _ctx.redirect_stdout(_io.StringIO()):
        _inc = ghost._stage5_run(_VA(dag_mixing=False), _pf, None, [], "stg",
                                 None, Decimal("9"), distribution_mode="peel",
                                 change_target=(4, 0), change_sweep_jobs=[],
                                 veil_file=_vf, veil_target=(7, 2),
                                 veil_need=Decimal("8.5"))
finally:
    (ghost._run_round, ghost._wait_for_carrier, ghost._run_peel_chain,
     ghost.newnym, ghost.tor_recheck, ghost._run_change_sweeps) = (
        _r_rr, _r_wc, _r_rpc2, _r_nn, _r_tr, _r_cs)
check("veil wiring: a veil that never confirms does NOT distribute",
      ("peels",) not in _seq6)
check("veil wiring: ...and the run reports why rather than claiming success",
      _inc and "nothing was distributed" in _inc[0])

# With the veil off there is no round 0 at all.
_seq7 = []
try:
    ghost._run_round = lambda a, f, sd, label: _seq7.append(("round", label))
    ghost._wait_for_carrier = lambda *a, **k: True
    ghost._run_peel_chain = lambda *a, **k: (_seq7.append(("peels",)) or 3)
    ghost._run_change_sweeps = lambda *a, **k: 0
    ghost.newnym = lambda **k: None
    ghost.tor_recheck = lambda *a, **k: None
    with _ctx.redirect_stdout(_io.StringIO()):
        ghost._stage5_run(_VA(dag_mixing=False), _pf, None, [], "stg", None,
                          Decimal("9"), distribution_mode="peel",
                          change_target=(4, 0), change_sweep_jobs=[],
                          veil_file=None)
finally:
    (ghost._run_round, ghost._wait_for_carrier, ghost._run_peel_chain,
     ghost.newnym, ghost.tor_recheck, ghost._run_change_sweeps) = (
        _r_rr, _r_wc, _r_rpc2, _r_nn, _r_tr, _r_cs)
check("veil wiring: --no-entry-veil skips round 0 entirely",
      not any(x[0] == "round" and x[1] == "Entry veil" for x in _seq7)
      and ("peels",) in _seq7)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
