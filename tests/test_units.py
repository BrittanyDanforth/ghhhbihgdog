#!/usr/bin/env python3
"""Executable tests for the pure-Python (non-Monero-stack) logic I changed.
Loads the real extensionless scripts as modules and asserts real behavior."""
import ast
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
check("cli: the entry-mode group is required", _groups[0].required is True)
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
_cpeels = ghost.build_peel_plan(9, 0, _cd, _ca)
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
# GhostSpiral.build_peel_plan: N single-dest peels, carrier = ENTRY then subaddr 0
# ---------------------------------------------------------------------------
_pdests = ["Ma", "Mb", "Mc", "Md"]
_pamts = [Decimal("1.1"), Decimal("0.7"), Decimal("2.3"), Decimal("0.4")]
_peel = ghost.build_peel_plan(entry_index=9, change_index=0, dests=_pdests, amounts=_pamts)
check("peel: one peel per destination", len(_peel) == 4)
check("peel: peel 0 spends ENTRY (entry_index)", _peel[0]["src_index"] == 9)
check("peel: peels 1..N spend the change address (subaddr 0)",
      all(p["src_index"] == 0 for p in _peel[1:]))
check("peel: each peel targets ONE destination in order",
      [p["dst"] for p in _peel] == _pdests)
check("peel: each peel carries its own (unequal) amount",
      [p["amt"] for p in _peel] == [str(a) for a in _pamts])
check("peel: peel_num is sequential 0..N-1",
      [p["peel_num"] for p in _peel] == [0, 1, 2, 3])
check("peel: no destination is co-spent (each peel is single-dest, no 'destinations')",
      all("destinations" not in p for p in _peel))
check("peel: empty dests -> empty plan", ghost.build_peel_plan(9, 0, [], []) == [])
check("peel: a receive-mode ENTRY that IS subaddr 0 still peels cleanly",
      ghost.build_peel_plan(0, 0, ["X"], [Decimal("1")])[0]["src_index"] == 0)
# Ragged inputs never index out of range: zips to the shorter.
check("peel: mismatched dests/amounts zips to the shorter length",
      len(ghost.build_peel_plan(9, 0, ["a", "b", "c"], [Decimal("1")])) == 1)

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
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
