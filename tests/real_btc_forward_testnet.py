#!/usr/bin/env python3
"""Drive the SHIPPED btc_forwarder --broadcast against the REAL Bitcoin
testnet, over the REAL Tor, with only the swap quote stubbed.

WHY THIS EXISTS: tests/test_btc_forwarder.py drives the forwarder end to end
against an in-process SOCKS5 + TLS Electrum server, so it proves the code
path but not that a real Electrum server over a real Tor circuit accepts
what this tool signs, relays a 105-byte OP_RETURN, and lists the result.
This file does that, on a box that has Tor and a funded testnet address.
It SKIPS (exit 0) anywhere else -- this sandbox has no Tor and no egress --
so the ordinary suite still compiles and imports it.

WHAT IT PROVES, on the box that can run it:

  A. derivation: address 0 of the seed's testnet account is what the Pi's
     watch-only derivation says it is (the two halves agree on the key);
  B. the look, over Tor, on the address's own circuit, finds the settled
     testnet money the operator put there;
  C. sign + send + see, in one process, from memory: the REAL
     gs_btc_broadcast.submit hands the signed bytes to the configured
     servers and one accepts them, and the REAL seen() finds the txid in
     the address's history within the wait;
  D. the transaction's OP_RETURN is the real-shaped swap memo the stub
     quoted, laid out with OP_PUSHDATA1, and its first output pays the
     "inbound" -- address 1 of the same account -- which then shows the
     money as unconfirmed when looked at;
  E. (stage 5) --reconcile against the real history: every listed
     transaction fetched from the server and re-hashed, our forward found
     listed, the plan brought up to date, nothing sent again;
  F. (stage 6) the bump: --reconcile with --bump-after 0 and the estimate
     forced one above the rate the first send paid, while the forward still
     sits in the mempool -- a REAL server takes a BIP125 replacement of a
     transaction it holds (the same outpoints, today's rate, a fresh
     quote), lists it, and the old plan is rotated aside naming what it
     replaces. Skipped when act E found the forward already in a block.

WHAT IT CANNOT PROVE, said plainly: that THORChain accepts the memo. There
is no testnet THORChain and no testnet XMR quote, so the aggregator is
stubbed here (the "inbound" is our own address 1, the "expected" Monero is
derived from a fixed rate; THORNode's inbound list is stubbed to agree).
Only mainnet, with money, proves the swap starts; that is the stage the
design gates on every stage before it. Nor does it drive the re-send, the
evicted re-sign or the returned money: those need a server that refuses
the bytes, or a second payment to address 0 after this run -- pay it
again and run the same argv with --reconcile by hand; it must answer
`returned` until the payment settles, then forward it on its own.

Requires, in the environment:
  GS_BTC_TESTNET_SEED      a BIP39 mnemonic whose testnet account (m/84'/1'/0')
                           address 0 holds settled testnet coins
  GS_BTC_TESTNET_ELECTRUM  one or more Electrum servers, ';'-separated (a
                           comma is the pin's separator), HOST[:PORT][,PIN]
                           each (an .onion preferred); at
                           least one must run a node that relays a >80-byte
                           OP_RETURN (Bitcoin Core >= 30 default policy)
  GS_BTC_TESTNET_TOR       the Tor SOCKS proxy (default socks5h://127.0.0.1:9050)
  GS_BTC_TESTNET_OP_RETURN the OP_RETURN policy to declare (default 130)

SPENDS TESTNET COINS. Never run it with a mainnet seed; the tool refuses a
mainnet xpub for --network testnet, and this file refuses a seed whose
testnet account derives nothing before touching the network.
"""
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "third_party"))

_SEED = os.environ.get("GS_BTC_TESTNET_SEED", "").strip()
_SERVERS = [s for s in os.environ.get("GS_BTC_TESTNET_ELECTRUM", "").split(";")
            if s.strip()]
if not _SEED or not _SERVERS:
    print("SKIP: set GS_BTC_TESTNET_SEED and GS_BTC_TESTNET_ELECTRUM "
          "(';'-separated HOST[:PORT][,PIN]) on a box with Tor to run this")
    sys.exit(0)

_TOR = os.environ.get("GS_BTC_TESTNET_TOR", "socks5h://127.0.0.1:9050")
_POLICY = int(os.environ.get("GS_BTC_TESTNET_OP_RETURN", "130"))

import gs_btc_tx as T                                        # noqa: E402
import gs_btc_watch as W                                     # noqa: E402
from embit.transaction import Transaction                    # noqa: E402

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


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


_scratch = tempfile.mkdtemp(prefix="gs_fwd_testnet_")
os.chdir(_scratch)
F = load("btc_forwarder")

# --- A. the two halves agree on the key -------------------------------------
print("== A. derivation: the seed's testnet account and the Pi's xpub agree ==")
_acct = T.account_from_mnemonic(_SEED, "testnet", "")
_XPUB = _acct.to_public().to_base58()
_addr0 = W.derive_receive_address(_XPUB, 0, "testnet")
_addr1 = W.derive_receive_address(_XPUB, 1, "testnet")
check("address 0 derives from the xpub the seed publishes, and is testnet "
      "native segwit", _addr0.startswith("tb1q") and _addr1.startswith("tb1q")
      and _addr0 != _addr1
      and T.p2wpkh_script(T.key_for(_acct, 0, 0).get_public_key())
      .address(T.network_of("testnet")) == _addr0)
print(f"      deposit (index 0): {_addr0}")
print(f"      'inbound' (index 1): {_addr1}")

# --- B. the look, over Tor ---------------------------------------------------
print("\n== B. the look over Tor ==")
_servers = [W.parse_server(s) for s in _SERVERS]
_pic = W.look(_addr0, _servers, _TOR, min_conf=1, network="testnet",
              fee_blocks=3)
print(f"      state {_pic['state']}, settled {_pic['settled_sat']} sat, "
      f"tip {_pic['tip']}, fee {_pic.get('fee_sat_vb')} sat/vB, "
      f"server {_pic['server']}")
check("the address holds settled testnet money (fund index 0 and wait for "
      "one confirmation if not)", _pic["settled_sat"] > 0)
if _pic["settled_sat"] <= 0:
    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    print("FAILED:", FAILS)
    sys.exit(1)

# --- C/D. the forward: quote stubbed, everything else live -------------------
print("\n== C. sign + send + see, through the real forwarder ==")
_DEST = "8" + "A" * 94                       # a real-shaped subaddress
_bundle = os.path.join(_scratch, "wallet_testnet.json")
with open(_bundle, "w") as fh:
    json.dump({"schema": "gs_receive_wallet_v1", "created": 0,
               "address": _DEST, "account_index": 1, "subaddress_index": 1,
               "label": "t", "rpc_endpoint": "http://127.0.0.1:1"}, fh)
_RATE = Decimal("0.004")                     # BTC per XMR, fixed for the stub
_posts = []


def _fake_quote(url, payload, proxies=None):
    """The aggregator, stubbed: the 'inbound' is our own address 1, the
    memo a real-shaped swap memo with a zero limit (the forwarder must
    set its own), the expected Monero from the fixed rate."""
    _posts.append(payload)
    exp = (Decimal(payload["sellAmount"]) / _RATE).quantize(
        Decimal("0.00000001"))
    return {"routes": [{"targetAddress": _addr1,
                        "memo": f"=:XMR.XMR:{_DEST}:0/1/0",
                        "expectedBuyAmount": str(exp)}]}


def _fake_inbound(url, proxies=None):
    """THORNode's inbound list, stubbed to agree with the stubbed quote:
    there is no testnet THORNode, and a sending forward refuses to run
    without the cross-check (STAGE5_PLAN.md 3.5), so the check runs here
    against the same address the quote named. What this proves is that the
    check is wired and passes when the two agree; what it cannot prove is
    anything about the real THORNode."""
    return [{"chain": "BTC", "address": _addr1, "halted": False,
             "dust_threshold": "10000"}]


F.safe_post = _fake_quote
F.safe_get = _fake_inbound
F.btc_per_xmr_oracle = lambda proxies=None, getter=None: _RATE
_out = os.path.join(_scratch, "plan.json")
os.environ[F.SEED_ENV] = _SEED
os.environ["GS_BTC_XPUB"] = _XPUB
os.environ["GS_BTC_INDEX"] = "0"
argv = ["--broadcast", "--tor-proxy", _TOR, "--network", "testnet",
        "--dest-from-receive-wallet", _bundle, "--outfile", _out,
        "--min-conf", "1", "--op-return-max-bytes", str(_POLICY),
        "--seen-wait", "120", "--thornode", "https://thornode.stub.invalid"]
for s in _SERVERS:
    argv += ["--electrum", s]
buf = io.StringIO()
try:
    with redirect_stdout(buf):
        code = F.main(argv)
except SystemExit as e:
    code = e.code
finally:
    os.environ.pop("GS_BTC_XPUB", None)
    os.environ.pop("GS_BTC_INDEX", None)
    os.environ.pop(F.SEED_ENV, None)
text = buf.getvalue()
print("      " + "\n      ".join(text.strip().splitlines()))
plan = json.load(open(_out)) if os.path.exists(_out) else None
check("the forwarder exited 0 and wrote a plan", code == 0 and plan is not None)
check("the quote was asked for exactly the amount sent, to our destination",
      len(_posts) == 1 and plan is not None
      and _posts[0]["destinationAddress"] == _DEST
      and Decimal(_posts[0]["sellAmount"])
      == Decimal(plan["send_sat"]) / Decimal(10 ** 8))
check("a REAL Electrum server, over Tor, ACCEPTED the signed transaction",
      plan is not None and plan["broadcast_outcome"] == "accepted"
      and plan["broadcast"] is True and plan["broadcast_server"])
check("...and it was SEEN in the address's history within the wait",
      plan is not None and plan["seen"] is True
      and plan["seen_height"] is not None)
check("...so the signed hex is NOT kept on disk (the network has it)",
      plan is not None and plan["tx_hex"] is None)
check("the memo's zero limit was SET by the tool, and the memo laid out is "
      "over 80 bytes (the relay policy of the accepting server carried it)",
      plan is not None and plan["memo_limit_set"] is True
      and plan["memo_bytes"] > 80 and plan["memo"] != plan["memo_quoted"])

print("\n== D. the 'inbound' sees the money ==")
_pic1 = W.look(_addr1, _servers, _TOR, min_conf=1, network="testnet")
print(f"      index 1: state {_pic1['state']}, unconfirmed "
      f"{_pic1['unconfirmed_sat']} sat, confirmed {_pic1['confirmed_sat']}")
check("address 1 shows the forwarded amount (unconfirmed or confirmed)",
      plan is not None
      and _pic1["unconfirmed_sat"] + _pic1["confirmed_sat"] >= plan["send_sat"])
_pic0 = W.look(_addr0, _servers, _TOR, min_conf=1, network="testnet")
check("address 0's spent outputs are gone from its unspent list",
      _pic0["settled_sat"] < _pic["settled_sat"])

# --- E. the reconciliation, against the real history ------------------------
print("\n== E. --reconcile: the real history, each transaction fetched ==")
# The tap after a forward runs this (stage 5): the forwarder reads the
# address's history from a real server -- blockchain.transaction.get for
# every listed transaction, parsed here -- finds our transaction listed, and
# brings the plan up to date without sending anything. What it proves: the
# history path works against a real server over Tor. What it cannot prove
# here: the re-send, the evicted re-sign and the returned money, which need
# a server that refuses the bytes or a second payment to the address; act
# on those by hand -- pay address 0 again after this run and run the same
# argv with --reconcile: it must answer `returned` until the payment
# settles, then forward it on its own.
_before = len(_posts)
argv_r = [a for a in argv if a != "--broadcast"] + ["--reconcile"]
buf_r = io.StringIO()
os.environ[F.SEED_ENV] = _SEED
os.environ["GS_BTC_XPUB"] = _XPUB
os.environ["GS_BTC_INDEX"] = "0"
try:
    with redirect_stdout(buf_r):
        code_r = F.main(argv_r)
except SystemExit as e:
    code_r = e.code
finally:
    os.environ.pop("GS_BTC_XPUB", None)
    os.environ.pop("GS_BTC_INDEX", None)
    os.environ.pop(F.SEED_ENV, None)
print("      " + "\n      ".join(buf_r.getvalue().strip().splitlines()))
plan_r = json.load(open(_out)) if os.path.exists(_out) else None
check("--reconcile found our transaction LISTED by a real server (the "
      "history read, each transaction fetched and re-hashed) and reported "
      "done", code_r == 0 and plan_r is not None
      and plan_r.get("reconciled_ts") and plan_r["seen"] is True
      and plan_r["txid"] == plan["txid"])
check("...it asked for no quote and rotated no plan: nothing was sent again",
      len(_posts) == _before and not [
          f for f in os.listdir(_scratch)
          if f.startswith("plan.") and f.endswith(".json") and f != "plan.json"
          and f[5:-5].isdigit()])

# --- F. the bump, against the real mempool -----------------------------------
print("\n== F. --reconcile --bump-after 0: the forward replaced while it sits ==")
# Stage 6 (STAGE6_PLAN.md 3.1): a forward of ours listed in the mempool past
# --bump-after at a rate under today's estimate is REPLACED -- the same
# outpoints at today's rate, quoted afresh, the new plan naming the old.
# The drill cannot wait two hours or move the market, so the window is zero
# and the estimate is forced one above the rate the first send paid
# (--feerate-sat-vb): the replacement is due at once, and pays the floor a
# node holding the original takes (the original's fee plus its own size).
# What it proves: a real server over Tor accepts a BIP125 replacement of a
# transaction it holds, and lists it. What it cannot: a stuck predecessor
# behind a later plan, or a replacement priced over several earlier
# signatures -- those are driven against the mock in test_btc_forwarder.
_paid = int((plan_r or {}).get("feerate_target_sat_vb") or 0)
_mined = int((plan_r or {}).get("seen_height") or 0) > 0
if plan_r is None or _mined or not _paid:
    print("      skipped: the forward is already in a block, or act E left "
          "no plan with a rate; there is nothing to replace")
else:
    _before_f = len(_posts)
    argv_f = argv_r + ["--bump-after", "0", "--feerate-sat-vb",
                       str(_paid + 1)]
    buf_f = io.StringIO()
    os.environ[F.SEED_ENV] = _SEED
    os.environ["GS_BTC_XPUB"] = _XPUB
    os.environ["GS_BTC_INDEX"] = "0"
    try:
        with redirect_stdout(buf_f):
            code_f = F.main(argv_f)
    except SystemExit as e:
        code_f = e.code
    finally:
        os.environ.pop("GS_BTC_XPUB", None)
        os.environ.pop("GS_BTC_INDEX", None)
        os.environ.pop(F.SEED_ENV, None)
    print("      " + "\n      ".join(buf_f.getvalue().strip().splitlines()))
    plan_f = json.load(open(_out)) if os.path.exists(_out) else None
    _chain_f = F._plan_chain(_out)
    _old_f = json.load(open(_chain_f[1])) if len(_chain_f) > 1 else {}
    check("with the window at zero and the estimate one above the rate paid, "
          "--reconcile REPLACED the forward: a NEW transaction over the SAME "
          "outpoints, accepted by a real server and seen, the plan saying "
          "`bumped` and naming the one it replaces",
          code_f == 0 and plan_f is not None
          and plan_f.get("reconcile_reason") == "bumped"
          and plan_f.get("replaces") == plan_r["txid"]
          and plan_f.get("txid") != plan_r["txid"]
          and plan_f.get("broadcast_outcome") == "accepted"
          and plan_f.get("seen") is True
          and {(i["tx_hash"], i["vout"]) for i in plan_f.get("inputs") or []}
          == {(i["tx_hash"], i["vout"]) for i in plan_r.get("inputs") or []})
    check("...at a higher real rate, paying the original's fee plus its own "
          "size (BIP125), quoted afresh for the smaller amount",
          plan_f is not None
          and plan_f.get("fee_sat", 0) >= plan_r["fee_sat"] + plan_f.get("vsize_bound", 0)
          and plan_f.get("feerate_real_sat_vb", 0) > plan_r["feerate_real_sat_vb"]
          and plan_f.get("send_sat", 0) < plan_r["send_sat"]
          and len(_posts) == _before_f + 1)
    check("...and the original plan is rotated aside, the chain two",
          len(_chain_f) == 2 and _old_f.get("txid") == plan_r["txid"])

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
sys.exit(1 if FAIL else 0)
