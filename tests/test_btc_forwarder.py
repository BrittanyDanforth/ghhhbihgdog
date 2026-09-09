#!/usr/bin/env python3
"""THE FORWARDER, DRIVEN: it plans, it signs, it never broadcasts.

btc_forwarder is the vault-side stage-2 tool. It is run here through its
real main() with only the network stubbed -- the look at the deposit
address, the SwapKit quote, the price oracle, THORNode -- and every claim
is checked against the file it writes and the transaction inside it:

  * the happy path signs a transaction that an INDEPENDENT verification in
    this file accepts, pays the inbound exactly the settled amount minus the
    fee, carries the memo in an OP_RETURN laid out correctly, spends every
    settled output with RBF on, and is marked broadcast: false;
  * the quote is requested for EXACTLY the amount sent, in fixed notation;
  * THE MEMO DOES NOT FIT: on the default 80-byte policy every real forward
    is refused with the byte count, and only a raised policy lets it sign;
  * every refusal fires by its kind and signs nothing: unbound memo, wrong
    network, bad checksum, nothing settled, no fee estimate, fee out of
    band, fee eating the deposit, below the minimum, below the mix floor,
    a deviating quote, a THORNode mismatch or halt, a missing/invalid/
    wrong seed, no constant-time backend;
  * the seed comes from the environment only, is removed from it, and
    appears in neither the plan file nor the output;
  * what the hash chain gets is kinds without a digit in them.
"""
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
from contextlib import redirect_stdout
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "third_party"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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


from srcutil import fail_loudly_on_crash, code_only          # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_btc_forwarder.py")

_scratch = tempfile.mkdtemp(prefix="gs_fwd_")
os.chdir(_scratch)                     # integrity_chain.log lands here


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


F = load("btc_forwarder")
import gs_btc_tx as T                                        # noqa: E402
import gs_btc_watch as W                                     # noqa: E402
import gs_common as C                                        # noqa: E402
import gs_wake_proto as P                                    # noqa: E402
from embit import bip32, bip39                               # noqa: E402
from embit.networks import NETWORKS                          # noqa: E402
from embit.transaction import Transaction                    # noqa: E402
from embit.util import secp256k1 as _curve                   # noqa: E402

# --- fixtures ----------------------------------------------------------------
_MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
             "abandon abandon abandon about")
_XPUB = (bip32.HDKey.from_seed(bip39.mnemonic_to_seed(_MNEMONIC))
         .derive("m/84h/0h/0h").to_public().to_base58())
_ADDR0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"        # index 0
_ACCT = T.account_from_mnemonic(_MNEMONIC)
_PUB0 = T.key_for(_ACCT, 0, 0).get_public_key()
_DEST = "8" + "A" + "1" * 93                                  # 95 chars
_OTHER = "8" + "B" + "2" * 93
_INBOUND = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"       # valid mainnet
_MEMO = "=:XMR.XMR:" + _DEST + ":0/1/0"                       # 111 bytes
_TIP = 850000
_H1, _H2 = "ab" * 32, "cd" * 32
_ORACLE = Decimal("0.004")                                    # BTC per XMR


def _bundle(dest=_DEST):
    p = os.path.join(_scratch, f"wallet_{os.urandom(4).hex()}.json")
    with open(p, "w") as fh:
        json.dump({"schema": "gs_receive_wallet_v1", "created": 0,
                   "address": dest, "account_index": 1,
                   "subaddress_index": 1, "label": "t",
                   "rpc_endpoint": "http://127.0.0.1:1"}, fh)
    return p


_BUNDLE = _bundle()


class Net:
    """Everything the forwarder reaches over the network, canned."""

    def __init__(self, *, utxos=None, fee=10, inbound=_INBOUND, memo=_MEMO,
                 expected=None, oracle=_ORACLE, thornode=None,
                 look_error=None, post_error=None, routes=None,
                 factor=Decimal(1)):
        self.factor = factor                     # quote vs oracle, x
        self.utxos = utxos if utxos is not None else [
            {"tx_hash": _H1, "vout": 0, "value": 200000, "confirmations": 5}]
        self.fee = fee
        self.inbound, self.memo = inbound, memo
        self.expected = expected                 # None: derived from oracle
        self.oracle = oracle
        self.thornode = thornode
        self.look_error, self.post_error = look_error, post_error
        self.routes = routes
        self.look_calls, self.posts, self.gets, self.kinds = [], [], [], []

    def look(self, address, servers, proxy_url, **kw):
        self.look_calls.append((address, servers, proxy_url, kw))
        if self.look_error:
            raise self.look_error
        settled = sum(u["value"] for u in self.utxos
                      if u["confirmations"] > 0)
        pic = {"state": "confirmed" if settled else "not_seen",
               "confirmed_sat": settled, "unconfirmed_sat": 0,
               "settled_sat": settled, "confirmations": 5,
               "utxos": list(self.utxos), "tip": _TIP, "server": "s.onion",
               "cert_sha256": None}
        if kw.get("fee_blocks") is not None:
            pic["fee_sat_vb"] = self.fee
        return pic

    def safe_post(self, url, payload, proxies=None):
        self.posts.append((url, payload, proxies))
        if self.post_error:
            raise self.post_error
        if self.routes is not None:
            return {"routes": self.routes}
        exp = self.expected
        if exp is None:
            exp = str((Decimal(payload["sellAmount"]) / _ORACLE * self.factor)
                      .quantize(Decimal("0.00000001")))
        return {"routes": [{"targetAddress": self.inbound, "memo": self.memo,
                            "expectedBuyAmount": exp}]}

    def safe_get(self, url, proxies=None):
        self.gets.append((url, proxies))
        if isinstance(self.thornode, Exception):
            raise self.thornode
        return self.thornode

    def install(self):
        F.look = self.look
        F.safe_post = self.safe_post
        F.safe_get = self.safe_get
        F.btc_per_xmr_oracle = lambda proxies=None, getter=None: self.oracle
        F.integrity_log = lambda stage, kind, *a, **k: self.kinds.append(
            (stage, kind)) or ""
        F.verify_tor = lambda p: None
        F.newnym = lambda *a, **k: None
        F.validate_proxy = lambda p: {"http": p, "https": p}
        F.install_signal_handlers = lambda: None
        F.shutdown_requested = lambda: False
        return self


_PROXY = "socks5h://127.0.0.1:9050"


def run(net, *extra, seed=_MNEMONIC, dry_run=True, policy=120, outfile=None):
    """Drive main(). Returns (exit_code, stdout, plan_or_None, outfile)."""
    net.install()
    out = outfile or os.path.join(_scratch, f"plan_{os.urandom(4).hex()}.json")
    argv = ["--tor-proxy", _PROXY, "--electrum", "s.onion", "--xpub", _XPUB,
            "--index", "0", "--dest-from-receive-wallet", _BUNDLE,
            "--outfile", out]
    if dry_run:
        argv.append("--dry-run")
    if policy is not None:
        argv += ["--op-return-max-bytes", str(policy)]
    argv += list(extra)
    if seed is None:
        os.environ.pop(F.SEED_ENV, None)
    else:
        os.environ[F.SEED_ENV] = seed
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            code = F.main(argv)
    except SystemExit as e:
        code = e.code
    plan = None
    if os.path.exists(out):
        with open(out) as fh:
            plan = json.load(fh)
    return code, buf.getvalue(), plan, out


def _refusal(net, *extra, **kw):
    code, out, plan, _ = run(net, *extra, **kw)
    kinds = [k for s, k in net.kinds if k.startswith("refused:")]
    return code, out, plan, (kinds[-1][8:] if kinds else "")


# ===========================================================================
print("== the happy path: signed, verified independently, not broadcast ==")
_net = Net()
_code, _out, _plan, _outfile = run(_net)
check("exit 0, a plan file exists, mode 0600",
      _code == 0 and _plan is not None
      and oct(os.stat(_outfile).st_mode & 0o777) == "0o600")
check("the plan says: dry run, NOT broadcast, signed, schema v1",
      _plan["dry_run"] is True and _plan["broadcast"] is False
      and _plan["signed"] is True and _plan["schema"] == F.PLAN_SCHEMA)
_tx = Transaction.parse(bytes.fromhex(_plan["tx_hex"]))
check("the transaction spends the settled output with RBF, locktime = tip, "
      "version 2", len(_tx.vin) == 1 and _tx.vin[0].txid.hex() == _H1
      and _tx.vin[0].sequence == 0xFFFFFFFD and _tx.locktime == _TIP
      and _tx.version == 2)
_fee = _plan["fee_sat"]
check("output 0 pays the inbound vault EXACTLY settled minus the fee, and "
      "output 1 is the memo in an OP_RETURN laid out with OP_PUSHDATA1",
      len(_tx.vout) == 2 and _tx.vout[0].value == 200000 - _fee
      and _tx.vout[0].script_pubkey.data == T.address_script(_INBOUND).data
      and _tx.vout[1].value == 0
      and _tx.vout[1].script_pubkey.data
      == T.op_return_script(_MEMO.encode()).data
      and _tx.vout[1].script_pubkey.data[1] == 0x4c)
check("no change output: the whole deposit is forwarded (the sizing slack "
      "goes to the miner, never to an output that chains forwards)",
      len(_tx.vout) == 2 and _plan["send_sat"] + _fee == 200000)
check("INDEPENDENT VERIFICATION: the signature verifies against the public "
      "key this test derives itself from the seed at index 0",
      T.verify_signed(_tx, [200000], [_PUB0]))
check("...and fails against the key at index 1 (the signature is that "
      "key's, not just any key's)",
      not T.verify_signed(_tx, [200000],
                          [T.key_for(_ACCT, 0, 1).get_public_key()]))
check("the fee is the bound at the target rate: bound vB * 10 sat/vB, and "
      "the real size is at or under the bound, so the real rate is at or "
      "over 10", _fee == _plan["vsize_bound"] * 10
      and _plan["vsize"] <= _plan["vsize_bound"]
      and _plan["feerate_real_sat_vb"] >= 10
      and _plan["feerate_target_sat_vb"] == 10
      and T.measure(_tx)[0] == _plan["vsize"])
check("the memo is recorded with its byte count against the policy",
      _plan["memo"] == _MEMO and _plan["memo_bytes"] == 111
      and _plan["op_return_max_bytes"] == 120)
check("txid in the plan is the transaction's",
      _plan["txid"] == T.txid_hex(_tx))
check("expected and worst-case Monero are recorded (worst = 90% of expected)",
      Decimal(_plan["worst_case_xmr"])
      == (Decimal(_plan["expected_xmr"]) * Decimal("0.9"))
      .quantize(Decimal("0.000001")))

print("\n== what was asked of the network ==")
_addr, _servers, _proxy, _kw = _net.look_calls[0]
check("the look was at the address derived from the xpub at index 0, with "
      "min_conf 2, the fee target 3 in the SAME session, mainnet",
      _addr == _ADDR0 and _servers == [("s.onion", 50002, None)]
      and _kw["min_conf"] == 2 and _kw["fee_blocks"] == 3
      and _kw["network"] == "main")
_url, _payload, _prx = _net.posts[0]
check("the quote is a SwapKit v3 POST pinned to THORCHAIN, BTC.BTC -> "
      "XMR.XMR, slippage 10, to THIS deposit's XMR subaddress",
      _url.endswith("/v3/quote") and _payload["providers"] == ["THORCHAIN"]
      and _payload["sellAsset"] == "BTC.BTC"
      and _payload["buyAsset"] == "XMR.XMR" and _payload["slippage"] == 10
      and _payload["destinationAddress"] == _DEST)
check("...for EXACTLY the amount being sent, in fixed notation (fmt_btc), "
      "not str(Decimal)", _payload["sellAmount"]
      == C.fmt_btc(Decimal(_plan["send_sat"]) / Decimal(10 ** 8))
      and "E" not in _payload["sellAmount"])
check("...on its own isolation circuit, distinct from the oracle's",
      _prx and _prx != _net.look_calls[0][2]
      and _prx["http"] != C.isolated_proxy(_PROXY, "forward:oracle")["http"])
check("only one quote was asked (no re-quote loop)", len(_net.posts) == 1)

print("\n== the seed ==")
check("the seed is gone from the environment after the run",
      F.SEED_ENV not in os.environ)
_plan_text = open(_outfile).read()
check("the seed appears in neither the plan file nor the output",
      "abandon" not in _plan_text and "abandon" not in _out)
check("the output says NOT BROADCAST and names the txid; the deposit "
      "address is scrubbed, not printed in full",
      "NOT BROADCAST" in _out and _plan["txid"] in _out
      and _ADDR0 not in _out and _ADDR0[:8] in _out)
check("the hash chain got kinds only -- start, quoted, signed, not_broadcast "
      "-- and not one of them carries a digit",
      [k for s, k in _net.kinds if s == "forward"]
      == ["start", "quoted", "signed", "not_broadcast"]
      and not any(re.search(r"\d", k) for _, k in _net.kinds))

print("\n== THE MEMO DOES NOT FIT: the default policy refuses ==")
_code, _out, _plan, _kind = _refusal(Net(), policy=None)
check("on the DEFAULT 80-byte policy a real forward is REFUSED as "
      "memo_overflow, exit 2, nothing signed, no plan written",
      _code == 2 and _kind == "memo_overflow" and _plan is None)
check("...and the refusal names the byte count and the policy, and points "
      "at the plan section", "111 bytes" in _out and "80" in _out
      and "STAGE2_PLAN" in _out)
check("...the quote WAS fetched first (the memo has to be seen to be "
      "measured) but no seed was touched: refused before signing",
      len(_net.posts) == 1 and F.SEED_ENV in os.environ)
os.environ.pop(F.SEED_ENV, None)
check("a policy of exactly the memo's size (111) signs; 110 refuses",
      run(Net(), policy=111)[0] == 0
      and _refusal(Net(), policy=110)[3] == "memo_overflow")

print("\n== multiple settled outputs, plan-only, the fee override ==")
_net = Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 150000,
                   "confirmations": 5},
                  {"tx_hash": _H2, "vout": 2, "value": 90000,
                   "confirmations": 3},
                  {"tx_hash": "ef" * 32, "vout": 0, "value": 50000,
                   "confirmations": 0}])
_code, _out, _plan, _ = run(_net)
_tx = Transaction.parse(bytes.fromhex(_plan["tx_hex"]))
check("two settled outputs are both spent and both signed; the unconfirmed "
      "one is NOT an input and not in the plan",
      _code == 0 and len(_tx.vin) == 2
      and {i.txid.hex() for i in _tx.vin} == {_H1, _H2}
      and T.verify_signed(_tx, [150000, 90000], [_PUB0, _PUB0])
      and all(i["confirmations"] > 0 for i in _plan["inputs"])
      and len(_plan["inputs"]) == 2 and _plan["settled_sat"] == 240000)
check("...and the bound was sized for two inputs (larger than for one)",
      _plan["vsize_bound"] > run(Net())[2]["vsize_bound"])
check("...the plan counts the unsettled output it left, and the fee the "
      "transaction actually pays is EXACTLY the fee that was sized (no "
      "input's value leaks to the miner)",
      _plan["unsettled_outputs"] == 1 and _plan["skipped_dust"] == 0
      and 150000 + 90000 - _tx.vout[0].value == _plan["fee_sat"])

# A MINED BUT SHALLOW OUTPUT IS NOT AN INPUT. One confirmation under a
# min-conf of two used to be spent while not counted: its whole value went
# to the miner as fee. Found by review, fixed by selecting inputs by the
# same per-output depth the settled sum uses, and pinned here.
_net = Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 200000,
                   "confirmations": 5},
                  {"tx_hash": _H2, "vout": 1, "value": 70000,
                   "confirmations": 1}])
_code, _out, _plan, _ = run(_net)
_tx = Transaction.parse(bytes.fromhex(_plan["tx_hex"]))
check("an output mined ONE block deep under min-conf 2 is neither counted "
      "nor spent: one input, the fee is exactly the sized fee, and the "
      "shallow output is reported as not yet settled",
      _code == 0 and len(_tx.vin) == 1 and _tx.vin[0].txid.hex() == _H1
      and 200000 - _tx.vout[0].value == _plan["fee_sat"]
      and _plan["unsettled_outputs"] == 1 and _plan["settled_sat"] == 200000)
check("...and with --min-conf 1 the same output IS spent",
      len(Transaction.parse(bytes.fromhex(
          run(Net(utxos=_net.utxos), "--min-conf", "1")[2]["tx_hex"])).vin)
      == 2)

# DUST STORM. Two hundred 546-sat outputs parked on the address (anyone can
# send them) would, swept, make the fee eat the deposit and strand the real
# payment. Dust is left where it lies.
_storm = [{"tx_hash": ("%064x" % i), "vout": 0, "value": 546,
           "confirmations": 9} for i in range(1, 201)]
_net = Net(utxos=_storm + [{"tx_hash": _H1, "vout": 0, "value": 300000,
                            "confirmations": 9}])
_code, _out, _plan, _ = run(_net)
_tx = Transaction.parse(bytes.fromhex(_plan["tx_hex"]))
check("two hundred dust outputs beside a real deposit: the forward spends "
      "the deposit alone, leaves the dust, and says so",
      _code == 0 and len(_tx.vin) == 1 and _tx.vin[0].txid.hex() == _H1
      and _plan["skipped_dust"] == 200 and "200 dust left" in _out
      and _plan["settled_sat"] == 300000)
check("...an output is dust when it is worth no more than twice its own "
      "input cost at this rate (69 vB * 10 sat/vB * 2 = 1380): 1380 is left, "
      "1381 is spent",
      run(Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 200000,
                      "confirmations": 5},
                     {"tx_hash": _H2, "vout": 0, "value": 1380,
                      "confirmations": 5}]))[2]["skipped_dust"] == 1
      and run(Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 200000,
                          "confirmations": 5},
                         {"tx_hash": _H2, "vout": 0, "value": 1381,
                          "confirmations": 5}]))[2]["skipped_dust"] == 0)
check("an address holding only dust is refused nothing_economic, nothing "
      "signed", _refusal(Net(utxos=_storm))[3] == "nothing_economic"
      and _refusal(Net(utxos=_storm))[2] is None)
_code, _out, _plan, _ = run(Net(), "--plan-only", seed=None)
check("--plan-only needs no seed, writes an UNSIGNED transaction, signed "
      "false, and still no broadcast",
      _code == 0 and _plan["signed"] is False and _plan["broadcast"] is False
      and not Transaction.parse(bytes.fromhex(_plan["tx_hex"])).is_segwit
      and _plan["vsize"] is None and _plan["txid"])
_net = Net(fee=None)
_code, _out, _plan, _ = run(_net, "--feerate-sat-vb", "7")
check("--feerate-sat-vb overrides the server: the look asks for no estimate "
      "and the fee is at 7", _code == 0
      and _net.look_calls[0][3]["fee_blocks"] is None
      and _plan["feerate_target_sat_vb"] == 7)

print("\n== refusals, each by kind, each signing nothing ==")


def _r(name, net, *extra, **kw):
    code, out, plan, kind = _refusal(net, *extra, **kw)
    check(f"{name} -> refused:{kind or '(none)'} exit {code}",
          code == 2 and kind == name and plan is None)
    return out


check("without --dry-run: refused before anything is asked of the network",
      _refusal(Net(), dry_run=False)[3] == "not_dry_run"
      and not Net().look_calls)
_r("memo_unbound", Net(memo="=:XMR.XMR:" + _OTHER + ":0/1/0"))
_r("bad_memo", Net(memo=_MEMO + "\n:extra"))
_r("no_memo", Net(memo=""))
_r("inbound_wrong_network", Net(inbound="tb1q6rz28mcfaxtmd6v789l9rrlrusdpr"
                                          "r9pqcpvkl"))
_r("inbound_wrong_network", Net(inbound="1BitcoinEaterAddressDontSendf59kuE"))
_r("bad_inbound", Net(inbound=_INBOUND[:-1] + "x"))
_r("bad_inbound", Net(inbound=""))
_r("no_route", Net(routes=[]))
_r("quote_failed", Net(post_error=OSError("down")))
_r("nothing_settled", Net(utxos=[]))
_r("nothing_settled", Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 5,
                                   "confirmations": 0}]))
_r("no_fee_estimate", Net(fee=None))
_r("fee_out_of_band", Net(fee=500))
_r("fee_out_of_band", Net(fee=2), "--feerate-floor", "5")
_out = _r("fee_eats_deposit", Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                            "value": 20000,
                                            "confirmations": 5}], fee=100))
_out = _r("below_minimum", Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                        "value": 10100, "confirmations": 5}],
                               fee=1))
check("...the below-minimum refusal names the amount that must settle",
      "must settle first" in _out and "10000 sat" in _out)
_r("expected_unreadable", Net(expected="0"))
_r("expected_unreadable", Net(expected="abc"))
_r("below_mix_minimum", Net(), "--min-out-xmr", "1")
check("...while a mix floor the worst case clears passes",
      run(Net(), "--min-out-xmr", "0.01")[0] == 0)
_r("quote_deviates", Net(expected="0.9"))              # ~0.5 quoted -> 1.8x
_r("quote_deviates", Net(factor=Decimal("0.70")))        # 30% under the oracle
_out = run(Net(factor=Decimal("1.06")))[1]
check("a 6% deviation only warns, and the forward signs",
      "from the oracle" in _out and "SIGNED" in _out)
check("...and 24% passes the default 25% stop, while --max-slippage 0.2 "
      "refuses it", run(Net(factor=Decimal("1.24")))[0] == 0
      and _refusal(Net(factor=Decimal("1.24")), "--max-slippage", "0.2")[3]
      == "quote_deviates")
_net = Net(oracle=None)
_code, _out, _plan, _ = run(_net)
check("no oracle: the forward proceeds, says the quote is NOT cross-checked, "
      "and the chain records oracle_unavailable",
      _code == 0 and "NOT cross-checked" in _out
      and ("forward", "oracle_unavailable") in _net.kinds)

print("\n== THORNode's word on the inbound ==")
_ok_node = [{"chain": "BTC", "address": _INBOUND, "halted": False,
             "dust_threshold": "10000"},
            {"chain": "ETH", "address": "0xdead", "halted": True}]
_net = Net(thornode=_ok_node)
_code, _out, _plan, _ = run(_net, "--thornode", "https://thornode.example")
check("with --thornode the inbound is verified on a second circuit and the "
      "plan says so", _code == 0 and _plan["inbound_cross_checked"] is True
      and _net.gets and _net.gets[0][0].endswith("/thorchain/inbound_addresses")
      and _net.gets[0][1]["http"]
      == C.isolated_proxy(_PROXY, "forward:inbound")["http"]
      and "THORNode-verified" in _out)
_r("inbound_mismatch", Net(thornode=[{"chain": "BTC", "address": _ADDR0,
                                       "halted": False}]),
   "--thornode", "https://t")
_r("chain_halted", Net(thornode=[{"chain": "BTC", "address": _INBOUND,
                                   "halted": True}]), "--thornode", "https://t")
_r("chain_halted", Net(thornode=[{"chain": "BTC", "address": _INBOUND,
                                   "halted": False,
                                   "global_trading_paused": True}]),
   "--thornode", "https://t")
_r("inbound_unverified", Net(thornode=[{"chain": "ETH", "address": "x"}]),
   "--thornode", "https://t")
_r("inbound_unverified", Net(thornode=OSError("down")), "--thornode",
   "https://t")
_r("inbound_unverified", Net(thornode={"not": "a list"}), "--thornode",
   "https://t")
_r("below_thor_dust", Net(thornode=[{"chain": "BTC", "address": _INBOUND,
                                      "halted": False,
                                      "dust_threshold": "500000"}]),
   "--thornode", "https://t")
check("without --thornode the plan says the inbound was NOT cross-checked",
      run(Net())[2]["inbound_cross_checked"] is False)

print("\n== the seed and the backend ==")
_r("seed_missing", Net(), seed=None)
_r("seed_missing", Net(), seed="   ")
_r("seed_invalid", Net(), seed="abandon " * 11 + "abandon")
_r("seed_xpub_mismatch", Net(), seed="zoo " * 11 + "wrong")
os.environ[F.SEED_PASSPHRASE_ENV] = "TREZOR"
_r("seed_xpub_mismatch", Net())
check("...a passphrase is honoured and removed from the environment too",
      F.SEED_PASSPHRASE_ENV not in os.environ)
_saved = (_curve.NATIVE, _curve.BACKEND)
_curve.NATIVE, _curve.BACKEND = False, "python"
_r("backend_refused", Net())
_curve.NATIVE, _curve.BACKEND = _saved
check("...and with the native library back it signs again",
      run(Net())[0] == 0)

print("\n== configuration faults and failures ==")
for _label, _extra in (("op-return policy 0", ["--op-return-max-bytes", "0"]),
                       ("op-return policy 256",
                        ["--op-return-max-bytes", "256"]),
                       ("min-send under the dust threshold",
                        ["--min-send-sat", "5000"]),
                       ("floor above ceiling",
                        ["--feerate-floor", "50", "--feerate-ceiling", "10"]),
                       ("a negative index", ["--index", "-1"]),
                       ("min-conf 0", ["--min-conf", "0"]),
                       ("a bad mix floor", ["--min-out-xmr", "abc"])):
    _code, _o, _p, _kind = _refusal(Net(), *_extra, policy=None)
    check(f"bad args: {_label} -> refused:bad_args before any network call",
          _code == 2 and _kind == "bad_args")
_bad_bundle = os.path.join(_scratch, "wallet_bad.json")
with open(_bad_bundle, "w") as _fh:
    json.dump({"schema": "something_else", "address": _DEST}, _fh)
_net = Net().install()
_code = None
try:
    with redirect_stdout(io.StringIO()):
        _code = F.main(["--tor-proxy", _PROXY, "--electrum", "s.onion",
                        "--xpub", _XPUB, "--index", "0",
                        "--dest-from-receive-wallet", _bad_bundle,
                        "--outfile", os.path.join(_scratch, "x.json"),
                        "--dry-run"])
except SystemExit as _e:
    _code = _e.code
check("a bundle of the wrong schema is refused (the address that becomes "
      "the memo is never taken from an unrelated JSON)",
      _code == 2 and any(k == "refused:bad_bundle" for _, k in _net.kinds))
_net = Net(look_error=W.BtcWatchError("no Electrum server answered"))
_code, _out, _plan, _ = run(_net)
check("a look that fails is a FAILURE (exit 1, look_failed), not a refusal "
      "and not an invented plan", _code == 1 and _plan is None
      and ("forward", "look_failed") in _net.kinds)
_r("pin_mismatch", Net(look_error=W.PinMismatch("tls: pin")))

print("\n== what the source must not be ==")
_src = code_only(os.path.join(REPO, "btc_forwarder"))
check("FORWARD_MIN_SAT is gs_wake_proto.DEPOSIT_MIN_SAT: the two floors are "
      "one figure", F.FORWARD_MIN_SAT == P.DEPOSIT_MIN_SAT == 10_000)
check("the forwarder has no broadcast path: no Electrum broadcast method, no "
      "sendrawtransaction, no HTTP submit",
      "transaction.broadcast" not in _src and "sendrawtransaction" not in _src
      and "broadcast_tx" not in _src)
check("the seed is never an argument: no --seed, no --mnemonic",
      "--seed" not in _src and "--mnemonic" not in _src
      and "add_argument(\"--seed" not in _src)
check("the tool never opens a file for the seed (environment only)",
      "SEED_FILE" not in _src and "seed_file" not in _src)
check("the stage-1 client it uses still knows no method that could spend",
      "transaction.broadcast" not in code_only(os.path.join(REPO,
                                                            "gs_btc_watch.py")))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
