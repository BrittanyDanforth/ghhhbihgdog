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
# {LIMIT} is filled by the fake aggregator at quote time with the worst-case
# arrival in 1e8 base units -- a chain-enforced minimum output a careful
# quote would carry. A literal 0 there is a swap at ANY price: the tool does
# not trust the field, it writes its own floor in (checked further down).
_MEMO = "=:XMR.XMR:" + _DEST + ":{LIMIT}/1/0"
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
                 factor=Decimal(1), submit=None, seen=None, clock=None):
        self.factor = factor                     # quote vs oracle, x
        self.clock = clock                       # the quote-age clock
        # THE BROADCAST SIDE, canned: `submit` is the dict bcast.submit
        # would return (or an exception to raise, or "real" to leave the
        # real function in place); `seen` likewise. Every call is recorded.
        self.submit_result = submit
        self.seen_result = seen
        self.submits, self.seens = [], []
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
        pic = {"state": ("confirmed" if settled
                         else "seen" if self.utxos else "not_seen"),
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
        memo = self.memo
        if "{LIMIT}" in memo:
            try:
                _w = Decimal(exp) * Decimal("0.9")
            except Exception:                                # noqa: BLE001
                _w = Decimal(0)
            memo = memo.replace("{LIMIT}", str(int(_w * 10 ** 8)))
        self.last_memo = memo
        return {"routes": [{"targetAddress": self.inbound, "memo": memo,
                            "expectedBuyAmount": exp}]}

    def safe_get(self, url, proxies=None):
        self.gets.append((url, proxies))
        if isinstance(self.thornode, Exception):
            raise self.thornode
        return self.thornode

    def _submit(self, raw_hex, expected_txid, address, servers, proxy_url,
                **kw):
        self.submits.append({"raw_hex": raw_hex, "txid": expected_txid,
                             "address": address, "servers": servers,
                             "proxy": proxy_url, **kw})
        r = self.submit_result
        if isinstance(r, Exception):
            raise r
        return dict(r) if r else _UNREACHABLE

    def _seen(self, txid, address, servers, proxy_url, **kw):
        self.seens.append({"txid": txid, "address": address,
                           "servers": servers, "proxy": proxy_url, **kw})
        r = self.seen_result
        if isinstance(r, Exception):
            raise r
        return dict(r) if r else _NOT_SEEN

    def install(self):
        F.look = self.look
        F.safe_post = self.safe_post
        F.safe_get = self.safe_get
        F.bcast_submit = (_REAL_SUBMIT if self.submit_result == "real"
                          else self._submit)
        F.bcast_seen = (_REAL_SEEN if self.seen_result == "real"
                        else self._seen)
        F._clock = self.clock or _REAL_CLOCK
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
_REAL_SUBMIT, _REAL_SEEN, _REAL_CLOCK = F.bcast_submit, F.bcast_seen, F._clock
_ACCEPTED = {"outcome": "accepted", "server": "s.onion", "cert_sha256": None,
             "codes": [], "attempts": 1, "mismatched": 0,
             "pin_mismatch": False}
_AMBIGUOUS = {**_ACCEPTED, "outcome": "ambiguous", "server": None}
_REJECTED = {**_AMBIGUOUS, "outcome": "rejected", "codes": [1, 1],
             "attempts": 2}
_UNREACHABLE = {**_AMBIGUOUS, "outcome": "unreachable", "attempts": 2}
_SEEN0 = {"seen": True, "height": 0, "server": "s.onion", "cert_sha256": None,
          "polls": 1, "asked": True}
_NOT_SEEN = {**_SEEN0, "seen": False, "height": None, "polls": 7}
_NOT_ASKED = {**_NOT_SEEN, "asked": False, "server": None}


def run(net, *extra, seed=_MNEMONIC, dry_run=True, policy=120, outfile=None,
        ids="env", index="0", broadcast=False, proxy=_PROXY):
    """Drive main(). Returns (exit_code, stdout, plan_or_None, outfile).
    `ids` says how the xpub and index reach the tool: "env" (the wake
    agent's way), "argv" (a hand run), or None (neither). `broadcast`
    passes --broadcast INSTEAD of --dry-run unless dry_run is forced."""
    net.install()
    out = outfile or os.path.join(_scratch, f"plan_{os.urandom(4).hex()}.json")
    argv = ["--tor-proxy", proxy, "--electrum", "s.onion",
            "--dest-from-receive-wallet", _BUNDLE, "--outfile", out]
    if broadcast:
        argv.append("--broadcast")
        dry_run = dry_run is True and "--dry-run" in extra
    os.environ.pop("GS_BTC_XPUB", None)
    os.environ.pop("GS_BTC_INDEX", None)
    if ids == "env":
        os.environ["GS_BTC_XPUB"] = _XPUB
        os.environ["GS_BTC_INDEX"] = str(index)
    elif ids == "argv":
        argv += ["--xpub", _XPUB, "--index", str(index)]
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
    finally:
        os.environ.pop("GS_BTC_XPUB", None)
        os.environ.pop("GS_BTC_INDEX", None)
    plan = None
    if os.path.exists(out):
        with open(out) as fh:
            plan = json.load(fh)
    return code, buf.getvalue(), plan, out


_HEX_LINE = re.compile(r"signed hex \(dry run: NOT broadcast, not persisted\): "
                       r"([0-9a-f]+)")


def _signed_tx(out):
    """The signed transaction, from the ONE place a dry run puts it: stdout
    (the job log), never the plan file."""
    m = _HEX_LINE.search(out)
    return Transaction.parse(bytes.fromhex(m.group(1))) if m else None


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
check("the plan says: dry run, NOT broadcast (no outcome, nothing seen), "
      "signed, the current schema",
      _plan["dry_run"] is True and _plan["broadcast"] is False
      and _plan["broadcast_outcome"] is None and _plan["seen"] is False
      and _plan["signed"] is True and _plan["schema"] == F.PLAN_SCHEMA
      and _plan["tx_hex_reason"] is None)
check("A DRY RUN NEVER REACHES THE BROADCAST SIDE: neither submit nor "
      "seen was called", _net.submits == [] and _net.seens == [])
_tx = _signed_tx(_out)
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
      == T.op_return_script(_net.last_memo.encode()).data
      and _tx.vout[1].script_pubkey.data[1] == 0x4c)
check("THE SIGNED BYTES ARE NOT IN THE PLAN FILE (a bearer instrument with "
      "no consumer yet): tx_hex is null, signed_hex_written false, and the "
      "hex went to stdout -- the job log -- instead",
      _plan["tx_hex"] is None and _plan["signed_hex_written"] is False
      and _tx is not None and _tx.is_segwit)
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
check("the memo is recorded with its byte count against the policy, and "
      "its chain-enforced limit is the worst-case arrival in base units",
      _plan["memo"] == _net.last_memo
      and _plan["memo_bytes"] == len(_net.last_memo.encode())
      and _plan["op_return_max_bytes"] == 120
      and _plan["memo_limit_base_units"]
      == int(Decimal(_plan["worst_case_xmr"]) * 10 ** 8)
      and _plan["affiliate_bps"] == 0)
check("a quote whose limit already sits at the worst case is laid out AS "
      "QUOTED: memo_limit_set false, memo == memo_quoted, byte for byte",
      _plan["memo_limit_set"] is False
      and _plan["memo_quoted"] == _net.last_memo
      and _plan["memo"] == _plan["memo_quoted"]
      and "the quote's own" in _out)
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
_net = Net()
_code, _out, _plan, _kind = _refusal(_net, policy=None)
_L = len(_net.last_memo.encode())               # a real memo: over 80 always
check("on the DEFAULT 80-byte policy a real forward is REFUSED as "
      "memo_overflow, exit 2, nothing signed, no plan written",
      _code == 2 and _kind == "memo_overflow" and _plan is None and _L > 80)
check("...and the refusal names the byte count and the policy, and points "
      "at the plan section", f"{_L} bytes" in _out and "80" in _out
      and "STAGE2_PLAN" in _out)
check("...the quote WAS fetched first (the memo has to be seen to be "
      "measured) but no seed was touched: refused before signing",
      len(_net.posts) == 1 and F.SEED_ENV in os.environ)
os.environ.pop(F.SEED_ENV, None)
check(f"a policy of exactly the memo's size ({_L}) signs; {_L - 1} refuses",
      run(Net(), policy=_L)[0] == 0
      and _refusal(Net(), policy=_L - 1)[3] == "memo_overflow")

print("\n== multiple settled outputs, plan-only, the fee override ==")
_net = Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 150000,
                   "confirmations": 5},
                  {"tx_hash": _H2, "vout": 2, "value": 90000,
                   "confirmations": 3},
                  {"tx_hash": "ef" * 32, "vout": 0, "value": 50000,
                   "confirmations": 0}])
_code, _out, _plan, _ = run(_net)
_tx = _signed_tx(_out)
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
_tx = _signed_tx(_out)
check("an output mined ONE block deep under min-conf 2 is neither counted "
      "nor spent: one input, the fee is exactly the sized fee, and the "
      "shallow output is reported as not yet settled",
      _code == 0 and len(_tx.vin) == 1 and _tx.vin[0].txid.hex() == _H1
      and 200000 - _tx.vout[0].value == _plan["fee_sat"]
      and _plan["unsettled_outputs"] == 1 and _plan["settled_sat"] == 200000)
check("...and with --min-conf 1 the same output IS spent",
      len(_signed_tx(run(Net(utxos=_net.utxos), "--min-conf", "1")[1]).vin)
      == 2)

# DUST STORM. Two hundred 546-sat outputs parked on the address (anyone can
# send them) would, swept, make the fee eat the deposit and strand the real
# payment. Dust is left where it lies.
_storm = [{"tx_hash": ("%064x" % i), "vout": 0, "value": 546,
           "confirmations": 9} for i in range(1, 201)]
_net = Net(utxos=_storm + [{"tx_hash": _H1, "vout": 0, "value": 300000,
                            "confirmations": 9}])
_code, _out, _plan, _ = run(_net)
_tx = _signed_tx(_out)
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
_code, _out, _plan, _ = run(Net(), "--write-signed-hex")
check("--write-signed-hex puts the signed bytes in the plan file (stage 3's "
      "consumer flag) and says so",
      _code == 0 and _plan["signed_hex_written"] is True
      and Transaction.parse(bytes.fromhex(_plan["tx_hex"])).is_segwit
      and _HEX_LINE.search(_out) is None)

print("\n== where the xpub and the index come from ==")
_code, _out, _plan, _ = run(Net(), ids="argv")
check("a hand run may pass --xpub/--index on argv: it works, and the tool "
      "warns that argv is world-readable",
      _code == 0 and _plan["index"] == 0
      and "passed on the command line" in _out)
_code, _out, _plan, _ = run(Net(), ids="env")
check("the wake agent's way -- GS_BTC_XPUB / GS_BTC_INDEX in the "
      "environment -- works with no warning and nothing on argv",
      _code == 0 and "command line" not in _out)
check("neither: refused bad_args before any network call",
      _refusal(Net(), ids=None)[3] == "bad_args"
      and not Net().look_calls)
check("a non-numeric index in the environment is refused bad_args",
      _refusal(Net(), ids="env", index="three")[3] == "bad_args")

print("\n== the fee bound covers the largest inbound ThorChain could name ==")
_P2WSH_MAIN = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
_code, _out, _plan, _ = run(Net(inbound=_P2WSH_MAIN))
check("a P2WSH inbound (34-byte scriptPubKey): the real vsize is at or "
      "under the bound and the real rate at or over the target",
      _code == 0 and _plan["vsize"] <= _plan["vsize_bound"]
      and _plan["feerate_real_sat_vb"] >= _plan["feerate_target_sat_vb"])

print("\n== build_and_sign's own guards, driven directly ==")
_net = Net().install()
_chosen = [{"tx_hash": _H1, "vout": 0, "value": 200000, "confirmations": 5}]
_spk = T.address_script(_INBOUND)
_fee0 = 2540


def _bas(**kw):
    """The last refusal kind from a direct build_and_sign call."""
    args = dict(chosen=_chosen, tip=_TIP, inbound_spk=_spk,
                send_sat=200000 - _fee0, fee_sat=_fee0,
                memo_b=("=:XMR.XMR:" + _DEST + ":40000000/1/0").encode(),
                account=_ACCT, index=0, address=_ADDR0, network="main",
                sign=True)
    args.update(kw)
    _net.kinds.clear()
    try:
        with redirect_stdout(io.StringIO()):
            F.build_and_sign(**args)
        return "signed"
    except SystemExit:
        kinds = [k for s, k in _net.kinds if k.startswith("refused:")]
        return kinds[-1][8:] if kinds else "(none)"


check("the good call signs", _bas() == "signed")
check("key_address_mismatch when the key does not derive the address given "
      "(a wrong index, or the inbound address in its place)",
      _bas(index=1) == "key_address_mismatch"
      and _bas(address=_INBOUND) == "key_address_mismatch")
check("fee_mismatch when inputs minus outputs is not the sized fee, either "
      "way", _bas(fee_sat=_fee0 + 1) == "fee_mismatch"
      and _bas(send_sat=200000 - _fee0 - 1) == "fee_mismatch")
_saved = T.verify_signed
T.verify_signed = lambda *a, **k: False
try:
    _vk = _bas()
finally:
    T.verify_signed = _saved
check("the independent re-verification refuses when it fails (driven by "
      "making it fail)", _vk == "sign_failed")

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
_r("memo_affiliate_fee", Net(memo=_MEMO + ":thorname:1000"), policy=255)
_r("memo_affiliate_fee", Net(memo=_MEMO + ":thorname:abc"), policy=255)
check("...an affiliate fee within --max-affiliate-bps is accepted and "
      "recorded", (run(Net(memo=_MEMO + ":thorname:25"),
                       "--max-affiliate-bps", "25", policy=255)[2] or {})
      .get("affiliate_bps") == 25)

print("\n== THE LIMIT IS SET, NOT TRUSTED: the chain's only slippage guard ==")
# THORChain's own example memo carries ":0/1/0" -- a swap at ANY price --
# and aggregators quote it that way. The forwarder lays the OP_RETURN out
# itself, so it writes its own floor (99% of the worst-case arrival, in
# 1e8 base units) into the memo whenever the quote's limit is absent, zero
# or lower. The limit is the ONLY field touched.


def _floor_of(plan):
    return int(Decimal(plan["worst_case_xmr"]) * 10 ** 8 * Decimal("0.99"))


def _limit_case(memo_in, policy=255):
    net = Net(memo=memo_in)
    code, out, plan, _ = run(net, policy=policy)
    return code, out, plan, net, _signed_tx(out)


_code, _out, _plan, _net, _tx = _limit_case("=:XMR.XMR:" + _DEST + ":0/1/0")
check("a ZERO limit (THORChain's example) is SIGNED, with the floor written "
      "into field 3 and interval/quantity kept: memo_limit_set true",
      _code == 0 and _plan["memo_limit_set"] is True
      and _plan["memo"] == f"=:XMR.XMR:{_DEST}:{_floor_of(_plan)}/1/0"
      and _plan["memo_limit_base_units"] == _floor_of(_plan)
      and _floor_of(_plan) > 0)
check("...the floor is 99% of the worst case, which is 90% of expected",
      _floor_of(_plan)
      == int(Decimal(_plan["worst_case_xmr"]) * 10 ** 8 * Decimal("0.99"))
      and Decimal(_plan["worst_case_xmr"])
      < Decimal(_plan["expected_xmr"]))
check("...the memo AS QUOTED is kept beside it, unchanged",
      _plan["memo_quoted"] == "=:XMR.XMR:" + _DEST + ":0/1/0"
      and _plan["memo_quoted"] != _plan["memo"])
check("...and it is the REWRITTEN memo that sits in the OP_RETURN of the "
      "signed transaction, with its byte count recorded",
      _tx is not None
      and _tx.vout[1].script_pubkey.data
      == T.op_return_script(_plan["memo"].encode()).data
      and _plan["memo_bytes"] == len(_plan["memo"].encode()))
check("...the summary says the limit was SET by this tool",
      "SET by this tool" in _out and str(_floor_of(_plan)) in _out)

_code, _out, _plan, _net, _tx = _limit_case("=:XMR.XMR:" + _DEST)
check("a memo with NO limit field at all gets one appended: "
      "=:XMR.XMR:<dest>:<floor>",
      _code == 0 and _plan["memo_limit_set"] is True
      and _plan["memo"] == f"=:XMR.XMR:{_DEST}:{_floor_of(_plan)}"
      and _tx.vout[1].script_pubkey.data
      == T.op_return_script(_plan["memo"].encode()).data)
_code, _out, _plan, _net, _tx = _limit_case("=:XMR.XMR:" + _DEST + ":/1/0")
check("an EMPTY limit field (legal on chain, executes at any price) is "
      "filled in", _code == 0 and _plan["memo_limit_set"] is True
      and _plan["memo"] == f"=:XMR.XMR:{_DEST}:{_floor_of(_plan)}/1/0")
_code, _out, _plan, _net, _tx = _limit_case("=:XMR.XMR:" + _DEST + ":1/1/0")
check("a limit UNDER the floor (1 base unit) is raised to the floor",
      _code == 0 and _plan["memo_limit_set"] is True
      and _plan["memo_limit_base_units"] == _floor_of(_plan)
      and _plan["memo"].endswith(f":{_floor_of(_plan)}/1/0"))
# a limit between the floor and the expected output: the aggregator was
# stricter than us; kept as written, even its notation
_code, _out, _plan, _net, _tx = _limit_case(
    "=:XMR.XMR:" + _DEST + ":{LIMIT}/3/5:thorname:0")
check("a limit at or over the floor is kept as written -- streaming 3/5 "
      "and the affiliate fields untouched, memo_limit_set false",
      _code == 0 and _plan["memo_limit_set"] is False
      and _plan["memo"] == _net.last_memo
      and _plan["memo"].endswith("/3/5:thorname:0")
      and _plan["memo_limit_base_units"]
      == int(_net.last_memo.split(":")[3].split("/")[0]))
# ABOVE the expected output: that swap can only refund, minus fees
_r("memo_bad_limit", Net(memo="=:XMR.XMR:" + _DEST + ":99999999999/1/0"),
   policy=255)
_r("memo_bad_limit", Net(memo="=:XMR.XMR:" + _DEST + ":abc/1/0"),
   policy=255)
_r("memo_bad_limit", Net(memo="=:XMR.XMR:" + _DEST + ":-5/1/0"),
   policy=255)
_r("memo_bad_limit", Net(memo="=:XMR.XMR:" + _DEST + ":1.5e8/1/0"),
   policy=255)


def _direct(fn, *a, **kw):
    """Drive one piece alone: ("ok", result) or ("refused", kind)."""
    net = Net().install()
    try:
        return "ok", fn(*a, **kw)
    except SystemExit:
        kinds = [k for s, k in net.kinds if k.startswith("refused:")]
        return "refused", (kinds[-1][8:] if kinds else "")


_E, _W = Decimal("1.5"), Decimal("0.5")                   # expected, worst
check("a limit in scientific notation (the chain accepts 1e8) parses, is "
      "over the floor, and is kept in ITS notation",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:1e8/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:1e8/1/0", 100000000, 0, False)))
check("the floor is int(worst * 1e8 * 0.99), and 0 is raised to exactly it",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:49500000/1/0", 49500000, 0, True)))
check("one base unit under the floor is raised; the floor itself is kept",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:49499999/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:49500000/1/0", 49500000, 0, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:49500000/1/0",
                  _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:49500000/1/0", 49500000, 0, False)))
check("a limit of exactly the expected output is kept; one over is refused",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:150000000/1/0",
              _E, _W, 0)[0] == "ok"
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:150000001/1/0",
                  _E, _W, 0) == ("refused", "memo_bad_limit"))
check("a worst case that rounds to nothing in base units is refused: no "
      "floor can be written, so no swap at any price either",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0", Decimal("1e-9"),
              Decimal("1e-9"), 0) == ("refused", "memo_bad_limit"))
check("the affiliate fields are read from positions 4-5 and the fee is "
      "capped by the policy passed in",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name:30", _E, _W, 30)
      == ("ok", ("=:XMR.XMR:x:49500000/1/0:name:30", 49500000, 30, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name:31",
                  _E, _W, 30) == ("refused", "memo_affiliate_fee"))
# THE SIZE CHECK IS ON THE FINAL BYTES, after the limit is written in
_qlen = len(("=:XMR.XMR:" + _DEST + ":0/1/0").encode())
check("a policy that fits the QUOTED memo but not the laid-out one refuses "
      "as memo_overflow (the floor is longer than '0')",
      _refusal(Net(memo="=:XMR.XMR:" + _DEST + ":0/1/0"), policy=_qlen)[3]
      == "memo_overflow"
      and run(Net(memo="=:XMR.XMR:" + _DEST + ":0/1/0"),
              policy=_qlen + 9)[0] == 0)
check("fit_memo re-checks the destination binding on the final text",
      _direct(F.fit_memo, "=:XMR.XMR:" + _OTHER + ":1/1/0", _DEST, 255)
      == ("refused", "memo_unbound")
      and _direct(F.fit_memo, "=:XMR.XMR:" + _DEST + ":1/1/0", _DEST, 255)
      == ("ok", ("=:XMR.XMR:" + _DEST + ":1/1/0").encode()))
# HEX. memo_binds_destination accepts a memo that binds once hex-decoded;
# this tool writes the OP_RETURN itself and must never embed the hex TEXT.
_hexmemo = ("=:XMR.XMR:" + _DEST + ":40000000/1/0").encode().hex()
_r("memo_hex", Net(memo=_hexmemo), policy=255)
_r("memo_hex", Net(memo="0x" + _hexmemo), policy=255)
_r("quote_refused", Net(post_error=SystemExit("401 from a keyed host")))
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
# WHAT IT SAW, FOR THE PHONE (STAGE4_PLAN.md 3.6): on nothing_settled the
# forwarder writes ONE word beside the plan path, and nothing else.
_code, _out, _plan, _of = run(Net(utxos=[]))
_sp = F.status_path(_of)
check("nothing on the address: refused, no plan, and a status file beside "
      "the plan path saying exactly {'state': 'not_seen'}",
      _code == 2 and _plan is None and _sp.exists()
      and json.load(open(_sp)) == {"state": "not_seen"}
      and oct(os.stat(_sp).st_mode & 0o777) == "0o600")
_code, _out, _plan, _of = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                          "value": 50000,
                                          "confirmations": 0}]))
check("money present but none settled: the word is 'seen' -- and the amount "
      "is NOT in the file", json.load(open(F.status_path(_of)))
      == {"state": "seen"} and "50000" not in open(F.status_path(_of)).read())
_code, _out, _plan, _of = run(Net())
check("a forward that signed writes NO status file", _code == 0
      and not F.status_path(_of).exists())
check("the status path sits under the plan's own wipe pattern "
      "(btc_forward_*.json)", F.status_path("/x/btc_forward_A3F1.json").name
      == "btc_forward_A3F1.status.json")
F.write_status(_of, "confirmed")
check("write_status never writes a word outside the two it may: anything "
      "else becomes not_seen", json.load(open(F.status_path(_of)))
      == {"state": "not_seen"})
_r("no_fee_estimate", Net(fee=None))
_r("fee_out_of_band", Net(fee=500))
_r("fee_out_of_band", Net(fee=2), "--feerate-floor", "5")
# THE FRACTION GUARD MUST BE THE DECIDING CHECK. A 20,000-sat fixture at
# 100 sat/vB was refused by every guard downstream (the fee exceeded the
# whole deposit), so the 20% rule was never what refused it. 100,000 sat at
# 100 sat/vB: the fee is ~25% and the send is far above the floor.
_out = _r("fee_eats_deposit", Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                            "value": 100000,
                                            "confirmations": 5}], fee=100))
_b = run(Net())[2]["vsize_bound"]
_v = 5 * _b * 100                                # fee = exactly 20%
check("the boundary: a fee of exactly 20% of the deposit signs; one satoshi "
      "less of deposit refuses fee_eats_deposit",
      run(Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": _v,
                      "confirmations": 5}], fee=100))[0] == 0
      and _refusal(Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": _v - 1,
                               "confirmations": 5}], fee=100))[3]
      == "fee_eats_deposit")
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
                       ("min-conf 0", ["--min-conf", "0"]),
                       ("a bad mix floor", ["--min-out-xmr", "abc"])):
    _code, _o, _p, _kind = _refusal(Net(), *_extra, policy=None)
    check(f"bad args: {_label} -> refused:bad_args before any network call",
          _code == 2 and _kind == "bad_args")
_code, _o, _p, _kind = _refusal(Net(), policy=None, index="-1")
check("bad args: a negative index (in the environment, the agent's way) -> "
      "refused:bad_args before any network call",
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

# ===========================================================================
print("\n== --broadcast: the forward leaves the machine (STAGE3_PLAN.md) ==")


def _b(net, *extra, **kw):
    """A broadcast run: (code, out, plan, net)."""
    code, out, plan, _ = run(net, *extra, broadcast=True, **kw)
    return code, out, plan, net


check("both flags is a contradiction and neither is the old refusal, by the "
      "same name; --plan-only cannot broadcast; a bad clock is refused",
      _refusal(Net(), "--dry-run", broadcast=True)[3] == "not_dry_run"
      and _refusal(Net(), dry_run=False)[3] == "not_dry_run"
      and _refusal(Net(), "--plan-only", broadcast=True)[3] == "bad_args"
      and _refusal(Net(), "--quote-max-age", "0", broadcast=True)[3]
      == "bad_args"
      and _refusal(Net(), "--seen-interval", "0", broadcast=True)[3]
      == "bad_args"
      and not Net().submits)

_code, _out, _plan, _net = _b(Net(submit=_ACCEPTED, seen=_SEEN0))
check("ACCEPTED and SEEN: exit 0, the plan says broadcast true, outcome "
      "accepted by the server, seen at height 0, dry_run false",
      _code == 0 and _plan["broadcast"] is True and _plan["dry_run"] is False
      and _plan["broadcast_outcome"] == "accepted"
      and _plan["broadcast_server"] == "s.onion" and _plan["seen"] is True
      and _plan["seen_height"] == 0 and _plan["seen_asked"] is True
      and _plan["signed"] is True)
_sent = Transaction.parse(bytes.fromhex(_net.submits[0]["raw_hex"]))
check("...what was SENT is what was SIGNED: the submitted hex parses to the "
      "plan's txid, verifies against the key at index 0, and pays the "
      "inbound exactly send_sat", len(_net.submits) == 1
      and T.txid_hex(_sent) == _plan["txid"] == _net.submits[0]["txid"]
      and T.verify_signed(_sent, [200000], [_PUB0])
      and _sent.vout[0].value == _plan["send_sat"])
check("...submit was given THIS address, the configured servers, the proxy, "
      "the network and the timeout -- and seen the same, with the txid and "
      "the default wait", _net.submits[0]["address"] == _ADDR0
      and _net.submits[0]["servers"] == [("s.onion", 50002, None)]
      and _net.submits[0]["proxy"] == _PROXY
      and _net.submits[0]["network"] == "main"
      and _net.submits[0]["timeout"] == 30.0
      and _net.seens[0]["txid"] == _plan["txid"]
      and _net.seens[0]["address"] == _ADDR0
      and _net.seens[0]["wait_s"] == 90.0
      and _net.seens[0]["interval_s"] == 15.0)
check("...and seen is told which server ACCEPTED, so its proof comes from "
      "another one where there is one",
      _net.seens[0]["avoid"] == "s.onion" == _plan["broadcast_server"])
check("...THE HEX IS NOWHERE: not in the plan (the network has it), not on "
      "stdout", _plan["tx_hex"] is None and _plan["tx_hex_reason"] is None
      and _plan["signed_hex_written"] is False
      and _HEX_LINE.search(_out) is None
      and _net.submits[0]["raw_hex"] not in _out)
check("...the summary says SENT, accepted, seen in the mempool, and NOT "
      "'NOT BROADCAST'", "SENT: accepted by s.onion" in _out
      and "seen: in the mempool" in _out and "NOT BROADCAST" not in _out)
check("...the hash chain got kinds only: sending, broadcast_accepted, "
      "broadcast_seen, and no not_broadcast; not one carries a digit",
      [k for s, k in _net.kinds if s == "forward"]
      == ["start", "quoted", "signed", "sending", "broadcast_accepted",
          "broadcast_seen"]
      and not any(re.search(r"\d", k) for _, k in _net.kinds))
check("...the seed is gone from the environment and appears nowhere",
      F.SEED_ENV not in os.environ and "abandon" not in _out
      and "abandon" not in open(run(Net(submit=_ACCEPTED, seen=_SEEN0),
                                    broadcast=True)[3]).read())

_code, _out, _plan, _net = _b(Net(submit=_ACCEPTED, seen=_NOT_SEEN))
check("ACCEPTED but NOT SEEN within the wait: still exit 0 (a server took "
      "it), the plan keeps the signed hex with reason 'unseen', and the "
      "summary says so", _code == 0 and _plan["broadcast"] is True
      and _plan["seen"] is False and _plan["seen_asked"] is True
      and _plan["seen_polls"] == 7
      and _plan["tx_hex_reason"] == "unseen" and _plan["signed_hex_written"]
      and Transaction.parse(bytes.fromhex(_plan["tx_hex"])).is_segwit
      and "KEPT in the plan file (unseen)" in _out
      and "NOT yet listed" in _out
      and [k for s, k in _net.kinds if s == "forward"][-1]
      == "broadcast_unseen")
_code, _out, _plan, _net = _b(Net(submit=_AMBIGUOUS, seen=_NOT_SEEN))
check("AMBIGUOUS and not seen: exit 0 (the money MAY have moved -- never "
      "'failed'), broadcast true, the hex kept with reason 'ambiguous', "
      "the warning printed", _code == 0 and _plan["broadcast"] is True
      and _plan["broadcast_outcome"] == "ambiguous"
      and _plan["tx_hex_reason"] == "ambiguous" and _plan["tx_hex"]
      and "[!] AMBIGUOUS" in _out
      and "broadcast_ambiguous" in [k for s, k in _net.kinds])
_code, _out, _plan, _net = _b(Net(submit=_AMBIGUOUS, seen=_SEEN0))
check("AMBIGUOUS then SEEN by the poll: the network has it, so the hex is "
      "NOT kept", _code == 0 and _plan["seen"] is True
      and _plan["tx_hex"] is None and _plan["tx_hex_reason"] is None)
_code, _out, _plan, _net = _b(Net(submit=_ACCEPTED, seen=_NOT_ASKED))
check("accepted, and nobody could be asked afterwards: seen false, "
      "seen_asked false, the hex kept, 'UNKNOWN' said",
      _code == 0 and _plan["seen_asked"] is False
      and _plan["tx_hex_reason"] == "unseen" and "seen: UNKNOWN" in _out)

_code, _out, _plan, _net = _b(Net(submit=_REJECTED))
check("REJECTED by every server: refused broadcast_rejected, exit 2, NO plan "
      "(nothing moved), seen never asked, the codes and the plan section "
      "named", _code == 2 and _plan is None and _net.seens == []
      and "refused:broadcast_rejected" in [k for s, k in _net.kinds]
      and "codes [1, 1]" in _out and "STAGE3_PLAN" in _out
      and "nothing moved" in _out)
_code, _out, _plan, _net = _b(Net(submit=_UNREACHABLE))
check("UNREACHABLE: exit 1 (a failure, nothing moved), no plan, seen never "
      "asked, the kind logged", _code == 1 and _plan is None
      and _net.seens == [] and "nothing moved" in _out
      and "broadcast_unreachable" in [k for s, k in _net.kinds])
_code, _out, _plan, _net = _b(Net(submit=W.PinMismatch("tls: pin")))
check("a PinMismatch while sending (before any bytes left): refused "
      "pin_mismatch, no plan, nothing sent", _code == 2 and _plan is None
      and "refused:pin_mismatch" in [k for s, k in _net.kinds])
_code, _out, _plan, _net = _b(Net(submit=_ACCEPTED,
                                  seen=W.PinMismatch("tls: pin")))
check("a PinMismatch while LOOKING (after acceptance): exit 0, seen false "
      "and not asked, the kind logged, the hex kept, the certificate named "
      "in the summary", _code == 0 and _plan["seen"] is False
      and _plan["seen_asked"] is False and _plan["tx_hex_reason"] == "unseen"
      and "seen_pin_mismatch" in [k for s, k in _net.kinds]
      and "another certificate" in _out)
_code, _out, _plan, _net = _b(Net(submit={**_AMBIGUOUS, "pin_mismatch": True,
                                          "mismatched": 1}, seen=_NOT_SEEN))
check("an ambiguous result carrying pin_mismatch and a foreign-txid count "
      "logs both kinds", "send_pin_mismatch" in [k for s, k in _net.kinds]
      and "txid_mismatch" in [k for s, k in _net.kinds]
      and "1 foreign txid" in _out and _plan["broadcast_mismatched"] == 1)
_code, _out, _plan, _net = _b(Net(submit=_ACCEPTED, seen=_SEEN0),
                              "--write-signed-hex")
check("--write-signed-hex keeps the hex even when the network has it, with "
      "its own reason", _code == 0 and _plan["tx_hex"]
      and _plan["tx_hex_reason"] == "write_signed_hex")
_code, _out, _plan, _net = _b(Net(submit=_ACCEPTED, seen=_SEEN0),
                              "--seen-wait", "0", "--seen-interval", "2.5",
                              "--timeout", "12")
check("--seen-wait, --seen-interval and --timeout reach the broadcast side",
      _net.seens[0]["wait_s"] == 0.0 and _net.seens[0]["interval_s"] == 2.5
      and _net.submits[0]["timeout"] == 12.0
      and _net.seens[0]["timeout"] == 12.0)

print("\n== the quote is bounded in time ==")
_ticks = iter([0.0, 301.0, 1000.0, 1000.0])
_net = Net(submit=_ACCEPTED, seen=_SEEN0, clock=lambda: next(_ticks))
_code, _out, _plan, _ = run(_net, broadcast=True)
_kinds = [k for s, k in _net.kinds if s == "forward"]
check("301 s between the quote and the send on a 300 s allowance: refused "
      "quote_stale AFTER signing (the seed was used, nothing was sent), no "
      "plan, submit never called", _code == 2 and _plan is None
      and _net.submits == [] and "refused:quote_stale" in _kinds
      and "signed" in _kinds and F.SEED_ENV not in os.environ)
_ticks = iter([0.0, 301.0, 1000.0, 1000.0])
_net = Net(submit=_ACCEPTED, seen=_SEEN0, clock=lambda: next(_ticks))
_code, _out, _plan, _ = run(_net, "--quote-max-age", "301", broadcast=True)
check("...exactly the allowance is sent; --quote-max-age raises it",
      _code == 0 and len(_net.submits) == 1)
_ticks = iter([0.0, 300.0, 1000.0, 1000.0])
_net = Net(submit=_ACCEPTED, seen=_SEEN0, clock=lambda: next(_ticks))
check("...and 300 s on the default allowance is sent (the bound is 'over', "
      "not 'at')", run(_net, broadcast=True)[0] == 0)

print("\n== the order of the guards: nothing is sent before the last one ==")
_orig_bas = F.build_and_sign


def _low_rate(*a, **k):
    tx, txid, vsize, real_rate, signed = _orig_bas(*a, **k)
    return tx, txid, vsize, 0, signed


F.build_and_sign = _low_rate
try:
    _code, _out, _plan, _net = _b(Net(submit=_ACCEPTED, seen=_SEEN0))
finally:
    F.build_and_sign = _orig_bas
check("a signed transaction whose real rate is under the floor is refused "
      "fee_out_of_band BEFORE the broadcast: submit never called",
      _code == 2 and _net.submits == []
      and "refused:fee_out_of_band" in [k for s, k in _net.kinds])
_net = Net(submit=_ACCEPTED, seen=_SEEN0, memo="=:XMR.XMR:" + _OTHER + ":0/1/0")
_code, _out, _plan, _ = run(_net, broadcast=True)
check("...and every stage-2 refusal (here: an unbound memo) still fires "
      "first, with nothing sent", _code == 2 and _net.submits == [])

print("\n== END TO END through the REAL broadcast module: sign, send, see ==")
from btcmock import mock_socks, tls_server_context           # noqa: E402
_sctx, _CERT_SHA = tls_server_context()
_port, _cap, _srv = mock_socks("electrum", {"txid": "compute",
                                            "history": "compute"},
                               tls_ctx=_sctx, connections=2)
try:
    _code, _out, _plan, _net = _b(Net(submit="real", seen="real"),
                                  proxy=f"socks5h://127.0.0.1:{_port}")
finally:
    _srv.close()
check("the real transport, the real subclass and the real forwarder: the "
      "in-process server received the signed hex, answered its real txid, "
      "listed it, and the plan says accepted + seen at height 0",
      _code == 0 and _plan["broadcast_outcome"] == "accepted"
      and _plan["broadcast_server"] == "s.onion" and _plan["seen"] is True
      and _plan["seen_height"] == 0 and _cap.get("hex")
      and T.txid_hex(Transaction.parse(bytes.fromhex(_cap["hex"])))
      == _plan["txid"] == _cap["txid_answered"]
      and _plan["tx_hex"] is None
      and _cap.get("tls_version") in ("TLSv1.2", "TLSv1.3"))
check("...two sessions, both on the broadcast circuit credential for this "
      "address (not the look's), the methods in order: version, broadcast; "
      "version, get_history", _cap["sessions"] == 2
      and _cap["methods_asked"] == ["server.version",
                                    "blockchain.transaction.broadcast",
                                    "server.version",
                                    "blockchain.scripthash.get_history"]
      and len(set(_cap["users"])) == 1
      and _cap["users"][0] == W._socks_parts(
          f"socks5h://127.0.0.1:{_port}", "btcsend:" + _ADDR0)[2]
      and _cap["users"][0] != W._socks_parts(
          f"socks5h://127.0.0.1:{_port}", "btcwatch:" + _ADDR0)[2])
_port, _cap, _srv = mock_socks("electrum", {"reject": 1}, tls_ctx=_sctx,
                               connections=1)
try:
    _code, _out, _plan, _net = _b(Net(submit="real", seen="real"),
                                  proxy=f"socks5h://127.0.0.1:{_port}")
finally:
    _srv.close()
check("...a real rejection whose message carries the hex: refused "
      "broadcast_rejected with the code alone, the hex nowhere in the "
      "output", _code == 2 and _plan is None and "codes [1]" in _out
      and _cap["hex"] not in _out)

print("\n== what the source must not be ==")
_src = code_only(os.path.join(REPO, "btc_forwarder"))
check("FORWARD_MIN_SAT is gs_wake_proto.DEPOSIT_MIN_SAT: the two floors are "
      "one figure", F.FORWARD_MIN_SAT == P.DEPOSIT_MIN_SAT == 10_000)
check("the forwarder names no Electrum method that spends: the broadcast is "
      "reached through gs_btc_broadcast's submit, called exactly once, "
      "inside the --broadcast branch, after the real-rate floor",
      "transaction.broadcast" not in _src and "sendrawtransaction" not in _src
      and _src.count("bcast_submit(") == 1
      and _src.index("rate fell under the floor")
      < _src.index("if args.broadcast:\n") < _src.index("bcast_submit("))
check("the forwarder never reads a transaction from a file to send it (no "
      "--rebroadcast, no plan read)", "--rebroadcast" not in _src
      and "json.load(" not in _src)
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
