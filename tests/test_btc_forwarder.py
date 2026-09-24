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
import fnmatch
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
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
# THE CHAIN-SIDE JITTER (fix pass after the deep read) is pinned to nothing
# here, so every figure below is exact; the jitter itself is tested where
# it is named, at the end.
F.FEE_JITTER = lambda bound: 0
F.LIMIT_JITTER = lambda cap: 0
F.LIMIT_MARGIN_BPS = lambda: 1000                # the tolerance: 90% of expected
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
                 factor=Decimal(1), submit=None, seen=None, clock=None,
                 spends=None, funding=None, truncated=None):
        self.factor = factor                     # quote vs oracle, x
        self.clock = clock                       # the quote-age clock
        # A HISTORY LONGER THAN THE READER'S WINDOW (the MED pass): the
        # total spends_of would report through on_truncated, or None.
        self.truncated = truncated
        # WHAT PAID THE ADDRESS (third self-doubt pass): the `paid` half
        # bcast.spends_of returns with_funding -- memos and sources.
        self.funding_result = funding
        # THE BROADCAST SIDE, canned: `submit` is the dict bcast.submit
        # would return (or an exception to raise, or "real" to leave the
        # real function in place); `seen` likewise. Every call is recorded.
        self.submit_result = submit
        self.seen_result = seen
        self.submits, self.seens = [], []
        # THE ADDRESS'S SPENDS (stage 5): what bcast.spends_of would return
        # (a list), an exception to raise, or "real"; every call recorded.
        self.spends_result = spends
        self.spend_calls = []
        self.utxos = utxos if utxos is not None else [
            {"tx_hash": _H1, "vout": 0, "value": 200000, "confirmations": 5}]
        self.fee = fee
        self.inbound, self.memo = inbound, memo
        self.expected = expected                 # None: derived from oracle
        self.oracle = oracle
        # THORNode's inbound list, canned. A broadcast now REQUIRES the
        # cross-check (STAGE5_PLAN.md 3.5), so the default agrees with the
        # quote's inbound; a test that wants the check to refuse passes its
        # own list, as the checks further down do.
        self.thornode = (thornode if thornode is not None else
                         [{"chain": "BTC", "address": inbound,
                           "halted": False}])
        self.look_error, self.post_error = look_error, post_error
        self.routes = routes
        self.look_calls, self.posts, self.gets, self.kinds = [], [], [], []

    def look(self, address, servers, proxy_url, **kw):
        self.look_calls.append((address, servers, proxy_url, kw))
        if self.look_error:
            raise self.look_error
        # SETTLED AS gs_btc_watch.summarize COUNTS IT: at min_conf, output
        # by output. Counting every mined output hid each decision that
        # turns on depth (a payment one block short read as settled), and
        # the outputs go out as COPIES: main() marks a replacement's
        # inputs `must` on the dicts it is handed, and a fixture reused
        # after that would carry the mark into every later Net.
        _mc = max(1, int(kw.get("min_conf") or 1))
        confirmed = sum(u["value"] for u in self.utxos
                        if u["confirmations"] > 0)
        settled = sum(u["value"] for u in self.utxos
                      if u["confirmations"] >= _mc)
        pic = {"state": ("confirmed" if settled
                         else "seen" if self.utxos else "not_seen"),
               "confirmed_sat": confirmed,
               "unconfirmed_sat": sum(u["value"] for u in self.utxos
                                      if u["confirmations"] <= 0),
               "settled_sat": settled, "confirmations": 5,
               "utxos": [dict(u) for u in self.utxos], "tip": _TIP,
               "server": "s.onion", "cert_sha256": None}
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
        if isinstance(r, list):
            # One outcome per call, in order (a re-send, then a fresh send).
            r = r.pop(0) if r else _UNREACHABLE
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

    def _spends(self, address, servers, proxy_url, **kw):
        self.spend_calls.append({"address": address, "servers": servers,
                                 "proxy": proxy_url, **kw})
        r = self.spends_result
        if isinstance(r, Exception):
            raise r
        if self.truncated is not None and kw.get("on_truncated") is not None:
            kw["on_truncated"](self.truncated)
        if kw.get("with_funding"):
            return list(r or []), list(self.funding_result or [])
        return list(r or [])

    def install(self):
        F.look = self.look
        F.safe_post = self.safe_post
        F.safe_get = self.safe_get
        F.bcast_submit = (_REAL_SUBMIT if self.submit_result == "real"
                          else self._submit)
        F.bcast_seen = (_REAL_SEEN if self.seen_result == "real"
                        else self._seen)
        F.bcast_spends = (_REAL_SPENDS if self.spends_result == "real"
                          else self._spends)
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
_REAL_SPENDS = F.bcast_spends
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
        ids="env", index="0", broadcast=False, proxy=_PROXY, thornode=True,
        account=None, xpub=_XPUB):
    """Drive main(). Returns (exit_code, stdout, plan_or_None, outfile).
    `ids` says how the xpub and index reach the tool: "env" (the wake
    agent's way), "argv" (a hand run), or None (neither). `broadcast`
    passes --broadcast INSTEAD of --dry-run unless dry_run is forced, and
    names a THORNode (a broadcast requires the cross-check) unless
    `thornode` is False or the caller passed --thornode. `account`, when
    given, rides in GS_BTC_ACCOUNT like the xpub."""
    net.install()
    out = outfile or os.path.join(_scratch, f"plan_{os.urandom(4).hex()}.json")
    argv = ["--tor-proxy", proxy, "--electrum", "s.onion",
            "--dest-from-receive-wallet", _BUNDLE, "--outfile", out]
    if broadcast:
        argv.append("--broadcast")
        dry_run = dry_run is True and "--dry-run" in extra
        if thornode and "--thornode" not in extra:
            argv += ["--thornode", "https://tn.example"]
    os.environ.pop("GS_BTC_XPUB", None)
    os.environ.pop("GS_BTC_INDEX", None)
    os.environ.pop("GS_BTC_ACCOUNT", None)
    if account is not None:
        os.environ["GS_BTC_ACCOUNT"] = str(account)
    if ids == "env":
        os.environ["GS_BTC_XPUB"] = xpub
        os.environ["GS_BTC_INDEX"] = str(index)
    elif ids == "argv":
        argv += ["--xpub", xpub, "--index", str(index)]
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
        os.environ.pop("GS_BTC_ACCOUNT", None)
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
# A FLOOD JUST OVER THE DUST LINE: 1,600 outputs of 300 sat (above the
# 294 sat relay dust limit, above this rate's dust line) beside a real
# 400,000 sat deposit. Every one was spent, and the transaction -- signed,
# "passing" as a dry run -- weighed over the 400,000 WU every relaying node
# refuses; every retry built it again, so the deposit could never move.
_flood = ([{"tx_hash": _H1, "vout": 0, "value": 400000, "confirmations": 9}]
          + [{"tx_hash": "%064x" % (i + 1000), "vout": 0, "value": 300,
              "confirmations": 9} for i in range(1600)])
_code, _out, _plan, _ = run(Net(utxos=_flood, fee=1))
_tx = _signed_tx(_out)
check("a dust flood beside a deposit: the forward stays standard (weight "
      "within 400,000), spends the deposit, and the plan counts what was "
      "left over for a standard size",
      _code == 0 and _tx is not None
      and T.measure(_tx)[1] <= F.STANDARD_TX_WEIGHT
      and any(i.txid.hex() == _H1 for i in _tx.vin)
      and _plan["left_over"] == 1601 - len(_tx.vin) > 0
      and f"{_plan['left_over']} left for a standard size" in _out)
check("...the cap is the vsize bound's: one input more would not be standard",
      F.standard_fits(len(_tx.vin), 120)
      and not F.standard_fits(len(_tx.vin) + 1, 120))
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
# itself, so it writes its own floor (the expected output less a margin
# drawn per forward -- pinned here to the arrival tolerance, 10% -- in 1e8
# base units) into the memo whenever the quote's limit is absent, zero or
# lower. The limit is the ONLY field touched.


def _floor_of(plan, margin_bps=1000):
    return int(Decimal(plan["expected_xmr"]) * 10 ** 8
               * (10000 - margin_bps) / 10000)


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
check("...the floor is the expected output less the margin (the tolerance "
      "here), never under the worst case the watcher accepts",
      _floor_of(_plan)
      == int(Decimal(_plan["expected_xmr"]) * 10 ** 8 * Decimal("0.9"))
      and Decimal(_plan["worst_case_xmr"])
      < Decimal(_plan["expected_xmr"])
      and _floor_of(_plan)
      >= int(Decimal(_plan["worst_case_xmr"]) * 10 ** 8) - 100)
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
_net = Net(memo="=:XMR.XMR:" + _DEST + ":{LIMIT}/3/5:thorname:25")
_code, _out, _plan, _ = run(_net, "--max-affiliate-bps", "25", policy=255)
check("a limit at or over the floor is kept as written -- streaming 3/5 "
      "and an affiliate fee within policy untouched, memo_limit_set false",
      _code == 0 and _plan["memo_limit_set"] is False
      and _plan["memo"] == _net.last_memo
      and _plan["memo"].endswith("/3/5:thorname:25")
      and _plan["memo_limit_base_units"]
      == int(_net.last_memo.split(":")[3].split("/")[0]))
# AFFILIATE FIELDS THAT CARRY NO FEE ARE DROPPED: a 0-bps affiliate pays
# nobody and changes nothing on the chain, but its bytes decided whether
# the memo fit the OP_RETURN policy -- for every quote that carried it.
_code, _out, _plan, _net, _tx = _limit_case(
    "=:XMR.XMR:" + _DEST + ":{LIMIT}/3/5:" + "a" * 30 + ":0", policy=255)
check("a thirty-character THORName at 0 bps is dropped from the memo laid "
      "out (the quoted memo kept beside it): the limit and streaming "
      "fields stay, nothing else follows them",
      _code == 0 and _plan["memo"].endswith("/3/5")
      and _plan["memo"].count(":") == 3
      and _plan["memo_quoted"].endswith(":" + "a" * 30 + ":0")
      and _plan["affiliate_bps"] == 0)
_qlen30 = len(("=:XMR.XMR:" + _DEST + ":0/1/0:" + "a" * 30 + ":0").encode())
_code, _out, _plan, _net, _tx = _limit_case(
    "=:XMR.XMR:" + _DEST + ":0/1/0:" + "a" * 30 + ":0", policy=_qlen30 - 20)
check("...so a policy the DECORATED memo would not fit still forwards: the "
      "laid-out memo is the bounded one",
      _code == 0 and _plan["memo_bytes"] <= _qlen30 - 20)
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
      "over the floor (90% of a 1.0 quote), and is kept in ITS notation",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:1e8/1/0", Decimal("1.0"),
              _W, 0)
      == ("ok", ("=:XMR.XMR:x:1e8/1/0", 100000000, 0, False)))
check("the floor is int(expected * 1e8 * (1 - margin)) -- the margin pinned "
      "to 10% -- and 0 is raised to exactly it",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, True)))
# A LIMIT WITH A HUGE EXPONENT IS REFUSED AT ONCE. int(Decimal("1e2000000"))
# is quadratic in the exponent -- 56 s, driven -- and the aggregator (or
# whoever answers as it) chooses the memo; 119 bytes held the forward until
# the job's budget ran out, and the operator got a timeout for a refusal.
import time as _t_lim                                          # noqa: E402
_t0_lim = _t_lim.monotonic()
_big_lim = _direct(F.enforce_memo_terms, "=:XMR.XMR:x:1e2000000/1/0", _E, _W, 0)
check("a limit of 1e2000000 is refused as memo_bad_limit, at once",
      _big_lim == ("refused", "memo_bad_limit")
      and _t_lim.monotonic() - _t0_lim < 2)
check("...and so is twenty-one digits: no limit in 1e8 base units needs them",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:" + "1" * 21 + "/1/0",
              _E, _W, 0) == ("refused", "memo_bad_limit"))
check("the limit pattern itself is bounded: 20 digits, a 2-digit exponent",
      F._LIMIT_RE.match("1" * 20) and F._LIMIT_RE.match("1e99")
      and not F._LIMIT_RE.match("1" * 21) and not F._LIMIT_RE.match("1e100"))
# ...AND EVERY OTHER NUMBER FROM OUTSIDE. The limit was bounded and THORNode's
# dust_threshold and outbound_fee went on to int(Decimal(...)) unbounded --
# 56 s for 1e2000000, driven by the review of the fix, and a traceback out
# of main past that. The bound is at the one parse every external number
# takes (gs_common.finite_decimal), so it cannot be half-applied again.
_t0_in = _t_lim.monotonic()
_n_in = Net(thornode=[{"chain": "BTC", "address": _INBOUND, "halted": False,
                       "dust_threshold": "1e2000000",
                       "outbound_fee": "1e2000000"}]).install()
try:
    _r_in = ("ok", F.cross_check_inbound(_INBOUND, "https://tn.example",
                                         _PROXY))
except SystemExit:
    _r_in = ("refused", None)
except Exception as _e_in:                                   # noqa: BLE001
    _r_in = ("crash", f"{type(_e_in).__name__}")
check("THORNode figures of 1e2000000 are no figures: read as absent, at once, "
      "never a crash", _r_in == ("ok", (None, None))
      and _t_lim.monotonic() - _t0_in < 2)
_t0_ef = _t_lim.monotonic()
check("...and an Electrum fee estimate of 1e999990 is no estimate, at once",
      C.electrum_fee_to_sat_vb("1e999990") is None
      and C.electrum_fee_to_sat_vb("0.00012") == 12
      and _t_lim.monotonic() - _t0_ef < 2)
check("the parse every external number takes is bounded both ways, and a "
      "zero keeps no exponent",
      C.finite_decimal("1e30") == Decimal("1e30")
      and C.finite_decimal("1e31") is None
      and C.finite_decimal("1e-31") is None
      and C.finite_decimal("1e-30") == Decimal("1e-30")
      and str(C.finite_decimal("0E+2000000")) == "0")

check("one base unit under the floor is raised; the floor itself is kept",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:134999999/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:135000000/1/0",
                  _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, False)))
_saved_margin = F.LIMIT_MARGIN_BPS
F.LIMIT_MARGIN_BPS = lambda: 300
check("a margin of 3% writes 97% of the expected output; a draw over the "
      "tolerance is clamped to it and a negative one to zero (the limit "
      "never under what the watcher accepts, never over the quote)",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:145500000/1/0", 145500000, 0, True)))
F.LIMIT_MARGIN_BPS = lambda: 5000
check("...clamped: a draw of 50% still writes 90%",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, True)))
F.LIMIT_MARGIN_BPS = lambda: -7
check("...and a negative draw writes the whole expected output",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:150000000/1/0", 150000000, 0, True)))
F.LIMIT_MARGIN_BPS = _saved_margin
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
      == ("ok", ("=:XMR.XMR:x:135000000/1/0:name:30", 135000000, 30, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name:31",
                  _E, _W, 30) == ("refused", "memo_affiliate_fee"))
check("affiliate fields at 0 bps are dropped (a name, an empty name, a "
      "name with no fee field); fields THIS tool does not read after the "
      "fee keep everything; a fee the policy allows keeps the fields",
      _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name:0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0::0", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name", _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0", 135000000, 0, True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name:0:evm:x",
                  _E, _W, 0)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0:name:0:evm:x", 135000000, 0,
                 True))
      and _direct(F.enforce_memo_terms, "=:XMR.XMR:x:0/1/0:name:5", _E, _W,
                  10)
      == ("ok", ("=:XMR.XMR:x:135000000/1/0:name:5", 135000000, 5, True)))
check("the memo bound the pairing enforces is the forward's own arithmetic: "
      "op and asset, a 95-character address, a 16-digit limit, '/1/0'",
      C.SWAP_MEMO_MAX_BYTES == len("=:XMR.XMR:") + 95 + 1 + 16 + 4
      and C.SWAP_MEMO_POLICY_BYTES > C.SWAP_MEMO_MAX_BYTES
      and len(F.enforce_memo_terms("=:XMR.XMR:" + "8" * 95 + ":0/1/0",
                                   Decimal("20000000"), Decimal("19999999"),
                                   0)[0].encode()) <= C.SWAP_MEMO_MAX_BYTES)
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
# `routes` IS WHATEVER JSON THE HOST CHOSE: 5, true, an object or a float
# were indexed before their type was looked at -- a TypeError/KeyError
# traceback and a bare exit 1, with no kind on the chain.
# (A traceback here is the defect itself; caught, so it fails THIS check
# instead of ending the suite before every check after it.)


def _r_nocrash(name, net, *extra, **kw):
    try:
        return _r(name, net, *extra, **kw)
    except Exception as _ex:                                  # noqa: BLE001
        check(f"{name}: refused by kind, not a traceback "
              f"({type(_ex).__name__})", False)


for _bad in (5, True, {"x": 1}, 3.5):
    _r_nocrash("no_route", Net(routes=_bad))
# MORE MONERO THAN EXISTS IS NOT A PRICE: 1e23 overflowed the 28-digit
# quantize into an uncaught InvalidOperation, with or without an oracle.
for _big in ("1e23", "99999999999999999999999.5", "1e30", "2e9"):
    _r_nocrash("expected_unreadable",
               Net(expected=_big, memo="=:XMR.XMR:" + _DEST + ":0/1/0"))
    _r_nocrash("expected_unreadable",
               Net(expected=_big, oracle=None,
                   memo="=:XMR.XMR:" + _DEST + ":0/1/0"))
try:
    _mo_kind = _refusal(Net(), "--min-out-xmr", "1e25")[3]
except Exception as _ex:                                      # noqa: BLE001
    _mo_kind = type(_ex).__name__
check("...and an operator --min-out-xmr far past the supply refuses by kind, "
      "not a traceback", _mo_kind == "below_mix_minimum")
# ARGUMENTS ARE REFUSED BEFORE ANYTHING RUNS. NaN passed every `< 0` and
# `<= 0`: --seen-interval nan reached time.sleep AFTER the send, a finite
# 1e10 timeout escaped the socket layer, --feerate-sat-vb 0 was read as
# "none given", and a negative one was blamed on the server as `delayed`.
for _flags in (("--seen-interval", "nan"), ("--seen-wait", "inf"),
               ("--seen-wait", "nan"), ("--seen-wait", "3601"),
               ("--timeout", "1e10"), ("--timeout", "nan"),
               ("--feerate-sat-vb", "0"), ("--feerate-sat-vb", "-5")):
    _nA = Net()
    _cA, _oA, _pA, _kA = _refusal(_nA, *_flags)
    check(f"{' '.join(_flags)}: refused bad_args before the look",
          _cA == 2 and _kA == "bad_args" and _nA.look_calls == [])
for _of_bad in ("fwd.plan", "fwd", "x.status.json", "x.signed.json"):
    _nO = Net()
    _cO, _oO, _pO, _kO = _refusal(
        _nO, outfile=os.path.join(_scratch, _of_bad))
    check(f"--outfile {_of_bad}: refused bad_args (the chain, the status word "
          "and the signed record are named from a <name>.json stem)",
          _cO == 2 and _kO == "bad_args" and _nO.look_calls == [])
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
# BELOW THE FLOOR PAYS THE FLOOR. Refusing a cheap estimate as "out of band"
# made an operator's floor turn every cheap day into a day nothing moved
# (a refusal became `delayed`, retried hourly, for as long as the network
# stayed cheap). Paying more than an estimate never strands money.
_nf = Net(fee=2)
_c, _o, _p, _ = run(_nf, "--feerate-floor", "5")
check("an estimate UNDER the floor is not refused: the forward pays the "
      "floor, says so, and the kind is on the chain",
      _c == 0 and _p is not None and _p["feerate_target_sat_vb"] == 5
      and ("forward", "fee_floor_applied") in _nf.kinds
      and "paying the floor" in _o)
_nf2 = Net(fee=7)
_c, _o, _p, _ = run(_nf2, "--feerate-floor", "5")
check("...an estimate inside the band is paid as estimated",
      _c == 0 and _p["feerate_target_sat_vb"] == 7
      and ("forward", "fee_floor_applied") not in _nf2.kinds)
check("...and --feerate-sat-vb under the floor is likewise lifted to it",
      run(Net(fee=50), "--feerate-floor", "5", "--feerate-sat-vb", "2")[2]
      ["feerate_target_sat_vb"] == 5)
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

print("\n== STAGE 5: a fee refusal is a word; an emptied address is read ==")


def _status_of(outfile):
    p = F.status_path(outfile)
    return json.load(open(p))["state"] if os.path.exists(p) else None


# TODAY'S FEE, NOT THE DEPOSIT: `delayed` -- the same deposit forwards with
# cheaper blocks, and the Pi tries again by itself (STAGE5_PLAN.md 3.2).
for _why, _net, _kind in (
        ("an estimate above the ceiling", Net(fee=500), "fee_out_of_band"),
        ("no estimate from the server", Net(fee=None), "no_fee_estimate"),
        ("a fee over a fifth of the deposit at this rate",
         Net(fee=200, utxos=[{"tx_hash": _H1, "vout": 0, "value": 60000,
                              "confirmations": 5}]), "fee_eats_deposit"),
        ("what is left after THIS fee is under the dust floor, though a "
         "cheaper block would clear it",
         Net(fee=4, utxos=[{"tx_hash": _H1, "vout": 0, "value": 11000,
                            "confirmations": 5}]), "below_minimum")):
    _c, _o, _p, _of = run(_net)
    check(f"{_why}: refused {_kind}, nothing signed, and the status word is "
          "'delayed'", _c == F.EXIT_REFUSED
          and ("forward", f"refused:{_kind}") in _net.kinds
          and _p is None and _status_of(_of) == "delayed")
# NEVER AT ANY RATE THIS PAIR ALLOWS: `short` -- what settled is under the
# one-input floor even at the FLOOR rate, so no waiting changes it.
for _why, _net, _kind in (
        ("what settled is under the one-input floor even at the floor rate",
         Net(fee=10, utxos=[{"tx_hash": _H1, "vout": 0, "value": 9000,
                             "confirmations": 5}]), "fee_eats_deposit"),
        ("what settled is all dust at this rate and under the floor",
         Net(fee=10, utxos=[{"tx_hash": _H1, "vout": 0, "value": 500,
                             "confirmations": 5}]), "nothing_economic")):
    _c, _o, _p, _of = run(_net)
    check(f"{_why}: refused {_kind} and the status word is 'short'",
          _c == F.EXIT_REFUSED and ("forward", f"refused:{_kind}") in _net.kinds
          and _p is None and _status_of(_of) == "short")
# THE WORD IS DECIDED ON THE MONEY A FORWARD WOULD SPEND, not the look's
# total. Two hundred 546 sat outputs sum to 109,200 -- far over the
# one-input floor -- but with a 5 sat/vB floor each is dust even at the
# cheapest rate this box pays (2 * 69 * 5 = 690), so no forward at any
# rate this pair allows spends one. The sum said `delayed`: "nothing to
# do" on the phone and a wake per retry, for ever.
_nDs = Net(utxos=_storm)
_c, _o, _p, _of = run(_nDs, "--feerate-floor", "5")
check("dust at every rate this pair allows, however much of it: refused "
      "nothing_economic and the status word is 'short', not 'delayed'",
      _c == F.EXIT_REFUSED
      and ("forward", "refused:nothing_economic") in _nDs.kinds
      and _p is None and _status_of(_of) == "short")
_nDd = Net(utxos=_storm)
_c, _o, _p, _of = run(_nDd, "--feerate-floor", "1")
check("NON-VACUITY: the same outputs with a 1 sat/vB floor are not dust at "
      "that rate (138) and carry a forward there: 'delayed'",
      _c == F.EXIT_REFUSED
      and ("forward", "refused:nothing_economic") in _nDd.kinds
      and _status_of(_of) == "delayed")


def _outs(vals, conf=9):
    """Outputs of these values; a (value, confirmations) pair sets a depth."""
    out = []
    for i, v in enumerate(vals):
        v, c = v if isinstance(v, tuple) else (v, conf)
        out.append({"tx_hash": "%064x" % (i + 1), "vout": 0, "value": v,
                    "confirmations": c})
    return out


# NOT DUST, AND STILL NEVER A FORWARD: the one-input floor is not the test.
# A hundred 200 sat outputs (20,000: twice the one-input floor at 1 sat/vB)
# pay a hundred-input fee of over a fifth at 1 sat/vB and are dust from
# 2 up; twenty of 520 carry under the minimum at 1, eat over a fifth at 2
# and 3, and are dust from 4. No rate in the band forwards either.
for _vals, _est, _kind, _fl in (([200] * 100, 1, "fee_eats_deposit", "1"),
                                ([200] * 100, 5, "nothing_economic", "1"),
                                ([520] * 20, 1, "below_minimum", "1"),
                                ([1000] * 200, 5, "fee_eats_deposit", "5")):
    _nX = Net(utxos=_outs(_vals), fee=_est)
    _c, _o, _p, _of = run(_nX, "--feerate-floor", _fl)
    check(f"{len(_vals)} outputs of {_vals[0]} sat, estimate {_est}, floor "
          f"{_fl}: refused {_kind}, and 'short' -- no rate in the band "
          "forwards them", _c == F.EXIT_REFUSED
          and ("forward", f"refused:{_kind}") in _nX.kinds
          and _p is None and _status_of(_of) == "short")
# ...AND THE CHEAPEST RATE IS NOT ALWAYS THE ONE THAT FORWARDS. 20,000 sat
# beside a hundred of 140 fails at 1 sat/vB (a 101-input fee over a fifth)
# and forwards at 2, where the 140s are dust: `delayed`, not `short` --
# the naive fix (the whole selection's fee at the floor rate) says short.
_mix = _outs([20000] + [140] * 100)
_nY = Net(utxos=_mix, fee=1)
_c, _o, _p, _of = run(_nY)
check("fails at the floor rate, forwards at a higher one: 'delayed'",
      _c == F.EXIT_REFUSED
      and ("forward", "refused:fee_eats_deposit") in _nY.kinds
      and _status_of(_of) == "delayed")
check("NON-VACUITY: ...and at an estimate of 2 the same address signs",
      run(Net(utxos=_mix, fee=2))[0] == 0)
check("dust_from is the rate from which select_inputs leaves an output of "
      "that value behind, and not one below it",
      all(F.select_inputs(_outs([_v]), 1, F.dust_from(_v))[0] == []
          and (F.dust_from(_v) <= 1
               or F.select_inputs(_outs([_v]), 1, F.dust_from(_v) - 1)[0])
          for _v in (1, 137, 138, 139, 276, 277, 1000, 123457)))
# THE ONE-INPUT FLOOR ITSELF: exactly it forwards at the floor rate, so on
# a day the estimate is over the ceiling it is `delayed`; a satoshi under
# it can never go, and is `short`. `<=` for `<` anywhere on that edge
# stops the Pi retrying a deposit that forwards.
_flr = T.forward_floor_sat(120, 1, T.FORWARD_MIN_SAT)
for _v, _w in ((_flr, "delayed"), (_flr - 1, "short")):
    _nE = Net(fee=500, utxos=_outs([_v]))
    _c, _o, _p, _of = run(_nE)
    check(f"the one-input floor's edge ({_v} sat, estimate over the "
          f"ceiling): '{_w}'", _c == F.EXIT_REFUSED
          and ("forward", "refused:fee_out_of_band") in _nE.kinds
          and _status_of(_of) == _w)
check("NON-VACUITY: exactly the floor signs at the floor rate",
      run(Net(fee=1, utxos=_outs([_flr])))[0] == 0)
# MONEY STILL CONFIRMING IS NOT SHORT. `short` reads "it has stopped
# growing" on the phone, and the Pi does not start a `short` deposit again
# until its confirmed total grows -- which a payment going from one
# confirmation to two does not do. A whole payment one block short of
# min_conf beside a small settled output was `short`, and sat there.
for _why, _vals, _extra in (
        ("5,000 settled and 300,000 at one confirmation",
         [(5000, 6), (300000, 1)], ()),
        ("5,000 settled and 300,000 in the mempool",
         [(5000, 6), (300000, 0)], ()),
        ("two hundred settled dust outputs and 100,000 at one confirmation",
         [(546, 9)] * 200 + [(100000, 1)], ("--feerate-floor", "5"))):
    _nU = Net(fee=5, utxos=_outs(_vals))
    _c, _o, _p, _of = run(_nU, *_extra)
    check(f"{_why}: refused, nothing signed, and the word is 'seen' (the Pi "
          "asks again), not 'short'", _c == F.EXIT_REFUSED and _p is None
          and any(k.startswith("refused:") for s, k in _nU.kinds)
          and _status_of(_of) == "seen")
check("NON-VACUITY: one block later the same payment signs",
      run(Net(fee=5, utxos=_outs([(5000, 6), (300000, 2)])))[0] == 0)
check("...and 5,000 sat alone, nothing confirming, is still 'short'",
      _status_of(run(Net(fee=5, utxos=_outs([(5000, 6)])))[3]) == "short")
_nm = Net(memo="=:XMR.XMR:" + _OTHER + ":0/1/0")
_c, _o, _p, _of = run(_nm)
check("a refusal that is not about the fee (memo_unbound) writes NO status "
      "word: it is a refusal, and the phone hears that",
      _c == F.EXIT_REFUSED and _status_of(_of) is None)
check("the five words the status file may carry, and the six fee kinds that "
      "earn one", set(F.STATUS_WORDS) == {"not_seen", "seen", "delayed",
                                          "short", "returned"}
      and set(F.DELAY_KINDS) == {"no_fee_estimate", "bad_fee_estimate",
                                 "fee_out_of_band", "fee_eats_deposit",
                                 "nothing_economic", "below_minimum"})

# THE ADDRESS HOLDS NOTHING UNSPENT. Was it paid and emptied? A forward that
# went out and died before its plan was written used to be "not yet" for
# ever (STAGE5_PLAN.md section 1, case 1).
_IN_SPK = T.address_script(_INBOUND, "main")


def _spend_tx(memo_text=None, send=190000):
    outs = [(send, _IN_SPK)]
    if memo_text is not None:
        outs.append((0, T.op_return_script(memo_text.encode("utf-8"))))
    tx = T.build_unsigned([{"tx_hash": _H1, "vout": 0, "value": 200000}],
                          outs, locktime=_TIP)
    return {"txid": tx.txid().hex(), "height": 850001,
            "hex": tx.serialize().hex(),
            "inputs": [{"tx_hash": _H1, "vout": 0, "value": 200000}],
            "server": "s.onion"}


_OURS = _spend_tx("=:XMR.XMR:" + _DEST + ":123456/1/0")


def _new_of():
    return os.path.join(_scratch, f"plan_{os.urandom(4).hex()}.json")


def _ours_of(txid):
    """A plan path whose record says this tool sent `txid`: what a send
    that died before its plan leaves behind."""
    _p = _new_of()
    F.record_signed(_p, txid)
    return _p


# OUR MEMO ALONE IS NOT OURS. Every forward puts it on the chain, so a
# seed thief who read this code attached it to a theft: the alarm became
# "forward found on chain", a reconstructed plan the agent read as sent.
_nk = Net(utxos=[], spends=[_OURS])
_c, _o, _p, _of = run(_nk)
check("EMPTIED BY A SPEND CARRYING OUR OWN MEMO THAT THIS BOX NEVER RECORDED "
      "SENDING (a seed thief who copied the memo): FAILED, foreign_spend, no "
      "plan -- and the log says the memo is copyable",
      _c == F.EXIT_FAILED and _p is None
      and ("forward", "foreign_spend") in _nk.kinds
      and ("forward", "reconstructed") not in _nk.kinds
      and "never recorded sending it" in _o and _nk.submits == [])
_nr = Net(utxos=[], spends=[_OURS])
_c, _o, _p, _of = run(_nr, outfile=_ours_of(_OURS["txid"]))
check("EMPTIED BY OUR OWN FORWARD (its txid recorded before it was sent, "
      "its memo naming this deposit's destination): the run reports done, "
      "no quote is asked, nothing is signed or sent, and the plan is "
      "RECONSTRUCTED from the chain",
      _c == F.EXIT_OK and _p is not None and _p.get("reconstructed") is True
      and _nr.posts == [] and _nr.submits == [] and _nr.seens == []
      and ("forward", "reconstructed") in _nr.kinds
      and _status_of(_of) is None)
check("...the reconstructed plan reads as SENT to the agent (broadcast, "
      "accepted, seen) and carries what the chain shows: the txid, the "
      "inputs and their values, what reached the inbound, the fee, the "
      "memo, the destination -- and no hex, no quote",
      _p is not None and _p["broadcast"] is True
      and _p["broadcast_outcome"] == "accepted" and _p["seen"] is True
      and _p["txid"] == _OURS["txid"] and _p["seen_height"] == 850001
      and _p["inputs"][0]["tx_hash"] == _H1 and _p["inputs"][0]["value"]
      == 200000 and _p["send_sat"] == 190000 and _p["fee_sat"] == 10000
      and _p["inbound"] == _INBOUND and _p["memo"] == "=:XMR.XMR:" + _DEST
      + ":123456/1/0" and _p["dest_xmr"] == _DEST and _p["tx_hex"] is None
      and _p["expected_xmr"] is None and _p["schema"] == F.PLAN_SCHEMA)
check("...the history was asked for THIS address with the pair's servers, "
      "over the proxy", len(_nr.spend_calls) == 1
      and _nr.spend_calls[0]["address"] == F.derive_receive_address(
          _XPUB, 0, "main")
      and _nr.spend_calls[0]["servers"] == [("s.onion", 50002, None)]
      and _nr.spend_calls[0]["proxy"] == _PROXY)
for _why, _sp in (("a memo naming another destination",
                   _spend_tx("=:XMR.XMR:" + _OTHER + ":0/1/0")),
                  ("no memo at all", _spend_tx(None)),
                  ("a memo that is not text", {**_spend_tx(None), "hex": None})):
    if _sp["hex"] is None:
        _tx = T.build_unsigned([{"tx_hash": _H1, "vout": 0, "value": 200000}],
                               [(190000, _IN_SPK),
                                (0, T.op_return_script(b"\xff\xfe" * 20))],
                               locktime=_TIP)
        _sp = {**_sp, "hex": _tx.serialize().hex(), "txid": _tx.txid().hex()}
    _nf = Net(utxos=[], spends=[_sp])
    _c, _o, _p, _of = run(_nf)
    check(f"EMPTIED BY A SPEND THIS TOOL DID NOT SIGN ({_why}): the run FAILS "
          "(not refused, not done), nothing is signed, no plan, no status "
          "word, the kind on the chain",
          _c == F.EXIT_FAILED and _p is None and _status_of(_of) is None
          and ("forward", "foreign_spend") in _nf.kinds
          and _nf.posts == [] and _nf.submits == [])
_nu = Net(utxos=[], spends=F.watch.BtcWatchError("no server answered"))
_c, _o, _p, _of = run(_nu)
check("the history could not be read: answered from what is unspent alone "
      "-- nothing_settled with 'not_seen', the kind on the chain",
      _c == F.EXIT_REFUSED and _status_of(_of) == "not_seen"
      and ("forward", "history_unavailable") in _nu.kinds
      and ("forward", "refused:nothing_settled") in _nu.kinds)
_nn = Net(utxos=[], spends=[])
_c, _o, _p, _of = run(_nn)
check("never paid (no spend in the history): nothing_settled with "
      "'not_seen', as before", _c == F.EXIT_REFUSED
      and _status_of(_of) == "not_seen" and len(_nn.spend_calls) == 1)
_ns = Net(utxos=[{"tx_hash": _H2, "vout": 0, "value": 200000,
                  "confirmations": 0}], spends=[_OURS])
_c, _o, _p, _of = run(_ns)
check("money on the address (unconfirmed): the history is NOT read -- that "
      "is 'seen', still confirming, not an emptied address",
      _c == F.EXIT_REFUSED and _status_of(_of) == "seen"
      and _ns.spend_calls == [])
_two = Net(utxos=[], spends=[_spend_tx("=:XMR.XMR:" + _OTHER + ":0/1/0"),
                             _OURS])
_c, _o, _p, _of = run(_two, outfile=_ours_of(_OURS["txid"]))
check("with several spends the LAST one decides (the newest state of the "
      "address)", _c == F.EXIT_OK and _p is not None
      and _p["txid"] == _OURS["txid"])
check("an OP_RETURN is read exactly as this tool lays one out -- one push, "
      "direct or PUSHDATA1 -- and nothing else is mistaken for one",
      F._op_return_data(bytes([0x6a, 3]) + b"abc") == b"abc"
      and F._op_return_data(bytes([0x6a, 0x4c, 3]) + b"abc") == b"abc"
      and F._op_return_data(bytes([0x6a, 3]) + b"ab") is None
      and F._op_return_data(bytes([0x6a, 0x4c, 3]) + b"abcd") is None
      and F._op_return_data(_IN_SPK.data) is None
      and F._op_return_data(b"") is None and F._op_return_data(None) is None)


# SENT, THEN KILLED BEFORE THE PLAN -- the case the reconstruction exists
# for, driven end to end: the seen-wait runs for minutes over Tor, and the
# box dies in it. The record must already hold the txid when the first
# byte goes to a server.
class _Died(BaseException):
    pass


class _DyingNet(Net):
    def _submit(self, raw_hex, expected_txid, *a, **kw):
        self.rec_at_submit = set(F.signed_txids(self.of))
        return super()._submit(raw_hex, expected_txid, *a, **kw)

    def _seen(self, *a, **kw):
        raise _Died()


_nd = _DyingNet(submit=_ACCEPTED)
_nd.of = _new_of()
try:
    run(_nd, broadcast=True, outfile=_nd.of)
    _died = False
except _Died:
    _died = True
_dtx = (_nd.submits[0]["txid"] if _nd.submits else None)
check("a forward's txid is RECORDED, and on disk, before its bytes reach "
      "any server",
      _died and _dtx is not None and _nd.rec_at_submit == {_dtx}
      and not os.path.exists(_nd.of))
_nd2 = Net(utxos=[], spends=[{"txid": _dtx, "height": 850001,
                              "hex": _nd.submits[0]["raw_hex"],
                              "inputs": [{"tx_hash": _H1, "vout": 0,
                                          "value": 200000}],
                              "server": "s.onion"}])
_c, _o, _p, _ = run(_nd2, outfile=_nd.of)
check("...and the next run finds that very forward on the emptied address "
      "and reconstructs its plan: sent, not a leaked seed",
      _c == F.EXIT_OK and _p is not None and _p.get("reconstructed") is True
      and _p["txid"] == _dtx and ("forward", "foreign_spend") not in _nd2.kinds)
# A RECORD THAT CANNOT BE WRITTEN SENDS NOTHING.
_real_awj = F.atomic_write_json


def _no_record(obj, path, *a, **k):
    if str(path).endswith(".signed.json"):
        raise OSError(28, "No space left on device")
    return _real_awj(obj, path, *a, **k)


F.atomic_write_json = _no_record
try:
    _nx = Net(submit=_ACCEPTED, seen=_SEEN0)
    _c, _o, _p, _ = run(_nx, broadcast=True)
finally:
    F.atomic_write_json = _real_awj
check("a record that cannot be written is a refusal: nothing is sent",
      _c == F.EXIT_REFUSED and _nx.submits == []
      and ("forward", "refused:signed_record_failed") in _nx.kinds)
# The record yields txids and nothing else, keeps the newest SIGNED_KEEP,
# and an unreadable one reads as empty -- the side that raises the alarm.
_ofk = _new_of()
_ids = [f"{i:064x}" for i in range(F.SIGNED_KEEP + 6)]
for _t in _ids:
    F.record_signed(_ofk, _t)
F.record_signed(_ofk, _ids[-3].upper())
_kept = F._read_signed(_ofk)
check("the record keeps the newest SIGNED_KEEP txids, once each, the "
      "re-recorded one moved to the end",
      len(_kept) == F.SIGNED_KEEP and _kept[-1] == _ids[-3]
      and _kept.count(_ids[-3]) == 1 and _ids[0] not in _kept
      and _kept[0] == _ids[len(_ids) - F.SIGNED_KEEP])
with open(F.signed_path(_ofk), "w") as _fh:
    json.dump({"schema": F.SIGNED_SCHEMA,
               "txids": [_nd.submits[0]["raw_hex"], "zz" * 32, 7, _dtx]}, _fh)
check("...a record yields only 64-hex txids: a transaction or junk in it "
      "is never read as one", F._read_signed(_ofk) == [_dtx])
with open(F.signed_path(_ofk), "w") as _fh:
    _fh.write("{not json")
_nb = Net().install()
check("...and an unreadable record reads as EMPTY, with a kind on the "
      "chain: a spend it named is foreign, never a theft passed as ours",
      F.signed_txids(_ofk) == set()
      and ("forward", "signed_record_unreadable") in _nb.kinds)
check("the record is wiped and sealed with the plans (btc_forward_*.json) "
      "and is never read as a rotated plan",
      any(fnmatch.fnmatch(F.signed_path("/a/btc_forward_h.json").name, _pt)
          for _pt in C.GS_ARTIFACT_FILE_PATTERNS)
      and F.signed_path("/a/btc_forward_h.json").name
      == "btc_forward_h.signed.json"
      and F._plan_chain(_ofk) == [])

print("\n== STAGE 5: --reconcile, what became of a forward that went out ==")
_TN = ("--thornode", "https://tn.example")


def _first_send(submit=_ACCEPTED, seen=_SEEN0):
    """A first forward that SENT: returns (plan, outfile, signed hex)."""
    net = Net(submit=submit, seen=seen)
    code, out, plan, of = run(net, broadcast=True)
    assert code == 0 and plan is not None, (code, out)
    return plan, of, net.submits[0]["raw_hex"]


def _listed(plan, raw_hex, height=850002, inputs=None):
    return {"txid": plan["txid"], "height": height, "hex": raw_hex,
            "inputs": inputs or [{"tx_hash": _H1, "vout": 0,
                                  "value": 200000}],
            "server": "s.onion"}


def _reconcile(net, of, *extra):
    return run(net, "--reconcile", *_TN, *extra, dry_run=False, outfile=of)


_UNSPENT0 = [{"tx_hash": _H1, "vout": 0, "value": 200000,
              "confirmations": 5}]

# (a) LISTED, nothing new: bring the plan up to date, send nothing.
_p1, _of1, _hx1 = _first_send()
_n1 = Net(utxos=[], spends=[_listed(_p1, _hx1)])
_c, _o, _p, _ = _reconcile(_n1, _of1)
check("the reconciliation names its OWN transactions to the history read "
      "-- the forward and what funded its inputs -- so a dust flood that "
      "pushes them off the window cannot jam it history_inconsistent",
      _n1.spend_calls
      and {_p1["txid"].lower(), _H1}
      <= set(_n1.spend_calls[0].get("keep_txids") or ()))
check("listed in a block, nothing new on the address: done, no quote, no "
      "send; the plan is brought up to date (seen, the height, a "
      "reconciliation stamp) and NOT rotated",
      _c == F.EXIT_OK and _n1.posts == [] and _n1.submits == []
      and _p is not None and _p["txid"] == _p1["txid"] and _p["seen"] is True
      and _p["seen_height"] == 850002 and _p.get("reconciled_ts")
      and ("forward", "reconciled_listed") in _n1.kinds
      and len(F._plan_chain(_of1)) == 1 and _status_of(_of1) is None)
# (b) an AMBIGUOUS first send, now listed: the outcome becomes accepted and
# the kept bytes are dropped -- the phone stops hearing "unsure".
_p2, _of2, _hx2 = _first_send(submit=_AMBIGUOUS, seen=_NOT_SEEN)
check("(setup) an ambiguous, unseen first send kept its bytes",
      _p2["broadcast_outcome"] == "ambiguous" and _p2["tx_hex"] == _hx2)
_n2 = Net(utxos=[], spends=[_listed(_p2, _hx2, height=0)])
_c, _o, _p, _ = _reconcile(_n2, _of2)
check("an ambiguous send found listed (mempool): accepted now, the kept bytes "
      "dropped, done", _c == F.EXIT_OK and _p["broadcast_outcome"] == "accepted"
      and _p["tx_hex"] is None and _p["seen"] is True
      and _p["seen_height"] == 0 and _n2.submits == [])
# (c) NOT listed, inputs still unspent, bytes kept: the SAME bytes again.
_p3, _of3, _hx3 = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
_n3 = Net(utxos=_UNSPENT0, spends=[], submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_n3, _of3)
check("not listed, inputs unspent, bytes kept: RE-SENT -- the identical "
      "bytes, no quote, no new signature; seen now, the bytes dropped, "
      "resends counted, the plan not rotated",
      _c == F.EXIT_OK and len(_n3.submits) == 1
      and _n3.submits[0]["raw_hex"] == _hx3
      and _n3.submits[0]["txid"] == _p3["txid"] and _n3.posts == []
      and _p["resends"] == 1 and _p["seen"] is True and _p["tx_hex"] is None
      and _p["txid"] == _p3["txid"] and len(F._plan_chain(_of3)) == 1
      and ("forward", "resend") in _n3.kinds)
# (c') the re-send is REJECTED by every server: stale bytes, live money --
# a fresh forward at today's fee follows, the old plan rotated aside.
_p4, _of4, _hx4 = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
_n4 = Net(utxos=_UNSPENT0, spends=[], submit=[_REJECTED, _ACCEPTED],
          seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_n4, _of4)
_chain4 = F._plan_chain(_of4)
check("a rejected re-send: a FRESH forward is quoted, signed and sent; the "
      "old plan is rotated aside (rejected, not moved) and the new one says "
      "why it exists", _c == F.EXIT_OK and len(_n4.submits) == 2
      and _n4.submits[0]["raw_hex"] == _hx4 and len(_n4.posts) == 1
      and len(_chain4) == 2 and _p["reconcile_reason"] == "rejected"
      and _p["broadcast_outcome"] == "accepted"
      and json.load(open(_chain4[1]))["broadcast"] is False
      and json.load(open(_chain4[1]))["resends"] == 1
      and ("forward", "resend_rejected") in _n4.kinds
      and ("forward", "reconcile_rejected") in _n4.kinds)
# A STOP ASKED AFTER THE LOOK STOPS THE SEND. The handler only sets a flag
# and main() read it once, right after the look: a SIGTERM during the
# quote (or the reconciliation's history read) went on to sign and SEND,
# and the agent SIGKILLed the child in the seen wait with no plan written.
class _StopNet(Net):
    """A Net whose stop flag rises during the quote (`at`="quote") or the
    history read (`at`="history")."""

    def __init__(self, at, **kw):
        super().__init__(**kw)
        self.at, self.stop = at, False

    def install(self):
        super().install()
        F.shutdown_requested = lambda: self.stop
        return self

    def safe_post(self, url, payload, proxies=None):
        if self.at == "quote":
            self.stop = True
        return super().safe_post(url, payload, proxies)

    def _spends(self, *a, **kw):
        if self.at == "history":
            self.stop = True
        return super()._spends(*a, **kw)


_nSt = _StopNet("quote", submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ofSt = run(_nSt, broadcast=True)
check("a stop that lands during the quote: nothing recorded as signed, "
      "nothing handed to any server, exit failed, the kind on the chain",
      _c == F.EXIT_FAILED and _nSt.submits == []
      and not os.path.exists(F.signed_path(_ofSt))
      and ("forward", "stopped_before_send") in _nSt.kinds)
_nSn = Net(submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = run(_nSn, broadcast=True)
check("NON-VACUITY: without the stop the same forward is sent, and its seen "
      "wait is handed the live stop flag to end on",
      _c == F.EXIT_OK and len(_nSn.submits) == 1
      and _nSn.seens[0].get("stop") is F.shutdown_requested)
_p3s, _of3s, _hx3s = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
_nSr = _StopNet("history", utxos=_UNSPENT0, spends=[], submit=_ACCEPTED,
                seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nSr, _of3s)
check("a stop during the reconciliation's history read: the kept bytes are "
      "NOT re-sent, exit failed", _c == F.EXIT_FAILED and _nSr.submits == []
      and ("forward", "stopped_before_send") in _nSr.kinds)
# (c'') the re-send reaches NO server: nothing was sent this time, and the
# earlier send's outcome stands. It was overwritten with `unreachable`,
# and the plan then read as a forward that never went out -- to the agent
# (no word when it confirmed; the next wake a plain --broadcast) and to
# the pairs rewrite -- about money the network had once accepted.
_p4u, _of4u, _hx4u = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
_n4u = Net(utxos=_UNSPENT0, spends=[], submit=_UNREACHABLE, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_n4u, _of4u)
check("an unreachable re-send: exit failed, the plan keeps broadcast True and "
      "the earlier 'accepted', the attempt recorded beside it, the bytes kept",
      _c == F.EXIT_FAILED and len(_n4u.submits) == 1
      and _p["broadcast"] is True and _p["broadcast_outcome"] == "accepted"
      and _p["resend_outcome"] == "unreachable" and _p["resends"] == 1
      and _p["tx_hex"] == _hx4u)
# (d) NOT listed, inputs unspent, no bytes (it was listed once): evicted --
# re-signed afresh (every input opts into RBF), the old plan rotated.
_p5, _of5, _hx5 = _first_send()
check("(setup) a seen first send kept no bytes", _p5["tx_hex"] is None)
_n5 = Net(utxos=_UNSPENT0, spends=[], submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_n5, _of5)
check("evicted (not listed, inputs unspent, nothing kept): a fresh forward "
      "of the same money -- quoted, signed, sent -- the old plan rotated, "
      "the reason recorded", _c == F.EXIT_OK and len(_n5.posts) == 1
      and len(_n5.submits) == 1 and _p["reconcile_reason"] == "evicted"
      and _p["inputs"][0]["tx_hash"] == _H1
      and len(F._plan_chain(_of5)) == 2
      and ("forward", "evicted") in _n5.kinds)
# (e) listed, and NEW settled money on the address: a refund or a second
# payment -- forwarded, and ONLY the new outputs.
_p6, _of6, _hx6 = _first_send()
_n6 = Net(utxos=[{"tx_hash": _H2, "vout": 0, "value": 150000,
                  "confirmations": 5}],
          spends=[_listed(_p6, _hx6)], submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_n6, _of6)
check("RETURNED, settled: the new output is forwarded on its own (the old "
      "plan's input is excluded), quoted for its own amount, a new plan "
      "beside the rotated old one", _c == F.EXIT_OK and len(_n6.posts) == 1
      and _p["reconcile_reason"] == "returned"
      and [(i["tx_hash"], i["vout"]) for i in _p["inputs"]] == [(_H2, 0)]
      and _p["excluded_outpoints"] == 1 and _p["settled_sat"] == 150000
      and len(F._plan_chain(_of6)) == 2
      and json.load(open(F._plan_chain(_of6)[1]))["txid"] == _p6["txid"]
      and ("forward", "returned_settled") in _n6.kinds)
# (f) listed, new money NOT settled yet: the word `returned`, sent on later.
_p7, _of7, _hx7 = _first_send()
_n7 = Net(utxos=[{"tx_hash": _H2, "vout": 0, "value": 150000,
                  "confirmations": 0}], spends=[_listed(_p7, _hx7)])
_c, _o, _p, _ = _reconcile(_n7, _of7)
check("RETURNED, not settled: refused returned_unsettled with the status "
      "word 'returned', nothing sent, the plan (seen) not rotated",
      _c == F.EXIT_REFUSED and _status_of(_of7) == "returned"
      and _n7.submits == [] and _n7.posts == []
      and ("forward", "refused:returned_unsettled") in _n7.kinds
      and len(F._plan_chain(_of7)) == 1 and _p["seen"] is True)
# (f2) listed IN THE MEMPOOL, and the server still lists the input it
# spends as unspent -- the case `exclude` exists for. What came back is
# 5,000 sat: under the one-input floor even at 1 sat/vB, so it is `short`
# exactly as it is on an address holding nothing else. The look's total
# (205,000) counted the forward's own input and said `delayed`.
_p7b, _of7b, _hx7b = _first_send()
_IN_STILL = {"tx_hash": _H1, "vout": 0, "value": 200000, "confirmations": 5}
_n7b = Net(utxos=[_IN_STILL, {"tx_hash": _H2, "vout": 0, "value": 5000,
                              "confirmations": 5}],
           spends=[_listed(_p7b, _hx7b, height=0)], submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_n7b, _of7b)
check("RETURNED, too small to send on, beside the listed forward's own input "
      "still shown unspent: refused, nothing sent, and the status word is "
      "'short' -- the excluded input is not money this forward carries",
      _c == F.EXIT_REFUSED and ("forward", "reconcile_returned") in _n7b.kinds
      and ("forward", "refused:fee_eats_deposit") in _n7b.kinds
      and _n7b.submits == [] and _status_of(_of7b) == "short")
_p7c, _of7c, _hx7c = _first_send()
_n7c = Net(utxos=[_IN_STILL, {"tx_hash": _H2, "vout": 0, "value": 150000,
                              "confirmations": 5}],
           spends=[_listed(_p7c, _hx7c, height=0)], fee=500)
_c, _o, _p, _ = _reconcile(_n7c, _of7c)
check("NON-VACUITY: 150,000 sat back beside the same input, on a day the "
      "estimate is over the ceiling, is still 'delayed' -- it forwards with "
      "cheaper blocks", _c == F.EXIT_REFUSED
      and ("forward", "refused:fee_out_of_band") in _n7c.kinds
      and _n7c.submits == [] and _status_of(_of7c) == "delayed")
# (f3) A REPLACEMENT TODAY'S FEE WILL NOT CARRY IS `delayed`, never
# `short`: the forward it would replace stands in the mempool. 15,000 sat
# went out at 11 sat/vB and sat four hours; at an estimate of 30 the
# replacement's floor (12) puts its fee over a fifth, and the one-input
# floor at 12 is over 15,000 -- the fresh-forward test said `short`,
# "under what was quoted, stopped growing", about money that went out.
_n7d = Net(utxos=_outs([15000]), fee=11, submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p7d, _of7d = run(_n7d, broadcast=True)
_pl7d = json.load(open(_of7d))
_pl7d["ts"] = int(time.time()) - 4 * 3600
with open(_of7d, "w") as _fh:
    json.dump(_pl7d, _fh)
_n7e = Net(utxos=[], fee=30, submit=_ACCEPTED, seen=_SEEN0,
           spends=[{"txid": _p7d["txid"], "height": 0,
                    "hex": _n7d.submits[0]["raw_hex"],
                    "inputs": [{"tx_hash": _outs([15000])[0]["tx_hash"],
                                "vout": 0, "value": 15000}],
                    "server": "s.onion"}])
_c, _o, _p, _ = _reconcile(_n7e, _of7d)
check("a replacement refused on today's fee (the original still in the "
      "mempool): nothing sent, the original's plan stands, and the word is "
      "'delayed', not 'short'", _c == F.EXIT_REFUSED
      and ("forward", "reconcile_bumped") in _n7e.kinds
      and any(k.startswith("refused:fee") for s, k in _n7e.kinds)
      and _n7e.submits == [] and _p["txid"] == _p7d["txid"]
      and _status_of(_of7d) == "delayed")
# (g) a spend of the address that is NOT ours: the run fails, nothing signed.
_p8, _of8, _hx8 = _first_send()
_n8 = Net(utxos=[], spends=[_listed(_p8, _hx8),
                            {**_spend_tx("=:XMR.XMR:" + _OTHER + ":0/1/0"),
                             "inputs": [{"tx_hash": _H2, "vout": 0,
                                         "value": 5000}]}])
_c, _o, _p, _ = _reconcile(_n8, _of8)
check("a spend this tool did not sign among the address's spends: FAILED, "
      "the kind on the chain, nothing signed or sent",
      _c == F.EXIT_FAILED and _n8.submits == [] and _n8.posts == []
      and ("forward", "foreign_spend") in _n8.kinds)
# (h) our plan's txid is not listed, but a listed spend with OUR memo
# consumed its inputs (an earlier reconciliation re-signed and died before
# its plan; this plan is the older one): adopted -- ONLY because its txid
# was recorded before it was sent -- recorded as superseded, done.
_p9, _of9, _hx9 = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
_adopt = {**_spend_tx("=:XMR.XMR:" + _DEST + ":99/1/0"), "height": 850003}
_n9k = Net(utxos=[], spends=[_adopt])
_c, _o, _p, _ = _reconcile(_n9k, _of9)
check("a listed spend with OUR memo that this box never recorded sending "
      "(a seed thief who copied the memo from our first forward): FAILED, "
      "foreign_spend -- it was adopted as ours and this plan marked "
      "superseded by the theft, `forwarded` once it mined",
      _c == F.EXIT_FAILED and ("forward", "foreign_spend") in _n9k.kinds
      and ("forward", "adopted_spend") not in _n9k.kinds
      and "never recorded sending it" in _o
      and json.load(open(_of9)).get("superseded_by") is None
      and _n9k.submits == [])
F.record_signed(_of9, _adopt["txid"])
_n9 = Net(utxos=[], spends=[_adopt])
_c, _o, _p, _ = _reconcile(_n9, _of9)
check("a listed spend whose txid this box recorded before sending, that the "
      "plan chain did not know: adopted as ours; this plan's inputs were "
      "consumed by it, so it is recorded as superseded and the run is done "
      "-- nothing re-sent",
      _c == F.EXIT_OK and _p["superseded_by"] == _adopt["txid"]
      and _n9.submits == [] and _n9.posts == []
      and ("forward", "adopted_spend") in _n9.kinds
      and ("forward", "reconciled_superseded") in _n9.kinds)
# (h2) SUPERSEDED, AND MONEY CAME BACK NOT YET SETTLED: the same state the
# listed branch answers `returned` (or keeps, at the bound). The superseded
# branch had no such tail -- done, the phone hearing `forwarded`, and a
# kept mark dropped -- two answers to one state, decided twice.
for _rmax, _want in (((), "returned"), (("--returns-max", "0"), "kept")):
    _pS9, _ofS9, _hxS9 = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
    _adS = {**_spend_tx("=:XMR.XMR:" + _DEST + ":99/1/0"), "height": 850003}
    F.record_signed(_ofS9, _adS["txid"])
    _nS9 = Net(utxos=[{"tx_hash": _H2, "vout": 0, "value": 150000,
                       "confirmations": 0}], spends=[_adS])
    _c, _o, _p, _ = _reconcile(_nS9, _ofS9, *_rmax)
    _pS9now = json.load(open(_ofS9))
    if _want == "returned":
        _ok = (_c == F.EXIT_REFUSED and _status_of(_ofS9) == "returned"
               and ("forward", "refused:returned_unsettled") in _nS9.kinds)
    else:
        _ok = (_c == F.EXIT_OK and isinstance(_pS9now.get("returned_kept"),
                                              dict))
    check(f"superseded, with unsettled money back ({_rmax or 'the default'}"
          f" bound): '{_want}', as the listed branch says",
          _ok and ("forward", "reconciled_superseded") in _nS9.kinds
          and _pS9now.get("superseded_by") == _adS["txid"]
          and _nS9.submits == [])
# (h3) THE SUPERSEDER IS THE FORWARD OVER THIS PLAN'S INPUTS, not the newest
# of all ours: a newer forward of ours in the mempool over OTHER outpoints
# (returned money) was named, its height 0, and `forwarded` for this plan
# waited on an unrelated transaction.
_pS10, _ofS10, _hxS10 = _first_send(submit=_ACCEPTED, seen=_NOT_SEEN)
_adA = {**_spend_tx("=:XMR.XMR:" + _DEST + ":99/1/0"), "height": 850003}
_adB = {**_spend_tx("=:XMR.XMR:" + _DEST + ":98/1/0", send=140000),
        "height": 0, "inputs": [{"tx_hash": _H2, "vout": 0,
                                 "value": 150000}]}
F.record_signed(_ofS10, _adA["txid"])
F.record_signed(_ofS10, _adB["txid"])
_nS10 = Net(utxos=[], spends=[_adA, _adB])
_c, _o, _p, _ = _reconcile(_nS10, _ofS10)
check("superseded: superseded_by names our forward over THIS plan's inputs "
      "(mined at 850003), not a newer one of ours over other outpoints",
      _c == F.EXIT_OK and _p["superseded_by"] == _adA["txid"]
      and _p["superseded_height"] == 850003)
# (i) the history could not be read: a reconciliation cannot decide.
_p10, _of10, _hx10 = _first_send()
_n10 = Net(utxos=_UNSPENT0, spends=F.watch.BtcWatchError("nobody answered"),
           submit=_ACCEPTED)
_c, _o, _p, _ = _reconcile(_n10, _of10)
check("the history unreadable: FAILED with the kind, nothing sent (a decision "
      "without the history could double-spend)",
      _c == F.EXIT_FAILED and _n10.submits == []
      and ("forward", "history_unavailable") in _n10.kinds)
# (j) the plan's inputs are neither unspent nor in any listed spend.
_p11, _of11, _hx11 = _first_send()
_n11 = Net(utxos=[], spends=[], submit=_ACCEPTED)
_c, _o, _p, _ = _reconcile(_n11, _of11)
check("the server's history and unspent set contradict each other: FAILED, "
      "nothing signed", _c == F.EXIT_FAILED and _n11.submits == []
      and _n11.posts == []
      and ("forward", "history_inconsistent") in _n11.kinds)
# (k) the arguments.
_nk = Net(utxos=_UNSPENT0)
check("--reconcile without a plan at --outfile is refused no_plan; with "
      "--dry-run it is two modes; without --thornode it may not send",
      _refusal(_nk, "--reconcile", *_TN, dry_run=False)[3] == "no_plan"
      and _refusal(Net(), "--reconcile", *_TN)[3] == "not_dry_run"
      and _refusal(Net(), "--reconcile", dry_run=False,
                   outfile=_of1)[3] == "bad_args")
_ch, _du, _un = F.select_inputs(
    [{"tx_hash": _H1, "vout": 0, "value": 200000, "confirmations": 5},
     {"tx_hash": _H2, "vout": 1, "value": 150000, "confirmations": 5}],
    2, 10, exclude=[(_H1, 0)])
check("select_inputs leaves an excluded outpoint out before anything else "
      "is decided", [u["tx_hash"] for u in _ch] == [_H2] and _du == 0
      and _un == 0)
check("the plan chain: the current plan first, then the rotated ones newest "
      "first, and the status file is never mistaken for one",
      [p.name for p in F._plan_chain(_of4)]
      == [os.path.basename(_of4), os.path.basename(_of4)[:-5] + ".1.json"]
      and not any(".status." in p.name for p in F._plan_chain(_of7)))

print("\n== STAGE 6: the chain never lacks a current plan ==")
# STAGE6_PLAN.md 1(b): the fresh forward a verdict called for used to
# rotate the current plan aside FIRST and then refuse -- a fee over the
# ceiling on the day a refund came back was enough -- and every later run
# read `--outfile`, found nothing, and refused `no_plan`, for ever.
_pB, _ofB, _hxB = _first_send()
_RET = [{"tx_hash": _H2, "vout": 0, "value": 150000, "confirmations": 5}]
_nB = Net(utxos=_RET, spends=[_listed(_pB, _hxB)], fee=500)
_c, _o, _p, _ = _reconcile(_nB, _ofB)
check("(setup) returned money on a day the estimate is over the ceiling: "
      "delayed, nothing sent", _c == F.EXIT_REFUSED
      and _status_of(_ofB) == "delayed" and _nB.submits == [])
check("a fresh forward that was REFUSED after the verdict leaves the old "
      "plan where it was: the current plan still stands, the chain is one, "
      "nothing rotated", os.path.exists(_ofB) and len(F._plan_chain(_ofB)) == 1
      and _p is not None and _p["txid"] == _pB["txid"]
      and ("forward", "plan_recovered") not in _nB.kinds)
_nB2 = Net(utxos=_RET, spends=[_listed(_pB, _hxB)], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB2, _ofB)
check("...and the next reconcile, with the fee inside the band, forwards the "
      "returned money: rotated at the WRITE, the chain is two, the new plan "
      "says why", _c == F.EXIT_OK and _p is not None
      and _p["reconcile_reason"] == "returned"
      and len(F._plan_chain(_ofB)) == 2
      and json.load(open(F._plan_chain(_ofB)[1]))["txid"] == _pB["txid"]
      and ("forward", "plan_recovered") not in _nB2.kinds)
# A chain ALREADY in the old state (a deployment that hit the trap before
# this fix): no current plan, the record one file over. Restored, not
# refused -- and restored by MOVING it back, so the reconciliation's
# in-place update does not leave the same forward as two files.
_pR, _ofR, _hxR = _first_send()
F._rotate_plan(_ofR)
check("(setup) a chain with no current plan and one rotated predecessor",
      not os.path.exists(_ofR) and len(F._plan_chain(_ofR)) == 1)
_nR = Net(utxos=[], spends=[_listed(_pR, _hxR)])
_c, _o, _p, _ = _reconcile(_nR, _ofR)
check("a chain with no current plan is read from its newest rotated one, "
      "moved back into place: listed, done, the kind on the chain, and the "
      "chain is ONE file again (no duplicate to count twice)",
      _c == F.EXIT_OK and os.path.exists(_ofR)
      and len(F._plan_chain(_ofR)) == 1 and _p is not None
      and _p["txid"] == _pR["txid"] and _p["seen"] is True
      and ("forward", "plan_recovered") in _nR.kinds
      and ("forward", "reconciled_listed") in _nR.kinds)
check("NON-VACUITY: a chain with NO plan anywhere is still refused no_plan",
      _refusal(Net(utxos=_UNSPENT0), "--reconcile", *_TN, dry_run=False)[3]
      == "no_plan")
# A ROTATED NAME IS NEVER TAKEN TWICE. The rotation counts the rotated
# files and writes count+1; with a gap in the numbers (a file removed by
# hand, a recovery that moved one back beside a foreign file that kept its
# number) that name can already be a plan of ours, and the rotation would
# have put the current plan OVER it -- a record the pairs rewrite and the
# reconciliation both read, gone.
_pG, _ofG, _hxG = _first_send()
_stemG = _ofG[:-len(".json")]
with open(_stemG + ".1.json", "w") as _fh:
    json.dump({**json.load(open(_ofG)), "txid": "11" * 32}, _fh)
with open(_stemG + ".3.json", "w") as _fh:
    json.dump({**json.load(open(_ofG)), "txid": "33" * 32}, _fh)
_nG = Net(utxos=_RET, spends=[_listed(_pG, _hxG)], fee=10,
          submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nG, _ofG)
check("a rotation into a chain whose numbers have a gap (.1 and .3 present) "
      "takes the next FREE number (.4) rather than writing over .3",
      _c == F.EXIT_OK and _p is not None
      and _p["reconcile_reason"] == "returned"
      and json.load(open(_stemG + ".3.json"))["txid"] == "33" * 32
      and json.load(open(_stemG + ".4.json"))["txid"] == _pG["txid"]
      and len(F._plan_chain(_ofG)) == 4)
_pX, _ofX, _hxX = _first_send()
F._rotate_plan(_ofX)
with open(F._plan_chain(_ofX)[0], "w") as _fh:
    json.dump({"schema": "somebody_elses", "txid": "00" * 32}, _fh)
check("...and a rotated file that is not one of ours is skipped without a "
      "refusal on the chain: no plan of ours anywhere means no_plan",
      _refusal(Net(utxos=_UNSPENT0), "--reconcile", *_TN, dry_run=False,
               outfile=_ofX)[3] == "no_plan")

print("\n== STAGE 6: a forward sitting in the mempool is bumped ==")
# STAGE6_PLAN.md 1(c), 3.1: listed in the mempool was answered "nothing to
# send" however long it sat and however far fees rose. Every input opts
# into RBF; past --bump-after, with today's estimate above the rate paid,
# the forward is REPLACED: the same outpoints, a fresh quote for the
# smaller amount, today's rate, the new plan naming the old.
_time = __import__("time")


def _age_plan(of, seconds):
    """Move the plan's send stamp back, as if it had sat that long."""
    _pl = json.load(open(of))
    _pl["ts"] = int(_time.time()) - int(seconds)
    with open(of, "w") as _fh:
        json.dump(_pl, _fh)


_pS, _ofS, _hxS = _first_send()            # accepted, seen in the mempool
check("(setup) the first send paid the estimate and knows it",
      _pS["feerate_target_sat_vb"] == 10 and _pS["seen_height"] == 0
      and isinstance(_pS["ts"], int))
_age_plan(_ofS, 4 * 3600)
_nS0 = Net(utxos=[], spends=[_listed(_pS, _hxS, height=0)], fee=10)
_c, _o, _p, _ = _reconcile(_nS0, _ofS)
check("listed in the mempool past the window, but today's estimate is NOT "
      "above the rate paid: done, nothing quoted, nothing sent, the chain "
      "one", _c == F.EXIT_OK and _nS0.posts == [] and _nS0.submits == []
      and ("forward", "reconcile_bumped") not in _nS0.kinds
      and len(F._plan_chain(_ofS)) == 1)
_nS1 = Net(utxos=[], spends=[_listed(_pS, _hxS, height=0)], fee=None)
_c, _o, _p, _ = _reconcile(_nS1, _ofS)
check("...no estimate from the server: done, not bumped (nothing to compare)",
      _c == F.EXIT_OK and _nS1.submits == [] and _p["replaces"] is None
      and ("forward", "reconcile_bumped") not in _nS1.kinds)
_nS2 = Net(utxos=[], spends=[_listed(_pS, _hxS, height=850002)], fee=30)
_c, _o, _p, _ = _reconcile(_nS2, _ofS)
check("...MINED (height > 0): done, never bumped, whatever the estimate",
      _c == F.EXIT_OK and _nS2.submits == [] and _nS2.posts == []
      and ("forward", "reconcile_bumped") not in _nS2.kinds)
_nS3 = Net(utxos=[], spends=[_listed(_pS, _hxS, height=0)], fee=30,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nS3, _ofS)
_chainS = F._plan_chain(_ofS)
_oldS = json.load(open(_chainS[1])) if len(_chainS) > 1 else {}
check("...in the mempool, past the window, estimate above the rate: "
      "REPLACED -- one fresh quote for the SMALLER amount, one NEW "
      "transaction over the SAME outpoints at today's rate, accepted and "
      "seen; the new plan says `bumped` and names the one it replaces; the "
      "old is rotated aside; the kind on the chain",
      _c == F.EXIT_OK and len(_nS3.posts) == 1 and len(_nS3.submits) == 1
      and _nS3.submits[0]["raw_hex"] != _hxS
      and _nS3.submits[0]["txid"] != _pS["txid"]
      and _p is not None and _p["reconcile_reason"] == "bumped"
      and _p["replaces"] == _pS["txid"]
      and [(i["tx_hash"], i["vout"]) for i in _p["inputs"]]
      == [(i["tx_hash"], i["vout"]) for i in _pS["inputs"]]
      and _p["feerate_target_sat_vb"] == 30
      and _p["send_sat"] < _pS["send_sat"]
      and Decimal(_nS3.posts[0][1]["sellAmount"])
      == Decimal(_p["send_sat"]) / Decimal(10 ** 8)
      and len(_chainS) == 2 and _oldS.get("txid") == _pS["txid"]
      and _p["excluded_outpoints"] == 0
      and ("forward", "reconcile_bumped") in _nS3.kinds)
check("...the replacement pays MORE absolute fee than the original by at "
      "least its own size (BIP125), at a higher real rate, so a node "
      "holding the original takes it in its place",
      _p["fee_sat"] >= _pS["fee_sat"] + _p["vsize_bound"]
      and _p["feerate_real_sat_vb"] > _pS["feerate_real_sat_vb"]
      and _p["memo"] != _pS["memo"])
check("...and a bumped plan's inputs carry at least --min-conf of depth "
      "(they were settled when chosen; the look could not show them)",
      all(i["confirmations"] >= 2 for i in _p["inputs"]))
# TOO YOUNG: a forward listed for less than --bump-after is left alone.
_pY, _ofY, _hxY = _first_send()
_nY = Net(utxos=[], spends=[_listed(_pY, _hxY, height=0)], fee=30,
          submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nY, _ofY)
check("a forward listed in the mempool for LESS than --bump-after is left "
      "alone whatever the estimate (the default window is two hours)",
      _c == F.EXIT_OK and _nY.submits == [] and _nY.posts == []
      and F.DEFAULT_BUMP_AFTER_S == 7200
      and ("forward", "reconcile_bumped") not in _nY.kinds)
_nY2 = Net(utxos=[], spends=[_listed(_pY, _hxY, height=0)], fee=30,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nY2, _ofY, "--bump-after", "0")
check("...and --bump-after 0 (the testnet drill's setting) replaces it at "
      "once", _c == F.EXIT_OK and len(_nY2.submits) == 1
      and _p["replaces"] == _pY["txid"])
check("...a negative --bump-after is refused",
      _refusal(Net(), "--reconcile", *_TN, "--bump-after", "-1",
               dry_run=False, outfile=_ofY)[3] == "bad_args")
# THE WINDOW IS DRAWN, NOT THE FLAG'S EXACT NUMBER (the host-privacy
# pass): a replacement at a fixed offset after the transaction it
# replaces put every one of this host's bumps in one population, on a
# pair of public transactions. Never BELOW the operator's setting: it is
# a "has waited at least this long" bound, and bumping sooner would be
# this tool overriding them into a second fee.
_bw = sorted(F.BUMP_WINDOW(7200) for _ in range(400))
check("the bump window is drawn per reconciliation: at or above the "
      "operator's setting, never above it by more than the spread, and "
      "genuinely spread (not one value repeated)",
      _bw[0] >= 7200
      and _bw[-1] <= 7200 + int(7200 * float(F.BUMP_SPREAD_MAX))
      and len(set(_bw)) > 100
      and _bw[-1] - _bw[0] > int(7200 * float(F.BUMP_SPREAD_MAX)) // 2)
check("...and a window of 0 stays 0: the operator turned the bump off "
      "and a drill must still replace at once",
      F.BUMP_WINDOW(0) == 0 and F.BUMP_WINDOW(-5) == 0)
# THE LOOK STILL LISTS THE INPUTS (a server whose mempool never saw the
# original): not duplicated -- one input, not two of the same outpoint.
_pD, _ofD, _hxD = _first_send()
_age_plan(_ofD, 4 * 3600)
_nD = Net(utxos=_UNSPENT0, spends=[_listed(_pD, _hxD, height=0)], fee=30,
          submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nD, _ofD)
check("a server that still lists the original's inputs as unspent: the "
      "replacement spends each outpoint ONCE (deduplicated), and is sent",
      _c == F.EXIT_OK and len(_p["inputs"]) == 1
      and _p["settled_sat"] == 200000 and len(_nD.submits) == 1)
# THE ESTIMATE OVER THE CEILING: the replacement is `delayed` like a first
# forward would be; the original stands, the plan is not rotated.
_pE, _ofE, _hxE = _first_send()
_age_plan(_ofE, 4 * 3600)
_nE = Net(utxos=[], spends=[_listed(_pE, _hxE, height=0)], fee=500,
          submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nE, _ofE)
check("today's estimate over the ceiling: the replacement is `delayed` (the "
      "status word, nothing sent), the original stands, the plan not "
      "rotated, the chain one",
      _c == F.EXIT_REFUSED and _status_of(_ofE) == "delayed"
      and _nE.submits == [] and _nE.posts == []
      and len(F._plan_chain(_ofE)) == 1 and _p["txid"] == _pE["txid"])
# THE ORIGINAL ALREADY PAYS THE CEILING: more would be over it.
_nC0 = Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 2_000_000,
                   "confirmations": 5}], fee=200, submit=_ACCEPTED,
           seen=_SEEN0)
_cC, _oC, _pC, _ofC = run(_nC0, broadcast=True)
check("(setup) a first send at the ceiling rate", _cC == F.EXIT_OK
      and _pC["feerate_target_sat_vb"] == 200)
_age_plan(_ofC, 4 * 3600)
# 211: the forward aimed at 200 and REALLY pays 50800 / 241 = 210.8 sat/vB
# (the fee is sized against the bound), and a bump is due only once the
# estimate is above what it really pays (bump_due).
_nC = Net(utxos=[], spends=[_listed(_pC, _nC0.submits[0]["raw_hex"],
                                    height=0,
                                    inputs=[{"tx_hash": _H1, "vout": 0,
                                             "value": 2_000_000}])],
          fee=211, submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nC, _ofC)
check("a forward already paying the ceiling cannot be replaced within the "
      "band: refused bump_over_ceiling with the word `delayed`, nothing "
      "quoted or sent, the original stands",
      _c == F.EXIT_REFUSED and _status_of(_ofC) == "delayed"
      and _nC.posts == [] and _nC.submits == []
      and ("forward", "refused:bump_over_ceiling") in _nC.kinds
      and len(F._plan_chain(_ofC)) == 1)
# A REJECTED REPLACEMENT: the original stands, nothing rotated.
_pR2, _ofR2, _hxR2 = _first_send()
_age_plan(_ofR2, 4 * 3600)
_nR2 = Net(utxos=[], spends=[_listed(_pR2, _hxR2, height=0)], fee=30,
           submit=_REJECTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nR2, _ofR2)
check("every server rejects the replacement: refused broadcast_rejected, "
      "the original stands as the current plan, the chain one",
      _c == F.EXIT_REFUSED and len(_nR2.submits) == 1
      and ("forward", "refused:broadcast_rejected") in _nR2.kinds
      and len(F._plan_chain(_ofR2)) == 1 and _p["txid"] == _pR2["txid"])
# THE FLOOR A NODE HOLDING THE ORIGINAL WILL TAKE. With the same policy the
# estimate-above-the-rate test already guarantees it; with a policy that
# shrank the bound between the two runs (the operator lowered
# --op-return-max-bytes by one), an estimate one above the old rate would
# pay LESS absolute fee than the original plus the replacement's size, and
# a node would refuse it. bump_floor raises the rate until it does not.
_pF, _ofF, _hxF = _first_send()
check("(setup) the memo fits a policy one byte smaller", _pF["memo_bytes"]
      <= 119)
_age_plan(_ofF, 4 * 3600)
_nF = Net(utxos=[], spends=[_listed(_pF, _hxF, height=0)], fee=30,
          submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nF, _ofF, "--op-return-max-bytes", "119",
                           "--feerate-sat-vb", "11")
check("an explicit rate one above the original's, under a policy one byte "
      "smaller: the floor is raised so the replacement's fee still exceeds "
      "the original's by its own size, and that floor is what is paid",
      _c == F.EXIT_OK and _p["feerate_target_sat_vb"] == 12
      and _p["fee_sat"] >= _pF["fee_sat"] + _p["vsize_bound"]
      and _p["vsize_bound"] == _pF["vsize_bound"] - 1
      and ("forward", "fee_floor_applied") in _nF.kinds)
_nF2 = Net(utxos=[], spends=[_listed(_pF, _hxF, height=0)], fee=30)
_c, _o, _p, _ = _reconcile(_nF2, _ofF, "--feerate-sat-vb", "12")
check("...an explicit rate EQUAL to what the replacement pays is not above "
      "it: not due, done", _c == F.EXIT_OK and _nF2.submits == [])
check("bump_due is pure and refuses what it cannot compare: a reconstructed "
      "plan (no rate), a plan with no stamp, a bool, a young plan",
      F.bump_due({"feerate_target_sat_vb": None, "ts": 0}, 30, 0) is False
      and F.bump_due({"feerate_target_sat_vb": 10}, 30, 0) is False
      and F.bump_due({"feerate_target_sat_vb": 10, "ts": 0}, True, 0) is False
      and F.bump_due({"feerate_target_sat_vb": 10, "ts": 1000}, 30, 7200,
                     now=5000) is False
      and F.bump_due({"feerate_target_sat_vb": 10, "ts": 1000}, 30, 7200,
                     now=8800) is True
      and F.bump_due({"feerate_target_sat_vb": 10, "ts": 1000}, 10, 7200,
                     now=8800) is False)
# THE STAMP IS A TEN-MINUTE BUCKET'S START: the forward went out up to 599 s
# after it, so the age is measured from the bucket's END -- a replacement
# never goes out sooner than --bump-after. The drill's 0 is still at once.
check("bump_due never bumps sooner than the setting though the stamp is "
      "coarsened: 7200 s after a bucket's start is not yet 7200 s after the "
      "send; 7799 s is; and --bump-after 0 is still at once",
      F.bump_due({"feerate_target_sat_vb": 10, "ts": 1200}, 30, 7200,
                 now=1200 + 7200) is False
      and F.bump_due({"feerate_target_sat_vb": 10, "ts": 1200}, 30, 7200,
                     now=1200 + 7799) is True
      and F.bump_due({"feerate_target_sat_vb": 10, "ts": 1200}, 30, 0,
                     now=1200) is True)
# THE RATE IT PAYS, not the rate it aimed at. Target 10, but the fee was
# sized against the vsize bound (274) and the real transaction is 240 vB:
# it pays 2850 sat, 11.875 sat/vB. An estimate of 11 is BELOW that, and
# replacing it paid 588 sat more of the client's deposit for a forward
# already ahead of the market -- and put one more RBF pair on the chain.
_paid_real = {"feerate_target_sat_vb": 10, "fee_sat": 2850, "vsize": 240,
              "ts": 1000}
check("bump_due compares today's estimate with what the forward REALLY pays "
      "(fee/vsize): 11 sat/vB is not above 11.875, so no replacement -- it "
      "used to compare with the target (10) and replace",
      F.bump_due(_paid_real, 11, 7200, now=9000) is False
      and F.bump_due(_paid_real, 12, 7200, now=9000) is True
      and F.bump_due(dict(_paid_real, fee_sat=None), 11, 7200,
                     now=9000) is True)
# A PLAN RECONSTRUCTED FROM THE CHAIN KNOWS ITS RATE: the fee and vsize off
# the transaction itself. It was never bumped for want of a target, so a
# first forward whose sending run died sat at its rate however far fees rose.
check("bump_due takes a RECONSTRUCTED plan (no target, the fee and vsize "
      "off the chain) by the rate it really pays",
      F.bump_due({"feerate_target_sat_vb": None, "fee_sat": 2850,
                  "vsize": 240, "ts": 1000}, 12, 7200, now=9000) is True
      and F.bump_due({"feerate_target_sat_vb": None, "fee_sat": 2850,
                      "vsize": 240, "ts": 1000}, 11, 7200,
                     now=9000) is False)
_bnd1 = F.btx.vsize_upper_bound(1, [F.INBOUND_SPK_MAX,
                                     F.btx.op_return_script_len(120)])
check("bump_floor never goes under the paid rate plus one, the operator's "
      "floor, or the fee the original paid plus the replacement's size",
      F.bump_floor({"inputs": [{}], "fee_sat": 10 * _bnd1,
                    "feerate_target_sat_vb": 10}, 120, 1) == 11
      and F.bump_floor({"inputs": [{}], "fee_sat": 10 * _bnd1,
                        "feerate_target_sat_vb": 10}, 120, 40) == 40
      and F.bump_floor({"inputs": [{}], "fee_sat": 30 * _bnd1,
                        "feerate_target_sat_vb": 10}, 120, 1) == 31)

# THE WHOLE CHAIN, NOT THE CURRENT PLAN ALONE (stage 6, self-doubt pass).
# A forward left in the mempool falls BEHIND a later plan when money came
# back and was forwarded beside it: the fresh plan is the current one, and
# a reconciliation that read the current plan alone never saw the stuck
# one again. And money that came back while a forward is stuck rides in
# the replacement -- one transaction, one fee -- instead of a second
# forward beside a stuck one.
_H2U = [{"tx_hash": _H2, "vout": 0, "value": 300000, "confirmations": 5}]
_pQ, _ofQ, _hxQ = _first_send()
_age_plan(_ofQ, 4 * 3600)
_nQ = Net(utxos=_H2U, spends=[_listed(_pQ, _hxQ, height=0)], fee=30,
          submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nQ, _ofQ)
check("a stuck forward AND money that came back and settled: ONE "
      "replacement, spending the stuck one's outpoints and the new money "
      "together, quoted for the whole, naming the stuck one; not a "
      "`returned` forward beside it",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "bumped"
      and _p["replaces"] == _pQ["txid"]
      and {(i["tx_hash"], i["vout"]) for i in _p["inputs"]}
      == {(_H1, 0), (_H2, 0)} and _p["settled_sat"] == 500000
      and _p["excluded_outpoints"] == 0 and len(_nQ.submits) == 1
      and ("forward", "stuck_current") in _nQ.kinds
      and ("forward", "returned_settled") not in _nQ.kinds
      and len(F._plan_chain(_ofQ)) == 2
      and "with what settled since" in _o)
_pP, _ofP, _hxP = _first_send()                         # plan 1, 10 sat/vB
_nP1 = Net(utxos=_H2U, spends=[_listed(_pP, _hxP, height=0)], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p2, _ = _reconcile(_nP1, _ofP)
check("(setup) money came back while the first forward sat at today's rate "
      "(not due): forwarded beside it, the first plan rotated behind",
      _c == F.EXIT_OK and _p2["reconcile_reason"] == "returned"
      and _p2["replaces"] is None and len(F._plan_chain(_ofP)) == 2
      and _p2["txid"] != _pP["txid"])
_chainP = F._plan_chain(_ofP)
_age_plan(str(_chainP[1]), 4 * 3600)                    # the rotated plan 1
_hxP2 = _nP1.submits[0]["raw_hex"]
_nP2 = Net(utxos=[], spends=[_listed(_pP, _hxP, height=0),
                             _listed(_p2, _hxP2, height=0,
                                     inputs=[{"tx_hash": _H2, "vout": 0,
                                              "value": 300000}])],
           fee=30, submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p3, _ = _reconcile(_nP2, _ofP)
_txsP = {json.load(open(f)).get("txid") for f in F._plan_chain(_ofP)}
check("...fees rose: the ROTATED first forward, stuck behind the current "
      "plan, is found and replaced -- its own outpoints, the current plan's "
      "consumed ones left out, `replaces` naming it, the kind on the chain; "
      "the chain is three, every plan kept",
      _c == F.EXIT_OK and _p3["reconcile_reason"] == "bumped"
      and _p3["replaces"] == _pP["txid"]
      and [(i["tx_hash"], i["vout"]) for i in _p3["inputs"]] == [(_H1, 0)]
      and _p3["excluded_outpoints"] == 1
      and _p3["fee_sat"] >= _pP["fee_sat"] + _p3["vsize_bound"]
      and ("forward", "stuck_predecessor") in _nP2.kinds
      and len(_nP2.submits) == 1
      and _txsP == {_pP["txid"], _p2["txid"], _p3["txid"]})
# MORE THAN ONE SIGNATURE OVER THE SAME OUTPOINTS ALREADY: a replacement
# the server asked does not list beside the original it does. The next
# replacement is priced to beat EVERY one of them, and the window is
# measured from the newest attempt.
_pV, _ofV, _hxV = _first_send()                          # F at 10
_age_plan(_ofV, 4 * 3600)
_nV1 = Net(utxos=[], spends=[_listed(_pV, _hxV, height=0)], fee=12,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _pV2, _ = _reconcile(_nV1, _ofV)
check("(setup) replaced once at 12", _c == F.EXIT_OK
      and _pV2["replaces"] == _pV["txid"]
      and _pV2["feerate_target_sat_vb"] == 12)
_nV2 = Net(utxos=[], spends=[_listed(_pV, _hxV, height=0)], fee=13,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nV2, _ofV)
check("the server lists the ORIGINAL and not the replacement sent minutes "
      "ago: the window is measured from the newest attempt, so nothing is "
      "replaced again yet (the replacement is recorded as superseded, the "
      "original the record)",
      _c == F.EXIT_OK and _nV2.submits == [] and _nV2.posts == []
      and _p["superseded_by"] == _pV["txid"]
      and ("forward", "reconcile_bumped") not in _nV2.kinds)
_age_plan(_ofV, 4 * 3600)                                # the replacement too
_nV3 = Net(utxos=[], spends=[_listed(_pV, _hxV, height=0)], fee=11,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _pV3, _ = _reconcile(_nV3, _ofV)
check("...both past the window and the estimate above the original's rate: "
      "the original is replaced again at a rate that beats the FIRST "
      "replacement too (13, over an estimate of 11), so a node holding "
      "either takes it; the new plan names the original",
      _c == F.EXIT_OK and _pV3["reconcile_reason"] == "bumped"
      and _pV3["replaces"] == _pV["txid"]
      and _pV3["feerate_target_sat_vb"] == 13
      and _pV3["fee_sat"] >= _pV2["fee_sat"] + _pV3["vsize_bound"]
      and _pV3["fee_sat"] >= _pV["fee_sat"] + _pV3["vsize_bound"]
      and ("forward", "fee_floor_applied") in _nV3.kinds
      and len(F._plan_chain(_ofV)) == 3)
check("(and) a superseded plan records WHERE its superseder is: in the "
      "mempool (0) when it was listed there",
      _p.get("superseded_height") == 0)
_nV4 = Net(utxos=[], spends=[_listed(_pV, _hxV, height=850010)], fee=11,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nV4, _ofV)
check("...the ORIGINAL mined after all: the current plan (the second "
      "replacement) is superseded by it at that height -- so the agent can "
      "say `forwarded` for a forward whose own txid never mines -- and "
      "nothing is bumped or sent",
      _c == F.EXIT_OK and _p["superseded_by"] == _pV["txid"]
      and _p["superseded_height"] == 850010 and _p["txid"] == _pV3["txid"]
      and _nV4.submits == [] and _nV4.posts == []
      and ("forward", "reconcile_bumped") not in _nV4.kinds)
# ...AND WHEN THE NETWORK THEN LISTS THE CURRENT PLAN'S OWN TRANSACTION (a
# lagging server had listed the original; this one mined), the stale mark
# goes: the plan said both "listed" and "superseded by the original", and
# the pairs rewrite counted the original, which never confirms.
_nV5 = Net(utxos=[], spends=[_listed(_pV3, _nV3.submits[0]["raw_hex"],
                                     height=850011)], fee=11,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nV5, _ofV)
check("...a plan marked superseded whose OWN transaction is then listed "
      "sheds the stale mark: the network named it the record",
      _c == F.EXIT_OK and _p["txid"] == _pV3["txid"]
      and _p.get("seen_height") == 850011
      and "superseded_by" not in _p and "superseded_height" not in _p)
# THE REPLACED OUTPOINTS ARE SPENT WHOLE: an input worth spending at the
# original's rate but dust at today's is still spent by the replacement --
# it is committed either way, and the floor was sized over the same count.
_nM0 = Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 200000,
                   "confirmations": 5},
                  {"tx_hash": _H2, "vout": 1, "value": 1500,
                   "confirmations": 5}], fee=10, submit=_ACCEPTED,
           seen=_SEEN0)
_cM, _oM, _pM, _ofM = run(_nM0, broadcast=True)
check("(setup) a first send over two inputs, the small one worth spending "
      "at 10 sat/vB", _cM == F.EXIT_OK and len(_pM["inputs"]) == 2)
_age_plan(_ofM, 4 * 3600)
_nM = Net(utxos=[], spends=[_listed(_pM, _nM0.submits[0]["raw_hex"], height=0,
                                    inputs=[{"tx_hash": _H1, "vout": 0,
                                             "value": 200000},
                                            {"tx_hash": _H2, "vout": 1,
                                             "value": 1500}])],
          fee=30, submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nM, _ofM)
check("the replacement at 30 sat/vB spends BOTH outpoints, the small one "
      "dust at that rate or not, and pays the original's fee plus its own "
      "size; the plan's input records carry no `must` mark",
      _c == F.EXIT_OK and len(_p["inputs"]) == 2
      and _p["replaces"] == _pM["txid"]
      and _p["fee_sat"] >= _pM["fee_sat"] + _p["vsize_bound"]
      and all("must" not in i for i in _p["inputs"]))
check("select_inputs: a `must` output is spent whatever its value, but "
      "never while unsettled (a reorg)",
      F.select_inputs([{"tx_hash": _H1, "vout": 0, "value": 100,
                        "confirmations": 5, "must": True},
                       {"tx_hash": _H2, "vout": 0, "value": 100,
                        "confirmations": 0, "must": True},
                       {"tx_hash": _H2, "vout": 1, "value": 100,
                        "confirmations": 5}], 2, 30)
      == ([{"tx_hash": _H1, "vout": 0, "value": 100, "confirmations": 5,
            "must": True}], 1, 1))
_cS = {"txid": "aa", "feerate_target_sat_vb": 10, "ts": 0,
       "inputs": [{"tx_hash": _H1, "vout": 0}]}
_cR = {"txid": "bb", "feerate_target_sat_vb": 12, "ts": 7000,
       "inputs": [{"tx_hash": _H1, "vout": 0}]}
_cO = {"txid": "cc", "feerate_target_sat_vb": 10, "ts": 0,
       "inputs": [{"tx_hash": _H2, "vout": 0}]}
_spS = [{"txid": "aa", "height": 0, "inputs": [{"tx_hash": _H1, "vout": 0}]}]
check("stuck_forward is pure: listed in the mempool, due -> (it, its "
      "conflicts); the window from the NEWEST conflicting attempt; mined, "
      "not due, no inputs, not listed -> nothing; the current plan first",
      F.stuck_forward([_cS], _spS, {"aa"}, 30, 7200, now=8000) == (_cS, [])
      and F.stuck_forward([_cS, _cR], _spS, {"aa", "bb"}, 30, 7200,
                          now=8000) == (None, [])
      and F.stuck_forward([_cS, _cR], _spS, {"aa", "bb"}, 30, 7200,
                          now=15000) == (_cS, [_cR])
      and F.stuck_forward([_cS], [{**_spS[0], "height": 5}], {"aa"}, 30,
                          7200, now=8000) == (None, [])
      and F.stuck_forward([_cS], _spS, {"aa"}, 10, 7200, now=8000)
      == (None, [])
      and F.stuck_forward([{**_cS, "inputs": []}], _spS, {"aa"}, 30, 7200,
                          now=8000) == (None, [])
      and F.stuck_forward([_cO], _spS, {"aa"}, 30, 7200, now=8000)
      == (None, [])
      and F.stuck_forward([_cO, _cS], _spS + [{"txid": "cc", "height": 0,
                                               "inputs": []}],
                          {"aa", "cc"}, 30, 7200, now=8000) == (_cO, []))
check("replacement_floor beats the stuck plan AND every conflicting one, "
      "each sized over the replacement's own input count",
      F.replacement_floor({"inputs": [{}], "fee_sat": 10 * _bnd1,
                           "feerate_target_sat_vb": 10},
                          [{"inputs": [{}], "fee_sat": 12 * _bnd1,
                            "feerate_target_sat_vb": 12}], 120, 1) == 13
      and F.replacement_floor({"inputs": [{}], "fee_sat": 10 * _bnd1,
                               "feerate_target_sat_vb": 10}, [], 120, 1)
      == 11
      and F.bump_floor({"inputs": [{}, {}], "fee_sat": 10 * _bnd1,
                        "feerate_target_sat_vb": None}, 120, 1, n_inputs=1)
      == 11)

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
# THE SERVERS A SENDING FORWARD LISTENS TO ARE WHO THEY SAY (the review of
# stages 2-6): an unpinned clearnet Electrum server is whatever the Tor
# exit says, and the forward took its fee estimate and its word on "seen".
_cl = run(Net(), "--electrum", "electrum.example.com:50002",
          broadcast=True)
check("a SENDING forward refuses an unpinned clearnet --electrum server "
      "before any look, and a pinned one or an onion is taken",
      _cl[0] == F.EXIT_REFUSED and "bad_args" in _cl[1]
      and F.watch.server_authenticated(("x.onion", 50002, None))
      and F.watch.server_authenticated(("electrum.example.com", 50002,
                                        "ab" * 32))
      and not F.watch.server_authenticated(("electrum.example.com", 50002,
                                            None)))
# THE CROSS-CHECK RESTS ON TLS OR ON AN ONION KEY (the review of stages
# 2-6): a plaintext http:// THORNode was accepted, and then any Tor exit
# could answer for it -- echo the aggregator's own address, mark BTC halted.
_r("bad_args", Net(), "--thornode", "http://thornode.example")
check("...an http:// THORNode that is not an onion is refused before any "
      "look; https:// and http:// to a .onion are the two it can rest on",
      F.watch.thornode_url_ok("https://thornode.example")
      and F.watch.thornode_url_ok("http://abcdefghijklmnop.onion/")
      and not F.watch.thornode_url_ok("http://thornode.example")
      and not F.watch.thornode_url_ok("https://u:p@thornode.example")
      and not F.watch.thornode_url_ok("ftp://thornode.example")
      and not F.watch.thornode_url_ok(""))
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
# ...BEFORE ANYTHING: not in build_and_sign after the look, the quote and a
# derivation from the seed on the variable-time curve.
_nNB = Net()
_c, _o, _p, _ = run(_nNB)
check("without the constant-time backend: refused backend_refused before the "
      "look and the quote -- no address looked at, nothing quoted",
      _c == F.EXIT_REFUSED and ("forward", "refused:backend_refused")
      in _nNB.kinds and _nNB.look_calls == [] and _nNB.posts == [])
check("...while --plan-only (it signs nothing) still runs without it",
      run(Net(), "--plan-only", seed=None)[0] == 0)
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
# MONEY DOES NOT MOVE ON THE AGGREGATOR'S WORD ALONE (STAGE5_PLAN.md 3.5).
_nt = Net(submit=_ACCEPTED, seen=_SEEN0)
check("--broadcast WITHOUT --thornode is refused bad_args before anything is "
      "asked of the network: the cross-check is mandatory where money moves",
      _refusal(_nt, broadcast=True, thornode=False)[3] == "bad_args"
      and _nt.look_calls == [] and _nt.submits == [])
_nt2 = Net()
check("...a rehearsal still runs without one",
      run(_nt2)[0] == 0 and _nt2.gets == [])
# THE ACCOUNT NUMBER (STAGE5_PLAN.md 3.5): the signer derives the account it
# is told and proves it against the xpub, so a wrong number signs for
# nothing; the right number with that account's xpub signs for its address.
_ACCT1 = T.account_from_mnemonic(_MNEMONIC, account=1)
_XPUB1 = _ACCT1.to_public().to_base58()
_ADDR1_0 = F.derive_receive_address(_XPUB1, 0, "main")
_na = Net()
check("GS_BTC_ACCOUNT=1 with account 0's xpub: refused seed_xpub_mismatch, "
      "nothing signed", _refusal(_na, account=1)[3] == "seed_xpub_mismatch")
_code_a, _out_a, _plan_a, _ = run(Net(), account=1, xpub=_XPUB1)
check("...GS_BTC_ACCOUNT=1 with account 1's xpub: the forward signs for "
      "account 1's address 0, proven on the plan",
      _code_a == 0 and _plan_a is not None and _plan_a["address"] == _ADDR1_0
      and _plan_a["signed"] is True)
check("...absent means account 0 (every pair before the field), and a "
      "number that is not one is refused bad_args",
      run(Net())[0] == 0
      and _refusal(Net(), account="x")[3] == "bad_args"
      and _refusal(Net(), account=-1)[3] == "bad_args")

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
# ONE DECLARATION, in gs_btc_tx, for the floor and the fee fraction: the
# vault's deposit floor is built from both (forward_floor_sat), and two
# copies is how the floor and this tool's guards came to disagree
# (STAGE5_PLAN.md section 1, item 7).
check("...and both guards are gs_btc_tx's own objects, not copies",
      F.FORWARD_MIN_SAT is T.FORWARD_MIN_SAT
      and F.MAX_FEE_FRACTION is T.FORWARD_MAX_FEE_FRACTION
      and "FORWARD_MIN_SAT = btx.FORWARD_MIN_SAT" in _src
      and "MAX_FEE_FRACTION = btx.FORWARD_MAX_FEE_FRACTION" in _src)
# A DEPOSIT AT THE FLOOR IS FORWARDABLE AT THE CEILING under every guard
# that does not need a quote: it is not dust at that rate, the fee sized
# against the largest transaction the policy allows is within the cap, and
# what is left clears the dust floor. Both policies the vault can pair.
for _opm, _ceil in ((80, 200), (130, 200), (80, 40), (255, 100000), (1, 1)):
    _fl = T.forward_floor_sat(_opm, _ceil)
    _ch, _du, _un = F.select_inputs([{"tx_hash": "aa" * 32, "vout": 0,
                                      "value": _fl, "confirmations": 6}],
                                    2, _ceil)
    _bound, _fee = F.size_the_fee(1, _opm, _ceil)
    try:
        _send = F.amount_to_send(_fl, _fee, F.FORWARD_MIN_SAT)
        _why = None
    except SystemExit as _e:
        _send, _why = None, getattr(_e, "code", _e)
    check(f"a deposit of exactly the floor ({_fl} sat at policy {_opm}, "
          f"ceiling {_ceil}) is chosen, its fee is within the cap, and it "
          "clears the dust floor",
          len(_ch) == 1 and _du == 0 and _why is None
          and _send == _fl - _fee and _send >= F.FORWARD_MIN_SAT
          and _fee <= _fl * F.MAX_FEE_FRACTION)
    try:
        F.amount_to_send(_fl - 1, _fee, F.FORWARD_MIN_SAT)
        _under = None
    except SystemExit as _e:
        _under = getattr(_e, "code", _e)
    # Refused is a SystemExit whose .code is the exit status; the kind goes
    # to the chain and the terminal. Refused is what matters here; which of
    # the two guards is test_btc_tx's arithmetic check.
    check(f"...and one satoshi under it is REFUSED by one of the two guards "
          f"at that ceiling ({_opm}/{_ceil}) -- the floor is minimal, not "
          "padded", _under == F.EXIT_REFUSED)
_i_main_send = _src.index("bcast_submit(", _src.index("if args.broadcast:\n"))
check("the forwarder names no Electrum method that spends: the broadcast is "
      "reached through gs_btc_broadcast's submit, called in exactly two "
      "places -- inside the --broadcast branch after the real-rate floor, "
      "and inside resend() for bytes this tool itself kept",
      "transaction.broadcast" not in _src and "sendrawtransaction" not in _src
      and _src.count("bcast_submit(") == 2
      and _src.index("rate fell under the floor")
      < _src.index("if args.broadcast:\n") < _i_main_send
      and _src.index("def resend(") < _src.index("bcast_submit(")
      < _src.index("def build_cli("))
# THE ONE FILE A TRANSACTION IS READ FROM TO SEND IT is the plan this tool
# wrote (STAGE5_PLAN.md 3.1): only under --reconcile, only after the
# schema is checked, and only the bytes kept because the network had not
# shown them. No --rebroadcast flag, no other read.
# TWO FILES ARE READ, AND ONE OF THEM CAN HOLD A TRANSACTION: the plan.
# The other is the record of sent txids, and it yields 64-hex strings and
# nothing else (driven above, "a record yields only 64-hex txids").
_jl = [_m.start() for _m in re.finditer(r"json\.load\(", _src)]


def _inside(fn):
    _a = _src.index(f"def {fn}(")
    _b = _src.index("\ndef ", _a + 1)
    return sum(1 for _j in _jl if _a < _j < _b)


check("the forwarder reads a transaction from a file to send it ONLY in "
      "--reconcile, from its own plan (schema checked), the kept bytes; the "
      "one other file it parses is the txid record, inside _read_signed",
      "--rebroadcast" not in _src and len(_jl) == 2
      and _inside("_plan_file") == 1 and _inside("_read_signed") == 1
      and "json.loads(" not in _src
      and 'plan.get("schema") != PLAN_SCHEMA' in _src
      and 'if plan.get("tx_hex"):' in _src
      and _src.index("_read_plan(args.outfile)")
      > _src.index("if args.reconcile:\n        try:"))
check("the seed is never an argument: no --seed, no --mnemonic",
      "--seed" not in _src and "--mnemonic" not in _src
      and "add_argument(\"--seed" not in _src)
check("the tool never opens a file for the seed (environment only)",
      "SEED_FILE" not in _src and "seed_file" not in _src)
check("the stage-1 client it uses still knows no method that could spend",
      "transaction.broadcast" not in code_only(os.path.join(REPO,
                                                            "gs_btc_watch.py")))

print("\n== THIRD SELF-DOUBT PASS: money that comes back AGAIN is kept ==")
# A refund was sent on again at a fresh quote -- right once (a limit the
# price moved past while the forward confirmed), ruinous for ever: ThorChain
# refunds what it will not swap less its outbound fee, the refund settled by
# the next recheck, and the reconciliation forwarded it into the same swap,
# a network fee and an outbound fee per round, a round per recheck, until
# the deposit was gone. Past --returns-max forwards of returned money in the
# chain, the next return is KEPT: written on the plan, done, nothing quoted
# or sent, and the vault's word is `kept`.
_HK3 = "77" * 32
_pK, _ofK, _hxK = _first_send()
_nK1 = Net(utxos=_RET, spends=[_listed(_pK, _hxK)], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nK1, _ofK)
check("(setup) the first return is forwarded: one forward of returned money "
      "in the chain, counted once though the current plan is read twice",
      _c == F.EXIT_OK and len(_nK1.posts) == 1
      and _p["reconcile_reason"] == "returned"
      and F.returned_forwards(
          [_p] + [json.load(open(f)) for f in F._plan_chain(_ofK)]) == 1)
_pK2, _hxK2 = _p, _nK1.submits[0]["raw_hex"]
_LK2 = _listed(_pK2, _hxK2, inputs=[{"tx_hash": _H2, "vout": 0,
                                     "value": 150000}])
_RET2 = [{"tx_hash": _H2, "vout": 1, "value": 140000, "confirmations": 5}]
_nK2 = Net(utxos=_RET2, spends=[_listed(_pK, _hxK), _LK2], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nK2, _ofK)
check("a SECOND return under the default bound (two) is still forwarded",
      _c == F.EXIT_OK and len(_nK2.posts) == 1
      and _p["reconcile_reason"] == "returned"
      and len(F._plan_chain(_ofK)) == 3 and F.DEFAULT_RETURNS_MAX == 2)
_pK3, _hxK3 = _p, _nK2.submits[0]["raw_hex"]
_LK3 = _listed(_pK3, _hxK3, inputs=[{"tx_hash": _H2, "vout": 1,
                                     "value": 140000}])
_RET3 = [{"tx_hash": _HK3, "vout": 0, "value": 130000, "confirmations": 5}]
_nK3 = Net(utxos=_RET3, spends=[_listed(_pK, _hxK), _LK2, _LK3], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nK3, _ofK)
check("a THIRD return is KEPT: done, nothing quoted or sent, the current "
      "plan (the second returned forward, listed) marked returned_kept with "
      "the count and what waits, the kind on the chain, nothing rotated",
      _c == F.EXIT_OK and _nK3.posts == [] and _nK3.submits == []
      and _p is not None and _p["txid"] == _pK3["txid"]
      and _p.get("returned_kept") == {"outputs": 1, "sat": 130000,
                                      "settled": True,
                                      "forwards_of_returned": 2,
                                      "refunds": 0,
                                      "outpoints": [[_HK3, 0]]}
      and ("forward", "returned_kept") in _nK3.kinds
      and ("forward", "returned_settled") not in _nK3.kinds
      and len(F._plan_chain(_ofK)) == 3)
_nK4 = Net(utxos=_RET3, spends=[_listed(_pK, _hxK), _LK2, _LK3], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nK4, _ofK)
check("...asked again (a tap): kept again, the same answer, no wake spent "
      "on a quote", _c == F.EXIT_OK and _nK4.posts == []
      and _nK4.submits == [] and _p.get("returned_kept") is not None
      and len(F._plan_chain(_ofK)) == 3)
_nK5 = Net(utxos=_RET3, spends=[_listed(_pK, _hxK), _LK2, _LK3], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nK5, _ofK, "--returns-max", "3")
check("...re-paired with a higher bound (--returns-max 3) the same ask "
      "forwards it, and the fresh plan carries no kept mark",
      _c == F.EXIT_OK and len(_nK5.posts) == 1
      and _p["reconcile_reason"] == "returned"
      and "returned_kept" not in _p and len(F._plan_chain(_ofK)) == 4)
_pU, _ofU, _hxU = _first_send()
_nU = Net(utxos=[{"tx_hash": _H2, "vout": 0, "value": 150000,
                  "confirmations": 0}], spends=[_listed(_pU, _hxU)])
_c, _o, _p, _ = _reconcile(_nU, _ofU, "--returns-max", "0")
check("--returns-max 0: even the FIRST return is kept, settled or not -- "
      "done, and NO `returned` status word (the Pi would watch the address "
      "and start the forward when it settled); the mark says unsettled",
      _c == F.EXIT_OK and _status_of(_ofU) is None and _nU.posts == []
      and (_p.get("returned_kept") or {}).get("settled") is False
      and (_p.get("returned_kept") or {}).get("sat") == 150000
      and ("forward", "returned_kept") in _nU.kinds
      and ("forward", "refused:returned_unsettled") not in _nU.kinds)
check("returned_forwards counts forwards of returned money once per txid, "
      "whatever the case, and nothing else",
      F.returned_forwards([
          {"reconcile_reason": "returned", "txid": "AA" * 32},
          {"reconcile_reason": "returned", "txid": "aa" * 32},
          {"reconcile_reason": "returned", "txid": "bb" * 32},
          {"reconcile_reason": "bumped", "txid": "cc" * 32},
          {"reconcile_reason": "evicted"}, "junk", None, 7,
          {"reconcile_reason": "returned"}]) == 3
      and F.returned_forwards([]) == 0 and F.returned_forwards(None) == 0)
check("a negative --returns-max is refused before anything runs",
      _refusal(Net(), "--reconcile", *_TN, "--returns-max", "-1",
               dry_run=False, outfile=_ofK)[3] == "bad_args")

print("\n== THIRD SELF-DOUBT PASS: a refund is told from a second payment ==")
# The memo ThorChain puts on a refund is a public convention anyone can
# write into a transaction of their own to the address, and the amount can
# be matched; only the SOURCE cannot be forged -- nobody but ThorChain's
# signers spend from ThorChain's vault. A refund is verified by its source
# alone; a claim is recorded as one and nothing rests on it.
_HRF = "88" * 32
# A valid mainnet address that is NOT the inbound the fixtures pay.
_OTHER_ADDR = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"


def _paid(txid, value, memo, src, vout=0):
    return {"txid": txid, "height": 850003, "vout": vout, "value": value,
            "memo": memo, "from_address": src}


_pR, _ofR, _hxR = _first_send()
check("(setup) the first forward sent more than the return below carries",
      int(_pR["send_sat"]) > 150000 and _pR["inbound"] == _INBOUND)
_RF = [{"tx_hash": _HRF, "vout": 0, "value": 150000, "confirmations": 5}]
_nR1 = Net(utxos=_RF, spends=[_listed(_pR, _hxR)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0,
           funding=[_paid(_HRF, 150000, "REFUND:" + _pR["txid"].upper(),
                          _INBOUND)])
_c, _o, _p, _ = _reconcile(_nR1, _ofR)
_oldR = json.load(open(F._plan_chain(_ofR)[1]))
check("a CONFIRMED return whose memo names our forward, carrying LESS than "
      "it sent but within the fee slack, from the vault that forward PAID: "
      "a VERIFIED, FULL refund -- recorded on the plan (which the chain "
      "keeps when it is rotated aside), the kind on the chain, NO live "
      "lookup (one THORNode ask: the fresh forward's own cross-check), and "
      "forwarded again like any first return",
      _c == F.EXIT_OK and len(_nR1.posts) == 1
      and _p["reconcile_reason"] == "returned"
      and _oldR.get("refunds") == [{"txid": _HRF, "vout": 0, "value": 150000,
                                    "of": _pR["txid"].lower(),
                                    "verified": True, "full": True,
                                    "outbound_fee_sat": None}]
      and ("forward", "refund_seen") in _nR1.kinds
      and sum("inbound_addresses" in u for u, _ in _nR1.gets) == 1)
_pU2, _ofU2, _hxU2 = _first_send()
_nR2 = Net(utxos=_RF, spends=[_listed(_pU2, _hxU2)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0,
           funding=[_paid(_HRF, 150000, "refund:" + _pU2["txid"],
                          _OTHER_ADDR)])
_c, _o, _p, _ = _reconcile(_nR2, _ofU2)
_oldU2 = json.load(open(F._plan_chain(_ofU2)[1]))
check("the same memo (any case) from an address that is NOT a vault this "
      "run knows: a CLAIM -- recorded as unverified, its own kind, and "
      "otherwise handled as a payment",
      _c == F.EXIT_OK and len(_nR2.posts) == 1
      and (_oldU2.get("refunds") or [{}])[0].get("verified") is False
      and ("forward", "refund_claimed") in _nR2.kinds
      and ("forward", "refund_seen") not in _nR2.kinds)
_pV, _ofV, _hxV = _first_send()
_nR3 = Net(utxos=_RF, spends=[_listed(_pV, _hxV)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0, inbound=_OTHER_ADDR,
           funding=[_paid(_HRF, 150000, "REFUND:" + _pV["txid"].upper(),
                          _OTHER_ADDR)])
_c, _o, _p, _ = _reconcile(_nR3, _ofV)
check("...a source that is only THORNode's CURRENT inbound (a vault no "
      "forward of ours paid) stays a CLAIM: one party's word at reconcile "
      "time verifies nothing, so a lying node cannot make an attacker's "
      "dust lower what the client is told to expect",
      _c == F.EXIT_OK
      and (json.load(open(F._plan_chain(_ofV)[1])).get("refunds")
           or [{}])[0].get("verified") is False
      and ("forward", "refund_claimed") in _nR3.kinds)
_pW, _ofW, _hxW = _first_send()
_nRW = Net(utxos=_RF, spends=[_listed(_pW, _hxW)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0,
           funding=[{**_paid(_HRF, 150000, "REFUND:" + _pW["txid"].upper(),
                             _OTHER_ADDR),
                     "from_addresses": [_OTHER_ADDR, _INBOUND]}])
_c, _o, _p, _ = _reconcile(_nRW, _ofW)
check("...ANY input from a vault a forward of ours paid verifies it (a "
      "ThorChain outbound consolidates several vault outputs; one is "
      "proof, since only its signers spend from it)",
      _c == F.EXIT_OK
      and (json.load(open(F._plan_chain(_ofW)[1])).get("refunds")
           or [{}])[0].get("verified") is True)
_pP, _ofP, _hxP = _first_send()
_RP = [{"tx_hash": _HRF, "vout": 0, "value": 40000, "confirmations": 5}]
_nRP = Net(utxos=_RP, spends=[_listed(_pP, _hxP)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0,
           funding=[_paid(_HRF, 40000, "REFUND:" + _pP["txid"].upper(),
                          _INBOUND)])
_c, _o, _p, _ = _reconcile(_nRP, _ofP)
check("a verified refund carrying much LESS than what was sent, past the "
      "fee slack (a streaming swap that filled part of the way), is a "
      "refund IN PART: recorded verified but not full -- it must not read "
      "as 'the swap never happened'",
      _c == F.EXIT_OK
      and (json.load(open(F._plan_chain(_ofP)[1])).get("refunds")
           or [{}])[0].get("verified") is True
      and (json.load(open(F._plan_chain(_ofP)[1])).get("refunds")
           or [{}])[0].get("full") is False)
_pM, _ofM, _hxM = _first_send()
_nRM = Net(utxos=_RF, spends=[_listed(_pM, _hxM)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0,
           funding=[{**_paid(_HRF, 150000, "REFUND:" + _pM["txid"].upper(),
                             _INBOUND), "height": 0}])
_c, _o, _p, _ = _reconcile(_nRM, _ofM)
check("a claimed refund still in the MEMPOOL decides nothing: not recorded "
      "until it is in a block (a record that only ever upgrades must not "
      "be written from a transaction that can still vanish)",
      _c == F.EXIT_OK
      and "refunds" not in json.load(open(F._plan_chain(_ofM)[1]))
      and ("forward", "refund_seen") not in _nRM.kinds)
for _why, _fund in (
        ("a memo naming a forward that is not ours",
         _paid(_HRF, 150000, "REFUND:" + "ab" * 32, _INBOUND)),
        ("a memo naming ours but carrying MORE than it sent (a refund is "
         "the inbound less a fee, never more)",
         _paid(_HRF, 150000, "REFUND:{TXID}", _INBOUND)),
        ("no memo at all (a second payment)",
         _paid(_HRF, 150000, None, None)),
        ("an OUT memo (a swap output, not a refund)",
         _paid(_HRF, 150000, "OUT:{TXID}", _INBOUND))):
    _pX, _ofX, _hxX = _first_send()
    _fx = dict(_fund)
    if _fx["memo"] and "{TXID}" in _fx["memo"]:
        _fx["memo"] = _fx["memo"].replace("{TXID}", _pX["txid"].upper())
    _ux = [{"tx_hash": _HRF, "vout": 0,
            "value": 150000 if "MORE" not in _why else int(_pX["send_sat"]),
            "confirmations": 5}]
    if "MORE" in _why:
        _fx["value"] = int(_pX["send_sat"])
    _nX = Net(utxos=_ux, spends=[_listed(_pX, _hxX)], fee=10,
              submit=_ACCEPTED, seen=_SEEN0, funding=[_fx])
    _c, _o, _p, _ = _reconcile(_nX, _ofX)
    check(f"{_why}: not a refund -- nothing recorded, no THORNode ask for "
          "it, forwarded as a payment",
          _c == F.EXIT_OK and len(_nX.posts) == 1
          and "refunds" not in json.load(open(F._plan_chain(_ofX)[1]))
          and ("forward", "refund_seen") not in _nX.kinds
          and ("forward", "refund_claimed") not in _nX.kinds
          and sum("inbound_addresses" in u for u, _ in _nX.gets) == 1)
_pKR, _ofKR, _hxKR = _first_send()
_nKR = Net(utxos=_RF, spends=[_listed(_pKR, _hxKR)], fee=10,
           funding=[_paid(_HRF, 150000, "REFUND:" + _pKR["txid"].upper(),
                          _INBOUND)])
_c, _o, _p, _ = _reconcile(_nKR, _ofKR, "--returns-max", "0")
check("a return kept (--returns-max) says how many of its outputs are "
      "verified refunds, and the refund is on the same plan",
      _c == F.EXIT_OK and (_p.get("returned_kept") or {}).get("refunds") == 1
      and (_p.get("refunds") or [{}])[0].get("verified") is True)
_nL = Net(utxos=[], spends=[_listed(_pKR, _hxKR)]).install()
F.bcast_spends = lambda *a, **k: [_listed(_pKR, _hxKR)]
_c, _o, _p, _ = run(_nL, "--reconcile", *_TN, dry_run=False, outfile=_ofKR)
check("a spends reader of the stage-5 shape (a list, no funding) is taken "
      "as knowing of no memo: the reconciliation still runs, nothing "
      "recorded", _c == F.EXIT_OK and _p is not None)
check("classify_returns is pure and tolerant: junk entries, a memo in any "
      "case, a plan without send_sat, a source in any case, an unconfirmed "
      "output skipped; verified by ANY input from the inbound of ANY plan "
      "in the chain (each cross-checked when its forward was built), "
      "never by a live lookup; full within the slack",
      F.classify_returns(
          ["junk", None, {"memo": 7},
           {"txid": "AA" * 32, "vout": 1, "value": 4, "height": 7,
            "memo": "Refund:" + "BB" * 32,
            "from_address": _INBOUND.upper()},
           {"txid": "cc" * 32, "vout": 0, "value": 4, "height": 7,
            "memo": "REFUND:" + "bb" * 32,
            "from_addresses": [_OTHER_ADDR, _OTHER_ADDR.upper()]},
           {"txid": "dd" * 32, "vout": 0, "value": 4, "height": 7,
            "memo": "REFUND:" + "ee" * 32, "from_address": _INBOUND},
           {"txid": "ee" * 32, "vout": 2, "value": 4, "height": 7,
            "memo": "REFUND:" + "BB" * 32 + ":something-later",
            "from_addresses": [_OTHER_ADDR, _INBOUND]},
           {"txid": "ff" * 32, "vout": 0, "value": 5, "height": 0,
            "memo": "REFUND:" + "BB" * 32, "from_address": _INBOUND},
           {"txid": "11" * 32, "vout": 0, "value": 4900000, "height": 9,
            "memo": "REFUND:" + "99" * 32, "from_address": _OTHER_ADDR}],
          [{"txid": "bb" * 32, "send_sat": 10, "inbound": _INBOUND},
           {"txid": "ee" * 32, "inbound": _INBOUND},
           {"txid": "99" * 32, "send_sat": 5000000, "inbound": _OTHER_ADDR},
           "junk"])
      == [{"txid": "aa" * 32, "vout": 1, "value": 4, "of": "bb" * 32,
           "verified": True, "full": False, "outbound_fee_sat": None},
          {"txid": "cc" * 32, "vout": 0, "value": 4, "of": "bb" * 32,
           "verified": True, "full": False, "outbound_fee_sat": None},
          {"txid": "ee" * 32, "vout": 2, "value": 4, "of": "bb" * 32,
           "verified": True, "full": False, "outbound_fee_sat": None},
          {"txid": "11" * 32, "vout": 0, "value": 4900000, "of": "99" * 32,
           "verified": True, "full": True, "outbound_fee_sat": None}]
      and F.classify_returns([], []) == [] and F.classify_returns(None, None) == [])
check("the refund slack is the larger of a twentieth and a fixed floor: a "
      "5 BTC forward refunded 0.05 short is full, 0.26 short is not; a "
      "0.001 BTC forward refunded as 1 sat is not",
      F.classify_returns(
          [{"txid": "11" * 32, "vout": 0, "value": 495000000, "height": 9,
            "memo": "REFUND:" + "99" * 32, "from_address": _INBOUND},
           {"txid": "22" * 32, "vout": 0, "value": 474000000, "height": 9,
            "memo": "REFUND:" + "99" * 32, "from_address": _INBOUND},
           {"txid": "33" * 32, "vout": 0, "value": 1, "height": 9,
            "memo": "REFUND:" + "88" * 32, "from_address": _INBOUND}],
          [{"txid": "99" * 32, "send_sat": 500000000, "inbound": _INBOUND},
           {"txid": "88" * 32, "send_sat": 100000, "inbound": _INBOUND}])
      == [{"txid": "11" * 32, "vout": 0, "value": 495000000, "of": "99" * 32,
           "verified": True, "full": True, "outbound_fee_sat": None},
          {"txid": "22" * 32, "vout": 0, "value": 474000000, "of": "99" * 32,
           "verified": True, "full": False, "outbound_fee_sat": None},
          {"txid": "33" * 32, "vout": 0, "value": 1, "of": "88" * 32,
           "verified": True, "full": False, "outbound_fee_sat": None}]
      and F.REFUND_FEE_SLACK_SAT == 100000
      and not hasattr(F, "thor_inbound_address"))
check("the forwarder's memo reader IS gs_btc_tx's (one reader for what it "
      "writes, what it recognises as its own, and what it reads back)",
      F._op_return_data is F.btx.op_return_data)
# THE OUTBOUND FEE RIDES ON THE PLAN AND THE REFUND RECORD (self-doubt over
# the partial-refund fix). ThorChain takes its outbound fee from the
# unfilled part before refunding it, so a refund alone reads the fill a
# fee's worth too high -- the whole arrival tolerance of a small forward.
_fee_node = [{"chain": "BTC", "address": _INBOUND, "halted": False,
              "dust_threshold": "10000", "outbound_fee": "30000"}]
check("with --thornode the plan records THORNode's outbound fee for BTC, "
      "in sat; without the field, or without a node, None",
      run(Net(thornode=_fee_node), "--thornode", "https://t")[2]
      ["outbound_fee_sat"] == 30000
      and run(Net(thornode=_ok_node), "--thornode", "https://t")[2]
      ["outbound_fee_sat"] is None
      and run(Net())[2]["outbound_fee_sat"] is None)
check("...junk or a negative fee is None, and a fee over the refund slack is "
      "CAPPED at it (a lying node lowers what a client is told to expect by "
      "no more than a FULL refund already rests on)",
      run(Net(thornode=[{**_fee_node[0], "outbound_fee": "abc"}]),
          "--thornode", "https://t")[2]["outbound_fee_sat"] is None
      and run(Net(thornode=[{**_fee_node[0], "outbound_fee": "-5"}]),
              "--thornode", "https://t")[2]["outbound_fee_sat"] is None
      and run(Net(thornode=[{**_fee_node[0], "outbound_fee": "9999999"}]),
              "--thornode", "https://t")[2]["outbound_fee_sat"] == 100000
      and F.REFUND_FEE_SLACK_SAT == F.btx.REFUND_FEE_SLACK_SAT == 100000)
check("a refund of a plan that carries the fee records it, and FULL is judged "
      "on the refund PLUS the fee: 0.003 BTC sent, 0.00195 back with a "
      "0.0003 fee is the whole swap undone (0.00225 >= 0.002); the same "
      "refund of a plan without the fee is not",
      F.classify_returns(
          [{"txid": "11" * 32, "vout": 0, "value": 195000, "height": 9,
            "memo": "REFUND:" + "99" * 32, "from_address": _INBOUND},
           {"txid": "22" * 32, "vout": 0, "value": 195000, "height": 9,
            "memo": "REFUND:" + "88" * 32, "from_address": _INBOUND}],
          [{"txid": "99" * 32, "send_sat": 300000, "inbound": _INBOUND,
            "outbound_fee_sat": 30000},
           {"txid": "88" * 32, "send_sat": 300000, "inbound": _INBOUND}])
      == [{"txid": "11" * 32, "vout": 0, "value": 195000, "of": "99" * 32,
           "verified": True, "full": True, "outbound_fee_sat": 30000},
          {"txid": "22" * 32, "vout": 0, "value": 195000, "of": "88" * 32,
           "verified": True, "full": False, "outbound_fee_sat": None}]
      and F.classify_returns(
          [{"txid": "11" * 32, "vout": 0, "value": 195000, "height": 9,
            "memo": "REFUND:" + "99" * 32, "from_address": _INBOUND}],
          [{"txid": "99" * 32, "send_sat": 300000, "inbound": _INBOUND,
            "outbound_fee_sat": "30000"}])[0]["outbound_fee_sat"] is None
      and F.btx.refund_is_full(200000, 300000) is True
      and F.btx.refund_is_full(199999, 300000) is False
      and F.btx.refund_is_full(1, 100000) is False
      and F.btx.refund_is_full(50000, 100000) is True
      and F.btx.refund_is_full("x", 100000) is False
      and F.btx.refund_is_full(True, 100000) is False
      and F.btx.refund_is_full(5, 0) is False)
# ...AND A RECORD FROM BEFORE THE FIELD LEARNS IT when the same output is
# classified again with the fee known (the merge upgrades, never lowers).
_pF, _ofF, _hxF = _first_send()
_plF = json.load(open(_ofF))
_plF["refunds"] = [{"txid": _HRF, "vout": 0, "value": 40000,
                    "of": _pF["txid"], "verified": True, "full": False}]
_plF["outbound_fee_sat"] = 30000
with open(_ofF, "w") as _fh:
    json.dump(_plF, _fh)
_nF = Net(utxos=[{"tx_hash": _HRF, "vout": 0, "value": 40000,
                  "confirmations": 5}],
          spends=[_listed(_pF, _hxF)], fee=10, submit=_ACCEPTED, seen=_SEEN0,
          funding=[_paid(_HRF, 40000, "REFUND:" + _pF["txid"], _INBOUND)])
_c, _o, _p, _ = _reconcile(_nF, _ofF)
_recF = [r for q in [_p] + [json.load(open(f)) for f in F._plan_chain(_ofF)]
         for r in (q.get("refunds") or []) if r.get("txid") == _HRF]
check("a refund record written before the fee field carries the fee once "
      "the same output is classified again on a plan that knows it",
      _c == F.EXIT_OK and _recF
      and all(r.get("outbound_fee_sat") == 30000 for r in _recF))

print("\n== THE BOUND HOLDS ON EVERY PATH (after the review of the third pass) ==")
# The evicted re-sign and the rejected re-send's fresh forward used to
# leave the kept money in: their exclusion was the listed forwards' inputs
# alone, and the kept outputs are not those. And a bump or a re-sign that
# carried returned money was never counted, so the bound could be over-run
# by rounds it never saw.


def _two_returns(seen2=_SEEN0):
    """A chain at the bound: a first forward, then two forwards of money
    that came back. Returns (first plan, its hex, chain listings, the
    current plan, its hex)."""
    p1, of, hx1 = _first_send()
    n1 = Net(utxos=_RET, spends=[_listed(p1, hx1)], fee=10, submit=_ACCEPTED,
             seen=_SEEN0)
    _c, _o, p2, _ = _reconcile(n1, of)
    assert _c == F.EXIT_OK, _o
    hx2 = n1.submits[0]["raw_hex"]
    l2 = _listed(p2, hx2, inputs=[{"tx_hash": _H2, "vout": 0,
                                   "value": 150000}])
    n2 = Net(utxos=_RET2, spends=[_listed(p1, hx1), l2], fee=10,
             submit=_ACCEPTED, seen=seen2)
    _c, _o, p3, _ = _reconcile(n2, of)
    assert _c == F.EXIT_OK, _o
    hx3 = n2.submits[0]["raw_hex"]
    return of, [_listed(p1, hx1), l2], p3, hx3


_ofE, _lE, _pE3, _hxE3 = _two_returns()
_UNSPENT_E = [{"tx_hash": _H2, "vout": 1, "value": 140000, "confirmations": 5}]
_nE = Net(utxos=_UNSPENT_E + _RET3, spends=_lE, fee=10, submit=_ACCEPTED,
          seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nE, _ofE)
check("AT THE BOUND, the current forward evicted (not listed, its input "
      "unspent again, no bytes kept) beside a return that came back: the "
      "re-sign spends ITS OWN input only, the returned output is left out "
      "(excluded with the listed forwards' inputs), and it carried nothing "
      "that came back",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "evicted"
      and [(i["tx_hash"], i["vout"]) for i in _p["inputs"]] == [(_H2, 1)]
      and _p["excluded_outpoints"] == 3 and _p["carried_returned"] == 0
      and ("forward", "evicted") in _nE.kinds)
_ofR, _lR, _pR3, _hxR3 = _two_returns(seen2=_NOT_SEEN)
check("(setup) the current forward at the bound kept its bytes (unseen)",
      _pR3["tx_hex"] == _hxR3)
_nRj = Net(utxos=_UNSPENT_E + _RET3, spends=_lR, fee=10,
           submit=[_REJECTED, _ACCEPTED], seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nRj, _ofR)
check("...and when the kept bytes are RE-SENT and every server rejects "
      "them, the fresh forward that follows leaves the returned output out "
      "too (the reconciliation handed the exclusion over with the bytes)",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "rejected"
      and _nRj.submits[0]["raw_hex"] == _hxR3
      and [(i["tx_hash"], i["vout"]) for i in _p["inputs"]] == [(_H2, 1)]
      # 3, as the evicted branch's above: the returned output AND the two
      # outpoints our listed forwards spend. It was 1 -- the returned
      # output alone -- which is the NEVER TWICE gap pinned just below.
      and _p["excluded_outpoints"] == 3 and _p["carried_returned"] == 0)
# NEVER TWICE, ON THE REJECTED RE-SEND AS WELL. The look and the history
# fail over per call, so they can come from different servers: the look's
# has not got our listed forward X in its mempool and shows X's input as
# unspent. The evicted branch excluded every outpoint a listed forward of
# ours spends; the rejected re-send's fresh forward excluded only the kept
# money, and signed over X's input a second time.
_HX = "ef" * 32
_pX, _ofX, _hxX = _first_send(seen=_NOT_SEEN)
check("(setup) the current forward kept its bytes (unseen)",
      bool(_pX["tx_hex"]))
_X = dict(_pX, txid="99" * 32, tx_hex=None,
          inputs=[{"tx_hash": _HX, "vout": 0, "value": 150000,
                   "confirmations": 5}])
json.dump(_X, open(_ofX[:-5] + ".1.json", "w"))
_nX = Net(utxos=[{"tx_hash": _H1, "vout": 0, "value": 200000,
                  "confirmations": 5},
                 {"tx_hash": _HX, "vout": 0, "value": 150000,
                  "confirmations": 5}],
          spends=[{"txid": _X["txid"], "height": 0, "hex": _hxX,
                   "inputs": [{"tx_hash": _HX, "vout": 0, "value": 150000}],
                   "server": "s.onion"}],
          fee=10, submit=[_REJECTED, _ACCEPTED], seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nX, _ofX)
check("a rejected re-send's fresh forward does NOT sign again over an "
      "outpoint a LISTED forward of ours already spends, though the look "
      "(another server) shows it unspent -- the same exclusion the evicted "
      "branch makes",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "rejected"
      and [(i["tx_hash"], i["vout"]) for i in _p["inputs"]] == [(_H1, 0)])
# UNDER the bound, a re-sign that carries returned money is COUNTED.
_pC1, _ofC, _hxC1 = _first_send()
_nC1 = Net(utxos=_RET, spends=[_listed(_pC1, _hxC1)], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _pC2, _ = _reconcile(_nC1, _ofC)
check("(setup) one forward of returned money in the chain",
      _c == F.EXIT_OK and _pC2["reconcile_reason"] == "returned")
_nC2 = Net(utxos=[{"tx_hash": _H2, "vout": 0, "value": 150000,
                   "confirmations": 5}] + _RET2,
           spends=[_listed(_pC1, _hxC1)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _pC3, _ = _reconcile(_nC2, _ofC)
_chainC = [json.load(open(f)) for f in F._plan_chain(_ofC)]
check("under the bound, the evicted re-sign carries the returned output "
      "beside its own input, records how many inputs came back "
      "(carried_returned), and the bound counts it as a forward of returned "
      "money: two now, so the next return is kept",
      _c == F.EXIT_OK and _pC3["reconcile_reason"] == "evicted"
      and sorted((i["tx_hash"], i["vout"]) for i in _pC3["inputs"])
      == [(_H2, 0), (_H2, 1)]
      and _pC3["carried_returned"] == 1
      and F.returned_forwards(_chainC) == 2)
_hxC3 = _nC2.submits[0]["raw_hex"]
_nC3 = Net(utxos=_RET3, spends=[_listed(_pC1, _hxC1),
                                _listed(_pC3, _hxC3, inputs=[
                                    {"tx_hash": _H2, "vout": 0,
                                     "value": 150000},
                                    {"tx_hash": _H2, "vout": 1,
                                     "value": 140000}])],
           fee=10, submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nC3, _ofC)
check("...kept indeed", _c == F.EXIT_OK and _nC3.posts == []
      and (_p.get("returned_kept") or {}).get("forwards_of_returned") == 2)
check("_carried_returned / returned_forwards: a plan with reason "
      "'returned', or any reason with carried_returned above zero, counts; "
      "zero, None, a bool or junk does not",
      F.returned_forwards([
          {"reconcile_reason": "bumped", "txid": "a" * 64, "carried_returned": 1},
          {"reconcile_reason": "evicted", "txid": "b" * 64, "carried_returned": 0},
          {"reconcile_reason": "rejected", "txid": "c" * 64,
           "carried_returned": None},
          {"reconcile_reason": "bumped", "txid": "d" * 64, "carried_returned": True},
          {"reconcile_reason": "returned", "txid": "e" * 64},
          {"reconcile_reason": None, "txid": "f" * 64, "carried_returned": "2"}])
      == 2)

print("\n== MED PASS: the bound counts ROUNDS of returned money, not honest "
      "top-ups ==")
# The bound counted every return: a client who paid a deposit in three
# instalments had the third KEPT on the address for the operator's hand, as
# if a route were refunding. A round is a VERIFIED refund, or an output the
# SIZE of a refund of some forward on the chain (round_outpoints: less than
# it sent, within refund_is_full's slack); a payment that is neither is
# forwarded and counts for nothing. Nothing a refund has is certain to be
# there -- the memo's shape is ThorChain's, and after a churn the refunding
# vault is one no forward of ours paid -- so a round is counted by its
# source when that verifies and by its amount otherwise; a top-up the size
# of a forward still counts, the cheap direction.
_HT1, _HT2, _HT3 = "a1" * 32, "a2" * 32, "a3" * 32
check("round_outpoints: a verified refund of any size, and an output less "
      "than a forward sent and within refund_is_full's slack of it; not "
      "one larger, not one under half, not a claim by itself; junk (a bool "
      "value, a junk vout, a plan without send_sat) counts for nothing",
      F.round_outpoints(
          [{"tx_hash": _HT1, "vout": 0, "value": 40000},
           {"tx_hash": _HT1, "vout": 1, "value": 150000},
           {"tx_hash": _HT2, "vout": 0, "value": 500000},
           {"tx_hash": _HT2, "vout": 1, "value": 50000},
           {"tx_hash": _HT3.upper(), "vout": 0, "value": 150000, "x": 1},
           {"tx_hash": _HT3, "vout": "j", "value": 1}, "junk", None,
           {"tx_hash": _HT3, "vout": 2, "value": True}],
          [{"txid": _HT1, "vout": 0, "verified": True},
           {"txid": _HT2, "vout": 1, "verified": False}, "junk",
           {"txid": _HT3, "vout": 1, "verified": 1}, {"vout": "x"}],
          [{"send_sat": 190000}, {"send_sat": 0}, {"send_sat": True},
           "junk", None, {}])
      == {(_HT1, 0), (_HT1, 1), (_HT3, 0)}
      and F.round_outpoints(None, None, None) == set()
      and F.round_outpoints([{"tx_hash": _HT1, "vout": 0, "value": 190000}],
                            [], [{"send_sat": 190000}]) == set())
_pT, _ofT, _hxT = _first_send()
_TOP1 = [{"tx_hash": _HT1, "vout": 0, "value": 500000, "confirmations": 5}]
_nT1 = Net(utxos=_TOP1, spends=[_listed(_pT, _hxT)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _pT2, _ = _reconcile(_nT1, _ofT)
check("a second payment LARGER than the forward (a top-up, no memo) is "
      "forwarded as returned money and is NOT a round: the plan says so "
      "(carried_refunds 0) and the bound counts nothing",
      _c == F.EXIT_OK and len(_nT1.posts) == 1
      and _pT2["reconcile_reason"] == "returned"
      and _pT2["carried_refunds"] == 0 and _pT2["carried_returned"] is None
      and F.returned_forwards(
          [_pT2] + [json.load(open(f)) for f in F._plan_chain(_ofT)]) == 0)
_hxT2 = _nT1.submits[0]["raw_hex"]
_LT2 = _listed(_pT2, _hxT2, inputs=[{"tx_hash": _HT1, "vout": 0,
                                     "value": 500000}])
_TOP2 = [{"tx_hash": _HT2, "vout": 0, "value": 600000, "confirmations": 5}]
_nT2 = Net(utxos=_TOP2, spends=[_listed(_pT, _hxT), _LT2], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _pT3, _ = _reconcile(_nT2, _ofT)
_hxT3 = _nT2.submits[0]["raw_hex"]
_LT3 = _listed(_pT3, _hxT3, inputs=[{"tx_hash": _HT2, "vout": 0,
                                     "value": 600000}])
_TOP3 = [{"tx_hash": _HT3, "vout": 0, "value": 700000, "confirmations": 5}]
_nT3 = Net(utxos=_TOP3, spends=[_listed(_pT, _hxT), _LT2, _LT3], fee=10,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _pT4, _ = _reconcile(_nT3, _ofT)
check("...a SECOND and a THIRD top-up are forwarded too, under the default "
      "bound of two: three `returned` forwards on the chain and not one "
      "round among them -- the third used to be KEPT for the operator's "
      "hand",
      _c == F.EXIT_OK and len(_nT3.posts) == 1
      and _pT4["reconcile_reason"] == "returned"
      and "returned_kept" not in _pT4
      and _pT3["carried_refunds"] == 0 and _pT4["carried_refunds"] == 0
      and len(F._plan_chain(_ofT)) == 4
      and F.returned_forwards(
          [json.load(open(f)) for f in F._plan_chain(_ofT)]) == 0
      and ("forward", "returned_kept") not in _nT3.kinds
      and ("forward", "returned_settled") in _nT3.kinds)
check("...and the evicted re-sign above, which carried an output the size "
      "of a refund, records it as a round beside the older count",
      _pC3["carried_refunds"] == 1 and _pC3["carried_returned"] == 1)
_pQ, _ofQ, _hxQ = _first_send()
_RQ = [{"tx_hash": _HRF, "vout": 0, "value": 40000, "confirmations": 5}]
_nQ = Net(utxos=_RQ, spends=[_listed(_pQ, _hxQ)], fee=10, submit=_ACCEPTED,
          seen=_SEEN0,
          funding=[_paid(_HRF, 40000, "REFUND:" + _pQ["txid"].upper(),
                         _INBOUND)])
_c, _o, _pQ2, _ = _reconcile(_nQ, _ofQ)
check("a VERIFIED refund far under the size of one (a streaming swap that "
      "filled part of the way) is a round by its source: carried_refunds "
      "1, and the bound counts it",
      _c == F.EXIT_OK and _pQ2["reconcile_reason"] == "returned"
      and _pQ2["carried_refunds"] == 1
      and F.returned_forwards(
          [json.load(open(f)) for f in F._plan_chain(_ofQ)]) == 1)
_pQc, _ofQc, _hxQc = _first_send()
_nQc = Net(utxos=_RQ, spends=[_listed(_pQc, _hxQc)], fee=10,
           submit=_ACCEPTED, seen=_SEEN0,
           funding=[_paid(_HRF, 40000, "REFUND:" + _pQc["txid"].upper(),
                          _OTHER_ADDR)])
_c, _o, _pQc2, _ = _reconcile(_nQc, _ofQc)
check("...the same amount with the same memo from an address no forward of "
      "ours paid is a CLAIM, and a claim of that size is not a round: "
      "nothing rests on it",
      _c == F.EXIT_OK and _pQc2["carried_refunds"] == 0
      and F.returned_forwards(
          [json.load(open(f)) for f in F._plan_chain(_ofQc)]) == 0)
check("_carried_returned: a plan with carried_refunds counts by it alone "
      "(zero is no round, whatever its reason or carried_returned); a "
      "bool or None there falls back to the older rule",
      F.returned_forwards([
          {"reconcile_reason": "returned", "txid": "1" * 64,
           "carried_refunds": 0, "carried_returned": 3},
          {"reconcile_reason": "evicted", "txid": "2" * 64,
           "carried_refunds": 1, "carried_returned": 0},
          {"reconcile_reason": "returned", "txid": "3" * 64,
           "carried_refunds": True},
          {"reconcile_reason": "bumped", "txid": "4" * 64,
           "carried_refunds": None, "carried_returned": 2},
          {"reconcile_reason": None, "txid": "5" * 64,
           "carried_refunds": None}]) == 3)

print("\n== MED PASS: a flooded history is read as its newest entries ==")
# The reader refused a history over its window outright, so anyone who could
# read the address (it is in the chat) could jam every reconciliation of a
# deposit for good with a flood of dust. It now reads the newest window and
# says so through on_truncated; the forwarder puts the kind on the chain and
# the count in the job log, and reconciles what the window holds.
B_MAX_HISTORY = int(F.bcast.MAX_HISTORY)
_pH, _ofH, _hxH = _first_send()
_nH = Net(utxos=[], spends=[_listed(_pH, _hxH)], fee=10, submit=_ACCEPTED,
          seen=_SEEN0, truncated=B_MAX_HISTORY + 137)
_c, _o, _p, _ = _reconcile(_nH, _ofH)
check("a reconciliation whose history reader had to truncate is told, puts "
      "history_truncated on the chain and the count in the job log, and "
      "goes on to reconcile the listed forward: done",
      _c == F.EXIT_OK and ("forward", "history_truncated") in _nH.kinds
      and str(B_MAX_HISTORY + 137) in _o and str(B_MAX_HISTORY) in _o
      and ("forward", "reconciled_listed") in _nH.kinds
      and _nH.spend_calls and callable(
          _nH.spend_calls[0].get("on_truncated")))
_nH2 = Net(utxos=[], spends=[_listed(_pH, _hxH)], fee=10, submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nH2, _ofH)
check("...and one whose history fit says nothing of the kind",
      _c == F.EXIT_OK and ("forward", "history_truncated") not in _nH2.kinds)
# MONEY THE VAULT KEPT, MOVED BY HAND: the documented remedy, and it used
# to raise the seed-leak alarm on every later reconciliation.
_ofM, _lM, _pM3, _hxM3 = _two_returns()
_lM3 = _listed(_pM3, _hxM3, inputs=[{"tx_hash": _H2, "vout": 1,
                                     "value": 140000}])
_nM1 = Net(utxos=_RET3, spends=_lM + [_lM3], fee=10, submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nM1, _ofM)
check("(setup) the third return is kept, and the mark names its outpoints",
      _c == F.EXIT_OK
      and (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]])
_moved = {**_spend_tx(None, send=120000), "inputs": [{"tx_hash": _HK3,
                                                       "vout": 0,
                                                       "value": 130000}]}
_nM2 = Net(utxos=[], spends=_lM + [_lM3, _moved], fee=10)
_c, _o, _p, _ = _reconcile(_nM2, _ofM)
check("a later spend of EXACTLY the kept outputs by a transaction this tool "
      "did not sign is the operator's hand: done, the kind kept_moved, no "
      "seed-leak alarm, the mark cleared",
      _c == F.EXIT_OK and ("forward", "kept_moved") in _nM2.kinds
      and ("forward", "foreign_spend") not in _nM2.kinds
      and "returned_kept" not in _p)
check("...and the move is RECORDED on the plan (returned_moved names the "
      "outpoints), since the kept mark it matched is now gone",
      _p.get("returned_moved") == [[_HK3, 0]])
# THE RUN AFTER: the same spend is still in the history and the kept mark
# is cleared. This used to be foreign_spend -- "the seed has leaked" --
# on every later reconciliation of the deposit, for ever, before any
# forward logic, so nothing that came to the address later could move.
_nM2b = Net(utxos=[], spends=_lM + [_lM3, _moved], fee=10)
_c, _o, _p, _ = _reconcile(_nM2b, _ofM)
check("the NEXT reconciliation, with the same hand move in the history "
      "and no kept mark left, is still the operator's hand: done, "
      "kept_moved, no seed-leak alarm, the record kept as it was",
      _c == F.EXIT_OK and ("forward", "kept_moved") in _nM2b.kinds
      and ("forward", "foreign_spend") not in _nM2b.kinds
      and _p.get("returned_moved") == [[_HK3, 0]])
_nM2c = Net(utxos=[], spends=_lM + [_lM3, _moved], fee=10)
_c, _o, _p, _ = _reconcile(_nM2c, _ofM)
check("...and the one after that (the record is not rewritten when it "
      "already names the spend)",
      _c == F.EXIT_OK and ("forward", "kept_moved") in _nM2c.kinds
      and ("forward", "foreign_spend") not in _nM2c.kinds)
# WHAT FUNDED THE KEPT OUTPUT IS ALWAYS READ. The history keeps only the
# txids it is handed from beyond its newest-MAX_HISTORY window; a flood
# that pushed the kept output's funding off it left the operator's hand
# move listed with no inputs -- a foreign spend, "the seed has leaked".
check("the history is asked to keep the kept output's funding transaction "
      "(kept mark in place) and the moved one's (after the move)",
      _HK3.lower() in (_nM2.spend_calls[0].get("keep_txids") or [])
      and _HK3.lower() in (_nM2c.spend_calls[0].get("keep_txids") or []))
# A LOOK THAT HAS NOT SEEN THE HAND MOVE: the history lists it (the
# operator's K, in a mempool) while the look -- another server, or taken a
# moment before K -- still lists the kept output unspent. The run said
# kept_moved and then, under a raised bound, SIGNED A FORWARD OVER K's
# INPUT in the same breath: a second signature over an outpoint a listed
# transaction spends -- the kept money into the swap if ours wins, and if
# K wins, our own forward's input read as foreign on every later run.
for _rmax in ((), ("--returns-max", "5")):
    _ofS, _lS, _pS3, _hxS3 = _two_returns()
    _lS3 = _listed(_pS3, _hxS3, inputs=[{"tx_hash": _H2, "vout": 1,
                                         "value": 140000}])
    _c, _o, _p, _ = _reconcile(Net(utxos=_RET3, spends=_lS + [_lS3],
                                   fee=10, submit=_ACCEPTED, seen=_SEEN0),
                               _ofS)
    assert (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]]
    _K = {**_moved, "height": 0}
    _nS = Net(utxos=_RET3, spends=_lS + [_lS3, _K], fee=10,
              submit=_ACCEPTED, seen=_SEEN0)
    _c, _o, _p, _ = _reconcile(_nS, _ofS, *_rmax)
    _bound = "a raised bound" if _rmax else "the bound"
    check(f"a hand move the look has not seen yet ({_bound}): kept_moved, "
          "and NOTHING signed over the moved output -- no submit, no "
          "returned forward, and no kept mark naming money already moved",
          _c == F.EXIT_OK and ("forward", "kept_moved") in _nS.kinds
          and _nS.submits == [] and _nS.posts == []
          and ("forward", "returned_settled") not in _nS.kinds
          and [_HK3, 0] not in ((_p.get("returned_kept") or {})
                                .get("outpoints") or []))
    _nS2 = Net(utxos=[], spends=_lS + [_lS3, {**_K, "height": 850040}],
               fee=10)
    _c, _o, _p, _ = _reconcile(_nS2, _ofS, *_rmax)
    check(f"...and the run after ({_bound}), K mined and the look caught "
          "up: the operator's hand still, no seed-leak alarm",
          _c == F.EXIT_OK and ("forward", "foreign_spend") not in _nS2.kinds)
_moved2 = {**_spend_tx(None, send=120000),
           "inputs": [{"tx_hash": _HK3, "vout": 0, "value": 130000},
                      {"tx_hash": _H2, "vout": 1, "value": 140000}]}
_nM3 = Net(utxos=[], spends=_lM + [_moved2], fee=10)
_c, _o, _p, _ = _reconcile(_nM3, _ofM)
check("...a spend that takes MORE than the kept outputs is still the alarm",
      _c == F.EXIT_FAILED and ("forward", "foreign_spend") in _nM3.kinds)
# AT THE BOUND, A BUMP DOES NOT LOSE THE KEPT MARK. The listed branch
# cleared the mark before the bump check, and a bump never rewrites it,
# so the replacement's chain carried no mark: the agent said `sent`
# about money that sat kept on the address, and a hand move of it in
# that window was the seed-leak alarm.
_ofB, _lB, _pB3, _hxB3 = _two_returns()
_lB3u = _listed(_pB3, _hxB3, height=0,
                inputs=[{"tx_hash": _H2, "vout": 1, "value": 140000}])
_nB1 = Net(utxos=_RET3, spends=_lB + [_lB3u], fee=10, submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB1, _ofB)
check("(setup) at the bound, the current forward in the mempool at today's "
      "rate: the return is kept and the mark names it",
      _c == F.EXIT_OK and _p.get("reconcile_reason") == "returned"
      and (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]])
_age_plan(_ofB, 4 * 3600)
_nB2 = Net(utxos=_RET3, spends=_lB + [_lB3u], fee=30, submit=_ACCEPTED,
           seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB2, _ofB)
_chainB = [json.load(open(_f)) for _f in F._plan_chain(_ofB)]
check("...fees rise and the forward is BUMPED: the replacement leaves the "
      "kept output out, and the kept mark SURVIVES on the rotated plan, so "
      "the agent still says kept and a hand move is still recognised",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "bumped"
      and all((i["tx_hash"], i["vout"]) != (_HK3, 0) for i in _p["inputs"])
      and any((q.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]]
              for q in _chainB))
# SELF-DOUBT OVER THAT FIX. The agent reads the word `kept` off the CURRENT
# plan alone (gs_wake_agent _forward_kept), and the replacement IS the
# current plan: a mark that survived only on the rotated one still left
# the client hearing `sent` about money that sat on the address, until
# the next reconciliation marked it again. The mark travels with the plan.
check("...and the REPLACEMENT itself carries the kept mark (the current "
      "plan is the one the agent reads `kept` off), naming the same output",
      (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]])
# UNDER A RAISED BOUND THE MARK GOES. Re-paired --returns-max 3, the bump
# CARRIES the kept output (the tool is moving it); the mark on the rotated
# plan then blessed a spend of exactly that output by a transaction this
# tool did not sign -- a replacement of ours by a leaked seed -- as the
# operator's hand. Two guards: the run that goes on to forward under the
# bound pops the mark, and an output any plan of ours signed for is never
# kept, whatever a stale mark says.
_ofB2, _lB2, _pB23, _hxB23 = _two_returns()
_lB23u = _listed(_pB23, _hxB23, height=0,
                 inputs=[{"tx_hash": _H2, "vout": 1, "value": 140000}])
_nB21 = Net(utxos=_RET3, spends=_lB2 + [_lB23u], fee=10, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB21, _ofB2)
check("(setup) kept at the bound, the forward in the mempool",
      _c == F.EXIT_OK
      and (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]])
_age_plan(_ofB2, 4 * 3600)
_nB22 = Net(utxos=_RET3, spends=_lB2 + [_lB23u], fee=30, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB22, _ofB2, "--returns-max", "3")
_chainB2 = [json.load(open(_f)) for _f in F._plan_chain(_ofB2)]
check("re-paired with a HIGHER bound, the bump CARRIES the kept output and "
      "NO plan in the chain still calls it kept: the tool is moving it",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "bumped"
      and any((i["tx_hash"], i["vout"]) == (_HK3, 0) for i in _p["inputs"])
      and not any(isinstance(q.get("returned_kept"), dict) for q in _chainB2))
_rbf = {**_spend_tx(None, send=120000),
        "inputs": [{"tx_hash": _HK3, "vout": 0, "value": 130000}]}
_nB23 = Net(utxos=[], spends=_lB2 + [_lB23u, _rbf], fee=30)
_c, _o, _p, _ = _reconcile(_nB23, _ofB2, "--returns-max", "3")
check("...so a spend of exactly that output by a transaction this tool did "
      "NOT sign -- a replacement of ours, by a leaked seed -- is the alarm "
      "(foreign_spend), never the operator's hand",
      _c == F.EXIT_FAILED and ("forward", "foreign_spend") in _nB23.kinds
      and ("forward", "kept_moved") not in _nB23.kinds)
# THE SAME THROUGH AN EVICTED RE-SIGN, which never rewrites the old plan:
# the mark rides into the chain on the rotated file, and only the second
# guard (signed for, so never kept) stands between a foreign RBF of the
# carried output and `kept_moved`.
_ofB3, _lB3, _pB33, _hxB33 = _two_returns()
_lB33u = _listed(_pB33, _hxB33, height=0,
                 inputs=[{"tx_hash": _H2, "vout": 1, "value": 140000}])
_nB31 = Net(utxos=_RET3, spends=_lB3 + [_lB33u], fee=10, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB31, _ofB3)
check("(setup) kept at the bound, again",
      _c == F.EXIT_OK
      and (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]])
_nB32 = Net(utxos=_UNSPENT_E + _RET3, spends=_lB3, fee=10, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB32, _ofB3, "--returns-max", "3")
_chainB3 = [json.load(open(_f)) for _f in F._plan_chain(_ofB3)]
check("(setup) re-paired higher and EVICTED, the re-sign carries the kept "
      "output while the rotated plan still names it kept",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "evicted"
      and any((i["tx_hash"], i["vout"]) == (_HK3, 0) for i in _p["inputs"])
      and any((q.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]]
              for q in _chainB3))
_nB33 = Net(utxos=_UNSPENT_E, spends=_lB3 + [_rbf], fee=10)
_c, _o, _p, _ = _reconcile(_nB33, _ofB3, "--returns-max", "3")
check("...and a foreign spend of exactly that output is STILL the alarm: an "
      "output a plan of ours signed for is never kept, whatever a stale "
      "mark on a rotated plan says",
      _c == F.EXIT_FAILED and ("forward", "foreign_spend") in _nB33.kinds
      and ("forward", "kept_moved") not in _nB33.kinds)
# THE MARK IS POPPED, NOT ONLY OVERRULED: kept UNSETTLED money under a
# raised bound rides in no replacement (nothing settled to carry), so the
# second guard says nothing about it -- and a mark left standing would be
# carried onto the replacement, and the agent would say `kept` about money
# the next window's forward will send on.
_ofB4, _lB4, _pB43, _hxB43 = _two_returns()
_lB43u = _listed(_pB43, _hxB43, height=0,
                 inputs=[{"tx_hash": _H2, "vout": 1, "value": 140000}])
_RET3U = [{**_RET3[0], "confirmations": 0}]
_nB41 = Net(utxos=_RET3U, spends=_lB4 + [_lB43u], fee=10, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB41, _ofB4)
check("(setup) an UNSETTLED return at the bound is kept, the mark naming it",
      _c == F.EXIT_OK
      and (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]]
      and _p["returned_kept"]["settled"] is False)
_age_plan(_ofB4, 4 * 3600)
_nB42 = Net(utxos=_RET3U, spends=_lB4 + [_lB43u], fee=30, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB42, _ofB4, "--returns-max", "3")
check("re-paired higher, a bump that carries nothing of it still DROPS the "
      "mark: the replacement names no kept money (it will be sent on once "
      "settled, not held for the operator)",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "bumped"
      and "returned_kept" not in _p
      and all((i["tx_hash"], i["vout"]) != (_HK3, 0) for i in _p["inputs"]))
# A HAND MOVE TAKES THE OUTPUT OFF THE MARK, whatever else the run does.
# With the forward stuck and today's rate over the ceiling the run is
# refused after the reconciliation wrote the plan, and the mark stood
# beside a `returned_moved` naming the same output: kept money, said the
# operator's copy, that the next line said was gone.
_ofB5, _lB5, _pB53, _hxB53 = _two_returns()
_lB53u = _listed(_pB53, _hxB53, height=0,
                 inputs=[{"tx_hash": _H2, "vout": 1, "value": 140000}])
_nB51 = Net(utxos=_RET3, spends=_lB5 + [_lB53u], fee=10, submit=_ACCEPTED,
            seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nB51, _ofB5)
check("(setup) kept at the bound, the forward in the mempool, once more",
      _c == F.EXIT_OK
      and (_p.get("returned_kept") or {}).get("outpoints") == [[_HK3, 0]])
_age_plan(_ofB5, 4 * 3600)
_nB52 = Net(utxos=[], spends=_lB5 + [_lB53u, _rbf], fee=30)
_c, _o, _p, _ = _reconcile(_nB52, _ofB5, "--feerate-ceiling", "10")
check("the kept output moved by hand while the forward sits stuck under a "
      "ceiling that refuses the bump: refused (delayed), the move recorded "
      "under returned_moved, and the mark GONE from the plan -- never both",
      _c == F.EXIT_REFUSED and _status_of(_ofB5) == "delayed"
      and ("forward", "kept_moved") in _nB52.kinds
      and _p.get("returned_moved") == [[_HK3, 0]]
      and "returned_kept" not in _p)
# A CORRUPT RECORD IS A VERDICT, NOT A TRACEBACK: `returned_moved` and the
# mark's outpoints are read by the tool that wrote them, and a hand-edited
# or damaged plan used to escape main as an uncaught TypeError (no kind
# on the chain, no exit code the agent knows).
_pX, _ofX, _hxX = _first_send()
_plX = json.load(open(_ofX))
_plX["returned_moved"] = 5
_plX["returned_kept"] = {"outpoints": [["zz", "x"], 7, None], "outputs": 1}
with open(_ofX, "w") as _fh:
    json.dump(_plX, _fh)
_nX = Net(utxos=[], spends=[_listed(_pX, _hxX)])
try:
    _c, _o, _p, _ = _reconcile(_nX, _ofX)
except Exception as _e:                                      # noqa: BLE001
    _c, _p = ("crashed", type(_e).__name__), {}
check("a plan whose returned_moved is not a list and whose mark names junk "
      "still reconciles (listed: done), rather than dying with a traceback",
      _c == F.EXIT_OK and _p.get("seen") is True
      and ("forward", "reconciled_listed") in _nX.kinds)
# A STRANGER'S CLAIMS WRITE ONE LINE, not one per output.
_pS, _ofS, _hxS = _first_send()
_nS = Net(utxos=[{"tx_hash": _HRF, "vout": i, "value": 600,
                  "confirmations": 5} for i in range(5)],
          spends=[_listed(_pS, _hxS)], fee=10, submit=_ACCEPTED, seen=_SEEN0,
          funding=[_paid(_HRF, 600, "REFUND:" + _pS["txid"].upper(),
                         _OTHER_ADDR, vout=i) for i in range(5)])
_c, _o, _p, _ = _reconcile(_nS, _ofS)
check("five dust outputs with a forged REFUND memo: five claims recorded, "
      "ONE refund_claimed line on the chain (a stranger cannot write a "
      "countable line per output)",
      sum(1 for k in _nS.kinds if k == ("forward", "refund_claimed")) == 1
      and len(json.load(open(F._plan_chain(_ofS)[-1])).get("refunds") or [])
      == 5)

# KERCKHOFFS ON THE CHAIN (fix pass after the deep read). The fee was
# EXACTLY the vsize bound times the rate, and the memo's limit EXACTLY 99
# times an integer: two public formulas that picked this host's forwards
# out of every ThorChain inbound with public data alone, one false
# positive in ~27,000. Each now carries a little randomness.
print("\n== KERCKHOFFS ON THE CHAIN: the fee and the limit are not formulas ==")
_draws = {F._fee_jitter(274) for _ in range(400)}
check("the default fee jitter is 0..bound-1 and not constant (a bound of 1 "
      "draws 0)",
      all(0 <= d < 274 for d in _draws) and len(_draws) > 20
      and F._fee_jitter(1) == 0)
_ldraws = {F._limit_jitter(5000) for _ in range(400)}
check("the default limit jitter is 0..cap and not constant (a cap of 0 "
      "draws 0)",
      all(0 <= d <= 5000 for d in _ldraws) and len(_ldraws) > 20
      and F._limit_jitter(0) == 0)
_srcF = open(F.__file__, encoding="utf-8").read()
check("all FOUR draws -- the fee jitter, the limit jitter, the limit's "
      "margin and the bump window -- come from the system CSPRNG "
      "(secrets), never the random module",
      _srcF.count("secrets.randbelow(") == 4 and "import random" not in _srcF)
# THE LIMIT'S RATIO TO THE QUOTE IS A BAND, NOT A NUMBER (self-doubt over
# the fix): the jitter killed the "99 times an integer" test, but the limit
# was still 0.99 of 0.90 of the quote -- 0.891 to five decimals, a public
# ratio Midgard's swap list lets anyone test. The margin is now drawn per
# forward across the band common wallet settings cover.
_mdraws = {F._limit_margin() for _ in range(400)}
check("the default margin is drawn in 300..1000 basis points (3% to the "
      "arrival tolerance) and is not constant",
      all(F.LIMIT_MARGIN_MIN_BPS <= d <= F.LIMIT_MARGIN_MAX_BPS
          for d in _mdraws) and len(_mdraws) > 20
      and F.LIMIT_MARGIN_MIN_BPS == 300
      and F.LIMIT_MARGIN_MAX_BPS == int(F.ARRIVAL_TOLERANCE * 10000))
_saved_margin = F.LIMIT_MARGIN_BPS
F.LIMIT_MARGIN_BPS = lambda: 300
_pm3, _, _ = _first_send()
F.LIMIT_MARGIN_BPS = lambda: 740
_pm7, _, _ = _first_send()
F.LIMIT_MARGIN_BPS = _saved_margin
check("two forwards with two draws write two different ratios of limit to "
      "quote (0.97 and 0.926), each the expected output less its own margin",
      _pm3["memo_limit_base_units"] == _floor_of(_pm3, 300)
      and _pm7["memo_limit_base_units"] == _floor_of(_pm7, 740)
      and _pm3["expected_xmr"] == _pm7["expected_xmr"]
      and _pm3["memo_limit_base_units"] > _pm7["memo_limit_base_units"]
      > int(Decimal(_pm7["worst_case_xmr"]) * 10 ** 8))
# A BUMP UNDER A JITTERED FEE. The original paid bound*rate + j; a
# replacement must pay at least the original plus one bound (BIP125 rule
# 4), so with any j >= 1 its rate is the paid rate plus TWO, not one, and
# a ceiling of paid + 1 refuses it. Arithmetically right; pinned here so
# the plan's "paid + 1" reads as what it is: the floor, not the usual.
F.FEE_JITTER = lambda bound: bound - 1
_pJ, _ofJ, _hxJ = _first_send()
F.FEE_JITTER = lambda bound: 0
check("(setup) the first send paid the bound times the rate plus bound-1",
      _pJ["fee_sat"] == _pJ["vsize_bound"] * 10 + _pJ["vsize_bound"] - 1
      and _pJ["feerate_target_sat_vb"] == 10)
_age_plan(_ofJ, 4 * 3600)
# 12: aimed at 10, it REALLY pays 2793 / 240 = 11.6 sat/vB, so an estimate
# of 11 is not above it (bump_due) and 12 is.
check("(setup) the jittered forward really pays between 11 and 12 sat/vB",
      11 * _pJ["vsize"] < _pJ["fee_sat"] < 12 * _pJ["vsize"])
_nJ1 = Net(utxos=[], spends=[_listed(_pJ, _hxJ, height=0)], fee=12,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nJ1, _ofJ, "--feerate-ceiling", "11")
check("stuck at 10 (really 11.6) with the estimate at 12 and a ceiling of "
      "11: the replacement would have to pay 12 (one bound over a jittered "
      "fee), so it is refused bump_over_ceiling (delayed) and the original "
      "stands",
      _c == F.EXIT_REFUSED and "bump_over_ceiling" in _o
      and _status_of(_ofJ) == "delayed" and _nJ1.submits == [])
_nJ2 = Net(utxos=[], spends=[_listed(_pJ, _hxJ, height=0)], fee=12,
           submit=_ACCEPTED, seen=_SEEN0)
_c, _o, _p, _ = _reconcile(_nJ2, _ofJ)
check("...under the default ceiling it is bumped at 12 sat/vB, paying at "
      "least the original's fee plus one bound",
      _c == F.EXIT_OK and _p["reconcile_reason"] == "bumped"
      and _p["feerate_target_sat_vb"] == 12
      and _p["fee_sat"] >= _pJ["fee_sat"] + _p["vsize_bound"]
      and _p["replaces"] == _pJ["txid"])
# THE DUST CHECK IS NOT A COIN FLIP. The jitter's room knew the floor and
# the fee fraction, not a live dust threshold above the floor: a send
# within one bound of it was signed on some draws and refused on others.
_p0J, _, _ = _first_send()                            # jitter pinned to 0
_fee0J = _p0J["fee_sat"]
_dustN = [{"chain": "BTC", "address": _INBOUND, "halted": False,
           "dust_threshold": "11200"}]
F.FEE_JITTER = lambda bound: 200
# 11,260 sat would go on before the jitter (the deposit is 13,800 with a
# 2,540 fee, so the fee fraction leaves the draw its full 200); the draw
# takes it to 11,060, under the live threshold of 11,200.
_cD, _oD, _pD, _ = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                   "value": 11260 + _fee0J,
                                   "confirmations": 5}],
                           thornode=_dustN), "--thornode", "https://t")
F.FEE_JITTER = lambda bound: 0
check("a send of 11,260 sat that a draw of 200 took under a live dust "
      "threshold of 11,200 is signed AT OR ABOVE the threshold: the jitter "
      "gives back what it needs, never a refusal by chance -- and what it "
      "has left over is drawn, so the send does not land exactly on "
      "THORNode's published figure (pinned here to the top of that draw)",
      _cD == 0 and 11200 <= _pD["send_sat"] <= 11260
      and _pD["send_sat"] + _pD["fee_sat"] == 11260 + _fee0J
      and _pD["fee_sat"] >= _fee0J and _pD["send_sat"] == 11260)
_cD2, _oD2, _pD2, _ = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                      "value": 11160 + _fee0J,
                                      "confirmations": 5}],
                              thornode=_dustN), "--thornode", "https://t")
check("...and a send under the threshold with NO jitter at all is refused "
      "below_thor_dust, as before -- the refusal is about the deposit, not "
      "the draw",
      _cD2 == F.EXIT_REFUSED and "below_thor_dust" in _oD2 and _pD2 is None)
_p0, _of0, _ = _first_send()                          # jitter pinned to 0
F.FEE_JITTER = lambda bound: 7
_p7, _of7, _hx7 = _first_send()
check("a forward with a fee jitter of 7 pays bound*rate + 7 sat -- the SIGNED "
      "transaction's fee (fee_mismatch still enforced) -- so the fee is not "
      "the bound times anything",
      _p7["fee_sat"] == _p0["fee_sat"] + 7
      and _p7["fee_sat"] % _p7["vsize_bound"] == 7
      and _p7["send_sat"] == _p0["send_sat"] - 7)
F.FEE_JITTER = lambda bound: 10 ** 9
_fee0 = _p0["fee_sat"]
_cF, _oF, _pF, _ = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                   "value": 20000 + _fee0,
                                   "confirmations": 5}]),
                       "--min-send-sat", "20000")
check("AT THE EXACT FLOOR (settled = the smallest forward + the fee) there "
      "is no room and no jitter: the forward is signed at the smallest "
      "amount, never refused below_minimum by a satoshi of randomness",
      _cF == 0 and _pF["fee_sat"] == _fee0 and _pF["send_sat"] == 20000)
_cG, _oG, _pG, _ = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                   "value": 200000, "confirmations": 5}]))
check("...and the jitter never takes the fee past the fee fraction: at "
      "200,000 sat a huge draw stops at exactly 20%",
      _cG == 0 and _pG["fee_sat"] == 40000 and _pG["send_sat"] == 160000)
# DRAWN OVER THE ROOM THERE IS (the review of stages 2-6): with less room
# than a bound, a draw over the bound clamped to the room put most of its
# weight ON the cap -- the fee exactly bound x rate plus the room, or the
# send exactly the minimum. The jitter is asked for the room it has.
_widths = []
F.FEE_JITTER = lambda bound: (_widths.append(bound), bound - 1)[1]
_cW, _oW, _pW, _ = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                   "value": 20030 + _fee0,
                                   "confirmations": 5}]),
                       "--min-send-sat", "20000")
check("with 30 sat of room under a bound of hundreds, the jitter is asked "
      "for a width of 31 -- uniform over what is allowed -- not the bound "
      "then clamped",
      _cW == 0 and _widths and _widths[0] == 31
      and _pW["fee_sat"] == _fee0 + 30 and _pW["send_sat"] == 20000)
F.FEE_JITTER = F._fee_jitter
_caps = 0
for _ in range(40):
    _cX, _oX, _pX, _ = run(Net(utxos=[{"tx_hash": _H1, "vout": 0,
                                       "value": 20030 + _fee0,
                                       "confirmations": 5}]),
                           "--min-send-sat", "20000")
    _caps += int(_cX == 0 and _pX["send_sat"] == 20000)
check("...so with the real draw the send lands on the minimum about one "
      "time in 31, not on most runs", _caps <= 8)
F.FEE_JITTER = lambda bound: 0
# THE JITTER'S SHAPE, at a margin that leaves it room above the worst
# arrival (3%). These two checks used to run at the suite's margin -- the
# tolerance itself, where the floor IS the worst arrival -- and so pinned
# a limit written up to 5,000 units UNDER it: a swap executed there was
# `short` to the watcher by the memo's own doing.
F.LIMIT_MARGIN_BPS = lambda: 300
F.LIMIT_JITTER = lambda cap: 1
_code, _out, _plan, _net, _tx = _limit_case("=:XMR.XMR:" + _DEST + ":0/1/0")
check("a limit jitter of 1 writes the floor LESS ONE into the memo: not the "
      "margin times anything",
      _code == 0 and _plan["memo_limit_set"] is True
      and _plan["memo_limit_base_units"] == _floor_of(_plan, 300) - 1
      and _plan["memo"] == f"=:XMR.XMR:{_DEST}:{_floor_of(_plan, 300) - 1}/1/0")
F.LIMIT_JITTER = lambda cap: cap
_code, _out, _plan, _net, _tx = _limit_case("=:XMR.XMR:" + _DEST + ":0/1/0")
check("the largest draw takes at most LIMIT_JITTER_MAX base units and 1% "
      "of the floor",
      _code == 0 and _plan["memo_limit_base_units"]
      == _floor_of(_plan, 300) - min(F.LIMIT_JITTER_MAX,
                                     _floor_of(_plan, 300) // 100)
      and _plan["memo_limit_base_units"] > 0)
# AT THE TOLERANCE no draw -- the largest, or one that ignores its cap --
# takes the limit under the watcher's own line, expected * (1 - tolerance).
F.LIMIT_MARGIN_BPS = lambda: 1000
for _jit, _why in ((lambda cap: cap, "the largest draw"),
                   (lambda cap: 10 ** 9, "a draw that ignores its cap")):
    F.LIMIT_JITTER = _jit
    _code, _out, _plan, _net, _tx = _limit_case(
        "=:XMR.XMR:" + _DEST + ":0/1/0")
    _line = Decimal(_plan["expected_xmr"]) * (1 - F.ARRIVAL_TOLERANCE) \
        * 10 ** 8
    check(f"margin at the tolerance, {_why}: the limit is never under the "
          "watcher's line (a swap that executes is never short by the "
          "memo's own doing)", _code == 0
          and Decimal(_plan["memo_limit_base_units"]) >= _line)
F.LIMIT_JITTER = lambda cap: 0

# A TRANSACTION THE SIGNER WILL NOT BUILD IS A REFUSAL, NOT A TRACEBACK
# (the MED pass after the deep read). A server that repeated an outpoint
# reached the signer as an input twice, and its refusal escaped main as an
# uncaught exception: exit 1, no kind, no word, the same server leading
# every retry of that deposit.
print("\n== what the signer declines is a refusal ==")
_dupU = {"tx_hash": _H1, "vout": 0, "value": 200000, "confirmations": 5}
try:
    _cX, _oX, _pX, _ = run(Net(utxos=[_dupU, dict(_dupU)]))
except Exception as _e:                                      # noqa: BLE001
    _cX, _oX, _pX = ("crashed", type(_e).__name__), "", None
check("the look handing the forwarder one outpoint twice: refused build_failed "
      "(exit 2, the kind on the chain, no plan), never a traceback",
      _cX == F.EXIT_REFUSED and "build_failed" in _oX and _pX is None
      and "Traceback" not in _oX)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
