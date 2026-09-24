#!/usr/bin/env python3
"""THE BROADCAST SIDE, DRIVEN: the one method that moves bitcoin, and what
it says about the money afterwards.

gs_btc_broadcast is the vault's module. These checks prove:

  * submit()'s FOUR outcomes are decided by what happened to the bytes,
    server by server: accepted (our txid came back), rejected (every
    answering server said no, codes only), ambiguous (the bytes left and no
    acceptance came back -- a hang-up, a foreign txid), unreachable (no send
    ever completed). Across a server list the worse-for-money word wins:
    ambiguous over rejected, rejected over unreachable, accepted over all.
  * a PinMismatch ends the submit at once -- an interception is not a
    server to route around;
  * seen() polls the deposit address's history until the txid is listed,
    tells "not listed" from "nobody could be asked", and never waits past
    its budget;
  * the real transport and the real subclass END TO END through an
    in-process SOCKS5 proxy to an in-process Electrum server, plaintext and
    TLS, on a circuit credential that is NOT the look's for the same
    address;
  * what the source must and must not be: the Pi's modules never name this
    one or its method; no text a server chose ever reaches an error.

No real network and no money.
"""
import json
import os
import sys

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
                                 "test_btc_broadcast.py")

import gs_btc_broadcast as B                                 # noqa: E402
import gs_btc_watch as W                                     # noqa: E402
import gs_btc_tx as T                                        # noqa: E402

# --- fixtures ----------------------------------------------------------------
_A0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"            # BIP84 index 0
_SH = W.address_to_scripthash(_A0)
# A REAL TRANSACTION, ITS HEX UPPER-CASED (the stage 3 read). The bytes
# were "02000000000101" and filler, all digits and lower case: a check that
# the hex reaches the server lower-cased compared a string with itself, and
# nothing tied the bytes to _TXID -- which submit now checks, as it must.
_TX0 = T.build_unsigned([{"tx_hash": "11" * 32, "vout": 0, "value": 50000}],
                        [(40000, T.address_script(_A0, "main"))])
_TXID = _TX0.txid().hex()
_OTHER = "cd" * 32
_HEX = _TX0.serialize().hex().upper()
_PROXY = "socks5h://127.0.0.1:9050"
_SERVERS = [("s1.onion", 50002)]
_TWO = [("s1.onion", 50002), ("s2.onion", 50002)]


def _refused(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except W.BtcWatchError:
        return True
    except AssertionError:
        # _never was reached: the call got past the refusals it should have
        # met. A red check, not a dead suite.
        return False


# ===========================================================================
print("== what submit refuses before any connection ==")


def _never(host, port, tag):
    raise AssertionError("a transport was made for a call that must refuse "
                         "before connecting")


for _bad, _why in (("abc", "odd length"), ("zz", "not hex"), ("", "empty"),
                   ("00" * (B.MAX_TX_BYTES + 1), "too large")):
    check(f"a transaction that is {_why} is refused before connecting",
          _refused(B.submit, _bad, _TXID, _A0, _SERVERS, _PROXY,
                   transport_factory=_never))
check("an expected txid that is not 64 hex digits is refused",
      all(_refused(B.submit, _HEX, t, _A0, _SERVERS, _PROXY,
                   transport_factory=_never)
          for t in ("", "ab" * 31, "zz" * 32, None)))
check("an address that is not this network's native segwit is refused",
      _refused(B.submit, _HEX, _TXID, "1BitcoinEaterAddressDontSendf59kuE",
               _SERVERS, _PROXY, transport_factory=_never)
      and _refused(B.submit, _HEX, _TXID, _A0, _SERVERS, _PROXY,
                   network="testnet", transport_factory=_never))
check("no servers, a malformed server, a bad timeout: each refused",
      _refused(B.submit, _HEX, _TXID, _A0, [], _PROXY,
               transport_factory=_never)
      and _refused(B.submit, _HEX, _TXID, _A0, ["s1.onion"], _PROXY,
                   transport_factory=_never)
      and all(_refused(B.submit, _HEX, _TXID, _A0, _SERVERS, _PROXY,
                       timeout=t, transport_factory=_never)
              for t in (0, -1, True, float("nan"))))
check("without a transport factory, a proxy URL that cannot isolate is ONE "
      "refusal before any server is tried",
      _refused(B.submit, _HEX, _TXID, _A0, _SERVERS, "socks5://127.0.0.1:9050")
      and _refused(B.submit, _HEX, _TXID, _A0, _SERVERS,
                   "socks5h://u:p@127.0.0.1:9050"))
# THE BYTES ARE THE TXID'S (the stage 3 read): submit compares a server's
# answer with the txid it was handed, so bytes and txid that disagree made
# a lying server "accepted" and an honest one a liar.
check("bytes whose txid is not the expected one are refused before "
      "connecting", _refused(B.submit, _HEX, _OTHER, _A0, _SERVERS, _PROXY,
                             transport_factory=_never))
check("...and hex that is not a transaction at all is refused too",
      _refused(B.submit, "00" * 60, _TXID, _A0, _SERVERS, _PROXY,
               transport_factory=_never))
_reached = []


def _reach(host, port, tag):
    _reached.append(host)
    raise KeyError("reached the transport")


try:
    B.submit(_HEX, _TXID, _A0, _SERVERS, _PROXY, transport_factory=_reach)
except KeyError:
    pass
check("NON-VACUITY: the same bytes with their own txid get past every "
      "check before connecting (a transport is asked for)",
      _reached == ["s1.onion"])
check("the outcome vocabulary is four words and MAYBE_MOVED is exactly the "
      "two after which money may have moved",
      B.OUTCOMES == ("accepted", "rejected", "ambiguous", "unreachable")
      and B.MAYBE_MOVED == ("accepted", "ambiguous"))


# ===========================================================================
print("\n== submit against a fake transport: the four outcomes ==")


class _FT:
    """Speaks the Electrum line protocol for the two methods this module
    adds, with one `mode` per server: accept, reject, foreign, hangup,
    junk, nullid, down. `history` is what get_history answers (a list, or
    a callable returning one per call)."""

    def __init__(self, mode="accept", *, code=1, history=(), pin_mismatch=False,
                 version_error=False, message="SECRET-MEMO-TEXT",
                 transactions=None):
        self.mode, self.code, self.message = mode, code, message
        self.history = history
        # blockchain.transaction.get, by txid (stage 5): a hex string, or
        # an Exception to hang up on; an unknown id is the server's error.
        self.transactions = dict(transactions or {})
        self.pin_mismatch = pin_mismatch
        self.version_error = version_error
        self.queue, self.methods, self.requests = [], [], []
        self.connected = self.closed = False
        self.dead = False

    def connect(self):
        if self.mode == "down":
            raise W.BtcWatchError("socks: CONNECT refused (reply=5)")
        if self.pin_mismatch:
            raise W.PinMismatch("tls: certificate does not match the pin")
        self.connected = True

    def send_line(self, line):
        req = json.loads(line)
        self.requests.append(req)
        i, m = req.get("id"), req.get("method")
        self.methods.append(m)
        if m == "server.version":
            if self.version_error:
                self.queue.append(json.dumps(
                    {"jsonrpc": "2.0", "id": i,
                     "error": {"code": 1, "message": "unsupported"}}))
            else:
                self.queue.append(json.dumps(
                    {"jsonrpc": "2.0", "id": i,
                     "result": ["ElectrumX 1.16.0", "1.4"]}))
            return
        if m == "blockchain.transaction.broadcast":
            if self.mode == "accept":
                res = {"result": req["params"][0][:0] + _TXID}
            elif self.mode == "reject":
                res = {"error": {"code": self.code, "message": self.message}}
            elif self.mode == "foreign":
                res = {"result": _OTHER}
            elif self.mode == "junk":
                res = {"result": 12345}
            elif self.mode == "nullid":
                self.queue.append(json.dumps(
                    {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": self.message}}))
                return
            elif self.mode == "hangup":
                self.dead = True
                return
            else:
                raise AssertionError(self.mode)
            self.queue.append(json.dumps({"jsonrpc": "2.0", "id": i, **res}))
            return
        if m == "blockchain.scripthash.get_history":
            h = self.history() if callable(self.history) else self.history
            if isinstance(h, Exception):
                self.dead = True
                return
            self.queue.append(json.dumps({"jsonrpc": "2.0", "id": i,
                                          "result": h}))
            return
        if m == "blockchain.transaction.get":
            t = self.transactions.get(req["params"][0])
            if isinstance(t, Exception):
                self.dead = True
                return
            if t is None:
                self.queue.append(json.dumps(
                    {"jsonrpc": "2.0", "id": i,
                     "error": {"code": -32603, "message": "no such tx"}}))
                return
            self.queue.append(json.dumps({"jsonrpc": "2.0", "id": i,
                                          "result": t}))
            return
        self.queue.append(json.dumps({"jsonrpc": "2.0", "id": i,
                                      "error": {"code": -32601,
                                                "message": "unknown"}}))

    def recv_line(self):
        if self.dead or not self.queue:
            raise W.BtcWatchError("electrum: connection closed")
        return self.queue.pop(0)

    def close(self):
        self.closed = True


def _factory(*fts):
    """One fake per server, handed out in the order servers are tried;
    records the hosts and tags asked for."""
    fts = list(fts)
    seen = {"hosts": [], "tags": []}

    def make(host, port, tag):
        seen["hosts"].append(host)
        seen["tags"].append(tag)
        return fts.pop(0) if fts else _FT("down")
    make.seen = seen
    return make


def _submit(*fts, servers=None, **kw):
    f = _factory(*fts)
    r = B.submit(_HEX, _TXID, _A0, servers or _SERVERS[:len(fts)] or _SERVERS,
                 _PROXY, transport_factory=f, **kw)
    return r, f.seen


_ft = _FT("accept")
_r, _s = _submit(_ft)
check("ACCEPTED: the server answered with our txid -- outcome accepted, the "
      "server named, one attempt, no codes, no mismatch",
      _r == {"outcome": "accepted", "server": "s1.onion", "cert_sha256": None,
             "codes": [], "attempts": 1, "mismatched": 0,
             "mismatched_servers": [], "pin_mismatch": False})
check("...the session spoke server.version then the broadcast and NOTHING "
      "else, with the hex lower-cased as the one parameter",
      _ft.methods == ["server.version", "blockchain.transaction.broadcast"]
      and _ft.requests[1]["params"] == [_HEX.lower()]
      and isinstance(_ft.requests[1]["id"], int)
      and _ft.requests[1]["jsonrpc"] == "2.0")
check("...on the broadcast circuit tag for this address, which is NOT the "
      "look's tag", _s["tags"] == ["btcsend:" + _A0]
      and _s["tags"][0] != "btcwatch:" + _A0
      and W._socks_parts(_PROXY, _s["tags"][0])[2]
      != W._socks_parts(_PROXY, "btcwatch:" + _A0)[2])
check("...and the transport was closed afterwards", _ft.closed)
_r, _ = _submit(_FT("accept", version_error=True))
check("a server that rejects server.version is still handed the "
      "transaction (the handshake is best effort)", _r["outcome"] == "accepted")

_r, _ = _submit(_FT("reject", code=1))
check("REJECTED: the server said no -- outcome rejected, its numeric code "
      "recorded, no server named", _r["outcome"] == "rejected"
      and _r["codes"] == [1] and _r["server"] is None and _r["attempts"] == 1)
_r, _ = _submit(_FT("reject", code=2 ** 40))
check("...a code outside int16 is recorded as 'unknown' (a 256-bit channel "
      "closed)", _r["outcome"] == "rejected" and _r["codes"] == ["unknown"])
_r, _ = _submit(_FT("nullid"))
check("...a null-id error (the server could not parse the request) is a "
      "rejection too: it answered, nothing moved",
      _r["outcome"] == "rejected" and _r["codes"] == [-32700])

_r, _ = _submit(_FT("hangup"))
check("AMBIGUOUS: the bytes left and the server hung up -- outcome "
      "ambiguous, no server named", _r["outcome"] == "ambiguous"
      and _r["server"] is None and _r["codes"] == [])
_r, _ = _submit(_FT("foreign"))
check("...a server answering with a FOREIGN txid is ambiguous and counted "
      "as a mismatch, never accepted", _r["outcome"] == "ambiguous"
      and _r["mismatched"] == 1)
_r, _ = _submit(_FT("junk"))
check("...a reply that is not a txid at all is ambiguous (the bytes left)",
      _r["outcome"] == "ambiguous")

_r, _ = _submit(_FT("down"))
check("UNREACHABLE: the connection never opened -- outcome unreachable, "
      "nothing sent", _r["outcome"] == "unreachable" and _r["attempts"] == 1)

print("\n== across a server list: the word that is worse for money wins ==")
_r, _s = _submit(_FT("reject", code=1), _FT("accept"), servers=_TWO)
check("reject then accept: ACCEPTED on the second server, the first's code "
      "kept, two attempts", _r["outcome"] == "accepted"
      and _r["codes"] == [1] and _r["attempts"] == 2
      and _r["server"] == _s["hosts"][1])
_r, _ = _submit(_FT("hangup"), _FT("accept"), servers=_TWO)
check("hang-up then accept: ACCEPTED (re-submitting the same signed bytes "
      "is idempotent)", _r["outcome"] == "accepted" and _r["attempts"] == 2)
_r, _ = _submit(_FT("down"), _FT("reject", code=3), servers=_TWO)
check("unreachable then reject: REJECTED (a server answered)",
      _r["outcome"] == "rejected" and _r["codes"] == [3])
_r, _ = _submit(_FT("reject", code=3), _FT("hangup"), servers=_TWO)
check("reject then hang-up: AMBIGUOUS (the bytes left once; money may have "
      "moved)", _r["outcome"] == "ambiguous" and _r["codes"] == [3])
_r, _ = _submit(_FT("down"), _FT("down"), servers=_TWO)
check("down then down: UNREACHABLE, two attempts",
      _r["outcome"] == "unreachable" and _r["attempts"] == 2)
_r, _s = _submit(_FT("foreign"), _FT("accept"), servers=_TWO)
check("a foreign txid then our own: accepted on the second, mismatched 1",
      _r["outcome"] == "accepted" and _r["mismatched"] == 1)
check("...and the server that answered the foreign txid is NAMED, for seen "
      "to leave out (the stage 3 read)",
      _r.get("mismatched_servers") == _s["hosts"][:1]
      and _r["server"] == _s["hosts"][1])
# A STOP IS HEARD BETWEEN SERVERS (the stage 3 read): over Tor a server can
# take the whole timeout, and SIGKILL follows SIGTERM by twenty seconds.


def _submit_stop(f, servers, stop):
    """submit with `stop`; a submit that takes no stop is a red check."""
    try:
        return B.submit(_HEX, _TXID, _A0, servers, _PROXY,
                        transport_factory=f, stop=stop)
    except TypeError:
        return {"outcome": "(no stop parameter)", "attempts": -1}


_f = _factory(_FT("accept"))
_r = _submit_stop(_f, _SERVERS, lambda: True)
check("a stop already raised: no server is dialled, and the result is "
      "unreachable -- nothing left, the caller keeps the bytes",
      _f.seen["hosts"] == [] and _r["outcome"] == "unreachable"
      and _r["attempts"] == 0)
_f = _factory(_FT("hangup"), _FT("accept"))
_r = _submit_stop(_f, _TWO, lambda: bool(_f.seen["hosts"]))
check("a stop raised during the first server: the second is never dialled, "
      "and bytes that left are still ambiguous",
      len(_f.seen["hosts"]) == 1 and _r["outcome"] == "ambiguous")
_f = _factory(_FT("hangup"), _FT("accept"))
_r = _submit_stop(_f, _TWO, lambda: False)
check("NON-VACUITY: a stop that is never raised changes nothing -- the "
      "second server is dialled and accepts",
      len(_f.seen["hosts"]) == 2 and _r["outcome"] == "accepted")
_f = _factory(_FT("accept", pin_mismatch=True), _FT("accept"))
try:
    B.submit(_HEX, _TXID, _A0, _TWO, _PROXY, transport_factory=_f)
    _pm = "returned"
except W.PinMismatch:
    _pm = "raised"
check("a PinMismatch on the first server is RAISED, and the second server "
      "is never tried", _pm == "raised" and len(_f.seen["hosts"]) == 1)
_f = _factory(_FT("hangup"), _FT("accept", pin_mismatch=True), _FT("accept"))
_r = B.submit(_HEX, _TXID, _A0, _TWO + [("s3.onion", 50002)], _PROXY,
              transport_factory=_f)
check("a PinMismatch AFTER the bytes left for an earlier server is NOT "
      "raised: the result is ambiguous WITH pin_mismatch set, the third "
      "server never tried -- 'may have moved' survives the interception "
      "signal", _r["outcome"] == "ambiguous" and _r["pin_mismatch"] is True
      and len(_f.seen["hosts"]) == 2)
_r, _ = _submit(_FT("reject"), _FT("accept"), servers=_TWO)
check("...and pin_mismatch is False on every ordinary result",
      _r["pin_mismatch"] is False
      and _submit(_FT("down"))[0]["pin_mismatch"] is False)
_f = _factory(_FT("accept"), _FT("accept"))
B.submit(_HEX, _TXID, _A0, _TWO, _PROXY, transport_factory=_f)
_order = [h for h, _p, _pin in W.server_order(_TWO, _SH)]
check("the servers are tried in the SAME rotation the look uses (by this "
      "address's own scripthash), and the first acceptance ends it",
      _f.seen["hosts"] == _order[:1])
_f = _factory(_FT("reject"), _FT("reject"), _FT("reject"))
_r = B.submit(_HEX, _TXID, _A0, _TWO + [("s3.onion", 50002)], _PROXY,
              transport_factory=_f)
check("...and every server is tried before 'rejected' is the answer",
      _f.seen["hosts"] == [h for h, _p, _pin in
                           W.server_order(_TWO + [("s3.onion", 50002)], _SH)]
      and _r["attempts"] == 3 and _r["codes"] == [1, 1, 1])

print("\n== the Broadcaster itself ==")
_ft = _FT("hangup")
_b = B.Broadcaster(_ft)
_b.connect = lambda: None
try:
    with _b:
        _b.broadcast(_HEX)
    _hu = None
except W.BtcWatchError as e:
    _hu = e
check("`sent` is False before the request leaves and True once it has, "
      "whatever the server does next", B.Broadcaster.sent is False
      and _b.sent is True and _hu is not None
      and not isinstance(_hu, W.ServerError))
_ft = _FT("reject", code=7)
_b = B.Broadcaster(_ft)
try:
    with _b:
        _b.broadcast(_HEX)
    _rj = None
except W.ServerError as e:
    _rj = e
check("a rejection is a ServerError carrying the code -- and its text is "
      "the code alone, never what the server wrote",
      _rj is not None and _rj.code == 7 and "SECRET" not in str(_rj)
      and "(code 7)" in str(_rj))
_b = B.Broadcaster(_FT("down"))
try:
    with _b:
        pass
    _dn = False
except W.BtcWatchError:
    _dn = True
check("a connection that never opens leaves `sent` False", _dn and not _b.sent)
check("broadcast() refuses bad hex itself, before sending",
      _refused(B.Broadcaster(_FT("accept")).broadcast, "abc")
      and not B.Broadcaster(_FT("accept")).sent)

# ===========================================================================
print("\n== seen(): the proof, from the deposit address's history ==")


def _seen(*fts, servers=None, **kw):
    f = _factory(*fts)
    kw.setdefault("sleeper", lambda s: None)
    r = B.seen(_TXID, _A0, servers or _SERVERS[:len(fts)] or _SERVERS,
               _PROXY, transport_factory=f, **kw)
    return r, f.seen


_ft = _FT(history=[{"tx_hash": _OTHER, "height": 100},
                   {"tx_hash": _TXID.upper(), "height": 0}])
_r, _s = _seen(_ft, wait_s=0)
check("the txid listed in the mempool (height 0): seen, height 0, one poll, "
      "asked", _r == {"seen": True, "height": 0, "server": "s1.onion",
                      "cert_sha256": None, "polls": 1, "asked": True})
check("...the session asked get_history for THIS address's scripthash, and "
      "nothing that could spend",
      _ft.methods == ["server.version", "blockchain.scripthash.get_history"]
      and _ft.requests[1]["params"] == [_SH])
check("...on the broadcast circuit (a re-check is not a new fact to leak)",
      _s["tags"] == ["btcsend:" + _A0])
_r, _ = _seen(_FT(history=[{"tx_hash": _TXID, "height": -1}]), wait_s=0)
check("height -1 (unconfirmed parents) is the mempool too: seen",
      _r["seen"] is True and _r["height"] == -1)
_r, _ = _seen(_FT(history=[{"tx_hash": _TXID, "height": 850001}]), wait_s=0)
check("a height above 0 is a block: seen, the height reported",
      _r["seen"] is True and _r["height"] == 850001)
_r, _ = _seen(_FT(history=[{"tx_hash": _OTHER, "height": 5}]), wait_s=0)
check("not listed, wait 0: one poll, NOT seen, but asked (the network was "
      "asked and does not list it)",
      _r["seen"] is False and _r["polls"] == 1 and _r["asked"] is True
      and _r["height"] is None)
_r, _ = _seen(_FT("down"), wait_s=0)
check("no server answered: NOT seen and NOT asked -- 'nobody could be "
      "asked' is a different fact from 'not listed'",
      _r["seen"] is False and _r["asked"] is False and _r["server"] is None)

_calls = {"n": 0}


def _later():
    _calls["n"] += 1
    return ([{"tx_hash": _TXID, "height": 0}] if _calls["n"] >= 2 else [])


_slept, _t = [], [0.0]
_r, _ = _seen(_FT(history=_later), _FT(history=_later),
              _FT(history=_later), wait_s=60, interval_s=15,
              sleeper=lambda s: (_slept.append(s), _t.__setitem__(
                  0, _t[0] + s)), clock=lambda: _t[0])
check("found on the SECOND poll: seen, two polls, one sleep of the interval",
      _r["seen"] is True and _r["polls"] == 2 and _slept == [15.0])
_slept, _t = [], [0.0]
_r, _ = _seen(*[_FT(history=[]) for _ in range(5)], wait_s=30, interval_s=15,
              sleeper=lambda s: (_slept.append(s), _t.__setitem__(
                  0, _t[0] + s)), clock=lambda: _t[0])
check("never found, wait 30 at 15: polls at 0, 15 and 30, then stops -- "
      "never past the budget", _r["seen"] is False and _r["polls"] == 3
      and _slept == [15.0, 15.0] and _r["asked"] is True)
# A STOP ENDS THE WAIT (the caller's SIGTERM): asked during the sleep in
# slices of at most a second, so the caller can still write down what it
# sent inside the agent's ten-second grace instead of being killed with
# nothing on disk.
_slept, _t, _asks = [], [0.0], [0]


def _stop_at_3():
    # A wait that does NOT end on the stop stops sleeping and polls on a
    # clock that no longer moves: bounded here, so that is a red check and
    # not a suite that never finishes.
    _asks[0] += 1
    if _asks[0] > 200:
        raise RuntimeError("the wait did not end on the stop")
    return _t[0] >= 3


try:
    _r, _ = _seen(*[_FT(history=[]) for _ in range(5)], wait_s=90,
                  interval_s=15, sleeper=lambda s: (_slept.append(s),
                                                    _t.__setitem__(
                                                        0, _t[0] + s)),
                  clock=lambda: _t[0], stop=_stop_at_3)
except RuntimeError:
    _r = None
check("a stop three seconds into the first sleep ends the wait there: one "
      "poll, three one-second slices, not seen but asked",
      _r is not None and _r["seen"] is False and _r["polls"] == 1
      and _r["asked"] is True and _slept == [1.0, 1.0, 1.0])
_slept, _t = [], [0.0]
_r, _ = _seen(*[_FT(history=[]) for _ in range(5)], wait_s=30, interval_s=15,
              sleeper=lambda s: (_slept.append(s), _t.__setitem__(
                  0, _t[0] + s)), clock=lambda: _t[0], stop=lambda: False)
check("NON-VACUITY: a stop that never comes changes nothing but the slicing: "
      "polls at 0, 15 and 30", _r["polls"] == 3 and sum(_slept) == 30.0)
# A STOP ALREADY RAISED ON ENTRY -- one that landed during the submit --
# polls nothing: the first poll used to fail over through every server
# (--timeout each, 30 s by default) before the stop was first asked, and
# the agent's SIGKILL came first, with no plan written.
_S3 = [("s1.onion", 50002), ("s2.onion", 50002), ("s3.onion", 50002)]
_r, _s = _seen(_FT("down"), _FT("down"), _FT("down"), servers=_S3,
               wait_s=600, interval_s=15, stop=lambda: True)
check("a stop raised before the wait: no server dialled, not seen, not "
      "asked -- the caller writes its plan with the bytes kept",
      _s["hosts"] == [] and _r["seen"] is False and _r["asked"] is False
      and _r["polls"] == 0)
# ...AND ONE RAISED DURING A POLL'S FAILOVER stops it before the next server.
_raised = [False]


def _dial_then_stop(*fts):
    f = _factory(*fts)

    def make(host, port, tag):
        _raised[0] = True
        return f(host, port, tag)
    make.seen = f.seen
    return make


_fs = _dial_then_stop(_FT("down"), _FT("down"), _FT("down"))
_r = B.seen(_TXID, _A0, _S3, _PROXY, transport_factory=_fs, wait_s=600,
            interval_s=15, sleeper=lambda s: None, stop=lambda: _raised[0])
check("a stop raised while the first server is being dialled: the poll does "
      "not fail over to the others", len(_fs.seen["hosts"]) == 1
      and _r["seen"] is False)
check("a wait under 0 or an interval of 0 is refused",
      _refused(B.seen, _TXID, _A0, _SERVERS, _PROXY, wait_s=-1,
               transport_factory=_never)
      and _refused(B.seen, _TXID, _A0, _SERVERS, _PROXY, interval_s=0,
                   transport_factory=_never))
for _bad in ([{"tx_hash": _TXID}], [{"tx_hash": _TXID, "height": -2}],
             [{"tx_hash": _TXID, "height": True}], [{"tx_hash": "zz",
                                                       "height": 0}],
             ["x"], "not a list", [{"tx_hash": _TXID, "height": "0"}]):
    _r, _ = _seen(_FT(history=_bad), wait_s=0)
    check(f"a malformed history ({str(_bad)[:30]}...) is refused for that "
          "server: not seen, not asked", _r["seen"] is False
          and _r["asked"] is False)
_r, _ = _seen(_FT(history="bad"), _FT(history=[{"tx_hash": _TXID,
                                                 "height": 0}]),
              servers=_TWO, wait_s=0)
check("...and the next server is asked instead", _r["seen"] is True)
_f = _factory(_FT(pin_mismatch=True), _FT(history=[]))
try:
    B.seen(_TXID, _A0, _TWO, _PROXY, transport_factory=_f, wait_s=0,
           sleeper=lambda s: None)
    _pm = "returned"
except W.PinMismatch:
    _pm = "raised"
check("a PinMismatch while polling is raised at once", _pm == "raised")
check("a bad txid is refused before connecting",
      _refused(B.seen, "zz" * 32, _A0, _SERVERS, _PROXY,
               transport_factory=_never))
# A SECOND SERVER'S WORD. The poll starts away from the server that
# accepted the transaction, so a server that lied about taking it cannot
# also be the one vouching that it propagated.
_first = W.server_order(_TWO, _SH)[0][0]
_second = W.server_order(_TWO, _SH)[1][0]
_r, _s = _seen(_FT(history=[{"tx_hash": _TXID, "height": 0}]),
               _FT(history=[]), servers=_TWO, wait_s=0, avoid=_first)
check("with two servers and avoid= naming the first in rotation, the SECOND "
      "is asked first", _s["hosts"][0] == _second and _r["server"] == _second)
_r, _s = _seen(_FT(history=[{"tx_hash": _TXID, "height": 0}]),
               _FT(history=[]), servers=_TWO, wait_s=0, avoid=_second)
check("...avoid= naming a server that is not first changes nothing",
      _s["hosts"][0] == _first)
_r, _s = _seen(_FT("down"), _FT(history=[{"tx_hash": _TXID, "height": 0}]),
               servers=_TWO, wait_s=0, avoid=_first)
check("...and with the OTHER server down, the accepting one is NOT asked "
      "in its place: nobody could be asked, and the caller keeps the bytes "
      "-- it used to fail over to it, which vouched for itself",
      _s["hosts"] == [_second] and _r["seen"] is False
      and _r["asked"] is False)
_r, _s = _seen(_FT(history=[{"tx_hash": _TXID, "height": 0}]),
               servers=_SERVERS, wait_s=0, avoid="s1.onion")
check("...and with ONE server there is nobody else: it is asked anyway",
      _s["hosts"] == ["s1.onion"] and _r["seen"] is True)
# ...AND EVERY SERVER THE SUBMIT CAUGHT OUT (the stage 3 read): one that
# answered a txid not ours was asked here, and its word dropped the bytes.
_S3x = _TWO + [("s3.onion", 50002)]
_o3 = [h for h, _p, _pin in W.server_order(_S3x, _SH)]
_r, _s = _seen(_FT(history=[{"tx_hash": _TXID, "height": 0}]),
               _FT(history=[{"tx_hash": _TXID, "height": 0}]),
               _FT(history=[{"tx_hash": _TXID, "height": 0}]),
               servers=_S3x, wait_s=0, avoid=[_o3[0], _o3[1]])
check("avoid= naming the accepting server AND a server that answered a "
      "foreign txid: only the third is asked",
      _s["hosts"] == [_o3[2]] and _r["server"] == _o3[2])
try:
    _r, _s = _seen(_FT(history=[{"tx_hash": _TXID, "height": 0}]),
                   _FT(history=[{"tx_hash": _TXID, "height": 0}]),
                   servers=_TWO, wait_s=600, avoid=[_first, _second],
                   sleeper=lambda s: (_ for _ in ()).throw(AssertionError(
                       "slept with nobody to ask")))
except AssertionError:
    # A red check, not a dead suite: it waited out the poll with nobody
    # to ask.
    _r, _s = {"seen": None}, {"hosts": ["(slept)"]}
check("...and with every server avoided nobody is asked, at once: not "
      "seen, not asked -- the caller keeps the bytes",
      _s["hosts"] == [] and _r["seen"] is False and _r["asked"] is False
      and _r["polls"] == 0)
# A HEIGHT NO TIP MAY HAVE IS NOT A HEIGHT (the stage 3 read): 10**30 read
# as mined.
_r, _ = _seen(_FT(history=[{"tx_hash": _TXID,
                            "height": W.Electrum.MAX_TIP_HEIGHT}]), wait_s=0)
check("a history height at the locktime threshold is a malformed answer: "
      "not seen, nobody answered", _r["seen"] is False
      and _r["asked"] is False)
_r, _ = _seen(_FT(history=[{"tx_hash": _TXID,
                            "height": W.Electrum.MAX_TIP_HEIGHT - 1}]),
              wait_s=0)
check("NON-VACUITY: one under it is a height", _r["seen"] is True)

# ===========================================================================
print("\n== unused(): has this address ever been used? ==")


def _unused(*fts, servers=None, **kw):
    f = _factory(*fts)
    r = B.unused(_A0, servers or _SERVERS[:len(fts)] or _SERVERS, _PROXY,
                 transport_factory=f, **kw)
    return r, f.seen


_r, _s = _unused(_FT(history=[]))
check("an empty history: unused, asked on the broadcast circuit with "
      "get_history for this scripthash and nothing that could spend",
      _r is True and _s["tags"] == ["btcsend:" + _A0])
_r, _ = _unused(_FT(history=[{"tx_hash": _OTHER, "height": 850000}]))
check("one entry in a block: USED", _r is False)
_r, _ = _unused(_FT(history=[{"tx_hash": _OTHER, "height": 0}]))
check("one entry in the mempool: USED (a payment in flight is a use)",
      _r is False)
check("no server answered: RAISED -- 'could not ask' is never 'unused'",
      _refused(B.unused, _A0, _SERVERS, _PROXY,
               transport_factory=_factory(_FT("down"))))
_r, _s = _unused(_FT("down"), _FT(history=[]), servers=_TWO)
check("a dead first server is routed around and the second decides",
      _r is True and len(_s["hosts"]) == 2)
_r, _ = _unused(_FT(history="junk"), _FT(history=[{"tx_hash": _OTHER,
                                                   "height": 1}]),
                servers=_TWO)
check("a malformed answer is not an answer: the next server decides",
      _r is False)
_f = _factory(_FT(pin_mismatch=True), _FT(history=[]))
try:
    B.unused(_A0, _TWO, _PROXY, transport_factory=_f)
    _pm = "returned"
except W.PinMismatch:
    _pm = "raised"
check("a PinMismatch is raised at once", _pm == "raised")
check("a bad address or network is refused before connecting",
      _refused(B.unused, "1BitcoinEaterAddressDontSendf59kuE", _SERVERS,
               _PROXY, transport_factory=_never)
      and _refused(B.unused, _A0, _SERVERS, _PROXY, network="testnet",
                   transport_factory=_never))

# ===========================================================================
print("\n== spends_of(): what the address's history spent (stage 5) ==")

import gs_btc_tx as T                                        # noqa: E402

_SPK0 = T.address_script(_A0, "main")
_OTHER_SPK = T.address_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                              "main")
# A funding transaction paying the address twice, a spend of one of those
# outputs, and a spend of the other by a transaction with a memo.
_FUND = T.build_unsigned([{"tx_hash": "11" * 32, "vout": 0, "value": 900000}],
                         [(300000, _SPK0), (100000, _OTHER_SPK),
                          (250000, _SPK0)])
_FUND_ID, _FUND_HEX = _FUND.txid().hex(), _FUND.serialize().hex()
_SPEND1 = T.build_unsigned([{"tx_hash": _FUND_ID, "vout": 0,
                             "value": 300000}], [(290000, _OTHER_SPK)])
_SPEND1_ID, _SPEND1_HEX = _SPEND1.txid().hex(), _SPEND1.serialize().hex()
_SPEND2 = T.build_unsigned([{"tx_hash": _FUND_ID, "vout": 2,
                             "value": 250000},
                            {"tx_hash": "22" * 32, "vout": 1,
                             "value": 50000}],
                           [(280000, _OTHER_SPK),
                            (0, T.op_return_script(b"=:XMR.XMR:x:0/1/0"))])
_SPEND2_ID, _SPEND2_HEX = _SPEND2.txid().hex(), _SPEND2.serialize().hex()
_HIST = [{"tx_hash": _FUND_ID, "height": 850000},
         {"tx_hash": _SPEND1_ID, "height": 850001},
         {"tx_hash": _SPEND2_ID, "height": 0}]
_TXS = {_FUND_ID: _FUND_HEX, _SPEND1_ID: _SPEND1_HEX, _SPEND2_ID: _SPEND2_HEX}


def _spends(*fts, servers=None, **kw):
    f = _factory(*fts)
    r = B.spends_of(_A0, servers or _SERVERS[:len(fts)] or _SERVERS, _PROXY,
                    transport_factory=f, **kw)
    return r, f.seen, fts


_r, _s, _fts = _spends(_FT(history=_HIST, transactions=_TXS))
check("a funding transaction and two spends: exactly the two spends come "
      "back, oldest first, each with the address's own outputs it consumed "
      "and their values read off the funding transaction",
      [x["txid"] for x in _r] == [_SPEND1_ID, _SPEND2_ID]
      and _r[0]["inputs"] == [{"tx_hash": _FUND_ID, "vout": 0,
                               "value": 300000}]
      and _r[1]["inputs"] == [{"tx_hash": _FUND_ID, "vout": 2,
                               "value": 250000}]
      and _r[0]["height"] == 850001 and _r[1]["height"] == 0
      and _r[0]["hex"] == _SPEND1_HEX and _r[1]["hex"] == _SPEND2_HEX
      and _r[1]["server"] == "s1.onion")
check("...in ONE session: the history, then transaction.get for each entry, "
      "on the broadcast circuit; the foreign input of the second spend is "
      "not listed as ours",
      _fts[0].methods == ["server.version",
                          "blockchain.scripthash.get_history"]
      + ["blockchain.transaction.get"] * 3
      and _s["tags"] == ["btcsend:" + _A0]
      and all(i["tx_hash"] == _FUND_ID for i in _r[1]["inputs"]))
_r, _, _ = _spends(_FT(history=_HIST[:1], transactions=_TXS))
check("a history of the funding alone: no spend", _r == [])
_r, _, _ = _spends(_FT(history=[], transactions={}))
check("an empty history: no spend, nothing fetched", _r == [])
# WHAT PAID THE ADDRESS, WITH MEMOS AND SOURCES (third self-doubt pass): a
# ThorChain refund names the forward it refunds in its memo, and its source
# -- the previous output of its first input -- is what tells a refund from
# a memo anyone could have written.
_VAULT_ADDR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
_VAULT = T.build_unsigned([{"tx_hash": "44" * 32, "vout": 0, "value": 500000}],
                          [(400000, _OTHER_SPK)])
_VAULT_ID, _VAULT_HEX = _VAULT.txid().hex(), _VAULT.serialize().hex()
_REFUND = T.build_unsigned([{"tx_hash": _VAULT_ID, "vout": 0,
                             "value": 400000}],
                           [(280000, _SPK0),
                            (0, T.op_return_script(
                                b"REFUND:" + _SPEND1_ID.upper().encode()))])
_REFUND_ID, _REFUND_HEX = _REFUND.txid().hex(), _REFUND.serialize().hex()
_HIST_R = _HIST + [{"tx_hash": _REFUND_ID, "height": 850002}]
_TXS_R = {**_TXS, _REFUND_ID: _REFUND_HEX, _VAULT_ID: _VAULT_HEX}
_rr, _sr, _ftr = _spends(_FT(history=_HIST_R, transactions=_TXS_R),
                         with_funding=True)
_spr, _pdr = _rr
check("with_funding: (spends, paid) -- the spends as before, and every "
      "output that pays the address oldest first with its memo; the one "
      "whose memo claims a REFUND carries the address its first input was "
      "paid from, read off that input's previous transaction",
      [x["txid"] for x in _spr] == [_SPEND1_ID, _SPEND2_ID]
      and _pdr == [{"txid": _FUND_ID, "height": 850000, "vout": 0,
                    "value": 300000, "memo": None, "from_address": None,
                    "from_addresses": []},
                   {"txid": _FUND_ID, "height": 850000, "vout": 2,
                    "value": 250000, "memo": None, "from_address": None,
                    "from_addresses": []},
                   {"txid": _REFUND_ID, "height": 850002, "vout": 0,
                    "value": 280000,
                    "memo": "REFUND:" + _SPEND1_ID.upper(),
                    "from_address": _VAULT_ADDR,
                    "from_addresses": [_VAULT_ADDR]}]
      and B.REFUND_SOURCE_INPUTS == 4)
check("...the previous transaction is fetched in the SAME session, once, "
      "and only for the claim: four history entries and one source",
      _ftr[0].methods.count("blockchain.transaction.get") == 5
      and _ftr[0].methods[:2] == ["server.version",
                                  "blockchain.scripthash.get_history"])
_rn, _, _ftn = _spends(_FT(history=_HIST_R, transactions=_TXS_R))
check("...without with_funding the answer is the list it always was, and "
      "no source is fetched",
      isinstance(_rn, list) and [x["txid"] for x in _rn]
      == [_SPEND1_ID, _SPEND2_ID]
      and _ftn[0].methods.count("blockchain.transaction.get") == 4)
_rm, _, _ = _spends(_FT(history=_HIST_R,
                        transactions={**_TXS, _REFUND_ID: _REFUND_HEX}),
                    with_funding=True)
check("a claim whose source the server cannot produce is still listed, "
      "unverifiable (from_address None) -- the session is not failed over "
      "for it", _rm[1][2]["from_address"] is None
      and _rm[1][2]["memo"] == "REFUND:" + _SPEND1_ID.upper()
      and [x["txid"] for x in _rm[0]] == [_SPEND1_ID, _SPEND2_ID])
check("op_return_data reads what op_return_script writes, direct and "
      "PUSHDATA1, and nothing else",
      T.op_return_data(T.op_return_script(b"REFUND:x").data) == b"REFUND:x"
      and T.op_return_data(T.op_return_script(b"y" * 100).data) == b"y" * 100
      and T.op_return_data(_SPK0.data) is None
      and T.op_return_data(b"") is None and T.op_return_data(None) is None
      and T.op_return_data(b"\x6a\x05abc") is None)
check("a listed transaction that does not touch the address is a "
      "contradiction: refused, not reasoned from",
      _refused(B.spends_of, _A0, _SERVERS, _PROXY, transport_factory=_factory(
          _FT(history=[{"tx_hash": "33" * 32, "height": 1}],
              transactions={"33" * 32: _SPEND1_HEX}))))
check("a transaction that is not the one asked for (its txid does not "
      "match) is refused", _refused(
          B.spends_of, _A0, _SERVERS, _PROXY, transport_factory=_factory(
              _FT(history=_HIST[:1], transactions={_FUND_ID: _SPEND1_HEX}))))
# A HISTORY LONGER THAN THE WINDOW IS READ AS ITS NEWEST ENTRIES (the MED
# pass after the deep read). It was refused outright, so anyone who could
# read the address -- it is in the chat -- could jam a deposit's every
# reconciliation for good with a flood of dust, until the operator acted by
# hand. Electrum lists confirmed entries by height and the mempool's after
# them: the tail is the newest.
_trunc_seen = []
_HIST_LONG = ([{"tx_hash": _FUND_ID, "height": 849000}] * (B.MAX_HISTORY + 2)
              + _HIST)
_rl, _, _ftl = _spends(_FT(history=_HIST_LONG, transactions=_TXS),
                       on_truncated=_trunc_seen.append)
check("a history longer than MAX_HISTORY is read as its newest MAX_HISTORY "
      "entries, not refused: the spends at the tail come back with their "
      "inputs, exactly MAX_HISTORY transactions are fetched, and the caller "
      "is told once with the total",
      [x["txid"] for x in _rl] == [_SPEND1_ID, _SPEND2_ID]
      and _rl[0]["inputs"] == [{"tx_hash": _FUND_ID, "vout": 0,
                                "value": 300000}]
      and _ftl[0].methods.count("blockchain.transaction.get")
      == B.MAX_HISTORY
      and _trunc_seen == [len(_HIST_LONG)])
_trunc_seen2 = []
_spends(_FT(history=_HIST, transactions=_TXS),
        on_truncated=_trunc_seen2.append)
check("...and a history within the window tells the caller nothing",
      _trunc_seen2 == [])
_rc, _, _ = _spends(_FT(history=[{"tx_hash": _FUND_ID, "height": 849000}]
                        + [{"tx_hash": _SPEND1_ID, "height": 850001}]
                        * (B.MAX_HISTORY + 1), transactions=_TXS),
                    on_truncated=lambda n: None)
check("a spend in the window whose funding fell OFF it is still LISTED, "
      "with no inputs (a spend that is not ours must stay the alarm it "
      "was), not refused as 'does not touch the address'",
      _rc and {x["txid"] for x in _rc} == {_SPEND1_ID}
      and all(x["inputs"] == [] and x["hex"] == _SPEND1_HEX for x in _rc))
check("...while in a history WITHIN the window such a transaction is still "
      "the contradiction it always was: refused",
      _refused(B.spends_of, _A0, _SERVERS, _PROXY, transport_factory=_factory(
          _FT(history=[{"tx_hash": _SPEND1_ID, "height": 850001}],
              transactions=_TXS))))
check("a server that has no such transaction, or hangs up mid-fetch, is "
      "routed around and the next decides",
      _spends(_FT(history=_HIST, transactions={}),
              _FT(history=_HIST, transactions=_TXS), servers=_TWO)[0][1]["txid"]
      == _SPEND2_ID
      and _spends(_FT(history=_HIST, transactions={
          **_TXS, _SPEND1_ID: OSError("cut")}),
          _FT(history=_HIST, transactions=_TXS), servers=_TWO)[0][0]["txid"]
      == _SPEND1_ID)
check("no server answered: RAISED",
      _refused(B.spends_of, _A0, _SERVERS, _PROXY,
               transport_factory=_factory(_FT("down"))))
_f = _factory(_FT(pin_mismatch=True), _FT(history=[]))
try:
    B.spends_of(_A0, _TWO, _PROXY, transport_factory=_f)
    _pm = "returned"
except W.PinMismatch:
    _pm = "raised"
check("a PinMismatch is raised at once", _pm == "raised")
_bt = B.Broadcaster(_FT(transactions={_FUND_ID: "zz", _SPEND1_ID: _FUND_HEX}))
_bt.__enter__()
check("Broadcaster.transaction refuses a bad id, non-hex, and a transaction "
      "that is not the one asked for",
      _refused(_bt.transaction, "nope")
      and _refused(_bt.transaction, _FUND_ID)
      and _refused(_bt.transaction, _SPEND1_ID))
check("history_of() is what unused() reads: (entries, host)",
      B.history_of(_A0, _SERVERS, _PROXY, transport_factory=_factory(
          _FT(history=_HIST)))[0] == _HIST)

# ===========================================================================
print("\n== END TO END: the real transport and the real subclass through an "
      "in-process SOCKS5 proxy to an in-process Electrum server ==")


from btcmock import mock_socks                               # noqa: E402


def _e2e(fn, scenario, *, behaviour="electrum", tls_ctx=None, pin=None,
         **kw):
    port, cap, srv = mock_socks(behaviour, scenario, tls_ctx=tls_ctx)
    proxy = f"socks5h://127.0.0.1:{port}"

    def factory(host, p, tag):
        cap["tag"] = tag
        return W.SocksTlsTransport(host, p, proxy, tag,
                                   tls=tls_ctx is not None, timeout=5.0,
                                   pin=pin)
    try:
        r = fn([("send.example.onion", 50002)], proxy,
               transport_factory=factory, **kw)
    finally:
        srv.close()
    return r, cap


# THE HISTORY READ IS BUDGETED BY WHAT IT READS (the review of stages 2-6).
# One session had one deadline for the handshake, the history and a
# transaction.get per entry, one after another: about sixty dust payments
# to the address -- which is in the chat -- ran every server out of it, and
# every reconciliation failed history_unavailable for good. Driven through
# the real transport and a server that takes 40 ms a reply, at a 1 s
# deadline the 45 requests cannot fit in.
_SPK0 = T.address_script(_A0, "main")
_DUST, _DTXS = [], dict(_TXS)
for _k in range(40):
    _dt = T.build_unsigned([{"tx_hash": "%064x" % (_k + 1000), "vout": 0,
                             "value": 2000}], [(546, _SPK0)])
    _DUST.append({"tx_hash": _dt.txid().hex(), "height": 850100 + _k})
    _DTXS[_dt.txid().hex()] = _dt.serialize().hex()


def _flood(per_entry):
    port, _c, srv = mock_socks("electrum", {"history": _HIST + _DUST,
                                            "transactions": _DTXS,
                                            "delay": 0.04})
    proxy = f"socks5h://127.0.0.1:{port}"
    _o = B.PER_ENTRY_S
    B.PER_ENTRY_S = per_entry
    try:
        return B.spends_of(
            _A0, [("s.example.onion", 50002)], proxy,
            transport_factory=lambda h, p, t: W.SocksTlsTransport(
                h, p, proxy, t, tls=False, timeout=1.0))
    except W.BtcWatchError as e:
        return e
    finally:
        B.PER_ENTRY_S = _o
        srv.close()


_fl = _flood(B.PER_ENTRY_S)
check("a dust flood no longer runs the session out of its deadline: each "
      "history entry brings its own allowance, and the spends come back",
      isinstance(_fl, list) and [x["txid"] for x in _fl]
      == [_SPEND1_ID, _SPEND2_ID])
check("...NON-VACUITY: with no allowance the same read runs out of its one "
      "deadline, as every reconciliation used to",
      isinstance(_flood(0.0), W.BtcWatchError))
check("...and the allowance has a ceiling that keeps two servers inside the "
      "forward job's budget",
      2 * (30 + B.READ_EXTENSION_MAX_S)
      < __import__("gs_wake_proto").JOBS["forward_to_swap"]["budget_s"])
# OUR OWN TRANSACTIONS ARE READ WHEREVER THEY SIT. A flood that pushed our
# forward off the newest MAX_HISTORY left its inputs neither unspent nor
# consumed: history_inconsistent, safe, on every run -- a jam all the same.
_HIST_OLD = _HIST[:2] + [{"tx_hash": _FUND_ID, "height": 851000}] \
    * (B.MAX_HISTORY + 1)
_rk0, _, _ = _spends(_FT(history=_HIST_OLD, transactions=_TXS),
                     on_truncated=lambda n: None)
_rk1, _, _ = _spends(_FT(history=_HIST_OLD, transactions=_TXS),
                     on_truncated=lambda n: None,
                     keep_txids=[_SPEND1_ID, _FUND_ID])
check("a spend of ours OLDER than the window is read all the same when the "
      "caller names it, with the inputs it consumed -- and without the name "
      "it falls off, as before",
      [x["txid"] for x in _rk1] == [_SPEND1_ID]
      and _rk1[0]["inputs"] == [{"tx_hash": _FUND_ID, "vout": 0,
                                 "value": 300000}]
      and _SPEND1_ID not in [x["txid"] for x in _rk0])

_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k),
                {"txid": "compute"})
check("plaintext: the real SOCKS5 handshake, then the real subclass hands "
      "the hex to the server and gets our txid back -- accepted, the server "
      "named", _r["outcome"] == "accepted" and _r["server"] == "send.example.onion")
check("...the destination reached the proxy as a domain name, on the right "
      "port", _cap.get("dest_host") == "send.example.onion"
      and _cap.get("dest_port") == 50002)
check("...the server was asked exactly server.version then the broadcast, "
      "with the hex", _cap["methods_asked"] == [
          "server.version", "blockchain.transaction.broadcast"]
      and _cap.get("hex") == _HEX.lower())
check("...on a SOCKS credential derived from the BROADCAST tag, which is "
      "not the credential the look uses for the same address",
      _cap.get("user") == W._socks_parts(_PROXY, "btcsend:" + _A0)[2]
      and _cap.get("user") != W._socks_parts(_PROXY, "btcwatch:" + _A0)[2]
      and _cap["tag"] == "btcsend:" + _A0)
_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k),
                {"reject": 1})
check("a rejection whose message carries the transaction (as ElectrumX's "
      "does) comes back as the code alone", _r["outcome"] == "rejected"
      and _r["codes"] == [1] and _HEX.lower() not in json.dumps(_r)
      and _cap.get("hex") == _HEX.lower())
_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k),
                {"hangup": True})
check("a server that reads the request and hangs up: ambiguous",
      _r["outcome"] == "ambiguous" and _cap.get("hex") == _HEX.lower())
_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k),
                {}, behaviour="connect_refuse")
check("a proxy that refuses the CONNECT: unreachable, nothing sent",
      _r["outcome"] == "unreachable" and "hex" not in _cap)
_r, _cap = _e2e(lambda s, p, **k: B.seen(_TXID, _A0, s, p, wait_s=0, **k),
                {"history": [{"tx_hash": _TXID, "height": 0}]})
check("seen() end to end: get_history for this scripthash, the txid found in "
      "the mempool", _r["seen"] is True and _r["height"] == 0
      and _cap["requests"][-1]["params"] == [_SH])
_r, _cap = _e2e(lambda s, p, **k: B.spends_of(_A0, s, p, **k),
                {"history": _HIST, "transactions": _TXS})
check("spends_of() end to end: the history, then each transaction fetched "
      "from the server, the two spends found with their values",
      [x["txid"] for x in _r] == [_SPEND1_ID, _SPEND2_ID]
      and _r[0]["inputs"][0]["value"] == 300000
      and _cap["methods_asked"].count("blockchain.transaction.get") == 3)

from btcmock import tls_server_context                       # noqa: E402
_sctx, _CERT_SHA256 = tls_server_context()
_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k),
                {"txid": "compute"}, tls_ctx=_sctx, pin=_CERT_SHA256)
check("TLS with the right pin: accepted, TLS 1.2+, the certificate reported",
      _r["outcome"] == "accepted" and _r["cert_sha256"] == _CERT_SHA256
      and _cap.get("tls_version") in ("TLSv1.2", "TLSv1.3"))
def _pin_caught(s, p, **k):
    try:
        B.submit(_HEX, _TXID, _A0, s, p, **k)
        return "returned"
    except W.PinMismatch:
        return "raised"


# "...AND NEVER SENT" WAS NOT CHECKED (the stage 3 read): only the raise
# was, so a submit that sent first and raised after would have passed.
# What the server captured is asked now.
_pm, _cap = _e2e(_pin_caught, {"txid": "compute"}, tls_ctx=_sctx,
                 pin="00" * 32)
check("TLS with the WRONG pin: PinMismatch raised through submit, and the "
      "transaction was never sent -- the server received no hex",
      _pm == "raised" and "hex" not in _cap)

# ===========================================================================
print("\n== what the source must and must not be ==")
_src = code_only(os.path.join(REPO, "gs_btc_broadcast.py"))
_wsrc = code_only(os.path.join(REPO, "gs_btc_watch.py"))
check("the watch module STILL never names the broadcast method: the Pi's "
      "client knows no method that could move money",
      "transaction.broadcast" not in _wsrc and "sendrawtransaction" not in _wsrc
      and "get_history" not in _wsrc)
check("the Pi's modules never import this one",
      all("gs_btc_broadcast" not in code_only(os.path.join(REPO, f))
          for f in ("gs_btc_watch.py", "gs_doorbell", "gs_telegram_pager")))
check("this module never opens a file: the signed bytes are a parameter, "
      "never read from disk", "open(" not in _src and "read_text" not in _src
      and "read_bytes" not in _src)
check("this module writes nothing to the hash chain (the forwarder records "
      "the outcome, once, as a kind)", "integrity_log" not in _src)
check("the broadcast method appears exactly once, inside Broadcaster",
      _src.count("blockchain.transaction.broadcast") == 1)
check("no error text and no result carries what a server wrote",
      "SECRET" not in json.dumps(_submit(_FT("reject"))[0])
      and "SECRET" not in json.dumps(_submit(_FT("nullid"))[0]))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
