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

# --- fixtures ----------------------------------------------------------------
_A0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"            # BIP84 index 0
_SH = W.address_to_scripthash(_A0)
_TXID = "ab" * 32
_OTHER = "cd" * 32
_HEX = "02000000000101" + "11" * 40 + "ffffffff" + "00" * 12
_PROXY = "socks5h://127.0.0.1:9050"
_SERVERS = [("s1.onion", 50002)]
_TWO = [("s1.onion", 50002), ("s2.onion", 50002)]


def _refused(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except W.BtcWatchError:
        return True


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
                 version_error=False, message="SECRET-MEMO-TEXT"):
        self.mode, self.code, self.message = mode, code, message
        self.history = history
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
             "pin_mismatch": False})
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
_r, _s = _seen(_FT(history=[{"tx_hash": _TXID, "height": 0}]),
               servers=_SERVERS, wait_s=0, avoid="s1.onion")
check("...and with ONE server there is nobody else: it is asked anyway",
      _s["hosts"] == ["s1.onion"] and _r["seen"] is True)

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


_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k), {})
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
      and _r["codes"] == [1] and _HEX not in json.dumps(_r)
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

from btcmock import tls_server_context                       # noqa: E402
_sctx, _CERT_SHA256 = tls_server_context()
_r, _cap = _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k), {},
                tls_ctx=_sctx, pin=_CERT_SHA256)
check("TLS with the right pin: accepted, TLS 1.2+, the certificate reported",
      _r["outcome"] == "accepted" and _r["cert_sha256"] == _CERT_SHA256
      and _cap.get("tls_version") in ("TLSv1.2", "TLSv1.3"))
try:
    _e2e(lambda s, p, **k: B.submit(_HEX, _TXID, _A0, s, p, **k), {},
         tls_ctx=_sctx, pin="00" * 32)
    _pm = "returned"
except W.PinMismatch:
    _pm = "raised"
check("TLS with the WRONG pin: PinMismatch raised through submit, and the "
      "transaction was never sent", _pm == "raised")

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
