#!/usr/bin/env python3
"""THE WATCH-ONLY SIDE, DRIVEN: it derives, it looks, it holds no key.

gs_btc_watch runs on the seizable Pi. These checks prove the two things it
does and the things it must NOT do:

  * DERIVATION against the BIP84 known-answer vector, from an account xPUB by
    public derivation; a hardened index or an xPRV is refused (a Pi must never
    hold or reach a secret).
  * The SOCKS5 layer against a REAL in-process SOCKS5 server: the handshake is
    framed correctly, the destination is sent as a DOMAIN name (resolved at
    the proxy -- no local DNS leak), and the per-address isolation tag becomes
    the SOCKS username so each address rides its own Tor circuit.
  * The Electrum client and look() against a fake transport speaking the line
    protocol, through every state -- nothing, unconfirmed, confirmed below the
    threshold, confirmed at it -- plus server failover, a skipped notification,
    and the confirmations arithmetic.

No real network and no money. The one live network fact -- that this Tor's
SOCKS port isolates by credential -- is already proven in gs_common's suite;
here the SOCKS server is ours, so the framing is what is under test.
"""
import json
import os
import socket
import sys
import threading
from pathlib import Path

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


from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_btc_watch.py")

import gs_btc_watch as W                                     # noqa: E402
from embit import bip32, bip39                               # noqa: E402

# The BIP84 reference account xPUB (m/84'/0'/0'), public only.
_root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"))
_ACCT_XPUB = _root.derive("m/84h/0h/0h").to_public().to_base58()
_ACCT_XPRV = _root.derive("m/84h/0h/0h").to_base58()

# ===========================================================================
print("== derivation: the vector, uniqueness, and what it refuses ==")
check("index 0 is the BIP84 published first receive address",
      W.derive_receive_address(_ACCT_XPUB, 0)
      == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
check("index 1 is the published second receive address",
      W.derive_receive_address(_ACCT_XPUB, 1)
      == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
check("change=1 index 0 is the published first change address",
      W.derive_receive_address(_ACCT_XPUB, 0, change=1)
      == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
_addrs = [W.derive_receive_address(_ACCT_XPUB, i) for i in range(64)]
check("sixty-four indexes give sixty-four distinct bc1q addresses",
      len(set(_addrs)) == 64 and all(a.startswith("bc1q") for a in _addrs))
check("a testnet derivation is a tb1 address",
      W.derive_receive_address(_ACCT_XPUB, 0, network="testnet")
      .startswith("tb1q"))


def _refused(fn):
    try:
        fn()
        return False
    except W.BtcWatchError:
        return True


check("a hardened index is refused (a Pi must not walk toward the key)",
      _refused(lambda: W.derive_receive_address(_ACCT_XPUB, 0x80000000)))
check("a negative index is refused",
      _refused(lambda: W.derive_receive_address(_ACCT_XPUB, -1)))
check("a boolean index is refused (True is not index 1 here)",
      _refused(lambda: W.derive_receive_address(_ACCT_XPUB, True)))
check("change other than 0/1 is refused",
      _refused(lambda: W.derive_receive_address(_ACCT_XPUB, 0, change=2)))
check("an xPRV where an xPUB belongs is refused -- no secret on the Pi",
      _refused(lambda: W.derive_receive_address(_ACCT_XPRV, 0)))
check("a junk xpub is refused, loudly",
      _refused(lambda: W.derive_receive_address("not-an-xpub", 0)))

check("the scripthash of index 0 is the Electrum-standard value",
      W.address_to_scripthash("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
      == "6e4f16236139f15046b38f399a683fb2aa8edf5fd128b3e5db017fb0ac74078a")
check("a junk address has no scripthash, loudly",
      _refused(lambda: W.address_to_scripthash("nope")))

# ===========================================================================
print("\n== per-address circuit isolation: the tag becomes the SOCKS user ==")
_PROXY = "socks5h://127.0.0.1:9050"
_h1, _p1, _u1, _pw1 = W._socks_parts(_PROXY, "btcwatch:addrA")
_h2, _p2, _u2, _pw2 = W._socks_parts(_PROXY, "btcwatch:addrB")
_h1b, _, _u1b, _ = W._socks_parts(_PROXY, "btcwatch:addrA")
check("the proxy host/port are parsed out for a raw socket",
      _h1 == "127.0.0.1" and _p1 == 9050)
check("two different addresses get two different SOCKS usernames "
      "(different circuits)", _u1 and _u2 and _u1 != _u2)
check("the SAME address gets the SAME username (a retry reuses its circuit)",
      _u1 == _u1b)
check("an empty proxy is refused rather than connecting directly",
      _refused(lambda: W._socks_parts("", "btcwatch:x")))


# ===========================================================================
print("\n== the SOCKS5 handshake, against a real in-process SOCKS5 server ==")


def _mock_socks(behaviour="ok"):
    """A one-shot SOCKS5 server. Returns (port, captured, stop). `captured`
    fills with what the client sent; `behaviour` picks the reply."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    captured = {}

    def _recvn(c, n):
        b = b""
        while len(b) < n:
            d = c.recv(n - len(b))
            if not d:
                raise OSError("closed")
            b += d
        return b

    def serve():
        try:
            c, _ = srv.accept()
        except OSError:
            return
        try:
            ver, nm = _recvn(c, 2)
            methods = _recvn(c, nm)
            captured["methods"] = list(methods)
            if 0x02 in methods:
                c.sendall(b"\x05\x02")
                _av, ul = _recvn(c, 2)
                user = _recvn(c, ul)
                pl = _recvn(c, 1)[0]
                _recvn(c, pl)
                captured["user"] = user.decode()
                if behaviour == "auth_reject":
                    c.sendall(b"\x01\x01")
                    return
                c.sendall(b"\x01\x00")
            else:
                c.sendall(b"\x05\x00")
            head = _recvn(c, 4)
            captured["atyp"] = head[3]
            if head[3] == 0x03:
                hl = _recvn(c, 1)[0]
                captured["dest_host"] = _recvn(c, hl).decode()
            captured["dest_port"] = int.from_bytes(_recvn(c, 2), "big")
            if behaviour == "connect_refuse":
                c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            else:
                c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                # leave the stream open; the SOCKS test does not speak Electrum
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, captured, srv


_port, _cap, _srv = _mock_socks("ok")
try:
    _s = W._socks5_connect("deposit.example.onion", 50002, "127.0.0.1", _port,
                           "isotag123", "x", 5.0)
    _s.close()
    _ok = True
except Exception:                                            # noqa: BLE001
    _ok = False
finally:
    _srv.close()
check("the handshake completes and returns a socket", _ok)
check("...the isolation tag was sent as the SOCKS username",
      _cap.get("user") == "isotag123")
check("...the destination went as a DOMAIN name (resolved at the proxy, no "
      "local DNS)", _cap.get("atyp") == 0x03
      and _cap.get("dest_host") == "deposit.example.onion")
check("...to the right port", _cap.get("dest_port") == 50002)

_port, _cap, _srv = _mock_socks("auth_reject")
try:
    W._socks5_connect("h.onion", 50002, "127.0.0.1", _port, "u", "p", 5.0)
    _rej = False
except W.BtcWatchError:
    _rej = True
finally:
    _srv.close()
check("a rejected SOCKS auth is a loud failure, not a silent direct connect",
      _rej)

_port, _cap, _srv = _mock_socks("connect_refuse")
try:
    W._socks5_connect("h.onion", 50002, "127.0.0.1", _port, "u", "p", 5.0)
    _cref = False
except W.BtcWatchError:
    _cref = True
finally:
    _srv.close()
check("a refused CONNECT is a loud failure", _cref)


# ===========================================================================
print("\n== the Electrum client and look(), against a fake transport ==")


class _FakeSock:
    """A socket-like object that speaks the Electrum line protocol from a
    fixed balance/history/tip. Optionally prepends a subscription-style
    notification, or drops the connection, to test those paths."""

    def __init__(self, *, tip, balance, history, notify_first=False,
                 drop=False):
        self._tip = tip
        self._bal = balance
        self._hist = history
        self._notify = notify_first
        self._drop = drop
        self._in = b""
        self._out = b""
        self._sent_methods = []

    def sendall(self, data):
        self._in += data
        while b"\n" in self._in:
            line, _, self._in = self._in.partition(b"\n")
            req = json.loads(line.decode())
            self._sent_methods.append(req.get("method"))
            self._out += self._respond(req)

    def _respond(self, req):
        i, m = req.get("id"), req.get("method")
        if m == "server.version":
            res = ["ElectrumX 1.16.0", "1.4"]
        elif m == "blockchain.headers.subscribe":
            res = {"height": self._tip, "hex": "00"}
        elif m == "blockchain.scripthash.get_balance":
            res = self._bal
        elif m == "blockchain.scripthash.get_history":
            res = self._hist
        else:
            return (json.dumps({"id": i, "error": "unknown"}) + "\n").encode()
        out = b""
        if self._notify and m == "blockchain.headers.subscribe":
            # a notification carries no matching id; the client must skip it
            out += (json.dumps({"method": "blockchain.headers.subscribe",
                                "params": [{"height": self._tip}]})
                    + "\n").encode()
        out += (json.dumps({"id": i, "result": res}) + "\n").encode()
        return out

    def recv(self, n):
        if self._drop:
            return b""
        chunk, self._out = self._out[:n], self._out[n:]
        return chunk

    def close(self):
        pass


_ADDR = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
_SERVERS = [("s1.onion", 50002)]


def _factory(sock):
    return lambda host, port, tag: (lambda: sock)


_r = W.look(_ADDR, _SERVERS, _PROXY, min_conf=1,
            connect_factory=_factory(_FakeSock(
                tip=800000, balance={"confirmed": 0, "unconfirmed": 0},
                history=[])))
check("nothing on the address: not_seen, zero, zero",
      _r["state"] == "not_seen" and _r["confirmed_sat"] == 0
      and _r["unconfirmed_sat"] == 0 and _r["confirmations"] == 0)

_r = W.look(_ADDR, _SERVERS, _PROXY, min_conf=1,
            connect_factory=_factory(_FakeSock(
                tip=800000, balance={"confirmed": 0, "unconfirmed": 500000},
                history=[{"tx_hash": "aa", "height": 0}])))
check("money landed, in the mempool: seen, the unconfirmed amount, zero confs",
      _r["state"] == "seen" and _r["unconfirmed_sat"] == 500000
      and _r["confirmations"] == 0)

_r = W.look(_ADDR, _SERVERS, _PROXY, min_conf=3,
            connect_factory=_factory(_FakeSock(
                tip=800000, balance={"confirmed": 500000, "unconfirmed": 0},
                history=[{"tx_hash": "bb", "height": 799999}])))
check("one confirmation but three required: still seen, not confirmed, and "
      "the confirmation count is exact (800000-799999+1=2)",
      _r["state"] == "seen" and _r["confirmed_sat"] == 500000
      and _r["confirmations"] == 2)

_r = W.look(_ADDR, _SERVERS, _PROXY, min_conf=3,
            connect_factory=_factory(_FakeSock(
                tip=800000, balance={"confirmed": 500000, "unconfirmed": 0},
                history=[{"tx_hash": "bb", "height": 799998}])))
check("three confirmations and three required: confirmed",
      _r["state"] == "confirmed" and _r["confirmations"] == 3)

_r = W.look(_ADDR, _SERVERS, _PROXY, min_conf=1,
            connect_factory=_factory(_FakeSock(
                tip=800000, balance={"confirmed": 500000, "unconfirmed": 0},
                history=[{"tx_hash": "bb", "height": 800000}],
                notify_first=True)))
check("a subscription notification interleaved before the answer is skipped, "
      "not mistaken for the result", _r["state"] == "confirmed"
      and _r["confirmations"] == 1)


# server failover: the first connect dies, the second answers.
def _failover_factory(host, port, tag):
    if host == "dead.onion":
        def _bad():
            raise OSError("circuit died")
        return _bad
    return lambda: _FakeSock(tip=800000,
                             balance={"confirmed": 700000, "unconfirmed": 0},
                             history=[{"tx_hash": "cc", "height": 799999}])


_r = W.look(_ADDR, [("dead.onion", 50002), ("live.onion", 50002)], _PROXY,
            min_conf=1, connect_factory=_failover_factory)
check("a dead first server fails over to a live second one",
      _r["state"] == "confirmed" and _r["server"] == "live.onion"
      and _r["confirmed_sat"] == 700000)


def _all_dead(host, port, tag):
    def _bad():
        raise OSError("nope")
    return _bad


check("every server dead: look() raises rather than inventing an answer",
      _refused(lambda: W.look(_ADDR, _SERVERS, _PROXY,
                              connect_factory=_all_dead)))
check("no servers configured: refused up front",
      _refused(lambda: W.look(_ADDR, [], _PROXY, connect_factory=_factory(
          _FakeSock(tip=1, balance={"confirmed": 0, "unconfirmed": 0},
                    history=[])))))

# a server that hangs up mid-conversation is a failure, not a partial answer.
check("a dropped connection is a loud failure",
      _refused(lambda: W.look(_ADDR, _SERVERS, _PROXY, connect_factory=_factory(
          _FakeSock(tip=800000, balance={"confirmed": 0, "unconfirmed": 0},
                    history=[], drop=True)))))

# look() tags each address's circuit by the address itself, so the network
# sees each on its own Tor circuit. Capture the tag it hands the transport.
_tags = []


def _tag_factory(host, port, tag):
    _tags.append(tag)
    return lambda: _FakeSock(tip=1, balance={"confirmed": 0, "unconfirmed": 0},
                             history=[])


W.look(_addrs[0], _SERVERS, _PROXY, connect_factory=_tag_factory)
W.look(_addrs[1], _SERVERS, _PROXY, connect_factory=_tag_factory)
check("look() isolates each address on its own circuit tag: the address is "
      "in the tag, and two addresses give two different tags",
      _addrs[0] in _tags[0] and _tags[0] != _tags[1])

# the client really did ask for balance AND history (confirmations need both).
_fs = _FakeSock(tip=800000, balance={"confirmed": 1, "unconfirmed": 0},
                history=[{"tx_hash": "dd", "height": 800000}])
W.look(_ADDR, _SERVERS, _PROXY, connect_factory=_factory(_fs))
check("look() asks the server for the tip, the balance AND the history",
      "blockchain.headers.subscribe" in _fs._sent_methods
      and "blockchain.scripthash.get_balance" in _fs._sent_methods
      and "blockchain.scripthash.get_history" in _fs._sent_methods)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
