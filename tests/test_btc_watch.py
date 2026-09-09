#!/usr/bin/env python3
"""THE WATCH-ONLY SIDE, DRIVEN: it derives, it looks, it holds no key.

gs_btc_watch runs on the seizable Pi. These checks prove the two things it
does and the things it must NOT do:

  * DERIVATION against the BIP84 known-answer vectors, from an account xPUB
    (and the published zpub) by public derivation; a hardened index, an
    xPRV, a key for another network or script type, and a key at the wrong
    depth are each refused (a Pi must never hold, reach, or quietly
    mis-derive).
  * SETTLEMENT as a pure function of the unspent outputs: each output is
    depth-checked on its own, so settled dust can never vouch for a fresh
    deposit, and a malformed reply is refused rather than coerced.
  * The SOCKS5 layer against a REAL in-process SOCKS5 server: the framing,
    the destination sent as a DOMAIN name (resolved at the proxy -- no local
    DNS), the per-address isolation tag as the SOCKS username, and the
    refusals -- a proxy that will not take the credential, a rejected auth,
    a refused CONNECT, a byte-trickle past the deadline.
  * The real transport and the real client END TO END through that mock
    proxy to an in-process Electrum server, in plaintext AND over TLS, and
    then look() against a fake transport through every state, server
    failover, a skipped notification, a notification flood, and every
    malformed reply a hostile server could send.

No real network and no money. The one live network fact -- that this Tor's
SOCKS port isolates by credential -- is already proven in gs_common's suite;
here the SOCKS server is ours, so the framing is what is under test.
"""
import hashlib
import io
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from contextlib import redirect_stdout

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
from embit import bech32, bip32, bip39                       # noqa: E402
from embit.networks import NETWORKS                          # noqa: E402


def _refused(fn, *a, **k):
    """True iff fn raises the module's own error -- never a stray one."""
    try:
        fn(*a, **k)
        return False
    except W.BtcWatchError:
        return True


def _raises(fn, exc, *a, **k):
    try:
        fn(*a, **k)
        return False
    except exc:
        return True
    except Exception:                                        # noqa: BLE001
        return False


# The BIP84 reference account keys (m/84'/0'/0' and m/84'/1'/0'), public only.
_MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
             "abandon abandon abandon about")
_root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(_MNEMONIC))
_acct = _root.derive("m/84h/0h/0h")
_ACCT_XPUB = _acct.to_public().to_base58()
_ACCT_XPRV = _acct.to_base58()
_ACCT_ZPUB = _acct.to_public(version=NETWORKS["main"]["zpub"]).to_base58()
_troot = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(_MNEMONIC),
                               version=NETWORKS["test"]["xprv"])
_tacct = _troot.derive("m/84h/1h/0h")
_ACCT_TPUB = _tacct.to_public().to_base58()
_ACCT_VPUB = _tacct.to_public(version=NETWORKS["test"]["zpub"]).to_base58()

# ===========================================================================
print("== derivation: the vectors, uniqueness, and what it refuses ==")
check("the account key re-encodes to the zpub BIP84 publishes for this seed",
      _ACCT_ZPUB == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3"
                    "EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
check("index 0 is the BIP84 published first receive address",
      W.derive_receive_address(_ACCT_XPUB, 0)
      == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
check("...and the zpub encoding of the same key derives the same address",
      W.derive_receive_address(_ACCT_ZPUB, 0)
      == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
check("index 1 is the published second receive address",
      W.derive_receive_address(_ACCT_XPUB, 1)
      == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
check("change=1 index 0 is the published first change address",
      W.derive_receive_address(_ACCT_XPUB, 0, change=1)
      == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
check("testnet: a tpub derives the published first testnet address",
      W.derive_receive_address(_ACCT_TPUB, 0, network="testnet")
      == "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl")
check("testnet: ...and so does its vpub encoding, on signet too (same hrp)",
      W.derive_receive_address(_ACCT_VPUB, 0, network="signet")
      == "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl")
check("regtest gives a bcrt1 address from the same testnet key",
      W.derive_receive_address(_ACCT_TPUB, 0, network="regtest")
      .startswith("bcrt1q"))
_addrs = [W.derive_receive_address(_ACCT_XPUB, i) for i in range(64)]
check("sixty-four indexes give sixty-four distinct bc1q addresses",
      len(set(_addrs)) == 64 and all(a.startswith("bc1q") for a in _addrs))
check("the largest non-hardened index derives (the boundary is inclusive)",
      W.derive_receive_address(_ACCT_XPUB, W.HARDENED - 1).startswith("bc1q"))

check("a hardened index is refused (a Pi must not walk toward the key)",
      _refused(W.derive_receive_address, _ACCT_XPUB, W.HARDENED))
check("a negative index is refused",
      _refused(W.derive_receive_address, _ACCT_XPUB, -1))
check("a boolean index is refused (True is not index 1 here)",
      _refused(W.derive_receive_address, _ACCT_XPUB, True))
check("a float index is refused",
      _refused(W.derive_receive_address, _ACCT_XPUB, 1.0))
check("change other than 0/1 is refused",
      _refused(W.derive_receive_address, _ACCT_XPUB, 0, change=2))
check("a boolean change is refused",
      _refused(W.derive_receive_address, _ACCT_XPUB, 0, change=True))
check("an xPRV where an xPUB belongs is refused -- no secret on the Pi",
      _refused(W.derive_receive_address, _ACCT_XPRV, 0))
check("a junk xpub is refused, loudly, through the module's own error",
      _refused(W.derive_receive_address, "not-an-xpub", 0))
check("a mainnet xpub asked for a testnet address is refused (it would "
      "quietly derive a tb1 address nobody's wallet holds)",
      _refused(W.derive_receive_address, _ACCT_XPUB, 0, network="testnet"))
check("a testnet tpub asked for a mainnet address is refused",
      _refused(W.derive_receive_address, _ACCT_TPUB, 0, network="main"))
check("a ypub (nested segwit) is refused: wrong script type for bc1q",
      _refused(W.derive_receive_address,
               _acct.to_public(version=NETWORKS["main"]["ypub"]).to_base58(),
               0))
check("a ROOT xpub (depth 0) is refused: only an account key derives here",
      _refused(W.derive_receive_address, _root.to_public().to_base58(), 0))
check("a key one level below the account (depth 4) is refused too",
      _refused(W.derive_receive_address,
               _acct.derive([0]).to_public().to_base58(), 0))
check("an unknown network name is refused",
      _refused(W.derive_receive_address, _ACCT_XPUB, 0, network="mars"))


def _errtext(fn, *a, **k):
    try:
        fn(*a, **k)
        return None
    except W.BtcWatchError as e:
        return str(e)


check("the xPRV refusal never echoes the key it refused (the error class "
      "promises: never carries key material)",
      _ACCT_XPRV[:12] not in _errtext(W.derive_receive_address, _ACCT_XPRV, 0)
      and _ACCT_XPRV[-12:] not in _errtext(W.derive_receive_address,
                                           _ACCT_XPRV, 0))
check("...and it says WHY -- a private key was handed to the watch-only box "
      "-- rather than falling through to the version-bytes check, so an "
      "operator who pasted the wrong key is told exactly that",
      "xPRV" in _errtext(W.derive_receive_address, _ACCT_XPRV, 0))
check("the junk refusal never echoes the junk",
      "not-an-xpub" not in _errtext(W.derive_receive_address,
                                    "not-an-xpub", 0))
check("no derivation refusal echoes the input xpub either",
      all(_ACCT_XPUB[:12] not in (_errtext(W.derive_receive_address,
                                           _ACCT_XPUB, *a, **k) or "")
          for a, k in ((( -1,), {}), ((0,), {"network": "testnet"}),
                       ((0,), {"change": 2}))))

# ===========================================================================
print("\n== scripthash: cross-computed from the address, not from the module ==")
_A0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
_wv, _prog = bech32.decode("bc", _A0)
_cross = hashlib.sha256(b"\x00\x14" + bytes(_prog)).digest()[::-1].hex()
check("scripthash = reversed sha256(OP_0 PUSH20 <program>) -- matches an "
      "independent computation from the bech32 program",
      _wv == 0 and len(_prog) == 20 and W.address_to_scripthash(_A0) == _cross)
check("...and it is the Electrum-standard value for the BIP84 first address",
      _cross == "6e4f16236139f15046b38f399a683fb2aa8edf5fd128b3e5db017fb0ac74078a")
check("a junk address has no scripthash, loudly",
      _refused(W.address_to_scripthash, "nope"))
check("an address with one character altered has no scripthash (checksum)",
      _refused(W.address_to_scripthash, _A0[:-1] + ("a" if _A0[-1] != "a"
                                                     else "b")))

# ===========================================================================
print("\n== settlement: a pure function of the unspent outputs ==")
_H = "ab" * 32
_H2 = "cd" * 32


def _u(height, value, txid=_H, pos=0):
    return {"tx_hash": txid, "tx_pos": pos, "height": height, "value": value}


_s = W.summarize([], 800000, 3)
check("nothing unspent: every figure is zero and the state is not_seen",
      _s == {"confirmed_sat": 0, "unconfirmed_sat": 0, "settled_sat": 0,
             "confirmations": 0, "utxos": []}
      and W.classify(0, 0, 0) == "not_seen")
_s = W.summarize([_u(0, 500000)], 800000, 1)
check("money in the mempool only: seen, the amount counted as unconfirmed, "
      "nothing settled even at min_conf=1",
      _s["unconfirmed_sat"] == 500000 and _s["confirmed_sat"] == 0
      and _s["settled_sat"] == 0 and _s["confirmations"] == 0
      and W.classify(0, 500000, 0) == "seen")
_s = W.summarize([_u(799999, 500000)], 800000, 3)
check("mined two blocks ago (800000-799999+1=2) with three required: seen, "
      "the depth reported exactly, nothing settled",
      _s["confirmed_sat"] == 500000 and _s["confirmations"] == 2
      and _s["settled_sat"] == 0
      and W.classify(500000, 0, 0) == "seen")
_s = W.summarize([_u(799998, 500000)], 800000, 3)
check("three deep with three required: settled, confirmed",
      _s["settled_sat"] == 500000 and _s["confirmations"] == 3
      and W.classify(500000, 0, 500000) == "confirmed")
_s = W.summarize([_u(799900, 1, _H, 0), _u(800000, 500000, _H2, 1)],
                 800000, 3)
check("THE DUST TRAP: 1 sat settled 101 deep plus the real deposit 1 deep -- "
      "only the dust is settled, the newest depth is 1, and the deposit's "
      "own output is marked 1 deep so it can never be handed over as spendable",
      _s["settled_sat"] == 1 and _s["confirmed_sat"] == 500001
      and _s["confirmations"] == 1
      and [x["confirmations"] for x in _s["utxos"]] == [101, 1])
_s = W.summarize([_u(799990, 500000, _H, 0), _u(800000, 546, _H2, 1)],
                 800000, 3)
check("the reverse: a settled deposit plus fresh dust -- the deposit IS "
      "settled (fresh dust cannot hold a settled deposit hostage)",
      _s["settled_sat"] == 500000 and _s["confirmations"] == 1
      and W.classify(500546, 0, 500000) == "confirmed")
_s = W.summarize([_u(800001, 10)], 800000, 1)
check("a mined output above the tip we were told (server race) is at least 1 "
      "deep, never zero or negative",
      _s["confirmations"] == 1 and _s["confirmed_sat"] == 10
      and _s["settled_sat"] == 10)
_s = W.summarize([_u(0, 5), _u(0, 7, _H2, 3)], 800000, 1)
check("two mempool outputs sum; a negative Electrum height (-1, unconfirmed "
      "parent) also counts as unconfirmed",
      _s["unconfirmed_sat"] == 12
      and W.summarize([_u(-1, 9)], 800000, 1)["unconfirmed_sat"] == 9)
check("tx_hash is normalised to lower case, vout carried through",
      W.summarize([_u(1, 1, _H.upper(), 7)], 1, 1)["utxos"][0]
      == {"tx_hash": _H, "vout": 7, "value": 1, "confirmations": 1})
check("classify truth table: (mined, mempool, settled) -> state",
      [W.classify(*t) for t in ((0, 0, 0), (5, 0, 0), (0, 5, 0), (5, 5, 0),
                                (5, 0, 5), (12, 7, 3))]
      == ["not_seen", "seen", "seen", "seen", "confirmed", "confirmed"])

for _label, _bad in [
        ("value as a string", [_u(1, "5")]),
        ("value as a bool", [_u(1, True)]),
        ("value as a float", [_u(1, 5.0)]),
        ("a negative value", [_u(1, -5)]),
        ("height as a float", [_u(1.0, 5)]),
        ("height as a bool", [_u(True, 5)]),
        ("height as a string", [_u("1", 5)]),
        ("tx_hash that is not 64 hex chars", [_u(1, 5, "zz" * 32)]),
        ("tx_hash too short", [_u(1, 5, "ab" * 31)]),
        ("tx_pos negative", [_u(1, 5, _H, -1)]),
        ("a missing field", [{"tx_hash": _H, "height": 1, "value": 5}]),
        ("an entry that is not an object", [7]),
        ("a reply that is not a list", {"tx_hash": _H}),
]:
    check(f"a malformed reply is refused, not coerced: {_label}",
          _refused(W.summarize, _bad, 800000, 1))

# ===========================================================================
print("\n== host:port parsing, for the proxy and the server list ==")
check("a bare host takes the TLS default port and no pin",
      W.parse_server("s.onion") == ("s.onion", 50002, None))
check("host:port is honoured",
      W.parse_server("s.onion:50001") == ("s.onion", 50001, None))
check("a bracketed IPv6 literal parses",
      W.parse_server("[::1]:50001") == ("::1", 50001, None)
      and W.parse_server("[::1]") == ("::1", 50002, None))
check("a bare IPv6 literal is refused as ambiguous",
      _refused(W.parse_server, "::1"))
check("a spec refusal never repeats the spec (it names a machine, and an "
      "error is the string a caller is likeliest to log)",
      "evil.onion" not in _errtext(W.parse_server, "evil.onion:99999")
      and "evil" not in _errtext(W.parse_server, "[evil:1"))
_PIN = "ab" * 32
check("host:port,pin carries the certificate pin, lower-cased, with or "
      "without a sha256: prefix",
      W.parse_server(f"s.onion:50002,{_PIN}") == ("s.onion", 50002, _PIN)
      and W.parse_server(f"s.onion,sha256:{_PIN.upper()}")
      == ("s.onion", 50002, _PIN))
for _spec in ("s.onion:0", "s.onion:70000", "s.onion:abc", ":50002", "",
              "[::1", "s.onion:-5", "s.onion,abc", "s.onion," + "zz" * 32,
              "s.onion," + "ab" * 31):
    check(f"a bad server spec is refused up front: {_spec!r}",
          _refused(W.parse_server, _spec))

# ===========================================================================
print("\n== per-address circuit isolation: the tag becomes the SOCKS user ==")
_PROXY = "socks5h://127.0.0.1:9050"
_h1, _p1, _u1, _pw1 = W._socks_parts(_PROXY, "btcwatch:addrA")
_h2, _p2, _u2, _pw2 = W._socks_parts(_PROXY, "btcwatch:addrB")
_h1b, _, _u1b, _ = W._socks_parts(_PROXY, "btcwatch:addrA")
check("the proxy host/port are parsed out for a raw socket",
      _h1 == "127.0.0.1" and _p1 == 9050 and _pw1)
check("two different addresses get two different SOCKS usernames "
      "(different circuits)", _u1 and _u2 and _u1 != _u2)
check("the SAME address gets the SAME username (a retry reuses its circuit)",
      _u1 == _u1b)
check("the address itself never appears in the credential (only its hash)",
      "addrA" not in _u1 and "btcwatch" not in _u1)
check("an empty proxy is refused rather than connecting directly",
      _refused(W._socks_parts, "", "btcwatch:x"))
check("a proxy URL that already carries a credential is REFUSED: used as-is "
      "it would put every address on one circuit",
      _refused(W._socks_parts, "socks5h://op:pw@127.0.0.1:9050", "btcwatch:x"))
check("a socks5:// (local-DNS) URL is refused; only socks5h:// is accepted",
      _refused(W._socks_parts, "socks5:// 127.0.0.1:9050".replace(" ", ""),
               "btcwatch:x"))
check("an http:// proxy is refused",
      _refused(W._socks_parts, "http://127.0.0.1:8118", "btcwatch:x"))
check("a proxy with a bad port is refused",
      _refused(W._socks_parts, "socks5h://127.0.0.1:90500", "btcwatch:x"))
check("a proxy with no port is refused (no guessing 9050)",
      _refused(W._socks_parts, "socks5h://127.0.0.1", "btcwatch:x"))


# ===========================================================================
print("\n== the SOCKS5 handshake, against a real in-process SOCKS5 server ==")

_TIP = 800000
_SCRIPTHASH = W.address_to_scripthash(_A0)


def _electrum_reply(req, scenario):
    """A tiny Electrum server's answer to one request, for the end-to-end
    runs through the mock proxy."""
    i, m = req.get("id"), req.get("method")
    if m == "server.version":
        res = ["ElectrumX 1.16.0", "1.4"]
    elif m == "blockchain.headers.subscribe":
        res = {"height": scenario["tip"], "hex": "00"}
    elif m == "blockchain.scripthash.listunspent":
        res = (scenario["utxos"] if req.get("params") == [_SCRIPTHASH]
               else [])
    elif m == "blockchain.estimatefee":
        res = scenario.get("fee", -1)
    else:
        return json.dumps({"jsonrpc": "2.0", "id": i,
                           "error": {"code": -32601,
                                     "message": "unknown method"}}) + "\n"
    return json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n"


def _mock_socks(behaviour="ok", scenario=None, tls_ctx=None):
    """A one-shot SOCKS5 server. Returns (port, captured, srv). `captured`
    fills with what the client sent; `behaviour` picks the reply. With
    behaviour "electrum" it goes on to speak Electrum after CONNECT (over
    `tls_ctx` if given), so the real transport and client can be driven end
    to end."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    captured = {"methods_asked": []}

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
            srv.settimeout(10)
            c, _ = srv.accept()
        except OSError:
            return
        try:
            c.settimeout(10)
            ver, nm = _recvn(c, 2)
            methods = _recvn(c, nm)
            captured["greeting_ver"] = ver
            captured["methods"] = list(methods)
            if behaviour == "ver4":
                c.sendall(b"\x04\x00")
                return
            if behaviour == "method_none":
                # a proxy that "helpfully" downgrades to no-auth; then
                # record WHATEVER the client sends next (a conforming client
                # sends nothing and hangs up; a downgraded one CONNECTs)
                c.sendall(b"\x05\x00")
                c.settimeout(1.0)
                try:
                    captured["after_downgrade"] = c.recv(64)
                except OSError:
                    captured["after_downgrade"] = b""
                return
            if behaviour == "method_ff":
                c.sendall(b"\x05\xff")
                return
            if behaviour == "drip":
                # A valid handshake, one byte per 0.25 s, then padding, for
                # ten seconds -- longer than any deadline a test sets, so
                # the client's clock, not this mock's hang-up, decides.
                stream = (b"\x05\x02" + b"\x01\x00"
                          + b"\x05\x00\x00\x01" + b"\x00" * 6 + b"\x00" * 26)
                try:
                    for i in range(len(stream)):
                        c.sendall(stream[i:i + 1])
                        time.sleep(0.25)
                except OSError:
                    pass
                return
            if behaviour == "stall":
                # the proxy handshake completes, then the "server" says
                # nothing at all
                time.sleep(4.0)
                return
            if behaviour == "close_early":
                c.sendall(b"\x05")
                return
            if 0x02 in methods:
                c.sendall(b"\x05\x02")
                av, ul = _recvn(c, 2)
                user = _recvn(c, ul)
                pl = _recvn(c, 1)[0]
                pw = _recvn(c, pl)
                captured["auth_ver"] = av
                captured["user"] = user.decode()
                captured["password"] = pw.decode()
                if behaviour == "auth_reject":
                    c.sendall(b"\x01\x01")
                    return
                if behaviour == "auth_badver":
                    c.sendall(b"\x05\x00")
                    return
                c.sendall(b"\x01\x00")
            else:
                c.sendall(b"\x05\x00")
            head = _recvn(c, 4)
            captured["cmd"] = head[1]
            captured["atyp"] = head[3]
            if head[3] == 0x03:
                hl = _recvn(c, 1)[0]
                captured["dest_host"] = _recvn(c, hl).decode()
            elif head[3] == 0x01:
                captured["dest_host"] = socket.inet_ntoa(_recvn(c, 4))
            captured["dest_port"] = int.from_bytes(_recvn(c, 2), "big")
            if behaviour == "connect_refuse":
                c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if behaviour == "bound_v6":
                c.sendall(b"\x05\x00\x00\x04" + b"\x00" * 16 + b"\x00\x00")
            elif behaviour == "bound_domain":
                c.sendall(b"\x05\x00\x00\x03\x05bound\x00\x00")
            else:
                c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            if behaviour == "stall_tls":
                # TLS completes, then the server says nothing at all
                stream = tls_ctx.wrap_socket(c, server_side=True)
                captured["tls_version"] = stream.version()
                time.sleep(4.0)
                return
            if behaviour != "electrum":
                return                           # leave the stream to the test
            stream = c
            if tls_ctx is not None:
                stream = tls_ctx.wrap_socket(c, server_side=True)
                captured["tls_version"] = stream.version()
            f = stream.makefile("rb")
            for raw in f:
                req = json.loads(raw.decode())
                captured["methods_asked"].append(req.get("method"))
                captured.setdefault("requests", []).append(req)
                if scenario.get("notify_before") and \
                        req.get("method") == "blockchain.headers.subscribe":
                    for _ in range(scenario["notify_before"]):
                        stream.sendall((json.dumps(
                            {"jsonrpc": "2.0",
                             "method": "blockchain.headers.subscribe",
                             "params": [{"height": scenario["tip"]}]})
                            + "\n").encode())
                stream.sendall(_electrum_reply(req, scenario).encode())
        except (OSError, ValueError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    captured["_thread"] = t
    return port, captured, srv


def _deadline(seconds=5.0):
    return time.monotonic() + seconds


def _handshake(*a):
    """(refused, message) for a _socks5_connect call against a mock. The
    module's own refusal is the only thing that counts as refused; a raw
    socket error is reported and counts as NOT refused, so one peer-close
    can never kill this file and silently disarm every check after it."""
    try:
        W._socks5_connect(*a).close()
        return False, ""
    except W.BtcWatchError as e:
        return True, str(e)
    except OSError as e:
        print("       (raw socket error, not a refusal:",
              type(e).__name__ + ")")
        return False, type(e).__name__


_port, _cap, _srv = _mock_socks("ok")
try:
    _s = W._socks5_connect("deposit.example.onion", 50002, "127.0.0.1", _port,
                           "isotag123", "x", _deadline())
    _s.close()
    _ok = True
except Exception as _e:                                      # noqa: BLE001
    _ok = False
finally:
    _srv.close()
check("the handshake completes and returns a socket", _ok)
check("...offering exactly ONE method, username/password, as SOCKS5",
      _cap.get("greeting_ver") == 5 and _cap.get("methods") == [2])
check("...the isolation tag was sent as the SOCKS username (RFC 1929 v1)",
      _cap.get("auth_ver") == 1 and _cap.get("user") == "isotag123"
      and _cap.get("password") == "x")
check("...the destination went as a DOMAIN name (resolved at the proxy, no "
      "local DNS), by CONNECT", _cap.get("cmd") == 1 and _cap.get("atyp") == 3
      and _cap.get("dest_host") == "deposit.example.onion")
check("...to the right port", _cap.get("dest_port") == 50002)

_port, _cap, _srv = _mock_socks("ok")
try:
    _s = W._socks5_connect("h.onion", 1, "127.0.0.1", _port, "", "",
                           _deadline())
    _s.close()
    _ok = True
except Exception:                                            # noqa: BLE001
    _ok = False
finally:
    _srv.close()
check("with no credential at all the greeting offers no-auth only, and the "
      "handshake still completes", _ok and _cap.get("methods") == [0])

_port, _cap, _srv = _mock_socks("method_none")
_rej, _msg = _handshake("h.onion", 50002, "127.0.0.1", _port, "u", "p",
                        _deadline())
_cap["_thread"].join(3.0)
_srv.close()
check("a proxy that answers 'no auth' to an offer of username/password is "
      "REFUSED -- a stream with no isolation is never used",
      _rej and "isolation" in _msg)
check("...and NOTHING was sent on that un-isolated stream afterwards (the "
      "mock recorded what came next: nothing)",
      "after_downgrade" in _cap and _cap["after_downgrade"] == b"")

for _b, _why, _text in (
        ("method_ff", "no acceptable method", "isolation"),
        ("ver4", "not a SOCKS5 proxy", "not a SOCKS5"),
        ("auth_reject", "auth rejected", "auth rejected"),
        ("auth_badver", "auth reply with a bad version byte", "bad auth"),
        ("connect_refuse", "CONNECT refused", "CONNECT refused"),
        ("close_early", "stream closed mid-frame", "closed mid-frame")):
    _port, _cap, _srv = _mock_socks(_b)
    _r, _msg = _handshake("h.onion", 50002, "127.0.0.1", _port, "u", "p",
                          _deadline())
    _srv.close()
    check(f"{_why}: a loud failure with the module's own reason, not a "
          f"silent direct connect", _r and _text in _msg)

for _b in ("bound_v6", "bound_domain"):
    _port, _cap, _srv = _mock_socks(_b)
    try:
        W._socks5_connect("h.onion", 50002, "127.0.0.1", _port, "u", "p",
                          _deadline()).close()
        _ok = True
    except Exception:                                        # noqa: BLE001
        _ok = False
    _srv.close()
    check(f"a CONNECT reply with a {_b[6:]} bound address is consumed "
          f"correctly", _ok)

# THE TRICKLE. One byte per 0.25 s never trips a per-read timeout of 0.6 s,
# and the mock keeps dripping a VALID handshake for ten seconds -- so a
# client without a deadline would complete it at ~3.5 s and return a
# socket. Only the client's own deadline can produce a refusal under 1 s.
_port, _cap, _srv = _mock_socks("drip")
_t0 = time.monotonic()
_r, _msg = _handshake("h.onion", 50002, "127.0.0.1", _port, "u", "p",
                      time.monotonic() + 0.6)
_el = time.monotonic() - _t0
_srv.close()
check("a proxy that trickles one byte at a time is cut off at the DEADLINE "
      f"by the module's own clock (refused after {_el:.2f}s with its own "
      "reason, not held open)",
      _r and _el < 1.0 and "deadline exceeded" in _msg)

check("a destination port out of range is refused BEFORE any connection, "
      "through the module's own error", all(
          _refused(W._socks5_connect, "h.onion", p, "127.0.0.1", 1, "u", "p",
                   _deadline()) for p in (0, 65536, -1)))
check("an empty password with a username is refused (RFC 1929: PLEN 1..255)",
      _refused(W._socks5_connect, "h.onion", 1, "127.0.0.1", 1, "u", "",
               _deadline()))
check("a destination host over 255 bytes is refused before connecting",
      _refused(W._socks5_connect, "h" * 256, 1, "127.0.0.1", 1, "u", "p",
               _deadline()))
check("a deadline already passed is refused before connecting",
      _refused(W._socks5_connect, "h.onion", 1, "127.0.0.1", 1, "u", "p",
               time.monotonic() - 1))
check("a proxy that is not listening is an OSError (the failover kind)",
      _raises(W._socks5_connect, OSError, "h.onion", 1, "127.0.0.1", 1,
              "u", "p", _deadline()))


# ===========================================================================
print("\n== the transport's line framing, on a fake socket ==")


class _ChunkSock:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""
        self.timeouts = []
        self.closed = False

    def settimeout(self, t):
        self.timeouts.append(t)

    def recv(self, n):
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, b):
        self.sent += b

    def close(self):
        self.closed = True


def _transport(chunks, deadline=None):
    t = W.SocksTlsTransport("h.onion", 50002, _PROXY, "btcwatch:x", tls=False)
    t._sock = _ChunkSock(chunks)
    t._deadline = deadline if deadline is not None else _deadline()
    return t


_t = _transport([b'{"a"', b":1}\n{", b'"b":2}\n'])
check("a line split across reads, and two lines in one read, both frame "
      "correctly", _t.recv_line() == '{"a":1}' and _t.recv_line() == '{"b":2}')
check("...and the clock was re-armed from the deadline before each of the "
      "three reads it took", len(_t._sock.timeouts) == 3
      and all(0 < x <= 5 for x in _t._sock.timeouts))
_t = _transport([b"x" * 65536] * 40)
check("a line that never ends is cut off at MAX_LINE_BYTES",
      _refused(_t.recv_line))
_t = _transport([b"{}\n"] * 3)
_t._received = W.MAX_SESSION_BYTES - 1
check("a server that has sent MAX_SESSION_BYTES in one exchange is cut off, "
      "however well-formed its lines", _refused(_t.recv_line))
_t = _transport([])
check("a connection closed mid-line is a loud failure", _refused(_t.recv_line))
_t = _transport([b"late\n"], deadline=time.monotonic() - 1)
check("a deadline that has passed refuses the read before it happens",
      _refused(_t.recv_line))
_t = _transport([])
_t.send_line('{"m":1}')
check("send_line frames with a newline", _t._sock.sent == b'{"m":1}\n')
_t = _transport([b"\xff\xfe\n"])
check("undecodable bytes become a replaced-character line, not a crash",
      _t.recv_line() == "\ufffd\ufffd")
_t = _transport([])
_sk = _t._sock
_t.close()
_t.close()
check("close() closes the socket, forgets it, and is idempotent",
      _sk.closed and _t._sock is None)
check("an unconnected transport refuses to speak",
      _refused(W.SocksTlsTransport("h", 1, _PROXY, "t").send_line, "x")
      and _refused(W.SocksTlsTransport("h", 1, _PROXY, "t").recv_line))


# ===========================================================================
print("\n== END TO END: real transport + real client, through the mock proxy "
      "to an in-process Electrum server ==")

_SCEN = {"tip": _TIP, "utxos": [_u(_TIP - 2, 700000)]}


def _e2e(scenario, *, tls_ctx=None, min_conf=1, timeout=5.0, pin=None):
    port, cap, srv = _mock_socks("electrum", scenario, tls_ctx=tls_ctx)
    proxy = f"socks5h://127.0.0.1:{port}"

    def factory(host, p, tag):
        cap["tag"] = tag
        return W.SocksTlsTransport(host, p, proxy, tag,
                                   tls=tls_ctx is not None, timeout=timeout,
                                   pin=pin)
    try:
        r = W.look(_A0, [("watch.example.onion", 50002)], proxy,
                   min_conf=min_conf, transport_factory=factory)
    finally:
        srv.close()
    return r, cap


_r, _cap = _e2e(_SCEN, min_conf=3)
check("plaintext end to end: the real SOCKS5 handshake, then the real client "
      "asks and gets 'confirmed' with the right figures",
      _r["state"] == "confirmed" and _r["settled_sat"] == 700000
      and _r["confirmations"] == 3 and _r["tip"] == _TIP
      and _r["server"] == "watch.example.onion")
check("...the destination reached the proxy as a domain name",
      _cap.get("atyp") == 3 and _cap.get("dest_host") == "watch.example.onion"
      and _cap.get("dest_port") == 50002)
check("...on a circuit credential derived from the address tag",
      _cap.get("user") == W._socks_parts(_PROXY, _cap["tag"])[2]
      and _A0 in _cap["tag"])
check("...every request carried the JSON-RPC 2.0 member and an id",
      all(q.get("jsonrpc") == "2.0" and isinstance(q.get("id"), int)
          for q in _cap.get("requests", [])) and _cap.get("requests"))
check("...and the server was asked ONLY the three read-only methods, "
      "in order: version, tip, listunspent -- nothing that could spend "
      "(a fourth, estimatefee, only when a fee target is asked for)",
      _cap["methods_asked"] == ["server.version",
                                "blockchain.headers.subscribe",
                                "blockchain.scripthash.listunspent"])
check("...announcing a stock wallet's version string, not a bare badge",
      _cap["requests"][0]["params"] == [W.CLIENT_NAME, "1.4"]
      and W.CLIENT_NAME.startswith("electrum/") and "." in W.CLIENT_NAME)
check("...and a plaintext session reports no certificate",
      _r["cert_sha256"] is None)

_r, _cap = _e2e({"tip": _TIP, "utxos": [_u(_TIP - 2, 700000)],
                 "notify_before": 3})
check("three subscription notifications interleaved before the tip reply "
      "are skipped, not mistaken for the answer",
      _r["state"] == "confirmed" and _r["tip"] == _TIP)


def _e2e_fee(scenario, fee_blocks):
    port, cap, srv = _mock_socks("electrum", scenario)
    proxy = f"socks5h://127.0.0.1:{port}"
    try:
        r = W.look(_A0, [("watch.example.onion", 50002)], proxy,
                   fee_blocks=fee_blocks,
                   transport_factory=lambda h, p, t: W.SocksTlsTransport(
                       h, p, proxy, t, tls=False, timeout=5.0))
    finally:
        srv.close()
    return r, cap


_r, _cap = _e2e_fee({"tip": _TIP, "utxos": [_u(_TIP - 2, 700000)],
                     "fee": 0.00015}, 2)
check("end to end with a fee target: four read-only methods, the estimate "
      "converted to 15 sat/vB, the look unchanged",
      _cap["methods_asked"] == ["server.version",
                                "blockchain.headers.subscribe",
                                "blockchain.scripthash.listunspent",
                                "blockchain.estimatefee"]
      and _cap["requests"][-1]["params"] == [2]
      and _r["fee_sat_vb"] == 15 and _r["state"] == "confirmed")

# TLS: the same, wrapped. A throwaway self-signed certificate lives here so
# the test needs no binary and no network; it signs nothing but this test.
_CERT = """-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIUDJRNtLwkLwZf7LiAeFsSb1QGZOIwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAgFw0yNjA5MDcxMjE3MzVaGA8yMTI2MDgxNDEyMTcz
NVowDzENMAsGA1UEAwwEdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLL+
8FOfUNx6Wb0wNEL5AMErj37LWDte4iePjiTiZJJ5nn3K/6ASgc/8yxid7tf/eaOg
czBRfRAWvo8ajre2PaCjUzBRMB0GA1UdDgQWBBSaCWiY15FNripajzLhwREtwUXa
3TAfBgNVHSMEGDAWgBSaCWiY15FNripajzLhwREtwUXa3TAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQDlzYSszz/pDduksVN8OJP8Uq2Uxk8f0jzl
oBJYqtMHQwIgd1IPLkFTBJ/zddKG/Q3yvxIxDaN/S/6nLfMw7Dbiumo=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn49cpPD0RG7XY+kl
IT1dHKG9k01uZw1A+YoscdQwNKyhRANCAASy/vBTn1Dcelm9MDRC+QDBK49+y1g7
XuInj44k4mSSeZ59yv+gEoHP/MsYne7X/3mjoHMwUX0QFr6PGo63tj2g
-----END PRIVATE KEY-----
"""
_cert_path = os.path.join(tempfile.mkdtemp(prefix="gs_btcw_"), "tls.pem")
with open(_cert_path, "w") as _fh:
    _fh.write(_CERT)
_sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
_sctx.load_cert_chain(_cert_path)
_CERT_SHA256 = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
    _CERT.split("-----END CERTIFICATE-----")[0]
    + "-----END CERTIFICATE-----\n")).hexdigest()
_r, _cap = _e2e(_SCEN, tls_ctx=_sctx, min_conf=1)
check("TLS end to end: SOCKS5, then TLS to a self-signed server, then the "
      "client -- confirmed, with the right figures",
      _r["state"] == "confirmed" and _r["settled_sat"] == 700000)
check("...and the session was TLS 1.2 or newer",
      _cap.get("tls_version") in ("TLSv1.2", "TLSv1.3"))
check("...and the result carries the certificate's SHA-256, so a caller can "
      "record it once and pin from then on",
      _r["cert_sha256"] == _CERT_SHA256)
_r, _cap = _e2e(_SCEN, tls_ctx=_sctx, min_conf=1, pin=_CERT_SHA256)
check("with the RIGHT pin the session completes",
      _r["state"] == "confirmed" and _r["cert_sha256"] == _CERT_SHA256)
_r, _cap = _e2e(_SCEN, tls_ctx=_sctx, pin="sha256:" + _CERT_SHA256.upper())
check("...however the pin is spelled", _r["state"] == "confirmed")
_wrong = "00" * 32
_port, _cap, _srv = _mock_socks("electrum", _SCEN, tls_ctx=_sctx)
_proxy = f"socks5h://127.0.0.1:{_port}"
try:
    W.look(_A0, [("watch.example.onion", 50002)], _proxy,
           transport_factory=lambda h, p, t: W.SocksTlsTransport(
               h, p, _proxy, t, tls=True, timeout=5.0, pin=_wrong))
    _pinned = False
    _pmsg = ""
except W.BtcWatchError as _e:
    _pinned = True
    _pmsg = str(_e)
finally:
    _srv.close()
check("with a WRONG pin the certificate is refused and look() fails loudly: "
      "an exit terminating TLS itself would be caught", _pinned)
check("...and neither fingerprint is in the error (a fact about what an "
      "attacker presented would otherwise travel with the log)",
      _CERT_SHA256 not in _pmsg and _wrong not in _pmsg)
check("...and the mock server was never asked a question over that session",
      _cap["methods_asked"] == [])
check("a malformed pin is refused before any connection",
      _refused(W.SocksTlsTransport, "h", 1, _PROXY, "t", pin="abc"))

# THE OPERATOR'S ROUTE: no factory. The pin travels from the (host, port,
# pin) server entry through look() into the real transport. Every check
# above injected its own transport; this is the wiring a real caller uses.
_port, _cap, _srv = _mock_socks("electrum", _SCEN, tls_ctx=_sctx)
_proxy = f"socks5h://127.0.0.1:{_port}"
try:
    _r = W.look(_A0, [("watch.example.onion", 50002, _CERT_SHA256)], _proxy,
                min_conf=3, timeout=5.0)
finally:
    _srv.close()
check("WITHOUT a factory: the pin in a (host, port, pin) entry reaches the "
      "real transport, TLS is on by default, and the right pin completes",
      _r["state"] == "confirmed" and _r["cert_sha256"] == _CERT_SHA256
      and _cap.get("tls_version") in ("TLSv1.2", "TLSv1.3")
      and _cap["methods_asked"] == ["server.version",
                                    "blockchain.headers.subscribe",
                                    "blockchain.scripthash.listunspent"])
_port, _cap, _srv = _mock_socks("electrum", _SCEN, tls_ctx=_sctx)
_proxy = f"socks5h://127.0.0.1:{_port}"
try:
    _pmsg = _errtext(W.look, _A0, [("watch.example.onion", 50002, _wrong)],
                     _proxy, timeout=5.0)
finally:
    _srv.close()
check("...and the WRONG pin in the entry is refused by look() itself, with "
      "the module's reason, the server asked nothing",
      _pmsg is not None and "does not match the pin" in _pmsg
      and _cap["methods_asked"] == [])
_port, _cap, _srv = _mock_socks("electrum", _SCEN, tls_ctx=_sctx)
_proxy = f"socks5h://127.0.0.1:{_port}"
try:
    _is_pin = _raises(W.look, W.PinMismatch, _A0,
                      [("watch.example.onion", 50002, _wrong)], _proxy,
                      timeout=5.0)
finally:
    _srv.close()
check("...raised as PinMismatch, the subclass a caller can single out from "
      "an ordinary dead-server failure", _is_pin)

# the deadline reaches the real transport from look()'s timeout argument:
# a server that completes TLS and then says nothing is cut off at ~1 s.
_port, _cap, _srv = _mock_socks("stall_tls", _SCEN, tls_ctx=_sctx)
_proxy = f"socks5h://127.0.0.1:{_port}"
_t0 = time.monotonic()
try:
    _smsg = _errtext(W.look, _A0, [("watch.example.onion", 50002)], _proxy,
                     timeout=1.0)
finally:
    _el = time.monotonic() - _t0
    _srv.close()
check("WITHOUT a factory: look()'s timeout is the real transport's deadline "
      f"-- a server that goes silent after TLS is cut off (after {_el:.2f}s)",
      _smsg is not None and "deadline exceeded" in _smsg and _el < 2.5)
_ctx = W._tls_context()
check("the TLS context floors at 1.2 and does no authority verification "
      "(the pin is the authentication)",
      _ctx.minimum_version == ssl.TLSVersion.TLSv1_2
      and _ctx.verify_mode == ssl.CERT_NONE and not _ctx.check_hostname)
os.remove(_cert_path)

# a server that hangs up straight after the SOCKS handshake, via the real
# transport: look() reports 'no server answered', never a state.
_port, _cap, _srv = _mock_socks("ok")
_proxy = f"socks5h://127.0.0.1:{_port}"
check("through the real transport, a server that says nothing is a loud "
      "failure of look(), not an invented state",
      _refused(W.look, _A0, [("h.onion", 50002)], _proxy,
               transport_factory=lambda h, p, t: W.SocksTlsTransport(
                   h, p, _proxy, t, tls=False, timeout=2.0)))
_srv.close()


# ===========================================================================
print("\n== the Electrum client and look(), against a fake transport ==")


class _FakeTransport:
    """Speaks the Electrum line protocol from a fixed tip and utxo set.
    Knobs reproduce every way a server can misbehave."""

    def __init__(self, *, tip=_TIP, utxos=(), connect_error=None,
                 notify=0, raw=None, tip_reply=None, unspent_reply=None,
                 version_error=False, drop_after=None, fee_reply=-1):
        self.tip = tip
        self.fee_reply = fee_reply
        self.utxos = list(utxos)
        self.connect_error = connect_error
        self.notify = notify
        self.raw = raw or {}                     # method -> raw line override
        self.tip_reply = tip_reply
        self.unspent_reply = unspent_reply
        self.version_error = version_error
        self.drop_after = drop_after             # method after which it dies
        self.queue = []
        self.methods = []
        self.requests = []
        self.connected = False
        self.closed = False

    def connect(self):
        if self.connect_error:
            raise self.connect_error
        self.connected = True

    def send_line(self, line):
        req = json.loads(line)
        self.requests.append(req)
        i, m = req.get("id"), req.get("method")
        self.methods.append(m)
        if m in self.raw:
            v = self.raw[m]
            self.queue.extend(v if isinstance(v, list) else [v])
            return
        if m == "server.version":
            if self.version_error:
                self.queue.append(json.dumps(
                    {"jsonrpc": "2.0", "id": i,
                     "error": {"code": 1, "message": "unsupported"}}))
                return
            res = ["ElectrumX 1.16.0", "1.4"]
        elif m == "blockchain.headers.subscribe":
            for _ in range(self.notify):
                self.queue.append(json.dumps(
                    {"jsonrpc": "2.0",
                     "method": "blockchain.headers.subscribe",
                     "params": [{"height": self.tip}]}))
            res = (self.tip_reply if self.tip_reply is not None
                   else {"height": self.tip, "hex": "00"})
        elif m == "blockchain.scripthash.listunspent":
            res = (self.unspent_reply if self.unspent_reply is not None
                   else self.utxos)
        elif m == "blockchain.estimatefee":
            res = self.fee_reply
        else:
            self.queue.append(json.dumps({"jsonrpc": "2.0", "id": i,
                                          "error": "unknown method"}))
            return
        self.queue.append(json.dumps({"jsonrpc": "2.0", "id": i,
                                      "result": res}))
        if self.drop_after == m:
            # a dropped connection stays dropped: nothing more ever arrives
            self.queue = []
            self.dead = True

    dead = False

    def recv_line(self):
        if self.dead or not self.queue:
            raise W.BtcWatchError("electrum: connection closed")
        return self.queue.pop(0)

    def close(self):
        self.closed = True


_SERVERS = [("s1.onion", 50002)]


def _one(ft):
    return lambda host, port, tag: ft


def _look(ft, **kw):
    return W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(ft), **kw)


_r = _look(_FakeTransport())
check("nothing on the address: not_seen, all zeros, an empty utxo list",
      _r["state"] == "not_seen" and _r["confirmed_sat"] == 0
      and _r["unconfirmed_sat"] == 0 and _r["settled_sat"] == 0
      and _r["confirmations"] == 0 and _r["utxos"] == [])
_r = _look(_FakeTransport(utxos=[_u(0, 500000)]))
check("money landed, in the mempool: seen, the unconfirmed amount, zero confs",
      _r["state"] == "seen" and _r["unconfirmed_sat"] == 500000
      and _r["settled_sat"] == 0 and _r["confirmations"] == 0)
_r = _look(_FakeTransport(utxos=[_u(_TIP - 1, 500000)]), min_conf=3)
check("two deep but three required: still seen, not confirmed, the depth "
      "exact", _r["state"] == "seen" and _r["confirmed_sat"] == 500000
      and _r["confirmations"] == 2 and _r["settled_sat"] == 0)
_r = _look(_FakeTransport(utxos=[_u(_TIP - 2, 500000)]), min_conf=3)
check("three deep and three required: confirmed, settled in full",
      _r["state"] == "confirmed" and _r["settled_sat"] == 500000
      and _r["confirmations"] == 3)
_r = _look(_FakeTransport(utxos=[_u(_TIP - 100, 1, _H, 0),
                                 _u(_TIP, 500000, _H2, 1)]), min_conf=3)
check("through look(): settled dust plus a fresh deposit -- settled_sat is "
      "the dust alone and the deposit's output is marked 1 deep",
      _r["settled_sat"] == 1 and _r["confirmations"] == 1
      and _r["utxos"][1]["confirmations"] == 1)
_r = _look(_FakeTransport(utxos=[_u(_TIP, 500000)], notify=1))
check("a subscription notification before the answer is skipped, not "
      "mistaken for the result", _r["state"] == "confirmed"
      and _r["confirmations"] == 1)
_r = _look(_FakeTransport(utxos=[_u(_TIP, 500000)],
                          notify=W.MAX_SKIPPED_LINES))
check("exactly MAX_SKIPPED_LINES notifications are tolerated",
      _r["state"] == "confirmed")
check("one more than MAX_SKIPPED_LINES notifications: the server is given up "
      "on -- it cannot stall the watcher by streaming frames",
      _refused(_look, _FakeTransport(utxos=[_u(_TIP, 500000)],
                                     notify=W.MAX_SKIPPED_LINES + 1)))
_r = _look(_FakeTransport(utxos=[_u(_TIP, 500000)], version_error=True))
check("a server that rejects server.version is still asked the real "
      "questions (the handshake is best effort)", _r["state"] == "confirmed")

for _label, _ft in [
        ("a non-JSON line", _FakeTransport(raw={
            "blockchain.headers.subscribe": "not json"})),
        ("a non-object frame", _FakeTransport(raw={
            "blockchain.headers.subscribe": "[1,2,3]"})),
        ("a line nested a hundred thousand deep (json raises "
         "RecursionError, not ValueError)", _FakeTransport(raw={
             "blockchain.headers.subscribe": "[" * 100000})),
        ("an error reply to our request", _FakeTransport(raw={
            "blockchain.scripthash.listunspent":
            '{"jsonrpc":"2.0","id":3,"error":{"code":1,"message":"no"}}'})),
        ("an error with a null id (the request itself rejected)",
         _FakeTransport(raw={"blockchain.headers.subscribe":
                             '{"jsonrpc":"2.0","id":null,"error":"bad"}'})),
        ("a tip reply that is not an object", _FakeTransport(tip_reply=7)),
        ("a tip height that is a string", _FakeTransport(
            tip_reply={"height": "800000"})),
        ("a tip height that is a bool", _FakeTransport(
            tip_reply={"height": True})),
        ("a listunspent reply that is an object", _FakeTransport(
            unspent_reply={"value": 5})),
        ("a listunspent entry with a string value", _FakeTransport(
            unspent_reply=[_u(1, "5")])),
        ("a listunspent entry with a bool value", _FakeTransport(
            unspent_reply=[_u(1, True)])),
        ("a connection dropped after the tip", _FakeTransport(
            drop_after="blockchain.headers.subscribe")),
        ("a connection dropped before anything", _FakeTransport(
            drop_after="server.version")),
]:
    check(f"{_label}: a loud failure through the module's error, never a "
          f"stray exception or an invented state", _refused(_look, _ft))


# failover: whichever server this address starts at, the first transport
# dies at connect and the second answers. (Which server is first is the
# address's own choice -- see the rotation checks below.)
_order = []


def _failover_factory(host, port, tag):
    _order.append(host)
    if len(_order) == 1:
        return _FakeTransport(connect_error=OSError("circuit died"))
    return _FakeTransport(utxos=[_u(_TIP - 1, 700000)])


_r = W.look(_A0, [("x.onion", 50002), ("y.onion", 50002)], _PROXY,
            transport_factory=_failover_factory)
check("a dead first server fails over to the live second one",
      _r["state"] == "confirmed" and len(_order) == 2
      and _r["server"] == _order[1] and _order[0] != _order[1]
      and _r["confirmed_sat"] == 700000)

_bad = _FakeTransport(unspent_reply=[_u(1, "5")])
_good = _FakeTransport(utxos=[_u(_TIP, 1)])
_order.clear()
_r = W.look(_A0, [("a.onion", 50002), ("b.onion", 50002)], _PROXY,
            transport_factory=lambda h, p, t: (_order.append(h),
                                               _bad if len(_order) == 1
                                               else _good)[1])
check("a server whose reply is malformed is failed over, and its transport "
      "was closed on the way out",
      _r["server"] == _order[1] and _bad.closed and _good.closed)

check("every server dead: look() raises, naming the last error",
      _raises(lambda: W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(
          _FakeTransport(connect_error=OSError("nope")))), W.BtcWatchError))
try:
    W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(
        _FakeTransport(connect_error=OSError("refused by 10.1.2.3:9050"))))
    _msg = ""
except W.BtcWatchError as _e:
    _msg = str(_e)
check("...by CLASS for a system error: the socket's own text (which can "
      "name a peer) never travels with it",
      "OSError" in _msg and "10.1.2.3" not in _msg
      and "refused by" not in _msg)
try:
    W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(_FakeTransport(
        raw={"blockchain.scripthash.listunspent":
             '{"jsonrpc":"2.0","id":3,"error":{"code":1,"message":'
             '"SECRET-TEXT-CHOSEN-BY-SERVER"}}'})))
    _msg = ""
except W.BtcWatchError as _e:
    _msg = str(_e)
check("a server's error is reported by its CODE only: text the server chose "
      "(ElectrumX echoes the scripthash there) never reaches the caller",
      "code 1" in _msg and "SECRET" not in _msg)
try:
    W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(_FakeTransport(
        raw={"blockchain.headers.subscribe":
             '{"jsonrpc":"2.0","id":null,"error":"SECRET-TEXT"}'})))
    _msg = ""
except W.BtcWatchError as _e:
    _msg = str(_e)
check("...and the same for a null-id rejection with a bare-string error",
      "code unknown" in _msg and "SECRET" not in _msg)
_big = int(_SCRIPTHASH, 16)
try:
    W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(_FakeTransport(
        raw={"blockchain.scripthash.listunspent":
             '{"jsonrpc":"2.0","id":3,"error":{"code":%d,"message":"x"}}'
             % _big})))
    _msg = ""
except W.BtcWatchError as _e:
    _msg = str(_e)
check("a 256-bit 'code' (the scripthash in base 10 -- a JSON integer is "
      "unbounded) is NOT passed through: only a 16-bit code is a code",
      "code unknown" in _msg and str(_big) not in _msg)
try:
    W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(_FakeTransport(
        raw={"blockchain.scripthash.listunspent":
             '{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"x"}}'}
    )))
    _msg = ""
except W.BtcWatchError as _e:
    _msg = str(_e)
check("...while a real JSON-RPC code (-32601) is reported",
      "code -32601" in _msg)
_r = _look(_FakeTransport(raw={"blockchain.scripthash.listunspent": [
    '{"jsonrpc":"2.0","id":2,"result":[]}',
    json.dumps({"jsonrpc": "2.0", "id": 3, "result": [_u(_TIP, 900)]})]}))
check("a reply carrying a STALE id (2) ahead of ours (3) is skipped, not "
      "taken as the answer: the client matches on its own id",
      _r["state"] == "confirmed" and _r["settled_sat"] == 900)
try:
    W.look(_A0, _SERVERS, _PROXY, transport_factory=_one(
        _FakeTransport(drop_after="blockchain.headers.subscribe")))
    _msg = ""
except W.BtcWatchError as _e:
    _msg = str(_e)
check("...while the module's OWN reason is repeated in full",
      "connection closed" in _msg)
check("no servers configured: refused up front",
      _refused(W.look, _A0, [], _PROXY, transport_factory=_one(
          _FakeTransport())))

_calls = []


def _counting(host, port, tag):
    _calls.append(host)
    return _FakeTransport()


check("a bad server spec (port 0) is refused BEFORE any connection is tried",
      _refused(W.look, _A0, [("a.onion", 50002), ("b.onion", 0)], _PROXY,
               transport_factory=_counting) and _calls == [])
check("a server spec that is not a pair is refused",
      _refused(W.look, _A0, ["a.onion:50002"], _PROXY,
               transport_factory=_counting) and _calls == [])
check("a server spec with a malformed pin is refused",
      _refused(W.look, _A0, [("a.onion", 50002, "nope")], _PROXY,
               transport_factory=_counting) and _calls == [])
check("a four-element server spec is refused",
      _refused(W.look, _A0, [("a.onion", 50002, None, 1)], _PROXY,
               transport_factory=_counting) and _calls == [])
for _mc in (0, -1, True, "1", 1.0):
    check(f"min_conf={_mc!r} is refused: an unconfirmed deposit is never "
          f"settled money", _refused(_look, _FakeTransport(), min_conf=_mc))
for _to in (float("inf"), float("nan"), "abc", None, 0, -1, True):
    check(f"timeout={_to!r} is refused up front through the module's error "
          f"(inf/nan used to escape from the socket layer)",
          _refused(W.look, _A0, _SERVERS, _PROXY, timeout=_to,
                   transport_factory=_counting))
check("timeout=1 (an int) is fine",
      W.look(_A0, _SERVERS, _PROXY, timeout=1,
             transport_factory=_one(_FakeTransport()))["state"] == "not_seen")
_bmsg = _errtext(W.look, _A0, [("a.onion", 50002), ("b.onion", 50002)],
                 "socks5h://u:p@127.0.0.1:9050", timeout=2.0)
check("without a factory, a proxy URL that can never work is ONE "
      "configuration refusal, not a failover per server",
      _bmsg is not None and "credential" in _bmsg
      and "no Electrum server answered" not in _bmsg)
check("a proxy host that is not a valid hostname (IDNA) is a refusal "
      "through the module's error, not a UnicodeError from the resolver",
      _refused(W.look, _A0, _SERVERS, "socks5h://x..y:9050", timeout=2.0))


def _pin_then_good(host, port, tag):
    _calls.append(host)
    if len(_calls) == 1:
        return _FakeTransport(connect_error=W.PinMismatch("tls: pin"))
    return _FakeTransport()


_calls.clear()
check("a PIN MISMATCH on the first server is NOT absorbed by failover: "
      "look() raises it at once and the second server is never contacted "
      "(a detected interception is not a dead server to route around)",
      _raises(W.look, W.PinMismatch, _A0,
              [("a.onion", 50002), ("b.onion", 50002)], _PROXY,
              transport_factory=_pin_then_good) and len(_calls) == 1)
_calls.clear()
check("a testnet address looked up as mainnet is refused (never the wrong "
      "chain)", _refused(W.look, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
                         _SERVERS, _PROXY, transport_factory=_counting))
check("...and it is accepted when the network says testnet",
      W.look("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", _SERVERS, _PROXY,
             network="testnet", transport_factory=_one(_FakeTransport()))
      ["state"] == "not_seen")
check("a legacy (non-segwit) address is refused by look(): it is not a kind "
      "this module ever derives", _refused(
          W.look, "1BitcoinEaterAddressDontSendf59kuE", _SERVERS, _PROXY,
          transport_factory=_counting))
_TAPROOT = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
check("a taproot (bc1p, witness v1) address is refused by look() for the "
      "same reason, even though it is valid bech32m on this network",
      bech32.decode("bc", _TAPROOT)[0] == 1
      and _refused(W.look, _TAPROOT, _SERVERS, _PROXY,
                   transport_factory=_counting))
check("a P2WSH (bc1q, 32-byte) address is refused by look() too",
      _refused(W.look, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q"
               "ccfmv3", _SERVERS, _PROXY, transport_factory=_counting))
check("an unknown network is refused by look()",
      _refused(W.look, _A0, _SERVERS, _PROXY, network="mars",
               transport_factory=_counting))
check("NON-VACUITY: none of those refusals reached the transport",
      _calls == [])

_tags = []


def _tag_factory(host, port, tag):
    _tags.append(tag)
    return _FakeTransport()


W.look(_addrs[0], _SERVERS, _PROXY, transport_factory=_tag_factory)
W.look(_addrs[1], _SERVERS, _PROXY, transport_factory=_tag_factory)
W.look(_addrs[0], _SERVERS, _PROXY, transport_factory=_tag_factory)
check("look() isolates each address on its own circuit tag: the address is "
      "in the tag, two addresses give two tags, a retry gives the same tag",
      _addrs[0] in _tags[0] and _tags[0] != _tags[1] and _tags[0] == _tags[2])

_seen = []


def _seen_factory(host, port, tag):
    _seen.append((host, tag))
    if host == "dead.onion":
        return _FakeTransport(connect_error=OSError("down"))
    return _FakeTransport()


def _first_dies_factory(host, port, tag):
    _seen.append((host, tag))
    if len(_seen) == 1:
        return _FakeTransport(connect_error=OSError("down"))
    return _FakeTransport()


W.look(_addrs[0], [("p.onion", 50002), ("q.onion", 50002)], _PROXY,
       transport_factory=_first_dies_factory)
check("within ONE look(), the failover server is reached on the SAME "
      "circuit tag as the dead one: a retry is not a new fact to leak",
      len(_seen) == 2 and _seen[0][1] == _seen[1][1]
      and _seen[0][0] != _seen[1][0]
      and _seen[0][1] == "btcwatch:" + _addrs[0])

# no single server sees every address: the starting server is chosen by
# the address's own scripthash, and every server is still tried on failure.
_THREE = [("a.onion", 50002), ("b.onion", 50002), ("c.onion", 50002)]
_by_start = {}
for _a in _addrs:
    _by_start.setdefault(
        int(W.address_to_scripthash(_a)[:8], 16) % 3, _a)
_firsts = {}
for _start, _a in sorted(_by_start.items()):
    _seen.clear()
    W.look(_a, _THREE, _PROXY, transport_factory=_seen_factory)
    _firsts[_start] = _seen[0][0]
check("with three servers configured, addresses start at different servers "
      f"(seen: {sorted(_firsts.values())}) -- one third party never gets "
      "the whole set", len(set(_firsts.values())) == 3
      and _firsts == {0: "a.onion", 1: "b.onion", 2: "c.onion"})
_seen.clear()
_refused(W.look, _addrs[5], [("dead.onion", 1), ("dead.onion", 2),
                             ("dead.onion", 3)], _PROXY,
         transport_factory=_seen_factory)
check("...and rotation is a rotation, not a truncation: every server is "
      "still tried when all are dead", len(_seen) == 3)

_ft = _FakeTransport(utxos=[_u(_TIP, 1)])
_look(_ft)
check("the transport is connected, asked exactly the three read-only "
      "methods with JSON-RPC 2.0 framing and increasing ids, and closed",
      _ft.connected and _ft.closed
      and _ft.methods == ["server.version", "blockchain.headers.subscribe",
                          "blockchain.scripthash.listunspent"]
      and [q["id"] for q in _ft.requests] == [1, 2, 3]
      and all(q["jsonrpc"] == "2.0" for q in _ft.requests))
check("...and listunspent was asked about THIS address's scripthash",
      _ft.requests[2]["params"] == [_SCRIPTHASH])
_ft = _FakeTransport(drop_after="server.version")
_refused(_look, _ft)
check("a transport is closed even when the exchange fails", _ft.closed)

# THE FOURTH METHOD, asked only when the caller wants a fee estimate: still
# read-only, still the same session and circuit as the look itself.
_ft = _FakeTransport(utxos=[_u(_TIP, 1)], fee_reply=0.00002)
_r = _look(_ft, fee_blocks=3)
check("with fee_blocks set, the SAME session also asks blockchain.estimatefee "
      "(one circuit, one fact fewer to leak) and reports it in sat/vB, "
      "rounded up", _ft.methods[-1] == "blockchain.estimatefee"
      and _ft.requests[-1]["params"] == [3] and _r["fee_sat_vb"] == 2
      and len(_ft.methods) == 4)
check("...and the result key is absent when no fee was asked for",
      "fee_sat_vb" not in _look(_FakeTransport()))
check("Electrum's -1 ('no estimate') is None, never 0 and never a refusal "
      "of the look itself: the caller decides",
      _look(_FakeTransport(fee_reply=-1), fee_blocks=3)["fee_sat_vb"] is None)
check("a junk fee reply (string, dict, bool) is None too",
      all(_look(_FakeTransport(fee_reply=v), fee_blocks=3)["fee_sat_vb"]
          is None for v in ("abc", {"x": 1}, True)))
check("fee_blocks out of range is refused up front",
      all(_refused(_look, _FakeTransport(), fee_blocks=v)
          for v in (0, 1009, True, "3", 1.0)))
check("the client's own estimate_fee refuses a bad target before asking",
      _refused(W.Electrum(_FakeTransport()).estimate_fee, 0))

# The default (no factory) path builds the real transport with the caller's
# timeout and the proxy, and a dead proxy is a loud look() failure.
_dead = socket.socket()
_dead.bind(("127.0.0.1", 0))
_dead_port = _dead.getsockname()[1]
_dead.close()
check("without a factory, look() builds the real Tor transport; a proxy that "
      "is not there is a loud failure, not a direct connection",
      _refused(W.look, _A0, _SERVERS, f"socks5h://127.0.0.1:{_dead_port}",
               timeout=2.0))
check("...and a proxy URL with a credential is refused there too",
      _refused(W.look, _A0, _SERVERS, "socks5h://u:p@127.0.0.1:9050",
               timeout=2.0))


# ===========================================================================
print("\n== the manual dry-run ==")
_out = io.StringIO()
with redirect_stdout(_out):
    _rc = W._main(["--xpub", _ACCT_XPUB, "--index", "1"])
check("derive-only: prints the address and scripthash, asks nobody, exits 0",
      _rc == 0 and "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" in _out.getvalue()
      and W.address_to_scripthash(
          "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g") in _out.getvalue()
      and "derived only" in _out.getvalue())
_out = io.StringIO()
with redirect_stdout(_out):
    _rc = W._main(["--xpub", _ACCT_TPUB, "--index", "0", "--network",
                   "testnet"])
check("derive-only on testnet prints the tb1 address",
      _rc == 0 and "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
      in _out.getvalue())
check("a bad xpub on the command line fails loudly",
      _refused(W._main, ["--xpub", "junk", "--index", "0"]))
_out = io.StringIO()
with redirect_stdout(_out):
    _r = _refused(W._main, ["--xpub", _ACCT_XPUB, "--index", "0",
                            "--electrum", "s.onion",
                            "--tor", f"socks5h://127.0.0.1:{_dead_port}",
                            "--timeout", "2"])
check("with a server named and no proxy there: the look fails loudly and "
      "prints no state", _r and "state:" not in _out.getvalue())

# ===========================================================================
print("\n== what the module must not be ==")
_src = open(os.path.join(REPO, "gs_btc_watch.py"), encoding="utf-8").read()
check("the module never speaks a method that could spend or broadcast",
      "transaction.broadcast" not in _src and "sendrawtransaction" not in _src
      and "blockchain.transaction." not in _src)
check("the module never touches a private key API",
      "from_seed" not in _src and "mnemonic" not in _src
      and ".sign(" not in _src and "PrivateKey" not in _src)
check("the module never writes the hash chain or a log",
      "integrity_log" not in _src and "import logging" not in _src
      and "open(" not in _src)
check("the module imports no third-party SOCKS or HTTP client (no PySocks, "
      "no requests): the framing is its own, so the dependency surface is",
      "import socks" not in _src and "import requests" not in _src)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
