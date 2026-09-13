#!/usr/bin/env python3
"""An in-process SOCKS5 proxy that goes on to speak Electrum, for the
broadcast-side suites (test_btc_broadcast, test_btc_forwarder).

The SOCKS5 half accepts username/password and CONNECT-by-domain, the way
the real transport speaks to Tor; the Electrum half answers server.version,
blockchain.transaction.broadcast and blockchain.scripthash.get_history from
a `scenario` dict. It can compute the REAL txid of the hex it is handed
("txid": "compute") and list it in the history ("history": "compute"), so
a whole forward -- sign, send, see -- can be driven through the real
transport, the real subclass and the real forwarder with no network.

Serves `connections` sessions in turn (a forward opens one to send and
one to look), each on a fresh accept.
"""
import hashlib
import json
import os
import socket
import ssl
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "third_party"))
from embit.transaction import Transaction                    # noqa: E402

# A throwaway self-signed certificate so a TLS session needs no binary and
# no network; it signs nothing but these tests.
TEST_CERT = """-----BEGIN CERTIFICATE-----
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


def tls_server_context():
    """(server SSLContext for TEST_CERT, its certificate's SHA-256 hex)."""
    path = os.path.join(tempfile.mkdtemp(prefix="gs_btcmock_"), "tls.pem")
    with open(path, "w") as fh:
        fh.write(TEST_CERT)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(path)
    os.remove(path)
    sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        TEST_CERT.split("-----END CERTIFICATE-----")[0]
        + "-----END CERTIFICATE-----\n")).hexdigest()
    return ctx, sha


def mock_socks(behaviour, scenario, tls_ctx=None, connections=1):
    """Returns (port, captured, server_socket). behaviour: "electrum" or
    "connect_refuse". `captured` fills with what the client sent."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(connections)
    port = srv.getsockname()[1]
    cap = {"methods_asked": [], "requests": [], "users": [], "sessions": 0}

    def _recvn(c, n):
        b = b""
        while len(b) < n:
            d = c.recv(n - len(b))
            if not d:
                raise OSError("closed")
            b += d
        return b

    def _txid_of(hex_tx):
        return Transaction.parse(bytes.fromhex(hex_tx)).txid().hex()

    def reply(req):
        i, m = req.get("id"), req.get("method")
        if m == "server.version":
            res = ["ElectrumX 1.16.0", "1.4"]
        elif m == "blockchain.transaction.broadcast":
            cap["hex"] = req["params"][0]
            if scenario.get("reject"):
                return json.dumps({"jsonrpc": "2.0", "id": i, "error": {
                    "code": scenario["reject"],
                    "message": "the transaction was rejected by network "
                               "rules.\n\nscriptpubkey\n" + cap["hex"]}}) + "\n"
            if scenario.get("hangup"):
                return None
            res = scenario.get("txid", "ab" * 32)
            if res == "compute":
                res = _txid_of(cap["hex"])
            cap["txid_answered"] = res
        elif m == "blockchain.scripthash.get_history":
            res = scenario.get("history", [])
            if res == "compute":
                res = ([{"tx_hash": _txid_of(cap["hex"]), "height": 0}]
                       if cap.get("hex") else [])
        else:
            return json.dumps({"jsonrpc": "2.0", "id": i, "error": {
                "code": -32601, "message": "unknown method"}}) + "\n"
        return json.dumps({"jsonrpc": "2.0", "id": i, "result": res}) + "\n"

    def one(c):
        try:
            c.settimeout(10)
            _ver, nm = _recvn(c, 2)
            methods = _recvn(c, nm)
            if 0x02 in methods:
                c.sendall(b"\x05\x02")
                _av, ul = _recvn(c, 2)
                cap["user"] = _recvn(c, ul).decode()
                cap["users"].append(cap["user"])
                pl = _recvn(c, 1)[0]
                _recvn(c, pl)
                c.sendall(b"\x01\x00")
            else:
                c.sendall(b"\x05\x00")
            head = _recvn(c, 4)
            if head[3] == 0x03:
                hl = _recvn(c, 1)[0]
                cap["dest_host"] = _recvn(c, hl).decode()
            cap["dest_port"] = int.from_bytes(_recvn(c, 2), "big")
            if behaviour == "connect_refuse":
                c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            stream = c
            if tls_ctx is not None:
                stream = tls_ctx.wrap_socket(c, server_side=True)
                cap["tls_version"] = stream.version()
            f = stream.makefile("rb")
            for raw in f:
                req = json.loads(raw.decode())
                cap["methods_asked"].append(req.get("method"))
                cap["requests"].append(req)
                out = reply(req)
                if out is None:
                    return                       # hang up mid-request
                stream.sendall(out.encode())
        except (OSError, ValueError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def serve():
        for _ in range(connections):
            try:
                srv.settimeout(10)
                c, _ = srv.accept()
            except OSError:
                return
            cap["sessions"] += 1
            one(c)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    cap["_thread"] = t
    return port, cap, srv
