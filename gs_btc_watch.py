#!/usr/bin/env python3
"""Watch-only Bitcoin intake for the Pi. It holds an xpub and never a key.

STAGE 1 of the BTC-intake rework (BTC_INTAKE_DESIGN.md). This runs on the Pi,
which is assumed seizable, so it carries NO spend key and can move NO money.
It does exactly two things:

  * DERIVE a fresh, unique deposit address per handle, by public BIP32
    derivation from an account xpub. A seized Pi learns the addresses it was
    going to watch and nothing else -- it cannot spend them, and it cannot
    derive a hardened child, so it can never reach the account key.
  * LOOK at one such address on the Bitcoin network -- has anything landed,
    is it confirmed -- by asking an Electrum server. It reads; it never
    writes a transaction.

OPSEC of the looking (BTC_INTAKE_DESIGN.md, rule 6):
  * Over Tor, always. `socks5h`, so DNS resolves at the proxy, never locally.
  * ONE FRESH CIRCUIT PER ADDRESS. The query -- "does scripthash X have a
    balance" -- is the fingerprint, not the IP; Tor hides who, not what. Each
    address is looked at on its own Tor circuit (gs_common.isolated_proxy's
    per-tag SOCKS credential, IsolateSOCKSAuth), so a server logging its
    queries cannot cluster this operator's addresses by circuit. Retries of
    one address reuse that address's circuit -- a retry is not a new fact.
  * Default is a public Electrum server over Tor; an operator who wants no
    third party at all points --electrum at their own node's server.
  * This module writes nothing to the hash chain: watching is frequent, and
    the deep-read pass already taught that a frequent path must not flood the
    card. The caller records state transitions, not polls.

Nothing here is a substitute for the forward, which SPENDS and is a woken vault
job (stage 2). This side only ever answers "did the money arrive".
"""
import hashlib
import json
import socket
import ssl
import struct
import sys
from pathlib import Path

# The one vendored crypto dependency. Pure-Python derivation is correct and
# side-channel-free HERE because there is no secret: an xpub is public.
sys.path.insert(0, str(Path(__file__).resolve().parent / "third_party"))
from embit import bip32, script                              # noqa: E402
from embit.networks import NETWORKS                          # noqa: E402

from gs_common import isolated_proxy                         # noqa: E402

#: Electrum's default TLS port. Plaintext is 50001; we default to TLS.
DEFAULT_ELECTRUM_PORT = 50002
#: Client identity sent in server.version. Deliberately generic -- a
#: distinctive name would fingerprint across circuits.
CLIENT_NAME = "electrum"
PROTOCOL_VERSION = "1.4"
#: A hard cap on a single server response, so a hostile or broken server
#: cannot make this read grow without bound.
MAX_LINE_BYTES = 2 * 1024 * 1024

#: The hardened bit. A public key can derive only NON-hardened children; the
#: derivation below refuses anything else so a bad index can never be a silent
#: wrong address (or an attempt to walk toward the account key).
_HARDENED = 0x80000000

#: Accepted network names -> embit's own keys.
_NET = {"main": "main", "mainnet": "main",
        "test": "test", "testnet": "test",
        "regtest": "regtest", "signet": "signet"}


class BtcWatchError(Exception):
    """A watch could not be completed. Never carries key material."""


# --- derivation: pure, no network, no secret --------------------------------

def _network(name: str) -> dict:
    key = _NET.get(str(name).lower())
    if key is None:
        raise BtcWatchError(f"unknown network {name!r}")
    return NETWORKS[key]


def derive_receive_address(account_xpub: str, index: int,
                           network: str = "main", change: int = 0) -> str:
    """The deposit address at m/<change>/<index> under an account xpub.

    `account_xpub` is the PUBLIC key at the account level (m/84'/0'/0' for
    native segwit); the Pi holds only this. Derivation is public and
    non-hardened, so it never needs -- and never reaches -- a secret.
    """
    if not isinstance(index, int) or isinstance(index, bool) or index < 0 \
            or index >= _HARDENED:
        raise BtcWatchError("index must be a non-negative, non-hardened int")
    if change not in (0, 1):
        raise BtcWatchError("change must be 0 (receive) or 1 (change)")
    try:
        hd = bip32.HDKey.from_base58(account_xpub)
    except Exception as e:                                   # noqa: BLE001
        raise BtcWatchError(f"not a usable account xpub: {type(e).__name__}")
    if hd.key.is_private:
        # Handed an xPRV where an xPUB belongs: refuse, do not quietly accept a
        # secret onto the watch-only box.
        raise BtcWatchError("an account xPUB is required here, not an xPRV")
    pub = hd.derive(f"m/{int(change)}/{int(index)}").get_public_key()
    return script.p2wpkh(pub).address(_network(network))


def address_to_scripthash(address: str) -> str:
    """The Electrum scripthash for an address: sha256(scriptPubKey), reversed.

    Raises on an address embit cannot turn into a scriptPubKey, so a mistyped
    or wrong-network address is a loud failure here, not a watch that silently
    matches nothing for ever.
    """
    try:
        spk = script.address_to_scriptpubkey(address).data
    except Exception as e:                                   # noqa: BLE001
        raise BtcWatchError(f"not a usable address: {type(e).__name__}")
    return hashlib.sha256(spk).digest()[::-1].hex()


# --- SOCKS5 over Tor: a small framing protocol, hand-rolled, no dependency --

def _recvn(sock, n: int) -> bytes:
    """Read EXACTLY n bytes or raise. A short read is a broken stream, not a
    partial answer to interpret."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise BtcWatchError("socks: stream closed mid-frame")
        buf += chunk
    return buf


def _socks_parts(proxy_url: str, tag: str):
    """(host, port, user, password) for a Tor SOCKS proxy, with the SOCKS
    credential made unique to `tag` so this stream gets its own circuit.

    Reuses gs_common.isolated_proxy for the credential derivation (per-process
    salt, tag hashed, never logged), then unpacks its URL for a raw socket.
    """
    d = isolated_proxy(proxy_url, tag)
    url = d.get("http") or d.get("https")
    if not url:
        raise BtcWatchError("no Tor proxy configured")
    rest = url.split("://", 1)[1]
    cred, _, hostport = rest.rpartition("@")
    user, password = ("", "")
    if cred:
        user, _, password = cred.partition(":")
    host, _, port = hostport.rpartition(":")
    try:
        return host, int(port), user, password
    except ValueError:
        raise BtcWatchError("malformed proxy address")


def _socks5_connect(dest_host: str, dest_port: int, proxy_host: str,
                    proxy_port: int, user: str, password: str,
                    timeout: float):
    """Open a TCP stream to dest through a SOCKS5 proxy, resolving the
    destination AT THE PROXY (socks5h). Username/password auth carries the
    per-address isolation tag. Returns a connected socket."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        s.settimeout(timeout)
        # Greeting. Offer user/pass auth when we have a credential (the normal
        # case: isolation needs it), else no-auth.
        if user:
            s.sendall(b"\x05\x01\x02")
        else:
            s.sendall(b"\x05\x01\x00")
        ver, method = _recvn(s, 2)
        if ver != 0x05:
            raise BtcWatchError("socks: not a SOCKS5 proxy")
        if method == 0x02:
            u = user.encode()
            p = (password or "").encode()
            if len(u) > 255 or len(p) > 255:
                raise BtcWatchError("socks: credential too long")
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            av, status = _recvn(s, 2)
            if status != 0x00:
                raise BtcWatchError("socks: auth rejected")
        elif method != 0x00:
            raise BtcWatchError("socks: no acceptable auth method")
        # CONNECT with a DOMAINNAME target (ATYP 0x03) => the proxy resolves
        # it. This is what socks5h means and it is why DNS never leaks locally.
        host_b = dest_host.encode()
        if len(host_b) > 255:
            raise BtcWatchError("socks: destination host too long")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
                  + struct.pack(">H", int(dest_port)))
        rep = _recvn(s, 4)
        if rep[1] != 0x00:
            raise BtcWatchError(f"socks: CONNECT refused (rep={rep[1]})")
        atyp = rep[3]
        if atyp == 0x01:
            _recvn(s, 4)
        elif atyp == 0x03:
            _recvn(s, _recvn(s, 1)[0])
        elif atyp == 0x04:
            _recvn(s, 16)
        else:
            raise BtcWatchError("socks: unknown bound-address type")
        _recvn(s, 2)                                          # bound port
        return s
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise


# --- the Electrum client: line JSON over the SOCKS+TLS stream ---------------

class Electrum:
    """A minimal, synchronous Electrum-protocol client. Read-only usage.

    Injectable: pass `connect` (a zero-argument callable returning a
    socket-like object) to drive it in a test without a real network. The
    default connect goes SOCKS5 -> TLS to a server over Tor.
    """

    def __init__(self, host: str, port: int, proxy_url: str, *, tag: str,
                 tls: bool = True, timeout: float = 30.0, connect=None):
        self._host = host
        self._port = int(port)
        self._proxy = proxy_url
        self._tag = tag
        self._tls = tls
        self._timeout = timeout
        self._connect = connect or self._default_connect
        self._sock = None
        self._buf = b""
        self._id = 0

    def _default_connect(self):
        ph, pp, user, password = _socks_parts(self._proxy, self._tag)
        raw = _socks5_connect(self._host, self._port, ph, pp, user, password,
                              self._timeout)
        if self._tls:
            # Electrum servers use self-signed certs and clients pin on first
            # use; here the channel's confidentiality is Tor and the data
            # (a public address's balance) is public anyway, so an unverified
            # TLS wrapper is the standard, correct choice -- it stops a Tor
            # exit or the server operator reading the scripthash in clear.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=None)
        return raw

    def __enter__(self):
        self._sock = self._connect()
        return self

    def __exit__(self, *_a):
        self.close()

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _rpc(self, method: str, params: list):
        self._id += 1
        want = self._id
        line = (json.dumps({"id": want, "method": method,
                            "params": params}) + "\n").encode()
        self._sock.sendall(line)
        # Read one whole line whose id matches ours, skipping any subscription
        # notification a server might interleave (those carry no matching id).
        while True:
            while b"\n" not in self._buf:
                chunk = self._sock.recv(4096)
                if not chunk:
                    raise BtcWatchError("electrum: connection closed")
                self._buf += chunk
                if len(self._buf) > MAX_LINE_BYTES:
                    raise BtcWatchError("electrum: response too large")
            raw, _, self._buf = self._buf.partition(b"\n")
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                raise BtcWatchError("electrum: non-JSON line")
            if not isinstance(obj, dict) or obj.get("id") != want:
                continue                                     # a notification
            if obj.get("error"):
                raise BtcWatchError(
                    f"electrum error: {str(obj['error'])[:120]}")
            return obj.get("result")

    def handshake(self):
        # Best effort: some servers require server.version first, some do not.
        try:
            self._rpc("server.version", [CLIENT_NAME, PROTOCOL_VERSION])
        except BtcWatchError:
            pass

    def tip_height(self) -> int:
        r = self._rpc("blockchain.headers.subscribe", [])
        if isinstance(r, dict) and isinstance(r.get("height"), int):
            return r["height"]
        raise BtcWatchError("electrum: no tip height")

    def get_balance(self, scripthash: str) -> dict:
        r = self._rpc("blockchain.scripthash.get_balance", [scripthash])
        if not isinstance(r, dict):
            raise BtcWatchError("electrum: bad get_balance")
        return {"confirmed": int(r.get("confirmed", 0) or 0),
                "unconfirmed": int(r.get("unconfirmed", 0) or 0)}

    def get_history(self, scripthash: str) -> list:
        r = self._rpc("blockchain.scripthash.get_history", [scripthash])
        if not isinstance(r, list):
            raise BtcWatchError("electrum: bad get_history")
        out = []
        for e in r:
            if isinstance(e, dict) and isinstance(e.get("height"), int):
                out.append({"tx_hash": str(e.get("tx_hash", "")),
                            "height": e["height"]})
        return out


# --- the answer the caller wants -------------------------------------------

#: The states look() reports. Deliberately about CURRENT funds on the address:
#: an address swept empty reads not_seen, which is the honest "nothing here".
STATE_NOT_SEEN = "not_seen"
STATE_SEEN = "seen"          # money has landed, not yet confirmed to min_conf
STATE_CONFIRMED = "confirmed"


def look(address: str, servers, proxy_url: str, *, min_conf: int = 1,
         network: str = "main", timeout: float = 30.0,
         connect_factory=None) -> dict:
    """Ask the network whether `address` has been paid, and how confirmed.

    `servers` is a list of (host, port); they are tried in order until one
    answers, so one dead server is not a dead watch. `connect_factory(host,
    port, tag)` may inject a transport for tests. Returns
        {state, confirmed_sat, unconfirmed_sat, confirmations, server}
    and NEVER raises for "not paid yet" -- only for "could not ask anyone".
    """
    scripthash = address_to_scripthash(address)
    tag = "btcwatch:" + address       # one circuit per address; see the header
    if not servers:
        raise BtcWatchError("no Electrum servers configured")
    if min_conf < 1:
        min_conf = 1
    last = None
    for host, port in servers:
        conn = None
        if connect_factory is not None:
            conn = connect_factory(host, port, tag)
        try:
            with Electrum(host, port, proxy_url, tag=tag, timeout=timeout,
                          connect=conn) as e:
                e.handshake()
                tip = e.tip_height()
                bal = e.get_balance(scripthash)
                hist = e.get_history(scripthash)
                confs = [tip - h["height"] + 1
                         for h in hist if h["height"] > 0]
                best = max(confs) if confs else 0
                confirmed = bal["confirmed"]
                unconfirmed = bal["unconfirmed"]
                if confirmed > 0 and best >= min_conf:
                    state = STATE_CONFIRMED
                elif confirmed > 0 or unconfirmed > 0:
                    state = STATE_SEEN
                else:
                    state = STATE_NOT_SEEN
                return {"state": state, "confirmed_sat": confirmed,
                        "unconfirmed_sat": unconfirmed,
                        "confirmations": best, "server": host}
        except (BtcWatchError, OSError, ssl.SSLError) as ex:
            last = ex
            continue
    raise BtcWatchError(f"no Electrum server answered (last: {last})")


# --- a small manual dry-run (no key, no money) -----------------------------

def _main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Watch-only: derive a deposit address and look at it. "
                    "Holds no key, spends nothing.")
    ap.add_argument("--xpub", required=True, help="account xPUB (m/84'/0'/0')")
    ap.add_argument("--index", type=int, required=True)
    ap.add_argument("--network", default="main")
    ap.add_argument("--electrum", action="append", default=[],
                    metavar="HOST:PORT",
                    help="Electrum server; repeatable. Omit to derive only.")
    ap.add_argument("--tor", default="socks5h://127.0.0.1:9050")
    ap.add_argument("--min-conf", type=int, default=1)
    args = ap.parse_args(argv)
    addr = derive_receive_address(args.xpub, args.index, args.network)
    print(f"  address[{args.index}]: {addr}")
    print(f"  scripthash:  {address_to_scripthash(addr)}")
    if not args.electrum:
        print("  (no --electrum given; derived only)")
        return 0
    servers = []
    for s in args.electrum:
        host, _, port = s.rpartition(":")
        servers.append((host, int(port) if port else DEFAULT_ELECTRUM_PORT))
    r = look(addr, servers, args.tor, min_conf=args.min_conf,
             network=args.network)
    print(f"  state: {r['state']}  confirmed: {r['confirmed_sat']} sat  "
          f"unconfirmed: {r['unconfirmed_sat']} sat  "
          f"confirmations: {r['confirmations']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
