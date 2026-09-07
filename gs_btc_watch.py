#!/usr/bin/env python3
"""Watch-only Bitcoin intake for the Pi. It holds an xpub and never a key.

STAGE 1 of the BTC-intake rework (BTC_INTAKE_DESIGN.md). This runs on the Pi,
which is assumed seizable, so it carries NO spend key and can move NO money.
Two jobs, and nothing else:

  DERIVE  a fresh, unique deposit address per handle, by PUBLIC BIP32
          derivation from an account xpub. A seized Pi learns the addresses
          it was watching and nothing more: it cannot spend them, and it
          cannot derive a hardened child, so it can never step toward the key.

  LOOK    at one such address on the Bitcoin network -- what unspent money
          sits there, and how deep each piece is -- by asking an Electrum
          server. It reads; it never builds or broadcasts a transaction.

What "confirmed" means here, precisely. The answer is built from the
address's UNSPENT OUTPUTS (blockchain.scripthash.listunspent), never from an
aggregate balance, because an aggregate cannot say WHICH satoshis are
settled: a long-settled dust output plus a one-block-old real deposit would
read as "confirmed money, many confirmations" and hand the vault an output
that a reorg or an RBF replacement could still take back. So each output is
depth-checked on its own, and

  settled_sat  = the sum of outputs at least `min_conf` blocks deep,
  state        = confirmed   iff settled_sat > 0
                 seen        iff money is present but none of it is settled
                 not_seen    iff the address holds nothing right now.

The vault (stage 2) spends only the settled outputs it is handed; nothing
shallower ever becomes an input.

How the looking stays quiet (BTC_INTAKE_DESIGN.md, rule 6):

  * Over Tor, always, `socks5h` -- the destination goes to the proxy as a
    DOMAIN NAME, so DNS resolves at the proxy and never here.
  * ONE FRESH CIRCUIT PER ADDRESS. The query -- "what does scripthash X
    hold" -- is the fingerprint, not the source IP; Tor hides who, not what.
    Each address is looked at on its own Tor circuit, keyed by the address
    through gs_common.isolated_proxy (IsolateSOCKSAuth), so a server logging
    its queries cannot cluster this operator's addresses by circuit. A retry
    of one address reuses that address's circuit -- a retry is not a new fact
    to leak. A proxy URL that already carries a credential is REFUSED rather
    than used as-is: it would put every address on one circuit, silently.
  * Default is a public Electrum server over Tor; an operator who wants no
    third party at all points the server list at their own node.
  * Nothing here is written to the hash chain. Watching is frequent and the
    deep-read pass already taught that a frequent path must not flood the SD
    card. The caller records a state CHANGE, never a poll.

How it fails: loudly, through BtcWatchError, and never with an invented
answer. A malformed server reply, a proxy that will not isolate, a stream
that drips one byte at a time past the deadline, a port out of range -- each
is a refusal the caller sees, not a silent "not paid yet". look() falls
through to the next configured server only on a transport or server fault;
the state it returns was computed from a complete, well-typed reply.

The forward that SPENDS is a woken vault job (stage 2), not this. This side
only ever answers "did the money arrive, and which of it is settled".
"""
import hashlib
import json
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

# The one vendored crypto dependency. Its pure-Python curve is correct and
# side-channel-free HERE because there is no secret: an xpub is public. The
# signer (stage 2) is the side that needs the constant-time native library.
sys.path.insert(0, str(Path(__file__).resolve().parent / "third_party"))
from embit import bech32, bip32, script                      # noqa: E402
from embit.networks import NETWORKS                          # noqa: E402

from gs_common import isolated_proxy                         # noqa: E402

#: Electrum's default TLS port (plaintext is 50001; TLS is the default here).
DEFAULT_ELECTRUM_PORT = 50002
#: Ceiling, in seconds, on ONE server's whole exchange -- proxy handshake,
#: TLS, every request and reply. A deadline, not a per-read timeout, so a
#: server that drips one byte at a time cannot hold the watcher for ever.
DEFAULT_TIMEOUT = 30.0
#: server.version identity. Deliberately generic -- a distinctive name would
#: be a fingerprint that survives across circuits.
CLIENT_NAME = "electrum"
PROTOCOL_VERSION = "1.4"
#: Ceiling on one server response line, so a hostile or broken server cannot
#: make a single read grow without bound.
MAX_LINE_BYTES = 2 * 1024 * 1024
#: Ceiling on how many unmatched lines (subscription notifications) a server
#: may interleave before we give up on an answer -- a server cannot stall us
#: by streaming frames instead of the reply we asked for.
MAX_SKIPPED_LINES = 64
#: The BIP32 hardened offset. A public key can derive only NON-hardened
#: children; derivation below refuses anything at or above this, so a bad
#: index is a loud failure, never a silent wrong address.
HARDENED = 0x80000000
#: An account key sits at depth 3 (m/84'/coin'/account'). A root xpub or a
#: deeper one would still derive addresses -- the WRONG ones, quietly -- so
#: anything else is refused.
ACCOUNT_DEPTH = 3

#: Reported states. Deliberately about the address's CURRENT unspent money:
#: an address swept empty reads not_seen, the honest "nothing here now".
STATE_NOT_SEEN = "not_seen"
STATE_SEEN = "seen"            # money present, none of it settled yet
STATE_CONFIRMED = "confirmed"  # some money is at least min_conf deep

_NETWORKS = {"main": "main", "mainnet": "main",
             "test": "test", "testnet": "test",
             "regtest": "regtest", "signet": "signet"}

# SOCKS5 wire constants (RFC 1928 / RFC 1929).
_SOCKS_VER = 0x05
_AUTH_NONE = 0x00
_AUTH_USERPASS = 0x02
_USERPASS_VER = 0x01
_CMD_CONNECT = 0x01
_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6 = 0x01, 0x03, 0x04


class BtcWatchError(Exception):
    """A watch could not be completed. Never carries key material."""


# --- derivation and scripthash: pure, no network, no secret -----------------

def _network(name):
    key = _NETWORKS.get(str(name).lower())
    if key is None:
        raise BtcWatchError(f"unknown network {name!r}")
    return NETWORKS[key]


def derive_receive_address(account_xpub, index, network="main", change=0):
    """The native-segwit deposit address at <change>/<index> under an
    account xpub.

    `account_xpub` is the account-level PUBLIC key (m/84'/coin'/0'), as an
    xpub or a zpub for mainnet, a tpub or a vpub for the test networks; the
    Pi holds only this. Derivation is public and non-hardened, so it never
    needs -- and can never reach -- a secret. Everything that could yield a
    wrong address quietly (an xprv, a hardened index, a key for another
    network or script type, a key at the wrong depth) is refused loudly.
    """
    net = _network(network)
    if isinstance(index, bool) or not isinstance(index, int) \
            or index < 0 or index >= HARDENED:
        raise BtcWatchError("index must be a non-negative, non-hardened int")
    if isinstance(change, bool) or change not in (0, 1):
        raise BtcWatchError("change must be 0 (receive) or 1 (change)")
    try:
        hd = bip32.HDKey.from_base58(str(account_xpub))
    except Exception as e:                                   # noqa: BLE001
        raise BtcWatchError(f"not a usable account xpub: {type(e).__name__}")
    if hd.key.is_private:
        raise BtcWatchError("an account xPUB is required here, not an xPRV")
    if hd.version not in (net["xpub"], net["zpub"]):
        raise BtcWatchError("this xpub is for another network or script "
                            "type; a native-segwit account key is required")
    if hd.depth != ACCOUNT_DEPTH:
        raise BtcWatchError(f"an ACCOUNT xpub (depth {ACCOUNT_DEPTH}) is "
                            f"required; this one is at depth {hd.depth}")
    pub = hd.derive([change, index]).get_public_key()
    return script.p2wpkh(pub).address(net)


def address_to_scripthash(address):
    """The Electrum scripthash of an address: sha256(scriptPubKey), reversed.

    Raises on an address embit cannot turn into a scriptPubKey, so a mistyped
    or wrong-network address fails loudly here instead of becoming a watch
    that silently matches nothing for ever.
    """
    try:
        spk = script.address_to_scriptpubkey(str(address)).data
    except Exception as e:                                   # noqa: BLE001
        raise BtcWatchError(f"not a usable address: {type(e).__name__}")
    return hashlib.sha256(spk).digest()[::-1].hex()


def _require_native_segwit(address, net):
    """The address must be a native-segwit address OF THIS NETWORK -- the only
    kind derived here -- so a testnet address is never looked up as if it
    were mainnet money, and vice versa."""
    witver, prog = bech32.decode(net["bech32"], str(address))
    if witver is None:
        raise BtcWatchError("address is not a native-segwit address of the "
                            f"{net['name']} network")


def _is_uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def summarize(utxos, tip, min_conf):
    """Turn a listunspent reply and the chain tip into the settled picture.

    Pure, so it can be reasoned about on its own. Each output is depth-checked
    individually; an aggregate balance could not say which satoshis are
    settled. Raises on any malformed entry -- a server that returns a string
    where a satoshi count belongs gets a refusal, not a coerced number.
    Returns {confirmed_sat, unconfirmed_sat, settled_sat, confirmations,
    utxos}, where `confirmations` is the depth of the SHALLOWEST mined output
    (0 if none is mined) -- how far the newest money has come.
    """
    if not isinstance(utxos, list):
        raise BtcWatchError("electrum: bad listunspent")
    confirmed = unconfirmed = settled = 0
    shallowest = None
    out = []
    for u in utxos:
        if not isinstance(u, dict):
            raise BtcWatchError("electrum: bad listunspent entry")
        txid, vout, height, value = (u.get("tx_hash"), u.get("tx_pos"),
                                     u.get("height"), u.get("value"))
        if not (isinstance(txid, str) and len(txid) == 64
                and all(c in "0123456789abcdef" for c in txid.lower())):
            raise BtcWatchError("electrum: bad listunspent entry (tx_hash)")
        if not _is_uint(vout) or not _is_uint(value) \
                or not (isinstance(height, int)
                        and not isinstance(height, bool)):
            raise BtcWatchError("electrum: bad listunspent entry (fields)")
        if height > 0:
            # Mined. Depth is tip - height + 1; a mined output can never be
            # shallower than 1 even if the tip we were told lags the block
            # the server itself just indexed.
            depth = max(1, tip - height + 1)
            confirmed += value
            shallowest = depth if shallowest is None else min(shallowest,
                                                              depth)
        else:
            depth = 0
            unconfirmed += value
        if depth >= min_conf:
            settled += value
        out.append({"tx_hash": txid.lower(), "vout": vout, "value": value,
                    "confirmations": depth})
    return {"confirmed_sat": confirmed, "unconfirmed_sat": unconfirmed,
            "settled_sat": settled, "confirmations": shallowest or 0,
            "utxos": out}


def classify(confirmed_sat, unconfirmed_sat, settled_sat):
    """One of the three states from the settled picture. Pure."""
    if settled_sat > 0:
        return STATE_CONFIRMED
    if confirmed_sat > 0 or unconfirmed_sat > 0:
        return STATE_SEEN
    return STATE_NOT_SEEN


# --- host:port parsing, shared by the proxy and the server list --------------

def _split_hostport(spec, default_port=None):
    """'host', 'host:port' or '[v6]:port' -> (host, port). Raises on a port
    that is not a number in 1..65535, on an empty host, and on a bare IPv6
    literal (ambiguous: bracket it)."""
    spec = str(spec).strip()
    if spec.startswith("["):
        host, sep, rest = spec[1:].partition("]")
        if not sep:
            raise BtcWatchError(f"malformed address {spec!r}")
        port = rest[1:] if rest.startswith(":") else (None if not rest
                                                     else "")
    elif spec.count(":") > 1:
        raise BtcWatchError(f"bracket an IPv6 literal: {spec!r}")
    else:
        host, sep, port = spec.partition(":")
        if not sep:
            port = None
    if not host:
        raise BtcWatchError(f"empty host in {spec!r}")
    if port is None:
        if default_port is None:
            raise BtcWatchError(f"a port is required in {spec!r}")
        return host, default_port
    try:
        p = int(port)
    except ValueError:
        raise BtcWatchError(f"port is not a number in {spec!r}")
    if not 1 <= p <= 0xFFFF:
        raise BtcWatchError(f"port out of range in {spec!r}")
    return host, p


def parse_server(spec):
    """'host' or 'host:port' -> (host, port), defaulting the TLS port."""
    return _split_hostport(spec, DEFAULT_ELECTRUM_PORT)


# --- SOCKS5 over Tor: a small framing protocol, hand-rolled, no dependency --

def _remaining(deadline):
    """Seconds left before `deadline`, or a loud failure once it has passed."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise BtcWatchError("deadline exceeded")
    return left


def _read_exact(sock, n, deadline):
    """Read EXACTLY n bytes before `deadline` or raise. A short read is a
    broken stream, not a partial frame to guess at; the clock is re-armed
    from the deadline before every read, so a trickle cannot reset it."""
    out = bytearray()
    while len(out) < n:
        sock.settimeout(_remaining(deadline))
        try:
            chunk = sock.recv(n - len(out))
        except socket.timeout:
            raise BtcWatchError("socks: deadline exceeded")
        if not chunk:
            raise BtcWatchError("socks: stream closed mid-frame")
        out += chunk
    return bytes(out)


def _socks_parts(proxy_url, tag):
    """(host, port, user, password) for the Tor SOCKS proxy, the credential
    made unique to `tag` so this stream gets its own circuit.

    Reuses gs_common.isolated_proxy for the credential (per-process salt, the
    tag hashed, never logged), then unpacks its URL for a raw socket. Refuses
    a URL that already carries a credential: isolated_proxy would hand it
    back verbatim, and every address would then share ONE circuit.
    """
    if not proxy_url:
        raise BtcWatchError("no Tor proxy configured")
    scheme, sep, rest = str(proxy_url).partition("://")
    if not sep or scheme.lower() != "socks5h":
        raise BtcWatchError("the proxy must be a socks5h:// URL")
    if "@" in rest:
        raise BtcWatchError("proxy URL must not carry a credential: "
                            "per-address isolation sets its own")
    d = isolated_proxy(proxy_url, tag)
    url = d.get("http") or d.get("https")
    if not url:
        raise BtcWatchError("no Tor proxy configured")
    body = url.split("://", 1)[1]
    cred, _, hostport = body.rpartition("@")
    user, _, password = cred.partition(":")
    if not user or not password:
        raise BtcWatchError("isolation credential missing")
    host, port = _split_hostport(hostport)
    return host, port, user, password


def _socks5_connect(dest_host, dest_port, proxy_host, proxy_port,
                    user, password, deadline):
    """Open a TCP stream to (dest_host, dest_port) through a SOCKS5 proxy,
    resolving the destination AT THE PROXY (socks5h). The username carries
    the per-address isolation tag. Returns a connected socket, or raises --
    and it raises, rather than proceeding un-isolated, if the proxy will not
    take the credential it was offered."""
    port = int(dest_port)
    if not 1 <= port <= 0xFFFF:
        raise BtcWatchError("socks: destination port out of range")
    host_b = str(dest_host).encode()
    if not 1 <= len(host_b) <= 255:
        raise BtcWatchError("socks: destination host must be 1..255 bytes")
    offered = _AUTH_USERPASS if user else _AUTH_NONE
    if offered == _AUTH_USERPASS:
        u, p = str(user).encode(), str(password or "").encode()
        # RFC 1929: ULEN and PLEN are each 1..255. Tor tolerates an empty
        # password; the standard does not, and a stricter daemon would hang
        # up with an error that points nowhere near the cause.
        if not (1 <= len(u) <= 255 and 1 <= len(p) <= 255):
            raise BtcWatchError("socks: credential must be 1..255 bytes")
    sock = socket.create_connection((proxy_host, int(proxy_port)),
                                    timeout=_remaining(deadline))
    try:
        # Greeting: offer exactly ONE method, and require that one back. A
        # proxy answering "no auth" when a credential was offered would give
        # a stream with no isolation at all -- fail closed instead.
        sock.sendall(bytes([_SOCKS_VER, 1, offered]))
        ver, method = _read_exact(sock, 2, deadline)
        if ver != _SOCKS_VER:
            raise BtcWatchError("socks: not a SOCKS5 proxy")
        if method != offered:
            raise BtcWatchError("socks: proxy would not take the isolation "
                                "credential; refusing an un-isolated stream")
        if offered == _AUTH_USERPASS:
            sock.sendall(bytes([_USERPASS_VER, len(u)]) + u
                         + bytes([len(p)]) + p)
            aver, status = _read_exact(sock, 2, deadline)
            if aver != _USERPASS_VER:
                raise BtcWatchError("socks: bad auth reply")
            if status != 0x00:
                raise BtcWatchError("socks: auth rejected")
        # CONNECT with a DOMAINNAME target (ATYP 0x03) so the PROXY resolves
        # it. This is what socks5h means, and it is why a hostname never hits
        # a local resolver.
        sock.sendall(bytes([_SOCKS_VER, _CMD_CONNECT, 0x00, _ATYP_DOMAIN,
                            len(host_b)]) + host_b + struct.pack(">H", port))
        rver, rep, _rsv, atyp = _read_exact(sock, 4, deadline)
        if rver != _SOCKS_VER:
            raise BtcWatchError("socks: bad CONNECT reply")
        if rep != 0x00:
            raise BtcWatchError(f"socks: CONNECT refused (reply={rep})")
        if atyp == _ATYP_IPV4:
            _read_exact(sock, 4, deadline)
        elif atyp == _ATYP_DOMAIN:
            _read_exact(sock, _read_exact(sock, 1, deadline)[0], deadline)
        elif atyp == _ATYP_IPV6:
            _read_exact(sock, 16, deadline)
        else:
            raise BtcWatchError("socks: unknown bound-address type")
        _read_exact(sock, 2, deadline)                       # bound port
        return sock
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise


def _wrap_tls(sock, server_name, deadline):
    """Wrap a connected socket in TLS 1.2+. Electrum servers use self-signed
    certificates and clients pin on first use; here the channel's
    confidentiality is Tor and the queried data is public, so an unverified
    wrapper is the standard, correct choice -- it stops a Tor exit or the
    server's neighbours reading the scripthash in the clear, which is all
    TLS is for on this link."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock.settimeout(_remaining(deadline))
    return ctx.wrap_socket(sock, server_hostname=server_name)


# --- the transport seam: a line channel the Electrum client speaks over -----

class SocksTlsTransport:
    """The real transport: SOCKS5 over Tor, then TLS, then newline-delimited
    frames, all under ONE deadline. Tests substitute an object with the same
    connect/send_line/recv_line/close surface, so the Electrum client never
    sees a socket."""

    def __init__(self, host, port, proxy_url, tag, *, tls=True,
                 timeout=DEFAULT_TIMEOUT):
        self._host = str(host)
        self._port = int(port)
        self._proxy = proxy_url
        self._tag = tag
        self._tls = tls
        self._timeout = float(timeout)
        self._deadline = None
        self._sock = None
        self._buf = b""

    def connect(self):
        self._deadline = time.monotonic() + self._timeout
        ph, pp, user, password = _socks_parts(self._proxy, self._tag)
        sock = _socks5_connect(self._host, self._port, ph, pp, user,
                               password, self._deadline)
        try:
            self._sock = (_wrap_tls(sock, self._host, self._deadline)
                          if self._tls else sock)
        except BaseException:
            sock.close()
            raise
        return self

    def _arm(self):
        """Re-arm the socket clock from the deadline before every operation,
        so a peer that trickles bytes cannot keep resetting a per-read
        timeout."""
        if self._sock is None:
            raise BtcWatchError("electrum: not connected")
        self._sock.settimeout(_remaining(self._deadline))

    def send_line(self, line):
        self._arm()
        try:
            self._sock.sendall((line + "\n").encode())
        except socket.timeout:
            raise BtcWatchError("electrum: deadline exceeded")

    def recv_line(self):
        while b"\n" not in self._buf:
            if len(self._buf) > MAX_LINE_BYTES:
                raise BtcWatchError("electrum: response too large")
            self._arm()
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout:
                raise BtcWatchError("electrum: deadline exceeded")
            if not chunk:
                raise BtcWatchError("electrum: connection closed")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", "replace")

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._buf = b""


# --- the Electrum client: synchronous JSON-RPC over a transport, read-only --

class Electrum:
    """A minimal, synchronous, READ-ONLY Electrum-protocol client over a
    transport. It knows three methods, none of which can move money. Use as
    a context manager: it connects on enter, closes on exit."""

    def __init__(self, transport):
        self._t = transport
        self._id = 0

    def __enter__(self):
        self._t.connect()
        return self

    def __exit__(self, *_a):
        self._t.close()

    def _rpc(self, method, params):
        self._id += 1
        want = self._id
        self._t.send_line(json.dumps({"jsonrpc": "2.0", "id": want,
                                      "method": method, "params": params}))
        # Read lines until one carries our id, skipping subscription
        # notifications (no id) -- but only so many, so a server cannot
        # stall by streaming frames instead of answering.
        for _ in range(MAX_SKIPPED_LINES + 1):
            raw = self._t.recv_line()
            try:
                obj = json.loads(raw)
            except ValueError:
                raise BtcWatchError("electrum: non-JSON line")
            if not isinstance(obj, dict):
                raise BtcWatchError("electrum: non-object frame")
            if obj.get("id") == want:
                if obj.get("error") is not None:
                    raise BtcWatchError(
                        f"electrum error: {str(obj['error'])[:120]}")
                return obj.get("result")
            if obj.get("id") is None and obj.get("error") is not None:
                # A request the server could not even parse comes back with
                # a null id. That is our failure to hear about, not a
                # notification to skip past.
                raise BtcWatchError(
                    f"electrum rejected the request: "
                    f"{str(obj['error'])[:120]}")
        raise BtcWatchError("electrum: no matching reply")

    def handshake(self):
        # Best effort: some servers require server.version first, some ignore
        # it. Its failure is not our failure -- the next call decides that.
        try:
            self._rpc("server.version", [CLIENT_NAME, PROTOCOL_VERSION])
        except BtcWatchError:
            pass

    def tip_height(self):
        r = self._rpc("blockchain.headers.subscribe", [])
        if isinstance(r, dict) and _is_uint(r.get("height")):
            return r["height"]
        raise BtcWatchError("electrum: no tip height")

    def listunspent(self, scripthash):
        r = self._rpc("blockchain.scripthash.listunspent", [scripthash])
        if not isinstance(r, list):
            raise BtcWatchError("electrum: bad listunspent")
        return r


# --- the answer the caller wants --------------------------------------------

def look(address, servers, proxy_url, *, min_conf=1, network="main",
         timeout=DEFAULT_TIMEOUT, transport_factory=None):
    """Ask the network what unspent money sits at `address`, and how settled.

    `servers` is a list of (host, port), tried in order until one answers,
    so a single dead server is not a dead watch. `network` names the chain
    the address must belong to. `timeout` bounds ONE server's whole
    exchange. `transport_factory(host, port, tag)` may inject a transport
    for tests. Returns
        {state, confirmed_sat, unconfirmed_sat, settled_sat, confirmations,
         utxos, tip, server}
    and NEVER raises for "not paid yet" -- only for "could not ask anyone",
    or for a configuration that could not be right.
    """
    net = _network(network)
    _require_native_segwit(address, net)
    scripthash = address_to_scripthash(address)
    if not _is_uint(min_conf) or min_conf < 1:
        raise BtcWatchError("min_conf must be an int of at least 1: an "
                            "unconfirmed deposit is never settled money")
    if not servers:
        raise BtcWatchError("no Electrum servers configured")
    checked = []
    for spec in servers:
        try:
            host, port = spec
        except (TypeError, ValueError):
            raise BtcWatchError("each server must be a (host, port) pair")
        checked.append(_split_hostport(f"[{host}]:{port}" if ":" in str(host)
                                       else f"{host}:{port}"))
    tag = "btcwatch:" + address       # one circuit per address; see the header
    last = None
    for host, port in checked:
        if transport_factory is not None:
            transport = transport_factory(host, port, tag)
        else:
            transport = SocksTlsTransport(host, port, proxy_url, tag,
                                          timeout=timeout)
        try:
            with Electrum(transport) as e:
                e.handshake()
                tip = e.tip_height()
                picture = summarize(e.listunspent(scripthash), tip, min_conf)
        except (BtcWatchError, OSError) as ex:
            last = ex
            continue
        picture["state"] = classify(picture["confirmed_sat"],
                                    picture["unconfirmed_sat"],
                                    picture["settled_sat"])
        picture["tip"] = tip
        picture["server"] = host
        return picture
    raise BtcWatchError(f"no Electrum server answered (last: {last})")


# --- a small manual dry-run (no key, no money) ------------------------------

def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Watch-only: derive a deposit address and look at it. "
                    "Holds no key, spends nothing.")
    ap.add_argument("--xpub", required=True,
                    help="account xPUB (m/84'/coin'/0'), xpub/zpub/tpub/vpub")
    ap.add_argument("--index", type=int, required=True)
    ap.add_argument("--network", default="main")
    ap.add_argument("--electrum", action="append", default=[],
                    metavar="HOST[:PORT]",
                    help="Electrum server; repeatable. Omit to derive only.")
    ap.add_argument("--tor", default="socks5h://127.0.0.1:9050")
    ap.add_argument("--min-conf", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = ap.parse_args(argv)
    addr = derive_receive_address(args.xpub, args.index, args.network)
    print(f"  address[{args.index}]: {addr}")
    print(f"  scripthash:  {address_to_scripthash(addr)}")
    if not args.electrum:
        print("  (no --electrum given; derived only)")
        return 0
    servers = [parse_server(s) for s in args.electrum]
    r = look(addr, servers, args.tor, min_conf=args.min_conf,
             network=args.network, timeout=args.timeout)
    print(f"  state: {r['state']}  settled: {r['settled_sat']} sat  "
          f"mined: {r['confirmed_sat']} sat  "
          f"mempool: {r['unconfirmed_sat']} sat  "
          f"newest depth: {r['confirmations']}  outputs: {len(r['utxos'])}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
