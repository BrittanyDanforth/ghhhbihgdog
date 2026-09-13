#!/usr/bin/env python3
"""The one method in this codebase that can move bitcoin. Vault side only.

STAGE 3 of the BTC-intake rework (STAGE3_PLAN.md). gs_btc_watch is the
Pi's module: it derives, it looks, and its client "knows no method that
could move money" -- three tests read its source to keep that literally
true. This module is the other half, and it lives in its own file so that
sentence stays true: it subclasses the watch client, adds
blockchain.transaction.broadcast (the spend) and blockchain.scripthash.get_history
(read-only, to see the spend), and nothing on the Pi imports it.

Two questions are answered here, and the answers are shaped by money:

  submit  hand a SIGNED transaction to the network, through the operator's
          configured Electrum servers in turn, over Tor on the address's
          own broadcast circuit. Its outcome is one of FOUR words, and the
          word says what happened to the money:

            accepted     a server answered with OUR txid. Moved.
            rejected     every server that answered said no (numeric codes
                         only). Nothing moved. Rejection is as often the
                         node's RELAY POLICY as consensus -- a pre-Core-30
                         node refuses the 105-byte swap memo the next node
                         relays -- which is why the servers are tried in
                         turn rather than the first "no" being final.
            ambiguous    the bytes LEFT for at least one server and no
                         acceptance came back: a hang-up, a deadline, a
                         server answering with a foreign txid. The money
                         MAY have moved. The caller keeps the signed bytes.
            unreachable  no send ever completed. Nothing moved.

          A server that answers with a txid that is not ours is treated as
          lying or broken (a segwit txid cannot be malleated by a third
          party) and counts toward ambiguous: the bytes were sent.

  seen    ask the DEPOSIT address's history -- the transaction spends it, so
          it appears there -- until the txid is listed or the wait runs out.
          This is the broadcast PROOF: a server, asked read-only, reports the
          transaction. Height 0 or -1 is the mempool, above 0 a block.
          Confirmation DEPTH is deliberately not waited for (STAGE3_PLAN.md
          3.4): a block is ten minutes on average and an hour is ordinary,
          and a woken job cannot hold the vault up for that.

What never leaves this module: text a server chose. A rejection carries the
server's numeric code and nothing else (gs_btc_watch._error_code), because
ElectrumX echoes the node's reason into the message and for a rejected
OP_RETURN that reason carries the memo. A PinMismatch is re-raised at once,
as look() does: an interception is not a dead server to route around.

The signed bytes are a PARAMETER. This module never reads a file, so a
signed transaction on disk is never the input to a broadcast (STAGE3_PLAN.md
3.2); the forwarder hands it what it signed a moment ago, from memory.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gs_btc_watch as watch                                 # noqa: E402
from gs_btc_watch import (                                   # noqa: E402
    BtcWatchError, PinMismatch, ServerError, DEFAULT_TIMEOUT,
)

#: A serialized transaction over this many BYTES is refused before any
#: connection: the standard weight limit (400,000 WU) bounds a relayable
#: transaction well under it, and a forward is two outputs and a few inputs.
MAX_TX_BYTES = 400_000
#: How long `seen` polls by default, and how often. Ninety seconds is a few
#: propagation rounds; a transaction a server accepted and no server lists
#: after that is reported as unseen, never as absent.
DEFAULT_SEEN_WAIT_S = 90.0
DEFAULT_SEEN_INTERVAL_S = 15.0

OUTCOME_ACCEPTED = "accepted"
OUTCOME_REJECTED = "rejected"
OUTCOME_AMBIGUOUS = "ambiguous"
OUTCOME_UNREACHABLE = "unreachable"
OUTCOMES = (OUTCOME_ACCEPTED, OUTCOME_REJECTED, OUTCOME_AMBIGUOUS,
            OUTCOME_UNREACHABLE)
#: The outcomes after which the money MAY have moved. Everything the caller
#: decides about the signed bytes, the exit code and the phase word keys on
#: this tuple, so it is declared once.
MAYBE_MOVED = (OUTCOME_ACCEPTED, OUTCOME_AMBIGUOUS)

_TXID_RE = re.compile(r"^[0-9a-f]{64}\Z")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+\Z")


def _check_txid(txid):
    t = str(txid or "").lower()
    if not _TXID_RE.match(t):
        raise BtcWatchError("broadcast: expected txid is not 64 hex digits")
    return t


def _check_hex(raw_hex):
    h = str(raw_hex or "")
    if not _HEX_RE.match(h):
        raise BtcWatchError("broadcast: the transaction is not even-length "
                            "hex")
    if len(h) // 2 > MAX_TX_BYTES:
        raise BtcWatchError("broadcast: the transaction is larger than any "
                            "node relays")
    return h.lower()


class Broadcaster(watch.Electrum):
    """The watch client plus the ONE method that spends and the one
    read-only method that sees the spend. `sent` is True from the moment
    the broadcast request's bytes have left, whatever happens after: it is
    what separates "nothing moved" from "may have moved"."""

    sent = False

    def broadcast(self, raw_hex):
        """blockchain.transaction.broadcast. Returns the txid the server
        answered with (lower-case hex), or raises: ServerError when the
        server said no, BtcWatchError when it never said."""
        raw = _check_hex(raw_hex)
        self.sent = False
        want = self._send("blockchain.transaction.broadcast", [raw])
        self.sent = True
        r = self._await(want)
        if not isinstance(r, str) or not _TXID_RE.match(r.lower()):
            raise BtcWatchError("electrum: bad broadcast reply")
        return r.lower()

    def history(self, scripthash):
        """blockchain.scripthash.get_history: [{tx_hash, height}, ...],
        each entry validated, anything else refused."""
        r = self._rpc("blockchain.scripthash.get_history", [scripthash])
        if not isinstance(r, list):
            raise BtcWatchError("electrum: bad history")
        out = []
        for e in r:
            if not isinstance(e, dict):
                raise BtcWatchError("electrum: bad history entry")
            h, tx = e.get("height"), e.get("tx_hash")
            if isinstance(h, bool) or not isinstance(h, int) or h < -1 \
                    or not isinstance(tx, str) or not _TXID_RE.match(tx.lower()):
                raise BtcWatchError("electrum: bad history entry")
            out.append({"tx_hash": tx.lower(), "height": h})
        return out


def _tag_for(address):
    """One broadcast circuit per address, distinct from the look's circuit
    (btcwatch:<address>): the look and the spend never share one."""
    return "btcsend:" + address


def _prepare(address, network, servers, proxy_url, transport_factory,
             timeout):
    net = watch._network(network)
    watch._require_native_segwit(address, net)
    scripthash = watch.address_to_scripthash(address)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
            or timeout <= 0 or timeout != timeout:
        raise BtcWatchError("timeout must be a positive number of seconds")
    order = watch.server_order(servers, scripthash)
    tag = _tag_for(address)
    if transport_factory is None:
        watch._socks_parts(proxy_url, tag)      # one configuration refusal

    def make(host, port, pin):
        if transport_factory is not None:
            return transport_factory(host, port, tag)
        return watch.SocksTlsTransport(host, port, proxy_url, tag,
                                       timeout=timeout, pin=pin)
    return scripthash, order, make


def submit(raw_hex, expected_txid, address, servers, proxy_url, *,
           network="main", timeout=DEFAULT_TIMEOUT, transport_factory=None):
    """Hand the signed transaction to the network. See the module header
    for the four outcomes. Returns
        {outcome, server, cert_sha256, codes, attempts, mismatched,
         pin_mismatch}
    where `codes` are the numeric codes of every rejection, `attempts` how
    many servers were tried and `mismatched` how many answered with a
    txid that was not ours. `server` names the accepting server, else
    None. Raises only for a configuration that could not be right, or a
    PinMismatch before any bytes left; a PinMismatch AFTER they did is
    reported in the result (`pin_mismatch`) under outcome ambiguous, so
    the fact that money may have moved is never lost to the interception
    signal."""
    raw = _check_hex(raw_hex)
    want = _check_txid(expected_txid)
    _scripthash, order, make = _prepare(address, network, servers, proxy_url,
                                        transport_factory, timeout)
    codes, attempts, mismatched, ambiguous = [], 0, 0, False
    pinned = False
    for host, port, pin in order:
        attempts += 1
        transport = make(host, port, pin)
        b = Broadcaster(transport)
        try:
            with b:
                b.handshake()
                got = b.broadcast(raw)
        except PinMismatch:
            # An interception ends the submit at once -- UNLESS the bytes
            # already left for an earlier server, in which case "may have
            # moved" is the fact that must survive: the result says both.
            if ambiguous:
                pinned = True
                break
            raise
        except ServerError as e:
            # The server ANSWERED: this one did not take it. Nothing moved
            # through it. Policy or consensus, the next server decides.
            codes.append(e.code)
            continue
        except (BtcWatchError, OSError):
            # No well-formed answer. If the bytes left, the money may have
            # moved; if they never did, this server was simply unreachable.
            if b.sent:
                ambiguous = True
            continue
        if got != want:
            mismatched += 1
            ambiguous = True
            continue
        return {"outcome": OUTCOME_ACCEPTED, "server": host,
                "cert_sha256": getattr(transport, "cert_sha256", None),
                "codes": codes, "attempts": attempts,
                "mismatched": mismatched, "pin_mismatch": False}
    if ambiguous:
        outcome = OUTCOME_AMBIGUOUS
    elif codes:
        outcome = OUTCOME_REJECTED
    else:
        outcome = OUTCOME_UNREACHABLE
    return {"outcome": outcome, "server": None, "cert_sha256": None,
            "codes": codes, "attempts": attempts, "mismatched": mismatched,
            "pin_mismatch": pinned}


def _history_once(txid, scripthash, order, make):
    """One pass over the servers: the first that answers decides. Returns
    (entry_or_None, host, cert_sha256); raises BtcWatchError when no
    server answered at all."""
    last = None
    for host, port, pin in order:
        transport = make(host, port, pin)
        try:
            with Broadcaster(transport) as b:
                b.handshake()
                entries = b.history(scripthash)
        except PinMismatch:
            raise
        except (BtcWatchError, OSError) as ex:
            last = ex
            continue
        hit = next((e for e in entries if e["tx_hash"] == txid), None)
        return hit, host, getattr(transport, "cert_sha256", None)
    why = str(last) if isinstance(last, BtcWatchError) \
        else type(last).__name__
    raise BtcWatchError(f"no Electrum server answered (last: {why})")


def seen(txid, address, servers, proxy_url, *, network="main",
         timeout=DEFAULT_TIMEOUT, wait_s=DEFAULT_SEEN_WAIT_S,
         interval_s=DEFAULT_SEEN_INTERVAL_S, sleeper=None, clock=None,
         transport_factory=None):
    """Is `txid` in the deposit address's history yet? Polls until it is
    or `wait_s` has passed (at least once; wait_s 0 is one look). Returns
        {seen, height, server, cert_sha256, polls, asked}
    `asked` is False when NO poll got an answer from any server -- the
    difference between "the network does not list it" and "nobody could be
    asked", which the caller must not collapse."""
    want = _check_txid(txid)
    scripthash, order, make = _prepare(address, network, servers, proxy_url,
                                       transport_factory, timeout)
    if isinstance(wait_s, bool) or not isinstance(wait_s, (int, float)) \
            or wait_s < 0 or isinstance(interval_s, bool) \
            or not isinstance(interval_s, (int, float)) or interval_s <= 0:
        raise BtcWatchError("seen: wait must be >= 0 and interval > 0")
    sleeper = sleeper or time.sleep
    clock = clock or time.monotonic
    deadline = clock() + float(wait_s)
    polls, asked = 0, False
    host = cert = None
    while True:
        polls += 1
        try:
            hit, host, cert = _history_once(want, scripthash, order, make)
            asked = True
        except PinMismatch:
            raise
        except BtcWatchError:
            hit = None
        if hit is not None:
            return {"seen": True, "height": hit["height"], "server": host,
                    "cert_sha256": cert, "polls": polls, "asked": True}
        if clock() + float(interval_s) > deadline:
            break
        sleeper(float(interval_s))
    return {"seen": False, "height": None, "server": host,
            "cert_sha256": cert, "polls": polls, "asked": asked}
