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
import gs_btc_tx as btx                                      # noqa: E402
from embit.transaction import Transaction                    # noqa: E402

#: A history longer than this is refused before any transaction is fetched:
#: a deposit address is paid once or twice and spent once, and a server
#: listing hundreds of entries is either wrong about the address or trying
#: to make this side fetch for ever.
MAX_HISTORY = 200
#: THE READ IS BUDGETED BY WHAT IT READS. One session had one 30 s deadline
#: for the handshake, the history and a transaction.get PER ENTRY, one
#: after another over Tor -- so a stranger who can read the address (it is
#: in the chat) jammed every reconciliation for good with about sixty dust
#: payments, some $30, long before MAX_HISTORY: every server ran out of
#: deadline, reconcile failed history_unavailable, and a stuck forward was
#: never bumped, a refund never sent on. Each entry now brings its own
#: allowance, under a ceiling that keeps two servers' worth inside the
#: forward job's 900 s budget (gs_wake_proto JOBS). Measured over Tor a
#: round trip is 0.3-1 s; the allowance is twice the slow end.
PER_ENTRY_S = 2.0
READ_EXTENSION_MAX_S = 300.0

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

    def transaction(self, txid):
        """blockchain.transaction.get: the raw transaction, lower-case hex,
        bounded like a broadcast and checked to be the transaction it was
        asked for (its txid recomputed here). Read-only."""
        want = _check_txid(txid)
        r = self._rpc("blockchain.transaction.get", [want])
        if not isinstance(r, str) or not _HEX_RE.match(r) \
                or len(r) // 2 > MAX_TX_BYTES:
            raise BtcWatchError("electrum: bad transaction")
        try:
            tx = Transaction.parse(bytes.fromhex(r))
        except Exception:                                    # noqa: BLE001
            raise BtcWatchError("electrum: unparseable transaction")
        if tx.txid().hex() != want:
            raise BtcWatchError("electrum: transaction does not match its "
                                "txid")
        return r.lower()


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


def history_of(address, servers, proxy_url, *, network="main",
               timeout=DEFAULT_TIMEOUT, transport_factory=None):
    """The address's history -- [{tx_hash, height}, ...], oldest first,
    mempool last -- from the first server that answers, read-only over Tor
    on the address's own circuit, as (entries, host). Raises BtcWatchError
    when no server answered."""
    scripthash, order, make = _prepare(address, network, servers, proxy_url,
                                       transport_factory, timeout)
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
        return entries, host
    why = str(last) if isinstance(last, BtcWatchError) \
        else type(last).__name__
    raise BtcWatchError(f"no Electrum server answered (last: {why})")


def unused(address, servers, proxy_url, *, network="main",
           timeout=DEFAULT_TIMEOUT, transport_factory=None):
    """Has this address EVER been used? True iff a server, asked read-only
    over Tor on the address's own circuit, lists no history for it at all
    -- mempool or block, received or spent. Raises BtcWatchError when no
    server answered: "could not ask" is never "unused", because the caller
    is about to hand this address to a client and a reused address is two
    clients' money on one line (STAGE4_PLAN.md 2). The vault calls this
    before issuing a deposit address; the ledger's own counter is not
    trusted for it, since paranoia_mode wipes the ledger."""
    entries, _host = history_of(address, servers, proxy_url, network=network,
                                timeout=timeout,
                                transport_factory=transport_factory)
    return not entries


#: The memo ThorChain puts on a transaction that REFUNDS an inbound it
#: would not swap: "REFUND:" and the refunded transaction's id. A public
#: convention anyone can write into an OP_RETURN of their own, so a memo
#: alone is a claim; the SOURCE of the money (the input's previous output,
#: fetched here for a claim) is what a caller verifies against.
REFUND_MEMO_PREFIX = "REFUND:"
#: How many of a claimed refund's inputs have their source read: a
#: ThorChain outbound may consolidate several vault outputs, and one input
#: from the vault is proof enough; the bound keeps a claim from costing
#: more than this many fetches.
REFUND_SOURCE_INPUTS = 4


def _memo_of(tx):
    """The first OP_RETURN's data as text, or None."""
    for o in tx.vout:
        data = btx.op_return_data(o.script_pubkey.data)
        if data is not None:
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return None
    return None


def _prev_address(raw, vout, net):
    """The address the `vout`-th output of the raw transaction pays, or
    None (no transaction, no such output, not an address)."""
    if not raw:
        return None
    try:
        tx = Transaction.parse(bytes.fromhex(raw))
        return str(tx.vout[int(vout)].script_pubkey.address(net)).lower()
    except Exception:                                        # noqa: BLE001
        return None


def spends_of(address, servers, proxy_url, *, network="main",
              timeout=DEFAULT_TIMEOUT, transport_factory=None,
              with_funding=False, on_truncated=None, keep_txids=()):
    """Every transaction in the address's history that SPENDS an output
    paying it, oldest first, with what each spend carried.

    Returns [{txid, height, hex, inputs: [{tx_hash, vout, value}],
    server}], the inputs being the address's own outputs that transaction
    consumed, their values read off the FUNDING transactions in the same
    history -- so a caller can tell what a spend it never recorded
    carried (STAGE5_PLAN.md 3.1: a forward that went out and whose plan was
    never written is found here, not answered "not yet" for ever).

    With `with_funding`, (spends, paid): `paid` is every output in the
    history that PAYS the address, oldest first -- [{txid, height, vout,
    value, memo, from_address, from_addresses}] -- its transaction's
    OP_RETURN as text (or None), and, for a transaction whose memo claims
    to be a ThorChain REFUND (REFUND_MEMO_PREFIX), the addresses its first
    REFUND_SOURCE_INPUTS inputs were paid from, read off those inputs'
    previous transactions, fetched in the same session (None for one that
    could not be; `from_address` is the first). That is how a refund is
    told from a second payment (third self-doubt pass): the memo is a
    public convention anyone can write, the source is not -- a
    transaction with ANY input from ThorChain's vault was signed by
    ThorChain, since only its signers spend from its vault.

    One server's session: the history, then blockchain.transaction.get for
    each entry, each transaction parsed and its txid recomputed (a server
    cannot hand back a different transaction under a listed id). Read-only.
    Refuses a listed transaction that neither pays nor spends the address
    (a server whose history and transactions contradict each other is not
    one to reason from). Raises BtcWatchError when no server answered.

    A HISTORY LONGER THAN MAX_HISTORY IS READ AS ITS NEWEST MAX_HISTORY
    ENTRIES, not refused (the MED pass after the deep read). It was
    refused outright, so anyone who could read the address -- it is in
    the chat -- could jam a deposit's every reconciliation for good with
    a flood of dust, until the operator acted by hand. Electrum lists the
    confirmed entries by height and the mempool's after them, so the tail
    is the newest. `on_truncated(total)` is called once, for the caller
    to put a kind on the chain. What the window cannot hold cannot be
    reasoned from, and the reconciliation fails SAFELY for it, never
    falsely: listunspent stays the source of truth for what is on the
    address, a forward of ours that fell off the window leaves its
    inputs neither unspent nor consumed (history_inconsistent, nothing
    signed), and a spend in the window whose inputs are older than the
    window is still LISTED, with no inputs, so a spend that is not ours
    is still the alarm it was.

    `keep_txids` ARE READ WHEREVER THEY SIT IN THE HISTORY: the caller's
    own transactions -- its forwards and what funded them. A flood that
    pushed our forward off the newest MAX_HISTORY left its inputs neither
    unspent nor consumed, which is history_inconsistent on every run: safe,
    and a jam all the same, bought with MAX_HISTORY dust payments."""
    spk = btx.address_script(address, network).data
    _keep = {str(t).lower() for t in (keep_txids or ())}
    net = btx.network_of(network)
    scripthash, order, make = _prepare(address, network, servers, proxy_url,
                                       transport_factory, timeout)
    last = None
    for host, port, pin in order:
        transport = make(host, port, pin)
        try:
            with Broadcaster(transport) as b:
                b.handshake()
                entries = b.history(scripthash)
                n_all, truncated = len(entries), False
                if len(entries) > MAX_HISTORY:
                    entries = ([e for e in entries[:-MAX_HISTORY]
                                if e["tx_hash"] in _keep]
                               + entries[-MAX_HISTORY:])
                    truncated = True
                _ext = [0.0]

                def _allow(n=1):
                    """One more fetch's allowance, under the ceiling."""
                    _step = min(PER_ENTRY_S * n,
                                READ_EXTENSION_MAX_S - _ext[0])
                    if _step > 0 and hasattr(transport, "extend"):
                        transport.extend(_step)
                        _ext[0] += _step
                _allow(len(entries))
                txs = [(e, b.transaction(e["tx_hash"])) for e in entries]
                prevs = {}
                if with_funding:
                    # THE SOURCE OF A CLAIMED REFUND: its first input's
                    # previous transaction, in the same session, only for
                    # a transaction that pays the address and claims one
                    # (at most MAX_HISTORY fetches). A fetch that fails
                    # leaves the claim unverified; it does not fail over.
                    for _e, _raw in txs:
                        _tx = Transaction.parse(bytes.fromhex(_raw))
                        if not any(o.script_pubkey.data == spk
                                   for o in _tx.vout) or not _tx.vin:
                            continue
                        _m = _memo_of(_tx)
                        if not isinstance(_m, str) \
                                or not _m.upper().startswith(
                                    REFUND_MEMO_PREFIX):
                            continue
                        for _vin in _tx.vin[:REFUND_SOURCE_INPUTS]:
                            _prev = _vin.txid.hex()
                            if _prev in prevs or set(_prev) <= {"0"}:
                                continue
                            _allow()
                            try:
                                prevs[_prev] = b.transaction(_prev)
                            except (BtcWatchError, OSError):
                                prevs[_prev] = None
        except PinMismatch:
            raise
        except (BtcWatchError, OSError) as ex:
            last = ex
            continue
        parsed = [(e, raw, Transaction.parse(bytes.fromhex(raw)))
                  for e, raw in txs]
        funding = {}
        for e, _raw, tx in parsed:
            for n, o in enumerate(tx.vout):
                if o.script_pubkey.data == spk:
                    funding[(e["tx_hash"], n)] = int(o.value)
        out, paid = [], []
        for e, raw, tx in parsed:
            spent = [{"tx_hash": i.txid.hex(), "vout": int(i.vout),
                      "value": funding[(i.txid.hex(), int(i.vout))]}
                     for i in tx.vin
                     if (i.txid.hex(), int(i.vout)) in funding]
            pays = any(o.script_pubkey.data == spk for o in tx.vout)
            if not spent and not pays:
                if not truncated:
                    raise BtcWatchError("electrum: the history lists a "
                                        "transaction that does not touch "
                                        "the address")
                # A SPEND OF OUTPUTS OLDER THAN THE WINDOW: the funding it
                # consumed fell off the tail, so nothing here names its
                # inputs. Listed all the same, with none: the caller tells
                # a spend of ours from a foreign one by its id and memo,
                # and a foreign spend it could not see was the hole.
                out.append({"txid": e["tx_hash"], "height": e["height"],
                            "hex": raw, "inputs": [], "server": host})
                continue
            if spent:
                out.append({"txid": e["tx_hash"], "height": e["height"],
                            "hex": raw, "inputs": spent, "server": host})
            if pays and with_funding:
                memo = _memo_of(tx)
                srcs = []
                if isinstance(memo, str) \
                        and memo.upper().startswith(REFUND_MEMO_PREFIX):
                    srcs = [_prev_address(prevs.get(i.txid.hex()),
                                          int(i.vout), net)
                            for i in tx.vin[:REFUND_SOURCE_INPUTS]]
                for n, o in enumerate(tx.vout):
                    if o.script_pubkey.data == spk:
                        paid.append({"txid": e["tx_hash"],
                                     "height": e["height"], "vout": n,
                                     "value": int(o.value), "memo": memo,
                                     "from_address": (srcs[0] if srcs
                                                      else None),
                                     "from_addresses": list(srcs)})
        if truncated and on_truncated is not None:
            on_truncated(n_all)
        return (out, paid) if with_funding else out
    why = str(last) if isinstance(last, BtcWatchError) \
        else type(last).__name__
    raise BtcWatchError(f"no Electrum server answered (last: {why})")


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
         transport_factory=None, avoid=None):
    """Is `txid` in the deposit address's history yet? Polls until it is
    or `wait_s` has passed (at least once; wait_s 0 is one look). Returns
        {seen, height, server, cert_sha256, polls, asked}
    `asked` is False when NO poll got an answer from any server -- the
    difference between "the network does not list it" and "nobody could be
    asked", which the caller must not collapse.

    `avoid` names the server that ACCEPTED the transaction: with more than
    one server configured the poll starts elsewhere, so the proof is a
    SECOND server's word and a server that lied about accepting cannot
    also be the one vouching that it propagated. With one server there is
    nobody else to ask, and it is asked.

    LEFT OUT, not moved to the end. It was rotated to the back, and the
    poll fails over within itself -- so with the other server down the
    accepting one was asked after all, listed its own claimed txid, and
    the forward dropped the signed bytes as proven. Now nobody else
    answering is "nobody could be asked", and the bytes are kept."""
    want = _check_txid(txid)
    scripthash, order, make = _prepare(address, network, servers, proxy_url,
                                       transport_factory, timeout)
    if avoid and len(order) > 1:
        order = [o for o in order if o[0] != avoid] or order
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
