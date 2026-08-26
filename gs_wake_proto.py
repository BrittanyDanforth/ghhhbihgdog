"""gs_wake_proto - the wire format the Pi doorbell and the wake agent share.

WHY THIS IS ITS OWN FILE, importing nothing but the stdlib and PyNaCl.

`gs_doorbell` runs on the Raspberry Pi, which OPSEC_SETUP.md §3 defines by what
it must NEVER hold: spend key, view key, wallet_*.json, thor_pairs.json, memo,
seed. A doorbell that imported `gs_common` would drag `requests`, `tenacity` and
the wallet-RPC client onto that SD card, and every one of those is a reason for
the next person to reach for them. The split is enforced by the import list, not
by a promise: tests/test_opsec_doc.py asserts that `gs_doorbell` imports none of
`gs_common`, `monero`, `stem`, `psutil` or `requests`, and references none of
`wallet_`, `thor_pairs`, `view_key`, `spend_key`, `mnemonic`, `seed`.

So the protocol lives here, both boxes import this, and this imports almost
nothing.

--------------------------------------------------------------------------
THE ONE ATTACK THAT SHAPED THIS FILE
--------------------------------------------------------------------------
The first design used a single `crypto_box` for both directions. That is
broken, and not subtly. Measured on PyNaCl 1.6.2:

    crypto_box_beforenm(pi_pk, tp_sk) == crypto_box_beforenm(tp_pk, pi_sk)
    -> True.  ONE symmetric key, both directions.

So the ThinkPad's own request, replayed back at it by anyone on the switch,
decrypts and authenticates as if it were the Pi's answer -- and because the
request CARRIES the challenge, the echoed-challenge check passes too. Both
stated acceptance gates satisfied by a message the ThinkPad wrote itself.
Executed end to end before this file was written; it is not a worry, it is a
result.

Two independent defences, because they cover different message pairs:

  * M2 is boxed to a PER-BOOT EPHEMERAL public key the ThinkPad mints at
    startup and never writes to disk. M1 is boxed to the Pi's static key. They
    are different keys, so a replayed M1 does not decrypt at the M2 reader at
    all -- the attack dies at the first step rather than at a JSON KeyError.
    It also buys forward secrecy for the only message carrying content: a door
    kick that yields the Pi's long-term secret does not decrypt six months of
    M2s recorded off the switch.
  * M1 and M3 DO share a key (both ThinkPad-static -> Pi-static), so they get a
    16-byte DOMAIN TAG as the first bytes of the plaintext, compared with
    `hmac.compare_digest` before anything is parsed. M3 replayed as M1 is
    refused by the tag.

`crypto_kx` would give directional keys too. It was considered and cut: the
ephemeral already separates M1 from M2, the tag already separates M1 from M3,
and crypto_kx would add client/server role semantics to the keyfile and drop
this file from `nacl.public` to `nacl.bindings` for a property already held.

--------------------------------------------------------------------------
EVERY RECORD IS EXACTLY 1064 BYTES
--------------------------------------------------------------------------
`Box.encrypt()` is length-preserving: it returns the 24-byte nonce prepended to
the ciphertext and its 16-byte MAC, so the wire size is len(plaintext) + 40.
Unpadded, that leaks which job was requested by size alone. Measured on the
real vocabulary:

    receive_new   76 bytes
    receive_and_quote / swap-shaped  91 bytes
    watch        100 bytes

An observer on the switch reads the job off the length without touching the
crypto. So every plaintext is padded with `sodium_pad` (ISO/IEC 7816-4) to
exactly one PAD_BLOCK block, making every record on the wire 1064 bytes:

    24 (nonce) + 1024 (padded plaintext) + 16 (MAC) = 1064

Verified for every inner length 0..1023: the set of resulting record sizes is
exactly {1064}. sodium_pad always adds at least one byte, so an inner of 1024
would pad to 2048 -- which is why `seal` REFUSES an inner over 1023 rather than
silently emitting a double-length record that is itself a signal.

1064, NOT THE 296 THIS SECTION SAID FOR MOST OF ITS LIFE. The block went from
256 to 1024 to carry a sealed slip (see "THE SEALED SLIP" below), and this
paragraph is rewritten rather than left standing, because a header that
confidently states a number the code no longer uses is worse than no header:
the next person sizes a field against 255 and finds out on a woken box in the
field. The property never changed and is not smallness -- it is that there is
exactly ONE length, so an M1, an M2, an M3 with no slip and an M3 carrying one
are indistinguishable on the switch.

What this hides and what it does not: a passive observer learns that an
exchange happened, when, and between which two addresses. It does not learn
which job, or how large an amount. The WOL packet and the fans announce the
rest, and OPSEC_SETUP.md §6 says so honestly ("jitter helps, does not erase").

--------------------------------------------------------------------------
THE NONCE IS NOT A DECISION ANYONE GETS TO MAKE
--------------------------------------------------------------------------
XSalsa20-Poly1305 with a repeated (key, nonce) is not weakened, it is broken:
the keystreams XOR out and the Poly1305 one-time key falls out with them, after
which an attacker forges arbitrary messages. The classic way to get there is a
counter in the payload that someone later "reuses" as the nonce.

So there is no counter in this protocol (freshness is the challenge -- see
below), and `seal()` takes no nonce parameter. `Box.encrypt()` draws its own
24 random bytes. The API surface makes the mistake unrepresentable rather than
discouraged, and tests/test_wake_protocol.py asserts that this module exposes
no way for a caller to supply one.

--------------------------------------------------------------------------
NO CLOCK. THE CHALLENGE IS THE FRESHNESS.
--------------------------------------------------------------------------
An earlier draft carried `issued_at` / `expires_at`. Measured against a
ThinkPad that boots cold with a flat CMOS battery:

    clock at epoch      every note ever recorded passes  (fails OPEN)
    clock 2 h fast      a valid, current note is refused (fails CLOSED, wrongly)

and when it fails closed it tells the operator "job expired", which is false --
the job is current and the clock is wrong. That is this repo's named recurring
defect, a message that contradicts what the code did.

Freshness is therefore the challenge: 32 bytes the ThinkPad draws AFTER it has
booted, sends in M1, and requires echoed in M2. It needs no clock and no
persisted state, which is exactly what a machine that boots cold with a
wipeable disk can deliver. The round trip is bounded by the ThinkPad's OWN
`time.monotonic()` -- one machine, one clock, correct with a dead RTC.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import secrets
import time

#: Wire version. A peer that does not recognise a tag REFUSES. There is no
#: negotiation and no "try v1 if v2 fails" -- a downgrade path is a way to be
#: talked back to the version whose flaw you are patching.
#:
#: 2: M3 may carry a SEALED SLIP, which took PAD_BLOCK from 256 to 1024. Both
#: boxes must be updated together and there is no compatibility mode: an old
#: doorbell rejects a new record on LENGTH, before any crypto, with "wake
#: record is 1064 bytes, not 296" -- loud, immediate and impossible to
#: misread. That is the intended failure. A silent partial upgrade, where the
#: vault seals a slip the Pi cannot carry, is the one outcome worth ruling
#: out, because it fails at the moment money is waiting on it.
WIRE_VERSION = 2

#: Fixed-width so the tag never changes the padded length, and so the compare
#: is constant-length. NUL-padded to 16.
TAG_LEN = 16
TAG_M1 = b"GSWAKE-v1-M1".ljust(TAG_LEN, b"\0")   # ThinkPad -> Pi   "I am awake"
TAG_M2 = b"GSWAKE-v1-M2".ljust(TAG_LEN, b"\0")   # Pi -> ThinkPad   "do this job"
TAG_M3 = b"GSWAKE-v1-M3".ljust(TAG_LEN, b"\0")   # ThinkPad -> Pi   "it is done"
#: The pairing ceremony's LAST exchange, after both operators confirmed the
#: code. Two tags, not one, for the same reason M1 and M3 have two: both are
#: sealed under the same static-static key, so only a domain tag stops one
#: being replayed as the other.
TAG_PC = b"GSWAKE-v2-PC".ljust(TAG_LEN, b"\0")   # Pi -> ThinkPad   "my address"
TAG_PV = b"GSWAKE-v2-PV".ljust(TAG_LEN, b"\0")   # ThinkPad -> Pi   "my MAC"
#: The sealed slip. NOT a record on the wire -- it is a payload that TRAVELS
#: inside M3 and then onward through the Pi and Telegram to a machine that
#: holds a key neither of them has. It gets its own tag for the same reason M1
#: and M3 do: it is sealed under a static-static box, and only a domain tag
#: stops one kind of message being opened as another.
TAG_SL = b"GSWAKE-v3-SL".ljust(TAG_LEN, b"\0")   # ThinkPad -> delivery machine

#: One 1024-byte block. See the header for why every record is the same size.
#:
#: WAS 256, AND THE REASON IT MOVED IS THE SLIP. An M3 carrying a sealed slip
#: measures 750 bytes of inner (tag + JSON), against 148 for the M3 that
#: carries only a status and a handle. 256 cannot hold it and neither can 512;
#: 1024 holds it with 273 bytes to spare, which is the same headroom argument
#: WINDOW_BYTES makes one screen down.
#:
#: THE SECURITY PROPERTY IS UNIFORMITY, NOT SMALLNESS. Every record on the
#: switch is still exactly one length, so a watcher still cannot tell an M1
#: from an M2 from an M3, nor a job that produced a slip from one that did
#: not -- an M3 with no slip pads to the same 1064 bytes as one with. What is
#: given up is 768 bytes per record on a LAN that carries at most five records
#: per wake. That is not a cost worth protecting.
PAD_BLOCK = 1024
#: 24-byte nonce + 16-byte MAC, measured, not assumed.
BOX_OVERHEAD = 40
#: The only length any record may have. Checked BEFORE any crypto runs.
RECORD_LEN = PAD_BLOCK + BOX_OVERHEAD            # 1064

#: The largest inner (tag + body) that still pads to ONE block.
MAX_INNER = PAD_BLOCK - 1

#: THE SLIP'S OWN BLOCK, and it is padded for a different reason than the
#: records are.
#:
#: A record is padded so the LAN cannot tell the messages apart. A slip is
#: padded so that the length of the base64 blob -- which travels through
#: Telegram, in a chat, in the clear as far as Telegram is concerned -- says
#: nothing about what is inside it. Unpadded, the blob's length is a direct
#: readout of the memo's length, and the memo's length distinguishes a
#: 95-character standard XMR address from a 106-character integrated one; the
#: amount's digit count leaks the same way. Padded, every slip this repo ever
#: emits is exactly SLIP_B64_LEN characters, whatever it holds.
#:
#: 384 against a measured 346-byte worst case (tag + a payload carrying a
#: 95-char destination, a 111-char memo, a 42-char deposit address, both
#: amounts, a timestamp and a handle).
SLIP_PAD = 384
#: The largest inner (tag + body) a slip may carry.
SLIP_MAX_INNER = SLIP_PAD - 1
#: Exactly one length, always: base64(SLIP_PAD + BOX_OVERHEAD) = base64(424).
#: Asserted at import rather than trusted, because this number is what the
#: doorbell length-checks an inbound slip against before it does anything else
#: with it, and a wrong constant there is a check that passes nothing.
SLIP_B64_LEN = 568
if len(base64.b64encode(b"\0" * (SLIP_PAD + BOX_OVERHEAD))) != SLIP_B64_LEN:
    raise RuntimeError(                                      # pragma: no cover
        "SLIP_B64_LEN does not match SLIP_PAD + BOX_OVERHEAD. One of these "
        "three numbers was edited without the others, and the doorbell "
        "length-checks every inbound slip against SLIP_B64_LEN — so the "
        "mismatch would present as every slip being rejected as malformed.")

# ---------------------------------------------------------------------------
#  THE PLAINTEXT SLIP, AND WHY IT EXISTS ALONGSIDE THE SEALED ONE
#
#  The sealed slip solved "the operator cannot walk to the vault" by moving the
#  payload to a THIRD machine holding a delivery key. That assumed a third
#  machine. An operator with only a phone has none, and told us so.
#
#  So there is a second mode: the vault puts the deposit instructions in M3 in
#  the clear, the Pi relays them to the chat, and the operator reads them on
#  their phone. The wire itself is unchanged -- M3 is still boxed between the
#  vault and the Pi, so nothing on the LAN sees this -- but the Pi sees it in
#  RAM and Telegram keeps a copy for ever.
#
#  WHAT THIS COSTS, AND IT IS NOT ONLY PRIVACY.
#
#  The privacy half is the smaller half. The ThorChain deposit address is a
#  SHARED pooled inbound vault (thor_swap_preparer says so) and the destination
#  is a one-shot Monero account minted inside the same job, so the transcript
#  is not publishing a long-lived identity. The real privacy loss is
#  ATTRIBUTION -- a SIM-bound account and a phone are now tied to a swap -- and
#  ARCHIVE, a searchable server-side ledger of every run that paranoia_mode
#  cannot reach.
#
#  THE MONEY HALF IS WORSE AND MUST BE READ BEFORE TURNING THIS ON. Because
#  the deposit address is shared, the memo is the ENTIRE binding between the
#  operator's Bitcoin and their Monero. The sealed slip was AUTHENTICATED:
#  gs_unseal refuses anything the vault did not seal. This is not. Whoever
#  holds the bot token can leave the deposit line correct, substitute their own
#  address into the memo, and the operator's BTC becomes their XMR,
#  irreversibly.
#
#  That is not fixable here and this comment will not pretend otherwise. A
#  human cannot verify a 111-character memo by eye, and every scheme that looks
#  like it helps -- a one-time code sheet, an HMAC, echoing the memo back for
#  confirmation -- fails against the same attacker, because someone holding the
#  token IS the bot as far as the phone can tell: they can suppress the real
#  message and send theirs first. The mitigation is the token, and only the
#  token.
#
#  So: OFF unless the vault's own keyfile turns it on, which needs physical
#  access to the vault. A compromised Pi cannot ask for plaintext.
# ---------------------------------------------------------------------------

#: The ONLY fields a plaintext slip may carry, and the length each may have.
#:
#: An allowlist with bounds, not "whatever the pair record holds", for the same
#: reason the sealed slip has one: the pair is written by another tool and the
#: next field somebody adds there must not ride along into a chat window.
#: The bounds are generous enough for a 106-character integrated Monero
#: address and a taproot deposit address, and tight enough that no field can
#: become a channel.
PLAIN_FIELDS = {
    "b": 24,      # btc_in, as a decimal string
    "d": 100,     # the ThorChain inbound deposit address
    "m": 220,     # the swap memo
    "x": 32,      # expected_xmr
    "h": 4,       # the handle
}
#: dest_xmr is DELIBERATELY ABSENT. The sealed slip carries it so gs_unseal can
#: re-check memo_binds_destination on a second machine. A phone cannot run that
#: check, so the field would be a second copy of the destination in the
#: transcript buying nothing. `ts` is absent for the same reason: the operator
#: reads the message's own timestamp.

#: The one word an M3 may carry about how a swap is going.
#:
#: A CLOSED SET, not free text, and that is the whole design. The operator
#: needs "has my money arrived?" answered on their phone; the vault must not
#: gain a free-text channel to the Pi and onward to Telegram while answering
#: it. Each word maps to one fixed sentence on the pager side.
#:
#:   ""         nothing to say (every job that is not a status probe)
#:   not_yet    the address is empty. Normal. This is NOT a failure, and
#:              reporting it as one is the defect this vocabulary exists for.
#:   arriving   something landed and is still confirming
#:   landed     at or over the expected amount, unlocked and spendable
#:   short      money arrived, stopped growing, and is under what was quoted
#:   stuck      the wallet is not scanning; says NOTHING about the money
#:   more_left  a withdrawal finished and another arrival is still here
#:
#: "more_left" IS ON THE `phase` FIELD RATHER THAN A NEW ONE, deliberately.
#: The field is already on the wire, already a CLOSED vocabulary the doorbell
#: validates before the pager can see it, and it is unused by every spending
#: job -- _phase_of returns "" for anything that is not a watching job. Adding
#: a key to the M3 record instead would break the doorbell's exact-key-set
#: check and force both boxes to be updated in the same sitting, which is a
#: real cost to pay for a fact that fits in a word this record already carries.
PHASES = ("", "not_yet", "arriving", "landed", "short", "stuck", "more_left")

CHALLENGE_BYTES = 32
JOB_ID_BYTES = 16
#: The doorbell's per-window nonce. SIXTEEN, not thirty-two, and the reason is
#: arithmetic rather than taste: M1 already carries a 32-byte ephemeral public
#: key and a 32-byte challenge, each 64 hex characters, and at 32 bytes this
#: took the inner record to 248 of the 255 that fit in one padded block at the
#: time. seal() refuses a longer one rather than emitting a visibly different
#: record -- correct, but it means the next field anybody adds fails on a woken
#: box in the field. 16 bytes leaves real headroom.
#:
#: PAD_BLOCK is 1024 now, so that particular squeeze is long gone and the 16
#: is no longer load-bearing. It stays at 16 because there is nothing to gain
#: from 32 -- see the paragraph below -- and because re-widening it would be
#: another incompatible wire change for no property.
#:
#: Nothing is lost. This value is not a key and does not need to resist search:
#: forging an M1 needs the vault's static secret, so the nonce only has to be
#: FRESH. 128 bits of it, from the same getrandom() as everything else here.
WINDOW_BYTES = 16
#: The handle the operator reads off the terminal and the doorbell may learn.
#: FOUR hex characters, uppercase, and RANDOM -- never derived from the slip,
#: the address or the memo. A derived handle would let a seized Pi confirm or
#: deny candidate addresses read straight off the public Bitcoin OP_RETURNs,
#: which links a specific BTC deposit to this operator.
HANDLE_RE = re.compile(r"^[0-9A-F]{4}\Z")
_HEX_RE = re.compile(r"^[0-9a-f]+\Z")


class WakeError(Exception):
    """A record was refused. The message is operator-facing and must never
    echo attacker-supplied bytes back into a log or a terminal."""


class PairAborted(WakeError):
    """A HUMAN decided not to pair. Distinct from every other pairing failure.

    The vault keeps listening through connections that fail before anyone was
    asked anything -- a port scanner, a monitoring probe, a half-open TCP
    connection, an attacker sending noise -- because otherwise the first stray
    packet on the LAN consumes the ceremony and the operator has to start over
    without being told why. Found by driving it: a two-line readiness probe in
    a test connected, closed, and the real Pi then got 'connection refused'
    from a vault that had already 'paired' with nothing.

    It must NOT keep listening once a person has answered no. That is a
    decision, not a fault, and retrying past it would ask them again until they
    got it wrong.
    """


# ---------------------------------------------------------------------------
#  PyNaCl, imported at point of use and fail-closed
# ---------------------------------------------------------------------------
def _nacl():
    """Return (public, bindings) or raise WakeError.

    ABORT, NEVER DEGRADE. thor_swap_preparer's --gpg-recipient has a
    meaningful unencrypted state to fall back to; "an unauthenticated wake
    note" is not a thing that exists. There is no HAVE_NACL flag, no fallback
    to hmac/hashlib, and no second path through `cryptography` -- a second code
    path is a second thing to audit, and a hand-rolled one is the invented
    crypto the house style forbids.

    Imported HERE rather than at module top so `--help` still works on a clean
    install; tests/test_cli_flags.py runs --help on every shipped program and
    would go red on a top-level import.
    """
    try:
        import nacl.public
        import nacl.bindings
        return nacl.public, nacl.bindings
    except Exception as e:                                   # noqa: BLE001
        raise WakeError(
            f"PyNaCl is not installed ({type(e).__name__}), so no wake message "
            f"can be authenticated or encrypted. Install it with "
            f"`pip install PyNaCl`. There is no unauthenticated mode: a wake "
            f"note nobody can authenticate is a magic packet with extra steps."
        ) from e


def require_nacl() -> None:
    """Fail now, loudly, rather than at the first relay."""
    _nacl()


# ---------------------------------------------------------------------------
#  Hardened JSON
# ---------------------------------------------------------------------------
def _refuse_constant(name):
    # json.loads('{"a": Infinity}') returns inf by DEFAULT in CPython, measured.
    # tests/test_signer_schema.py records what that already cost this repo once:
    # an INFINITE amount passed a positivity test because Decimal("Infinity") <= 0
    # is False.
    raise WakeError(f"refusing a non-finite JSON constant ({name}) in a wake note")


def _refuse_dupes(pairs):
    # json.loads('{"job":"receive_new","job":"run_pipeline"}') returns
    # {'job': 'run_pipeline'} -- LAST KEY WINS, measured. A parser that silently
    # picks one of two conflicting job ids is a parser that can be argued into
    # picking the wrong one.
    seen = set()
    for k, _v in pairs:
        if k in seen:
            raise WakeError("refusing a wake note with a duplicate JSON key")
        seen.add(k)
    return dict(pairs)


def _refuse_floats(obj):
    """No float anywhere in the tree.

    Nothing in this vocabulary is fractional: every schema value is a bounded
    int or a fixed-shape string. Refusing floats outright removes the whole
    numeric-parsing surface -- no precision, no sign, no magnitude, no NaN --
    rather than defending each of its edges.
    """
    if isinstance(obj, float):
        raise WakeError("refusing a float in a wake note")
    if isinstance(obj, dict):
        for v in obj.values():
            _refuse_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _refuse_floats(v)


def parse_body(raw: bytes) -> dict:
    """Parse a wake note body under every guard at once."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise WakeError("wake note body is not valid UTF-8") from e
    try:
        obj = json.loads(text, parse_constant=_refuse_constant,
                         object_pairs_hook=_refuse_dupes)
    except WakeError:
        raise
    except Exception as e:                                   # noqa: BLE001
        raise WakeError(f"wake note body is not JSON ({type(e).__name__})") from e
    if not isinstance(obj, dict):
        raise WakeError("wake note body is not a JSON object")
    _refuse_floats(obj)
    return obj


# ---------------------------------------------------------------------------
#  Seal / open. The ONLY encrypt and decrypt paths.
# ---------------------------------------------------------------------------
def seal(sender_secret, recipient_public, tag: bytes, body: dict) -> bytes:
    """Encrypt+authenticate one record. Returns exactly RECORD_LEN bytes.

    No nonce parameter, deliberately -- see the header.
    """
    public, bindings = _nacl()
    if tag not in (TAG_M1, TAG_M2, TAG_M3, TAG_PC, TAG_PV):
        raise WakeError("refusing to seal a record with an unknown tag")
    # sort_keys so the same body always produces the same inner length; the
    # padding makes the WIRE length constant regardless, but a deterministic
    # encoding is what lets a test assert the length is constant rather than
    # merely observing that it happened to be.
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    inner = tag + raw
    if len(inner) > MAX_INNER:
        # REFUSE rather than emit a 512-byte record. A record twice the size of
        # every other record is itself the signal the padding exists to remove.
        raise WakeError(
            f"wake note is {len(inner)} bytes and the wire format carries at "
            f"most {MAX_INNER}; a longer record would be visibly different on "
            f"the switch, which is what the padding exists to prevent")
    padded = bindings.sodium_pad(inner, PAD_BLOCK)
    rec = bytes(public.Box(sender_secret, recipient_public).encrypt(padded))
    if len(rec) != RECORD_LEN:                               # pragma: no cover
        raise WakeError(
            f"sealed record is {len(rec)} bytes, not {RECORD_LEN}; refusing to "
            f"put a distinguishable record on the wire")
    return rec


def open_record(recipient_secret, sender_public, record: bytes,
                expect_tag: bytes) -> dict:
    """Decrypt, authenticate, check the tag, and parse. The ONLY decrypt path.

    Order matters and is asserted by the suite:
      1. length, before any crypto touches attacker bytes
      2. box open -- authenticity and integrity
      3. unpad
      4. tag, with compare_digest
      5. hardened parse
    """
    public, bindings = _nacl()
    if not isinstance(record, (bytes, bytearray)):
        raise WakeError("wake record is not bytes")
    if len(record) != RECORD_LEN:
        # Cheap, and it means a flood of garbage never reaches the AEAD.
        raise WakeError(
            f"wake record is {len(record)} bytes, not {RECORD_LEN} — refusing "
            f"before decrypting")
    try:
        padded = public.Box(recipient_secret, sender_public).decrypt(bytes(record))
    except Exception as e:                                   # noqa: BLE001
        raise WakeError(
            "wake record failed to authenticate: it was not written by the "
            "expected peer, or it was altered in flight") from e
    try:
        inner = bindings.sodium_unpad(padded, PAD_BLOCK)
    except Exception as e:                                   # noqa: BLE001
        raise WakeError("wake record padding is malformed") from e
    if len(inner) < TAG_LEN:
        raise WakeError("wake record carries no tag")
    # compare_digest, not ==. The tag is the only thing standing between a
    # replayed M1 and the M3 reader, both of which are sealed under the SAME
    # key (ThinkPad-static -> Pi-static).
    if not hmac.compare_digest(inner[:TAG_LEN], expect_tag):
        # Never echo the received tag. It is attacker-controlled bytes and this
        # message reaches a terminal and, on the Pi, a journal.
        raise WakeError(
            "wake record is the wrong kind of message for this endpoint")
    return parse_body(inner[TAG_LEN:])


# ---------------------------------------------------------------------------
#  THE SEALED SLIP
#
#  WHAT THIS IS FOR, because it looks like a hole in the design until you know.
#
#  Every other line in this repo works to keep the deposit address and the memo
#  ON THE VAULT. OPSEC_SETUP.md section 8 is blunt about it: "Do not 'just run a
#  Telegram bot' that prints the memo -- that throws away the only reason to
#  have a Pi." That rule is right, and it is not what this is.
#
#  The rule assumes the operator can WALK TO THE VAULT and read the slip off
#  its screen. When they cannot -- and the vault is meant to live somewhere
#  far away and hard to reach, which is the entire point of it -- then "read it
#  on the vault" is not an OPSEC property, it is a dead end: the operator is
#  told a swap is quoted and given no way to pay it. A quote they cannot act on
#  is a quote that expires.
#
#  So the payload travels, and it travels SEALED TO A KEY THAT NEITHER THE PI
#  NOR TELEGRAM HAS:
#
#    * sealed with Box(vault_static_secret, delivery_public) -- authenticated,
#      so the delivery machine knows the vault wrote it and not whoever holds
#      the bot token. NOT SealedBox: an anonymous box would let anyone who
#      learned the delivery public key hand the operator a deposit address of
#      their choosing, and "where do I send the BTC" is the single field in
#      this whole system that must be authenticated.
#    * the delivery SECRET never exists on the Pi and never exists on the
#      vault after setup -- gs_delivery_key writes it to removable media and
#      the operator carries it to the machine that will send the BTC.
#    * so a seized Pi, a stolen SD card, a stolen phone, a stolen bot token
#      and Telegram itself all get the same thing: 568 characters of base64
#      that decrypt to nothing without a key that was never near any of them.
#
#  What is genuinely given up, stated plainly rather than buried: the ciphertext
#  now exists off the vault, so an adversary who later obtains the delivery key
#  can read any blob they kept. That is strictly more than "the slip never
#  left", and it is the trade the operator is choosing when they set
#  delivery_public. With no delivery_public set, nothing is sealed, nothing
#  travels, and the old behaviour is exactly what it was.
# ---------------------------------------------------------------------------
def seal_slip(sender_secret, recipient_public, body: dict) -> str:
    """Seal one slip for a machine that is not on the wake channel.

    Returns base64, always exactly SLIP_B64_LEN characters.
    """
    public, bindings = _nacl()
    # SYMMETRIC WITH THE READER, deliberately. open_slip goes through
    # parse_body, which calls _refuse_floats -- so without this the vault can
    # seal a slip that the delivery machine will refuse to open, and it fails
    # at the machine holding the money, for a swap already quoted, on a box
    # 500 km from the one that made the mistake. Failing HERE means the vault
    # says so on its own terminal, seal_slip_for_delivery reports no slip, and
    # the chat says so honestly.
    #
    # Nothing in a slip is fractional today: both amounts are strings (fmt_btc
    # and str(Decimal)) and the timestamp is an int. This is about the field
    # somebody changes the type of later, in the other tool that writes the
    # pair record.
    _refuse_floats(body)
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    inner = TAG_SL + raw
    if len(inner) > SLIP_MAX_INNER:
        # Same refusal as seal(), for a related reason: a slip twice the length
        # of every other slip is a slip that announces something about itself
        # in a chat window.
        raise WakeError(
            f"slip is {len(inner)} bytes and the format carries at most "
            f"{SLIP_MAX_INNER}; a longer one would be visibly different in "
            f"the chat, which is what the padding exists to prevent")
    padded = bindings.sodium_pad(inner, SLIP_PAD)
    box = bytes(public.Box(sender_secret, recipient_public).encrypt(padded))
    blob = base64.b64encode(box).decode("ascii")
    if len(blob) != SLIP_B64_LEN:                            # pragma: no cover
        raise WakeError(
            f"sealed slip is {len(blob)} characters, not {SLIP_B64_LEN}; "
            f"refusing to emit a distinguishable slip")
    return blob


def open_slip(recipient_secret, sender_public, blob: str) -> dict:
    """Open one sealed slip. The ONLY slip decrypt path.

    Same order as open_record and for the same reasons: length first, so a
    pasted-in blob of garbage never reaches the AEAD; then the box; then the
    unpad; then the tag under compare_digest; then the hardened parse.
    """
    public, bindings = _nacl()
    if not isinstance(blob, str):
        raise WakeError("slip is not text")
    blob = blob.strip()
    if len(blob) != SLIP_B64_LEN:
        raise WakeError(
            f"slip is {len(blob)} characters, not {SLIP_B64_LEN}. A slip is "
            f"one line and is never truncated, wrapped or re-typed by hand — "
            f"paste the whole thing.")
    try:
        # validate=True, so base64 does not silently DISCARD characters it does
        # not recognise. Without it a blob with a space, a newline or a chat
        # client's smart quote in the middle decodes to something shorter and
        # then fails at the AEAD with "it was not written by the expected
        # peer" -- an alarming message for what is really a copy/paste fault.
        box = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError) as e:
        raise WakeError(
            "slip is not valid base64 — something rewrote it in transit. "
            "Copy it again straight from the message.") from e
    # THE DECODED LENGTH, not just the encoded one. 568 characters can decode
    # to 424, 425 or 426 bytes depending on how many "=" the tail carries, and
    # only 424 is a slip. Without this the odd ones reach the AEAD and fail as
    # "it was not sealed by your vault — DO NOT SEND ANY BITCOIN", which tells
    # an operator their vault may be compromised when a character got mangled
    # in a chat client. slip_is_wellformed already checks this; open_slip
    # checking something weaker than the doorbell's shape test is backwards.
    if len(box) != SLIP_PAD + BOX_OVERHEAD:
        raise WakeError(
            "slip decodes to the wrong size — something rewrote it in "
            "transit. Copy it again straight from the message.")
    try:
        padded = public.Box(recipient_secret, sender_public).decrypt(box)
    except Exception as e:                                   # noqa: BLE001
        raise WakeError(
            "slip failed to authenticate: it was not sealed by your vault, or "
            "it was altered. DO NOT SEND ANY BITCOIN ON THE STRENGTH OF IT."
        ) from e
    try:
        inner = bindings.sodium_unpad(padded, SLIP_PAD)
    except Exception as e:                                   # noqa: BLE001
        raise WakeError("slip padding is malformed") from e
    if len(inner) < TAG_LEN:
        raise WakeError("slip carries no tag")
    if not hmac.compare_digest(inner[:TAG_LEN], TAG_SL):
        raise WakeError("that is not a slip — it is a different kind of record")
    return parse_body(inner[TAG_LEN:])


def plain_slip_is_wellformed(obj) -> bool:
    """Is this the right SHAPE for a plaintext slip? Nothing about correctness.

    The doorbell relays this to a chat, so it checks what it can: an EXACT key
    set (not a superset -- a field the Pi does not know about must not be
    forwarded to Telegram unexamined), string values only, non-empty, within
    the declared bound, and no control characters.

    Control characters matter here more than anywhere else in this file: the
    pager pastes these values into a message a human reads and copies into a
    wallet, and a newline in the memo forges a line of it.
    """
    if not isinstance(obj, dict) or set(obj) != set(PLAIN_FIELDS):
        return False
    for k, cap in PLAIN_FIELDS.items():
        v = obj[k]
        if not isinstance(v, str) or not v or len(v) > cap:
            return False
        if any(ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f for c in v):
            return False
    return True


def phase_is_known(word) -> bool:
    """Is this one of the words this protocol has? Never a substring test."""
    return isinstance(word, str) and word in PHASES


#: One word -> one sentence, and the sentences live HERE, next to the
#: vocabulary, for the same reason VAULT_JITTER_LO_S does: two boxes render
#: this and they must not drift into disagreeing about what a word means.
#:
#: Every line says what is TRUE and what to do next. "not_yet" in particular
#: is written to read as ordinary, because it is the answer the operator will
#: get most often and the old code delivered it as "the vault ran it and it
#: FAILED" while their money was simply still in flight.
#: THESE ARE CHAT TEXT, and they live in the wrong file to look like it.
#:
#: gs_telegram_pager sends them verbatim -- `f"{h}: {PHASE_LINES.get(phase)}"`
#: -- so every word here lands in the transcript. The source-level guard that
#: strips machine names from the pager's replies reads string literals in
#: gs_telegram_pager and could not see these: two of them said "check it on
#: the vault" and "the vault's wallet is not scanning", which is the operator's
#: own hardware named in the readable surface, twice, on the two answers most
#: likely to be asked for when something has gone wrong.
#:
#: The information survives without the noun. "Check before mixing" is the same
#: instruction; the operator knows which machine is theirs.
PHASE_LINES = {
    "not_yet": "nothing on the address yet. Normal — ask again in a while.",
    "arriving": "something arrived and is still confirming. Ask again shortly.",
    # "Done." WAS TOO SHORT AND SAID SOMETHING FALSE. Shortening this from
    # "The swap is done" to "Done" changed which noun it was about: the
    # swap has landed, the mix has NOT run, and the mix is the entire
    # point. An operator reading "Done" on the surface they check most is
    # being told the job finished when the money is sitting un-mixed. It
    # says which step ended, without naming the one that has not.
    "landed": "landed and spendable. The swap is done.",
    "short": "arrived, but UNDER what was quoted, and it has stopped growing. "
             "Check before going further.",
    "stuck": "not scanning, so this says NOTHING about your money. Check.",
    # NOT RENDERED ON ITS OWN. The pager acts on this one -- it starts the
    # next leg -- and says so in its own words, because "more left" is not
    # something the operator has to do anything about. The sentence is here
    # so that a version which does NOT act on it still says something true.
    "more_left": "that one is done and there is more here. Run /withdraw "
                 "again for the next.",
}


def plain_lines(plain: dict) -> list:
    """The deposit instructions as lines a human reads and copies. No I/O.

    Shared so the doorbell's terminal and the pager's chat message cannot
    drift: an operator running the doorbell by hand must see exactly what the
    chat would have shown, or the by-hand path stops being a way to check the
    automated one.

    THE MEMO IS ON ITS OWN LINE, LAST, AND UNDECORATED. It is the field that
    has to be copied character-for-character into a wallet, and anything
    wrapped around it -- a bullet, a trailing note, a closing bracket -- ends
    up in the paste.
    """
    return [
        f"Send exactly:  {plain.get('b', '')} BTC",
        f"To address:    {plain.get('d', '')}",
        f"Expected out:  ~{plain.get('x', '')} XMR",
        f"Slip:          {plain.get('h', '')}",
        "",
        "The memo below MUST go in an OP_RETURN in the same transaction.",
        "A payment without it is one ThorChain cannot route.",
        "",
        plain.get("m", ""),
    ]


def slip_is_wellformed(blob) -> bool:
    """Is this the RIGHT SHAPE for a slip? Says nothing about whether it opens.

    The doorbell needs this: it must decide whether to carry a blob it has no
    key for, and the only honest thing it can check is the shape.
    """
    if not isinstance(blob, str) or len(blob) != SLIP_B64_LEN:
        return False
    try:
        return len(base64.b64decode(blob, validate=True)) == SLIP_PAD + BOX_OVERHEAD
    except (binascii.Error, ValueError):
        return False


# ---------------------------------------------------------------------------
#  Field helpers
# ---------------------------------------------------------------------------
def new_challenge() -> bytes:
    """32 bytes from secrets.token_bytes.

    secrets routes to getrandom(), which BLOCKS until the kernel CRNG is
    seeded. That is fail-closed by construction: on a machine that has just
    booted, the challenge cannot come out weak, it can only come out late.
    Never `random`, and never mixed with libsodium's randombytes -- one source,
    so there is one thing to reason about.
    """
    return secrets.token_bytes(CHALLENGE_BYTES)


def new_job_id() -> str:
    return secrets.token_bytes(JOB_ID_BYTES).hex()


def new_handle() -> str:
    """A RANDOM 4-hex-character handle. See HANDLE_RE for why not derived."""
    return secrets.token_bytes(2).hex().upper()


def _hexfield(body: dict, key: str, nbytes: int) -> bytes:
    v = body.get(key)
    if not isinstance(v, str) or len(v) != nbytes * 2 or not _HEX_RE.match(v):
        raise WakeError(f"wake note field {key!r} is not {nbytes} hex bytes")
    return bytes.fromhex(v)


def challenge_of(body: dict) -> bytes:
    return _hexfield(body, "challenge", CHALLENGE_BYTES)


def eph_pk_of(body: dict) -> bytes:
    return _hexfield(body, "eph_pk", 32)


def new_window() -> bytes:
    return secrets.token_bytes(WINDOW_BYTES)


def window_of(body: dict) -> bytes:
    """The doorbell's per-window nonce, echoed back in M1. See Pending.window."""
    return _hexfield(body, "window", WINDOW_BYTES)


def job_id_of(body: dict) -> str:
    return _hexfield(body, "job_id", JOB_ID_BYTES).hex()


# ---------------------------------------------------------------------------
#  THE KEYFILE CONTAINER, AND WHY IT EXISTS
# ---------------------------------------------------------------------------
# KERCKHOFFS, TAKEN LITERALLY. This repository is public. An adversary has read
# every line of it: they know the file names, the ports, the record size, the
# job vocabulary, the systemd units, the wipe patterns and this comment. The
# ONLY thing that may be secret is key material. So the question is not "would
# anyone think to look at /etc/gs_wake_pi.key" -- they would, they read it
# here -- but "what do they get when they do".
#
# WHAT THEY GOT BEFORE. The v1 keyfile was plaintext JSON at mode 0400. A
# Raspberry Pi's SD card is not encrypted in any realistic build: pull it out,
# mount it on any laptop, and 0400 means nothing because you are root on the
# machine doing the reading. That handed over, in one file:
#
#     the Pi's long-term X25519 SECRET    -> forge job notes to the vault
#     the vault's public key              -> recognise its traffic anywhere
#     target_mac                          -> the vault's NIC, a hardware
#                                            identifier that ties that laptop
#                                            to this setup for the rest of its
#                                            life
#     listen_host / wol_broadcast         -> the LAN layout
#     pair_fingerprint                    -> a stable identifier for the pair
#
# The MAC is arguably worse than the key. A key can be rotated in one sitting;
# a NIC cannot, and it is the one value that survives reinstalling both boxes.
#
# So the Pi's keyfile is now a sealed container: Argon2id over a passphrase,
# then XSalsa20-Poly1305 over the whole payload. An imaged SD card yields the
# KDF parameters and a salt, which are not secrets, and nothing else.
#
# THE FILE SAYS WHAT IT IS. "kdf": "none" is a real, supported value and it
# stores the payload as plain JSON under "plain" rather than as unencrypted
# bytes dressed up as a ciphertext. A file that LOOKS encrypted and is not is
# worse than one that says so, because the operator plans around the look.
# gs_wake_agent's keyfile uses it deliberately -- see load_key there for why an
# unattended boot cannot do better, stated rather than papered over.

#: The keyfile format. Versioned SEPARATELY from WIRE_VERSION: the messages on
#: the wire did not change when the file format did, and one number covering
#: two things that change for different reasons is a number that lies about one
#: of them.
KEYFILE_SCHEMA = "gs_wake_v2"

#: ...AND THIS IS THE NUMBER THAT ACTUALLY MAKES IT SEPARATE.
#:
#: The paragraph above has claimed since the format landed that the keyfile is
#: "versioned SEPARATELY from WIRE_VERSION", and the code did not do it:
#: lock_keyfile stamped WIRE_VERSION into the file and unlock_keyfile demanded
#: an exact match. While WIRE_VERSION sat at 1 forever, nothing showed. The
#: moment it moved to 2 for the sealed slip, every keyfile on both boxes became
#: unreadable -- not because the FILE format changed (it did not; a keyfile
#: written yesterday is byte-identical to one written today) but because a
#: number describing the wire was being used to describe a file.
#:
#: The concrete cost of leaving it: upgrading both machines would demand a full
#: re-pairing ceremony, which needs physical access to a vault that is supposed
#: to be far away and hard to reach -- to fix nothing.
#:
#: 1, and it stays 1 until the FILE format changes. Existing files say
#: "version": 1 because WIRE_VERSION was 1 when they were written, so they keep
#: opening; that is luck, and it is why this is fixed now rather than at the
#: next bump, when it would not be.
KEYFILE_VERSION = 1

#: Argon2id profiles, by name, recorded IN the file. A file derived under one
#: profile must always be derived under that profile, so the reader takes the
#: parameters from the file rather than from this table -- the table only says
#: what a NEW file gets. Values are libsodium's own.
#:
#: MODERATE (3 passes, 256 MiB) is the default and is chosen for the hardware
#: this actually runs on. Measured with PyNaCl 1.6.2: 2.15 s on the machine
#: this was written on. A Pi 3B+ is markedly slower and has 1 GB of RAM total
#: with Tor already resident, so 256 MiB is a real allocation there -- which is
#: why `pair` MEASURES the derivation on the box doing it and prints the number,
#: instead of this comment guessing at hardware it has never run on.
#:
#: SENSITIVE (1 GiB) is deliberately absent: it cannot allocate on a 1 GB Pi,
#: and a profile that OOM-kills the doorbell is not a stronger profile.
KDF_PROFILES = {
    "moderate": (3, 268435456),
    "interactive": (2, 67108864),
}
DEFAULT_KDF = "moderate"

#: Crockford's alphabet: no I, L, O or U, so there is no 1/l, 0/O or
#: rhymes-with-you confusion when a human reads one code off a Pi's console and
#: compares it to a laptop screen. That comparison is the entire security of
#: the pairing, so the character set is a security parameter.
_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SAS_BYTES = 5                                    # 40 bits -> exactly 8 chars


def _b32(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = []
    for _ in range(len(raw) * 8 // 5):
        out.append(_B32[n & 31])
        n >>= 5
    return "".join(reversed(out))


def pair_commitment(public_key: bytes) -> bytes:
    """SHA-256 over a domain tag and one public key. See pair_sas."""
    import hashlib
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise WakeError("commitment takes a 32-byte X25519 public key")
    return hashlib.sha256(b"GSWAKE-commit-v2" + bytes(public_key)).digest()


def pair_sas(pub_a: bytes, pub_b: bytes) -> str:
    """The code the operator compares on both screens. 40 bits, 8 characters.

    WHY 40 BITS IS ENOUGH HERE, AND WOULD NOT BE ON ITS OWN.

    A man in the middle on the LAN runs two pairings at once: one with the Pi
    using a key he made up, one with the vault using another. He wins if the
    two codes come out the same, and he can pick both of his keys -- so with
    a bare short code he grinds keypairs until they collide, which for 40 bits
    is a birthday search of about 2^20 X25519 keygens. Seconds. The short code
    would be theatre.

    So the exchange COMMITS FIRST. The initiator sends SHA-256 of its public
    key before it has seen the responder's; the responder then reveals; the
    initiator reveals and the responder checks the commitment. Neither party --
    and therefore neither half of a man in the middle -- ever chooses a key
    while knowing the other side's. Grinding has nothing to grind against, and
    the attack collapses to guessing one code, once, at 1 in 2^40, with a
    failure that the operator sees. This is the ZRTP construction and it is
    used here for the same reason: it lets the thing a human must compare be
    short enough that they actually compare it.

    Sorted, so both boxes print the same string without either needing to know
    which of them is 'first'. Public keys only: a code read aloud must never be
    derived from a secret.
    """
    import hashlib
    lo, hi = sorted((bytes(pub_a), bytes(pub_b)))
    raw = hashlib.sha256(b"GSWAKE-sas-v2" + lo + hi).digest()[:SAS_BYTES]
    s = _b32(raw)
    return f"{s[:4]}-{s[4:]}"


def lock_keyfile(payload: dict, passphrase: bytes, kdf: str = DEFAULT_KDF,
                 role: str = "") -> dict:
    """Wrap a keyfile payload in a sealed container.

    passphrase=b"" means kdf="none": the payload is stored as plain JSON and
    the file SAYS so. That is not an oversight, it is the only honest way to
    represent a file that an unattended process must be able to read.
    """
    public, bindings = _nacl()
    import nacl.pwhash
    import nacl.secret
    import nacl.utils
    if not isinstance(payload, dict):
        raise WakeError("keyfile payload must be an object")
    head = {"schema": KEYFILE_SCHEMA, "version": KEYFILE_VERSION, "role": role}
    if not passphrase:
        head["kdf"] = "none"
        head["plain"] = payload
        return head
    if kdf not in KDF_PROFILES:
        raise WakeError(f"unknown KDF profile {kdf!r}")
    ops, mem = KDF_PROFILES[kdf]
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    try:
        key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE,
                                       passphrase, salt,
                                       opslimit=ops, memlimit=mem)
    except Exception as e:                                   # noqa: BLE001
        # NEVER quietly drop to a cheaper profile. A keyfile that is weaker
        # than the operator asked for, without saying so, is the exact defect
        # this whole file is written against.
        raise WakeError(
            f"could not derive the keyfile key with the {kdf!r} profile "
            f"({type(e).__name__}: {e}). That profile needs "
            f"{mem // 2**20} MiB of RAM. Free some, or pair with "
            f"--kdf interactive, which uses "
            f"{KDF_PROFILES['interactive'][1] // 2**20} MiB and is recorded in "
            f"the file so you can always see which one you chose.") from e
    box = nacl.secret.SecretBox(key)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sealed = bytes(box.encrypt(raw))
    head.update({"kdf": "argon2id", "profile": kdf, "ops": ops, "mem": mem,
                 "salt": salt.hex(), "box": sealed.hex()})
    return head


def keyfile_is_sealed(container: dict) -> bool:
    return isinstance(container, dict) and container.get("kdf") == "argon2id"


def unlock_keyfile(container: dict, passphrase: bytes = b"") -> dict:
    """Return the payload, or raise WakeError. The ONLY keyfile read path."""
    public, bindings = _nacl()
    import nacl.pwhash
    import nacl.secret
    if not isinstance(container, dict):
        raise WakeError("keyfile is not a JSON object")
    if container.get("schema") != KEYFILE_SCHEMA:
        raise WakeError(
            f"keyfile is {container.get('schema')!r}, not {KEYFILE_SCHEMA}. "
            f"The v1 format was plaintext on disk and is not read any more: "
            f"pair the two boxes again, which generates a fresh key on each "
            f"of them and carries no secret between machines.")
    if container.get("version") != KEYFILE_VERSION:
        raise WakeError(f"keyfile is format version "
                        f"{container.get('version')!r}, not {KEYFILE_VERSION}")
    kdf = container.get("kdf")
    if kdf == "none":
        payload = container.get("plain")
        if not isinstance(payload, dict):
            raise WakeError("keyfile says kdf=none but carries no payload")
        return payload
    if kdf != "argon2id":
        raise WakeError(f"keyfile names an unknown KDF {kdf!r}")
    if not passphrase:
        raise WakeError("this keyfile is passphrase-protected and no "
                        "passphrase was supplied")
    ops, mem = container.get("ops"), container.get("mem")
    # Read the parameters FROM THE FILE, never from KDF_PROFILES: a file
    # written under one profile must always be derived under that one, or
    # changing the table's defaults would silently brick every existing file.
    # Bound them anyway -- these numbers come off a disk an attacker may have
    # written to, and memlimit is an allocation.
    # isinstance(True, int) is True, so `"ops": true` would sail through an
    # isinstance check and be used as ops=1 -- below the floor of BOTH profiles,
    # silently. _int_range in the job schema already refuses bools for exactly
    # this reason; a second place in the same file that does not is the kind of
    # inconsistency that gets copied rather than noticed.
    if isinstance(ops, bool) or not isinstance(ops, int) or not 1 <= ops <= 16:
        raise WakeError("keyfile carries an out-of-range Argon2 opslimit")
    if (isinstance(mem, bool) or not isinstance(mem, int)
            or not 2**23 <= mem <= 2**30):
        # 8 MiB .. 1 GiB. Below the floor is a weakened file; above the ceiling
        # is a keyfile that OOM-kills the doorbell when it is read, which is a
        # denial of service written into a file.
        raise WakeError("keyfile carries an out-of-range Argon2 memlimit")
    try:
        salt = bytes.fromhex(container["salt"])
        sealed = bytes.fromhex(container["box"])
    except Exception as e:                                   # noqa: BLE001
        raise WakeError("keyfile salt or body is not hex") from e
    if len(salt) != nacl.pwhash.argon2id.SALTBYTES:
        raise WakeError("keyfile salt is the wrong length")
    try:
        key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE,
                                       passphrase, salt,
                                       opslimit=ops, memlimit=mem)
    except Exception as e:                                   # noqa: BLE001
        raise WakeError(f"could not derive the keyfile key "
                        f"({type(e).__name__}). This profile needs "
                        f"{mem // 2**20} MiB of RAM.") from e
    try:
        raw = nacl.secret.SecretBox(key).decrypt(sealed)
    except Exception as e:                                   # noqa: BLE001
        # ONE MESSAGE for a wrong passphrase and for a tampered file. They are
        # not distinguishable here -- Poly1305 fails the same way for both --
        # and pretending to tell them apart would be inventing a fact.
        raise WakeError(
            "the keyfile did not open: the passphrase is wrong, or the file "
            "has been altered. There is no way to tell which from here.") from e
    payload = parse_body(raw)
    return payload


# ---------------------------------------------------------------------------
#  FIRST-START PAIRING. EACH BOX MAKES ITS OWN KEY; ONLY PUBLIC KEYS MOVE.
# ---------------------------------------------------------------------------
# WHAT THIS REPLACES. v1 minted BOTH keypairs on the ThinkPad and told the
# operator to carry the Pi's SECRET across on a USB stick and then remember to
# shred it. Three copies of a secret existed at once -- the ThinkPad's disk,
# the stick, the Pi -- and two of them were the operator's job to destroy. The
# instruction was correct and nobody follows instructions at 2am.
#
# Now each box generates its own keypair, in place, and the only thing that
# crosses the LAN is a PUBLIC key. There is no step at which a secret exists
# anywhere except on the machine that will use it, so there is no step for the
# operator to get wrong.
#
# THE MAN IN THE MIDDLE, HANDLED HONESTLY. Two boxes that have never met cannot
# tell each other apart from an attacker on the same switch: whoever answers
# first is who you paired with. Nothing in software fixes that. What software
# CAN do is make the attack visible, and that is what the code below does --
# both boxes derive one short string from both public keys and show it, and a
# human compares them. An attacker in the middle held two different pairings,
# so the two strings differ and the operator sees it.
#
# That check is the entire security of this exchange. If the operator does not
# actually look at both screens, this is unauthenticated key agreement and the
# code says so where they will read it.
#
# See pair_sas for why the commitment step is what lets the string be short.

# 4, NOT 3. Bumped at 3 when the per-window nonce was added to M1 and the
# pairing `reveal` lost its plaintext `info` in favour of the sealed
# post-confirmation config exchange; bumped again at 4 when PAD_BLOCK went from
# 256 to 1024 to make room for the sealed slip. All three are incompatible wire
# changes; leaving this number alone let a new box and an old box agree to pair
# and then fail at wake time, which is the worst place to discover it.
PAIR_PROTO = 4
PAIR_MAX_LINE = 8192
#: The ceremony runs once, with a human at both ends. Generous, but bounded:
#: a pairing socket that waits forever is a socket someone can leave open.
PAIR_TIMEOUT_S = 300
#: How long a peer gets to send one MACHINE message. A real peer sends
#: immediately; this bound exists because the reads below are byte-at-a-time
#: and a socket timeout is PER READ, not for the message. Without it a peer
#: that sends one byte every 299 seconds holds the ceremony open for the better
#: part of a month while every individual recv() comes in comfortably inside
#: its timeout. Slowloris, on a socket a human is standing in front of.
PAIR_MSG_S = 30


def _pair_send(sock, obj: dict) -> None:
    """Send one line. A dead peer becomes a WakeError, never a BrokenPipeError.

    AND IT TRIES TO FIND OUT WHY FIRST. Driven over a real socket: when the
    vault refused a bad commitment it sent its abort and closed, and the Pi --
    already past its own reveal -- hit the closed socket on the NEXT send and
    reported "[Errno 32] Broken pipe". The operator standing at the Pi was
    shown a plumbing error for a detected attack. A socket closed by the peer
    still delivers whatever it sent before the FIN, so on a failed send this
    reads once more and surfaces the abort that is sitting there.
    """
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(raw) > PAIR_MAX_LINE:
        raise WakeError("pairing message is too long to send")
    try:
        sock.sendall(raw)
    except OSError as e:
        try:
            _pair_step(sock, "__none__")          # raises on an abort
        except WakeError:
            raise
        except Exception:                                    # noqa: BLE001
            pass
        raise WakeError(
            "the other box closed the connection mid-pairing and did not say "
            "why. Nothing was written here.") from e


def _pair_recv(sock, budget_s: float = PAIR_MSG_S) -> dict:
    """One newline-delimited JSON object, under a hard cap and a hard deadline.

    Read byte-at-a-time up to the cap rather than buffering: this runs exactly
    three times per pairing, so the cost does not matter, and it means a peer
    cannot make this allocate by sending a long line.

    THE DEADLINE IS FOR THE WHOLE MESSAGE, not for each read. A socket timeout
    bounds one recv(); with reads this small a peer that dribbles one byte per
    timeout-minus-a-second holds the socket for as long as it likes and every
    single read looks healthy. Bounded here instead.

    budget_s is short for the machine steps and long for the one a human is
    deciding -- the confirm exchange happens while somebody compares two
    screens, and hurrying that is how they stop comparing.
    """
    deadline = time.monotonic() + budget_s
    buf = bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise WakeError(
                f"the other box did not finish sending within {int(budget_s)} "
                f"s. Nothing was written here.")
        try:
            sock.settimeout(min(left, 5.0))
            b = sock.recv(1)
        except OSError as e:
            # WHICH IT WAS MATTERS. A read that timed out because the whole
            # message ran out of time is a peer dribbling bytes; a read that
            # failed for another reason is a broken connection. Saying
            # "connection failed" for the first sends the operator to check a
            # cable that is fine.
            if time.monotonic() >= deadline:
                raise WakeError(
                    f"the other box did not finish sending within "
                    f"{int(budget_s)} s. Nothing was written here.") from e
            raise WakeError(f"the pairing connection failed while reading "
                            f"({type(e).__name__}). Nothing was written "
                            f"here.") from e
        if not b:
            raise WakeError("the other box closed the connection mid-pairing")
        if b == b"\n":
            break
        buf += b
        if len(buf) > PAIR_MAX_LINE:
            raise WakeError("pairing message exceeded the size limit")
    return parse_body(bytes(buf))


#: WHY THE OTHER BOX GAVE UP, AS A CODE FROM A CLOSED SET. The peer's reason
#: is attacker-controlled text and must never be printed; a code is looked up
#: in THIS table and this box's own words are shown. Without any abort message
#: at all the operator standing at the other screen sees only "closed the
#: connection" and has to guess -- which is how a person decides to just try
#: again on a network that has something on it.
PAIR_ABORT = {
    "declined": "the other box's operator answered no to the code comparison.",
    "commitment": "the other box says the key it received did not match what "
                  "was committed to. Something on the network is trying to "
                  "make the two codes agree.",
    "protocol": "the other box did not understand this pairing protocol. Are "
                "both boxes running the same version of this repository?",
    "self_key": "the other box says it was offered its own public key back.",
    "info": "the other box refused the address or MAC this one sent.",
}


def _pair_abort(sock, code: str) -> None:
    """Best effort. A peer that has already gone is not an error here."""
    try:
        _pair_send(sock, {"t": "abort", "v": PAIR_PROTO, "code": code})
    except Exception:                                        # noqa: BLE001
        pass


def _pair_step(sock, expect: str, budget_s: float = PAIR_MSG_S) -> dict:
    """Receive one message, turning a peer abort into a local explanation."""
    body = _pair_recv(sock, budget_s)
    if body.get("t") == "abort":
        code = body.get("code")
        why = PAIR_ABORT.get(code if isinstance(code, str) else "",
                             "the other box gave up without saying why.")
        exc = PairAborted if code == "declined" else WakeError
        raise exc(f"pairing abandoned: {why} Nothing was written here.")
    if body.get("t") != expect or body.get("v") != PAIR_PROTO:
        raise WakeError("the other box is not speaking this pairing protocol")
    return body


def _pair_pub(body: dict) -> bytes:
    return _hexfield(body, "pub", 32)


def _pair_info(body: dict) -> dict:
    """The peer's non-secret configuration, shape-checked.

    EVERY VALUE HERE COMES OFF THE LAN and is written into a keyfile that then
    composes a command line and a UDP packet, so each one is validated against
    what it will be used for. An unvalidated 'host' here becomes the URL the
    vault fetches from for as long as the pairing lasts.
    """
    info = body.get("info")
    if not isinstance(info, dict):
        raise WakeError("pairing message carries no info object")
    out = {}
    for k, v in sorted(info.items()):
        if k not in ("host", "port", "mac", "broadcast"):
            raise WakeError("pairing info carries an unexpected field")
        if k == "port":
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 65535:
                raise WakeError("pairing info carries a bad port")
        elif k == "mac":
            # \Z, NOT $ -- see the IPv4 note below; the same hole let
            # "de:ad:be:ef:ca:fe\n" through into the keyfile.
            if not isinstance(v, str) or not re.match(
                    r"^([0-9a-f]{2}:){5}[0-9a-f]{2}\Z", v):
                raise WakeError("pairing info carries a bad MAC")
        else:
            # Dotted-quad only. It is pasted into a URL and into sendto(), and
            # a hostname here would mean a DNS lookup on a box whose whole
            # point is that it does not make unexpected lookups.
            #
            # \Z, NOT $. Python's `$` also matches before a trailing newline,
            # so "10.0.0.1\n" passed the shape check, and int("1\n") == 1 so
            # the range check passed too. It reaches gs_wake_keys as
            # f"http://{host}:{port}" -> urllib "URL can't contain control
            # characters", swallowed by the agent's broad except. This value
            # comes off the LAN, so it is the one that must not be sloppy.
            # str(int(p)) == p additionally refuses "010", which inet_aton
            # reads as octal 8.
            if not isinstance(v, str) or not re.match(
                    r"^(\d{1,3}\.){3}\d{1,3}\Z", v) or any(
                    str(int(p)) != p or int(p) > 255 for p in v.split(".")):
                raise WakeError("pairing info carries a bad IPv4 address")
        out[k] = v
    return out


def _pair_finish(sock, my_pub: bytes, peer_pub: bytes, ask, out) -> dict:
    """Show the code, ask the human, exchange answers, and only then agree.

    BOTH SIDES MUST SAY YES. Each box sends its own answer and reads the
    other's, and writes nothing unless both are yes -- so answering 'n' on
    either screen aborts the pairing on BOTH boxes rather than leaving one of
    them holding a keyfile for a peer that never wrote one.
    """
    sas = pair_sas(my_pub, peer_pub)
    mine = bool(ask(sas))
    if not mine:
        _pair_abort(sock, "declined")
        raise PairAborted(
            "pairing abandoned: you did not confirm the code. NOTHING was "
            "written on either box. If the two codes really differed, "
            "something on your network answered instead of the box you meant "
            "-- unplug the switch from anything you do not own and try again.")
    _pair_send(sock, {"t": "confirm", "v": PAIR_PROTO, "ok": True})
    # THE LONG ONE. Somebody is reading two screens; the other box does not
    # answer until they have. Every other step gets PAIR_MSG_S.
    ans = _pair_step(sock, "confirm", PAIR_TIMEOUT_S)
    theirs = ans.get("ok")
    if theirs is not True and theirs is not False:
        raise WakeError("the other box sent an answer that is not yes or no")
    if not theirs:
        raise PairAborted(
            "pairing abandoned: the other box's operator did not confirm the "
            "code. NOTHING was written on either box. If the two codes really "
            "differed, something on your network answered instead of the box "
            "you meant -- unplug the switch from anything you do not own and "
            "try again.")
    out("  [+] Codes matched on both boxes.")
    return {"peer_public": peer_pub.hex(), "sas": sas}


def _pair_read_record(sock) -> bytes:
    """Exactly RECORD_LEN bytes, under the same whole-message deadline."""
    deadline = time.monotonic() + PAIR_MSG_S
    buf = b""
    while len(buf) < RECORD_LEN:
        left = deadline - time.monotonic()
        if left <= 0:
            raise WakeError("the other box did not finish sending its "
                            "configuration. Nothing was written here.")
        try:
            sock.settimeout(min(left, 5.0))
            chunk = sock.recv(RECORD_LEN - len(buf))
        except OSError as e:
            if time.monotonic() >= deadline:
                raise WakeError("the other box did not finish sending its "
                                "configuration. Nothing was written "
                                "here.") from e
            raise WakeError(f"the pairing connection failed while reading the "
                            f"configuration ({type(e).__name__}).") from e
        if not chunk:
            raise WakeError("the other box closed the connection before "
                            "sending its configuration")
        buf += chunk
    return buf


def _pair_config(sock, my_sk, peer_pub_raw: bytes, my_info: dict,
                 send_tag: bytes, recv_tag: bytes, first: bool) -> dict:
    """Swap configuration AFTER both operators confirmed, and only sealed.

    THIS USED TO RIDE IN THE PLAINTEXT `reveal`, which the vault sends to
    whoever connects, on a socket bound to every interface, before anybody has
    authenticated anything. So any host on the switch could open the pairing
    port during the ceremony and be handed the vault's MAC ADDRESS and its
    broadcast address -- the exact value the sealed keyfile exists to keep off
    a stolen SD card, given away over the LAN by the tool that seals it. A key
    can be rotated in one sitting; a NIC cannot.

    Now nothing but a public key crosses before the two operators have compared
    the code, and the configuration crosses after, boxed to the key that
    comparison authenticated. It reuses seal/open_record, so it is the same
    RECORD_LEN bytes as every other record on this wire and carries a domain
    tag.

    `first` decides who speaks: one side sends then reads, the other reads then
    sends, or they deadlock.
    """
    public, _b = _nacl()
    peer_pub = public.PublicKey(peer_pub_raw)
    # VALIDATE WHAT WE ARE ABOUT TO SEND, not only what we receive.
    #
    # This runs AFTER _pair_finish, so a rejection here lands after both
    # operators already said yes. With validation only on the receiving side,
    # the box holding a bad value sent it happily and wrote its keyfile, while
    # the peer rejected it and wrote nothing -- HALF A PAIRING, the exact state
    # the passphrase prompt was moved earlier to prevent: "the next attempt
    # then refused on BOTH boxes for reasons that look nothing like the last
    # one died halfway". The realistic trigger is not an attacker, it is
    # sock.getsockname() returning an IPv6 address on an IPv6-routed LAN.
    #
    # Checking my own info first makes the failure land on the box that OWNS
    # the bad value, before anything is sent, and the abort stops the peer --
    # which is still blocked reading. It also means a peer only ever receives
    # info that already passed this identical validator.
    try:
        _pair_info({"info": my_info})
    except WakeError as e:
        _pair_abort(sock, "info")
        raise WakeError(
            f"this box's own network configuration is not usable for pairing "
            f"({e}). Nothing was written on either box.") from e
    rec = seal(my_sk, peer_pub, send_tag, {"info": my_info})
    if first:
        sock.sendall(rec)
        got = _pair_read_record(sock)
    else:
        got = _pair_read_record(sock)
        sock.sendall(rec)
    try:
        return _pair_info(open_record(my_sk, peer_pub, got, recv_tag))
    except WakeError:
        # Best-effort: revives PAIR_ABORT["info"], which this exchange had
        # otherwise left as dead code. After local pre-validation above, a peer
        # can only get here by sending something no honest build would send.
        _pair_abort(sock, "info")
        raise


def pair_initiator(sock, my_sk, my_pub: bytes, my_info: dict, ask,
                   out) -> dict:
    """The side that connects (the Pi). COMMITS FIRST -- see pair_sas."""
    # No blanket settimeout here: _pair_recv sets its own per-read timeout
    # under a per-message deadline. A blanket one here silently overrode the
    # shorter greeting timeout the caller had just set, which is how a
    # deliberate 30-second bound became a 300-second one.
    sock.settimeout(PAIR_MSG_S)
    _pair_send(sock, {"t": "commit", "v": PAIR_PROTO,
                      "c": pair_commitment(my_pub).hex()})
    body = _pair_step(sock, "reveal")
    peer_pub = _pair_pub(body)
    if peer_pub == my_pub:
        # Both boxes drew the same key: either the same box is talking to
        # itself, or something is reflecting the exchange.
        _pair_abort(sock, "self_key")
        raise WakeError("the other box offered THIS box's own public key")
    _pair_send(sock, {"t": "reveal", "v": PAIR_PROTO, "pub": my_pub.hex()})
    agreed = _pair_finish(sock, my_pub, peer_pub, ask, out)
    agreed["peer_info"] = _pair_config(sock, my_sk, peer_pub, my_info,
                                       TAG_PC, TAG_PV, first=True)
    return agreed


def pair_responder(sock, my_sk, my_pub: bytes, my_info: dict, ask,
                   out) -> dict:
    """The side that listens (the vault). Reveals only after the commitment."""
    sock.settimeout(PAIR_MSG_S)
    body = _pair_step(sock, "commit")
    commitment = _hexfield(body, "c", 32)
    _pair_send(sock, {"t": "reveal", "v": PAIR_PROTO, "pub": my_pub.hex()})
    body = _pair_step(sock, "reveal")
    peer_pub = _pair_pub(body)
    if peer_pub == my_pub:
        _pair_abort(sock, "self_key")
        raise WakeError("the other box offered THIS box's own public key")
    # THE CHECK THE SHORT CODE DEPENDS ON. Without it the initiator could pick
    # its key after seeing this one, grind a few million candidates and match
    # any 40-bit code it liked -- and the operator would compare two identical
    # strings while an attacker sat between them.
    if not hmac.compare_digest(pair_commitment(peer_pub), commitment):
        _pair_abort(sock, "commitment")
        raise WakeError(
            "the other box revealed a key that does not match what it "
            "committed to. That is what an attempt to fix the comparison code "
            "looks like. Refusing, and nothing was written.")
    agreed = _pair_finish(sock, my_pub, peer_pub, ask, out)
    agreed["peer_info"] = _pair_config(sock, my_sk, peer_pub, my_info,
                                       TAG_PV, TAG_PC, first=False)
    return agreed


# ---------------------------------------------------------------------------
#  THE JOB VOCABULARY
# ---------------------------------------------------------------------------
# WHAT THE PI MAY ASK FOR, AND NOTHING ELSE.
#
# The first design let the Pi pass `--param k=v` through to the tool. Every
# reviewer independently found the same thing, and they were right: every
# parameter a whitelisted tool accepts is a way to lose money without ever
# touching a spend RPC.
#
#   --tor-proxy socks5h://<pi>:9050   puts the pwned Pi on the path OPSEC_SETUP
#                                     §4 exists to keep it off
#   --rpc http://<pi>:18083           hands the wallet RPC to the attacker
#   --allow-unbound-memo              disables the only check binding the swap
#                                     to your address
#   --outfile /srv/x.json             relocates the slip outside wipe_covers()
#   anything starting with "--"       becomes a new flag
#
# So there is no k=v channel. A job is an id plus a CLOSED set of typed,
# range-checked scalars, and the agent composes 100% of the argv itself from
# this table plus its own keyfile. This is the discipline gs_console.clean()
# and pipeline_argv() already use one directory over.
#
# THERE IS NO `swap_quote`, AND THAT IS THE MOST IMPORTANT LINE IN THIS FILE.
#
# If the Pi can name -- or merely SELECT -- the XMR destination of a swap,
# "they can wake and spam quotes, not spend" holds literally while the money is
# gone. A pwned Pi names its own address; thor_swap_preparer runs happily
# because the memo binds correctly to the destination it was GIVEN; the slip
# lands 0600 on the ThinkPad; the operator follows OPSEC_SETUP.md §5 step 6 to
# the letter, reads the deposit address and memo off the bay, sends real BTC,
# and ThorChain delivers the XMR to the attacker. No spend key is touched.
#
# `receive_and_quote` therefore MINTS ITS OWN destination in the same job and
# hands that bundle to --dest-from-receive-wallet. The Pi cannot name, select
# or influence an address.
#
# THE AMOUNT IS A COUNT OF SATOSHIS, and it used to be an index into a ladder
# held in the ThinkPad's keyfile. The ladder's argument was a good one -- a
# finite parameter space is exhaustively testable and has no numeric parsing
# surface at all -- and it was answering the wrong question.
#
# What the operator is doing is quoting a swap for the amount they are ABOUT
# TO SEND. A ladder can only answer that if the amount was foreseen and
# written into the keyfile with physical access, and the rung they pick is
# otherwise a quote for a number that is not the number. "The intended
# direction of friction" was friction against being correct.
#
# What the ladder actually bought was that the Pi never learned an amount, and
# that is worth less here than it looks:
#
#   * The amount is a BITCOIN transaction. It is public on the Bitcoin chain
#     and again in the ThorChain swap before the mix ever starts. The ladder
#     hid it from an adversary holding the Pi who could not correlate a chain
#     -- and that adversary learns nothing from the Pi either way.
#   * It does not survive on the Pi. gs_telegram_pager burns the operator's
#     own messages (see its `burn` list) and Convo lives in process memory
#     with a three-minute deadline and is not in anything Limits.save writes.
#   * receive_and_quote SPENDS NOTHING. It mints a receive subaddress and asks
#     for a quote. A stolen phone naming a huge amount achieves a wrong quote
#     and a burnt wake, not a payment -- so the ladder was not bounding a
#     spend, which is the only thing that would have justified the friction.
#
# The parsing surface the ladder avoided is answered by not having one:
# btc_to_sat below is integer string arithmetic with no float and no Decimal,
# and what crosses the wire is a plain bounded int -- the same shape the
# ladder index was, carrying the number that is actually true.

#: Satoshis in one bitcoin. Named because `100000000` in an expression is a
#: digit-count nobody verifies at a glance.
SATS_PER_BTC = 100_000_000

#: What a typed deposit amount must fall between, in satoshis.
#:
#: THESE ARE TYPO GUARDS AND NOT PROTOCOL MINIMUMS, which matters because a
#: number in a constant reads like an authority. The real lower bound is
#: whatever ThorChain's outbound fee makes uneconomic that day, and the real
#: upper bound is judgement about how large a single swap should ever be;
#: neither is knowable here and both move. These bounds exist to catch the
#: hand that meant 0.05 and typed 5 -- wide enough never to obstruct a real
#: deposit, narrow enough that a slipped decimal point lands outside.
DEPOSIT_MIN_SAT = 10_000              # 0.0001 BTC
DEPOSIT_MAX_SAT = 10_000_000_000      # 100 BTC


#: What btc_to_sat accepts: plain decimal BTC, at most 8 places.
#:
#: NO EXPONENT, NO SIGN, NO SEPARATOR, NO SPACE. Each is a way for a string to
#: look like one number and parse as another, and this repo has already paid
#: for a float on a money path once (see gs_common.env_or_argv).
#:
#: [0-9] AND NOT \d, and this was a real defect and not a style preference.
#: Python's \d matches every Unicode decimal digit, and int() converts them
#: all -- so "１", FULLWIDTH DIGIT ONE, passed the pattern and parsed as
#: one whole bitcoin. It renders as a slightly wide "1" and a phone keyboard
#: set to a CJK layout emits it without being asked twice. Driven before the
#: fix: it was accepted for 100,000,000 satoshis. This is the same family as
#: the bug step_convo's docstring records ("²".isdigit() is True), except
#: that one raised and this one quietly agreed.
_BTC_RE = re.compile(r"[0-9]{1,9}(?:\.[0-9]{1,8})?\Z")


def btc_to_sat(text) -> int:
    """A decimal BTC string to an exact satoshi count, or raise WakeError.

    INTEGER STRING ARITHMETIC, no float and no Decimal. float(0.07) is not
    7000000 satoshis and never will be; Decimal would be correct but would
    make this module's "importing nothing but the stdlib" claim carry a money
    parser it does not need. Splitting on the dot and padding the fraction to
    eight places is exact by construction.

    NINE DECIMAL PLACES IS AN ERROR, not something to round. Bitcoin has eight
    and a ninth means the operator is thinking in a different unit or has
    mistyped; silently truncating it would spend a different amount than the
    one they read back.
    """
    s = text if isinstance(text, str) else ""
    s = s.strip()
    if not _BTC_RE.match(s):
        raise WakeError("expected a plain BTC amount like 0.05, at most 8 "
                        "decimal places")
    whole, _dot, frac = s.partition(".")
    sat = int(whole) * SATS_PER_BTC + int(frac.ljust(8, "0") or "0")
    if not DEPOSIT_MIN_SAT <= sat <= DEPOSIT_MAX_SAT:
        raise WakeError(f"expected between {btc_display(DEPOSIT_MIN_SAT)} and "
                        f"{btc_display(DEPOSIT_MAX_SAT)} BTC")
    return sat


def sat_to_btc(sat) -> str:
    """An exact satoshi count back to the decimal BTC string tools read.

    Always eight places, so the output is a fixed shape rather than one that
    varies with the value -- thor_swap_preparer hands it to decimal_env, which
    wants a decimal string, and "0.05000000" and "0.05" are the same number
    while only one of them has a length that depends on the amount.
    """
    whole, frac = divmod(int(sat), SATS_PER_BTC)
    return f"{whole}.{frac:08d}"


def btc_display(sat) -> str:
    """The same amount, for a human to read. NEVER for a tool to parse.

    sat_to_btc's fixed eight places are right for the environment variable and
    wrong for a chat: "Deposit 0.05000000 BTC" is six characters of noise on
    the line an operator is being asked to check, and a confirm that is
    tiresome to read is a confirm that gets answered without being read.

    Trailing zeros only. The value is identical -- 0.05 and 0.05000000 are the
    same number of satoshis -- so this cannot show an amount other than the
    one being sent, which is the only property a confirm line needs.
    """
    s = sat_to_btc(sat)
    return s.rstrip("0").rstrip(".") if "." in s else s

#: Bounded integer parameter: (lo, hi) inclusive.
def _int_range(lo, hi):
    def _check(v):
        if isinstance(v, bool) or not isinstance(v, int):
            raise WakeError("expected a plain integer")
        if not (lo <= v <= hi):
            raise WakeError(f"expected an integer in {lo}..{hi}")
        return v
    _check.spec = f"int {lo}..{hi}"
    return _check


def _handle_field(v):
    if not isinstance(v, str) or not HANDLE_RE.match(v):
        raise WakeError("expected a 4-character uppercase hex handle")
    return v


_handle_field.spec = "handle ^[0-9A-F]{4}$"

#: A Monero address, and THE ONLY FREE TEXT THIS CHANNEL HAS EVER CARRIED.
#:
#: Every other field is a bounded int or a 4-hex label, and that was a design
#: rule, not an accident: OPSEC_SETUP.md's "the Pi is never given the chance to
#: send a number" is the same argument. It holds here only because of what the
#: value is used FOR -- gs_wake_agent puts it in GS_EXIT_TO, an environment
#: variable, and never on an argv -- and because of what this refuses.
#:
#: WHY A REGEX AND NOT A CHECKSUM. A full Monero address check needs the
#: network byte and a Keccak checksum, which this file cannot do without a
#: crypto dependency it does not have; the VAULT re-validates properly
#: (validate_xmr_address, an RPC round trip) before a single coin moves. What
#: this gate is for is narrower and it is the part that must not be skipped:
#: nothing shaped like a FLAG, a path, a URL or a shell fragment may travel,
#: because the value crosses a machine boundary and is handed to a subprocess
#: on the other side.
#:
#: So: base58's alphabet only (no 0, O, I, l -- and therefore no '-', '/',
#: '=', '$', whitespace or a quote), starting with 4 or 8, at exactly the two
#: lengths Monero uses. A standard address is 95 characters and an integrated
#: one 106. Nothing else is admitted, and length is checked before content so
#: an enormous string is rejected without scanning it.
_B58_XMR = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def _xmr_address_field(v):
    """One Monero address, checked the way the other two validators check it.

    HAND-ROLLED BECAUSE THIS FILE IMPORTS NOTHING (see the module header: a
    doorbell that imported gs_common would drag requests, tenacity and psutil
    onto the Pi), which is right -- and it had drifted. gs_common.XMR_ADDR_RE
    and gs_console.XMR_RE are the same expression and a test pins them
    together:

        ^[48][base58]{94}\Z | ^4[base58]{105}\Z

    -- the 106-character INTEGRATED form starts with 4, always, because an
    integrated address carries netbyte 19. This accepted a leading 8 at 106
    too, so there was one string shape the two regexes reject and this admits.
    No such Monero address exists, so it is a typo shape rather than an attack.

    IT MATTERS BECAUSE OF WHICH BOX HOLDS WHICH CHECK. _xmr_address_list is
    what the pager applies to an address the operator types into the chat, and
    its own docstring says why duplicates are refused there: so "the operator
    is told by the box they are typing at, rather than by a vault that has
    already been woken". This one shape got the other outcome -- accepted on
    the phone, refused on the vault, a wake spent.
    """
    if not isinstance(v, str):
        raise WakeError("expected a Monero address as text")
    if len(v) not in (95, 106):
        raise WakeError("expected a Monero address of 95 or 106 characters")
    if v[0] not in ("4", "8"):
        raise WakeError("a Monero address starts with 4 or 8")
    if len(v) == 106 and v[0] != "4":
        raise WakeError("an integrated address (106 characters) starts with 4")
    if any(c not in _B58_XMR for c in v):
        raise WakeError("a Monero address is base58 and this is not")
    return v


_xmr_address_field.spec = ("xmr address "
                           "^[48][base58]{94}\Z|^4[base58]{105}\Z")

#: ONE Monero address, under a name a caller may use.
#:
#: Callers outside this file used to reach for
#: JOBS["withdraw"]["schema"]["exit_to"] when they wanted "check that this is
#: an address" -- gs_wake_agent did it for the operator's USAGE FEE address,
#: which is not an exit destination and has nothing to do with the withdraw
#: job. That borrowing broke the moment exit_to became a list: the fee address
#: came back as ["<addr>"] and went into GS_USAGE_FEE_ADDRESS as the text of a
#: Python list. Nothing about the fee had changed.
#:
#: So the check every caller actually wanted has its own name, and a job
#: schema is once again only about that job's fields.
xmr_address = _xmr_address_field


#: HOW MANY EXIT ADDRESSES ONE WITHDRAWAL MAY NAME.
#:
#: SEVEN BECAUSE THE WIRE CARRIES SEVEN, and the number is derived rather than
#: chosen. A withdraw note is {job_id, challenge, job, exit_to[], depth} and
#: MAX_INNER is 1023 bytes.
#:
#: THE FIRST VERSION OF THIS SAID EIGHT, measured against the shipped seal()
#: with 95-character standard addresses: 963 bytes, comfortably inside, and
#: nine refused. That measurement used the WRONG ADDRESS FORM.
#: _xmr_address_field also accepts the 106-character INTEGRATED form -- which
#: is not an edge case here, because an exchange deposit address is commonly
#: integrated, and an exchange is the likeliest single destination anyone
#: types. Eight of those is 1051 bytes, and the assertion below caught it at
#: import the first time this file was loaded.
#:
#: So the cap is the worst case, not the typical one: 7 x 106 characters plus
#: the envelope is 942 bytes, leaving 81 to spare. A field added to this schema
#: later will trip the assertion -- loudly, on every box, at start-up -- rather
#: than turning the top of the range into a withdrawal that fails on the wire
#: at 3am. That is the SLIP_B64_LEN pattern and it has now earned its place
#: twice.
#:
#: THE CONSOLE ALLOWS SIXTEEN and this allows seven, and that is not a
#: disagreement to be tidied away: gs_console composes an argv on the same
#: machine and has no wire, while this has a fixed-size padded record whose
#: constant length is the whole reason a record reveals nothing about the job
#: it carries. Seven is what that format has room for.
MAX_WAKE_EXIT_DESTS = 7

#: The worst case this cap has to fit: MAX_WAKE_EXIT_DESTS integrated addresses
#: (106 characters, the longer of the two forms) plus the envelope. Computed
#: rather than asserted from a literal so the two cannot drift -- which is
#: exactly what this sentence did: it said "eight" while the expression below
#: has always used MAX_WAKE_EXIT_DESTS, which is SEVEN. Both numbers check out
#: (seven is 942 bytes against a 1023-byte inner limit; eight is 1051 and
#: seal() refuses it), so the guard was correct and only its description was
#: off by one -- and naming the constant rather than a literal is the fix that
#: cannot go stale a second time.
_MAX_WITHDRAW_NOTE = (
    TAG_LEN
    + len(json.dumps({"job_id": "0" * 32, "challenge": "0" * 64,
                      "job": "withdraw", "depth": 3,
                      "exit_to": ["4" + "1" * 105] * MAX_WAKE_EXIT_DESTS},
                     sort_keys=True, separators=(",", ":")).encode()))
if _MAX_WITHDRAW_NOTE > MAX_INNER:                           # pragma: no cover
    raise WakeError(
        f"MAX_WAKE_EXIT_DESTS is {MAX_WAKE_EXIT_DESTS}, which makes the "
        f"largest withdraw note {_MAX_WITHDRAW_NOTE} bytes against a wire "
        f"format that carries {MAX_INNER}. Lower the cap or widen PAD_BLOCK; "
        f"do not ship a maximum the wire cannot send.")


def _xmr_address_list(v):
    """One or more exit addresses. Returns a list, always.

    WHY THIS IS A LIST AT ALL, and it is the whole point of the field.
    GhostSpiral's exit sends ONE TRANSACTION PER OUTPUT. A withdrawal funds
    `wallets + randint(DECOY_MIN, DECOY_MAX)` outputs, so at the depths this
    service offers that is at fewest 5, 12 and 22 separate arrivals -- and with
    a single destination every one of them lands on the same address.
    resolve_exit_destinations says what that costs, in the file that does it:
    the run "spends hours giving these outputs separate accounts precisely so
    they cannot be grouped; one destination groups them again off-chain, and no
    amount of mixing undoes that."

    That warning was unreachable from a phone. It prints on the vault's stdout,
    which the unit diverts to a 0600 log on a machine that powers off minutes
    later, and this schema took a single address -- so the wizard could not
    have offered a second one even if the operator had been told. Every
    phone-initiated withdrawal was the single-destination case, silently. The
    console has spread a withdrawal across up to sixteen addresses since it was
    written; the wake path, added later, never learned how.

    A BARE STRING IS STILL ACCEPTED, and that is not laxity. Both boxes are the
    operator's and they are usually upgraded together, but not always in the
    same sitting -- and the failure mode of getting it wrong is a vault that
    refuses its owner's withdrawal with a schema error they cannot act on from
    a phone. An older pager sends `"exit_to": "<addr>"`; it means one
    destination; it is normalised to a list of one and runs exactly as it did.

    DUPLICATES ARE REFUSED, mirroring resolve_exit_destinations' own refusal
    word for word in intent: repeating an address "looks like a request to
    spread the withdrawal while actually sending more of it to one place".
    Caught here so the operator is told by the box they are typing at, rather
    than by a vault that has already been woken.
    """
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        raise WakeError("expected one Monero address, or a list of them")
    if not v:
        raise WakeError("a withdrawal needs at least one exit address")
    if len(v) > MAX_WAKE_EXIT_DESTS:
        raise WakeError(
            f"at most {MAX_WAKE_EXIT_DESTS} exit addresses; the wake record "
            f"is a fixed-size block and more than that does not fit in it")
    out = []
    for a in v:
        a = _xmr_address_field(a)
        if a in out:
            # NEVER THE VALUE. It reaches a terminal and a log on the far side.
            raise WakeError(
                "the same exit address was given twice; repeating one spreads "
                "nothing, it just sends more of the withdrawal to one place")
        out.append(a)
    return out


_xmr_address_list.spec = (f"1-{MAX_WAKE_EXIT_DESTS} xmr addresses "
                          f"^[48][base58]{{94,105}}$")


#: THE DEPTHS THE SERVICE OFFERS, and the numbers are the whole point.
#:
#: WHAT DEPTH ACTUALLY BUYS, stated more carefully than the first version of
#: this comment stated it. That version said a fixed depth is "a FLOOR on what
#: can be mixed at all", quoting mix_minimum_xmr at 0.1748 XMR for three
#: wallets and 0.2936 for ten. Those two figures are now 0.1784 and 0.2972 --
#: mix_minimum_xmr was understating both by one hop_fee_reserve, the entry
#: veil's own fee, which size_and_prune_chunks takes off the balance before it
#: budgets anything. Both were measured with NO operator cut -- which was true
#: of this path only because the wake agent was not passing --usage-fee at all,
#: which was itself a bug. With the
#: cut on, mix_minimum_xmr's own docstring is the authority: the cut's
#: spendability floor is (hop_fee_reserve + DUST_XMR)/usage_pct, and it sits
#: ABOVE the mixing minimum at every wallet count up to about fifteen.
#:
#: THE TABLE HAS THREE ROWS AND THIS PARAGRAPH USED TO STOP AT TWO. It read
#: "0.3364 XMR at three hops and 0.3364 at ten -- the same number, because the
#: cut is what sets it, not the hops", which is true of exactly the two rows it
#: names. Computed by calling the shipped mix_minimum_xmr at a 0.0024 fee, with
#: --dag-mixing, one chunk and an exit destination (a withdrawal always has
#: one):
#:
#:                        no cut     with the shipped 1.1% cut
#:   depth 1 (3 hops)     0.1784     0.3364   <- the cut sets it
#:   depth 2 (10 hops)    0.2972     0.3364   <- the cut sets it
#:   depth 3 (20 hops)    0.4764     0.4817   <- the HOPS set it again
#:
#: At the deepest depth the phone offers, the cut stops being the binding
#: constraint and the minimum is 43% above the figure the old sentence gave.
#: The operator-facing menu was never wrong -- WITHDRAW_DEPTH_NOTE[3] says
#: "highest minimum" and deliberately quotes no number -- but this is the
#: analysis a future reader would size that menu from.
#:
#: So the honest claim is narrower and still worth the change:
#:
#:   * RUNTIME is where depth really moves, and it moves a lot: 6.1 h at three
#:     hops against 12.9 h at twenty. That is the vault powered on with an
#:     unlocked spend wallet, which is the signature this design spends its
#:     effort hiding, and it is the operator's call to make.
#:   * THE MINIMUM moves too, but only in the regime where no cut is taken --
#:     below the waiver threshold, where plan_usage_fee skips the cut and the
#:     mix goes ahead in full. That is exactly the small-deposit case, so the
#:     effect survives where it matters and vanishes where it does not.
#:   * PRIVACY is the thing being bought, and it is not a number in this file.
#:
#: A single fixed depth denies all three to the person whose money it is.
#:
#: AND THE TOOL MUST NOT PICK IT FROM THE BALANCE. That was tried here and is
#: worse than either extreme: the fan-out's output count is PUBLIC, so a depth
#: derived from the amount makes that public count a direct readout of a lower
#: bound on the deposit. A depth the operator chose leaks nothing about the
#: amount, because it is not a function of it. It is also the thing they are
#: choosing to buy, and a service that picks it for them has removed the only
#: decision that was theirs to make.
#:
#: (wallets, worst-case seconds). The seconds come from GhostSpiral's own
#: _runtime_terms at the SLOW end of DEFAULT_HOP_DELAY -- 180-720s per
#: transaction, about thirty draws a run -- never at its median.
#: tests/test_wake_agent.py recomputes both and fails if either drifts.
WITHDRAW_DEPTHS = {
    1: (3, 22080),     # 6.1h  -- the floor, so small deposits are possible
    2: (10, 32160),    # 8.9h
    3: (20, 46560),    # 12.9h
}

#: HOP COUNT -> the depth key the wire carries. Derived, never written twice.
#:
#: THE CHAT TALKS IN HOPS AND THE WIRE TALKS IN KEYS, and for two turns the
#: chat talked in both at once. The question read:
#:
#:     1  3 hops · ~6h · lowest minimum
#:     2  10 hops · ~9h
#:     3  20 hops · ~13h · highest minimum
#:
#: so "3" was simultaneously the KEY for twenty hops and the HOP COUNT on the
#: first line. An operator who read "3 hops" and typed 3 got twenty: more than
#: twice the runtime, the highest minimum balance of the three, and -- if
#: their balance sat between the two minimums -- a run that fails at stage 0
#: after they have already confirmed it. Nothing was wrong on screen and
#: nothing was wrong on the wire; the two vocabularies collided on one
#: character.
#:
#: Hops are what the buttons say, what the note says and what the operator is
#: actually choosing, so hops are what the chat now accepts. The keys never
#: leave this file. 10 and 20 were never keys and so were never ambiguous;
#: 3 now means three hops, which is what it looks like it means. An operator
#: who had memorised "2" for ten hops is REFUSED rather than silently given
#: something else, which is the safe direction for the one gate that costs
#: hours.
WITHDRAW_HOPS = {v[0]: k for k, v in WITHDRAW_DEPTHS.items()}

#: GhostSpiral.DECOY_MIN, mirrored, because the box that has to state the
#: consequence cannot import the file that owns it.
#:
#: The fan-out funds `wallets + randint(DECOY_MIN, DECOY_MAX)` outputs and the
#: exit relays one transaction per output, so the number of separate arrivals a
#: withdrawal produces is not `wallets` -- it is at fewest `wallets +
#: DECOY_MIN`. The pager has to say that number out loud when it asks where the
#: money goes, and the pager may not have GhostSpiral on disk at all (see
#: WITHDRAW_DEPTH_NOTE for the same argument about the XMR minimum).
#:
#: MIRRORED, NOT GUESSED, and pinned: tests/test_wake_protocol.py asserts this
#: equals GhostSpiral.DECOY_MIN, the way tests/test_wake_agent.py already
#: recomputes WITHDRAW_DEPTHS' budgets from GhostSpiral's own arithmetic. A
#: mirror with a test is the shape this repo uses when a constant has to cross
#: a box that cannot import its owner; a mirror without one is how JOB_TIMEOUT
#: drifted 6x.
DECOY_MIN_MIRROR = 2


def exit_arrivals_floor(depth: int) -> int:
    """The fewest separate transactions a withdrawal at `depth` sends out.

    A FLOOR, not an estimate, and it is the number the operator needs before
    choosing how many destinations to give. resolve_exit_destinations computes
    the same figure on the vault (`_lo = _w + DECOY_MIN`) to warn about a
    single destination -- onto a stdout nobody reads. This is that figure,
    available to the box the operator is actually typing at.

    A FAN-OUT ADDS ONE MORE PER SWAP CHUNK for its change, which this does not
    include; a withdrawal is one chunk, and a floor that could be too HIGH
    would be the wrong error for a number whose whole job is "at least this
    many arrivals will land wherever you point them".
    """
    return WITHDRAW_DEPTHS[depth][0] + DECOY_MIN_MIRROR

#: What each depth needs, in words the operator reads before choosing.
#:
#: NO XMR FIGURE APPEARS HERE, and that is a constraint rather than a choice.
#: The real minimum is GhostSpiral.mix_minimum_xmr at that hop count, it moves
#: with the network fee, and the box that draws this menu is the PAGER --
#: which may not import GhostSpiral and may not have it on disk at all (see
#: gs_telegram_pager's USAGE_FEE_LABEL for the same argument). A number
#: frozen in here would therefore be a quote nobody can honour and nothing
#: can check. So the menu says which end of the range each depth sits at,
#: which is the part that is true regardless of the fee, and the vault -- the
#: box that CAN ask -- is what refuses a deposit too small for the depth it
#: was given.
WITHDRAW_DEPTH_NOTE = {
    1: "3 hops · ~6h · lowest minimum",
    2: "10 hops · ~9h",
    3: "20 hops · ~13h · highest minimum",
}


JOBS = {
    # Mint receive subaddresses. Spends nothing.
    # "receive_new" WAS HERE AND IS GONE. It minted a Monero subaddress to be
    # paid into directly -- an entry point for somebody who already holds XMR.
    #
    # Nothing in this repository swaps XMR to BTC; every path is BTC to XMR.
    # So it was half a feature: it could take money in and had no way to say
    # where. Both slip builders returned empty on it by construction (no quote,
    # so no thor_pairs file to build one from), which meant the command whose
    # entire purpose was to hand the operator an address delivered no address,
    # on any configuration. Both watching jobs refused its handle for the same
    # reason, so /check and /wait spent a wake to be told no.
    #
    # Removing it is a WIRE change: a note naming it is now refused by
    # validate_job on the vault, which is the loud failure this file's header
    # promises for a version mismatch. Update both boxes together.
    # Mint ONE receive subaddress and quote a swap TO IT. The destination is
    # minted inside the job; the Pi never supplies one. See above.
    #
    # THE AMOUNT IS THE ONE BEING SENT, in satoshis, and it replaced an index
    # into a ladder in the vault's keyfile. The long argument for the change
    # is above _int_range; the short one is that a quote for a rung the
    # operator picked off a list is a quote for a number that is not the
    # number they are about to send, and a swap quoted for the wrong amount is
    # simply wrong.
    "receive_and_quote": {
        "schema": {"amount_sat": _int_range(DEPOSIT_MIN_SAT,
                                            DEPOSIT_MAX_SAT)},
        "tools": ("create_receive_wallet", "thor_swap_preparer"),
        "budget_s": 1800,
    },
    # Wait for a payment to land on a bundle this machine already minted.
    "watch": {
        "schema": {"handle": _handle_field},
        "tools": ("receive_watch",),
        "budget_s": 7200,
    },
    # LOOK ONCE, ANSWER IN ONE WORD, POWER OFF. The operator's question is
    # "has my money arrived?" and `watch` answers it terribly:
    #
    #   * it holds the Pi's one-job lock for up to 9900 s -- 900 s pre-WOL
    #     jitter + a 600 s fetch window + an 8400 s result budget -- so for the
    #     better part of three hours every other command is refused with
    #     "a wake is already running";
    #   * it keeps the vault powered on, with its disk auto-unlocked, for over
    #     two of those hours, which is the power and network signature the
    #     whole design exists to avoid;
    #   * and when the money has simply not arrived yet, receive_watch exits
    #     non-zero and the chat is told the vault FAILED.
    #
    # A NEW JOB NAME rather than a parameter on `watch`, and that is forced
    # rather than chosen: validate_job enforces an EXACT key set, so adding a
    # `minutes` field to watch's schema would make a half-upgraded pair refuse
    # every watch. A new name fails cleanly on an old vault instead -- "wake
    # note names a job this machine does not run".
    "swap_status": {
        "schema": {"handle": _handle_field},
        "tools": ("receive_watch",),
        # Five minutes of looking. Long enough for the wallet to answer, short
        # enough that the vault is off again before it is worth noticing.
        "budget_s": 300,
    },
    # MIX WHAT LANDED AND SEND IT OUT. The only job that spends, the only one
    # that carries free text, and the only one the vault refuses by default.
    #
    # WHY IT EXISTS AT ALL. Without it the documented cycle ends with the money
    # sitting on a receive subaddress whose full address the swap already
    # published in a Bitcoin OP_RETURN, and the operator holding a phone that
    # cannot do anything about it. "Go to the vault" is not an answer when the
    # reason the vault is far away is that it is a vault.
    #
    # WHAT IT COSTS, stated here rather than in a doc nobody reads at 3am:
    #
    #   * The spend wallet has to be reachable by a machine the phone can wake.
    #     That is custody on a networked box, and it is the trade OPSEC_SETUP
    #     spends a section refusing for every OTHER job. Whoever holds the bot
    #     token can trigger a withdrawal; the address is theirs to type.
    #   * The destination is free text from a chat. It is validated three
    #     times -- here, at the pager, and at the vault with a real checksum --
    #     and it is never put on an argv, but it is still the first value this
    #     channel has carried that an attacker gets to CHOOSE.
    #
    # WHICH IS WHY THE VAULT REFUSES IT UNLESS ITS OWN KEYFILE SAYS OTHERWISE.
    # `allow_withdraw` is set with physical access, like the amount ladder, and
    # is absent from every keyfile that existed before this job did -- so an
    # upgraded pair does not silently gain the ability to spend.
    "withdraw": {
        # TWO FIELDS: WHERE IT GOES, AND HOW DEEP.
        #
        # It used to take a HANDLE as well -- the 4-hex label of a receive
        # bundle a /depo had minted -- so a withdrawal was only possible for
        # money that had arrived through this tool's own deposit flow, and the
        # operator had to know which label named which pile. That is backend
        # bookkeeping leaking into the one command that should need none: the
        # money is wherever the operator put it, and the only thing they
        # actually have to decide is where it goes.
        #
        # The vault finds the funded output itself now (see
        # gs_wake_agent._funded_entry). It is the machine holding the wallet;
        # asking a phone to name an account index was asking the wrong box.
        #
        # `depth` is the SECOND thing that is genuinely theirs to decide: it
        # sets how long the vault stays powered on with an unlocked spend
        # wallet (6.1 h at three hops against 12.9 h at twenty) and, on a
        # deposit small enough that the operator's cut is waived, how little
        # can be mixed at all. A hard-coded 10 decided both for them. See
        # WITHDRAW_DEPTHS, which states exactly how much of that second effect
        # is real once a cut is being taken -- less than the first draft of
        # this comment claimed.
        # `exit_to` IS A LIST NOW. See _xmr_address_list: the exit sends one
        # transaction per output, so a single destination collects every
        # arrival this run spent hours separating -- and the pipeline's own
        # warning about that prints on a vault nobody is watching. A bare
        # string is still accepted and means a list of one, so an older pager
        # keeps working against a newer vault.
        "schema": {"exit_to": _xmr_address_list,
                   "depth": _int_range(1, 3)},
        "tools": ("GhostSpiral",),
        # SIZED FOR THE DEEPEST DEPTH OFFERED, and this number was wrong.
        #
        # It was 21600 (6h), computed against a hop-delay window of (300,300).
        # DEFAULT_HOP_DELAY is (180, 720). At the real slow end even the
        # SHALLOWEST depth needs 6.1h, so the shipped budget could not cover
        # any run at all -- and over budget is not a late report: run_child
        # SIGTERMs the process group and then SIGKILLs it, mid-mix, with the
        # money already moving. Every withdrawal would have been killed.
        #
        # It is the deepest entry in WITHDRAW_DEPTHS plus a quarter, and it is
        # a CEILING rather than a duration: the agent powers off as soon as
        # the job finishes, so choosing depth 1 does not keep the vault up for
        # depth 3's budget.
        #
        # WHY A QUARTER ON TOP OF A NUMBER THAT IS ALREADY A CEILING. The
        # seconds in WITHDRAW_DEPTHS bound the hop delays exactly -- they
        # assume every one of ~58 draws lands on the slow end of (180, 720),
        # which cannot be exceeded. The confirmation term cannot: it is
        # FANOUT_CONFIRM_POLL_ESTIMATE, an ESTIMATE of how long the chain
        # takes to confirm, and a slow chain is not bounded by anything in
        # this repo. The margin covers that term, and it is deliberately
        # generous in the cheap direction: a budget too long only matters if
        # the job also hangs, and the deadman still fires; a budget too short
        # SIGKILLs a mix mid-spend, which is the one failure nothing here can
        # undo.
        "budget_s": int(max(t for _w, t in WITHDRAW_DEPTHS.values()) * 1.25),
    },
}

#: Jobs that need a spend-capable wallet, and therefore an explicit keyfile
#: opt-in on the vault. A tuple rather than a flag on each job, so the agent's
#: gate and the doorbell's window sizing read the same list.
SPENDING_JOBS = ("withdraw",)


#: THE VAULT'S MANDATORY JITTER, DECLARED WHERE BOTH BOXES CAN SEE IT.
#:
#: gs_wake_agent sleeps a random VAULT_JITTER_LO_S..VAULT_JITTER_HI_S after it
#: has collected a job and BEFORE it starts any of the job's work
#: (OPSEC_SETUP.md section 5 step 4: "a random 5-20 min"). It lived only in
#: gs_wake_agent, so the Pi -- which has to decide how long to wait for a
#: result -- was sizing its window as though that sleep did not exist.
VAULT_JITTER_LO_S, VAULT_JITTER_HI_S = 300, 1200

#: EVERYTHING ON THE VAULT THAT IS NOT THE JITTER AND NOT THE CHILD.
#:
#: result_budget_s summed the jitter and the per-step budget and stopped, so
#: the window was EXACTLY the vault's worst case with ZERO margin -- for a
#: withdrawal, 1 x 58200 + 1200 = 59400 on both sides of the equation. Every
#: other thing the vault does between collecting a job and reporting on it
#: therefore ran past the window:
#:
#:   preflight (removable-device scan, resource check, unit_is_active),
#:   verify_tor with a real exit request, extend_deadman's systemd-run and its
#:   verification, _funded_entry's connect_rpc plus a wallet refresh on a
#:   just-booted wallet, the slip sealing, and the report POST itself over Tor.
#:
#: A job that used its full budget therefore reported into a closed socket,
#: and the operator was told "collected_no_result" -- "I do NOT know whether
#: the funds moved ... Do not run /withdraw again until you have checked the
#: balance yourself" -- about a run that had finished normally. On the one job
#: that spends, on the exact run where they most need the answer.
#:
#: FIVE MINUTES, and the direction of the error is the reason for the number.
#: Too long costs the pager's one-job lock a few extra minutes on a job that
#: has already hung; too short costs the operator the only report they get.
#: The same asymmetry WITHDRAW_DEPTHS' own budget margin is argued from.
VAULT_FIXED_OVERHEAD_S = 300


def result_budget_s(job: str) -> int:
    """How long the Pi must hold the line for a result, worst case.

    NOT budget_s. Three things stack up on the vault between collecting a job
    and reporting on it, and the doorbell's window counted only the last one:

      * the mandatory jitter above, up to VAULT_JITTER_HI_S, before any work;
      * budget_s PER STEP, not per job -- gs_wake_agent's _dispatch passes the
        same budget to run_child for every tool in the job, so a two-tool job
        is allowed twice it (tests/test_wake_agent.py says so in as many
        words: "the budget is PER STEP, not per job");
      * the work itself, which is what budget_s bounds;
      * and the FIXED per-boot overhead either side of it, which this stopped
        one term short of. See VAULT_FIXED_OVERHEAD_S.

    Measured against the shipped constants, every job could report late:

        job                tools  budget   old window   vault worst case
        receive_new            1     900          900               2100
        receive_and_quote      2    1800         1800               4800
        watch                  1    7200         7200               8400

    Past the window Pending.finished() goes true, do_wake's `while not
    pending.finished()` loop exits and the server is shut down -- so the vault
    reports into a closed socket and the operator is told
    "collected_no_result" for a job that in fact ran to completion.
    """
    spec = JOBS[job]
    return (len(spec["tools"]) * spec["budget_s"] + VAULT_JITTER_HI_S
            + VAULT_FIXED_OVERHEAD_S)


#: Named so a test can assert they are unreachable rather than merely absent.
#:
#: THIS LIST USED TO CONTAIN "GhostSpiral", and removing it is the single
#: largest change this channel has ever taken -- so it is narrowed rather than
#: shortened, and the narrowing is the whole security argument.
#:
#: The old rule was "no job may drive a spending tool", which was enforceable
#: and absolute and left the operator holding a phone that could not move their
#: own money. The new rule is: no job may drive a spending tool EXCEPT the one
#: job that exists to spend, which the vault refuses unless its own keyfile
#: says otherwise (see SPENDING_JOBS and gs_wake_agent's allow_withdraw gate).
#:
#: Everything else on this list stays unreachable from any job at all, and
#: they are the ones with no gate that could make them safe: the cold signer
#: and the broadcaster take a plan file and relay it, so a job that could name
#: them could relay a plan the operator never saw.
FORBIDDEN_TOOLS = ("run_pipeline", "airgap_tx_signer",
                   "broadcast_signed_xmr", "exit_strategy_simulator")

#: Tools only a SPENDING job may name, and only then. Kept separate from
#: FORBIDDEN_TOOLS so "unreachable from every job" stays a testable property of
#: that list, rather than becoming "unreachable except sometimes".
GATED_TOOLS = ("GhostSpiral",)


def job_tools_are_permitted() -> bool:
    """Every job's tools are allowed to it. Checked, not assumed.

    Three properties in one predicate, because they only mean anything
    together: no job names a FORBIDDEN tool at all; only a SPENDING job names a
    GATED one; and a spending job names nothing but gated tools -- so
    `withdraw` cannot quietly acquire a second tool that runs unattended
    alongside the mix.
    """
    for _name, _spec in JOBS.items():
        _tools = tuple(_spec["tools"])
        if any(t in FORBIDDEN_TOOLS for t in _tools):
            return False
        _gated = [t for t in _tools if t in GATED_TOOLS]
        if _gated and _name not in SPENDING_JOBS:
            return False
        if _name in SPENDING_JOBS and set(_tools) - set(GATED_TOOLS):
            return False
    return True


def validate_job(body: dict) -> tuple:
    """(job_id, job, params) from an M2 body, or raise WakeError.

    EXACT KEY SET. An unknown key is refused rather than ignored: ignoring it
    means a future field silently does nothing on an old agent, which is how a
    security parameter comes to be carried and never checked.
    """
    job = body.get("job")
    if not isinstance(job, str) or job not in JOBS:
        # Never echo the received value -- it reaches a terminal and a log.
        raise WakeError("wake note names a job this machine does not run")
    spec = JOBS[job]
    job_id = job_id_of(body)
    reserved = {"job", "job_id", "challenge"}
    got = set(body) - reserved
    want = set(spec["schema"])
    if got != want:
        missing = sorted(want - got)
        extra = sorted(k for k in (got - want))
        bits = []
        if missing:
            bits.append(f"missing {missing}")
        if extra:
            # Key NAMES are attacker-controlled; report the count, not the text.
            bits.append(f"{len(extra)} unexpected key(s)")
        raise WakeError(f"wake note does not match the {job} schema: "
                        + ", ".join(bits))
    params = {}
    for k, check in spec["schema"].items():
        try:
            params[k] = check(body[k])
        except WakeError as e:
            raise WakeError(f"wake note field {k!r}: {e}") from None
    return job_id, job, params
