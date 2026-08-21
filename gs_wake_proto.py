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
EVERY RECORD IS EXACTLY 296 BYTES
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
exactly one 256-byte block, making every record on the wire 296 bytes:

    24 (nonce) + 256 (padded plaintext) + 16 (MAC) = 296

Verified for every inner length 0..255: the set of resulting record sizes is
exactly {296}. sodium_pad always adds at least one byte, so an inner of 256
would pad to 512 -- which is why `seal` REFUSES an inner over 255 rather than
silently emitting a double-length record that is itself a signal.

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

import hmac
import json
import re
import secrets

#: Wire version. A peer that does not recognise a tag REFUSES. There is no
#: negotiation and no "try v1 if v2 fails" -- a downgrade path is a way to be
#: talked back to the version whose flaw you are patching.
WIRE_VERSION = 1

#: Fixed-width so the tag never changes the padded length, and so the compare
#: is constant-length. NUL-padded to 16.
TAG_LEN = 16
TAG_M1 = b"GSWAKE-v1-M1".ljust(TAG_LEN, b"\0")   # ThinkPad -> Pi   "I am awake"
TAG_M2 = b"GSWAKE-v1-M2".ljust(TAG_LEN, b"\0")   # Pi -> ThinkPad   "do this job"
TAG_M3 = b"GSWAKE-v1-M3".ljust(TAG_LEN, b"\0")   # ThinkPad -> Pi   "it is done"

#: One 256-byte block. See the header for why every record is the same size.
PAD_BLOCK = 256
#: 24-byte nonce + 16-byte MAC, measured, not assumed.
BOX_OVERHEAD = 40
#: The only length any record may have. Checked BEFORE any crypto runs.
RECORD_LEN = PAD_BLOCK + BOX_OVERHEAD            # 296

#: The largest inner (tag + body) that still pads to ONE block.
MAX_INNER = PAD_BLOCK - 1

CHALLENGE_BYTES = 32
JOB_ID_BYTES = 16
#: The handle the operator reads off the terminal and the doorbell may learn.
#: FOUR hex characters, uppercase, and RANDOM -- never derived from the slip,
#: the address or the memo. A derived handle would let a seized Pi confirm or
#: deny candidate addresses read straight off the public Bitcoin OP_RETURNs,
#: which links a specific BTC deposit to this operator.
HANDLE_RE = re.compile(r"^[0-9A-F]{4}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")


class WakeError(Exception):
    """A record was refused. The message is operator-facing and must never
    echo attacker-supplied bytes back into a log or a terminal."""


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
    if tag not in (TAG_M1, TAG_M2, TAG_M3):
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


def job_id_of(body: dict) -> str:
    return _hexfield(body, "job_id", JOB_ID_BYTES).hex()


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
# The amount is an INDEX INTO A LADDER held in the ThinkPad's keyfile, never a
# number on the wire. A finite parameter space is exhaustively testable and has
# no numeric parsing surface at all. The stated cost: quoting an amount that is
# not on the ladder requires editing the ThinkPad's keyfile, which requires
# physical access. That is the intended direction of friction.

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


JOBS = {
    # Mint receive subaddresses. Spends nothing.
    "receive_new": {
        "schema": {"count": _int_range(1, 4)},
        "tools": ("create_receive_wallet",),
        "budget_s": 900,
    },
    # Mint ONE receive subaddress and quote a swap TO IT. The destination is
    # minted inside the job; the Pi never supplies one. See above.
    "receive_and_quote": {
        "schema": {"amount_slot": _int_range(0, 7)},
        "tools": ("create_receive_wallet", "thor_swap_preparer"),
        "budget_s": 1800,
    },
    # Wait for a payment to land on a bundle this machine already minted.
    "watch": {
        "schema": {"handle": _handle_field},
        "tools": ("receive_watch",),
        "budget_s": 7200,
    },
}

#: Named so a test can assert they are unreachable rather than merely absent.
#: The mix needs a physically-present spend USB and must never be driven by a
#: pager -- OPSEC_SETUP.md §8.
FORBIDDEN_TOOLS = ("GhostSpiral", "run_pipeline", "airgap_tx_signer",
                   "broadcast_signed_xmr", "exit_strategy_simulator")


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
