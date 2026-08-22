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
import time

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
#: The pairing ceremony's LAST exchange, after both operators confirmed the
#: code. Two tags, not one, for the same reason M1 and M3 have two: both are
#: sealed under the same static-static key, so only a domain tag stops one
#: being replayed as the other.
TAG_PC = b"GSWAKE-v2-PC".ljust(TAG_LEN, b"\0")   # Pi -> ThinkPad   "my address"
TAG_PV = b"GSWAKE-v2-PV".ljust(TAG_LEN, b"\0")   # ThinkPad -> Pi   "my MAC"

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
#: The doorbell's per-window nonce. SIXTEEN, not thirty-two, and the reason is
#: arithmetic rather than taste: M1 already carries a 32-byte ephemeral public
#: key and a 32-byte challenge, each 64 hex characters, and at 32 bytes this
#: took the inner record to 248 of the 255 that fit in one padded block. seal()
#: refuses a longer one rather than emitting a visibly different 512-byte
#: record -- correct, but it means the next field anybody adds fails on a woken
#: box in the field. 16 bytes leaves real headroom.
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
    head = {"schema": KEYFILE_SCHEMA, "version": WIRE_VERSION, "role": role}
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
    if container.get("version") != WIRE_VERSION:
        raise WakeError(f"keyfile is for wire version "
                        f"{container.get('version')!r}, not {WIRE_VERSION}")
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

# 3, NOT 2. Bumped when the per-window nonce was added to M1 and the pairing
# `reveal` lost its plaintext `info` in favour of the sealed post-confirmation
# config exchange. Both are incompatible wire changes; leaving this at 2 let a
# new box and an old box agree to pair and then fail at wake time, which is the
# worst place to discover it.
PAIR_PROTO = 3
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
    comparison authenticated. It reuses seal/open_record, so it is the same 296
    bytes as every other record on this wire and carries a domain tag.

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

#: THE VAULT'S MANDATORY JITTER, DECLARED WHERE BOTH BOXES CAN SEE IT.
#:
#: gs_wake_agent sleeps a random VAULT_JITTER_LO_S..VAULT_JITTER_HI_S after it
#: has collected a job and BEFORE it starts any of the job's work
#: (OPSEC_SETUP.md section 5 step 4: "a random 5-20 min"). It lived only in
#: gs_wake_agent, so the Pi -- which has to decide how long to wait for a
#: result -- was sizing its window as though that sleep did not exist.
VAULT_JITTER_LO_S, VAULT_JITTER_HI_S = 300, 1200


def result_budget_s(job: str) -> int:
    """How long the Pi must hold the line for a result, worst case.

    NOT budget_s. Three things stack up on the vault between collecting a job
    and reporting on it, and the doorbell's window counted only the last one:

      * the mandatory jitter above, up to VAULT_JITTER_HI_S, before any work;
      * budget_s PER STEP, not per job -- gs_wake_agent's _dispatch passes the
        same budget to run_child for every tool in the job, so a two-tool job
        is allowed twice it (tests/test_wake_agent.py says so in as many
        words: "the budget is PER STEP, not per job");
      * the work itself, which is what budget_s bounds.

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
    return len(spec["tools"]) * spec["budget_s"] + VAULT_JITTER_HI_S


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
