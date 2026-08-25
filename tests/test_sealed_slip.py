#!/usr/bin/env python3
"""THE SEALED SLIP: it must REACH the operator and it must READ to nobody else.

This file exists because the wake channel solved half a problem. Everything
about it was built so the deposit address and the memo stay on the vault --
correct, and useless to an operator who cannot go to the vault. OPSEC_SETUP.md
§8's rule ("do not just run a Telegram bot that prints the memo") assumes a
walk to the ThinkPad that the whole design assumes is not available.

So the payload travels sealed, and the two properties that matter pull in
opposite directions. Both are driven here, against the real crypto:

  REACHES        a slip sealed by the vault OPENS on the delivery machine and
                 yields the deposit address, the memo and the amount, exactly.

  READS TO NOBODY the Pi, the pager and anyone holding the bot token get 568
                 characters of base64 and nothing else. Asserted by SEARCHING
                 the doorbell's state and the whole chat transcript for the
                 address, the memo and the amount -- not by reading the code
                 and believing it.

AND THE ONE THAT IS EASY TO FORGET: a slip must be AUTHENTICATED, not merely
encrypted. Whoever holds the bot token can put any 568 characters into that
chat. If gs_unseal accepted a slip anyone could construct, the pager would have
become a channel for telling the operator where to send their Bitcoin -- which
is worse than the leak the whole design is defending against. Driven: a slip
sealed by a DIFFERENT key, to the right recipient, is refused.

FAILS, NEVER SKIPS, WHEN PyNaCl IS ABSENT.
"""
import base64
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = FAIL = 0
FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   " + name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL: " + name)


def load(name):
    path = os.path.join(REPO, name)
    ld = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(ld.name, ld)
    mod = importlib.util.module_from_spec(spec)
    ld.exec_module(mod)
    return mod


P = load("gs_wake_proto.py")
from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILURES),
                                 "test_sealed_slip")

import nacl.public as NP                                     # noqa: E402

XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSs"
       "aBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
MEMO = f"=:XMR.XMR:{XMR}:0/1/0"
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
AMOUNT = "0.05000000"

VAULT = NP.PrivateKey.generate()
DELIVERY = NP.PrivateKey.generate()
STRANGER = NP.PrivateKey.generate()

BODY = {"b": AMOUNT, "d": BTC, "m": MEMO, "a": XMR,
        "x": "1.23456789", "t": 1755900000, "h": "A3F1"}


def sealed(body=None, sender=None, recipient=None):
    return P.seal_slip(sender or VAULT,
                       (recipient or DELIVERY).public_key if hasattr(
                           recipient or DELIVERY, "public_key")
                       else recipient,
                       body if body is not None else BODY)


# ===========================================================================
# 1. IT REACHES. The round trip, on the real primitives.
# ===========================================================================
print("\n-- the slip reaches the delivery machine --")
BLOB = sealed()
check("a sealed slip opens with the delivery secret and the vault's public key",
      P.open_slip(DELIVERY, VAULT.public_key, BLOB) == BODY)
check("...and every field survives byte for byte, including the memo",
      P.open_slip(DELIVERY, VAULT.public_key, BLOB)["m"] == MEMO)

# ===========================================================================
# 2. IT IS ONE LENGTH, ALWAYS.
#
# The blob travels through a chat. Unpadded, its length is a readout of the
# memo's length, which distinguishes a 95-character standard XMR address from
# a 106-character integrated one, and the amount's digit count leaks the same
# way. This is the property that stops the ciphertext being a fingerprint.
# ===========================================================================
print("\n-- one length, whatever is inside --")
lengths = set()
for body in (BODY,
             {"b": "0.001", "d": BTC, "m": MEMO, "a": XMR, "x": "0.02",
              "t": 1, "h": "0000"},
             {"b": "9.99999999", "d": BTC, "m": f"=:XMR.XMR:{XMR}:0/1/0",
              "a": XMR, "x": "250.00000000", "t": 1755900000, "h": "FFFF"},
             {"h": "AAAA"}):
    lengths.add(len(P.seal_slip(VAULT, DELIVERY.public_key, body)))
check("every slip is exactly SLIP_B64_LEN characters, whatever it carries",
      lengths == {P.SLIP_B64_LEN})
check("SLIP_B64_LEN is what base64 of one padded box actually measures",
      P.SLIP_B64_LEN ==
      len(base64.b64encode(b"\0" * (P.SLIP_PAD + P.BOX_OVERHEAD))))
check("two seals of the SAME body differ (a fresh nonce, not a fingerprint)",
      P.seal_slip(VAULT, DELIVERY.public_key, BODY) !=
      P.seal_slip(VAULT, DELIVERY.public_key, BODY))

# ===========================================================================
# 3. IT IS AUTHENTICATED, NOT MERELY ENCRYPTED.
#
# THE ATTACK: whoever holds the bot token owns the chat. If a slip were sealed
# anonymously -- to the delivery public key, by anyone -- they could hand the
# operator a deposit address of their choosing and the operator would send real
# Bitcoin to it. "Where do I send the money" is the one field here that must
# prove who wrote it.
# ===========================================================================
print("\n-- a slip nobody's vault sealed is refused --")
FORGED = P.seal_slip(STRANGER, DELIVERY.public_key,
                     dict(BODY, d="bc1qattackerattackerattackerattackerqqq0000"))


def refused(fn):
    try:
        fn()
        return ""
    except P.WakeError as e:
        return str(e)


msg = refused(lambda: P.open_slip(DELIVERY, VAULT.public_key, FORGED))
check("a slip sealed by a DIFFERENT key, to the right recipient, is refused",
      bool(msg))
check("...and the refusal says not to spend on the strength of it",
      "DO NOT SEND ANY BITCOIN" in msg)
check("the right key still opens the real one after that",
      P.open_slip(DELIVERY, VAULT.public_key, BLOB) == BODY)

_flip = bytearray(base64.b64decode(BLOB))
_flip[100] ^= 0x01
check("one flipped bit anywhere in the box is refused",
      bool(refused(lambda: P.open_slip(
          DELIVERY, VAULT.public_key,
          base64.b64encode(bytes(_flip)).decode()))))
check("the delivery key cannot open a slip meant for someone else",
      bool(refused(lambda: P.open_slip(
          STRANGER, VAULT.public_key, BLOB))))

# ===========================================================================
# 4. A SLIP IS NOT A WAKE RECORD AND CANNOT BE SUBSTITUTED FOR ONE.
#
# Both are sealed under a static-static box between the same two keys in the
# M1/M3 case, so only the domain tag separates them. Without TAG_SL, an M3
# could be handed to open_slip -- and, more to the point, a slip could be
# pushed into the doorbell's /result and opened as an M3.
# ===========================================================================
print("\n-- domain separation, both directions --")
M3 = P.seal(VAULT, DELIVERY.public_key, P.TAG_M3,
            {"job_id": "a" * 32, "challenge": "b" * 64,
             "status": "done", "handle": "A3F1", "slip": "",
             "plain": {}, "phase": ""})
check("an M3 is not the right LENGTH for a slip, so it dies before the AEAD",
      bool(refused(lambda: P.open_slip(
          DELIVERY, VAULT.public_key,
          base64.b64encode(M3).decode()))))
_raw = base64.b64decode(BLOB)
check("a slip is not the right length for a wake record either",
      bool(refused(lambda: P.open_record(
          DELIVERY, VAULT.public_key, _raw, P.TAG_M3))))
# The tag check itself, reached by building something the right SHAPE with the
# wrong tag. A length collision cannot happen with the shipped constants, so
# the tag is exercised directly rather than pretended at.
_pub, _bind = P._nacl()
_wrong = _bind.sodium_pad(P.TAG_M1 + b'{"x":1}', P.SLIP_PAD)
_wrongblob = base64.b64encode(
    bytes(_pub.Box(VAULT, DELIVERY.public_key).encrypt(_wrong))).decode()
check("a correctly-sealed, correctly-sized record with the WRONG TAG is "
      "refused by open_slip",
      "not a slip" in refused(
          lambda: P.open_slip(DELIVERY, VAULT.public_key, _wrongblob)))

# ===========================================================================
# 5. THE REFUSALS AN OPERATOR WILL ACTUALLY HIT.
#
# Copy/paste is the normal case, not the exotic one: a chat client wraps a
# line, a terminal drops the tail, somebody re-types four characters. Each of
# these must fail with a sentence that names the real cause, because the
# alternative message ("it was not written by the expected peer") reads as an
# attack and would send an operator looking for one.
# ===========================================================================
print("\n-- copy/paste failures say what actually went wrong --")
check("a truncated slip is refused for its LENGTH, naming the number",
      str(P.SLIP_B64_LEN) in refused(
          lambda: P.open_slip(DELIVERY, VAULT.public_key, BLOB[:-4])))
check("...and says a slip is one line and must be pasted whole",
      "paste the whole thing" in refused(
          lambda: P.open_slip(DELIVERY, VAULT.public_key, BLOB[:-4])))
check("surrounding whitespace and a trailing newline are tolerated",
      P.open_slip(DELIVERY, VAULT.public_key, f"  {BLOB}\n ") == BODY)
_bad = BLOB[:100] + "!" + BLOB[101:]
check("a slip with a character base64 does not know is refused AS base64, "
      "not as an authentication failure",
      "not valid base64" in refused(
          lambda: P.open_slip(DELIVERY, VAULT.public_key, _bad)))
check("a non-string slip is refused without reaching the decoder",
      bool(refused(lambda: P.open_slip(DELIVERY, VAULT.public_key, None))))
# 568 CHARACTERS CAN DECODE TO 424, 425 OR 426 BYTES depending on how many "="
# the tail carries, and only 424 is a slip. Without a decoded-length check the
# odd ones reach the AEAD and come back as "it was not sealed by your vault —
# DO NOT SEND ANY BITCOIN", which tells the operator their vault may be
# compromised when a chat client mangled a character.
_short = base64.b64encode(base64.b64decode(BLOB)[:-1]).decode()
_short = _short + "A" * (P.SLIP_B64_LEN - len(_short))
_msg_short = refused(lambda: P.open_slip(DELIVERY, VAULT.public_key, _short))
check("a 568-character blob that decodes to the wrong SIZE is refused as a "
      "transit fault", "rewrote it in transit" in _msg_short)
check("...and NOT as 'your vault did not seal this', which would send the "
      "operator hunting a compromise that did not happen",
      "DO NOT SEND ANY BITCOIN" not in _msg_short)
check("a discontinuous '=' is caught as base64, before the AEAD",
      "not valid base64" in refused(
          lambda: P.open_slip(DELIVERY, VAULT.public_key,
                              BLOB[:100] + "=" + BLOB[101:])))

# ===========================================================================
# 6. seal_slip REFUSES an oversized payload rather than emitting a long one.
#
# Same rule seal() follows for records, for the same reason one screen down in
# gs_wake_proto: a slip twice the length of every other slip announces
# something about itself in a chat window.
# ===========================================================================
print("\n-- an oversized slip is refused, not emitted at double length --")
_huge = {"m": "x" * P.SLIP_PAD}
check("a payload that will not fit one block raises rather than growing",
      bool(refused(lambda: P.seal_slip(VAULT, DELIVERY.public_key, _huge))))
check("...and the refusal explains that a longer one would be visible",
      "visibly different" in refused(
          lambda: P.seal_slip(VAULT, DELIVERY.public_key, _huge)))
# The boundary, from the other side: the largest thing that DOES fit still
# produces exactly one length.
#           the block ceiling  minus the tag   minus the JSON scaffolding
_fill = (P.SLIP_MAX_INNER - P.TAG_LEN
         - len(json.dumps({"m": ""}, sort_keys=True, separators=(",", ":"))))
# SEAL AND OPEN MUST REFUSE THE SAME THINGS. open_slip goes through
# parse_body, which refuses floats; without the same check on the way out, the
# vault can seal a slip the delivery machine will not open -- and that failure
# lands at the machine holding the money, for a swap already quoted, 500 km
# from the box that made the mistake.
check("a float in a slip is refused at SEAL time, not left for the reader",
      bool(refused(lambda: P.seal_slip(VAULT, DELIVERY.public_key,
                                       dict(BODY, x=1.5)))))
check("...which is the same thing the reader refuses, so the two agree",
      bool(refused(lambda: P.parse_body(b'{"x":1.5}'))))
check("the largest payload that fits still seals to SLIP_B64_LEN",
      len(P.seal_slip(VAULT, DELIVERY.public_key,
                      {"m": "x" * _fill})) == P.SLIP_B64_LEN)

# ===========================================================================
# 7. slip_is_wellformed -- the ONLY check the Pi can make.
#
# The doorbell has no delivery key, by design. It must decide whether to carry
# a blob it cannot read, so it checks shape, and shape has to be checked
# strictly: a mangled blob must fail on the vault's own channel, not later in
# a chat window where the failure looks like the vault's fault.
# ===========================================================================
print("\n-- the shape check the Pi runs, having no key --")
check("a real slip is well-formed", P.slip_is_wellformed(BLOB))
check("a truncated one is not", not P.slip_is_wellformed(BLOB[:-4]))
check("a padded-out one is not", not P.slip_is_wellformed(BLOB + "AAAA"))
check("non-base64 of the right length is not",
      not P.slip_is_wellformed("!" * P.SLIP_B64_LEN))
check("a non-string is not", not P.slip_is_wellformed(None))
check("the empty string is not (the doorbell treats '' as 'no slip', "
      "separately)", not P.slip_is_wellformed(""))
check("well-formed says NOTHING about whether it opens -- a forged slip is "
      "well-formed", P.slip_is_wellformed(FORGED))

# ===========================================================================
# 8. THE WIRE STILL HAS EXACTLY ONE RECORD LENGTH.
#
# PAD_BLOCK went 256 -> 1024 to make room for this. The security property was
# never smallness, it is UNIFORMITY: a watcher on the switch must not be able
# to tell an M1 from an M3, nor a job that produced a slip from one that did
# not. That second half is new and is the one worth driving.
# ===========================================================================
print("\n-- every record on the switch is still one length --")
_eph = NP.PrivateKey.generate()
recs = [
    P.seal(VAULT, DELIVERY.public_key, P.TAG_M1,
           {"eph_pk": bytes(_eph.public_key).hex(), "challenge": "a" * 64,
            "window": "b" * 32}),
    P.seal(VAULT, _eph.public_key, P.TAG_M2,
           {"job_id": "c" * 32, "challenge": "a" * 64,
            "job": "receive_and_quote", "amount_sat": 5_000_000}),
    P.seal(VAULT, DELIVERY.public_key, P.TAG_M3,
           {"job_id": "c" * 32, "challenge": "a" * 64, "status": "done",
            "handle": "A3F1", "slip": "", "plain": {}, "phase": ""}),
    P.seal(VAULT, DELIVERY.public_key, P.TAG_M3,
           {"job_id": "c" * 32, "challenge": "a" * 64, "status": "done",
            "handle": "A3F1", "slip": BLOB, "plain": {}, "phase": ""}),
]
check("M1, M2, an M3 with no slip and an M3 WITH one are all one length",
      len(set(len(r) for r in recs)) == 1)
check("...and that length is RECORD_LEN",
      set(len(r) for r in recs) == {P.RECORD_LEN})
check("an M3 carrying a slip fits, with headroom left over",
      P.RECORD_LEN == P.PAD_BLOCK + P.BOX_OVERHEAD and P.PAD_BLOCK >= 1024)

# ===========================================================================
# 9. THE KEYFILE VERSION IS NOT THE WIRE VERSION.
#
# lock_keyfile stamped WIRE_VERSION into the file and unlock_keyfile demanded
# an exact match, while the comment above KEYFILE_SCHEMA claimed the two were
# "versioned SEPARATELY". Nothing showed while WIRE_VERSION sat at 1 forever.
# Bumping it to 2 for this feature would have made every keyfile on both boxes
# unreadable -- and the fix for that is a re-pairing ceremony needing physical
# access to a vault that is deliberately far away, to fix nothing.
# ===========================================================================
print("\n-- a wire bump must not brick every keyfile --")
_payload = {"role": "thinkpad", "secret": "aa" * 32}
_c = P.lock_keyfile(_payload, b"", role="thinkpad")
check("a keyfile is stamped with KEYFILE_VERSION, not WIRE_VERSION",
      _c["version"] == P.KEYFILE_VERSION)
check("the wire version has moved past it, which is the whole point",
      P.WIRE_VERSION != P.KEYFILE_VERSION)
check("a keyfile written when WIRE_VERSION was 1 still opens today",
      P.unlock_keyfile({"schema": P.KEYFILE_SCHEMA, "version": 1,
                        "role": "thinkpad", "kdf": "none",
                        "plain": _payload}) == _payload)
check("a keyfile from a FORMAT version that does not exist is still refused",
      bool(refused(lambda: P.unlock_keyfile(
          {"schema": P.KEYFILE_SCHEMA, "version": 99, "role": "x",
           "kdf": "none", "plain": _payload}))))

# ===========================================================================
# 10. THE VAULT SEALS ONLY WHAT IT SHOULD, AND NEVER RAISES.
#
# seal_slip_for_delivery runs after the job has already succeeded. A job that
# ran is a job that ran: a failure to seal must not turn a completed swap quote
# into a reported failure, which would send the operator to check a vault that
# has already powered off.
# ===========================================================================
print("\n-- the vault side: what gets sealed, and what happens when it cannot --")
AG = load("gs_wake_agent")

PAIR = {"schema": "x", "btc_in": AMOUNT, "deposit": BTC, "memo": MEMO,
        "dest_xmr": XMR, "expected_xmr": "1.23456789", "ts": 1755900000}


def vault_key(**over):
    k = {"secret": bytes(VAULT).hex(),
         "delivery_public": bytes(DELIVERY.public_key).hex()}
    k.update(over)
    return k


class _Dir:
    """An artifact dir whose handles file says where the slip is."""

    def __init__(self, handles):
        self.d = tempfile.mkdtemp(prefix="slipdir_")
        with open(os.path.join(self.d, AG.HANDLES_FILE), "w") as f:
            json.dump(handles, f)

    @property
    def path(self):
        from pathlib import Path
        return Path(self.d)


_d = _Dir({"A3F1": {"bundle": "w.json", "minted": 1, "slip": "/nope/x.json"}})
_blob = AG.seal_slip_for_delivery(vault_key(), _d.path, "done", "A3F1",
                                  reader=lambda p: [PAIR])
check("a done receive_and_quote seals a slip",
      P.slip_is_wellformed(_blob))
_opened = P.open_slip(DELIVERY, VAULT.public_key, _blob)
check("...carrying the deposit address, the memo and the amount",
      _opened["d"] == BTC and _opened["m"] == MEMO and _opened["b"] == AMOUNT)
check("...and the handle, so a slip names the job it came from",
      _opened["h"] == "A3F1")
check("...and NOTHING the pair record carries that was not allowlisted",
      set(_opened) == {s for _, s in AG.SLIP_FIELDS} | {"h"})

check("no delivery_public configured -> no slip, and that is not an error",
      AG.seal_slip_for_delivery(vault_key(delivery_public=""), _d.path,
                                "done", "A3F1", reader=lambda p: [PAIR]) == "")
check("a job that FAILED seals nothing",
      AG.seal_slip_for_delivery(vault_key(), _d.path, "failed", "A3F1",
                                reader=lambda p: [PAIR]) == "")
check("a job that was REFUSED seals nothing",
      AG.seal_slip_for_delivery(vault_key(), _d.path, "refused", "",
                                reader=lambda p: [PAIR]) == "")

_recv = _Dir({"B2C4": {"bundle": "w.json", "minted": 1, "slip": None}})
check("receive_new has no quote to deliver, so no slip and no complaint",
      AG.seal_slip_for_delivery(vault_key(), _recv.path, "done", "B2C4",
                                reader=lambda p: [PAIR]) == "")


def _raises(p):
    raise OSError("no such file")


check("an unreadable slip file returns '' rather than raising",
      AG.seal_slip_for_delivery(vault_key(), _d.path, "done", "A3F1",
                                reader=_raises) == "")
check("TWO quoted pairs is refused rather than guessing which to pay",
      AG.seal_slip_for_delivery(vault_key(), _d.path, "done", "A3F1",
                                reader=lambda p: [PAIR, PAIR]) == "")
check("a pair missing its memo seals nothing rather than a slip with a hole",
      AG.seal_slip_for_delivery(
          vault_key(), _d.path, "done", "A3F1",
          reader=lambda p: [{k: v for k, v in PAIR.items()
                             if k != "memo"}]) == "")

# ===========================================================================
# 11. THE DOORBELL CARRIES IT AND CANNOT READ IT.
# ===========================================================================
print("\n-- the Pi carries ciphertext and holds no key for it --")
DB = load("gs_doorbell")
PI = NP.PrivateKey.generate()


def pending(job="receive_and_quote", params=None):
    return DB.Pending({"secret": bytes(PI).hex(),
                       "peer_public": bytes(VAULT.public_key).hex()},
                      job, params or {"amount_sat": 5000000})


def m3(pend, **over):
    body = {"job_id": pend.job_id, "challenge": "a" * 64, "status": "done",
            "handle": "A3F1", "slip": BLOB, "plain": {}, "phase": ""}
    body.update(over)
    return P.seal(VAULT, PI.public_key, P.TAG_M3, body)


_p = pending()
_p.on_m3(m3(_p))
check("a well-formed slip is accepted and carried", _p.result["slip"] == BLOB)
check("...and recorded as an event, so the operator can see one came back",
      "slip_carried" in _p.events)

_p2 = pending()
try:
    _p2.on_m3(m3(_p2, slip=BLOB[:-4]))
    _bad_ok = True
except DB.Doorbell:
    _bad_ok = False
check("a MANGLED slip is refused on the vault's own channel, not relayed",
      not _bad_ok)

_p3 = pending()
try:
    _p3.on_m3(m3(_p3, status="failed", handle="", slip=BLOB))
    _fail_ok = True
except DB.Doorbell:
    _fail_ok = False
check("a slip attached to a job that did not finish is refused",
      not _fail_ok)

_p4 = pending()
_p4.on_m3(m3(_p4, slip=""))
check("no slip is still a perfectly good result", _p4.result["slip"] == "")

# A TYPE CHECK BEFORE A TRUTHINESS ONE. `if slip and not wellformed(slip)`
# reads as a complete gate and is not: every falsy non-string skips validation
# and is stored, and nothing downstream crashes on it -- the pager does
# `res.get("slip") or ""` -- so the symptom is a slip that silently never
# arrives, which is the hardest kind to trace from a phone.
for _junk in (0, [], {}, None, 5, ["a"]):
    _pj = pending()
    try:
        _pj.on_m3(m3(_pj, slip=_junk))
        _ok = True
    except DB.Doorbell:
        _ok = False
    check(f"a slip field of {type(_junk).__name__} {_junk!r} is refused, not "
          f"stored", not _ok)

# THE ONE THAT MATTERS: search everything the Pi now holds for the secrets.
_state = json.dumps({"result": _p.result, "events": _p.events,
                     "job": _p.job, "params": _p.params})
for label, secret in (("the XMR destination", XMR), ("the swap memo", MEMO),
                      ("the BTC deposit address", BTC),
                      ("the amount", AMOUNT)):
    check(f"{label} is NOWHERE in the doorbell's state after carrying a slip",
          secret not in _state)
check("the doorbell module names no delivery key at all",
      "delivery_secret" not in open(os.path.join(REPO, "gs_doorbell")).read())

# ===========================================================================
# 12. AND THE SAME SEARCH ON WHAT THE CHAT RECEIVED.
#
# The pager's own suite proves the no-slip path carries nothing. This is the
# path that carries something, which is the one worth searching twice.
# ===========================================================================
print("\n-- what reaches the chat is ciphertext and a label --")
pg = load("gs_telegram_pager")
sys.modules["gs_doorbell"] = DB
pg._DOORBELL[0] = DB

_sent = []
pg.safe_post = lambda url, payload, proxies=None: (
    _sent.append(payload["text"]) or {"ok": True})
_pager = pg.Pager.__new__(pg.Pager)
_pager.proxies = {}
_pager.token = "123456:TOKEN"
_pager.handle_owner = {}
_ok_send = [True]
_pager.send = lambda cid, text: (_sent.append(text), _ok_send[0])[1]


class _Done:
    result = None
    def outcome(self):
        return "done"


_done = _Done()
_done.result = {"status": "done", "handle": "A3F1", "slip": BLOB,
                "plain": {}, "phase": ""}
pg.integrity_log = lambda *a, **k: None
_pager.args = None
pg.Pager.poke.__wrapped__ if False else None
# Drive the real reply-building branch by handing poke a doorbell whose
# run_wake returns our finished Pending. Nothing is stubbed inside poke.
pg._DOORBELL[0] = type("D", (), {
    "run_wake": staticmethod(lambda a, k, j, p: _done)})()
_pager.key = {}
_pager.poke(111, "receive_and_quote", {"amount_sat": 5000000})

_chat = "\n".join(_sent)
for label, secret in (("the XMR destination", XMR), ("the swap memo", MEMO),
                      ("the BTC deposit address", BTC),
                      ("the amount", AMOUNT)):
    check(f"{label} does not appear in the chat", secret not in _chat)
check("the sealed blob DOES reach the chat -- otherwise none of this delivers",
      BLOB in _chat)
check("the blob is sent ALONE, so tap-and-hold copies it and nothing else",
      BLOB in _sent)
check("the handle still reaches the chat", "A3F1" in _chat)
# AND IT NAMES NO TOOL. This used to assert the reply said "gs_unseal it on
# the machine you send the BTC from". Useful exactly once -- the operator
# turned this mode on themselves, in a keyfile, so they know what the blob is
# -- and after that it is a tool name repeated into the readable surface on
# every single job, forever.
check("and it names no tool to open it with", "gs_unseal" not in _chat)
check("NON-VACUITY -- the blob and the handle are both there, so the reply "
      "still carries everything the operator needs",
      BLOB in _chat and "A3F1" in _chat)

# A DROPPED SEND MUST NOT LEAVE A PROMISE WITH NOTHING BEHIND IT.
#
# send() used to return None and swallow the failure into a print(), which the
# shipped unit routes to StandardOutput=null. With a status line that was
# survivable. With the slip it is not: the operator is looking at "sealed slip
# below" with nothing below it, on a box they cannot walk to, while the quote
# expires. The blob is sent FIRST now and the caption states what happened.
pg.SLIP_RETRY_S = 0                     # no real sleeping in a suite
_sent.clear()
_ok_send[0] = False
_pager.poke(111, "receive_and_quote", {"amount_sat": 5000000})
_failtext = "\n".join(t for t in _sent if t != BLOB)
check("a blob that does not send is RETRIED once before anyone is told bad "
      "news -- one lost POST is not a reason to send someone to the vault",
      _sent.count(BLOB) == 2)
check("...and not more than once: a retry storm holds the busy lock for the "
      "whole rate-limit window", _sent.count(BLOB) == 2)
# CASE-INSENSITIVE, because the sentence was shortened and the check was
# pinned to its exact capitalisation. What matters is that the reply says the
# thing did not arrive, not which letter is capital.
check("when both attempts fail, the reply says so rather than pointing at a "
      "message that is not there",
      "did not get through" in _failtext.lower())
check("...and does not claim the slip is below it",
      "↑ sealed slip" not in _failtext)
check("...and still gives the handle, so the job is not lost",
      "A3F1" in _failtext)
# NOT "/watch <handle>". watch waits for a payment to LAND on a bundle, so it
# cannot hand back a deposit address the operator never received -- it would
# sit for two hours waiting for money nobody could send.
check("...and does NOT tell them to /watch, which cannot deliver an address "
      "and would wait two hours for a payment nobody could make",
      "/watch" not in _failtext)
check("...and sends them to /depo for a fresh quote, since this one expires",
      "/depo" in _failtext)

# THE RETRY MUST NOT FIRE WHEN THE FIRST SEND WORKED.
_sent.clear()
_ok_send[0] = True
_pager.poke(111, "receive_and_quote", {"amount_sat": 5000000})
check("a blob that sends first time is sent exactly ONCE",
      _sent.count(BLOB) == 1)

# AND THE REAL send(), NOT THE STUB ABOVE. The mutation sweep caught this
# exact gap: with send() replaced wholesale, an anchor that made it report
# every dropped reply as delivered SURVIVED -- the branch above was proven and
# the thing it branches on was not. So the real method runs here, against a
# safe_post that raises the way a Tor circuit dying mid-reply does.
_real = pg.Pager.send.__get__(_pager, pg.Pager)
_posts = []
pg.safe_post = lambda url, payload, proxies=None: (
    _posts.append(payload) or {"ok": True})
check("the real send() reports TRUE when the post goes through",
      _real(111, "hello") is True and len(_posts) == 1)


def _boom(url, payload, proxies=None):
    raise OSError("SOCKS5 connection failed")


pg.safe_post = _boom
check("the real send() reports FALSE when the post raises, rather than "
      "swallowing it into a print nobody reads",
      _real(111, "hello") is False)
pg.safe_post = lambda url, payload, proxies=None: (
    _posts.append(payload) or {"ok": True})

# The no-slip path must be unchanged for anyone who never sets a delivery key.
_sent.clear()
_done.result = {"status": "done", "handle": "A3F1", "slip": "",
                "plain": {}, "phase": ""}
_pager.poke(111, "receive_and_quote", {"amount_sat": 5000000})
# THE NO-KEY PATH IS THE HANDLE, AND NOTHING ELSE. This asserted the reply
# said "Read the address and memo on the vault." -- a sentence naming the
# machine, sent on every job, telling the operator where their own hardware is.
# THE CHAT NAME, NOT THE INTERNAL ONE. OPSEC_SETUP section 5 step 5 specifies
# "depo ready · slip A3F1"; the code sent "receive_and_quote ready · slip A3F1"
# -- the pipeline's own identifier for the job, in the vocabulary of the
# machine rather than of the person reading a phone.
check("with no delivery key the reply is the handle line and nothing more",
      any(t.strip() == "depo ready · slip A3F1" for t in _sent))
check("...and it uses the short name the doc specifies, not the internal one",
      not any("receive_and_quote" in t for t in _sent))
check("...and it names no machine", not any("vault" in t.lower() for t in _sent))
check("...and no empty message is sent in place of the blob", len(_sent) == 1)

# ===========================================================================
# 13. gs_unseal REFUSES BEFORE IT SHOWS ANYTHING.
#
# The memo is the only thing routing the XMR. thor_swap_preparer already
# refuses an unbound memo on the vault; this is the second machine checking the
# same invariant from a field sealed under the same key, because the failure it
# catches is total and cannot be reversed.
# ===========================================================================
print("\n-- the delivery machine re-checks the one invariant that matters --")
US = load("gs_unseal")


def _show(body):
    import io
    import contextlib
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = US.show(body, now=1755900000)
        return rc, buf.getvalue()
    except SystemExit as e:
        return e, buf.getvalue()


_rc, _out = _show(dict(BODY))
check("a good slip prints the deposit address", BTC in _out)
check("...the memo", MEMO in _out)
check("...and the exact amount to send", AMOUNT in _out)

_evil = dict(BODY, m=f"=:XMR.XMR:{'4' + 'B' * 94}:0/1/0")
_rc2, _out2 = _show(_evil)
check("a memo naming SOMEONE ELSE'S address exits rather than printing it",
      isinstance(_rc2, SystemExit))
check("...and the attacker's address is never shown",
      "4" + "B" * 94 not in _out2)

# A CONTROL CHARACTER FORGES A LINE IN A BLOCK MEANT TO BE COPIED AND PAID.
# thor_swap_preparer gates its own SENDER INSTRUCTIONS block on exactly this;
# gs_unseal prints the same fields on a different machine, so it needs the same
# gate. It cannot use terminal_safe for it -- that REDACTS addresses, and this
# is the one screen where the address must appear in full.
for _field, _label in (("d", "deposit address"), ("m", "memo"),
                       ("b", "amount")):
    _inj = dict(BODY)
    _inj[_field] = f"{BODY[_field]}\n  To address:    bc1qattacker"
    if _field == "m":
        # keep it binding, so this tests the control-char gate and not the
        # memo gate that already sits behind it
        _inj["m"] = f"=:XMR.XMR:{XMR}:0/1/0\n  To address: bc1qattacker"
    _rc3, _out3 = _show(_inj)
    check(f"a control character in the {_label} exits instead of printing a "
          f"forged line", isinstance(_rc3, SystemExit))
    check(f"...and the forged 'To address' never reaches the screen",
          "bc1qattacker" not in _out3)

_stale, _ = _show(dict(BODY, t=1755900000 - 3600))
check("an hour-old quote returns non-zero rather than reading as fine",
      _stale == 1)
_fresh, _ = _show(dict(BODY, t=1755900000 - 60))
check("a one-minute-old quote is fine", _fresh == 0)

# ===========================================================================
# 14. NEITHER NEW TOOL PUTS A SECRET ON A COMMAND LINE.
#
# /proc/<pid>/cmdline is 0444 and every local account can read it. This repo
# moved the wallet password, the BTC entry address and the bot token off argv
# for exactly this reason; two new tools are two new chances to undo it.
# ===========================================================================
print("\n-- nothing secret on argv --")
_us_src = open(os.path.join(REPO, "gs_unseal")).read()
_dk_src = open(os.path.join(REPO, "gs_delivery_key")).read()
def _flags(src):
    """Every flag the file actually DEFINES, not every string that looks like one.

    The first version of this checked `"--slip" not in src` and went red on
    correct code: gs_unseal's docstring says "THERE IS NO --slip FLAG" in as
    many words, so the substring is there precisely because the flag is not.
    A check that a well-written file fails is a check that gets deleted.
    """
    import re
    return set(re.findall(r'add_argument\(\s*"(--[a-z-]+)"', src))


# ===========================================================================
# gs_unseal LEAVES NOTHING BEHIND, AND THAT IS ABOUT WHERE IT RUNS.
#
# Every other tool here chains events into integrity_chain.log and the first
# version of this one did too. gs_common writes that file to the CURRENT
# WORKING DIRECTORY, and this is the only tool in the repo whose home is a
# machine paranoia_mode never sweeps -- an ordinary laptop with Electrum on
# it. A few lines of tamper-evidence nobody recomputes, against a permanent
# file on the one box in the design that has no wipe.
#
# Driven as a REAL SUBPROCESS in an empty directory, because the failure this
# guards against is a side effect at import time or in a finally, and neither
# shows up when the module is called in-process from a suite that has already
# imported half the repo.
# ===========================================================================
print("\n-- gs_unseal runs on an unswept machine and leaves nothing --")
import subprocess                                            # noqa: E402

_clean = tempfile.mkdtemp(prefix="unseal_cwd_")
_dkey = os.path.join(_clean, "d.key")
with open(_dkey, "w") as _f:
    json.dump(P.lock_keyfile(
        {"role": "delivery", "delivery_secret": bytes(DELIVERY).hex(),
         "vault_public": bytes(VAULT.public_key).hex()},
        b"pw", kdf="interactive", role="delivery"), _f)
_before = set(os.listdir(_clean))
_p = subprocess.run(
    [sys.executable, os.path.join(REPO, "gs_unseal"), "--key", _dkey],
    input=f"pw\n{BLOB}\n", capture_output=True, text=True, cwd=_clean,
    timeout=300)
_after = set(os.listdir(_clean))
check("a real gs_unseal run prints the deposit address", BTC in _p.stdout)
check("...and creates NO file in the directory it ran from -- no integrity "
      f"log, no state, no temp file (found: {sorted(_after - _before)})",
      _after == _before)
check("...and the source names no integrity_log call at all",
      "integrity_log(" not in _us_src)

_us_flags, _dk_flags = _flags(_us_src), _flags(_dk_src)
check("_flags actually finds the flags these tools do define, so the "
      "assertions below are not vacuous",
      "--key" in _us_flags and "--vault-key" in _dk_flags)
check("gs_unseal defines no --slip flag: the blob comes in on stdin",
      "--slip" not in _us_flags)
check("gs_unseal defines no passphrase flag",
      not any("pass" in f for f in _us_flags))
check("gs_delivery_key defines no passphrase flag",
      not any("pass" in f for f in _dk_flags))
check("gs_unseal reads the passphrase with getpass, which uses /dev/tty",
      "getpass" in _us_src)
check("gs_delivery_key refuses an empty passphrase rather than writing a "
      "plaintext secret to removable media",
      "empty passphrase" in _dk_src)
check("gs_delivery_key confirms the file opens BEFORE it shreds the copy",
      _dk_src.index("_open_delivery(path, args)") <
      _dk_src.index("secure_delete_file(path)"))

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
