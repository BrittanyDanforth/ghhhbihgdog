#!/usr/bin/env python3
"""THE WAKE WIRE FORMAT, EXECUTED.

gs_wake_proto is the only thing standing between "anyone on the switch can send
a magic packet" and a vault that runs a job. Everything here drives the real
seal/open path; nothing at the level being tested is stubbed.

THE ATTACK THIS FILE EXISTS FOR
The first design boxed both directions with one crypto_box. Measured on PyNaCl
1.6.2 before a line of it was written:

    crypto_box_beforenm(pi_pk, tp_sk) == crypto_box_beforenm(tp_pk, pi_sk) -> True

One key, both directions. So the vault's own request, replayed back at it,
decrypted AND authenticated AND echoed the challenge the vault had just
generated -- both stated acceptance gates satisfied by a message the vault
wrote itself. The only thing left between that and an executed job was whether
the JSON parser happened to KeyError.

Two independent defences now cover two different message pairs, and this file
tests them SEPARATELY, because a test that only proves "the reflection is
refused" would stay green if either one were deleted:

  * M1 vs M2 -- different keys (M2 is boxed to a per-boot EPHEMERAL), so the
    reflection dies at the box.
  * M1 vs M3 -- the SAME key, so only the 16-byte domain tag defends.

FAILS, NEVER SKIPS, WHEN PyNaCl IS ABSENT. A skipped authentication test is a
green suite that proves nothing. The pyflakes SKIP elsewhere in this repo is a
developer nicety; this is the product.
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
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


import gs_wake_proto as P                                    # noqa: E402
from srcutil import fail_loudly_on_crash                     # noqa: E402

# A crash prints no RESULT line, and mutation_sweep scores a suite by parsing
# that line -- so a mutation that makes this file DIE would be recorded as a
# SURVIVOR. See srcutil.fail_loudly_on_crash: it has happened three times here.
_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_wake_protocol.py")

try:
    import nacl.public as NP
    import nacl.bindings as NB
except Exception as e:                                       # noqa: BLE001
    print(f"  FAIL: PyNaCl must be installed to test the wake protocol ({e})")
    print("\nRESULT: 0 passed, 1 failed")
    print("FAILED: ['PyNaCl missing — the wake protocol cannot be verified']")
    sys.exit(1)


TP = NP.PrivateKey.generate()      # vault, static
PI = NP.PrivateKey.generate()      # doorbell, static
EPH = NP.PrivateKey.generate()     # vault, per boot

SAMPLE = {"receive_new": {"count": 4},
          "receive_and_quote": {"amount_slot": 7},
          "watch": {"handle": "A3F1"}}


def m2_for(job, eph_pub=None):
    body = {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex(),
            "job": job}
    body.update(SAMPLE[job])
    return P.seal(PI, eph_pub or EPH.public_key, P.TAG_M2, body), body


print("== the premise: crypto_box gives ONE key in both directions ==")
check("crypto_box_beforenm is symmetric, which is why a tag and an ephemeral "
      "are both needed",
      NB.crypto_box_beforenm(PI.public_key.encode(), TP.encode())
      == NB.crypto_box_beforenm(TP.public_key.encode(), PI.encode()))


print("\n== every record is exactly 296 bytes ==")
lens = set()
for job in P.JOBS:
    rec, _ = m2_for(job)
    lens.add(len(rec))
    check(f"M2 for {job} is {P.RECORD_LEN} bytes", len(rec) == P.RECORD_LEN)
m1 = P.seal(TP, PI.public_key, P.TAG_M1,
            {"eph_pk": EPH.public_key.encode().hex(),
             "challenge": P.new_challenge().hex()})
m3 = P.seal(TP, PI.public_key, P.TAG_M3,
            {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex(),
             "status": "done", "handle": "A3F1"})
lens.update({len(m1), len(m3)})
check("M1, M2 and M3 are indistinguishable by length, across every job",
      lens == {P.RECORD_LEN})
# Unpadded the sizes were 76 / 91 / 100 -- the job was readable off the wire
# without touching the crypto.
check("...and that is the padding, not luck: the raw bodies DO differ in size",
      len({len(str(SAMPLE[j])) for j in P.JOBS}) > 1)


print("\n== the reflection attack ==")
try:
    P.open_record(EPH, PI.public_key, m1, P.TAG_M2)
    check("M1 reflected into the M2 reader is refused", False)
except P.WakeError as e:
    check("M1 reflected into the M2 reader is refused (at the BOX: M2 is "
          "sealed to a per-boot ephemeral, M1 to the static key)",
          "authenticate" in str(e))

# The tag is the OTHER half, and it defends the pair that shares a key.
try:
    P.open_record(PI, TP.public_key, m3, P.TAG_M1)
    check("M3 replayed as M1 is refused", False)
except P.WakeError as e:
    check("M3 replayed as M1 is refused (same key both ways — only the domain "
          "tag can tell them apart)", "wrong kind of message" in str(e))
try:
    P.open_record(PI, TP.public_key, m1, P.TAG_M3)
    check("M1 replayed as M3 is refused", False)
except P.WakeError:
    check("M1 replayed as M3 is refused", True)
def _refusal_text(recip, sender, rec, tag):
    try:
        P.open_record(recip, sender, rec, tag)
    except P.WakeError as e:
        return str(e)
    return ""


# Refusal text reaches a terminal and, on the Pi, the journal. It must not
# carry attacker-supplied bytes back out.
check("the wrong-kind refusal does not echo the received tag",
      "GSWAKE" not in _refusal_text(PI, TP.public_key, m3, P.TAG_M1))


print("\n== forward secrecy: M2 is sealed to the per-boot ephemeral ==")
rec, _ = m2_for("receive_new")
for name, sk in (("the Pi's long-term secret", PI),
                 ("the vault's long-term secret", TP)):
    try:
        P.open_record(sk, PI.public_key, rec, P.TAG_M2)
        check(f"a captured M2 stays sealed against {name}", False)
    except P.WakeError:
        check(f"a captured M2 stays sealed against {name} — a door kick does "
              f"not decrypt months of recorded notes", True)
check("...while the boot that made it can open it",
      P.open_record(EPH, PI.public_key, rec, P.TAG_M2)["job"] == "receive_new")


print("\n== integrity ==")
ok, _ = m2_for("receive_new")
flipped = 0
for i in (0, 30, 150, 295):
    bad = bytearray(ok)
    bad[i] ^= 0x01
    try:
        P.open_record(EPH, PI.public_key, bytes(bad), P.TAG_M2)
    except P.WakeError:
        flipped += 1
check("flipping a bit anywhere in the record is refused", flipped == 4)
for n, why in ((295, "one short"), (297, "one long"), (0, "empty")):
    try:
        P.open_record(EPH, PI.public_key, b"\x00" * n, P.TAG_M2)
        check(f"a record {why} is refused", False)
    except P.WakeError as e:
        check(f"a record {why} is refused before any crypto runs",
              "not " + str(P.RECORD_LEN) in str(e) or "296" in str(e))


print("\n== the hardened parser ==")
cases = [
    (b'{"job":"receive_new","job":"run_pipeline"}', "duplicate key"),
    (b'{"amount_slot": Infinity}', "Infinity"),
    (b'{"amount_slot": NaN}', "NaN"),
    (b'{"amount_slot": 1.5}', "a float"),
    (b'{"a": {"b": 2.0}}', "a nested float"),
    (b'[]', "a JSON array"),
    (b'not json', "not JSON"),
    (b'\xff\xfe', "not UTF-8"),
]
for raw, why in cases:
    try:
        P.parse_body(raw)
        check(f"{why} is refused", False)
    except P.WakeError:
        check(f"{why} is refused", True)
# The duplicate-key case is the one with teeth: CPython's default keeps the
# LAST value, so a note carrying both a safe job and a spending one would parse
# as the spending one.
try:
    P.parse_body(b'{"job":"receive_new","job":"run_pipeline"}')
    check("...and never resolves to the shadowed value", False)
except P.WakeError:
    check("...and never resolves to the shadowed value (CPython keeps the LAST "
          "key, so this would have parsed as run_pipeline)", True)


print("\n== the job vocabulary ==")
check("no job template can name a spending tool",
      all(t not in P.FORBIDDEN_TOOLS
          for spec in P.JOBS.values() for t in spec["tools"]))
check("...and the forbidden list actually names the mix",
      "GhostSpiral" in P.FORBIDDEN_TOOLS
      and "airgap_tx_signer" in P.FORBIDDEN_TOOLS)
check("there is no swap_quote job — a job that takes a destination is how a "
      "pwned doorbell steals the incoming BTC",
      "swap_quote" not in P.JOBS)
check("no schema field is a free-form string that could become a flag, a path "
      "or a URL",
      all(getattr(c, "spec", "").startswith("int ")
          or getattr(c, "spec", "").startswith("handle ")
          for spec in P.JOBS.values() for c in spec["schema"].values()))

for job in P.JOBS:
    body = {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex(),
            "job": job}
    body.update(SAMPLE[job])
    jid, j, params = P.validate_job(body)
    check(f"{job} validates and returns its typed params", j == job and params)

bad_bodies = [
    ({"job": "run_pipeline"}, "a spending job id"),
    ({"job": "receive_new", "count": 0}, "an int below range"),
    ({"job": "receive_new", "count": 5}, "an int above range"),
    ({"job": "receive_new", "count": True}, "a bool wearing an int's hat"),
    ({"job": "receive_new", "count": "1"}, "an int as a string"),
    ({"job": "receive_new", "count": 1, "extra": 1}, "an unknown extra key"),
    ({"job": "receive_new"}, "a missing key"),
    ({"job": "watch", "handle": "a3f1"}, "a lowercase handle"),
    ({"job": "watch", "handle": "4" + "A" * 94}, "an address as a handle"),
    ({"job": "receive_and_quote", "amount_slot": 8}, "a slot past the ladder"),
]
for body, why in bad_bodies:
    b = {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex()}
    b.update(body)
    try:
        P.validate_job(b)
        check(f"{why} is refused", False)
    except P.WakeError:
        check(f"{why} is refused", True)

# Injection strings, which is what a flag-passthrough channel would have carried.
for v in ("--tor-proxy", "socks5h://10.0.0.9:9050", "--allow-unbound-memo",
          "; rm -rf ~", "../../etc/passwd", "--outfile", "/srv/x.json"):
    b = {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex(),
         "job": "receive_new", "count": v}
    try:
        P.validate_job(b)
        check(f"a flag-shaped value ({v[:18]}) is refused by the schema", False)
    except P.WakeError:
        check(f"a flag-shaped value ({v[:18]!r}) is refused by the schema", True)

def _jobmsg():
    try:
        P.validate_job({"job_id": P.new_job_id(),
                        "challenge": P.new_challenge().hex(),
                        "job": "run_pipeline"})
    except P.WakeError as e:
        return str(e)
    return ""


check("an unknown job id is refused, and the refusal does NOT echo the id "
      "back into a log", bool(_jobmsg()) and "run_pipeline" not in _jobmsg())


print("\n== nonce discipline ==")
b = {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex(),
     "job": "receive_new", "count": 1}
check("sealing the same body twice gives different records",
      P.seal(PI, EPH.public_key, P.TAG_M2, b)
      != P.seal(PI, EPH.public_key, P.TAG_M2, b))
import inspect                                               # noqa: E402
check("seal() exposes no nonce parameter — the classic counter-as-nonce "
      "mistake is unrepresentable, not merely discouraged",
      "nonce" not in inspect.signature(P.seal).parameters)
check("open_record() exposes no nonce parameter either",
      "nonce" not in inspect.signature(P.open_record).parameters)
src = open(os.path.join(REPO, "gs_wake_proto.py"), encoding="utf-8").read()
check("...and nothing in the module passes an explicit nonce to encrypt()",
      "encrypt(padded)" in src and "nonce=" not in src)


print("\n== the seal-side length gate ==")
try:
    P.seal(TP, PI.public_key, P.TAG_M3,
           {"job_id": P.new_job_id(), "challenge": P.new_challenge().hex(),
            "status": "done", "handle": "4" + "A" * 94})
    check("a note too long for one padded block is refused at seal time", False)
except P.WakeError as e:
    check("a note too long for one padded block is refused at seal time — so "
          "an address can never be smuggled out as a 'handle'",
          "255" in str(e) or "carries at most" in str(e))
check("...which is why the handle limit has TWO independent defences",
      P.MAX_INNER == P.PAD_BLOCK - 1)

try:
    P.seal(TP, PI.public_key, b"NOPE".ljust(16, b"\0"), {"a": 1})
    check("sealing with an unknown tag is refused", False)
except P.WakeError:
    check("sealing with an unknown tag is refused", True)


print("\n== challenge and field shapes ==")
good = {"challenge": P.new_challenge().hex()}
check("a well-formed challenge parses", len(P.challenge_of(good)) == 32)
for bad, why in (({"challenge": "zz"}, "non-hex"),
                 ({"challenge": "ab"}, "too short"),
                 ({"challenge": 5}, "not a string"),
                 ({}, "absent")):
    try:
        P.challenge_of(bad)
        check(f"a {why} challenge is refused", False)
    except P.WakeError:
        check(f"a {why} challenge is refused", True)
check("handles are random, not derived — two in a row differ",
      len({P.new_handle() for _ in range(50)}) > 1)
check("...and match the shape the doorbell will accept",
      all(P.HANDLE_RE.match(P.new_handle()) for _ in range(50)))



# ===========================================================================
print("\n== the sealed keyfile container ==")
import json as _json                                         # noqa: E402
import socket as _socket                                     # noqa: E402
import threading as _threading                               # noqa: E402
import nacl.public as _NP                                    # noqa: E402

_sk = _NP.PrivateKey.generate()
_payload = {"role": "pi", "secret": _sk.encode().hex(),
            "peer_public": "ab" * 32, "target_mac": "aa:bb:cc:dd:ee:ff",
            "listen_host": "192.168.1.9", "listen_port": 41337}
_PW = b"four random words please"
_c = P.lock_keyfile(_payload, _PW, kdf="interactive", role="pi")
check("a sealed keyfile round-trips", P.unlock_keyfile(_c, _PW) == _payload)
check("...and reports itself as sealed", P.keyfile_is_sealed(_c))

# THE WHOLE POINT. An imaged SD card is read by someone who is root on their
# own machine, so mode 0400 is nothing. What must survive that is the file
# revealing nothing but parameters.
_blob = _json.dumps(_c)
for _v, _what in ((_payload["secret"], "the X25519 secret"),
                  (_payload["target_mac"], "the vault's MAC"),
                  (_payload["listen_host"], "the LAN address"),
                  (_payload["peer_public"], "the peer's public key")):
    check(f"an imaged SD card does NOT yield {_what}", _v not in _blob)
check("...only the KDF parameters and a salt, which are not secrets",
      set(_c) == {"schema", "version", "role", "kdf", "profile", "ops", "mem",
                  "salt", "box"})

try:
    P.unlock_keyfile(_c, b"wrong")
    check("a wrong passphrase is refused", False)
except P.WakeError as e:
    check("a wrong passphrase is refused", "did not open" in str(e))
    check("...and does not claim to know WHETHER it was the passphrase or "
          "tampering, because Poly1305 fails identically for both",
          "no way to tell which" in str(e))
_t = dict(_c)
_t["box"] = ("00" if _c["box"][:2] != "00" else "11") + _c["box"][2:]
try:
    P.unlock_keyfile(_t, _PW)
    check("a tampered body is refused", False)
except P.WakeError:
    check("a tampered body is refused", True)

# Both numbers come off a disk an attacker may have written to, and memlimit is
# an allocation.
#
# ASSERT THE REASON, NOT JUST THE REFUSAL. The mutation sweep caught this file
# passing for the wrong reason: with the bounds check deleted, mem=2**40 sailed
# through to libsodium, which errored for its OWN reasons, and the test stayed
# green while the guarantee was gone. "It raised something" is not evidence
# that the thing you are testing exists.
for _k, _v, _why in (("ops", 99, "an out-of-range opslimit"),
                     ("ops", 0, "a zero opslimit"),
                     ("mem", 2 ** 40, "a memlimit that would OOM the reader"),
                     ("mem", 4096, "a memlimit far below the floor")):
    _b = dict(_c)
    _b[_k] = _v
    try:
        P.unlock_keyfile(_b, _PW)
        check(f"refuses {_why} in a keyfile", False)
    except P.WakeError as e:
        check(f"refuses {_why} in a keyfile, BEFORE deriving anything — the "
              f"message names the parameter, not libsodium's own complaint",
              "out-of-range" in str(e))
for _k, _v in (("ops", "3"), ("mem", None), ("ops", True)):
    _b = dict(_c)
    _b[_k] = _v
    try:
        P.unlock_keyfile(_b, _PW)
        check(f"refuses a non-integer {_k}", False)
    except P.WakeError as e:
        check(f"refuses a non-integer {_k}", "out-of-range" in str(e))

_plain = P.lock_keyfile(_payload, b"", role="thinkpad")
check("kdf=none stores the payload as PLAIN JSON rather than dressing "
      "plaintext up as a ciphertext",
      _plain["kdf"] == "none" and _plain["plain"] == _payload
      and "box" not in _plain)
check("...and says it is not sealed", not P.keyfile_is_sealed(_plain))
check("...and opens with no passphrase", P.unlock_keyfile(_plain) == _payload)
try:
    P.unlock_keyfile({"schema": "gs_wake_v1", "version": 1, "role": "pi"})
    check("the old PLAINTEXT v1 keyfile is not read any more", False)
except P.WakeError as e:
    check("the old PLAINTEXT v1 keyfile is not read any more",
          "pair the two boxes again" in str(e))


print("\n== the pairing ceremony: commit, reveal, compare ==")
_VINFO = {"mac": "aa:bb:cc:dd:ee:ff", "broadcast": "192.168.1.255"}
_PINFO = {"host": "192.168.1.9", "port": 41337}


def _ceremony(i_ask=lambda s: True, r_ask=lambda s: True, tamper=None,
              ipub=None, rpub=None, isk=None, rsk=None):
    a, b = _socket.socketpair()
    a.settimeout(20)
    b.settimeout(20)
    _isk = isk or _NP.PrivateKey.generate()
    _rsk = rsk or _NP.PrivateKey.generate()
    ip = ipub or _isk.public_key.encode()
    rp = rpub or _rsk.public_key.encode()
    res = {}

    def responder():
        try:
            res["r"] = P.pair_responder(b, _rsk, rp, _VINFO, r_ask,
                                        lambda m: None)
        except Exception as e:                               # noqa: BLE001
            res["r"] = e
        finally:
            try:
                b.close()
            except OSError:
                pass

    t = _threading.Thread(target=responder)
    t.start()
    try:
        res["i"] = (tamper(a, ip, i_ask) if tamper else
                    P.pair_initiator(a, _isk, ip, _PINFO, i_ask,
                                     lambda m: None))
    except Exception as e:                                   # noqa: BLE001
        res["i"] = e
    finally:
        t.join(30)
        try:
            a.close()
        except OSError:
            pass
    return res


_r = _ceremony()
check("both boxes derive the SAME code from the two public keys",
      isinstance(_r["i"], dict) and isinstance(_r["r"], dict)
      and _r["i"]["sas"] == _r["r"]["sas"])
check("...and it is 8 characters from an alphabet with no I, L, O or U, "
      "because a human reads one off a Pi and compares it to a laptop",
      len(_r["i"]["sas"]) == 9 and _r["i"]["sas"][4] == "-"
      and not (set(_r["i"]["sas"]) & set("ILOU")))
check("...and each box learned only the OTHER's public key",
      _r["i"]["peer_public"] != _r["r"]["peer_public"])
check("...and the config each side needs crossed with it: the Pi got a MAC "
      "and a broadcast, the vault got an address and a port",
      _r["i"]["peer_info"] == _VINFO and _r["r"]["peer_info"] == _PINFO)
check("...and NEITHER side sent a secret: the payload keys are exactly the "
      "public key and the non-secret config",
      "secret" not in _json.dumps(_r["i"]) + _json.dumps(_r["r"]))

# NOTHING BUT A PUBLIC KEY CROSSES BEFORE THE HUMANS HAVE CONFIRMED. The vault
# used to put its MAC and broadcast address in the plaintext `reveal`, which it
# sends to whoever connects, on a socket bound to every interface, before
# anybody has authenticated anything -- so any host on the switch could open
# the pairing port during the ceremony and be handed the exact value the sealed
# keyfile exists to keep off a stolen SD card.
_seen = []


def _eavesdrop(sock, pub, ask):
    sock.settimeout(20)
    P._pair_send(sock, {"t": "commit", "v": P.PAIR_PROTO,
                        "c": P.pair_commitment(pub).hex()})
    body = P._pair_step(sock, "reveal")
    _seen.append(_json.dumps(body))
    raise P.WakeError("hung up after taking whatever was offered")


_r = _ceremony(tamper=_eavesdrop)
check("a host that connects, takes the reveal and hangs up learns NOTHING "
      "but a public key — no MAC, no broadcast address, no LAN layout",
      _seen and all(v not in _seen[0] for v in
                    ("aa:bb:cc:dd:ee:ff", "192.168.1.255", "mac", "broadcast",
                     "info")))
check("...and what it does learn is exactly the one field it is meant to",
      _seen and set(_json.loads(_seen[0])) == {"t", "v", "pub"})

# THE ATTACK THE COMMITMENT EXISTS FOR. Without it the initiator picks its key
# AFTER seeing the responder's, so a man in the middle grinds keypairs until
# the two codes agree -- about 2^20 X25519 keygens for a 40-bit code, which is
# seconds. The short code the operator will actually compare depends entirely
# on this check.
def _grind(sock, pub, ask):
    sock.settimeout(20)
    other = _NP.PrivateKey.generate().public_key.encode()
    P._pair_send(sock, {"t": "commit", "v": P.PAIR_PROTO,
                        "c": P.pair_commitment(pub).hex()})
    body = P._pair_step(sock, "reveal")
    P._pair_send(sock, {"t": "reveal", "v": P.PAIR_PROTO, "pub": other.hex()})
    return P._pair_finish(sock, other, P._pair_pub(body), ask, lambda m: None)


_r = _ceremony(tamper=_grind)
check("a key that does not match its commitment is REFUSED — this is what "
      "lets the compare-code be short enough that a human compares it",
      isinstance(_r["r"], P.WakeError) and "committed to" in str(_r["r"]))
check("...and the operator at the OTHER screen is told why, rather than "
      "being shown a broken pipe for a detected attack",
      isinstance(_r["i"], P.WakeError)
      and "committed to" in str(_r["i"]))

_r = _ceremony(i_ask=lambda s: False)
check("answering no on ONE box aborts the pairing on BOTH — neither is left "
      "holding a keyfile for a peer that wrote none",
      isinstance(_r["i"], P.WakeError) and isinstance(_r["r"], P.WakeError))
check("...and each is told which end declined",
      "you did not confirm" in str(_r["i"])
      and "answered no" in str(_r["r"]))
_r = _ceremony(r_ask=lambda s: False)
check("...in the other direction too",
      isinstance(_r["i"], P.WakeError) and isinstance(_r["r"], P.WakeError)
      and "answered no" in str(_r["i"]))


# THE CONFIG NOW ARRIVES SEALED AND AFTER CONFIRMATION, so a bad value in it
# is refused there rather than in the plaintext reveal. It still must not reach
# a keyfile.
_evilsk = _NP.PrivateKey.generate()


def _hostname(sock, pub, ask):
    sock.settimeout(20)
    P._pair_send(sock, {"t": "commit", "v": P.PAIR_PROTO,
                        "c": P.pair_commitment(pub).hex()})
    body = P._pair_step(sock, "reveal")
    peer = P._pair_pub(body)
    P._pair_send(sock, {"t": "reveal", "v": P.PAIR_PROTO, "pub": pub.hex()})
    P._pair_finish(sock, pub, peer, ask, lambda m: None)
    # SEALED AND SENT DIRECTLY, not via _pair_config.
    #
    # _pair_config now validates its OWN info before sending, which is what
    # stops an HONEST box with a bad local value (an IPv6 address out of
    # sock.getsockname()) from half-pairing. An ATTACKER simply does not run
    # that check -- they run their own code -- so driving this through
    # _pair_config would only ever test our sender-side guard and would leave
    # the RECEIVER's guard, the one that actually has to hold, unexercised.
    rec = P.seal(_evilsk, _NP.PublicKey(peer), P.TAG_PC,
                 {"info": {"host": "evil.example.com", "port": 41337}})
    sock.sendall(rec)
    got = P._pair_read_record(sock)
    return P._pair_info(P.open_record(_evilsk, _NP.PublicKey(peer), got,
                                      P.TAG_PV))


_r = _ceremony(tamper=_hostname, ipub=_evilsk.public_key.encode())
check("a HOSTNAME where an address belongs is refused — it would become a "
      "DNS lookup on a box whose whole point is that it makes none",
      isinstance(_r["r"], P.WakeError) and "IPv4" in str(_r["r"]))
check("...and the vault wrote nothing, because the refusal happens before "
      "pair_responder returns",
      not isinstance(_r["r"], dict))


# A SOCKET TIMEOUT BOUNDS ONE recv(), NOT ONE MESSAGE. These reads are
# byte-at-a-time, so a peer that dribbles one byte per timeout-minus-a-second
# holds the ceremony open indefinitely while every individual read looks
# healthy. Driven with a real dribbler rather than reasoned about.
def _dribble(sock, pub, ask):
    import time as _t
    end = _t.monotonic() + 120
    while _t.monotonic() < end:
        sock.sendall(b"x")
        _t.sleep(2)
    return "still going"


_t0 = __import__("time").monotonic()
_r = _ceremony(tamper=_dribble)
_elapsed = __import__("time").monotonic() - _t0
check("a peer that dribbles bytes is cut off on a WHOLE-MESSAGE deadline, "
      "not left holding the ceremony open one healthy read at a time",
      isinstance(_r["r"], P.WakeError)
      and "did not finish sending" in str(_r["r"]))
check(f"...within the message budget rather than the human one "
      f"({int(_elapsed)}s elapsed, budget {P.PAIR_MSG_S}s, human step "
      f"{P.PAIR_TIMEOUT_S}s)",
      _elapsed < P.PAIR_MSG_S + 15)


def _flood(sock, pub, ask):
    sock.settimeout(20)
    sock.sendall(b"x" * 40000)
    return "sent"


_r = _ceremony(tamper=_flood)
check("a peer that floods the pairing socket is cut off at the size limit "
      "rather than allocating whatever it sends",
      isinstance(_r["r"], P.WakeError) and "size limit" in str(_r["r"]))

_samesk = _NP.PrivateKey.generate()
_same = _samesk.public_key.encode()
_r = _ceremony(ipub=_same, rpub=_same, isk=_samesk, rsk=_samesk)
check("a box offered its OWN public key back refuses — that is a reflection, "
      "not a peer",
      isinstance(_r["r"], P.WakeError) or isinstance(_r["i"], P.WakeError))

for _extra in ({"port": 0}, {"port": 70000}, {"mac": "nope"},
               {"broadcast": "999.1.1.1"}, {"outfile": "/srv/x"}):
    _bad = dict(_PINFO)
    _bad.update(_extra)
    try:
        P._pair_info({"info": _bad})
        check(f"pairing info refuses {sorted(_extra)[0]}={list(_extra.values())[0]!r}",
              False)
    except P.WakeError:
        check(f"pairing info refuses {sorted(_extra)[0]}={list(_extra.values())[0]!r}",
              True)


# ===========================================================================
# `$` IS NOT END-OF-STRING IN PYTHON. It also matches just before a trailing
# newline, so every "^...$" shape check on this wire accepted a value with
# "\n" glued on -- and the range guard did not catch it either, because
# int("255\n") is 255. The value is written into a keyfile and then composes
# f"http://{host}:{port}", which urllib rejects with "URL can't contain
# control characters" MONTHS LATER, at the one moment a machine must wake.
# ===========================================================================
for _bad, _why in [({"broadcast": "192.168.1.255\n"}, "broadcast newline"),
                   ({"mac": "de:ad:be:ef:ca:fe\n"}, "MAC newline"),
                   ({"host": "10.0.0.1\n", "port": 8770}, "host newline"),
                   ({"host": "10.0.0.010", "port": 8770}, "octal-looking host"),
                   ({"broadcast": "999.1.1.1"}, "out-of-range octet")]:
    _refused = False
    try:
        P._pair_info({"info": _bad})
    except P.WakeError:
        _refused = True
    check(f"_pair_info refuses a {_why} off the wire", _refused)
check("_pair_info still accepts an honest dotted quad",
      P._pair_info({"info": {"host": "10.0.0.1", "port": 8770}})
      == {"host": "10.0.0.1", "port": 8770})
check("the wire regexes are anchored with \\Z, not $",
      "$\", v)" not in src and "\\Z" in src)

# ===========================================================================
# A WIRE BREAK WITHOUT A VERSION BUMP LETS TWO BOXES AGREE TO PAIR AND THEN
# FAIL AT WAKE TIME, which is the worst place to find out. M1 gained a
# required `window` field and `reveal` lost its plaintext `info`; both are
# incompatible, and PAIR_PROTO stayed at 2.
# ===========================================================================
check("PAIR_PROTO was bumped past the version that had no per-window nonce",
      P.PAIR_PROTO >= 3)

# ===========================================================================
# HALF A PAIRING. _pair_config runs AFTER both operators confirmed, and only
# the RECEIVING side validated -- so the box holding a bad value (an IPv6
# address from sock.getsockname() on an IPv6-routed LAN) sent it and wrote its
# keyfile, while the peer rejected it and wrote nothing.
# ===========================================================================
check("_pair_config validates its OWN info before sending it",
      "_pair_info({\"info\": my_info})" in src)
_pc_body = src.split("def _pair_config")[1].split("\ndef ")[0]
check("...and aborts the peer rather than leaving it holding a keyfile "
      "(both on my own bad info and on the peer's)",
      _pc_body.count("_pair_abort(sock, \"info\")") == 2)
check("PAIR_ABORT['info'] is no longer dead code",
      "_pair_abort(sock, \"info\")" in src and "\"info\":" in src)

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
