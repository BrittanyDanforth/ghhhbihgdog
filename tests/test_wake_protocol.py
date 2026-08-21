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
print("\n== the pairing tool, run for real ==")
# gs_wake_keys had NO behavioural test: it was checked for --help and for being
# named in the doc, and nothing else. It is the one program here whose output
# every other program depends on, and a keyfile it writes wrong is discovered
# at 3am on a box that will not wake.
import json as _json                                         # noqa: E402
import subprocess as _sp                                     # noqa: E402
import tempfile as _tf                                       # noqa: E402
import nacl.public as _NP                                    # noqa: E402

_KEYS = os.path.join(REPO, "gs_wake_keys")


def _pair(*extra, out=None):
    d = out or _tf.mkdtemp(prefix="wakepair_")
    r = _sp.run([sys.executable, _KEYS, "--out", d,
                 "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
                 "--doorbell-host", "10.0.0.9", *extra],
                capture_output=True, text=True, cwd=d)
    return d, r


_d, _r = _pair("--amount-ladder", "0.01", "0.05")
check("pairing succeeds and writes both keyfiles", _r.returncode == 0)
_tp = _json.loads(open(os.path.join(_d, "gs_wake_thinkpad.key")).read())
_pi = _json.loads(open(os.path.join(_d, "gs_wake_pi.key")).read())
check("...each file holds ONE secret, never both",
      _tp["secret"] != _pi["secret"]
      and _tp["peer_public"] == _NP.PrivateKey(
          bytes.fromhex(_pi["secret"])).public_key.encode().hex()
      and _pi["peer_public"] == _NP.PrivateKey(
          bytes.fromhex(_tp["secret"])).public_key.encode().hex())
check("...both 0400, because the agent runs unattended and only reads them",
      all(oct(os.stat(os.path.join(_d, f)).st_mode)[-3:] == "400"
          for f in ("gs_wake_thinkpad.key", "gs_wake_pi.key")))
check("...and they print the SAME pair fingerprint, which is what the "
      "operator reads off both boxes",
      _tp["pair_fingerprint"] == _pi["pair_fingerprint"]
      and _tp["pair_fingerprint"] in _r.stdout)

# THE POINT OF THE TOOL: the two files must actually interoperate through the
# real seal/open path, in both directions, with the ephemeral in the middle.
_tpsk = _NP.PrivateKey(bytes.fromhex(_tp["secret"]))
_pisk = _NP.PrivateKey(bytes.fromhex(_pi["secret"]))
_eph = _NP.PrivateKey.generate()
_ch = P.new_challenge()
_m1 = P.seal(_tpsk, _NP.PublicKey(bytes.fromhex(_tp["peer_public"])), P.TAG_M1,
             {"eph_pk": _eph.public_key.encode().hex(), "challenge": _ch.hex()})
_b1 = P.open_record(_pisk, _NP.PublicKey(bytes.fromhex(_pi["peer_public"])),
                    _m1, P.TAG_M1)
_m2 = P.seal(_pisk, _NP.PublicKey(P.eph_pk_of(_b1)), P.TAG_M2,
             {"job_id": P.new_job_id(), "challenge": _ch.hex(),
              "job": "receive_new", "count": 1})
# The vault opens M2 with its EPHEMERAL secret against the PI's public key --
# which its own keyfile calls peer_public. Getting this backwards is exactly
# the confusion the two-file split exists to make impossible, and it failed
# loudly here rather than quietly passing.
_b2 = P.open_record(_eph, _NP.PublicKey(bytes.fromhex(_tp["peer_public"])),
                    _m2, P.TAG_M2)
check("a freshly minted pair completes a real M1/M2 exchange",
      P.challenge_of(_b2) == _ch and P.validate_job(_b2)[1] == "receive_new")

check("re-running over an existing pair REFUSES rather than silently "
      "replacing a keypair the other box still holds",
      _pair(out=_d)[1].returncode != 0)

# Everything below is written into a keyfile and only checked when the doorbell
# next tries to start -- i.e. at the moment the operator needs it to work.
_d2 = _tf.mkdtemp(prefix="wakepair_")
_bad = _sp.run([sys.executable, _KEYS, "--out", _d2,
                "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
                "--doorbell-host", "0.0.0.0"],
               capture_output=True, text=True, cwd=_d2)
check("an all-interfaces --doorbell-host is refused AT PAIRING, not at the "
      "doorbell's next start",
      _bad.returncode != 0 and "all-interfaces" in _bad.stdout + _bad.stderr)
check("...and no half-pairing is left behind", os.listdir(_d2) == [])

_d3 = _tf.mkdtemp(prefix="wakepair_")
_bad3 = _sp.run([sys.executable, _KEYS, "--out", _d3,
                 "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
                 "--doorbell-host", "10.0.0.9", "--doorbell-port", "0"],
                capture_output=True, text=True, cwd=_d3)
check("port 0 is refused: the Pi would bind a random port while the vault was "
      "told to fetch from ':0'",
      _bad3.returncode != 0 and "not a port" in _bad3.stdout + _bad3.stderr)

_d35 = _tf.mkdtemp(prefix="wakepair_")
_bad35 = _sp.run([sys.executable, _KEYS, "--out", _d35,
                  "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
                  "--doorbell-host", "10.0.0.9", "--artifact-dir", "bay"],
                 capture_output=True, text=True, cwd=_d35)
check("a RELATIVE --artifact-dir is refused: the agent runs under systemd, "
      "whose working directory is '/', and that is mounted read-only",
      _bad35.returncode != 0
      and "relative" in _bad35.stdout + _bad35.stderr)
_d36 = _tf.mkdtemp(prefix="wakepair_")
_sp.run([sys.executable, _KEYS, "--out", _d36,
         "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
         "--doorbell-host", "10.0.0.9"],
        capture_output=True, text=True, cwd=_d36)
_tp36 = _json.loads(open(os.path.join(_d36, "gs_wake_thinkpad.key")).read())
check("...and the DEFAULT is the absolute path the shipped unit's "
      "ReadWritePaths= names",
      _tp36["artifact_dir"] == "/var/lib/ghostspiral"
      and "/var/lib/ghostspiral" in open(
          os.path.join(REPO, "systemd", "gs-wake-agent.service")).read())

_d4 = _tf.mkdtemp(prefix="wakepair_")
_bad4 = _sp.run([sys.executable, _KEYS, "--out", _d4,
                 "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
                 "--doorbell-host", "10.0.0.9",
                 "--amount-ladder", "0.01", "0", "0.05"],
                capture_output=True, text=True, cwd=_d4)
check("a zero rung on the amount ladder is refused",
      _bad4.returncode != 0)
_d5 = _tf.mkdtemp(prefix="wakepair_")
_bad5 = _sp.run([sys.executable, _KEYS, "--out", _d5,
                 "--thinkpad-mac", "aa:bb:cc:dd:ee:ff",
                 "--doorbell-host", "10.0.0.9",
                 "--amount-ladder", *["0.01"] * 9],
                capture_output=True, text=True, cwd=_d5)
check("a ladder longer than the wire's slot range is refused, rather than "
      "carrying rungs no note could ever select",
      _bad5.returncode != 0 and "unreachable rungs" in _bad5.stdout + _bad5.stderr)


_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
