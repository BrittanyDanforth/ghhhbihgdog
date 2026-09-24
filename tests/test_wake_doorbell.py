#!/usr/bin/env python3
"""THE DOORBELL, over a real socket.

gs_doorbell runs on the Raspberry Pi that OPSEC_SETUP.md §3 defines by what it
must never hold. Two things are being tested and they are different:

  1. the STATE MACHINE -- one job, at most once, windows on the Pi's own clock;
  2. the BIND -- driven through ThreadingHTTPServer + http.client on
     127.0.0.1, exactly as tests/test_console.py does. A handler called
     directly proves the parse, not the bind, and the bind is half the
     guarantee.

The Pi's clock is injected, so window expiry is asserted without waiting ten
minutes for it.
"""
import contextlib
import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

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
from srcutil import code_only, fail_loudly_on_crash          # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_wake_doorbell.py")


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    sp = importlib.util.spec_from_loader(ld.name, ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    return m


DB = load("gs_doorbell")
import nacl.public as NP                                     # noqa: E402

# THE OPERATOR'S HOLD FILE DEFAULTS TO THE PI'S REAL ONE, and a second boot
# creates it. Every doorbell in this file holds into scratch instead: a run on
# a Pi must not hold that Pi's wakes, and one Bell's hold must not refuse the
# next Bell's vault.
_HOLD_REAL = P.HOLD_FILE_DEFAULT
_HOLD_DIR = tempfile.mkdtemp(prefix="gs_hold_")
P.HOLD_FILE_DEFAULT = os.path.join(_HOLD_DIR, "wakes.held")
_BELLS = [0]

TP = NP.PrivateKey.generate()
PI = NP.PrivateKey.generate()
#: The PAYLOAD. What lands on the SD card is the sealed container around it;
#: Pending() and run_wake() are handed the payload, because that is what
#: load_key returns after it opens the file.
KEY = {"role": "pi",
       "secret": PI.encode().hex(), "peer_public": TP.public_key.encode().hex(),
       "listen_host": "127.0.0.1", "listen_port": 0,
       "target_mac": "aa:bb:cc:dd:ee:ff", "wol_broadcast": "255.255.255.255",
       "wol_port": 9}
#: Cheap on purpose: this suite opens keyfiles many times and 'moderate' would
#: add minutes. The PROFILE is what is being varied, not the container, and the
#: container is identical either way.
PW = b"pairing test passphrase"
KDF = "interactive"


class Bell:
    """A doorbell on a real ephemeral port, with an injected clock."""

    def __init__(self, job="receive_and_quote", params=None, t=1000.0,
                 hold=None):
        self.t = [t]
        _BELLS[0] += 1
        self.hold = hold or os.path.join(_HOLD_DIR, f"held_{_BELLS[0]}")
        self.pending = DB.Pending(KEY, job, params or {"amount_sat": 5000000},
                                  clock=lambda: self.t[0],
                                  hold_file=self.hold)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port),
                                       DB.make_handler(self.pending))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def post(self, path, body):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request("POST", path, body=body,
                  headers={"Content-Length": str(len(body))})
        r = c.getresponse()
        d = r.read()
        c.close()
        return r.status, d

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request("GET", path)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def m1_for(eph, chal, window=None):
    """An M1 bound to a wake window. `window` is the Pending's live nonce.

    Defaulting it to a FRESH random value rather than to the live one, so a
    test that forgets to pass the real window gets a refusal instead of a
    silent pass -- the window check is the thing being tested, and a default
    that happens to satisfy it would test nothing.
    """
    return P.seal(TP, PI.public_key, P.TAG_M1,
                  {"eph_pk": eph.public_key.encode().hex(),
                   "challenge": chal.hex(),
                   "window": (window or P.new_window()).hex()})


print("== the Pi holds nothing, enforced by the import list ==")
src = code_only(os.path.join(REPO, "gs_doorbell"))
import ast                                                   # noqa: E402
mods = set()
for n in ast.walk(ast.parse(open(os.path.join(REPO, "gs_doorbell")).read())):
    if isinstance(n, ast.Import):
        mods.update(a.name.split(".")[0] for a in n.names)
    elif isinstance(n, ast.ImportFrom) and n.module:
        mods.add(n.module.split(".")[0])
for bad in ("gs_common", "monero", "stem", "psutil", "requests", "tenacity"):
    check(f"the doorbell does not import {bad}", bad not in mods)
for word in ("wallet_", "thor_pairs", "view_key", "spend_key", "mnemonic",
             "seed"):
    # code_only, so the header paragraph that NAMES these as forbidden does not
    # satisfy the check -- six checks in this repo already went red for
    # matching a string that lived only in a comment.
    check(f"...and its CODE never mentions {word}", word not in src)
def _refuses_bind(host):
    d = Path(tempfile.mkdtemp())
    p = d / "k.key"
    p.write_text(json.dumps({**KEY, "listen_host": host}))
    os.chmod(p, 0o400)
    try:
        DB.load_key(p)
        return False
    except DB.Doorbell:
        return True


for _h in ("0.0.0.0", "::", ""):
    check(f"it refuses a keyfile that asks it to bind {_h!r} — that would put "
          f"the doorbell on the Mullvad tunnel as well as the LAN",
          _refuses_bind(_h))


print("\n== the keyfile ==")
_d = Path(tempfile.mkdtemp())


def _keyfile(obj, mode=0o400, name="k.key", seal=True, mangle=None):
    """Write a REAL container around a payload. Never a hand-built shape."""
    c = (P.lock_keyfile(obj, PW, kdf=KDF, role=obj.get("role", "pi"))
         if seal else P.lock_keyfile(obj, b"", role=obj.get("role", "pi")))
    if mangle:
        c = mangle(dict(c))
    p = _d / name
    p.write_text(json.dumps(c))
    os.chmod(p, mode)
    return p


def _bad(**over):
    def f(c):
        c.update(over)
        return c
    return f


for kw, why in (
        (dict(obj={**KEY, "role": "thinkpad"}),
         "the VAULT's keyfile (it holds the vault's secret)"),
        (dict(obj=KEY, mode=0o644), "a world-readable keyfile"),
        (dict(obj=KEY, mangle=_bad(schema="nope")), "a foreign schema"),
        (dict(obj=KEY, mangle=_bad(version=99)), "a future wire version"),
        (dict(obj={**KEY, "target_mac": "nope"}), "an unusable MAC"),
        (dict(obj=KEY, seal=False),
         "an UNSEALED Pi keyfile — the SD card is the one that leaves the "
         "building, and 0400 means nothing to someone reading the card"),
        (dict(obj=KEY, mangle=_bad(ops=99)),
         "an out-of-range Argon2 opslimit off a disk an attacker may have "
         "written to"),
        (dict(obj=KEY, mangle=_bad(mem=2**40)),
         "an Argon2 memlimit that would OOM the doorbell when the file is "
         "read — a denial of service written into a keyfile")):
    kw.setdefault("mode", 0o400)
    p = _keyfile(name=f"k{abs(hash(why)) % 9999}.key", **kw)
    try:
        DB.load_key(p, PW)
        check(f"refuses {why}", False)
    except DB.Doorbell:
        check(f"refuses {why}", True)
check("accepts its own keyfile", DB.load_key(_keyfile(KEY, name="ok.key"), PW))
try:
    DB.load_key(_keyfile(KEY, name="wrongpw.key"), b"not the passphrase")
    check("refuses a wrong passphrase", False)
except DB.Doorbell as e:
    check("refuses a wrong passphrase", "did not open" in str(e))
_sealed = json.loads((_d / "ok.key").read_text())
check("...and NOTHING sensitive is outside the sealed box: not the secret, "
      "not the vault's MAC, not the LAN address",
      all(v not in json.dumps(_sealed) for v in
          (KEY["secret"], KEY["target_mac"], KEY["peer_public"])))
check("...while the KDF parameters ARE outside, because they are not secrets "
      "and the file has to be openable without guessing them",
      _sealed["kdf"] == "argon2id" and isinstance(_sealed["ops"], int)
      and isinstance(_sealed["mem"], int) and len(_sealed["salt"]) == 32)

print("\n== the intake floor rides on the pairing (the MED pass) ==")
# A vault paired with --btc-xpub sends the smallest deposit it can forward at
# its own fee ceiling; this box writes it on the card and the pager refuses a
# smaller deposit with the number before a wake is spent on the vault's
# refusal. A threshold the chat is already told, not an amount anyone paid.
check("load_key accepts a card carrying the intake floor the pairing sent, "
      "and hands it on as sent",
      DB.load_key(_keyfile({**KEY, "deposit_min_sat": 150000},
                           name="floor.key"), PW).get("deposit_min_sat")
      == 150000
      and "deposit_min_sat" not in DB.load_key(_keyfile(KEY, name="nofl.key"),
                                               PW))
# (A fraction is not tried here: the sealed card refuses any float before
# a field is read -- "refusing a float in a wake note" -- and the wire's
# shape check is what refuses one in test_wake_protocol.)
for _bad_f, _why in ((True, "a bool"), ("150000", "a string"),
                     (P.DEPOSIT_MIN_SAT - 1, "under the wire's floor"),
                     (P.DEPOSIT_MAX_SAT + 1, "over the wire's ceiling"),
                     (None, "null")):
    _refused = False
    try:
        DB.load_key(_keyfile({**KEY, "deposit_min_sat": _bad_f},
                             name=f"floor_{abs(hash(_why)) % 9999}.key"), PW)
    except DB.Doorbell as e:
        _refused = "intake floor" in str(e)
    check(f"...and refuses a card whose intake floor is {_why}", _refused)


class _DPSock:
    def getsockname(self):
        return ("192.168.1.9", 40000)

    def close(self):
        pass


def _do_pair_with(peer_info):
    """do_pair against a stubbed ceremony that agrees on `peer_info`:
    returns (rc, the card as load_key reads it)."""
    d = Path(tempfile.mkdtemp())

    class _A:
        key = str(d / "pi.key")
        vault, pair_port, port, kdf = "192.168.1.2", 8770, 41337, KDF

    _orig = DB.proto.pair_initiator
    DB.proto.pair_initiator = lambda sock, sk, pub, info, ask, say: {
        "peer_info": dict(peer_info),
        "peer_public": TP.public_key.encode().hex(), "sas": "0000-0000"}
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = DB.do_pair(_A(), connect=lambda: _DPSock(), ask=lambda s: True,
                            getpass_fn=lambda p: PW.decode())
    finally:
        DB.proto.pair_initiator = _orig
    return rc, DB.load_key(Path(_A.key), PW)


_dp_rc, _dp_key = _do_pair_with({"mac": "aa:bb:cc:dd:ee:ff",
                                 "broadcast": "192.168.1.255",
                                 "deposit_min_sat": 150000})
check("do_pair writes the floor the vault sent onto the card, beside the MAC",
      _dp_rc == 0 and _dp_key.get("deposit_min_sat") == 150000
      and _dp_key.get("target_mac") == "aa:bb:cc:dd:ee:ff")
_dp_rc2, _dp_key2 = _do_pair_with({"mac": "aa:bb:cc:dd:ee:ff",
                                   "broadcast": "192.168.1.255"})
check("...and a pair without the intake writes no floor (the pager then "
      "takes its flag, else the wire's own)",
      _dp_rc2 == 0 and "deposit_min_sat" not in _dp_key2)


print("\n== the job comes in on stdin, never on argv ==")
help_text = DB.build_cli().format_help()
for flag in ("--job", "--amount", "--count", "--handle", "--param"):
    check(f"there is no {flag} flag — a job on argv lands in "
          f"/proc/<pid>/cmdline, which is mode 0444",
          flag not in help_text)
for raw, why in (('{"job":"receive_and_quote","amount_sat":5000000}', None),
                 ('{"job":"receive_and_quote","amount_sat":5000000,'
                  '"replaces":"B4A1"}', None),
                 ('{"job":"receive_and_quote","amount_sat":5000000,'
                  '"replaces":"b4a1"}', "a replaces that is not a handle"),
                 ('{"job":"watch","handle":"B4A1","replaces":"C5D6"}',
                  "an optional field on a job that has none"),
                 ('{"job":"run_pipeline"}', "a spending job"),
                 ('{"job":"GhostSpiral"}', "the mix itself"),
                 ('{"job":"receive_new","count":9}', "an out-of-range count"),
                 ('{"job":"receive_new","count":1,"outfile":"/srv/x"}',
                  "a smuggled extra key"),
                 ('{"job":"receive_new"}', "a missing key"),
                 ('{"job":"receive_new","count":"--tor-proxy"}',
                  "a flag-shaped value"),
                 ('not json', "malformed input"),
                 ('', "empty input")):
    try:
        job, params = DB.read_job_from_stdin(io.StringIO(raw))
        check("a well-formed job is accepted" if why is None
              else f"refuses {why}", why is None)
    except (DB.Doorbell, P.WakeError):
        check(f"refuses {why}", why is not None)


print("\n== one job, handed over at most once ==")
b = Bell()
eph, chal = NP.PrivateKey.generate(), P.new_challenge()
st, m2 = b.post("/wake", m1_for(eph, chal, b.pending.window))
check("an authenticated M1 gets the job", st == 200 and len(m2) == P.RECORD_LEN)
body = P.open_record(eph, PI.public_key, m2, P.TAG_M2)
check("...the M2 echoes this boot's challenge", body["challenge"] == chal.hex())
check("...and names the job the operator asked for",
      body["job"] == "receive_and_quote" and body["amount_sat"] == 5000000)

st2, m2b = b.post("/wake", m1_for(eph, chal, b.pending.window))
check("REPLAYING the same M1 returns the SAME M2 and consumes nothing — a "
      "genuine retry and a LAN replay are the same request",
      st2 == 200 and m2b == m2)

eph2 = NP.PrivateKey.generate()
st3, _ = b.post("/wake", m1_for(eph2, P.new_challenge(), b.pending.window))
check("a DIFFERENT authenticated boot gets nothing — queue depth is one",
      st3 == 204)

# ONE CAPTURE USED TO BE A PERMANENT REMOTE DoS. The response cache makes a
# replay harmless WITHIN a process, and the reasoning was that capturing an M1
# needs the on-path position, so a replayer could just drop packets instead.
# That is wrong: capturing needs on-path ONCE. Replaying does not. Afterwards
# any host on the switch posts that M1 the moment a window opens, takes the
# job, and leaves the vault to boot, hear "no job" and power off -- for every
# wake, forever, while the operator reads "somebody sent a stray magic packet".
wb = Bell()
_stale = m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                P.new_window())          # a note from some other window
_ws, _wbody = wb.post("/wake", _stale)
check("an M1 written for a DIFFERENT wake window gets nothing", _ws == 204)
check("...and is recorded as such, not as a bad note",
      wb.pending.events.count("m1_stale_window") == 1)
_eph2, _ch2 = NP.PrivateKey.generate(), P.new_challenge()
_gs, _gm2 = wb.post("/wake", m1_for(_eph2, _ch2, wb.pending.window))
check("...and CONSUMED NOTHING: the real vault still collects the job "
      "afterwards, which is the whole point of refusing rather than caching",
      _gs == 200 and len(_gm2) == P.RECORD_LEN)
check("the window nonce is served to anyone who asks, because the vault must "
      "have it before it can seal anything",
      wb.post("/window", b"")[1] == wb.pending.window)
check(f"...and it is {P.WINDOW_BYTES} bytes, chosen so M1 still fits one "
      f"padded block with headroom for the next field",
      len(wb.pending.window) == P.WINDOW_BYTES)
wb.close()

wb2 = Bell()
check("two doorbells never share a window", wb2.pending.window != wb.pending.window)
wb2.close()

forged = P.seal(NP.PrivateKey.generate(), PI.public_key, P.TAG_M1,
                {"eph_pk": eph.public_key.encode().hex(),
                 "challenge": chal.hex()})
check("an M1 from an unknown key gets 204, not an error page",
      b.post("/wake", forged)[0] == 204)
check("a wrong-length body is refused before the AEAD",
      b.post("/wake", b"x" * 10)[0] == 400)
check("GET is refused — nothing this program knows goes in a URL",
      b.get("/wake") == 405)
check("an unknown path is refused", b.post("/nope", b"x" * P.RECORD_LEN)[0] == 404)


print("\n== the result ==")
def m3(status, handle, job_id=None, chall=None, **over):
    # THE FULL KEY SET, because on_m3 now enforces one. A result that is
    # missing a field this protocol version defines means the vault and the Pi
    # are on different versions, and the whole point of the check is that such
    # a record is refused loudly rather than half-read.
    body = {"job_id": job_id or b.pending.job_id,
            "challenge": (chall or chal).hex(),
            "status": status, "handle": handle,
            "slip": "", "plain": {}, "phase": ""}
    body.update(over)
    return P.seal(TP, PI.public_key, P.TAG_M3, body)


check("a 60-character 'handle' is refused — the doorbell may learn a label, "
      "never an address",
      b.post("/result", m3("done", "A" * 60))[0] == 204
      and b.pending.result is None)
check("a lowercase handle is refused", b.post("/result", m3("done", "a3f1"))[0] == 204)
check("a done with NO handle is refused — the operator would be told it "
      "worked and given nothing to look up",
      b.post("/result", m3("done", ""))[0] == 204 and b.pending.result is None)
check("a result for a different job is refused",
      b.post("/result", m3("done", "BEEF", job_id=P.new_job_id()))[0] == 204)
check("a well-formed result is accepted",
      b.post("/result", m3("done", "A3F1"))[0] == 200
      and b.pending.result == {"status": "done", "handle": "A3F1",
                               "slip": "", "plain": {}, "phase": ""})
# A HALF-UPGRADED PAIR MUST FAIL LOUDLY, NOT QUIETLY DROP THE PAYLOAD.
# gs_wake_proto's header promises a version mismatch is caught before any
# crypto and is "impossible to misread". That was true of a PAD_BLOCK change
# and false of a field addition: every field was read with .get() and no key
# set was enforced, so a vault running ahead of its Pi would send deposit
# instructions and this box would silently drop them.
#
# ON A FRESH DOORBELL, and with a GENUINELY old-shaped record. Both halves of
# that were wrong in the first version and the mutation sweep caught it: posted
# to a bell that had already recorded a result it was refused by the
# at-most-one rule instead, and a later bulk edit "fixed" the fixture by adding
# the very fields whose absence was the point. Deleting the key-set check left
# the suite green.
_bs = Bell()
_bs.post("/wake", m1_for(eph, chal, _bs.pending.window))
_stale = P.seal(TP, PI.public_key, P.TAG_M3,
                {"job_id": _bs.pending.job_id, "challenge": chal.hex(),
                 "status": "done", "handle": "BEEF"})
check("an M3 from an older protocol version is REFUSED, not half-read",
      _bs.post("/result", _stale)[0] == 204 and _bs.pending.result is None)
check("...NON-VACUITY: the same record with this version's fields IS accepted, "
      "so the refusal is about the key set and nothing else",
      _bs.post("/result", P.seal(
          TP, PI.public_key, P.TAG_M3,
          {"job_id": _bs.pending.job_id, "challenge": chal.hex(),
           "status": "done", "handle": "BEEF",
           "slip": "", "plain": {}, "phase": ""}))[0] == 200)
check("...and an M3 with an EXTRA field is refused too — a Pi running behind "
      "its vault must not half-read a record either",
      Bell().post("/result", P.seal(
          TP, PI.public_key, P.TAG_M3,
          {"job_id": "0" * 32, "challenge": chal.hex(), "status": "done",
           "handle": "BEEF", "slip": "", "plain": {}, "phase": "",
           "from_the_future": "x"}))[0] == 204)
_bs.close()
check("a SECOND result is refused — the outcome the operator sees must not "
      "depend on which note arrived last",
      b.post("/result", m3("failed", ""))[0] == 204
      and b.pending.result["status"] == "done")
check("the doorbell's outcome is what it was told", b.pending.outcome() == "done")
b.close()

b2 = Bell()
check("a failed/refused result may carry no handle, because there is nothing "
      "to name",
      b2.post("/wake", m1_for(eph, chal, b2.pending.window))[0] == 200
      and b2.post("/result", P.seal(TP, PI.public_key, P.TAG_M3,
                                    {"job_id": b2.pending.job_id,
                                     "challenge": chal.hex(),
                                     "status": "failed",
                                     "handle": "", "slip": "",
                                     "plain": {}, "phase": ""}))[0] == 200)
check("...and reports as failed", b2.pending.outcome() == "failed")
b2.close()


def _at(bell, dt):
    """finished() as it would read dt seconds from now, without advancing."""
    keep = bell.t[0]
    bell.t[0] = keep + dt
    try:
        return bell.pending.finished()
    finally:
        bell.t[0] = keep


print("\n== windows, on the Pi's own monotonic clock ==")
b3 = Bell()
check("before collection the job is not finished", not b3.pending.finished())
b3.t[0] += DB.FETCH_WINDOW_S + 1
check("an uncollected job expires after the fetch window",
      b3.pending.finished() and b3.pending.outcome() == "expired_uncollected")
check("...and a late M1 gets nothing",
      b3.post("/wake", m1_for(NP.PrivateKey.generate(),
                              P.new_challenge(), b3.pending.window))[0]
      == 204)
b3.close()

b4 = Bell()
b4.post("/wake", m1_for(eph, chal, b4.pending.window))
check("a collected job is not finished while its budget runs",
      not b4.pending.finished())
# result_budget_s, NOT budget_s. The property is unchanged -- a collected job
# with no result eventually reports collected_no_result -- but the deadline
# moved, because budget_s was never the whole wait. See below.
check("a collected job is STILL not finished at the old budget_s deadline, "
      "because the vault has not even started work by then",
      not (b4.t[0] + P.JOBS["receive_and_quote"]["budget_s"] + 1
           and _at(b4, P.JOBS["receive_and_quote"]["budget_s"] + 1)))
b4.t[0] += P.result_budget_s("receive_and_quote") + 1
check("a collected job with no result reports collected_no_result — the "
      "operator is told to CHECK THE VAULT before poking again",
      b4.pending.finished() and b4.pending.outcome() == "collected_no_result")
b4.close()


print("\n== Wake-on-LAN ==")
seen = {}


class FakeSock:
    def setsockopt(self, *a):
        seen["broadcast"] = a

    def sendto(self, pkt, addr):
        seen["pkt"], seen["addr"] = pkt, addr
        return len(pkt)

    def close(self):
        pass


n = DB.send_wol("aa:bb:cc:dd:ee:ff", "192.168.1.255", 9,
                sock_factory=lambda: FakeSock())
check("the magic packet is 102 bytes", n == 102 and len(seen["pkt"]) == 102)
check("...six 0xFF then the MAC sixteen times",
      seen["pkt"][:6] == b"\xff" * 6
      and seen["pkt"][6:] == bytes.fromhex("aabbccddeeff") * 16)
check("...to the configured broadcast and port",
      seen["addr"] == ("192.168.1.255", 9))
check("...with SO_BROADCAST set", seen.get("broadcast") is not None)
for bad in ("nope", "aa:bb:cc:dd:ee", "", "aa:bb:cc:dd:ee:ff:00"):
    try:
        DB.send_wol(bad, "1.2.3.4", 9, sock_factory=lambda: FakeSock())
        check(f"a malformed MAC ({bad!r}) refuses rather than sends", False)
    except DB.Doorbell:
        check(f"a malformed MAC ({bad!r}) refuses rather than sends", True)


print("\n== the socket is bound BEFORE the magic packet goes out ==")
order = []


class Args:
    no_jitter = True


def _boom(addr, handler):
    order.append("bind")
    raise OSError(98, "Address already in use")


try:
    DB.run_wake(Args(), KEY, "swap_status", {"handle": "A3F1"},
                server_factory=_boom,
                sock_factory=lambda: (order.append("wol"), FakeSock())[1])
    check("a doorbell that cannot listen refuses", False)
except DB.Doorbell as e:
    check("a doorbell that cannot listen refuses", "NOT sending" in str(e))
check("...and NO magic packet was sent — never wake a machine you have not "
      "proven you can answer", order == ["bind"])


print("\n== the magic packet is repeated until the vault collects ==")
# A packet that lands while the vault is still shutting down from its LAST
# job is ignored by a machine that is on and then missed by one that is off.
# A chained withdrawal's next leg is sent seconds after the previous leg's
# result -- exactly then -- and the chain died "never picked up" with money
# on the wallet. Repeated every WOL_RESEND_S while the fetch window is open
# and nothing has collected.


class _IdleSrv:
    refused_connections = 0

    def serve_forever(self):
        pass

    def shutdown(self):
        pass

    def server_close(self):
        pass


def _wake_uncollected(collect_at=None):
    """Drive run_wake on an injected clock; the vault collects at
    `collect_at` seconds (or never). Returns (packets sent, pending)."""
    t = [5000.0]
    sent = []

    class _Sock:
        def setsockopt(self, *a):
            pass

        def sendto(self, pkt, addr):
            sent.append(t[0])
            return len(pkt)

        def close(self):
            pass

    holder = {}

    def _factory(addr, handler):
        holder["pending"] = handler.pending if hasattr(handler, "pending") \
            else None
        return _IdleSrv()

    def _sleep(s):
        t[0] += s
        p = holder.get("p")
        if (p is not None and collect_at is not None
                and p.collected_at is None and t[0] - 5000.0 >= collect_at):
            p.collected_at = p.clock()
            p.result = {"status": "done"}

    _real_pending = DB.Pending

    class _Spy(_real_pending):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            holder["p"] = self

    DB.Pending = _Spy
    try:
        p = DB.run_wake(Args(), KEY, "swap_status", {"handle": "A3F1"},
                        server_factory=_factory,
                        sock_factory=lambda: _Sock(), sleep=_sleep,
                        clock=lambda: t[0])
    finally:
        DB.Pending = _real_pending
    return sent, p


_sent_never, _p_never = _wake_uncollected()
_expect = 1 + (DB.FETCH_WINDOW_S - 1) // DB.WOL_RESEND_S
check(f"resend: a vault that never collects is sent the packet once, then "
      f"every {DB.WOL_RESEND_S} s until the fetch window closes "
      f"({_expect} in all)",
      len(_sent_never) == _expect
      and all(b - a == DB.WOL_RESEND_S
              for a, b in zip(_sent_never, _sent_never[1:])))
check("resend: ...recorded once as an event, and the outcome is still "
      "'expired uncollected' -- the repeat changes nothing about the job",
      _p_never.events.count("wake_resent") == 1
      and _p_never.outcome() == "expired_uncollected")
_sent_soon, _p_soon = _wake_uncollected(collect_at=30)
check("resend: a vault that collects inside the first interval is sent "
      "exactly ONE packet -- nothing is repeated at a machine that answered",
      len(_sent_soon) == 1 and "wake_resent" not in _p_soon.events)
_sent_late, _p_late = _wake_uncollected(collect_at=150)
check("resend: ...and one that collects after two intervals was sent three "
      "and no more",
      len(_sent_late) == 3 and _p_late.events.count("wake_resent") == 1)
check("resend: the cadence is a named constant the docs can quote",
      isinstance(DB.WOL_RESEND_S, int) and 0 < DB.WOL_RESEND_S < DB.FETCH_WINDOW_S)


print("\n== the doorbell persists nothing ==")
scratch = Path(tempfile.mkdtemp())
cwd = os.getcwd()
os.chdir(scratch)
try:
    before = sorted(os.listdir("."))
    b5 = Bell()
    b5.post("/wake", m1_for(eph, chal, b5.pending.window))
    b5.post("/result", P.seal(TP, PI.public_key, P.TAG_M3,
                              {"job_id": b5.pending.job_id,
                               "challenge": chal.hex(),
                               "status": "done", "handle": "BEEF",
                               "slip": "", "plain": {}, "phase": ""}))
    b5.close()
    after = sorted(os.listdir("."))
finally:
    os.chdir(cwd)
check("a full cycle writes NOTHING to disk — the pending job, the response "
      "cache and the timers are process memory", before == after == [])
check("...and there is no persistent state file to go stale",
      not any("state" in n for n in after))


print("\n== the operator is TOLD when a second boot took the job ==")
# `events` was collected by every path in this file and read by NOTHING -- the
# same defect as a constant that is declared, documented and never called, and
# worse here: the one event meaning "your job did not go where you think" was
# among the ones being dropped on the floor.
er = Bell()
ereph, echal = NP.PrivateKey.generate(), P.new_challenge()
er.post("/wake", m1_for(ereph, echal, er.pending.window))
er.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(), er.pending.window))
er.close()
check("a second authenticated ephemeral is RECORDED, not just refused",
      er.pending.events.count("m1_second_ephemeral") == 1)
_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    DB.report(er.pending)
_txt = _buf.getvalue()
check("...and report() prints it, so a replay on the switch is not silent",
      "different boot" in _txt and "CHECK THE VAULT" in _txt)
check("...and says the vault's own ledger stops it running twice, rather than "
      "leaving the operator to guess",
      "repeated job id" in _txt)

# A malformed /result is NOT called hostile: any host on the LAN can post 296
# bytes of noise and land in that count.
er2 = Bell()
er2.post("/result", b"\x00" * P.RECORD_LEN)
er2.close()
_buf2 = io.StringIO()
with contextlib.redirect_stdout(_buf2):
    DB.report(er2.pending)
check("a junk /result is counted and reported without being called an attack",
      "did not authenticate" in _buf2.getvalue()
      and "hostile" not in _buf2.getvalue().lower())

# "did not authenticate" and "authenticated, then refused" are DIFFERENT
# FACTS and they used to share one line. A duplicate M3 can only come from
# something holding the vault's key; reporting it as LAN noise sends the
# operator to look at the switch instead of at the vault.
er3 = Bell()
er3eph, er3ch = NP.PrivateKey.generate(), P.new_challenge()
er3.post("/wake", m1_for(er3eph, er3ch, er3.pending.window))
_good = P.seal(TP, PI.public_key, P.TAG_M3,
               {"job_id": er3.pending.job_id, "challenge": er3ch.hex(),
                "status": "done", "handle": "BEEF",
                "slip": "", "plain": {}, "phase": ""})
_st_a = er3.post("/result", _good)[0]
_st_b = er3.post("/result", _good)[0]
_st_c = er3.post("/result", b"\x00" * P.RECORD_LEN)[0]
er3.close()
check("a duplicate result is refused, and recorded as REFUSED rather than as "
      "a record that did not authenticate",
      er3.pending.events.count("result_refused") == 1
      and er3.pending.events.count("result_bad") == 1)
check("...and the wire cannot tell the two apart: every refusal is 204, so a "
      "prober learns nothing from which one it hit",
      _st_a == 200 and _st_b == 204 and _st_c == 204)
# A STATUS WORD THIS BUILD DOES NOT HAVE (fix pass after the deep read): the
# answer is KEPT and the word dropped, and the event names the skew. It used
# to refuse the whole answer -- a finished job thrown away because the other
# box was one build newer -- and the pager took that for a failure.
er4 = Bell()
er4eph, er4ch = NP.PrivateKey.generate(), P.new_challenge()
er4.post("/wake", m1_for(er4eph, er4ch, er4.pending.window))
_newer = P.seal(TP, PI.public_key, P.TAG_M3,
                {"job_id": er4.pending.job_id, "challenge": er4ch.hex(),
                 "status": "done", "handle": "BEEF",
                 "slip": "", "plain": {}, "phase": "some_newer_word"})
_st_d = er4.post("/result", _newer)[0]
er4.close()
check("an authenticated answer carrying a status word this build lacks is "
      "ACCEPTED (200), its status and handle kept, the word replaced by "
      "PHASE_UNKNOWN (outside the vocabulary: never a rehearsal, never "
      "'nothing more') -- never passed through -- and the skew recorded as "
      "result_phase_unknown",
      _st_d == 200 and er4.pending.outcome() == "done"
      and er4.pending.result["handle"] == "BEEF"
      and er4.pending.result["phase"] == P.PHASE_UNKNOWN
      and P.PHASE_UNKNOWN not in P.PHASES
      and not P.phase_is_known(P.PHASE_UNKNOWN)
      and "some_newer_word" not in json.dumps(er4.pending.result)
      and "result_phase_unknown" in er4.pending.events
      and "result_ok" in er4.pending.events
      and "result_refused" not in er4.pending.events)
_buf_ph = io.StringIO()
with contextlib.redirect_stdout(_buf_ph):
    DB._report_events(er4.pending)
check("...and the terminal says UPDATE BOTH BOXES, naming the cause",
      "UPDATE BOTH BOXES" in _buf_ph.getvalue()
      and "status word" in _buf_ph.getvalue())
_buf4 = io.StringIO()
with contextlib.redirect_stdout(_buf4):
    DB.report(er3.pending)
_t4 = _buf4.getvalue()
check("...and report() says the vault contradicted itself, NOT that a "
      "stranger on the switch posted noise",
      "authenticated and were then refused" in _t4
      and "CHECK THE VAULT" in _t4)

_buf3 = io.StringIO()
q = Bell()
q.close()
with contextlib.redirect_stdout(_buf3):
    DB.report(q.pending)
check("...and a clean cycle prints NO event line at all",
      "different boot" not in _buf3.getvalue()
      and "did not authenticate" not in _buf3.getvalue())


# ---- A FINISHED FORWARD IS NOT A READY DEPOSIT EITHER --------------------
#
# report() fell through to the deposit path for the new job: "Vault
# finished job forward_to_swap. Handle A3F1." and then the slip or "the
# deposit address, the memo and the slip stayed on the vault" -- deposit
# instructions on a run that signed a spend of that deposit.
_fw = Bell("forward_to_swap", params={"handle": "A3F1",
                                      "owner": "0123456789abcdef"})
_fw.close()
_fw.pending.result = {"status": "done", "handle": "A3F1", "slip": "",
                      "plain": {}, "phase": ""}
_buf5 = io.StringIO()
with contextlib.redirect_stdout(_buf5):
    _rc5 = DB.report(_fw.pending)
_t5 = _buf5.getvalue()
check("a finished forward with no phase is reported as a SIGNED rehearsal, "
      "nothing sent -- with no handle line, no slip line and no deposit "
      "vocabulary", _rc5 == 0 and "SIGNED" in _t5 and "Nothing was sent"
      in _t5 and "Handle" not in _t5 and "deposit address" not in _t5
      and "how to pay" not in _t5 and "stayed on the vault. Read" not in _t5)
# ...AND `forwarded` (stage 6: the forward's transaction is in a block),
# which the doorbell must accept on the wire (phase_is_known) and print as
# the protocol's sentence, numberless, like the other two.
for _fph in ("sent", "unsure", "forwarded"):
    check(f"the doorbell knows the word {_fph!r} and its sentence carries "
          "no digit", P.phase_is_known(_fph) and _fph in P.PHASE_LINES
          and not any(ch.isdigit() for ch in P.PHASE_LINES[_fph]))
    _fw.pending.result = {"status": "done", "handle": "A3F1", "slip": "",
                          "plain": {}, "phase": _fph}
    _buf5 = io.StringIO()
    with contextlib.redirect_stdout(_buf5):
        _rc5 = DB.report(_fw.pending)
    _t5 = _buf5.getvalue()
    check(f"a finished forward with the word {_fph!r} prints the protocol's "
          "own sentence for it -- the same one the chat shows -- and not the "
          "rehearsal line", _rc5 == 0 and P.PHASE_LINES[_fph] in _t5
          and "rehearsal" not in _t5 and "Handle" not in _t5
          and "deposit address" not in _t5)

# ---- A FINISHED SPEND IS NOT A READY DEPOSIT ---------------------------
#
# report() branched on the OUTCOME and never on the job, so a completed
# withdrawal fell through the deposit path: it carries no handle, so the line
# read "Handle (none)"; it carries no slip, so the next line said "The deposit
# address, the memo and the slip stayed on the vault. Read them there" --
# deposit instructions, printed after a run that just spent money and issued
# none.
#
# This terminal is the by-hand path, and gs_wake_proto's own rule for it is
# that an operator running the doorbell by hand "must see exactly what the
# chat would have shown, or the by-hand path stops being a way to check the
# automated one". The chat says a spend was sent and whether more is left.
print("\n== a finished withdrawal is reported as a spend ==")


def _report_text(job, result):
    _b = Bell(job=job, params=({"exit_to": ["4" + "A" * 94], "depth": 1}
                               if job == "withdraw"
                               else {"amount_sat": 5000000}))
    _b.pending.result = result
    _b.pending.reported = True
    _b.close()
    _buf = io.StringIO()
    with contextlib.redirect_stdout(_buf):
        DB.report(_b.pending)
    return _buf.getvalue()


_wd_more = _report_text("withdraw", {"status": "done", "handle": "",
                                     "slip": "", "plain": {},
                                     "phase": "more_left"})
check("doorbell/withdraw: a finished spend is reported as a SPEND",
      "It SPENT" in _wd_more)
check("doorbell/withdraw: ...and never as a deposit whose details are "
      "waiting on the vault",
      "deposit address" not in _wd_more.lower()
      and "SEALED SLIP" not in _wd_more)
check("doorbell/withdraw: ...and names no handle, because a withdrawal "
      "registers none",
      "Handle" not in _wd_more)
check("doorbell/withdraw: ...and says there is more here, in the protocol's "
      "own words rather than the raw wire token",
      P.PHASE_LINES["more_left"] in _wd_more
      and "more_left" not in _wd_more)
_wd_last = _report_text("withdraw", {"status": "done", "handle": "",
                                     "slip": "", "plain": {}, "phase": ""})
# NOT "nothing is left": an empty phase also covers an arrival below the mix
# floor and a wallet that could not be asked, so the line may only say what
# was observed -- and it must be the chat's sentence, word for word, or the
# by-hand path stops being a way to check the automated one.
check("doorbell/withdraw: ...and with no phase it says nothing more was "
      "FOUND (not that the wallet is empty), rather than falling silent",
      P.WITHDRAW_NO_MORE_LINE in _wd_last
      and "Nothing is left" not in _wd_last
      and "empty" not in _wd_last.lower())
# NON-VACUITY: a DEPOSIT still takes the deposit path, so this is a branch and
# not a rewrite of report().
_dep = _report_text("receive_and_quote",
                    {"status": "done", "handle": "A3F1", "slip": "",
                     "plain": {}, "phase": ""})
check("doorbell/withdraw: NON-VACUITY -- a deposit still reports its handle "
      "and points at the vault for the details",
      "A3F1" in _dep and "stayed on the vault" in _dep
      and "It SPENT" not in _dep)


print("\n== the passphrase floor ==")
# It was eight characters. Against Argon2id at 256 MiB and somebody holding the
# SD card, eight characters of anything a person invents is a delay, not a
# passphrase -- and this passphrase is the ONLY thing between a stolen card and
# the vault's MAC address.
for _pw, _ok, _why in (("hunter2", False, "a seven-character classic"),
                       ("shortpw1", False, "eight characters"),
                       ("one two three", False, "three words"),
                       ("correct horse battery staple", True, "four words"),
                       ("aVeryLongSinglePassword", True, "one long string")):
    _seq = iter([_pw, _pw, "correct horse battery staple",
                 "correct horse battery staple"])
    with contextlib.redirect_stdout(io.StringIO()):
        _got = DB.new_passphrase(lambda p: next(_seq))
    check(f"{'accepts' if _ok else 'refuses'} {_why}",
          (_got.decode() == _pw) is _ok)
_seq = iter(["correct horse battery staple", "different words entirely here",
             "correct horse battery staple", "correct horse battery staple"])
with contextlib.redirect_stdout(io.StringIO()):
    _got = DB.new_passphrase(lambda p: next(_seq))
check("a mismatch on the second entry asks again rather than taking the first",
      _got == b"correct horse battery staple")
_buf = io.StringIO()
_seq = iter(["hunter2", "hunter2", "correct horse battery staple",
             "correct horse battery staple"])
with contextlib.redirect_stdout(_buf):
    DB.new_passphrase(lambda p: next(_seq))
check("...and the refusal says the number is a FLOOR, not a measure of "
      "strength, because nothing here can tell a dice roll from a memory",
      "not a measure" in _buf.getvalue())


print("\n== the doorbell does not introduce itself ==")
# The wake port is randomised at pairing so one install does not look like the
# next. A Server: header saying "BaseHTTP/0.6 Python/3.11.15" hands that back,
# names the language and the minor version, and DATES the SD image. Date: is
# worse: it is the Pi's wall clock to the second, and this Pi is the only box
# here with a correct clock -- so it is the one worth correlating against a Tor
# circuit or a Bitcoin timestamp.
hb = Bell()
_raw = socket.create_connection(("127.0.0.1", hb.port), timeout=10)
_raw.sendall(b"POST /wake HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
time.sleep(0.4)
_resp = _raw.recv(8192)
_raw.close()
for _tok in (b"Server:", b"Date:", b"Python", b"BaseHTTP"):
    check(f"no {_tok.decode().rstrip(':')} in the response", _tok not in _resp)
check("...and it still answers, so this is not a broken server passing by "
      "saying nothing", _resp.startswith(b"HTTP/1.1 400"))
check("every response closes the connection: HTTP/1.1 keep-alive would let a "
      "client hold the socket for the whole window by not sending anything",
      b"Connection: close" in _resp)

# ANY LAN HOST CAN OPEN A CONNECTION AND SEND NOTHING. ThreadingHTTPServer
# starts a thread per connection, on a Pi with 1 GB of RAM and Tor resident,
# and the window is ten minutes long.
_t0 = time.monotonic()
_silent = socket.create_connection(("127.0.0.1", hb.port), timeout=90)
_silent.settimeout(90)
try:
    _got = _silent.recv(4096)
    _held = time.monotonic() - _t0
    check(f"a connection that sends nothing is dropped ({int(_held)}s), not "
          f"left holding a thread for the whole wake window",
          _got == b"" and _held < 60)
except socket.timeout:
    check("a connection that sends nothing is dropped, not left holding a "
          "thread for the whole wake window", False)
finally:
    _silent.close()
check("...on a bound that is stated in the handler rather than inherited",
      DB.make_handler(hb.pending).timeout is not None
      and DB.make_handler(hb.pending).timeout <= 60)
hb.close()


print("\n== the doorbell is quiet ==")
check("log_message is overridden to a no-op, so every wake is not timestamped "
      "into the Pi's journal with the vault's address",
      "def log_message" in src and "return" in src)


# ===========================================================================
# THE BANNER SUPPRESSION ONLY COVERED THE PATHS THIS HANDLER WRITES ITSELF.
#
# _reply uses send_response_only, which emits neither Server: nor Date:. But
# anything BaseHTTPRequestHandler rejects BEFORE dispatch -- an unsupported
# method, an over-long request line -- goes through send_error -> send_response
# and got both anyway, plus the stock HTML error page that fingerprints
# http.server as well as the banner did. Measured against the running handler:
#
#   PUT /wake HTTP/1.1  -> 501, Server: , Date: Sat, 22 Aug 2026 05:15:38 GMT
#
# The Pi is the only box here with a correct clock, which is what makes it
# worth correlating against a Tor circuit or a Bitcoin timestamp.
# ===========================================================================
_bb = Bell()
try:
    def _raw(req: bytes) -> str:
        c = socket.create_connection(("127.0.0.1", _bb.port), 10)
        c.sendall(req)
        out = b""
        try:
            while True:
                chunk = c.recv(4096)
                if not chunk:
                    break
                out += chunk
        except OSError:
            pass
        c.close()
        return out.decode("latin1")

    for _name, _req in [
            ("an unsupported method", b"PUT /wake HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("an over-long request line",
             b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")]:
        _resp = _raw(_req)
        _head = _resp.split("\r\n\r\n")[0]
        check(f"{_name} does not leak the Pi's wall clock",
              "Date:" not in _head)
        check(f"{_name} does not leak a Server banner at all",
              "Server:" not in _head)
        check(f"{_name} does not return the stock http.server error page",
              "<title>" not in _resp and "Error response" not in _resp)
finally:
    _bb.close()
check("the error path is overridden in the handler, not left to the default",
      "def send_error" in open(os.path.join(REPO, "gs_doorbell")).read())

# ===========================================================================
# AN M1 WITH NO window FIELD IS AN OLD BUILD, NOT AN INTRUDER.
#
# window_of raises before events.append, so do_POST answered 204 with nothing
# recorded, and the agent printed its no-job line: "that is what a magic packet
# from anyone on the switch looks like". A half-upgraded pair therefore booted
# the vault, powered it off, and sent the operator hunting for an intruder on
# their own LAN. The per-window nonce went in without bumping PAIR_PROTO, so
# this is OUR wire break and it has to name itself.
# ===========================================================================
_wb = Bell()
try:
    import nacl.public as _NPUB
    _tp_sk = _NPUB.PrivateKey(bytes.fromhex(KEY["secret"]))
    _pi_pk = _NPUB.PublicKey(bytes.fromhex(KEY["peer_public"]))
    _eph = _NPUB.PrivateKey.generate()
    # An old build's M1: every field the current one has EXCEPT window.
    _old_m1 = P.seal(_tp_sk, _pi_pk, P.TAG_M1, {
        "eph_pk": _eph.public_key.encode().hex(),
        "challenge": os.urandom(P.CHALLENGE_BYTES).hex(),
    })
    _st, _ = _wb.post("/wake", _old_m1)
    check("an M1 with no window field is still answered 204 (nothing leaks)",
          _st == 204)
    check("...but it is RECORDED as a version mismatch, not silence",
          "m1_no_window_field" in _wb.pending.events)
    check("...and NOT as a stranger's magic packet",
          "m1_stale_window" not in _wb.pending.events)
finally:
    _wb.close()

# ===========================================================================
# THE FETCH WINDOW WAS BEING SPENT WHILE THE VAULT WAS SWITCHED OFF.
#
# Pending.opened is set in __init__, and run_wake constructs the Pending, then
# sleeps a random 0..PRE_WOL_MAX_S (900) before sending the magic packet. So
# the 600 s the vault has to collect its job was already running while the
# vault was still powered down. Driven through the REAL run_wake with an
# injected clock, at HEAD~ (before the fix):
#
#   pre_wol_delay=700 -> status=SOCKET-GONE (ConnectionRefusedError)
#                        fetch_open=False finished=True
#                        outcome=expired_uncollected
#
# The Pi sent the magic packet and then IMMEDIATELY tore down its listener,
# because finished() is `not fetch_open()` while collected_at is None and
# run_wake's loop is `while not pending.finished()`. The vault boots into
# nothing, prints its no-job line -- "that is what a magic packet from anyone
# on the switch looks like" -- and powers off.
#
# Measured: the pre-WOL delay alone closes the window 33.2% of the time, and
# 46.7% once 120 s of real boot is allowed for. OPSEC_SETUP.md section 5 step 3
# already specifies the right order: "waits a random 0-15 min, THEN sends the
# magic packet and holds one job for 10 min".
# ===========================================================================
print("\n== the fetch window starts at the magic packet, not before it ==")
check("Pending can be armed", hasattr(DB.Pending, "arm"))
_ba = Bell()
_ba.t[0] += DB.PRE_WOL_MAX_S           # the whole pre-WOL delay elapses
check("...and without arming, that delay has already closed the window "
      "(this is the defect)", not _ba.pending.fetch_open())
_ba.pending.arm()
check("arming at the magic packet reopens the full window",
      _ba.pending.fetch_open() and not _ba.pending.finished())
check("...and the vault can still collect after a maximum pre-WOL delay",
      _ba.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                               _ba.pending.window))[0] == 200)
_ba.close()
# NON-VACUITY: arming must not make the window infinite.
_bb = Bell()
_bb.pending.arm()
_bb.t[0] += DB.FETCH_WINDOW_S + 1
check("an armed window STILL expires on time, so this is not a window that "
      "never closes",
      not _bb.pending.fetch_open()
      and _bb.pending.outcome() == "expired_uncollected")
_bb.close()
check("run_wake arms it where the packet actually goes out",
      "pending.arm()" in open(os.path.join(REPO, "gs_doorbell")).read())

# ===========================================================================
# THE RESULT WINDOW IGNORED THE VAULT'S JITTER AND ITS PER-STEP BUDGET.
#
# The doorbell waited budget_s for a result. The vault sleeps up to
# VAULT_JITTER_HI_S (1200 s) BEFORE it starts, and _dispatch spends budget_s
# PER STEP (tests/test_wake_agent.py: "the budget is PER STEP, not per job").
# So the true worst case is jitter + len(tools) * budget_s, and EVERY job
# could report into a socket the Pi had already closed:
#
#   job                tools  budget   old window   vault worst case
#   receive_new            1     900          900               2100
#   receive_and_quote      2    1800         1800               4800
#   watch                  1    7200         7200               8400
#
# The operator is then told "collected_no_result" for a job that ran fine.
# ===========================================================================
print("\n== the result window covers the jitter and every step ==")
for _job in P.JOBS:
    _spec = P.JOBS[_job]
    _worst = P.VAULT_JITTER_HI_S + len(_spec["tools"]) * _spec["budget_s"]
    check(f"{_job}: the Pi waits for the vault's true worst case",
          P.result_budget_s(_job) >= _worst)
    check(f"{_job}: ...which is strictly longer than the old budget_s",
          P.result_budget_s(_job) > _spec["budget_s"])
# ...AND DRIVEN ON THE SHORTEST ONE, which is where the defect lived: a job
# whose budget is smaller than the jitter has its window close before the
# vault has started, and the operator is told "collected_no_result" about a
# run that went fine. This was written against receive_new's 900 s; that job
# is gone and swap_status's 300 s is now the tightest margin in the table,
# so the drive follows the smallest budget rather than a job name.
_SHORTEST = min(P.JOBS, key=lambda j: P.JOBS[j]["budget_s"])
check(f"the tightest window in the table is {_SHORTEST}, and it is smaller "
      f"than the jitter that precedes it",
      P.JOBS[_SHORTEST]["budget_s"] < P.VAULT_JITTER_HI_S)
_bc = Bell(_SHORTEST, params={"handle": "A3F1"})
_bc.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                         _bc.pending.window))
_bc.t[0] += P.VAULT_JITTER_HI_S        # the jitter alone, no work done yet
check(f"{_SHORTEST} is STILL open after the maximum jitter — before the fix "
      f"its own budget_s had run out and the vault had not started",
      _bc.pending.result_open() and not _bc.pending.finished())
_bc.t[0] += P.result_budget_s(_SHORTEST)
check("NON-VACUITY: it does still close eventually",
      _bc.pending.finished()
      and _bc.pending.outcome() == "collected_no_result")
_bc.close()
check("the vault reads its jitter from the protocol module, so the two boxes "
      "cannot disagree about it again",
      "proto.VAULT_JITTER_LO_S" in open(os.path.join(REPO,
                                                     "gs_wake_agent")).read())

# ===========================================================================
#  THE WORDS THE CHAT OFFERS, AND WHY THEY MAY LIVE ON THIS CARD
# ===========================================================================
print("\n== the amount ladder is gone, and so is every trace of it ==")
#
# THIS SECTION USED TO TEST --amount-labels: the operator's words for the rungs
# of a ladder of amounts held on the vault, written onto the Pi's card so the
# chat could ask "small / medium / large" instead of "Which slot? Reply 0-7".
# The pairing refused any label that looked like a number, because a decimal on
# this card was the exact value the ladder existed to keep off it.
#
# The ladder is gone -- see gs_wake_proto above _int_range -- so the labels
# name nothing. What is tested now is that the removal was COMPLETE, because a
# half-removed feature is worse than either state: a flag that still parses and
# changes nothing, or a field on a sealed card whose meaning the next person
# has to reconstruct.
_lbl_src = open(os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read()
check("ladder: the pairing no longer writes amount_labels onto the card",
      '"amount_labels": _labels,' not in _lbl_src
      and '"amount_labels"' not in _lbl_src)
check("ladder: ...and the flag is gone rather than accepted and ignored",
      '"--amount-labels"' not in _lbl_src)
check("ladder: ...and the label validator went with it",
      "_label_ok" not in _lbl_src and "len(str(_lb)) > 24" not in _lbl_src)
# ARGPARSE REFUSES IT, which is the behaviour that matters: a pairing script
# that still passes --amount-labels stops, rather than sealing a card whose
# labels nothing will ever read.
_ap = DB.build_cli()
_rejected = False
try:
    _ap.parse_args(["pair", "192.168.1.20", "--amount-labels", "small"])
except SystemExit:
    _rejected = True
check("ladder: a pairing that still passes --amount-labels is refused, not "
      "silently ignored", _rejected)
# NON-VACUITY: the same parser accepts the pairing without that flag, so the
# check above is about the flag and not about a parser that refuses everything.
_accepts = True
try:
    _ap.parse_args(["pair", "192.168.1.20"])
except SystemExit:
    _accepts = False
check("ladder: NON-VACUITY -- the same pairing without the flag still parses",
      _accepts)
# AND THE VAULT SIDE, so the ladder cannot survive on the other card either.
_keys_src = open(os.path.join(REPO, "gs_wake_keys"), encoding="utf-8").read()
check("ladder: gs_wake_keys no longer writes amount_ladder either",
      '"amount_ladder": list(args.amount_ladder),' not in _keys_src
      and "MAX_LADDER" not in _keys_src)


# THE CHALLENGE ECHO IS CHECKED FOR ASCII BEFORE compare_digest, which raises
# TypeError on a non-ASCII str -- an uncaught exception in the request
# handler where a Doorbell is a clean refusal.
_db_src_ch = open(os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read()
check("result: a non-ASCII challenge echo is refused as a Doorbell, not "
      "raised as a TypeError out of compare_digest",
      "not _ch.isascii() or not any(" in _db_src_ch
      and _db_src_ch.index("_ch.isascii()")
      < _db_src_ch.index("hmac.compare_digest(_ch, c.hex())"))

# ===========================================================================
#  THE PI'S HALF OF THE VAULT'S STATE KEY (STAGE7_PLAN.md)
# ===========================================================================
print("\n== the card carries half of the vault's state key ==")
#
# WHY THIS LIVES HERE AND NOT ONLY ON THE VAULT. The vault's disk unlocks
# itself at boot, so nothing the vault keeps can seal the vault's records
# against somebody who takes the vault. The only secret in this system that is
# NOT on that machine is the one on this card -- so the records are sealed
# under two halves, and the doorbell's job is to hand its half over inside M2,
# which is boxed to the vault's per-boot ephemeral key.
#
# What is asserted: the half the doorbell SENDS is the one the vault's own
# reader takes out, it is derived rather than drawn (so it is the same across
# boots and a wiped Pi that still has its card can still open the store), it
# is one-way (a captured M2 is not the card's X25519 secret), and it is
# different on a different card.
_sb = Bell()
_seph, _schal = NP.PrivateKey.generate(), P.new_challenge()
_sst, _sm2 = _sb.post("/wake", m1_for(_seph, _schal, _sb.pending.window))
_sbody = P.open_record(_seph, PI.public_key, _sm2, P.TAG_M2)
check("state: the M2 carries a state_half", _sst == 200
      and "state_half" in _sbody)
check("state: ...and the vault's own reader takes the same bytes out of it, "
      "so the two boxes agree without a second format",
      P.state_half_of(_sbody) == P.derive_state_half(KEY["secret"]))
check("state: ...which is STATE_HALF_BYTES long",
      len(P.state_half_of(_sbody)) == P.STATE_HALF_BYTES)
# ONE-WAY. An M2 is boxed, but the vault opens it in RAM and a bug that logged
# a job body must not have logged the card's long-term secret with it.
check("state: the half is NOT the card's X25519 secret, so an M2 that leaked "
      "does not hand over the pairing",
      _sbody["state_half"] != KEY["secret"]
      and KEY["secret"] not in json.dumps(_sbody))
# DERIVED, NOT DRAWN. A fresh random half per boot would mean the vault could
# never open a store written by an earlier boot -- the whole ledger would be
# unreadable after every power cycle.
_sb2 = Bell()
_seph2, _schal2 = NP.PrivateKey.generate(), P.new_challenge()
_, _sm2b = _sb2.post("/wake", m1_for(_seph2, _schal2, _sb2.pending.window))
_sbody2 = P.open_record(_seph2, PI.public_key, _sm2b, P.TAG_M2)
check("state: a second boot sends the SAME half — it is derived from the "
      "card, not drawn per wake, so yesterday's store still opens",
      P.state_half_of(_sbody2) == P.state_half_of(_sbody))
_sb.close()
_sb2.close()
# A DIFFERENT CARD IS A DIFFERENT HALF, so two installs of this public
# repository do not seal their stores under the same key.
_other = NP.PrivateKey.generate()
check("state: a different card derives a different half",
      P.derive_state_half(_other.encode().hex())
      != P.derive_state_half(KEY["secret"]))

# THE RECOVERY PATH. The Pi is dead, a deposit has to be paid out, the
# operator is standing at the vault: `gs_doorbell state-key` prints the half
# so `gs_wake_agent --unseal-state` can take it. Without this the pair is a
# way to lose money, not a way to keep it private.
_sk_path = _keyfile({**KEY, "role": "pi"}, name="statekey.key")
_sk_out = io.StringIO()
os.environ[DB.PASSPHRASE_ENV] = PW.decode()
try:
    with contextlib.redirect_stdout(_sk_out):
        _sk_rc = DB.main(["state-key", "--key", str(_sk_path)])
finally:
    os.environ.pop(DB.PASSPHRASE_ENV, None)
_sk_txt = _sk_out.getvalue()
check("state-key: it exits clean and prints this card's half",
      _sk_rc == 0 and P.derive_state_half(KEY["secret"]).hex() in _sk_txt)
check("state-key: ...and never the secret it came from",
      KEY["secret"] not in _sk_txt)
check("state-key: ...and names the command that takes it at the vault, so "
      "the half is not a number with no instructions",
      "--unseal-state" in _sk_txt and "gs_wake_agent" in _sk_txt)
check("state-key: ...and says the other half is the vault's, so nobody "
      "reads this as the whole key",
      "vault's own half" in _sk_txt)
check("state-key: ...and warns that a re-pairing orphans the store",
      "re-pairing" in _sk_txt)
check("state-key: ...and names the OTHER hand commands that take the same "
      "half -- sealing the spend secrets is a setup step every sealed box "
      "needs once, and this output named only the recovery one",
      "--seal-secrets" in _sk_txt and "--unseal-key" in _sk_txt
      and "--fee-sweep --unseal-state" in _sk_txt)
# IT IS A SUBCOMMAND OF THE SAME CLI, and it reads a sealed keyfile like every
# other read: no unsealed shortcut for the recovery path.
check("state-key: the subcommand parses with the keyfile default",
      DB.build_cli().parse_args(["state-key"]).key == "/etc/gs_wake_pi.key")
_unsealed = _keyfile({**KEY, "role": "pi"}, name="statekey_open.key",
                     seal=False)
_sk_refused = False
try:
    with contextlib.redirect_stdout(io.StringIO()):
        DB.main(["state-key", "--key", str(_unsealed)])
except SystemExit:
    _sk_refused = True
check("state-key: an UNSEALED card is refused here too — the recovery path "
      "is not a way around the passphrase", _sk_refused)
_sk_half = P.derive_state_half(KEY["secret"]).hex()
check("state-key: the half is printed ONCE, on its own line, and the command "
      "beneath it does not carry it -- pasted onto a command line it would "
      "sit in the vault's shell history, on the disk the seal exists for",
      _sk_txt.count(_sk_half) == 1
      and "--unseal-state \\\n" in _sk_txt
      and "asks for the half" in _sk_txt)


print("\n== the operator's hold: nothing wakes, nothing is handed over ==")
# gs_wake_keys says it plainly: the vault's keyfile is plaintext, so a copy of
# its disk can answer the NEXT wake as the vault -- and M2 carries this card's
# half of the state key. No protocol change closes that; not waking does.
check("hold: the default is the Pi's state directory, which the pager's unit "
      "can write (ReadWritePaths) and where its WorkingDirectory is",
      _HOLD_REAL == "/var/lib/gs/wakes.held"
      and "ReadWritePaths=/var/lib/gs\n" in open(os.path.join(
          REPO, "systemd", "gs-telegram-pager.service.example")).read())
check("hold: the wake CLI takes it, defaulting to the same file",
      DB.build_cli().parse_args(["wake", "--key", "k"]).hold_file
      == P.HOLD_FILE_DEFAULT)
_hd = Path(tempfile.mkdtemp(prefix="gs_holdt_"))
check("hold: absent is not held", not P.wakes_held(str(_hd / "x")))
(_hd / "there").write_text("")
check("hold: present is held", P.wakes_held(str(_hd / "there")))
os.symlink(str(_hd / "nowhere"), str(_hd / "dangling"))
check("hold: a dangling symlink by that name is held -- it is THERE",
      P.wakes_held(str(_hd / "dangling")))
check("hold: FAILS CLOSED -- a path whose existence cannot be told (a "
      "component that is a file) is held, not waved through",
      P.wakes_held(str(_hd / "there" / "wakes.held")))
Path(P.HOLD_FILE_DEFAULT).write_text("")
check("hold: an empty path is the default file, never 'off' -- with the "
      "default there, '' and None both hold",
      P.wakes_held("") is True and P.wakes_held(None) is True)
os.unlink(P.HOLD_FILE_DEFAULT)
check("hold: ...and NON-VACUITY, with it gone neither does",
      P.wakes_held("") is False and P.wakes_held(None) is False)
check("hold: creating it gives a 0600 file naming what held it",
      P.hold_wakes(str(_hd / "made"), "m1_second_ephemeral")
      and (os.stat(_hd / "made").st_mode & 0o777) == 0o600
      and (_hd / "made").read_text() == "m1_second_ephemeral\n")
check("hold: ...and nothing from the caller but [a-z0-9_] reaches the card",
      P.hold_wakes(str(_hd / "made2"), "../x\ny Z")
      and (_hd / "made2").read_text() == "xy\n")
os.symlink(str(_hd / "target"), str(_hd / "linked"))
check("hold: an existing link is not written through -- it already holds, "
      "and its target is never created",
      P.hold_wakes(str(_hd / "linked"), "x")
      and not os.path.lexists(_hd / "target"))
check("hold: a file that cannot be created says so (False), so the report "
      "can tell the operator to hold by hand",
      P.hold_wakes(str(_hd / "no_such_dir" / "wakes.held"), "x") is False)

# ON_M1: THE CHECK THAT MATTERS. Everything before it is a magic packet.
hb = Bell()
Path(hb.hold).write_text("")
_heph, _hchal = NP.PrivateKey.generate(), P.new_challenge()
_hs, _hbody = hb.post("/wake", m1_for(_heph, _hchal, hb.pending.window))
check("hold: an authenticated M1 while held gets 204 and NO note",
      _hs == 204 and _hbody == b"" and hb.pending._issued == {}
      and hb.pending.collected_at is None)
check("hold: ...recorded as m1_held",
      hb.pending.events.count("m1_held") == 1)
os.unlink(hb.hold)
_hs2, _hbody2 = hb.post("/wake", m1_for(_heph, _hchal, hb.pending.window))
hb.close()
check("hold: NON-VACUITY -- the same note, the hold lifted, is handed the job",
      _hs2 == 200 and len(_hbody2) == P.RECORD_LEN
      and hb.pending.collected_at is not None)

# A SECOND BOOT SIGNED AS THE VAULT HOLDS EVERY LATER WAKE.
hs = Bell()
hs.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                        hs.pending.window))
hs.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                        hs.pending.window))
hs.close()
_hsb = io.StringIO()
with contextlib.redirect_stdout(_hsb):
    DB.report(hs.pending)
check("hold: a second authenticated boot CREATES the hold file",
      os.path.exists(hs.hold) and "wakes_held" in hs.pending.events
      and Path(hs.hold).read_text() == "m1_second_ephemeral\n")
check("hold: ...and the report says every later wake is held, and no longer "
      "offers a replay as the comforting reading -- the window nonce ruled "
      "that out, and whichever boot took the job took the half",
      "now HELD" in _hsb.getvalue() and "replayed" not in _hsb.getvalue()
      and "half" in _hsb.getvalue())
hn = Bell(hold=str(_hd / "no_such_dir" / "wakes.held"))
hn.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                        hn.pending.window))
hn.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                        hn.pending.window))
hn.close()
_hnb = io.StringIO()
with contextlib.redirect_stdout(_hnb):
    DB.report(hn.pending)
check("hold: ...and when the file cannot be made, the report says to hold "
      "by hand rather than claiming a hold that is not there",
      "wakes_held" not in hn.pending.events
      and "could NOT be created" in _hnb.getvalue())


# NOTHING IS HANDED OVER BEFORE THE MAGIC PACKET (the review of the hold).
# run_wake binds before its pre-WOL delay and the fetch window was open from
# construction, so for up to a quarter of an hour an M1 signed as the vault
# took the job -- and a hold placed then reported "nothing ran" over a job,
# and a half, already handed over.
_pa = DB.Pending(KEY, "swap_status", {"handle": "A3F1"}, clock=lambda: 0.0,
                 hold_file=str(_hd / "arm_hold"), armed=False)
_pa_eph, _pa_chal = NP.PrivateKey.generate(), P.new_challenge()
try:
    _pa.on_m1(m1_for(_pa_eph, _pa_chal, _pa.window))
    _pa_e = None
except DB.Doorbell as e:
    _pa_e = e
check("arm: an authenticated note before the magic packet is REFUSED and "
      "recorded -- nothing is sealed to it",
      _pa_e is not None and _pa._issued == {} and _pa.collected_at is None
      and "m1_before_wake" in _pa.events)
_pa.arm()
check("arm: NON-VACUITY -- the same note after the packet is handed the job",
      len(_pa.on_m1(m1_for(_pa_eph, _pa_chal, _pa.window))) == P.RECORD_LEN
      and _pa.collected_at is not None)
_pab = io.StringIO()
with contextlib.redirect_stdout(_pab):
    DB._report_events(_pa)
check("arm: ...and the report names it: only something already switched on "
      "can do that", "BEFORE the magic packet" in _pab.getvalue()
      and "hold every wake" in _pab.getvalue())
# ...and run_wake really builds its Pending unarmed: a note posted during
# the pre-WOL delay is refused, one after the packet is taken.
_ra_seen = {}


class _ArmSpy(DB.Pending):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        _ra_seen["p"] = self


#: A clock only the sleeps move: the note below is posted at t=0, with the
#: fetch window open by its own measure -- so the refusal it gets can only
#: be the one this is about. (A clock that ran on by itself closed the
#: window first, and the check passed with the gate removed.)
_ra_t = [0.0]


def _ra_sleep(s):
    _p = _ra_seen.get("p")
    if _p is not None and "during" not in _ra_seen:
        try:
            _p.on_m1(m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                            _p.window))
            _ra_seen["during"] = "taken"
        except DB.Doorbell:
            _ra_seen["during"] = "refused"
        _ra_seen["open"] = _p.fetch_open()
    _ra_t[0] += s


_ra_real = DB.Pending
DB.Pending = _ArmSpy
try:
    with contextlib.redirect_stdout(io.StringIO()):
        DB.run_wake(type("A", (), {"no_jitter": False,
                                   "hold_file": str(_hd / "arm_hold")})(),
                    KEY, "swap_status", {"handle": "A3F1"},
                    server_factory=lambda a, h: _IdleSrv(),
                    sock_factory=lambda: FakeSock(), sleep=_ra_sleep,
                    rng=type("R", (), {"randint": lambda self, a, b: 5})(),
                    clock=lambda: _ra_t[0])
finally:
    DB.Pending = _ra_real
check("arm: run_wake refuses a note that arrives during its pre-WOL delay "
      "-- with its fetch window open, so the refusal is the gate's",
      _ra_seen.get("during") == "refused" and _ra_seen.get("open") is True
      and "m1_before_wake" in _ra_seen["p"].events)
# A HOLD THE DOORBELL COULD NOT WRITE IS SAID, so the pager can hold in
# memory instead of handing the half over again at the next start.
_hf_b = Bell(hold=str(_hd / "no_such_dir2" / "wakes.held"))
_hf_b.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                           _hf_b.pending.window))
_hf_b.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                           _hf_b.pending.window))
_hf_b.close()
check("hold: a hold the doorbell could not write is recorded as hold_failed",
      "hold_failed" in _hf_b.pending.events
      and "wakes_held" not in _hf_b.pending.events)


class _HArgs:
    no_jitter = True

    def __init__(self, hold):
        self.hold_file = hold


# RUN_WAKE: held before it starts -> not even a bind.
_hbind = []
_hpk = []
Path(_hd / "held_rw").write_text("")
try:
    DB.run_wake(_HArgs(str(_hd / "held_rw")), KEY, "swap_status",
                {"handle": "A3F1"},
                server_factory=lambda a, h: (_hbind.append(1), _IdleSrv())[1],
                sock_factory=lambda: (_hpk.append(1), FakeSock())[1])
    _hre = None
except DB.Doorbell as e:
    _hre = e
check("hold: a held box sends NO magic packet and does not even bind",
      _hre is not None and "held" in str(_hre) and _hbind == [] and _hpk == [])


# RUN_WAKE: the hold appears during the pre-WOL delay.
class _HArgsJ(_HArgs):
    no_jitter = False


_hpk2 = []


def _hold_while_waiting(s):
    Path(_hd / "held_late").write_text("")


class _HRng:
    def randint(self, a, b):
        return 5


try:
    with contextlib.redirect_stdout(io.StringIO()):
        DB.run_wake(_HArgsJ(str(_hd / "held_late")), KEY, "swap_status",
                    {"handle": "A3F1"},
                    server_factory=lambda a, h: _IdleSrv(),
                    sock_factory=lambda: (_hpk2.append(1), FakeSock())[1],
                    sleep=_hold_while_waiting, rng=_HRng())
    _hre2 = None
except DB.Doorbell as e:
    _hre2 = e
check("hold: held during the pre-WOL delay -- which can be a quarter of an "
      "hour -- still sends no packet",
      _hre2 is not None and "held" in str(_hre2) and _hpk2 == [])

# RUN_WAKE: the hold appears after the packet, before collection.
_ht = [7000.0]
_hsent = []


class _HSock:
    def setsockopt(self, *a):
        pass

    def sendto(self, pkt, addr):
        _hsent.append(_ht[0])
        return len(pkt)

    def close(self):
        pass


def _hsleep(s):
    _ht[0] += s
    if _ht[0] - 7000.0 >= 30:
        Path(_hd / "held_mid").touch()


with contextlib.redirect_stdout(io.StringIO()):
    _hp3 = DB.run_wake(_HArgs(str(_hd / "held_mid")), KEY, "swap_status",
                       {"handle": "A3F1"},
                       server_factory=lambda a, h: _IdleSrv(),
                       sock_factory=lambda: _HSock(), sleep=_hsleep,
                       clock=lambda: _ht[0])
check("hold: held after the packet and before collection, the wait ENDS -- "
      "no repeated packet, nothing collected",
      len(_hsent) == 1 and _hp3.collected_at is None
      and "held_before_collection" in _hp3.events
      and "wake_resent" not in _hp3.events
      and _ht[0] - 7000.0 < DB.WOL_RESEND_S)
_hrb = io.StringIO()
with contextlib.redirect_stdout(_hrb):
    _hrc = DB.report(_hp3)
check("hold: ...and the report says the hold stopped it, not 'poking again "
      "is safe' -- later is exactly as held",
      _hrc == 1 and "HELD" in _hrb.getvalue()
      and "poking again is safe" not in _hrb.getvalue())

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
