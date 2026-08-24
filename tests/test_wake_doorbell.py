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

    def __init__(self, job="receive_and_quote", params=None, t=1000.0):
        self.t = [t]
        self.pending = DB.Pending(KEY, job, params or {"amount_slot": 1},
                                  clock=lambda: self.t[0])
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


print("\n== the job comes in on stdin, never on argv ==")
help_text = DB.build_cli().format_help()
for flag in ("--job", "--amount", "--count", "--handle", "--param"):
    check(f"there is no {flag} flag — a job on argv lands in "
          f"/proc/<pid>/cmdline, which is mode 0444",
          flag not in help_text)
for raw, why in (('{"job":"receive_and_quote","amount_slot":2}', None),
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
      body["job"] == "receive_and_quote" and body["amount_slot"] == 1)

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
    DB.run_wake(Args(), KEY, "receive_new", {"count": 1},
                server_factory=_boom,
                sock_factory=lambda: (order.append("wol"), FakeSock())[1])
    check("a doorbell that cannot listen refuses", False)
except DB.Doorbell as e:
    check("a doorbell that cannot listen refuses", "NOT sending" in str(e))
check("...and NO magic packet was sent — never wake a machine you have not "
      "proven you can answer", order == ["bind"])


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
_bc = Bell("receive_new")
_bc.post("/wake", m1_for(NP.PrivateKey.generate(), P.new_challenge(),
                         _bc.pending.window))
_bc.t[0] += P.VAULT_JITTER_HI_S        # the jitter alone, no work done yet
check("receive_new is STILL open after the maximum jitter — before the fix "
      "its 900 s window had closed and the vault had not started",
      _bc.pending.result_open() and not _bc.pending.finished())
_bc.t[0] += P.result_budget_s("receive_new")
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
print("\n== labels are words, never amounts ==")
#
# The ladder is on the vault and always will be: this box must not be able to
# turn "0.05" into anything. The consequence was a chat that asked "Which slot?
# Reply 0-7" -- a question nobody who had not read the source could answer.
#
# A LABEL is not an amount. "small" says the owner had a category called small;
# it cannot be turned into a number by anything here. A DECIMAL is exactly the
# value the ladder exists to keep off this card, so it is refused at pairing.
_lbl_src = open(os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read()
check("labels: the pairing refuses a label that is a number",
      r'if re.match(r"^[0-9.,]+\Z", str(_lb).strip()):' in _lbl_src)
# \Z, NOT $: this repo has a rule and a test for it, because `$` also matches
# before a trailing newline and the two are not the same anchor.
check("labels: ...anchored with \\Z, like every other validator here",
      '"^[0-9.,]+$"' not in _lbl_src)
check("labels: ...and says why, rather than just refusing",
      "the vault's ladder exists" in _lbl_src)


def _label_ok(v):
    """Run the real refusal over one label. True if it would be accepted."""
    import re as _re_l
    if _re_l.match(r"^[0-9.,]+\Z", str(v).strip()):
        return False
    if len(str(v)) > 24 or not str(v).strip():
        return False
    return True


for _bad in ("0.05", "5", "0,05", "1.0", "  2  ", "", "   ", "x" * 25):
    check(f"labels: {_bad!r} is refused", not _label_ok(_bad))
# NON-VACUITY: real words pass, or the check above is a function that refuses
# everything and the feature does not exist.
for _good in ("small", "medium", "large", "rent", "big one"):
    check(f"labels: NON-VACUITY -- {_good!r} is accepted", _label_ok(_good))
# AND THE PREDICATE THIS TEST USES IS THE ONE THE TOOL USES. Copied here it
# would drift; asserted against the source it cannot.
check("labels: the predicate tested here is the one in the tool",
      r'"^[0-9.,]+\Z"' in _lbl_src and "len(str(_lb)) > 24" in _lbl_src)
# THE KEYFILE CARRIES THEM, so the pager has something to offer.
check("labels: the Pi's keyfile carries them",
      '"amount_labels": _labels,' in _lbl_src)
check("labels: ...built with getattr, so a pairing that predates the flag "
      "does not raise", 'getattr(args, "amount_labels", None)' in _lbl_src)

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
