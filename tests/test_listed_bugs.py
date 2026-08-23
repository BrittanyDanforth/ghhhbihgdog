#!/usr/bin/env python3
"""FOUR DEFECTS THAT WERE FOUND, WRITTEN DOWN, AND THEN NOT FIXED.

Each of these was reported to the operator in a list of "real findings" and
then left alone across several commits. This file is the fix landing, and it
is a separate suite because the thing they have in common is not a subsystem
-- it is that a known defect can sit in a repo indefinitely if nothing red
ever points at it.

Every one was REPRODUCED before it was fixed, against the real code, and every
check here has a NON-VACUITY partner: the normal path must still work, or
"nothing happened" would pass as "the bug is gone".

  1. post_record FOLLOWED HTTP REDIRECTS. urllib installs a redirect handler
     by default and this call carries no proxy, so a doorbell answering 302
     sent the vault off to any host it named -- off the LAN entirely, outside
     the Mullvad-then-Tor path §4 exists to enforce.

     STATED PRECISELY, because the first description of this overstated it:
     urllib turns a redirected POST into a GET, so the RECORD IS NOT RE-SENT
     (the second server sees a zero-length request), and the record is a
     sealed box besides. What leaks is the CONTACT -- a machine designed to be
     off, unreachable and to speak to one peer on the LAN reaching out to an
     address a third party chose. And /window's answer is trusted as a wake
     window, which a redirected fetch would let someone else supply.

  2. --dry-run RAN THE REAL JOB. It sent a real M1, the doorbell handed the
     job over -- consuming its at-most-once handover -- and the agent ran
     create_receive_wallet and thor_swap_preparer, minting a wallet and
     quoting a live swap. Its own --help said "do everything except run a job
     and power off", and OPSEC_SETUP tells the operator to use it to confirm
     the pairing. The one command described as safe was the one that spent a
     wake and a job.

  3. THE INHIBIT FILE WAS READ ONCE, AT PREFLIGHT. It means "a person is using
     this machine", and the moment a person reaches for it is the moment they
     walk up to a running vault -- mid-job. Read once, the case it was written
     for was the one it could not see: the job ran to completion and powered
     the box off under them.

  4. THE DOORBELL HAD NO CAP ON CONCURRENT CONNECTIONS. ThreadingHTTPServer
     starts a thread per connection; the 20 s socket timeout bounds how LONG
     each lives and says nothing about how MANY, on a 1 GB Pi with Tor
     resident.
"""
import contextlib
import http.server
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
import types
from pathlib import Path

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
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(ld.name, ld)
    mod = importlib.util.module_from_spec(spec)
    ld.exec_module(mod)
    return mod


import gs_wake_proto as P                                    # noqa: E402
from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILURES),
                                 "test_listed_bugs")

DB = load("gs_doorbell")
sys.modules["gs_doorbell"] = DB
A = load("gs_wake_agent")
import nacl.public as NP                                     # noqa: E402

TP, PI = NP.PrivateKey.generate(), NP.PrivateKey.generate()


def _port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ===========================================================================
# 1. THE VAULT TALKS TO THE DOORBELL AND TO NOTHING ELSE.
# ===========================================================================
print("\n-- a doorbell cannot redirect the vault to another host --")
HITS = []
SINK_PORT = _port()


class _Redirector(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        HITS.append("redirector")
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.1:{SINK_PORT}/stolen")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _Sink(http.server.BaseHTTPRequestHandler):
    # BOTH VERBS. urllib rewrites a redirected POST into a GET, so a sink that
    # only answers POST records nothing and the check passes for the wrong
    # reason -- which is exactly what happened: the anchor for this SURVIVED
    # against a sink with no do_GET, while the redirect was being followed.
    def _hit(self):
        try:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
        except Exception:                                    # noqa: BLE001
            pass
        HITS.append("SINK")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = _hit
    do_GET = _hit

    def log_message(self, *a):
        pass


_RED_PORT = _port()
_SERVERS = []
for _cls, _p in ((_Redirector, _RED_PORT), (_Sink, SINK_PORT)):
    _s = http.server.HTTPServer(("127.0.0.1", _p), _cls)
    _SERVERS.append(_s)
    threading.Thread(target=_s.serve_forever, daemon=True).start()

_st, _ = A.post_record(f"http://127.0.0.1:{_RED_PORT}", "/result", b"X" * 100)
check("the redirector really did see the record, so the fixture works",
      "redirector" in HITS)
check("the vault NEVER contacted the host the redirect named, by any verb",
      "SINK" not in HITS)
check("...and the caller is told a non-200, which it already reads as "
      "'unreachable' and retries the whole wake for", _st != 200)

HITS.clear()
_st2, _ = A.post_record(f"http://127.0.0.1:{SINK_PORT}", "/result", b"Y" * 50)
check("NON-VACUITY: an ordinary POST to an ordinary server still succeeds",
      _st2 == 200 and HITS == ["SINK"])

# ===========================================================================
# 2. --dry-run CANNOT SPEND A JOB.
# ===========================================================================
print("\n-- --dry-run collects nothing and runs nothing --")


def _env():
    d = Path(tempfile.mkdtemp(prefix="dryrun_"))
    key = {"schema": "gs_wake_v1", "version": 1, "role": "thinkpad",
           "secret": TP.encode().hex(),
           "peer_public": PI.public_key.encode().hex(),
           "doorbell_url": "http://10.0.0.9:8770",
           "tor_proxy": "socks5h://127.0.0.1:9050",
           "rpc_primary": "http://127.0.0.1:18083",
           "artifact_dir": str(d), "amount_ladder": ["0.01", "0.05"],
           "account_ceiling": 45}
    kf = d / "tp.key"
    kf.write_text(json.dumps(P.lock_keyfile(key, b"", role="thinkpad")))
    os.chmod(kf, 0o400)
    bell = DB.Pending({"secret": PI.encode().hex(),
                       "peer_public": TP.public_key.encode().hex()},
                      "receive_and_quote", {"amount_slot": 1},
                      clock=lambda: 0.0)
    return d, kf, bell


def _run(dry):
    d, kf, bell = _env()
    ran = []

    def post(url, path, rec, timeout=30):
        if path == "/window":
            return 200, bell.window
        if path == "/wake":
            try:
                return 200, bell.on_m1(rec)
            except Exception:                                # noqa: BLE001
                return 204, b""
        try:
            bell.on_m3(rec)
            return 200, b""
        except Exception:                                    # noqa: BLE001
            return 204, b""

    def child(argv, env_extra, budget):
        ran.append(os.path.basename(argv[1]))
        if "create_receive_wallet" in " ".join(argv):
            (d / "wallet_recv_1.json").write_text("{}")
        return 0, False

    deps = dict(post_record=post, sleep=lambda s: None, clock=lambda: 0.0,
                rng=types.SimpleNamespace(randint=lambda a, b: a),
                run_child=child, verify_tor=lambda: None,
                account_count=lambda: 3, unit_is_active=lambda u: True,
                removable_devices=lambda: [], resource_check=lambda *a: True,
                tor_bootstrapped=lambda u: True, wipe_covers=lambda p: True)
    buf = io.StringIO()
    err = None
    with contextlib.redirect_stdout(buf):
        try:
            A.run_once(types.SimpleNamespace(key=str(kf), dry_run=dry), deps)
        except A.Refused as e:
            err = e
    return ran, bell, err, buf.getvalue()


_ran, _bell, _err, _text = _run(dry=True)
check("--dry-run runs no tool at all", _ran == [])
check("...and does NOT consume the doorbell's at-most-once handover -- there "
      "is no way to ask whether a job is waiting without taking it",
      "job_collected" not in _bell.events)
check("...and does not power the machine off",
      _err is not None and _err.code == "dry_run" and not _err.power)
check("...and reports what it DID check", "doorbell" in _text.lower())
check("...and says out loud what it did NOT prove, rather than letting the "
      "operator infer the keyfiles are a matched pair", "NOT proven" in _text)
_help = A.build_cli().format_help()
check("the --help no longer claims 'everything except run a job', which it "
      "used to say while doing exactly that", "except run a job" not in _help)
check("...and does say that asking would take the job",
      "at-most-once" in _help or "takes the job" in _help)

_ran2, _bell2, _err2, _ = _run(dry=False)
check("NON-VACUITY: a real run still collects the job and runs both tools",
      _ran2 == ["create_receive_wallet", "thor_swap_preparer"]
      and "job_collected" in _bell2.events)

# ===========================================================================
# 3. SOMEBODY SITTING DOWN MID-JOB IS SEEN.
# ===========================================================================
print("\n-- the inhibit file is re-read between steps --")
_k3 = {"tor_proxy": "socks5h://127.0.0.1:9050",
       "rpc_primary": "http://127.0.0.1:18083",
       "amount_ladder": ["0.01", "0.05"]}


def _dispatch_with(child, d):
    (d / A.HANDLES_FILE).write_text("{}")
    buf = io.StringIO()
    caught = None
    out = None
    with contextlib.redirect_stdout(buf):
        try:
            out = A._dispatch("receive_and_quote", {"amount_slot": 1}, _k3, d,
                              "ZZZZ", child, "j" * 24)
        except A.Refused as e:
            caught = e
    return out, caught, buf.getvalue()


_d3 = Path(tempfile.mkdtemp(prefix="inhibit_"))
_seen = []


def _sits_down(argv, env_extra, budget):
    _seen.append(os.path.basename(argv[1]))
    (_d3 / A.INHIBIT_FILE).touch()          # an operator walks up, mid-job
    (_d3 / "wallet_recv_1.json").write_text("{}")
    return 0, False


_out, _caught, _txt = _dispatch_with(_sits_down, _d3)
check("an inhibit file appearing MID-JOB stops the job",
      _caught is not None and _caught.code == "inhibited")
check("...and the machine is NOT powered off under the person who created it",
      _caught is not None and not _caught.power)
check("...the tool already running was allowed to finish; the NEXT one never "
      "started, because killing a tool halfway leaves a quote nobody knows "
      "about", _seen == ["create_receive_wallet"])
check("...and the refusal names the file, so the operator knows what to "
      "remove", _caught is not None and A.INHIBIT_FILE in _caught.msg)

_d3b = Path(tempfile.mkdtemp(prefix="noinhibit_"))
_seen2 = []


def _plain(argv, env_extra, budget):
    _seen2.append(os.path.basename(argv[1]))
    if "create_receive_wallet" in " ".join(argv):
        (_d3b / "wallet_recv_1.json").write_text("{}")
    return 0, False


_out2, _caught2, _ = _dispatch_with(_plain, _d3b)
check("NON-VACUITY: with no inhibit file both steps run and the job finishes",
      _caught2 is None and len(_seen2) == 2)

# THE PREFLIGHT COPY IS STILL THERE. Two checks, and the second does not
# replace the first: preflight catches the operator who was already present
# before the wake, this one catches the one who arrives during it.
_src = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("preflight still checks it too -- the mid-job check is a SECOND place, "
      "not a move", _src.split("def preflight")[1]
      .split("\ndef ")[0].count("INHIBIT_FILE") >= 1)

# ===========================================================================
# 4. THE DOORBELL'S THREAD COUNT IS BOUNDED.
# ===========================================================================
print("\n-- concurrent connections are capped on a 1 GB box --")
_KEY = {"role": "pi", "secret": PI.encode().hex(),
        "peer_public": TP.public_key.encode().hex(),
        "listen_host": "127.0.0.1", "listen_port": 0,
        "target_mac": "aa:bb:cc:dd:ee:ff", "wol_broadcast": "255.255.255.255",
        "wol_port": 9}
_pend = DB.Pending(_KEY, "receive_and_quote", {"amount_slot": 1})
_dport = _port()
_srv = DB.BoundedHTTPServer(("127.0.0.1", _dport), DB.make_handler(_pend))
threading.Thread(target=_srv.serve_forever, daemon=True).start()
time.sleep(0.2)
_base = threading.active_count()

# A REAL SLOWLORIS, and the Content-Length matters. An arbitrary length is
# rejected instantly by the doorbell's own length gate and holds nothing --
# the first version of this test used 4000 and proved nothing, showing zero
# refusals against a working cap. RECORD_LEN passes that gate, so the handler
# blocks reading a body that never comes.
_held = []
for _i in range(DB.MAX_CONNECTIONS + 10):
    try:
        _c = socket.create_connection(("127.0.0.1", _dport), timeout=3)
        _c.sendall(b"POST /result HTTP/1.1\r\nHost: x\r\nContent-Length: %d"
                   b"\r\n\r\nA" % P.RECORD_LEN)
        _held.append(_c)
        time.sleep(0.08)
    except OSError:
        break
time.sleep(1.0)
_live, _refused = _srv._live, _srv.refused_connections
_extra = threading.active_count() - _base
print(f"       opened {len(_held)}, live {_live}, refused {_refused}, "
      f"threads +{_extra}, cap {DB.MAX_CONNECTIONS}")
check("connections past the cap are refused rather than given a thread",
      _refused > 0)
check(f"...and the live count never exceeds MAX_CONNECTIONS "
      f"({DB.MAX_CONNECTIONS})", _live <= DB.MAX_CONNECTIONS)
check("...so the thread count is bounded by the cap, not by the flood",
      _extra <= DB.MAX_CONNECTIONS + 2)

for _c in _held:
    try:
        _c.close()
    except OSError:
        pass
time.sleep(0.8)

# THE CAP MUST RELEASE. A counter that only goes up is a doorbell that stops
# answering after one flood -- which is a worse outcome than the flood, since
# the vault would then never collect a job again.
_after = 0
for _ in range(20):
    try:
        _c = socket.create_connection(("127.0.0.1", _dport), timeout=3)
        _c.sendall(b"POST /nope HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        _c.recv(64)
        _c.close()
        _after += 1
    except OSError:
        break
check("NON-VACUITY: after the flood, 20 ordinary requests are all served -- "
      "the cap releases slots and does not ratchet shut", _after == 20)
check("...and the live count is back to zero", _srv._live == 0)
_srv.shutdown()
for _s in _SERVERS:
    _s.shutdown()

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
