#!/usr/bin/env python3
"""SIX DEFECTS THAT WERE FOUND, WRITTEN DOWN, AND THEN NOT FIXED.

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

  5. THE FAN-OUT FLOOR RESERVED THE HOP AND NOT THE EXIT SWEEP. An output is
     spent twice -- the DAG round sweeps it to its neighbour, the exit sweeps
     that subaddress to the operator -- and min_hop_fundable reserved one fee.
     An output on the floor cleared every planning gate, hopped, and then sat
     below the cost of moving it: over 200 seeded draws at 0.2 XMR with the
     default --wallets 10, the median plan left ALL TEN unwithdrawable (range
     7-10, and not one draw came back empty). At 1 XMR / --wallets 60 it is 28
     of 60. With --dag-mixing off the floor was DUST_XMR * 2 and
     reserved nothing at all -- and "disable --dag-mixing" is one of the three
     remedies main() prints when the floor cannot be funded.

  6. --expect-xmr THREW AWAY THE PER-CHUNK BREAKDOWN. swap_arrival_floor keys
     the arrival gate on the SMALLEST chunk; with no breakdown it assumes EQUAL
     chunks, which is the assumption its own docstring names as the one the
     JoinMarket path breaks. --expect-xmr's --help says it overrides "the total
     from --pairs" -- the total, not the pairs -- and it discarded the pairs,
     so on 0.50/0.30/0.15/0.05 the gate dropped from 0.950000000001 to 0.9 and
     reported PAID with a whole swap missing. It also printed "(--expect-xmr
     without --pairs)" on a run that passed --pairs.
"""
import ast
import contextlib
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import socket
import sys
import tokenize
import tempfile
import threading
import time
import types
from decimal import Decimal, InvalidOperation
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


# ===========================================================================
#  CORE-DUMP PROBES RUN FIRST, AND THEY HAVE TO
# ===========================================================================
#
# gs_common suppresses core dumps at import with setrlimit(RLIMIT_CORE, (0,0)),
# which lowers the HARD limit -- and a lowered hard limit cannot be raised
# again by anyone, root included (measured: `ValueError: not allowed to raise
# maximum limit` as uid 0). It is inherited by every descendant.
#
# So the instant this file loads gs_doorbell or gs_wake_agent below, this
# process and every subprocess it will ever spawn are pinned at 0, and a probe
# can no longer observe a child STARTING with dumps enabled. The first version
# of these checks ran after those loads and their non-vacuity partners went red
# for exactly that reason -- the fixture could not reach the state it was
# asserting about.
#
# Running them here, before the first gs_common-importing load, is not tidiness:
# it is the only point in this file where the observation is still possible.
_CORE_PROBE_SRC = r"""
import importlib.machinery, importlib.util, contextlib, io, os, resource, signal, sys
REPO = "@REPO@"
sys.path.insert(0, REPO)
os.environ["GS_WALLET_PASSWORD"] = "spend-key-password"
def core():
    return resource.getrlimit(resource.RLIMIT_CORE)[0]
def load(n):
    ld = importlib.machinery.SourceFileLoader(n, os.path.join(REPO, n))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m
which = sys.argv[1]
before = core()
m = load(which)
imported = core()
with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
    try:
        if which == "gs_console":
            sys.argv = [which, "--not-a-real-flag"]; m.main()
        else:
            m.main(["--not-a-real-flag"])
    except SystemExit:
        pass
after = core()
try:
    os.kill(os.getpid(), signal.SIGINT); ctrlc = "BROKEN"
except KeyboardInterrupt:
    ctrlc = "works"
print("%s %s %s %s" % (before, imported, after, ctrlc))
""".replace("@REPO@", REPO)

_IMPORT_PROBE_SRC = r"""
import builtins, importlib.machinery, importlib.util, os, resource, sys
REPO = "@REPO@"
sys.path.insert(0, REPO)
RISKY = {"nacl", "requests", "tenacity", "monero", "psutil", "stem", "gs_wake_proto"}
seen = {}
_real = builtins.__import__
def spy(name, *a, **k):
    t = name.split(".")[0]
    if t in RISKY and t not in seen:
        seen[t] = resource.getrlimit(resource.RLIMIT_CORE)[0]
    return _real(name, *a, **k)
builtins.__import__ = spy
tool = sys.argv[1]
ld = importlib.machinery.SourceFileLoader(tool, os.path.join(REPO, tool))
m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
ld.exec_module(m)
builtins.__import__ = _real
bad = sorted(k for k, v in seen.items() if v != 0)
print("|".join(bad) + "#" + str(len(seen)))
""".replace("@REPO@", REPO)

import subprocess                                            # noqa: E402


def _run_probe(src, tool):
    with tempfile.TemporaryDirectory() as _t:
        _p = os.path.join(_t, "probe.py")
        open(_p, "w").write(src)
        r = subprocess.run(
            ["bash", "-c",
             "ulimit -c unlimited; GS_WAKE_PASSPHRASE=x exec "
             + sys.executable + " " + _p + " " + tool],
            capture_output=True, text=True, timeout=180, cwd=_t)
    out = (r.stdout or "").strip().splitlines()
    return out[-1] if out else ""


CORE_RESULTS = {t: _run_probe(_CORE_PROBE_SRC, t).split()
                for t in ("gs_doorbell", "gs_console")}
IMPORT_RESULTS = {}
for _t in ("gs_console", "gs_doorbell", "GhostSpiral", "airgap_tx_signer",
           "receive_watch", "thor_swap_preparer"):
    _line = _run_probe(_IMPORT_PROBE_SRC, _t)
    if "#" in _line:
        _b, _n = _line.rsplit("#", 1)
        IMPORT_RESULTS[_t] = ([x for x in _b.split("|") if x], int(_n))
    else:
        IMPORT_RESULTS[_t] = (None, None)


import gs_wake_proto as P                                    # noqa: E402
# ONE ALIAS FOR gs_common, IMPORTED UNCONDITIONALLY.
#
# There were four -- C, GSC, GSC, GSC -- all naming the same cached
# module object, and one of them (GSC) was bound INSIDE `if _CAN_DROP:`,
# i.e. only when this suite runs as root. Section 13 then used it
# unconditionally, so on any non-root runner the whole file died with
# NameError before reaching a third of its checks. A suite that silently
# requires root is a suite most people cannot run, and four names for one
# import is how the conditional one went unnoticed.
import gs_common as GSC                                      # noqa: E402
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
                      "receive_and_quote", {"amount_sat": 5000000},
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
            out = A._dispatch("receive_and_quote", {"amount_sat": 5000000}, _k3, d,
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
_pend = DB.Pending(_KEY, "receive_and_quote", {"amount_sat": 5000000})
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
# POLLED, NOT SAMPLED. This was a bare `_srv._live == 0` taken the instant the
# last client socket closed -- and the decrement happens in the SERVER's
# handler thread, in close_request, after that thread returns from handle().
# The client closing first is not the server having finished, so on a loaded
# box the last thread had not run its decrement yet and this went red against
# a doorbell that was working perfectly. Observed once, under the load of
# nine parallel agents.
#
# A test that cries wolf under load is worse than no test: the next red is
# assumed to be this one. The GUARANTEE is "the cap releases", which is a
# statement about eventually, so the check is now bounded-eventually. Two
# seconds is ~2000x the observed decrement latency and still fails fast if the
# counter genuinely ratchets shut.
_deadline = time.time() + 2.0
while _srv._live != 0 and time.time() < _deadline:
    time.sleep(0.01)
check("...and the live count comes back to zero", _srv._live == 0)
_srv.shutdown()
for _s in _SERVERS:
    _s.shutdown()


# ===========================================================================
#  5. THE FAN-OUT FLOOR RESERVED THE HOP AND NOT THE EXIT SWEEP
# ===========================================================================
#
# A fan-out output is spent TWICE before the operator sees it: the DAG round
# sweeps it to its neighbour, and _run_exit_withdrawals issues one sweep_all
# per funded subaddress to the destination. Both pay a fee. min_hop_fundable
# reserves ONE, so an output on the floor cleared every planning gate, hopped,
# and then sat below the cost of moving it.
#
# It is not recoverable afterwards either. Each output has its own subaddress
# and this pipeline REFUSES to sweep two together -- that is permanent public
# proof of common ownership -- so the one spend that would rescue the dust is
# the one the whole run exists to prevent.
#
# Every number below comes from driving the shipped functions, and the
# NON-VACUITY partners are the ones that matter: an over-refusing floor would
# make "no unwithdrawable output" true by emitting no plans at all.
G = load("GhostSpiral")
_D = __import__("decimal").Decimal
import random as _r5                                         # noqa: E402

_f5 = _D("0.0024")

# The exit's OWN rule, not a restatement of it: _run_exit_withdrawals reads
# meta["fee_per_round"], which _stage4 writes as str(hop_fee_reserve(fee_xmr)),
# and drops every target whose balance is <= that.
_exit_floor = G.hop_fee_reserve(_f5)
check("exit floor: the meta field the exit filters on is hop_fee_reserve",
      '"fee_per_round": str(hop_fee_reserve(fee_xmr)),'
      in Path(os.path.join(REPO, "GhostSpiral")).read_text()
      and "_dust = [t for t in targets if t[2] <= _floor]"
      in Path(os.path.join(REPO, "GhostSpiral")).read_text())

# THE BUG, stated as the old floor and driven through the real hop formula.
_old_floor = G.min_hop_fundable(_f5)
check("exit floor: REPRODUCED -- an output on the OLD floor hops fine...",
      G.hop_is_fundable(_old_floor, _f5))
check("...and what survives that hop is below the exit's own dust threshold, "
      f"so it is never withdrawn ({G.compute_hop_amount(_old_floor, _f5)} "
      f"<= {_exit_floor})",
      G.compute_hop_amount(_old_floor, _f5) <= _exit_floor)

# THE FIX. The new floor clears it, and is MINIMAL -- one tick less does not,
# so the guarantee is not bought with an arbitrary safety pad.
_new_floor = G.min_exit_fundable(_f5, True)
check("exit floor: the new floor funds the hop AND the exit sweep",
      G.exit_is_fundable(_new_floor, _f5, True))
check("exit floor: ...and is MINIMAL -- one tick less cannot",
      not G.exit_is_fundable(_new_floor - G.DUST_XMR, _f5, True))
check("exit floor: it never drops below the hop floor build_dag_plan gates on",
      _new_floor >= _old_floor and G.hop_is_fundable(_new_floor, _f5))

# --dag-mixing OFF reserved NOTHING for the exit: the branch was DUST_XMR * 2,
# 0.0002 XMR against a 0.0036 sweep. That branch is where main() SENDS an
# operator whose fan-out was refused ("disable --dag-mixing"), so the remedy
# for "these outputs are too small" pointed at the setting with no floor.
check("exit floor: REPRODUCED -- the old DAG-OFF floor was below the exit's "
      "own dust threshold, so every output on it was unwithdrawable",
      (G.DUST_XMR * 2) <= _exit_floor)
check("exit floor: the DAG-off floor now clears the exit sweep",
      G.exit_is_fundable(G.min_exit_fundable(_f5, False), _f5, False))
check("exit floor: ...and is minimal there too",
      not G.exit_is_fundable(G.min_exit_fundable(_f5, False) - G.DUST_XMR,
                             _f5, False))

# END TO END, through compute_fee_budget -> compute_fanout_amounts ->
# compute_hop_amount -> the exit's filter, over settings the CLI accepts.
_bad = _plans = _outs = 0
for _b5 in ("0.2", "0.3", "0.5", "0.8", "1", "2", "5", "20"):
    for _w5 in (4, 10, 20, 40, 60):
        for _dag5 in (True, False):
            _u5 = G.compute_fee_budget(_D(_b5), _f5, _w5, peel=False,
                                       dag_mixing=_dag5, exit_set=True)[0]
            if _u5 <= G.DUST_XMR:
                continue
            for _s5 in range(6):
                _a5 = G.compute_fanout_amounts(_u5, _w5, _f5, _dag5,
                                               rng=_r5.Random(_s5))
                if not _a5:
                    continue
                _plans += 1
                _outs += len(_a5)
                for _x5 in _a5:
                    _held = (G.compute_hop_amount(_x5, _f5) if _dag5 else _x5)
                    if _held <= _exit_floor:
                        _bad += 1
check(f"exit floor: no plan the planner emits contains an output the exit "
      f"cannot withdraw ({_bad} of {_outs} outputs across {_plans} plans)",
      _bad == 0)
# NON-VACUITY, and this is the check that makes the one above mean something:
# a floor so high it refused everything would also score 0.
check(f"NON-VACUITY: the planner still emits plans at all ({_plans} of them, "
      f"{_outs} outputs)", _plans > 100 and _outs > 1000)

# NON-VACUITY the other way: put the OLD floor back and the same sweep must
# find the defect, or the sweep above is not looking where the bug lived.
_saved_min = G.min_exit_fundable
G.min_exit_fundable = lambda fee_xmr, dag: (
    G.min_hop_fundable(fee_xmr) if dag
    else (G.DUST_XMR * 2).quantize(G.DUST_XMR, rounding=G.ROUND_UP))
_oldbad = _oldplans = 0
for _b5 in ("0.2", "0.3", "0.5", "0.8", "1", "2", "5", "20"):
    for _w5 in (4, 10, 20, 40, 60):
        for _dag5 in (True, False):
            _u5 = G.compute_fee_budget(_D(_b5), _f5, _w5, peel=False,
                                       dag_mixing=_dag5, exit_set=True)[0]
            if _u5 <= G.DUST_XMR:
                continue
            for _s5 in range(6):
                _a5 = G.compute_fanout_amounts(_u5, _w5, _f5, _dag5,
                                               rng=_r5.Random(_s5))
                if not _a5:
                    continue
                _oldplans += 1
                for _x5 in _a5:
                    _held = (G.compute_hop_amount(_x5, _f5) if _dag5 else _x5)
                    if _held <= _exit_floor:
                        _oldbad += 1
G.min_exit_fundable = _saved_min
check(f"NON-VACUITY: with the OLD floor restored the SAME sweep finds the "
      f"defect ({_oldbad} unwithdrawable outputs across {_oldplans} plans)",
      _oldbad > 500)

# The refusals this costs are exactly the plans that were broken -- measured,
# not asserted. A floor that refused a WORKING plan would be a regression.
_lost = _lostbad = 0
for _b5 in range(2, 101):
    _bal5 = _D(_b5) * _D("0.1")
    for _w5 in (4, 6, 10, 12, 20, 30, 40, 60):
        for _dag5 in (True, False):
            _u5 = G.compute_fee_budget(_bal5, _f5, _w5, peel=False,
                                       dag_mixing=_dag5, exit_set=True)[0]
            if _u5 <= G.DUST_XMR:
                continue
            _bud5 = _u5 * G.FANOUT_SPEND_FRACTION
            _om = G.min_hop_fundable(_f5) if _dag5 else G.DUST_XMR * 2
            if _bud5 >= _om * _w5 and _bud5 < G.min_exit_fundable(_f5, _dag5) * _w5:
                _lost += 1
                _oheld = G.compute_hop_amount(_om, _f5) if _dag5 else _om
                if _oheld <= _exit_floor:
                    _lostbad += 1
check(f"exit floor: every setting the new floor refuses ({_lost}) is one whose "
      f"old plan had an unwithdrawable floor output ({_lostbad})",
      _lost > 0 and _lost == _lostbad)

# ...and the refusal message's three remedies all actually work on the setting
# it refuses. "disable --dag-mixing" is one of them, which is why the DAG-off
# branch had to be fixed too.
_rem = {}
for _lbl, _b5, _w5, _dag5 in (("fewer wallets", "0.2", 4, True),
                              ("no dag-mixing", "0.2", 10, False),
                              ("more funds", "0.3", 10, True)):
    _u5 = G.compute_fee_budget(_D(_b5), _f5, _w5, peel=False,
                               dag_mixing=_dag5, exit_set=True)[0]
    _a5 = G.compute_fanout_amounts(_u5, _w5, _f5, _dag5, rng=_r5.Random(5))
    _rem[_lbl] = bool(_a5) and not any(
        (G.compute_hop_amount(_x, _f5) if _dag5 else _x) <= _exit_floor
        for _x in _a5)
check("exit floor: the refused setting's own remedies all produce a plan with "
      f"no unwithdrawable output ({_rem})", all(_rem.values()))
check("exit floor: NON-VACUITY -- the setting they are remedies FOR is "
      "genuinely refused",
      not G.compute_fanout_amounts(
          G.compute_fee_budget(_D("0.2"), _f5, 10, peel=False,
                               dag_mixing=True, exit_set=True)[0],
          10, _f5, True, rng=_r5.Random(5)))

# The stepping loop is sized for QUANTISE DRIFT, and the first version of
# min_exit_fundable was not: it started at min_hop_fundable and stepped, but
# the gap between the two floors is a whole extra fee reserve -- 36 grid ticks
# at this fee -- so it ran out of steps and returned an amount its own
# predicate REJECTS. Driven across the fee range, both branches.
_viol = _worst = 0
for _i5 in range(1, 501):
    _fx = _D(_i5) * _D("0.0001")
    for _dag5 in (True, False):
        _m5 = G.min_exit_fundable(_fx, _dag5)
        if not G.exit_is_fundable(_m5, _fx, _dag5):
            _viol += 1
        if G.exit_is_fundable(_m5 - G.DUST_XMR, _fx, _dag5):
            _viol += 1
        if _m5 < G.min_hop_fundable(_fx):
            _viol += 1
check(f"exit floor: over 500 fees x 2 branches the floor satisfies its own "
      f"predicate, is minimal, and never drops below the hop floor "
      f"({_viol} violations)", _viol == 0)
check("exit floor: REPRODUCED -- the step-from-the-hop-floor version this "
      "replaced runs out of steps and returns a REJECTED amount",
      not G.exit_is_fundable(
          # what that version returned: min_hop_fundable + at most 8 ticks
          G.min_hop_fundable(_D("0.0024")) + G.DUST_XMR * 8, _D("0.0024"), True))


# ===========================================================================
#  6. --expect-xmr THREW AWAY THE PER-CHUNK BREAKDOWN
# ===========================================================================
#
# swap_arrival_floor keys the arrival gate on the SMALLEST chunk, because a
# tolerance charged against the summed total also covers a whole chunk as soon
# as one chunk is worth less than it. Without a breakdown it falls back to
# assuming EQUAL chunks -- the assumption its own docstring names as the one
# the JoinMarket path breaks ("arbitrarily unequal ... 0.50/0.30/0.15/0.05").
#
# --expect-xmr discarded the breakdown, so it walked an operator who passed
# --pairs straight back into that fallback. Its --help says it "overrides the
# total from --pairs" -- the total, not the pairs.
from gs_common import swap_arrival_floor, sum_quoted_xmr    # noqa: E402

_JM = [{"expected_xmr": s} for s in ("0.50", "0.30", "0.15", "0.05")]
_q, _unread, _chunks = sum_quoted_xmr(_JM)
_tol = _D("0.10")
_keep, _kt = swap_arrival_floor(_q, _tol, _chunks, len(_chunks))
_drop, _dt = swap_arrival_floor(_q, _tol, [], len(_JM))
# Everything except the smallest chunk: what arrives when one swap never lands.
_partial = _q - min(_chunks)
check("expect-xmr: --pairs alone tightens the gate above the partial arrival",
      _kt and _partial < _keep)
check(f"expect-xmr: REPRODUCED -- discarding the breakdown drops the gate to "
      f"{_drop}, and the {_partial} XMR that arrives with a whole swap missing "
      f"clears it", (not _dt) and _partial >= _drop)

# THE FIX, driven through the SHIPPED CLI rather than a copy of its arithmetic:
# receive_watch computes the gate before it touches Tor, so a real invocation
# reaches the line and then aborts.
import subprocess                                            # noqa: E402

_addr5 = "4" + "A" * 94
with tempfile.TemporaryDirectory() as _td5:
    _rw = os.path.join(_td5, "recv.json")
    _pj = os.path.join(_td5, "pairs.json")
    _pb = os.path.join(_td5, "pairs_bad.json")
    _pn = os.path.join(_td5, "pairs_none.json")
    _p2 = os.path.join(_td5, "pairs_two.json")
    json.dump({"schema": "gs_receive_wallet_v1", "address": _addr5,
               "account_index": 1, "subaddress_index": 3,
               "rpc_endpoint": "http://127.0.0.1:18083"}, open(_rw, "w"))
    json.dump([{"schema": "thor_pairs_v1", "dest_xmr": _addr5,
                "expected_xmr": s}
               for s in ("0.50", "0.30", "0.15", "0.05")], open(_pj, "w"))
    # THE UNREADABLE ONE IS THE LARGEST. With a small quote unreadable the
    # rescaled gate does not tighten at all, so the line under test is never
    # printed and the check would pass on an empty string -- which is how the
    # first version of this fixture "passed". Driven: 0.50/0.30/0.15/0.05 with
    # the 0.50 unreadable scales to 0.60/0.30/0.10 against a 1.0 total, guard
    # 0.900000000001 over a 0.9 tolerance floor, so it tightens.
    json.dump([{"schema": "thor_pairs_v1", "dest_xmr": _addr5,
                "expected_xmr": s}
               for s in ("NaN", "0.30", "0.15", "0.05")], open(_pb, "w"))
    # EVERY quote unreadable. This is the ONLY way _chunk_amounts is empty
    # while --pairs was given, so it is the only case that separates "the swap
    # count is unknown" from "the count is known and the shape is not". A
    # mutation collapsing those two branches SURVIVED the first version of this
    # file, because nothing here drove the case that tells them apart.
    json.dump([{"schema": "thor_pairs_v1", "dest_xmr": _addr5,
                "expected_xmr": s}
               for s in ("NaN", "Infinity", "0", "nonsense")], open(_pn, "w"))
    # TWO unreadable, and the message counts rather than saying "One".
    #
    # The readable pair has to be LOPSIDED or the gate never tightens and the
    # line under test is never printed. First attempt used 0.30/0.10: rescaled
    # onto a 1.0 total that is 0.75/0.25, guard 0.75, under the 0.9 tolerance
    # floor -- no tightening, and every check about the wording would have
    # passed against an empty string. Caught by the non-vacuity partner below,
    # which is the only reason it is not still in here. 0.90/0.05 rescales to
    # ~0.947/~0.053, guard ~0.947, which clears 0.9.
    json.dump([{"schema": "thor_pairs_v1", "dest_xmr": _addr5,
                "expected_xmr": s}
               for s in ("NaN", "Infinity", "0.90", "0.05")], open(_p2, "w"))

    def _rw_run(*extra):
        _e = dict(os.environ)
        _e["PYTHONPATH"] = REPO
        return subprocess.run(
            [sys.executable, os.path.join(REPO, "receive_watch"),
             "--receive-wallet", _rw, "--tor-proxy",
             "socks5h://127.0.0.1:9"] + list(extra),
            capture_output=True, text=True, timeout=120,
            env=_e, cwd=_td5).stdout

    _o_pairs = _rw_run("--pairs", _pj)
    _o_both = _rw_run("--pairs", _pj, "--expect-xmr", "1")
    _o_alone = _rw_run("--expect-xmr", "1")
    _o_bad = _rw_run("--pairs", _pb, "--expect-xmr", "1")
    _o_badonly = _rw_run("--pairs", _pb)
    _o_none = _rw_run("--pairs", _pn, "--expect-xmr", "1")
    _o_two = _rw_run("--pairs", _p2, "--expect-xmr", "1")

_TIGHT = "Arrival gate tightened to 0.950000000001 XMR"
check("expect-xmr: the shipped CLI tightens the gate on --pairs alone",
      _TIGHT in _o_pairs)
check("expect-xmr: ...and --expect-xmr restating the SAME total no longer "
      "loses that tightening", _TIGHT in _o_both)
check("expect-xmr: REPRODUCED -- the shipped CLI used to answer that "
      "combination with 'the number of swaps is UNKNOWN (--expect-xmr without "
      "--pairs)' on a run that PASSED --pairs",
      "without --pairs" not in _o_both)
# NON-VACUITY: that message is still printed where it is TRUE, so the check
# above is not passing because the message was deleted.
check("NON-VACUITY: --expect-xmr with no --pairs still says the swap count is "
      "unknown", "without --pairs" in _o_alone
      and "UNKNOWN" in _o_alone)
# A PARTIAL SHAPE IS STILL SCALED -- the same answer GhostSpiral's
# stage4_await_swap gives, so the pipeline's two arrival gates do not drift --
# but the wording stops calling the result a reading. One unreadable quote
# means the breakdown covers 3 of 4 swaps while the override covers all 4.
check("expect-xmr: a partially readable set is still rescaled (it does not "
      "fall back to assuming equal chunks)", "assumed EQUAL" not in _o_bad)
check("expect-xmr: ...and the gate line stops claiming a MEASURED smallest "
      "chunk when one of the swaps was never quoted readably",
      "the smallest chunk this target implies is" in _o_bad
      and "the smallest quoted chunk is" not in _o_bad)
check("expect-xmr: ...and says how many swaps it is inferring",
      "1 of the 4 swaps carried no readable quote" in _o_bad
      and "its size is inferred" in _o_bad)
# NON-VACUITY: the fixture must actually REACH the tightening line, or every
# check above it passes against an empty string.
check("NON-VACUITY: the partial-shape fixture really does tighten the gate",
      "Arrival gate tightened" in _o_bad)
# The two lines ABOVE the gate describe a target --expect-xmr replaced. They
# said the watch would finish without the unreadable swaps; with an override
# covering all of them, that is the opposite of what the gate then does.
check("expect-xmr: the unreadable-quote note no longer tells an operator who "
      "passed --expect-xmr that those swaps are excluded from the target",
      "contribute NOTHING" not in _o_bad
      and "covers all 4 of them" in _o_bad)
check("NON-VACUITY: without the override it still says exactly that",
      "contribute NOTHING" in _o_badonly
      and "built from 3 pair(s) only" in _o_badonly)
# NON-VACUITY: the fully readable set still says "quoted", so the check above
# is not passing because the phrase was deleted from the file.
check("NON-VACUITY: a fully readable set still reports a MEASURED smallest "
      "chunk", "the smallest quoted chunk is" in _o_both
      and "implies is" not in _o_both)
check("expect-xmr: neither says 'without --pairs' on a run that passed them",
      "without --pairs" not in _o_bad)

# NO QUOTE AT ALL READABLE, WITH --pairs. The count is known and the shape is
# not, which is a THIRD statement -- and the branch that says it is only
# reachable here. Without this case a mutation collapsing it into the
# no---pairs branch survives the whole suite.
check("expect-xmr: with --pairs and not one readable quote, the gate says the "
      "SHAPE is unknown, not that --pairs was absent",
      "none of them carried a readable quote" in _o_none
      and "without --pairs" not in _o_none)
check("expect-xmr: ...and it names the real swap count from --pairs, not 1",
      "The 4 swap(s) behind this target are assumed EQUAL" in _o_none)
check("expect-xmr: with TWO unreadable quotes the note counts them and reads "
      "as plural -- it does not say 'One'",
      "2 of the 4 swaps carried no readable quote" in _o_two
      and "their sizes are inferred" in _o_two)
check("NON-VACUITY: the two-unreadable fixture reaches the tightening line, so "
      "the check above is not passing vacuously",
      "Arrival gate tightened" in _o_two)
check("NON-VACUITY: the count-unknown wording is still reserved for the run "
      "that really has no --pairs",
      "without --pairs" in _o_alone
      and "none of them carried a readable quote" not in _o_alone)

# THE SAME THREE-WAY DISTINCTION IN GhostSpiral's COPY. Its rescale was already
# right; its message was not -- with a partial shape chunk_amounts is truthy,
# so it printed "The smallest quoted chunk is" about a set that does not cover
# every swap in the target. Measured over 4000 random shapes (2-8 swaps, 1..N-1
# unreadable): 1007 printed it. The rescale STAYS -- over those same 4000 it
# opened a gate the count-only fallback would have held zero times.
_gsrc = Path(os.path.join(REPO, "GhostSpiral")).read_text()
check("expect-xmr: GhostSpiral's gate line distinguishes all THREE bases -- "
      "quoted, inferred, and assumed-equal",
      '"The smallest chunk this target implies is"' in _gsrc
      and '"The smallest quoted chunk is"' in _gsrc
      and 'f"Split equally, each of the {n_chunks} chunks would be"' in _gsrc)
check("expect-xmr: ...and it is keyed on the SHAPE covering every swap, not "
      "merely on the breakdown being non-empty",
      "if len(chunk_amounts) != n_chunks" in _gsrc)
check("expect-xmr: GhostSpiral still RESCALES a partial shape rather than "
      "discarding it (the two gates give one answer)",
      "        if _quoted_sum > 0 and chunk_amounts:\n"
      "            _scale = args.expect_total_xmr / _quoted_sum" in _gsrc)

# The rescale keys on PROPORTIONS, so an override that really does change the
# total still guards the smallest swap at its new size.
for _ex5 in (_D("0.95"), _D("1.10"), _D("2")):
    _scaled = [c * _ex5 / _q for c in _chunks]
    _fs, _ts = swap_arrival_floor(_ex5, _tol, _scaled, len(_scaled))
    _fd, _td_ = swap_arrival_floor(_ex5, _tol, [], len(_JM))
    _miss = _ex5 - min(_scaled)
    check(f"expect-xmr: at --expect-xmr {_ex5} the rescaled gate refuses the "
          f"partial arrival ({_miss} XMR) and the discard accepts it",
          _miss < _fs and _miss >= _fd)

# ===========================================================================
#  7. THE TWO LONG-LIVED SERVERS WROTE CORE DUMPS
# ===========================================================================
#
# gs_common.disable_core_dumps exists because "these processes hold the wallet
# password (and ... key material) in memory, so a crash on a machine with the
# common `ulimit -c unlimited` default would persist that secret to a file
# nothing here ever wipes". It is wired into install_signal_handlers, whose
# docstring claimed that is "the one hook that reliably covers them all"
# because "every script calls this at startup".
#
# Two never did, and they are the worst two to miss: gs_console holds the
# WALLET SPEND PASSWORD in its environment for its whole lifetime, and
# gs_doorbell decrypts the PI'S X25519 SECRET and holds it for the life of the
# server. Both are long-running, both run unattended, and no systemd unit here
# sets LimitCORE.
#
# SUBPROCESSES, not in-process. setrlimit(RLIMIT_CORE, (0,0)) lowers the HARD
# limit, which a non-root process cannot raise again -- so a check that ran it
# here would silently make every later check pass. Each of these forks a child
# with `ulimit -c unlimited` and asks the child what it observed.
print("\n-- the two long-lived servers do not write core dumps --")
import subprocess                                            # noqa: E402,F811

for _srv, _what in (("gs_doorbell", "the Pi's X25519 secret"),
                    ("gs_console", "the wallet spend password")):
    _p = CORE_RESULTS.get(_srv) or None
    check(f"core dumps: the {_srv} probe ran (it is the fixture, not the "
          f"subject)", _p is not None and len(_p) == 4)
    if not _p or len(_p) != 4:
        continue
    _before, _imported, _after, _ctrlc = _p
    # NON-VACUITY FIRST: if the child did not actually start with core dumps
    # enabled, every check below passes for the wrong reason.
    check(f"NON-VACUITY: the {_srv} child really started with core dumps "
          f"ENABLED (rlimit={_before})", _before != "0")
    # BOTH OF THESE WERE WRONG, IN OPPOSITE DIRECTIONS, AND THE SECOND ONE
    # BLOCKED THE REPAIR OF THE FIRST.
    #
    # The old pair asserted (a) that merely IMPORTING the module leaves dumps
    # allowed -- "so nothing at module scope suppresses them" -- and (b) that
    # main() suppressing them makes the secret "never dumpable".
    #
    # (b) is false: the secret arrives in the ENVIRONMENT, so it is in the
    # process image from execve, and the whole IMPORT PHASE ran with dumps
    # enabled. Driven -- a SIGABRT during the import of gs_console wrote a 5 MB
    # core file with the wallet password in it twice.
    #
    # And (a) is the worse one: it PINNED the defect. Moving the suppression to
    # module scope -- the actual fix -- makes it go red, so the next person to
    # do the right thing gets a failing check named "REPRODUCED", telling them
    # they broke something. A test that certifies a guarantee the code does not
    # have is bad; one that mechanically resists the repair is worse.
    check(f"core dumps: {_srv} suppresses them AT IMPORT, before its own heavy "
          f"imports -- not at the top of main(), which leaves the import phase "
          f"open with {_what} already in the environment", _imported == "0")
    check(f"core dumps: ...and they are still suppressed after main() runs",
          _after == "0")
    check(f"core dumps: ...and {_srv} did NOT gain the flag-setting SIGINT "
          f"handler -- it ends in a blocking loop inside `except "
          f"KeyboardInterrupt`, and that still fires", _ctrlc == "works")

# THE GUARANTEE, STATED AS WHAT IT ACTUALLY IS. "Never dumpable" is not
# achievable from Python: exec, dynamic linking and site.py all run before our
# first statement, and so does the entry script's own `import hashlib, decimal`.
# What IS achievable, and what this pins, is that no THIRD-PARTY or CRYPTO
# module is ever imported while dumps are still allowed -- those are the
# imports that run foreign C code and can take a fatal signal. The window
# before the interpreter reaches us belongs to the launcher, and the systemd
# units set LimitCORE=0 for it.
for _tool, (_bad, _n) in sorted(IMPORT_RESULTS.items()):
    check(f"core dumps: the import probe ran for {_tool} (fixture, not subject)",
          _bad is not None)
    if _bad is None:
        continue
    check(f"core dumps: {_tool} imports NO third-party or crypto module while "
          f"dumps are still allowed ({_bad or 'none did'})", not _bad)
# NON-VACUITY: the probe must actually be WATCHING something, or "none did" is
# just what an empty observation looks like.
_watched = [t for t, (_b, n) in IMPORT_RESULTS.items() if (n or 0) > 0]
check(f"NON-VACUITY: the probe really observes risky imports happening "
      f"({sorted(_watched)})", len(_watched) >= 3)
# ...and the launcher covers what no Python statement can reach.
for _u in ("systemd/gs-wake-agent.service",
           "systemd/gs-doorbell.service.example",
           "systemd/gs-telegram-pager.service.example"):
    check(f"core dumps: {_u.split('/')[-1]} sets LimitCORE=0 for the window "
          f"before the interpreter runs any of our code",
          "LimitCORE=0" in Path(os.path.join(REPO, _u)).read_text())

# THE TRAP THE OBVIOUS FIX WALKS INTO, driven rather than argued. Adding
# install_signal_handlers() to those two would have suppressed the dumps AND
# stopped Ctrl-C from working, because it replaces SIGINT's disposition with a
# flag-setter and neither server checks the flag.
_SIG_PROBE = r'''
import os, signal, sys, time
sys.path.insert(0, %r)
import gs_common as C
if sys.argv[1] == "with":
    C.install_signal_handlers()
try:
    os.kill(os.getpid(), signal.SIGINT)
    time.sleep(0.2)
    print("swallowed")
except KeyboardInterrupt:
    print("raised")
''' % (REPO,)
with tempfile.TemporaryDirectory() as _t:
    _sp = os.path.join(_t, "sig.py")
    open(_sp, "w").write(_SIG_PROBE)
    # THE LAST LINE, not the whole stream. The installed handler PRINTS
    # "[!] Shutdown signal received (2)..." before control returns, so
    # .strip() on all of stdout is never equal to the verdict word -- which is
    # how the first version of this check failed against a working fix.
    def _sig(mode):
        _o = subprocess.run([sys.executable, _sp, mode], capture_output=True,
                            text=True, timeout=60).stdout.strip().splitlines()
        return _o[-1].strip() if _o else ""
    _r_def, _r_ins = _sig("without"), _sig("with")
check("core dumps: NON-VACUITY -- without the handlers a SIGINT raises "
      "KeyboardInterrupt", _r_def == "raised")
check("core dumps: ...and install_signal_handlers() SWALLOWS it, which is why "
      "these two suppress the dump directly instead of taking the shared hook",
      _r_ins == "swallowed")

# ANTI-DRIFT. Three implementations of one rule now exist, and neither server
# can use the shared one -- gs_doorbell is forbidden from importing gs_common
# at all, gs_console is stdlib-only while gs_common imports requests. So the
# guarantee is pinned where it can fail: all three must do the same thing.
_SRC = {n: Path(os.path.join(REPO, n)).read_text()
        for n in ("gs_common.py", "gs_doorbell", "gs_console")}
_RULE = "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))"
check("core dumps: all three implementations set the SAME limit (soft AND "
      "hard, so it cannot be raised again)",
      all(_RULE in s for s in _SRC.values()))
check("core dumps: ...and all three VERIFY it took rather than assuming",
      all("resource.getrlimit(resource.RLIMIT_CORE)[0] == 0" in s
          for s in _SRC.values()))
# The reason there are three and not one. If this ever stops being true, the
# duplication has no justification left and should collapse to the shared one.
# AN IMPORT, NOT THE WORDS. `"from gs_common" not in src` reads as an import
# check and is a PROSE check: gs_console line 1041 says "drifting from
# gs_common.MAX_SPLIT" in a comment, so the substring test failed against a
# file that imports nothing. Match a real import statement at the start of a
# line instead -- and prove the matcher works by pointing it at a file that
# genuinely does import gs_common.
import re as _re5                                            # noqa: E402


def _imports_gs_common(src):
    return bool(_re5.search(r"^[ \t]*(?:import gs_common|from gs_common import)",
                            src, _re5.M))


check("core dumps: NON-VACUITY -- the import matcher finds a real import when "
      "there is one",
      _imports_gs_common(Path(os.path.join(REPO, "receive_watch")).read_text()))
check("core dumps: ...and is not fooled by a comment that merely NAMES "
      "gs_common (gs_console has one)",
      "gs_common" in _SRC["gs_console"])
check("core dumps: gs_doorbell still imports no gs_common -- the ban that "
      "forces a local copy is intact",
      not _imports_gs_common(_SRC["gs_doorbell"]))
check("core dumps: gs_console still imports no gs_common, and gs_common still "
      "pulls requests at module scope -- the other reason for a local copy",
      not _imports_gs_common(_SRC["gs_console"])
      and _re5.search(r"^import requests", _SRC["gs_common.py"], _re5.M))
# The claim that started this: install_signal_handlers no longer asserts a
# coverage it does not have.
# SCOPED TO THE DOCSTRING, not to the file. This read `"gs_console" in
# _SRC["gs_common.py"]` -- satisfied by either name appearing anywhere in three
# thousand lines, including in an unrelated comment or in the wipe-pattern
# list. The claim under test is about what install_signal_handlers' OWN
# docstring says, so that is what is read.
_ISH_DOC = ""
for _n in ast.walk(ast.parse(_SRC["gs_common.py"])):
    if isinstance(_n, ast.FunctionDef) and _n.name == "install_signal_handlers":
        _ISH_DOC = ast.get_docstring(_n) or ""
check("core dumps: the docstring under test was actually found, so the checks "
      "below are reading something", len(_ISH_DOC) > 200)
# FLATTENED, and that is not cosmetic. This asserted
#     "the one hook that reliably covers them all" not in _ISH_DOC
# and passed -- while the docstring contains that exact phrase, wrapped across
# two lines. It was passing on the line break, not on the claim, and would have
# gone on passing if the docstring had asserted the coverage outright in two
# lines instead of one.
#
# The real guarantee is not "the phrase is absent" -- it is quoted deliberately,
# as the thing this docstring used to say. It is "the phrase appears only as
# history, with the correction attached".
_ISH_FLAT = _re5.sub(r"\s+", " ", _ISH_DOC)
check("core dumps: NON-VACUITY -- the phrase really is in the docstring, and "
      "the unflattened check could not see it",
      "the one hook that reliably covers them all" in _ISH_FLAT
      and "the one hook that reliably covers them all" not in _ISH_DOC)
check("core dumps: install_signal_handlers no longer claims to cover EVERY "
      "script -- the old phrase survives only as a quoted correction",
      'used to say it was -- "the one hook that reliably covers them all"'
      in _ISH_FLAT
      and "THAT IS NOT EVERY SCRIPT" in _ISH_FLAT
      and "gs_console" in _ISH_FLAT
      and "gs_doorbell" in _ISH_FLAT)
# NON-VACUITY: the names must be scarce enough in the docstring that finding
# them there means something -- and absent from a docstring that never
# mentioned them, which is what the old check could not tell apart.
check("core dumps: NON-VACUITY -- the file-wide search the old check did would "
      "pass on a docstring that named neither",
      "gs_console" in _SRC["gs_common.py"]
      and "gs_console" not in (ast.get_docstring(
          next(_n for _n in ast.walk(ast.parse(_SRC["gs_common.py"]))
               if isinstance(_n, ast.FunctionDef)
               and _n.name == "disable_core_dumps")) or ""))
# NON-VACUITY: every OTHER tool must still take the shared hook, or the two
# local copies are the start of a spread rather than two named exceptions.
_MISSING = [t for t in
            ("GhostSpiral", "airgap_tx_signer", "receive_watch", "paranoia_mode",
             "broadcast_signed_xmr", "thor_swap_preparer", "create_receive_wallet",
             "exit_strategy_simulator", "gs_delivery_key", "gs_unseal",
             "gs_wake_agent", "gs_wake_keys", "gs_telegram_pager")
            if not _re5.search(r"^[ \t]*install_signal_handlers\(\)",
                               Path(os.path.join(REPO, t)).read_text(), _re5.M)]
check(f"core dumps: NON-VACUITY -- every other tool still takes the shared "
      f"hook, so the local copies stay two named exceptions ({_MISSING or 'none missing'})",
      not _MISSING)

# ===========================================================================
#  8. THE WIPE COULD NOT ERASE THE TWO FILES IT MOST NEEDED TO
# ===========================================================================
#
# secure_delete_file opens O_WRONLY, which is EACCES for any non-root owner of
# a 0400 file -- and the two most secret files in this toolchain are minted
# 0400 ON PURPOSE. gs_wake_keys._write_key does it ("a writable keyfile is a
# keyfile something can rewrite between boots") and gs_delivery_key does it via
# atomic_write_json(..., perms=0o400). Both hold an X25519 secret, and
# "gs_wake_*.key" is in GS_ARTIFACT_FILE_PATTERNS -- the wipe list.
#
# So paranoia_mode could not erase the wake keypair it lists, and
# `gs_delivery_key shred` -- the one command whose job is getting the delivery
# secret OFF the vault -- failed every time. It failed silently, because that
# call site is the ONLY one of fifteen in this repo that discards
# secure_delete_file's return value: it printed "[+] <path> destroyed." and
# exited 0 with the sealed secret still on disk.
#
# EVERY CHECK BELOW RUNS AS A NON-ROOT USER, in a forked child that drops to
# uid 65534. Running as root is what hid this: uid 0 ignores the write bit
# entirely, so as root the whole thing works and the bug is invisible.
print("\n-- the wipe can erase the 0400 keyfiles this toolchain mints --")

_CAN_DROP = os.geteuid() == 0
check("wipe/0400: the checks below can drop privileges (running as root, so "
      "uid 65534 is reachable)", _CAN_DROP)


def _as_nobody(fn_src, *paths):
    """Run a snippet as uid 65534 in a forked child; return its stdout lines."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            out = fn_src(*paths)
            os.write(w, json.dumps(out).encode())
        except BaseException as e:                           # noqa: BLE001
            with contextlib.suppress(Exception):
                os.write(w, json.dumps({"error": repr(e)[:200]}).encode())
        finally:
            os._exit(0)
    os.close(w)
    buf = b""
    with os.fdopen(r, "rb") as f:
        buf = f.read()
    os.waitpid(pid, 0)
    return json.loads(buf.decode() or "{}")


if _CAN_DROP:

    def _probe(d):
        from gs_common import secure_delete_file as _sdf
        _res = {}
        for _k in sorted(os.listdir(d)):
            _p = Path(d) / _k
            if _k == "nod":
                _p = _p / "x.json"
            _got = _sdf(_p)
            _res[_k] = [bool(_got), _p.exists() or _p.is_symlink()]
        return _res

    _d = Path(tempfile.mkdtemp())
    os.chmod(_d, 0o777)
    # a: the exact shape gs_wake_keys and gs_delivery_key mint.
    (_d / "a_mine_0400").write_text("SECRET" * 40)
    os.chmod(_d / "a_mine_0400", 0o400)
    os.chown(_d / "a_mine_0400", 65534, 65534)
    # b: somebody ELSE's 0400 file. Must stay refused -- the fix must not hand
    #    the caller power over a file it does not own.
    (_d / "b_notmine_0400").write_text("SECRET" * 40)
    os.chmod(_d / "b_notmine_0400", 0o400)
    # c: the ordinary path, unchanged.
    (_d / "c_normal_0600").write_text("x" * 100)
    os.chmod(_d / "c_normal_0600", 0o600)
    os.chown(_d / "c_normal_0600", 65534, 65534)
    # d: a 0400 FIFO. Non-regular files must stay refused even when owned.
    os.mkfifo(_d / "d_fifo")
    os.chmod(_d / "d_fifo", 0o400)
    os.chown(_d / "d_fifo", 65534, 65534)
    # e: an EMPTY 0400 file -- the size==0 branch skips the overwrite entirely.
    (_d / "e_empty_0400").write_text("")
    os.chmod(_d / "e_empty_0400", 0o400)
    os.chown(_d / "e_empty_0400", 65534, 65534)
    # nod: unlink denied by the DIRECTORY. Must report failure, not success.
    (_d / "nod").mkdir()
    (_d / "nod" / "x.json").write_text("y" * 50)
    os.chown(_d / "nod" / "x.json", 65534, 65534)
    os.chmod(_d / "nod" / "x.json", 0o600)
    os.chmod(_d / "nod", 0o555)

    _R = _as_nobody(_probe, str(_d))
    check(f"wipe/0400: the non-root probe ran (fixture, not subject) "
          f"({sorted(_R) if 'error' not in _R else _R})", "error" not in _R)
    if "error" not in _R:
        check("wipe/0400: a 0400 file the caller OWNS is now overwritten and "
              "removed -- this is the wake keyfile and the delivery key",
              _R.get("a_mine_0400") == [True, False])
        check("wipe/0400: NON-VACUITY -- a 0400 file owned by SOMEBODY ELSE is "
              "still refused, so nothing gained power it did not have",
              _R.get("b_notmine_0400") == [False, True])
        check("wipe/0400: an ordinary 0600 file still works (the common path "
              "is untouched)", _R.get("c_normal_0600") == [True, False])
        check("wipe/0400: an EMPTY 0400 file is removed (the size==0 branch "
              "skips the overwrite and must still unlink)",
              _R.get("e_empty_0400") == [True, False])
        check("wipe/0400: a 0400 FIFO the caller owns is STILL refused -- "
              "non-regular files are never overwritten",
              _R.get("d_fifo") == [False, True])
        check("wipe/0400: a file whose DIRECTORY denies unlink reports FAILURE "
              "rather than claiming success", _R.get("nod") == [False, True])

    # THE TWO REAL FILES, end to end, as a non-root operator.
    def _wake_probe(kp):
        import importlib.machinery as _m, importlib.util as _u
        _ld = _m.SourceFileLoader("pm", os.path.join(REPO, "paranoia_mode"))
        _pm = _u.module_from_spec(_u.spec_from_loader(_ld.name, _ld))
        _ld.exec_module(_pm)
        _ok = _pm._secure_delete_file(Path(kp))
        return {"ok": bool(_ok), "exists": Path(kp).exists()}

    _kd = Path(tempfile.mkdtemp())
    os.chmod(_kd, 0o777)
    _kf = _kd / "gs_wake_thinkpad.key"
    GSC.atomic_write_json(
        P.lock_keyfile({"role": "thinkpad", "secret": "ab" * 32}, b"",
                       role="thinkpad"), _kf, perms=0o400)
    os.chown(_kf, 65534, 65534)
    check("wipe/0400: the wake keyfile really is 0400, as gs_wake_keys writes "
          "it", (os.stat(_kf).st_mode & 0o777) == 0o400)
    check("wipe/0400: ...and it really is in the wipe list",
          any(__import__("fnmatch").fnmatch(_kf.name, _p)
              for _p in GSC.GS_ARTIFACT_FILE_PATTERNS))
    _W = _as_nobody(_wake_probe, str(_kf))
    check(f"wipe/0400: paranoia_mode's sweep primitive now ERASES the wake "
          f"keypair it lists ({_W})",
          _W.get("ok") is True and _W.get("exists") is False)

    def _shred_probe(kp):
        # cwd must be writable by uid 65534: cmd_shred calls integrity_log,
        # which creates integrity_chain.log in the CURRENT directory. Pointing
        # it at the key's own directory made the probe die on a PermissionError
        # from the LOG rather than exercising the shred -- the fixture failing,
        # dressed as the subject failing.
        import importlib.machinery as _m, importlib.util as _u
        os.chdir(tempfile.mkdtemp())
        _ld = _m.SourceFileLoader("dk", os.path.join(REPO, "gs_delivery_key"))
        _dk = _u.module_from_spec(_u.spec_from_loader(_ld.name, _ld))
        _ld.exec_module(_dk)

        class _A:
            pass
        _a = _A()
        _a.key = kp
        _a._getpass = lambda p: "pw"
        _a._input = lambda p: "shred it"
        _o = io.StringIO()
        try:
            with contextlib.redirect_stdout(_o):
                _rc = _dk.cmd_shred(_a)
            _said = _o.getvalue() + " rc=%s" % _rc
        except SystemExit as _e:
            # _o bound OUTSIDE the with, so the failure path can still read what
            # was printed. `"_o" in dir()` did not do that: inside a function
            # dir() lists locals, and the name is only bound on the happy path.
            _said = _o.getvalue() + " exit=%s" % _e
        return {"said": _said, "exists": Path(kp).exists()}

    import nacl.public as _NP2                               # noqa: E402
    # THE DIRECTORY'S OWNER MATTERS, not just its mode. The first version made
    # both directories root-owned and used 0o755 for the "writable" case -- so
    # uid 65534 could not unlink from EITHER, both cases were the deny case,
    # and only one of them asserted it. 0o777 is what actually lets the
    # dropped-privilege child remove the file.
    for _label, _mkdir_mode, _want_gone in (("a writable directory", 0o777, True),
                                            ("a directory that denies unlink", 0o555, False)):
        _sd = Path(tempfile.mkdtemp())
        os.chmod(_sd, 0o777)
        _inner = _sd / "m"
        _inner.mkdir()
        _dkf = _inner / "gs_delivery.key"
        GSC.atomic_write_json(P.lock_keyfile(
            {"role": "delivery",
             "delivery_secret": bytes(_NP2.PrivateKey.generate()).hex(),
             "vault_public": bytes(_NP2.PrivateKey.generate().public_key).hex()},
            b"pw", kdf="interactive", role="delivery"), _dkf, perms=0o400)
        os.chown(_dkf, 65534, 65534)
        os.chmod(_inner, _mkdir_mode)
        _S = _as_nobody(_shred_probe, str(_dkf))
        if _want_gone:
            check(f"wipe/0400: `gs_delivery_key shred` in {_label} now actually "
                  f"destroys the delivery secret",
                  _S.get("exists") is False and "destroyed" in _S.get("said", ""))
        else:
            check(f"wipe/0400: `gs_delivery_key shred` in {_label} REFUSES "
                  f"rather than printing 'destroyed'",
                  _S.get("exists") is True
                  # THREE messages now, one per state. This branch is the
                  # unlink-denied one, where the overwrite SUCCEEDED -- so the
                  # honest wording is "was OVERWRITTEN but could not be
                  # removed", not the old "could NOT be destroyed / nothing was
                  # overwritten", which was false for exactly this case.
                  and "was OVERWRITTEN but could not be removed"
                      in _S.get("said", "")
                  and "IS GONE" in _S.get("said", "")
                  and "[+]" not in _S.get("said", ""))
        os.chmod(_inner, 0o755)

# THE CALL SITE, pinned by source. Fourteen callers check this return value and
# one did not; that one is the reason the failure was silent.
_DKSRC = Path(os.path.join(REPO, "gs_delivery_key")).read_text()
check("wipe/0400: cmd_shred checks secure_delete_file's return value",
      "if not secure_delete_file(path):" in _DKSRC)
check("wipe/0400: ...and no caller anywhere still discards it",
      not _re5.search(r"^\s*secure_delete_file\([^)]*\)\s*$",
                      "\n".join(Path(os.path.join(REPO, _t)).read_text()
                                for _t in ("GhostSpiral", "paranoia_mode",
                                           "thor_swap_preparer", "gs_delivery_key",
                                           "gs_common.py")), _re5.M))
# The chmod must stay scoped to the caller's OWN file, or it becomes a way to
# destroy files the caller could not otherwise touch.
_GCSRC = Path(os.path.join(REPO, "gs_common.py")).read_text()
check("wipe/0400: the retry only widens a file the caller OWNS",
      "rst.st_uid != os.geteuid()" in _GCSRC)
check("wipe/0400: ...only to 0600, never wider", "os.fchmod(rfd, 0o600)" in _GCSRC)
# SCOPED TO THE FUNCTION. `"os.chmod(path" not in _GCSRC` asked the whole
# 3400-line module, and gs_common's atomic writer legitimately chmods by path
# at line 1243 -- so this went red against a correct fix. Slice out
# secure_delete_file's own body and ask there.
_SDF_BODY = _GCSRC.split("def secure_delete_file(", 1)[-1].split("\ndef ", 1)[0]
check("wipe/0400: ...and through a DESCRIPTOR, not a path -- os.chmod cannot "
      "take follow_symlinks=False on Linux, so a path chmod is a TOCTOU",
      "os.fchmod(" in _SDF_BODY and "os.chmod(" not in _SDF_BODY)
check("wipe/0400: NON-VACUITY -- the slice really is secure_delete_file's body",
      "O_NOFOLLOW" in _SDF_BODY and len(_SDF_BODY) < 6000)

# ===========================================================================
#  9. "THE WIPE WILL MISS THIS" NAMED THE WRONG REASON AND THE WRONG REMEDY
# ===========================================================================
#
# The sweep matches on TWO things -- the location (roots at depth 0 and 1) and
# the file's NAME against GS_ARTIFACT_FILE_PATTERNS. wipe_will_erase asks both,
# which is right. The warnings printed when it says no asked neither: they
# stated a LOCATION fact ("<dir> is OUTSIDE the directories paranoia_mode
# sweeps") and prescribed a LOCATION remedy ("--search-dir <dir>", "write it
# under the working directory or $HOME").
#
# `--outfile myplan.json` in the CURRENT DIRECTORY is the live case. The
# directory is searched; the name will never match. The operator was told the
# opposite, followed a remedy that cannot fix a name, re-ran the wipe, and the
# file -- the holding size and its fiat value, or every BTC deposit address and
# the memos naming the destination XMR address in full -- was still there.
#
# thor_swap_preparer's own comment MEASURES this case two lines above the
# message ("~/gs/my_notes.json covers=True NO match -> NEVER erased") and the
# message still spoke only about the directory.
print("\n-- the wipe warning names which half of the test failed --")

_w9 = Path(tempfile.mkdtemp()).resolve()
_prev_home, _prev_cwd = os.environ.get("HOME"), os.getcwd()
os.environ["HOME"] = str(_w9)
os.chdir(_w9)
try:
    (_w9 / "deep").mkdir()
    (_w9 / "deep" / "deeper").mkdir()
    _cases = {
        "exitplan_v1.json": "",                       # covered + matching
        "myplan.json": "name",                        # covered, name fails
        "deep/deeper/exitplan_v1.json": "location",   # name ok, too deep
        "deep/deeper/myplan.json": "both",            # neither
    }
    _bad9 = []
    for _rel, _want in _cases.items():
        _p = _w9 / _rel
        _p.write_text("{}")
        _got = GSC.wipe_miss_reason(_p)
        if _got != _want:
            _bad9.append((_rel, _got, _want))
    check(f"wipe reason: every case is classified correctly "
          f"({_bad9 or 'all four'})", not _bad9)
    # NON-VACUITY: the four cases must not all be the same answer, or the
    # classifier could be a constant and still pass.
    check("NON-VACUITY: the four cases really do produce four different "
          "answers", len(set(_cases.values())) == 4)
    # And it must agree with the predicate it explains: "" exactly when the
    # sweep would erase the file.
    _dis = [r for r in _cases
            if (GSC.wipe_miss_reason(_w9 / r) == "")
            != bool(GSC.wipe_will_erase(_w9 / r))]
    check(f"wipe reason: '' means exactly what wipe_will_erase means "
          f"({_dis or 'agrees on all four'})", not _dis)
finally:
    os.chdir(_prev_cwd)
    if _prev_home is not None:
        os.environ["HOME"] = _prev_home

# THE MESSAGES. Both free-form-outfile tools must be able to say all three
# things; the location-only sentence must no longer be the only one there.
# THE LOCATION REMEDY IS DIFFERENT IN EACH TOOL, and a shared needle asserted
# the wrong one: exit_strategy_simulator offers --search-dir, thor_swap_preparer
# offers "write it under the working directory or $HOME". Checking for
# --search-dir in both went red against a correct message.
for _t9, _needle, _loc_remedy in (
        ("exit_strategy_simulator", "exitplan_*.json", "--search-dir"),
        ("thor_swap_preparer", "thor_pairs*.json",
         "working directory or $HOME")):
    _s9 = Path(os.path.join(REPO, _t9)).read_text()
    check(f"wipe reason: {_t9} asks WHY rather than assuming location",
          "wipe_miss_reason(" in _s9)
    check(f"wipe reason: ...and can say the NAME is what failed, naming the "
          f"pattern that would work ({_needle})",
          "NAME matches none of the artifact patterns" in _s9
          and _needle in _s9)
    check(f"wipe reason: ...and says --search-dir/moving it will NOT help in "
          f"that case", "will NOT help" in _s9)
    check(f"wipe reason: ...and still has the location branch, with THIS "
          f"tool's own location remedy ({_loc_remedy})",
          "outside" in _s9 and _loc_remedy in _s9)
# create_receive_wallet is deliberately NOT changed: it picks the name itself
# (wallet_<hex>.json, which the sweep matches), so only the directory can vary
# and its location-only message is the true one. Pinned, so that stays a
# reasoned exception rather than an oversight.
_crw = Path(os.path.join(REPO, "create_receive_wallet")).read_text()
check("wipe reason: create_receive_wallet still picks its own matching name, "
      "so its location-only message stays correct",
      'f"wallet_{secure_hex(8)}.json"' in _crw
      and any(__import__("fnmatch").fnmatch("wallet_deadbeef.json", _p)
              for _p in GSC.GS_ARTIFACT_FILE_PATTERNS))
# ONE IMPLEMENTATION. The reason must not become a fourth inline copy of the
# root list -- that is the drift wipe_covers was extracted to stop.
for _t9 in ("exit_strategy_simulator", "thor_swap_preparer",
            "create_receive_wallet"):
    check(f"wipe reason: {_t9} still does not ask the location-only question "
          f"itself", "wipe_covers(" not in
          Path(os.path.join(REPO, _t9)).read_text())

# ===========================================================================
#  10. TWO CONTROL-CHARACTER GATES, ONE JOB, TWO ANSWERS
# ===========================================================================
#
# A BTC deposit address, a swap memo and an amount reach the operator down two
# paths: sealed (gs_unseal, via gs_common.instruction_field_safe) and plaintext
# (the pager, via gs_wake_proto.plain_slip_is_wellformed). Same values, same
# human, same wallet they get pasted into. The gates disagreed:
#
#     plain_slip_is_wellformed   ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f
#     instruction_field_safe     ord(c) < 0x20 or ord(c) == 0x7f
#
# so the whole C1 block (U+0080-U+009F) passed the sealed path. U+009B is the
# single-character CSI: ECMA-48 lets every ESC-Fe sequence be written as one C1
# code instead, so a terminal honouring 8-bit controls reads U+009B exactly as
# ESC [ -- and ESC is refused here while U+009B was not.
#
# STATED HONESTLY: whether an emulator honours 8-bit C1 varies by terminal and
# configuration, so this is a hazard that depends on the terminal rather than a
# universal exploit. It is not worth leaving open to find out, and it costs
# nothing: every value guarded here is base58, bech32 or ASCII digits.
print("\n-- the sealed and plaintext paths gate control characters alike --")
from gs_common import instruction_field_safe as _IFS            # noqa: E402


def _slip_gate(v):
    return P.plain_slip_is_wellformed(
        {"b": v, "d": "x" * 10, "m": "y" * 10, "x": "z" * 10, "h": "abcd"})


_dis10 = [cp for cp in range(0, 0x300)
          if _IFS("a" + chr(cp) + "b") != _slip_gate("a" + chr(cp) + "b")]
check(f"c1 gate: the sealed and plaintext gates agree on every codepoint "
      f"0x000-0x2FF ({len(_dis10)} disagreements)", not _dis10)
# NON-VACUITY: the comparison must be exercising both gates, not comparing a
# constant to a constant.
check("NON-VACUITY: both gates actually discriminate -- they accept an "
      "ordinary address and refuse an ESC",
      _IFS("bc1qexample") and _slip_gate("bc1qexample")
      and not _IFS("bc1q\x1bx") and not _slip_gate("bc1q\x1bx"))
for _nm, _cp in (("ESC 0x1b", 0x1B), ("DEL 0x7f", 0x7F), ("PAD U+0080", 0x80),
                 ("NEL U+0085", 0x85), ("CSI U+009B", 0x9B),
                 ("OSC U+009D", 0x9D), ("APC U+009F", 0x9F)):
    check(f"c1 gate: {_nm} is refused in a field meant to be copied and paid",
          not _IFS("bc1q" + chr(_cp) + "x"))
# THE BOUNDARY. 0xA0 up is printable; over-refusing would break legitimate
# text and would be a different bug.
check("c1 gate: U+00A0 and above are still accepted -- they are not controls",
      _IFS(chr(0xA0)) and _IFS(chr(0xE9)) and _IFS("café"))
# NON-VACUITY: nothing this actually guards may be refused. These are the real
# shapes -- bech32, base58, a full ThorChain memo, amounts.
_real10 = ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
           "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
           "=:XMR.XMR:" + "4" + "A" * 94 + ":0/1/0",
           "0.01234567", "1", "0.00000546", "~12 min", "abcd"]
_rej10 = [v for v in _real10 if not _IFS(v)]
check(f"c1 gate: NON-VACUITY -- every real deposit address, memo and amount is "
      f"still accepted ({_rej10 or 'all 8'})", not _rej10)
# BOTH CALLERS of the widened gate get it, and gs_unseal is the one that
# prints the address an operator is about to pay.
_US = Path(os.path.join(REPO, "gs_unseal")).read_text()
_TS = Path(os.path.join(REPO, "thor_swap_preparer")).read_text()
check("c1 gate: gs_unseal screens the slip's fields through the shared gate",
      "instruction_field_safe(v)" in _US)
check("c1 gate: ...and so does thor_swap_preparer's sender-instructions block",
      "instruction_field_safe" in _TS)
check("c1 gate: the rule lives in ONE place, not a copy per caller",
      "0x7f <= ord(ch) <= 0x9f" in
      Path(os.path.join(REPO, "gs_common.py")).read_text()
      and "0x7f" not in _US)

# ===========================================================================
#  11. THE FILE WITH ZERO MUTATION ANCHORS
# ===========================================================================
#
# exit_strategy_simulator had no mutation anchor and no dedicated suite, which
# is how it kept two defects its own comments had already written down.
#
#  (a) The comment above the amount guard names THREE inputs Decimal accepts
#      and it must reject -- "NaN", "Infinity" and "1e400" -- and the guard
#      tested is_finite() only. 1e400 IS finite and positive, so it passed both
#      local checks and crashed further down in
#      `(net * fiat_rate).quantize(Decimal("0.01"))` with InvalidOperation:
#      a raw traceback out of the middle of main(), AFTER Tor was verified and
#      the oracle queried over it. gs_common.decimal_env exists for exactly
#      this and its docstring names the other three call sites it fixed; this
#      was the fourth, half-applying the lesson.
#
#  (b) The block that exists to "Name the ACTUAL failure" instead of blaming
#      Tor only ever saw failures that RAISE. A Bisq response that is HTTP 200,
#      parses cleanly and simply carries no XMR market falls out of the try
#      with _bisq_err unbound -- so the operator was told "Check Tor
#      connectivity" about a request that succeeded over a working circuit.
#      And the message said "did not fail on the network" and then "Check Tor
#      connectivity" in the same breath.
print("\n-- exit_strategy_simulator: the two its own comments named --")
_ESS = load("exit_strategy_simulator")
_ESS.integrity_log = lambda *a, **k: None


def _ess_amount(v):
    """What the shipped CLI says about GS_EXIT_AMOUNT=v, before Tor."""
    _e = dict(os.environ)
    _e["GS_EXIT_AMOUNT"] = v
    _e["PYTHONPATH"] = REPO
    r = subprocess.run(
        [sys.executable, os.path.join(REPO, "exit_strategy_simulator"),
         "--tor-proxy", "socks5h://127.0.0.1:9"],
        capture_output=True, text=True, timeout=120, env=_e,
        cwd=tempfile.mkdtemp())
    return (r.stdout + r.stderr)


_A400 = _ess_amount("1e400")
check("ess/amount: REPRODUCED -- 1e400 is FINITE and POSITIVE, so the old "
      "is_finite/positive pair let it through",
      Decimal("1e400").is_finite() and Decimal("1e400") > 0)



def _quantize_raises(v):
    """Does the fiat conversion actually blow up on this amount? Driven."""
    try:
        (Decimal(v) * Decimal("150")).quantize(Decimal("0.01"))
        return False
    except InvalidOperation:
        return True


check("ess/amount: ...and it really would have crashed the fiat conversion "
      "the old guards let it reach", _quantize_raises("1e400"))
check("ess/amount: NON-VACUITY -- an ordinary amount does not crash it",
      not _quantize_raises("2.5"))
check("ess/amount: an absurd amount is now REFUSED with a sentence, not a "
      "traceback", "implausibly large" in _A400 and "Traceback" not in _A400)
for _v, _needle in (("NaN", "not a finite number"),
                    ("Infinity", "not a finite number"),
                    ("-5", "must be positive"),
                    ("0", "must be positive"),
                    ("abc", "is not a number")):
    _o = _ess_amount(_v)
    check(f"ess/amount: GS_EXIT_AMOUNT={_v} -> a message, never a traceback",
          _needle in _o and "Traceback" not in _o)
# NON-VACUITY: a real amount must still get through to the Tor gate, or the
# checks above would pass on a tool that refuses everything.
_OK = _ess_amount("2.5")
check("ess/amount: NON-VACUITY -- an ordinary amount still passes validation "
      "and reaches the Tor gate",
      "implausibly large" not in _OK and "not a number" not in _OK
      and "Tor" in _OK)
_ESS_SRC = Path(os.path.join(REPO, "exit_strategy_simulator")).read_text()
check("ess/amount: the shared validator is used, not a fourth hand-rolled "
      "parse", "decimal_env(_src, _amt, positive=True," in _ESS_SRC
      and "max_value=XMR_ABSURD_TOTAL" in _ESS_SRC)
# The label is no longer the hard-coded variable name, and that is a BEHAVIOUR
# worth driving rather than a string worth grepping: decimal_env puts the label
# at the front of every refusal it writes, so hard-coding "GS_EXIT_AMOUNT" sent
# an operator who typed a bad POSITIONAL to go unset a variable they never set.


def _ess_positional(v):
    """What the shipped CLI says about a bad positional, with NO env set."""
    _e = {k: x for k, x in os.environ.items() if k != "GS_EXIT_AMOUNT"}
    _e["PYTHONPATH"] = REPO
    r = subprocess.run(
        [sys.executable, os.path.join(REPO, "exit_strategy_simulator"),
         v, "--tor-proxy", "socks5h://127.0.0.1:9"],
        capture_output=True, text=True, timeout=120, env=_e,
        cwd=tempfile.mkdtemp())
    return (r.stdout + r.stderr)


# 1e400, not "abc": argparse's own type=decimal_arg rejects a non-number before
# main() runs, so a bad positional has to be one that PARSES to reach the line
# under test. 1e400 is finite and positive and fails only on max_value.
_APOS = _ess_positional("1e400")
check("ess/amount: a bad POSITIONAL is diagnosed as the off-ramp amount, not "
      "as an environment variable the operator never set",
      "The off-ramp amount is implausibly large" in _APOS
      and "GS_EXIT_AMOUNT is" not in _APOS)
# NON-VACUITY: when the variable really IS the source, it must still be named,
# or the check above passes on a tool that never mentions it at all.
check("ess/amount: NON-VACUITY -- a bad ENV value is still diagnosed by "
      "variable name", "GS_EXIT_AMOUNT is implausibly large" in _A400)

# (b) THE ORACLE DIAGNOSIS.
_ESS.integrity_log = lambda *a, **k: None


def _oracle(fn):
    _ESS.safe_get = fn
    try:
        _ESS.fetch_prices("socks5h://127.0.0.1:9")
    except SystemExit as _e:
        return str(_e)
    return ""


def _cg_down(u, p):
    if "coingecko" in u:
        raise ConnectionError("coingecko down")
    return {"data": [{"currencyCode": "USD", "price": 60000.0},
                     {"currencyCode": "EUR", "price": 55000.0}]}


def _all_down(u, p):
    raise ConnectionError("no route")


def _both(cg_exc, bisq):
    """CoinGecko fails one way, Bisq another. Returns the refusal text."""
    def _sg(u, p):
        if "coingecko" in u:
            raise cg_exc
        if isinstance(bisq, Exception):
            raise bisq
        return bisq
    return _oracle(_sg)


_BISQ_NOXMR = {"data": [{"currencyCode": "USD", "price": 60000.0},
                        {"currencyCode": "EUR", "price": 55000.0}]}
_NOXMR = _oracle(_cg_down)
check("ess/oracle: REPRODUCED -- a Bisq reply that parses but carries no XMR "
      "market no longer reports a Tor problem",
      "did not fail on the network" in _NOXMR)
check("ess/oracle: ...and it names WHICH market was missing and what did come "
      "back",
      "carried no XMR market at all" in _NOXMR and "btc_usd" in _NOXMR)
_NET = _oracle(_all_down)
check("ess/oracle: NON-VACUITY -- a genuine network failure STILL says to "
      "check Tor", "Check Tor connectivity" in _NET
      and "did not fail on the network" not in _NET)
# The 200-char clip: the diagnosis this file composes must survive to the
# operator. A 60-char clip cut it at "carried no XMR".
check("ess/oracle: the composed diagnosis is not truncated before its useful "
      "half", "codes returned:" in _NOXMR)

# ABSENT vs UNUSABLE. `prices` is only populated when the price ALSO passes the
# (0, ABSURD_RATE] guard, so the message inferred "no XMR market" from an entry
# that WAS there and quoted 0, or a negative, or 1e30.
for _bad, _shape in ((0, "zero"), (-1, "negative"), (1e30, "above ABSURD_RATE")):
    _UNUSABLE = _both(ConnectionError("cg"),
                      {"data": [{"currencyCode": "XMR", "price": _bad},
                                {"currencyCode": "USD", "price": 60000.0}]})
    check(f"ess/oracle: an XMR market quoting a {_shape} price is reported as "
          f"a bad PRICE, not as a missing market",
          "DID carry an XMR market" in _UNUSABLE
          and "carried no XMR market" not in _UNUSABLE)
# NON-VACUITY: a genuinely absent market must still be called absent, or the
# checks above pass on a tool that never says "missing" at all.
check("ess/oracle: NON-VACUITY -- a genuinely absent market is still reported "
      "as absent, and names the codes that DID come back",
      "carried no XMR market at all" in _NOXMR
      and "codes returned: EUR, USD" in _NOXMR)

# THE REMEDY FOLLOWS BOTH DIAGNOSES. It was computed from the Bisq failure
# alone, so a run where CoinGecko never got a packet back and Bisq answered
# with an unusable payload printed "Tor is not the problem".
_MIXED = _both(ConnectionError("cg down"), _BISQ_NOXMR)
check("ess/oracle: REPRODUCED -- CoinGecko's failure is now reported too, not "
      "swallowed into the integrity chain",
      "CoinGecko was tried first and failed on the NETWORK" in _MIXED)
check("ess/oracle: ...and the mixed case no longer says 'Tor is not the "
      "problem' about a run whose first oracle was unreachable",
      "CHECK BOTH" in _MIXED and "Tor is not the problem" not in _MIXED)
_BOTH_NET = _both(ConnectionError("cg"), ConnectionError("bisq"))
_BOTH_FMT = _both(ValueError("cg json"), _BISQ_NOXMR)
# THE OTHER MIXED CASE, and it is the one that separates the two conditions.
# With Bisq dying on the NETWORK and CoinGecko on the payload, a remedy
# computed from the Bisq failure alone says "Check Tor connectivity" -- which
# is half right and hides that the other oracle answered fine and sent
# something unusable. Only this shape tells `_network` apart from
# `_network and _cg_net`; the first mixed case above gives the same answer
# either way, so a test with only that one cannot see the difference.
_MIXED2 = _both(ValueError("cg json"), ConnectionError("bisq down"))
check("ess/oracle: the OTHER mixed case is caught too -- Bisq unreachable "
      "while CoinGecko answered with something unusable",
      "CHECK BOTH" in _MIXED2
      and "Check Tor connectivity and retry." not in _MIXED2)
check("ess/oracle: ...and it names CoinGecko's failure as a RESPONSE problem, "
      "not a network one",
      "CoinGecko was tried first and failed on the response" in _MIXED2)
check("ess/oracle: NON-VACUITY -- both-network still says exactly 'Check Tor "
      "connectivity'",
      "Check Tor connectivity" in _BOTH_NET and "CHECK BOTH" not in _BOTH_NET)
check("ess/oracle: NON-VACUITY -- both-payload still says exactly 'Tor is not "
      "the problem'",
      "Tor is not the problem" in _BOTH_FMT and "CHECK BOTH" not in _BOTH_FMT)
check("ess/oracle: ...and the three remedies are mutually exclusive, so one "
      "run never prints two",
      all(["Check Tor connectivity" in _t,
           "Tor is not the problem" in _t,
           "CHECK BOTH" in _t].count(True) == 1
          for _t in (_BOTH_NET, _BOTH_FMT, _MIXED, _MIXED2)))

# ===========================================================================
#  12. A "LIVE" PRICE THAT VALUED THE HOLDING AT NOTHING
# ===========================================================================
#
# The Bisq branch gates each entry on `price > 0`, which 1e-9 satisfies, and
# the derived xmr_usd = xmr_btc * btc_usd inherits it. Nothing downstream
# looked at the magnitude, so main() RETURNED NORMALLY printing
#
#     Value       : 0.00 USD
#     Prices from : bisq_oracle (live)
#
# and wrote exitplan_v1.json with amount_out_fiat "0.00" -- from a file whose
# header promises "The PRICE is fetched live ... or the tool aborts. It never
# serves a made-up price", and whose Bisq comment already records this exact
# outcome happening once before via the inversion bug.
#
# AND the coarsening defeated itself: oracle_prices is rounded to whole units
# so the 10-minute timestamp bucket cannot be inverted from a spot rate, while
# amount_out_fiat sat beside it at CENT precision next to amount_in_xmr,
# fee_pct and slippage_pct -- and net is a pure function of those three.
print("\n-- a live rate that values the holding at nothing --")


def _ess_run(price_xmr, price_usd, gross="13.37"):
    _E = load("exit_strategy_simulator")
    for _n in ("integrity_log", "install_signal_handlers"):
        setattr(_E, _n, lambda *a, **k: None)
    _E.verify_tor = lambda p: None
    _E.validate_proxy = lambda p: {"http": p, "https": p}
    _E.shutdown_requested = lambda: False
    _E.safe_get = lambda u, p: (
        (_ for _ in ()).throw(ConnectionError("cg")) if "coingecko" in u
        else {"data": [{"currencyCode": "XMR", "price": price_xmr},
                       {"currencyCode": "USD", "price": price_usd}]})
    _d = tempfile.mkdtemp()
    _prev = os.getcwd()
    os.chdir(_d)
    os.environ["GS_EXIT_AMOUNT"] = gross
    _argv = sys.argv
    sys.argv = ["ess", "--tor-proxy", "socks5h://127.0.0.1:9",
                "--outfile", os.path.join(_d, "exitplan_v1.json")]
    _b = io.StringIO()
    _rc = "returned"
    try:
        with contextlib.redirect_stdout(_b):
            _E.main()
    except SystemExit as _e:
        _rc = f"refused: {_e}"
    finally:
        sys.argv = _argv
        os.chdir(_prev)
        os.environ.pop("GS_EXIT_AMOUNT", None)
    return _b.getvalue(), _rc, Path(_d) / "exitplan_v1.json"


_o12, _rc12, _p12 = _ess_run(1e-9, 1e-9)
check("ess/zero: a rate that values the holding at 0.00 is REFUSED, not "
      "reported as live", "refused:" in _rc12
      and "cannot round to zero" in _rc12)
check("ess/zero: ...and no plan file is written claiming a live 0.00 "
      "valuation", not _p12.exists())
check("ess/zero: ...and the screen never printed 'Value : 0.00'",
      "Value       : 0.00" not in _o12)
# NON-VACUITY: a realistic rate must still produce a plan, or the check above
# passes on a tool that refuses everything.
# A NON-ROUND TRUE RATE, deliberately. The old fixture used 0.005 * 33000 =
# exactly 165, so "the stored coarse rate" and "the true spot rate" were the
# same number and no check here could tell them apart -- the coarsening could
# have been deleted entirely and this block would have stayed green.
# 0.00251937 * 65432.10 = 164.8476697770, which rounds to a different figure.
#
# .quantize(Decimal("0.01")) because that is what fetch_prices ACTUALLY hands
# back: the Bisq branch derives xmr_usd = xmr_btc * btc_usd and stores it at
# cent precision, so the raw product (164.8476697770) is not a rate this tool
# ever holds. Computing the expected screen figure from the raw product missed
# the printed one by three cents -- small, and a test that "nearly" matches is
# a test that will be loosened next time instead of read.
_TRUE12 = (Decimal("0.00251937") * Decimal("65432.10")).quantize(Decimal("0.01"))
_o12b, _rc12b, _p12b = _ess_run(0.00251937, 65432.10)
check("ess/zero: NON-VACUITY -- a realistic rate still valuates and writes "
      "the plan", _rc12b == "returned" and _p12b.exists()
      and "Value" in _o12b)
_j12 = json.loads(_p12b.read_text())
_net12 = Decimal(_j12["net_xmr"])
# THE COARSENING. The exact figure is still PRINTED; the file stores a figure
# derived from the coarsened rate, so inverting it returns that rate and not
# the spot rate the 10-minute timestamp bucket exists to hide.
# RECOMPUTED FROM THE FILE'S OWN FULL-PRECISION FIELDS, not from net_xmr.
# net_xmr is stored at 4dp and the screen figure comes from the full-precision
# net, so `net_xmr * rate` misses by a few cents -- the rate multiplies the
# rounding. gross, fee_pct and slippage_pct are all in the file at full
# precision and net is exactly `gross - gross*fee - gross*slip` (the identity
# the amount_out_fiat comment names as the inversion), so this is exact and
# needs no tolerance.
_netfull12 = (Decimal(_j12["amount_in_xmr"])
              - Decimal(_j12["amount_in_xmr"]) * Decimal(_j12["fee_pct"])
              - Decimal(_j12["amount_in_xmr"]) * Decimal(_j12["slippage_pct"]))
_screen12 = str((_netfull12 * _TRUE12).quantize(Decimal("0.01")))
check(f"ess/coarse: the terminal still shows the exact figure the operator "
      f"needs ({_screen12}), computed from the TRUE rate",
      _screen12 in _o12b)
check("ess/coarse: NON-VACUITY -- the coarse figure the FILE stores is a "
      "different number, so the check above is not matching that",
      _j12["amount_out_fiat"] != _screen12)
_rec12 = Decimal(_j12["amount_out_fiat"]) / _net12
_stored12 = Decimal(_j12["oracle_prices"]["xmr_usd"])
check(f"ess/coarse: inverting amount_out_fiat recovers {_rec12.quantize(Decimal('0.0001'))}"
      f" -- the COARSE rate already stored beside it, not the true "
      f"{_TRUE12.quantize(Decimal('0.0001'))}",
      abs(_rec12 - _stored12) < Decimal("0.01")
      and abs(_rec12 - _TRUE12) > Decimal("0.1"))
# NON-VACUITY: computed from the TRUE rate at cent precision -- what this field
# used to hold -- the same inversion comes back exact, which is what makes
# deriving it from the coarsened rate worth anything.
_cent12 = (_net12 * _TRUE12).quantize(Decimal("0.01")) / _net12
check("ess/coarse: NON-VACUITY -- from the true rate at cent precision the "
      "same inversion returns the spot rate to 4dp",
      abs(_cent12 - _TRUE12) < Decimal("0.001"))
# AND THE FIELD THAT USED TO BE EXEMPT. Whole-unit rounding is an ABSOLUTE
# blur, so btc_usd at ~65000 kept eight significant figures while xmr_usd at
# ~165 kept three -- the note claimed neither handed back a spot rate.
_btc12 = Decimal(_j12["oracle_prices"]["btc_usd"])
_btc_blur = abs(_btc12 - Decimal("65432.10")) / Decimal("65432.10")
check(f"ess/coarse: btc_usd is blurred RELATIVELY too ({_btc_blur * 100:.4f}%), "
      f"not left at whole units where it pinned the instant to seconds",
      _btc_blur > Decimal("0.0001"))
check("ess/coarse: NON-VACUITY -- whole-unit rounding really would have left "
      "btc_usd essentially exact",
      abs(Decimal("65432.10").quantize(Decimal("1")) - Decimal("65432.10"))
      / Decimal("65432.10") < Decimal("0.00001"))
check("ess/coarse: ...and the XMR rate is unchanged by the switch, so the "
      "field the coarsening was written for did not regress",
      _stored12 == _TRUE12.quantize(Decimal("1")))
# THE ZERO IT USED TO INVENT. Rounding the PRODUCT to whole units wrote "0"
# for a holding genuinely worth 0.40 -- one step after the guard that refuses
# a zero valuation. Deriving from the rate cannot do that.
_o12c, _rc12c, _p12c = _ess_run(0.00251937, 65432.10, gross="0.0025")
check("ess/coarse: a small but real holding is not recorded as nothing",
      _rc12c == "returned" and _p12c.exists()
      and Decimal(json.loads(_p12c.read_text())["amount_out_fiat"]) > 0)
check("ess/coarse: NON-VACUITY -- rounding the product to whole units, which "
      "is what this replaced, really would have written 0 for it",
      (Decimal("0.0025") * _TRUE12).quantize(Decimal("1")) == 0)
check("ess/coarse: the note states a LIMIT rather than claiming the "
      "timestamp is protected",
      "Residual" in _j12["oracle_prices_note"]
      and "approximate" in _j12["oracle_prices_note"])
check("ess/coarse: ...and it names the RELATIVE blur, which is the property "
      "whole units did not have",
      "significant" in _j12["oracle_prices_note"]
      and "btc_usd" in _j12["oracle_prices_note"])


# ===========================================================================
#  13. "THE VAULT SEALS TO IT" -- ABOUT A KEY IT HAD NEVER READ
# ===========================================================================
#
# _refuse_existing decided which sentence to print from `bool(existing)` -- the
# vault naming SOME delivery key -- and nothing ever read the key out of the
# file at --out. Three states reach it and it had two branches, so a stale copy
# or another vault's key produced "already exists and the vault seals to it":
# a confident false statement about the one file that decides whether any slip
# can ever be opened.
print("\n-- the delivery key refusal reads the key it is talking about --")
_DK = load("gs_delivery_key")
_DK_SRC13 = Path(os.path.join(REPO, "gs_delivery_key")).read_text()
import nacl.public as _NP13                                  # noqa: E402


def _dk_states(file_key, vault_key, with_pub=True):
    _d = Path(tempfile.mkdtemp())
    _out = _d / "gs_delivery.key"
    _c = P.lock_keyfile(
        {"role": "delivery", "delivery_secret": bytes(file_key).hex(),
         "vault_public": bytes(_NP13.PrivateKey.generate().public_key).hex()},
        b"pw", kdf="interactive", role="delivery")
    if with_pub:
        _c["delivery_public"] = bytes(file_key.public_key).hex()
    GSC.atomic_write_json(_c, _out, perms=0o400)
    _v = _d / "vault.key"
    _pl = {"role": "thinkpad",
           "secret": bytes(_NP13.PrivateKey.generate()).hex()}
    if vault_key is not None:
        _pl["delivery_public"] = bytes(vault_key.public_key).hex()
    _v.write_text(json.dumps(P.lock_keyfile(_pl, b"", role="thinkpad")))
    os.chmod(_v, 0o400)

    class _A:
        pass
    _a = _A()
    _a.out = str(_out)
    _a.vault_key = str(_v)
    _a.kdf = "interactive"
    _a.replace = False
    _a._getpass = lambda p: "pw"
    _a._input = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            _DK.cmd_new(_a)
        return "proceeded"
    except SystemExit as _e:
        return str(_e)


_A13, _B13 = _NP13.PrivateKey.generate(), _NP13.PrivateKey.generate()
_MIS = _dk_states(_B13, _A13)
check("dk/identity: REPRODUCED -- a file holding a DIFFERENT key no longer "
      "gets 'the vault seals to it'",
      "is NOT the delivery key this vault seals to" in _MIS
      and "and the vault seals to it" not in _MIS)
check("dk/identity: ...and it prints BOTH keys so the operator can see which "
      "is which", _MIS.count("...") >= 2 and "the vault seals to :" in _MIS)
_MATCH = _dk_states(_A13, _A13)
# "RECORDS", not "is". The head field is outside the sealed box, so a match is
# what the file CLAIMS -- see _refuse_existing. The sentence changed with it.
check("dk/identity: NON-VACUITY -- the MATCHING key still gets its own "
      "sentence, and it no longer overstates what a head field proves",
      "RECORDS the delivery key this vault seals to" in _MATCH
      and "is NOT the delivery key" not in _MATCH)
_UNK = _dk_states(_B13, _A13, with_pub=False)
check("dk/identity: a keyfile minted before the public field says the answer "
      "is UNKNOWN rather than guessing",
      "CANNOT be" in _UNK and "checked from here" in _UNK)
# ...AND SAYS WHICH KIND OF UNKNOWN. _file_delivery_public returned a bare ""
# and swallowed every failure into it, so this branch stated ONE cause -- "it
# was minted before that field existed" -- for six different shapes. Three of
# them are the TAMPERED-head shape, where an explanation that closes the
# question is worse than none.
_DKP = _DK._file_delivery_public
_d13u = Path(tempfile.mkdtemp())


def _dk_why(body):
    _p = _d13u / "k.json"
    _p.write_text(body)
    return _DKP(_p)[1]


for _body, _want, _shape in (
        (json.dumps({"v": 1, "sealed": "aa"}), "absent",
         "the field is genuinely missing -- the only shape it described"),
        (json.dumps({"v": 1, "delivery_public": "ab" * 16}), "malformed",
         "a truncated hex value: a head somebody edited"),
        (json.dumps({"v": 1, "delivery_public": "not-hex"}), "malformed",
         "a non-hex value"),
        (json.dumps({"v": 1, "delivery_public": 12345}), "malformed",
         "a number where a hex string belongs"),
        ("{{{ truncated", "unreadable", "the file does not parse at all"),
        ("", "unreadable", "the file is empty")):
    check(f"dk/identity: UNKNOWN is reported as {_want!r} -- {_shape}",
          _dk_why(_body) == _want)
# NON-VACUITY: a real, well-formed public key still comes back with no reason,
# or "reports a cause" would be true of a function that always reports one.
check("dk/identity: NON-VACUITY -- a well-formed head returns the key and NO "
      "reason",
      _DKP.__call__ and _dk_why(
          json.dumps({"v": 1, "delivery_public": "ab" * 32})) == ""
      and _DK._file_delivery_public(_d13u / "k.json")[0] == "ab" * 32)
# And the operator-facing sentence must carry the distinction, not just the
# return value -- the whole defect was in what was PRINTED.
check("dk/identity: ...and the refusal no longer asserts 'minted before that "
      "field existed' for a head that was edited",
      "was minted before that field existed" not in _DK_SRC13
      or "delivery_public field at all" in _DK_SRC13)
_NOV = _dk_states(_B13, None)
check("dk/identity: NON-VACUITY -- the 'vault names no delivery key' branch "
      "is untouched", "does NOT name a delivery" in _NOV)
# The public key must actually be written, or the comparison can never fire.
_d13 = Path(tempfile.mkdtemp())
_v13 = _d13 / "vault.key"
_vsk13 = _NP13.PrivateKey.generate()
_v13.write_text(json.dumps(P.lock_keyfile(
    {"role": "thinkpad", "secret": bytes(_vsk13).hex()}, b"", role="thinkpad")))
os.chmod(_v13, 0o400)


class _A13c:
    pass


_a13 = _A13c()
_a13.out = str(_d13 / "gs_delivery.key")
_a13.vault_key = str(_v13)
_a13.kdf = "interactive"
_a13.replace = False
_a13._getpass = lambda p: "pw"
_a13._input = None
with contextlib.redirect_stdout(io.StringIO()):
    _DK.cmd_new(_a13)
_head13 = json.loads(Path(_a13.out).read_text())
check("dk/identity: a freshly minted delivery key records its PUBLIC key in "
      "the container head", len(bytes.fromhex(_head13["delivery_public"])) == 32)
check("dk/identity: ...and that head field is the vault's delivery_public, so "
      "the two agree by construction",
      _head13["delivery_public"]
      == json.loads(_v13.read_text())["plain"]["delivery_public"])
check("dk/identity: ...and the file still OPENS -- the extra head field does "
      "not change how it unlocks",
      P.unlock_keyfile(_head13, b"pw").get("role") == "delivery")

# ===========================================================================
#  14. THE RELAY VALIDATED ITS DELAY IN ONE PATH AND COERCED IT IN THE OTHER
# ===========================================================================
#
# broadcast_signed_xmr reads a per-TX delay from the signed manifest, strictly:
# "a float, a bool or a negative index means it was tampered with or corrupted,
# and coercing it would silently mis-key a transaction's delay". When the
# manifest carries no delays it falls back to recovering them from an unsigned
# plan in ./unsigned -- and there it did `int(tx["delay"])` inside a
# try/except (TypeError, ValueError). int() COERCES, so that except never fired
# for the values the manifest rule exists to catch.
#
# The unsigned plan is read off local disk and is not signed at all, so it is a
# WEAKER trust boundary than the manifest, and it was the one validated less.
print("\n-- the relay's two delay readers apply one rule --")
_BX = load("broadcast_signed_xmr")

_HOSTILE = [(True, "a bool -> int(True) is 1"),
            (3600.9, "a float -> silently truncated"),
            (-500, "negative -> a delay that is not a delay"),
            ("604800", "a numeric string"),
            (10 ** 12, "~31,700 years: the relay parks signed TXs for ever")]
for _v, _why in _HOSTILE:
    check(f"relay/delay: {_v!r} is refused ({_why})", not _BX.delay_is_sane(_v))
    # REPRODUCED: the old expression accepted every one of them.
    _old_ok = True
    try:
        int(_v)
    except (TypeError, ValueError):
        _old_ok = False
    check(f"relay/delay: REPRODUCED -- the old int() coercion accepted {_v!r}",
          _old_ok)
# NON-VACUITY: real delays must still be honoured, or the relay would refuse
# every plan and the timing decorrelation would be gone in the other direction.
for _v in (0, 1, 3600, 604800):
    check(f"relay/delay: NON-VACUITY -- a real delay of {_v}s is still accepted",
          _BX.delay_is_sane(_v))
check("relay/delay: the cap is exactly MAX_PLANNED_DELAY, not an off-by-one",
      _BX.delay_is_sane(_BX.MAX_PLANNED_DELAY)
      and not _BX.delay_is_sane(_BX.MAX_PLANNED_DELAY + 1))
# The manifest reader keeps its own over-cap sentence, so it asks the
# type-and-sign half only. Both halves must still be one rule.
check("relay/delay: the manifest reader takes the same rule minus the cap it "
      "reports itself",
      _BX.delay_is_sane(10 ** 12, cap=False)
      and not _BX.delay_is_sane(-1, cap=False)
      and not _BX.delay_is_sane(3600.9, cap=False))
# THE THIRD READER. GhostSpiral sizes the kill timeout it gives the broadcast
# child from the same field, reading the UNSIGNED plan off local disk -- the
# weakest of the three boundaries -- and it was the one still coercing. It does
# not mis-time a transaction; it defeats the timeout that kills a hung child.
_GS_TXS = [{"delay": 300}, {"delay": 300}]


def _timeout_old(ptxs):
    """The shipped expression, kept so the claim below is measured."""
    return sum(max(0, int(t.get("delay") or 0)) for t in ptxs)


def _timeout_new(ptxs):
    """What GhostSpiral does now: refuse rather than coerce."""
    total = 0
    for t in ptxs:
        d = t.get("delay") or 0
        if not GSC.delay_is_sane(d):
            raise ValueError(d)
        total += d
    return total


for _v, _cost in ((10 ** 12, "~31,700 years -- the child is never killed"),
                  ("604800", "a week bought with a string"),
                  (True, "a bool"), (3600.9, "a float"), (-500, "a negative")):
    check(f"relay/delay: a plan delay of {_v!r} no longer sizes the kill "
          f"timeout ({_cost})",
          not GSC.delay_is_sane(_v))
check("relay/delay: REPRODUCED -- the shipped expression turned 10**12 into a "
      "31,700-year broadcast timeout",
      _timeout_old([{"delay": 10 ** 12}]) == 10 ** 12)
_fallback_applies = False
try:
    _timeout_new([{"delay": 10 ** 12}])
except ValueError:
    _fallback_applies = True
check("relay/delay: ...and the replacement raises instead, so the caller's "
      "conservative fallback applies", _fallback_applies)
check("relay/delay: NON-VACUITY -- a sane plan is summed exactly as before",
      _timeout_new(_GS_TXS) == _timeout_old(_GS_TXS) == 600)
_GSS = Path(os.path.join(REPO, "GhostSpiral")).read_text()
check("relay/delay: ...and GhostSpiral takes the SHARED rule rather than a "
      "third private copy",
      "delay_is_sane(_d)" in _GSS
      and "isinstance(value, bool)" not in _GSS)

# THE WRITER, WHICH ACCEPTED WHAT THE READER REFUSES. airgap_tx_signer puts
# `delay` verbatim into unsigned_manifest.json and carries it verbatim into
# signed_manifest_v1.json, and neither of its two validators looked at it --
# while broadcast calls that manifest "the sign->relay trust boundary" and
# refuses the same values there. Signing is the air-gapped, manual half of this
# toolchain, so the refusal landed after every blob had been built.
_SGN = load("airgap_tx_signer")
_SGN_TX = {"src": "addr", "src_index": 1, "dst": "d", "amt": "1.0"}


def _signer_takes(delay, entries=False):
    _t = dict(_SGN_TX)
    if delay is not None:
        _t["delay"] = delay
    try:
        if entries:
            _od = tempfile.mkdtemp()
            _f = os.path.join(_od, "tx_0.unsigned")
            Path(_f).write_text("x")
            _SGN._validate_manifest_entries(
                [{"idx": 0, "file": _f, "hash": "a" * 64,
                  **({} if delay is None else {"delay": delay})}], Path(_od))
        else:
            _SGN._validate_plan([_t], phase="create")
        return True
    except SystemExit:
        return False


for _v, _why in _HOSTILE:
    check(f"relay/delay: the SIGNER refuses {_v!r} too, so the batch is not "
          f"built before the relay rejects it ({_why})",
          not _signer_takes(_v))
    check(f"relay/delay: ...and its manifest validator refuses {_v!r} as well, "
          f"for a manifest edited between create and sign",
          not _signer_takes(_v, entries=True))
# NON-VACUITY: the signer must still accept every legitimate shape, or it would
# refuse every plan and the checks above would be meaningless.
for _v in (None, 0, 300, 604800):
    check(f"relay/delay: NON-VACUITY -- the signer still accepts {_v!r}",
          _signer_takes(_v) and _signer_takes(_v, entries=True))
check("relay/delay: NON-VACUITY -- the signer's bound is the SHARED one, so "
      "the two tools cannot disagree about the edge",
      _signer_takes(GSC.MAX_PLANNED_DELAY)
      and not _signer_takes(GSC.MAX_PLANNED_DELAY + 1))
_SGS = Path(os.path.join(REPO, "airgap_tx_signer")).read_text()
check("relay/delay: ...and the signer imports the rule rather than restating "
      "it", "delay_is_sane, MAX_PLANNED_DELAY," in _SGS
      and "isinstance(value, bool)" not in _SGS)

# THE COPY THAT MATTERS. _canonical_plan covers `delay` and says why --
# "broadcast reads it from the manifest, so a swapped delay changes relay
# timing, which is an OPSEC property worth detecting" -- but the fingerprint is
# computed over the PLAN and broadcast reads the MANIFEST. Editing
# entries[i]["delay"] leaves the plan untouched, so the fingerprint matched
# perfectly and the relay schedule was rewritten anyway.
def _signing_manifest(mani_delays, plan_delays=(300, 300)):
    _od = Path(tempfile.mkdtemp())
    _plan = [{"src": "a", "src_index": _i, "dst": "d", "amt": "1.0",
              **({} if _d is None else {"delay": _d})}
             for _i, _d in enumerate(plan_delays)]
    _entries = []
    for _i, _d in enumerate(mani_delays):
        _f = _od / f"tx_{_i}.unsigned"
        _f.write_text("x")
        _e = {"idx": _i, "file": str(_f), "hash": "a" * 64}
        if _d is not None:
            _e["delay"] = _d
        _entries.append(_e)
    (_od / "unsigned_manifest.json").write_text(json.dumps(
        {"plan_fingerprint": _SGN._compute_plan_fingerprint(_plan),
         "entries": _entries}))
    try:
        _SGN._load_signing_manifest(_od, _plan)
        return ""
    except SystemExit as _e:
        return str(_e)


_SWAP = _signing_manifest([300, 86400])
check("relay/delay: REPRODUCED -- a manifest-only delay edit leaves the plan "
      "fingerprint MATCHING, so nothing before this caught it",
      "fingerprint mismatch" not in _SWAP)
check("relay/delay: ...and it is refused now, naming both values",
      "different 'delay' than the plan" in _SWAP
      and "plan says 300s, manifest says 86400s" in _SWAP)
check("relay/delay: ...and the refusal explains why the fingerprint could not "
      "see it", "computed over the PLAN" in _SWAP)
check("relay/delay: a DELETED manifest delay is caught too -- 0 is a schedule, "
      "not an absence",
      "plan says 300s, manifest says 0s" in _signing_manifest([300, None]))
# NON-VACUITY: an agreeing manifest must still load, and an absent delay on
# BOTH sides must not be read as a mismatch (phase_create writes 0 for it).
check("relay/delay: NON-VACUITY -- a manifest that agrees with its plan still "
      "loads", _signing_manifest([300, 300]) == "")
check("relay/delay: NON-VACUITY -- an absent plan delay against the 0 "
      "phase_create writes is NOT a mismatch",
      _signing_manifest([0, 0], plan_delays=(None, None)) == ""
      and _signing_manifest([None, None], plan_delays=(None, None)) == "")
check("relay/delay: ...and the _canonical_plan docstring no longer implies "
      "covering the field is the whole protection",
      "the MANIFEST" in _SGS and "_load_signing_manifest" in _SGS)

# CODE, NOT PROSE. `'int(tx["delay"])' not in src` went red against a correct
# fix, because the docstring and the inline comment both QUOTE the old
# expression to explain what changed.
#
# STRIPPED WITH tokenize, NOT BY LINE PREFIX. The previous version dropped only
# lines whose stripped form starts with "#" and its own comment claimed it
# stripped "comment and docstring lines" -- docstrings were left in entirely.
# It passed anyway because the one docstring quoting the old expression lived
# in the same file as the code being searched and the needle happened not to
# collide. That is a coincidence, not a check: any future docstring quoting a
# construct this asserts is absent would fail it for the wrong reason, which is
# exactly the trap the comment was written about.
_BXS = Path(os.path.join(REPO, "broadcast_signed_xmr")).read_text()
_GCS = Path(os.path.join(REPO, "gs_common.py")).read_text()


def _code_only(src: str) -> str:
    """Source with comments AND docstrings removed, by tokenising it."""
    out, prev_end, prev_type = [], (1, 0), tokenize.INDENT
    for ttype, tstr, (srow, scol), (erow, ecol), _ in tokenize.generate_tokens(
            io.StringIO(src).readline):
        if srow > prev_end[0]:
            prev_end = (srow, 0)
        _drop = (ttype == tokenize.COMMENT
                 # A STRING that follows a line break or an indent IS the whole
                 # statement -- a docstring or a bare string expression.
                 or (ttype == tokenize.STRING and prev_type in (
                     tokenize.INDENT, tokenize.NEWLINE, tokenize.NL,
                     tokenize.DEDENT, tokenize.ENCODING)))
        if not _drop:
            if scol > prev_end[1] and srow == prev_end[0]:
                out.append(" " * (scol - prev_end[1]))
            out.append(tstr)
        if ttype not in (tokenize.NL, tokenize.COMMENT):
            prev_type = ttype
        prev_end = (erow, ecol)
    return "".join(out)


_BXCODE, _GCCODE, _GSCODE = _code_only(_BXS), _code_only(_GCS), _code_only(_GSS)
check("relay/delay: ONE implementation, and it lives where all THREE readers "
      "can reach it",
      _GCCODE.count("isinstance(value, bool) or not isinstance(value, int)") == 1
      and "isinstance(value, bool) or not isinstance(value, int)" not in _BXCODE
      and "isinstance(value, bool) or not isinstance(value, int)" not in _GSCODE)
check("relay/delay: ...and no reader coerces any more",
      'by_idx[pos] = int(' not in _BXCODE
      and 'max(0, int(t.get("delay")' not in _GSCODE)
# NON-VACUITY, IN BOTH DIRECTIONS. The prose must still quote the old
# expressions (or the history is gone), and the stripper must actually be
# removing them (or the checks above are passing on a no-op).
check("relay/delay: NON-VACUITY -- the prose still QUOTES the old expressions, "
      "which is why the naive check had to go",
      'int(tx["delay"])' in _GCS and 'max(0, int(t.get("delay")' in _GSS)
check("relay/delay: NON-VACUITY -- the tokenising stripper really removes "
      "them, which line-prefix stripping did not",
      'int(tx["delay"])' not in _GCCODE
      and 'max(0, int(t.get("delay")' not in _GSCODE)
check("relay/delay: NON-VACUITY -- and it leaves real code alone",
      "def delay_is_sane(value, cap: bool = True) -> bool:" in _GCCODE)
check("relay/delay: ...and both relay readers call it",
      "delay_is_sane(delay, cap=False)" in _BXS
      and 'delay_is_sane(tx["delay"])' in _BXS)
check("relay/delay: the fallback DISCARDS a bad candidate rather than exiting "
      "-- a stray plan in ./unsigned must not stop a good relay",
      "by_idx = {}\n                        break" in _BXS)

# ===========================================================================
#  15. THE THREE FINDINGS FROM THE THIN-COVERAGE AUDIT, AND FOUR OF MY OWN
# ===========================================================================
print("\n-- the slip's timestamp, GPG, and counting the chain --")

# (a) gs_unseal: "I cannot tell how old this is" is not "it is fresh". `t` came
#     off the pairs file unchecked, so a float/str/bool/absent value made `age`
#     None -- no age line, no stale warning, and EXIT 0 on a quote that a real
#     int would have flagged as stale with exit 1.
_US15 = load("gs_unseal")
_D15 = "4" + "A" * 94


def _slip15(t, now):
    _b = {"b": "0.01", "d": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
          "m": f"=:XMR.XMR:{_D15}:0/1/0", "a": _D15, "x": "1.2", "h": "ab12"}
    if t is not None:
        _b["t"] = t
    _o = io.StringIO()
    with contextlib.redirect_stdout(_o):
        _rc = _US15.show(_b, now=now)
    return _rc, _o.getvalue()


_now15 = 1_700_000_000.0
_STALE = int(_now15 - 10800)                       # three hours old
_rc_int, _o_int = _slip15(_STALE, _now15)
check("slip/age: a real int timestamp still reports the age and flags a "
      "3-hour-old quote", _rc_int == 1 and "~180 min ago" in _o_int
      and "MINUTES OLD" in _o_int)
for _label, _t in (("a float", float(_STALE)), ("a string", str(_STALE)),
                   ("a bool", True), ("absent", None)):
    _rc, _o = _slip15(_t, _now15)
    check(f"slip/age: REPRODUCED -- with {_label} the SAME 3-hour-old quote "
          f"used to print no age and exit 0; it now says UNKNOWN and exits "
          f"non-zero", _rc == 1 and "UNKNOWN" in _o
          and "CANNOT BE ESTABLISHED" in _o)
    check(f"slip/age: ...and it says WHY ({_label})",
          "timestamp is" in _o)
# NON-VACUITY: a fresh quote must still pass cleanly, or "exit 1" is just what
# this tool always does now.
_rc_f, _o_f = _slip15(int(_now15 - 120), _now15)
check("slip/age: NON-VACUITY -- a fresh quote still exits 0 with a real age",
      _rc_f == 0 and "~2 min ago" in _o_f and "UNKNOWN" not in _o_f)
# A slip stamped in the FUTURE is unusable too -- every "N minutes old" from it
# is fiction.
_rc_fut, _o_fut = _slip15(int(_now15 + 3600), _now15)
check("slip/age: a slip stamped in the FUTURE is treated as unknown, not as "
      "fresh", _rc_fut == 1 and "FUTURE" in _o_fut)
# ...and the vault refuses to seal one at all, where the operator can see why.
_AG15 = load("gs_wake_agent")
check("slip/age: the vault validates `ts` before sealing, so a malformed "
      "pairs file is caught on the machine that can show it",
      "the quoted pair's 'ts' is not a usable timestamp"
      in Path(os.path.join(REPO, "gs_wake_agent")).read_text())

# (b) thor_swap_preparer: gnupg.GPG() raises OSError when the gpg BINARY is
#     absent -- not ImportError -- so the handler missed it, and the PLAINTEXT
#     bundle was already on disk.
_TS15 = Path(os.path.join(REPO, "thor_swap_preparer")).read_text()
check("gpg: the capability is checked at STARTUP, before any quote is fetched "
      "or plaintext written",
      "--gpg-recipient given but GPG cannot run" in _TS15
      and "Nothing has been fetched or written yet" in _TS15)
check("gpg: ...and the check is an ImportError branch AND a constructor "
      "branch, because an absent binary raises OSError not ImportError",
      "except ImportError:" in _TS15 and "gpg_unusable:" in _TS15)
check("gpg: every failure in the encrypt block now names the plaintext, not "
      "just the two somebody thought of",
      "gpg_broke_late:" in _TS15 and "gpg_write_failed:" in _TS15
      and "PARTIAL file" in _TS15)
# NON-VACUITY: the constructor really does raise OSError, so the branch is not
# guarding an impossible case.
try:
    import gnupg as _g15
    try:
        _g15.GPG(gpgbinary="/nonexistent/gpg")
        _raised = "nothing"
    except BaseException as _e15:
        _raised = type(_e15).__name__
    check(f"gpg: NON-VACUITY -- an absent binary really raises OSError, which "
          f"`except ImportError` cannot catch (got {_raised})",
          _raised == "OSError")
except ImportError:
    check("gpg: NON-VACUITY skipped -- python-gnupg is not installed here",
          False)

# (c) COUNTING THE CHAIN. chain_safe redacts the digits, so a per-index kind
#     writes N byte-identical lines and N is the batch size -- the run-structure
#     value chain_safe promises to withhold. Three sites in each of the two
#     sibling swap paths were still doing it.
for _f15, _stage in (("thor_swap_preparer", "thor"), ("GhostSpiral", "stage2")):
    _src15 = Path(os.path.join(REPO, _f15)).read_text()
    for _kind in ("expected_output_unreadable", "slippage_warn",
                  "memo_dest_mismatch"):
        check(f"chain/count: {_f15} logs {_kind} ONCE, not once per chunk",
              f'integrity_log_once("{_stage}", "{_kind}")' in _src15
              and f'{_kind}_{{i}}' not in _src15
              and f'{_kind}_{{idx}}' not in _src15)
# NON-VACUITY: the ABORTING per-index writes must be untouched -- exactly one
# is ever written, so they carry no count and the index is useful there.
check("chain/count: NON-VACUITY -- the aborting per-index writes still carry "
      "their index (they can only ever fire once)",
      'integrity_log("thor", f"slippage_ABORT_{i}:dev={deviation:.4f}")'
      in Path(os.path.join(REPO, "thor_swap_preparer")).read_text()
      and 'integrity_log("thor", f"no_deposit_{i}")'
      in Path(os.path.join(REPO, "thor_swap_preparer")).read_text())
# ...and memo_dest_mismatch is the subtle one: it is written BEFORE the abort
# check, so with --allow-unbound-memo the run continues and it repeats.
check("chain/count: memo_dest_mismatch is logged before the abort check, "
      "which is why --allow-unbound-memo made it repeat",
      "integrity_log_once(\"thor\", \"memo_dest_mismatch\")\n"
      "            if not args.allow_unbound_memo:"
      in Path(os.path.join(REPO, "thor_swap_preparer")).read_text())


_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
