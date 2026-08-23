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

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
