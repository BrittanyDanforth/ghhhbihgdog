#!/usr/bin/env python3
"""THE WHOLE WAKE CHANNEL, END TO END, OVER A REAL SOCKET.

Every other wake suite tests one side against a stand-in for the other:
test_wake_agent drives the agent against a Pending object it constructs itself,
and test_wake_doorbell drives the doorbell with M1s it seals itself. Both can
be green while the two halves do not fit -- a swapped key direction, a URL
built wrong, a status code one side never emits.

So this one wires the real things together:

  * the keyfiles are minted by running gs_wake_keys as a SUBPROCESS, not built
    as dicts in this file;
  * gs_doorbell.run_wake binds a real ThreadingHTTPServer and runs in a thread;
  * gs_wake_agent.run_once posts to it with the module's own post_record --
    real urllib, real HTTP, over 127.0.0.1;
  * the M2 the agent opens was sealed by the doorbell, and the M3 the doorbell
    reads was sealed by the agent.

Only the edges of the world are stubbed: the magic packet (a fake datagram
socket), the child tools, the resource and Tor probes, and the sleeps.
Everything between the two keyfiles is the shipped code.
"""
import importlib.machinery
import importlib.util
import io
import json
import os
import contextlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
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
from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_wake_endtoend.py")


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    sp = importlib.util.spec_from_loader(ld.name, ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    return m


A = load("gs_wake_agent")
DB = load("gs_doorbell")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeWOL:
    """Stands in for the datagram socket. Records the magic packet verbatim."""

    sent = []

    def setsockopt(self, *a):
        pass

    def sendto(self, pkt, addr):
        FakeWOL.sent.append((pkt, addr))
        return len(pkt)

    def close(self):
        pass


def mint_pair(port, artifact_dir):
    """Run the REAL pairing tool and return (dir, thinkpad_key, pi_key)."""
    d = tempfile.mkdtemp(prefix="wake_e2e_")
    r = subprocess.run(
        [sys.executable, os.path.join(REPO, "gs_wake_keys"), "--out", d,
         "--thinkpad-mac", "AA:BB:CC:DD:EE:FF",
         "--doorbell-host", "127.0.0.1", "--doorbell-port", str(port),
         "--artifact-dir", str(artifact_dir),
         "--amount-ladder", "0.01", "0.02", "0.05"],
        capture_output=True, text=True, cwd=d)
    if r.returncode != 0:
        raise AssertionError(f"pairing failed: {r.stdout}{r.stderr}")
    tp = json.loads(open(os.path.join(d, "gs_wake_thinkpad.key")).read())
    pi = json.loads(open(os.path.join(d, "gs_wake_pi.key")).read())
    return d, tp, pi


def agent_deps(bay, ran, **over):
    def child(argv, env_extra, budget):
        ran.append((list(argv), dict(env_extra or {})))
        if "create_receive_wallet" in " ".join(argv):
            (bay / f"wallet_e2e_{len(ran)}.json").write_text("{}")
        return 0, False

    base = dict(sleep=lambda s: None, clock=lambda: 0.0,
                rng=types.SimpleNamespace(randint=lambda a, b: a),
                run_child=child, verify_tor=lambda: None,
                account_count=lambda: 3,
                unit_is_active=lambda u: True, removable_devices=lambda: [],
                resource_check=lambda *a: True,
                tor_bootstrapped=lambda u: True, wipe_covers=lambda p: True)
    base.update(over)
    return base


def cycle(job, params, bay):
    """One full poke: doorbell in a thread, agent against it over HTTP."""
    port = free_port()
    kd, tp, pi = mint_pair(port, bay)
    FakeWOL.sent = []
    pending = {}

    def pi_side():
        args = types.SimpleNamespace(no_jitter=True)
        pending["p"] = DB.run_wake(args, pi, job, params,
                                   sock_factory=lambda: FakeWOL(),
                                   sleep=lambda s: time.sleep(0.02))

    t = threading.Thread(target=pi_side, daemon=True)
    t.start()
    # Wait for the doorbell to be listening -- run_wake BINDS before it wakes
    # anything, so a connection refused here would be a real defect, not a race.
    for _ in range(500):
        if FakeWOL.sent:
            break
        time.sleep(0.01)

    ran = []
    kf = Path(kd) / "gs_wake_thinkpad.key"
    args = types.SimpleNamespace(key=str(kf), dry_run=False)
    buf = io.StringIO()
    err = out = None
    with contextlib.redirect_stdout(buf):
        try:
            out = A.run_once(args, agent_deps(bay, ran))
        except (A.Refused, P.WakeError) as e:
            err = e
    t.join(timeout=30)
    return pending.get("p"), out, err, ran, buf.getvalue()


_cwd0 = os.getcwd()
_bay = Path(tempfile.mkdtemp(prefix="wake_e2e_bay_"))
os.chdir(_bay)

try:
    print("== receive_and_quote, both halves, real HTTP ==")
    p1, out1, err1, ran1, text1 = cycle("receive_and_quote",
                                        {"amount_slot": 2}, _bay)
    check("the agent finished the job", err1 is None and out1
          and out1[0] == "done" and out1[1] == "done")
    check("...and the DOORBELL heard it, sealed by the agent's own key",
          p1 is not None and p1.result
          and p1.result["status"] == "done")
    check("...naming the SAME handle the agent generated",
          p1.result["handle"] == out1[2]
          and P.HANDLE_RE.match(p1.result["handle"]))
    check("...and the doorbell reports success to the operator",
          DB.report(p1) == 0)
    check("a real magic packet went out first: 102 bytes, 6x0xFF then the MAC "
          "16 times", len(FakeWOL.sent) == 1
          and FakeWOL.sent[0][0] == b"\xff" * 6
          + bytes.fromhex("aabbccddeeff") * 16)
    check("...and it is 102 bytes", len(FakeWOL.sent[0][0]) == 102)

    check("both tools ran, in order, from the agent's own templates",
          len(ran1) == 2
          and os.path.basename(ran1[0][0][1]) == "create_receive_wallet"
          and os.path.basename(ran1[1][0][1]) == "thor_swap_preparer")
    check("the AMOUNT came off the ThinkPad's ladder by index and rode in the "
          "ENVIRONMENT, never on argv",
          ran1[1][1].get("GS_SWAP_AMOUNTS") == "0.05"
          and not any("0.05" in a for a in ran1[1][0]))
    check("...and the swap destination is a bundle THIS BOOT minted, not "
          "anything the doorbell named",
          "--dest-from-receive-wallet" in ran1[1][0]
          and ran1[1][0][ran1[1][0].index("--dest-from-receive-wallet") + 1]
          .startswith(str(_bay)))

    print("\n== the doorbell's queue depth is one, over the wire ==")
    # The first boot's M3 is DROPPED on the floor here, deliberately, for two
    # reasons at once: it keeps the doorbell listening (a result ends its
    # window, and then a second boot would meet a closed socket and report
    # "unreachable" -- true, but not the property under test), and it drives
    # the agent's "an undeliverable result is not a failure of the job" path
    # over real HTTP. The Pi's clock is injected so the thread can be released
    # on demand instead of sitting out the job budget.
    port2 = free_port()
    kd2, tp2, pi2 = mint_pair(port2, _bay)
    FakeWOL.sent = []
    hold = {}
    _clk = [0.0]

    def pi2_side():
        hold["p"] = DB.run_wake(types.SimpleNamespace(no_jitter=True), pi2,
                                "receive_new", {"count": 1},
                                sock_factory=lambda: FakeWOL(),
                                sleep=lambda s: time.sleep(0.02),
                                clock=lambda: _clk[0])

    t2 = threading.Thread(target=pi2_side, daemon=True)
    t2.start()
    for _ in range(500):
        if FakeWOL.sent:
            break
        time.sleep(0.01)

    def _drop_m3(url, path, rec, timeout=30):
        if path == "/result":
            return 0, b""
        return A.post_record(url, path, rec, timeout=timeout)

    kf2 = Path(kd2) / "gs_wake_thinkpad.key"
    a2 = types.SimpleNamespace(key=str(kf2), dry_run=False)
    r2a, r2b = [], []
    with contextlib.redirect_stdout(io.StringIO()):
        o2a = A.run_once(a2, agent_deps(_bay, r2a, post_record=_drop_m3))
        try:
            o2b, e2b = A.run_once(a2, agent_deps(_bay, r2b)), None
        except (A.Refused, P.WakeError) as e:
            o2b, e2b = None, e
    _clk[0] = 10.0 ** 9          # release the doorbell's result window
    t2.join(timeout=30)
    check("the first boot gets the job and finishes it", o2a and o2a[1] == "done")
    check("...even though its result never arrived: an undeliverable M3 is not "
          "a failed job, and the job either happened or did not",
          hold["p"] is not None and hold["p"].result is None)
    check("a SECOND boot against the same doorbell is refused: queue depth is "
          "one, and it is the doorbell that enforces it",
          o2b is None and e2b is not None and e2b.code == "no_job")
    check("...and it ran nothing", r2b == [])
    check("...and the doorbell RECORDED the second authenticated boot, which "
          "is what report() shows the operator",
          hold["p"].events.count("m1_second_ephemeral") == 1)
    _e2 = io.StringIO()
    with contextlib.redirect_stdout(_e2):
        DB.report(hold["p"])
    check("...and its report says both things: a second boot arrived, and "
          "nothing reported back",
          "different boot" in _e2.getvalue()
          and "never reported back" in _e2.getvalue())

    print("\n== nothing readable crosses to the Pi ==")
    _bay_files = " ".join(sorted(os.path.basename(f)
                                 for f in os.listdir(_bay)))
    check("the bundles and the slip stayed on the VAULT",
          "wallet_e2e_1.json" in _bay_files)
    _report = io.StringIO()
    with contextlib.redirect_stdout(_report):
        DB.report(p1)
    _rt = _report.getvalue()
    check("the doorbell's whole report to the operator is a job name and a "
          "4-hex handle: no address, no memo, no amount",
          "0.05" not in _rt and "wallet_" not in _rt
          and "thor_pairs" not in _rt and out1[2] in _rt)
finally:
    os.chdir(_cwd0)


_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
