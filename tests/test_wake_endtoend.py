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

#: interactive, not moderate: this suite pairs several times and moderate
#: would add minutes. The container is identical either way.
PW = b"end to end pairing passphrase"


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


def free_port_pair():
    return free_port()


def mint_pair(port, artifact_dir, kdf="interactive"):
    """Run the REAL two-box ceremony and return (dir, tp_payload, pi_payload).

    NOT a hand-built pair of dicts, and not one tool writing both files: the
    vault half runs as a real subprocess of gs_wake_keys, the Pi half runs
    gs_doorbell's own do_pair, and they talk over a real TCP socket. That is
    the only way to test the property the ceremony exists for -- that NO SECRET
    EVER CROSSES -- because a fixture that fabricates two keyfiles proves
    nothing about what moved between them.

    --mac / --broadcast are passed because the ceremony runs here on loopback,
    which has no usable hardware address. That is a supported path (the tool
    refuses rather than guessing when detection fails); the DETECTION itself is
    driven separately against this host's real interface below.
    """
    d = tempfile.mkdtemp(prefix="wake_e2e_")
    pport = free_port()
    v = subprocess.Popen(
        [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair",
         "--out", d, "--bind", "127.0.0.1", "--pair-port", str(pport),
         "--mac", "aa:bb:cc:dd:ee:ff", "--broadcast", "255.255.255.255",
         "--artifact-dir", str(artifact_dir),
         "--amount-ladder", "0.01", "0.02", "0.05"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, cwd=d)
    # Wait for the listener rather than sleeping a guess: a fixed sleep here
    # is a flaky suite on a loaded machine.
    for _ in range(400):
        try:
            probe = socket.create_connection(("127.0.0.1", pport), timeout=0.2)
            probe.close()
            break
        except OSError:
            time.sleep(0.05)

    seen = {}
    pi_args = types.SimpleNamespace(
        vault="127.0.0.1", pair_port=pport,
        key=os.path.join(d, "gs_wake_pi.key"), port=port, kdf=kdf)
    out = {}

    def pi_side():
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                out["rc"] = DB.do_pair(
                    pi_args, ask=lambda sas: (seen.setdefault("pi", sas), True)[1],
                    getpass_fn=lambda prompt: PW.decode())
        except BaseException as e:                           # noqa: BLE001
            out["rc"] = e

    t = threading.Thread(target=pi_side, daemon=True)
    t.start()
    try:
        vout, _ = v.communicate(input="yes\n", timeout=180)
    except subprocess.TimeoutExpired:
        v.kill()
        vout, _ = v.communicate()
    t.join(120)
    out["vault_stdout"] = vout
    out["pi_sas"] = seen.get("pi")
    tp_path = os.path.join(d, "gs_wake_thinkpad.key")
    pi_path = os.path.join(d, "gs_wake_pi.key")
    out["tp_container"] = (json.loads(open(tp_path).read())
                           if os.path.exists(tp_path) else None)
    out["pi_container"] = (json.loads(open(pi_path).read())
                           if os.path.exists(pi_path) else None)
    tp = P.unlock_keyfile(out["tp_container"]) if out["tp_container"] else None
    pi = P.unlock_keyfile(out["pi_container"], PW) if out["pi_container"] else None
    out["dir"] = d
    return d, tp, pi, out


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


def cycle(job, params, bay, info_out=None):
    """One full poke: doorbell in a thread, agent against it over HTTP."""
    port = free_port()
    kd, tp, pi, _info = mint_pair(port, bay)
    if info_out is not None:
        info_out.update(_info)
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
    _cinfo = {}
    p1, out1, err1, ran1, text1 = cycle("receive_and_quote",
                                        {"amount_slot": 2}, _bay,
                                        info_out=_cinfo)
    check("the two boxes showed the SAME pairing code, and it is the one the "
          "operator compares",
          _cinfo.get("pi_sas") and _cinfo["pi_sas"] in _cinfo["vault_stdout"])
    check("...and NO SECRET crossed: neither box's private key appears in "
          "anything the other one wrote",
          _cinfo["tp_container"]["plain"]["secret"]
          not in json.dumps(_cinfo["pi_container"]))
    check("the Pi's keyfile on the SD card is SEALED and gives up nothing but "
          "KDF parameters",
          P.keyfile_is_sealed(_cinfo["pi_container"])
          and all(v not in json.dumps(_cinfo["pi_container"]) for v in
                  ("aa:bb:cc:dd:ee:ff", "255.255.255.255",
                   _cinfo["tp_container"]["plain"]["peer_public"])))
    check("the vault's keyfile is NOT sealed, says so in the file, and the "
          "tool said so out loud rather than letting it be discovered",
          not P.keyfile_is_sealed(_cinfo["tp_container"])
          and _cinfo["tp_container"]["kdf"] == "none"
          and "NOT encrypted" in _cinfo["vault_stdout"])
    check("...and the vault learned the MAC it must wake, without anyone "
          "typing it into the Pi",
          _cinfo["pi_container"] is not None
          and DB.load_key(Path(_cinfo["dir"]) / "gs_wake_pi.key",
                          PW)["target_mac"] == "aa:bb:cc:dd:ee:ff")
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

    print("\n== the ceremony survives whatever else is on the switch ==")
    # FOUND BY DRIVING IT. A two-line readiness probe in this very file
    # connected to the pairing port and closed; the vault accepted it as "the
    # Pi", gave up, and the real Pi then got 'connection refused' from a box
    # that had already finished pairing with nothing. On a real LAN that is a
    # port scanner, a monitoring agent, or anyone who wants the ceremony to
    # fail. The vault now keeps listening through connections that never speak
    # the protocol.
    _sd = tempfile.mkdtemp(prefix="wake_stray_")
    _sp = free_port()
    _sv = subprocess.Popen(
        [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair",
         "--out", _sd, "--bind", "127.0.0.1", "--pair-port", str(_sp),
         "--mac", "aa:bb:cc:dd:ee:ff", "--broadcast", "255.255.255.255"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, cwd=_sd)
    for _ in range(400):
        try:
            _junk = socket.create_connection(("127.0.0.1", _sp), timeout=0.2)
            break
        except OSError:
            time.sleep(0.05)
    else:
        _junk = None
    if _junk is not None:
        _junk.close()                       # connect and vanish: a port scan
        _junk2 = socket.create_connection(("127.0.0.1", _sp), timeout=2)
        _junk2.sendall(b"GET / HTTP/1.0\r\n\r\n")   # and now noise
        _junk2.close()
    _sargs = types.SimpleNamespace(vault="127.0.0.1", pair_port=_sp,
                                   key=os.path.join(_sd, "gs_wake_pi.key"),
                                   port=0, kdf="interactive")
    _sout = {}

    def _spi():
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                _sout["rc"] = DB.do_pair(_sargs, ask=lambda x: True,
                                         getpass_fn=lambda p: PW.decode())
        except BaseException as e:                           # noqa: BLE001
            _sout["rc"] = e

    _st = threading.Thread(target=_spi, daemon=True)
    _st.start()
    try:
        _svout, _ = _sv.communicate(input="yes\n", timeout=180)
    except subprocess.TimeoutExpired:
        _sv.kill()
        _svout, _ = _sv.communicate()
    _st.join(120)
    check("two stray connections do NOT consume the ceremony: the real Pi "
          "still pairs afterwards",
          _sout.get("rc") == 0
          and os.path.exists(os.path.join(_sd, "gs_wake_thinkpad.key")))
    check("...and the operator is TOLD each one happened, rather than just "
          "seeing a slow pairing",
          _svout.count("That was not the Pi") >= 2)


    print("\n== the doorbell's queue depth is one, over the wire ==")
    # The first boot's M3 is DROPPED on the floor here, deliberately, for two
    # reasons at once: it keeps the doorbell listening (a result ends its
    # window, and then a second boot would meet a closed socket and report
    # "unreachable" -- true, but not the property under test), and it drives
    # the agent's "an undeliverable result is not a failure of the job" path
    # over real HTTP. The Pi's clock is injected so the thread can be released
    # on demand instead of sitting out the job budget.
    port2 = free_port()
    kd2, tp2, pi2, _i2 = mint_pair(port2, _bay)
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
    print("\n== the pairing tool refuses before it opens a socket ==")
    # These used to be checked in test_wake_protocol against the OLD gs_wake_keys
    # CLI. That CLI is gone and the checks went with it, leaving a mutation
    # anchor pointing at a guarantee nothing tested any more -- the sweep would
    # have reported it as a survivor, which is the sweep doing its job and this
    # file having stopped doing its own.
    def _keys_cli(*extra):
        d = tempfile.mkdtemp(prefix="wake_val_")
        try:
            return subprocess.run(
                [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair",
                 "--out", d, "--bind", "127.0.0.1",
                 "--pair-port", str(free_port()), *extra],
                capture_output=True, text=True, timeout=60, cwd=d, input="")
        except subprocess.TimeoutExpired:
            # A TOOL THAT HANGS ON A BAD FLAG HAS NOT REFUSED IT. Reported as
            # a failed check, not as a crashed suite: this is exactly how
            # --broadcast 999.1.1.1 was found (the regex counted digits and
            # never asked whether 999 was a byte, so the tool went on to bind
            # and wait 5 minutes).
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    for _extra, _why, _needle in (
            (("--artifact-dir", "bay"),
             "a RELATIVE artifact dir: the agent runs under systemd, whose "
             "working directory is '/', and that is mounted read-only",
             "relative"),
            (("--amount-ladder", "0.01", "0", "0.05"),
             "a zero rung on the amount ladder", "positive"),
            (("--amount-ladder", *(["0.01"] * 9)),
             "a ladder longer than the wire's slot range, whose extra rungs "
             "no note could ever select", "never be selected"),
            (("--account-ceiling", "0"), "a zero account ceiling", "at least"),
            (("--daily-wake-budget", "0"), "a zero wake budget", "between"),
            (("--mac", "not-a-mac"), "a MAC that is not a MAC", "MAC address"),
            (("--broadcast", "999.1.1.1"),
             "a broadcast address that is not an address", "IPv4"),
            (("--pair-port", "0"), "port 0 for the ceremony", "not a port")):
        _r = _keys_cli(*_extra)
        check(f"refuses {_why}",
              _r.returncode != 0 and _needle in (_r.stdout + _r.stderr))

    # And it refuses BEFORE binding, so a bad flag never leaves a socket open.
    _r = _keys_cli("--artifact-dir", "bay")
    check("...and says nothing about waiting, because it never got as far as "
          "opening the pairing socket",
          "Waiting up to" not in _r.stdout + _r.stderr)

    _d0 = tempfile.mkdtemp(prefix="wake_exist_")
    open(os.path.join(_d0, "gs_wake_thinkpad.key"), "w").write("{}")
    _r = subprocess.run(
        [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair",
         "--out", _d0, "--bind", "127.0.0.1", "--pair-port", str(free_port())],
        capture_output=True, text=True, timeout=60, cwd=_d0, input="")
    check("refuses to overwrite an existing keyfile: the Pi holds the "
          "matching half, and replacing this one silently breaks the pair in "
          "a way that looks exactly like a dead switch",
          _r.returncode != 0 and "already exists" in _r.stdout + _r.stderr)


    print("\n== the MAC is detected, never typed ==")
    # --thinkpad-mac used to be a REQUIRED flag, and a typo in it produced a
    # setup that paired perfectly, reported success on both boxes, and then
    # woke nothing forever. A magic packet is not acknowledged, so no layer of
    # this system could ever have told the operator.
    _keys = load("gs_wake_keys")
    _u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _u.settimeout(1)
    try:
        _u.connect(("192.0.2.1", 9))
        _src = _u.getsockname()[0]
    except OSError:
        _src = ""
    finally:
        _u.close()
    _iface, _mac, _brd = _keys.local_link(_src) if _src else (None, None, None)
    if _src and _src != "127.0.0.1":
        check(f"the interface holding this host's own address ({_src}) is "
              f"found, with a usable MAC and broadcast",
              bool(_iface) and bool(_keys.MAC_RE.match(_mac or ""))
              and _mac != "00:00:00:00:00:00"
              and bool(_keys.IPV4_RE.match(_brd or "")))
    else:
        # No route off this host. The tool must say so, not invent a MAC.
        check("with no route off this host, detection returns nothing rather "
              "than guessing", (_iface, _mac, _brd) == (None, None, None))
    check("loopback is never offered as the interface to wake: it has no "
          "hardware address and a magic packet there reaches nothing",
          _keys.local_link("127.0.0.1") == (None, None, None))
    check("an address no interface holds returns nothing",
          _keys.local_link("203.0.113.77") == (None, None, None))


finally:
    os.chdir(_cwd0)


# ===========================================================================
# gs_wake_keys.is_ipv4 HAD NO TEST AT ALL.
#
# The mutation sweep proved it: flipping IPV4_RE's \Z back to $ SURVIVED both
# suites the anchor named, because every trailing-newline check written for
# this lived in test_wake_protocol and exercised gs_wake_proto._pair_info --
# a DIFFERENT function in a different file. The regex that validates
# --wol-broadcast on the way into the keyfile was never driven.
#
# `$` also matches just before a trailing newline, and int("255\n") == 255,
# so the range guard did not catch it either. gs_wake_keys builds
# f"http://{host}:{port}" from these values, and urllib rejects a control
# character in a URL at WAKE time -- months after the ceremony that stored it.
# ===========================================================================
_KEYS = load("gs_wake_keys")
for _v, _want, _why in [
        ("1.2.3.4", True, "an honest dotted quad"),
        ("255.255.255.255", True, "the broadcast address itself"),
        ("0.0.0.0", True, "the all-zeros address"),
        ("1.2.3.4\n", False, "a TRAILING NEWLINE ($ matches before one)"),
        ("1.2.3.4 ", False, "a trailing space"),
        (" 1.2.3.4", False, "a leading space"),
        ("999.1.1.1", False, "an out-of-range octet"),
        ("256.0.0.1", False, "one over the top of the range"),
        ("01.02.03.04", False, "leading zeros (inet_aton reads them as octal)"),
        ("10.0.0.010", False, "one octal-looking octet"),
        ("1.2.3", False, "three octets"),
        ("1.2.3.4.5", False, "five octets"),
]:
    check(f"is_ipv4 accepts {_why}" if _want else f"is_ipv4 refuses {_why}",
          _KEYS.is_ipv4(_v) is _want)
# MAC_RE is the LOAD-BEARING one: gs_wake_keys:166 and :304 match on it
# directly, with no octet-style guard behind it, so its \Z is the only thing
# between "de:ad:be:ef:ca:fe\n" and a keyfile.
check("the MAC regex is anchored the same way, and there is no second guard "
      "behind it",
      not _KEYS.MAC_RE.match("de:ad:be:ef:ca:fe\n")
      and bool(_KEYS.MAC_RE.match("de:ad:be:ef:ca:fe")))
# IPV4_RE asserted DIRECTLY, because is_ipv4 cannot show it: the octet guard
# str(int(p)) == p rejects "4\n" on its own, so the regex anchor there is
# defence in depth with a second layer behind it. Two mutation sweeps reported
# SURVIVED on it before that was understood -- the harness was right both
# times. Pinning the layer needs a check on the layer.
check("IPV4_RE itself refuses a trailing newline, independently of the octet "
      "guard that also happens to catch it",
      not _KEYS.IPV4_RE.match("1.2.3.4\n")
      and bool(_KEYS.IPV4_RE.match("1.2.3.4")))

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
