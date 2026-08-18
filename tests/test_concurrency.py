#!/usr/bin/env python3
"""Concurrency and hang-safety, none of which any other suite covered.

Every one of these came from asking "what does gs_console actually do to a
child?" rather than from a failing test:

  * integrity_log did an UNLOCKED read-modify-write, so two tools logging at
    once chained off the same prev and forked the hash chain -- destroying the
    tamper-evidence that is the file's only purpose. gs_console runs jobs
    concurrently by construction (a thread per job).
  * console children inherited fd 0, so receive_watch's `sys.stdin.isatty()`
    was True for a job nobody can type into: the moment a payment landed the
    job blocked on input() forever.
  * the console's JOB_TIMEOUT_S kill sat downstream of the stdout drain loop,
    which ends only when the child exits -- so the timeout could never fire on
    a child that hung while holding stdout open. The two defects composed into
    an unkillable hang.
  * console children block-buffered stdout into the pipe, so the live-output
    pane stayed empty for hours on a slow-ticking job.
"""
import hashlib, importlib.machinery, importlib.util, os, subprocess, sys
import tempfile, time, multiprocessing as mp
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
from srcutil import code_only

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


gs = load("gs_common.py")

print("=== integrity chain under concurrent writers ===")


def _verify(log: Path):
    """Recompute the chain; return the number of broken links."""
    prev = "0" * 64
    broken = 0
    for line in log.read_text().splitlines():
        h, _, rest = line.partition(" | ")
        if hashlib.sha256((prev + rest).encode()).hexdigest() != h.strip():
            broken += 1
        prev = h.strip()
    return broken


def _writer(log_str, n, locked):
    import sys as _s
    _s.path.insert(0, REPO)
    import gs_common as _g
    if not locked:
        # Reproduce the OLD unlocked behaviour so this test can show the
        # difference rather than just asserting the good case -- a green
        # result that would be green either way proves nothing.
        import fcntl as _f
        _g.fcntl = type("X", (), {"flock": staticmethod(lambda *a: None),
                                  "LOCK_EX": 0, "LOCK_UN": 0})
    for i in range(40):
        _g.integrity_log("w", f"p{n}-{i}", log_path=Path(log_str))


def _run(locked):
    d = tempfile.mkdtemp(prefix="gs_chain_")
    log = Path(d) / "integrity_chain.log"
    ps = [mp.Process(target=_writer, args=(str(log), n, locked)) for n in range(6)]
    for p in ps: p.start()
    for p in ps: p.join()
    n = len(log.read_text().splitlines())
    return n, _verify(log)


_n_ok, _broken_ok = _run(locked=True)
check("6 concurrent writers all recorded their entries", _n_ok == 240)
check("...and the hash chain verifies end to end (0 broken links)",
      _broken_ok == 0)

# Non-vacuity: the same load WITHOUT the lock must actually fork the chain,
# or the assertion above would pass no matter what integrity_log did.
_n_bad, _broken_bad = _run(locked=False)
check("control: the same load with locking disabled DOES fork the chain "
      f"({_broken_bad} broken links) — so the check above is not vacuous",
      _broken_bad > 0)

# The lock file is an artifact like any other.
_para = load("paranoia_mode")
import fnmatch
check("the lock file is on paranoia_mode's wipe list",
      any(fnmatch.fnmatch("integrity_chain.log.lock", p)
          for p in _para.GS_ARTIFACT_FILE_PATTERNS))

print("=== console children cannot wait for a human, and cannot hang forever ===")
c = load("gs_console")
src = open(os.path.join(REPO, "gs_console")).read()

# stdin: a job must never inherit a terminal.
check("console jobs are spawned with stdin closed (DEVNULL)",
      "stdin=subprocess.DEVNULL" in src)
# proven, not just read: a child that reads stdin must see EOF immediately
jid = c.start([sys.executable, "-c",
               "import sys;print('isatty=%s' % sys.stdin.isatty());"
               "print('read=%r' % sys.stdin.read())"], "stdin-probe",
              action_id="units")
deadline = time.time() + 60
while time.time() < deadline and not c.JOBS[jid]["done"]:
    time.sleep(0.05)
out = "\n".join(c.JOBS[jid]["lines"])
check("a console child sees a NON-tty stdin (so input() prompts are skipped)",
      "isatty=False" in out)
check("...and reading stdin returns EOF instead of blocking", "read=''" in out)

# receive_watch's menu is gated on isatty, so with DEVNULL it takes the
# no-choice path rather than blocking.
rw_src = open(os.path.join(REPO, "receive_watch")).read()
check("receive_watch's interactive prompt is gated on stdin being a tty",
      "sys.stdin.isatty()" in rw_src)

# The watchdog must be able to fire DURING the drain, i.e. on a child that
# hangs while holding stdout open. This is the case the old p.wait(timeout)
# could never reach.
real_timeout = c.JOB_TIMEOUT_S
c.JOB_TIMEOUT_S = 3
try:
    t0 = time.time()
    jid = c.start([sys.executable, "-c",
                   "import time,sys;print('alive',flush=True);time.sleep(600)"],
                  "hang-probe", action_id="units")
    deadline = time.time() + 90
    while time.time() < deadline and not c.JOBS[jid]["done"]:
        time.sleep(0.1)
    elapsed = time.time() - t0
finally:
    c.JOB_TIMEOUT_S = real_timeout

check("a child that hangs holding stdout open IS killed by the job timeout",
      c.JOBS[jid]["done"])
check(f"...promptly, near the timeout rather than never (took {elapsed:.1f}s)",
      elapsed < 60)
check("...and the kill is reported in the job's output",
      any("exceeded" in l for l in c.JOBS[jid]["lines"]))

print("=== console children stream output instead of block-buffering it ===")
check("console children run unbuffered", "PYTHONUNBUFFERED" in src)
# proven: a child that prints without flush must still appear promptly
jid = c.start([sys.executable, "-c",
               "import time;print('early line');time.sleep(3)"],
              "buffer-probe", action_id="units")
seen = False
deadline = time.time() + 30
while time.time() < deadline:
    if any("early line" in l for l in c.JOBS[jid]["lines"]):
        seen = True
        break
    if c.JOBS[jid]["done"]:
        break
    time.sleep(0.1)
check("an unflushed child print reaches the console BEFORE the child exits",
      seen)
deadline = time.time() + 30
while time.time() < deadline and not c.JOBS[jid]["done"]:
    time.sleep(0.1)

print("=== exit_strategy_simulator must honour the signals it installs ===")
esrc = open(os.path.join(REPO, "exit_strategy_simulator")).read()
check("it installs signal handlers", "install_signal_handlers()" in esrc)
check("...and actually CHECKS the flag they set (it did not, so Ctrl-C was "
      "swallowed entirely)", "shutdown_requested()" in esrc)
check("...before the oracle fetch and before writing the plan",
      esrc.count("shutdown_requested()") >= 2)

print("=== the run lock must actually be a lock ===")
# The original was `if path.exists(): exit` then `write_text(pid)` -- check
# then act, so two runs started milliseconds apart both saw no lock and both
# went on to spend the same wallet. The console starts jobs from threads, so
# that is an ordinary race.
#
# The FIRST rewrite of it was also wrong, and this is the check that caught it:
# it used O_CREAT|O_EXCL plus a PID-liveness test, and -- to avoid locking an
# operator out on a recycled PID -- treated a holder whose /proc cmdline did
# not mention the tool as dead. Twelve concurrent acquirers ALL won, because no
# holder's cmdline matched. A heuristic meant to soften a lockout had removed
# the lock. flock has no such failure mode: the kernel releases it when the
# holder dies, so there is no staleness to detect and nothing to guess.
import multiprocessing as _mp
_lk_dir = Path(tempfile.mkdtemp(prefix="gs_lock_"))
_LK = _lk_dir / ".ghostspiral.lock"


def _lock_child(path_str, q, ready, hold_s):
    import sys as _s
    _s.path.insert(0, REPO)
    import gs_common as _g
    _g.integrity_log = lambda *a, **k: None
    try:
        with _g.run_lock(Path(path_str), "GhostSpiral"):
            q.put("won")
            if ready is not None:
                ready.set()
            time.sleep(hold_s)
    except SystemExit:
        q.put("blocked")


with gs.run_lock(_LK, "GhostSpiral"):
    check("run lock: the lock file is created owner-only",
          _LK.exists() and (_LK.stat().st_mode & 0o777) == 0o600)

# A LIVE holder must block.
_ready = _mp.Event(); _q = _mp.Queue()
_h = _mp.Process(target=_lock_child, args=(str(_LK), _q, _ready, 2.5))
_h.start(); _ready.wait(10)
_blocked = False
try:
    with gs.run_lock(_LK, "GhostSpiral"):
        pass
except SystemExit as e:
    _blocked = "already running" in str(e)
check("run lock: a second run is REFUSED while the first holds it", _blocked)
_h.join()

# A holder that is SIGKILLed leaves nothing to clean up. The old design's
# advice on a stale lock was "delete the lock file manually", which is what
# trains an operator to clear the guard reflexively.
_r2 = _mp.Event(); _q2 = _mp.Queue()
_k = _mp.Process(target=_lock_child, args=(str(_LK), _q2, _r2, 60))
_k.start(); _r2.wait(10)
os.kill(_k.pid, 9); _k.join()
_after_kill = False
try:
    with gs.run_lock(_LK, "GhostSpiral"):
        _after_kill = True
except SystemExit:
    _after_kill = False
check("run lock: a SIGKILLed holder leaves NO stale lock (the kernel releases "
      "it, so there is never a file to delete by hand)", _after_kill)

# THE RACE ITSELF: many simultaneous acquirers, exactly one winner.
_q3 = _mp.Queue()
_ps = [_mp.Process(target=_lock_child, args=(str(_LK), _q3, None, 0.5))
       for _ in range(12)]
for _p in _ps: _p.start()
for _p in _ps: _p.join()
_res = [_q3.get() for _ in range(_q3.qsize())]
check(f"run lock: 12 concurrent runs -> exactly ONE wins "
      f"(won={_res.count('won')}, blocked={_res.count('blocked')})",
      _res.count("won") == 1 and _res.count("blocked") == 11)

# and GhostSpiral must use it rather than keeping its own check-then-act
_gs_code = code_only(os.path.join(REPO, "GhostSpiral"))
check("run lock: GhostSpiral acquires it through the shared helper",
      "run_lock(" in _gs_code)
check("run lock: ...and no longer does exists()-then-write",
      "lock_path.exists()" not in _gs_code)

import shutil as _sh2
_sh2.rmtree(_lk_dir, ignore_errors=True)


print("=== every real-binary suite must own its ports ===")
# Three suites shared 28090/28091/28093, two shared 28100, two shared 28080,
# two shared 28130 -- and leak_audit used 28082, which is monerod's DEFAULT
# testnet ZMQ port. Running any colliding pair together produced a daemon that
# died at startup and a suite that failed with an unexplained "Connection
# refused", which reads as flakiness rather than as a bug in the harness.
# (It was nearly written off as CPU contention; it was not.)
import collections as _co, glob as _glob, re as _re
_suites = sorted(_glob.glob(os.path.join(REPO, "tests", "real_*_testnet.py"))
                 + [os.path.join(REPO, "tests", "leak_audit_testnet.py")])
check("the real-binary suites were found", len(_suites) >= 15)
_ports = {}
for _f in _suites:
    _txt = open(_f).read()
    _ports[os.path.basename(_f)] = {
        int(x) for x in _re.findall(r"\b(\d{5})\b", _txt)
        if 20000 <= int(x) < 40000}
_count = _co.Counter()
for _ps in _ports.values():
    _count.update(_ps)
_dupes = {p: n for p, n in _count.items() if n > 1}
check(f"no port is claimed by two suites (dupes: {_dupes})", not _dupes)

# monerod's testnet ZMQ default must not be claimed by anyone, and every
# suite must disable ZMQ -- its port ignores --rpc-bind-port entirely.
check("nobody binds monerod's default testnet ZMQ port (28082)",
      28082 not in _count)
# A suite may launch monerod itself, or delegate to tests/monerolab.py. Either
# way the flag has to be there: check the helper explicitly rather than letting
# "it must be in the helper" be an assumption.
_lab_src = open(os.path.join(REPO, "tests", "monerolab.py")).read()
check("the shared regtest lab disables ZMQ", "--no-zmq" in _lab_src)
_no_zmq = [os.path.basename(f) for f in _suites
           if "--no-zmq" not in open(f).read()
           and "monerolab" not in open(f).read()]
check(f"every suite disables ZMQ, directly or via the lab (missing: {_no_zmq})",
      not _no_zmq)
# The lab must not hardcode a port either, or two suites using it collide on
# exactly the ports this block exists to keep apart.
check("the shared lab takes its ports from the caller",
      "def __init__(self, base, daemon_port, wallet_port)" in _lab_src)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES); sys.exit(1)
print("ALL GREEN")
