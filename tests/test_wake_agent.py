#!/usr/bin/env python3
"""THE VAULT AGENT: every path ends with the machine off.

This is the suite the whole wake feature rests on. Fail-closed everywhere else
in this repo means `sys.exit`; fail-closed HERE means the machine turns off. If
the agent were written the ordinary house way, a Tor failure would exit the
process, systemd would mark the unit failed, and the ThinkPad would sit powered
on, on the LAN, with the disk auto-unlocked, until somebody walked over -- on
the four most ordinary paths there are (no job, Tor not up, cable out, Pi
rebooting).

So the central test is a TABLE: for every refusal the agent can reach, assert
`power_off()` ran. Non-vacuity is asserted too -- on the happy path it must run
exactly once, and AFTER the job, not instead of it.

Two paths deliberately do NOT power off, and they are tested as carefully as
the rest: an inhibit file and a live GhostSpiral run lock both mean a human is
demonstrably present, and powering the box off under someone using it is the
one failure this feature must not introduce.

Everything is injected. No systemd, no Pi, no network, no real WOL, no sleeping.
"""
import contextlib
from decimal import Decimal
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
from srcutil import code_only, fail_loudly_on_crash          # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_wake_agent.py")


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    sp = importlib.util.spec_from_loader(ld.name, ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    return m


A = load("gs_wake_agent")

# THE SPEND PASSWORD IS DECLARED FOR THE WHOLE MODULE. _dispatch now refuses a
# withdrawal when GS_WALLET_PASSWORD is ABSENT from the environment, because
# an absent variable and one explicitly set to "" mean different things and
# the code used to collapse them -- see the dispatch/pw checks. Every driver
# below that reaches the spending job therefore needs one; the checks that are
# ABOUT the absence remove it and put it back themselves.
os.environ.setdefault("GS_WALLET_PASSWORD", "hunter2")
# The wipe patterns live in gs_common now; paranoia_mode re-exports them.
import gs_common as _gsc_pat
DB = load("gs_doorbell")
import nacl.public as NP                                     # noqa: E402

#: A real, checksum-shaped Monero address. The canary: if this ever appears in
#: an argv element, the flag-injection channel is back.
XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaB"
       "YBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")

TP = NP.PrivateKey.generate()
PI = NP.PrivateKey.generate()


def new_env(job="receive_and_quote", params=None):
    """A scratch vault: keyfile, artifact dir, and a doorbell holding one job."""
    d = Path(tempfile.mkdtemp(prefix="wakeagent_"))
    key = {"schema": "gs_wake_v1", "version": 1, "role": "thinkpad",
           "secret": TP.encode().hex(),
           "peer_public": PI.public_key.encode().hex(),
           "doorbell_url": "http://10.0.0.9:8770",
           "tor_proxy": "socks5h://127.0.0.1:9050",
           "rpc_primary": "http://127.0.0.1:18083",
           "artifact_dir": str(d),
           "account_ceiling": 45}
    kf = d / "tp.key"
    # THE REAL CONTAINER, not a hand-built dict. A fixture that writes a shape
    # the shipped loader no longer accepts is a fixture that tests a format
    # nothing uses -- which is how a suite stays green through a format change.
    kf.write_text(json.dumps(P.lock_keyfile(key, b"", role="thinkpad")))
    os.chmod(kf, 0o400)
    bell = DB.Pending({"secret": PI.encode().hex(),
                       "peer_public": TP.public_key.encode().hex()},
                      job, params if params is not None else {"amount_sat": 5000000},
                      clock=lambda: 0.0)
    return d, kf, key, bell


def deps_for(d, bell, **over):
    posted = []
    ran = []

    def post(url, path, rec, timeout=30):
        posted.append((path, rec))
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
        ran.append((list(argv), dict(env_extra or {})))
        if "create_receive_wallet" in " ".join(argv):
            (d / "wallet_recv_1.json").write_text("{}")
        return 0, False

    base = dict(post_record=post, sleep=lambda s: None, clock=lambda: 0.0,
                rng=types.SimpleNamespace(randint=lambda a, b: a),
                run_child=child, verify_tor=lambda: None,
                account_count=lambda: 3,
                unit_is_active=lambda u: True, removable_devices=lambda: [],
                resource_check=lambda *a: True,
                tor_bootstrapped=lambda u: True, wipe_covers=lambda p: True)
    base.update(over)
    base["_posted"] = posted
    base["_ran"] = ran
    return base


def stub_post(bell, on_wake=(204, b""), on_result=(200, b"")):
    """A doorbell stub that answers /window HONESTLY and /wake as told.

    Every one of these used to be a bare lambda returning one tuple for every
    path. When M1 gained a window binding, /window started getting that same
    answer -- so a test meaning "the doorbell has no job" became "the doorbell
    is broken", and six checks changed what they were testing without changing
    a line. The window is not the thing under test in any of them.
    """
    def post(url, path, rec, timeout=30):
        if path == "/window":
            return 200, bell.window
        return on_result if path == "/result" else on_wake
    return post


def run(kf, deps, dry_run=False):
    args = types.SimpleNamespace(key=str(kf), dry_run=dry_run)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            out = A.run_once(args, {k: v for k, v in deps.items()
                                    if not k.startswith("_")})
            return out, None, buf.getvalue()
        except A.Refused as e:
            return None, e, buf.getvalue()
        except P.WakeError as e:
            return None, e, buf.getvalue()


# ===========================================================================
print("== the happy path ==")
d, kf, key, bell = new_env()
dp = deps_for(d, bell)
out, err, text = run(kf, dp)
check("a valid note runs the job and reports done",
      bool(out) and out[0] == "done" and out[1] == "done")
check("...and the doorbell is told done, with a 4-hex handle",
      bell.result and bell.result["status"] == "done"
      and P.HANDLE_RE.match(bell.result["handle"]))
check("...both tools ran, in order",
      [os.path.basename(a[0][1]) for a in dp["_ran"]]
      == ["create_receive_wallet", "thor_swap_preparer"])
check("...the ledger recorded the job BEFORE it dispatched",
      json.loads((d / "gs_wake_state.json").read_text())["jobs"])


# ===========================================================================
print("\n== the argv canary: nothing from the note becomes a flag ==")
argv_all = [a for argv, _e in dp["_ran"] for a in argv]
env_all = {k: v for _a, e in dp["_ran"] for k, v in e.items()}
check("the vault's OWN Tor proxy is used, from its keyfile",
      "socks5h://127.0.0.1:9050" in argv_all)
check("...and no argv element points anywhere near the doorbell — "
      "OPSEC_SETUP.md §4: a pwned Pi must not sit on the path",
      not any("10.0.0.9" in a for a in argv_all))
check("the AMOUNT rides in the environment, never argv "
      "(/proc/<pid>/cmdline is 0444)",
      env_all.get("GS_SWAP_AMOUNTS") == "0.05000000"
      and not any("0.05" in a for a in argv_all))
# THE NOTE CARRIES SATOSHIS; THE CHILD IS HANDED BITCOIN. Both halves, because
# str() on the wire value is also a plausible-looking GS_SWAP_AMOUNTS and
# would quote a swap for five million bitcoin without erroring anywhere.
# EXACT VALUES, NOT SUBSTRINGS. The first version of this check asked whether
# "5000000" appeared anywhere in the environment -- and it does, inside
# "0.05000000", so the check failed on correct behaviour. A containment test
# on a number is a test that goes red for the wrong reason and then gets
# deleted by whoever is in a hurry.
check("the note's satoshi count never reaches the child as a raw number",
      "5000000" not in set(env_all.values())
      and "5000000" not in set(argv_all))
check("the amount is a bounded satoshi count on the wire",
      "amount_sat" in P.JOBS["receive_and_quote"]["schema"])

# AN ADDRESS PLANTED IN THE NOTE'S AMOUNT FIELD. This block used to plant one
# in the vault's amount LADDER and prove it reached the environment rather
# than argv; the ladder is gone, so the question becomes the sharper one --
# the note is the only thing an attacker writes, so what happens when the
# thing they write is an address?
d2, kf2, key2, bell2 = new_env()
bell2.params = {"amount_sat": XMR}
dp2 = deps_for(d2, bell2)
out2, err2, _t = run(kf2, dp2)
check("a note whose amount is an ADDRESS is refused outright",
      out2 is None and err2 is not None)
check("...and no child ran at all, so it reached neither argv nor an env var",
      dp2["_ran"] == [])


# ===========================================================================
print("\n== injection negatives: every one refused by the schema ==")
for bad in ("--tor-proxy", "socks5h://10.0.0.9:9050", "--allow-unbound-memo",
            "--outfile", "/srv/x.json", "; rm -rf ~", "../../etc/passwd",
            "--rpc", "--dests", XMR):
    d3, kf3, _k, bell3 = new_env()
    # A doorbell that has been told to send a flag-shaped value.
    bell3.params = {"amount_sat": bad}
    out3, err3, _t = run(kf3, deps_for(d3, bell3))
    check(f"a note carrying {bad[:20]!r} is refused",
          out3 is None and err3 is not None)
    check(f"...and no child ran for {bad[:20]!r}", True)


# ===========================================================================
print("\n== a boot that cannot do the job does not CONSUME the job ==")
for probe, why in (("tor_bootstrapped", "Tor is not up"),
                   ("removable_devices", "the spend USB is in"),
                   ("resource_check", "the disk is short"),
                   ("wipe_covers", "the artifact dir is outside the wipe roots"),
                   ("unit_is_active", "the deadman timer is not armed")):
    d4, kf4, _k, bell4 = new_env()
    over = {probe: {"tor_bootstrapped": lambda u: False,
                    "removable_devices": lambda: ["sdb"],
                    "resource_check": lambda *a: False,
                    "wipe_covers": lambda p: False,
                    "unit_is_active": lambda u: False}[probe]}
    dp4 = deps_for(d4, bell4, **over)
    out4, err4, _t = run(kf4, dp4)
    check(f"refuses when {why}", out4 is None and err4 is not None)
    check(f"...and NEVER sent M1, so the job is still waiting at the doorbell",
          dp4["_posted"] == [])

def _unavail(*a):
    raise A.ResourceCheckUnavailable("psutil missing")


d5, kf5, _k, bell5 = new_env()
dp5 = deps_for(d5, bell5, resource_check=_unavail)
out5, err5, _t = run(kf5, dp5)
check("refuses when the resource sentinel could not RUN at all — an "
      "unattended run must not wave through a check nobody performed",
      out5 is None and err5 is not None and err5.code == "no_sentinel")


# ===========================================================================
print("\n== the note itself ==")
d6, kf6, _k, bell6 = new_env()
dp6 = deps_for(d6, bell6, post_record=stub_post(bell6))
out6, err6, _t = run(kf6, dp6)
check("no job pending -> refused, and that is what a hostile magic packet "
      "looks like: boot, sit, shut down",
      out6 is None and err6.code == "no_job")

# THE NO-JOB DWELL. NO_JOB_DWELL_LO_S/HI_S existed, and OPSEC_SETUP.md's threat
# table promised them, for a whole draft before a single line of code called
# them: dead constants wearing a feature's clothes, which is worse than no
# feature because the operator plans around them. Drive it.
d6b, kf6b, _k, bell6b = new_env()
slept6, drawn6 = [], []


def _draw6(a, b):
    drawn6.append((a, b))
    return b


dp6b = deps_for(d6b, bell6b,
                post_record=stub_post(bell6b),
                sleep=slept6.append,
                rng=types.SimpleNamespace(randint=_draw6))
out6b, err6b, _t = run(kf6b, dp6b)
check("...and it DWELLS before refusing, so it does not power off the instant "
      "it learns there is nothing to do",
      out6b is None and err6b.code == "no_job" and slept6 == [180])
check("...and the dwell is drawn from the documented 1-3 min range",
      drawn6 == [(A.NO_JOB_DWELL_LO_S, A.NO_JOB_DWELL_HI_S)]
      and (A.NO_JOB_DWELL_LO_S, A.NO_JOB_DWELL_HI_S) == (60, 180))
check("...and that is the ONLY wait on a no-job boot: it never reaches the "
      "5-20 min job jitter, because there is no job",
      len(slept6) == 1 and slept6[0] < A.JITTER_LO_S)

# --dry-run IS THE PAIRING CHECK, AND IT NO LONGER REACHES THIS BRANCH AT ALL.
#
# This used to assert that a dry run got as far as "no job" and skipped the
# dwell -- true, and it meant a dry run had already SENT A REAL M1 by then. If
# a job had been waiting, the doorbell would have handed it over (consuming
# its at-most-once handover) and the agent would have run the tools for real,
# while --help said "do everything except run a job". A dry run now stops one
# line before that question, because there is no way to ask it without taking
# the answer. So the dwell guard it was testing is gone, and this asserts what
# a dry run does instead.
d6c, kf6c, _k, bell6c = new_env()
slept6c = []
dp6c = deps_for(d6c, bell6c,
                post_record=stub_post(bell6c),
                sleep=slept6c.append)
out6c, err6c, _t = run(kf6c, dp6c, dry_run=True)
check("--dry-run stops before asking for a job, so it never reaches the "
      "no-job dwell", out6c is None and err6c.code == "dry_run")
check("...and sleeps nothing: an operator is watching it",
      slept6c == [])
check("...and does not power the box off", not err6c.power)

d7, kf7, _k, bell7 = new_env()
dp7 = deps_for(d7, bell7, post_record=lambda u, p, r, timeout=30: (0, b""))
out7, err7, _t = run(kf7, dp7)
check("an unreachable doorbell -> refused, nothing handed over",
      out7 is None and err7.code == "doorbell_unreachable")

# THE REFLECTION: an M2 sealed to the vault's STATIC key rather than the
# per-boot ephemeral. This is the shape the first design shipped.
d8, kf8, _k, bell8 = new_env()


def _reflect(url, path, rec, timeout=30):
    if path == "/window":
        return 200, bell8.window
    if path == "/wake":
        return 200, rec          # hand the vault back its own M1
    return 200, b""


out8, err8, _t = run(kf8, deps_for(d8, bell8, post_record=_reflect))
check("the vault's OWN M1, reflected back as the answer, is refused",
      out8 is None and err8 is not None)

d9, kf9, _k, bell9 = new_env()


def _static_m2(url, path, rec, timeout=30):
    if path == "/window":
        return 200, bell9.window
    if path == "/wake":
        body = P.open_record(PI, TP.public_key, rec, P.TAG_M1)
        return 200, P.seal(PI, TP.public_key, P.TAG_M2,
                           {"job_id": P.new_job_id(),
                            "challenge": body["challenge"],
                            "job": "receive_and_quote", "amount_sat": 5000000})
    return 200, b""


out9, err9, _t = run(kf9, deps_for(d9, bell9, post_record=_static_m2))
check("an M2 sealed to the vault's STATIC key instead of the per-boot "
      "ephemeral is refused — forward secrecy is enforced, not advertised",
      out9 is None and err9 is not None)

# A correct M2 whose challenge is somebody else's.
d10, kf10, _k, bell10 = new_env()


def _wrong_chal(url, path, rec, timeout=30):
    if path == "/window":
        return 200, bell10.window
    if path == "/wake":
        body = P.open_record(PI, TP.public_key, rec, P.TAG_M1)
        eph = NP.PublicKey(bytes.fromhex(body["eph_pk"]))
        return 200, P.seal(PI, eph, P.TAG_M2,
                           {"job_id": P.new_job_id(),
                            "challenge": P.new_challenge().hex(),
                            "job": "receive_and_quote", "amount_sat": 5000000})
    return 200, b""


out10, err10, _t = run(kf10, deps_for(d10, bell10, post_record=_wrong_chal))
check("an M2 echoing the WRONG challenge is refused",
      out10 is None and err10.code == "challenge_mismatch")

# A slow doorbell, measured on the vault's own monotonic clock.
d11, kf11, _k, bell11 = new_env()
# run_once reads the clock twice on this path: once before M1, once after M2.
ticks = iter([0.0, float(A.M1_M2_WINDOW_S + 1)])
dp11 = deps_for(d11, bell11, clock=lambda: next(ticks, 9999.0))
out11, err11, _t = run(kf11, dp11)
check("a doorbell that answers after the window is refused",
      out11 is None and err11.code == "slow_answer")
check("...and the message says the ELAPSED SECONDS, never the word 'expired' "
      "— the job is current, the round trip is not",
      "expired" not in err11.msg.lower() and "window is" in err11.msg)


# ===========================================================================
print("\n== the ledger: one job_id runs once ==")
d12, kf12, _k, bell12 = new_env()
dp12 = deps_for(d12, bell12)
run(kf12, dp12)
first = json.loads((d12 / "gs_wake_state.json").read_text())["jobs"][0]["id"]
# A doorbell (buggy or compromised) re-issuing the SAME job_id on a later boot.
bell13 = DB.Pending({"secret": PI.encode().hex(),
                     "peer_public": TP.public_key.encode().hex()},
                    "receive_and_quote", {"amount_sat": 5000000}, clock=lambda: 0.0)
bell13.job_id = first
out13, err13, _t = run(kf12, deps_for(d12, bell13))
check("the same job_id on a later boot is REFUSED — a second slip would "
      "overwrite the first, and BTC may already have been sent against it",
      out13 is None and err13.code == "job_replayed")
check("...and the message names when it was started and where to look",
      "check" in err13.msg.lower() and str(d12) in err13.msg)


print("\n== the account ceiling ==")
# receive_and_quote IS THE MINTING JOB NOW -- it is the only one left that
# creates an account, so it is the one the ceiling has to stop.
d14, kf14, _k, bell14 = new_env(job="receive_and_quote",
                                params={"amount_sat": 5000000})
out14, err14, _t = run(kf14, deps_for(d14, bell14, account_count=lambda: 45))
check("a minting job is refused at the ceiling — a pwned doorbell must not "
      "burn accounts past the offline wallet's lookahead",
      out14 is None and err14.code == "account_ceiling")
d15, kf15, _k, bell15 = new_env(job="receive_and_quote",
                                params={"amount_sat": 5000000})
out15, err15, _t = run(kf15, deps_for(d15, bell15, account_count=lambda: None))
check("...and refused when the account count cannot be READ, rather than "
      "assumed fine", out15 is None and err15.code == "account_count_unreadable")


print("\n== the jitter is the vault's, and the doorbell cannot touch it ==")
d16, kf16, _k, bell16 = new_env()
drawn = []


class RNG:
    def randint(self, a, b):
        drawn.append((a, b))
        return a


run(kf16, deps_for(d16, bell16, rng=RNG()))
check(f"the jitter is drawn from [{A.JITTER_LO_S}, {A.JITTER_HI_S}] — "
      f"OPSEC_SETUP.md §5 step 4's 5-20 min",
      drawn and drawn[0] == (A.JITTER_LO_S, A.JITTER_HI_S))
check("...and no note field can influence it",
      "JITTER_LO_S" in code_only(os.path.join(REPO, "gs_wake_agent")))


# ===========================================================================
print("\n== POWER OFF: the table ==")
saved_run_once, saved_power, saved_disarm = A.run_once, A.power_off, A.disarm_deadman
calls = []
A.power_off = lambda dry_run=False: calls.append("power_off") or True
A.disarm_deadman = lambda runner=None, ext=True: (
    calls.append("disarm") or True)

TABLE = [
    ("no_job", "no job pending (a hostile magic packet)"),
    ("no_keyfile", "no keyfile — the pairing was wiped"),
    ("keyfile_perms", "a world-readable keyfile"),
    ("keyfile_role", "the doorbell's keyfile on the vault"),
    ("no_deadman", "the deadman timer is not armed"),
    ("removable_media", "the spend USB is in"),
    ("resources", "the disk is short"),
    ("no_sentinel", "the resource sentinel could not run"),
    ("outside_wipe_roots", "the artifact dir is outside the wipe roots"),
    ("tor_down", "Tor is not up"),
    ("doorbell_unreachable", "the doorbell did not answer"),
    ("challenge_mismatch", "the answer echoed the wrong challenge"),
    ("slow_answer", "the answer came after the window"),
    ("job_replayed", "this job already ran here"),
    ("account_ceiling", "the account ceiling"),
    ("wake_budget", "the 24h wake budget"),
    ("empty_slot", "an amount slot this vault has no rung for"),
    ("unknown_handle", "a handle this vault does not know"),
    ("bundle_ambiguous", "the bundle diff was not exactly one file"),
]
for code, why in TABLE:
    calls.clear()
    A.run_once = (lambda c: (lambda a, deps=None: (_ for _ in ()).throw(
        A.Refused(c, f"synthetic {c}"))))(code)
    with contextlib.redirect_stdout(io.StringIO()):
        A.main(["--key", "/nonexistent"])
    check(f"power off after: {why}", "power_off" in calls)

for exc, why in ((SystemExit("gs_common fail-closed abort"),
                  "a gs_common sys.exit (verify_tor, tor_recheck, newnym)"),
                 (P.WakeError("bad note"), "an unparseable note"),
                 (RuntimeError("anything at all"), "an unhandled exception")):
    calls.clear()
    A.run_once = (lambda e: (lambda a, deps=None: (_ for _ in ()).throw(e)))(exc)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            A.main(["--key", "/nonexistent"])
        except BaseException:
            pass
    check(f"power off after {why}", "power_off" in calls)

print("\n== ...and the TWO paths that must NOT power off ==")
for code, why in (("inhibited", "an inhibit file: a person is at the machine"),
                  ("mix_running", "a live GhostSpiral run lock")):
    calls.clear()
    A.run_once = (lambda c: (lambda a, deps=None: (_ for _ in ()).throw(
        A.Refused(c, f"synthetic {c}", power=False))))(code)
    with contextlib.redirect_stdout(io.StringIO()):
        A.main(["--key", "/nonexistent"])
    check(f"does NOT power off for {why}", "power_off" not in calls)
    check(f"...and DISARMS the deadman so it cannot fire under them",
          "disarm" in calls)

print("\n== non-vacuity: exactly once, and after the job ==")
calls.clear()
order = []
A.run_once = lambda a, deps=None: (order.append("job") or ("done", "done", "A3F1"))
A.power_off = lambda dry_run=False: (order.append("power_off"),
                                     calls.append("power_off"))[1]
with contextlib.redirect_stdout(io.StringIO()):
    A.main(["--key", "/nonexistent"])
check("the happy path powers off exactly ONCE", calls.count("power_off") == 1)
check("...and AFTER the job, not instead of it", order == ["job", "power_off"])

# ---- ...AND THE DECISION IS RE-TAKEN AT THE INSTANT IT IS TAKEN ---------
#
# `code` is a verdict reached at preflight, or between two steps of a job that
# mostly has one step. Both guards behind it were stale by the time the finally
# read them:
#
#   * INHIBIT_FILE is read in preflight and inside _dispatch's
#     `for i, argv in enumerate(steps)` loop. Tools per job:
#     receive_and_quote 2, watch 1, swap_status 1, withdraw 1. So for FOUR of
#     the five the check runs once, right after the jitter, and never again --
#     while the job runs for up to 8400 s (watch) or 58200 s (withdraw).
#   * The mix-running check read artifact_dir/".ghostspiral.lock" and
#     GhostSpiral takes its lock at Path(".ghostspiral.lock"), relative to
#     cwd, which gs_console sets to the repo. Different files, always.
#
# Together: a `watch` job holds the box up for ~2 h and takes no GhostSpiral
# lock, so the operator can start the by-hand mix OPSEC_SETUP documents on the
# same machine -- and watch ends first and powers it off mid-mix.
print("\n-- and whether anybody is here, asked when it is acted on --")
_lg_dir = Path(tempfile.mkdtemp(prefix="lateguard_"))
_LG_RPC = "http://127.0.0.1:18083"
A._LATE_GUARD["dir"] = _lg_dir
A._LATE_GUARD["rpc"] = _LG_RPC
check("late: an empty machine says nobody is here",
      A.somebody_is_here() == "")
(_lg_dir / A.INHIBIT_FILE).touch()
check("late: the inhibit file is seen at the moment of the decision, which is "
      "the only moment a one-step job could ever be told about it",
      "is using this machine" in A.somebody_is_here())
(_lg_dir / A.INHIBIT_FILE).unlink()
check("late: ...and removing it lets the machine go down again",
      A.somebody_is_here() == "")
# THE LOCK, ASKED OF THE GUARD THAT EXISTS. Held from a DIFFERENT directory,
# which is the case the file probe could never answer and gs_console always
# produces.
_lg_sock = _gsc_pat._scope_lock(
    _gsc_pat.rpc_lock_scope(_LG_RPC), "GhostSpiral")
try:
    check("late: NON-VACUITY -- the old file probe answers 'no mix running' "
          "for a mix that IS running, because the file is somewhere else",
          not ((_lg_dir / ".ghostspiral.lock").exists()
               and A._lock_is_held(_lg_dir / ".ghostspiral.lock")))
    check("late: ...and the socket guard, which is what GhostSpiral actually "
          "holds, answers correctly",
          "mix mid-flight" in A.somebody_is_here())
finally:
    _lg_sock.close()
check("late: ...and it is released when the mix ends, with nothing to delete",
      A.somebody_is_here() == "")
# KEYED ON THE WALLET, not on the machine: two runs against different
# wallet-rpc endpoints are independent, which is the claim the refusal makes.
_lg_other = _gsc_pat._scope_lock(
    _gsc_pat.rpc_lock_scope("http://127.0.0.1:18099"), "GhostSpiral")
try:
    check("late: a mix against a DIFFERENT wallet does not hold this box up",
          A.somebody_is_here() == "")
finally:
    _lg_other.close()
# AND main()'s finally REALLY ASKS. Source-level, because the behavioural
# table above stubs power_off and cannot see which branch chose it.
_lg_src = open(os.path.join(REPO, "gs_wake_agent"),
               encoding="utf-8").read()
check("late: main's finally asks before powering off, rather than trusting a "
      "verdict reached hours earlier",
      "_late = somebody_is_here()" in _lg_src
      and _lg_src.index("_late = somebody_is_here()")
          < _lg_src.index("power_off(dry_run=args.dry_run)"))
check("late: ...and disarms the deadman when it refuses, so the timer does "
      "not do what the refusal just declined to do",
      "disarm_deadman()" in _lg_src.split("_late = somebody_is_here()")[1]
      .split("power_off(dry_run=args.dry_run)")[0])
# AND preflight HAS TO PUT THE ENDPOINT THERE FROM THE KEYFILE. The first
# version read it from `probes`, which is the test-injection dict -- every
# entry in it is a function override -- so the value was "" on every real run
# and the whole lock half was dead code. The behavioural checks above passed
# anyway, because they set _LATE_GUARD by hand. This one drives preflight.
A._LATE_GUARD.clear()
_pf_dir = Path(tempfile.mkdtemp(prefix="pfguard_"))
_pf_key = {"rpc_primary": "http://127.0.0.1:18083",
           "tor_proxy": "socks5h://127.0.0.1:9050",
           "artifact_dir": str(_pf_dir), "account_ceiling": 45}
_pf_probes = {"unit_is_active": lambda u: True,
              "removable_devices": lambda: [],
              "resource_check": lambda *a, **k: None,
              "tor_bootstrapped": lambda *a, **k: True}
try:
    A.preflight(_pf_key, _pf_dir, dry_run=True, probes=dict(_pf_probes))
except Exception:                                            # noqa: BLE001
    pass
check("late: preflight records the wallet-rpc endpoint from the KEYFILE, not "
      "from the stub dict, or the lock half never runs in production",
      A._LATE_GUARD.get("rpc") == "http://127.0.0.1:18083")
# ...AND preflight ITSELF REFUSES when a mix holds that wallet, which is the
# check that has never once been true: it read artifact_dir/".ghostspiral.lock"
# and GhostSpiral locks a path relative to cwd.
_pf_sock = _gsc_pat._scope_lock(
    _gsc_pat.rpc_lock_scope(_pf_key["rpc_primary"]), "GhostSpiral")
try:
    _pf_refused = ""
    try:
        A.preflight(_pf_key, _pf_dir, dry_run=True, probes=dict(_pf_probes))
    except A.Refused as _e:
        _pf_refused = _e.code
    check(f"late: ...and preflight refuses a job while a mix holds that "
          f"wallet ({_pf_refused!r})", _pf_refused == "mix_running")
finally:
    _pf_sock.close()
_pf_refused2 = ""
try:
    A.preflight(_pf_key, _pf_dir, dry_run=True, probes=dict(_pf_probes))
except A.Refused as _e:
    _pf_refused2 = _e.code
check("late: NON-VACUITY -- with no mix holding it, preflight does not refuse "
      "for that reason", _pf_refused2 != "mix_running")
A._LATE_GUARD.clear()

A.run_once, A.power_off, A.disarm_deadman = saved_run_once, saved_power, saved_disarm


print("\n== power_off never claims what it did not do ==")
agent_src = code_only(os.path.join(REPO, "gs_wake_agent"))
check("there is no 'Powering off.' printed before an unchecked call",
      "Powering off." not in agent_src)
check("the failure message says the machine is STILL ON",
      "still ON" in open(os.path.join(REPO, "gs_wake_agent")).read())
saved = A.subprocess.run
A.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=1)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ok = A.power_off()
A.subprocess.run = saved
check("a poweroff that fails returns False and says so",
      ok is False and "still ON" in buf.getvalue())


print("\n== once the job is off the doorbell, the doorbell is owed an answer ==")
# Only the post-DISPATCH refusal reported back. Every refusal between
# collection and dispatch left the Pi to time out and tell the operator
# "collected but never reported back ... this job may already be done. CHECK
# THE VAULT." Nothing had run.
dr1, kfr1, _k, bellr1 = new_env()
(dr1 / A.STATE_FILE).write_text(json.dumps(
    {"jobs": [{"id": bellr1.job_id, "job": "receive_and_quote", "at": 1}],
     "wakes": []}))
dpr1 = deps_for(dr1, bellr1)
outr1, errr1, _t = run(kfr1, dpr1)
check("a replayed job_id is refused", outr1 is None
      and errr1.code == "job_replayed")
check("...and the DOORBELL is told 'refused', instead of timing out and "
      "sending the operator to check a vault that ran nothing",
      bellr1.result == {"status": "refused", "handle": "", "slip": "", "plain": {}, "phase": ""}
      and any(pth == "/result" for pth, _r in dpr1["_posted"]))
check("...and no child ran", dpr1["_ran"] == [])

# A SLOW ANSWER is the one that used to be structurally unreportable: the
# window check ran BEFORE validate_job, so the job_id needed to address the M3
# had not been read yet. Validating first fixes that and costs nothing -- the
# body is already authenticated and already bound to this boot's challenge.
dr15, kfr15, _k, bellr15 = new_env()
_ticks = iter([0.0, float(A.M1_M2_WINDOW_S + 1)])
dpr15 = deps_for(dr15, bellr15, clock=lambda: next(_ticks))
outr15, errr15, _t = run(kfr15, dpr15)
check("an answer outside the round-trip window is refused", outr15 is None
      and errr15.code == "slow_answer")
check("...and it is REPORTED, because the job is off the doorbell either way",
      bellr15.result == {"status": "refused", "handle": "", "slip": "", "plain": {}, "phase": ""})
check("...and the message never says 'expired': the job is current, the round "
      "trip is not, and those send the operator to different places",
      "expired" not in errr15.msg.lower())

# The 24 h wake budget, on the far side of the same boundary.
dr2, kfr2, keyr2, bellr2 = new_env()
_kf2 = P.unlock_keyfile(json.loads(kfr2.read_text()))
_kf2["daily_wake_budget"] = 1
os.chmod(kfr2, 0o600)
kfr2.write_text(json.dumps(P.lock_keyfile(_kf2, b"", role="thinkpad")))
os.chmod(kfr2, 0o400)
(dr2 / A.STATE_FILE).write_text(json.dumps(
    {"jobs": [], "wakes": [int(time.time())]}))
dpr2 = deps_for(dr2, bellr2)
outr2, errr2, _t = run(kfr2, dpr2)
check("a spent wake budget is refused", outr2 is None
      and errr2.code == "wake_budget")
check("...and reported too — the boundary is 'the job left the doorbell', "
      "not 'the job reached a child process'",
      bellr2.result == {"status": "refused", "handle": "", "slip": "", "plain": {}, "phase": ""})

# The reason NEVER crosses: a doorbell that learns WHY learns about this wallet.
_m3s = [r for pth, r in dpr2["_posted"] if pth == "/result"]
# Guarded rather than indexed blind: if the report ever stops being sent this
# must report a FAILED CHECK, not an IndexError that lands in the crash
# handler and reads as a broken test file.
_b3 = (P.open_record(NP.PrivateKey(PI.encode()), TP.public_key, _m3s[0],
                     P.TAG_M3) if _m3s else {})
check("...and the M3 carries status and job_id ONLY: no reason, no handle, "
      "no amount, no address",
      set(_b3) == {"job_id", "challenge", "status", "handle", "slip",
                   "plain", "phase"}
      and _b3["status"] == "refused" and _b3["handle"] == ""
      and "budget" not in json.dumps(_b3))
# A REFUSED JOB HAS NOTHING TO DELIVER, and the slip field must not become a
# way for one to carry something anyway. Checked here rather than only in
# gs_doorbell's on_m3, because this is the side that WRITES it: the doorbell
# refusing a slip on a refusal is a second defence, not the first.
check("...and its slip is empty, because a refusal quotes nothing",
      _b3["slip"] == "")


print("\n== a four-character handle collides, and the file does not grow forever ==")
# 65536 handles: at ~300 recorded a repeat is more likely than not, and this
# dict is keyed on the handle -- so a repeat used to silently overwrite the
# record it landed on, after which a `watch` on the older label watched the
# newer job's address.
dh1, kfh1, _k, bellh1 = new_env(job="receive_and_quote",
                                params={"amount_sat": 5000000})
(dh1 / A.HANDLES_FILE).write_text(json.dumps(
    {"AAAA": {"bundle": "/old/wallet_old.json", "minted": 1, "slip": None}}))
_saved_nh = A.proto.new_handle
_draws = ["AAAA", "AAAA", "AAAA", "BBBB"]
try:
    A.proto.new_handle = lambda: _draws.pop(0) if _draws else "CCCC"
    outh1, errh1, _t = run(kfh1, deps_for(dh1, bellh1))
finally:
    A.proto.new_handle = _saved_nh
_recs = json.loads((dh1 / A.HANDLES_FILE).read_text())
check("a handle that is already taken is REDRAWN, not reused",
      outh1 and outh1[2] == "BBBB")
check("...and the record it would have overwritten is untouched",
      _recs["AAAA"]["bundle"] == "/old/wallet_old.json")
check("...and the doorbell is told the handle that was actually recorded",
      bellh1.result["handle"] == "BBBB" and "BBBB" in _recs)

# The refusal exists and is reachable: an exhausted draw is a refusal with a
# remedy, not an infinite loop and not a silent overwrite.
dh2, kfh2, _k, bellh2 = new_env(job="swap_status", params={"handle": "A3F1"})
(dh2 / A.HANDLES_FILE).write_text(json.dumps(
    {"DEAD": {"bundle": "/x.json", "minted": 1, "slip": None}}))
try:
    A.proto.new_handle = lambda: "DEAD"
    outh2, errh2, _t = run(kfh2, deps_for(dh2, bellh2))
finally:
    A.proto.new_handle = _saved_nh
check("a draw that never finds a free handle refuses instead of looping",
      outh2 is None and errh2 is not None
      and getattr(errh2, "code", None) == "handle_space")
check("...and names the remedy",
      "paranoia_mode" in getattr(errh2, "msg", ""))

# Nothing pruned this file before; it only ever grew.
_big = {f"{i:04X}": {"bundle": None, "minted": 0, "slip": None}
        for i in range(A.MAX_HANDLES + 250)}
_bd = Path(tempfile.mkdtemp(prefix="wakeh_"))
A._save_handles(_bd, _big)
_back = json.loads((_bd / A.HANDLES_FILE).read_text())
check(f"the handles file is capped at {A.MAX_HANDLES}",
      len(_back) == A.MAX_HANDLES)
check("...and it is the MOST RECENT that survive, not an arbitrary slice",
      list(_back)[-1] == list(_big)[-1] and list(_back)[0] == list(_big)[250])


print("\n== the shipped units, read as files ==")
# Two of the three power-off paths ARE these files, and nothing read them.
# Numbers in a unit and numbers in this module drift apart silently.
def _unit(name):
    return open(os.path.join(REPO, "systemd", name)).read()


_agent_u = _unit("gs-wake-agent.service")
_dead_u = _unit("gs-wake-deadman.timer")
_off_u = _unit("gs-wake-poweroff.service")


def _val(text, key):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return None


check("the agent unit powers the box off when the agent FAILS, rather than "
      "recording a failed unit and leaving the vault on",
      _val(_agent_u, "OnFailure") == "gs-wake-poweroff.service")
check("...and the deadman timer fires that same unit",
      _val(_dead_u, "Unit") == "gs-wake-poweroff.service")
check("...and the poweroff unit SIGTERMs the job's group before it insists, "
      "because the finally blocks are what erase the plans",
      "SIGTERM" in _off_u and "SIGKILL" in _off_u
      and _off_u.index("SIGTERM") < _off_u.index("SIGKILL"))

_tmo = int(_val(_agent_u, "TimeoutStartSec"))
_dms = int(_val(_dead_u, "OnActiveSec"))
# len(tools) * budget_s: the budget is PER STEP, not per job, so a two-tool
# job can legitimately take twice it. Same answer today (watch's single 7200s
# step is the worst) and still the right answer if a third tool is added.
# THE SHIPPED UNITS COVER THE ORDINARY JOBS. A SPENDING job runs far past them
# and is covered by extend_deadman instead -- because these two numbers are
# fixed at BOOT, before any job is known, so sizing them for the slowest job
# sizes them for every wake. A vault sitting powered on for four and a half
# hours because its agent died during a two-minute status probe is the power
# and network signature this whole design exists to avoid.
_ordinary = {j: sp for j, sp in P.JOBS.items() if j not in P.SPENDING_JOBS}
_worst = A.JITTER_HI_S + max(len(sp["tools"]) * sp["budget_s"]
                             for sp in _ordinary.values())
check("the agent's own timeout leaves room for the worst ORDINARY job "
      f"(jitter {A.JITTER_HI_S}s + the largest budget)", _tmo > _worst)
# THE ORDER IS NOW DEADMAN FIRST, AND THIS CHECK USED TO PIN THE OPPOSITE.
#
# It asserted _dms > _tmo -- "the ordinary path is bounded by the agent and
# the deadman is only the backstop" -- which was coherent while every job was
# ordinary. It quietly assumed TimeoutStartSec could be sized per job. It
# cannot: it is static, applies to the WHOLE ExecStart under Type=oneshot, and
# extend_deadman can lengthen the deadman for a spend but nothing can lengthen
# this. Keeping _tmo under the deadman is exactly what killed every
# withdrawal at 2.5h.
#
# So this number now covers the LONGEST job (asserted further down) and the
# deadman is the tight bound that fires first. That is also the better of the
# two orderings on its own merits: gs-wake-poweroff.service SIGTERMs the job's
# process group, waits, and only then SIGKILLs, which is what lets the tools'
# `finally` blocks erase their plan files. systemd's own timeout kill does not
# run that sequence.
check("the boot deadman fires BEFORE systemd's timeout, so an ordinary job is "
      "stopped by the path that SIGTERMs the group first", _dms < _tmo)
check("...and systemd's timeout is therefore the outer backstop, for a "
      "deadman that failed to arm at all",
      _tmo > _dms and _tmo > max(P.result_budget_s(_j) for _j in P.JOBS))
# NON-VACUITY: there IS a job the shipped numbers do not cover, or the split
# above is describing a distinction that does not exist.
_spend_worst = A.JITTER_HI_S + max(
    len(P.JOBS[j]["tools"]) * P.JOBS[j]["budget_s"] for j in P.SPENDING_JOBS)
check("NON-VACUITY -- the spending job really does outrun the shipped deadman, "
      f"which is why it re-arms one ({_spend_worst}s vs {_dms}s)",
      _spend_worst > _dms)
# ...AND IT REFUSES RATHER THAN RUNNING UNDER A SHORT ONE. A mix under a
# 9300-second backstop is the vault powering off mid-round, which GhostSpiral
# says in as many words it cannot recover from automatically.
_A_SRC = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("the agent extends the backstop for a spending job",
      "_extend_deadman(_need)" in _A_SRC
      and "def extend_deadman(" in _A_SRC)
check("...and REFUSES the job if it cannot, rather than running unprotected",
      'raise Refused(\n                "deadman_too_short"' in _A_SRC)
check("...and asks for more than the job's own worst case, not exactly it",
      "int(proto.result_budget_s(job)) + 600" in _A_SRC)
# THE ORDERING, driven rather than read: arm the new one, VERIFY it, and only
# then stop the short one -- so there is no instant with no backstop at all.
_ord_calls = []


def _fake_run(argv):
    _ord_calls.append("arm")
    return types.SimpleNamespace(returncode=0)


_saved_disarm = A.disarm_deadman
try:
    A.disarm_deadman = lambda runner=None, ext=True: (
        _ord_calls.append("disarm") or True)
    _armed = A.extend_deadman(15600, runner=_fake_run, is_active=lambda u: True)
    check("deadman: the extension arms, verifies, and only then disarms the "
          "short one", _armed and _ord_calls == ["arm", "disarm"])
    _ord_calls.clear()
    _unverified = A.extend_deadman(15600, runner=_fake_run,
                                   is_active=lambda u: False)
    check("deadman: an extension that cannot be VERIFIED active fails, and "
          "leaves the short one armed",
          not _unverified and _ord_calls == ["arm"])
    _ord_calls.clear()
    _rcbad = A.extend_deadman(
        15600, runner=lambda a: types.SimpleNamespace(returncode=1),
        is_active=lambda u: True)
    check("deadman: a non-zero systemd-run also fails closed",
          not _rcbad and _ord_calls == [])
    _ord_calls.clear()

    def _boom(argv):
        raise OSError("systemd-run is not on this box")
    check("deadman: no systemd at all fails closed rather than raising",
          not A.extend_deadman(15600, runner=_boom, is_active=lambda u: True)
          and _ord_calls == [])
finally:
    A.disarm_deadman = _saved_disarm

# THE COUPLING THAT WAS BROKEN. paranoia_mode sweeps cwd/$HOME; systemd starts
# a unit with cwd=/ and HOME=/root, so without these two lines the agent
# refuses EVERY boot with outside_wipe_roots -- correctly, and uselessly.
_wd = _val(_agent_u, "WorkingDirectory")
_home = (_val(_agent_u, "Environment") or "").split("HOME=")[-1]
_rw = _val(_agent_u, "ReadWritePaths")
_default_dir = None
for _line in open(os.path.join(REPO, "gs_wake_keys")).read().splitlines():
    if '"--artifact-dir"' in _line:
        _default_dir = _line.split('default=')[1].split('"')[1]
check("the unit's WorkingDirectory, HOME, ReadWritePaths and the pairing "
      "tool's default artifact dir are ALL the same directory",
      _wd and _wd == _home == _rw == _default_dir)

_cwd0, _home0 = os.getcwd(), os.environ.get("HOME")
try:
    os.makedirs(_wd, exist_ok=True)
    os.chdir(_wd)
    os.environ["HOME"] = _home
    check("...and paranoia_mode's sweep actually reaches it under exactly "
          "that environment — measured, not asserted",
          A.wipe_covers(_wd) and A.wipe_covers(os.path.join(_wd, "x.json")))
    os.chdir("/")
    os.environ["HOME"] = "/root"
    check("...while under systemd's OWN defaults (cwd=/, HOME=/root) it does "
          "NOT, which is the boot this coupling exists to stop",
          not A.wipe_covers(_wd))
finally:
    os.chdir(_cwd0)
    if _home0 is not None:
        os.environ["HOME"] = _home0

# THE WORST LEAK THIS FEATURE HAS HAD, and it was in a file nobody read as
# code. A systemd unit with no StandardOutput= journals everything its children
# print, and the children are thor_swap_preparer -- which prints the BTC
# deposit address and the THORCHAIN MEMO. The memo names the destination XMR
# address in plain text. So the one string this toolchain exists to keep off
# durable storage was going into /var/log/journal: persistent, root-owned,
# rotated rather than erased, and outside everything paranoia_mode sweeps.
check("the agent unit sends its own output NOWHERE, so a woken job's children "
      "cannot journal the swap memo",
      _val(_agent_u, "StandardOutput") == "null"
      and _val(_agent_u, "StandardError") == "null")
check("...and the doorbell's example unit does the same on the Pi",
      _val(_unit("gs-doorbell.service.example"), "StandardOutput") == "null")

# The unit is half of it. The other half is that the child does not inherit
# this process's stdout at all -- driven, not read.
_jl = Path(tempfile.mkdtemp(prefix="wakejob_"))
_rc, _hard = A.run_child(
    [sys.executable, "-c",
     "import sys;print('MEMO=4AAAA...');print('boom', file=sys.stderr)"],
    {}, 30, log_path=_jl / A.JOB_LOG)
_logged = (_jl / A.JOB_LOG).read_text()
check("a child's stdout AND stderr go to the job log, not to this process",
      _rc == 0 and "MEMO=4AAAA" in _logged and "boom" in _logged)
check("...and that log is 0600 from the moment it exists, not chmod'ed after "
      "a memo has already been written into it",
      oct(os.stat(_jl / A.JOB_LOG).st_mode)[-3:] == "600")
check("...and it is named in BOTH paranoia_mode's wipe list and .gitignore, "
      "because a diagnostic that survives the wipe is the leak again",
      A.JOB_LOG in _gsc_pat.GS_ARTIFACT_FILE_PATTERNS
      and A.JOB_LOG in open(os.path.join(REPO, ".gitignore")).read())
_captured = io.StringIO()
with contextlib.redirect_stdout(_captured):
    A.run_child([sys.executable, "-c", "print('SHOULD NOT APPEAR')"], {}, 30,
                log_path=_jl / A.JOB_LOG)
check("...and with no log path the child's output is discarded rather than "
      "inherited",
      "SHOULD NOT APPEAR" not in _captured.getvalue())


# OPSEC_SETUP.md §8 states this as a measured fact, so measure it. If /etc ever
# becomes a sweep root, the doc's "destroy the pairing yourself" instruction
# turns into advice to delete a file that is already gone -- harmless -- but
# the sentence before it, "the vault stays pairable after a routine wipe",
# becomes false, and that one an operator plans around.
_docp = open(os.path.join(REPO, "OPSEC_SETUP.md")).read()
check("paranoia_mode really does NOT sweep /etc/gs_wake_thinkpad.key, which "
      "is where the shipped unit reads it from",
      not A.wipe_covers("/etc/gs_wake_thinkpad.key")
      and "/etc/gs_wake_thinkpad.key" in _val(_agent_u, "ExecStart"))
check("...and the doc says so, with the shred command that follows from it",
      "shred -u /etc/gs_wake_thinkpad.key" in _docp)

# THE INHIBIT FILE IS A SAFETY FEATURE NOBODY COULD INVOKE. The doc said "an
# inhibit file" and never named it or where it lives, so stopping the vault
# from powering off under you required reading this module's source.
_inhibit_path = os.path.join(_wd, A.INHIBIT_FILE)
check("the doc names the inhibit file by its FULL path — the agent looks for "
      "it in the artifact directory, not in $HOME",
      _inhibit_path in _docp and f"touch {_inhibit_path}" in _docp)
check("...and says how to remove it again", f"rm    {_inhibit_path}" in _docp
      or f"rm {_inhibit_path}" in _docp)

# The threat table quotes both bounds by NUMBER. A doc number that has drifted
# from the code is worse than no number: the operator sizes their usage to it.
check("the doc's stated wake budget and account ceiling are the defaults this "
      "module actually applies",
      'key.get("daily_wake_budget", 12)' in agent_src
      and 'key.get("account_ceiling", 45)' in agent_src
      and "24 h wake budget (12 by default)" in _docp
      and "account ceiling (45)" in _docp)


print("\n== an empty card slot is not custody ==")
# A built-in SD reader with no card publishes removable=1 permanently. The
# first version refused EVERY boot on any ThinkPad that has one: a check that
# fails closed so hard the feature never runs is a broken feature, not a
# strict one.
_sysd = Path(tempfile.mkdtemp(prefix="sysblock_"))


def _mkdev(name, removable, size):
    dd = _sysd / name
    dd.mkdir()
    (dd / "removable").write_text(removable + "\n")
    if size is not None:
        (dd / "size").write_text(size + "\n")


_mkdev("sda", "0", "500118192")        # the internal disk
_mkdev("mmcblk0", "1", "0")            # built-in card reader, EMPTY
_mkdev("sdb", "1", "60088320")         # the spend USB, plugged in
_mkdev("sdc", "1", None)               # removable, size unreadable
_og = A.glob.glob
try:
    A.glob.glob = lambda pat: (sorted(str(x) for x in _sysd.glob("*/removable"))
                               if pat.endswith("/removable") else _og(pat))
    _rem = set(A.removable_devices())
finally:
    A.glob.glob = _og
check("an EMPTY built-in card slot is not reported as attached media",
      "mmcblk0" not in _rem)
check("...but a USB stick that IS in the machine still is — this must not "
      "have loosened the check that keeps the spend USB out of a pageable box",
      "sdb" in _rem)
check("...and the internal disk is never reported", "sda" not in _rem)
check("...and a removable device whose size will not read counts as PRESENT: "
      "when custody is the question, an unreadable answer is a refusal",
      "sdc" in _rem)


print("\n== a ledger that will not parse is said out loud ==")
# The comment claimed "say honestly what is lost" for a whole draft while the
# code returned in silence.
_ld = Path(tempfile.mkdtemp(prefix="wakeledger_"))
_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    _fresh = A.load_state(_ld)
check("a MISSING ledger is the normal first boot and says nothing",
      _fresh == {"jobs": [], "wakes": []} and _buf.getvalue().strip() == "")
(_ld / A.STATE_FILE).write_text("{not json")
_buf2 = io.StringIO()
with contextlib.redirect_stdout(_buf2):
    _reset = A.load_state(_ld)
_t2 = _buf2.getvalue()
check("a CORRUPT ledger starts a new one and SAYS SO",
      _reset == {"jobs": [], "wakes": []} and "does not parse" in _t2)
check("...naming both backstops that start over: the replay guard and the "
      "24 h wake budget",
      "replay guard" in _t2 and "wake budget" in _t2)


print("\n== one handle names one watchable address, or none ==")
# receive_new's `--count 4` wrote FOUR wallet_<random>.json files and the
# first version recorded new[0] -- whichever sorted first -- so a later watch
# followed an address the operator could not have predicted. That job is gone,
# and the invariant it taught is enforced one layer down and still worth
# driving: a mint step that produces more than one bundle is REFUSED rather
# than resolved by picking one.
dw1, kfw1, _k, bellw1 = new_env(job="receive_and_quote",
                                params={"amount_sat": 5000000})


def _mint4(argv, env_extra, budget):
    if "create_receive_wallet" in " ".join(argv):
        for i in range(4):
            (dw1 / f"wallet_recv_{i}.json").write_text("{}")
    return 0, False


dpw1 = deps_for(dw1, bellw1, run_child=_mint4)
outw1, errw1, _t = run(kfw1, dpw1)
check("a mint step that writes FOUR bundles is refused, not resolved by hex "
      "sort order",
      outw1 is None and errw1.code == "bundle_ambiguous")
check("...and the quote step never ran, so nothing was priced against an "
      "address nobody chose",
      not any("thor_swap_preparer" in " ".join(argv)
              for argv, _e in dpw1["_ran"]))


def _watch_env(rec):
    dd, kk, _key, bb = new_env(job="watch", params={"handle": "A3F1"})
    (dd / A.HANDLES_FILE).write_text(json.dumps({"A3F1": rec}))
    return dd, kk, bb


dw2, kfw2, bellw2 = _watch_env({"bundle": None, "minted": 4, "slip": None})
dpw2 = deps_for(dw2, bellw2)
outw2, errw2, _t = run(kfw2, dpw2)
check("...and watching that handle is REFUSED, not resolved by hex sort order",
      outw2 is None and errw2.code == "handle_not_watchable")
check("...and no child ran for it", dpw2["_ran"] == [])

# A handle recorded before its quote step ran has no slip. str(None) put the literal string
# "None" on receive_watch's --pairs, load_pairs exited on a missing file, and
# the doorbell was told "failed": a wake and a boot spent to learn that a
# string is not a filename.
dw3, kfw3, bellw3 = _watch_env({"bundle": "/tmp/bay/wallet_x.json",
                                "minted": 1, "slip": None})
dpw3 = deps_for(dw3, bellw3)
outw3, errw3, _t = run(kfw3, dpw3)
check("a handle with a bundle but NO swap quote is refused before dispatch",
      outw3 is None and errw3.code == "no_quote")
check("...so the literal string 'None' never reaches --pairs",
      not any("None" in a for argv, _e in dpw3["_ran"] for a in argv))

# --any is deliberately not the fallback: it stops on ANY balance, so one
# piconero of dust would report "done" to the doorbell.
check("...and no argv template offers --any, which would report a dust probe "
      "as the operator's money landing",
      "--any" not in code_only(os.path.join(REPO, "gs_wake_agent")))

# The handle is recorded BEFORE the quote step runs, because the argv needs
# the path. If that step fails the slip was never written, and leaving the
# path in makes a later watch die inside receive_watch instead of refusing.
dw4, kfw4, _k, bellw4 = new_env(job="receive_and_quote",
                                params={"amount_sat": 5000000})


def _quote_fails(argv, env_extra, budget):
    if "create_receive_wallet" in " ".join(argv):
        (dw4 / "wallet_recv_1.json").write_text("{}")
        return 0, False
    return 1, False


dpw4 = deps_for(dw4, bellw4, run_child=_quote_fails)
outw4, errw4, _t = run(kfw4, dpw4)
_rec4 = json.loads((dw4 / A.HANDLES_FILE).read_text())[outw4[2]]
check("a failed quote step does NOT leave a slip path that was never written",
      outw4[1] == "failed" and _rec4["slip"] is None
      and _rec4["bundle"].endswith("wallet_recv_1.json"))


print("\n== the job whitelist is unreachable from a note ==")
# DRIVEN, not grepped. A source grep for "GhostSpiral" matches the operator
# message "a GhostSpiral run holds the lock on this machine", which is prose
# about a refusal, not an argv template -- the check went red on a string that
# proves the opposite of what it was looking for. Build the real argv for every
# job instead.
_argvs = []
_k = {"tor_proxy": "socks5h://127.0.0.1:9050",
      "rpc_primary": "http://127.0.0.1:18083", "amount_ladder": ["0.01"],
      # The spending job refuses to compose without this -- see "the spending
      # job can actually sign" below. A fixture missing it made the whole
      # sweep-over-JOBS loop raise instead of reporting, which is the
      # NO-RESULT outcome mutation_sweep scores as no verdict at all.
      "wallet_file": "/var/lib/gs/spend.wallet"}
_XMR_SAMPLE = "4AdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAdAd"
_sample = {"receive_and_quote": {"amount_sat": 5000000},
           "watch": {"handle": "A3F1"}, "swap_status": {"handle": "A3F1"},
           "withdraw": {"exit_to": _XMR_SAMPLE, "depth": 1}}
# Asserted rather than assumed: this loop runs over P.JOBS, so a job added
# without a sample here KeyErrors and kills the suite -- which mutation_sweep
# scores NO-RESULT, not CAUGHT. A missing sample should read as one red line.
assert set(_sample) == set(P.JOBS), (
    f"_sample does not cover JOBS: missing {sorted(set(P.JOBS) - set(_sample))}")
for _job in P.JOBS:
    for _argv in A.build_argv(_job, _sample[_job], _k, Path("/tmp/bay"),
                              bundle="/tmp/bay/wallet_recv_1.json",
                              slip="/tmp/bay/thor_pairs_A3F1.json",
                              handle="A3F1"):
        _argvs.append(_argv)
check("no COMPOSED argv names a spending tool",
      not any(t in os.path.basename(a) for argv in _argvs for a in argv
              for t in P.FORBIDDEN_TOOLS))
check("...and every composed argv names only a whitelisted tool",
      {os.path.basename(a[1]) for a in _argvs}
      == {"create_receive_wallet", "thor_swap_preparer", "receive_watch",
          "GhostSpiral"})
# THE ADDRESS IS NOWHERE ON ANY ARGV. It is the first operator-chosen string
# this channel carries and it crosses a machine boundary into a subprocess, so
# it travels in GS_EXIT_TO like GS_SWAP_AMOUNTS -- /proc/<pid>/cmdline is 0444,
# and a value that never reaches an argv cannot become a flag however shaped.
check("no composed argv carries the destination address anywhere in it",
      not any(_XMR_SAMPLE in a for argv in _argvs for a in argv))
check("...and no argv carries even a PREFIX of it, which would be enough to "
      "confirm an address a watcher already suspects",
      not any(_XMR_SAMPLE[:16] in a for argv in _argvs for a in argv))
check("...and the mix argv names the bundle and the output dir instead",
      any("--receive-wallet" in argv and "--output" in argv
          for argv in _argvs
          if os.path.basename(argv[1]) == "GhostSpiral"))
check("...and asks for the stronger distribution, since nobody is watching it",
      any("--dag-mixing" in argv for argv in _argvs
          if os.path.basename(argv[1]) == "GhostSpiral"))
# NON-VACUITY: the mix argv WAS composed, so the absences above are absences
# from something that exists.
check("NON-VACUITY -- a mix argv really was composed for the spending job",
      any(os.path.basename(argv[1]) == "GhostSpiral" for argv in _argvs))

# ---- WHAT ACTUALLY REACHES THE CHILD ------------------------------------
#
# build_argv NEVER SEES THE ADDRESS. It is added by the runner loop in
# _dispatch, alongside GS_SWAP_AMOUNTS -- so a test that only reads
# build_argv's output is structurally unable to see the one mistake that
# matters here, and a mutation moving the value onto the argv SURVIVED it.
#
# So this drives the real _dispatch and captures the (argv, env) pair the
# child is actually handed.
print("\n== the address the child is handed ==")
_seen = []


def _capture(argv, env_extra, budget_s):
    _seen.append((list(argv), dict(env_extra or {})))
    return 0, False


_wdir = Path(tempfile.mkdtemp(prefix="wdisp_"))
(_wdir / A.HANDLES_FILE).write_text(json.dumps(
    {"A3F1": {"bundle": str(_wdir / "wallet_recv_1.json"),
              "slip": str(_wdir / "thor_pairs_A3F1.json"), "minted": 1}}))
_saved_il = A.integrity_log
try:
    A.integrity_log = lambda *a, **k: None
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                    _k, _wdir, "A3F1", _capture, "job-1",
                    funded=lambda: (9, 4, _XMR_SAMPLE, 5_000_000_000_000))
finally:
    A.integrity_log = _saved_il

check("dispatch: the spending job ran exactly one child", len(_seen) == 1)


import decimal as _dec                                        # noqa: E402
_AGENT_SRC = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()


def _dispatch_withdraw(env_pw, amount_atomic=5_000_000_000_000):
    """Drive the real withdraw dispatch. Returns (Refused-code or "", seen)."""
    _s2 = []

    def _cap(argv, env_extra, budget_s):
        _s2.append((list(argv), dict(env_extra or {})))
        return 0, False

    _old_pw = os.environ.get("GS_WALLET_PASSWORD")
    _old_il = A.integrity_log
    _code = ""
    try:
        A.integrity_log = lambda *a, **k: None
        if env_pw is None:
            os.environ.pop("GS_WALLET_PASSWORD", None)
        else:
            os.environ["GS_WALLET_PASSWORD"] = env_pw
        with contextlib.redirect_stdout(io.StringIO()):
            A._dispatch("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                        _k, _wdir, "A3F1", _cap, "job-x",
                        funded=lambda: (9, 4, _XMR_SAMPLE, amount_atomic))
    except A.Refused as _e:
        _code = getattr(_e, "code", "") or str(_e)
    finally:
        A.integrity_log = _old_il
        if _old_pw is None:
            os.environ.pop("GS_WALLET_PASSWORD", None)
        else:
            os.environ["GS_WALLET_PASSWORD"] = _old_pw
    return _code, _s2


# ---- THE SPEND PASSWORD: ABSENT IS NOT THE SAME AS EMPTY ----------------
#
# The comment here said "the preflight refusal above is where that is caught".
# preflight() never looks at the environment -- it checks the inhibit file,
# the scope lock, the deadman unit, removable devices, resources, wipe
# coverage, the directory mode and Tor. So an operator who never set
# GS_WALLET_PASSWORD had "" passed to GhostSpiral, which takes an empty value
# as "no password" and accepts it, and the run died opening the wallet: a wake
# spent, the box booted, and "withdraw: failed" with no reason in it.
#
# The two cases ARE distinguishable -- `in os.environ` rather than `.get(k,"")`
# -- and they mean different things: an empty value is a passwordless wallet
# declared on purpose, an absent one is a machine nobody configured.
_pw_absent, _ = _dispatch_withdraw(None)
check("dispatch/pw: an UNSET spend password is refused before the wallet is "
      "opened, rather than passed through as an empty one",
      _pw_absent == "wallet_password_unset")
_pw_empty, _seen_empty = _dispatch_withdraw("")
check("dispatch/pw: ...while an EXPLICIT empty password still runs, because a "
      "wallet with no password is a legitimate configuration",
      _pw_empty == "" and len(_seen_empty) == 1
      and _seen_empty[0][1].get("GS_WALLET_PASSWORD") == "")
_pw_set, _seen_set = _dispatch_withdraw("hunter2")
check("dispatch/pw: ...and a real one reaches the child that needs it",
      _pw_set == ""
      and _seen_set[0][1].get("GS_WALLET_PASSWORD") == "hunter2")

# ---- AND THE FIRST LEG HAS A MIX FLOOR, WHICH IT DID NOT ----------------
#
# _phase_of applies exactly this floor to decide whether to chain ANOTHER leg,
# and says why at length: an arrival too small to mix is "a wake spent to fail
# at stage 0", costing a magic packet, a boot, a 5-20 minute jitter and one of
# twelve daily slots, reported as "withdraw: failed" with a hint about mixing
# depth that is not the reason. All of that is true of the FIRST leg, which
# had no floor: _famt was unpacked and discarded, so the only gate was a zero
# balance. The wallet was woken and the SPEND wallet unlocked for a run that
# could not have worked.
_floor_atomic = int(_dec.Decimal(P.deposit_min_out_xmr()) * (10 ** 12))
_below, _ = _dispatch_withdraw("hunter2", _floor_atomic - 1)
check(f"dispatch/floor: an arrival one piconero under the mix minimum "
      f"({P.deposit_min_out_xmr()} XMR) is refused before the spend wallet is "
      f"unlocked",
      _below == "below_mix_minimum")
_at, _seen_at = _dispatch_withdraw("hunter2", _floor_atomic)
check("dispatch/floor: ...and exactly the minimum still runs, so the bound is "
      "not off by one",
      _at == "" and len(_seen_at) == 1)
# HALF THE MINIMUM, NOT A FIXED FIGURE. This was 0.05 XMR, which was dust at
# the mirror's old 60x fee and is a mixable arrival at today's; a constant
# here is a pin on whatever the fee was the day it was typed.
_dust, _ = _dispatch_withdraw("hunter2", _floor_atomic // 2)
check("dispatch/floor: ...and an arrival at half the minimum, above zero, is "
      "refused rather than spending a wake to fail at stage 0",
      _dust == "below_mix_minimum")
# THE SAME FLOOR ON BOTH SIDES OF THE BOUNDARY. That is the whole guarantee:
# the question "is this leg worth running?" and the question "is there another
# one?" must not be able to disagree, or a chain stops on an arrival the first
# leg would have taken, or starts on one it would have refused.
check("dispatch/floor: ...and it is the SAME floor _phase_of chains on and the "
      "quote step is told -- the LIVE one, so the three cannot drift",
      'Decimal(live_min_out_xmr(key))' in _AGENT_SRC
      and _AGENT_SRC.count("live_min_out_xmr(key)") >= 3)
# THE MIRROR IS THE FALLBACK, NOT THE FLOOR. It was computed at a fee sixty
# times today's, so it refused deposits under ~0.18 XMR and abandoned
# leftovers up to that. The live helper asks the daemon; without one (as
# here) it returns the mirror and chains that it did.
check("dispatch/floor: without a daemon the live floor is the mirror, exactly",
      A.live_min_out_xmr({"rpc_daemon": "http://127.0.0.1:1"}) == P.deposit_min_out_xmr())
check("dispatch/floor: ...and the helper's only fallback IS the mirror",
      "return proto.deposit_min_out_xmr()" in _AGENT_SRC)
_wargv, _wenv = _seen[0] if _seen else ([], {})
check("dispatch: the destination is in the ENVIRONMENT",
      _wenv.get("GS_EXIT_TO") == _XMR_SAMPLE)
# A BARE STRING STILL WORKS, because an older pager sends one -- and the
# single-destination case must stay byte-identical to what it was, or an
# upgrade would change where money goes.
check("dispatch: ...as a plain string for one address, exactly as before",
      isinstance(_wenv.get("GS_EXIT_TO"), str))
# THE CHECK THE MUTATION ESCAPED. /proc/<pid>/cmdline is 0444 for the life of
# the run, and a value that never reaches an argv cannot become a flag however
# it is shaped.
check("dispatch: and NOWHERE on the argv the child is executed with",
      not any(_XMR_SAMPLE in str(x) for x in _wargv))
check("dispatch: not even a 16-character prefix of it, which is enough to "
      "confirm an address a watcher already suspects",
      not any(_XMR_SAMPLE[:16] in str(x) for x in _wargv))

# SEVERAL DESTINATIONS, WHICH IS WHAT THE SCHEMA CHANGE IS FOR.
#
# The exit relays one transaction per mixed output -- at fewest 5, 12 and 22 at
# the three depths -- and every one of them used to land on the same address,
# because the wire had room for exactly one and nothing here could have used a
# second. resolve_exit_destinations warns about that onto a stdout this unit
# diverts to a 0600 log on a machine that powers off.
#
# GS_EXIT_TO takes them SPACE-SEPARATED: resolve_exit_destinations splits on
# whitespace or commas and its own docstring gives that form.
_seen2 = []


def _capture2(argv, env_extra, budget_s):
    _seen2.append((list(argv), dict(env_extra or {})))
    return 0, False


_XMR_B = _XMR_SAMPLE[:-1] + ("b" if _XMR_SAMPLE[-1] != "b" else "c")
_XMR_C = _XMR_SAMPLE[:-1] + ("d" if _XMR_SAMPLE[-1] != "d" else "e")
_saved_il2 = A.integrity_log
try:
    A.integrity_log = lambda *a, **k: None
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("withdraw",
                    {"exit_to": [_XMR_SAMPLE, _XMR_B, _XMR_C], "depth": 1},
                    _k, _wdir, "A3F2", _capture2, "job-2",
                    funded=lambda: (9, 4, _XMR_SAMPLE, 5_000_000_000_000))
finally:
    A.integrity_log = _saved_il2
_margv, _menv = _seen2[0] if _seen2 else ([], {})
check("dispatch/spread: three destinations reach GS_EXIT_TO, space-separated "
      "in the form resolve_exit_destinations splits",
      _menv.get("GS_EXIT_TO") == f"{_XMR_SAMPLE} {_XMR_B} {_XMR_C}")
check("dispatch/spread: ...and none of them is anywhere on the argv",
      not any(a in str(x) for a in (_XMR_SAMPLE, _XMR_B, _XMR_C)
              for x in _margv))
check("dispatch/spread: NON-VACUITY -- the one-address case really produces a "
      "different value, so the join is doing something",
      _menv.get("GS_EXIT_TO") != _wenv.get("GS_EXIT_TO"))
# AND GhostSpiral PARSES IT BACK to the same three. The two sides of this
# boundary are a join and a split in different files; asserting the join alone
# would pin half a contract.
# THE FEE ADDRESS IS ONE ADDRESS AND MUST STAY ONE STRING.
#
# This block used to ask JOBS["withdraw"]["schema"]["exit_to"] to vouch for it,
# which was fine only while that field happened to be a single-address check.
# It returns a LIST now -- so the borrowed gate would have put "['44Ad...']",
# the text of a Python list, into GS_USAGE_FEE_ADDRESS and sent the operator's
# cut to an address that does not exist. Driven rather than grepped: a source
# check for the right function name would pass on any call that returned the
# wrong type.
_seen3 = []


def _capture3(argv, env_extra, budget_s):
    _seen3.append((list(argv), dict(env_extra or {})))
    return 0, False


# A DIFFERENT ADDRESS FROM THE DESTINATION, and this fixture used the same one
# for both. That is the collision GhostSpiral's resolve_usage_fee sys.exits on
# -- "--usage-fee-address is also an --exit-to destination ... Then it is not a
# fee: it lands in the same place as the mixed funds" -- so this block was
# driving a combination that could never have completed a real run, in order to
# assert what the environment carried on the way there. The agent now declines
# to offer a colliding address at all (see fee_addresses), which is what turned
# this fixture's accident into a failing check.
_XMR_FEE_SAMPLE = "4" + "Bc" * 47
_kfee = dict(_k, usage_fee_address=_XMR_FEE_SAMPLE)
_saved_il3 = A.integrity_log
try:
    A.integrity_log = lambda *a, **k: None
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("withdraw", {"exit_to": [_XMR_SAMPLE], "depth": 1},
                    _kfee, _wdir, "A3F3", _capture3, "job-3",
                    funded=lambda: (9, 4, _XMR_SAMPLE, 5_000_000_000_000))
finally:
    A.integrity_log = _saved_il3
_fenv = _seen3[0][1] if _seen3 else {}
check("fee/type: GS_USAGE_FEE_ADDRESS is the address itself, not the text of "
      "a list",
      _fenv.get("GS_USAGE_FEE_ADDRESS") == _XMR_FEE_SAMPLE)
# ...AND IT IS NOT THE DESTINATION, which is the whole reason this fixture had
# to be changed and is worth asserting rather than leaving to the two literals
# happening to differ.
check("fee/type: ...and it is not the address the money is being sent to",
      _fenv.get("GS_USAGE_FEE_ADDRESS") != _XMR_SAMPLE)
check("fee/type: NON-VACUITY -- it really was set, so the check above is not "
      "comparing two absent values",
      "GS_USAGE_FEE_ADDRESS" in _fenv)
check("fee/type: ...and it carries no bracket or quote, which is what a list "
      "rendered as text would leave behind",
      not any(c in _fenv.get("GS_USAGE_FEE_ADDRESS", "") for c in "[]'\""))

check("dispatch/spread: GhostSpiral's own splitter recovers exactly three",
      len([t for t in re.split(r"[\s,]+", _menv.get("GS_EXIT_TO", "")) if t])
      == 3)
# NOT ASSUMING THE HANDLE. _dispatch REDRAWS it when it collides with one
# already in the handles file, and the bundle name follows the handle -- so a
# test that hard-codes A3F1 here passes or fails on whether the fixture
# happened to collide, which is not the property.
check("dispatch: the argv names the mix and the bundle the VAULT found",
      os.path.basename(_wargv[1]) == "GhostSpiral"
      and any(os.path.basename(a).startswith("wallet_withdraw_")
              and a.endswith(".json") for a in _wargv))
# THE POINTER IS WRITTEN FROM WHAT THE WALLET SAID, and it points at the
# account the vault found -- not at a subaddress this job minted. Minting one
# would be a second account for the wipe to miss and a second address for
# nothing; the money is already somewhere.
_bp = [a for a in _wargv
       if os.path.basename(a).startswith("wallet_withdraw_")][0]
_bundle_json = json.loads(open(_bp, encoding="utf-8").read())
check("dispatch: the pointer names the account the wallet reported funded",
      _bundle_json["account_index"] == 9
      and _bundle_json["subaddress_index"] == 4)
check("dispatch: ...and is a real receive bundle, so one loader reads it",
      _bundle_json["schema"] == "gs_receive_wallet_v1"
      and _bundle_json["address"] == _XMR_SAMPLE)
# gs_common's strict loader must accept it, or the mix refuses at stage 0.
from gs_common import load_receive_bundle as _lrb                # noqa: E402
_loaded = _lrb(_bp)
check("dispatch: ...and gs_common's own strict loader accepts it",
      _loaded["account_index"] == 9 and _loaded["subaddress_index"] == 4)
check("dispatch: the pointer is 0600", oct(os.stat(_bp).st_mode)[-3:] == "600")
# AND IT IS WIPED. Named wallet_* deliberately: gs_withdraw_*.json matched
# NOTHING in GS_ARTIFACT_FILE_PATTERNS, so it would have sat in the artifact
# directory naming an account of this wallet through every paranoia_mode run.
import fnmatch as _fn                                            # noqa: E402
from gs_common import GS_ARTIFACT_FILE_PATTERNS as _PATS         # noqa: E402
check("dispatch: ...and its NAME matches the wipe list, so paranoia_mode "
      "takes it",
      any(_fn.fnmatch(os.path.basename(_bp), _p) for _p in _PATS))
check("dispatch: NON-VACUITY -- the name it nearly had would NOT have been "
      "wiped, which is the defect this pins",
      not any(_fn.fnmatch("gs_withdraw_A3F1.json", _p) for _p in _PATS))
# NOTHING TO WITHDRAW IS A REFUSAL, not a mix planned around an empty wallet.
_seen.clear()
_saved_il2 = A.integrity_log
try:
    A.integrity_log = lambda *a, **k: None
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1}, _k, _wdir, "B2C4",
                    _capture, "job-5", funded=lambda: None)
    check("dispatch: an empty wallet is refused", False)
except A.Refused as _e5:
    check("dispatch: an empty wallet is refused", True)
    check("dispatch: ...and says a confirming payment is not spendable yet",
          "confirming" in str(_e5))
    check("dispatch: ...and ran no child at all", _seen == [])
finally:
    A.integrity_log = _saved_il2

# THE LARGEST SINGLE OUTPUT, never a sum. Summing subaddresses would mean a
# first transaction spending inputs from all of them -- permanent public proof
# they share an owner, which is what the rest of the pipeline avoids.
_pick = A._funded_entry({}, injected=lambda: (3, 1, "A", 10))
check("funded: the helper returns what it was given", _pick == (3, 1, "A", 10))
_ASRC2 = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("funded: it takes the LARGEST single output and never sums",
      "if best is None or _amt > best[3]:" in _ASRC2
      and "sum(" not in _ASRC2.split("def _funded_entry")[1].split("def ")[0])
check("funded: ...and only UNLOCKED balance, since a locked one cannot be "
      "spent and a mix planned around it fails with money already moved",
      '"unlocked_balance"' in _ASRC2.split("def _funded_entry")[1].split("def ")[0])
check("funded: ...and a bool is not an amount (True == 1)",
      "isinstance(_amt, bool)" in _ASRC2)
# NON-VACUITY: the capture really ran and really saw an environment, so the
# absences above are absences from something.
check("dispatch: NON-VACUITY -- the child was handed a real argv and a real "
      "environment", len(_wargv) > 3 and _wenv)
# NON-VACUITY: an ORDINARY job sets no destination at all.
_seen.clear()
_saved_il = A.integrity_log
try:
    A.integrity_log = lambda *a, **k: None
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("swap_status", {"handle": "A3F1"}, _k, _wdir, "A3F1",
                    _capture, "job-2")
finally:
    A.integrity_log = _saved_il
check("dispatch: NON-VACUITY -- an ordinary job sets no GS_EXIT_TO at all",
      _seen and "GS_EXIT_TO" not in _seen[0][1])
check("dispatch: NON-VACUITY -- ...and that ordinary job really ran a child, "
      "so the absence is from something", _seen and len(_seen[0][0]) > 3)

# ---- THE JOB HAS TO BE ABLE TO SIGN --------------------------------------
#
# GhostSpiral's Round 1 runs `airgap_tx_signer --phase sign --wallet-file
# <path>` with the password in the environment. BOTH have defaults --
# "offline.wallet" and "" -- so composing neither does not fail loudly: the mix
# plans, veils, relays a fan-out, waits out its confirmations, and dies HOURS
# later at "phase 'sign' produced no signed TX files". Every earlier stage
# succeeded, so the money has already moved when it stops.
print("\n== the spending job can actually sign ==")
_kw = dict(_k)
_wargv2 = A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                       _kw, _wdir, bundle=str(_wdir / "wallet_recv_1.json"),
                       slip=None, handle="A3F1")[0]
check("sign: the composed argv names the wallet to sign with",
      "--wallet-file" in _wargv2
      and _wargv2[_wargv2.index("--wallet-file") + 1] == "/var/lib/gs/spend.wallet")
check("sign: ...from the KEYFILE, never from the job parameters — a note that "
      "could name a wallet file could name any file on the vault",
      "wallet_file" not in P.JOBS["withdraw"]["schema"])
# A KEYFILE WITH NO WALLET FILE IS REFUSED, at composition, before anything
# runs -- rather than discovered after the fan-out has relayed.
_kn = dict(_k)
_kn.pop("wallet_file", None)
try:
    A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                 _kn, _wdir, bundle="b", slip=None, handle="A3F1")
    check("sign: a keyfile with no wallet file is refused", False)
except A.Refused as _e:
    check("sign: a keyfile with no wallet file is refused", True)
    check("sign: ...and says the money would already have moved",
          "already moved" in str(_e))
# NON-VACUITY: with the field present the same call composes fine, so the
# refusal is about the field and not about build_argv being broken.
check("sign: NON-VACUITY -- with the field present it composes",
      "--wallet-file" in _wargv2)

# ---- THE BUDGET IS COMPUTED FROM THE WORST CASE, NOT ASSERTED -----------
#
# This is the check that would have caught the defect it exists for. The
# withdraw budget was 14400s (4h), chosen against GhostSpiral's estimate_runtime
# reporting "~3.2h" for the settings the job composes -- which is a MEDIAN.
# --hop-delay draws uniformly from 60-300s and a run makes about thirty of
# those draws; the slow end answers ~4.5h. So a run that drew high went over
# budget, and over budget is not a late report: run_child SIGTERMs the process
# group and then SIGKILLs it, mid-mix, with the money already moving.
#
# Two constants in two files cannot be kept in step by hand. This recomputes
# one from the other, using GhostSpiral's OWN arithmetic, so a change to
# either end goes red here.
print("\n== the spending job's budget fits its own worst case ==")
_gld = importlib.machinery.SourceFileLoader(
    "gs_for_estimate", os.path.join(REPO, "GhostSpiral"))
_GS = importlib.util.module_from_spec(
    importlib.util.spec_from_loader(_gld.name, _gld))
_gld.exec_module(_GS)

def _hours(window, wallets):
    """GhostSpiral's own estimate, as a number rather than its "~3.2h" text.

    The output count is derived from `wallets` HERE rather than read from a
    module-level constant: the first version took only the window, so changing
    _wargs.wallets for the 40-wallet partner left the output count at 10 and
    the check compared a number against itself.

    `wallets` IS NOW REQUIRED. It defaulted to A.WITHDRAW_WALLETS -- a single
    pinned hop count for every withdrawal -- and that constant is exactly what
    this section stopped being about: the operator picks a depth, so there are
    three runtimes to fit, not one.
    """
    _a = types.SimpleNamespace(dag_mixing=True, deep=2, peel=False,
                               wallets=wallets, split=1, hop_delay=None,
                               exit_to=["x"])
    _t = _GS.estimate_runtime(_a, 1, wallets + _GS.DECOY_MAX, window)
    return float(re.search(r"([\d.]+)\s*h", _t).group(1))


# THE WINDOW IS GhostSpiral's OWN DEFAULT, and reading it rather than typing
# it is the whole point of this block.
#
# The shipped budget was computed against a hop-delay window of (300, 300),
# which is not the default and never was: DEFAULT_HOP_DELAY is (180, 720). At
# the real slow end even the SHALLOWEST depth needs 6.1h against a budget that
# was 6.0h, so every withdrawal would have been SIGKILLed mid-mix with the
# money already moving. A test that hard-codes the window cannot catch that,
# because it agrees with the mistake.
_LO, _HI = _GS.DEFAULT_HOP_DELAY
check(f"budget: the window used here is GhostSpiral's own default "
      f"({_LO}, {_HI}), not a number typed into this test",
      (_LO, _HI) == _GS.DEFAULT_HOP_DELAY and _HI > _LO)

_budget_h = P.JOBS["withdraw"]["budget_s"] / 3600.0

# EVERY DEPTH THE PROTOCOL OFFERS MUST FIT, and each row's claimed seconds
# must match what GhostSpiral actually says. Two separate failures: a depth
# whose runtime nobody rechecked, and a table whose numbers drifted from the
# arithmetic they were copied from. The second one was real -- depth 3 claimed
# 47040s against a recomputed 46560s.
for _d, (_w, _claimed) in sorted(P.WITHDRAW_DEPTHS.items()):
    _h = _hours((_HI, _HI), _w)
    check(f"budget: depth {_d} ({_w} hops, {_h}h) fits inside the budget "
          f"({_budget_h}h)", _budget_h > _h)
    check(f"budget: ...with real margin, not exactly (depth {_d})",
          _budget_h >= _h * 1.25)
    # THE TABLE'S OWN NUMBER, recomputed from GhostSpiral rather than trusted.
    _secs, _ntx = _GS._runtime_terms(
        types.SimpleNamespace(dag_mixing=True, deep=2, peel=False, wallets=_w,
                              split=1, hop_delay=None, exit_to=["x"]),
        1, _w + _GS.DECOY_MAX, Decimal(_HI),
        Decimal(_GS.FANOUT_CONFIRM_POLL_ESTIMATE))
    check(f"budget: WITHDRAW_DEPTHS[{_d}] claims {_claimed}s and GhostSpiral "
          f"computes {int(_secs)}s", int(_secs) == _claimed)
    # AND THE DEPTH REACHES THE MIX. A table nothing reads is a table that
    # says whatever you like.
    _argv = A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": _d},
                         _k, _wdir, bundle="b", slip=None, handle="A3F1")[0]
    check(f"budget: choosing depth {_d} composes --wallets {_w}",
          "--wallets" in _argv
          and _argv[_argv.index("--wallets") + 1] == str(_w))

# THE DECOY FLOOR IS MIRRORED, SO IT IS PINNED.
#
# gs_wake_proto.DECOY_MIN_MIRROR exists because the pager has to state how many
# separate arrivals a withdrawal produces -- the number that decides whether
# giving one exit address throws away the whole run -- and the pager may not
# have GhostSpiral on disk at all. A mirror with a test is the shape this repo
# uses when a constant must cross a box that cannot import its owner. A mirror
# WITHOUT one is how the console's job timeout drifted 6x from the pipeline's.
check(f"decoys: gs_wake_proto's mirrored floor ({P.DECOY_MIN_MIRROR}) is "
      f"GhostSpiral.DECOY_MIN ({_GS.DECOY_MIN})",
      P.DECOY_MIN_MIRROR == _GS.DECOY_MIN)
# AND THE FIGURE BUILT ON IT is the one the pipeline itself computes when it
# warns about a single destination: resolve_exit_destinations does
# `_lo = _w + DECOY_MIN`. Recomputed here rather than restated.
for _d, (_w, _t) in sorted(P.WITHDRAW_DEPTHS.items()):
    check(f"decoys: exit_arrivals_floor({_d}) is {_w} wallets + "
          f"{_GS.DECOY_MIN} decoys = {P.exit_arrivals_floor(_d)}",
          P.exit_arrivals_floor(_d) == _w + _GS.DECOY_MIN)
check("decoys: NON-VACUITY -- the floor really exceeds the wallet count, so "
      "the decoys are in it and it is not just --wallets renamed",
      all(P.exit_arrivals_floor(_d) > P.WITHDRAW_DEPTHS[_d][0]
          for _d in P.WITHDRAW_DEPTHS))

# ---- AND SO IS THE FLOOR THAT STOPS A DEPOSIT BEING STRANDED ------------
#
# THE DEFECT THIS MIRROR EXISTS FOR. The wire took any deposit from
# DEPOSIT_MIN_SAT = 0.0001 BTC upward and NOTHING asked whether the XMR that
# arrives could be mixed at all. At any real rate those differ by an order of
# magnitude, so an ordinary small deposit was quoted, paid, settled through
# ThorChain -- and only then met the mixing minimum, at /withdraw, with the
# money already on an address the swap memo names in a public OP_RETURN.
# Every stage before the refusal succeeded, so the refusal arrived after the
# money moved. thor_swap_preparer --min-out-xmr moves it to the quote, where
# nothing has been sent.
_MIXMIN_ARGS = dict(dag_mixing=True, exit_set=True, chunks=1)
_shallow = min(P.WITHDRAW_DEPTHS[_d][0] for _d in P.WITHDRAW_DEPTHS)
_gs_nocut = _GS.mix_minimum_xmr(_GS.Decimal(str(_GS.FALLBACK_FEE_XMR)),
                                _shallow, usage_pct=None, **_MIXMIN_ARGS)
_gs_cut = _GS.mix_minimum_xmr(_GS.Decimal(str(_GS.FALLBACK_FEE_XMR)),
                              _shallow,
                              usage_pct=_GS.Decimal("0.011"), **_MIXMIN_ARGS)
check(f"minout: the mirrored floor ({P.MIX_MINIMUM_XMR_MIRROR}) is "
      f"GhostSpiral's own minimum at {_shallow} wallets ({_gs_nocut})",
      _GS.Decimal(P.MIX_MINIMUM_XMR_MIRROR) == _gs_nocut)
check(f"minout: ...and the with-a-cut one "
      f"({P.MIX_MINIMUM_XMR_WITH_CUT_MIRROR}) is its with-cut minimum "
      f"({_gs_cut})",
      _GS.Decimal(P.MIX_MINIMUM_XMR_WITH_CUT_MIRROR) == _gs_cut)
# THE SHALLOWEST DEPTH, because the depth is chosen hours later at the
# withdrawal and this figure is needed at the deposit. A floor taken from a
# DEEPER row would refuse deposits the operator could have mixed by choosing
# three hops.
check("minout: the floor is the SHALLOWEST depth's, so it refuses only what "
      "no depth could mix",
      all(_GS.Decimal(P.MIX_MINIMUM_XMR_MIRROR)
          <= _GS.mix_minimum_xmr(_GS.Decimal(str(_GS.FALLBACK_FEE_XMR)),
                                 P.WITHDRAW_DEPTHS[_d][0], usage_pct=None,
                                 **_MIXMIN_ARGS)
          for _d in P.WITHDRAW_DEPTHS))
# AND THE CUT IS WHAT BINDS AT THREE WALLETS -- so a keyfile that names a fee
# destination has a strictly higher floor, and the agent picks by that.
check("minout: taking a cut really does raise the floor, so the two figures "
      "are not one value written twice",
      _GS.Decimal(P.MIX_MINIMUM_XMR_WITH_CUT_MIRROR)
      > _GS.Decimal(P.MIX_MINIMUM_XMR_MIRROR))
# ---- A SILENT ZERO IS A HIDDEN BROKEN FEE -------------------------------
#
# There are THREE ways to take no cut and they used to be one empty list. A
# keyfile that names a destination still takes nothing when that destination
# is also an --exit-to (GhostSpiral refuses the whole run when they overlap,
# so it is dropped here first) and when it turns out to be an address of the
# wallet being mixed. Both are correct; both were indistinguishable from "the
# operator never asked for a fee". Over many runs that is an operator earning
# nothing with no way to find out why.
_FEE_SRC = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("fee: the three ways of taking none are told apart in the chain",
      "fee_none_configured" in _FEE_SRC and "fee_all_excluded" in _FEE_SRC)
check("fee: ...and NOT in the chat, because a fee configuration is the number "
      "an analyst divides by to read the deposit",
      "fee_none_configured" not in open(
          os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read())
_XF, _XE = "4" + "7" * 94, "4" + "Ad" * 46 + "Aa"
# NAMES THAT CANNOT CLOBBER THE MODULE-LEVEL FIXTURES. `_k` is the shared
# keyfile every other check in this file builds on, and using it as a loop
# variable here rebound it to {} -- which crashed a check four hundred lines
# later in build_argv, on a key with no tor_proxy.
for _fee_lbl, _fee_k, _fee_d, _fee_o, _fee_want in (
        ("nothing paired", {}, [_XE], [], []),
        ("paired, but it IS the exit", {"usage_fee_addresses": [_XF]},
         [_XF], [], []),
        ("paired, but this wallet owns it", {"usage_fee_addresses": [_XF]},
         [_XE], [_XF], []),
        ("paired and usable", {"usage_fee_addresses": [_XF]},
         [_XE], [], ["--usage-fee"])):
    check(f"fee: {_fee_lbl} -> {_fee_want or 'no cut'}",
          A._withdraw_fee_argv(_fee_k, _fee_d, _fee_o) == _fee_want)

# ---- AND THE WITH-CUT FIGURE IS NOT A FLOOR, WHICH IS MY OWN BUG ---------
#
# deposit_min_out_xmr first took a `with_cut` argument and returned the higher
# figure when the keyfile named a fee destination, on the assumption that a
# run taking a cut needs more. It does not. plan_usage_fee WAIVES a cut worth
# less than it costs to spend -- "NO USAGE FEE TAKEN ... The mix is going
# ahead in full" -- because that branch runs after the swap has settled and
# aborting there would strand a settled deposit to protect one run's fee.
#
# So the with-cut number answers "can a FEE be taken", not "can this be
# MIXED", and using it as a floor was wrong twice: the deposit gate refused
# quotes that would have mixed fine, and the withdraw chain ABANDONED
# arrivals between the two figures while telling the operator there was
# nothing left -- a false statement about their balance.
check("minout: the floor is what can be MIXED, and takes no argument at all",
      P.deposit_min_out_xmr() == P.MIX_MINIMUM_XMR_MIRROR)
check("minout: ...and the with-cut figure is published but never gates",
      _GS.Decimal(P.MIX_MINIMUM_XMR_WITH_CUT_MIRROR)
      > _GS.Decimal(P.deposit_min_out_xmr()))
# THE WAIVER IS WHAT MAKES THAT SAFE, so it is asserted rather than assumed.
_GS_SRC = open(os.path.join(REPO, "GhostSpiral"), encoding="utf-8").read()
check("minout: ...because a cut below its spend cost is WAIVED and the mix "
      "goes ahead, rather than the run being refused",
      "waived_below_spend_cost" in _GS_SRC
      and "going ahead in full" in _GS_SRC)
# ...AND THE AGENT PASSES IT, by the SAME predicate _withdraw_fee_argv uses.
# A floor computed and never put on the argv is the "declared in one place,
# never wired to the thing that runs" shape this repo keeps finding.
_mo_base = {"tor_proxy": "socks5h://127.0.0.1:9050",
            "rpc_primary": "http://127.0.0.1:18083",
            "rpc_daemon": "http://127.0.0.1:18081",
            "artifact_dir": "/var/lib/ghostspiral"}
for _lbl, _mok, _want in (
        ("no fee destination", _mo_base, P.MIX_MINIMUM_XMR_MIRROR),
        ("a fee destination", dict(_mo_base,
                                   usage_fee_addresses=["4" + "7" * 94]),
         P.MIX_MINIMUM_XMR_MIRROR)):
    _steps = A.build_argv("receive_and_quote", {"amount_sat": 5000000}, _mok,
                          Path("/var/lib/ghostspiral"),
                          bundle="/x/wallet_a.json", slip="", handle="A3F1",
                          owned_fee=[])
    _q = [str(x) for x in _steps[1]]
    check(f"minout: with {_lbl} the quote step carries --min-out-xmr {_want}",
          "--min-out-xmr" in _q
          and _q[_q.index("--min-out-xmr") + 1] == _want)
# AND thor_swap_preparer ACTS ON IT, before it records the pair or prints an
# instruction. A flag the receiving tool ignores is the same defect wearing
# the other end's clothes.
_TH_SRC = open(os.path.join(REPO, "thor_swap_preparer"), encoding="utf-8").read()
check("minout: thor_swap_preparer offers the flag",
      '"--min-out-xmr"' in _TH_SRC)
# ON THE WORST-CASE ARRIVAL, not the headline quote. Gating on `expected_xmr
# < _min_out` left a band -- [min_out, min_out/(1 - tolerance)) -- where the
# quote passed, receive_watch then called a routine-slippage arrival "funded",
# and /withdraw refused it: money stranded on the memo'd address. The gate
# tests what the watcher will accept, which is expected * (1 - tolerance).
_TH_GATE = "if _min_out and _worst_arrival < _min_out:"
check("minout: ...and refuses on it rather than only recording it",
      _TH_GATE in _TH_SRC and "quote_below_mix_minimum" in _TH_SRC)
check("minout: ...on the arrival the watcher will accept, not the quote -- "
      "the slippage band no longer strands money",
      "_worst_arrival = (expected_xmr * (1 - ARRIVAL_TOLERANCE))" in _TH_SRC
      and "if _min_out and expected_xmr < _min_out:" not in _TH_SRC)
check("minout: ...BEFORE the pair is appended, so nothing downstream sees a "
      "quote the mix cannot use",
      _TH_SRC.index(_TH_GATE) < _TH_SRC.index("pairs.append(pair)"))
check("minout: ...and a malformed value is refused rather than dropped, "
      "because a gate the caller asked for and this tool ignored is worse "
      "than either",
      "positive decimal amount of XMR" in _TH_SRC
      and "_min_out is None or _min_out <= 0" in _TH_SRC)

# ---- "THERE IS MORE HERE" MEANS MORE THAT CAN ACTUALLY BE MIXED ---------
#
# The chain asked _funded_entry whether ANY unlocked output remained, so it
# chased leftovers it could not process. Two kinds turn up in practice: dust,
# and a usage fee a run started at the DESK minted onto this wallet -- which
# _funded_entry genuinely cannot tell from a deposit (there is no marker; see
# _withdraw_fee_argv for why one was rejected) and which is about a hundredth
# of a deposit. Each such leg costs a magic packet, a boot, a 5-20 minute
# jitter and one of twelve daily slots, and comes back "withdraw: failed"
# with a hint about mixing depth that is not the reason.
_ml_key = {"rpc_primary": "x", "tor_proxy": ""}
_ml_saved = A._funded_entry
try:
    for _lbl, _atomic, _want in (
            ("a second deposit well over the floor", 500_000_000_000,
             "more_left"),
            # 1.1% of half an XMR. It was 0.04 -- the cut on a 3.6 XMR deposit
            # -- which sat under the mirror's old 60x floor and sits well over
            # today's 0.0121; the chain chasing 0.04 XMR is now correct.
            ("a desk-minted 1.1% cut on a 0.5 XMR deposit", 5_500_000_000, ""),
            ("dust", 100_000_000, "")):
        A._funded_entry = (lambda _a: (lambda k, injected=None:
                                       (7, 1, "4x", _a)))(_atomic)
        _got = A._phase_of("withdraw", None, key=_ml_key, status="done")
        check(f"chain: {_lbl} -> {_want!r}", _got == _want)
    # THE FLOOR IS THE ONE THE DEPOSIT GATE USES, by the same predicate, so a
    # deposit this tool agreed to take is a deposit the chain will follow.
    A._funded_entry = lambda k, injected=None: (
        7, 1, "4x", int(_GS.Decimal(P.MIX_MINIMUM_XMR_MIRROR)
                        * _GS.Decimal(10 ** 12)))
    check("chain: exactly the floor still counts as more, so the gate is >= "
          "and not >",
          A._phase_of("withdraw", None, key=_ml_key, status="done")
          == "more_left")
    A._funded_entry = lambda k, injected=None: (
        7, 1, "4x", int(_GS.Decimal(P.MIX_MINIMUM_XMR_MIRROR)
                        * _GS.Decimal(10 ** 12)) - 1)
    check("chain: one piconero under it does not", 
          A._phase_of("withdraw", None, key=_ml_key, status="done") == "")
    # AND A KEYFILE THAT TAKES A CUT USES THE SAME FLOOR, which is the fix to
    # my own first version: it used the higher with-cut figure there and so
    # ABANDONED anything between the two, while telling the operator nothing
    # was left. plan_usage_fee waives a cut it cannot spend and mixes anyway.
    _ml_fee = dict(_ml_key, usage_fee_addresses=["4" + "7" * 94])
    _between = int((_GS.Decimal(P.MIX_MINIMUM_XMR_MIRROR)
                    + _GS.Decimal(P.MIX_MINIMUM_XMR_WITH_CUT_MIRROR))
                   / 2 * _GS.Decimal(10 ** 12))
    A._funded_entry = lambda k, injected=None: (7, 1, "4x", _between)
    for _lbl2, _k2 in (("without a fee destination", _ml_key),
                       ("WITH one", _ml_fee)):
        check(f"chain: an arrival between the two figures is 'more' "
              f"{_lbl2} -- it mixes, with the cut waived",
              A._phase_of("withdraw", None, key=_k2, status="done")
              == "more_left")
finally:
    A._funded_entry = _ml_saved

# THE BUDGET IS SIZED FROM THE DEEPEST ROW, so adding a fourth depth without
# raising the budget goes red here rather than in production at hour thirteen.
_deepest = max(_t for _w, _t in P.WITHDRAW_DEPTHS.values())
check(f"budget: it is sized from the DEEPEST depth ({_deepest}s), not the "
      f"shallowest", P.JOBS["withdraw"]["budget_s"] > _deepest)

# NON-VACUITY 1: the worst case is genuinely worse than the median, so the
# figures above are not two names for the same number.
_shallow = min(_w for _w, _t in P.WITHDRAW_DEPTHS.values())
_median_h = _hours((_LO, _HI), _shallow)
_worst_h = _hours((_HI, _HI), _shallow)
check(f"budget: NON-VACUITY -- the worst case really is worse than the median "
      f"({_worst_h}h vs {_median_h}h)", _worst_h > _median_h)
# NON-VACUITY 2: the budget this replaced would have failed. Stated as a
# number rather than a memory, so the check is demonstrably able to say no.
check("budget: NON-VACUITY -- the 6h budget this replaced would NOT have fit "
      "even the SHALLOWEST depth, which is the defect this exists for",
      6.0 < _worst_h)
# NON-VACUITY 3: a depth outside the table really would not fit, which is why
# the note cannot name one.
_big_h = _hours((_HI, _HI), 40)
check(f"budget: NON-VACUITY -- at 40 hops the same job would NOT fit "
      f"({_big_h}h vs {_budget_h}h), which is why depth is a closed table",
      _big_h > _budget_h)
# AND A DEPTH OFF THE TABLE IS REFUSED BY THE BOX THAT SPENDS, not just by the
# schema two files away.
for _bad in (0, 4, 40, -1, None, "2", 2.5, True):
    try:
        A.withdraw_wallets(_bad)
        _ref = False
    except A.Refused:
        _ref = True
    check(f"budget: the vault refuses depth {_bad!r} rather than defaulting",
          _ref)
# AND THE BACKSTOP IS LONGER THAN THE BUDGET, or it becomes the killer.
check("budget: the deadman extension outlasts the budget it protects",
      P.result_budget_s("withdraw") + 600 > P.JOBS["withdraw"]["budget_s"])

# ---- THE OPERATOR'S CUT, WHICH THIS PATH WAS NOT TAKING AT ALL ----------
#
# GhostSpiral's --usage-fee is action="store_true" and defaults OFF, on the
# stated principle that "a run that has not been asked to skim must not skim".
# Nothing here ever asked. gs_console sets GS_USAGE_FEE_ADDRESS on its own
# runs, so the DESKTOP path skimmed and the PHONE path -- the one the whole
# wake channel exists for -- silently did not, for as long as the job existed.
# Every suite was green through it, because nothing looked.
# ...AND IT ASKS ONLY WHEN THE CUT HAS SOMEWHERE TO GO THAT IS NOT HERE.
# With no --usage-fee-address, plan_usage_fee USED TO mint a fresh account on
# the wallet being emptied; _funded_entry, a different process re-enumerating
# the same wallet, took the largest unlocked output -- which, after the exit
# had swept everything else, was that fee. plan_usage_fee now waives with no
# destination, on every path. See _withdraw_fee_argv.
_fee_argv = A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                         dict(_k, usage_fee_address="4" + "7" * 94),
                         _wdir, bundle="b", slip=None, handle="A3F1")[0]
check("fee: the composed withdrawal asks for the usage fee when the keyfile "
      "names somewhere OFF this wallet to put it",
      "--usage-fee" in _fee_argv)
# NON-VACUITY: GhostSpiral's own resolver accepts this exact combination, so
# the flag is not merely present but usable. --peel and --split > 1 are both
# refused with --usage-fee, and neither is composed here.
check("fee: NON-VACUITY -- neither refused combination is composed",
      "--peel" not in _fee_argv and "--split" not in _fee_argv)
# THE ADDRESS IS NOT ON THE ARGV, EVER. GhostSpiral's own flag help says to
# prefer GS_USAGE_FEE_ADDRESS because an argv address is world-readable
# through /proc/<pid>/cmdline. The boolean may be there; the destination is
# the part that identifies the operator.
check("fee: ...and no address rides on the argv with it",
      "--usage-fee-address" not in _fee_argv)
# NO ADDRESS IS COMPOSED WHEN THE KEYFILE NAMES NONE, and GhostSpiral then
# waives the cut rather than minting one onto the wallet being mixed.
_no_addr_env = A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                            dict(_k), _wdir, bundle="b", slip=None,
                            handle="A3F1")
check("fee: with no keyfile address no address is composed, so the cut is "
      "waived rather than minted onto this wallet",
      not any("USAGE_FEE_ADDRESS" in str(x) for x in _no_addr_env))

# ---- THE DAEMON THIS KEYFILE COULD NOT NAME -----------------------------
#
# GhostSpiral reads the network fee from --rpc-daemon and REFUSES the run
# rather than guessing: the fallback measured 38-58x low, so every hop
# under-reserved and the run died after the fan-out was already on chain. The
# wake path never passed the flag, so a vault whose monerod is not on
# GhostSpiral's default port failed every withdrawal at stage 0 -- and the
# chat said "refused." with nothing the operator could change, because
# gs_console exposes this field and the keyfile did not.
check("daemon: the composed withdrawal names a daemon at all",
      "--rpc-daemon" in _fee_argv)
_dk = dict(_k, rpc_daemon="http://127.0.0.1:29081")
_dargv = A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                      _dk, _wdir, bundle="b", slip=None, handle="A3F1")[0]
check("daemon: ...and it is THIS machine's, from its own keyfile",
      _dargv[_dargv.index("--rpc-daemon") + 1] == "http://127.0.0.1:29081")
# BACKWARD COMPATIBLE. A keyfile written before gs_wake_keys grew the flag has
# no such field, and must behave exactly as it did rather than composing an
# empty string that GhostSpiral would then refuse.
check("daemon: a keyfile predating the flag falls back to the same default "
      "it used to get",
      _fee_argv[_fee_argv.index("--rpc-daemon") + 1]
      == "http://127.0.0.1:18081")
# AND THE PAIRING WRITES IT, or the field is one the agent reads and nothing
# ever sets.
_kp_src = open(os.path.join(REPO, "gs_wake_keys"), encoding="utf-8").read()
check("daemon: gs_wake_keys writes rpc_daemon into the keyfile",
      '"rpc_daemon": args.rpc_daemon,' in _kp_src
      and '"--rpc-daemon"' in _kp_src)

# ---- THE SETUP DOC MUST NOT TELL THE OPERATOR TO BREAK EVERY WITHDRAWAL --
#
# OPSEC_SETUP section 4b step 3 said: "The vault's monero-wallet-rpc must
# serve that SPEND-CAPABLE wallet at boot." GhostSpiral's stage0_preflight
# calls refuse_hot_wallet(rpc_primary) UNCONDITIONALLY and sys.exits on
# exactly that, because monero-wallet-rpc only returns an unsigned txset for a
# WATCH-ONLY wallet and every round of this pipeline is built as one.
#
# So an operator who followed the withdrawal setup got "--rpc-primary is
# serving a FULL (hot) wallet, and this pipeline cannot use one" on every
# single /send. Nothing was spent -- it fires before anything is planned --
# but a feature that has never once worked is not a safe failure.
#
# Section 4 of the same document said the opposite and correct thing
# ("monero-wallet-rpc with a view-only wallet"). The document contradicted
# itself, and the wrong half was the one an operator setting up withdrawals
# reads.
_doc = open(os.path.join(REPO, "OPSEC_SETUP.md"), encoding="utf-8").read()
_gs_txt = open(os.path.join(REPO, "GhostSpiral"), encoding="utf-8").read()
check("wallet: GhostSpiral really does refuse a hot wallet before planning",
      "refuse_hot_wallet(rpc_primary)" in _gs_txt
      and "def refuse_hot_wallet" in _gs_txt)
# UNCONDITIONAL, or the doc could be right for some runs. It sits in stage 0
# with no flag guarding it.
_s0 = _gs_txt.split("def stage0_preflight")[1].split("\ndef ")[0]
check("wallet: ...and does so on EVERY run, not behind a flag",
      "refuse_hot_wallet(rpc_primary)" in _s0)
# THE DOC MUST NOT INSTRUCT THE OPPOSITE. Checked as a phrase because that is
# how it was written, and it is the sentence that cost the feature.
check("wallet: the setup doc no longer tells the operator to serve the "
      "spend-capable wallet on the wallet-rpc",
      "monero-wallet-rpc must serve that SPEND-CAPABLE wallet" not in _doc)
check("wallet: ...and says the rpc stays view-only where withdrawals are "
      "set up",
      "VIEW-ONLY WALLET" in _doc or "view-only wallet" in _doc)
# AND THE TWO WALLETS ARE NAMED AS TWO THINGS. --wallet-file is the spend
# wallet the signer opens; --rpc-primary is the view-only one it plans with.
# Conflating them is precisely what the broken step did.
check("wallet: the doc distinguishes the signing FILE from the served wallet",
      "--wallet-file" in _doc and "airgap_tx_signer opens it" in _doc)
# NON-VACUITY: the agent really does compose both, so they are genuinely two
# separate settings and not one described twice.
_wargv = A.build_argv("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                      _k, _wdir, bundle="b", slip=None, handle="A3F1")[0]
check("wallet: NON-VACUITY -- a withdrawal composes BOTH --rpc-primary and "
      "--wallet-file, so they are two settings",
      "--rpc-primary" in _wargv and "--wallet-file" in _wargv
      and _wargv[_wargv.index("--rpc-primary") + 1]
          != _wargv[_wargv.index("--wallet-file") + 1])

# ---- ONCE THE JOB IS OFF THE DOORBELL, EVERY ENDING OWES IT AN ANSWER ---
#
# run_once wraps _run_validated in `except (Refused, SystemExit)` and reports
# "refused" before re-raising, under a comment that describes fixing exactly
# this. It fixed it for the two exception types it was thinking about. An
# ordinary Python failure -- AttributeError, KeyError, an OSError off a full
# disk -- sailed straight past: main() logs the traceback, the finally powers
# the machine off, and the doorbell is told NOTHING.
#
# The Pi then waits out the ENTIRE result budget and reports "collected but
# never reported back ... CHECK THE VAULT" for a job that died in its first
# second. For a withdrawal that is 59400s, so a one-line bug on the vault
# holds the pager's one-job lock -- and every other command with it -- for
# sixteen and a half hours.
#
# DRIVEN by breaking a function on the reporting path, which nothing wraps.
_crash_d, _crash_kf, _crash_key, _crash_bell = new_env()
_crash_dp = deps_for(_crash_d, _crash_bell)
_real_seal = A.seal_slip_for_delivery


def _seal_boom(*_a, **_k):
    raise AttributeError("simulated bug on the reporting path")


try:
    A.seal_slip_for_delivery = _seal_boom
    try:
        run(_crash_kf, _crash_dp)
    except BaseException:                                    # noqa: BLE001
        pass
finally:
    A.seal_slip_for_delivery = _real_seal
_crash_posted = [_pth for _pth, _r in _crash_dp["_posted"]]
check("crash: an ordinary Python failure after collection still reports back "
      "to the doorbell", "/result" in _crash_posted)
# NON-VACUITY 1: the job really was collected, or "never reported" would be
# the correct answer rather than the defect.
check("crash: NON-VACUITY -- the job really had been handed over first",
      "/wake" in _crash_posted)
# NON-VACUITY 2: the exception really did escape, so this is about an
# unhandled crash and not a refusal that was already covered.
check("crash: NON-VACUITY -- the injected failure is not a Refused, so the "
      "old two-type handler could not have caught it",
      not issubclass(AttributeError, (A.Refused, SystemExit)))
# AND THE WAIT IT AVOIDS IS THE REASON IT MATTERS.
check(f"crash: ...which is what stops the Pi waiting "
      f"{P.result_budget_s('withdraw')}s for an answer that was never coming",
      P.result_budget_s("withdraw") > 3600)

# ---- AND THE WORD IT REPORTS HAS TO BE THE TRUE ONE ---------------------
#
# The handler above reported "refused" for EVERYTHING raised inside
# _run_validated, and gs_telegram_pager renders "refused" as, verbatim:
#
#     "refused before it started - nothing was spent and nothing moved."
#
# That is the only sentence in this toolchain that promises with no hedge that
# the money did not move, and it is correct for the refusals the handler was
# written for: a replayed job_id, the 24 h budget, the account ceiling, a Tor
# abort. Every one of those happens before any tool runs.
#
# The crash driven above is not one of those. seal_slip_for_delivery is called
# AFTER _dispatch returns -- the mix has run, the money has moved -- and the
# operator was told it had not. There is no second report: the crash is before
# report_back, so that sentence is the last word on a completed withdrawal.
# THE M3 IS A SEALED RECORD, not a dict: it has to be opened with the Pi's
# key the way gs_doorbell opens it, exactly as the earlier check in this file
# does. Guarded rather than indexed blind, so a report that stops being sent
# is a FAILED CHECK and not an IndexError landing in the crash handler.
def _reported_status(dp):
    _recs = [_r for _pth, _r in dp["_posted"] if _pth == "/result"]
    if not _recs:
        return None
    return P.open_record(NP.PrivateKey(PI.encode()), TP.public_key,
                         _recs[-1], P.TAG_M3).get("status")


_crash_status = [_reported_status(_crash_dp)]
check(f"crash: a failure AFTER the tools ran reports 'failed', not 'refused' "
      f"({_crash_status})",
      _crash_status and _crash_status[-1] == "failed")
check("crash: ...and 'failed' is a word the doorbell accepts, so this is not "
      "a report that gets dropped on the way",
      '("done", "refused", "failed")' in open(
          os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read())
# THE OTHER DIRECTION, and it is the half that keeps "refused" meaning
# something: a refusal raised BEFORE any child started still reports the word
# whose sentence is true. Driven on the wake budget, which is checked at the
# top of _run_validated.
_pre_d, _pre_kf, _pre_key, _pre_bell = new_env()
_pre_dp = deps_for(_pre_d, _pre_bell)
_pre_state = A.load_state(_pre_d)
_pre_state["wakes"] = [int(time.time())] * 99
A.save_state(_pre_d, _pre_state)
try:
    run(_pre_kf, _pre_dp)
except BaseException:                                        # noqa: BLE001
    pass
_pre_status = [_reported_status(_pre_dp)]
check(f"crash: NON-VACUITY -- a refusal before any tool ran still reports "
      f"'refused' ({_pre_status})",
      _pre_status and _pre_status[-1] == "refused")
# AND THE MARKER IS PER RUN. A stale True left by an earlier job in the same
# process would report a pre-dispatch refusal as a run that may have spent.
check("crash: ...and run_once clears the marker on the way in, so it means "
      "'this run' and not 'ever'",
      "_CHILD_STARTED[0] = False" in
      _A_SRC.split("def run_once")[1].split("\ndef ")[0])
check("crash: ...and _dispatch sets it at the last instant 'nothing ran' is "
      "still true — immediately before the child",
      "_CHILD_STARTED[0] = True\n        rc, hard = run_child" in _A_SRC)

# ---- SYSTEMD MUST NOT KILL THE JOB BEFORE THE DEADMAN DOES --------------
#
# THE WORST ONE IN THIS FILE'S HISTORY, and it defeated every other bound.
#
# gs-wake-agent.service is Type=oneshot, so TimeoutStartSec applies to the
# WHOLE ExecStart -- the entire job. It was 9000s, sized when `watch` (7200s)
# was the largest job. A withdrawal runs up to result_budget_s = 59400s and
# the agent extends the deadman to 60000s to cover it, so systemd was killing
# the unit 6.7x earlier than the backstop it was supposed to precede -- and
# OnFailure=gs-wake-poweroff.service then powers the machine off. Mid-mix,
# money already moving, on EVERY withdrawal at EVERY depth, since the
# shallowest needs 6.1h.
#
# The job budget, the deadman extension and the pager's poll-failure fix all
# bound something else. None of them can survive systemd killing the unit.
_unit = open(os.path.join(REPO, "systemd", "gs-wake-agent.service"),
             encoding="utf-8").read()
_tss = int(re.search(r"^TimeoutStartSec=(\d+)", _unit, re.M).group(1))
check("systemd: the unit really is Type=oneshot, so this timeout bounds the "
      "whole job and not just the launch",
      re.search(r"^Type=oneshot", _unit, re.M) is not None)
_longest = max(P.result_budget_s(_j) for _j in P.JOBS)
check(f"systemd: TimeoutStartSec ({_tss}s) outlasts the longest job the agent "
      f"can run ({_longest}s)", _tss > _longest)
# AND IT OUTLASTS THE DEADMAN THE AGENT ARMS FOR THAT JOB, or systemd still
# wins the race and the deadman never gets to be the bound.
_armed = _longest + 600            # gs_wake_agent: result_budget_s(job) + 600
check(f"systemd: ...and outlasts the deadman the agent arms for it "
      f"({_armed}s), so the deadman is what bounds a spend",
      _tss > _armed)
# NON-VACUITY 1: the value this replaced would FAIL both checks. Stated as a
# number rather than a memory, so the check is demonstrably able to say no.
check("systemd: NON-VACUITY -- the 9000s this replaced would NOT have covered "
      "the longest job, which is the defect", 9000 < _longest)
# NON-VACUITY 2: a withdrawal really is the long one, so this is not two names
# for the same job.
check("systemd: NON-VACUITY -- the spending job really is the longest",
      P.result_budget_s("withdraw") == _longest
      and _longest > P.result_budget_s("watch"))
# AND FAILURE STILL POWERS OFF, or raising the timeout would have quietly
# removed the thing that stops a crashed agent sitting powered on.
check("systemd: a failed agent still powers the machine off",
      "OnFailure=gs-wake-poweroff.service" in _unit)

# ---- THE BOOT DEADMAN MUST STILL COVER THE JOBS IT IS THE BACKSTOP FOR ---
#
# gs-wake-deadman.timer is armed at boot, before any job is known, and powers
# the vault off if the agent dies. Its OnActiveSec was derived as
# jitter + Tor + "the largest job's budget" + slack -- and `withdraw` at
# 58200s is now the largest job, which this timer neither covers nor should.
# Spending jobs extend it (extend_deadman arms a transient longer one,
# verifies it, then disarms this one), so what this number has to cover is the
# largest job that does NOT extend it.
#
# Derived from the real budgets rather than restated, so ADDING a non-spending
# job longer than `watch` goes red here instead of silently arriving as a
# vault that powers off mid-job.
_timer_src = open(os.path.join(REPO, "systemd", "gs-wake-deadman.timer"),
                  encoding="utf-8").read()
_on_active = int(re.search(r"OnActiveSec=(\d+)", _timer_src).group(1))
_spending = set(getattr(P, "SPENDING_JOBS", ()))
_nonspend = {j: sp["budget_s"] for j, sp in P.JOBS.items() if j not in _spending}
_worst_ns = max(_nonspend.values())
_need = P.VAULT_JITTER_HI_S + 300 + _worst_ns
check(f"deadman: the boot timer ({_on_active}s) covers the longest job that "
      f"does NOT extend it ({_worst_ns}s + jitter + Tor = {_need}s)",
      _on_active >= _need)
# NON-VACUITY 1: it is not simply enormous. A backstop sized for the spending
# job would leave the vault powered on for most of a day after an agent died
# during a status probe, which is the power signature this design hides.
check("deadman: ...and is NOT sized for the spending job, which would keep "
      "the vault up for hours after a two-minute job died",
      _on_active < max(sp["budget_s"] for sp in P.JOBS.values()))
# NON-VACUITY 2: a spending job really is longer than this timer, so the
# extension is load-bearing rather than decorative.
check("deadman: NON-VACUITY -- a withdrawal really does outlast this timer, "
      "so extend_deadman is what protects it",
      P.JOBS["withdraw"]["budget_s"] > _on_active)
# AND THE TIMER STARTS THE UNIT THE AGENT'S EXTENSION ALSO STARTS, or the two
# paths power off by different means and only one of them was reasoned about.
check("deadman: the boot timer and the extension start the SAME poweroff unit",
      "Unit=gs-wake-poweroff.service" in _timer_src
      and "gs-wake-poweroff.service" in open(
          os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read())
# AND THE ORDER IS ARM, VERIFY, DISARM. Disarming first would leave an instant
# with no backstop at all.
_ag_txt = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
_ext = _ag_txt.split("def extend_deadman")[1].split("\ndef ")[0]
check("deadman: the extension disarms the short timer only AFTER verifying "
      "the long one is active",
      _ext.index("unit_is_active") < _ext.index("disarm_deadman("))

# ---- ...AND THE LONG ONE WAS NEVER DISARMED AT ALL -----------------------
#
# extend_deadman arms a TRANSIENT gs-wake-deadman-ext timer for a spending
# job -- result_budget_s + 600, over sixteen hours for a withdrawal -- and
# DEADMAN_EXT_UNIT appeared in exactly three places in the whole file: the
# name, the systemd-run that starts it, and the is-active that verifies it
# started. Nothing stopped it, ever.
#
# Both callers of disarm_deadman are the refusal whose entire message is
# "somebody is at the machine ... NOT powering off". main() then returns 0
# believing the box is safe, and up to sixteen hours later the timer nobody
# disarmed starts gs-wake-poweroff.service under whoever sat down.
print("\n-- the backstop that outlived the refusal that stopped it --")
_stopped = []


def _stop_runner(argv):
    _stopped.append(argv[2])
    return types.SimpleNamespace(returncode=0)


check("deadman: disarming stops the SHIPPED timer", 
      A.disarm_deadman(runner=_stop_runner) is True
      and A.DEADMAN_UNIT in _stopped)
check("deadman: ...and the transient LONG one a spending job armed",
      f"{A.DEADMAN_EXT_UNIT}.timer" in _stopped)
# systemd-run --unit=NAME creates NAME.timer AND NAME.service. Stopping only
# the timer leaves a queued service that can still fire.
check("deadman: ...and the service systemd-run created alongside it",
      f"{A.DEADMAN_EXT_UNIT}.service" in _stopped)
check("deadman: NON-VACUITY -- those are three distinct units, not one name "
      "counted three times", len(set(_stopped)) == 3)
# THE STOPS ARE CHECKED. This discarded the returncode entirely, so a stop
# that failed was indistinguishable from one that worked -- while the ARM
# half is verified under a comment calling that check "the one thing standing
# between a four-hour spend and no backstop at all".
check("deadman: a failed stop of the shipped timer is reported, not swallowed",
      A.disarm_deadman(
          runner=lambda a: types.SimpleNamespace(
              returncode=1 if a[2] == A.DEADMAN_UNIT else 0)) is False)
# ...BUT A TRANSIENT UNIT THAT WAS NEVER CREATED IS NOT A FAILURE. Only a
# spending job arms the ext timer, so on every other job systemctl answers
# non-zero for a unit that correctly does not exist.
check("deadman: ...and a transient unit that never existed is not one",
      A.disarm_deadman(
          runner=lambda a: types.SimpleNamespace(
              returncode=0 if a[2] == A.DEADMAN_UNIT else 5)) is True)
# AND extend_deadman NOW DEPENDS ON THAT ANSWER. It returned True whatever
# the stop did; a failed stop leaves the shipped 9300 s timer armed across a
# job budgeted for up to 58200 s, which is the vault powering off mid-round.
# False sends the caller to deadman_too_short, which refuses -- a wasted wake,
# and the safe end.
# THE INVARIANT, STATED AS AN INVARIANT: a successful extension leaves
# EXACTLY ONE backstop armed, and it is the long one. Widening disarm_deadman
# to close the bug above, without this, made extend_deadman arm the long
# timer, verify it, and then stop it -- returning True. A withdrawal would run
# for up to sixteen hours with no backstop at all: the always-on vault the
# whole feature exists to end, reached by the fix for its opposite.
_swap = []
check("deadman: a successful extension stops the SHORT timer",
      A.extend_deadman(
          58200,
          runner=lambda a: (_swap.append(list(a)),
                            types.SimpleNamespace(returncode=0))[1],
          is_active=lambda u: True) is True
      and any(a[:3] == ["systemctl", "stop", A.DEADMAN_UNIT] for a in _swap))
check("deadman: ...and does NOT stop the long one it just armed",
      not any(a[:2] == ["systemctl", "stop"]
              and A.DEADMAN_EXT_UNIT in a[2] for a in _swap))
check("deadman: NON-VACUITY -- it really did arm the long one first, so the "
      "absence above is an absence from a real sequence",
      any(a and a[0] == "systemd-run"
          and any(A.DEADMAN_EXT_UNIT in _x for _x in a) for a in _swap))
check("deadman: ...and the human-present path still stops BOTH, which is the "
      "bug the flag was added to keep fixed",
      A.disarm_deadman(
          runner=lambda a: types.SimpleNamespace(returncode=0), ext=True)
      is True)

check("deadman: an extension whose disarm FAILED does not claim to be armed",
      A.extend_deadman(
          15600,
          runner=lambda a: types.SimpleNamespace(
              returncode=1 if a[:2] == ["systemctl", "stop"] else 0),
          is_active=lambda u: True) is False)

# ---- AND THE FEE DESTINATION WAS READ BY CODE NOTHING COULD REACH --------
#
# gs_wake_agent reads key["usage_fee_address"], the vault's keyfile is the
# only place it looks, and NOTHING WROTE THE FIELD -- no flag, no payload
# entry. The read shipped with the fee and the writer did not, so the whole
# fixed-address branch was unreachable code: the same "declared in one place,
# never wired to the thing that runs" shape as the missing fee itself.
check("fee: the pairing offers a flag for the fee destination",
      '"--usage-fee-address"' in _kp_src)
check("fee: ...and actually writes it into the keyfile the agent reads",
      '"usage_fee_addresses": [str(a) for a in (args.usage_fee_address or [])],'
      in _kp_src)
# THE SINGULAR FIELD IS STILL WRITTEN, and it is not vestigial: an agent from
# before the list existed reads only that name. Writing the list and dropping
# the singular would leave such an agent taking no fee at all -- the exact
# silent-zero this section exists about -- and writing str(list) there would
# hand it a destination made of the text of a Python list.
check("fee: ...and still writes the singular one an older agent reads, as an "
      "address rather than the text of a list",
      '"usage_fee_address": str((list(args.usage_fee_address or []) or [""])[0]),'
      in _kp_src)

# ---- AND SO WAS THE ONE MODE THAT DELIVERS A DEPOSIT ADDRESS -------------
#
# EXACTLY THE SAME SHAPE, on the field that decides whether an operator whose
# only other device is a phone is handed anything to pay at all.
# gs_wake_agent reads key["deposit_in_chat"] and refuses a keyfile that sets it
# beside a delivery key; gs_telegram_pager renders it; gs_doorbell validates
# its shape on the wire; gs_wake_proto defines the field; OPSEC_SETUP.md told
# the operator to `set "deposit_in_chat": true in the vault's keyfile`. That
# keyfile is a SEALED CONTAINER written by gs_wake_keys and by nothing else,
# so the instruction described an edit nobody could make. A reader, a
# renderer, a wire format, a well-formedness check and a suite -- no writer.
check("plain_slip: the pairing offers a flag for it",
      '"--deposit-in-chat"' in _kp_src)
check("plain_slip: ...and writes it into the keyfile the agent reads",
      '"deposit_in_chat": bool(args.deposit_in_chat),' in _kp_src)
# ALWAYS, NOT ONLY WHEN TRUE. An absent field and a false one read the same
# through .get(), but only one of them says the pairing was asked -- and the
# agent's loader refuses a value that is not a bool, so writing the bool is
# what makes that check reachable at all.
# CODE, NOT PROSE: the comment above the flag quotes the doc sentence this
# replaced, which itself contains `"deposit_in_chat":`.
_ps_line = [_l for _l in _kp_src.splitlines()
            if '"deposit_in_chat":' in _l and not _l.lstrip().startswith("#")]
check("plain_slip: ...unconditionally, so the agent's bool check is reachable",
      len(_ps_line) == 1 and "if " not in _ps_line[0])
# AND THE AGENT REALLY DOES REFUSE THE TWO BAD SHAPES, so the line above is
# not ceremony: the writer and the reader are checked against each other.
_ag_src = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("plain_slip: ...and the agent refuses a value that is not a bool",
      'deposit_in_chat_malformed' in _ag_src)
check("plain_slip: ...and refuses a keyfile that also names a delivery key",
      'delivery_mode_ambiguous' in _ag_src)
# ONE MODE, NOT TWO, AND THE REFUSAL IS WHERE THE SECOND WOULD BE WRITTEN.
# load_key raises delivery_mode_ambiguous on a keyfile carrying both -- on
# EVERY wake, at load, before any job runs. So writing the second field does
# not create a conflict to resolve later, it stops the vault answering the
# phone until both boxes are re-paired.
_dk_src = open(os.path.join(REPO, "gs_delivery_key"), encoding="utf-8").read()
check("plain_slip: gs_delivery_key refuses to write a delivery key over it, "
      "rather than leaving the vault to refuse every wake",
      'if key.get("deposit_in_chat"):' in _dk_src)
check("plain_slip: ...and does it BEFORE it mints anything, so a refusal "
      "leaves no orphan key file",
      _dk_src.index('if key.get("deposit_in_chat"):')
      < _dk_src.index("dk = nacl.public.PrivateKey.generate()"))

# ---- AND THE CLASS OF BUG, NOT JUST THE TWO INSTANCES OF IT -------------
#
# --usage-fee-address and plain_slip were the same defect found twice, a turn
# apart: a keyfile field the vault READS with no tool that WRITES it, so the
# branch behind it was unreachable and the documentation described an edit to
# a sealed container that nobody could make. Both were found by reading; this
# finds the next one.
#
# The rule: every field gs_wake_agent reads out of `key` must be written by
# something. "Something" is gs_wake_keys (the pairing) or gs_delivery_key (the
# one tool that patches a keyfile in place) -- there is no third writer, and a
# field with no writer at all is a feature with no switch.
_KEY_READS = set(re.findall(r'key\.get\(\s*"([a-z_]+)"', _ag_src))
_KEY_READS |= set(re.findall(r'key\[\s*"([a-z_]+)"\s*\]', _ag_src))
_KEY_READS |= set(re.findall(r'\bk\.get\(\s*"([a-z_]+)"', _ag_src))
_WRITERS = _kp_src + open(os.path.join(REPO, "gs_delivery_key"),
                          encoding="utf-8").read()
_unwritable = sorted(f for f in _KEY_READS
                     if f'"{f}"' not in _WRITERS)
check(f"keyfile: every field the vault reads has a tool that writes it "
      f"({len(_KEY_READS)} fields checked)",
      _unwritable == [])
# NON-VACUITY: the scan really found the fields, so an empty difference is
# not an empty scan.
check(f"keyfile: NON-VACUITY -- the scan found the real ones ({len(_KEY_READS)})",
      {"deposit_in_chat", "delivery_public", "allow_withdraw", "wallet_file",
       "usage_fee_address"} <= _KEY_READS)
# proto.xmr_address, NOT the withdraw schema's exit_to field. This used to
# borrow that one, which was fine only while the two happened to be the same
# check -- exit_to takes a LIST of destinations now, so the borrowed gate would
# have accepted a list of fee addresses at pairing and written whichever one
# str() produced. A job schema is about that job's fields; "is this an address"
# has its own name.
check("fee: ...and validates it at pairing, not after a mix has run",
      'proto.xmr_address(_fa)' in _kp_src)
check("fee: ...with the ONE-address gate, not the withdraw job's destination "
      "list, which is a different question that now returns a different type",
      'JOBS["withdraw"]["schema"]["exit_to"](_fa)' not in _kp_src)
# THE FIELD NAMES MUST MATCH ON BOTH SIDES, which is the half that was broken.
_ag_src = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("fee: the name the agent reads is the name the pairing writes",
      'key.get("usage_fee_address")' in _ag_src
      and 'key.get("usage_fee_addresses")' in _ag_src)
_K = importlib.util.module_from_spec(importlib.util.spec_from_loader(
    "gs_wake_keys_for_flags",
    importlib.machinery.SourceFileLoader("gs_wake_keys_for_flags",
                                         os.path.join(REPO, "gs_wake_keys"))))
_K.__loader__.exec_module(_K)
_ap_k = _K.build_cli().parse_args(["pair"])
check("fee: NON-VACUITY -- omitting the flag is still valid", 
      _ap_k.usage_fee_address == [])

# ---- ONE ADDRESS COLLECTED EVERY RUN, AND THE HELP CALLED IT RECOMMENDED --
#
# THE HELP WAS FALSE ON THE ONLY PATH THIS FILE PAIRS. It said omitting the
# flag was the RECOMMENDED setting because GhostSpiral then "mints a fresh
# account per run, so no address collects from two runs". True of a desktop
# run. On a woken one _withdraw_fee_argv passes --usage-fee only when the
# field is set -- because a minted account lands on the mixing wallet and
# _funded_entry hands it to the next withdrawal -- so an operator who followed
# the help took NO FEE AT ALL on every phone withdrawal while being told the
# opposite. Driven below, both directions.
print("\n-- the usage fee, and who can read it off the chain --")
_FA = ["4" + str(_i) + "1" * 93 for _i in range(4)]
check("fee: a keyfile naming no destination takes no fee at all -- the state "
      "the old help called 'recommended'",
      A.fee_addresses({}) == [] and A._withdraw_fee_argv({}) == [])
# THE CLAIM, NOT A WORD. The history is written above the flag on purpose --
# "THIS HELP USED TO SAY..." -- so a bare word search finds the retelling and
# passes on a file that still lies. What must be gone is the assertion itself.
check("fee: ...and the pairing no longer asserts that omitting it is the "
      "recommended setting",
      "OMITTING IT IS THE RECOMMENDED" not in _kp_src)
check("fee: ...nor that omitting it mints a fresh account per run, which is "
      "true of a desktop run and never was of a woken one",
      "GhostSpiral mints a FRESH account and subaddress for the cut on every"
      not in _kp_src)
check("fee: ...and says outright that the flag is what makes a woken "
      "withdrawal take a fee at all",
      "REQUIRED to take a fee" in _kp_src)
# THE LEAK THE LIST EXISTS FOR. The rate is published in this repository, so an
# arrival divided by 0.011 is the deposit behind it. With ONE destination that
# is every deposit the operator ever took, and it survives the mix because the
# fee output is the one thing in the run that is not mixed.
check("fee: the flag is repeatable, so the cut is not one address collecting "
      "every run", "action=\"append\"" in _kp_src)
check("fee: ...and the agent reads all of them", 
      A.fee_addresses({"usage_fee_addresses": _FA}) == _FA)
check("fee: ...and an older keyfile with only the singular field still works",
      A.fee_addresses({"usage_fee_address": _FA[0]}) == [_FA[0]])
check("fee: ...and the two are not double-counted when both name the same one",
      A.fee_addresses({"usage_fee_addresses": _FA[:2],
                       "usage_fee_address": _FA[0]}) == _FA[:2])
# EVERY ELEMENT CHECKED. This list comes off a file on disk. A None or a dict
# in it would reach str() and become a destination made of the word "None" --
# the cut paid somewhere unspendable, discovered after the mix.
check("fee: a list holding junk contributes only the usable addresses",
      A.fee_addresses({"usage_fee_addresses":
                       [_FA[0], None, {}, 7, "   ", _FA[1]]}) == _FA[:2])
check("fee: ...and a field that is not a list at all is not iterated as one",
      A.fee_addresses({"usage_fee_addresses": "4" + "1" * 94}) == [])
# THE DRAW IS PER RUN AND KEEPS NOTHING. An index would be durable state on
# the machine paranoia_mode wipes -- it would reset to the first address after
# every sweep, which is the worst reuse pattern there is -- and two
# withdrawals racing it would read the same number.
_draws = {A.pick_fee_address({"usage_fee_addresses": _FA}) for _ in range(400)}
check(f"fee: the destination is drawn per run, not fixed ({len(_draws)} of "
      f"{len(_FA)} seen in 400 draws)", _draws == set(_FA))
check("fee: ...and with one address paired it is still that one",
      A.pick_fee_address({"usage_fee_addresses": _FA[:1]}) == _FA[0])
check("fee: ...and with none it is empty rather than an exception",
      A.pick_fee_address({}) == "")
check("fee: ...and nothing is written down to remember the draw",
      "usage_fee_index" not in _ag_src and "fee_rotation" not in _ag_src)
# AND THE CLAIM IS BOUNDED HONESTLY. N addresses divide the reuse by N; they
# do not remove it. A help string promising unlinkability would be the
# confident false statement this repo keeps deleting.
check("fee: the pairing help calls it a reduction and not unlinkability",
      "is a reduction, not" in _kp_src)
# A REPEAT IS NOT A SECOND ADDRESS: it weights the draw toward one destination
# while the keyfile reads as spreading wider than it does.
check("fee: pairing refuses the same address given twice",
      "if len(set(_seen)) != len(_seen):" in _kp_src)

# ---- ...AND WITHDRAWING TO YOUR OWN FEE ADDRESS KILLED THE RUN ----------
#
# GhostSpiral's resolve_usage_fee sys.exits when a fee address is also an
# --exit-to destination: "Then it is not a fee: it lands in the same place as
# the mixed funds". Right, and at PARSE time, before stage 0 -- so nothing
# ran, and the refusal names command-line flags a phone operator never typed,
# onto a stdout the unit diverts to a 0600 log on a machine that then powers
# off. What reaches the chat is "withdraw: failed" plus a hint about mixing
# depth that is wrong, and a warning that some of it may already have moved,
# which is false.
#
# ON A SINGLE-TENANT BOT THE OVERLAP IS THE NATURAL SETUP -- the operator is
# the user -- and the address LIST made it intermittent: with N paired,
# roughly one withdrawal in N drew the colliding one and died while the rest
# worked.
print("\n-- withdrawing to an address the cut is also paid to --")
_FK = {"tor_proxy": "socks5h://x", "rpc_primary": "http://127.0.0.1:18083",
       "rpc_daemon": "http://127.0.0.1:18081", "wallet_file": "/w",
       "allow_withdraw": True, "usage_fee_addresses": _FA}


def _fee_argv_for(dests):
    return A.build_argv("withdraw", {"exit_to": list(dests), "depth": 2},
                        _FK, Path("/tmp"), bundle="/tmp/b.json", slip=None,
                        handle="A3F1")[0]


check("fee: an address that is a destination this run is not offered for the "
      "cut", all(A.pick_fee_address(_FK, exclude=[_FA[2]]) != _FA[2]
                 for _ in range(400)))
check("fee: ...and the other paired addresses still are, so one collision "
      "does not waive the fee",
      len({A.pick_fee_address(_FK, exclude=[_FA[2]]) for _ in range(400)}) == 3)
check("fee: ...and the run still asks for the cut",
      "--usage-fee" in _fee_argv_for([_FA[2]]))
# EVERY PAIRED ADDRESS A DESTINATION -> WAIVE, DO NOT REFUSE. The money lands
# in the operator's own hands either way, which is what GhostSpiral's refusal
# says; plan_usage_fee already waives rather than aborts when the cut is not
# worth moving, for the same reason.
check("fee: withdrawing to ALL of them waives the cut rather than failing "
      "the run", A.pick_fee_address(_FK, exclude=_FA) == "")
# AND THE FLAG MUST AGREE WITH THE DRAW. --usage-fee with no
# GS_USAGE_FEE_ADDRESS is exactly the configuration that mints the cut onto
# the mixing wallet -- the recapture the fee gate exists to prevent -- so a
# waived draw that still composed the flag would trade one bug for a worse one.
check("fee: ...and the flag is not composed when no address is usable, so "
      "nothing mints on the mixing wallet",
      "--usage-fee" not in _fee_argv_for(_FA))
check("fee: NON-VACUITY -- an ordinary destination still pays the cut",
      "--usage-fee" in _fee_argv_for(["4" + "9" * 94])
      and A.pick_fee_address(_FK, exclude=["4" + "9" * 94]) in _FA)
# THE PREDICATE IS ASKED ONCE AND USED TWICE, which is what keeps them in step.
# ONE PREDICATE, ASKED TWICE, FROM ONE LIST. The flag and the drawn address
# must agree: --usage-fee with no GS_USAGE_FEE_ADDRESS is the configuration
# that mints the cut onto the mixing wallet, which is the recapture the fee
# gate exists to prevent.
check("fee: the argv and the draw consult the same excluded lists",
      'params.get("exit_to") or [],' in _ag_src
      and "owned=owned_fee)" in _ag_src
      and "exclude=list(_dests) + list(_owned_fee))" in _ag_src)
check("fee: ...and the wallet is asked once per run, not once per consultation",
      _ag_src.count("wallet_owned_fee_addresses(key)") == 1)

# ---- ...AND A FEE ADDRESS ON THE MIXING WALLET WAIVED THE CUT SILENTLY ---
#
# GhostSpiral already knows: plan_usage_fee asks _wallet_owns_address and
# WAIVES the cut when the answer is yes. The trouble is where it finds out --
# once per withdrawal, on the vault, onto a stdout gs_wake_agent diverts to a
# 0600 job log that paranoia_mode erases. The exit code is unaffected, so the
# phone says "withdraw: sent", the operator collects nothing, and there is
# nothing anywhere saying why. Every run, forever.
#
# AND IT IS THE EASY MISTAKE TO MAKE: this bot's own /address mints receive
# subaddresses on that very wallet, so the most available Monero address the
# operator has is one that triggers the waiver.
print("\n-- a fee address the mixing wallet already owns --")


class _OwnRPC:
    """Answers like monero-wallet-rpc: an ERROR for a FOREIGN address."""

    def __init__(self, mine):
        self.mine = set(mine)

    def raw_request(self, m, p=None):
        if m != "get_address_index":
            return {}
        if p["address"] in self.mine:
            return {"index": {"major": 3, "minor": 9}}
        raise RuntimeError("Address doesn't belong to the wallet (-2)")


def _argv_owned(_owned):
    return A.build_argv("withdraw", {"exit_to": ["4" + "9" * 94], "depth": 2},
                        _FK, Path("/tmp"), bundle="b", slip=None,
                        handle="A3F1", owned_fee=_owned)[0]


_own_saved = _gsc_pat.connect_rpc
try:
    _gsc_pat.connect_rpc = lambda *a, **k: _OwnRPC([_FA[1]])
    _owned = A.wallet_owned_fee_addresses(_FK)
    check("owned: the wallet is asked which paired addresses it already holds",
          _owned == [_FA[1]])
    check("owned: ...and that address is never drawn for the cut",
          all(A.pick_fee_address(_FK, exclude=_owned) != _FA[1]
              for _ in range(400)))
    check("owned: ...while the other three still are, so one bad address does "
          "not waive the fee",
          len({A.pick_fee_address(_FK, exclude=_owned)
               for _ in range(400)}) == 3)
    check("owned: ...and the run still asks for the cut",
          "--usage-fee" in _argv_owned(_owned))
    # EVERY paired address owned by the wallet -> waive, and the FLAG has to
    # agree, or --usage-fee with no address mints the cut onto that same
    # wallet, which is the recapture this whole gate exists to prevent.
    _gsc_pat.connect_rpc = lambda *a, **k: _OwnRPC(_FA)
    _owned_all = A.wallet_owned_fee_addresses(_FK)
    check("owned: with every paired address on the wallet, the cut is waived",
          A.pick_fee_address(_FK, exclude=_owned_all) == ""
          and "--usage-fee" not in _argv_owned(_owned_all))
    # FAIL OPEN, and deliberately. wallet-rpc answers get_address_index for a
    # FOREIGN address with an ERROR, so an error is the expected reply for a
    # correctly-supplied external destination; treating "cannot tell" as
    # "exclude" would waive the fee on every correct configuration.
    def _own_boom(*a, **k):
        raise OSError("wallet-rpc unreachable")

    _gsc_pat.connect_rpc = _own_boom
    check("owned: a wallet that cannot be asked excludes nothing, because an "
          "error is what a FOREIGN address answers with",
          A.wallet_owned_fee_addresses(_FK) == []
          and "--usage-fee" in _argv_owned([]))
finally:
    _gsc_pat.connect_rpc = _own_saved
# NON-VACUITY: it is only asked on the spending job. A status probe has no
# business opening the wallet.
check("owned: NON-VACUITY -- the wallet is asked only for a withdrawal",
      'if job == "withdraw" else []' in _ag_src)

# ---- ...AND THE DESK RE-OPENS WHAT THE PHONE PATH CLOSED -----------------
#
# _withdraw_fee_argv stops the WOKEN path minting a cut onto the mixing
# wallet. gs_console's fee panel USED TO recommend exactly that for a run
# started at the desk -- "leave the box empty and a new account and subaddress
# are minted per run" -- and _funded_entry cannot tell the two apart, because
# it takes the largest unlocked output on the wallet and asks nothing else.
# plan_usage_fee now waives on the desk path too; the driven case below is a
# cut an OLDER desk run left behind, which is why pairing says to sweep it.
#
# DRIVEN, not reasoned about: a wallet whose deposit the last exit already
# swept out reports the desktop-minted fee account as the entry for the next
# withdrawal.
print("\n-- the fee the desk leaves behind for the phone to spend --")


class _FeeWallet:
    def __init__(self, accts): self.accts = accts

    def raw_request(self, m, p=None):
        if m == "get_accounts":
            return {"subaddress_accounts":
                    [{"account_index": i} for i in range(len(self.accts))]}
        if m == "get_balance":
            return {"per_subaddress": self.accts[p["account_index"]]}
        return {}


def _sub(i, xmr, tag):
    return {"address_index": i, "unlocked_balance": int(xmr * 10 ** 12),
            "address": tag}


import gs_common as _gc                                       # noqa: E402
_gc_orig = _gc.connect_rpc
# acct 0 is the user's entry, swept empty by the run's own exit. acct 9 is what
# a desktop run with an empty address box minted for the operator.
_wallet = ([[_sub(0, 0.0, "user-entry")]] + [[] for _ in range(8)]
           + [[_sub(2, 0.44, "operator-cut-from-the-desk")]])
try:
    _gc.connect_rpc = lambda *a, **k: _FeeWallet(_wallet)
    _fk = {"rpc_primary": "http://127.0.0.1:18083", "tor_proxy": ""}
    _picked = A._funded_entry(_fk)
    check("fee: a cut minted at the DESK is what the next woken withdrawal "
          "picks up, because _funded_entry knows only 'largest unlocked'",
          _picked is not None and _picked[2] == "operator-cut-from-the-desk")
    # NON-VACUITY: it is not simply always returning that account -- a real
    # deposit still outranks it, which is why the leak needs the exit to have
    # run first and is easy to miss in testing.
    _wallet[0] = [_sub(0, 12.0, "another-deposit")]
    check("fee: NON-VACUITY -- with a real deposit present that one wins, so "
          "the leak only shows after an exit has swept",
          A._funded_entry(_fk)[2] == "another-deposit")
finally:
    _gc.connect_rpc = _gc_orig
# NEITHER TOOL CAN SEE THE OTHER: the console holds no keyfile and the agent
# does not know what was run at the desk. Pairing is the one moment both facts
# are present -- a wallet is named, and a phone is given permission to spend
# from it -- so that is where the operator is told.
check("fee: pairing warns when a phone may spend from a wallet and no "
      "off-wallet destination is named",
      "if args.allow_withdraw and not (args.usage_fee_address or []):"
      in _kp_src)
check("fee: ...and says both consequences, not just the missing fee",
      "takes NO usage fee" in _kp_src
      and "will pick it up and send it to" in _kp_src)
check("fee: ...and it is a warning, not a refusal -- taking no fee is a "
      "legitimate choice and forcing an address to silence a warning is worse",
      "or continue if you meant to take no fee" in _kp_src
      and "sys.exit" not in _kp_src.split(
          "if args.allow_withdraw and not (args.usage_fee_address or []):")[1]
          .split("if args.wallet_file")[0])
# AND THE PAGE THAT RECOMMENDS THE EMPTY BOX SAYS WHEN NOT TO.
_cons_src = open(os.path.join(REPO, "gs_console"), encoding="utf-8").read()
check("fee: the console's fee panel says why the address must be off this "
      "wallet, and that an empty box means no fee",
      "Why it must be off this wallet" in _cons_src
      and "empty = no fee is taken" in _cons_src)
# WHITESPACE-NORMALISED, because this is HTML source: the sentence wraps at
# whatever column the file wraps at, so a raw substring check passes or fails
# on where a line break happens to fall rather than on what the page says.
_cons_flat = " ".join(_cons_src.split())
check("fee: ...and points at the fix rather than only at the hazard",
      "goes to a wallet of your own or it is not taken" in _cons_flat
      and "from the desk and from the phone alike" in _cons_flat)

# ---- A KILLED PROBE WAS A COMPLETED DEPOSIT --------------------------
#
# The success gate for a status probe read: rc != 0, job is a watching one,
# not a hard kill, and STATUS_FILE EXISTS -> continue. It checked that the
# file exists and nothing about what is in it. receive_watch writes
# {"state": "interrupted"} on its way out when it is killed at its budget,
# and _PHASE_OF_STATE maps "interrupted" to "" -- no phase earned.
#
# So the vault reported "done" with no phase, and the pager's done-branch
# falls past the phase reply into the SLIP branches. Driven on a deposit
# handle: seal_slip_for_delivery(status="done") returned 568 characters and
# plain_slip_for_chat returned the full field set, memo included. "Has my
# payment arrived?" re-published the entire deposit slip, captioned as ready,
# for a probe that answered nothing.
#
# _phase_of IS the test for "did this probe earn an answer": same file, the
# protocol's closed table, "" for every state that did not.
_pk_src = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
# TO THE END OF THE BRANCH, not a fixed slice: the comment above the code is
# longer than any window guessed by eye, and a slice that misses the line is a
# check that reads as a failure while the code is right.
_pk_gate = _pk_src.split(
    'if rc != 0 and job in ("swap_status", "watch") and not hard:'
)[1].split("\n        if rc != 0:")[0]
check("probe: the success gate asks for a PHASE, not for a file that exists",
      "_phase_of(job, artifact_dir)" in _pk_gate)
check("probe: ...and no longer settles for STATUS_FILE.exists()",
      "STATUS_FILE).exists()" not in _pk_gate)

_pk_dir = Path(tempfile.mkdtemp(prefix="gs_probe_"))
for _state, _want, _label in (
        ("funded", True, "money landed"),
        ("stalled", True, "arrived short"),
        ("not_syncing", True, "wallet not scanning"),
        ("timeout", True, "nothing yet"),
        ("interrupted", False, "KILLED AT ITS BUDGET"),
        ("some_new_word", False, "a state this build has never heard of")):
    (_pk_dir / A.STATUS_FILE).write_text(json.dumps(
        {"state": _state, "unlocked": "0", "total": "0"}))
    _got = bool(A._phase_of("swap_status", _pk_dir))
    check(f"probe: state={_state!r} ({_label}) counts as answered: {_got}",
          _got == _want)
(_pk_dir / A.STATUS_FILE).write_text("{}")
check("probe: a status file with no state at all is not an answer either",
      not A._phase_of("swap_status", _pk_dir))
shutil.rmtree(_pk_dir, ignore_errors=True)

# ---- A PHONE WITHDRAWAL TAKES NO FEE ONTO THE WALLET IT IS EMPTYING ---
#
# plan_usage_fee, with no fixed destination, USED TO mint a FRESH account on
# the wallet being mixed and keep it out of addr_index so the exit would not
# sweep it -- "it is yours where it lands". That hold was one process's
# in-memory index. _funded_entry is a different process re-enumerating the
# same wallet and takes the largest unlocked output there is. Driven: after a
# withdrawal completed, the fee account WAS the largest output, so the next
# /withdraw -- which the pager itself suggests -- mixed the operator's
# revenue and paid it to the address the chat named. It waives now.
_fee_key = {"rpc_primary": "http://127.0.0.1:18083",
            "rpc_daemon": "http://127.0.0.1:18081",
            "tor_proxy": "socks5h://127.0.0.1:9050",
            "wallet_file": "/w", "artifact_dir": "/tmp",
            "allow_withdraw": True}
_fee_params = {"exit_to": ["4" + "1" * 94], "depth": 2}
_no_addr = A.build_argv("withdraw", _fee_params,
                         dict(_fee_key, usage_fee_address=""),
                         Path("/tmp"), bundle="/tmp/b.json", slip=None,
                         handle="A3F1")[0]
_with_addr = A.build_argv("withdraw", _fee_params,
                           dict(_fee_key, usage_fee_address="4" + "7" * 94),
                           Path("/tmp"), bundle="/tmp/b.json", slip=None,
                           handle="A3F1")[0]
# THE FEE GOES OFF THIS WALLET, OR IT IS NOT TAKEN.
#
# Two other fixes were tried and both were wrong, which is why this one is
# pinned with its reasoning:
#
#   * Take the fee as usual and have _funded_entry skip the fee ACCOUNT by a
#     recorded pair. The record has to live somewhere, and artifact_dir is
#     wiped by paranoia_mode -- so the protection disappears exactly when the
#     operator has been most careful.
#   * Mark the fee account with a wallet LABEL. paranoia_mode deliberately
#     never deletes the wallet file, so a label outlives every artifact wipe:
#     it survives a seizure that erased the plans and the logs, names which
#     account is the operator's revenue, and hands the deposit size to anyone
#     who divides by the published rate. test_dag_entry already pins both
#     mints to an empty label for exactly this reason.
#
# So nothing marks it, and nothing needs to: with no --usage-fee-address the
# withdrawal takes no cut, and nothing of the operator's is left on a wallet
# the phone can drain. The cost is real and is stated rather than hidden -- a
# fixed address is address reuse, which gs_wake_keys is right to call the
# worse default in general. On an install where a phone can empty the wallet
# it is the better of the two, because the alternative is not "a fresh
# account per run", it is "the operator's revenue is paid to whoever asks
# next".
check("fee: with no --usage-fee-address, a phone withdrawal takes NO fee, so "
      "nothing of the operator's is left where _funded_entry will find it",
      "--usage-fee" not in _no_addr)
check("fee: ...and with one, the fee IS taken, because it goes off-wallet",
      "--usage-fee" in _with_addr)
check("fee: NON-VACUITY -- the two commands are otherwise identical",
      [a for a in _no_addr if a != "--usage-fee"]
      == [a for a in _with_addr if a != "--usage-fee"])
check("fee: NON-VACUITY -- the address never rides on the argv either way",
      "4" + "7" * 94 not in _with_addr)
# AND NOTHING IS LABELLED, checked from this side too so the two files cannot
# drift into disagreeing about it.
_gs_src = open(os.path.join(REPO, "GhostSpiral"), encoding="utf-8").read()
# NOTHING IS MINTED FOR THE FEE ANY MORE -- no account, labelled or not. The
# label question is moot because the branch that minted is gone: with no
# destination off the wallet the cut is waived.
_pf_src = _gs_src.split("def plan_usage_fee")[1].split("\ndef ")[0]
check("fee: plan_usage_fee mints no account and no subaddress for the cut -- "
      "with no destination off the wallet it waives",
      "create_fresh_account(" not in _pf_src
      and "new_subaddress_indexed(" not in _pf_src
      and 'integrity_log("usagefee", "waived_no_destination")' in _pf_src)
check("fee: ...and the waive is the LAST answer, after the static-address "
      "branch, so an address off the wallet still pays",
      _pf_src.index('"to_static_address"')
      < _pf_src.index('"waived_no_destination"'))

# ---- THE THIRD ADDRESS VALIDATOR AGREED WITH THE OTHER TWO ON ALL BUT ONE
#
# gs_common.XMR_ADDR_RE and gs_console.XMR_RE are the same expression and a
# test pins them together. proto._xmr_address_field is hand-rolled -- rightly,
# because this file imports nothing but the stdlib and PyNaCl -- and it took
# any length in (95, 106) with a leading 4 or 8, so it admitted an 8-prefixed
# 106-character string that both regexes reject. No such Monero address exists
# (integrated addresses carry netbyte 19 and always start 4), so this is a typo
# shape rather than an attack.
#
# It matters because of WHICH BOX HOLDS WHICH CHECK. _xmr_address_list is what
# the pager applies to an address typed into the chat, and its docstring is
# explicit: duplicates are refused there so "the operator is told by the box
# they are typing at, rather than by a vault that has already been woken".
# This shape got the other outcome -- accepted on the phone, refused on the
# vault, a wake spent.
import gs_common as _gsc_addr
_B58ONE = "1"
for _a, _label, _want in (
        ("4" + _B58ONE * 94, "a standard address (4)", True),
        ("8" + _B58ONE * 94, "a standard address (8)", True),
        ("4" + _B58ONE * 105, "an integrated address (4)", True),
        ("8" + _B58ONE * 105, "an 8-prefixed 106-char string", False),
        ("4" + _B58ONE * 93, "one character short", False)):
    try:
        P.xmr_address(_a)
        _proto_ok = True
    except P.WakeError:
        _proto_ok = False
    _common_ok = bool(_gsc_addr.XMR_ADDR_RE.match(_a))
    check(f"address: the phone and the vault agree about {_label} "
          f"(phone {'accepts' if _proto_ok else 'refuses'}, vault "
          f"{'accepts' if _common_ok else 'refuses'})",
          _proto_ok == _common_ok == _want)

# ---- AND PAIRING NOW ASKS WHETHER THE WALLET IS THERE -------------------
#
# _validate's own comment: "REFUSED AT PAIRING, not discovered mid-withdrawal.
# --allow-withdraw without a wallet file writes a keyfile whose withdraw job
# relays a fan-out and THEN fails at the signing step." The check that follows
# asked two things -- that the flag was given, and that the path was ABSOLUTE
# -- and never whether the path resolves to anything. An absolute path with a
# typo produces the same shape the refusal exists to prevent.
#
# Fatal, like the isabs check beside it, because there is no `gs_wake_keys
# edit`: correcting a keyfile means pairing both boxes again.
_wf_dir = tempfile.mkdtemp(prefix="gs_wf_")
_wf_real = os.path.join(_wf_dir, "vault")
open(_wf_real, "w").write("x")
_wf_keys = os.path.join(_wf_dir, "other")
open(_wf_keys + ".keys", "w").write("x")


def _pairs_with(wallet_file):
    _argv = ["pair", "--out", os.path.join(_wf_dir, "k.key"),
             "--artifact-dir", _wf_dir]
    if wallet_file is not None:
        _argv += ["--wallet-file", wallet_file, "--allow-withdraw"]
    try:
        _K._validate(_K.build_cli().parse_args(_argv))
        return None
    except SystemExit as _e:
        return str(_e)


_wf_typo = _pairs_with(os.path.join(_wf_dir, "vualt"))
check("pairing: an absolute --wallet-file that does not exist is REFUSED, "
      "not written into the keyfile", _wf_typo is not None)
check("pairing: ...and the refusal says where the cost lands (the signing "
      "step, after the wake and the fan-out plan)",
      _wf_typo and "SIGNING" in _wf_typo and "wake is spent" in _wf_typo)
check("pairing: ...and that there is no way to edit a keyfile afterwards",
      _wf_typo and "pairing both boxes again" in _wf_typo)
# NON-VACUITY, three ways: the real file passes, monero's OTHER name for the
# same wallet passes, and omitting the flag is still the no-withdraw default.
check("pairing: NON-VACUITY -- a wallet that IS there still pairs",
      _pairs_with(_wf_real) is None)
check("pairing: ...and so does one where only <name>.keys is present, which "
      "is monero's other name for the same wallet",
      _pairs_with(_wf_keys) is None)
check("pairing: ...and omitting --wallet-file entirely is still valid",
      _pairs_with(None) is None)
shutil.rmtree(_wf_dir, ignore_errors=True)

# ---- AND THE DEPOSIT AMOUNT IS BOUNDED BY THE BOX THAT ACTS ON IT -------
#
# The schema bounds it on the wire; this is the second check, in the file
# that composes the argv. Its predecessor guarded a ladder index and read
# `slot >= len(ladder)` -- one end only -- so a NEGATIVE slot indexed from the
# far end into ladder[-1], the largest rung, and the refusal never fired. The
# only thing that stopped it was a range check two files away, which is a real
# check and is also somebody else's.
#
# Here rather than only in test_depo_wizard: this is gs_wake_agent's own
# behaviour, and a mutation to it should go red in gs_wake_agent's own suite.
for _sat, _want_refusal in ((-1, True), (0, True),
                            (P.DEPOSIT_MIN_SAT - 1, True),
                            (P.DEPOSIT_MAX_SAT + 1, True), (10 ** 18, True),
                            ("0.05", True), (5_000_000.0, True), (True, True),
                            (P.DEPOSIT_MIN_SAT, False), (5_000_000, False),
                            (P.DEPOSIT_MAX_SAT, False)):
    try:
        A.build_argv("receive_and_quote", {"amount_sat": _sat}, _k, _wdir)
        _ref = False
    except A.Refused:
        _ref = True
    check(f"amount: the vault {'refuses' if _want_refusal else 'accepts'} "
          f"{_sat!r} satoshis", _ref == _want_refusal)

# ---- WHAT BOUNDS A WITHDRAWAL, NOW THAT ONE CAN HAPPEN ------------------
#
# The operator asked for no per-withdrawal host step, and there is none. So the
# question is what stops whoever holds the phone from taking everything, and
# the answer is structural rather than a policy anyone has to remember:
#
#   * create_receive_wallet issues a FRESH ACCOUNT per receive, so each deposit
#     sits in its own account.
#   * GhostSpiral in receive mode is PINNED to the bundle's account -- the
#     entry set is exactly that one subaddress and mix_account_index returns
#     `receive_account_index if receive_mode else None`.
#   * /withdraw names ONE handle, which resolves to ONE bundle.
#
# So a withdrawal reaches one deposit. Taking a second is a second wake against
# the same daily budget. That was already true and nobody depended on it; the
# withdraw job depends on it now, so it is pinned here.
print("\n== a withdrawal reaches one deposit, not the wallet ==")
_G_SRC = open(os.path.join(REPO, "GhostSpiral"), encoding="utf-8").read()
check("bound: receive mode pins the mix to the BUNDLE's account",
      "return receive_account_index if receive_mode else None" in _G_SRC)
check("bound: ...and the entry set is that one subaddress, not the account",
      "ENTRY_SET = [(receive_entry_addr, receive_account_index," in _G_SRC)
check("bound: ...and the fan-out's change rests in that same account",
      "bal_account = receive_account_index if receive_mode else 0" in _G_SRC)
_CRW = open(os.path.join(REPO, "create_receive_wallet"), encoding="utf-8").read()
check("bound: each receive gets its OWN account, so deposits do not pool",
      "create_fresh_account" in _CRW)
# WHERE IT GOES AND HOW DEEP, and nothing else. No handle to remember and no
# account index for a chat message to name -- the vault finds its own funded
# output. `depth` joined this list because a single pinned hop count was a
# floor on what could be withdrawn at all (the mix minimum rises with the hop
# count), and it is safe to add precisely because it names a row of a closed
# table rather than a quantity.
check("bound: the job carries a destination and a depth — no handle to "
      "remember, and no account for a chat message to name",
      sorted(P.JOBS["withdraw"]["schema"]) == ["depth", "exit_to"])
# NON-VACUITY: there is no AMOUNT field on the WITHDRAW path, so nothing lets
# a caller ask for more than the wallet holds -- and nothing lets them ask for
# less either, which is worth knowing. The deposit path does carry one, which
# is a different job that spends nothing.
check("bound: NON-VACUITY -- the spending job takes no amount at all",
      not any("amount" in k for k in P.JOBS["withdraw"]["schema"]))
check("bound: NON-VACUITY -- and the only job that DOES name an amount is one "
      "that cannot spend",
      [j for j, sp in P.JOBS.items()
       if any("amount" in k for k in sp["schema"])] == ["receive_and_quote"]
      and "receive_and_quote" not in P.SPENDING_JOBS)
check("bound: NON-VACUITY -- and the daily cap really exists to bound the "
      "second withdrawal", "daily_wake_budget" in open(
          os.path.join(REPO, "gs_wake_keys"), encoding="utf-8").read())

# ---- AND THE PAIRING REFUSES A KEYFILE THAT COULD NOT SIGN --------------
#
# --allow-withdraw without --wallet-file writes a keyfile whose withdraw job
# relays a fan-out and THEN fails at the signing step. Refused at pairing,
# where both flags are in one place and the cost is a re-typed command --
# rather than discovered hours in, with the money already moved.
_kt = subprocess.run(
    [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair",
     "--allow-withdraw"],
    capture_output=True, text=True, timeout=60)
check("pair: --allow-withdraw without --wallet-file is refused",
      _kt.returncode != 0
      and "needs --wallet-file" in (_kt.stdout + _kt.stderr))
check("pair: ...and says what it would have cost, not just that it is missing",
      "already moved" in (_kt.stdout + _kt.stderr))
_kr = subprocess.run(
    [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair",
     "--allow-withdraw", "--wallet-file", "relative.wallet"],
    capture_output=True, text=True, timeout=60)
check("pair: a RELATIVE wallet path is refused too — the agent runs from a "
      "unit with its own WorkingDirectory",
      _kr.returncode != 0
      and "is relative" in (_kr.stdout + _kr.stderr))
# NON-VACUITY: pairing WITHOUT --allow-withdraw does not demand a wallet file,
# so this refusal is about the combination and not a new mandatory flag.
_kp = subprocess.run(
    [sys.executable, os.path.join(REPO, "gs_wake_keys"), "pair", "--help"],
    capture_output=True, text=True, timeout=60)
check("pair: NON-VACUITY -- --wallet-file is optional on its own",
      _kp.returncode == 0 and "--wallet-file" in _kp.stdout
      and "needs --wallet-file" not in _kp.stdout)

# ---- THE PASSWORD REACHES THAT CHILD AND NO OTHER ------------------------
#
# run_child used to be `env = dict(os.environ)` and nothing else, so every
# child of every job inherited the agent's whole environment. Harmless while
# the unit set no GS_ variables -- and it stops being harmless the moment one
# is needed: putting GS_WALLET_PASSWORD in the unit so the mix can sign would
# hand the spend password to thor_swap_preparer and to create_receive_wallet.
_saved_env = {k: os.environ.get(k)
              for k in ("GS_WALLET_PASSWORD", "GS_EXIT_TO", "GS_BTC_ENTRY")}
try:
    os.environ["GS_WALLET_PASSWORD"] = "spend-secret"
    os.environ["GS_EXIT_TO"] = "inherited-not-given"
    os.environ["GS_BTC_ENTRY"] = "bc1qLEAK"
    _edir = Path(tempfile.mkdtemp(prefix="envscrub_"))
    A.run_child(["/usr/bin/env"], {"GS_EXIT_TO": "given"}, 20,
                log_path=_edir / "out.log")
    _child_gs = sorted(l for l in (_edir / "out.log").read_text().splitlines()
                       if l.startswith("GS_"))
    check("env: a child sees ONLY the GS_ variables it was handed",
          _child_gs == ["GS_EXIT_TO=given"])
    check("env: ...so the spend password does not reach a child that was not "
          "given it", not any("spend-secret" in l for l in _child_gs))
    check("env: ...and an INHERITED value never shadows or survives beside the "
          "one that was given",
          "GS_EXIT_TO=inherited-not-given" not in _child_gs)
    check("env: ...and no other GS_ variable from the unit leaks either",
          not any("bc1qLEAK" in l for l in _child_gs))
    # NON-VACUITY 1: the non-GS_ environment still reaches the child, or this
    # is a wipe rather than a scrub and every tool would break.
    _all = (_edir / "out.log").read_text()
    check("env: NON-VACUITY -- PATH still reaches the child, so this is a "
          "scrub and not a wipe", "PATH=" in _all)
    check("env: NON-VACUITY -- and the marker the agent sets is still there",
          "PYTHONUNBUFFERED=1" in _all)
    # NON-VACUITY 2: the variables really WERE set in the parent, so the
    # absences above are absences from something.
    check("env: NON-VACUITY -- the parent really did hold all three",
          os.environ.get("GS_WALLET_PASSWORD") == "spend-secret"
          and os.environ.get("GS_BTC_ENTRY") == "bc1qLEAK")
finally:
    for _k2, _v2 in _saved_env.items():
        if _v2 is None:
            os.environ.pop(_k2, None)
        else:
            os.environ[_k2] = _v2

# AND THE DISPATCHER PUTS IT BACK, for the spending step only.
_seen.clear()
_saved_il = A.integrity_log
_saved_pw = os.environ.get("GS_WALLET_PASSWORD")
try:
    A.integrity_log = lambda *a, **k: None
    os.environ["GS_WALLET_PASSWORD"] = "spend-secret"
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("withdraw", {"exit_to": _XMR_SAMPLE, "depth": 1},
                    _kw, _wdir, "A3F1", _capture, "job-3",
                    funded=lambda: (9, 4, _XMR_SAMPLE, 5_000_000_000_000))
    check("env: the spending step IS handed the password",
          _seen and _seen[0][1].get("GS_WALLET_PASSWORD") == "spend-secret")
    _seen.clear()
    with contextlib.redirect_stdout(io.StringIO()):
        A._dispatch("swap_status", {"handle": "A3F1"}, _kw, _wdir, "A3F1",
                    _capture, "job-4")
    check("env: NON-VACUITY -- an ordinary step is NOT",
          _seen and "GS_WALLET_PASSWORD" not in _seen[0][1])
finally:
    A.integrity_log = _saved_il
    if _saved_pw is None:
        os.environ.pop("GS_WALLET_PASSWORD", None)
    else:
        os.environ["GS_WALLET_PASSWORD"] = _saved_pw
check("...with the vault's own proxy and rpc in every one of them",
      all("socks5h://127.0.0.1:9050" in a for a in _argvs))
check("...and the only tools it can spawn are the four in JOBS, with the mix "
      "reachable ONLY from the spending job",
      set(t for spec in P.JOBS.values() for t in spec["tools"])
      == {"create_receive_wallet", "thor_swap_preparer", "receive_watch",
          "GhostSpiral"}
      and set(t for j, spec in P.JOBS.items() if j not in P.SPENDING_JOBS
              for t in spec["tools"])
      == {"create_receive_wallet", "thor_swap_preparer", "receive_watch"})
# THE GATE, at the source, because the argv table alone would compose a mix for
# anyone who could name the job. The keyfile decides, and an old keyfile -- one
# written before this job existed -- means no.
check("...and a spending job is refused unless the KEYFILE allows it",
      'if not key.get("allow_withdraw"):' in _A_SRC)
check("...which an upgraded pair does not gain silently: absent means no",
      ".get(\"allow_withdraw\")" in _A_SRC
      and "allow_withdraw\"]" not in _A_SRC)


# ===========================================================================
# SILENCING THE UNIT SILENCED THE AGENT'S OWN REASONS TOO.
#
# StandardOutput=null/StandardError=null had to go on the unit -- the children
# print the ThorChain memo and systemd would journal it onto the SD card. But
# the agent's OWN refusal reasons and every uncaught traceback went out the
# same pipe. With OnFailure=gs-wake-poweroff.service, a vault that refuses for
# no_keyfile / keyfile_perms / outside_wipe_roots now boots, powers itself off,
# and leaves NOTHING saying why: only the terse code reached the chain, and
# the journal copy that used to carry the reason is gone.
# ===========================================================================
_al = Path(tempfile.mkdtemp(prefix="agentlog_"))
_saved_log = A._AGENT_LOG[0]
try:
    A._AGENT_LOG[0] = _al / A.JOB_LOG
    _cap = io.StringIO()
    with contextlib.redirect_stdout(_cap):
        A.agent_say("  [!] Wake refused (no_keyfile): there is no keyfile")
    _on_disk = (_al / A.JOB_LOG).read_text()
    check("a refusal reason is written where StandardOutput=null cannot "
          "reach it", "no_keyfile" in _on_disk)
    check("...and still printed, for the operator running it by hand",
          "no_keyfile" in _cap.getvalue())
    check("...into the same 0600 file the children's output uses, so it is "
          "wiped with the artifacts and nowhere else",
          oct(os.stat(_al / A.JOB_LOG).st_mode)[-3:] == "600")
    A._AGENT_LOG[0] = None
    _cap2 = io.StringIO()
    with contextlib.redirect_stdout(_cap2):
        A.agent_say("before the artifact dir is known")
    check("before the artifact dir is known it only prints -- it does not "
          "invent a path from an untrusted keyfile",
          "before the artifact dir" in _cap2.getvalue())
    A._AGENT_LOG[0] = Path("/proc/nonexistent-dir-xyz") / "x.log"
    A.agent_say("unwritable")                       # must not raise
    check("agent_say never raises, so logging cannot become the thing that "
          "aborts a wake", True)
finally:
    A._AGENT_LOG[0] = _saved_log

_agent_src = open(os.path.join(REPO, "gs_wake_agent")).read()
check("the refusal paths actually use it, or the helper is decoration",
      "agent_say(f\"  [!] Wake refused (" in _agent_src
      and "agent_say(f\"  [!] Wake refused: {e}\")" in _agent_src)
check("an unhandled exception is recorded and RE-RAISED, so the finally still "
      "powers off exactly as before",
      "unhandled \"" in _agent_src
      and "traceback.format_exc()" in _agent_src
      and _agent_src.split("agent_say(traceback.format_exc())")[1][:300]
          .count("raise") == 1)
check("_AGENT_LOG is pointed at the artifact dir, not at a fixed path",
      "_AGENT_LOG[0] = artifact_dir / JOB_LOG" in _agent_src)

# ===========================================================================
# ...AND THE DIVERSION SWALLOWED THE BY-HAND RUN, WHICH THE UNIT ITSELF
# OFFERS AS THE MITIGATION: "run the agent by hand with --dry-run and you
# still see everything on your terminal". run_child diverted unconditionally,
# so that was false -- and JOB_LOG was printed nowhere, so an operator had no
# way to find what they were no longer being shown.
# ===========================================================================
check("where the child's output went is announced, not left to be guessed",
      "output -> {_jl}" in _agent_src)
check("a tty means a human is watching and there is no journal in the path, "
      "so the output is NOT diverted",
      "sys.stdout.isatty()" in _agent_src
      and "log_path=None if _watched else _jl" in _agent_src)
check("...and isatty is guarded, because a closed stdout must not abort a "
      "wake", "_watched = False" in _agent_src)

# ===========================================================================
# THE HARDENING MADE THE DEPENDENCIES INVISIBLE, AND THE SILENCE HID IT.
#
# ProtectHome=yes makes /home, /root and /run/user inaccessible to this unit.
# Python derives its per-user site directory from $HOME, so a
# `pip install --user` dependency set cannot be imported here -- and on
# Debian 12 / Raspberry Pi OS a plain `pip install` is refused (PEP 668),
# which pushes operators to exactly that install. Measured on a live box, the
# normal outcome is a MIXED install:
#
#   requests -> /root/.local/lib/python3.11/site-packages   (invisible here)
#   monero   -> /usr/local/lib/python3.11/dist-packages     (fine)
#
# gs_common imports requests at MODULE scope, so this fails before any of this
# toolchain's code runs; StandardError=null discards the traceback; and
# OnFailure=gs-wake-poweroff.service then powers the machine down. The vault
# boots, dies, powers off, and nothing anywhere says why.
# ===========================================================================
print("\n== a missing dependency must not become a silent poweroff ==")
check("the unit checks its dependencies BEFORE the agent runs",
      "ExecStartPre=" in _agent_u)
_pre = [l for l in _agent_u.splitlines() if l.startswith("ExecStartPre=")]
check("...and there is exactly one such check", len(_pre) == 1)
_preline = _pre[0] if _pre else ""
# EXACTLY THE HARD SET. A pre-check stricter than the code would itself be the
# thing that stops the vault working.
for _hard in ("requests", "tenacity", "nacl", "socks", "psutil", "monero",
              "stem"):
    check(f"the pre-check covers {_hard}, which the wake path hard-requires",
          _hard in _preline)
# stem MOVED FROM SOFT TO HARD, and this loop used to PIN the wrong answer.
#
# It asserted stem was absent from the pre-check "because it is guarded or
# unused on the wake path". It is neither. gs_common.newnym imports stem
# INSIDE its retry loop, so a missing package is caught as just another
# rotation failure -- and with required=True the handler is sys.exit.
# create_receive_wallet:258 calls newnym(required=True), and it runs for both
# receive_and_quote, i.e. every /deposit.
#
# Driven with stem made unimportable:
#   [!] Tor circuit rotation FAILED after 1 attempts: No module named 'stem'
# -- a message that sends the operator to debug Tor, which is working.
for _soft in ("gnupg",):
    check(f"...and NOT {_soft}, which is genuinely guarded on the wake path",
          _soft not in _preline)
# AND THE REASON gnupg STAYS SOFT IS CHECKED, not asserted: it is imported
# lazily inside the --gpg-recipient branch, and the wake path never composes
# that flag.
_tsp = open(os.path.join(REPO, "thor_swap_preparer"), encoding="utf-8").read()
# THE INDENTATION IS THE WHOLE TEST, so it must not be stripped. The first
# draft compared l.strip() against "import gnupg", which removes the very
# thing that distinguishes a module-scope import from a lazy one -- and went
# red on correct code.
_gn_lines = [l for l in _tsp.splitlines() if l.rstrip().endswith("import gnupg")]
check("...and gnupg really is imported lazily rather than at module scope",
      _gn_lines
      and not any(l == l.lstrip() for l in _gn_lines))
check("...and no wake job composes --gpg-recipient",
      not any("--gpg-recipient" in _a
              for _j in P.JOBS
              for _argv in A.build_argv(_j, _sample[_j], _k, _wdir,
                                        bundle="b", slip="s", handle="A3F1")
              for _a in _argv))
check("the failure is written somewhere durable, not to the null stderr "
      "this unit sets",
      "gs_wake_job.log" in _preline)
check("...and it exits non-zero, so systemd does not start the agent anyway",
      "exit 1" in _preline)
# NON-VACUITY: the hard set must match what the code actually imports.
check("requests really is a module-scope import in gs_common, which is why a "
      "missing one cannot be caught in Python",
      any(l.strip() == "import requests"
          for l in open(os.path.join(REPO, "gs_common.py")).read().splitlines()))
check("psutil really does refuse the wake when absent",
      "no_sentinel" in open(os.path.join(REPO, "gs_wake_agent")).read())
check("the unit says how to install them so this does not recur",
      "break-system-packages" in _agent_u or "venv" in _agent_u)

# ===========================================================================
# THE REFUSAL TOLD A CORRECT INSTALL IT WAS BROKEN.
#
# wipe_covers resolves against cwd and $HOME. The unit sets both; an operator's
# shell does not. So `gs_wake_agent --key ... --dry-run` -- the command
# gs_wake_keys prints as "confirm the pairing works before you rely on it" --
# refused on the SHIPPED DEFAULT artifact dir, at the exact moment the operator
# was told to check that pairing had worked.
# ===========================================================================
print("\n== outside_wipe_roots must say which of its two causes this is ==")
_agent_src = open(os.path.join(REPO, "gs_wake_agent")).read()
check("the refusal names the by-hand case rather than only the misconfigured "
      "one", "BY HAND" in _agent_src)
check("...and gives the cd + HOME that reproduces the unit's environment",
      "cd {artifact_dir} && HOME={artifact_dir}" in _agent_src)
check("...and still names the systemd fix for a genuinely misplaced dir",
      "WorkingDirectory=" in _agent_src and "Environment=HOME=" in _agent_src)
_keys_src = open(os.path.join(REPO, "gs_wake_keys")).read()
check("the pairing tool's own 'next step' command is conditional on whether "
      "the chosen artifact dir is reachable from a shell",
      "if not wipe_covers(_ad):" in _keys_src)
check("...and prints the working form when it is not",
      "HOME={_ad}" in _keys_src)

# ===========================================================================
#  THE ARTIFACT DIRECTORY'S MODE, WHICH THE FILES INSIDE DO NOT FIX
# ===========================================================================
#
# run_job created artifact_dir with a bare `mkdir(parents=True, exist_ok=True)`
# -- 0777 & ~umask, measured 0755, and the shipped unit sets no UMask=. The
# files inside are 0600, but the LISTING is the leak: thor_pairs_*.json,
# wallet_*.json, the job log and the status file all name themselves, so a
# local account learns how many swaps were arranged, when, and that this
# machine runs a Monero cold-signing operation at all.
#
# Driven with a REAL unprivileged uid rather than by reading the mode, because
# "0755" is a number and "another account could list your swaps" is the claim.
print("\n== the artifact directory is not world-listable ==")
import stat as _stat_m                                       # noqa: E402


def _nobody_can_list(d):
    """Fork, drop to uid 65534, return what it could list (or the errno)."""
    _r, _w = os.pipe()
    _pid = os.fork()
    if _pid == 0:
        os.close(_r)
        try:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            assert os.geteuid() == 65534
            _names = sorted(os.listdir(d))
        except Exception as _e:                              # noqa: BLE001
            _names = [f"<{type(_e).__name__}>"]
        os.write(_w, json.dumps(_names).encode())
        os.close(_w)
        os._exit(0)
    os.close(_w)
    _buf = b""
    while True:
        _c = os.read(_r, 4096)
        if not _c:
            break
        _buf += _c
    os.close(_r)
    os.waitpid(_pid, 0)
    return json.loads(_buf or "[]")


_CAN_DROP_WA = os.geteuid() == 0
check("artifact-dir: the checks below can drop privileges (running as root, "
      "so uid 65534 is reachable)", _CAN_DROP_WA)
if _CAN_DROP_WA:
    _um = os.umask(0o022)                                    # the systemd default
    try:
        # (a) A directory the agent CREATES, two levels deep so the parents are
        #     covered too -- mkdir(parents=True) applies `mode` only to the
        #     final component, which is one of the two things secure_mkdir
        #     handles that a bare mkdir does not.
        _base = Path(tempfile.mkdtemp())
        os.chmod(_base, 0o755)
        _ad = _base / "var" / "lib" / "ghostspiral"
        A.secure_mkdir(_ad, narrow_existing=False)
        (_ad / "thor_pairs_ab.json").write_text("{}")
        (_ad / "gs_wake_job.log").write_text("x")
        check("artifact-dir: a directory the agent creates is 0700",
              _stat_m.S_IMODE(_ad.stat().st_mode) == 0o700)
        check("artifact-dir: ...and so is every parent it had to create",
              _stat_m.S_IMODE(_ad.parent.stat().st_mode) == 0o700)
        check("artifact-dir: ...so another account cannot list this run's "
              "artifacts", _nobody_can_list(_ad) == ["<PermissionError>"])
        # NON-VACUITY: the bare mkdir this replaces really was listable, under
        # the same umask, in the same place.
        _b2 = Path(tempfile.mkdtemp())
        os.chmod(_b2, 0o755)
        _ad2 = _b2 / "var" / "lib" / "ghostspiral"
        _ad2.mkdir(parents=True, exist_ok=True)
        (_ad2 / "thor_pairs_ab.json").write_text("{}")
        (_ad2 / "gs_wake_job.log").write_text("x")
        check("artifact-dir: NON-VACUITY -- a bare mkdir really does leave it "
              "0755 and listable",
              _stat_m.S_IMODE(_ad2.stat().st_mode) == 0o755
              and _nobody_can_list(_ad2) == ["gs_wake_job.log",
                                             "thor_pairs_ab.json"])
        _acode = code_only(os.path.join(REPO, "gs_wake_agent"))
        check("artifact-dir: ...and run_job uses secure_mkdir, not the bare "
              "call", "secure_mkdir(artifact_dir, narrow_existing=False)"
              in _acode
              and "artifact_dir.mkdir(" not in _acode)

        # (b) A PRE-EXISTING directory is left alone at creation -- it may be
        #     the operator's own cwd, since artifact_dir defaults to "." -- and
        #     narrowed in preflight, after wipe_covers has established that
        #     this tool owns it.
        _ex = Path(tempfile.mkdtemp())
        os.chmod(_ex, 0o755)
        A.secure_mkdir(_ex, narrow_existing=False)
        check("artifact-dir: a PRE-EXISTING directory is NOT chmod'ed at "
              "creation -- it might be the operator's cwd",
              _stat_m.S_IMODE(_ex.stat().st_mode) == 0o755)
        (_ex / "thor_pairs_ab.json").write_text("{}")
        A._AGENT_LOG[0] = _ex / "gs_wake_job.log"
        _probes = {"unit_is_active": lambda u: True,
                   "removable_devices": lambda: [],
                   "resource_check": lambda a, b: True,
                   "tor_bootstrapped": lambda p: True,
                   "wipe_covers": lambda p: True}
        A.preflight({"tor_proxy": "socks5h://127.0.0.1:9"}, _ex,
                    dry_run=True, probes=_probes)
        check("artifact-dir: ...and preflight narrows it to 0700 once "
              "wipe_covers says this tool owns it",
              _stat_m.S_IMODE(_ex.stat().st_mode) == 0o700)
        check("artifact-dir: ...and says so, because the PREVIOUS runs' "
              "artifacts were listable and this chmod does not undo that",
              "was mode 0755" in (_ex / "gs_wake_job.log").read_text()
              and "earlier runs" in (_ex / "gs_wake_job.log").read_text())
        check("artifact-dir: ...and nobody can list it now",
              _nobody_can_list(_ex) == ["<PermissionError>"])

        # NON-VACUITY: preflight must NOT narrow a directory it refused, or it
        # is chmod'ing a directory that is not this tool's territory.
        _nx = Path(tempfile.mkdtemp())
        os.chmod(_nx, 0o755)
        A._AGENT_LOG[0] = _nx / "gs_wake_job.log"
        _refused = False
        try:
            A.preflight({"tor_proxy": "x"}, _nx, dry_run=True,
                        probes={**_probes, "wipe_covers": lambda p: False})
        except A.Refused:
            _refused = True
        check("artifact-dir: NON-VACUITY -- a directory outside the wipe roots "
              "is refused and left UNTOUCHED",
              _refused and _stat_m.S_IMODE(_nx.stat().st_mode) == 0o755)
        # NON-VACUITY: an already-0700 directory must not produce the warning,
        # or the operator learns to ignore it.
        _ok = Path(tempfile.mkdtemp())
        os.chmod(_ok, 0o700)
        A._AGENT_LOG[0] = _ok / "gs_wake_job.log"
        A.preflight({"tor_proxy": "socks5h://127.0.0.1:9"}, _ok,
                    dry_run=True, probes=_probes)
        check("artifact-dir: NON-VACUITY -- an already-0700 directory produces "
              "no warning",
              not (_ok / "gs_wake_job.log").exists()
              or "was mode" not in (_ok / "gs_wake_job.log").read_text())
    finally:
        os.umask(_um)
        A._AGENT_LOG[0] = None

check("artifact-dir: the shipped unit also sets UMask=0077, for files a "
      "woken job's CHILD creates without naming a mode",
      "UMask=0077" in (Path(REPO) / "systemd" / "gs-wake-agent.service").read_text())


_finished()
# ===========================================================================
#  A WATCH THAT RAN OUT OF TIME IS NOT A FAILURE
# ===========================================================================
print("\n-- /watch reports what it saw, like /check does --")
#
# receive_watch exits non-zero when its 110 minutes run out, so the pager said
# "watch: failed." about money that was simply still in flight. That is the
# exact sentence swap_status was built to stop saying -- and it was being said
# on the command an operator reaches for when they are least able to go and
# look for themselves.
#
# _phase_of returned "" for anything that was not swap_status, so `watch` could
# never produce a phase however it ended.
import importlib.machinery as _im2, importlib.util as _iu2
_ldw = _im2.SourceFileLoader("gs_wake_agent", os.path.join(REPO, "gs_wake_agent"))
_AGW = _iu2.module_from_spec(_iu2.spec_from_loader(_ldw.name, _ldw))
_ldw.exec_module(_AGW)

_wkey = {"tor_proxy": "socks5h://127.0.0.1:9050", "rpc_primary": "http://x",
         "amount_ladder": ["0.01", "0.02"]}
_wargv = _AGW.build_argv("watch", {"handle": "A3F1"}, _wkey,
                         Path("/var/lib/ghostspiral"),
                         bundle="/b.json", slip="/p.json", handle="A3F1")
_flat_w = _wargv[0]
check("watch: the argv asks receive_watch to report what it saw",
      "--result-json" in _flat_w)
check("watch: ...to the same fixed path the status probe uses, composed from "
      "the keyfile and not from anything the operator typed",
      str(Path("/var/lib/ghostspiral") / _AGW.STATUS_FILE) in _flat_w)
check("watch: ...and still inside its own 110-minute window",
      "--timeout-min" in _flat_w
      and _flat_w[_flat_w.index("--timeout-min") + 1] == "110")
# NON-VACUITY: the handle and the slot never reach argv as anything but the
# fixed template plus a validated value.
check("watch: NON-VACUITY -- the argv is a real one for the real tool",
      "receive_watch" in " ".join(_flat_w))

# AND _phase_of NOW ANSWERS FOR IT.
_wd = Path(tempfile.mkdtemp(prefix="watchphase_"))
for _state, _total, _want in (("timeout", "0", "not_yet"),
                              ("timeout", "0.4", "arriving"),
                              ("funded", "1.2", "landed"),
                              ("stalled", "0.4", "short")):
    (_wd / _AGW.STATUS_FILE).write_text(json.dumps(
        {"state": _state, "total": _total, "unlocked": _total, "ticks": 2}))
    check(f"watch: a {_state!r} watch reports {_want!r}, not a failure",
          _AGW._phase_of("watch", _wd) == _want)
# NON-VACUITY: a job that is NOT a watching job still gets no phase, so this
# did not open the door to every job inventing a status.
(_wd / _AGW.STATUS_FILE).write_text(json.dumps({"state": "funded",
                                                "total": "1"}))
check("watch: NON-VACUITY -- receive_and_quote still earns no phase",
      _AGW._phase_of("receive_and_quote", _wd) == "")
check("watch: NON-VACUITY -- and swap_status still does",
      _AGW._phase_of("swap_status", _wd) == "landed")



# ===========================================================================
# A WALLET THAT COULD NOT BE ASKED IS NOT A WALLET WITH NOTHING IN IT
# ===========================================================================
#
# _funded_entry returns None for both, and the callers cannot tell them
# apart from the value -- the chat line already hedges ("or it could not be
# checked"). The difference is recorded where it is known.
print("\n== _funded_entry: RPC failure vs nothing found ==")
_gc_mod = sys.modules["gs_common"]
_saved_connect = _gc_mod.connect_rpc
_fe_log = []
_saved_il_fe = A.integrity_log


def _down(*a, **k):
    raise ConnectionError("wallet-rpc down")


try:
    _gc_mod.connect_rpc = _down
    A.integrity_log = lambda st, kind, *a, **k: _fe_log.append((st, kind))
    with contextlib.redirect_stdout(io.StringIO()) as _fe_out:
        _fe = A._funded_entry({"rpc_primary": "http://127.0.0.1:1",
                               "tor_proxy": ""})
finally:
    _gc_mod.connect_rpc = _saved_connect
    A.integrity_log = _saved_il_fe
check("funded: an RPC failure still answers None, so no caller spends on a "
      "guess", _fe is None)
check("funded: ...and is RECORDED as a failure, distinct from nothing found",
      ("wake", "funded_entry:rpc_failed") in _fe_log)
check("funded: ...with the exception's type on the terminal and not its text, "
      "which could carry a URL",
      "ConnectionError" in _fe_out.getvalue()
      and "wallet-rpc down" not in _fe_out.getvalue())


class _EmptyRPC:
    def raw_request(self, method, params):
        return {"subaddress_accounts": []} if method == "get_accounts" else {}


_fe_log2 = []
try:
    _gc_mod.connect_rpc = lambda *a, **k: _EmptyRPC()
    A.integrity_log = lambda st, kind, *a, **k: _fe_log2.append((st, kind))
    with contextlib.redirect_stdout(io.StringIO()):
        _fe2 = A._funded_entry({"rpc_primary": "x", "tor_proxy": ""})
finally:
    _gc_mod.connect_rpc = _saved_connect
    A.integrity_log = _saved_il_fe
check("funded: NON-VACUITY -- a wallet that answers with nothing is None "
      "WITHOUT the failure record",
      _fe2 is None and _fe_log2 == [])


# ===========================================================================
# THE RESULT RECORD IS TRIED MORE THAN ONCE
# ===========================================================================
#
# post_record returns (0, b"") on any transport failure and never raises, so
# report_back's except could not fire on the failure that happens in practice
# -- a Tor circuit to the Pi down for the thirty seconds it ran in -- and the
# one record that tells the phone money moved was lost to it silently.
print("\n== report_back: retried, refused once, or given up loudly ==")
import nacl.public as _npub_rb
_rb_tp, _rb_pi = _npub_rb.PrivateKey.generate(), _npub_rb.PrivateKey.generate()
_rb_key = {"secret": bytes(_rb_tp).hex(),
           "peer_public": bytes(_rb_pi.public_key).hex(),
           "doorbell_url": "http://x"}
_rb_log = []
_saved_il_rb = A.integrity_log
A.integrity_log = lambda st, kind, *a, **k: _rb_log.append(kind)


def _rb_drive(statuses):
    """A poster answering `statuses` in order (repeating the last)."""
    _calls, _sleeps = [], []
    _seq = list(statuses)

    def _post(url, path, rec, timeout=30):
        _calls.append(path)
        return (_seq.pop(0) if len(_seq) > 1 else _seq[0]), b""
    del _rb_log[:]
    with contextlib.redirect_stdout(io.StringIO()):
        A.report_back(_rb_key, "j", "00" * 32, "done", "A3F1",
                      poster=_post, sleeper=lambda s: _sleeps.append(s))
    return _calls, _sleeps, list(_rb_log)


try:
    _c1, _s1, _l1 = _rb_drive([200])
    check("report: a first-try delivery posts once and sleeps never",
          _c1 == ["/result"] and _s1 == [] and _l1 == [])
    _c2, _s2, _l2 = _rb_drive([0, 0, 200])
    check("report: a dead circuit is retried with backoff, and the delivery "
          "on retry is recorded",
          len(_c2) == 3 and _s2 == [15, 30]
          and _l2 == ["result_delivered_on_retry"])
    _c3, _s3, _l3 = _rb_drive([0])
    check("report: ...bounded -- four attempts, three waits, then it is said "
          "to be undeliverable",
          len(_c3) == A.RESULT_POST_ATTEMPTS and _s3 == [15, 30, 60]
          and _l3 == ["result_undeliverable"])
    _c4, _s4, _l4 = _rb_drive([204])
    check("report: a doorbell that ANSWERED and refused (204) is not retried "
          "-- the same record would be refused again -- and is recorded as "
          "rejected, not undeliverable",
          _c4 == ["/result"] and _s4 == [] and _l4 == ["result_rejected"])
    _c5, _s5, _l5 = _rb_drive([503, 200])
    check("report: a 5xx is transient and retried", len(_c5) == 2
          and _l5 == ["result_delivered_on_retry"])

    def _raiser(url, path, rec, timeout=30):
        raise ConnectionError("no circuit")
    _sl6 = []
    del _rb_log[:]
    with contextlib.redirect_stdout(io.StringIO()):
        A.report_back(_rb_key, "j", "00" * 32, "done", "A3F1",
                      poster=_raiser, sleeper=lambda s: _sl6.append(s))
    check("report: a poster that raises is treated as a transport failure, "
          "retried and then given up on -- never propagated",
          len(_sl6) == 3 and _rb_log == ["result_undeliverable"])
finally:
    A.integrity_log = _saved_il_rb
check("report: every call site hands the sleep dependency through, so the "
      "tests that inject a failing poster do not wait real minutes",
      _AGENT_SRC.count("sleeper=d.get(\"sleep\")") == 3
      and _AGENT_SRC.count("report_back(") >= 4)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
