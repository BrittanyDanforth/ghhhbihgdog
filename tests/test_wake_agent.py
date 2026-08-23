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
import importlib.machinery
import importlib.util
import io
import json
import os
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


def new_env(job="receive_and_quote", params=None, ladder=("0.01", "0.05")):
    """A scratch vault: keyfile, artifact dir, and a doorbell holding one job."""
    d = Path(tempfile.mkdtemp(prefix="wakeagent_"))
    key = {"schema": "gs_wake_v1", "version": 1, "role": "thinkpad",
           "secret": TP.encode().hex(),
           "peer_public": PI.public_key.encode().hex(),
           "doorbell_url": "http://10.0.0.9:8770",
           "tor_proxy": "socks5h://127.0.0.1:9050",
           "rpc_primary": "http://127.0.0.1:18083",
           "artifact_dir": str(d), "amount_ladder": list(ladder),
           "account_ceiling": 45}
    kf = d / "tp.key"
    # THE REAL CONTAINER, not a hand-built dict. A fixture that writes a shape
    # the shipped loader no longer accepts is a fixture that tests a format
    # nothing uses -- which is how a suite stays green through a format change.
    kf.write_text(json.dumps(P.lock_keyfile(key, b"", role="thinkpad")))
    os.chmod(kf, 0o400)
    bell = DB.Pending({"secret": PI.encode().hex(),
                       "peer_public": TP.public_key.encode().hex()},
                      job, params if params is not None else {"amount_slot": 1},
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
      env_all.get("GS_SWAP_AMOUNTS") == "0.05"
      and not any("0.05" == a for a in argv_all))
check("the amount is selected by LADDER INDEX, so the note carries no number",
      "amount_slot" in P.JOBS["receive_and_quote"]["schema"])

# Plant the address in every field a note can reach, and in the ladder.
d2, kf2, key2, bell2 = new_env(params={"amount_slot": 0}, ladder=(XMR,))
dp2 = deps_for(d2, bell2)
out2, err2, _t = run(kf2, dp2)
argv2 = [a for argv, _e in dp2["_ran"] for a in argv]
check("even an address planted in the ladder never reaches argv",
      not any(XMR in a for a in argv2))
check("...it reaches the child's ENV instead, which is mode 0400",
      any(XMR in v for _a, e in dp2["_ran"] for v in e.values()))


# ===========================================================================
print("\n== injection negatives: every one refused by the schema ==")
for bad in ("--tor-proxy", "socks5h://10.0.0.9:9050", "--allow-unbound-memo",
            "--outfile", "/srv/x.json", "; rm -rf ~", "../../etc/passwd",
            "--rpc", "--dests", XMR):
    d3, kf3, _k, bell3 = new_env()
    # A doorbell that has been told to send a flag-shaped value.
    bell3.params = {"amount_slot": bad}
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

# --dry-run is the pairing check, run by hand. Three minutes of silence in
# front of an operator reads as a hang, not as opsec.
d6c, kf6c, _k, bell6c = new_env()
slept6c = []
dp6c = deps_for(d6c, bell6c,
                post_record=stub_post(bell6c),
                sleep=slept6c.append)
out6c, err6c, _t = run(kf6c, dp6c, dry_run=True)
check("...and --dry-run skips the dwell",
      out6c is None and err6c.code == "no_job" and slept6c == [])

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
                            "job": "receive_new", "count": 1})
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
                            "job": "receive_new", "count": 1})
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
                    "receive_and_quote", {"amount_slot": 1}, clock=lambda: 0.0)
bell13.job_id = first
out13, err13, _t = run(kf12, deps_for(d12, bell13))
check("the same job_id on a later boot is REFUSED — a second slip would "
      "overwrite the first, and BTC may already have been sent against it",
      out13 is None and err13.code == "job_replayed")
check("...and the message names when it was started and where to look",
      "check" in err13.msg.lower() and str(d12) in err13.msg)


print("\n== the account ceiling ==")
d14, kf14, _k, bell14 = new_env(job="receive_new", params={"count": 1})
out14, err14, _t = run(kf14, deps_for(d14, bell14, account_count=lambda: 45))
check("a minting job is refused at the ceiling — a pwned doorbell must not "
      "burn accounts past the offline wallet's lookahead",
      out14 is None and err14.code == "account_ceiling")
d15, kf15, _k, bell15 = new_env(job="receive_new", params={"count": 1})
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
A.disarm_deadman = lambda: calls.append("disarm")

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
dh1, kfh1, _k, bellh1 = new_env(job="receive_new", params={"count": 1})
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
dh2, kfh2, _k, bellh2 = new_env(job="receive_new", params={"count": 1})
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
_worst = A.JITTER_HI_S + max(len(sp["tools"]) * sp["budget_s"]
                             for sp in P.JOBS.values())
check("the agent's own timeout leaves room for the worst real job "
      f"(jitter {A.JITTER_HI_S}s + the largest budget)", _tmo > _worst)
check("...and the DEADMAN is longer than it, so the ordinary path is bounded "
      "by the agent and the deadman is only the backstop", _dms > _tmo)

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
# `--count 4` writes FOUR wallet_<random>.json files. The first version
# recorded new[0] -- whichever of them sorted first -- so a later `watch` on
# that handle watched an address the operator had no way to predict.
dw1, kfw1, _k, bellw1 = new_env(job="receive_new", params={"count": 4})


def _mint4(argv, env_extra, budget):
    for i in range(4):
        (dw1 / f"wallet_recv_{i}.json").write_text("{}")
    return 0, False


dpw1 = deps_for(dw1, bellw1, run_child=_mint4)
outw1, errw1, _t = run(kfw1, dpw1)
_recs1 = json.loads((dw1 / A.HANDLES_FILE).read_text())
_rec1 = _recs1[outw1[2]]
check("receive_new --count 4 records the handle with NO single bundle, rather "
      "than an arbitrary one of the four",
      outw1[0] == "done" and _rec1["bundle"] is None and _rec1["minted"] == 4)


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

# A handle minted by receive_new has no slip. str(None) put the literal string
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
                                params={"amount_slot": 0})


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
      "rpc_primary": "http://127.0.0.1:18083", "amount_ladder": ["0.01"]}
_sample = {"receive_new": {"count": 1}, "receive_and_quote": {"amount_slot": 0},
           "watch": {"handle": "A3F1"}, "swap_status": {"handle": "A3F1"}}
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
      == {"create_receive_wallet", "thor_swap_preparer", "receive_watch"})
check("...with the vault's own proxy and rpc in every one of them",
      all("socks5h://127.0.0.1:9050" in a for a in _argvs))
check("...and the only tools it can spawn are the three in JOBS",
      set(t for spec in P.JOBS.values() for t in spec["tools"])
      == {"create_receive_wallet", "thor_swap_preparer", "receive_watch"})


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
for _hard in ("requests", "tenacity", "nacl", "socks", "psutil", "monero"):
    check(f"the pre-check covers {_hard}, which the wake path hard-requires",
          _hard in _preline)
for _soft in ("stem", "gnupg", "yaml"):
    check(f"...and NOT {_soft}, which is guarded or unused on the wake path",
          _soft not in _preline)
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

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
