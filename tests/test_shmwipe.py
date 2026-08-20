#!/usr/bin/env python3
"""paranoia_mode must wipe the signer's scratch from /dev/shm and $TMPDIR.

airgap_tx_signer deliberately PREFERS /dev/shm for its two worst artifacts --
the plaintext wallet password (.gs_pw_*) and the wallet output-set scratch
(gs_impout_*, the holdings picture) -- and creates gs_sign_* (which holds a
signed, RELAYABLE transaction) with tempfile.mkdtemp(), which honours TMPDIR.
paranoia_mode's Temp files phase hard-coded /tmp and /var/tmp, and its artifact
search roots are cwd/$HOME, so on the normal path nothing covered either
location. Normal runs delete them in a finally, so this only ever showed up
after a SIGKILL/OOM/power loss -- exactly the case the wipe exists for.

The fix must be PREFIX-TARGETED, and that is the other half of what is tested
here: /dev/shm is shared infrastructure (Chromium, PostgreSQL, PulseAudio keep
live segments there under this same uid) and TMPDIR can legitimately point at
$HOME, so a blanket uid-scoped sweep of either would break running software or
destroy a home directory. Unrelated entries MUST survive.

Nothing here touches the real /dev/shm: the roots are redirected at fake
directories, and every deletion is a real deletion inside those fakes.
"""
import importlib.machinery, importlib.util, os, sys, tempfile
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    loader = importlib.machinery.SourceFileLoader(
        name.replace(".py", ""), os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


para = load("paranoia_mode")

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


def populate(root: Path):
    """Recreate exactly what airgap_tx_signer leaves behind, plus decoys."""
    # ours -- must go
    (root / "gs_sign_abc123").mkdir()
    (root / "gs_sign_abc123" / "signed_monero_tx").write_bytes(b"RELAYABLE" * 64)
    (root / "gs_sign_abc123" / "unsigned_monero_tx").write_bytes(b"U" * 64)
    (root / "gs_impout_zz").mkdir()
    (root / "gs_impout_zz" / "outputs_blob").write_bytes(b"HOLDINGS" * 64)
    (root / ".gs_pw_9f2").write_text("correct horse battery staple")
    # not ours -- must survive (these are the live segments real software keeps
    # in /dev/shm under the SAME uid; wiping them breaks running processes)
    (root / "pulse-shm-1234567").write_bytes(b"audio")
    (root / ".org.chromium.Chromium.AbCdEf").write_bytes(b"renderer")
    (root / "PostgreSQL.9876").write_bytes(b"pg")
    (root / "sem.mylock").write_bytes(b"sem")
    (root / "important_user_dir").mkdir()
    (root / "important_user_dir" / "keep.txt").write_text("keep me")


OURS = ["gs_sign_abc123", "gs_impout_zz", ".gs_pw_9f2"]
THEIRS = ["pulse-shm-1234567", ".org.chromium.Chromium.AbCdEf",
          "PostgreSQL.9876", "sem.mylock", "important_user_dir"]

# ---------------------------------------------------------------------------
# real wipe: ours gone, theirs untouched
# ---------------------------------------------------------------------------
sandbox = Path(tempfile.mkdtemp(prefix="gs_shmtest_"))
shm = sandbox / "shm"; shm.mkdir()
tmpd = sandbox / "customtmp"; tmpd.mkdir()
populate(shm)
populate(tmpd)

real_gettempdir = tempfile.gettempdir
para.tempfile.gettempdir = lambda: str(tmpd)
_orig_roots = None

# BOTH roots are redirected, and the /dev/shm one has to be.
#
# This previously patched only tempfile.gettempdir and claimed it therefore ran
# "without ever scanning the host's real /dev/shm". That was FALSE: the helper
# built ["/dev/shm", gettempdir()] with the first entry as a literal, so the
# real /dev/shm was scanned on every iteration no matter what gettempdir said.
# With dry=False this test then SECURELY DELETED any live
# gs_sign_*/gs_impout_*/.gs_pw_* it found there -- which is precisely the
# scratch a concurrently running signer keeps in RAM. Running the suite beside
# a real pipeline run made the count wrong, because the sweep had reached into
# the other run and erased its working directory.
#
# paranoia_mode.SHM_ROOT exists so this is patchable. Each iteration points
# BOTH roots at the same fake directory, so the assertions below describe only
# files this test created.
for label, root in (("shm-like", shm), ("tmpdir", tmpd)):
    para.SHM_ROOT = str(root)
    para.tempfile.gettempdir = lambda r=root: str(r)
    count, failed = para._wipe_targeted_temp_roots(
        dry=False, uid=os.getuid(), already_done=["/tmp", "/var/tmp"])
    for name in OURS:
        check(f"{label}: {name} securely deleted",
              not (root / name).exists())
    for name in THEIRS:
        check(f"{label}: {name} SURVIVES (other software's shared memory)",
              (root / name).exists())
    check(f"{label}: keep.txt inside unrelated dir survives",
          (root / "important_user_dir" / "keep.txt").read_text() == "keep me")
    check(f"{label}: counted the 3 entries it removed", count == 3)
    check(f"{label}: no failures", failed == 0)

# ---------------------------------------------------------------------------
# BOTH ROOTS IN ONE CALL, AND THEY MUST BE DIFFERENT DIRECTORIES.
#
# The loop above points SHM_ROOT and gettempdir() at the SAME directory each
# iteration, for the good reason documented there. The cost is that it cannot
# tell the two roots apart: with both aliased, removing /dev/shm from the
# helper's root list entirely still finds every file through the tmpdir entry,
# and the suite stays green. Verified by mutation — `roots = [SHM_ROOT,
# tempfile.gettempdir()]` reduced to `[tempfile.gettempdir()]` passed this file
# and every other.
#
# What /dev/shm holds is the signer's RAM scratch: gs_sign_*, gs_impout_* and
# .gs_pw_* — the wallet password and unsigned transaction data, kept there
# specifically to stay off a disk. A wipe that silently stopped covering it is
# the whole phase failing quietly.
#
# Safe to point them at DIFFERENT fakes now: SHM_ROOT exists as a patchable
# constant precisely so the real /dev/shm is never scanned. Nothing below
# touches it.
shm2 = sandbox / "shm_only"; shm2.mkdir()
tmp2 = sandbox / "tmp_only"; tmp2.mkdir()
populate(shm2)
populate(tmp2)
para.SHM_ROOT = str(shm2)
para.tempfile.gettempdir = lambda: str(tmp2)
_c2, _f2 = para._wipe_targeted_temp_roots(
    dry=False, uid=os.getuid(), already_done=["/tmp", "/var/tmp"])
for name in OURS:
    check(f"both-roots: {name} cleaned from the SHM root", not (shm2 / name).exists())
    check(f"both-roots: {name} cleaned from the TMPDIR root", not (tmp2 / name).exists())
check("both-roots: ONE call covered both distinct roots (3 + 3 removed)",
      _c2 == 6)
check("both-roots: no failures", _f2 == 0)
for name in THEIRS:
    check(f"both-roots: {name} survives in the SHM root", (shm2 / name).exists())
    check(f"both-roots: {name} survives in the TMPDIR root", (tmp2 / name).exists())

# Non-vacuity: the two roots really are different directories, or this whole
# section would be the aliased case again under a new name.
check("control: the two roots are genuinely different directories",
      os.path.realpath(shm2) != os.path.realpath(tmp2))


# ---------------------------------------------------------------------------
# dry run must delete NOTHING
# ---------------------------------------------------------------------------
dryroot = sandbox / "dry"; dryroot.mkdir()
populate(dryroot)
para.tempfile.gettempdir = lambda: str(dryroot)
count, failed = para._wipe_targeted_temp_roots(
    dry=True, uid=os.getuid(), already_done=["/tmp", "/var/tmp"])
check("dry run reports 3", count == 3)
check("dry run deleted nothing",
      all((dryroot / n).exists() for n in OURS + THEIRS))

# ---------------------------------------------------------------------------
# a root already covered by the blanket sweep must not be walked twice
# (double-counting would overstate the wipe -- the exact defect already fixed
# in wipe_gs_artifacts)
# ---------------------------------------------------------------------------
dupe = sandbox / "dupe"; dupe.mkdir()
populate(dupe)
para.tempfile.gettempdir = lambda: str(dupe)
count, failed = para._wipe_targeted_temp_roots(
    dry=True, uid=os.getuid(), already_done=["/tmp", "/var/tmp", str(dupe)])
check("root already blanket-swept is skipped", count == 0)

# a symlinked duplicate of an already-swept root is also skipped (realpath)
linked = sandbox / "linked"
os.symlink(str(dupe), str(linked))
para.tempfile.gettempdir = lambda: str(linked)
count, failed = para._wipe_targeted_temp_roots(
    dry=True, uid=os.getuid(), already_done=["/tmp", "/var/tmp", str(dupe)])
check("symlink to an already-swept root is skipped", count == 0)

# ---------------------------------------------------------------------------
# a missing root is a clean skip, not a failure
# ---------------------------------------------------------------------------
para.tempfile.gettempdir = lambda: str(sandbox / "does_not_exist")
count, failed = para._wipe_targeted_temp_roots(
    dry=False, uid=os.getuid(), already_done=[])
check("missing root: no failures counted", failed == 0 and count == 0)

# ---------------------------------------------------------------------------
# entries owned by ANOTHER uid are left alone even when the name matches --
# another user could plant /dev/shm/.gs_pw_x and we must not act on it
# ---------------------------------------------------------------------------
foreign = sandbox / "foreign"; foreign.mkdir()
populate(foreign)
para.tempfile.gettempdir = lambda: str(foreign)
count, failed = para._wipe_targeted_temp_roots(
    dry=False, uid=os.getuid() + 4242, already_done=[])
check("entries not owned by this uid are skipped", count == 0)
check("...and left on disk", all((foreign / n).exists() for n in OURS))

para.tempfile.gettempdir = real_gettempdir

# ---------------------------------------------------------------------------
# the CONTRACT that made this a gap: the prefixes must match what the signer
# actually creates. Read the prefixes out of airgap_tx_signer's source rather
# than restating them, so renaming one there fails HERE.
# ---------------------------------------------------------------------------
import ast
signer_src = open(os.path.join(REPO, "airgap_tx_signer")).read()
tree = ast.parse(signer_src)
created = set()
for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue
    fn = node.func
    name = getattr(fn, "attr", None)
    if name not in ("mkdtemp", "mkstemp"):
        continue
    for kw in node.keywords:
        if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
            created.add(kw.value.value)
check("signer's scratch prefixes were found in source", len(created) >= 3)
for pfx in sorted(created):
    check(f"paranoia_mode covers signer prefix {pfx!r}",
          pfx in para.GS_TEMP_PREFIXES)

# and the same prefixes must be wipe-able from cwd/$HOME too, via the glob
# patterns -- /dev/shm coverage must not have quietly replaced that path
for pfx in sorted(created):
    check(f"{pfx!r} also has an artifact glob pattern",
          any(p.startswith(pfx) for p in
              para.GS_ARTIFACT_FILE_PATTERNS + para.GS_ARTIFACT_DIR_PATTERNS))

# ---------------------------------------------------------------------------
# wipe_tmp_files must actually CALL the targeted sweep -- the helper being
# correct is worthless if the phase never reaches it
# ---------------------------------------------------------------------------
called = {}
_real_helper = para._wipe_targeted_temp_roots


def _spy(dry, uid, already_done):
    called["args"] = (dry, uid, list(already_done))
    return (0, 0)


para._wipe_targeted_temp_roots = _spy
# dry=True, so this scans but never deletes; silence its per-entry output so
# the suite's log does not fill with the host's real /tmp listing.
import contextlib, io
with contextlib.redirect_stdout(io.StringIO()):
    para.wipe_tmp_files(dry=True)
para._wipe_targeted_temp_roots = _real_helper
check("wipe_tmp_files calls the targeted sweep", "args" in called)
check("...passing the dry flag through", called.get("args", (None,))[0] is True)
check("...and telling it which roots were already blanket-swept",
      set(called.get("args", (0, 0, []))[2]) == {"/tmp", "/var/tmp"})

# THE SUITE MUST NOT REACH INTO THE HOST'S REAL /dev/shm.
#
# This is the regression guard for a defect in this very file. It patched only
# tempfile.gettempdir while the helper hard-coded "/dev/shm" as its first root,
# so every run scanned the real one -- with dry=False, i.e. it SECURELY DELETED
# whatever matched there. The matching names are a live signer's RAM scratch:
# gs_impout_* (the wallet output-set blob) and .gs_pw_* (the wallet password in
# plaintext). Running the suite beside a real pipeline erased another run's
# working directory, and the comment above claimed the opposite.
#
# Proven both ways before this was added: with the literal restored the decoy
# below is destroyed; with SHM_ROOT patchable it survives.
_decoy = Path("/dev/shm/gs_impout_SUITE_DECOY")
_decoy_ok = None
try:
    _decoy.mkdir(parents=True, exist_ok=True)
    (_decoy / "outputs.bin").write_text("a concurrently running signer's scratch")
    para.SHM_ROOT = str(shm)
    para.tempfile.gettempdir = lambda: str(tmpd)
    para._wipe_targeted_temp_roots(dry=False, uid=os.getuid(),
                                   already_done=["/tmp", "/var/tmp"])
    _decoy_ok = (_decoy / "outputs.bin").exists()
except OSError:
    _decoy_ok = None          # no /dev/shm on this host: skip, never fake
finally:
    _sh0 = __import__("shutil")
    _sh0.rmtree(_decoy, ignore_errors=True)

if _decoy_ok is None:
    print("  skip  /dev/shm is unavailable; real-root isolation not checked")
else:
    check("the sweep does NOT touch the host's real /dev/shm "
          "(a live signer's gs_impout_* scratch survives)", _decoy_ok)

import shutil as _sh
_sh.rmtree(sandbox, ignore_errors=True)

# ==========================================================================
# A FAILED SECURE DELETE IS NEVER SILENT.
#
# secure_delete_file returns True/False, and ELEVEN call sites discarded it
# against ONE that checked. What those sites erase is the most sensitive
# material this toolchain creates:
#
#   * the WALLET SPEND-KEY PASSWORD, written to a 0600 temp file because
#     monero-wallet-cli cannot take a password on argv (/proc/<pid>/cmdline is
#     world-readable) -- four sites in airgap_tx_signer, all in `finally`;
#   * the EXIT PLAN, carrying the operator's --exit-to destination;
#   * per-peel and change-sweep plans, carrying destinations and amounts;
#   * atomic_write's partial temp file, holding the same plaintext it staged.
#
# Every one of those deletions can fail -- read-only or full filesystem, a
# permission change, the O_NOFOLLOW open losing a race -- and every one failed
# SILENTLY. The password file's own comment says it "may live in /dev/shm,
# outside the scratch tree the rmtree below covers, so it would otherwise
# survive the whole run": its survival was understood to matter, and then not
# checked.
#
# .gs_pw_* is already in paranoia_mode's artifact patterns because "it is
# deleted in a finally, but a SIGKILL runs no finally". That covers the
# process dying. It never covered the delete returning False.
# ==========================================================================
print()
import io as _io2, contextlib as _ctx2, tempfile as _tf2

_gsm = load_gs_common() if "load_gs_common" in dir() else None
if _gsm is None:
    _l2 = importlib.machinery.SourceFileLoader(
        "gs_common_wipewarn", os.path.join(REPO, "gs_common.py"))
    _gsm = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(_l2.name, _l2))
    _l2.exec_module(_gsm)

# A directory is a path secure_delete_file REFUSES (non-regular file), so this
# exercises the real failure return rather than a mocked one.
# dir="/tmp" explicitly: this file re-points TMPDIR for its own scenarios
# and the old value may already be gone by the time these run.
_undeletable = _tf2.mkdtemp(prefix="wipefail_", dir="/tmp")
_b2 = _io2.StringIO()
with _ctx2.redirect_stdout(_b2):
    _rc = _gsm.secure_delete_or_warn(_undeletable, "the wallet password")
_out2 = _b2.getvalue()
check("wipe-warn: a failed secure delete returns False", _rc is False)
check("wipe-warn: ...and SAYS SO, rather than returning quietly",
      "Could not securely erase" in _out2)
check("wipe-warn: ...naming WHAT the file holds, which is what tells an "
      "operator whether to care", "the wallet password" in _out2)
check("wipe-warn: ...and the path, so they can go and remove it",
      _undeletable in _out2)
check("wipe-warn: ...and says nothing else will clean it up later",
      "STILL ON DISK" in _out2)

# The chain records that a wipe failed and NOTHING about where -- the path is
# operator-facing only, like every other location in this toolchain.
_chained = []
_saved_il = _gsm.integrity_log
try:
    _gsm.integrity_log = lambda stage, msg, **k: _chained.append((stage, msg))
    with _ctx2.redirect_stdout(_io2.StringIO()):
        _gsm.secure_delete_or_warn(_undeletable, "the wallet password")
finally:
    _gsm.integrity_log = _saved_il
check("wipe-warn: the failure is recorded on the integrity chain",
      any("secure_delete_failed" in m for _s, m in _chained))
check("wipe-warn: ...without the path, and without naming the content",
      all(_undeletable not in m and "password" not in m
          for _s, m in _chained))

# CONTROL: a real file is deleted, silently, returning True.
_fd2, _real = _tf2.mkstemp(prefix="wipeok_", dir="/tmp")
os.write(_fd2, b"secret"); os.close(_fd2)
_b3 = _io2.StringIO()
with _ctx2.redirect_stdout(_b3):
    _rc2 = _gsm.secure_delete_or_warn(_real, "the wallet password")
check("control: a deletable file returns True", _rc2 is True)
check("control: ...is actually gone", not os.path.exists(_real))
check("control: ...and warns about nothing", _b3.getvalue() == "")

_sh.rmtree(_undeletable, ignore_errors=True)

# A FILE THAT WAS NEVER THERE IS NOT A FILE LEFT ON DISK. secure_delete_file
# lstats first and returns False when the path does not exist, which is
# indistinguishable from a wipe that could not run -- and the warning says
# "It is STILL ON DISK". atomic_write_json/atomic_write_text call this from
# `except BaseException` precisely when secure_write_bytes may have failed
# BEFORE creating the temp file, so this is the ordinary case, not an edge.
_missing = os.path.join("/tmp", f"never_written_{os.getpid()}.tmp")
if os.path.exists(_missing):
    os.unlink(_missing)
_chain_m = []
_b4 = _io2.StringIO()
_saved_il2 = _gsm.integrity_log
try:
    _gsm.integrity_log = lambda stage, msg, **k: _chain_m.append((stage, msg))
    with _ctx2.redirect_stdout(_b4):
        _rc3 = _gsm.secure_delete_or_warn(_missing, "the wallet password")
finally:
    _gsm.integrity_log = _saved_il2
check("wipe-warn: a path that never existed reports success", _rc3 is True)
check("wipe-warn: ...and prints no wipe-failure warning",
      "STILL ON DISK" not in _b4.getvalue())
check("wipe-warn: ...and writes no secure_delete_failed to the chain",
      not any("secure_delete_failed" in m for _s, m in _chain_m))

# ...and the real caller does not cry wolf either. Drive atomic_write_json
# into a directory that does not exist: secure_write_bytes cannot create the
# temp file, the BaseException handler runs, and nothing is on disk to warn
# about.
_b5 = _io2.StringIO()
_chain_a = []
_saved_il3 = _gsm.integrity_log
try:
    _gsm.integrity_log = lambda stage, msg, **k: _chain_a.append((stage, msg))
    with _ctx2.redirect_stdout(_b5):
        try:
            _gsm.atomic_write_json({"a": 1},
                                   Path("/tmp/gs_no_such_dir_x9/plan.json"))
        except Exception:
            pass
finally:
    _gsm.integrity_log = _saved_il3
check("wipe-warn: atomic_write_json's failure path does not claim a "
      "nonexistent temp file is still on disk",
      "STILL ON DISK" not in _b5.getvalue())
check("wipe-warn: ...and does not write secure_delete_failed for it",
      not any("secure_delete_failed" in m for _s, m in _chain_a))

# NO CALLER MAY GO BACK TO DISCARDING THE RESULT. An unchecked
# secure_delete_file( in statement position is the defect this replaced.
import re as _re2
for _f2 in ("GhostSpiral", "gs_common.py", "airgap_tx_signer",
            "broadcast_signed_xmr", "thor_swap_preparer",
            "create_receive_wallet"):
    _src2 = open(os.path.join(REPO, _f2)).read()
    _bare = _re2.findall(r"^\s*secure_delete_file\(", _src2, _re2.M)
    check(f"wipe-warn: {_f2} has no bare secure_delete_file() whose result is "
          f"thrown away", not _bare)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAIL:
    print("FAILURES: " + ", ".join(FAILURES))
    sys.exit(1)
print("ALL GREEN")
