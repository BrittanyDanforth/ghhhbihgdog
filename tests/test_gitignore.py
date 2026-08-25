#!/usr/bin/env python3
"""ENFORCE that .gitignore covers every artifact paranoia_mode wipes.

Why this exists: paranoia_mode.wipe_gs_artifacts lists the files this toolchain
considers sensitive enough to securely delete. Anything on that list is, by
definition, something that must never be committed -- these carry BTC deposit
addresses, ThorChain memos, XMR destinations, txids and per-run traces.

Those two lists had already drifted once: .gitignore matched only the DEFAULT
filenames, so an operator-supplied --outfile (thor_pairs_MYNAME.json) or a
progress file (signer_progress.json) would have been committed by a
`git add -A`. A comment asking the lists to stay in sync did not prevent that
and would not prevent the next one, so this test asks the REAL `git
check-ignore` whether a concrete filename built from each pattern is actually
blocked. It fails loudly the moment a new wipe pattern lands without a
matching ignore rule.
"""
import os, subprocess, sys
import importlib.machinery, importlib.util

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
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


def is_ignored(relpath: str) -> bool:
    """Ask git itself -- not a reimplementation of glob semantics."""
    r = subprocess.run(["git", "check-ignore", "-q", "--no-index", relpath],
                       cwd=REPO, capture_output=True)
    return r.returncode == 0


def concrete(pattern: str) -> str:
    """Turn a wipe glob into a representative real filename.

    'thor_pairs_*.json' -> 'thor_pairs_EXAMPLE.json'  (the operator-renamed
    case that actually leaked), '*.blob' -> 'EXAMPLE.blob'.
    """
    return pattern.replace("*", "EXAMPLE") if "*" in pattern else pattern


# Files that are legitimately TRACKED and so must NOT be gitignored, even
# though paranoia wipes them from an operator's working copy. Each needs a
# reason -- this is an escape hatch, not a dumping ground.
TRACKED_EXCEPTIONS = {
    # A checked-in one-line note that ships with the repo. paranoia wipes it
    # from a live machine, but it is source, not a runtime artifact.
    "renamethis1",
}

print("=== every paranoia wipe pattern must be gitignored ===")
for pat in para.GS_ARTIFACT_FILE_PATTERNS:
    if pat in TRACKED_EXCEPTIONS:
        continue
    name = concrete(pat)
    check(f"gitignore covers file pattern {pat!r} (e.g. {name})", is_ignored(name))

for pat in para.GS_ARTIFACT_DIR_PATTERNS:
    if pat in TRACKED_EXCEPTIONS:
        continue
    name = concrete(pat) + "/"
    check(f"gitignore covers dir pattern {pat!r} (e.g. {name})", is_ignored(name))

# The specific filenames that DID slip through the first, too-narrow ignore
# list. Regression-locked by name so the exact past bug cannot return.
print("=== regression: the exact names the narrow patterns missed ===")
for leaked in [
    "signer_progress.json",          # 'prog*.json' did not match this
    "broadcast_progress.json",       # 'prog*.json' did not match this
    "thor_pairs_myname.json",        # --outfile override; default-only pattern
    "thor_pairs_myname.json.gpg",    # --outfile override, encrypted variant
    "exitplan_myname.json",          # --outfile override; default-only pattern
    "unsigned_batch1.json",          # phase_create bundle, not covered at all
    "integrity.log",                 # paranoia's alternate log name
    "tx_0.blob",                     # broadcast intermediate
    ".ghostspiral.lock",
]:
    check(f"regression: {leaked} stays ignored", is_ignored(leaked))

# Wallet files are NOT on paranoia's list but are the worst thing to publish:
# the .keys file holds the encrypted spend key, which is offline-crackable.
print("=== monero-wallet-cli's own output must not be committable ===")
for w in ["offline.wallet", "offline.wallet.keys", "offline.wallet.address.txt"]:
    check(f"wallet artifact {w} ignored", is_ignored(w))

# Guard the other direction: the wider patterns must not swallow real source.
print("=== ignore rules must NOT shadow tracked source ===")
tracked = subprocess.run(["git", "ls-files"], cwd=REPO,
                         capture_output=True, text=True).stdout.split()
shadowed = [f for f in tracked if is_ignored(f)]
check(f"no tracked file is shadowed by .gitignore (found: {shadowed})", not shadowed)


# ===========================================================================
# NO TRACKED FILE MAY BE ON THE WIPE LIST.
#
# The two lists are kept in lockstep in one direction already: anything worth
# secure-deleting is worth gitignoring. This is the other direction, and it was
# missing. "renamethis1" sat on GS_ARTIFACT_FILE_PATTERNS and is a committed
# file, so a real wipe shredded it and left git reporting a deletion -- the
# wipe tool dirtying the working tree of the repository it lives in, for no
# gain, because a file that is already published is not unpublished by deleting
# the local copy.
import fnmatch as _fn                                        # noqa: E402
import subprocess as _sp2                                    # noqa: E402

_tracked = _sp2.run(["git", "ls-files"], capture_output=True, text=True,
                    cwd=REPO).stdout.split()
check("git ls-files returned something, so this check is not passing "
      "vacuously outside a checkout", len(_tracked) > 10)
_clash = []
for _t in _tracked:
    _base = os.path.basename(_t)
    for _pat in list(para.GS_ARTIFACT_FILE_PATTERNS):
        if _fn.fnmatch(_base, _pat):
            _clash.append(f"{_t} matches wipe pattern {_pat!r}")
    for _pat in list(para.GS_ARTIFACT_DIR_PATTERNS):
        if _fn.fnmatch(_base, _pat):
            _clash.append(f"{_t} matches wipe DIR pattern {_pat!r}")
check("no file tracked by git matches a paranoia_mode wipe pattern"
      + ("" if not _clash else " -- " + "; ".join(_clash[:4])),
      not _clash)

# ===========================================================================
# "WILL THIS BE WIPED?" HAS TWO HALVES AND ONLY ONE WAS BEING ASKED.
#
# The sweep matches on the LOCATION (roots at depth 0 and 1) AND on the file's
# NAME against GS_ARTIFACT_FILE_PATTERNS. Every tool that tells the operator
# "this artifact will be wiped with the rest of the run" was calling
# wipe_covers, which answers the location half only. Measured, with the file in
# a perfectly ordinary place:
#
#     ~/gs/thor_pairs.json   covers=True   name matches   -> erased
#     ~/gs/my_notes.json     covers=True   NO match       -> NEVER erased
#
# and --outfile is free-form, so the second row is one flag away. That file
# holds every BTC deposit address and every memo, and a memo carries the
# destination XMR address in full -- and thor_swap_preparer printed no warning
# for it, because wipe_covers said the directory was fine.
# ===========================================================================
import gs_common as _gsc_w

_H = os.path.expanduser("~")
check("a slip with a swept NAME in a swept place is erased",
      _gsc_w.wipe_will_erase(f"{_H}/gs/thor_pairs.json"))
check("...and so is the batch default the tool actually writes",
      _gsc_w.wipe_will_erase(f"{_H}/gs/thor_pairs_batch.json"))
check("a custom --outfile NAME in the same swept place is NOT erased, and "
      "that is the case wipe_covers could not see",
      _gsc_w.wipe_covers(f"{_H}/gs/my_notes.json")
      and not _gsc_w.wipe_will_erase(f"{_H}/gs/my_notes.json"))
check("a swept name OUTSIDE the roots is still not erased",
      not _gsc_w.wipe_will_erase("/srv/elsewhere/thor_pairs.json"))
check("NON-VACUITY: the two answers really do differ somewhere, or this "
      "helper is wipe_covers with extra steps",
      _gsc_w.wipe_covers(f"{_H}/gs/my_notes.json")
      != _gsc_w.wipe_will_erase(f"{_H}/gs/my_notes.json"))
# THE PATTERNS HAVE ONE OWNER NOW, which is what stops the sweep and the
# prediction drifting apart again.
check("the patterns live in gs_common",
      hasattr(_gsc_w, "GS_ARTIFACT_FILE_PATTERNS")
      and hasattr(_gsc_w, "GS_ARTIFACT_DIR_PATTERNS"))
check("...and paranoia_mode uses the very same objects, not a copy",
      para.GS_ARTIFACT_FILE_PATTERNS is _gsc_w.GS_ARTIFACT_FILE_PATTERNS
      and para.GS_ARTIFACT_DIR_PATTERNS is _gsc_w.GS_ARTIFACT_DIR_PATTERNS)
# THE CALL SITES that make the promise must ask the right question.
for _tool, _needle in (("thor_swap_preparer", "wipe_will_erase(_out)"),
                       ("exit_strategy_simulator", "wipe_will_erase(_out)"),
                       ("create_receive_wallet", "wipe_will_erase(fname)")):
    _src = open(os.path.join(REPO, _tool)).read()
    check(f"{_tool} asks whether the file will actually be ERASED",
          _needle in _src)
    check(f"...and {_tool} no longer asks the location-only question",
          "wipe_covers(" not in _src.replace("# ", ""))

# ===========================================================================
#  THE OTHER DIRECTION, WHICH NOTHING ASKED.
# ===========================================================================
#
# Everything above enforces WIPE-LIST -> .gitignore: "anything on that list is,
# by definition, something that must never be committed". Both lists are
# checked against each other, and a file that is in NEITHER is invisible to
# every check in this file.
#
# That is not hypothetical. gs_wake_status.json -- receive_watch's
# --result-json outcome, written by the wake agent's swap_status job into the
# SAME artifact_dir as gs_wake_state.json, gs_wake_handles.json and
# gs_wake_job.log -- landed in neither list. All three siblings were in both.
# Driven against the real sweep with the four side by side: three "WOULD BE
# ERASED", it "SURVIVES THE WIPE", holding `unlocked` and `total` as exact
# decimals -- the amount that arrived from the swap, to the piconero.
#
# So this asks the missing question: of the filenames the tools actually WRITE,
# is each one erased, or inside a directory that is erased, or exempt for a
# stated reason? A new artifact now lands here as a red check until somebody
# classifies it, which is the point the last one slipped past.
print()
import fnmatch as _fn                                        # noqa: E402
import re as _re                                             # noqa: E402

_TOOLS = ("GhostSpiral", "gs_console", "airgap_tx_signer", "receive_watch",
          "paranoia_mode", "broadcast_signed_xmr", "thor_swap_preparer",
          "create_receive_wallet", "exit_strategy_simulator", "gs_delivery_key",
          "gs_unseal", "gs_doorbell", "gs_wake_agent", "gs_wake_keys",
          "gs_telegram_pager")

#: Artifacts that are NOT matched by name, each with the reason it is allowed.
#: Nothing gets in here without one.
_EXEMPT = {
    # Deliberately never swept: .gitignore says so at length -- "wiping the
    # operator's only delivery key destroys every future slip".
    "gs_delivery.key": "deliberately never wiped; losing it loses every slip",
    # Written as {staging_dir}/bcast_progress.json, and staging_dir is
    # "tx_staging" -- a GS_ARTIFACT_DIR_PATTERNS entry, so the whole tree goes.
    # Matched by DIRECTORY, not by name; that is why the name check misses it.
    "bcast_progress.json": "lives under tx_staging/, erased as a directory",
    # The OPERATOR'S OWN MONERO WALLET, the default for --wallet-file. Written
    # by monero-wallet-cli, not by anything here, and sweeping it would destroy
    # the wallet the whole toolchain exists to spend from -- the same reason
    # gs_delivery.key is exempt, with more at stake.
    "offline.wallet": "the operator's wallet file; this toolchain never writes "
                      "or wipes it",
}

#: Names that match the scan's shape but are not artifacts at all: source files
#: and external binaries this toolchain READS. Separate from _EXEMPT, which
#: means "an artifact we deliberately do not wipe" -- collapsing the two would
#: make the exemption list a place to hide a real artifact.
_NOT_ARTIFACTS = {
    "gs_common.py": "this repo's own source",
    # Named by gs_console's "Compile all" action, which py_compiles every
    # shipped script. Source, like gs_common.py -- the extensionless entry
    # points in that same list do not match this scan's shape at all.
    "gs_wake_proto.py": "this repo's own source, named by the compile action",
    "tumble.py": "JoinMarket's tumbler, named in a comment about a wrong path",
    "tumbler.py": "JoinMarket's tumbler script, an INPUT this tool executes",
    # The placeholder in the console's JoinMarket wallet field. JoinMarket
    # writes and owns it; this toolchain only passes the path through to
    # --joinmarket-wallet, and wiping the operator's tumbler wallet would be
    # the gs_delivery.key mistake with coins in it.
    "wallet.jmdat": "JoinMarket's own wallet, an INPUT named as a form "
                    "placeholder; this toolchain never writes it",
    "tor.exe": "the Tor binary on Windows, a path gs_console searches",
}


def _erased_by_name(name):
    return any(_fn.fnmatch(name, p) for p in _gsc_w.GS_ARTIFACT_FILE_PATTERNS)


# A BLACKLIST, NOT A WHITELIST, and that is the whole repair. This read
#
#     r'"([a-z0-9_]+\.(?:json|log|hex|key))"'
#
# -- an enumeration of the extensions somebody had thought of. accounts_count
# .txt is the toolchain's only .txt artifact, written by airgap_tx_signer one
# line after the outputs_export.hex that IS swept, into the same directory, and
# matched by no wipe pattern. This scan exists so that a new artifact "lands
# here as a red check until somebody classifies it", and instead the .txt was
# INVISIBLE to it: not unaccounted, just never looked at. A whitelist of
# extensions cannot do the job this check is for, because the next artifact
# will have the next extension.
#
# So: any extension, and the two things that shape rules out are ruled out by
# RULE rather than by list. The extension must start with a LETTER, which drops
# every decimal literal ("0.0001", "65432.10") without naming them; and .py/
# .exe names go in _NOT_ARTIFACTS with a reason, the same as any exemption.
_ARTIFACT_LITERAL = _re.compile(r'"([a-z0-9_]+\.[a-z][a-z0-9]{0,5})"')
_seen, _unaccounted = {}, []
for _t in _TOOLS:
    _src = open(os.path.join(REPO, _t)).read()
    # Only literals that look like a written artifact, and only where the file
    # is a NAME rather than a URL path or a doc reference.
    for _m in _ARTIFACT_LITERAL.finditer(_src):
        if _m.group(1) in _NOT_ARTIFACTS:
            continue
        _seen.setdefault(_m.group(1), set()).add(_t)
for _name, _who in sorted(_seen.items()):
    if _erased_by_name(_name) or _name in _EXEMPT:
        continue
    _unaccounted.append((_name, sorted(_who)))
check(f"every artifact filename the tools write is erased by name, erased as "
      f"part of a directory, or exempt with a reason "
      f"(unaccounted: {_unaccounted or 'none'})", not _unaccounted)
# NON-VACUITY: the scan must actually be finding filenames, or "none
# unaccounted" is what an empty scan looks like.
check(f"NON-VACUITY: the scan found artifact filenames to check "
      f"({len(_seen)} of them)", len(_seen) >= 10)
check("NON-VACUITY: ...including the one that was missing, which is now "
      "erased by name", "gs_wake_status.json" in _seen
      and _erased_by_name("gs_wake_status.json"))
# NON-VACUITY: the widened scan must actually SEE the extension the old one
# enumerated past, or this is the same check with longer comments.
check("NON-VACUITY: the scan now sees the .txt artifact the extension "
      "whitelist made invisible", "accounts_count.txt" in _seen)
check("...and accounts_count.txt is erased by name",
      _erased_by_name("accounts_count.txt"))
check("NON-VACUITY: a fabricated artifact name is NOT erased, so "
      "_erased_by_name is not answering True to everything",
      not _erased_by_name("some_new_artifact.txt"))

# ---------------------------------------------------------------------------
# THE NAMES BUILT AT RUNTIME, which the literal scan structurally cannot see.
#
# Half this toolchain's artifacts are f-strings -- f"thor_pairs_{handle}.json",
# f"unsigned_exit_{secure_hex(6)}.json", f"tx_{idx}.signed" -- and a scan over
# string literals walks straight past every one. They are meant to be covered
# by GLOB patterns rather than by exact names, and they are; but "they are" was
# an unverified claim, so the next one added would have been too.
#
# Substituting * for each {...} turns the f-string into the narrowest glob that
# can describe what it produces, which is exactly what the wipe list has to
# match.
_RUNTIME_NAME = _re.compile(
    r'f"([a-z0-9_]*\{[a-z0-9_.\[\]()]+\}[a-z0-9_{}]*\.[a-z][a-z0-9]{0,5})"')
#: f-strings that are a SUFFIX concatenated onto another artifact's stem, not a
#: whole filename. The scan cannot tell the difference from the literal alone,
#: so each one is classified here with the name it actually composes to -- and
#: that composed name is checked against the wipe list below, so this is a
#: statement of shape, not a way out of the check.
_RUNTIME_FRAGMENTS = {
    # GhostSpiral:8339 -- str(peel_file)[:-5] + f"_peel{i}.json", and peel_file
    # is the fanout plan (GhostSpiral:7554, unsigned_fanout_{plan_tag}.json).
    "_peel*.json": "unsigned_fanout_*_peel*.json",
}
_runtime, _runtime_bad = {}, []
for _t in _TOOLS:
    _src = open(os.path.join(REPO, _t)).read()
    for _m in _RUNTIME_NAME.finditer(_src):
        _g = _re.sub(r"\{[^}]*\}", "*", _m.group(1))
        if _g.rsplit(".", 1)[-1] in ("py", "exe"):
            continue                     # source/binaries, per _NOT_ARTIFACTS
        _runtime.setdefault(_RUNTIME_FRAGMENTS.get(_g, _g), set()).add(_t)
# Every classification must still describe something the scan actually found,
# or the dict becomes a place to park a name nobody checks.
check(f"every runtime-name classification still matches a live f-string "
      f"({sorted(set(_RUNTIME_FRAGMENTS.values()) - set(_runtime)) or 'all present'})",
      not (set(_RUNTIME_FRAGMENTS.values()) - set(_runtime)))
for _g, _who in sorted(_runtime.items()):
    # Substitute a concrete token for the * so fnmatch has something to chew.
    if not _erased_by_name(_g.replace("*", "X")):
        _runtime_bad.append((_g, sorted(_who)))
check(f"every artifact name BUILT AT RUNTIME is erased by a glob "
      f"(unaccounted: {_runtime_bad or 'none'})", not _runtime_bad)
check(f"NON-VACUITY: the runtime scan found names to check "
      f"({len(_runtime)} globs)", len(_runtime) >= 5)
check("NON-VACUITY: ...including the peel chain's derived name, which is a "
      "suffix appended to another artifact's stem rather than a literal",
      _erased_by_name("unsigned_fanout_ab12_peel3.json"))
# ...and every exemption must still be a real artifact somebody writes, or the
# list becomes a place to hide things.
check(f"every exemption still corresponds to a filename in the source "
      f"({sorted(set(_EXEMPT) - set(_seen)) or 'all present'})",
      not (set(_EXEMPT) - set(_seen)))
# The four files gs_wake_agent writes into artifact_dir travel together. Naming
# them is what makes the next addition to that directory visible.
for _f in ("gs_wake_state.json", "gs_wake_handles.json", "gs_wake_job.log",
           "gs_wake_status.json"):
    check(f"artifact_dir: {_f} is erased by name", _erased_by_name(_f))
    check(f"artifact_dir: ...and {_f} is git-ignored", is_ignored(_f))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
