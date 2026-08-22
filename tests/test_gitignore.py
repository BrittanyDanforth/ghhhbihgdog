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

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
