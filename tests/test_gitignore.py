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

# Wallet files are the worst thing to publish: .keys is the encrypted spend
# key (offline-crackable) and .address.txt is PRIMARY in plaintext.
# wallet-cli --generate-from-keys uses *.wallet*; wallet-rpc create_wallet
# "name1" uses name1.keys / name1.address.txt. Both must be ignored.
print("=== monero wallet files must not be committable ===")
for w in ["offline.wallet", "offline.wallet.keys", "offline.wallet.address.txt",
          "name1.keys", "name1.address.txt", "name2.keys", "name2.address.txt"]:
    check(f"wallet artifact {w} ignored", is_ignored(w))

# Guard the other direction: the wider patterns must not swallow real source.
print("=== ignore rules must NOT shadow tracked source ===")
tracked = subprocess.run(["git", "ls-files"], cwd=REPO,
                         capture_output=True, text=True).stdout.split()
shadowed = [f for f in tracked if is_ignored(f)]
check(f"no tracked file is shadowed by .gitignore (found: {shadowed})", not shadowed)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
