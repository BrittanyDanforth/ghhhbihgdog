#!/usr/bin/env python3
"""Executable tests for broadcast_signed_xmr's relay loop.

Every test here drives the REAL main() with the network, Tor and sleep calls
stubbed -- nothing reimplements the logic under test. Each one was confirmed to
FAIL against the pre-fix build before being committed (see run_all's banner).
"""
import sys, os, io, json, hashlib, shutil, tempfile, importlib.util, importlib.machinery

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


class Harness:
    """A staging dir + a stubbed broadcast module, driven through real main()."""

    def __init__(self, n=1, delay=0, hashes=True, wrap=None,
                 no_hash_on=()):
        self.mod = load("broadcast_signed_xmr")
        self.work = tempfile.mkdtemp(prefix="bcast_t_")
        self.dir = os.path.join(self.work, "signed")
        os.makedirs(self.dir)
        self.posts = []          # payloads actually submitted
        self.slept = 0           # seconds of planned delay actually served
        self.on_sleep = None     # hook fired mid-delay (used for TOCTOU test)
        self.shutdown_after = None
        self._sd_calls = 0
        self.egress = lambda: {"verdict": "tor", "detail": "stub"}
        self.responder = lambda payload: {"result": {"tx_hash_list": ["a" * 64]}}

        entries = []
        for i in range(n):
            p = os.path.join(self.dir, f"tx_{i}.signed")
            with open(p, "wb") as f:
                f.write(bytes([i + 1]) * 8)
            e = {"idx": i, "file": p, "delay": delay}
            # no_hash_on names the entries to leave UNHASHED while the rest are
            # hashed. `hashes=False` is all-or-nothing (the legacy format); a
            # MIXED manifest is a different shape entirely and neither manifest
            # writer in airgap_tx_signer can produce one.
            if hashes and i not in no_hash_on:
                e["hash"] = hashlib.sha256(bytes([i + 1]) * 8).hexdigest()
            entries.append(e)
        self.entries = entries
        self.manifest = os.path.join(self.dir, "signed_manifest_v1.json")
        body = entries if wrap is None else {wrap: entries}
        with open(self.manifest, "w") as f:
            json.dump(body, f)

        m = self.mod
        for stub in ("verify_tor", "tor_recheck", "newnym",
                     "secure_delay", "integrity_log", "install_signal_handlers"):
            setattr(m, stub, lambda *a, **k: None)
        m.check_daemon_relay_egress = lambda *a, **k: self.egress()
        m._single_post = self._post
        m.shutdown_requested = self._sd
        m.time.sleep = self._sleep

    def _post(self, url, payload, proxies=None):
        # Recorded only when the node ACCEPTS it, so `posts` means "relayed",
        # not "attempted". A rejected attempt still reaches the responder, so a
        # test asserting `posts == []` still catches a submit that was made.
        res = self.responder(payload)
        self.posts.append(payload)
        return res

    def _sleep(self, n):
        self.slept += n
        if self.on_sleep:
            self.on_sleep()

    def _sd(self):
        self._sd_calls += 1
        if self.shutdown_after is None:
            return False
        return self._sd_calls > self.shutdown_after

    def blob(self, i):
        return os.path.join(self.dir, f"tx_{i}.signed")

    def run(self, path=None, extra=()):
        os.chdir(self.work)
        sys.argv = ["broadcast_signed_xmr", path or self.dir,
                    "--tor-proxy", "socks5h://127.0.0.1:9050",
                    "--rebroadcast", "1", *extra]
        # CAPTURED, NOT DISCARDED. This sent stdout to /dev/null, so no test
        # in this file could assert on what the operator is TOLD -- in a
        # toolchain where the message is frequently the whole protection (the
        # withheld-output explanation, the no-delays warning, the unprovable
        # -identity warning). A check written against `msg` alone silently
        # tests the exit path only, which is how an operator-facing warning
        # can be deleted with every suite still green.
        #
        # `self.out` holds everything printed; the return signature is
        # unchanged so existing checks keep working.
        out = sys.stdout
        buf = io.StringIO()
        sys.stdout = buf
        try:
            self.mod.main()
            return 0, ""
        except SystemExit as e:
            return (e.code if isinstance(e.code, int) else 1), str(e.code or "")
        except Exception as e:
            # An unhandled traceback is a FAILURE, not a pass and not a reason
            # to abort the suite. Reported with a distinct code so a test can
            # tell "refused cleanly" from "crashed".
            return 70, f"CRASH: {type(e).__name__}: {e}"
        finally:
            sys.stdout = out
            self.out = buf.getvalue()

    def progress(self):
        with open(os.path.join(self.work, "broadcast_progress.json")) as f:
            return json.load(f)


# --------------------------------------------------------------------------
# 1. A shutdown during a planned delay must NOT relay the transaction early.
#    Pre-fix: the sleep loop broke out and the TX was submitted immediately --
#    ignoring the operator AND collapsing the anti-correlation delay to zero.
# --------------------------------------------------------------------------
def test_shutdown_during_delay_does_not_relay():
    h = Harness(n=1, delay=3600)
    h.shutdown_after = 1   # False at the loop gate, True once inside the delay
    code, msg = h.run()
    check("shutdown mid-delay relays nothing", h.posts == [])
    check("shutdown mid-delay exits nonzero", code != 0)
    check("shutdown mid-delay is reported to the operator", "stopped by operator" in msg)
    check("shutdown mid-delay leaves the TX unrelayed for resume",
          h.progress()["relayed"] == [] and h.progress()["failed_perm"] == [])


# --------------------------------------------------------------------------
# 2. A blob swapped AFTER the startup hash pass must not be relayed.
#    Pre-fix: hashes were verified once at startup and the bytes were re-read
#    hours later at submit time, so the check could not vouch for what went out.
# --------------------------------------------------------------------------
def test_blob_swapped_during_delay_is_caught():
    h = Harness(n=1, delay=60)

    def swap():
        with open(h.blob(0), "wb") as f:
            f.write(b"ATTACKER" * 8)
    h.on_sleep = swap
    code, msg = h.run()
    check("blob swapped during the delay is never relayed", h.posts == [])
    check("blob swapped during the delay aborts", code != 0)
    check("blob swap is reported as tampering", "manifest was verified" in msg
          or "changed on disk" in msg)


# --------------------------------------------------------------------------
# 3. Relay egress must be verified AFTER the planned delay, immediately before
#    the submit. Pre-fix the check ran at the top of the loop body, before a
#    delay that can be hours long, so a daemon that fell back to clearnet
#    peers during the wait was never noticed and the TX left from the real IP.
# --------------------------------------------------------------------------
def test_egress_rechecked_after_delay_not_before():
    h = Harness(n=1, delay=600)
    seen = {"n": 0}

    def egress():
        seen["n"] += 1
        # Tor-only at startup, clearnet by the time the delay has elapsed.
        return ({"verdict": "tor", "detail": "onion peers"} if seen["n"] == 1
                else {"verdict": "clearnet", "detail": "raw-IP peers"})
    h.egress = egress
    code, msg = h.run(extra=("--rpc-daemon", "http://127.0.0.1:18081"))
    check("egress is re-checked after the delay", seen["n"] >= 2)
    check("clearnet egress during the delay blocks the relay", h.posts == [])
    check("clearnet egress during the delay exits nonzero", code != 0)


# --------------------------------------------------------------------------
# 4. A momentarily-unreadable blob must not invalidate resume.
#    Pre-fix it was dropped from the list, which changed the progress
#    fingerprint, which made --resume abort telling the operator to delete the
#    progress file -- and deleting it re-broadcasts everything already relayed.
# --------------------------------------------------------------------------
def test_absent_blob_does_not_brick_resume():
    h = Harness(n=3)
    budget = {"n": 2}   # the node accepts 2 TXs, then goes down

    def responder(payload):
        if budget["n"] <= 0:
            raise RuntimeError("node down")
        budget["n"] -= 1
        return {"result": {"tx_hash_list": ["a" * 64]}}
    h.responder = responder
    h.run(path=h.manifest)
    check("run 1 relays 2 of 3", len(h.posts) == 2)

    os.rename(h.blob(1), os.path.join(h.work, "hidden"))   # drive hiccup
    budget["n"] = 99
    code, msg = h.run(path=h.manifest)
    check("resume with an absent blob succeeds", code == 0)
    check("resume relays only the outstanding TX", len(h.posts) == 3)
    check("resume never re-broadcasts a relayed TX",
          len([p for p in h.posts if p["params"]["tx_data_hex"] == "0101010101010101"]) == 1)


# --------------------------------------------------------------------------
# 4b. THE BATCH FENCE MUST ACTUALLY TELL TWO BATCHES APART.
#
# load_progress calls the fingerprint "a fingerprint of the blob set: a
# progress file written for a different batch must not be applied to this
# one". It was taken over the blob NAMES only -- and every batch this
# toolchain produces is named tx_0.signed, tx_1.signed, ... So two DIFFERENT
# batches with the same number of transactions fingerprinted IDENTICALLY: the
# second loaded the first's `relayed` set, skipped its own transactions as
# already-sent, and exited 0 reporting success, having broadcast nothing.
#
# The fence now covers each blob's manifest HASH as well as its name. The
# hashes come from the manifest rather than from reading the blobs, so the
# earlier fix -- one momentarily-absent blob must not change the fingerprint --
# still holds.
#
# GhostSpiral never hit this: it passes --resume <staging>/bcast_progress.json,
# a fresh path per round. The exposure is the documented STANDALONE use, where
# progF defaults to ./broadcast_progress.json and is never deleted after a
# successful run.
# --------------------------------------------------------------------------
def test_progress_fence_distinguishes_different_batches():
    # Batch A relays and leaves a progress file behind.
    a = Harness(n=1)
    a.entries[0]  # noqa: B018  (documents that the blob is tx_0.signed)
    code_a, _ = a.run(path=a.manifest)
    check("fence: batch A relays its transaction", code_a == 0 and len(a.posts) == 1)
    prog_a = a.progress()
    check("fence: ...and records it", prog_a.get("relayed"))

    # Batch B: a DIFFERENT transaction under the SAME blob name. The Harness
    # generates identical bytes for a given index, so rewrite B's blob and its
    # recorded hash -- two batches with byte-identical transactions cannot
    # occur in reality and the fence is right to call those the same batch.
    b = Harness(n=1)
    _bp = b.entries[0]["file"]
    with open(_bp, "wb") as _f:
        _f.write(b"FANOUT-TX-DIFFERENT")
    b.entries[0]["hash"] = hashlib.sha256(b"FANOUT-TX-DIFFERENT").hexdigest()
    with open(b.manifest, "w") as _f:
        json.dump(b.entries, _f)
    check("fence: both batches use the same blob name",
          os.path.basename(a.entries[0]["file"])
          == os.path.basename(b.entries[0]["file"]))
    check("fence: ...but carry different transactions",
          a.entries[0]["hash"] != b.entries[0]["hash"])
    # Move A's progress file next to B, which is what happens when an operator
    # broadcasts two batches from one directory without --resume.
    shutil.copy(os.path.join(a.work, "broadcast_progress.json"),
                os.path.join(b.work, "broadcast_progress.json"))
    code_b, msg_b = b.run(path=b.manifest)
    check("fence: batch B does NOT silently skip its own transaction as "
          "already-relayed", not (code_b == 0 and b.posts == []))
    check("fence: ...it refuses, naming the mismatch",
          code_b != 0 and "DIFFERENT set of blobs" in msg_b)
    check("fence: ...and relays nothing while refusing", b.posts == [])


def test_progress_fence_still_resumes_the_same_batch():
    # The fence must not break the thing it exists to enable.
    h = Harness(n=3)
    h.responder = lambda payload: (
        {"error": {"message": "timeout"}}
        if payload["params"]["tx_data_hex"] == "0303030303030303"
        else {"result": {"tx_hash_list": ["a" * 64]}})
    code, _ = h.run(path=h.manifest)
    check("fence control: a partly-failed batch does not report success",
          code != 0)
    sent = len(h.posts)
    h.posts.clear()
    h.responder = lambda payload: {"result": {"tx_hash_list": ["a" * 64]}}
    code2, _ = h.run(path=h.manifest)
    check("fence control: the SAME batch resumes and finishes", code2 == 0)
    check("fence control: ...re-sending only what was outstanding, not all "
          f"{sent}", len(h.posts) == 1)


def test_progress_fence_warns_when_identity_is_unprovable():
    # A legacy manifest records no hashes, so the fence degrades to names and
    # cannot prove identity. Not fatal -- refusing would strand an operator
    # mid-batch -- but never silent, because the failure mode is "reports
    # success, broadcast nothing".
    h = Harness(n=2, hashes=False)
    names = [os.path.basename(e["file"]) if isinstance(e, dict) else os.path.basename(e)
             for e in h.entries]
    fp = hashlib.sha256(
        "|".join(sorted(f"{n}:" for n in names)).encode()).hexdigest()[:32]
    with open(os.path.join(h.work, "broadcast_progress.json"), "w") as f:
        json.dump({"schema": "broadcast_progress_v2", "relayed": [], 
                   "failed_perm": [], "log": [], "blob_fingerprint": fp}, f)
    code, msg = h.run(path=h.manifest)
    # ON STDOUT, which is where the operator reads it -- `msg` is only the
    # exit message and this warning is not fatal.
    check("fence: a hashless manifest WARNS that identity cannot be proven",
          "matched by FILENAME" in h.out)
    check("fence: ...and says what the failure mode is",
          "report success" in h.out and "SKIPPED" in h.out)
    check("fence: ...and it is a warning, not an abort — refusing would strand "
          "an operator mid-batch on a legacy manifest", code == 0)


def test_a_rejected_plan_is_named_not_dropped_in_silence():
    # A plan that MATCHES this batch and is discarded for one unusable delay
    # produced exactly one line: "WARNING: No TX delays found - all TXs will
    # broadcast with minimal gap!" -- which means "there is no plan for these
    # blobs". The operator re-signs, or shrugs and relays with no schedule,
    # which is the timing correlation the delays exist to prevent.
    h = Harness(n=2, hashes=True)
    os.makedirs(os.path.join(h.work, "unsigned"), exist_ok=True)
    with open(os.path.join(h.work, "unsigned", "unsigned_plan.json"), "w") as f:
        json.dump({"txs": [{"delay": 300}, {"delay": "604800"}]}, f)
    h.run(path=h.dir)
    check("plan/reject: a matching plan discarded for a bad delay is NAMED",
          "unsigned_plan.json MATCHES this batch but was discarded" in h.out)
    check("plan/reject: ...and the offending field is quoted, not just counted",
          "'delay' is '604800'" in h.out and "tx[1]" in h.out)
    check("plan/reject: ...and the operator is told this is a corrupt plan "
          "rather than a missing one",
          "corrupt or tampered plan file, not a missing one" in h.out)
    check("plan/reject: ...and the honest 'no delays' warning still stands, "
          "because the relay really is about to run without them",
          "No TX delays found" in h.out)
    # NON-VACUITY (a): a SANE plan is still used, and says nothing about
    # rejection -- or the message above would appear on every run.
    h2 = Harness(n=2, hashes=True)
    os.makedirs(os.path.join(h2.work, "unsigned"), exist_ok=True)
    with open(os.path.join(h2.work, "unsigned", "unsigned_plan.json"), "w") as f:
        json.dump({"txs": [{"delay": 300}, {"delay": 900}]}, f)
    h2.run(path=h2.dir)
    check("plan/reject: NON-VACUITY -- a sane plan is still loaded and no "
          "rejection is reported",
          "TX delays loaded from unsigned_plan" in h2.out
          and "was discarded" not in h2.out)
    # NON-VACUITY (b): with NO plan at all the warning stands alone, so the
    # new lines are attached to a real rejection and not to the warning.
    h3 = Harness(n=2, hashes=True)
    h3.run(path=h3.dir)
    check("plan/reject: NON-VACUITY -- with no plan present the warning is "
          "still alone",
          "No TX delays found" in h3.out and "was discarded" not in h3.out)


def test_manifest_verification_counts_only_what_it_checked():
    # `tampered` only examines entries where i.sha is truthy, and the summary
    # line counted every PRESENT blob. So an entry with no 'hash' key was never
    # hashed -- not here, and not at the authoritative `if item.sha:` re-check
    # before submit -- and was still reported OK.
    #
    # Driven: two entries, the second with its hash stripped, that blob then
    # overwritten with different bytes. Before this, the operator was told
    # "Manifest verification: 2/2 present blobs OK" and it was relayed.
    h = Harness(n=2, no_hash_on=(1,))
    with open(h.blob(1), "wb") as f:
        f.write(b"ATTACKER BLOB -- a different signed transaction")
    code, msg = h.run(path=h.manifest)
    check("manifest: a partially-hashed manifest is REFUSED, not summarised "
          "as OK", code != 0 and "hashes some blobs and not others" in msg)
    check("manifest: ...and it names the entry nothing checked",
          "tx_1.signed" in msg)
    check("manifest: ...and no blob from it is relayed", h.posts == [])
    check("manifest: ...and the operator is never told a count that includes "
          "the unchecked blob", "2/2 present blobs OK" not in h.out)
    # NON-VACUITY (a): the same shape WITHOUT tampering is refused too -- the
    # refusal is about the manifest being unverifiable, not about catching this
    # particular swap, which nothing here could have caught.
    h2 = Harness(n=2, no_hash_on=(1,))
    code2, msg2 = h2.run(path=h2.manifest)
    check("manifest: NON-VACUITY -- an untampered partially-hashed manifest is "
          "refused for the same reason, because the check is unverifiability",
          code2 != 0 and "hashes some blobs and not others" in msg2)
    # NON-VACUITY (b): a fully hashed manifest still passes and still reports.
    h3 = Harness(n=2)
    code3, _ = h3.run(path=h3.manifest)
    check("manifest: NON-VACUITY -- a fully hashed manifest still verifies and "
          "reports the count", code3 == 0
          and "2/2 present blobs OK" in h3.out)
    # NON-VACUITY (c): the ALL-hashless legacy manifest is still ACCEPTED. The
    # refusal above must not have swallowed the case the warning path exists
    # for -- that one is a real older format, this one is not.
    h4 = Harness(n=2, hashes=False)
    code4, msg4 = h4.run(path=h4.manifest)
    check("manifest: NON-VACUITY -- an ALL-hashless legacy manifest is still "
          "accepted, not caught by the partial-hash refusal",
          code4 == 0 and "hashes some blobs and not others" not in msg4)
    # THE COUNT ITSELF, on a manifest where present != checked WITHOUT being
    # partial. Every entry has a hash; one blob is simply not readable yet
    # (the case _items_from_manifest deliberately keeps a slot for), so it is
    # PRESENT-less and unchecked. The summary must count the 1 it hashed, not
    # the 2 entries it holds -- which is the arithmetic the partial-hash
    # refusal above cannot exercise, because it exits first.
    h5 = Harness(n=2, hashes=True)
    os.unlink(h5.blob(1))
    code5, _ = h5.run(path=h5.manifest)
    check("manifest: the summary counts CHECKED blobs, not entries -- an "
          "absent blob is not verified and is not counted as OK",
          "Manifest verification: 1/1 present blobs OK" in h5.out)
    check("manifest: ...and the absent one is reported as absent, not as "
          "verified",
          "1 manifested blob(s) not readable yet" in h5.out)
    check("manifest: NON-VACUITY -- with both blobs present the same manifest "
          "reports 2/2",
          "2/2 present blobs OK" in h3.out)


# --------------------------------------------------------------------------
# 5. Progress must be keyed on the blob name, not the loop position, and an
#    old position-keyed file must migrate rather than re-broadcast.
# --------------------------------------------------------------------------
def test_v1_progress_migrates_without_rebroadcast():
    h = Harness(n=3)
    names = [f"tx_{i}.signed" for i in range(3)]
    legacy_fp = hashlib.sha256("|".join(names).encode()).hexdigest()[:32]
    with open(os.path.join(h.work, "broadcast_progress.json"), "w") as f:
        json.dump({"relayed": [0, 1], "failed_perm": [], "log": [],
                   "blob_fingerprint": legacy_fp}, f)
    code, msg = h.run(path=h.manifest)
    check("v1 progress migrates instead of re-broadcasting", len(h.posts) == 1)
    check("v1 migration relays only the outstanding TX",
          h.posts[0]["params"]["tx_data_hex"] == "0303030303030303")
    check("v1 migration completes the batch", code == 0)
    p = h.progress()
    check("migrated progress is name-keyed", set(p["relayed"]) == set(names))
    check("migrated progress is stamped v2", p.get("schema") == "broadcast_progress_v2")


def test_v1_progress_refuses_when_unmappable():
    h = Harness(n=3)
    with open(os.path.join(h.work, "broadcast_progress.json"), "w") as f:
        json.dump({"relayed": [0, 1], "failed_perm": [], "log": [],
                   "blob_fingerprint": "0" * 32}, f)   # from a different blob set
    code, msg = h.run(path=h.manifest)
    check("unmappable v1 progress relays nothing", h.posts == [])
    check("unmappable v1 progress aborts", code != 0 and "cannot be mapped" in msg)


# --------------------------------------------------------------------------
# 6. A wrapped manifest ({"manifest": [...]}) must load in DIRECTORY mode.
#    Pre-fix, directory mode iterated the dict and crashed with
#    "TypeError: string indices must be integers".
# --------------------------------------------------------------------------
def test_wrapped_manifest_loads_in_directory_mode():
    h = Harness(n=2, wrap="manifest")
    code, msg = h.run()
    check("wrapped manifest does not crash directory mode", not msg.startswith("CRASH"))
    check("wrapped manifest relays its entries", len(h.posts) == 2)


# --------------------------------------------------------------------------
# 7. Every tx hash in a multi-tx signed set must be recorded, not just the
#    first -- otherwise the progress log under-reports what went on-chain.
# --------------------------------------------------------------------------
def test_multi_tx_set_records_every_hash():
    h = Harness(n=1)
    h.responder = lambda p: {"result": {"tx_hash_list": ["a" * 64, "b" * 64]}}
    h.run()
    txid = [e for e in h.progress()["log"] if e.get("sent")][0]["txid"]
    check("both tx hashes recorded", "a" * 64 in txid and "b" * 64 in txid)


# --------------------------------------------------------------------------
# 8. A degenerate retry/timeout budget must be rejected up front rather than
#    silently attempting nothing and reporting failure.
# --------------------------------------------------------------------------
def test_degenerate_budgets_rejected():
    h = Harness(n=1)
    os.chdir(h.work)
    sys.argv = ["b", h.dir, "--tor-proxy", "socks5h://127.0.0.1:9050", "--rebroadcast", "0"]
    out = sys.stdout; sys.stdout = open(os.devnull, "w")
    try:
        h.mod.main(); code = 0
    except SystemExit as e:
        code = e.code
    finally:
        sys.stdout.close(); sys.stdout = out
    check("--rebroadcast 0 is refused", code != 0 and h.posts == [])


# --------------------------------------------------------------------------
# 9. The manifest is the sign->relay trust boundary. A tampered or corrupted
#    field must abort, not be coerced into something plausible.
# --------------------------------------------------------------------------
def _mutate_and_run(mutate):
    h = Harness(n=2)
    ents = json.loads(open(h.manifest).read())
    mutate(ents)
    with open(h.manifest, "w") as f:
        json.dump(ents, f)
    code, msg = h.run()
    return h, code, msg


def test_manifest_field_validation():
    cases = {
        "non-integer idx": lambda e: e[0].__setitem__("idx", 1.5),
        "negative idx": lambda e: e[0].__setitem__("idx", -1),
        "boolean idx": lambda e: e[0].__setitem__("idx", True),
        "truncated hash": lambda e: e[0].__setitem__("hash", "abc"),
        "non-string hash": lambda e: e[0].__setitem__("hash", 12345),
        "negative delay": lambda e: e[0].__setitem__("delay", -5),
        "absurd delay": lambda e: e[0].__setitem__("delay", 10 ** 9),
        "missing file field": lambda e: e[0].pop("file"),
    }
    for label, mut in cases.items():
        h, code, msg = _mutate_and_run(mut)
        check(f"manifest with {label} is refused", code != 0)
        check(f"manifest with {label} is refused CLEANLY (no traceback)",
              not msg.startswith("CRASH"))
        check(f"manifest with {label} relays nothing", h.posts == [])


def test_two_entries_resolving_to_one_file_are_refused():
    h = Harness(n=2)
    ents = json.loads(open(h.manifest).read())
    ents[1]["file"] = ents[0]["file"]      # both now point at tx_0.signed
    with open(h.manifest, "w") as f:
        json.dump(ents, f)
    code, msg = h.run()
    check("ambiguous manifest is refused", code != 0 and h.posts == [])
    check("ambiguous manifest names the collision", "ambiguous" in msg.lower())


def test_missing_manifest_gives_a_clean_error():
    h = Harness(n=1)
    code, msg = h.run(path=os.path.join(h.work, "nope.json"))
    check("missing manifest exits cleanly", code != 0 and "not found" in msg.lower())


def test_egress_gate_says_when_it_is_not_running():
    """The header promises the daemon's relay egress is re-verified before
    EVERY submit. Without --rpc-daemon -- which has no default -- EgressGate
    returns before that check on every submit, and said nothing.

    An operator who read the header has a guarantee they do not have, and the
    one being skipped is the leak-critical one: would this monerod hand this
    transaction to raw-IP peers?
    """
    import io as _io, contextlib as _ctx, types as _t
    c = load("broadcast_signed_xmr")
    c.integrity_log = lambda *a, **k: None
    c.tor_recheck = lambda *a, **k: None
    c.EgressGate._warned_no_daemon = False
    g = c.EgressGate.__new__(c.EgressGate)
    g.proxy = "socks5h://127.0.0.1:9050"
    g.args = _t.SimpleNamespace(rpc_daemon=None)
    g.last_tor_check = 0.0
    buf = _io.StringIO()
    with _ctx.redirect_stdout(buf):
        g.check("submit-1", False)
    out = buf.getvalue()
    check("egress: with no --rpc-daemon the gate SAYS the daemon check is not "
          "running", "NOT checked" in out and "--rpc-daemon" in out)
    check("egress: ...and names what is still running, so the operator can "
          "tell the two checks apart", "Tor exit check" in out)
    buf2 = _io.StringIO()
    with _ctx.redirect_stdout(buf2):
        g.check("submit-2", False)
        g.check("submit-3", False)
    check("egress: ...once per process, not once per transaction -- a warning "
          "on every submit is a warning nobody reads",
          "NOT checked" not in buf2.getvalue())
    check("egress: and the header no longer states the guarantee "
          "unconditionally",
          "AND ONLY THEN" in open(os.path.join(REPO, "broadcast_signed_xmr")).read())


def test_every_retry_submit_is_gated_not_just_the_first():
    """The gate ran ONCE per transaction, above the retry loop.

    A transaction gets --rebroadcast attempts (default 5) across --timeout-min
    minutes (default 30), and every attempt after the first re-submitted on an
    egress sample taken before the first -- across a newnym() and a 5-15 s
    delay, which is exactly when egress state changes. The gate's own docstring
    calls that the "verified, then assumed" pattern it exists to close.
    """
    h = Harness(n=1)
    calls = []
    h.egress = lambda: (calls.append(1) or {"verdict": "tor", "detail": "stub"})
    tries = []

    def _resp(payload):
        tries.append(1)
        if len(tries) < 3:
            return {"error": {"message": "timeout"}}      # transient -> retry
        return {"result": {"tx_hash_list": ["a" * 64]}}

    h.responder = _resp
    code, _out = h.run(extra=("--rebroadcast", "3",
                              "--rpc-daemon", "http://127.0.0.1:18081"))
    check("control: the TX took three submit attempts", len(tries) == 3)
    check("control: and it eventually relayed", code == 0)
    check("the daemon relay-egress check runs before EVERY submit, not only "
          f"the first (got {len(calls)} for {len(tries)} submits)",
          len(calls) >= len(tries))


def test_egress_degrading_between_retries_stops_the_batch():
    """NON-VACUITY for the above: the extra checks must actually be load-bearing.

    If egress goes clearnet while a transaction is being retried, the retry
    must not go out. Before the fix nothing looked again, so it did.
    """
    h = Harness(n=1)
    seq = []

    def _eg():
        seq.append(1)
        # Call 1 is the STARTUP sample, call 2 is the gate before the first
        # submit; both must pass or nothing is ever sent. Degrade from call 3,
        # which is the gate in front of the RETRY -- the submit that used to go
        # out unchecked.
        return ({"verdict": "tor", "detail": "stub"} if len(seq) <= 2
                else {"verdict": "clearnet", "detail": "raw-IP peer"})

    h.egress = _eg
    tries = []

    def _resp(payload):
        tries.append(1)
        return {"error": {"message": "timeout"}}          # always transient

    h.responder = _resp
    code, out = h.run(extra=("--rebroadcast", "3",
                             "--rpc-daemon", "http://127.0.0.1:18081"))
    check("a batch whose egress degrades mid-retry does not keep submitting "
          f"(submits={len(tries)}, expected exactly the first)",
          len(tries) == 1)
    # h.out is the CAPTURED STDOUT; `out` is the SystemExit message. The
    # warning and the exit reason are two different strings in two different
    # places, and the operator sees both.
    check("...and it says so rather than failing quietly",
          "CLEARNET" in h.out.upper())
    check("...and the exit reason names what would have leaked",
          "raw-IP peers" in out)
    check("...and exits non-zero", code != 0)


# --------------------------------------------------------------------------
# A PARTIAL SIGNING RUN MUST NOT RELAY. airgap_tx_signer already refuses one
# ("Only 2/3 TXs signed. Aborting rather than broadcast a partial chain") --
# but it writes signed_manifest_v1.json BEFORE that exit, and nothing here
# looked at completeness at all. So the refusal protected only the operator
# watching the signing terminal: carry signed/ to the online box on a USB
# stick, which is the entire point of an air-gapped signer, and the partial
# chain relayed and was reported as a clean run.
#
# Driven against the REAL phase_sign with a wallet-cli stub that fails on the
# last transaction: manifest on disk = 2 entries for a 3-tx plan, and this
# file then relayed both.
# --------------------------------------------------------------------------
def _rewrite(h, entries):
    with open(h.manifest, "w") as f:
        json.dump(entries, f)


def _with_of(entries, of):
    out = []
    for e in entries:
        e = dict(e)
        e["of"] = of
        out.append(e)
    return out


def test_truncated_manifest_is_refused():
    # A plan of 5 whose LAST transaction failed to sign: idx 0-3, contiguous,
    # byte-identical to a 4-transaction plan that signed perfectly. Only the
    # recorded total can tell them apart.
    h = Harness(n=5)
    _rewrite(h, _with_of(h.entries[:4], 5))
    code, msg = h.run()
    check("partial: a manifest short of its own plan relays NOTHING",
          h.posts == [])
    check("partial: ...and exits non-zero", code != 0)
    check("partial: ...and says how short it is",
          "4 transaction(s)" in msg and "5" in msg)
    check("partial: ...and names the consequence the signer refuses for",
          "strand" in msg.lower())


def test_gapped_manifest_is_refused():
    # TX 2 of 5 failed: idx 0,1,3,4.
    h = Harness(n=5)
    _rewrite(h, _with_of([e for e in h.entries if e["idx"] != 2], 5))
    code, msg = h.run()
    check("partial: a manifest with a HOLE in it relays nothing",
          h.posts == [] and code != 0)


def test_gapped_legacy_manifest_is_refused_without_a_total():
    # A manifest written before "of" existed still cannot hide a hole: the
    # signer numbers a plan 0..n-1, so a missing index is a missing signature.
    h = Harness(n=5)
    _rewrite(h, [e for e in h.entries if e["idx"] != 2])
    code, msg = h.run()
    check("partial: a legacy manifest (no total) with a hole is still refused",
          h.posts == [] and code != 0)
    check("partial: ...and the refusal names the missing transaction",
          "missing transaction" in msg.lower() and "2" in msg)


def test_manifest_from_two_signing_runs_is_refused():
    h = Harness(n=2)
    mixed = [dict(h.entries[0], of=5), dict(h.entries[1], of=3)]
    _rewrite(h, mixed)
    code, msg = h.run()
    check("partial: a manifest that disagrees with itself about the plan size "
          "is refused rather than reconciled",
          h.posts == [] and code != 0
          and "disagrees with itself" in msg)


def test_complete_manifest_still_relays():
    # NON-VACUITY, and the one that matters most: the gate must not refuse a
    # correctly signed batch. A relay guard that fires on good input strands
    # money on the wrong side of an air gap.
    h = Harness(n=5)
    _rewrite(h, _with_of(h.entries, 5))
    code, msg = h.run()
    check("partial: NON-VACUITY -- a COMPLETE manifest relays every "
          f"transaction (relayed {len(h.posts)}/5, code {code})",
          len(h.posts) == 5 and code == 0)


def test_complete_legacy_manifest_still_relays():
    # NON-VACUITY for the legacy shape: an old manifest carries no total, and
    # absence of a total is not evidence of a partial batch.
    h = Harness(n=5)
    _rewrite(h, h.entries)
    code, msg = h.run()
    check("partial: NON-VACUITY -- a COMPLETE legacy manifest (no total) "
          f"still relays every transaction (relayed {len(h.posts)}/5)",
          len(h.posts) == 5 and code == 0)


def test_signer_records_the_total_it_signed_against():
    # The other half of the invariant. A broadcaster that checks a field no
    # signer writes is a check that never fires.
    src = open(os.path.join(REPO, "airgap_tx_signer"), encoding="utf-8").read()
    body = src.split("def phase_sign")[1].split("\ndef ")[0]
    check("partial: phase_sign records the plan's transaction count in every "
          "signed-manifest entry",
          '"of": len(entries)' in body)
    check("partial: ...and still refuses the partial batch itself, so the "
          "guard is on BOTH sides of the sign->relay boundary",
          "signed_count < len(entries)" in body)


# --------------------------------------------------------------------------
# A PROGRESS FILE THAT NAMES NO BLOB SET WAS APPLIED TO ANY BLOB SET.
#
# Both staleness fences read `if saved_fp and saved_fp != ...`, so an absent,
# empty or null blob_fingerprint disabled BOTH, and the `relayed` list was
# applied to whatever batch was in hand. Driven against the shipped main()
# with three unsent transactions and a progress file listing all three:
#
#     missing   -> relayed 0/3, exit 0, silent
#     ""        -> relayed 0/3, exit 0, silent
#     v1 shape  -> relayed 0/3, exit 0, prints "Migrated v1 progress file:
#                  3 relayed, 0 permanently failed."
#
# Money that never leaves, reported as delivered. airgap_tx_signer made the
# identical change for plan_fingerprint one stage earlier.
# --------------------------------------------------------------------------
def _with_progress(h, body):
    with open(os.path.join(h.work, "broadcast_progress.json"), "w") as f:
        json.dump(body, f)
    return ["--resume", os.path.join(h.work, "broadcast_progress.json")]


def test_progress_without_a_blob_fingerprint_is_refused():
    _REL = ["tx_0.signed", "tx_1.signed", "tx_2.signed"]
    for _body, _label in (
            ({"schema": load("broadcast_signed_xmr").PROGRESS_SCHEMA,
              "relayed": _REL, "failed_perm": [], "log": []},
             "the field is missing"),
            ({"schema": load("broadcast_signed_xmr").PROGRESS_SCHEMA,
              "blob_fingerprint": "", "relayed": _REL, "failed_perm": [],
              "log": []}, "the field is an empty string"),
            ({"schema": load("broadcast_signed_xmr").PROGRESS_SCHEMA,
              "blob_fingerprint": None, "relayed": _REL, "failed_perm": [],
              "log": []}, "the field is null"),
            ({"relayed": [0, 1, 2], "failed_perm": [], "log": []},
             "a v1 position-keyed file with no blob set")):
        h = Harness(n=3)
        code, msg = h.run(extra=_with_progress(h, _body))
        check(f"progress: {_label} — the batch is REFUSED, not silently "
              f"skipped", code != 0)
        check(f"progress: {_label} — and nothing was relayed under it",
              h.posts == [])
    # THE MESSAGE HAS TO SAY WHAT WOULD HAVE HAPPENED, because the operator's
    # instinct on a refusal about a progress file is to delete or edit it --
    # which is what produces this state in the first place.
    h = Harness(n=3)
    code, msg = h.run(extra=_with_progress(
        h, {"schema": load("broadcast_signed_xmr").PROGRESS_SCHEMA,
            "relayed": _REL, "failed_perm": [], "log": []}))
    check("progress: the refusal says it would have skipped transactions that "
          "were never sent", "never sent" in msg)
    check("progress: ...and that it would have exited reporting success",
          "reporting success" in msg)
    check("progress: ...and tells them not to add the field by hand",
          "by hand" in msg)


def test_a_real_resume_still_resumes():
    """NON-VACUITY, and the one that matters: this must not brick --resume."""
    h = Harness(n=3)
    code, _ = h.run()
    check("progress: NON-VACUITY -- a fresh run still relays everything",
          len(h.posts) == 3 and code == 0)
    with open(os.path.join(h.work, "broadcast_progress.json")) as f:
        _prog = json.load(f)
    check("progress: ...and records a blob_fingerprint, so the field the "
          "refusal demands is one the tool actually writes",
          isinstance(_prog.get("blob_fingerprint"), str)
          and _prog["blob_fingerprint"])
    # Same blobs, so the same fingerprint; two of three already done.
    h2 = Harness(n=3)
    _p2 = dict(_prog, relayed=_prog["relayed"][:2])
    code2, _ = h2.run(extra=_with_progress(h2, _p2))
    check(f"progress: NON-VACUITY -- a matching resume relays only what is "
          f"left ({len(h2.posts)} of 3) and succeeds",
          len(h2.posts) == 1 and code2 == 0)
    # ...and a WRONG fingerprint is still caught, which was already true.
    h3 = Harness(n=3)
    code3, msg3 = h3.run(extra=_with_progress(
        h3, dict(_prog, blob_fingerprint="deadbeef" * 4)))
    check("progress: NON-VACUITY -- a fingerprint naming another batch is "
          "still refused for its own reason",
          code3 != 0 and h3.posts == [] and "DIFFERENT set of blobs" in msg3)


def run_all():
    for fn in sorted([f for n, f in globals().items() if n.startswith("test_")],
                     key=lambda f: f.__name__):
        fn()
    print(f"\n  broadcast: {PASS} passed, {FAIL} failed")
    if FAILURES:
        for f in FAILURES:
            print(f"    - {f}")
    return FAIL


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
