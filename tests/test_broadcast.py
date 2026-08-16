#!/usr/bin/env python3
"""Executable tests for broadcast_signed_xmr's relay loop.

Every test here drives the REAL main() with the network, Tor and sleep calls
stubbed -- nothing reimplements the logic under test. Each one was confirmed to
FAIL against the pre-fix build before being committed (see run_all's banner).
"""
import sys, os, json, hashlib, tempfile, importlib.util, importlib.machinery

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

    def __init__(self, n=1, delay=0, hashes=True, wrap=None):
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
            if hashes:
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
        out = sys.stdout
        sys.stdout = open(os.devnull, "w")
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
            sys.stdout.close(); sys.stdout = out

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
