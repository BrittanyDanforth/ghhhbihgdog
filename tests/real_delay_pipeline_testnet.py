#!/usr/bin/env python3
"""Does a planned per-TX delay actually survive to the wire? Real binaries.

WHY THIS EXISTS. The pipeline's stated purpose for --hop-delay is to stop the
transactions of one run from forming a timing cluster an analyst can pick out:
hop_delay() jitters a window, _run_exit_withdrawals stamps one on every exit
withdrawal, and broadcast_signed_xmr sleeps it before each submit. The operator
report that prompted this said the exit "didn't even send out nicely to
frustrate analysts" -- and there was NO test anywhere covering the delay's
journey from plan to relay. Not one: grepping the whole suite for
"delays loaded", "delay_source", "no_delays_found" or "minimal gap" returned
nothing.

What coverage did exist made the gap worse rather than smaller.
real_broadcast_testnet hand-writes its unsigned manifest and then patches the
delay into the SIGNED manifest directly:

    entries[0]["delay"] = 6

so it proves broadcast honours a delay that is already sitting in the manifest,
and proves nothing about how it got there. Every link before that -- the plan's
"delay" key, phase_create copying it into unsigned_manifest.json, phase_sign
carrying it across to signed_manifest_v1.json -- was untested. Any one of them
dropping the key degrades silently to "all TXs will broadcast with minimal
gap", which is a warning line in a run that otherwise looks completely normal.

So this drives the REAL chain, end to end, with real monero binaries:

    plan {"delay": N}
      -> shipped phase_create   -> unsigned_manifest.json
      -> shipped phase_sign     -> signed_manifest_v1.json
      -> shipped broadcast main -> the sleep actually taken before submit

TWO transactions with DIFFERENT delays, because one would pass on a build that
hard-codes a single delay or keys them all on position 0, and because the
exit's whole point is that the gaps differ. The RPC and the daemon are real;
only Tor, the sleep and the signal handlers are stubbed.

Requires monerod, monero-wallet-rpc, monero-wallet-cli on PATH. SKIPS (exit 0)
if absent.
"""
import time, os, shutil, tempfile, json, sys, io, contextlib
import importlib.machinery, importlib.util

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH (install monero to run this test)")
        sys.exit(0)

import os as _os, sys as _sys                              # noqa: E402
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
from monerolab import MoneroLab                              # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


airgap = load("airgap_tx_signer")
bcast = load("broadcast_signed_xmr")
ghost = load("GhostSpiral")

BASE = tempfile.mkdtemp(prefix="rd_")
DPORT, WPORT = 30121, 30123
lab = MoneroLab(BASE, DPORT, WPORT)
DR = f"http://127.0.0.1:{DPORT}"
WBASE = f"http://127.0.0.1:{WPORT}"

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL {name}")


dj = lab.dj
draw = lab.draw
wj = lab.wj


def step(s):
    print("\n===", s, "===")


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


# The two planned delays. Distinct, and neither is 0 -- a build that loses the
# key entirely reports 0 for both, and a build that keys on position rather
# than idx swaps them.
D0, D1 = 11, 29

# ---- stub ONLY the anonymity layer and the clock; the RPC stays real -------
slept = []
for _stub in ("verify_tor", "tor_recheck", "newnym", "install_signal_handlers"):
    setattr(bcast, _stub, lambda *a, **k: None)
bcast.check_daemon_relay_egress = lambda *a, **k: {"verdict": "tor",
                                                   "detail": "isolated testnet"}
bcast.shutdown_requested = lambda: False
# secure_delay is what actually serves a planned delay. Record what it is asked
# to wait rather than waiting it -- the point is the NUMBER, not the wall clock.
bcast.secure_delay = lambda s, *a, **k: slept.append(int(s))


def run_broadcast(path, progfile, extra=()):
    sys.argv = ["broadcast_signed_xmr", str(path),
                "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--rpc", WBASE, "--resume", str(progfile),
                "--rebroadcast", "2", *extra]
    try:
        bcast.main(); return 0, ""
    except SystemExit as e:
        return (e.code if isinstance(e.code, int) else 1), str(e.code or "")


result = "INCOMPLETE"
try:
    lab.start()
    step("1. fund a wallet on the isolated testnet")
    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    faddr = wj("get_address", {"account_index": 0})["result"]["address"]
    subs = []
    for i in range(2):
        subs.append(wj("create_address",
                       {"account_index": 0, "label": f"m{i}"})["result"]["address"])
    # TWO FUNDED ACCOUNTS, not two spends from one.
    #
    # The first version of this planned both transactions out of account 0.
    # phase_create builds each one with its own transfer_split call, and a
    # do_not_relay reservation does not survive across calls, so both picked
    # the same fat mining output: TX 0 relayed and the daemon rejected TX 1 as
    # a double spend. That is an artifact of the test's own plan, not of the
    # code under test -- but it would have masked a real relay failure, and a
    # test that cannot tell the two apart is worth nothing here.
    a1 = wj("create_account", {"label": "second"})["result"]
    a1_addr = a1["address"]
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < 80:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")
    # Fund account 1 from account 0 and let it confirm+unlock, so the two
    # planned transactions draw on disjoint outputs.
    wj("transfer", {"destinations": [{"amount": 5 * 10**12, "address": a1_addr}],
                    "account_index": 0, "priority": 1, "get_tx_key": False})
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    _t0 = time.time()
    while time.time() - _t0 < 180:
        time.sleep(3); wj("refresh")
        _b = wj("get_balance", {"account_index": 1})["result"]
        if int(_b.get("unlocked_balance") or 0) >= 4 * 10**12:
            break
    draw("/stop_mining"); wj("refresh")
    check("account 1 is funded and unlocked, so the two TXs cannot collide",
          int(wj("get_balance", {"account_index": 1})["result"].get(
              "unlocked_balance") or 0) >= 4 * 10**12)
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    kimages = wj("export_key_images", {"all": True}).get(
        "result", {}).get("signed_key_images")
    wj("close_wallet")

    step("2. view-only wallet -- what phase_create talks to in production")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view",
                              "address": faddr, "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})
    airgap.verify_tor = lambda *a, **k: None
    airgap.validate_proxy = lambda u: {"http": u, "https": u}

    step("3. hop_delay() actually produces a delay inside the asked window")
    _w = (D0, D1)
    _samples = [ghost.hop_delay(_w) for _ in range(200)]
    check("hop_delay stays inside its window",
          all(D0 <= s < D1 for s in _samples))
    check("hop_delay JITTERS -- a constant would put every TX in one cluster",
          len(set(_samples)) > 3)

    step("4. SHIPPED phase_create -- does the plan's delay reach the manifest?")
    outdir = os.path.join(BASE, "staging")
    os.chdir(BASE)
    plan = [{"src": faddr, "src_index": 0, "account_index": 0,
             "dst": subs[0], "amt": "0.3", "delay": D0},
            {"src": a1_addr, "src_index": 0, "account_index": 1,
             "dst": subs[1], "amt": "0.3", "delay": D1}]
    airgap.phase_create(
        Args(tor_proxy="socks5h://127.0.0.1:9050", rpc=WBASE,
             outdir=outdir, fee_priority=1), plan, {"account_index": 0})
    mani = json.load(open(os.path.join(outdir, "unsigned_manifest.json")))
    ents = sorted(mani.get("entries", []), key=lambda e: e["idx"])
    check("phase_create wrote both entries", len(ents) == 2)
    assert len(ents) == 2
    check("unsigned manifest carries TX 0's planned delay",
          ents[0].get("delay") == D0)
    check("unsigned manifest carries TX 1's DIFFERENT planned delay",
          ents[1].get("delay") == D1)

    step("5. SHIPPED phase_sign -- does it carry the delay across?")
    shim = os.path.join(BASE, "wcli-testnet")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\nexec monero-wallet-cli --offline "$@"\n')
    os.chmod(shim, 0o755)
    airgap.phase_sign(Args(outdir=outdir, wallet_cli=shim,
                           wallet_file=os.path.join(BASE, "w", "full"),
                           wallet_password=""), plan)
    signed_dir = os.path.join(outdir, "signed")
    smf = os.path.join(signed_dir, "signed_manifest_v1.json")
    check("phase_sign wrote a signed manifest", os.path.exists(smf))
    assert os.path.exists(smf)
    sents = sorted(json.load(open(smf)), key=lambda e: e["idx"])
    check("signed manifest still carries TX 0's delay",
          sents[0].get("delay") == D0)
    check("signed manifest still carries TX 1's delay",
          sents[1].get("delay") == D1)

    step("6. SHIPPED broadcast -- is the delay actually served before submit?")
    slept.clear()
    prog = os.path.join(BASE, "prog.json")
    _buf = io.StringIO()
    with contextlib.redirect_stdout(_buf):
        code, msg = run_broadcast(signed_dir, prog)
    btext = _buf.getvalue()
    print(btext[-1500:])
    check("broadcast relayed both transactions", code == 0)
    check("broadcast says its delays came from the MANIFEST",
          "delays loaded from manifest" in btext.lower())
    check("broadcast does NOT fall back to the 'minimal gap' warning",
          "minimal gap" not in btext)
    # [:2], not ==. --rebroadcast makes secure_delay serve retry backoffs too,
    # so the list can carry more than the plan's own delays; what must hold is
    # that the two PLANNED ones were served first and in order.
    check("both planned delays were actually waited, in plan order",
          slept[:2] == [D0, D1])

    step("7. NEGATIVE CONTROL -- strip the delays and the warning must fire")
    # Without this the checks above could pass on a build that always prints
    # the reassuring line. Same blobs, same daemon, delays removed.
    bare = os.path.join(BASE, "bare")
    shutil.copytree(signed_dir, bare)
    _b = json.load(open(os.path.join(bare, "signed_manifest_v1.json")))
    for e in _b:
        e["delay"] = 0
    with open(os.path.join(bare, "signed_manifest_v1.json"), "w") as f:
        json.dump(_b, f)
    slept.clear()
    _buf2 = io.StringIO()
    with contextlib.redirect_stdout(_buf2):
        run_broadcast(bare, os.path.join(BASE, "prog2.json"))
    btext2 = _buf2.getvalue()
    check("control: with no delays the operator IS warned about the cluster",
          "minimal gap" in btext2)
    check("control: ...and no planned delay was served",
          D0 not in slept and D1 not in slept)

    step("8. the exit stamps a delay on EVERY withdrawal, not just the first")
    # _run_exit_withdrawals builds one single-TX plan per output. A delay that
    # only applied between TXs inside one file would never fire for any of
    # them -- so the stamp has to be on each tx dict.
    _d = [ghost.hop_delay((D0, D1)) for _ in range(6)]
    check("every exit withdrawal gets its own nonzero planned delay",
          all(x >= D0 for x in _d))
    _src = open(os.path.join(REPO, "GhostSpiral")).read()
    _exit_fn = _src[_src.index("def _run_exit_withdrawals"):]
    _exit_fn = _exit_fn[:_exit_fn.index("\ndef ")]
    check("the exit's per-output tx carries a delay key",
          '"delay": hop_delay(delay_window)' in _exit_fn)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    try:
        lab.stop()
    except Exception:
        pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed -> {result}")
if FAILURES:
    print("FAILED:", FAILURES)
sys.exit(0 if FAIL == 0 else 1)
