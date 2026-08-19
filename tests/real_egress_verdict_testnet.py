#!/usr/bin/env python3
"""The relay-egress verdicts the console's spend gate branches on, from a REAL
monerod rather than a stub.

WHY THIS CANNOT BE A UNIT TEST. The console's OPSEC preflight decides whether
it will spend, and it branches on the STRING check_daemon_relay_egress returns:
"tor" passes, "clearnet" blocks, "offline" blocks, "unknown" warns-but-permits.
A stubbed gs_common proves the display logic handles those four values; it
proves nothing about whether a real daemon actually produces them. If monerod
reports something else -- or if an --offline daemon is not detected as offline
-- the branches are aimed at values that never occur and the gate is decorative.

That distinction is the exact defect this test exists for: the preflight used
to render "unknown" as a green "Relay egress not clearnet", and "unknown" is
what a freshly started daemon (no peers yet) and any failed probe both return.
Verifying the display without verifying the verdicts would have left half the
claim unchecked.

Isolated regtest daemon. SKIPs (exit 0) if monerod is not installed.
"""
import os
import shutil
import sys
import tempfile

for _b in ("monerod",):
    if shutil.which(_b) is None:
        print(f"SKIP: {_b} not on PATH")
        sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

from monerolab import MoneroLab                              # noqa: E402
import gs_common as gs                                       # noqa: E402

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


BASE = tempfile.mkdtemp(prefix="egressv_")
lab = MoneroLab(BASE, 31810, 31813)
result = "INCOMPLETE"
try:
    lab.start(wallet=False, offline=True)
    url = f"http://127.0.0.1:{lab.dp}"

    v = gs.check_daemon_relay_egress(url, None)
    print(f"  real --offline daemon -> {v['verdict']!r}: {v['detail']}")
    check("a REAL --offline daemon is reported as 'offline' (a broadcast would "
          "go nowhere, so the console blocks the spend)",
          v["verdict"] == "offline")
    check("...and the verdict is one of the four the gate branches on",
          v["verdict"] in ("tor", "clearnet", "offline", "unknown"))

    # An unreachable daemon must be "unknown" -- NOT a silent pass. This is the
    # value the preflight now shows as "Relay egress NOT VERIFIED" rather than
    # as a green tick.
    v2 = gs.check_daemon_relay_egress("http://127.0.0.1:9", None)
    print(f"  unreachable daemon    -> {v2['verdict']!r}: {v2['detail'][:70]}")
    check("an unreachable daemon is 'unknown', never a pass",
          v2["verdict"] == "unknown")
    check("...and it never claims a peer count it did not observe",
          v2["onion"] == 0 and v2["clear"] == 0)

    # A remote daemon with no proxy must refuse to probe rather than open a
    # clearnet connection to answer a diagnostic.
    v3 = gs.check_daemon_relay_egress("http://example.invalid:18081", None)
    check("a REMOTE daemon with no proxy is 'unknown' and says why, rather "
          "than connecting over clearnet to find out",
          v3["verdict"] == "unknown" and "proxy" in v3["detail"].lower())

    # The probe must never raise: the docstring promises a verdict dict, and a
    # raising diagnostic would take down the console's preflight.
    raised = False
    try:
        gs.check_daemon_relay_egress("not-a-url", None)
    except Exception:                                        # noqa: BLE001
        raised = True
    check("a malformed daemon URL yields a verdict rather than raising",
          not raised)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    try:
        lab.stop()
    except Exception:                                        # noqa: BLE001
        pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
print(f">>> RELAY EGRESS VERDICTS AGAINST A REAL DAEMON: {result}")
sys.exit(0 if result == "SUCCESS" else 1)
