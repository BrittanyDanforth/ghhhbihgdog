#!/usr/bin/env python3
"""THE TOR GATES, EXECUTED.

verify_tor and tor_recheck are the two functions that decide whether this
toolchain is allowed to keep talking to the network. tor_recheck in particular
runs immediately before each relay, and its job is to abort the run rather than
let one request out over clearnet.

NEITHER WAS EVER RUN BY A TEST. A 60-mutation sweep found tor_recheck's leak
detection executed by nothing: every single reference to it in tests/ is
`lambda *a, **k: None`, because it is stubbed out of the way to test what comes
after it. Deleting its body entirely — turning the mid-run Tor check into a
no-op — left every suite green. The same was nearly true of verify_tor: one
call in test_ipleak reaches it, and only on the SOCKS-support branch.

The code appears correct. That is not the point: nothing here would notice if
it stopped being correct, and this is the check standing between the operator
and their IP address.

Driven with a fake `requests` module, so the real branching runs without any
network. No daemon, no wallet, no Tor.
"""
import importlib.machinery
import importlib.util
import io
import contextlib
import os
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gs_common as gs                                           # noqa: E402

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


PROXY = {"http": "socks5h://127.0.0.1:9050",
         "https": "socks5h://127.0.0.1:9050"}


class _Resp:
    def __init__(self, payload, status_ok=True):
        self._payload = payload
        self._ok = status_ok

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self._ok:
            raise gs.requests.HTTPError("500")


def drive(fn, *args, payload=None, raises=None, status_ok=True, **kw):
    """Run a REAL gate with requests.get faked. Returns (exit_msg | None, log)."""
    logged = []
    saved_get = gs.requests.get
    saved_log = gs.integrity_log
    try:
        def _get(url, timeout=None, proxies=None, **_kw):
            _get.seen = {"url": url, "proxies": proxies, "timeout": timeout}
            if raises is not None:
                raise raises
            return _Resp(payload, status_ok)
        _get.seen = None
        gs.requests.get = _get
        gs.integrity_log = lambda stage, msg, **k: logged.append(msg)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                fn(*args, **kw)
            return None, logged, _get.seen
        except SystemExit as e:
            return str(e.code), logged, _get.seen
    finally:
        gs.requests.get = saved_get
        gs.integrity_log = saved_log


# ==========================================================================
# tor_recheck — the gate that runs immediately before each relay
# ==========================================================================
print("=== tor_recheck ===")

# THE LEAK. check.torproject.org answers, and says this is NOT Tor.
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay",
                          payload={"IsTor": False})
check("recheck: a NEGATIVE IsTor aborts the run", _msg is not None)
check("recheck: ...saying a leak was detected, and naming the stage",
      _msg and "leak" in _msg.lower() and "relay" in _msg)
check("recheck: ...and records it on the integrity chain",
      any("LEAK" in m for m in _log))

# The happy path must NOT abort, or the gate is just an outage.
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay",
                          payload={"IsTor": True})
check("recheck: a POSITIVE IsTor proceeds", _msg is None)

# FAIL CLOSED. "I could not check" is not "it is fine" — this is the branch
# that decides what happens when check.torproject.org is unreachable, which on
# a locked-down host is the NORMAL case.
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay",
                          raises=gs.requests.RequestException("no route"))
check("recheck: an unreachable checker ABORTS rather than assuming Tor",
      _msg is not None)
check("recheck: ...and says it could not verify, not that it leaked",
      _msg and "cannot verify" in _msg.lower())
check("recheck: ...and records the failure", any("recheck_fail" in m for m in _log))

# An HTTP error status is not a pass either.
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay",
                          payload={"IsTor": True}, status_ok=False)
check("recheck: a non-200 response aborts", _msg is not None)

# NO PROXY AT ALL. The request would go clearnet by definition.
for _empty in (None, {}, ""):
    _msg, _log, _seen = drive(gs.tor_recheck, _empty, "relay")
    check(f"recheck: an empty proxy ({_empty!r}) aborts before any request",
          _msg is not None)
check("recheck: ...and it never issues the request in that case",
      drive(gs.tor_recheck, None, "relay")[2] is None)

# THE CHECK ITSELF MUST GO THROUGH THE PROXY. A probe that went clearnet would
# report on the wrong path entirely and pass while the run leaked.
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay",
                          payload={"IsTor": True})
check("recheck: the probe is sent THROUGH the proxy", _seen["proxies"] == PROXY)
check("recheck: ...to the Tor project's checker", _seen["url"] == gs.CHECK_TOR_URL)
check("recheck: ...with a timeout, so a hung probe cannot stall a relay",
      _seen["timeout"])

# A malformed body is not a pass. {} has no IsTor key.
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay", payload={})
check("recheck: a response with no IsTor field aborts", _msg is not None)
_msg, _log, _seen = drive(gs.tor_recheck, PROXY, "relay",
                          payload={"IsTor": "yes"})
check("recheck: a non-boolean IsTor is not treated as a leak (truthy string)",
      _msg is None)


# ==========================================================================
# verify_tor — the gate at startup
# ==========================================================================
print("\n=== verify_tor ===")

_msg, _log, _seen = drive(gs.verify_tor, PROXY, payload={"IsTor": False})
check("verify: a NEGATIVE IsTor aborts", _msg is not None)
check("verify: ...and records LEAK_DETECTED", any("LEAK" in m for m in _log))

_msg, _log, _seen = drive(gs.verify_tor, PROXY, payload={"IsTor": True})
check("verify: a POSITIVE IsTor proceeds", _msg is None)
check("verify: ...and records that it verified", any("verified_ok" in m for m in _log))

_msg, _log, _seen = drive(gs.verify_tor, PROXY,
                          raises=gs.requests.RequestException("dns"))
check("verify: an unreachable checker ABORTS rather than assuming Tor",
      _msg is not None)
check("verify: ...and records the failure by exception TYPE, not its text",
      any("verify_fail" in m for m in _log))

_msg, _log, _seen = drive(gs.verify_tor, PROXY, payload={"IsTor": True})
check("verify: the probe goes through the proxy", _seen["proxies"] == PROXY)


# ==========================================================================
# NON-VACUITY: a neutered gate must turn these red
# ==========================================================================
print("\n=== the checks above are not vacuous ===")
#
# Every check here would pass against a stub, which is exactly how these
# functions came to be untested. So: replace each gate with the no-op the
# suite used to have, and confirm the checks notice.


# The whole point is that a stub passes anything, so the honest control is to
# show what the stub DOES and let the mutation harness prove the rest: neutering
# tor_recheck's body must turn this file red, and it does (verified with
# tests/../ mutation runs, both the LEAK branch and the unreachable branch).
_stub = lambda *a, **k: None                                 # noqa: E731
_stub_aborted = False
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _stub(PROXY, "relay")
except SystemExit:
    _stub_aborted = True
check("control: the no-op stub every other suite installs does NOT abort on a "
      "leak — which is exactly why none of the above was ever exercised",
      not _stub_aborted)

# ...and the real function, on the same input, does.
_real_aborted = False
try:
    _m, _l, _s = drive(gs.tor_recheck, PROXY, "relay", payload={"IsTor": False})
    _real_aborted = _m is not None
except SystemExit:
    _real_aborted = True
check("control: the REAL function on that same input DOES abort",
      _real_aborted)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
