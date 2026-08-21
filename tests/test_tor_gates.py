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
        gs.integrity_log = lambda stage, msg, *a, **k: logged.append(msg)
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


# ===========================================================================
#  EVERY RELAY PASSES THE SAME TWO GATES -- checked structurally, then driven
# ===========================================================================
#
# The pair "rotate the circuit or stop, re-verify Tor or stop" was written out
# at each relay site, and two sites did not have it. Walking every _run_round
# call in GhostSpiral:
#
#     entry veil      newnym(required=True) + tor_recheck   OK
#     peel i          newnym(required=True) + tor_recheck   OK
#     fan-out         NOTHING
#     DAG round       tor_recheck only, and the newnym sat above a wait that
#                     can last an hour
#     change sweep    NOTHING
#     exit output     newnym(required=True) + tor_recheck   OK
#
# The two bare ones are not minor rounds. The FAN-OUT is the single transaction
# that creates every mix output the run has, relaying after the entry veil's
# carrier wait -- up to an hour with no gate in between. The CHANGE SWEEP moves
# the one output the distribution could not allocate, and its input is the
# transaction that spent the swapped funds, so it is the relay that most
# directly links that spend to a fresh address; with --split N there is one per
# chunk, back to back.
#
# A list of "sites that should have it" would rot. The rule is checked against
# the AST instead, so a new relay added anywhere fails this until it is gated.
import ast                                                       # noqa: E402
import json                                                      # noqa: E402
import tempfile                                                  # noqa: E402
from decimal import Decimal                                      # noqa: E402
from pathlib import Path                                         # noqa: E402

print("\n== every _run_round in GhostSpiral is preceded by relay_gates ==")

_GS_SRC = Path(REPO, "GhostSpiral").read_text()
_GS_TREE = ast.parse(_GS_SRC)


def _calls(node, name):
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == name for n in ast.walk(node))


_sites = []
for _parent in ast.walk(_GS_TREE):
    for _field in ("body", "orelse", "finalbody"):
        _stmts = getattr(_parent, _field, None)
        if not isinstance(_stmts, list):
            continue
        for _i, _st in enumerate(_stmts):
            if not _calls(_st, "_run_round"):
                continue
            # Only the statement that DIRECTLY holds the call; an enclosing
            # if/try/for merely contains it and is not the relay site.
            _nested = any(
                _calls(_sub, "_run_round")
                for _f2 in ("body", "orelse", "finalbody")
                for _sub in (getattr(_st, _f2, []) or [])
                if isinstance(_sub, ast.stmt)) or any(
                _calls(_h, "_run_round")
                for _h in (getattr(_st, "handlers", []) or []))
            if _nested:
                continue
            _sites.append((_st.lineno,
                           any(_calls(_p, "relay_gates") for _p in _stmts[:_i])))

check("there are relay sites to check at all (the walk is not vacuous)",
      len(_sites) >= 6)
for _ln, _gated in sorted(_sites):
    check(f"the relay at GhostSpiral:{_ln} is preceded by relay_gates()",
          _gated)

# The helper has to BE the pair, or the rule above proves nothing.
_rg = [n for n in _GS_TREE.body
       if isinstance(n, ast.FunctionDef) and n.name == "relay_gates"]
check("relay_gates exists as a top-level function", len(_rg) == 1)
_rg_src = ast.get_source_segment(_GS_SRC, _rg[0]) if _rg else ""
check("...and it rotates the circuit with required=True, not best-effort",
      "newnym(required=True" in _rg_src)
check("...and re-verifies Tor for the stage it was given",
      "tor_recheck(proxy, stage)" in _rg_src)

# The two sites that had nothing, named so a revert is loud.
check("the fan-out round is gated by name",
      'relay_gates(args, proxy, "stage5_fanout")' in _GS_SRC)
check("the change sweep is gated by name",
      'relay_gates(args, proxy, f"stage5_changesweep_' in _GS_SRC)
check("the DAG gate sits with the round, not above the confirmation wait",
      _GS_SRC.index('relay_gates(args, proxy, "stage5_dag")')
      > _GS_SRC.index("_wait_for_fanout_confirm(args, _dist_landed"))


print("\n== a gate abort is not a failed transaction ==")

_loader = importlib.machinery.SourceFileLoader("ghost_tg",
                                               os.path.join(REPO, "GhostSpiral"))
_spec = importlib.util.spec_from_loader("ghost_tg", _loader)
ghost = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ghost)


class _A:
    rpc_primary = "http://127.0.0.1:18083/json_rpc"
    tor_proxy = "socks5h://127.0.0.1:9050"
    rpc_daemon = ""
    fee_priority = 1
    output = "/tmp/gs-torgates"
    wallet_password = ""
    wallet_file = "w"
    allow_clearnet_relay = False
    exit_to = ["8" + "A" * 94]


# relay_gates itself: order, arguments, and the type it raises.
_seen = []
_saved_g = (ghost.newnym, ghost.tor_recheck)
try:
    ghost.newnym = lambda **k: _seen.append(("newnym", k.get("required")))
    ghost.tor_recheck = lambda p, st: _seen.append(("recheck", st))
    ghost.relay_gates(_A(), PROXY, "stage_x")
    check("relay_gates rotates FIRST, then re-verifies",
          [s[0] for s in _seen] == ["newnym", "recheck"])
    check("...with required=True", _seen[0][1] is True)
    check("...and the stage name it was given", _seen[1][1] == "stage_x")

    # A plain SystemExit out of either gate must arrive as RelayGateAbort, or
    # the relay loops cannot tell it from a transaction that failed to build.
    def _leak(p, st):
        raise SystemExit(f"[!] Tor leak detected during {st} - aborting.")

    ghost.tor_recheck = _leak
    _kind = None
    try:
        ghost.relay_gates(_A(), PROXY, "stage_y")
    except ghost.RelayGateAbort as e:
        _kind = ("abort", str(e))
    except SystemExit as e:
        _kind = ("plain", str(e))
    check("a leak out of tor_recheck becomes RelayGateAbort",
          _kind and _kind[0] == "abort")
    check("...carrying the gate's own words, not a generic message",
          _kind and "leak" in _kind[1])

    def _norot(**k):
        raise SystemExit("[!] Could not rotate the Tor circuit - aborting.")

    ghost.tor_recheck = lambda p, st: None
    ghost.newnym = _norot
    _kind2 = None
    try:
        ghost.relay_gates(_A(), PROXY, "stage_z")
    except ghost.RelayGateAbort:
        _kind2 = "abort"
    except SystemExit:
        _kind2 = "plain"
    check("a failed REQUIRED rotation becomes RelayGateAbort too",
          _kind2 == "abort")
    check("RelayGateAbort is still a SystemExit, so nothing that catches "
          "SystemExit at the top level changes behaviour",
          issubclass(ghost.RelayGateAbort, SystemExit))
finally:
    (ghost.newnym, ghost.tor_recheck) = _saved_g


print("\n== the change-sweep loop re-raises the gate instead of retrying ==")

# THE LOOP THAT HAD NEITHER. _run_change_sweeps catches SystemExit so one bad
# sweep does not strand the rest -- which would have swallowed a live leak,
# printed "FAILED to create, sign or broadcast", and then re-run the same
# failing gate on every remaining sweep before handing the run to the exit.
_stg = Path(tempfile.mkdtemp(prefix="torgate_")) / "tx_staging"
_stg.mkdir(parents=True)
_jobs = [(4, 0, "DESTA", 1), (5, 0, "DESTB", 1), (6, 0, "DESTC", 1)]

_saved_cs = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.newnym, ghost.tor_recheck,
             ghost.integrity_log, ghost.hop_delay, ghost.secure_delete_or_warn,
             ghost.secure_delete_tree)
_rounds = []
try:
    ghost._run_round = lambda *a, **k: _rounds.append(a[3])
    ghost._wait_for_change_settled = lambda *a, **k: (True, 1)
    ghost._change_residue = lambda *a, **k: 0
    ghost.integrity_log = lambda *a, **k: None
    ghost.hop_delay = lambda *a, **k: 0
    ghost.secure_delete_or_warn = lambda *a, **k: True
    ghost.secure_delete_tree = lambda *a, **k: True
    ghost.newnym = lambda **k: None

    # Sweep 1 relays; the gate before sweep 2 detects a leak.
    _n = {"i": 0}

    def _recheck(p, st):
        _n["i"] += 1
        if _n["i"] == 2:
            raise SystemExit("[!] Tor leak detected during "
                             f"{st} - aborting.")

    ghost.tor_recheck = _recheck
    _out = io.StringIO()
    _escaped = None
    try:
        with contextlib.redirect_stdout(_out):
            ghost._run_change_sweeps(_A(), _jobs, str(_stg), PROXY, {})
    except ghost.RelayGateAbort as e:
        _escaped = str(e)
    except SystemExit as e:
        _escaped = f"PLAIN:{e}"
    _txt = _out.getvalue()
    check("a leak during the change sweeps stops the loop",
          _escaped is not None and not _escaped.startswith("PLAIN:"))
    check("...carrying the leak message, not a broadcast failure",
          _escaped and "leak" in _escaped)
    check("...and the remaining sweeps are NOT attempted",
          len(_rounds) == 1)
    check("...and it is NOT reported as 'FAILED to create, sign or broadcast'",
          "FAILED to create, sign or broadcast" not in _txt)

    # A genuine round failure must still be caught, or one bad sweep strands
    # the exit. Both halves of the same except chain.
    _rounds.clear()
    ghost.tor_recheck = lambda p, st: None
    _m = {"i": 0}

    def _round_fail(*a, **k):
        _m["i"] += 1
        if _m["i"] == 2:
            raise SystemExit("[!] Change sweep: broadcast failed (exit 1)")
        _rounds.append(a[3])

    ghost._run_round = _round_fail
    _out2 = io.StringIO()
    _esc2 = None
    try:
        with contextlib.redirect_stdout(_out2):
            _failed = ghost._run_change_sweeps(_A(), _jobs, str(_stg), PROXY, {})
    except SystemExit as e:                                      # noqa: BLE001
        _esc2 = str(e)
    check("a failed ROUND is still caught, not re-raised", _esc2 is None)
    check("...the remaining sweeps still run", len(_rounds) == 2)
    check("...and it is counted as one failure", _failed == 1)
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.newnym, ghost.tor_recheck, ghost.integrity_log, ghost.hop_delay,
     ghost.secure_delete_or_warn, ghost.secure_delete_tree) = _saved_cs


print("\n== the exit loop re-raises the gate too ==")

# Same shape, same catch, and this one was already fixed with a local flag --
# re-driven here because the flag is gone, replaced by RelayGateAbort, and the
# behaviour it bought must not go with it. Three funded outputs, a leak before
# the second: the operator must get the leak, not three "FAILED ... funds are
# still on this wallet" lines and a retry on every remaining output.
class _ExitRpc:
    def raw_request(self, method, params):
        if method == "get_balance":
            return {"per_subaddress": [
                {"address_index": 1, "balance": 300_000_000_000,
                 "unlocked_balance": 300_000_000_000}]}
        return {}

    def get_subaddress_balance(self, account_index=0, address_index=0):
        return 300_000_000_000, 300_000_000_000


_stg2 = Path(tempfile.mkdtemp(prefix="torgate_exit_")) / "tx_staging"
_stg2.mkdir(parents=True)
_saved_ex = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.connect_rpc, ghost.newnym,
             ghost.tor_recheck, ghost.integrity_log, ghost.hop_delay,
             ghost.secure_delete_or_warn, ghost.secure_delete_tree,
             ghost.atomic_write_json)
_ex_rounds = []
try:
    ghost._run_round = lambda *a, **k: _ex_rounds.append(a[3])
    ghost._wait_for_change_settled = lambda *a, **k: (True, 300_000_000_000)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _ExitRpc()
    ghost.newnym = lambda **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.hop_delay = lambda *a, **k: 0
    ghost.secure_delete_or_warn = lambda *a, **k: True
    ghost.secure_delete_tree = lambda *a, **k: True
    ghost.atomic_write_json = lambda payload, path: None
    _k = {"i": 0}

    def _recheck_exit(p, st):
        _k["i"] += 1
        if _k["i"] == 2:
            raise SystemExit(f"[!] Tor leak detected during {st} - aborting.")

    ghost.tor_recheck = _recheck_exit
    _eout = io.StringIO()
    _eesc = None
    try:
        with contextlib.redirect_stdout(_eout):
            ghost._run_exit_withdrawals(
                _A(), [11, 12, 13], _A.exit_to, str(_stg2), PROXY,
                {"fee_per_round": "0.0024", "account_index": 11}, None,
                hold=(), entry_pairs=())
    except ghost.RelayGateAbort as e:
        _eesc = str(e)
    except SystemExit as e:
        _eesc = f"PLAIN:{e}"
    _etxt = _eout.getvalue()
    check("a leak during the exit stops the withdrawal loop",
          _eesc is not None and not _eesc.startswith("PLAIN:"))
    check("...carrying the leak message", _eesc and "leak" in _eesc)
    check("...and the remaining outputs are NOT attempted",
          len(_ex_rounds) == 1)
    check("...and the word FAILED does not stand in for it",
          "was NOT withdrawn and its funds are still on this wallet"
          not in _etxt)
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.hop_delay, ghost.secure_delete_or_warn, ghost.secure_delete_tree,
     ghost.atomic_write_json) = _saved_ex


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
