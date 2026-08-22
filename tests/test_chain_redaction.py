#!/usr/bin/env python3
"""THE PERSISTENT INTEGRITY CHAIN MUST NOT MAP THE RUN.

integrity_chain.log survives the run. paranoia_mode calls it "the exact
forensic artifact this phase exists to destroy" -- but it is destroyed only if
the operator gets to run paranoia_mode, and OPSEC_SETUP.md's accepted worst
case is a machine seized while the work is on it.

This toolchain states the rule in three places and, before this suite, obeyed
it in one:

  * create_subs stopped labelling subaddresses, because labels live in the
    wallet file and hand an adversary "which outputs are decoys, which are real
    mix targets, which are peel carriers AND IN WHAT ORDER, which is the change
    sweep, and -- via 'GhostSpiral_entry' -- the name of the tool".
  * report_holdings prints the run's account grouping and tells the operator
    "Not written to disk: a file naming this run's accounts would hand anyone
    who reads the machine the grouping". It logs a count, no numbers.
  * paranoia_mode's mac_spoof already established the remedy after the spoofed
    MAC was found in the chain: "The log now records only THAT a spoof
    happened; the MAC itself is printed to the terminal for the operator and
    never stored."

The chain then recorded, for an ordinary run: ENTRY's account and subaddress,
every change-sweep account, every peel carrier index in order, the fan-out's
destination COUNT (the on-chain search key build_entry_veil exists to hide),
and one `withdrawn:<acct>/<sub>` line per withdrawn output -- so the grouping,
the roles, the order AND the output count were all on disk, more completely
than the labels that were removed for saying less.

Two properties are checked here, and the second is the one a redactor alone
does not give you:

  1. NO PAYLOAD CARRIES A NUMBER. Not "no account number" -- no number. It is
     one line to check and a call site written the obvious way cannot defeat it.
  2. NO PAYLOAD COUNT CARRIES A NUMBER EITHER. Eleven redacted `withdrawn:#/#`
     lines still count to eleven, so the loops that visit every output of the
     run must not write one line each.

Pure functions and driven fakes: no daemon, no wallet, no network.
"""
import ast
import collections
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import os
import re
import secrets as _secretsmod
import subprocess
import sys
import tempfile
import types
from decimal import Decimal
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

import gs_common as gsc                                          # noqa: E402

_ld = importlib.machinery.SourceFileLoader("GhostSpiral",
                                           os.path.join(REPO, "GhostSpiral"))
ghost = importlib.util.module_from_spec(
    importlib.util.spec_from_loader(_ld.name, _ld))
_ld.exec_module(ghost)

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


DIGIT = re.compile(r"\d")
_rand = _secretsmod.SystemRandom()


def payloads(log_path):
    """The msg field of every chain line -- what an analyst actually reads."""
    out = []
    for line in Path(log_path).read_text().splitlines():
        if " | " not in line:
            continue
        _h, rest = line.split(" | ", 1)
        out.append(rest.split("|", 3)[3])
    return out


# ==========================================================================
# 1. chain_safe, as a pure function
# ==========================================================================
print("=== the redactor ===")

# The exact payloads the shipped tools build, taken from their format strings.
REAL = [
    "spend_source_ok:acct=3:idx=1",
    "withdrawn:4/1", "withdraw_failed:12/0", "withdraw_unsettled:11/1",
    "fanout_plan:1_tx:9_dests", "dag_plan:9_hops", "peel_plan:6_peels",
    "btc_split:4_chunks", "holdings:11_accounts", "carrier_ready:idx=7",
    "withdraw_start:11_outputs:2_dests", "withdraw_done:11_of_11:failed=0",
    "peel_chain_done:6_of_6", "change_sweeps:5_of_6",
    "change_swept_into_mix:12", "accounts_count:19", "relayed:idx=3:n=2",
    "fanout_confirmed:9_targets", "exit_destinations_validated:2",
    "quote_ready:2", "rpc_sync_ok:height~2870115", "using_account_index:4",
]
check("no real payload survives redaction with a digit in it",
      not any(DIGIT.search(gsc.chain_safe(p)) for p in REAL))

# THE ADDRESS FRAGMENT, which digit-stripping does not cover and which is the
# worst thing on the chain. scrub_address keeps 8 leading and 8 trailing base58
# characters and callers hand that to integrity_log because its docstring calls
# it the safe form -- safe for a terminal. On disk it is a JOIN KEY: ENTRY is
# the address the ThorChain memo carries verbatim in a public Bitcoin
# OP_RETURN, so 16 base58 characters (~94 bits) tie a seized disk to the public
# BTC chain. Removing only the digits leaves 14 of them, still unique.
_ADDR = "4AdUndZSHcJ1nUAWkMHNTZLQmqCLpEJXqUq5bpvHzXvMhSmSbxJ9kQjMdKr"
_FRAG = gsc.scrub_address(_ADDR)
check("control: scrub_address really does emit an address fragment",
      "..." in _FRAG and len(_FRAG.replace(".", "")) >= 12)
check("an address fragment is removed WHOLE, not just its digits",
      gsc.chain_safe(f"receive_mode:entry={_FRAG}")
      == "receive_mode:entry=<addr>")
check("...and no piece of the address survives anywhere in the payload",
      not any(part and part in gsc.chain_safe(f"x:{_FRAG}")
              for part in _FRAG.split("...")))
for _p in (f"watch_start:{_FRAG}:idx=3", f"dest_from_bundle:{_FRAG}",
           f"created:{_FRAG}:label=False"):
    check(f"...at every site that logs one ({_p.split(':')[0]})",
          "..." not in gsc.chain_safe(_p)
          and "<addr>" in gsc.chain_safe(_p))
check("the surrounding event name is untouched",
      gsc.chain_safe(f"created:{_FRAG}:label=False")
      == "created:<addr>:label=False")

# Non-vacuity: those payloads really do carry the run's structure before
# redaction, or the check above would pass on an empty corpus.
check("control: the same payloads DO carry digits before redaction",
      all(DIGIT.search(p) for p in REAL))

check("the account/subaddress pair is gone, not just narrowed",
      gsc.chain_safe("withdrawn:4/1") == "withdrawn:#/#")
check("the fan-out's destination count is gone (it is the on-chain search key)",
      gsc.chain_safe("fanout_plan:1_tx:9_dests") == "fanout_plan:#_tx:#_dests")

# A run of digits collapses to ONE '#'. One '#' per digit would leak the
# magnitude, and "between 10 and 99 outputs" is most of the answer.
check("a digit RUN collapses to a single '#', so the width leaks no magnitude",
      gsc.chain_safe("holdings:7_accounts")
      == gsc.chain_safe("holdings:4096_accounts"))

# Total and pure: a logging call must never be the thing that aborts a run.
check("it never raises, whatever it is handed",
      all(isinstance(gsc.chain_safe(x), str)
          for x in ("", None, 12345, b"bytes", object(), "\x00\xff")))


# ==========================================================================
# 2. the invariant, through the REAL integrity_log
# ==========================================================================
print("\n=== the chain the tools actually write ===")

_d = Path(tempfile.mkdtemp(prefix="gs_chain_redact_"))
_log = _d / "integrity_chain.log"
for p in REAL:
    gsc.integrity_log("stage4", p, log_path=_log)

_pays = payloads(_log)
check("every line integrity_log wrote is digit-free",
      _pays and not any(DIGIT.search(p) for p in _pays))
check("...and the event name itself is preserved, so the chain still says "
      "what happened",
      any(p.startswith("withdrawn:") for p in _pays)
      and any(p.startswith("fanout_plan:") for p in _pays))

# Redaction happens BEFORE hashing, so tamper-evidence is unaffected -- the
# chain's only actual job.
_ok, _bad, _why = gsc.verify_integrity_chain(_log)
check("the redacted chain still verifies end to end", _ok and _bad is None)

# The edit is made blind to the payload's content and then ASSERTED to have
# changed the line. Spelling out a substring to replace is how the equivalent
# check in test_units came to pass a chain it had not actually tampered with:
# redaction had turned "event2" into "event#", so .replace() matched nothing.
_ls = _log.read_text().splitlines()
_h, _rest = _ls[3].split(" | ", 1)
_tampered = _h + " | " + _rest[:-1] + ("Z" if not _rest.endswith("Z") else "Y")
assert _tampered != _ls[3], "the tamper edit must actually change the line"
_ls[3] = _tampered
_log.write_text("\n".join(_ls) + "\n")
_ok2, _bad2, _why2 = gsc.verify_integrity_chain(_log)
check("...and an EDITED line is still caught, at the right line number",
      (not _ok2) and _bad2 == 4)


# ==========================================================================
# 3. THE COUNT. A redactor alone does not fix this.
# ==========================================================================
print("\n=== the chain's LINE COUNT must not count the run's outputs ===")


class _BalRPC:
    """per_subaddress balances, the shape wallet-rpc really returns."""

    def __init__(self, table):
        self.table = table

    def raw_request(self, method, params=None):
        if method != "get_balance":
            return {}
        subs = self.table.get((params or {}).get("account_index"), {})
        return {"per_subaddress": [{"address_index": i, "balance": b}
                                   for i, b in subs.items()]}


A1 = "4" + "A" * 94


def _exit_chain_lines(n_outputs):
    """Run the REAL exit over n_outputs and count the chain lines it wrote."""
    d = Path(tempfile.mkdtemp(prefix="gs_exit_chain_"))
    log = d / "integrity_chain.log"
    table = {a: {1: 3_000_000_000_000} for a in range(3, 3 + n_outputs)}
    saved = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.connect_rpc, ghost.newnym,
             ghost.tor_recheck, ghost.secure_delay, ghost.integrity_log)
    try:
        ghost._run_round = lambda *a, **k: 1
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: 0
        ghost.connect_rpc = lambda *a, **k: _BalRPC(table)
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        # The REAL logger, pointed at a scratch chain -- not a stub. A stub
        # here would test the stub, which is how two earlier checks in this
        # repo came to prove nothing.
        ghost.integrity_log = lambda stage, msg: gsc.integrity_log(
            stage, msg, log_path=log)
        args = types.SimpleNamespace(
            # The exit and change-sweep plans are written to args.output now,
            # not to Path(staging_dir).parent (the shell's cwd). A real args
            # namespace always has this; these fixtures stood in for one.
            output=tempfile.mkdtemp(prefix="exit_out_"),
            rpc_primary="http://127.0.0.1:18083", tor_proxy=None,
            rpc_daemon="http://127.0.0.1:18081", wallet_file="w",
            wallet_password="", fee_priority=1, allow_clearnet_relay=False,
            exit_to=[A1])
        stg = os.path.join(tempfile.mkdtemp(prefix="exit_stg_"), "tx_staging")
        os.makedirs(stg, exist_ok=True)
        with contextlib.redirect_stdout(io.StringIO()):
            relayed, _f, _s, _held, _u = ghost._run_exit_withdrawals(
                args, list(range(3, 3 + n_outputs)), [A1], stg, None, {}, (0, 0))
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.connect_rpc, ghost.newnym,
         ghost.tor_recheck, ghost.secure_delay, ghost.integrity_log) = saved
    return relayed, (payloads(log) if log.exists() else [])


_r3, _p3 = _exit_chain_lines(3)
_r11, _p11 = _exit_chain_lines(11)

check("control: the exit really did withdraw every output (3 and 11)",
      _r3 == 3 and _r11 == 11)
check("the exit writes the SAME number of chain lines for 3 outputs as for 11",
      len(_p3) == len(_p11))
check("...so counting the chain's lines does not count the run's outputs",
      len(_p11) < 11)
check("...and no line names an account or subaddress",
      not any(DIGIT.search(p) for p in _p11))
check("the chain still records that the exit ran and how it went",
      any(p.startswith("withdraw_done:") for p in _p11)
      and "emptied" in " ".join(_p11))

# The outcome KIND still reaches the chain -- redaction must not turn a
# partial exit into a clean one.
def _exit_with_residual():
    d = Path(tempfile.mkdtemp(prefix="gs_exit_res_"))
    log = d / "integrity_chain.log"
    saved = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.connect_rpc, ghost.newnym,
             ghost.tor_recheck, ghost.secure_delay, ghost.integrity_log)
    try:
        ghost._run_round = lambda *a, **k: 1
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: 5_000_000        # left behind
        ghost.connect_rpc = lambda *a, **k: _BalRPC(
            {3: {1: 3_000_000_000_000}, 4: {1: 2_000_000_000_000}})
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost.integrity_log = lambda stage, msg: gsc.integrity_log(
            stage, msg, log_path=log)
        args = types.SimpleNamespace(
            # The exit and change-sweep plans are written to args.output now,
            # not to Path(staging_dir).parent (the shell's cwd). A real args
            # namespace always has this; these fixtures stood in for one.
            output=tempfile.mkdtemp(prefix="exit_out_"),
            rpc_primary="x", tor_proxy=None, rpc_daemon="y", wallet_file="w",
            wallet_password="", fee_priority=1, allow_clearnet_relay=False,
            exit_to=[A1])
        stg = os.path.join(tempfile.mkdtemp(prefix="exit_stg2_"), "tx_staging")
        os.makedirs(stg, exist_ok=True)
        with contextlib.redirect_stdout(io.StringIO()):
            ghost._run_exit_withdrawals(args, [3, 4], [A1], stg, None, {}, (0, 0))
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.connect_rpc, ghost.newnym,
         ghost.tor_recheck, ghost.secure_delay, ghost.integrity_log) = saved
    return payloads(log) if log.exists() else []


_res = _exit_with_residual()
check("a residual exit is still visible in the chain (redaction is not "
      "silence)", any("residual" in p for p in _res))


# ==========================================================================
# 4. the same, for the change sweeps -- one call per peel hop
# ==========================================================================
print("\n=== change sweeps: one line per run, not one per hop ===")


def _sweep_chain_lines(n_jobs):
    """Drive the REAL _run_change_sweep, n_jobs times, through the real caller.

    NOT a stub in place of _run_change_sweep. An earlier version of this check
    faked the per-hop function and asserted on the caller's aggregate line
    only -- so reintroducing the per-hop `change_swept_into_mix:<account>` log
    left the suite green, which mutation testing caught and which is the exact
    "tested my own stub" failure this repo's audit kept finding. Only the
    process-spawning parts are stubbed; every integrity_log call on the path
    is the real one.
    """
    d = Path(tempfile.mkdtemp(prefix="gs_sweep_chain_"))
    log = d / "integrity_chain.log"
    stg = os.path.join(tempfile.mkdtemp(prefix="sweep_stg_"), "tx_staging")
    os.makedirs(stg, exist_ok=True)
    seen = []
    saved = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.integrity_log,
             ghost.newnym, ghost.tor_recheck)
    try:
        def _round(args, path, stage, label):
            seen.append(label)
            return 1
        ghost._run_round = _round
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: 0
        # The change sweep passes the same relay gates as every other round
        # now; offline they would abort on the missing Tor control socket.
        # tests/test_tor_gates.py drives the gates themselves.
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.integrity_log = lambda stage, msg: gsc.integrity_log(
            stage, msg, log_path=log)
        args = types.SimpleNamespace(
            # The exit and change-sweep plans are written to args.output now,
            # not to Path(staging_dir).parent (the shell's cwd). A real args
            # namespace always has this; these fixtures stood in for one.
            output=tempfile.mkdtemp(prefix="exit_out_"),
            rpc_primary="x", tor_proxy=None, rpc_daemon="y", wallet_file="w",
            wallet_password="", fee_priority=1, allow_clearnet_relay=False)
        jobs = [(a, 0, f"DST{a}", a * 10) for a in range(5, 5 + n_jobs)]
        with contextlib.redirect_stdout(io.StringIO()):
            ghost._run_change_sweeps(args, jobs, stg, None, {})
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.integrity_log,
         ghost.newnym, ghost.tor_recheck) = saved
    return seen, (payloads(log) if log.exists() else [])


_s2, _c2 = _sweep_chain_lines(2)
_s8, _c8 = _sweep_chain_lines(8)
check("control: every change location really was swept (2 and 8)",
      len(_s2) == 2 and len(_s8) == 8)
check("the change sweeps write the same number of chain lines for 2 hops "
      "as for 8", len(_c2) == len(_c8))
check("...so the chain does not count the peel chain's hops",
      len(_c8) < 8 and not any(DIGIT.search(p) for p in _c8))
check("...while still recording that the sweeps happened",
      any("change_sweeps:" in p for p in _c8))



# ==========================================================================
# 5. the rounds themselves -- the leak that survives everything above
# ==========================================================================
print("\n=== rounds: one line per KIND of round, not one per round ===")
#
# _run_round drives every peel, every change sweep and every exit withdrawal,
# and each success wrote create/sign/broadcast lines carrying its label. Taking
# the digits out of "Exit 7/11" gives "exit #/#" -- and an analyst who counts
# the `broadcast_ok:exit` lines has the number of outputs the run holds anyway,
# which is precisely what removing the per-output lines from the exit was for.
# Cardinality survives redaction wherever a loop writes a line per turn.


def _round_chain_lines(role, n_rounds):
    d = Path(tempfile.mkdtemp(prefix="gs_round_chain_"))
    log = d / "integrity_chain.log"
    saved = (ghost.subprocess, ghost.integrity_log,
             set(ghost._ROUND_EVENTS_LOGGED))
    try:
        class _OK:
            @staticmethod
            def run(*a, **k):
                return types.SimpleNamespace(returncode=0)
            TimeoutExpired = Exception
            CalledProcessError = Exception
        ghost.subprocess = _OK
        ghost.integrity_log = lambda stage, msg: gsc.integrity_log(
            stage, msg, log_path=log)
        ghost._ROUND_EVENTS_LOGGED.clear()
        args = types.SimpleNamespace(
            # The exit and change-sweep plans are written to args.output now,
            # not to Path(staging_dir).parent (the shell's cwd). A real args
            # namespace always has this; these fixtures stood in for one.
            output=tempfile.mkdtemp(prefix="exit_out_"),
            rpc_primary="x", tor_proxy="socks5h://127.0.0.1:9050",
            rpc_daemon="y", wallet_file="w", wallet_password="",
            fee_priority=1, allow_clearnet_relay=False)
        for i in range(1, n_rounds + 1):
            stg = tempfile.mkdtemp(prefix="round_stg_")
            # one .unsigned and one .signed so the phases believe they worked
            Path(stg, "a.unsigned").write_text("x")
            Path(stg, "a.signed").write_text("x")
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    ghost._run_round_body(args, "plan.json", stg,
                                          f"{role} {i}/{n_rounds}")
                except SystemExit:
                    pass
    finally:
        ghost.subprocess, ghost.integrity_log = saved[0], saved[1]
        ghost._ROUND_EVENTS_LOGGED.clear()
        ghost._ROUND_EVENTS_LOGGED.update(saved[2])
    return payloads(log) if log.exists() else []


_r2 = _round_chain_lines("Exit", 2)
_r9 = _round_chain_lines("Exit", 9)
check("control: the round body logged something at all", len(_r2) > 0)
check("9 exit rounds write the same number of chain lines as 2",
      len(_r2) == len(_r9))
check("...so counting round lines does not count the run's outputs",
      len(_r9) < 9)
check("...and the ROLE is kept, so the chain still says what ran",
      any("exit" in p for p in _r9))
check("...with no ordinal left in it",
      not any(DIGIT.search(p) for p in _r9))

# Different roles must still be distinguishable -- suppression is per (event,
# role), not "log once and go quiet".
_mixed = _round_chain_lines("Peel", 3)
check("a different KIND of round is still recorded",
      any("peel" in p for p in _mixed))


# ==========================================================================
# 6. ADDRESSES THAT NEVER PASSED THROUGH scrub_address
# ==========================================================================
print("\n=== addresses arriving by paths the fragment rule never saw ===")
#
# The fragment rule only recognises what scrub_address emits. Twenty-two chain
# payloads across the shipped tools were built from EXCEPTION TEXT --
# f"rpc_err:{str(e)[:40]}" and friends -- and monero-wallet-rpc puts addresses
# in its error messages, while a connection error carries host='...'. Stripping
# the digits left the letters: "could not resolve 4AdUndZSHcJ1nUAWkMHNTZ" put
# 22 base58 characters (~129 bits) of a publicly-memo-named address on disk.
#
# Two defences, and the first one is the real fix: those call sites now log
# type(e).__name__, so the message never reaches the chain at all. The rule
# below is the backstop for a call site added later.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_FULL = ("4AdUndZSHcJ1nUAWkMHNTZLQmqCLpEJXqUq5bpvHzXvMhSmSbxJ9kQjMdKr"
         "TeSqnAzWkMHNTZLQmqCLpEJXqUq5bpvHzXvMhSmSbxJ")[:95]

check("a FULL address in a payload is redacted whole",
      gsc.chain_safe(f"created:{_FULL}") == "created:<addr>")
check("...300 random full addresses, all of them",
      all("<addr>" in gsc.chain_safe("err:" + "".join(
          _rand.choice(_B58) for _ in range(95))) for _ in range(300)))

# THE CHECK ABOVE DOES NOT TEST THE EXACT MATCHER. Random 95-char addresses
# alternate case densely, so the STATISTICAL rule catches essentially all of
# them on its own -- deleting the exact 90+ match left the suite green, which
# mutation testing caught and which is precisely the "very specific test that
# is secretly not testing anything" failure. A discriminating case must have
# LOW case-alternation, so only a length-based match can see it.
_FLAT = "A" * 48 + "b" * 47            # 95 base58 chars, one case flip
check("control: the statistical rule alone does NOT recognise a flat "
      "low-alternation address", not gsc._b58_run_is_addressy(_FLAT))
check("a full address is redacted by LENGTH, whatever its case pattern",
      gsc.chain_safe(f"created:{_FLAT}") == "created:<addr>")
check("a long slice of one is redacted too",
      "<addr>" in gsc.chain_safe(f"rpc_err:could not resolve {_FULL[:22]}"))

# THE DIAGNOSTICS MUST SURVIVE. The call sites now log exception TYPE names,
# and an early version of this rule ate "ConnectionRefusedError" -- deleting
# the very diagnostic the primary fix introduced. A redactor that destroys
# what the operator needs is a redactor that gets turned off.
_EXC = ["ConnectionError", "TimeoutError", "JSONDecodeError", "InvalidOperation",
        "CalledProcessError", "ValueError", "OSError", "HTTPError", "KeyError",
        "TimeoutExpired", "ConnectionRefusedError", "RuntimeError", "TypeError",
        "ReadTimeout", "SSLError", "ProxyError", "DecodeError",
        "ChunkedEncodingError", "RemoteDisconnected", "IncompleteRead",
        "SubprocessError", "BrokenPipeError"]
_eaten = [e for e in _EXC if "<addr>" in gsc.chain_safe(f"rpc_err:{e}")]
check(f"no exception TYPE name is mistaken for an address ({len(_EXC)} checked)",
      not _eaten)

# ...and no REAL payload in the repo is damaged. Rendered from the actual
# format strings at every call site, with realistic substitutions -- a
# hand-written list would only test the shapes I happened to think of.
_rendered, _damaged = 0, []
for _tool in ("GhostSpiral", "gs_common.py", "receive_watch",
              "thor_swap_preparer", "create_receive_wallet",
              "broadcast_signed_xmr", "airgap_tx_signer", "paranoia_mode",
              "gs_console", "exit_strategy_simulator"):
    _src = Path(REPO, _tool).read_text()
    for _node in ast.walk(ast.parse(_src)):
        if not (isinstance(_node, ast.Call)
                and getattr(_node.func, "id", None) == "integrity_log"
                and len(_node.args) >= 2):
            continue
        _seg = ast.get_source_segment(_src, _node.args[1]) or ""
        for _sv in ("3", "12", "ConnectionError", "Peel 3/6", "Entry veil",
                    "wlan0", "clearnet", "0.2500", "TimeoutExpired", "funded"):
            _lit = re.sub(r"\{[^}]*\}", _sv, _seg).strip("f\"'")
            _rendered += 1
            if "<addr>" in gsc.chain_safe(_lit):
                _damaged.append((_tool, _node.lineno, _lit))
check(f"no real call-site payload is damaged by the address rule "
      f"({_rendered} rendered from the actual format strings)", not _damaged)
if _damaged:
    print("     damaged:", _damaged[:5])

# The primary fix: no chain payload is built from exception TEXT any more.
_textual = []
for _tool in ("GhostSpiral", "gs_common.py", "receive_watch",
              "thor_swap_preparer", "create_receive_wallet",
              "broadcast_signed_xmr", "airgap_tx_signer", "paranoia_mode",
              "gs_console", "exit_strategy_simulator"):
    _src = Path(REPO, _tool).read_text()
    for _i, _line in enumerate(_src.split("\n"), 1):
        if "integrity_log(" in _line and re.search(
                r"\{(str\(e\)|str\(exc\)|_?emsg)\[", _line):
            _textual.append(f"{_tool}:{_i}")
check("no chain payload carries an exception MESSAGE (only its type)",
      not _textual)
if _textual:
    print("     still textual:", _textual)



# ==========================================================================
# 7. A PAYLOAD MUST NOT BE ABLE TO FORGE A CHAIN LINE
# ==========================================================================
print("\n=== line structure ===")
#
# A chain entry is ONE line, and verify_integrity_chain splits on " | " then
# "|". A payload carrying a newline appends what looks like a second entry with
# no hash, so the verifier reports "line N does not chain ... this line or one
# before it was altered": A TAMPER THAT NEVER HAPPENED, in the file whose only
# job is telling the operator whether they have been tampered with. It is
# permanent once written — every later link recomputes against it — and it
# would send an operator into a compromise response over a stray "\n".
# THE CHARACTER SET IS DISCOVERED, NOT LISTED.
#
# The first version of this swept "normal / two\nlines / tab\there /
# pipe|char / crlf\r\nhere" — which is exactly the set the implementation
# already handled, so it could not fail. str.splitlines() breaks on TEN
# characters and the writer scrubbed three; the other seven still forked the
# chain, reachable through `paranoia_mode --iface $'wlan0\x0bEXTRA'` (argv,
# unvalidated) into the real spoof_mac.
#
# Asking Python which characters it splits on removes the author's imagination
# from the test entirely: whatever the runtime considers a line boundary is
# what gets swept, today and after any future Unicode revision.
_BOUNDARIES = [chr(_c) for _c in range(0x110000)
               if len((chr(_c) + "x").splitlines()) > 1]
check(f"(python treats {len(_BOUNDARIES)} characters as line boundaries)",
      len(_BOUNDARIES) >= 8)

_lp = Path(tempfile.mkdtemp(prefix="gs_chain_lines_")) / "integrity_chain.log"
for _m in ["normal", "tab\there", "pipe|char", "after"] + \
          [f"two{_b}lines" for _b in _BOUNDARIES]:
    gsc.integrity_log("stage", _m, log_path=_lp)

# The invariant, stated directly: no payload may survive as more than one line.
_multi = [hex(ord(_b)) for _b in _BOUNDARIES
          if len(gsc.chain_safe(f"a{_b}b").splitlines()) > 1]
check(f"NO line boundary survives chain_safe ({len(_BOUNDARIES)} checked)",
      not _multi)
if _multi:
    print("     survived:", _multi)

_lok, _lbad, _lwhy = gsc.verify_integrity_chain(_lp)
check("a payload containing a newline does NOT fork the chain",
      _lok and _lbad is None)
_expected_entries = 4 + len(_BOUNDARIES)
check("...and every entry is still exactly one line",
      len(_lp.read_text().splitlines()) == _expected_entries)
# Guarded: a forked chain has lines with no " | " at all, and an IndexError
# here would kill the file before it printed RESULT -- turning a clean FAIL
# into "no result", which is exactly how the ipleak suite hid six unmeasured
# guarantees. A test must FAIL, not crash.
def _fields(line):
    parts = line.split(" | ")
    return parts[1].split("|") if len(parts) > 1 else []


check("a payload containing the field separator does not forge a field",
      all(len(_fields(_l)) == 4 for _l in _lp.read_text().splitlines()))
check("...and the event text survives, merely flattened",
      "two lines" in _lp.read_text() and "pipe/char" in _lp.read_text())

# Non-vacuity: an unflattened newline really does break the verifier, so the
# check above is not passing on a payload that was harmless anyway.
_raw = Path(tempfile.mkdtemp(prefix="gs_chain_raw_")) / "c.log"
_prev = "0" * 64
with open(_raw, "w") as _fh:
    for _payload in ("normal", "two\nlines", "after"):
        _line = f"1787154000|10.5|stage|{_payload}"
        _h = hashlib.sha256((_prev + _line).encode()).hexdigest()
        _fh.write(f"{_h} | {_line}\n")
        _prev = _h
check("control: the SAME payloads written unflattened DO break the verifier",
      not gsc.verify_integrity_chain(_raw)[0])


# ==========================================================================
# N. THE CHAIN MUST NOT CARRY TEXT THIS TOOLCHAIN DID NOT AUTHOR.
#
# Every rule above is about what the run's own vocabulary may say. This is the
# other half: an EXCEPTION MESSAGE, or another program's stderr, is written by
# someone else and its content is unbounded. Three call sites put one straight
# into the persistent chain, and the worst of them was on the most-travelled
# path in the toolchain -- newnym(), whose exception comes from
# Controller.from_socket_file(ctrl) and therefore quotes the CONTROL SOCKET
# PATH. Under a per-user Tor that is /home/<operator>/... or /run/user/<uid>/,
# so the chain recorded a username. Found in a REAL integrity_chain.log: 294
# entries from that one line.
#
# chain_safe does not help here. It strips addresses and digits; a path is
# neither.
#
# Driven, not read: each function below is executed with a failure injected
# whose text carries a marker no redactor would recognise, and BOTH halves are
# asserted -- the marker must be absent from the chain and PRESENT on the
# terminal, because the fix is "log the type, print the text", not "say less".
# ==========================================================================
print("\n=== the chain must not carry foreign text ===")

MARKER = "/home/zzoperatorzz/.tor/ctrl"


def _capture(fn, *a, **k):
    """Run fn with integrity_log captured. Returns (chain_lines, stdout, exit)."""
    lines = []
    saved = gsc.integrity_log
    buf = io.StringIO()
    code = None
    try:
        gsc.integrity_log = lambda stage, msg, **kw: lines.append(str(msg))
        try:
            with contextlib.redirect_stdout(buf):
                fn(*a, **k)
        except SystemExit as e:
            code = str(e.code)
    finally:
        gsc.integrity_log = saved
    return lines, buf.getvalue() + (code or ""), code


# -- newnym: the control socket path ---------------------------------------
# stem is genuinely absent here, so import it into existence with a Controller
# whose from_socket_file raises the error a real per-user Tor would.
def _with_fake_stem(exc):
    saved = {k: sys.modules.get(k) for k in ("stem", "stem.control")}

    class _Ctx:
        def __enter__(self):
            pkg = types.ModuleType("stem")
            pkg.Signal = types.SimpleNamespace(NEWNYM="NEWNYM")
            ctl = types.ModuleType("stem.control")

            class _Controller:
                @staticmethod
                def from_socket_file(path):
                    raise exc
            ctl.Controller = _Controller
            pkg.control = ctl
            sys.modules["stem"] = pkg
            sys.modules["stem.control"] = ctl
            return self

        def __exit__(self, *a):
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
    return _Ctx()


_saved_sleep, _saved_backoff = gsc.time.sleep, gsc._NEWNYM_RETRY_BACKOFF
try:
    gsc.time.sleep = lambda *a, **k: None      # no real backoff in a test
    gsc._NEWNYM_RETRY_BACKOFF = 0
    for _exc, _what in (
            (FileNotFoundError(2, "No such file or directory", MARKER),
             "a missing control socket"),
            (PermissionError(13, "Permission denied", MARKER),
             "an unreadable control socket")):
        with _with_fake_stem(_exc):
            _chain, _term, _code = _capture(gsc.newnym, MARKER, required=False)
        _joined = " ".join(_chain)
        check(f"newnym: {_what} does NOT put the socket path on the chain",
              MARKER not in _joined)
        check(f"newnym: ...it records the failure by TYPE ({type(_exc).__name__}), "
              f"which is what tells the cases apart",
              type(_exc).__name__ in _joined)
        check(f"newnym: ...and the operator still sees the path on the terminal",
              MARKER in _term)
        # And nothing else foreign rode along: the payload after the counter
        # must be exactly the type name.
        _nl = [m for m in _chain if m.startswith("NEWNYM_fail:")]
        check("newnym: the NEWNYM_fail payload is counter + type and nothing else",
              bool(_nl) and _nl[-1].split(":")[-1] == type(_exc).__name__)

    # required=True aborts, and the abort must not leak it either.
    with _with_fake_stem(PermissionError(13, "Permission denied", MARKER)):
        _chain, _term, _code = _capture(gsc.newnym, MARKER, required=True)
    check("newnym: a REQUIRED rotation still aborts", _code is not None)
    check("newnym: ...and the abort path leaves no path on the chain",
          MARKER not in " ".join(_chain))
    check("newnym: ...while the abort message names it for the operator",
          MARKER in _term)
finally:
    gsc.time.sleep, gsc._NEWNYM_RETRY_BACKOFF = _saved_sleep, _saved_backoff

# -- paranoia: dns_check and clear_journal ---------------------------------
_pl = importlib.machinery.SourceFileLoader("paranoia_mode",
                                           os.path.join(REPO, "paranoia_mode"))
_par = importlib.util.module_from_spec(importlib.util.spec_from_loader(_pl.name, _pl))
_pl.exec_module(_par)


def _capture_par(fn, *a, **k):
    lines = []
    saved = _par.integrity_log
    buf = io.StringIO()
    try:
        _par.integrity_log = lambda stage, msg, **kw: lines.append(str(msg))
        with contextlib.redirect_stdout(buf):
            fn(*a, **k)
    finally:
        _par.integrity_log = saved
    return lines, buf.getvalue()


_saved_gai = _par.socket.getaddrinfo
try:
    def _boom(*a, **k):
        raise OSError(101, "Network is unreachable", MARKER)
    _par.socket.getaddrinfo = _boom
    _chain, _term = _capture_par(_par.dns_check)
    check("dns_check: the resolver's error text does NOT reach the chain",
          MARKER not in " ".join(_chain))
    check("dns_check: ...the type does", "OSError" in " ".join(_chain))
    check("dns_check: ...and the operator still sees the message",
          MARKER in _term)
finally:
    _par.socket.getaddrinfo = _saved_gai

_saved_run = _par.subprocess.run
try:
    def _boom_run(*a, **k):
        raise _par.subprocess.CalledProcessError(
            1, "journalctl", output=b"", stderr=MARKER.encode())
    _par.subprocess.run = _boom_run
    _chain, _term = _capture_par(_par.clear_journal, False)
    check("clear_journal: journalctl's OWN stderr does NOT reach the chain",
          MARKER not in " ".join(_chain))
    check("clear_journal: ...it records WHICH failure, in a fixed vocabulary",
          any(m.startswith("journal_fail:")
              and m.split(":", 1)[1] in ("needs_root", "journalctl_error")
              for m in _chain))
    check("clear_journal: ...and the stderr still reaches the operator",
          MARKER in _term)
finally:
    _par.subprocess.run = _saved_run

# -- CONTROL: the markers are findable at all ------------------------------
# Every check above is an absence. Without this, a _capture that silently
# returned nothing would make all of them pass.
check("control: _capture does see chain lines when they are written",
      len(_capture(lambda: gsc.integrity_log("t", "hello:world"))[0]) == 1)
# CONTROL: the absence above is the CALL SITE's doing.
#
# This used to assert the marker survives chain_safe. It no longer does -- the
# path rule further down now collapses it too -- so that phrasing would be
# quietly testing the redactor instead of the call site. Say the true thing
# instead: the injection really carries the marker, and the redactor alone
# does NOT turn the old payload into the new one. What changed is what the
# call site sends.
_exc_probe = PermissionError(13, "Permission denied", MARKER)
check("control: the injected exception really does carry the marker "
      "(so the checks above had something to find)",
      MARKER in str(_exc_probe))
check("control: chain_safe alone does NOT reduce the payload this call site "
      "used to write to the one it writes now — the difference is the call "
      "site, not the redactor",
      gsc.chain_safe(f"NEWNYM_fail:1:{str(_exc_probe)[:40]}")
      != gsc.chain_safe("NEWNYM_fail:1:PermissionError"))


# -- STRUCTURAL: no future call site may reintroduce it --------------------
#
# The three sites above were found by reading a real chain log, which is not a
# process that scales. The rule is mechanical, so enforce it mechanically:
# inside an `except ... as <name>` handler, no integrity_log argument may
# interpolate <name> itself or str(<name>). type(<name>).__name__ is the
# sanctioned form and is what ~24 other sites already use.
# DISCOVERED, not listed. A hand-maintained list of tools is the same hope as
# a comment asking two lists to stay in sync -- a tool added later would simply
# not be checked, and nothing would say so. Anything in the repo root that
# calls integrity_log is in scope, by definition.
def _is_python_source(p):
    """A .py file, or an extensionless script with a python shebang.

    NOT "any file mentioning integrity_log": the first version of this swept
    the repo root and picked up BRUTAL_AUDIT.md, which discusses the function
    in prose. ast.parse then died on a markdown heading and took the suite
    with it -- a discovery rule is only an improvement over a hand list if it
    discovers the right thing.
    """
    if p.suffix == ".py":
        return True
    try:
        return p.read_bytes()[:2] == b"#!" and b"python" in p.read_bytes()[:64]
    except OSError:
        return False


_TOOLS = sorted(
    p.name for p in Path(REPO).iterdir()
    if p.is_file() and not p.name.startswith(".") and _is_python_source(p)
    and "integrity_log" in p.read_text(errors="ignore"))
check("the rule below is applied to every tool that logs to the chain, found "
      f"by looking rather than by a list ({len(_TOOLS)} of them)",
      len(_TOOLS) >= 10 and "gs_common.py" in _TOOLS
      and "GhostSpiral" in _TOOLS)


def _exc_text_in_chain(path):
    """[(line, expr)] for every integrity_log arg quoting an exception's text."""
    tree = ast.parse(Path(path).read_text())
    bad = []

    class V(ast.NodeVisitor):
        def __init__(self):
            self.bound = []          # names bound by enclosing except handlers

        def visit_ExceptHandler(self, node):
            self.bound.append(node.name)
            self.generic_visit(node)
            self.bound.pop()

        def visit_Call(self, node):
            f = node.func
            if (isinstance(f, ast.Name) and f.id == "integrity_log") or \
               (isinstance(f, ast.Attribute) and f.attr == "integrity_log"):
                names = {b for b in self.bound if b}
                for arg in node.args + [k.value for k in node.keywords]:
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.FormattedValue):
                            e = sub.value
                            if isinstance(e, ast.Name) and e.id in names:
                                bad.append((node.lineno, e.id))
                            if (isinstance(e, ast.Call)
                                    and isinstance(e.func, ast.Name)
                                    and e.func.id == "str"
                                    and e.args
                                    and isinstance(e.args[0], ast.Name)
                                    and e.args[0].id in names):
                                bad.append((node.lineno, f"str({e.args[0].id})"))
                            # str(e)[:40] and friends
                            if isinstance(e, ast.Subscript):
                                for s2 in ast.walk(e):
                                    if (isinstance(s2, ast.Call)
                                            and isinstance(s2.func, ast.Name)
                                            and s2.func.id == "str"
                                            and s2.args
                                            and isinstance(s2.args[0], ast.Name)
                                            and s2.args[0].id in names):
                                        bad.append((node.lineno,
                                                    f"str({s2.args[0].id})[...]"))
            self.generic_visit(node)

    V().visit(tree)
    return bad


_offenders = []
for _t in _TOOLS:
    _offenders += [(_t, ln, ex) for ln, ex in _exc_text_in_chain(os.path.join(REPO, _t))]
check("no integrity_log call anywhere interpolates a caught exception's TEXT"
      + (f" (found {_offenders})" if _offenders else ""),
      not _offenders)

# The rule detector must actually detect. Feed it the code as it was.
_probe = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
_probe.write(
    "def f():\n"
    "    try:\n"
    "        g()\n"
    "    except Exception as e:\n"
    "        integrity_log('tor', f'fail:{str(e)[:40]}')\n"
    "        integrity_log('tor', f'fail:{e}')\n"
    "        integrity_log('tor', f'ok:{type(e).__name__}')\n")
_probe.close()
_found = _exc_text_in_chain(_probe.name)
os.unlink(_probe.name)
check("control: the rule CATCHES the two forms that were shipped "
      "(str(e)[:40] and a bare {e})", len(_found) == 2)
check("control: ...and does NOT flag the sanctioned type(e).__name__ form",
      all("type" not in f[1] for f in _found))


# ==========================================================================
# ...AND A FILESYSTEM PATH IS FOREIGN TEXT TOO.
#
# The exception rule above was scoped to `except ... as e`, and it missed the
# site right next to it: paranoia_mode logged `str(path)[-40:]` for every
# artifact it could not securely delete. /home/<operator>/... is not an
# address and not a digit, so nothing above touched it -- the operator's
# USERNAME went onto the persistent chain, written by the tool whose entire
# job is leaving nothing behind.
#
# Two defences, because they fail differently:
#   * the CALL SITE logs a basename. A left-truncated path fragment
#     ("alice/.local/share/x") is not something a chokepoint can fully undo.
#   * CHAIN_SAFE collapses any path that still reaches it, so a future call
#     site cannot reintroduce this the way this one was introduced.
# ==========================================================================
print("\n=== a path is an identifier ===")

_USER = "zzoperatorzz"
for _p, _keep in (
        (f"/home/{_USER}/.local/share/recently-used.xbel", "recently-used.xbel"),
        (f"/home/{_USER}/ghostspiral/thor_pairs.json", "thor_pairs.json"),
        ("/run/user/1000/tor/control", "control"),
        (f"/tmp/gs_sign_ab12/unsigned_monero_tx", "unsigned_monero_tx")):
    _got = gsc.chain_safe(f"secure_delete_fail:{_p}")
    check(f"chain_safe drops the directories of {_p}", _USER not in _got
          and "/home/" not in _got and "/run/" not in _got)
    check(f"...and keeps the basename ({_keep}), which is the diagnostic",
          _keep.replace("1", "#").replace("2", "#") in _got or _keep in _got)

# The left-truncated form the old call site produced.
check("chain_safe also collapses a path that was already truncated from the "
      "left (the shape `str(path)[-40:]` produced)",
      _USER not in gsc.chain_safe(
          f"secure_delete_fail:{_USER}/.local/share/recently-used.xbel"))

# NOT VACUOUS: it must leave the chain's own vocabulary alone. These are the
# real payloads the tools build, and an over-eager path rule would eat the
# account/subaddress pairs this file spends the rest of its length on.
for _p in REAL:
    check(f"real payload survives the path rule: {_p}",
          "<path>" not in gsc.chain_safe(_p))
check("in particular an account/subaddress pair is NOT read as a path",
      gsc.chain_safe("withdrawn:4/1") == "withdrawn:#/#")

# The call site itself, driven: paranoia's own failure log.
_recorded = []
_saved_log, _saved_del = _par.integrity_log, _par.secure_delete_file
try:
    _par.integrity_log = lambda stage, msg, **kw: _recorded.append(
        gsc.chain_safe(str(msg)))
    _par.secure_delete_file = lambda p: False        # every delete "fails"
    with contextlib.redirect_stdout(io.StringIO()):
        _par._secure_delete_file(Path(f"/home/{_USER}/ghostspiral/thor_pairs.json"))
finally:
    _par.integrity_log, _par.secure_delete_file = _saved_log, _saved_del
check("paranoia's own delete-failure line names the FILE, not where it lived",
      any("thor_pairs.json" in m for m in _recorded))
check("...and does not carry the operator's home directory",
      _recorded and not any(_USER in m for m in _recorded))
check("control: it did log something (so the absence above is a redaction, "
      "not a missing call)", len(_recorded) == 1)

# THE CASE ONLY THE CALL SITE CAN FIX, and the reason it is fixed there too.
#
# chain_safe needs TWO separators to recognise a path, so it cleans the
# ordinary `str(path)[-40:]` tail. It cannot clean a tail that truncation left
# with only ONE: a deep home directory pushes the leading separators off the
# front, and what remains is `<end-of-username>/f.json` -- which is a filename
# with a directory in front of it as far as any rule can tell.
#
# Without this case, reverting the call site to str(path)[-40:] changes
# nothing observable and the fix reads as redundant. It is not.
_DEEP = "/home/" + "x" * 30 + _USER + "/f.json"
check("a truncated tail with ONE separator is NOT recognisable as a path — "
      "which is why the call site must send a basename, not a tail",
      _USER in gsc.chain_safe(f"secure_delete_fail:{_DEEP[-40:]}"))

_recorded2 = []
_saved_log, _saved_del = _par.integrity_log, _par.secure_delete_file
try:
    _par.integrity_log = lambda stage, msg, **kw: _recorded2.append(
        gsc.chain_safe(str(msg)))
    _par.secure_delete_file = lambda p: False
    with contextlib.redirect_stdout(io.StringIO()):
        _par._secure_delete_file(Path(_DEEP))
finally:
    _par.integrity_log, _par.secure_delete_file = _saved_log, _saved_del
check("...and with a deep home directory the real call site STILL leaks no "
      "part of the operator's name",
      _recorded2 and not any(_USER in m for m in _recorded2))
check("...while still naming the file", any("f.json" in m for m in _recorded2))


# ==========================================================================
# ...AND THE REDACTOR MUST NOT EAT THE DIAGNOSTIC IT PROTECTS.
#
# Every check above asserts what does NOT reach the chain. This is the other
# direction, and it is the one a redactor gets switched off over.
#
# _b58_run_is_addressy's own docstring says "chain payloads now carry
# exception TYPE names for exactly the reason this function exists -- so a
# rule that ate them would delete the diagnostic it was introduced to
# protect". It was eating them. Swept over 34 realistic type names, three came
# out as addresses:
#
#     FileNotFoundError   -> Fil<addr>     ('l' is not base58, so the run is
#                                           "eNotFoundError": 6 flips over 14)
#     ModuleNotFoundError -> Modul<addr>
#     MaxRetryError       -> <addr>
#
# and the first two are this toolchain's commonest failures -- a missing Tor
# control socket, a missing plan file, an absent `stem`.
#
# IT SURVIVED BECAUSE EVERY TEST MEASURED THE WRONG THING. The suites capture
# integrity_log's ARGUMENT, which never passes through chain_safe. It was
# found by writing a real chain entry to disk and reading the file back, which
# is what the end-to-end check at the bottom of this section does.
#
# Reporting <addr> where no address existed is not a harmless over-redaction:
# integrity_chain.log is what an operator reads to find out what happened, and
# <addr> tells them an address leaked into the chain and was caught. Both
# halves are false.
# ==========================================================================
print("\n=== the redactor must not eat the diagnostic ===")

TYPE_NAMES = """FileNotFoundError PermissionError ConnectionError ModuleNotFoundError
NotADirectoryError IsADirectoryError TimeoutError OSError RuntimeError ValueError
TypeError KeyError IndexError AttributeError JSONDecodeError InvalidOperation
CalledProcessError TimeoutExpired RequestException InvalidSchema HTTPError
ConnectionRefusedError BrokenPipeError InterruptedError UnicodeDecodeError
AuthenticationFailure SocketError ProtocolError ReadTimeout SSLError
MaxRetryError NewConnectionError ProxyError ChunkedEncodingError""".split()

_eaten = [n for n in TYPE_NAMES
          if gsc.chain_safe(f"verify_fail:{n}") != f"verify_fail:{n}"]
check(f"no exception TYPE name is redacted by chain_safe"
      + (f" (eaten: {_eaten})" if _eaten else ""), not _eaten)

# The three that were, named individually so a regression says WHICH.
for _n in ("FileNotFoundError", "ModuleNotFoundError", "MaxRetryError"):
    check(f"{_n} survives the chain intact", gsc.chain_safe(f"x:{_n}") == f"x:{_n}")

# ...and the type names this toolchain writes today, taken from the call sites
# rather than from a list someone remembered to update.
for _n in ("NEWNYM_fail:3:ModuleNotFoundError", "dns_fail:OSError",
           "verify_fail:ConnectionError", "peel_carrier_timeout:0"):
    check(f"a real payload keeps its meaning: {_n}",
          "<addr>" not in gsc.chain_safe(_n))

# NON-VACUITY: addresses must STILL be redacted, or this section would be
# satisfied by deleting the rule.
_FULL = ("4AdUndZSGRTuLDcnbXWuqiCRjxvJyfKUnKbGRvHfHDbHqPBb7pTuT9Y2NPmEZQPHT"
         "RPtLbLDBnPa6NPRjXcSjSbUFqPWWxq")
check("control: a WHOLE address is still redacted", "<addr>" in gsc.chain_safe(f"x:{_FULL}"))
check("control: a scrub_address fragment is still redacted",
      "<addr>" in gsc.chain_safe("entry=4AdUndZS...9kQjMdKr"))
for _L in (30, 40, 60):
    check(f"control: a {_L}-character address fragment is still redacted",
          "<addr>" in gsc.chain_safe("x:" + _FULL[:_L]))

# The rule's shape, stated as a property rather than by example: at or above
# the threshold, length alone decides, so a digitless slice of an address is
# still caught. (Below it, a digitless run is treated as a word -- that is the
# trade, and the docstring measures its cost.)
_DIGITLESS = "AbCdEfGhAbCdEfGhAbCdEfGhAbCdEfGhAbCd"          # 36, no digits
check("a long DIGITLESS base58 run is still redacted — the threshold is a "
      "floor on the digit requirement, not a hole above it",
      "<addr>" in gsc.chain_safe(f"x:{_DIGITLESS}"))
check("...while a short digitless run (a word) is not",
      "<addr>" not in gsc.chain_safe("x:AbCdEfGh"))

# -- END TO END, through the file, which is how this was found ---------------
# Everything above calls chain_safe directly. The bug lived in the gap between
# what a test captured and what reached the disk, so close it: write real
# entries with the real writer and read the real file back.
_d = tempfile.mkdtemp(prefix="gs_chain_e2e_")
_lp = Path(_d, "chain.log")
_WROTE = [("tor", "NEWNYM_fail:3:ModuleNotFoundError"),
          ("tor", "NEWNYM_fail:1:FileNotFoundError"),
          ("paranoia", "secure_delete_fail:/home/zzoperatorzz/gs/thor_pairs.json"),
          ("exit", "withdrawn:4/1"),
          ("stage3", "entry_created")]
for _s, _m in _WROTE:
    gsc.integrity_log(_s, _m, log_path=_lp)
_disk = _lp.read_text()
check("e2e: the type name reaches the FILE unmangled",
      "ModuleNotFoundError" in _disk and "FileNotFoundError" in _disk)
check("e2e: ...and no <addr> was invented for it", "<addr>" not in _disk)
check("e2e: the operator's home directory does NOT reach the file",
      "zzoperatorzz" not in _disk and "/home/" not in _disk)
check("e2e: ...while the file that failed is still named",
      "thor_pairs.json" in _disk)
check("e2e: numbers are still stripped", "withdrawn:#/#" in _disk)
_v = gsc.verify_integrity_chain(_lp)
check("e2e: and the chain the real writer produced VERIFIES", _v[0] is True)
check("control: e2e actually wrote every line",
      len([ln for ln in _disk.splitlines() if " | " in ln]) == len(_WROTE))


# ==========================================================================
# 5. THE COUNT AGAIN, WHERE THE LOOP IS A COMPREHENSION.
#
# The sweep that closed this class looked for `for` and `while` statements and
# for functions called inside one. A list comprehension is neither, so
# thor_swap_preparer.resolve_destinations kept the leak:
#
#     out = [_dest_from_bundle(b) for b in bundles]
#
# and _dest_from_bundle chained `dest_from_bundle:{scrub_address(addr)}` on
# every call. chain_safe reduces that to `dest_from_bundle:<addr>` -- the same
# line for every bundle -- so a five-swap run left five byte-identical lines
# and the swap batch size came off the file by counting them. Driven with five
# real-shaped subaddresses: one distinct payload, five occurrences.
#
# The same file already applied the fix 393 lines below, for "pair_ready".
# ==========================================================================
print("\n=== a comprehension is a loop too ===")

_thor_src = (Path(__file__).resolve().parent.parent / "thor_swap_preparer").read_text()
check("thor: the per-bundle destination line is chained ONCE, not once per "
      "bundle — counting them would give the swap batch size",
      'integrity_log_once("thor", "dest_from_bundle")' in _thor_src
      and 'f"dest_from_bundle:{scrub_address(addr)}"' not in _thor_src)

# DRIVEN: five calls, one line. The count is the property, so count it.
_tl = Path(tempfile.mkdtemp(prefix="thor_card_")) / "chain.log"
for _i in range(5):
    gsc.integrity_log_once("thor", "dest_from_bundle", log_path=_tl)
check("thor: ...proven by driving it — five bundles leave one line",
      len(_tl.read_text().splitlines()) == 1)
check("thor: ...and that the destinations came from bundles is still recorded",
      "dest_from_bundle" in _tl.read_text())
check("thor: ...and the chain still verifies",
      gsc.verify_integrity_chain(_tl)[0] is True)



# ==========================================================================
# "AT MOST ONCE PER PROCESS" IS NOT ONCE PER RUN, and a round is three
# processes.
#
# integrity_log_once collapses a repeated event because "cardinality survives
# redaction whenever a loop writes a line per turn". Its set lived in the
# process, and GhostSpiral spawns a fresh signer twice and a fresh broadcaster
# once for EVERY round -- so an N-round loop wrote N copies of every line the
# guard exists to collapse.
#
# Measured on a completed run's chain file, between the exit's own
# withdraw_start and withdraw_done markers, with every digit already redacted:
#
#      9  signer     using_account_index:#
#      9  signer     create_done:#_created:#_failed
#      8  broadcast  relayed
#      8  broadcast  done
#     17  tor        verified_ok
#
# That run made exactly nine exit withdrawals -- the number the exit collapses
# its OWN lines into a set to avoid recording.
# ==========================================================================
print()
print("=== once-per-RUN, across child processes ===")

_REPO_DIR = str(Path(__file__).resolve().parent.parent)
_PROG = (
    "import sys, pathlib\n"
    "sys.path.insert(0, " + repr(_REPO_DIR) + ")\n"
    "import gs_common as gs\n"
    "_p = pathlib.Path(sys.argv[1])\n"
    'gs.integrity_log_once("signer", "using_account_index:7", _p)\n'
    'gs.integrity_log_once("broadcast", "relayed", _p)\n'
    'gs.integrity_log("signer", "create_fail:idx=3:Boom", _p)\n'
)

_od = Path(tempfile.mkdtemp(prefix="chain_once_"))
_oc, _om = _od / "chain.log", _od / "marker"


def _rounds(n, marker):
    _oc.write_text("")
    _om.write_text("")
    for _ in range(n):
        _e = dict(os.environ)
        if marker:
            _e["GS_CHAIN_RUN_ONCE"] = str(_om)
        else:
            _e.pop("GS_CHAIN_RUN_ONCE", None)
        subprocess.run([sys.executable, "-c", _PROG, str(_oc)], check=True,
                       env=_e, capture_output=True)
    return collections.Counter(
        l.split("|")[-1] for l in _oc.read_text().splitlines())


_no = _rounds(5, marker=False)
check("chain-once: WITHOUT the marker, five child rounds leave five copies - "
      "this is the defect, driven",
      _no["using_account_index:#"] == 5 and _no["relayed"] == 5)
_yes = _rounds(5, marker=True)
check("chain-once: WITH it, five child rounds leave ONE line each",
      _yes["using_account_index:#"] == 1 and _yes["relayed"] == 1)
check("chain-once: ...so the round count cannot be read off the chain",
      sum(v for k, v in _yes.items() if "fail" not in k) == 2)
check("chain-once: FAILURES still chain every time - counting those gives the "
      "number of things that went wrong, not the size of the run",
      _yes["create_fail:idx=#:Boom"] == 5)
check("chain-once: ...and the chain still verifies",
      gsc.verify_integrity_chain(_oc)[0] is True)

# THE WIRING. A guard nothing passes the marker to is the same guard.
_gs_src = (Path(__file__).resolve().parent.parent / "GhostSpiral").read_text()
check("chain-once: GhostSpiral creates the marker at the start of stage 5",
      "open_chain_once_marker(args.output)" in _gs_src)
check("chain-once: ...hands it to every child it spawns",
      'env["GS_CHAIN_RUN_ONCE"] = _CHAIN_ONCE_FILE[0]' in _gs_src)
check("chain-once: ...and erases it with the spent plans",
      '_CHAIN_ONCE_FILE[0] = ""' in _gs_src)
_sg_src = (Path(__file__).resolve().parent.parent / "airgap_tx_signer").read_text()
_bc_src = (Path(__file__).resolve().parent.parent / "broadcast_signed_xmr").read_text()
for _ev in ("using_account_index", "outputs_exported", "create_done",
            "outputs_imported", "sign_done"):
    check("chain-once: the signer's " + _ev + " is a once-per-run event",
          'integrity_log_once("signer", f"' + _ev in _sg_src
          or 'integrity_log_once("signer", "' + _ev in _sg_src)
for _ev in ("rpc_pool", "blobs_found", "delays_loaded", "manifest_verified",
            "egress_via_walletrpc_daemon_conn"):
    check("chain-once: the broadcaster's " + _ev + " is a once-per-run event",
          'integrity_log_once("broadcast", f"' + _ev in _bc_src
          or 'integrity_log_once("broadcast", "' + _ev in _bc_src)
check("chain-once: and Tor's verified_ok, which fired twice per withdrawal",
      'integrity_log_once("tor", "verified_ok")' in
      (Path(__file__).resolve().parent.parent / "gs_common.py").read_text())
# NON-VACUITY: failures must NOT have been routed through the guard.
for _bad in ("create_fail", "TAMPER_DETECTED", "DOUBLE_SPEND",
             "plan_fingerprint_mismatch"):
    check("chain-once: " + _bad + " still chains every time",
          'integrity_log_once("signer", f"' + _bad not in _sg_src
          and 'integrity_log_once("broadcast", f"' + _bad not in _bc_src)


# ===========================================================================
# A MAC AND A BECH32 ADDRESS ARE IDENTIFIERS, AND NEITHER HAD A RULE.
#
# Measured on the shipped function before this:
#
#   mac=de:ad:be:ef:ca:fe  ->  mac=de:ad:be:ef:ca:fe        (untouched)
#   a4:c3:f0:1b:de:ad      ->  a#:c#:f#:#b:de:ad            (two octets intact)
#   bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
#     ->  bc#qar#srrr#xfkvy#l#lydnw#re#gtzzwf#mdq           (most of it)
#
# The first has no digits, so the digit rule never fired. The others left the
# value in order with the gap widths shown -- a search key, not a redaction.
# A MAC survives reinstalling the machine, and the BTC entry address is what
# the ThorChain memo publishes in a public Bitcoin OP_RETURN.
for _v, _why in (
        ("mac=de:ad:be:ef:ca:fe", "an all-letters MAC, which the digit rule "
                                  "cannot touch at all"),
        ("mac=02:1a:4c:9b:7e:31", "a mixed MAC"),
        ("spoofed to a4-c3-f0-1b-de-ad", "a dash-separated MAC"),
        ("MAC A4:C3:F0:1B:DE:AD", "an upper-case MAC"),
        ("btc_entry:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
         "a bech32 v0 address"),
        ("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
         "a bech32m taproot address"),
        ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "a testnet address")):
    _got = gsc.chain_safe(_v)
    _tail = _v.split(":")[-1].split(" ")[-1]
    check(f"chain_safe removes {_why}",
          ("<mac>" in _got or "<addr>" in _got) and _tail not in _got)

# AND IT MUST NOT EAT THE PAYLOADS THIS CHAIN IS MADE OF. Two colons and hex
# digits are ordinary here.
for _v, _want in (("withdrawn:4/1", "withdrawn:#/#"),
                  ("spend_source_ok:acct=3:idx=1",
                   "spend_source_ok:acct=#:idx=#"),
                  ("job_accepted:receive_and_quote",
                   "job_accepted:receive_and_quote"),
                  ("refused:no_deadman", "refused:no_deadman"),
                  ("quotes_unreadable:2_of_5", "quotes_unreadable:#_of_#")):
    check(f"chain_safe leaves {_v!r} alone", gsc.chain_safe(_v) == _want)


# ===========================================================================
# THE DEDUPE MARKER IS A SECOND COPY OF EVERY CHAIN PAYLOAD.
#
# integrity_log_once keys its run-scoped marker file on the RAW (stage, kind)
# and writes that line to disk -- so a payload carrying an address or a MAC was
# stored verbatim beside the chain, while the chain one line below stored
# chain_safe's version. The redactor was bypassed by the deduplicator that
# feeds it. Driven with the real kinds the signer and broadcaster emit.
import tempfile as _tfm, os as _osm                          # noqa: E402
_md = _tfm.mkdtemp(prefix="gs_marker_")
_marker = _osm.path.join(_md, ".chain_once_test")
_mlog = Path(_md) / "chain.log"
_saved_env = os.environ.get("GS_CHAIN_RUN_ONCE")
try:
    os.environ["GS_CHAIN_RUN_ONCE"] = _marker
    gsc._CARDINAL_EVENTS_LOGGED.clear()
    gsc.integrity_log_once("signer", "using_account_index:7", log_path=_mlog)
    gsc._CARDINAL_EVENTS_LOGGED.clear()
    gsc.integrity_log_once("paranoia", "spoofed:a4:c3:f0:1b:de:ad",
                           log_path=_mlog)
    _mtext = open(_marker).read()
    check("the dedupe marker carries the REDACTED payload, not the raw one",
          "using_account_index:#" in _mtext
          and "using_account_index:7" not in _mtext)
    check("...including a MAC, which the chain itself now removes too",
          "a4:c3:f0:1b:de:ad" not in _mtext and "<mac>" in _mtext)
    check("...and it is 0600, not whatever the umask says",
          oct(_osm.stat(_marker).st_mode)[-3:] == "600")
finally:
    if _saved_env is None:
        os.environ.pop("GS_CHAIN_RUN_ONCE", None)
    else:
        os.environ["GS_CHAIN_RUN_ONCE"] = _saved_env
    gsc._CARDINAL_EVENTS_LOGGED.clear()

# It must also be erased and never committed. It was in neither list: an
# incomplete run keeps its marker by design (report_completion exits before
# _wipe_spent_plans), so the wipe walked straight past it.
_pm = open(os.path.join(REPO, "paranoia_mode")).read()
_gi = open(os.path.join(REPO, ".gitignore")).read()
check("the marker is on paranoia_mode's wipe list", '".chain_once_*"' in _pm)
check("...and in .gitignore, in lockstep as this repo requires",
      ".chain_once_*" in _gi)

# And the surviving-plans report must not name a destination those files do
# not contain: the three registered plans are the fan-out, the veil and the
# DAG round, whose destinations are mix subaddresses and carriers.
_gsrc = open(os.path.join(REPO, "GhostSpiral")).read()
_rep = _gsrc[_gsrc.index("unsigned plan file(s) are STILL ON DISK"):][:400]
check("the surviving-plans report no longer claims those files hold "
      "--exit-to", "--exit-to destination" not in _rep)
check("...and still says what they DO hold",
      "mix graph" in _rep and "account index" in _rep)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
