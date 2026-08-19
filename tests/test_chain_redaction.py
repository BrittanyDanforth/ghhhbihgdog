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
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import os
import re
import secrets as _secretsmod
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
             ghost._change_residue, ghost.integrity_log)
    try:
        def _round(args, path, stage, label):
            seen.append(label)
            return 1
        ghost._run_round = _round
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: 0
        ghost.integrity_log = lambda stage, msg: gsc.integrity_log(
            stage, msg, log_path=log)
        args = types.SimpleNamespace(
            rpc_primary="x", tor_proxy=None, rpc_daemon="y", wallet_file="w",
            wallet_password="", fee_priority=1, allow_clearnet_relay=False)
        jobs = [(a, 0, f"DST{a}", a * 10) for a in range(5, 5 + n_jobs)]
        with contextlib.redirect_stdout(io.StringIO()):
            ghost._run_change_sweeps(args, jobs, stg, None, {})
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.integrity_log) = saved
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
_lp = Path(tempfile.mkdtemp(prefix="gs_chain_lines_")) / "integrity_chain.log"
for _m in ("normal", "two\nlines", "tab\there", "pipe|char", "crlf\r\nhere",
           "after"):
    gsc.integrity_log("stage", _m, log_path=_lp)

_lok, _lbad, _lwhy = gsc.verify_integrity_chain(_lp)
check("a payload containing a newline does NOT fork the chain",
      _lok and _lbad is None)
check("...and every entry is still exactly one line",
      len(_lp.read_text().splitlines()) == 6)
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


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
