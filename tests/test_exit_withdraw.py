#!/usr/bin/env python3
"""THE EXIT: the stage that actually spends the mixed funds off the wallet.

Stage 5d used to run exit_strategy_simulator, which fetches a price and prints
a valuation. That is a report, not an exit -- the pipeline announced it was
complete while every output it had created was still sitting on the operator's
wallet. --exit-to performs the withdrawal.

What matters here, and why each is a test rather than a comment:

  * ONE TRANSACTION PER OUTPUT. A transaction's inputs are public, so spending
    N of these outputs together is permanent proof they share an owner -- the
    exact link the run spent hours breaking. A Monero transaction cannot span
    accounts, so the wallet enforces most of it; two subaddresses INSIDE one
    account could still be merged, and this must not.
  * DESTINATIONS ARE VALIDATED BEFORE ANYTHING MOVES. A mistyped address is
    well-formed often enough that only the checksum catches it, and funds sent
    to a key nobody holds are unrecoverable -- there is no confirmation step.
  * A FAILED WITHDRAWAL MUST NOT STRAND THE REST. _run_round aborts the process
    on a bad round; the exit is a loop of independent transactions.

Pure-function checks: no daemon, no wallet, no binaries. The end-to-end proof
that value really leaves the wallet is a separate regtest run.
"""
import importlib.machinery, importlib.util, io, os, sys, contextlib, types, json
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

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


# Real, checksum-valid mainnet addresses.
A1 = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
A2 = "43ZYYZBkwxZJNJFo6rGHf5KREAGR3LizKKXN3aPDCHYj1AAfkqEipXs4x9nnrTq2FuaqXMqLrVtED1kV2Z77b6NGE6FFTCm"
A3 = "47BDEBFVTx8DwkcmD3isorD69HXCwxk8WU56eb9dp9k9hE1sjbYgFHV2rtXChvDWDFhhYYxBGWqxRZz4g7BBFCVqHUhQ5Fe"


def _resolve(dests):
    a = types.SimpleNamespace(exit_to=dests)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ghost.resolve_exit_destinations(a)
        return None
    except SystemExit as e:
        return str(e.code)


# ---- destination validation, before anything moves -----------------------
check("exit: valid destinations are accepted", _resolve([A1, A2]) is None)
check("exit: no --exit-to is fine (nothing is withdrawn)", _resolve(None) is None)

_m = _resolve([A1, A1])
check("exit: the SAME address twice is refused", _m is not None)
check("exit: ...and the message explains repeating is for SPREADING",
      _m is not None and "SPREADING" in _m)

# A single transposed character keeps the format and breaks the checksum. This
# is the case only a checksum catches, and the one that loses the money.
_bad_ck = A1[:-2] + ("A" if A1[-2] != "A" else "B") + A1[-1]
check("exit: a checksum-invalid address is refused (format alone passes it)",
      _resolve([_bad_ck]) is not None)
check("exit: a truncated address is refused", _resolve([A1[:-1]]) is not None)
check("exit: a non-Monero string is refused", _resolve(["bc1qnotmonero"]) is not None)
check("exit: an empty destination is refused", _resolve([""]) is not None)

# SUBADDRESSES MUST BE ACCEPTED, and this is where the validator was wrong.
# monero.address.Address is the STANDARD-address class: it raises "Invalid
# address netbyte 42" on a subaddress. Every address this toolchain handles is
# one -- create_receive_wallet mints a subaddress, and an exchange deposit
# address is normally one too -- so validating with the class rejected the
# ordinary case and blamed the checksum, the one thing that was not wrong.
# Caught by an end-to-end run, where the real exit refused the lab's own
# destinations; the fix is the address() FACTORY.
_SUB = ("83Ss8Wx9CmH4EaWkan3bdGhAybs7r3xgHZnMeWMNgwwdW3BJc6nfjTbFL9V4"
        "Go9LxZjUvDCX9H416cHR68m8aLc6FUZFVRJ")
check("exit: a real SUBADDRESS is a valid destination", _resolve([_SUB]) is None)
check("exit: a subaddress with a broken checksum is still refused",
      _resolve([_SUB[:-2] + ("A" if _SUB[-2] != "A" else "B") + _SUB[-1]])
      is not None)
check("exit: standard and subaddress destinations can be mixed",
      _resolve([A1, _SUB]) is None)

# The same bug lived in thor_swap_preparer, where it broke this repo's own
# documented money-IN flow: create_receive_wallet mints a subaddress and
# `--dest-from-receive-wallet` fed it straight to a validator that always
# refused it. Both now share one checker.
_thld = importlib.machinery.SourceFileLoader(
    "thor_swap_preparer", os.path.join(REPO, "thor_swap_preparer"))
_thor = importlib.util.module_from_spec(
    importlib.util.spec_from_loader(_thld.name, _thld))
_thld.exec_module(_thor)
_thor_ok = True
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _thor._validate_xmr_addr(_SUB)
except SystemExit:
    _thor_ok = False
check("swap: thor_swap_preparer accepts a receive SUBADDRESS as a destination "
      "(it rejected every one, breaking the documented receive flow)", _thor_ok)


# ---- enumerating what to withdraw ---------------------------------------
class _BalRPC:
    """per_subaddress balances, the shape wallet-rpc really returns."""

    def __init__(self, table):
        self.table = table

    def raw_request(self, method, params=None):
        if method != "get_balance":
            return {}
        acct = (params or {}).get("account_index")
        subs = self.table.get(acct, {})
        return {"per_subaddress": [{"address_index": i, "balance": b}
                                   for i, b in subs.items()]}


_rpc = _BalRPC({4: {0: 0, 1: 5_000_000_000_000},
                5: {0: 250_000_000_000, 1: 0},
                6: {}})
_found = ghost._funded_subaddresses(_rpc, [4, 5, 6])
check("exit: finds every FUNDED subaddress across the run's accounts",
      sorted((a, s) for a, s, _ in _found) == [(4, 1), (5, 0)])
check("exit: ...and skips zero-balance subaddresses",
      all(amt > 0 for _, _, amt in _found))
check("exit: ...including swept change on a subaddress that is not index 1 "
      "(assuming index 1 would silently abandon it)",
      (5, 0) in [(a, s) for a, s, _ in _found])
check("exit: an account with no subaddresses contributes nothing",
      6 not in [a for a, _, _ in _found])

# WHICH accounts the exit is even told to look at. bal_account is the one that
# is easy to leave out: a FAN-OUT's change lands there, so if its change sweep
# fails that value sits on it, and an exit that never looked would abandon it
# silently -- the same defect as a wipe that misses a file.
_al = ghost._exit_account_list({"addrA": (11, 1), "addrB": (12, 1)}, [20, 21], 9)
check("exit: the account list covers the mix/veil/sweep-destination accounts",
      11 in _al and 12 in _al)
check("exit: ...the per-hop change accounts a peel chain leaves behind",
      20 in _al and 21 in _al)
check("exit: ...and bal_account, where a fan-out's change lands", 9 in _al)


# ---- the withdrawal loop -------------------------------------------------
class _Recorder:
    """Captures every plan _run_round is handed, without running anything."""

    def __init__(self):
        self.rounds = []

    def __call__(self, args, plan_file, staging, label):
        import json
        with open(plan_file) as f:
            self.rounds.append(json.load(f)["txs"])
        return 1


_saved = (ghost._run_round, ghost._wait_for_change_settled,
          ghost._change_residue, ghost.connect_rpc, ghost.newnym,
          ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay)
rec = _Recorder()
try:
    ghost._run_round = rec
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {7: {1: 3_000_000_000_000}, 8: {1: 2_000_000_000_000},
         9: {0: 1_000_000_000_000, 1: 4_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    _args = types.SimpleNamespace(
        rpc_primary="http://127.0.0.1:18083", tor_proxy=None,
        rpc_daemon="http://127.0.0.1:18081", wallet_file="w",
        wallet_password="", fee_priority=1, allow_clearnet_relay=False,
        exit_to=[A1, A2])
    import tempfile as _tf
    _stg = os.path.join(_tf.mkdtemp(prefix="exitwd_"), "tx_staging")
    os.makedirs(_stg, exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()):
        relayed, failed, skipped, held, unclean = ghost._run_exit_withdrawals(
            _args, [7, 8, 9], [A1, A2], _stg, None, {}, (0, 0))
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved

_txs = [t for r in rec.rounds for t in r]
check("exit: withdrew every funded output (4 of them)",
      relayed == 4 and failed == 0 and skipped == 0 and held == 0)
check("exit: ONE transaction per round -- never a collecting sweep",
      all(len(r) == 1 for r in rec.rounds) and len(rec.rounds) == 4)
check("exit: every withdrawal is a SWEEP (leaves no change behind)",
      all(t.get("sweep") is True for t in _txs))
check("exit: no withdrawal carries an amount (a sweep sends the balance)",
      all(t.get("amt") is None for t in _txs))
check("exit: each names its OWN account, so nothing spends across accounts",
      sorted((t["account_index"], t["src_index"]) for t in _txs)
      == [(7, 1), (8, 1), (9, 0), (9, 1)])
check("exit: the two outputs inside account 9 are sent SEPARATELY, not merged",
      len([t for t in _txs if t["account_index"] == 9]) == 2)
check("exit: every destination is one the operator supplied",
      all(t["dst"] in (A1, A2) for t in _txs))
check("exit: the withdrawal is SPREAD across both destinations",
      len({t["dst"] for t in _txs}) == 2)
check("exit: each carries its own random extra (no shared fingerprint)",
      len({t["extra"] for t in _txs}) == len(_txs))


# ---- the exit must NOT withdraw an unmixed output off ENTRY --------------
#
# Under --split N the swap chunks settle independently, so one can land on
# ENTRY after the run has finished planning against the others. It has been
# through none of the mixing, and the ThorChain memo names ENTRY in public --
# so a sweep from it to --exit-to publishes exactly the link the run exists to
# break, in the pipeline's final step, on the money it never mixed.
#
# Account 9 / subaddr 0 below stands in for that late chunk.
_saved2 = (ghost._run_round, ghost._wait_for_change_settled,
           ghost._change_residue, ghost.connect_rpc, ghost.newnym,
           ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay)
rec2 = _Recorder()
try:
    ghost._run_round = rec2
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {7: {1: 3_000_000_000_000},
         9: {0: 1_000_000_000_000, 1: 4_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    _stg2 = os.path.join(_tf.mkdtemp(prefix="exithold_"), "tx_staging")
    os.makedirs(_stg2, exist_ok=True)
    _held_out = io.StringIO()
    with contextlib.redirect_stdout(_held_out):
        _r2, _f2, _s2, _h2, _u2 = ghost._run_exit_withdrawals(
            _args, [7, 9], [A1, A2], _stg2, None, {}, (0, 0), hold=[(9, 0)])
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved2

_txs2 = [t for r in rec2.rounds for t in r]
check("exit: the held ENTRY output is NOT withdrawn",
      (9, 0) not in [(t["account_index"], t["src_index"]) for t in _txs2])
check("exit: ...and is reported as held, not as a silent success",
      _h2 == 1 and _r2 == 2 and _f2 == 0 and _s2 == 0)
check("exit: ...while every MIXED output still leaves",
      sorted((t["account_index"], t["src_index"]) for t in _txs2)
      == [(7, 1), (9, 1)])
_held_msg = _held_out.getvalue()
check("exit: ...and the operator is told it was not withdrawn",
      "NOT withdrawn" in _held_msg)
check("exit: ...and told the reason is the public swap memo, not a failure",
      "memo" in _held_msg and "FAILED" not in _held_msg)
check("exit: ...and told what to do with it instead of spending it by hand",
      "--receive-wallet" in _held_msg)
# The amount is printed so the operator knows what is sitting there. It is on
# an address the memo already names, so this leaks nothing they do not have.
check("exit: ...and how much is sitting there", "1 XMR" in _held_msg)

# The hold list itself: ENTRY, and only when the veil actually ran.
_ai = {"ENTRYADDR": (3, 1), "mixaddr": (4, 1)}
_hold_on = ghost._exit_hold_list(types.SimpleNamespace(entry_veil=True),
                                 _ai, "ENTRYADDR")
check("hold: ENTRY is held back when the entry veil ran", _hold_on == [(3, 1)])
check("hold: ...and nothing else is",
      (4, 1) not in _hold_on)
# --no-entry-veil is NOT a carve-out. It publishes ENTRY -> the mix, which an
# analyst still has to unpick; sweeping a late chunk publishes ENTRY -> the
# operator's destination, which is the answer rather than a graph. Two
# different links, and only the first was consented to.
check("hold: ENTRY is held under --no-entry-veil too",
      ghost._exit_hold_list(types.SimpleNamespace(entry_veil=False),
                            _ai, "ENTRYADDR") == [(3, 1)])
check("hold: an ENTRY that is not in addr_index holds nothing (no crash)",
      ghost._exit_hold_list(types.SimpleNamespace(entry_veil=True),
                            _ai, "unknown") == [])

# ---- THE WIRING, executed ------------------------------------------------
#
# The checks above test _exit_hold_list alone, and _run_exit_withdrawals with a
# hold passed in by hand. Nothing joined them, and a mutation sweep showed what
# that costs: emptying the hold at EITHER call site restores the exact
# ENTRY -> --exit-to sweep this exists to prevent, and both test files stayed
# green. A producer and a consumer that are each correct in isolation is not a
# wired pipeline.
#
# So drive _stage5_run, where main() joins them, and assert on the transactions
# that actually reach _run_round.
_wire = _Recorder()
_saved3 = (ghost._run_round, ghost._wait_for_change_settled,
           ghost._change_residue, ghost.connect_rpc, ghost.newnym,
           ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
           ghost._wait_for_fanout_confirm, ghost._run_change_sweeps)
_ENTRY = "ENTRY_ADDRESS"
_addr_index = {_ENTRY: (3, 1), "mix": (4, 1)}
_plan = os.path.join(_tf.mkdtemp(prefix="wireplan_"), "fanout.json")
with open(_plan, "w") as _pfh:
    json.dump({"meta": {}, "txs": []}, _pfh)
_wargs = types.SimpleNamespace(
    rpc_primary="http://127.0.0.1:18083", tor_proxy=None,
    rpc_daemon="http://127.0.0.1:18081", wallet_file="w",
    wallet_password="", fee_priority=1, allow_clearnet_relay=False,
    exit_to=[A1], entry_veil=True, dag_mixing=False, peel=False,
    output="./unsigned")


def _drive_stage5(args_ns, recorder):
    """Drive the REAL _stage5_run exit path. ENTRY (3/1) is funded -- a swap
    chunk that landed after the run had planned -- alongside a mixed output."""
    saved = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.connect_rpc, ghost.newnym,
             ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
             ghost._wait_for_fanout_confirm, ghost._run_change_sweeps)
    try:
        ghost._run_round = recorder
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: 0
        ghost.connect_rpc = lambda *a, **k: _BalRPC(
            {3: {1: 2_000_000_000_000}, 4: {1: 5_000_000_000_000}})
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost._wait_for_fanout_confirm = lambda *a, **k: True
        ghost._run_change_sweeps = lambda *a, **k: 0
        stg = os.path.join(_tf.mkdtemp(prefix="wire_"), "tx_staging")
        os.makedirs(stg, exist_ok=True)
        with contextlib.redirect_stdout(io.StringIO()):
            return ghost._stage5_run(
                args_ns, _plan, None, [], stg, None, 1,
                distribution_mode="fanout", change_target=(4, 0),
                change_sweep_jobs=None, delay_window=(0, 0),
                exit_accounts=ghost._exit_account_list(_addr_index, [], 3),
                exit_hold=ghost._exit_hold_list(args_ns, _addr_index, _ENTRY))
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.connect_rpc, ghost.newnym,
         ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
         ghost._wait_for_fanout_confirm, ghost._run_change_sweeps) = saved


_inc, _wh = _drive_stage5(_wargs, _wire)
_wsrc = [(t["account_index"], t["src_index"])
         for r in _wire.rounds for t in r]
check("WIRING: the funded ENTRY output is NOT swept to --exit-to",
      (3, 1) not in _wsrc)
check("WIRING: ...while the mixed output still leaves", (4, 1) in _wsrc)
check("WIRING: ...and the hold is reported as WITHHELD, not as an incomplete "
      "run (an incomplete run skips the plan-file wipe)",
      _wh and not _inc)

# Non-vacuity: the SAME drive with the hold removed MUST sweep ENTRY, or the
# check above would pass on a pipeline where nothing was ever wired. The lever
# is _exit_hold_list itself -- --no-entry-veil is no longer a carve-out, so it
# cannot serve as the control any more.
_wire2 = _Recorder()
_real_hold = ghost._exit_hold_list
try:
    ghost._exit_hold_list = lambda *a, **k: []
    _drive_stage5(_wargs, _wire2)
finally:
    ghost._exit_hold_list = _real_hold
_wsrc2 = [(t["account_index"], t["src_index"])
          for r in _wire2.rounds for t in r]
check("WIRING control: with the hold emptied the SAME drive DOES sweep ENTRY, "
      "so the check above is not vacuous", (3, 1) in _wsrc2)


# ---- everything held: the run must not read as clean ---------------------
_saved5 = (ghost._run_round, ghost._wait_for_change_settled,
           ghost._change_residue, ghost.connect_rpc, ghost.newnym,
           ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay)
try:
    ghost._run_round = _Recorder()
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _BalRPC({3: {1: 2_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    _hstg = os.path.join(_tf.mkdtemp(prefix="allheld_"), "tx_staging")
    os.makedirs(_hstg, exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()) as _hout:
        _hr, _hf, _hs, _hh, _hu = ghost._run_exit_withdrawals(
            _args, [3], [A1], _hstg, None, {}, (0, 0), hold=[(3, 1)])
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved5
check("ALL HELD: when the held ENTRY output is the ONLY funded one the hold is "
      "still reported, not a silent clean exit", _hh == 1 and _hr == 0)
check("ALL HELD: ...and the operator is told nothing was withdrawn",
      "nothing was withdrawn" in _hout.getvalue())



# ---- "EXIT COMPLETE" MUST NOT FOLLOW "XMR IS STILL ON ..." --------------
#
# _run_exit_withdrawals collapsed three per-output results into one `relayed`
# counter: emptied; relayed-but-residue-left (sweep_all cannot take an output
# that has not unlocked); and relayed-but-the-balance-could-not-be-re-read.
# _stage5_run's condition was `_relayed and not _held`, so the exit printed
# "0.000005 XMR is STILL on account 4 / subaddr 1" and the very next line said
# "EXIT COMPLETE ... Nothing left on this run's accounts" -- and the run exited
# 0. Reproduced end to end before the fix.
_saved6 = (ghost._run_round, ghost._wait_for_change_settled,
           ghost._change_residue, ghost.connect_rpc, ghost.newnym,
           ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay)


def _exit_with_residue(residue):
    """Drive the real exit where the sweep leaves `residue` atomic units."""
    try:
        ghost._run_round = lambda *a, **k: 1
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: residue
        ghost.connect_rpc = lambda *a, **k: _BalRPC({4: {1: 5_000_000_000_000}})
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        stg = os.path.join(_tf.mkdtemp(prefix="unclean_"), "tx_staging")
        os.makedirs(stg, exist_ok=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            res = ghost._run_exit_withdrawals(
                _args, [4], [A1], stg, None, {}, (0, 0))
        return res, buf.getvalue()
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.connect_rpc, ghost.newnym,
         ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay) = _saved6


(_ur, _uf, _us, _uh, _uu), _uout = _exit_with_residue(5_000_000)
check("UNCLEAN: an output that relayed with value STILL on it is counted",
      _uu == 1)
check("UNCLEAN: ...and is not silently folded into the relayed count",
      _ur == 1 and _uu == 1)
check("UNCLEAN control: the exit really did report the residue to the operator",
      "STILL on account" in _uout)

# ...and the same drive with a clean sweep must report zero, or the check
# above would pass on a counter that is always 1.
(_cr, _cf, _cs, _ch, _cu), _cout = _exit_with_residue(0)
check("UNCLEAN control: a fully emptied output counts as clean",
      _cr == 1 and _cu == 0)

# An unverifiable balance is unclean too: "I could not check" is not "it is
# empty", and it was being reported as the latter.
(_nr, _nf, _ns, _nh, _nu), _nout = _exit_with_residue(None)
check("UNCLEAN: an output whose balance could not be re-read is unclean too",
      _nu == 1)

# THE SENTENCE ITSELF. _stage5_run is where the claim is printed, so the claim
# is what has to be tested -- a counter that is right while the message is
# still wrong fixes nothing.
_s5src = Path(REPO, "GhostSpiral").read_text()
_branch = _s5src[_s5src.index("elif _unclean:"):
                 _s5src.index("EXIT COMPLETE")]
check("UNCLEAN: the EXIT COMPLETE branch is guarded by the unclean count",
      "_unclean" in _s5src.split("elif _relayed and not _held:")[0][-800:])
check("UNCLEAN: ...and the unclean branch says the value has NOT left",
      "has NOT left the wallet" in _branch)



# ---- THE CHANGE ADDRESS IS HELD BACK TOO --------------------------------
#
# The hold covered ENTRY's own subaddress only. A distribution cannot allocate
# its input exactly, so monerod returns the remainder as change to subaddress 0
# of the SPENDING account — and the exit swept that straight to --exit-to.
# Reproduced: ENTRY at 3/1 held, fan-out change at 3/0 withdrawn.
#
# That output is what the change sweep exists to push into the mix, and
# _run_change_sweep's own failure message calls what it leaves behind "UNMIXED
# ... the one output that never moves". It is also an output of the transaction
# that spent the swapped funds, so withdrawing it publishes that link in one
# hop — the same publication the ENTRY hold refuses, on the same run.
_cg = _Recorder()
_savedC = (ghost._run_round, ghost._wait_for_change_settled,
           ghost._change_residue, ghost.connect_rpc, ghost.newnym,
           ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
           ghost._wait_for_fanout_confirm, ghost._run_change_sweeps)
try:
    ghost._run_round = _cg
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    # 3/0 is the fan-out change, 3/1 is ENTRY, 5/1 is a mixed output.
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {3: {0: 2_000_000_000_000, 1: 1_000_000_000_000},
         5: {1: 4_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    ghost._wait_for_fanout_confirm = lambda *a, **k: True
    ghost._run_change_sweeps = lambda *a, **k: 1        # the sweep FAILED
    _cai = {"ENTRY": (3, 1), "mix": (5, 1)}
    _cargs = types.SimpleNamespace(**{**vars(_wargs), "entry_veil": True})
    _cstg = os.path.join(_tf.mkdtemp(prefix="chg_"), "tx_staging")
    os.makedirs(_cstg, exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()) as _cout:
        ghost._stage5_run(
            _cargs, _plan, None, [], _cstg, None, 1,
            distribution_mode="fanout", change_target=(3, 0),
            change_sweep_jobs=[(3, 0, "DST", 9)], delay_window=(0, 0),
            exit_accounts=ghost._exit_account_list(_cai, [], 3),
            exit_hold=ghost._exit_hold_list(_cargs, _cai, "ENTRY"))
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay, ghost._wait_for_fanout_confirm,
     ghost._run_change_sweeps) = _savedC

_csrc = [(t["account_index"], t["src_index"]) for r in _cg.rounds for t in r]
check("CHANGE HOLD: unswept distribution change is NOT withdrawn to --exit-to",
      (3, 0) not in _csrc)
check("CHANGE HOLD: ...ENTRY is still held too", (3, 1) not in _csrc)
check("CHANGE HOLD: ...and the MIXED output still leaves", (5, 1) in _csrc)

# The message must name what it actually is. Calling change "ENTRY" sends the
# operator to an address with nothing on it and describes the wrong risk.
_mbuf = io.StringIO()
_savedM = (ghost._run_round, ghost._wait_for_change_settled,
           ghost._change_residue, ghost.connect_rpc, ghost.newnym,
           ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay)
try:
    ghost._run_round = lambda *a, **k: 1
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {3: {0: 2_000_000_000_000, 1: 1_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    _mstg = os.path.join(_tf.mkdtemp(prefix="msg_"), "tx_staging")
    os.makedirs(_mstg, exist_ok=True)
    with contextlib.redirect_stdout(_mbuf):
        ghost._run_exit_withdrawals(_args, [3], [A1], _mstg, None, {}, (0, 0),
                                    hold=[(3, 1), (3, 0)], entry_pair=(3, 1))
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _savedM
_mtxt = _mbuf.getvalue()
check("CHANGE HOLD: the ENTRY output is described as ENTRY",
      "the swap ENTRY address (account 3 / subaddr 1)" in _mtxt)
check("CHANGE HOLD: the change output is described as CHANGE, not ENTRY",
      "a distribution CHANGE address (account 3 / subaddr 0)" in _mtxt)
check("CHANGE HOLD: ...and the change explanation is the change one",
      "The change sweep would have moved it once" in _mtxt)
# ...and it must not repeat the G7 claim. This message said the sweep "pushes
# it into the mix"; the sweep moves it once to a fresh address that is in no
# plan and no hop graph. Written here by the same pass that fixed the hold,
# and missed by a plain grep because it spans three source lines.
check("CHANGE HOLD: ...and does NOT claim the sweep mixes it",
      "into the mix" not in _mtxt)
check("CHANGE HOLD: ...but does say it is unmixed either way",
      "UNMIXED either way" in _mtxt)



# ==========================================================================
# G8: A PARTIAL PEEL CHAIN WAITED AN HOUR PER PEEL THAT NEVER RAN
# ==========================================================================
print("\n=== change sweeps skip peels that never ran ===")
#
# change_sweep_jobs is provisioned for EVERY hop in the plan, in hop order,
# before the chain runs. A chain that stops early leaves the rest of those
# accounts never funded — and _wait_for_change_settled cannot tell "nothing
# arrived yet" from "nothing is ever coming", so it waited out
# FANOUT_CONFIRM_TIMEOUT (3600s) on each. A 7-peel chain stopping at the first
# peel spent ~6 hours polling addresses that could not hold anything, then
# reported them "NOT swept — UNMIXED", sending the operator to look for money
# that was never there.
_g8_seen = []
_g8_saved = (ghost._run_peel_chain, ghost._run_change_sweeps,
             ghost._run_round, ghost._wait_for_fanout_confirm,
             ghost.integrity_log, ghost.newnym, ghost.tor_recheck,
             ghost.secure_delay, ghost._wait_for_carrier,
             ghost._run_exit_withdrawals)


def _g8_run(total_peels, relayed):
    """Drive _stage5_run's peel branch; return the jobs the sweeps were given."""
    _g8_seen.clear()
    d = _tf.mkdtemp(prefix="g8_")
    plan = os.path.join(d, "peel.json")
    with open(plan, "w") as fh:
        json.dump({"meta": {}, "txs": [{"i": i} for i in range(total_peels)]}, fh)
    stg = os.path.join(d, "tx_staging")
    os.makedirs(stg, exist_ok=True)
    jobs = [(10 + i, 0, f"DST{i}", 1) for i in range(total_peels)]
    try:
        ghost._run_peel_chain = lambda *a, **k: relayed
        ghost._run_change_sweeps = lambda a, j, *rest, **k: (
            _g8_seen.extend(j) or 0)
        ghost._run_round = lambda *a, **k: 1
        ghost._wait_for_fanout_confirm = lambda *a, **k: True
        ghost._wait_for_carrier = lambda *a, **k: True
        ghost.integrity_log = lambda *a, **k: None
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        # the exit is a separate concern; this drive is about the sweeps
        ghost._run_exit_withdrawals = lambda *a, **k: (0, 0, 0, 0, 0)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ghost._stage5_run(
                types.SimpleNamespace(**{**vars(_wargs), "peel": True}),
                plan, None, [], stg, None, 1,
                distribution_mode="peel", change_target=(4, 0),
                change_sweep_jobs=jobs, delay_window=(0, 0))
        return list(_g8_seen), buf.getvalue()
    finally:
        (ghost._run_peel_chain, ghost._run_change_sweeps, ghost._run_round,
         ghost._wait_for_fanout_confirm, ghost.integrity_log, ghost.newnym,
         ghost.tor_recheck, ghost.secure_delay, ghost._wait_for_carrier,
         ghost._run_exit_withdrawals) = _g8_saved


_g8_jobs, _g8_out = _g8_run(total_peels=7, relayed=1)
check("G8: a chain that relayed 1 of 7 peels sweeps only 1 change location",
      len(_g8_jobs) == 1)
check("G8: ...and it is the FIRST one, matching hop order",
      _g8_jobs and _g8_jobs[0][0] == 10)
check("G8: ...and the operator is told why the rest were skipped",
      "never ran" in _g8_out and "hold nothing" in _g8_out)

# The saving, stated in the units that matter.
check(f"G8: that is {6 * ghost.FANOUT_CONFIRM_TIMEOUT // 3600} hours of "
      f"polling empty addresses avoided",
      ghost.FANOUT_CONFIRM_TIMEOUT >= 3600)

# A COMPLETE chain must be unaffected — the fix must not skip real change.
_g8_full, _g8_fout = _g8_run(total_peels=7, relayed=7)
check("G8: a chain that relayed ALL 7 peels still sweeps all 7",
      len(_g8_full) == 7)
check("G8: ...and says nothing about skipping", "never ran" not in _g8_fout)

# Partial in the middle, to show it is the count and not a special case.
_g8_mid, _ = _g8_run(total_peels=12, relayed=5)
check("G8: 5 of 12 relayed -> exactly 5 change locations swept",
      len(_g8_mid) == 5)
check("G8: ...in hop order, not an arbitrary subset",
      [j[0] for j in _g8_mid] == [10, 11, 12, 13, 14])


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
