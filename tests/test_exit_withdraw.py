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
import importlib.machinery, importlib.util, io, os, sys, contextlib, types, json, tempfile
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
_found, _unread = ghost._funded_subaddresses(_rpc, [4, 5, 6])
check("exit: finds every FUNDED subaddress across the run's accounts",
      sorted((a, s) for a, s, _ in _found) == [(4, 1), (5, 0)])
check("exit: ...and reports nothing unreadable when every read worked",
      _unread == [])


# AN UNREADABLE ACCOUNT IS MONEY LEFT BEHIND, and it was silently skipped.
#
# The loop did `except Exception: continue`, so one transient wallet-rpc error
# during the exit dropped every output on that account out of the withdrawal
# list. The exit then announced "withdrawing N output(s)" with N too small and
# finished reporting success. This function's own docstring names that failure:
# "an exit that silently leaves money behind is the same defect as a wipe that
# silently leaves files behind."
class _FlakyRPC(_BalRPC):
    def __init__(self, table, fail_accounts, fail_times=99):
        super().__init__(table)
        self.fail = dict.fromkeys(fail_accounts, fail_times)
        self.calls = 0

    def raw_request(self, method, params=None):
        self.calls += 1
        acct = (params or {}).get("account_index")
        if self.fail.get(acct, 0) > 0:
            self.fail[acct] -= 1
            raise RuntimeError("wallet-rpc busy")
        return super().raw_request(method, params)


_flaky = _FlakyRPC({4: {1: 5_000_000_000_000},
                    5: {0: 250_000_000_000},
                    6: {1: 900_000_000_000}}, [5])
_ff, _fu = ghost._funded_subaddresses(_flaky, [4, 5, 6])
check("exit: an account that cannot be read is REPORTED, not skipped silently",
      _fu == [5])
check("exit: ...and the readable ones are still returned",
      sorted(a for a, _, _ in _ff) == [4, 6])
# A transient error must not cost the account: retry before giving up.
_trans = _FlakyRPC({4: {1: 5_000_000_000_000},
                    5: {0: 250_000_000_000}}, [5], fail_times=2)
_tf, _tu = ghost._funded_subaddresses(_trans, [4, 5])
check("exit: a transient read error is retried, not treated as empty",
      _tu == [] and sorted(a for a, _, _ in _tf) == [4, 5])
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
      relayed == 4 and failed == 0 and skipped == 0
      and sum(held.values()) == 0)
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
# THIS CHECK USED TO READ:
#
#   check("exit: each carries its own random extra (no shared fingerprint)",
#         len({t["extra"] for t in _txs}) == len(_txs))
#
# and it was verifying a property the field could not provide. Every plan
# entry carried `"extra": secure_hex(16)`, but airgap_tx_signer never forwards
# it to any RPC -- its own _canonical_plan says so -- so the bytes were
# generated, written to the plan, and dropped. "No shared fingerprint" was
# neither true nor false on-chain; nothing about tx_extra was being set at all.
#
# A green check asserting an OPSEC property that the code cannot deliver is
# worse than no check: it is what stops anyone looking. So the field is gone
# (forwarding it would have given every transaction a tx_extra size no
# ordinary wallet emits -- a fingerprint on every hop) and this asserts the
# absence instead.
check("exit: no exit TX carries an 'extra' field — tx_extra is left to the "
      "wallet's default, deliberately",
      all("extra" not in t for t in _txs))


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
            _args, [7, 9], [A1, A2], _stg2, None, {}, (0, 0), hold=[(9, 0)],
            entry_pairs=[(9, 0)])
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved2

_txs2 = [t for r in rec2.rounds for t in r]
check("exit: the held ENTRY output is NOT withdrawn",
      (9, 0) not in [(t["account_index"], t["src_index"]) for t in _txs2])
check("exit: ...and is reported as held, not as a silent success",
      sum(_h2.values()) == 1 and _r2 == 2 and _f2 == 0 and _s2 == 0)

# TWO HELD ENTRY OUTPUTS, which is what --split makes possible. The recovery
# advice ("mint a fresh receive wallet, send this balance to it") is printed
# INSIDE the per-output loop, so an operator holding two late swap chunks reads
# it twice and the natural move is to mint ONE wallet and send both. That
# single transaction spends two ENTRY outputs whose swaps both settled in
# public -- the intersection attack, arrived at by following the instructions.
#
# report_holdings does say "SPEND THEM ONE ACCOUNT AT A TIME", but it runs only
# on a COMPLETE run, and a run can reach the exit, hold two entry outputs and
# still finish incomplete. Then this message is the only place the warning can
# come from.
_saved3 = (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
           ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
           ghost.secure_delay)
rec3 = _Recorder()
try:
    ghost._run_round = rec3
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {7: {1: 3_000_000_000_000},
         9: {0: 1_000_000_000_000},
         11: {0: 2_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    _stg3 = os.path.join(_tf.mkdtemp(prefix="exithold2_"), "tx_staging")
    os.makedirs(_stg3, exist_ok=True)
    _held2_out = io.StringIO()
    with contextlib.redirect_stdout(_held2_out):
        _r3, _f3, _s3, _h3, _u3 = ghost._run_exit_withdrawals(
            _args, [7, 9, 11], [A1, A2], _stg3, None, {}, (0, 0),
            hold=[(9, 0), (11, 0)], entry_pairs=[(9, 0), (11, 0)])
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved3
_h2txt = _held2_out.getvalue()
check("exit: BOTH held ENTRY outputs are reported as entry, not change",
      _h3.get("entry") == 2)
check("exit: neither held ENTRY output is withdrawn",
      not ({(9, 0), (11, 0)} & {(t["account_index"], t["src_index"])
                                for r in rec3.rounds for t in r}))
check("exit: with TWO held entry outputs it refuses one shared recovery "
      "bundle — sending both to one address merges two swap chunks",
      "ONE FRESH BUNDLE PER ADDRESS" in _h2txt)
check("exit: ...and says why, in terms of the two public swap settlements",
      "intersect two known candidate sets" in _h2txt)
check("exit: ...and it counts them", "2 ENTRY" in _h2txt)
# CONTROL: one held entry output must NOT get the plural warning.
check("control: a single held ENTRY output does not get the "
      "do-not-merge warning", "ONE FRESH BUNDLE PER ADDRESS" not in _held_out.getvalue())
# WHICH KIND, not just how many. The caller words its report from this: an
# ENTRY hold and a distribution-CHANGE hold are different addresses with
# different reasons and different remedies, and the report used to assert
# ENTRY for both -- sending the operator to look at an address the swap does
# not name.
check("exit: ...and the breakdown says it was an ENTRY hold, not a change one",
      _h2 == {"entry": 1, "change": 0})

# THE OTHER SIDE OF THE BREAKDOWN. Every held-output test passed a pair that
# WAS an entry, so hard-coding the counter to "entry" survived a mutation
# sweep -- the branch that classifies a hold as CHANGE was never taken. That
# is the case where getting it wrong costs the most: the operator is sent to
# look at an address the swap memo does not name, with the wrong remedy.
_saved_chg = (ghost._run_round, ghost._wait_for_change_settled,
              ghost._change_residue, ghost.connect_rpc, ghost.newnym,
              ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay)
try:
    ghost._run_round = lambda *a, **k: 1
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {7: {1: 3_000_000_000_000}, 9: {0: 1_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    _cstg2 = os.path.join(_tf.mkdtemp(prefix="chgkind_"), "tx_staging")
    os.makedirs(_cstg2, exist_ok=True)
    _chg_out = io.StringIO()
    with contextlib.redirect_stdout(_chg_out):
        _cr2, _cf2, _cs2, _ch2, _cu2 = ghost._run_exit_withdrawals(
            _args, [7, 9], [A1], _cstg2, None, {}, (0, 0),
            hold=[(9, 0)], entry_pairs=[(3, 1)])     # 9/0 is CHANGE, not entry
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved_chg
# A CHANGE ACCOUNT WHOSE SWEEP DESTINATION COULD NOT BE CREATED MUST STILL BE
# HELD.
#
# The hold was built from change_sweep_jobs, and build_change_sweep_jobs SKIPS
# an account whose fresh destination could not be created -- so exactly the
# account whose change could not be swept was also the one not held, and with
# --exit-to the exit swept it to the operator's destination. The message they
# were shown said that change "is an output that never moves".
#
# One carrier hid it: change_target covered the only account there was. N
# carriers give N-1 more chances for that create to fail.
class _NoAcctRPC:
    """A wallet that refuses to create the change-sweep destination."""

    def raw_request(self, method, params=None):
        if method == "create_account":
            raise RuntimeError("wallet refused create_account")
        raise AssertionError(method)

    def new_subaddress_indexed(self, **k):
        raise AssertionError("should not be reached")


_ai_cs = {}
with contextlib.redirect_stdout(io.StringIO()) as _cs_out:
    _jobs = ghost.build_change_sweep_jobs(_NoAcctRPC(), _ai_cs, [41, 42, 43])
check("change hold: a wallet that cannot create the destination yields NO jobs",
      _jobs == [])
check("change hold: ...and the operator is told the value stays put",
      "UNMIXED" in _cs_out.getvalue())
check("change hold: ...and is NOT told it 'never moves' — the exit used to "
      "move it, straight to their destination",
      "never moves" not in _cs_out.getvalue()
      and "HOLDS it" in _cs_out.getvalue())


check("exit: a held output that is NOT an entry is counted as CHANGE",
      _ch2 == {"entry": 0, "change": 1})
check("exit: ...and described as a distribution change address, not as ENTRY",
      "distribution CHANGE" in _chg_out.getvalue()
      and "swap ENTRY" not in _chg_out.getvalue())
check("exit: ...with the remedy that fits it — the remainder the distribution "
      "could not allocate, not a late swap chunk",
      "remainder the distribution could not allocate" in _chg_out.getvalue())
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
            _args, [3], [A1], _hstg, None, {}, (0, 0), hold=[(3, 1)],
            entry_pairs=[(3, 1)])
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay) = _saved5
check("ALL HELD: when the held ENTRY output is the ONLY funded one the hold is "
      "still reported, not a silent clean exit",
      _hh == {"entry": 1, "change": 0} and _hr == 0)
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
# DRIVEN, not grepped. This was two source-substring checks, one of which
# split the file on the literal `elif _relayed and not _held:` -- so the moment
# that line was reworded the split returned the WHOLE file and the check
# stopped testing anything. It was reworded, for a real reason: `_held` became
# a {"entry": n, "change": n} breakdown, and a two-key dict is ALWAYS truthy,
# so `not _held` was permanently False and the clean-exit message could never
# print at all. A grep for the old text would have gone green on that.
def _drive_stage5_exit(residue, hold=(), entry_pairs=()):
    """Run the REAL _stage5_run exit block. Returns its stdout."""
    saved = (ghost._run_round, ghost._wait_for_change_settled,
             ghost._change_residue, ghost.connect_rpc, ghost.newnym,
             ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
             ghost._wait_for_fanout_confirm, ghost._run_change_sweeps)
    try:
        ghost._run_round = lambda *a, **k: 1
        ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
        ghost._change_residue = lambda *a, **k: residue
        ghost.connect_rpc = lambda *a, **k: _BalRPC(
            {4: {1: 5_000_000_000_000}, 3: {1: 1_000_000_000_000}})
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost._wait_for_fanout_confirm = lambda *a, **k: True
        ghost._run_change_sweeps = lambda *a, **k: 0
        _a = types.SimpleNamespace(**{**vars(_wargs), "entry_veil": True})
        _st = os.path.join(_tf.mkdtemp(prefix="s5exit_"), "tx_staging")
        os.makedirs(_st, exist_ok=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ghost._stage5_run(_a, _plan, None, [], _st, None, 1,
                              distribution_mode="fanout",
                              change_target=None, change_sweep_jobs=None,
                              delay_window=(0, 0),
                              exit_accounts=[4] + [p[0] for p in hold],
                              exit_hold=list(hold))
        return buf.getvalue()
    finally:
        (ghost._run_round, ghost._wait_for_change_settled,
         ghost._change_residue, ghost.connect_rpc, ghost.newnym,
         ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
         ghost._wait_for_fanout_confirm, ghost._run_change_sweeps) = saved


_clean_out = _drive_stage5_exit(0)
check("UNCLEAN: a genuinely clean exit DOES announce EXIT COMPLETE — the "
      "branch is reachable at all",
      "EXIT COMPLETE" in _clean_out)
_dirty_out = _drive_stage5_exit(5_000_000)
check("UNCLEAN: an exit that left value behind does NOT announce EXIT COMPLETE",
      "EXIT COMPLETE" not in _dirty_out)
check("UNCLEAN: ...and says the value has NOT left the wallet",
      "has NOT left the wallet" in _dirty_out)
_held_out = _drive_stage5_exit(0, hold=[(3, 1)], entry_pairs=[(3, 1)])
check("UNCLEAN: an exit that WITHHELD an output does not announce EXIT "
      "COMPLETE either", "EXIT COMPLETE" not in _held_out)



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
                                    hold=[(3, 1), (3, 0)],
                                    entry_pairs=[(3, 1)])
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


# The hold itself: drive _stage5_run with jobs EMPTY but change_accounts set,
# and confirm the exit refuses to withdraw those accounts.
_saved_h = (ghost._run_round, ghost._wait_for_change_settled,
            ghost._change_residue, ghost.connect_rpc, ghost.newnym,
            ghost.tor_recheck, ghost.integrity_log, ghost.secure_delay,
            ghost._wait_for_fanout_confirm, ghost._run_change_sweeps)
_seen_h = _Recorder()
try:
    ghost._run_round = _seen_h
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    # 41/0 and 42/0 are change locations no job could be made for;
    # 5/1 is a mixed output that must still leave.
    ghost.connect_rpc = lambda *a, **k: _BalRPC(
        {41: {0: 2_000_000_000_000}, 42: {0: 1_000_000_000_000},
         5: {1: 4_000_000_000_000}})
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None
    ghost._wait_for_fanout_confirm = lambda *a, **k: True
    ghost._run_change_sweeps = lambda *a, **k: 0
    _ha2 = types.SimpleNamespace(**{**vars(_wargs), "entry_veil": True})
    _hs = os.path.join(_tf.mkdtemp(prefix="chgacct_"), "tx_staging")
    os.makedirs(_hs, exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()):
        ghost._stage5_run(_ha2, _plan, None, [], _hs, None, 1,
                          distribution_mode="fanout",
                          change_target=None,
                          change_sweep_jobs=[],        # every job failed
                          change_accounts=[41, 42],    # ...but the accounts exist
                          delay_window=(0, 0),
                          exit_accounts=[41, 42, 5],
                          exit_hold=[])
finally:
    (ghost._run_round, ghost._wait_for_change_settled, ghost._change_residue,
     ghost.connect_rpc, ghost.newnym, ghost.tor_recheck, ghost.integrity_log,
     ghost.secure_delay, ghost._wait_for_fanout_confirm,
     ghost._run_change_sweeps) = _saved_h
_hsrc = [(t["account_index"], t["src_index"]) for r in _seen_h.rounds for t in r]
check("change hold: an unsweepable change account is NOT withdrawn to --exit-to",
      (41, 0) not in _hsrc and (42, 0) not in _hsrc)
check("change hold: ...while the MIXED output still leaves", (5, 1) in _hsrc)



# ==========================================================================
# A TOR LEAK IS NOT A WITHDRAWAL FAILURE.
#
# The exit loop opens each iteration with newnym(required=True) and
# tor_recheck(), both of which report by sys.exit -- tor_recheck's message is
# "[!] Tor leak detected during {stage} - aborting." They sat INSIDE the try
# whose `except SystemExit` exists so one failed ROUND does not strand the
# other outputs, so the leak was caught, its message discarded, and replaced
# by the loop's generic per-output line. The loop then continued to the next
# output and re-ran the same failing gate.
#
# Driven below with tor_recheck's real leak behaviour: before the fix, three
# funded outputs produced three "FAILED ... NOT withdrawn" lines and the words
# "Tor" and "leak" appeared nowhere. That reads as a wallet or daemon problem
# and invites a retry, which is the one response a live deanonymising leak
# must not get.
# ==========================================================================
print("\n=== a Tor leak during the exit fails CLOSED ===")

_tor_saved = (ghost.connect_rpc, ghost._funded_subaddresses,
              ghost._wait_for_change_settled, ghost._change_residue,
              ghost.newnym, ghost.tor_recheck, ghost._run_round,
              ghost.integrity_log, ghost.secure_delete_or_warn,
              ghost.secure_delete_tree)
_rounds_reached = []
try:
    ghost.connect_rpc = lambda *a, **k: types.SimpleNamespace(
        raw_request=lambda m, p=None: {})
    ghost._funded_subaddresses = lambda *a, **k: (
        [(3, 1, 1000), (4, 1, 1000), (5, 1, 1000)], [])
    # (the unreadable-account path gets its own driver below)
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.newnym = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delete_or_warn = lambda *a, **k: True
    ghost.secure_delete_tree = lambda *a, **k: True
    # gs_common.tor_recheck's REAL behaviour on a mid-run leak, verbatim.
    ghost.tor_recheck = lambda proxy, stage="recheck": sys.exit(
        f"[!] Tor leak detected during {stage} - aborting.")
    ghost._run_round = lambda *a, **k: _rounds_reached.append(1)

    _targs = types.SimpleNamespace(
        exit_to="8" + "A" * 94, wallet_password="x",
        rpc="http://127.0.0.1:18083", rpc_primary="http://127.0.0.1:18083",
        tor_proxy="socks5h://127.0.0.1:9050", hop_delay=None, dry_run=False,
        wallet_cli="/bin/true", split=1)
    _buf = io.StringIO()
    _leak_msg = None
    _returned = None
    _real_out, sys.stdout = sys.stdout, _buf
    try:
        _returned = ghost._run_exit_withdrawals(
            _targs, [(3, 1), (4, 1), (5, 1)], _targs.exit_to,
            tempfile.mkdtemp(prefix="gs_torleak_"), {"http": "x", "https": "x"},
            {}, (60, 120), hold=[], entry_pairs=[])
    except SystemExit as _e:
        _leak_msg = str(_e)
    finally:
        sys.stdout = _real_out
    _tor_out = _buf.getvalue()

    check("exit/tor: a mid-run Tor leak ABORTS the exit instead of being "
          "reported as a withdrawal failure",
          _leak_msg is not None and _returned is None)
    check("exit/tor: ...and the operator is told it was TOR, in its own words",
          _leak_msg and "Tor leak detected" in _leak_msg)
    check("exit/tor: ...it does NOT continue to the remaining outputs and "
          "re-run the failing gate",
          _tor_out.count("NOT withdrawn") == 0)
    check("exit/tor: ...and no round is broadcast after a leak is detected",
          _rounds_reached == [])

    # CONTROL: a failed ROUND must still be swallowed, or the fix has simply
    # made every failure fatal -- which is the behaviour the except was
    # written to prevent.
    ghost.tor_recheck = lambda *a, **k: None
    ghost._run_round = lambda *a, **k: sys.exit("[!] round failed")
    _buf2 = io.StringIO()
    _real_out, sys.stdout = sys.stdout, _buf2
    _res2 = None
    _esc = None
    try:
        _res2 = ghost._run_exit_withdrawals(
            _targs, [(3, 1), (4, 1), (5, 1)], _targs.exit_to,
            tempfile.mkdtemp(prefix="gs_roundfail_"),
            {"http": "x", "https": "x"}, {}, (60, 120), hold=[], entry_pairs=[])
    except SystemExit as _e:
        _esc = str(_e)
    finally:
        sys.stdout = _real_out
    check("control: a failed ROUND is still caught, so the other outputs are "
          "still attempted", _esc is None and _res2 is not None
          and _res2[1] == 3)
    check("control: ...and each one is reported",
          _buf2.getvalue().count("NOT withdrawn") == 3)
finally:
    (ghost.connect_rpc, ghost._funded_subaddresses,
     ghost._wait_for_change_settled, ghost._change_residue, ghost.newnym,
     ghost.tor_recheck, ghost._run_round, ghost.integrity_log,
     ghost.secure_delete_or_warn, ghost.secure_delete_tree) = _tor_saved


# ==========================================================================
# AN ACCOUNT THE EXIT COULD NOT READ IS NOT A CLEAN EXIT.
#
# _funded_subaddresses now reports what it could not read; the withdrawal loop
# has to act on that. Silently skipping it produced "withdrawing 2 output(s)"
# on a wallet with three funded accounts and then a success report -- money
# left behind, with nothing said.
# ==========================================================================
print("\n=== an unreadable account is reported and counted as a failure ===")

_ur_saved = (ghost.connect_rpc, ghost._funded_subaddresses,
             ghost._wait_for_change_settled, ghost._change_residue,
             ghost.newnym, ghost.tor_recheck, ghost._run_round,
             ghost.integrity_log, ghost.secure_delete_or_warn,
             ghost.secure_delete_tree)
try:
    ghost.connect_rpc = lambda *a, **k: types.SimpleNamespace(
        raw_request=lambda m, p=None: {})
    ghost._funded_subaddresses = lambda *a, **k: ([(3, 1, 1000)], [4, 5])
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost._run_round = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delete_or_warn = lambda *a, **k: True
    ghost.secure_delete_tree = lambda *a, **k: True
    _ur_args = types.SimpleNamespace(
        rpc_primary="http://127.0.0.1:18083", tor_proxy="",
        exit_to=["dest1"], output=tempfile.mkdtemp(prefix="gs_unread_"))
    _ur_buf = io.StringIO()
    _real = sys.stdout
    sys.stdout = _ur_buf
    try:
        _ur_res = ghost._run_exit_withdrawals(
            _ur_args, [3, 4, 5], _ur_args.exit_to,
            tempfile.mkdtemp(prefix="gs_unreadstage_"),
            {"http": "x", "https": "x"}, {}, (1, 2), hold=[], entry_pairs=[])
    finally:
        sys.stdout = _real
    _ur_out = _ur_buf.getvalue()
    check("exit: the unreadable accounts are named on the terminal",
          "could not be read" in _ur_out and "4, 5" in _ur_out)
    check("exit: ...and the run is told its exit is NOT complete",
          "NOT complete" in _ur_out)
    check("exit: ...and they are COUNTED as failures, so the caller reports "
          "the run as incomplete",
          _ur_res[1] == 2)
    check("exit: ...while the readable output is still withdrawn",
          _ur_res[0] == 1)
    # The empty case must count them too, or a wallet the exit could not read
    # AT ALL reports a clean 'nothing to withdraw'.
    ghost._funded_subaddresses = lambda *a, **k: ([], [7, 8, 9])
    _ur_buf2 = io.StringIO()
    sys.stdout = _ur_buf2
    try:
        _ur_res2 = ghost._run_exit_withdrawals(
            _ur_args, [7, 8, 9], _ur_args.exit_to,
            tempfile.mkdtemp(prefix="gs_unread2_"),
            {"http": "x", "https": "x"}, {}, (1, 2), hold=[], entry_pairs=[])
    finally:
        sys.stdout = _real
    check("exit: a wallet it could not read at all is NOT a clean 'nothing to "
          "withdraw'", _ur_res2[1] == 3)
finally:
    (ghost.connect_rpc, ghost._funded_subaddresses,
     ghost._wait_for_change_settled, ghost._change_residue, ghost.newnym,
     ghost.tor_recheck, ghost._run_round, ghost.integrity_log,
     ghost.secure_delete_or_warn, ghost.secure_delete_tree) = _ur_saved


# ==========================================================================
# AN OUTPUT SMALLER THAN ITS OWN SWEEP FEE IS NOT A FAILED WITHDRAWAL.
#
# Measured on a real chain: a peel whose fee moved 1200 piconero between the
# signer's two build passes left a 0.0000012 XMR change output.
# _funded_subaddresses returned it (balance > 0), _wait_for_change_settled
# reported it settled (it was -- total == unlocked), and sweep_all answered
# "No unlocked balance in the specified subaddress(es)", which is monerod's
# way of saying no output there is worth more than the fee to spend it. The
# exit counted that as a FAILED withdrawal, so the run was reported incomplete
# and its plans were left on disk -- over one millionth of an XMR.
# ==========================================================================
print("\n=== dust below the sweep fee is reported, not attempted ===")

_d_saved = (ghost.connect_rpc, ghost._funded_subaddresses,
            ghost._wait_for_change_settled, ghost._change_residue,
            ghost.newnym, ghost.tor_recheck, ghost._run_round,
            ghost.integrity_log, ghost.secure_delete_or_warn,
            ghost.secure_delete_tree)
try:
    ghost.connect_rpc = lambda *a, **k: types.SimpleNamespace(
        raw_request=lambda m, p=None: {})
    # one real output, one 1200-piconero crumb
    ghost._funded_subaddresses = lambda *a, **k: (
        [(3, 1, 5_000_000_000_000), (16, 0, 1_200_000)], [])
    ghost._wait_for_change_settled = lambda *a, **k: (True, 0)
    ghost._change_residue = lambda *a, **k: 0
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost._run_round = lambda *a, **k: None
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delete_or_warn = lambda *a, **k: True
    ghost.secure_delete_tree = lambda *a, **k: True
    _d_args = types.SimpleNamespace(
        rpc_primary="http://127.0.0.1:18083", tor_proxy="",
        exit_to=["dest1"], output=tempfile.mkdtemp(prefix="gs_dust_"))
    _d_buf = io.StringIO()
    _real_d = sys.stdout
    sys.stdout = _d_buf
    try:
        _d_res = ghost._run_exit_withdrawals(
            _d_args, [3, 16], _d_args.exit_to,
            tempfile.mkdtemp(prefix="gs_duststage_"),
            {"http": "x", "https": "x"}, {"fee_per_round": "0.0036"},
            (1, 2), hold=[], entry_pairs=[])
    finally:
        sys.stdout = _real_d
    _d_out = _d_buf.getvalue()
    check("exit: the crumb is NOT attempted",
          "withdrawing 1 output(s)" in _d_out)
    check("exit: ...it is reported, with its size and the reason",
          "smaller than the" in _d_out and "0.0000012" in _d_out)
    check("exit: ...and it does NOT count as a failed withdrawal",
          _d_res[1] == 0 and _d_res[0] == 1)
    # WITHOUT a fee estimate nothing may be dropped: an unknown threshold must
    # not silently abandon an output.
    _d_buf2 = io.StringIO()
    sys.stdout = _d_buf2
    try:
        _d_res2 = ghost._run_exit_withdrawals(
            _d_args, [3, 16], _d_args.exit_to,
            tempfile.mkdtemp(prefix="gs_duststage2_"),
            {"http": "x", "https": "x"}, {}, (1, 2), hold=[], entry_pairs=[])
    finally:
        sys.stdout = _real_d
    check("exit: with no fee estimate in the plan, nothing is filtered",
          "withdrawing 2 output(s)" in _d_buf2.getvalue())
finally:
    (ghost.connect_rpc, ghost._funded_subaddresses,
     ghost._wait_for_change_settled, ghost._change_residue, ghost.newnym,
     ghost.tor_recheck, ghost._run_round, ghost.integrity_log,
     ghost.secure_delete_or_warn, ghost.secure_delete_tree) = _d_saved


# ==========================================================================
# A FAILED CHANGE SWEEP MUST NOT TAKE THE EXIT DOWN WITH IT.
#
# _run_change_sweeps' docstring promises "A failure is reported and the
# remaining sweeps still run", and it only handled ONE of the two failure
# modes: _run_change_sweep returning False when the settle wait times out. Its
# other mode is _run_round, which sys.exits on any create/sign/broadcast
# failure and is called there with a `finally` but no `except` -- so SystemExit
# propagated straight out of the loop.
#
# These sweeps run BEFORE _run_exit_withdrawals, so one failed sweep took the
# whole pipeline down with every mixed output still on the wallet. The stranded
# change is the small loss; the exit never running is the large one.
# ==========================================================================
print("\n=== a failed change sweep does not strand the rest ===")

_cs_saved = (ghost._wait_for_change_settled, ghost._change_residue,
             ghost.integrity_log, ghost.secure_delete_or_warn,
             ghost.secure_delete_tree, ghost.atomic_write_json,
             ghost.connect_rpc, ghost._run_round)
try:
    ghost._wait_for_change_settled = lambda *a, **k: (True, 1000)
    ghost._change_residue = lambda *a, **k: 0
    ghost.integrity_log = lambda *a, **k: None
    ghost.secure_delete_or_warn = lambda *a, **k: True
    ghost.secure_delete_tree = lambda *a, **k: True
    ghost.atomic_write_json = lambda *a, **k: None
    ghost.connect_rpc = lambda *a, **k: types.SimpleNamespace(
        raw_request=lambda m, p=None: {})
    _cs_calls = []

    def _cs_round(args, path, stage, label):
        _cs_calls.append(label)
        if len(_cs_calls) == 2:
            sys.exit("[!] Change sweep 2/4: broadcast failed (exit 1)")
        return 1
    ghost._run_round = _cs_round

    _csargs = types.SimpleNamespace(
        rpc="x", wallet_password="x", tor_proxy="x", hop_delay=None,
        dry_run=False, rpc_primary="x", wallet_cli="/bin/true", split=1)
    _jobs = [(3, 0, "8" + "A" * 94, 1), (4, 0, "8" + "B" * 94, 1),
             (5, 0, "8" + "C" * 94, 1), (6, 0, "8" + "D" * 94, 1)]
    _buf3 = io.StringIO()
    _real_out, sys.stdout = sys.stdout, _buf3
    _csfailed = None
    _csesc = None
    try:
        _csfailed = ghost._run_change_sweeps(
            _csargs, _jobs, tempfile.mkdtemp(prefix="gs_cs_"),
            {"http": "x"}, {}, (60, 120))
    except SystemExit as _e:
        _csesc = str(_e)
    finally:
        sys.stdout = _real_out

    check("change sweeps: a round that ABORTS does not propagate out of the "
          "loop", _csesc is None)
    check("change sweeps: ...the remaining sweeps still run (4 of 4 attempted, "
          f"got {len(_cs_calls)})", len(_cs_calls) == 4)
    check("change sweeps: ...and the failure is counted, not swallowed",
          _csfailed == 1)
    check("change sweeps: ...and the operator is told that change is UNMIXED "
          "and still there",
          "UNMIXED" in _buf3.getvalue() and "still there" in _buf3.getvalue())
    check("change sweeps: ...and told the run continues rather than stopping",
          "Continuing with the remaining sweeps" in _buf3.getvalue())
finally:
    (ghost._wait_for_change_settled, ghost._change_residue,
     ghost.integrity_log, ghost.secure_delete_or_warn,
     ghost.secure_delete_tree, ghost.atomic_write_json, ghost.connect_rpc,
     ghost._run_round) = _cs_saved



# ==========================================================================
# HOW MANY DESTINATIONS, NOT JUST WHICH ONES.
#
# reject_self_exit checks that a destination is not one of this run's own
# addresses. Nothing checked how MANY there were -- and the exit sends ONE
# TRANSACTION PER OUTPUT, so with a single destination every one of them lands
# on the same address.
#
# Observed in the first end-to-end run of the real pipeline (--wallets 4):
#
#     === EXIT: withdrawing 9 output(s) in 9 SEPARATE transactions
#         to 1 destination(s) ===
#
# and nothing anywhere called that a problem. Whoever watches that address
# sees nine arrivals and knows they are one person's -- the separation the run
# spent hours building, handed back at the last step. --exit-to's own help
# says "repeat the flag to spread the withdrawal" and the comment beside it
# says a single destination "re-joins them off-chain, which no amount of
# mixing can undo"; neither reaches an operator who has already typed the
# command.
#
# It has to be said EARLY. resolve_exit_destinations runs before
# stage0_preflight and long before _stage5_run, so the operator hears it while
# they can still add an address -- once the exit starts, nothing can.
# ==========================================================================
print("\n=== how many exit destinations ===")

_EA = ("43ZYYZBkwxZJNJFo6rGHf5KREAGR3LizKKXN3aPDCHYj1AAfkqEipXs4x9nnrTq2"
       "FuaqXMqLrVtED1kV2Z77b6NGE6FFTCm")
_EB = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaB"
       "YBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
_EC = ("47BDEBFVTx8DwkcmD3isorD69HXCwxk8WU56eb9dp9k9hE1sjbYgFHV2rtXChvDW"
       "DFhhYYxBGWqxRZz4g7BBFCVqHUhQ5Fe")

_ed_saved_il = ghost.integrity_log
ghost.integrity_log = lambda *a, **k: None
_ed_saved_env = os.environ.pop("GS_EXIT_TO", None)
try:
    def _dests_kw(ds, **kw):
        _o = io.StringIO()
        with contextlib.redirect_stdout(_o):
            ghost.resolve_exit_destinations(
                types.SimpleNamespace(exit_to=list(ds), **kw))
        return "\n".join(l for l in _o.getvalue().splitlines()
                          if "command line" not in l)

    def _dests(ds, wallets):
        _o = io.StringIO()
        with contextlib.redirect_stdout(_o):
            ghost.resolve_exit_destinations(
                types.SimpleNamespace(exit_to=list(ds), wallets=wallets))
        # The argv-vs-environment warning is a different guarantee, tested
        # elsewhere; it fires on every call here and would mask the rest.
        return "\n".join(l for l in _o.getvalue().splitlines()
                          if "command line" not in l)

    _one = _dests([_EA], 12)
    check("exitdests: ONE destination for a many-output run is warned about",
          "ONE exit destination" in _one)
    # THE REAL RANGE, not --wallets. select_fanout_targets funds
    # `wallets + randint(DECOY_MIN, DECOY_MAX)` outputs, so --wallets 12 means
    # 14-19. The first version printed 12, and two real end-to-end runs at
    # --wallets 4 withdrew 8 and 9 outputs while it said "roughly 4" --
    # understating the one number the warning exists to convey.
    # A FLOOR, and it must never be above what a real run withdraws.
    #
    # Three measured end-to-end runs, all --wallets 4: 8 outputs, 9 outputs,
    # and 18 with --peel --dag-mixing. The first draft of this warning printed
    # args.wallets (4); the second printed wallets+DECOY_MIN..DECOY_MAX (6-11),
    # which brackets the first two and understates the third by half. A number
    # that can be too LOW is the wrong failure for a warning about how many
    # arrivals land on one address, so it states the certain part as certain.
    check("exitdests: ...as a FLOOR, so it can never understate",
          f"AT LEAST {12 + ghost.DECOY_MIN} separate output(s)" in _one)
    check("exitdests: ...and the floor is at or below every measured run",
          (4 + ghost.DECOY_MIN) <= min(8, 9, 18))
    # A FAN-OUT still returns its remainder to the spending account, so the
    # exit has one more withdrawal per swap chunk than the floor.
    check("exitdests: a fan-out says the real number is higher, and why",
          "one more per swap chunk" in _one and "change" in _one)
    # A PEEL CHAIN leaves no change at all now -- it consumes each carrier
    # exactly and the last hop sweeps -- so its withdrawals ARE the mix
    # outputs. The old wording pointed at a measured 18-output run, which was
    # 8 mix outputs plus 8 peel-change destinations plus the fan-out change;
    # saying "measurably more" now would overstate it in the other direction.
    _deep = _dests_kw([_EA], wallets=4, peel=True, dag_mixing=True)
    check("exitdests: --peel says its chain leaves no change to withdraw",
          "leaves no change" in _deep)
    check("exitdests: ...and does NOT still quote the change-heavy measurement",
          "withdrew 18" not in _deep)
    check("exitdests: ...while still giving the floor, because the decoy count "
          "is drawn at random",
          f"AT LEAST {4 + ghost.DECOY_MIN} separate output(s)" in _deep)
    check("exitdests: ...saying what it costs, not just that it is unusual",
          "no amount of mixing undoes that" in _one)
    check("exitdests: ...and how to fix it, including the env form",
          "--exit-to" in _one and 'GS_EXIT_TO="addr1 addr2 addr3"' in _one)
    check("exitdests: ...and that it must be fixed NOW, not at the exit",
          "the exit is the last step" in _one)

    # Several destinations but still lopsided: quieter, still said.
    _few = _dests([_EA, _EB, _EC], 12)
    check("exitdests: 3 destinations for a 12-wallet run is still reported",
          "3 exit destinations" in _few
          and f"at least {12 + ghost.DECOY_MIN} output(s)" in _few)
    check("exitdests: ...but not as the ONE-destination alarm",
          "ONE exit destination" not in _few)

    # Silence where there is nothing to say -- or the warning is noise and
    # gets tuned out on the run where it matters.
    check("exitdests: 3 destinations for a small run says nothing",
          _dests([_EA, _EB, _EC], 4).strip() == "")
    # There is no run small enough to be silent with ONE destination: even
    # --wallets 1 funds 1+DECOY_MIN outputs. Assert that rather than pretend
    # a silent case exists.
    check("exitdests: even the smallest run warns on a single destination, "
          "because even it withdraws several outputs",
          "ONE exit destination" in _dests([_EA], 1))

    # A REFUSAL WOULD BE WRONG. An exchange deposit address is one address and
    # cannot be spread; the operator has to be told the cost, not overruled.
    check("exitdests: one destination is a WARNING, and the run continues",
          _dests([_EA], 40) != "" )
finally:
    ghost.integrity_log = _ed_saved_il
    if _ed_saved_env is not None:
        os.environ["GS_EXIT_TO"] = _ed_saved_env

# And the exit itself repeats it with the REAL count, so the operator reads it
# while the arrivals are happening.
from srcutil import code_only as _ed_code                       # noqa: E402
_ed_src = " ".join(_ed_code(os.path.join(REPO, "GhostSpiral")).split())
check("exitdests: the exit re-states it with the real numbers",
      "if total > len(dest_pool):" in _ed_src
      and "outputs_exceed_destinations" in _ed_src)
# EARLY, or it is useless: nothing can add a destination once the exit starts.
#
# AST over main()'s own body, NOT a substring search. The first draft compared
# source .index() positions and went red on correct code, because
# "resolve_exit_destinations(args)" matches its own `def` line hundreds of
# lines above the call -- the same definition-matches-the-needle trap that let
# an earlier check in this session pass while the call site was reverted.
import ast as _ed_ast                                           # noqa: E402

_ed_tree = _ed_ast.parse(open(os.path.join(REPO, "GhostSpiral")).read())
_ed_main = [n for n in _ed_ast.walk(_ed_tree)
            if isinstance(n, _ed_ast.FunctionDef) and n.name == "main"][0]
_ed_calls = {}
for _n in _ed_ast.walk(_ed_main):
    if isinstance(_n, _ed_ast.Call):
        _fn = getattr(_n.func, "id", None)
        if _fn in ("resolve_exit_destinations", "stage0_preflight",
                   "_stage5_run") and _fn not in _ed_calls:
            _ed_calls[_fn] = _n.lineno
check("exitdests: main() actually calls all three",
      len(_ed_calls) == 3)
check("exitdests: the warning is raised before stage 0, while it is still "
      "actionable",
      _ed_calls.get("resolve_exit_destinations", 10**9)
      < _ed_calls.get("stage0_preflight", 0))
check("exitdests: ...and long before anything is spent",
      _ed_calls.get("resolve_exit_destinations", 10**9)
      < _ed_calls.get("_stage5_run", 0))


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
