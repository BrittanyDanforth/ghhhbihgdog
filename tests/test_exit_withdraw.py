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
import importlib.machinery, importlib.util, io, os, sys, contextlib, types

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
        relayed, failed, skipped, held = ghost._run_exit_withdrawals(
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
        _r2, _f2, _s2, _h2 = ghost._run_exit_withdrawals(
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
# --no-entry-veil spends the swap's output in the open by the operator's own
# explicit choice, announced at stage 4. Holding funds back there buys nothing
# and only strands them.
check("hold: nothing is held under --no-entry-veil",
      ghost._exit_hold_list(types.SimpleNamespace(entry_veil=False),
                            _ai, "ENTRYADDR") == [])
check("hold: an ENTRY that is not in addr_index holds nothing (no crash)",
      ghost._exit_hold_list(types.SimpleNamespace(entry_veil=True),
                            _ai, "unknown") == [])

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
