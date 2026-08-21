#!/usr/bin/env python3
"""The exit must not read a wallet that is still moving.

_run_exit_withdrawals enumerates the funded subaddresses ONCE and withdraws
exactly what that snapshot contained. It runs seconds after the last round
relayed, and monero-wallet-rpc does not know about a txpool payment to itself
until it scans the pool -- which its server does on a 20-second period, while
commit_tx marks the SOURCE spent the instant a round returns. For up to twenty
seconds the value is, as far as the wallet is concerned, in neither place.

An output missing from that snapshot is never withdrawn and never mentioned:
the caller's only clean-exit line said "Nothing left on this run's accounts".
Measured against a wallet modelled on those rules, ten hop destinations of
0.3 XMR: the last hop was stranded in ~half of 200 runs at --wallets 10 and
--wallets 20, and every one of them printed the clean-exit line.

Three things now stand between that and an operator:

  1. _funded_subaddresses forces a `refresh` before reading, like every other
     balance reader in the file already did;
  2. _stage5_run gates the exit on the last round's destinations being
     confirmed AND unlocked -- the same primitive that stops the DAG round
     being created before the distribution unlocks;
  3. the exit re-reads the wallet after its withdrawals and takes whatever
     appeared, so a late arrival is withdrawn rather than covered by a claim.

Everything here drives the real functions against a wallet model. Nothing at
the level being tested is stubbed.
"""
import ast
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

AUTO_REFRESH = 20          # wallet_rpc_server's DEFAULT_AUTO_REFRESH_PERIOD
UNLOCK_SECS = 20 * 60      # ~10 blocks
AMT = 300_000_000_000      # 0.3 XMR


def load(name, path):
    ld = importlib.machinery.SourceFileLoader(name, path)
    sp = importlib.util.spec_from_loader(name, ld)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


ghost = load("ghost", os.path.join(REPO, "GhostSpiral"))

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


# ---------------------------------------------------------------------------
#  A wallet that behaves the way monero-wallet-rpc actually behaves
# ---------------------------------------------------------------------------
class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += float(s)


class Wallet:
    """`true` is the chain and the pool; `seen` is what this wallet scanned."""

    def __init__(self, clock, pool_lag=0.0):
        self.clock = clock
        self.pool_lag = pool_lag
        self.true = {}
        self.seen = {}
        self.last_scan = -10 ** 9
        self.calls = []
        # Outputs that are VISIBLE but never become spendable. Real cause: a
        # long lock, or a chain that stops advancing. The settle wait must time
        # out on them, and the re-read must not start that hour again.
        self.never = set()

    def credit(self, acct, idx, amt, arrived_at):
        self.true[(acct, idx)] = [amt, arrived_at]

    def scan(self):
        self.last_scan = self.clock.t
        self.seen = {k: v[0] for k, v in self.true.items()
                     if v[1] + self.pool_lag <= self.clock.t}

    def unlocked(self, key):
        if key in self.never or not self.seen.get(key):
            return 0
        amt, arrived = self.true.get(key, (0, 0))
        return amt if self.clock.t - arrived >= UNLOCK_SECS else 0


class FakeRPC:
    def __init__(self, w):
        self.w = w

    def raw_request(self, method, params):
        self.w.calls.append(method)
        if method == "refresh":
            self.w.scan()
            return {}
        # The server's own periodic refresh, which is the ONLY thing that used
        # to make the exit work by accident.
        if self.w.clock.t - self.w.last_scan >= AUTO_REFRESH:
            self.w.scan()
        if method == "get_balance":
            acct = int(params.get("account_index", 0))
            want = params.get("address_indices")
            out = []
            for (a, i), amt in sorted(self.w.seen.items()):
                if a != acct or (want is not None and i not in want):
                    continue
                out.append({"address_index": i, "balance": amt,
                            "unlocked_balance": self.w.unlocked((a, i))})
            if want is not None and not out:
                out = [{"address_index": want[0], "balance": 0,
                        "unlocked_balance": 0}]
            return {"per_subaddress": out}
        return {}

    def get_subaddress_balance(self, account_index=0, address_index=0):
        r = self.raw_request("get_balance",
                             {"account_index": account_index,
                              "address_indices": [address_index]})
        p = r["per_subaddress"][0]
        return int(p["balance"]), int(p["unlocked_balance"])


class Args:
    rpc_primary = "http://127.0.0.1:18083/json_rpc"
    tor_proxy = ""
    rpc_daemon = ""
    fee_priority = 1
    output = "/tmp/gs-exit-landing"
    wallet_password = ""
    wallet_file = "w"
    allow_clearnet_relay = False
    exit_to = ["8" + "A" * 94]
    dag_mixing = True


@contextlib.contextmanager
def driven(w, clock, on_round=None):
    """Replace only the process boundaries: subprocesses, Tor, sleeping."""
    def _round(args, plan_file, staging_dir, label, wipe=True):
        tx = json.loads(Path(plan_file).read_text())["txs"][0]
        key = (int(tx["account_index"]), int(tx["src_index"]))
        if w.unlocked(key) <= 0:
            raise SystemExit("no unlocked balance in the specified subaddress")
        w.true[key] = [0, clock.t]
        if on_round:
            on_round(len([c for c in w.calls if c == "__round"]))
        w.calls.append("__round")
        w.scan()

    saved = {}
    for nm, val in [("_run_round", _round),
                    ("newnym", lambda *a, **k: None),
                    ("tor_recheck", lambda *a, **k: None),
                    ("secure_delay", lambda a=0, b=0: clock.sleep((a + b) / 2)),
                    ("hop_delay", lambda *a, **k: 0),
                    ("secure_delete_or_warn", lambda *a, **k: True),
                    ("secure_delete_tree", lambda *a, **k: True),
                    ("integrity_log", lambda *a, **k: None),
                    ("integrity_log_once", lambda *a, **k: None),
                    ("connect_rpc", lambda *a, **k: FakeRPC(w)),
                    ("shutdown_requested", lambda: False)]:
        saved[nm] = getattr(ghost, nm)
        setattr(ghost, nm, val)
    saved["__sleep"] = ghost.time.sleep
    ghost.time.sleep = clock.sleep
    try:
        yield
    finally:
        for nm, val in saved.items():
            if nm == "__sleep":
                ghost.time.sleep = val
            else:
                setattr(ghost, nm, val)


STAGE = os.path.join(tempfile.mkdtemp(prefix="exitland_"), "tx_staging")
Path(STAGE).mkdir(parents=True, exist_ok=True)
META = {"fee_per_round": "0.0024", "account_index": 10}


def exit_run(n, stale_last, scan_lag=12.0, submitted_ago=2.0, pool_lag=0.0,
             gate=False, on_round=None, extra_accounts=()):
    clock = Clock()
    w = Wallet(clock, pool_lag=pool_lag)
    for i in range(n):
        arrived = (-submitted_ago if i >= n - stale_last
                   else -(UNLOCK_SECS + 600))
        w.credit(10 + i, 1, AMT, arrived)
    w.last_scan = -scan_lag
    w.seen = {k: v[0] for k, v in w.true.items()
              if v[1] + pool_lag <= -scan_lag}
    accounts = [10 + i for i in range(n)] + list(extra_accounts)
    buf = io.StringIO()
    with driven(w, clock, on_round=on_round):
        with contextlib.redirect_stdout(buf):
            if gate:
                ghost._wait_for_fanout_confirm(
                    Args(), [(10 + i, 1) for i in range(n)], None,
                    what="last round's")
            res = ghost._run_exit_withdrawals(
                Args(), accounts, Args.exit_to, STAGE, None, META, None,
                hold=(), entry_pairs=())
    relayed, failed, skipped, held, unclean = res
    return {"relayed": relayed, "failed": failed, "unclean": unclean,
            "left": sum(v[0] for v in w.true.values()),
            "out": buf.getvalue(), "wallet": w, "clock": clock}


print("\n== the enumeration forces a sync before it reads ==")

# The whole defect in one assertion: the last hop is in the pool, the wallet
# scanned before it arrived, and the exit must still find it.
r = exit_run(10, 1)
check("the hop relayed seconds ago is enumerated and withdrawn",
      r["relayed"] == 10 and r["left"] == 0)
check("...so nothing is left behind", r["left"] == 0)
check("...and the run's own clean-exit line is therefore true",
      "EXIT COMPLETE" in r["out"] or r["relayed"] == 10)

r2 = exit_run(10, 10)
check("a wallet that had scanned NONE of the round still yields every output",
      r2["relayed"] == 10 and r2["left"] == 0)

# Order matters: a refresh AFTER the balance read is no refresh at all.
_w = Wallet(Clock())
_w.credit(7, 1, AMT, -(UNLOCK_SECS + 600))
_w.last_scan = -1.0
_w.seen = {}
_found, _unread = ghost._funded_subaddresses(FakeRPC(_w), [7])
check("_funded_subaddresses issues `refresh` BEFORE its first get_balance",
      _w.calls and _w.calls[0] == "refresh"
      and "get_balance" in _w.calls
      and _w.calls.index("refresh") < _w.calls.index("get_balance"))
check("...and therefore returns the output the stale view was missing",
      [(a, i) for a, i, _ in _found] == [(7, 1)])


print("\n== the exit re-reads afterwards instead of asserting ==")

# 0.3 XMR arrives on account 99 while the third withdrawal is running -- a late
# swap chunk, or a hop confirming during another output's --hop-delay.
def _late(nth):
    if nth == 2:
        _late.w.credit(99, 1, AMT, _late.w.clock.t - (UNLOCK_SECS + 60))


class _Holder:
    pass


_late.w = None


def run_with_late():
    clock = Clock()
    w = Wallet(clock)
    for i in range(6):
        w.credit(10 + i, 1, AMT, -(UNLOCK_SECS + 600))
    w.scan()
    _late.w = w
    _late.w.clock = clock
    buf = io.StringIO()
    with driven(w, clock, on_round=_late):
        with contextlib.redirect_stdout(buf):
            res = ghost._run_exit_withdrawals(
                Args(), [10 + i for i in range(6)] + [99], Args.exit_to, STAGE,
                None, META, None, hold=(), entry_pairs=())
    return res, sum(v[0] for v in w.true.values()), buf.getvalue()


_res, _left, _txt = run_with_late()
check("an output that appears DURING the exit is withdrawn, not left",
      _res[0] == 7 and _left == 0)
check("...and the operator is told a re-read found it",
      "are funded now that were not" in _txt)

# The re-read must not sweep an address the first pass already emptied, and it
# must not re-attempt one it already reported as failed.
_ac = [t for t in _txt.split("\n") if "emptied" in t]
check("no address is withdrawn twice (one 'emptied' line per output)",
      len(_ac) == 7)

# AN OUTPUT THAT FAILED IS NOT RETRIED BY THE RE-READ.
#
# A settle timeout leaves the output funded, so a straggler pass that did not
# remember what it had already tried would enumerate it again -- another full
# FANOUT_CONFIRM_TIMEOUT of polling the same address, and a second `failed`
# for one output, so the run reports more failures than it has outputs.
_fclock = Clock()
_fw = Wallet(_fclock)
_fw.credit(10, 1, AMT, -(UNLOCK_SECS + 600))        # settles
_fw.credit(11, 1, AMT, -(UNLOCK_SECS + 600))
_fw.never.add((11, 1))                              # visible, never spendable
_fw.scan()                                          # both VISIBLE
_settles = []
_real_settle = ghost._wait_for_change_settled


def _count_settle(args, account, sub, proxy, label):
    _settles.append((account, sub))
    return _real_settle(args, account, sub, proxy, label)


_fbuf = io.StringIO()
_saved_settle = ghost._wait_for_change_settled
try:
    ghost._wait_for_change_settled = _count_settle
    with driven(_fw, _fclock):
        # driven() replaces connect_rpc, which the real settle wait uses.
        with contextlib.redirect_stdout(_fbuf):
            _fres = ghost._run_exit_withdrawals(
                Args(), [10, 11], Args.exit_to, STAGE, None, META, None,
                hold=(), entry_pairs=())
finally:
    ghost._wait_for_change_settled = _saved_settle
check("an output that never settles is attempted exactly ONCE",
      _settles.count((11, 1)) == 1)
check("...and is counted as one failure, not one per pass",
      _fres[1] == 1)
check("...while the output that did settle was still withdrawn",
      _fres[0] == 1 and _fw.true[(10, 1)][0] == 0)

# A HELD address stays held on the re-read too -- otherwise the straggler pass
# would sweep ENTRY to --exit-to, which is the link the hold exists to refuse.
_hclock = Clock()
_hw = Wallet(_hclock)
_hw.credit(10, 1, AMT, -(UNLOCK_SECS + 600))
_hw.credit(55, 1, AMT, -(UNLOCK_SECS + 600))
_hw.scan()
_hbuf = io.StringIO()
with driven(_hw, _hclock):
    with contextlib.redirect_stdout(_hbuf):
        _hres = ghost._run_exit_withdrawals(
            Args(), [10, 55], Args.exit_to, STAGE, None, META, None,
            hold=[(55, 1)], entry_pairs=[(55, 1)])
check("the straggler pass still refuses a HELD address",
      _hw.true[(55, 1)][0] == AMT and _hres[0] == 1)
check("...and reports it as ENTRY, once", _hres[3]["entry"] == 1)


# A LATE SWAP CHUNK LANDING ON ENTRY, mid-exit. _exit_hold_list exists for
# exactly this. The initial enumeration cannot have seen it, so before the
# re-read nothing named it -- an unmixed balance on the address a public
# ThorChain memo points at, and not one line about it.
_lclock = Clock()
_lw = Wallet(_lclock)
for _i in range(4):
    _lw.credit(10 + _i, 1, AMT, -(UNLOCK_SECS + 600))
_lw.scan()


def _entry_lands(nth):
    if nth == 1:
        _lw.credit(55, 1, AMT, _lclock.t - (UNLOCK_SECS + 60))


_lbuf = io.StringIO()
with driven(_lw, _lclock, on_round=_entry_lands):
    with contextlib.redirect_stdout(_lbuf):
        _lres = ghost._run_exit_withdrawals(
            Args(), [10, 11, 12, 13, 55], Args.exit_to, STAGE, None, META,
            None, hold=[(55, 1)], entry_pairs=[(55, 1)])
_ltxt = _lbuf.getvalue()
check("a HELD address funded during the exit is not swept to --exit-to",
      _lw.true[(55, 1)][0] == AMT)
check("...and it is reported, with the account and subaddress",
      "account 55 / subaddr 1" in _ltxt and "while this exit was running" in _ltxt)
check("...named as ENTRY, because that is what the memo points at",
      "swap ENTRY" in _ltxt.split("while this exit was running")[0][-400:])
check("...and counted, so the caller words its report from a number",
      _lres[3]["entry"] == 1)
check("...while the four ordinary outputs still left", _lres[0] == 4)


print("\n== the pipeline gates the exit on the last round landing ==")

# _stage5_run must call the wait with the DAG round's DESTINATIONS, and must
# call it BEFORE the exit reads the wallet.
_calls = []


def _record_wait(args, targets, proxy, what="fan-out"):
    _calls.append(("wait", tuple(targets), what))
    return True


def _record_exit(*a, **k):
    _calls.append(("exit", tuple(a[1] or ())))
    return (0, 0, 0, {"entry": 0, "change": 0}, 0)


_tmp = Path(tempfile.mkdtemp(prefix="s5land_"))
_fan = _tmp / "fanout.json"
_fan.write_text(json.dumps({"meta": META, "txs": []}))
_dag = _tmp / "dag.json"
_dag.write_text(json.dumps({"meta": META, "txs": []}))

_saved = (ghost._run_round, ghost._run_peel_chain, ghost._run_change_sweeps,
          ghost._wait_for_fanout_confirm, ghost._run_exit_withdrawals,
          ghost.integrity_log, ghost.newnym, ghost.tor_recheck,
          ghost.secure_delay)
try:
    ghost._run_round = lambda *a, **k: 1
    ghost._run_peel_chain = lambda *a, **k: 3
    ghost._run_change_sweeps = lambda *a, **k: 0
    ghost._wait_for_fanout_confirm = _record_wait
    ghost._run_exit_withdrawals = _record_exit
    ghost.integrity_log = lambda *a, **k: None
    ghost.newnym = lambda *a, **k: None
    ghost.tor_recheck = lambda *a, **k: None
    ghost.secure_delay = lambda *a, **k: None

    # FAN-OUT + DAG: the gate must name the DAG destinations, not the
    # distribution's -- every hop source swept itself empty.
    _calls.clear()
    _dag.write_text(json.dumps({"meta": META, "txs": [
        {"src": "s1", "src_index": 1, "account_index": 1, "dst": "D3",
         "sweep": True},
        {"src": "s2", "src_index": 1, "account_index": 2, "dst": "D4",
         "sweep": True}]}))
    _DAGIX = {"D3": (3, 1), "D4": (4, 1)}
    with contextlib.redirect_stdout(io.StringIO()):
        ghost._stage5_run(Args(), str(_fan), str(_dag), [(1, 1), (2, 1)],
                          str(_tmp / "stg"), None, Decimal("9"),
                          distribution_mode="fanout", change_target=(4, 0),
                          change_sweep_jobs=[], exit_accounts=[1, 2],
                          dag_dst_index=_DAGIX, sweep_targets=[])
    _kinds = [c[0] for c in _calls]
    check("fan-out+DAG: a wait runs before the exit",
          "wait" in _kinds and "exit" in _kinds
          and _kinds.index("exit") > len(_kinds) - 1 - _kinds[::-1].index("wait"))
    _last_wait = [c for c in _calls if c[0] == "wait"][-1]
    check("...and it waits on the DAG DESTINATIONS, not the hop sources",
          _last_wait[1] == ((3, 1), (4, 1)))
    check("...labelled as the last round, not as the fan-out",
          "fan-out" not in _last_wait[2])
    check("fan-out: the DAG plan is left exactly as it was written",
          len(json.loads(_dag.read_text())["txs"]) == 2)

    # PEEL that stopped at 3 of 8: the gate must not poll the five carriers
    # nobody paid. An hour of polling, then the exit runs anyway.
    _calls.clear()
    _fan.write_text(json.dumps(
        {"meta": META, "txs": [{"src_index": i} for i in range(8)]}))
    _peel_targets = [(20 + i, 1) for i in range(8)]
    with contextlib.redirect_stdout(io.StringIO()):
        ghost._stage5_run(Args(), str(_fan), None, _peel_targets,
                          str(_tmp / "stg2"), None, Decimal("9"),
                          distribution_mode="peel", change_target=(4, 0),
                          change_sweep_jobs=[], exit_accounts=[1],
                          dag_dst_index={}, sweep_targets=[])
    _w2 = [c for c in _calls if c[0] == "wait"]
    check("peel stopped at 3/8: the gate waits on exactly the 3 that relayed",
          _w2 and _w2[-1][1] == tuple(_peel_targets[:3]))

    # ---- a partial peel chain must still get its second mixing round -------
    #
    # The five carriers the chain never reached hold nothing, so the five hops
    # that would sweep them cannot be built. Leaving them in the plan makes
    # phase_create exit 1, which _run_round turns into sys.exit -- the run dies
    # after the peels are on-chain and before the exit. Leaving the WAIT
    # untrimmed costs an hour and then skips the round outright.
    _calls.clear()
    _rounds = []
    ghost._run_round = lambda a, pf, sd, lb, **k: _rounds.append((str(pf), lb))
    _peel8 = [(20 + i, 1) for i in range(8)]
    _dag8 = _tmp / "dag8.json"
    _dag8.write_text(json.dumps({"meta": META, "txs": [
        {"src": f"m{i}", "src_index": 1, "account_index": 20 + i,
         "dst": f"D{(i + 1) % 8}", "sweep": True} for i in range(8)]}))
    _ix8 = {f"D{i}": (20 + i, 1) for i in range(8)}
    with contextlib.redirect_stdout(io.StringIO()):
        ghost._stage5_run(Args(), str(_fan), str(_dag8), _peel8,
                          str(_tmp / "stg2b"), None, Decimal("9"),
                          distribution_mode="peel", change_target=(4, 0),
                          change_sweep_jobs=[], exit_accounts=[1],
                          dag_dst_index=_ix8, sweep_targets=[])
    _kept8 = json.loads(_dag8.read_text())["txs"]
    check("partial peel: the DAG round still RUNS over what was funded",
          any(lb == "DAG" for _pf, lb in _rounds))
    check("...with only the hops whose source the chain actually funded",
          [t["account_index"] for t in _kept8] == [20, 21, 22])
    check("...so no hop is built from a carrier that holds nothing",
          all((t["account_index"], t["src_index"]) in set(_peel8[:3])
              for t in _kept8))
    _w2b = [c for c in _calls if c[0] == "wait"]
    check("...and the pre-round wait polls only those three",
          _w2b and _w2b[0][1] == tuple(_peel8[:3]))
    check("...while the exit's gate names the surviving hops' DESTINATIONS",
          _w2b and _w2b[-1][1] == tuple(_ix8[t["dst"]] for t in _kept8))

    # NO ADDRESS MAY END THE ROUND HOLDING TWO OUTPUTS -- the invariant the
    # whole hop planner exists to keep, re-checked on the FILTERED plan.
    # An address holds its own output only if the distribution funded it, and
    # a funded source's hop is exactly what the filter keeps, so the two can
    # never both be true. Asserted rather than argued.
    _funded8 = {f"m{i}" for i in range(3)}          # peels 0..2 relayed
    _hopped8 = {t["src"] for t in _kept8}
    _holders8 = _funded8 - _hopped8                 # still hold their own
    _receivers8 = {t["dst"] for t in _kept8}
    _srcname = {f"D{i}": f"m{i}" for i in range(8)}
    check("filtered round: nothing that keeps its own output also receives one",
          not {_srcname[d] for d in _receivers8} & _holders8)

    # A chain that relayed NOTHING has no hop to build at all.
    _calls.clear()
    _rounds.clear()
    ghost._run_peel_chain = lambda *a, **k: 0
    _dag0 = _tmp / "dag0.json"
    _dag0.write_text(json.dumps({"meta": META, "txs": [
        {"src": "m0", "src_index": 1, "account_index": 20, "dst": "D1",
         "sweep": True}]}))
    with contextlib.redirect_stdout(io.StringIO()):
        _inc0, _wh0 = ghost._stage5_run(
            Args(), str(_fan), str(_dag0), _peel8, str(_tmp / "stg2c"), None,
            Decimal("9"), distribution_mode="peel", change_target=(4, 0),
            change_sweep_jobs=[], exit_accounts=[1],
            dag_dst_index=_ix8, sweep_targets=[])
    check("a peel chain that relayed nothing does not run a DAG round",
          not any(lb == "DAG" for _pf, lb in _rounds))
    check("...and says the second mixing round did not happen",
          any("second mixing" in m for m in _inc0))
    check("...without an hour of polling first",
          not [c for c in _calls if c[0] == "wait" and c[1]])
    ghost._run_peel_chain = lambda *a, **k: 3
    ghost._run_round = lambda *a, **k: 1

    # A change sweep that FAILED left its destination unfunded; waiting on it
    # is an hour of polling an address nobody paid.
    _calls.clear()
    _fan.write_text(json.dumps({"meta": META, "txs": []}))
    ghost._run_change_sweeps = lambda *a, **k: 1        # one sweep missed
    with contextlib.redirect_stdout(io.StringIO()):
        ghost._stage5_run(Args(), str(_fan), None, [(1, 1)],
                          str(_tmp / "stg3"), None, Decimal("9"),
                          distribution_mode="fanout", change_target=(4, 0),
                          change_sweep_jobs=[(4, 0, "addr", 1)],
                          exit_accounts=[1], dag_dst_index={},
                          sweep_targets=[(77, 1)])
    _w3 = [c for c in _calls if c[0] == "wait"]
    check("a change sweep that failed is not waited on",
          _w3 and (77, 1) not in _w3[-1][1])

    # No --exit-to: nothing is withdrawn, so there is nothing to gate, and an
    # hour of polling would be pure cost.
    _calls.clear()
    ghost._run_change_sweeps = lambda *a, **k: 0

    class _NoExit(Args):
        exit_to = None

    with contextlib.redirect_stdout(io.StringIO()):
        ghost._stage5_run(_NoExit(), str(_fan), None, [(1, 1)],
                          str(_tmp / "stg4"), None, Decimal("9"),
                          distribution_mode="fanout", change_target=(4, 0),
                          change_sweep_jobs=[], exit_accounts=[1],
                          dag_dst_index={}, sweep_targets=[])
    check("without --exit-to there is no landing gate to pay for",
          not [c for c in _calls if c[0] == "wait"])
finally:
    (ghost._run_round, ghost._run_peel_chain, ghost._run_change_sweeps,
     ghost._wait_for_fanout_confirm, ghost._run_exit_withdrawals,
     ghost.integrity_log, ghost.newnym, ghost.tor_recheck,
     ghost.secure_delay) = _saved


print("\n== _landing_targets resolves addresses, and drops what it cannot ==")

_ai = {"dstA": (3, 1), "dstB": (4, 2), "sweepA": (9, 5)}
_dag_t, _sw_t = ghost._landing_targets(
    _ai, [{"dst": "dstA"}, {"dst": "dstB"}, {"dst": "unknown"}],
    [(1, 0, "sweepA", 5), (2, 0, "missing", 7)])
check("hop destinations are resolved through addr_index",
      _dag_t == {"dstA": (3, 1), "dstB": (4, 2)})
check("an unresolvable destination is DROPPED, never guessed",
      "unknown" not in _dag_t and (0, 0) not in _dag_t.values())
# A MAP, because _stage5_run may remove hops before the round runs and then
# has to name what survived. A positional list cannot answer that.
check("...and it is keyed by the destination address the plan entry carries",
      isinstance(_dag_t, dict))
check("a change sweep's destination account comes from addr_index",
      _sw_t == [(9, 5)])
check("...and an unresolvable one is dropped too", len(_sw_t) == 1)
check("empty in, empty out", ghost._landing_targets({}, None, None) == ({}, []))


print("\n== every balance reader still syncs first ==")

# The defect was one reader missing the refresh the others had. Assert the
# property across all of them rather than the one that was wrong.
_src = open(os.path.join(REPO, "GhostSpiral")).read()
_tree = ast.parse(_src)
_READERS = ("_funded_subaddresses", "_wait_for_fanout_confirm",
            "_wait_for_carrier", "_wait_for_change_settled", "_change_residue")
for _fn in _tree.body:
    if not isinstance(_fn, ast.FunctionDef) or _fn.name not in _READERS:
        continue
    _body = ast.get_source_segment(_src, _fn) or ""
    check(f"{_fn.name} forces a refresh before reading a balance",
          'raw_request("refresh"' in _body)

check("the exit's enumeration is not the only reader tested here",
      len(_READERS) == 5)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAIL:
    print("FAILURES: " + ", ".join(FAILS))
    sys.exit(1)
print("ALL GREEN")
