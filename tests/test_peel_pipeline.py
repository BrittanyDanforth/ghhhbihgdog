#!/usr/bin/env python3
"""THE PEELING CHAIN, THE DAG ROUND AND THE EXIT, DRIVEN THROUGH main().

test_split_pipeline drives --split 3 with the FAN-OUT, stubs the change sweeps
and never reaches the exit. Nothing drove a --peel run at all past the planner:
_run_peel_chain has its own orchestration test, build_peel_plan has unit tests,
_run_exit_withdrawals has a wallet model -- and the three had never been run
against each other by the function that ties them together.

What that gap hid, found by writing this file: a peeling chain that stops
part-way leaves EVERYTHING it had left on one carrier (each peel consumes its
carrier exactly and pays the rest forward), and the exit swept that carrier to
--exit-to and printed EXIT COMPLETE. Measured here at 9.62 of 12 XMR, to the
same address as the mixed outputs -- so whoever watches that address gets the
unmixed 80% and the mixed remainder as one owner's. _run_peel_chain had already
told the operator that balance was "safe on this wallet ... distribute it
manually".

The wallet below MOVES MONEY: a round's transactions are all built against the
balances at the START of the round and then applied together, which is what
monerod does. Applying them one after another -- so a hop's destination is
already credited when its own hop is built -- makes the merge invariant
untestable, because every path looks safe.

A FAN-OUT CONTROL runs at the end, for two reasons. It is the only place the
change sweep and the exit have ever run against each other through main()
(test_split_pipeline stubs _run_change_sweeps and never reaches the exit), and
it is what makes the peel assertions above mean something: an invariant that
only holds in one mode is an accident of that mode.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile

from decimal import Decimal as D

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from srcutil import fail_loudly_on_crash                    # noqa: E402

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


# A CRASH IS NOT A CATCH. mutation_sweep scores a suite by parsing its RESULT
# line, so a mutation that makes this file DIE is recorded as a SURVIVOR --
# and this file indexes into lists a mutation can empty (the fan-out plan, the
# change sweeps). Verified: dropping the change-sweep destination from
# addr_index made the shipped code raise, and this died on _sweeps[0] with
# three checks already red and no RESULT line at all.
_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_peel_pipeline.py")

ld = importlib.machinery.SourceFileLoader("GhostSpiral",
                                          os.path.join(REPO, "GhostSpiral"))
g = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
ld.exec_module(g)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def addr(seed):
    return "4" + B58[seed % 2] + "".join(
        B58[(seed * (i + 7) + i) % len(B58)] for i in range(93))


WALLETS = 6
FEE = 2_400_000_000                 # 0.0024 XMR, the fee the plan is priced at
ENTRY_ATOMIC = 12 * 10 ** 12
EXIT_ADDR = addr(9999)


class Run:
    """One driven pipeline: its wallet, its rounds and what they moved."""

    def __init__(self, stop_at_peel=None, peel=True):
        self.subs = [addr(2000 + i) for i in range(WALLETS + 4)]
        self.idx = {a: (30 + i, 1) for i, a in enumerate(self.subs)}
        self.bal = {}                    # (acct, sub) -> atomic
        self.addr_of = dict(self.idx)    # address -> (acct, sub)
        self.minted = []
        self.rounds = []                 # (label, [tx])
        self.spent = {}                  # (acct, sub) -> what a round spent
        self.left_wallet = 0             # atomic that reached EXIT_ADDR
        self.stop_at_peel = stop_at_peel
        self.peel = peel
        self.carrier_waits = []
        self.acct = 200

    # -- the wallet ------------------------------------------------------
    def pair_of(self, a):
        return self.addr_of.get(a)

    def rpc(self):
        run = self

        class RPC:
            def raw_request(self, m, p=None):
                if m == "refresh":
                    return {}
                if m == "get_balance":
                    a = int((p or {}).get("account_index", 0))
                    ix = (p or {}).get("address_indices")
                    if ix is None:
                        return {"per_subaddress": [
                            {"account_index": a, "address_index": i,
                             "balance": v, "unlocked_balance": v}
                            for (aa, i), v in sorted(run.bal.items())
                            if aa == a and v > 0]}
                    return {"per_subaddress": [
                        {"account_index": a, "address_index": i,
                         "balance": run.bal.get((a, i), 0),
                         "unlocked_balance": run.bal.get((a, i), 0)}
                        for i in ix]}
                if m == "get_address":
                    a = int((p or {}).get("account_index", 0))
                    for ad, (ac, ii) in run.addr_of.items():
                        if ac == a:
                            return {"addresses": [{"address": ad,
                                                   "address_index": ii}]}
                    return {"addresses": [{"address": addr(7000 + a),
                                           "address_index": 1}]}
                if m == "create_account":
                    run.acct += 1
                    run.minted.append(run.acct)
                    return {"account_index": run.acct}
                if m == "incoming_transfers":
                    return {"transfers": [{"amount": 10 ** 12, "spent": False}]}
                raise AssertionError("unexpected RPC: " + m)

            def get_subaddress_balance(self, account_index=0, address_index=0):
                v = run.bal.get((int(account_index), int(address_index)), 0)
                return (v, v)

            def new_subaddress_indexed(self, account_index=0, label=""):
                a = addr(7000 + int(account_index))
                run.addr_of[a] = (int(account_index), 1)
                return (a, 1)

        return RPC()

    # -- a round, applied the way monerod applies one --------------------
    def run_round(self, args, path, stage, label, wipe=True):
        d = json.loads(open(path).read())
        txs = d.get("txs", [])
        meta = d.get("meta", {})
        self.rounds.append((label, txs))
        snap = dict(self.bal)
        delta = {}

        def credit(pair, amt):
            if pair:
                delta[pair] = delta.get(pair, 0) + amt
            elif amt > 0:
                # Not one of this wallet's addresses: it left.
                self.left_wallet += amt

        for t in txs:
            src = (int(t.get("account_index", meta.get("account_index", 0))),
                   int(t["src_index"]))
            have = snap.get(src, 0)
            self.spent[src] = have
            if have <= 0:
                raise SystemExit(f"[!] {label}: no unlocked balance on {src}")
            if t.get("sweep"):
                credit(src, -have)
                credit(self.pair_of(t["dst"]), max(0, have - FEE))
            else:
                paid = 0
                for de in (t.get("destinations") or []):
                    amt = int(D(str(de["amount"])) * 10 ** 12)
                    paid += amt
                    credit(self.pair_of(de["address"]), amt)
                if t.get("consume_to"):
                    fwd = have - paid - FEE
                    if fwd < 0:
                        raise SystemExit(
                            f"[!] {label}: not enough money on {src} "
                            f"(have {have}, pay {paid}, fee {FEE})")
                    credit(self.pair_of(t["consume_to"]), fwd)
                    credit(src, -have)
                else:
                    left = have - paid - FEE
                    if left < 0:
                        raise SystemExit(f"[!] {label}: not enough money on {src}")
                    credit(src, -have)
                    credit((src[0], 0), left)
        for k, v in delta.items():
            self.bal[k] = self.bal.get(k, 0) + v
        return len(txs)

    def wait_for_carrier(self, args, account, sub_idx, need, proxy, label):
        self.carrier_waits.append(str(label))
        if self.stop_at_peel is None:
            return True
        return not str(label).startswith(f"peel {self.stop_at_peel}/")

    # -- drive it --------------------------------------------------------
    def go(self):
        outdir = tempfile.mkdtemp(prefix="peelpipe_")

        def create_subs(rpc, wallets, decoys):
            for a, pr in self.idx.items():
                self.addr_of[a] = pr
            return (list(self.subs), dict(self.idx), set())

        def create_entry_set(rpc, n):
            out = []
            for i in range(n):
                acct = g.create_fresh_account(rpc, label="")
                a, ix = rpc.new_subaddress_indexed(account_index=acct, label="")
                self.addr_of[a] = (acct, ix)
                self.bal[(acct, ix)] = ENTRY_ATOMIC // n
                out.append((a, acct, ix))
            return out

        stubs = dict(
            verify_tor=lambda *a, **k: None,
            require_resources=lambda *a, **k: None,
            check_daemon_relay_egress=lambda *a, **k: {
                "verdict": "tor", "onion": 4, "clear": 0, "detail": "ok"},
            connect_rpc=lambda *a, **k: self.rpc(),
            stage0_preflight=lambda *a, **k: (self.rpc(), self.rpc(), D("0.0024")),
            stage1_joinmarket=lambda *a, **k: [],
            resolve_mix_account=lambda *a, **k: None,
            create_subs=create_subs,
            create_entry_set=create_entry_set,
            newnym=lambda *a, **k: None,
            tor_recheck=lambda *a, **k: None,
            relay_gates=lambda *a, **k: None,
            validate_xmr_address=lambda *a, **k: None,
            resolve_wallet_password=lambda *a, **k: None,
            resolve_sensitive_inputs=lambda *a, **k: None,
            integrity_log=lambda *a, **k: None,
            integrity_log_once=lambda *a, **k: None,
            secure_delay=lambda *a, **k: None,
            reject_self_exit=lambda *a, **k: None,
            _run_round=self.run_round,
            _wait_for_carrier=self.wait_for_carrier,
            _wait_for_fanout_confirm=lambda *a, **k: True,
            _wait_for_change_settled=lambda a, ac, sb, px, lb: (
                True, self.bal.get((ac, sb), 0)),
            _change_residue=lambda a, ac, sb: self.bal.get((ac, sb), 0),
            report_completion=lambda *a, **k: None,
            safe_post=lambda url, payload, proxy: {"routes": [{
                "expectedBuyAmount": "12.0",
                "memo": "=:XMR.XMR:" + payload["destinationAddress"] + ":0/1/0::0",
                "targetAddress": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}]},
            btc_per_xmr_oracle=lambda *a, **k: None,
            wait_for_swap_arrival=lambda fn, floor_, n: dict(
                zip(("state", "total", "unlocked"), ("funded",) + fn())),
        )
        saved = {k: getattr(g, k) for k in stubs}

        @contextlib.contextmanager
        def nolock(*a, **k):
            yield None

        saved["run_lock"] = g.run_lock
        out = io.StringIO()
        try:
            for k, v in stubs.items():
                setattr(g, k, v)
            g.run_lock = nolock
            sys.argv = (["GhostSpiral",
                         "--btc-entry",
                         "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                         "--btc-amount", "0.6", "--wallets", str(WALLETS)]
                        + (["--peel"] if self.peel else [])
                        + ["--dag-mixing", "--hop-delay", "0-0",
                           "--exit-to", EXIT_ADDR, "--output", outdir,
                           "--tor-proxy", "socks5h://127.0.0.1:9050"])
            with contextlib.redirect_stdout(out):
                g.main()
            self.outcome = "returned"
        except SystemExit as e:
            self.outcome = "SystemExit: " + str(e.code)[:300]
        except Exception as e:                               # noqa: BLE001
            self.outcome = f"CRASHED {type(e).__name__}: {e}"
        finally:
            for k, v in saved.items():
                setattr(g, k, v)
        self.text = out.getvalue()
        return self

    # -- what the plans it produced actually say -------------------------
    def by_label(self, prefix):
        return [(l, txs) for l, txs in self.rounds if l.startswith(prefix)]

    @property
    def peels(self):
        return [t for _l, txs in self.by_label("Peel") for t in txs]

    @property
    def dag(self):
        return [t for _l, txs in self.by_label("DAG") for t in txs]

    @property
    def exits(self):
        return [t for _l, txs in self.by_label("Exit") for t in txs]

    def merges(self):
        """Addresses ending the DAG round holding TWO outputs.

        One if it receives two hops; one if it holds its own distribution
        output and does not sweep it away. Either is a subaddress the exit
        would spend in ONE multi-input transaction.
        """
        dsts = [t["dst"] for t in self.dag]
        srcs = {t["src"] for t in self.dag}
        funded = {t["dst"] for t in self.peels}
        return sorted({d for d in dsts
                       if dsts.count(d) > 1 or (d in funded and d not in srcs)})


# ===========================================================================
print("== a complete --peel --dag-mixing --exit-to run, end to end ==")
full = Run().go()
check(f"the whole pipeline RUNS ({full.outcome})", full.outcome == "returned")
check("one veil, then one confirmation-gated round per peel",
      len(full.by_label("Entry veil")) == 1
      and len(full.by_label("Peel")) == len(full.peels))
check("every peel is ONE transaction with ONE fixed destination",
      all(len(t.get("destinations") or []) <= 1 for t in full.peels))
check("...every peel but the last consumes its carrier exactly (no change)",
      all(t.get("consume_to") for t in full.peels[:-1]))
check("...and the last is a sweep, which is genuinely zero-change",
      bool(full.peels) and full.peels[-1].get("sweep") is True)
check("...so no peel ever spends subaddress 0",
      all(int(t["src_index"]) != 0 for t in full.peels))
check("no carrier is spent twice — the rotation, checked on the real plan",
      len({(t["account_index"], t["src_index"]) for t in full.peels})
      == len(full.peels))

check(f"the DAG round hops every mix output ({len(full.dag)} of "
      f"{len(full.peels)})", len(full.dag) == len(full.peels))
check("no address ends the DAG round holding TWO outputs",
      full.merges() == [])
check("...and no two hops share a destination",
      len({t["dst"] for t in full.dag}) == len(full.dag))

check(f"the exit spends every funded subaddress in its OWN transaction "
      f"({len(full.exits)})",
      len(full.exits) == len(full.dag)
      and all(len(txs) == 1 for _l, txs in full.by_label("Exit")))
check("...never two subaddresses in one transaction",
      len({(t["account_index"], t["src_index"]) for t in full.exits})
      == len(full.exits))
check("...and the wallet is EMPTY afterwards",
      not [v for v in full.bal.values() if v > 0])
check("...with the run saying so", "EXIT COMPLETE" in full.text)
# Conservation: everything that arrived either left for --exit-to or paid a fee.
_fees = FEE * (len(full.peels) + len(full.dag) + len(full.exits) + 1)
check(f"value is conserved: {full.left_wallet / 10**12:.4f} XMR out + fees "
      f"== {ENTRY_ATOMIC / 10**12} XMR in",
      full.left_wallet + _fees == ENTRY_ATOMIC)


# ===========================================================================
print("\n== a chain that STOPS PART-WAY ==")
part = Run(stop_at_peel=4).go()
check(f"the run still finishes instead of dying mid-flight ({part.outcome})",
      part.outcome == "returned")
check("the chain stopped where the carrier did", len(part.peels) == 3)
check("...and the operator is told which peel it stopped at",
      "Peeling chain stopped at 3/" in part.text)

# THE DAG ROUND. Its plan was built for every peel; the ones whose source the
# chain never funded cannot be built ("no unlocked balance") and phase_create
# exits 1 on any tx in a batch, which would take the run down AFTER the peels
# were on-chain and BEFORE the exit.
check(f"the DAG round is trimmed to the hops the chain actually funded "
      f"({len(part.dag)} of {len(part.peels)} funded outputs)",
      len(part.dag) == len(part.peels))
check("...and says how many it removed",
      "planned hop(s) would have swept a mix subaddress the distribution "
      "never reached" in part.text)
check("...without creating the merge the trim could have introduced",
      part.merges() == [])
check("...and every hop it kept has a source the chain really paid",
      {t["src"] for t in part.dag} <= {t["dst"] for t in part.peels})

# THE REMAINDER. Every peel consumes its carrier exactly and pays the rest
# forward, so the whole undistributed balance is on the carrier the next peel
# would have spent.
_left = {k: v for k, v in part.bal.items() if v > 0}
check(f"the undistributed balance is still on the wallet, on ONE carrier "
      f"({[f'{v/10**12:.2f} XMR' for v in _left.values()]})",
      len(_left) == 1)
check("...and it is most of the run — this is not rounding dust",
      sum(_left.values()) > ENTRY_ATOMIC // 2)
check("...the exit did NOT sweep it to --exit-to",
      all((t["account_index"], t["src_index"]) not in _left
          for t in part.exits))
check("...it is named as the peel chain's UNDISTRIBUTED balance, not as a "
      "distribution CHANGE (whose remedy is a change sweep this mode never "
      "runs) and not as the swap ENTRY",
      "UNDISTRIBUTED balance" in part.text
      and "distribution CHANGE address" not in part.text
      and "swap ENTRY address" not in part.text)
check("...and the run does NOT announce a clean exit over it",
      "EXIT COMPLETE" not in part.text)
check("...while every MIXED output still left",
      len(part.exits) == len(part.dag))



# ===========================================================================
print("\n== the FAN-OUT control: the change sweep and the exit, together ==")
fan = Run(peel=False).go()
check(f"a fan-out run finishes too ({fan.outcome})", fan.outcome == "returned")
_fanouts = [t for _l, txs in fan.by_label("Fan-out") for t in txs]
_sweeps = [t for _l, txs in fan.by_label("Change sweep") for t in txs]
check("ONE fan-out transaction creates every mix output",
      len(_fanouts) == 1
      and len(_fanouts[0].get("destinations") or []) > 1)
check("...and its unallocated remainder is swept, in its own transaction",
      len(_sweeps) == 1 and _sweeps[0].get("sweep") is True)
check("...from the SPENDING account's subaddress 0, which is where monerod "
      "puts change",
      bool(_sweeps) and int(_sweeps[0]["src_index"]) == 0)
check("no address ends the DAG round holding TWO outputs here either",
      fan.merges() == [])

# THE POINT OF THIS CONTROL. _stage5_run REPLACES its landing list with the
# DAG round's destinations, which drops the change-sweep destinations it had
# accumulated -- so the exit has to find that address by enumeration, not by
# having been told about it. If it does not, the swept change is left on the
# wallet while the run reports a clean exit.
_swept_to = {fan.pair_of(t["dst"]) for t in _sweeps} - {None}
_taken = {(t["account_index"], t["src_index"]) for t in fan.exits}
check("the exit finds and withdraws the SWEPT CHANGE, which the landing gate "
      "no longer names by the time the exit runs",
      bool(_swept_to) and _swept_to <= _taken)
check(f"...so the exit is mix outputs PLUS the swept change "
      f"({len(fan.exits)} = {len(fan.dag)} + {len(_swept_to)})",
      len(fan.exits) == len(fan.dag) + len(_swept_to))
check("...the wallet is empty afterwards",
      not [v for v in fan.bal.values() if v > 0])
_ffees = FEE * (len(_fanouts) + len(_sweeps) + len(fan.dag) + len(fan.exits) + 1)
check(f"...and value is conserved: {fan.left_wallet / 10**12:.4f} XMR out + "
      f"fees == {ENTRY_ATOMIC / 10**12} XMR in",
      fan.left_wallet + _ffees == ENTRY_ATOMIC)


_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
