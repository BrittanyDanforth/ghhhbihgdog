#!/usr/bin/env python3
"""Executable tests for receive_watch — the "wait until I'm actually paid" step.

This is the tool that decides an operator is done waiting, so every way it can
lie matters: calling a payment complete that never arrived, calling one
incomplete that did, watching the wrong subaddress, or abandoning a payment
that was merely still confirming. The real shipped functions are driven here
with a fake wallet-rpc and a fake clock; nothing sleeps and nothing connects.
"""
import sys, os, json, tempfile, importlib.util, importlib.machinery, re
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


_scratch = tempfile.mkdtemp(prefix="gs_recvw_")
os.chdir(_scratch)
rw = load("receive_watch")

DEST = "8" + "A" + "1" * 93
OTHER = "8" + "B" + "2" * 93
ATOMIC = 10 ** 12


def write(name, obj):
    p = os.path.join(_scratch, name)
    with open(p, "w") as fh:
        json.dump(obj, fh)
    return p


def bundle(**over):
    d = {"schema": "gs_receive_wallet_v1", "address": DEST,
         "account_index": 0, "subaddress_index": 7,
         "rpc_endpoint": "http://127.0.0.1:18083"}
    d.update(over)
    return d


def pair(dest=DEST, xmr="1.0", btc="0.01"):
    return {"schema": "thor_pairs_v1", "btc_in": btc, "deposit": "bc1qxxx",
            "memo": f"=:XMR.XMR:{dest}", "dest_xmr": dest,
            "expected_xmr": xmr, "ts": 1700000000}


print("=== bundle loading: the address it watches must be the right one ===")

ok = rw.load_receive_bundle(write("good.json", bundle()))
check("bundle: a valid gs_receive_wallet_v1 loads", ok["address"] == DEST)


def rejects(path, frag):
    try:
        rw.load_receive_bundle(path)
        return False
    except Exception as e:
        return frag.lower() in str(e).lower()


check("bundle: wrong schema is rejected",
      rejects(write("s.json", bundle(schema="something_else")), "schema"))
check("bundle: missing address is rejected",
      rejects(write("a.json", {k: v for k, v in bundle().items() if k != "address"}),
              "address"))
# The important one. Defaulting a missing index to 0 would silently watch
# account 0 / subaddress 0 -- the wallet's own primary AND change address --
# and report an unrelated balance as "the payment arrived".
check("bundle: missing subaddress_index is REJECTED, never defaulted to 0",
      rejects(write("i.json", {k: v for k, v in bundle().items()
                               if k != "subaddress_index"}), "subaddress_index"))
check("bundle: a non-object bundle is rejected",
      rejects(write("l.json", [1, 2, 3]), "object"))
check("bundle: a missing file is rejected",
      not os.path.exists("/nope/none.json") and rejects("/nope/none.json", "not found"))

# subaddress_index 0 is legal when explicitly recorded -- only ABSENCE is fatal.
check("bundle: an explicit subaddress_index of 0 is accepted",
      rw.load_receive_bundle(write("z.json", bundle(subaddress_index=0)))
      ["subaddress_index"] == 0)


print("=== pairs: only the swaps routed HERE set the target ===")

pf = write("pairs.json", [pair(DEST, "1.5"), pair(OTHER, "9.0"), pair(DEST, "0.5")])
allp = rw.load_pairs(pf)
mine = rw.pairs_for_dest(allp, DEST)
check("pairs: only pairs whose dest_xmr is this address are kept", len(mine) == 2)
check("pairs: a swap to a DIFFERENT destination never inflates the target",
      rw.expected_total(mine)[0] == Decimal("2.0"))
check("pairs: the other destination's 9.0 XMR is excluded",
      rw.expected_total(allp)[0] != rw.expected_total(mine)[0])
check("pairs: unreadable expected_xmr counts as 0, not a crash",
      rw.expected_total([pair(DEST, "not-a-number"), pair(DEST, "1.0")])[0]
      == Decimal("1.0"))

# ...but it must also SAY it did. A quote it could not read used to vanish into
# a smaller target with no mention: three swaps whose 2nd and 3rd quotes are
# unreadable produced a target of only the first, so the watch reported "PAID"
# and offered to mix once a third of the money had arrived. The count is
# returned so the caller can surface it.
_tot, _bad = rw.expected_total([pair(DEST, "3.0"), pair(DEST, "junk"),
                                pair(DEST, "0")])
check("pairs: the number of unreadable quotes is reported, not swallowed",
      _bad == 2 and _tot == Decimal("3.0"))
check("pairs: a fully readable set reports zero unreadable",
      rw.expected_total(mine)[1] == 0)
# and main() must actually print it. Joined from the AST's string constants,
# because the message is split across f-string continuations -- a literal
# substring search for the sentence fails on the line break, which is how this
# check first went red.
import ast as _ast0
_rw_src = open(os.path.join(REPO, "receive_watch")).read()
_m0 = next(n for n in _ast0.walk(_ast0.parse(_rw_src))
           if isinstance(n, _ast0.FunctionDef) and n.name == "main")
_pr0 = []
for _n0 in _ast0.walk(_m0):
    if (isinstance(_n0, _ast0.Call) and isinstance(_n0.func, _ast0.Name)
            and _n0.func.id == "print"):
        for _a0 in _n0.args:
            _pr0.append("".join(
                c.value for c in _ast0.walk(_a0)
                if isinstance(c, _ast0.Constant) and isinstance(c.value, str)))
_ptext0 = "\n".join(_pr0)
check("main() warns when the target was built from only some of the pairs",
      "contribute NOTHING to the target" in _ptext0)

# THE ARRIVAL GATE MUST KNOW HOW MANY SWAPS THERE ARE, and main() had that
# number and threw it away. `chunks` fell back to 1 whenever the per-chunk
# breakdown was empty -- which is exactly what --expect-xmr does, by design.
# With chunks=1 the second term of the floor collapses to a piconero and the
# slippage tolerance stands alone.
#
# Driven through the REAL gs_common.swap_arrival_floor rather than asserted
# about, because the claim is arithmetic.
from gs_common import swap_arrival_floor as _saf                # noqa: E402
_tot, _tol = Decimal("12"), Decimal("0.10")
_f_old, _ = _saf(_tot, _tol, [], 1)
_f_new, _tightened = _saf(_tot, _tol, [], 12)
check("with chunks=1 the gate opens at 11.0 XMR of a 12 XMR target — a whole "
      "1 XMR swap absent and the tool reports PAID",
      Decimal("11.0") >= _f_old)
check("...and with the real swap count it does not",
      Decimal("11.0") < _f_new and _tightened)
# The call site must supply that count. AST, not a substring: the call is
# wrapped across lines and a literal search is how this kind of check goes red
# for the wrong reason.
_calls = [n for n in _ast0.walk(_m0)
          if isinstance(n, _ast0.Call) and isinstance(n.func, _ast0.Name)
          and n.func.id == "swap_arrival_floor"]
check("main() calls swap_arrival_floor exactly once", len(_calls) == 1)
_chunkarg = _ast0.unparse(_calls[0].args[3]) if _calls else ""
check("...and the chunk count falls back to the number of SWAP PAIRS routed "
      "to this address before it falls back to 1"
      + (f" (got {_chunkarg!r})" if _calls else ""),
      "matched" in _chunkarg and _chunkarg.rstrip().endswith("or 1"))

# A shortfall INSIDE --tolerance is still a shortfall and must be named. The
# aggregator knows the default is 10%; skimming just inside it was reported as
# an unqualified success.
check("main() reports how far a 'PAID' result fell below the quote",
      "BELOW the" in _ptext0 and "tolerance, so it counts as paid" in _ptext0)
def _rej(path):
    try:
        rw.load_pairs(path)
        return False
    except Exception:
        return True


check("pairs: a pair with the wrong schema is rejected",
      _rej(write("bp.json", [{"schema": "nope"}])))
check("pairs: an empty list is rejected", _rej(write("e.json", [])))


print("=== accept floor: swap slippage must not hang the watch forever ===")

check("floor: 10% tolerance on 1.0 accepts 0.9",
      rw.accept_floor(Decimal("1.0"), Decimal("0.10")) == Decimal("0.9"))
check("floor: zero tolerance demands the full quote",
      rw.accept_floor(Decimal("2.5"), Decimal("0")) == Decimal("2.5"))
check("floor: no target -> no floor", rw.accept_floor(Decimal("0"), Decimal("0.1")) == 0)
check("floor: the floor is never ABOVE the target",
      all(rw.accept_floor(Decimal(t), Decimal("0.10")) <= Decimal(t)
          for t in ("0.1", "1", "7", "100")))
try:
    rw.accept_floor(Decimal("1"), Decimal("1"))
    _bad = True
except ValueError:
    _bad = False
check("floor: a tolerance of 1.0 (accept nothing) is rejected", not _bad)


print("=== poll cadence: jittered, never a fixed heartbeat ===")

_vals = {rw.poll_seconds() for _ in range(400)}
check("poll: every interval is inside the declared band",
      all(rw.POLL_MIN_S <= v <= rw.POLL_MAX_S for v in _vals))
check("poll: the interval actually varies (not a constant heartbeat)", len(_vals) > 5)


print("=== the watch loop ===")


class FakeRPC:
    """A wallet-rpc that returns a scripted sequence of (total, unlocked).

    It also answers get_height, and by default the height ADVANCES on every
    call -- i.e. it models a wallet that is keeping up with the chain.

    That default matters. This class originally had no raw_request at all, so
    when watch() started asking the wallet whether it was still scanning, every
    existing test silently fell into the "cannot tell" branch: the assertions
    still passed while the branch they were meant to cover never ran. A fake
    that cannot represent a state is a fake that hides every bug in it -- which
    is exactly how an IndexError in the real RPC wrapper survived a full test
    suite elsewhere in this repo. Set scanning=False to model a wallet whose
    daemon connection has dropped, or height=None for one that will not answer.
    """

    def __init__(self, script, scanning=True, height=0):
        self.script = list(script)
        self.calls = []
        self.scanning = scanning
        self.height = height
        self.height_calls = 0

    def get_subaddress_balance(self, account_index=0, address_index=0):
        self.calls.append((account_index, address_index))
        if self.script:
            t, u = self.script.pop(0)
        else:
            t, u = self.last
        self.last = (t, u)
        return int(t * ATOMIC), int(u * ATOMIC)

    def raw_request(self, method, params=None):
        if method == "get_height":
            self.height_calls += 1
            if self.height is None:
                raise RuntimeError("wallet-rpc will not answer get_height")
            if self.scanning:
                # ~2 min/block, so a real wallet advances many blocks across a
                # 30-minute stall window.
                self.height += 15
            return {"height": self.height}
        return {}


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def run(script, floor_, timeout_s=10_000, stall_s=1800, step=60, rpc=None):
    clk = Clock()
    rpc = rpc if rpc is not None else FakeRPC(script)

    def sleep(_s):
        clk.t += step
    return rw.watch(rpc, 0, 7, Decimal(str(floor_)), timeout_s=timeout_s,
                    stall_s=stall_s, sleep_fn=sleep, clock=clk,
                    echo=lambda *a, **k: None), rpc


# nothing, nothing, then the full amount confirmed+unlocked
r, rpc = run([(0, 0), (1.0, 0), (1.0, 1.0)], 0.9)
check("watch: reports funded once the unlocked balance clears the floor",
      r["state"] == "funded" and r["unlocked"] == Decimal("1.000000000000"))
check("watch: polls the subaddress from the bundle, not account 0/0",
      rpc.calls and all(c == (0, 7) for c in rpc.calls))

# arrived but still locked -> NOT funded yet
r, _ = run([(1.0, 0)] * 3 + [(1.0, 1.0)], 0.9)
check("watch: a confirmed-but-locked balance does NOT count as paid",
      r["state"] == "funded" and r["ticks"] == 4)

# THE REGRESSION: money arrives and sits locked longer than the stall window.
# Treating that as a shortfall abandons a payment that is merely confirming.
r, _ = run([(1.0, 0)] * 50 + [(1.0, 1.0)], 0.9, stall_s=120, step=60)
check("watch: locked funds past the stall window are NOT called a shortfall",
      r["state"] == "funded")

# a real shortfall: fully unlocked, stopped growing, still under the floor
r, _ = run([(0.5, 0.5)] * 50, 0.9, stall_s=120, step=60)
check("watch: an under-delivering swap reports 'stalled', not a hang",
      r["state"] == "stalled" and r["unlocked"] == Decimal("0.500000000000"))

# never paid at all -> timeout, and a zero balance is not a shortfall
r, _ = run([(0, 0)] * 100, 0.9, timeout_s=300, stall_s=120, step=60)
check("watch: nothing arriving times out rather than reporting stalled",
      r["state"] == "timeout")

# --any mode
r, _ = run([(0, 0), (0.01, 0.01)], 0)
check("watch: --any stops on any unlocked balance", r["state"] == "funded")
r, _ = run([(0.01, 0)] * 5 + [(0.01, 0.01)], 0)
check("watch: --any still waits for the balance to UNLOCK", r["ticks"] == 6)

# a shortfall that later completes must not be declared early
r, _ = run([(0.5, 0.5)] * 3 + [(1.0, 1.0)], 0.9, stall_s=1800, step=60)
check("watch: a partial arrival that later completes is reported funded",
      r["state"] == "funded")


class FlakyRPC(FakeRPC):
    def __init__(self, script, fail_at):
        super().__init__(script); self.fail_at = set(fail_at); self.n = 0

    def get_subaddress_balance(self, account_index=0, address_index=0):
        self.n += 1
        if self.n in self.fail_at:
            raise RuntimeError("wallet is busy")
        return super().get_subaddress_balance(account_index, address_index)


clk = Clock()
_r = rw.watch(FlakyRPC([(0, 0), (1.0, 1.0)], fail_at={1, 2}), 0, 7, Decimal("0.9"),
              timeout_s=10_000, stall_s=1800,
              sleep_fn=lambda _s: setattr(clk, "t", clk.t + 60),
              clock=clk, echo=lambda *a, **k: None)
check("watch: a transient RPC error does not abort a multi-hour wait",
      _r["state"] == "funded")


print("=== what-now menu: the command it prints must be real ===")

c1 = rw.choice_by_key("1")
argv = rw.build_mix_command(c1, "wallet_x.json", "socks5h://127.0.0.1:9050")
check("menu: Maximum safe emits BOTH --peel and --dag-mixing",
      "--peel" in argv and "--dag-mixing" in argv)
check("menu: the command targets receive mode with the given bundle",
      "--receive-wallet" in argv
      and argv[argv.index("--receive-wallet") + 1] == "wallet_x.json")
check("menu: the tor proxy is carried into the printed command",
      argv[argv.index("--tor-proxy") + 1] == "socks5h://127.0.0.1:9050")
check("menu: the command is an argv LIST, so a path with a space stays one arg",
      isinstance(argv, list) and " ".join(argv).count("wallet_x.json") == 1)

argv2 = rw.build_mix_command(rw.choice_by_key("2"), "w.json", "socks5h://127.0.0.1:9050")
check("menu: Peeling chain emits --peel and NOT --dag-mixing",
      "--peel" in argv2 and "--dag-mixing" not in argv2)
argv3 = rw.build_mix_command(rw.choice_by_key("3"), "w.json", "socks5h://127.0.0.1:9050")
check("menu: Balanced emits --dag-mixing and NOT --peel",
      "--dag-mixing" in argv3 and "--peel" not in argv3)
check("menu: the do-nothing choice produces NO command",
      rw.build_mix_command(rw.choice_by_key("4"), "w.json", "p") == [])
check("menu: choices are reachable by id as well as number",
      rw.choice_by_key("paranoid") is rw.choice_by_key("1"))
check("menu: an unknown choice is None, not a silent default",
      rw.choice_by_key("99") is None and rw.choice_by_key("") is None)

# Every flag the menu emits must be one GhostSpiral actually accepts, or the
# printed command is a paste that fails.
_gs = open(os.path.join(REPO, "GhostSpiral")).read()
_flags = {a for a in argv + argv2 + argv3 if a.startswith("--")}
check("menu: every flag it prints is a real GhostSpiral flag",
      all(f'"{f}"' in _gs or f"'{f}'" in _gs for f in _flags))


# ---------------------------------------------------------------------------
# A FROZEN BALANCE HAS TWO CAUSES AND THEY NEED OPPOSITE ANSWERS.
#
# Proven against real monero-wallet-rpc 0.18.3.1 by killing the daemon
# mid-poll: get_balance KEEPS ANSWERING, successfully, with the last scanned
# figure -- it does not raise, so watch()'s transient-error path never fires --
# while get_height stops advancing. From the balance alone, "the swap sent no
# more" and "my wallet stopped looking" are the same picture, and the tool used
# to assert the first one as fact and tell the operator to accept less money.
# ---------------------------------------------------------------------------
SHORT = [(0, 0), (0.5, 0.5)] + [(0.5, 0.5)] * 60

# (a) the wallet kept scanning -> the shortfall is REAL and may be stated
r, rpc = run(SHORT, 0.9, rpc=FakeRPC(SHORT, scanning=True))
check("watch: a real shortfall (wallet still scanning) reports 'stalled'",
      r["state"] == "stalled")
check("...and records that the sync was verified, not assumed",
      r.get("sync") == "ok")
check("...having actually asked the wallet its height", rpc.height_calls > 0)

# (b) the wallet stopped scanning -> this is NOT a shortfall
r, _ = run(SHORT, 0.9, rpc=FakeRPC(SHORT, scanning=False))
check("watch: a frozen balance with a FROZEN wallet is 'not_syncing', "
      "never 'stalled'", r["state"] == "not_syncing")
check("...and says the sync is the problem", r.get("sync") == "stuck")
check("...and still reports what it did see",
      r["unlocked"] == Decimal("0.500000000000"))

# (c) the wallet will not answer at all -> say 'unknown', do not guess
r, _ = run(SHORT, 0.9, rpc=FakeRPC(SHORT, height=None))
check("watch: an unreadable scan height reports stalled with sync='unknown'",
      r["state"] == "stalled" and r.get("sync") == "unknown")

# The two branches must be genuinely different: same balances, same timings,
# opposite verdicts, decided only by whether the wallet kept scanning.
r_ok, _ = run(SHORT, 0.9, rpc=FakeRPC(SHORT, scanning=True))
r_bad, _ = run(SHORT, 0.9, rpc=FakeRPC(SHORT, scanning=False))
check("the verdict is decided by the SCAN HEIGHT, not by the balance "
      "(identical balances, opposite states)",
      r_ok["state"] == "stalled" and r_bad["state"] == "not_syncing"
      and r_ok["unlocked"] == r_bad["unlocked"])

# A wallet that stops scanning must never be reported as a shortfall, because
# the recovery advice for a shortfall is "accept less money".
_src = open(os.path.join(REPO, "receive_watch")).read()
_ns = _src[_src.index('if state == "not_syncing":'):_src.index('if state == "stalled":')]
check("the not_syncing message does NOT tell the operator to accept less",
      "--any" not in _ns and "--expect-xmr" not in _ns)
check("...and says plainly it is not the swap under-delivering",
      "NOT the swap" in _ns)
check("...and warns against lowering the target to get past it",
      "Do NOT lower the target" in _ns)

# The honest-cause rule for the real shortfall: it may only claim the swap paid
# short when the sync was actually verified.
_st = _src[_src.index('if state == "stalled":'):]
_st = _st[:_st.index("return 1")]
# Asserted on the CONDITION, not on a literal spelling of it. This used to
# match the exact string 'r.get("sync") == "unknown"' plus the phrase "kept
# scanning throughout" -- which lives only in a COMMENT explaining what the
# code deliberately does not print. Both went stale the moment the rule was
# strengthened to cover a third verdict, and the test failed on code that had
# become MORE correct.
#
# The rule now: the shortfall cause may be named only when the wallet
# demonstrably advanced recently. "unknown" (height unreadable) and "stale"
# (height readable but static for longer than LIVENESS_DOUBT_S) both take the
# no-cause branch, because from here a slow wallet and a short payment look
# identical -- and the advice attached to a shortfall is to accept less money.
check("the stalled message blames the swap ONLY when the scan was recent",
      'r.get("sync") in ("unknown", "stale")' in _st)
check("...so an unreadable height does not get a cause", '"unknown"' in _st)
check("...and neither does a long-stale one", '"stale"' in _st)
check("...and the confident sentence is still reachable for a live wallet",
      "still following the chain" in _st)


# ---------------------------------------------------------------------------
# DUST MUST NOT DECIDE ANYTHING.
#
# The receive address is not a secret: the swap memo names it in plaintext and
# the sender puts that memo in a Bitcoin OP_RETURN, so anyone reading the BTC
# chain -- the swap provider included -- can send to it. Four decisions in
# watch() used to read "any non-zero balance" as "the payment", which gave an
# outsider two levers for the price of a transaction fee:
#   * one piconero set seen_any, so a balance that never moved again was
#     reported as "the swap paid short" when nothing had arrived;
#   * one piconero every 25 minutes reset the no-more-is-coming timer, and one
#     permanently-LOCKED piconero pinned still_confirming, either of which held
#     the shortfall verdict off for the entire 24 hours.
# ---------------------------------------------------------------------------
PICO = Decimal("0.000000000001")


class SeqRPC:
    """Balance follows a scripted sequence; the wallet always scans."""
    def __init__(self, seq):
        self.seq = seq; self.i = 0; self.h = 100
    def get_subaddress_balance(self, account_index=0, address_index=0):
        t, u = self.seq[min(self.i, len(self.seq) - 1)]
        self.i += 1
        return int(Decimal(str(t)) * ATOMIC), int(Decimal(str(u)) * ATOMIC)
    def raw_request(self, method, params=None):
        if method == "get_height":
            self.h += 15
            return {"height": self.h}
        return {}


def dust_run(seq, floor_, target, timeout_s=100_000, stall_s=1800, min_arr=None):
    clk = Clock()
    ma = Decimal(str(min_arr)) if min_arr is not None else rw.arrival_floor(
        Decimal(str(target)))
    return rw.watch(SeqRPC(seq), 0, 7, Decimal(str(floor_)), timeout_s=timeout_s,
                    stall_s=stall_s, sleep_fn=lambda _s: setattr(clk, "t", clk.t + 60),
                    clock=clk, echo=lambda *a, **k: None, min_arrival=ma)


# the floor itself: absolute for small swaps, proportional for large ones, so
# the attack does not just get more expensive-but-still-cheap as amounts grow
check("arrival floor for a tiny target is the absolute dust floor",
      rw.arrival_floor(Decimal("0.5")) == rw.DUST_FLOOR_XMR)
check("arrival floor scales with a large target (0.1%)",
      rw.arrival_floor(Decimal("1000")) == Decimal("1.000"))
check("arrival floor with no target is the absolute floor",
      rw.arrival_floor(Decimal(0)) == rw.DUST_FLOOR_XMR)
check("an explicit override wins",
      rw.arrival_floor(Decimal("1000"), Decimal("0.01")) == Decimal("0.01"))
check("the dust floor is above a typical Monero fee (it cannot pay to move "
      "itself below this)", rw.DUST_FLOOR_XMR >= Decimal("0.0002"))

# ATTACK 1: dust must not make the tool assert a shortfall
r = dust_run([(0, 0)] + [(PICO, PICO)] * 80, 2.7, target=3)
check("one piconero does NOT produce a 'swap paid short' verdict",
      r["state"] != "stalled")
check("...the watch keeps waiting instead", r["state"] == "timeout")

# ATTACK 2: a drip must not suppress the real verdict
_drip = [(0, 0), (Decimal("0.5"), Decimal("0.5"))]
for _k in range(1, 150):
    _drip.append((Decimal("0.5") + PICO * _k, Decimal("0.5") + PICO * _k))
check("a piconero drip no longer suppresses the shortfall verdict",
      dust_run(_drip, 2.7, target=3)["state"] == "stalled")

# ATTACK 2b: a permanently locked piconero must not pin still_confirming
check("a permanently LOCKED piconero no longer pins 'still confirming'",
      dust_run([(0, 0)] + [(Decimal("0.5") + PICO, Decimal("0.5"))] * 80,
               2.7, target=3)["state"] == "stalled")

# The accumulation case a naive `total - previous_tick >= floor` test misses:
# many sub-threshold increments that add up to a real amount must still count.
_acc = [(0, 0)]; _tot = Decimal(0)
for _k in range(60):
    _tot += Decimal("0.0005"); _acc.append((_tot, _tot))
_acc += [(_tot, _tot)] * 90
check("sub-threshold increments that ACCUMULATE to a real amount are seen "
      "(compared against the last marked total, not the previous tick)",
      dust_run(_acc, 2.7, target=3)["state"] == "stalled")

# --any must not be satisfiable by dust either
check("--any is NOT satisfied by dust",
      dust_run([(0, 0)] + [(PICO, PICO)] * 80, 0, target=0,
               timeout_s=3000)["state"] == "timeout")
check("--any still fires on a real payment",
      dust_run([(0, 0), (1.0, 0), (1.0, 1.0)], 0, target=0)["state"] == "funded")

# ...and none of this may break the legitimate paths
check("a real short delivery is still reported as a shortfall",
      dust_run([(0, 0)] + [(Decimal("0.5"), Decimal("0.5"))] * 80,
               2.7, target=3)["state"] == "stalled")
_full = dust_run([(0, 0), (3.0, 0), (3.0, 3.0)], 2.7, target=3)
check("the full payment still funds",
      _full["state"] == "funded" and _full["unlocked"] == Decimal("3.000000000000"))

# A sub-threshold balance must be REPORTED, not silently hidden -- it is the
# operator's address and something really is sitting on it.
_lines = []
_clk2 = Clock()
rw.watch(SeqRPC([(0, 0)] + [(PICO, PICO)] * 40), 0, 7, Decimal("2.7"),
         timeout_s=3000, stall_s=1800,
         sleep_fn=lambda _s: setattr(_clk2, "t", _clk2.t + 60), clock=_clk2,
         echo=lambda *a, **k: _lines.append(" ".join(str(x) for x in a)),
         min_arrival=Decimal("0.003"))
_txt = "\n".join(_lines)
check("a sub-threshold balance is reported to the operator, not hidden",
      "below the" in _txt and "arrival threshold" in _txt)
check("...and the operator is told who can send there",
      "seen the swap memo" in _txt)
check("...and how to change it", "--min-arrival" in _txt)

# The escape hatch must actually restore the old behaviour. `pending >=
# min_arrival` alone is TRUE when both are zero, so --min-arrival 0 left
# still_confirming permanently set and the shortfall verdict unreachable --
# the flag silently broke the thing it exists to restore. Found by the
# real-binary control run, not by inspection.
check("--min-arrival 0 really does restore the old dust-sensitive behaviour",
      dust_run([(0, 0)] + [(PICO, PICO)] * 80, 2.7, target=3,
               min_arr=0)["state"] == "stalled")
check("...and a settled balance is not reported as 'still confirming' at "
      "threshold zero",
      dust_run([(0, 0), (3.0, 3.0)], 2.7, target=3, min_arr=0)["state"] == "funded")

# main() must wire it, validate it, and say what it is using
check("main() exposes --min-arrival", "--min-arrival" in _src)
check("main() refuses a threshold above the amount that counts as paid",
      "could never succeed" in _src)
check("main() warns that --min-arrival 0 restores the old behaviour",
      "restores the old behaviour" in _src)
check("main() prints the threshold it is actually using",
      "as the payment arriving" in _src)
# and the shortfall message must not claim it can attribute the source
check("the shortfall message admits it cannot tell WHO sent the balance",
      "cannot tell WHO sent" in _src)


# ---------------------------------------------------------------------------
# LIVENESS MUST MEAN "SCANNED RECENTLY", AND MUST NOT HIDE BEHIND THE BALANCE.
#
# Both of these were defects in the FIRST version of the sync fix, found by
# adversarial review of that fix rather than by any test:
#   * liveness was `h_now > height_at_change`, satisfied by ONE block in thirty
#     minutes, while main() reported "your wallet has kept scanning throughout"
#     and advised accepting less money;
#   * the whole check sat behind `not still_confirming`, so a wallet that froze
#     during the ~10-block unlock window -- the twenty minutes right after the
#     money lands -- never reached it and ran to the 24-hour timeout undiagnosed.
# ---------------------------------------------------------------------------
class OneBlockThenBlind(FakeRPC):
    """Scans exactly one block after the balance settles, then nothing."""
    def __init__(self, script):
        super().__init__(script, scanning=False, height=100)
        self._bumped = False

    def raw_request(self, method, params=None):
        if method == "get_height":
            self.height_calls += 1
            if len(self.calls) >= 2 and not self._bumped:
                self._bumped = True
                self.height += 1
            return {"height": self.height}
        return {}


FLAT = [(0.5, 0.5)] * 60
r, _ = run(FLAT, 5.0, rpc=OneBlockThenBlind(FLAT))
check("one block in a whole stall window is still inside the threshold "
      "(so: reported, not silently escalated)", r["state"] == "stalled")
check("...and the AGE of that last scan is reported, not hidden",
      isinstance(r.get("last_scan_age_s"), int) and r["last_scan_age_s"] > 600)

# Read what main() PRINTS, via the AST -- the comment explaining why the old
# claim was wrong necessarily quotes it, and a text search cannot tell the two
# apart. (Fifth time in this repo; source-substring checks keep doing this.)
import ast as _ast
_mainf = next(n for n in _ast.walk(_ast.parse(_src))
              if isinstance(n, _ast.FunctionDef) and n.name == "main")
_printed = []
for _n in _ast.walk(_mainf):
    if (isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name)
            and _n.func.id == "print"):
        for _a in _n.args:
            for _c in _ast.walk(_a):
                if isinstance(_c, _ast.Constant) and isinstance(_c.value, str):
                    _printed.append(_c.value)
_ptext = "\n".join(_printed)
check("the print scan found main()'s output (not vacuous)", len(_printed) > 20)
check("main() never PRINTS that the wallet 'kept scanning throughout'",
      "kept scanning throughout" not in _ptext)
check("...it prints the measured fact: when the wallet last scanned",
      "last scanned a new block" in _ptext)
check("...and warns when that gap is long even though it passed the threshold",
      "a long gap though" in _ptext)
# the docstring must not over-claim either -- it is the contract callers read
check("watch()'s docstring does not promise 'kept scanning throughout' either",
      "kept scanning throughout, so no more" not in (rw.watch.__doc__ or ""))

# A healthy wallet must report a small age and get no warning.
r, _ = run(FLAT, 5.0, rpc=FakeRPC(FLAT, scanning=True))
check("a healthy wallet reports a recent scan", r["last_scan_age_s"] == 0)


class FreezeDuringUnlock(FakeRPC):
    """Money lands, then the wallet freezes while unlocked < total forever."""
    def __init__(self):
        super().__init__([(0, 0)] + [(3.0, 0.5)] * 60, scanning=False, height=100)


r, _ = run(None, 5.0, timeout_s=3000, rpc=FreezeDuringUnlock())
check("a wallet frozen DURING the unlock window is caught, not run to timeout",
      r["state"] == "not_syncing")
check("...rather than the old outcome of a bare 'timeout'", r["state"] != "timeout")

# The liveness check must be evaluated independently of the balance state --
# proven by the fact that it fires while still_confirming is permanently true.
check("liveness is checked independently of whether funds are still confirming",
      r["total"] > r["unlocked"] and r["state"] == "not_syncing")


# ---------------------------------------------------------------------------
# The wrong-wallet guard must FAIL CLOSED on an out-of-bound index.
# Real monero-wallet-rpc answers get_address for a missing account/subaddress
# with a JSON-RPC ERROR (-14/-15), which landed in the warn-and-continue
# branch -- so the guard whose comment says it catches "a bundle from a
# different wallet" failed open on exactly that. get_balance then returns
# (0, 0) with no error, so the watch cannot recover it either: it waits 24h and
# blames the swap provider.
# ---------------------------------------------------------------------------
_rb = _src[_src.index("    except SystemExit:\n        raise"):]
_rb = _rb[:_rb.index("integrity_log(\"recv\", f\"watch_start")]
check("an out-of-bound index aborts instead of warning-and-continuing",
      "out of bound" in _rb and "sys.exit(" in _rb)
check("...and says the bundle belongs to a different wallet",
      "DIFFERENT wallet" in _rb)
check("a genuine transport failure still only warns",
      "Continuing, but verify the wallet is the right one" in _rb)


# ---------------------------------------------------------------------------
# The memo is re-validated before the sender instructions are re-printed.
# ---------------------------------------------------------------------------
_DEST = "8" + "A" + "1" * 93
_OTHER = "8" + "B" + "2" * 93
def _instr(pairs, dest):
    try:
        rw._print_sender_instructions(pairs, dest, echo=lambda *a, **k: None)
        return "PRINTED"
    except SystemExit as e:
        return "REFUSED:" + str(e)


# A REAL bech32 address, not "bc1qxy": the deposit address is re-validated
# before these instructions are printed (a tampered one sends the BTC where
# ThorChain never sees it, and the memo check cannot catch that), so a
# placeholder here would refuse for the wrong reason and stop this block
# testing the MEMO property it is about.
_REAL_DEP = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
_good = [{"btc_in": "0.05", "deposit": _REAL_DEP, "expected_xmr": "1.0",
          "memo": f"=:XMR.XMR:{_DEST}:0/1/0"}]
_bad = [{"btc_in": "0.05", "deposit": _REAL_DEP, "expected_xmr": "1.0",
         "memo": f"=:XMR.XMR:{_OTHER}:0/1/0"}]
# ---------------------------------------------------------------------------
# AND THE ADDRESS THE BITCOIN ACTUALLY GOES TO IS RE-VALIDATED TOO.
#
# This function's own docstring argues that thor_swap_preparer checking a value
# once is not enough, because "between the two runs the file is an ordinary
# 0600 JSON that can be edited, truncated or swapped, and this is the copy the
# operator actually pastes to the sender". It then applied that to the memo
# only. A tampered DEPOSIT address is worse and quieter: the BTC leaves and
# ThorChain never sees it, so no swap is routed at all -- and the memo check
# cannot fire, because the memo can stay perfectly honest.
# ---------------------------------------------------------------------------
_REALDEP = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
_okmemo = f"=:XMR.XMR:{_DEST}:0/1/0"
check("an honest pair still prints",
      _instr([{"btc_in": "0.05", "deposit": _REALDEP, "expected_xmr": "1.0",
               "memo": _okmemo}], _DEST) == "PRINTED")
for _label, _dep in (
        ("one character flipped (only the checksum catches this)",
         _REALDEP[:-1] + ("q" if _REALDEP[-1] != "q" else "p")),
        ("an attacker's plausible-looking string", "bc1qEVILEVILEVILEVILEVILEVILEVIL"),
        ("not an address at all", "send-to-me-please"),
        ("empty", ""),
        ("missing entirely", None)):
    check(f"a deposit address that is {_label} is refused",
          _instr([{"btc_in": "0.05", "deposit": _dep, "expected_xmr": "1.0",
                   "memo": _okmemo}], _DEST).startswith("REFUSED"))
check("...and the refusal explains that the memo check cannot catch it",
      "memo can be honest" in
      _instr([{"btc_in": "0.05", "deposit": "nope", "expected_xmr": "1.0",
               "memo": _okmemo}], _DEST))
check("the address is checked even with no --dest to bind the memo against, "
      "because it is a different question",
      _instr([{"btc_in": "0.05", "deposit": "nope", "expected_xmr": "1.0",
               "memo": _okmemo}], "").startswith("REFUSED"))

check("a memo naming our address still prints", _instr(_good, _DEST) == "PRINTED")
check("a memo naming SOMEONE ELSE'S address is refused",
      _instr(_bad, _DEST).startswith("REFUSED"))
check("...explaining the payment would be irreversible",
      "irreversible" in _instr(_bad, _DEST))
check("an empty memo is refused too",
      _instr([{"btc_in": "1", "deposit": "bc1q", "memo": ""}], _DEST).startswith("REFUSED"))


# ---------------------------------------------------------------------------
# --expect-xmr must have an environment path. This process runs for up to 24
# hours with /proc/<pid>/cmdline at mode 0444, so it is the worst place in the
# toolchain to leave an amount on argv -- and every sibling already moved this
# class of value off it via gs_common.env_or_argv.
# ---------------------------------------------------------------------------
check("receive_watch imports the shared env_or_argv helper",
      "env_or_argv" in _src)
check("...and applies it to the expected amount", "GS_EXPECT_XMR" in _src)
check("...with --help pointing at the env var",
      "Prefer GS_EXPECT_XMR" in _src)


# ---------------------------------------------------------------------------
# "ANY balance" has to mean any SETTLED balance, or the mix strands money on
# the one address the swap provider already knows.
#
# --any fired on `unlocked > 0` alone, so a swap delivered as TWO transactions
# returned as soon as the first unlocked -- while the wallet could already see
# the second on the same subaddress. Mixing then moves only the unlocked part
# and leaves the rest on the receive address. That is not a cosmetic problem:
# the receive address is bound to a BTC payment by the swap memo, so value left
# there is value sitting on a burned address after the mix has already run.
# ---------------------------------------------------------------------------
TWO_TX = [(0, 0), (3.0, 0), (3.0, 0.5), (3.0, 0.5), (3.0, 3.0)]
r, _ = run(TWO_TX, 0)          # floor 0 == --any
check("--any waits for the whole visible balance, not the first unlock",
      r["state"] == "funded" and r["unlocked"] == Decimal("3.000000000000"))
check("--any reports nothing left confirming when it returns",
      r["pending"] == Decimal(0))

# It must still return promptly when there is genuinely only one payment.
r, _ = run([(0, 0), (1.0, 0), (1.0, 1.0)], 0)
check("--any still returns on a single settled payment",
      r["state"] == "funded" and r["unlocked"] == Decimal("1.000000000000"))

# A met TARGET is a real event and must still fire -- but the operator has to
# be told what is still in flight, or they mix and strand it.
r, _ = run([(0, 0), (3.0, 0), (3.0, 2.8), (3.0, 3.0)], 2.7)
check("a met target still reports funded even with money still confirming",
      r["state"] == "funded" and r["unlocked"] == Decimal("2.800000000000"))
check("...and reports the amount still confirming",
      r["pending"] == Decimal("0.200000000000"))
check("a fully settled payment reports zero pending",
      run([(0, 0), (1.0, 1.0)], 0.9)[0]["pending"] == Decimal(0))

# main() must actually warn, and name the risk rather than just the number.
_pend = _src[_src.index('_pending = r.get("pending")'):]
_pend = _pend[:_pend.index('integrity_log("recv", "watch_complete")')]
check("main() warns when a mix would strand the pending balance",
      "left sitting on the receive address" in _pend)
check("...naming WHY that address is the wrong place to leave it",
      "the swap provider already knows" in _pend)


# ---------------------------------------------------------------------------
# The printed mix command must survive copy-paste.
# ---------------------------------------------------------------------------
_argv = rw.build_mix_command(rw.choice_by_key("1"),
                             "/home/op/My Wallets/w.json",
                             "socks5h://127.0.0.1:9050")
check("build_mix_command returns the path as ONE argv element",
      "/home/op/My Wallets/w.json" in _argv)

import shlex as _shlex
_printed = rw.format_mix_command(_argv)
_reparsed = _shlex.split(_printed)
check("the PRINTED form survives shell splitting unchanged",
      _reparsed == _argv)
check("...so a spaced path is still one argument after copy-paste",
      _reparsed[_reparsed.index("--receive-wallet") + 1] == "/home/op/My Wallets/w.json")
# main() must actually USE it. Checked by AST over what main() passes to
# print(), not by grepping the file: format_mix_command's docstring quotes the
# old ' '.join(argv) verbatim to explain what was wrong with it, and a
# substring check cannot tell the explanation from the defect. (This exact
# false positive fired while writing this test.)
import ast as _ast
_mainfn = next(n for n in _ast.walk(_ast.parse(_src))
               if isinstance(n, _ast.FunctionDef) and n.name == "main")
_join_calls, _fmt_calls = 0, 0
for _n in _ast.walk(_mainfn):
    if isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name) and _n.func.id == "print":
        for _sub in _ast.walk(_n):
            if isinstance(_sub, _ast.Call):
                _f = _sub.func
                if isinstance(_f, _ast.Name) and _f.id == "format_mix_command":
                    _fmt_calls += 1
                if (isinstance(_f, _ast.Attribute) and _f.attr == "join"
                        and any(isinstance(a, _ast.Name) and a.id == "argv"
                                for a in _sub.args)):
                    _join_calls += 1
check("main() prints the mix command through format_mix_command", _fmt_calls == 1)
check("...and never prints a bare join of argv", _join_calls == 0)

# an ordinary path must not gain noisy quotes
_plain = _shlex.split(rw.format_mix_command(
    rw.build_mix_command(rw.choice_by_key("2"), "wallet_ab12.json",
                         "socks5h://127.0.0.1:9050")))
check("a path with no spaces is printed without added quoting",
      "'" not in rw.format_mix_command(
          rw.build_mix_command(rw.choice_by_key("2"), "wallet_ab12.json",
                               "socks5h://127.0.0.1:9050")))
check("...and still round-trips", "wallet_ab12.json" in _plain)


print("=== the menu must match the console's presets, not drift from them ===")

_con = open(os.path.join(REPO, "gs_console")).read()
_pre = _con[_con.index("const PRESETS={"):]


def preset_of(name):
    m = re.search(name + r":\{([^}]*)\}", _pre)
    body = m.group(1)
    out = {}
    for k in ("wallets", "deep", "fee_priority"):
        mm = re.search(k + r":(\d+)", body)
        if mm:
            out[k] = int(mm.group(1))
    for k in ("dag_mixing", "peel"):
        out[k] = (k + ":true") in body.replace(" ", "")
    # THE DELAY IS PART OF THE PRESET NOW. Neither side set one, so both shipped
    # GhostSpiral's DEFAULT_HOP_DELAY -- the weakest value of the setting its
    # own help calls "AN OPSEC PARAMETER" -- under entries named "Maximum safe"
    # and "MAXIMUM SAFETY". They agreed only because both were silent, which is
    # exactly the drift this comparison exists to catch.
    mm = re.search(r"hop_delay:'([^']*)'", body)
    out["hop_delay"] = mm.group(1) if mm else None
    return out


for _cid in ("paranoid", "peel", "balanced"):
    _c = [c for c in rw.CHOICES if c["id"] == _cid][0]
    _p = preset_of(_cid)
    check(f"sync: receive_watch '{_cid}' matches the console preset exactly",
          all(_c["flags"][k] == _p[k] for k in
              ("wallets", "deep", "fee_priority", "dag_mixing", "peel")))
    check(f"sync: ...including the hop delay ({_cid})",
          _c["flags"].get("hop_delay") == _p["hop_delay"])
    check(f"sync: ...and it is not the weak default ({_cid})",
          bool(_p["hop_delay"]))

# THE COMMAND MUST CARRY IT. A choice that names a delay and then prints a
# command without one is the same defect one layer along.
for _ck in ("1", "2", "3"):
    _cc = rw.choice_by_key(_ck)
    _cav = rw.build_mix_command(_cc, "w.json", "socks5h://127.0.0.1:9050")
    check(f"the printed command carries --hop-delay for choice {_ck}",
          "--hop-delay" in _cav
          and _cav[_cav.index("--hop-delay") + 1] == _cc["flags"]["hop_delay"])
# ...and a choice WITHOUT one must not invent a value: the default belongs to
# GhostSpiral, in one place, or it drifts.
_nohd = {"key": "9", "id": "t", "name": "t",
         "flags": {"wallets": 4, "deep": 1, "dag_mixing": False, "peel": False,
                   "fee_priority": 1},
         "blurb": ""}
check("a choice with no hop delay leaves the flag off entirely",
      "--hop-delay" not in rw.build_mix_command(_nohd, "w.json", "p"))


print("=== no-leak: the watch must not reach a third party ===")

_src = open(os.path.join(REPO, "receive_watch")).read()

# Scan the CODE, not the prose: the module docstring names the explorers on
# purpose, to record why they are never asked. What must not exist is a URL
# literal reaching any of them (or anywhere else outbound).
import ast as _ast
_tree = _ast.parse(_src)
_docstrings = set()
for _n in _ast.walk(_tree):
    if isinstance(_n, (_ast.Module, _ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
        _d = _ast.get_docstring(_n, clean=False)
        if _d:
            _docstrings.add(_d)
_strings = [n.value for n in _ast.walk(_tree)
            if isinstance(n, _ast.Constant) and isinstance(n.value, str)
            and n.value not in _docstrings]
_urls = [s for s in _strings if "http://" in s or "https://" in s]
for _host in ("mempool.space", "blockstream", "blockchair", "blockcypher",
              "esplora", "swapkit", "coingecko", "sochain", "btcscan"):
    check(f"noleak: no URL literal reaches {_host}",
          not any(_host in u.lower() for u in _urls))
# The only URLs it may carry are loopback defaults for the operator's own RPC.
check("noleak: every URL literal in the code is loopback",
      all(("127.0.0.1" in u or "localhost" in u) for u in _urls))
check("noleak: makes no outbound http call of its own",
      "safe_get" not in _src and "safe_post" not in _src
      and "requests." not in _src and "urlopen" not in _src)
# Tor is verified once at startup; a per-poll verify would be a louder pattern
# than the thing being watched.
check("noleak: Tor is verified exactly once, outside the poll loop",
      _src.count("verify_tor(") == 1)
_watch_body = _src[_src.index("def watch("):_src.index("def _print_sender_instructions")]
check("noleak: the poll loop itself performs no Tor/network verification",
      "verify_tor" not in _watch_body and "tor_recheck" not in _watch_body)
# Amounts are the most linkable value in the pipeline and are kept out of the
# persistent chain everywhere else; the same has to hold here.
for _m in re.findall(r"integrity_log\((.*?)\)", _src, re.S):
    check("noleak: no amount/address is interpolated into the integrity log",
          not re.search(r"\{(unlocked|total|target|floor_|bal|amt|amount)\b", _m))
check("noleak: the address in the log is scrubbed",
      "scrub_address(dest)" in _src)
check("noleak: it spends nothing — no transfer/relay/submit call",
      not re.search(r"\b(transfer_split|relay_tx|submit_transfer|sign_transfer)\b", _src))


print("=== console wiring ===")

check("console: the watch action exists and is marked safe (it only reads)",
      '"watch_receive"' in _con and _con.split('"watch_receive"')[1].split("}")[0]
      .count('"risk": "safe"') == 1)
check("console: pairs_file is in the parameter schema (unlisted keys are dropped)",
      '"pairs_file"' in _con and "pairs_file:v('pairs_file')" in _con)
check("console: with no swap quote the watch falls back to --any",
      '"--any"' in _con)
check("console: receive_watch is in the compile-everything check",
      '"receive_watch"' in _con)

# ==========================================================================
# THE HANDOFF MUST CARRY THE TARGET THIS WATCH USED.
#
# The printed mix command passed --wallets/--deep/--fee-priority and stopped,
# so GhostSpiral started with expect_total_xmr None -- and its receiver branch
# reads that as "no target, nothing to check", prints "this run does NOT wait",
# and plans against whatever is on ENTRY at that moment. The operator follows
# the tool's own printed instruction and gets the unguarded run: the gate that
# exists to stop a run spending a fraction of the money was disarmed by the
# command this tool told them to type.
# ==========================================================================
print()
print("=== the mix command carries the numbers the watch was waiting for ===")

from decimal import Decimal as D                                   # noqa: E402
from srcutil import code_only as _code_only                        # noqa: E402

_C2 = rw.choice_by_key("2")


def _mix(**kw):
    return rw.build_mix_command(_C2, "w.json", "socks5h://127.0.0.1:9050",
                                "http://127.0.0.1:18083", **kw)


def _flag(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


_h = _mix(target=D("4.0"), chunks=4, tolerance=D("0.1"))
# THE TOTAL TRAVELS IN THE ENVIRONMENT, NOT ON THE COMMAND LINE.
#
# /proc/<pid>/cmdline is mode 0444, so an argv amount is readable by every
# account on the host for the whole life of a run that lasts hours -- and
# GhostSpiral's own --expect-total-xmr help says exactly that and says to
# prefer GS_EXPECT_TOTAL_XMR. gs_console.secret_env already moved the Bitcoin
# address, the BTC amount and the exit destination off argv for this reason;
# this printed command was the one place that still put an amount there.
check("handoff: the quoted total is NOT on the command line",
      "--expect-total-xmr" not in _h)
check("handoff: ...it is in the environment prefix instead",
      rw.mix_command_env(D("4.0")) == {"GS_EXPECT_TOTAL_XMR": "4.0"})
check("handoff: ...and the printed line carries it as a shell assignment",
      rw.format_mix_command(_h, rw.mix_command_env(D("4.0"))).startswith(
          "GS_EXPECT_TOTAL_XMR=4.0 "))
check("handoff: ...which GhostSpiral reads in preference to argv",
      "GS_EXPECT_TOTAL_XMR" in open(
          os.path.join(REPO, "GhostSpiral")).read())
check("handoff: how many swaps make it up is passed as --split",
      _flag(_h, "--split") == "4")
check("handoff: the tolerance goes too, so both sides use ONE number",
      _flag(_h, "--swap-tolerance") == "0.1")

# The bundle itself, so GhostSpiral gets the PER-SWAP amounts. The typed total
# alone cannot carry them, and on 0.50/0.30/0.15/0.05 that is the difference
# between a 0.95 gate and a 0.90 one -- at 0.90 the smallest swap can be
# missing entirely while the mix starts.
_hp = _mix(target=D("1.0"), chunks=4, tolerance=D("0.1"),
           pairs="thor_pairs.json")
check("handoff: the pairs bundle is passed through as --swap-pairs",
      _flag(_hp, "--swap-pairs") == "thor_pairs.json")
check("handoff: ...alongside the total this watch actually waited for, in "
      "the environment",
      rw.mix_command_env(D("1.0")) == {"GS_EXPECT_TOTAL_XMR": "1.0"})
check("handoff: ...and no bundle means no flag",
      "--swap-pairs" not in _mix(target=D("1.0"), chunks=1,
                                 tolerance=D("0.1")))

# --any / no readable quote: there is genuinely no number, so none is invented.
_hn = _mix(target=None, chunks=0, tolerance=D("0.1"))
check("handoff: with no target (--any) nothing is passed and the behaviour "
      "is unchanged",
      "--expect-total-xmr" not in _hn and "--swap-tolerance" not in _hn)
_hz = _mix(target=D("0"), chunks=0, tolerance=D("0.1"))
check("handoff: a zero target is not passed either",
      "--expect-total-xmr" not in _hz)

# One swap: --split 1 is GhostSpiral's default, so do not add noise.
_h1 = _mix(target=D("1.5"), chunks=1, tolerance=D("0.2"))
check("handoff: a single swap does not add a redundant --split 1",
      "--split" not in _h1)
check("handoff: ...but a non-default tolerance still goes",
      _flag(_h1, "--swap-tolerance") == "0.2")

# It has to actually PARSE as GhostSpiral flags -- a handoff that produces an
# argparse error is worse than one that produces a weak run.
import importlib.machinery as _hm, importlib.util as _hu           # noqa: E402
_gld = _hm.SourceFileLoader("GhostSpiral", os.path.join(REPO, "GhostSpiral"))
_ghost = _hu.module_from_spec(_hu.spec_from_loader(_gld.name, _gld))
_gld.exec_module(_ghost)
_ns = _ghost.build_cli().parse_args(_h[2:])
check("handoff: GhostSpiral's own parser accepts the command, with the "
      "values intact",
      _ns.expect_total_xmr is None and _ns.split == 4
      and _ns.swap_tolerance == D("0.1"))
# ...and the total the parser did NOT get from argv must arrive from the
# environment, or the gate this handoff exists to arm is disarmed instead.
_old_env = os.environ.get("GS_EXPECT_TOTAL_XMR")
os.environ.update(rw.mix_command_env(D("4.0")))
try:
    _ns2 = _ghost.build_cli().parse_args(_h[2:])
    _ghost.resolve_swap_arrival(_ns2)
    check("handoff: the environment total reaches args.expect_total_xmr",
          _ns2.expect_total_xmr == D("4.0"))
finally:
    if _old_env is None:
        os.environ.pop("GS_EXPECT_TOTAL_XMR", None)
    else:
        os.environ["GS_EXPECT_TOTAL_XMR"] = _old_env

# AND IT MUST NEVER REFUSE A RUN THIS WATCH JUST APPROVED. GhostSpiral's
# receiver gate calls swap_arrival_floor with an EMPTY chunk-amount list, so
# its floor is equal to or looser than the one cleared here. If that ever
# inverts, the handoff starts telling operators to run a command that stops.
from gs_common import swap_arrival_floor as _saf                   # noqa: E402
for _amts in ([D("0.5"), D("0.3"), D("0.15"), D("0.05")],
              [D("1")] * 4, [D("1")], [D("2"), D("2")]):
    _t = sum(_amts)
    _watch = _saf(_t, D("0.1"), _amts, len(_amts))[0]
    _mixf = _saf(_t, D("0.1"), [], len(_amts))[0]
    check(f"handoff: the mix's gate is never stricter than the watch's "
          f"({len(_amts)} chunk(s), {_t} XMR)", _mixf <= _watch)

# main() must pass them -- building them correctly and then calling with the
# old signature would leave every check above green and the defect in place.
_rw_src = _code_only(os.path.join(REPO, "receive_watch"))
_norm_rw = " ".join(_rw_src.split())
check("handoff: main() passes the target, the chunk count, the tolerance "
      "and the bundle",
      "target=target, chunks=len(matched), tolerance=args.tolerance, "
      "pairs=(args.pairs or \"\")" in _norm_rw)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    for f in FAILURES:
        print("  - " + f)
    sys.exit(1)
print("ALL GREEN")
