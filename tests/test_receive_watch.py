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
      rw.expected_total(mine) == Decimal("2.0"))
check("pairs: the other destination's 9.0 XMR is excluded",
      rw.expected_total(allp) != rw.expected_total(mine))
check("pairs: unreadable expected_xmr counts as 0, not a crash",
      rw.expected_total([pair(DEST, "not-a-number"), pair(DEST, "1.0")])
      == Decimal("1.0"))
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
check("the stalled message only blames the swap when sync was verified",
      'r.get("sync") == "unknown"' in _st and "kept scanning throughout" in _st)


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


_good = [{"btc_in": "0.05", "deposit": "bc1qxy", "expected_xmr": "1.0",
          "memo": f"=:XMR.XMR:{_DEST}:0/1/0"}]
_bad = [{"btc_in": "0.05", "deposit": "bc1qxy", "expected_xmr": "1.0",
         "memo": f"=:XMR.XMR:{_OTHER}:0/1/0"}]
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
    return out


for _cid in ("paranoid", "peel", "balanced"):
    _c = [c for c in rw.CHOICES if c["id"] == _cid][0]
    _p = preset_of(_cid)
    check(f"sync: receive_watch '{_cid}' matches the console preset exactly",
          all(_c["flags"][k] == _p[k] for k in
              ("wallets", "deep", "fee_priority", "dag_mixing", "peel")))


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

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    for f in FAILURES:
        print("  - " + f)
    sys.exit(1)
print("ALL GREEN")
