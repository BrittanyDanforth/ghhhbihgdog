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
    """A wallet-rpc that returns a scripted sequence of (total, unlocked)."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def get_subaddress_balance(self, account_index=0, address_index=0):
        self.calls.append((account_index, address_index))
        if self.script:
            t, u = self.script.pop(0)
        else:
            t, u = self.last
        self.last = (t, u)
        return int(t * ATOMIC), int(u * ATOMIC)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def run(script, floor_, timeout_s=10_000, stall_s=1800, step=60):
    clk = Clock()
    rpc = FakeRPC(script)

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
