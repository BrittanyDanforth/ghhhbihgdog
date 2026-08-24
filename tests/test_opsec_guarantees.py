#!/usr/bin/env python3
"""Guarantees that could pass WITHOUT establishing the fact they name.

Four defects found by auditing for one shape: something named as a guarantee
that silently degrades to best-effort. Each was reproduced before it was
changed, and each check here fails if the old behaviour returns.

  1. newnym(required=True) did not rotate-or-stop.
  2. The artifact wipe RESURRECTED the integrity chain it had just destroyed.
  3. The broadcast's "egress re-verified before each submit" was a 5-minute
     timer for every transaction with no planned delay.
  4. The signer staged the wallet password on physical disk in two paths while
     the file's own comments claim it never touches a disk.

No daemon, no wallet, no network: these are the decision paths, driven directly.
"""
import contextlib
from decimal import Decimal
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile
import time
import types
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

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


def _load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


import gs_common as gs                                       # noqa: E402
from srcutil import code_only                                # noqa: E402

_real_ilog = gs.integrity_log

# ---------------------------------------------------------------------------
# 1. newnym(required=True): ROTATE OR STOP.
#
# Every caller passing required=True says in its own comment that the rotation
# must happen; none checks the return value. It used to increment a global
# consecutive counter and abort only on the THIRD strike, so the first two
# required rotations could silently not happen -- and a script calling it fewer
# than three times (create_receive_wallet calls it once) could never abort at
# all. Any success reset the counter, so alternating fail/success never aborted.
# ---------------------------------------------------------------------------
BAD_CTRL = "/nonexistent/tor/control"
_real_sleep = time.sleep
gs.time.sleep = lambda *_a, **_k: None          # keep the retry backoff instant
gs.integrity_log = lambda *a, **k: None
try:
    gs._NEWNYM_CONSECUTIVE_FAILURES = 0
    _aborted = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            gs.newnym(BAD_CTRL, required=True)
    except SystemExit:
        _aborted = True
    check("newnym: ONE required rotation that cannot happen aborts "
          "(create_receive_wallet calls it exactly once)", _aborted)

    gs._NEWNYM_CONSECUTIVE_FAILURES = 0
    _first_aborted = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            gs.newnym(BAD_CTRL, required=True)
    except SystemExit as e:
        _first_aborted = True
        _msg = str(e)
    check("newnym: it aborts on the FIRST required failure, not the third",
          _first_aborted)
    check("newnym: ...and the message says the operation will not proceed on "
          "the old circuit",
          _first_aborted and "will not proceed" in _msg)
    check("newnym: ...and names what to check (control socket / stem)",
          _first_aborted and "ControlSocket" in _msg and "stem" in _msg)

    # An alternating fail/success pattern used to never abort. Any single
    # required failure must now stop the run regardless of history.
    gs._NEWNYM_CONSECUTIVE_FAILURES = 0
    _alt = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            gs.newnym(BAD_CTRL, required=True)
    except SystemExit:
        _alt = True
    check("newnym: a required failure aborts even with a clean history "
          "(the counter no longer decides)", _alt)

    # Best-effort callers must still not be silent: a rotation that did not
    # happen is an OPSEC degradation whether or not it is the third one.
    gs._NEWNYM_CONSECUTIVE_FAILURES = 0
    _buf = io.StringIO()
    with contextlib.redirect_stdout(_buf):
        _r = gs.newnym(BAD_CTRL, required=False)
    _out = _buf.getvalue()
    check("newnym: best-effort still returns False", _r is False)
    check("newnym: ...and SAYS the rotation failed on the FIRST failure "
          "(it used to print nothing until the third)",
          "rotation failed" in _out.lower())
    check("newnym: ...naming the consequence, not just the error",
          "SAME circuit" in _out)
finally:
    gs.time.sleep = _real_sleep
    # RESTORE IT. paranoia_mode does `from gs_common import integrity_log` at
    # import time, so loading it while this is stubbed binds the STUB into that
    # module -- and the dry-run check below would then be testing this test's
    # own lambda rather than whether the chain is written. Cost me a false
    # failure on the first run.
    gs.integrity_log = _real_ilog

# ---------------------------------------------------------------------------
# 2. The artifact wipe must not resurrect the chain it just destroyed.
# ---------------------------------------------------------------------------
pm = _load("paranoia_mode")
_cwd = os.getcwd()
_d = tempfile.mkdtemp(prefix="wipechain_")
try:
    os.chdir(_d)
    Path("integrity_chain.log").write_text("h | an earlier run\n")
    Path("wallet_dead.json").write_text("{}")
    Path("monerod.log").write_text("x" * 64)
    # The realistic precondition: ONE artifact whose secure delete fails. The
    # patterns explicitly target files "created world-readable" that "we cannot
    # change from here" -- a root-owned monerod.log is exactly that, and for a
    # non-root operator its delete returns False.
    _real_del = pm.secure_delete_file
    pm.secure_delete_file = (
        lambda p: False if Path(p).name == "monerod.log" else _real_del(p))
    with contextlib.redirect_stdout(io.StringIO()) as _wb:
        _failed = pm.wipe_gs_artifacts(dry=False, extra_dirs=[])
    pm.secure_delete_file = _real_del
    check("wipe: the integrity chain stays GONE after a failed delete",
          not Path("integrity_chain.log").exists())
    check("wipe: ...and its lock file is not recreated either",
          not Path("integrity_chain.log.lock").exists())
    check("wipe: the failure is still counted honestly", _failed == 1)
    check("wipe: ...and still reported, to the terminal which leaves nothing "
          "behind", "could not securely delete" in _wb.getvalue())
    check("wipe: the artifact that could not be deleted is still there, not "
          "silently claimed gone", Path("monerod.log").exists())
    # A DRY run deletes nothing, so it must still record that it happened.
    Path("integrity_chain.log").unlink(missing_ok=True)
    with contextlib.redirect_stdout(io.StringIO()):
        pm.wipe_gs_artifacts(dry=True, extra_dirs=[])
    check("wipe: a DRY run still logs (it destroys nothing to protect)",
          Path("integrity_chain.log").exists())
    check("wipe: the flag is released afterwards", pm._WIPING_CHAIN is False)
finally:
    os.chdir(_cwd)
    __import__("shutil").rmtree(_d, ignore_errors=True)

# ---------------------------------------------------------------------------
# 3. Relay egress must be re-checked before EVERY submit, not on a timer.
# ---------------------------------------------------------------------------
bx = _load("broadcast_signed_xmr")
_probes = []
bx.tor_recheck = lambda *a, **k: None
bx.check_daemon_relay_egress = lambda d, p: (
    _probes.append(d), {"verdict": "tor", "detail": "all peers Tor"})[1]
_gate = bx.EgressGate(
    types.SimpleNamespace(rpc_daemon="http://127.0.0.1:18081",
                          allow_clearnet_relay=False),
    {"http": "socks5h://127.0.0.1:9050"}, "prog.json", set())
_gate.last_tor_check = time.time()          # timer NOT expired
for _i in range(5):
    _gate.check(f"tx{_i}", force=False)     # every tx has delay 0
check("egress: the daemon is probed before EVERY submit, even with no planned "
      "delay and the Tor timer unexpired (it used to be skipped entirely)",
      len(_probes) == 5)

# ...and a mid-batch degradation to clearnet must stop the batch.
bx.check_daemon_relay_egress = lambda d, p: {
    "verdict": "clearnet", "detail": "3 raw-IP peers"}
_stopped = False
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _gate.check("tx5", force=False)
except SystemExit:
    _stopped = True
check("egress: a daemon that turns clearnet mid-batch stops the run at the "
      "next submit", _stopped)

# ---------------------------------------------------------------------------
# 4. The wallet password must prefer tmpfs everywhere, not in two of four paths.
# ---------------------------------------------------------------------------
ats = _load("airgap_tx_signer")
check("password: there is ONE chooser for where it may be staged",
      callable(getattr(ats, "_pw_scratch_dir", None)))
if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
    check("password: it prefers tmpfs over the disk-backed default",
          ats._pw_scratch_dir() == "/dev/shm")
    check("password: ...even when a disk fallback is offered",
          ats._pw_scratch_dir("/var/tmp") == "/dev/shm")
else:
    print("  skip  /dev/shm unavailable; tmpfs preference not checked")
# code_only: comments and docstrings blanked. The first version of these two
# checks matched the literal mkstemp(prefix=".gs_pw_") inside the comment that
# EXPLAINS the bug, and failed on correct code -- a test that reads prose as
# behaviour.
_src_ats = code_only(os.path.join(REPO, "airgap_tx_signer"))
check("password: no mkstemp stages it without choosing a directory "
      "(two paths wrote the spend-key password to $TMPDIR on disk)",
      'mkstemp(prefix=".gs_pw_")' not in _src_ats)
# Whitespace-normalised: one of the four calls wraps onto a second line, so a
# line-based count reported it as missing dir= on correct code. Counting the
# formatting rather than the behaviour is its own kind of false positive.
_flat_ats = " ".join(_src_ats.split())
_n_pw = _flat_ats.count('mkstemp(prefix=".gs_pw_"')
_n_dir = _flat_ats.count('mkstemp(prefix=".gs_pw_", dir=')
check(f"password: ALL {_n_pw} staging sites pass an explicit dir "
      f"({_n_dir} do)", _n_pw > 0 and _n_pw == _n_dir)

# ---------------------------------------------------------------------------
# 5. memo_binds_destination: the memo must ROUTE to us, not merely MENTION us.
#
# The BTC a sender pays goes to a shared THORChain vault, never to the
# operator. The memo alone says where the XMR comes out, so this function is
# the only thing between them and an irreversible swap to someone else's
# address -- and all three callers treat True as permission to tell a sender to
# pay. It was `dest in memo`, a SUBSTRING test, while THORChain reads the
# destination from field 2 of a positional format that also contains an
# affiliate field. Five of six hostile memos were accepted.
# ---------------------------------------------------------------------------
_OURS = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7Sq"
         "SsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
_ATK = ("43ZYYZBkwxZJNJFo6rGHf5KREAGR3LizKKXN3aPDCHYj1AAfkqEipXs4x9nn"
        "rTq2FuaqXMqLrVtED1kV2Z77b6NGE6FFTCm")

# Legitimate memos must still bind -- a wrongly REFUSED memo blocks a real
# swap, so this half matters as much as the half below.
for _label, _memo in (
        ("short form with limit", f"=:XMR.XMR:{_OURS}:0/1/0"),
        ("no limit field", f"=:XMR.XMR:{_OURS}"),
        ("long SWAP: form", f"SWAP:XMR.XMR:{_OURS}:0"),
        ("with affiliate and fee", f"=:XMR.XMR:{_OURS}:0/1/0:someaff:10"),
        ("'s' short op", f"s:XMR.XMR:{_OURS}:0"),
        ("bare XMR asset spelling", f"=:XMR:{_OURS}:0"),
        ("hex-encoded", f"=:XMR.XMR:{_OURS}:0/1/0".encode().hex()),
        ("0x-prefixed hex", "0x" + f"=:XMR.XMR:{_OURS}:0".encode().hex())):
    check(f"memo: a legitimate memo still binds — {_label}",
          gs.memo_binds_destination(_memo, _OURS) is True)

# Hostile memos: every one of these ROUTES TO THE ATTACKER while containing
# the operator's address somewhere a substring test would find it.
for _label, _memo in (
        ("attacker in dest, ours in the AFFILIATE field",
         f"=:XMR.XMR:{_ATK}:0/1/0:{_OURS}:10"),
        ("attacker in dest, ours as trailing junk",
         f"=:XMR.XMR:{_ATK}:0/1/0::0 {_OURS}"),
        ("wrong output asset entirely (BTC.BTC)",
         f"=:BTC.BTC:{_ATK}:0/1/0:{_OURS}:0"),
        ("ours only in a comment-ish suffix",
         f"=:XMR.XMR:{_ATK}:0/1/0 // refund {_OURS}"),
        ("hex-encoded attacker variant",
         (f"=:XMR.XMR:{_ATK}:0/1/0:{_OURS}:10").encode().hex())):
    check(f"memo: REFUSES a memo that pays the attacker — {_label}",
          gs.memo_binds_destination(_memo, _OURS) is False)

for _label, _memo in (("a plain other address", f"=:XMR.XMR:{_ATK}:0/1/0"),
                      ("an empty destination field", "=:XMR.XMR::0/1/0"),
                      ("a non-swap op", f"ADD:XMR.XMR:{_OURS}"),
                      ("garbage", "zzzz"),
                      ("an empty memo", "")):
    check(f"memo: refuses {_label}",
          gs.memo_binds_destination(_memo, _OURS) is False)

check("memo: the destination is matched EXACTLY, not by prefix",
      gs.memo_binds_destination(f"=:XMR.XMR:{_OURS}extra:0", _OURS) is False)

# ---------------------------------------------------------------------------
# A MEMO THAT BINDS CORRECTLY COULD STILL FORGE THE SENDER INSTRUCTIONS.
#
# _memo_fields_bind splits on ':' and reads fields 0, 1 and 2. EVERYTHING after
# the destination is unexamined -- so a newline in field 3 rides through a
# perfect bind and into the copy-paste block every caller prints. Driven
# through the real thor_swap_preparer CLI as a subprocess before the fix, the
# operator saw:
#
#     To address:   <honest>
#     With memo:    =:XMR.XMR:<OURS>:0/1/0
#     [!] CORRECTION - the vault above rotated. Use this instead:
#     To address:   <attacker BTC>
#     With memo:    =:XMR.XMR:<attacker XMR>:0/1/0
#     Ignore the previous block.
#
# An earlier pass concluded this was impossible because it put the newline
# directly AFTER the destination, which breaks the bind. Field 3 is the hole.
# Nothing legitimate is lost: the value goes into a Bitcoin OP_RETURN, which
# cannot carry a control character.
# ---------------------------------------------------------------------------
_INJ = (f"=:XMR.XMR:{_OURS}:0/1/0\n  [!] CORRECTION - the vault above rotated. "
        f"Use this instead:\n    To address:   bc1qEVIL\n    Ignore the previous "
        f"block.")
check("memo: a memo that BINDS but carries a newline in a trailing field is "
      "refused", gs.memo_binds_destination(_INJ, _OURS) is False)
check("memo: ...and so is its hex-encoded form, which decodes to the same "
      "thing", gs.memo_binds_destination(_INJ.encode().hex(), _OURS) is False)
for _lbl, _ch in (("carriage return", "\r"), ("tab", "\t"),
                  ("vertical tab", "\x0b"), ("form feed", "\x0c"),
                  ("NUL", "\x00"), ("DEL", "\x7f")):
    check(f"memo: refuses a {_lbl} in a trailing field",
          gs.memo_binds_destination(f"=:XMR.XMR:{_OURS}:0/1/0{_ch}x", _OURS)
          is False)
# NON-VACUITY: the ordinary memos must still bind, or this refuses every swap.
check("memo: NON-VACUITY - the ordinary memo still binds",
      gs.memo_binds_destination(f"=:XMR.XMR:{_OURS}:0/1/0", _OURS) is True)
check("memo: NON-VACUITY - the bare form still binds",
      gs.memo_binds_destination(f"=:XMR.XMR:{_OURS}", _OURS) is True)
check("memo: NON-VACUITY - the hex form still binds",
      gs.memo_binds_destination(f"=:XMR.XMR:{_OURS}:0/1/0".encode().hex(),
                                _OURS) is True)

# The fields with no gate of their own get the same rule at the print sites.
check("instruction_field_safe accepts an ordinary value",
      gs.instruction_field_safe("0.05") is True)
check("...and refuses one carrying a line break",
      gs.instruction_field_safe("0.05\n  To address: bc1qEVIL") is False)
for _tool, _needle in (("thor_swap_preparer", "instruction_field_safe"),
                       ("receive_watch", "instruction_field_safe")):
    check(f"{_tool} checks every field it prints for the sender",
          _needle in open(os.path.join(REPO, _tool)).read())

# THE ASSET CHECK NEEDS OUR OWN ADDRESS IN THE DEST FIELD TO BE EXERCISED AT
# ALL. The "wrong asset" case above puts the ATTACKER there, so the
# destination comparison rejects it whether or not the asset is checked --
# mutation testing showed that removing the asset check broke nothing, i.e.
# the case was not testing what its name said. A memo naming OUR address but
# the wrong output asset is the one that isolates it: THORChain would be
# instructed to deliver a different coin to a Monero address.
check("memo: refuses OUR address under the WRONG output asset "
      "(isolates the asset check)",
      gs.memo_binds_destination(f"=:BTC.BTC:{_OURS}:0/1/0", _OURS) is False)
check("memo: refuses OUR address under an ETH asset too",
      gs.memo_binds_destination(f"=:ETH.ETH:{_OURS}:0", _OURS) is False)
check("memo: still accepts OUR address on the XMR chain",
      gs.memo_binds_destination(f"=:XMR.XMR:{_OURS}:0", _OURS) is True)


# ---------------------------------------------------------------------------
# 6. receive_watch: the money-in detection must not report what it did not see.
#
# Two separate false claims, both reproduced before the change:
#   * `--any --min-arrival 0` returned "funded" for a COMPLETELY EMPTY
#     subaddress on the first tick, so main() printed "PAID: 0 XMR ... THE
#     MONEY IS YOURS". The --any warning promises a floor of "one piconero";
#     the code had a floor of nothing.
#   * a wallet that died shortly after the payment was reported as
#     sync="ok" -> "your wallet last scanned a block 29 min ago, SO IT IS
#     STILL FOLLOWING THE CHAIN - this looks like the swap paying short",
#     and the recommended remedy is to accept less money. The next line
#     already admitted "29 min ago is a long gap though": it asserted a cause
#     and contradicted it two lines later.
# ---------------------------------------------------------------------------
rw = _load("receive_watch")
rw.integrity_log = lambda *a, **k: None


class _Clk:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class _RPC:
    """watch() calls with KEYWORD args -- a stub with positional-only names
    makes every balance read raise and silently reads as zero, which cost me a
    false 'fixed' reading once already."""

    def __init__(self, tot, unl, clk, die_at=None, frozen=False):
        self.tot, self.unl, self.c = tot, unl, clk
        self.die_at, self.frozen = die_at, frozen

    def get_subaddress_balance(self, account_index, address_index):
        return (self.tot, self.unl)

    def raw_request(self, m, p=None):
        if m == "get_height":
            if self.die_at is not None and self.c.t >= self.die_at:
                raise RuntimeError("height unreadable")
            return {"height": 100 if self.frozen else 100 + int(self.c.t // 10)}
        return {}


def _watch(rpc, target, clk, **kw):
    return rw.watch(rpc, 0, 1, target, stall_s=1800,
                    sleep_fn=lambda _s: setattr(clk, "t", clk.t + 60),
                    clock=clk, echo=lambda *a, **k: None, **kw)


_A = 2 * 10 ** 12
_c = _Clk()
_empty = _watch(_RPC(0, 0, _c), Decimal(0), _c, timeout_s=600,
                min_arrival=Decimal(0))
check("receive: an EMPTY subaddress is never 'funded', even with "
      "--any --min-arrival 0", _empty["state"] != "funded")
_c = _Clk()
_dust = _watch(_RPC(1, 1, _c), Decimal(0), _c, timeout_s=600,
               min_arrival=Decimal(0))
check("receive: ...but one piconero IS still accepted, as --any promises",
      _dust["state"] == "funded")
_c = _Clk()
_norm = _watch(_RPC(3 * 10 ** 12, 3 * 10 ** 12, _c), Decimal(0), _c,
               timeout_s=600)
check("receive: a normal --any payment is still funded",
      _norm["state"] == "funded")

_c = _Clk()
_live = _watch(_RPC(_A, _A, _c), Decimal("5.0"), _c, timeout_s=100000)
check("receive: a LIVE wallet genuinely paid short still reports the "
      "shortfall confidently",
      _live["state"] == "stalled" and _live.get("sync") == "ok")
_c = _Clk()
_dead = _watch(_RPC(_A, _A, _c, die_at=120), Decimal("5.0"), _c,
               timeout_s=100000)
check("receive: a wallet that DIED after the payment is not called 'ok' "
      f"(sync={_dead.get('sync')!r}, scan {_dead.get('last_scan_age_s')}s old)",
      _dead.get("sync") == "stale")
check("receive: ...and the shortfall CAUSE is therefore not asserted",
      _dead.get("sync") != "ok")
_c = _Clk()
_frozen = _watch(_RPC(_A, _A, _c, frozen=True), Decimal("5.0"), _c,
                 timeout_s=100000)
check("receive: a height frozen for a FULL window is still 'not_syncing'",
      _frozen["state"] == "not_syncing" and _frozen.get("sync") == "stuck")

_rw_src = code_only(os.path.join(REPO, "receive_watch"))
check("receive: main() treats a stale scan like an unreadable one — it names "
      "no cause", '"unknown", "stale"' in _rw_src)


# ---------------------------------------------------------------------------
# 7. The DAG hop round must not re-merge the mix it is meant to deepen.
#
# create_subs gives every output its own account so that no single transaction
# can spend two of them -- "IMPOSSIBLE rather than merely discouraged". The hop
# round then picked each destination INDEPENDENTLY, with nothing coordinating
# in-degree, so two sources routinely swept onto the same address. Two outputs
# on one subaddress are two outputs one sweep_all spends, and the exit issues
# exactly one sweep per funded subaddress -- so they left in a single
# multi-input transaction, which is public proof of common ownership.
#
# Measured over 200 planning runs per size BEFORE the fix: every run collided
# (7 outputs -> 4.2 shared, 12 -> 7.3, 20 -> 12.5). --dag-mixing is checked by
# default in the console, so this was the ordinary path, not a corner.
# ---------------------------------------------------------------------------
import secrets as _sec
from collections import Counter as _Ctr

ghost_g = _load("GhostSpiral")
ghost_g.integrity_log = lambda *a, **k: None


def _dag_trial(n_out, deep=2):
    _subs = [f"addr{i:02d}" for i in range(n_out)]
    _ai = {a: (10 + i, 1) for i, a in enumerate(_subs)}
    _fan = {a: Decimal("1.0") for a in _subs}
    _dag = {}
    for a in _subs:
        _others = [b for b in _subs if b != a]
        _k = min((_sec.randbelow(3) + 1) * deep, len(_others))
        _pool, _ch = list(_others), []
        for _ in range(max(_k, 1)):
            _ch.append(_pool.pop(_sec.randbelow(len(_pool))))
        _dag[a] = _ch
    _args = types.SimpleNamespace(dag_mixing=True)
    with contextlib.redirect_stdout(io.StringIO()):
        _plan = ghost_g.build_dag_plan(_args, Decimal("0.0024"), list(_subs),
                                       _fan, _dag, _subs, _ai, _sec,
                                       delay_window=(1, 1))
    _c = _Ctr(t["dst"] for t in _plan)
    return {"hops": len(_plan), "n": n_out,
            "shared": sum(v for v in _c.values() if v > 1),
            "self": sum(1 for t in _plan if t["dst"] == t["src"])}


_RUNS = 60
for _n in (7, 12, 20):
    _res = [_dag_trial(_n) for _ in range(_RUNS)]
    _collided = sum(1 for r in _res if r["shared"])
    _selfhops = sum(r["self"] for r in _res)
    _hops = sum(r["hops"] for r in _res) / _RUNS
    check(f"dag[{_n}]: NO two outputs ever share a hop destination "
          f"({_collided}/{_RUNS} runs collided)", _collided == 0)
    check(f"dag[{_n}]: no output hops to itself ({_selfhops} self-hops)",
          _selfhops == 0)
    check(f"dag[{_n}]: every output still hops — the fix costs no mixing "
          f"depth (avg {_hops:.1f}/{_n})", abs(_hops - _n) < 0.001)

# The assignment helper's own contract, driven directly on a deliberately
# SPARSE graph -- the case where staying inside the adjacency is impossible and
# the fallback has to preserve the invariant rather than the graph.
_srcs = [f"n{i}" for i in range(8)]
_sparse = {s: [_srcs[(i + 1) % 8]] for i, s in enumerate(_srcs)}   # a single cycle
_asg = ghost_g.assign_hop_destinations(_srcs, _sparse, _srcs, _sec)
check("dag: a sparse (single-cycle) graph still assigns every source",
      len(_asg) == len(_srcs))
check("dag: ...with all destinations distinct",
      len(set(_asg.values())) == len(_asg))
check("dag: ...and no self-assignment", all(k != v for k, v in _asg.items()))

# A graph whose adjacency is exhausted must fall back rather than collide.
_starved = {s: [_srcs[0]] for s in _srcs}      # everyone wants the same target
_asg2 = ghost_g.assign_hop_destinations(_srcs, _starved, _srcs, _sec)
check("dag: when every source wants the SAME target, destinations are still "
      "unique", len(set(_asg2.values())) == len(_asg2))
check("dag: ...and still never self-assigned",
      all(k != v for k, v in _asg2.items()))
check("dag: ...and the fallback keeps everyone assigned",
      len(_asg2) == len(_srcs))

# Two sources, two targets: the only legal answer is the swap.
_two = ghost_g.assign_hop_destinations(["a", "b"], {"a": ["b"], "b": ["a"]},
                                       ["a", "b"], _sec)
check("dag: the minimal 2-output case is a clean swap",
      _two == {"a": "b", "b": "a"})



# ==========================================================================
# WHAT IS LEFT ON DISK WHEN A RUN DOES NOT FINISH.
#
# Every unsigned_*.json holds each hop's source, destination and amount in
# plaintext, --exit-to included. A COMPLETE run wipes its own; nothing else
# does, until the START of some later run or a paranoia_mode the operator has
# to remember. The two endings that leave them behind said nothing about them:
# the incomplete branch prints "Funds are safe in the wallet" and exits 1, and
# an uncaught exception never reaches report_completion at all.
# ==========================================================================
print("\n=== plan files surviving an abnormal ending ===")

import tempfile as _pf_tmp, json as _pf_json, pathlib as _pf_path
import io as _pf_io, contextlib as _pf_ctx

_pf_dir = _pf_path.Path(_pf_tmp.mkdtemp(prefix="gs_plansurv_"))
_pf_a = _pf_dir / "unsigned_fanout_dead.json"
_pf_b = _pf_dir / "unsigned_veil_dead.json"
for _f in (_pf_a, _pf_b):
    _f.write_text(_pf_json.dumps({"txs": [{"dst": "4" + "Z" * 94}]}))

_pf_saved = list(ghost_g._SENSITIVE_PLANS)
try:
    ghost_g._SENSITIVE_PLANS.clear()

    # Silent when there is nothing registered -- a suite that never plans must
    # not grow a spurious warning.
    _o = _pf_io.StringIO()
    with _pf_ctx.redirect_stdout(_o):
        ghost_g._report_surviving_plans()
    check("plans: nothing registered -> the report says nothing",
          _o.getvalue() == "")

    ghost_g.register_sensitive_plan(str(_pf_a), str(_pf_b), None)
    check("plans: a None plan (a round that was not planned) is not tracked",
          len(ghost_g._SENSITIVE_PLANS) == 2)

    _o = _pf_io.StringIO()
    with _pf_ctx.redirect_stdout(_o):
        ghost_g._report_surviving_plans()
    _txt = _o.getvalue()
    check("plans: files still on disk are REPORTED", "STILL ON DISK" in _txt)
    check("plans: ...by full path, so the operator can act on it",
          str(_pf_a.resolve()) in _txt and str(_pf_b.resolve()) in _txt)
    # NOT "--exit-to". The three plans registered here are the fan-out, the
    # entry veil and the DAG round; their destinations are mix subaddresses and
    # carriers. The withdrawal address is only in unsigned_exit_*.json, which
    # is written later and erased in its own finally. Naming --exit-to here
    # sent an operator to look for the wrong thing in the right files, and made
    # the real disclosure -- the whole mix graph -- sound smaller than it is.
    check("plans: ...saying what is actually in them",
          "mix graph" in _txt and "account index" in _txt)
    check("plans: ...and not claiming a destination they do not contain",
          "--exit-to" not in _txt)
    check("plans: ...and how to erase them",
          "paranoia_mode" in _txt and "shred" in _txt)

    # THE COMPLETE RUN MUST BE UNCHANGED. _wipe_spent_plans erases them, and
    # the report then has nothing to say -- if this ever fires on a clean run
    # the operator is being told to go and delete files that are already gone.
    ghost_g._wipe_spent_plans(str(_pf_a), str(_pf_b))
    _o = _pf_io.StringIO()
    with _pf_ctx.redirect_stdout(_o):
        ghost_g._report_surviving_plans()
    check("plans: a COMPLETE run wiped them, so the report stays silent",
          _o.getvalue() == "")
finally:
    ghost_g._SENSITIVE_PLANS[:] = _pf_saved
    for _f in (_pf_a, _pf_b):
        if _f.exists():
            _f.unlink()
    _pf_dir.rmdir()

# The registration has to happen where the plans are BORN, or a later path can
# forget. _write_plans is the one place all three are created.
from srcutil import code_only as _pf_code_only                # noqa: E402
_pf_src = " ".join(_pf_code_only(os.path.join(REPO, "GhostSpiral")).split())
check("plans: _write_plans registers all three before returning them",
      "register_sensitive_plan(fanout_file, veil_file, dag_file) "
      "return fanout_file, veil_file, dag_file" in _pf_src)
# atexit, not a finally in main(): a finally does not run when the process
# dies of an exception raised outside main's body, and main() has no top-level
# handler at all.
check("plans: the report is armed with atexit, so an uncaught exception "
      "still triggers it",
      "atexit.register(_report_surviving_plans)" in _pf_src)
check("plans: ...and only under __main__, so importing the module for its "
      "helpers installs no process-wide hook",
      # .find, NOT .index. index() RAISES when the needle is gone, and the
      # needle going is exactly the mutation this pair of checks exists to
      # catch -- deleting the atexit line killed the whole suite on a
      # ValueError instead of reporting the check above as red.
      0 <= _pf_src.find('if __name__ == "__main__":')
      < _pf_src.find("atexit.register(_report_surviving_plans)"))


# ===========================================================================
#  wipe_miss_reason must answer the question wipe_will_erase was asked
# ===========================================================================
#
# wipe_will_erase deliberately selects GS_ARTIFACT_DIR_PATTERNS for a directory
# and GS_ARTIFACT_FILE_PATTERNS otherwise -- its own docstring says "A directory
# is judged by the directory patterns, the way the sweep does". wipe_miss_reason
# exists only to explain THAT function's answer, and it carried a second inline
# copy of the name test that always used the FILE patterns.
#
# So a directory whose name is a real GS_ARTIFACT_DIR_PATTERNS entry, sitting
# somewhere the sweep does not reach, was reported as "both" -- which tells the
# operator no name like theirs is ever swept, so moving it cannot help. The
# opposite of the truth, about the one remedy that would have worked.
print("\n-- the wipe's two answers come from one rule --")
import gs_common as _GW                                      # noqa: E402

_wd = Path(tempfile.mkdtemp())
_outside = Path(tempfile.mkdtemp()) / "elsewhere"
_outside.mkdir(parents=True, exist_ok=True)
_prev_home = os.environ.get("HOME")
os.environ["HOME"] = str(_wd)
try:
    _deep = _wd / "gs"
    _deep.mkdir(parents=True, exist_ok=True)
    # A directory NAME that is really on the sweep's directory list, so only
    # the location can be at fault.
    _dirname = _GW.GS_ARTIFACT_DIR_PATTERNS[2]               # "tx_staging"
    check("wipe/reason: the fixture uses a REAL directory pattern, so 'name' "
          "is genuinely not the problem",
          "*" not in _dirname and _dirname in _GW.GS_ARTIFACT_DIR_PATTERNS)

    for _label, _p, _isdir, _want in (
            ("a staging DIR outside the roots", _outside / _dirname, True,
             "location"),
            ("a staging DIR two levels down", _deep / _dirname, True,
             "location"),
            ("a DIR with an unswept name, at a root", _wd / "my_notes", True,
             "name"),
            ("a FILE with a swept name, outside", _outside / "thor_pairs.json",
             False, "location"),
            ("a FILE with an unswept name, at a root", _wd / "my_notes.json",
             False, "name"),
    ):
        if _isdir:
            _p.mkdir(parents=True, exist_ok=True)
        else:
            _p.write_text("{}")
        check(f"wipe/reason: {_label} -> {_want!r}",
              _GW.wipe_miss_reason(_p) == _want)

    # NON-VACUITY (a): a target the sweep DOES erase gets "" from both, or the
    # rows above are just a function that never says "".
    _hit_dir = _wd / _dirname
    _hit_dir.mkdir(parents=True, exist_ok=True)
    _hit_file = _wd / "thor_pairs.json"
    _hit_file.write_text("{}")
    check("wipe/reason: NON-VACUITY -- a directory the sweep really erases "
          "gets no reason at all",
          _GW.wipe_will_erase(_hit_dir) and _GW.wipe_miss_reason(_hit_dir) == "")
    check("wipe/reason: NON-VACUITY -- and so does a file it really erases",
          _GW.wipe_will_erase(_hit_file)
          and _GW.wipe_miss_reason(_hit_file) == "")
    # NON-VACUITY (b): "both" is still reachable, so the two rows above are not
    # passing because the function stopped being able to say it.
    check("wipe/reason: NON-VACUITY -- 'both' is still reachable for a target "
          "that fails on name AND location",
          _GW.wipe_miss_reason(_outside / "my_notes.json") == "both")
    # THE SHARED RULE ITSELF: one implementation, not two that can drift. This
    # is what the inline copy defeated, so it is checked directly.
    _gcs = Path(os.path.join(REPO, "gs_common.py")).read_text()
    check("wipe/reason: ONE name rule -- wipe_miss_reason no longer carries a "
          "second copy that hard-codes the FILE patterns",
          _gcs.count("GS_ARTIFACT_DIR_PATTERNS if res.is_dir()") == 1
          and "named = _wipe_name_matches(res)" in _gcs)
finally:
    if _prev_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = _prev_home


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
