#!/usr/bin/env python3
"""THE LAST GATES BEFORE MONEY MOVES, EXECUTED.

Three checks stand between a mistake and an irreversible transaction, and a
60-mutation sweep found that no green suite runs any of them:

  * validate_xmr_address — the only thing between a mistyped destination and
    XMR sent to a key nobody holds. Monero has no confirmation step and no
    reversal. Its only appearance in tests/ is a stub.
  * the catastrophic-slippage abort in GhostSpiral's own quote path. Only
    thor_swap_preparer's separate copy was tested; deleting GhostSpiral's left
    every suite green.
  * the duplicate --exit-to guard. Six exit-validation checks assert merely
    that SOME SystemExit happened, which a different abort satisfies just as
    well, so the guard itself was unpinned.

Where a check needs python-monero (the checksum maths), the LIBRARY is faked
rather than the check skipped: the maths is python-monero's job, but calling it
and aborting on its verdict is this toolchain's, and that wiring is what broke
here before — validate_xmr_address once used the Address CLASS, which raises on
every subaddress, and rejected every real destination in the repo.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import types
from decimal import Decimal as D

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gs_common as gs                                           # noqa: E402

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


def aborts(fn, *a, **k):
    """Run fn; return its exit message, or None if it did not abort."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fn(*a, **k)
        return None
    except SystemExit as e:
        return str(e.code)


STD = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98"
       "uNbr2VBBEt7f2wfn3RVGQBEP3A")
SUB = ("83Ss8Wx9CmH4EaWkan3bdGhAybs7r3xgHZnMeWMNgwwdW3BJc6nfjTbFL9V4Go9LxZjUv"
       "DCX9H416cHR68m8aLc6FUZFVRJ")


# ==========================================================================
# 1. validate_xmr_address
# ==========================================================================
print("=== validate_xmr_address ===")


class _FakeAddrModule(types.ModuleType):
    """Stands in for monero.address. `bad` is the set of strings it rejects."""

    def __init__(self, bad=()):
        super().__init__("monero.address")
        _bad = set(bad)

        def address(a):
            if a in _bad:
                raise ValueError("Invalid address")
            return object()

        self.address = address


@contextlib.contextmanager
def fake_monero(bad=(), missing=False):
    """Install (or remove) a fake monero.address for the duration."""
    saved = {k: sys.modules.get(k) for k in ("monero", "monero.address")}
    try:
        if missing:
            sys.modules["monero"] = None
            sys.modules["monero.address"] = None
        else:
            pkg = types.ModuleType("monero")
            mod = _FakeAddrModule(bad)
            pkg.address = mod
            sys.modules["monero"] = pkg
            sys.modules["monero.address"] = mod
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


# FORMAT, before any library is consulted.
with fake_monero():
    check("addr: a valid standard address is accepted",
          aborts(gs.validate_xmr_address, STD) is None)
    check("addr: a valid SUBADDRESS is accepted — every destination this repo "
          "produces is one, and the validator once rejected them all",
          aborts(gs.validate_xmr_address, SUB) is None)
    for bad, why in (("", "empty"), (None, "None"), ("bc1qnotmonero", "a BTC address"),
                     (STD[:-1], "truncated"), (STD + "A", "over-long"),
                     ("4" + "0" * 94, "containing base58-illegal 0"),
                     ("4" + "O" * 94, "containing base58-illegal O"),
                     ("4" + "l" * 94, "containing base58-illegal l"),
                     ("9" + "A" * 94, "a bad network prefix")):
        check(f"addr: {why} is refused", aborts(gs.validate_xmr_address, bad) is not None)
    check("addr: the refusal SCRUBS the address rather than echoing it",
          STD not in (aborts(gs.validate_xmr_address, STD[:-1]) or ""))

# THE CHECKSUM VERDICT is python-monero's; ACTING on it is ours.
with fake_monero(bad=[STD]):
    _m = aborts(gs.validate_xmr_address, STD)
    check("addr: a checksum rejection from the library ABORTS the run",
          _m is not None)
    check("addr: ...and says so, rather than blaming the format",
          _m and "checksum" in _m.lower())
with fake_monero(bad=[]):
    check("control: the SAME address passes when the library accepts it — so "
          "the check above is about the verdict, not the address",
          aborts(gs.validate_xmr_address, STD) is None)

# THE FACTORY, NOT THE CLASS. monero.address.Address raises on netbyte 42, so
# using it rejected every subaddress. Pinned by behaviour: a fake whose
# `address` factory accepts must let a subaddress through.
with fake_monero():
    check("addr: the SUBADDRESS path goes through the accepting factory",
          aborts(gs.validate_xmr_address, SUB) is None)

# MISSING LIBRARY MUST FAIL CLOSED. "I cannot check the checksum" is not
# "the checksum is fine" — the whole point is that a typo is unrecoverable.
with fake_monero(missing=True):
    _m = aborts(gs.validate_xmr_address, STD)
    check("addr: a MISSING python-monero refuses to send, rather than "
          "proceeding unverified", _m is not None)
    check("addr: ...and names the missing package", _m and "monero" in _m.lower())


# ==========================================================================
# 2. the duplicate --exit-to guard
# ==========================================================================
print("\n=== duplicate exit destinations ===")


def resolve(dests):
    saved = ghost.validate_xmr_address
    saved_env = os.environ.pop("GS_EXIT_TO", None)
    try:
        ghost.validate_xmr_address = lambda *a, **k: None
        return aborts(ghost.resolve_exit_destinations,
                      types.SimpleNamespace(exit_to=dests))
    finally:
        ghost.validate_xmr_address = saved
        if saved_env is not None:
            os.environ["GS_EXIT_TO"] = saved_env


_dup = resolve([STD, STD])
check("exit: the same destination twice is refused", _dup is not None)
# NOT just "it aborted". Six existing checks assert only that SOME SystemExit
# happened, which any other failure satisfies — so the guard was unpinned.
check("exit: ...and the abort is the DUPLICATE one, named as such",
      _dup and "more than once" in _dup)
check("exit: ...and it explains repeating is for SPREADING",
      _dup and "SPREADING" in _dup)
_dup3 = resolve([STD, SUB, STD])
check("exit: a duplicate anywhere in the list is caught, not just adjacent",
      _dup3 is not None and "more than once" in _dup3)
check("control: two DIFFERENT destinations are accepted, so the check above "
      "is about duplication and not about having two", resolve([STD, SUB]) is None)
check("exit: one destination is accepted", resolve([STD]) is None)
check("exit: no destination at all is accepted (nothing is withdrawn)",
      resolve(None) is None)


# ==========================================================================
# 3. the catastrophic-slippage abort
# ==========================================================================
print("\n=== catastrophic slippage ===")
#
# GhostSpiral has its own copy of this decision; only thor_swap_preparer's was
# tested, so deleting GhostSpiral's changed nothing observable. quote_deviation
# is the shared arithmetic; what is pinned here is what GhostSpiral DOES with
# it, over the boundary.
_dev = ghost.quote_deviation

check("slip: a quote matching the oracle deviates ~0",
      abs(_dev(D("200"), D("1"), D("0.005"))) < D("0.01"))
_far = _dev(D("100"), D("1"), D("0.005"))       # oracle says 200, quote says 100
check("slip: a quote at half the oracle rate deviates ~0.5",
      _far is not None and D("0.45") < abs(_far) < D("0.55"))
check("slip: an unusable oracle price yields no deviation rather than a wrong "
      "one", _dev(D("100"), D("1"), None) is None
      and _dev(D("100"), D("1"), D(0)) is None)
check("slip: an unreadable expected output yields no deviation",
      _dev(None, D("1"), D("0.005")) is None)

# THE BOUNDARY, DRIVEN THROUGH stage2_get_swap_quotes ITSELF.
#
# An earlier version of this section asserted `(_d > _LIMIT) == _should_abort`
# and grepped the source for "args.max_slippage". Both passed with GhostSpiral's
# abort DELETED — the first tests Python's `>` operator and the second tests a
# string the mutation left in place. That is the defect this whole file exists
# for, reproduced in the file itself. Only running the function proves it.
def run_stage2(expected_xmr, oracle_btc_per_xmr, max_slippage="0.10"):
    """Drive the REAL stage 2 for one chunk. Returns its exit message or None."""
    saved = (ghost.safe_post, ghost.safe_get, ghost.newnym, ghost.tor_recheck,
             ghost.secure_delay, ghost.integrity_log, ghost.validate_swap_route,
             ghost.shutdown_requested, ghost.btc_per_xmr_oracle)
    try:
        ghost.safe_post = lambda url, payload, proxy=None: {
            "routes": [{"transaction": {"depositAddress": "bc1qdeposit",
                                        "memo": f"=:XMR.XMR:{SUB}:0/1/0"},
                        "expectedOutput": str(expected_xmr)}]}
        ghost.safe_get = lambda url, proxy=None: {}
        ghost.newnym = lambda *a, **k: True
        ghost.tor_recheck = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        ghost.validate_swap_route = lambda *a, **k: None
        ghost.shutdown_requested = lambda: False
        ghost.btc_per_xmr_oracle = lambda *a, **k: oracle_btc_per_xmr
        a = types.SimpleNamespace(
            max_slippage=D(max_slippage), allow_unbound_memo=False,
            tor_proxy="socks5h://127.0.0.1:9050")
        return aborts(ghost.stage2_get_swap_quotes, a, None, [D("1")], SUB)
    finally:
        (ghost.safe_post, ghost.safe_get, ghost.newnym, ghost.tor_recheck,
         ghost.secure_delay, ghost.integrity_log, ghost.validate_swap_route,
         ghost.shutdown_requested, ghost.btc_per_xmr_oracle) = saved


# oracle: 1 BTC = 200 XMR, so 1 BTC should quote ~200 XMR.
_ORACLE = D("0.005")
_m_ok = run_stage2(D("200"), _ORACLE)
check("slip: a quote matching the oracle is ACCEPTED by the real stage 2",
      _m_ok is None)
_m_bad = run_stage2(D("100"), _ORACLE)          # 50% away
check("slip: a quote 50% from the oracle ABORTS the real stage 2",
      _m_bad is not None)
check("slip: ...and the abort names slippage and the limit",
      _m_bad and "slippage" in _m_bad.lower() and "10%" in _m_bad)

# Both sides of the operator's OWN limit, through the function.
check("slip: raising --max-slippage past the deviation lets it through",
      run_stage2(D("100"), _ORACLE, max_slippage="0.90") is None)
check("slip: lowering it below a small deviation stops it",
      run_stage2(D("199"), _ORACLE, max_slippage="0.001") is not None)

# An unusable oracle must not silently disable the gate.
check("slip: an unavailable oracle does not abort the run (the gate simply "
      "cannot judge)", run_stage2(D("100"), None) is None)


# ==========================================================================
# 4. NUMBERS THAT ARRIVE FROM OUTSIDE
# ==========================================================================
print("\n=== external numbers: quotes and price oracles ===")
#
# decimal_arg guards argv and decimal_env guards the environment. Everything
# that arrives over a socket or out of a file was still parsed with a bare
# Decimal() — and the trap is that Decimal parses "NaN" and "Infinity" happily,
# then poisons the COMPARISON rather than the conversion:
#
#     exp = Decimal(str(external))     # succeeds
#     if exp <= 0:                     # RAISES InvalidOperation here
#
# so the guard meant to reject the value is the line that crashes. Measured: a
# SwapKit quote of expectedOutput="NaN" took stage 2 out with an uncaught
# traceback, and quote_deviation — whose docstring promises it "returns None
# when the comparison cannot be made honestly" — raised on the same input.

check("ext: finite_decimal parses a real number", gs.finite_decimal("1.5") == D("1.5"))
for _bad in ("NaN", "Infinity", "-Infinity", "abc", None, ""):
    check(f"ext: finite_decimal({_bad!r}) -> the default, never a raise",
          gs.finite_decimal(_bad) is None)
check("ext: ...and the default is returned, not invented",
      gs.finite_decimal("NaN", D(0)) == D(0))

# quote_deviation must be TOTAL. Its docstring already promised this.
for _lbl, _args in (("expected=NaN", ("NaN", "1", "0.005")),
                    ("expected=Infinity", ("Infinity", "1", "0.005")),
                    ("oracle=NaN", ("200", "1", "NaN")),
                    ("oracle=Infinity", ("200", "1", "Infinity")),
                    ("amount=NaN", ("200", "NaN", "0.005"))):
    _raised = False
    try:
        _r = ghost.quote_deviation(D(_args[0]) if _args[0][0].isdigit() else _args[0],
                                   _args[1], _args[2])
    except Exception:                                        # noqa: BLE001
        _raised = True
        _r = "RAISED"
    check(f"ext: quote_deviation({_lbl}) returns None instead of raising",
          not _raised and _r is None)
check("control: a real comparison still produces a deviation",
      ghost.quote_deviation(D("100"), D("1"), D("0.005")) is not None)

# The price oracle must not hand back a non-finite rate.
def _oracle(v):
    return gs.btc_per_xmr_oracle(
        None, getter=lambda u, proxy=None: {"monero": {"btc": v}})


for _bad in ("Infinity", "NaN", "-1", "0"):
    check(f"ext: an oracle price of {_bad!r} yields None, not a usable rate",
          _oracle(_bad) is None)
check("control: a real oracle price is returned", _oracle("0.005") == D("0.005"))

# ...and stage 2 survives every one of them, reporting rather than crashing.
for _exp in ("NaN", "Infinity", "-5", "abc"):
    _out = run_stage2(_exp, D("0.005"))
    check(f"ext: stage 2 survives expectedOutput={_exp!r} without a traceback",
          _out is None or "Chunk" in str(_out))
check("control: a good quote still passes stage 2",
      run_stage2(D("200"), D("0.005")) is None)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
