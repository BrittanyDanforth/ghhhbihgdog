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


# ==========================================================================
# 4. reject_self_exit -- the exit destination must not be an address THIS RUN
#    created.
#
# resolve_exit_destinations checks FORM and DUPLICATES. A well-formed address
# the operator already owns passes both, and GS_EXIT_TO is an environment
# variable -- the kind of value that survives in a shell profile after the
# receive wallet it named has been replaced. Sweeping every mixed output onto
# ENTRY publishes them all on the address the ThorChain memo names; sweeping
# them onto a mix subaddress merges by hand the outputs create_subs gives
# separate accounts specifically so they can never be merged.
#
# Driven directly AND through the real main(), because a guard that is not
# called is not a guard -- which is the failure this whole file exists for.
# ==========================================================================
print("\n=== reject_self_exit ===")

_B58A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _addr(seed: int) -> str:
    """A distinct 95-char base58 string. Checksums are validate_xmr_address's
    job (tested above); this section is about IDENTITY, so only distinctness
    and shape matter."""
    out = []
    v = seed + 7
    for _ in range(95):
        v = (v * 1103515245 + 12345) % (2 ** 31)
        out.append(_B58A[v % len(_B58A)])
    return "4" + "".join(out[1:])


ENTRY_A, MIX_A, MIX_B, FOREIGN = (_addr(1), _addr(2), _addr(3), _addr(4))
check("fixture: the four addresses are distinct",
      len({ENTRY_A, MIX_A, MIX_B, FOREIGN}) == 4)

# ENTRY at account 9/1 so the mix message's numbers are unambiguous.
IDX = {ENTRY_A: (9, 1), MIX_A: (11, 1), MIX_B: (12, 1)}


def _rse(dests):
    """Run the REAL guard with `dests` as --exit-to. Returns the abort msg."""
    return aborts(ghost.reject_self_exit,
                  types.SimpleNamespace(exit_to=dests), dict(IDX), ENTRY_A)


# -- the two unrecoverable outcomes ---------------------------------------
_m = _rse([ENTRY_A])
check("self-exit: --exit-to ENTRY aborts", _m is not None)
check("self-exit: ...and says it is ENTRY, not just 'your own address'",
      _m is not None and "ENTRY" in _m)
check("self-exit: ...and names WHY that one is the worst case (the public "
      "memo), so the operator cannot read it as pedantry",
      _m is not None and "memo" in _m.lower() and "OP_RETURN" in _m)

_m = _rse([MIX_A])
check("self-exit: --exit-to a mix subaddress aborts", _m is not None)
check("self-exit: ...and locates it (account 11 / subaddr 1), which is what "
      "the operator needs to tell WHICH address they pasted",
      _m is not None and "11" in _m and "subaddr 1" in _m)
check("self-exit: ...and says what it costs -- the merge create_subs exists "
      "to make impossible",
      _m is not None and "merg" in _m.lower())

# The two messages must not be one generic message. They describe different
# unrecoverable outcomes and different remedies.
_e, _x = _rse([ENTRY_A]), _rse([MIX_A])
check("self-exit: ENTRY and mix produce DIFFERENT messages", _e != _x)
check("self-exit: the mix message does NOT claim the memo risk (it is not "
      "true of a mix subaddress, and a wrong reason teaches the wrong lesson)",
      _x is not None and "OP_RETURN" not in _x)

# -- NON-VACUITY: it must let a real destination through -------------------
check("control: a FOREIGN address does not abort", _rse([FOREIGN]) is None)
check("control: several foreign addresses do not abort",
      _rse([FOREIGN, _addr(5), _addr(6)]) is None)
check("control: no --exit-to at all does not abort", _rse(None) is None)
check("control: an empty --exit-to list does not abort", _rse([]) is None)

# -- EVERY element, not just the first -------------------------------------
# A guard written as `if dests[0] in addr_index` passes every check above.
check("self-exit: ENTRY in the SECOND position still aborts",
      _rse([FOREIGN, ENTRY_A]) is not None)
check("self-exit: ...with the ENTRY message, not the mix one",
      (_rse([FOREIGN, ENTRY_A]) or "").count("OP_RETURN") == 1)
check("self-exit: a mix subaddress LAST in a longer list still aborts",
      _rse([FOREIGN, _addr(5), MIX_B]) is not None)
check("self-exit: ...and names THAT one's account (12), not the first "
      "entry's",
      "12" in (_rse([FOREIGN, _addr(5), MIX_B]) or ""))

# -- the abort must not print the address it is complaining about ----------
# The message goes to a terminal and into the operator's scrollback. ENTRY is
# the one string this pipeline exists to keep off the record.
for _label, _msg in (("ENTRY", _rse([ENTRY_A])), ("mix", _rse([MIX_A]))):
    _full = ENTRY_A if _label == "ENTRY" else MIX_A
    check(f"self-exit: the {_label} abort SCRUBS the address rather than "
          f"echoing all 95 characters", _msg is not None and _full not in _msg)


# -- WIRED: the real main() must reach this before the swap ----------------
#
# The guard is only worth anything if main() calls it, and calls it while the
# money is still in Bitcoin. Drive the real main() to that point with the
# network, the wallet and Tor stubbed, and use tor_recheck's OWN stage label
# to prove where execution got to: "stage2_exec" is the first thing after the
# call site, so reaching it means the guard ran and let the run continue.
class _PastGuard(Exception):
    pass


def _drive_main(exit_to, receive=False):
    """Run the REAL main() to the swap. Returns ('past', None) if the guard
    allowed the run through, or ('abort', msg) if it stopped it."""
    subs_fixture = [ENTRY_A, MIX_A, MIX_B, _addr(5), _addr(6)]
    idx_fixture = {a: (10 + i, 1) for i, a in enumerate(subs_fixture)}
    saved = {n: getattr(ghost, n) for n in
             ("verify_tor", "require_resources", "check_daemon_relay_egress",
              "connect_rpc", "stage0_preflight", "stage1_joinmarket",
              "resolve_mix_account", "create_subs", "create_entry_set",
              "newnym", "tor_recheck",
              "validate_xmr_address", "resolve_wallet_password",
              "resolve_sensitive_inputs", "run_lock", "integrity_log")}
    _argv = sys.argv[:]
    try:
        ghost.verify_tor = lambda *a, **k: None
        ghost.require_resources = lambda *a, **k: None
        ghost.check_daemon_relay_egress = lambda *a, **k: {
            "verdict": "tor", "onion": 4, "clear": 0, "detail": "ok"}
        ghost.connect_rpc = lambda *a, **k: object()
        ghost.stage0_preflight = lambda *a, **k: (object(), object(), D("0.001"))
        ghost.stage1_joinmarket = lambda *a, **k: []
        ghost.resolve_mix_account = lambda *a, **k: None
        ghost.create_subs = lambda *a, **k: (list(subs_fixture),
                                             dict(idx_fixture), set())
        # The entry set is minted separately now (create_entry_set), so the
        # fixture supplies it rather than letting main() steal subs[0].
        ghost.create_entry_set = lambda rpc, n: [(subs_fixture[0], 10, 1)]
        ghost.newnym = lambda *a, **k: None
        ghost.validate_xmr_address = lambda *a, **k: None
        ghost.resolve_wallet_password = lambda *a, **k: None
        ghost.resolve_sensitive_inputs = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None

        @contextlib.contextmanager
        def _nolock(*a, **k):
            yield None
        ghost.run_lock = _nolock

        def _tr(_proxy, stage):
            if stage == "stage2_exec":
                raise _PastGuard()
        ghost.tor_recheck = _tr

        sys.argv = ["GhostSpiral", "--btc-entry",
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    "--tor-proxy", "socks5h://127.0.0.1:9050",
                    "--exit-to", exit_to]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ghost.main()
        except _PastGuard:
            return "past", None
        except SystemExit as e:
            return "abort", str(e.code)
        return "returned", None
    finally:
        for n, v in saved.items():
            setattr(ghost, n, v)
        sys.argv = _argv


# ENTRY is subs[0] in send mode, and the fixture puts ENTRY_A there.
_state, _msg = _drive_main(ENTRY_A)
check("wired: the REAL main() aborts on --exit-to == its own ENTRY",
      _state == "abort")
check("wired: ...with the self-exit message, not some other abort",
      _state == "abort" and _msg is not None and "OP_RETURN" in _msg)

_state, _msg = _drive_main(MIX_B)
check("wired: the REAL main() aborts on --exit-to == one of its own mix "
      "subaddresses", _state == "abort")
check("wired: ...with the merge message", _state == "abort"
      and _msg is not None and "merg" in _msg.lower())

# AND IT ABORTS BEFORE ANY MONEY MOVES. Reaching stage2_exec is the swap being
# executed; the guard must fire strictly before that, so the two runs above
# must NOT be 'past'. This control proves 'past' is reachable at all -- without
# it, a guard that aborted on everything would look identical.
_state, _msg = _drive_main(FOREIGN)
check("control: a FOREIGN --exit-to lets the real main() run ON to the swap "
      "(so the two aborts above are the guard, not a broken fixture)",
      _state == "past")


# ==========================================================================
# create_subs must PROVE the wallet gave it separate accounts
#
# One account per output is what this pipeline calls its exit defence, and it
# works only because a Monero transaction cannot spend across accounts. Two
# outputs sharing an account CAN be merged, and nothing downstream looks --
# the run would print the guarantee and be wrong. A repeated ADDRESS is worse
# still: addr_index is keyed by address, so the duplicate collapses two
# entries into one while subs keeps both, and fanout_by_addr = dict(zip(...))
# then drops one output's amount without a word.
#
# Defence in depth against a wallet that misnumbers, not a reproduced bug --
# but every other RPC answer here is verified the same way for the same
# reason, and this is the answer the central guarantee rests on.
# ==========================================================================
print("\n=== create_subs verifies the separation it promises ===")


class _SubsRPC:
    """A wallet-rpc that hands out accounts/addresses from scripted lists."""

    def __init__(self, accounts, addresses):
        self._accts = list(accounts)
        self._addrs = list(addresses)

    def raw_request(self, method, params):
        if method == "create_account":
            return {"account_index": self._accts.pop(0)}
        raise AssertionError(method)

    def new_subaddress_indexed(self, account_index=0, label=""):
        return self._addrs.pop(0), 1


def _mk(seed, k):
    return [_addr(1000 + seed * 100 + i) for i in range(k)]


def _run_subs(accounts, addresses, n, decoys):
    return aborts(ghost.create_subs, _SubsRPC(accounts, addresses), n, decoys)


# -- the honest wallet still works -----------------------------------------
_good = _mk(1, 5)
_msg = _run_subs([1, 2, 3, 4, 5], list(_good), 3, 2)
check("control: a wallet numbering 1,2,3,4,5 with distinct addresses is "
      "accepted", _msg is None)

def _subs_or_none(*a, **k):
    """create_subs's return value, or None if it refused.

    NOT a bare call: a mutation that makes the check fire unconditionally
    would raise SystemExit straight out of the module and kill the suite
    before it printed a RESULT line — which reads as 'no result', not as a
    catch. Same pathology this file's harness was fixed for once already.
    """
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return ghost.create_subs(*a, **k)
    except SystemExit:
        return None


_ok = _subs_or_none(_SubsRPC([1, 2, 3, 4, 5], list(_good)), 3, 2)
check("control: ...and returns all five, each in its own account",
      _ok is not None and len(_ok[0]) == 5
      and len({a for a, _ in _ok[1].values()}) == 5)
check("control: ...with the last `decoys` marked as the extra outputs",
      _ok is not None and _ok[2] == set(_good[3:]))

# -- a repeated ACCOUNT ----------------------------------------------------
_msg = _run_subs([1, 2, 2, 4, 5], list(_good), 3, 2)
check("two outputs in the SAME account are REFUSED", _msg is not None)
check("...and the refusal says why it matters (a transaction CAN spend two "
      "subaddresses of one account)",
      _msg is not None and "same wallet account" in _msg.lower())

# -- a repeated ADDRESS ----------------------------------------------------
_dupaddr = list(_good)
_dupaddr[3] = _dupaddr[0]
_msg = _run_subs([1, 2, 3, 4, 5], _dupaddr, 3, 2)
check("the same subaddress handed out TWICE is REFUSED", _msg is not None)
check("...and the refusal names the silent half — the dropped fan-out amount",
      _msg is not None and "drop" in _msg.lower())

# -- the duplicate is caught wherever it falls -----------------------------
for _pos in (1, 4):
    _d = list(_good)
    _d[_pos] = _d[0]
    check(f"a duplicate address at position {_pos} is caught too",
          _run_subs([1, 2, 3, 4, 5], _d, 3, 2) is not None)
    _a = [1, 2, 3, 4, 5]
    _a[_pos] = _a[0]
    check(f"a duplicate account at position {_pos} is caught too",
          _run_subs(_a, list(_good), 3, 2) is not None)

# -- NOT vacuous: the old code would have sailed through -------------------
# Without the check, a duplicated address leaves subs longer than addr_index,
# which is exactly the silent state described above. Show that state is real
# so the refusal above is not guarding an impossibility.
_d = list(_good)
_d[3] = _d[0]
_subs_raw, _idx_raw = [], {}
for _i, (_ac, _ad) in enumerate(zip([1, 2, 3, 4, 5], _d)):
    _subs_raw.append(_ad)
    _idx_raw[_ad] = (_ac, 1)
check("control: a duplicate really does collapse addr_index while subs keeps "
      "both — the silent state the refusal exists to stop",
      len(_subs_raw) == 5 and len(_idx_raw) == 4)


# ==========================================================================
# --split 3 THROUGH THE REAL main(), as far as the swap.
#
# Every check above drives one function. This drives the pipeline: the real
# main(), with the network, the wallet and Tor faked, up to the point where it
# would ask the operator to send BTC. What it proves is the thing the unit
# tests cannot -- that the entry set is minted, sized and THREADED, and that
# each chunk's quote carries its own destination.
#
# The old code posted one address in every chunk's request body. That is the
# defect (G5), and it is invisible to any test that does not look at what
# actually went on the wire.
# ==========================================================================
print("\n=== --split 3 through the real main() ===")


class _SplitStop(Exception):
    """Raised from the quote poster once every chunk has been quoted."""


def _drive_split(n_chunks, wallets=6):
    """Run the REAL main() to the swap quotes. Returns the posted payloads."""
    posted = []
    subs_fixture = [_addr(2000 + i) for i in range(wallets + 4)]
    idx_fixture = {a: (30 + i, 1) for i, a in enumerate(subs_fixture)}
    entry_fixture = [(_addr(3000 + i), 60 + i, 1) for i in range(n_chunks)]
    saved = {n: getattr(ghost, n) for n in
             ("verify_tor", "require_resources", "check_daemon_relay_egress",
              "connect_rpc", "stage0_preflight", "stage1_joinmarket",
              "resolve_mix_account", "create_subs", "create_entry_set",
              "newnym", "tor_recheck", "validate_xmr_address",
              "resolve_wallet_password", "resolve_sensitive_inputs",
              "run_lock", "integrity_log", "safe_post", "btc_per_xmr_oracle",
              "secure_delay", "reject_self_exit")}
    _argv = sys.argv[:]
    try:
        ghost.verify_tor = lambda *a, **k: None
        ghost.require_resources = lambda *a, **k: None
        ghost.check_daemon_relay_egress = lambda *a, **k: {
            "verdict": "tor", "onion": 4, "clear": 0, "detail": "ok"}
        ghost.connect_rpc = lambda *a, **k: object()
        ghost.stage0_preflight = lambda *a, **k: (object(), object(), D("0.001"))
        ghost.stage1_joinmarket = lambda *a, **k: []
        ghost.resolve_mix_account = lambda *a, **k: None
        ghost.create_subs = lambda *a, **k: (list(subs_fixture),
                                             dict(idx_fixture), set())
        ghost.create_entry_set = lambda rpc, n: list(entry_fixture[:n])
        ghost.newnym = lambda *a, **k: None
        ghost.tor_recheck = lambda *a, **k: None
        ghost.validate_xmr_address = lambda *a, **k: None
        ghost.resolve_wallet_password = lambda *a, **k: None
        ghost.resolve_sensitive_inputs = lambda *a, **k: None
        ghost.integrity_log = lambda *a, **k: None
        ghost.secure_delay = lambda *a, **k: None
        ghost.btc_per_xmr_oracle = lambda *a, **k: None
        ghost.reject_self_exit = lambda *a, **k: None

        @contextlib.contextmanager
        def _nolock(*a, **k):
            yield None
        ghost.run_lock = _nolock

        def _post(url, payload, proxy):
            posted.append(dict(payload))
            if len(posted) >= n_chunks:
                # Everything this test is about has happened by now; stop
                # before the arrival wait, which would block for hours.
                raise _SplitStop()
            # depositAddress and memo live under `transaction` -- see
            # parse_swap_route, which reads them from there.
            return {"routes": [{
                "expectedOutput": "1.0",
                "transaction": {
                    "memo": "=:XMR.XMR:" + payload["destinationAddress"]
                            + ":0/1/0::0",
                    "depositAddress":
                        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}}]}
        ghost.safe_post = _post

        sys.argv = ["GhostSpiral", "--btc-entry",
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    "--btc-amount", "0.6",
                    "--split", str(n_chunks),
                    "--wallets", str(wallets),
                    "--tor-proxy", "socks5h://127.0.0.1:9050"]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ghost.main()
        except _SplitStop:
            pass
        except SystemExit as e:
            return posted, str(e.code)
        return posted, None
    finally:
        for n, v in saved.items():
            setattr(ghost, n, v)
        sys.argv = _argv


_posted, _err = _drive_split(3)
check(f"e2e: a --split 3 run reaches the quote stage (err={_err})",
      len(_posted) == 3)
check("e2e: THREE quotes were posted, one per chunk", len(_posted) == 3)
_dests = [p["destinationAddress"] for p in _posted]
check("e2e: ...each naming a DIFFERENT destination — this is G5",
      len(set(_dests)) == 3)
check("e2e: ...and they are the run's own entry addresses, in chunk order",
      _dests == [_addr(3000 + i) for i in range(3)])
check("e2e: the BTC amount was split three ways",
      len({p["sellAmount"] for p in _posted}) <= 2       # remainder on chunk 0
      and all(D(p["sellAmount"]) > 0 for p in _posted))

# CONTROL: one chunk still posts one address, exactly as before.
_p1, _e1 = _drive_split(1)
check("control: a one-chunk run posts ONE quote", len(_p1) == 1)
check("control: ...to the single entry address",
      _p1[0]["destinationAddress"] == _addr(3000))

# THE REGRESSION THIS EXISTS FOR: if the destination ever goes back to being
# one shared value, the check above turns red. Show what that looked like.
check("control: three chunks sharing one destination would be visible here — "
      "the set of posted destinations would collapse to one",
      len({_addr(3000)}) == 1 and len(set(_dests)) == 3)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
