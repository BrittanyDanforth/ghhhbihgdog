#!/usr/bin/env python3
"""SENSITIVE VALUES MUST NOT REACH argv, NOR A THIRD-PARTY CHILD.

Two publication channels, one rule.

  * /proc/<pid>/cmdline is mode 0444 -- every account on the host can read a
    running process's arguments, for the whole several-hour life of a run.
    /proc/<pid>/environ is 0400. env_or_argv exists for exactly this, and its
    docstring says it exists "so the next caller cannot half-apply the
    lesson", having been written after the off-ramp amount, then the BTC entry
    address, then the swap amounts each went on argv in turn.
  * subprocess.run() with no env= hands the child a COPY OF OUR WHOLE
    ENVIRONMENT. Moving a value out of argv and into the environment is not a
    fix if the environment is then handed verbatim to JoinMarket's tumbler.

Both were being broken at once, in opposite directions:

  --exit-to was the LAST sensitive input with no environment path, and the
  most sensitive one there is -- the operator's final destination, the single
  value the whole pipeline exists to unlink from the public ThorChain memo.
  gs_console composed it onto GhostSpiral's argv while passing the lesser
  values by environment, and OPSEC_SETUP.md described that arrangement as
  "the console hands its children the sensitive values through the
  environment, not argv ... which is why no secret appears in it".

  GS_EXPECT_TOTAL_XMR was added to get the swapped total OFF argv and landed
  in an environment _child_env passed straight to the third-party tumbler,
  under the comment "third-party child: password scrubbed". _child_env popped
  the wallet password and nothing else, under a docstring whose own argument
  -- "a third-party child that logs or dumps its environment would leak it" --
  covers every other GS_ variable word for word.

Driven, not read.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import re
import sys
import types
from decimal import Decimal as D

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    mod = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(mod)
    return mod


import gs_common as _gsc
ghost = load("GhostSpiral")
console = load("gs_console")

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


A1 = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98"
      "uNbr2VBBEt7f2wfn3RVGQBEP3A")
A2 = ("43ZYYZBkwxZJNJFo6rGHf5KREAGR3LizKKXN3aPDCHYj1AAfkqEipXs4x9nnrTq2FuaqXM"
      "qLrVtED1kV2Z77b6NGE6FFTCm")

# ==========================================================================
# 1. the child environment
# ==========================================================================
print("=== what a third-party child is handed ===")

_saved = {k: os.environ.get(k) for k in
          ("GS_BTC_ENTRY", "GS_BTC_AMOUNT", "GS_EXPECT_TOTAL_XMR",
           "GS_EXIT_TO", "GS_WALLET_PASSWORD")}
try:
    os.environ["GS_BTC_ENTRY"] = "bc1qOPERATORS_OWN_BITCOIN_ADDRESS"
    os.environ["GS_BTC_AMOUNT"] = "0.4213"
    os.environ["GS_EXPECT_TOTAL_XMR"] = "12.7431"
    os.environ["GS_EXIT_TO"] = A1
    os.environ["GS_WALLET_PASSWORD"] = "spend-key-password"

    _third = ghost._child_env()
    _leaked = {k: v for k, v in _third.items() if k.startswith("GS_")}
    check("no GS_ variable reaches a third-party child", _leaked == {})
    check("...specifically not the operator's Bitcoin address",
          "GS_BTC_ENTRY" not in _third)
    check("...nor the swapped total that was moved off argv to 'protect' it",
          "GS_EXPECT_TOTAL_XMR" not in _third)
    check("...nor the exit destination", "GS_EXIT_TO" not in _third)
    check("...nor the wallet password (which was the only one ever removed)",
          "GS_WALLET_PASSWORD" not in _third)

    # Non-vacuity: the variables really are set, so an empty result means
    # scrubbed rather than never-present.
    check("control: the variables ARE in this process's environment",
          all(os.environ.get(k) for k in
              ("GS_BTC_ENTRY", "GS_EXPECT_TOTAL_XMR", "GS_EXIT_TO")))

    # The sign child is the one exception, and gets ONLY the password.
    _sign = ghost._child_env("spend-key-password")
    check("the SIGN child gets the wallet password (it is the one that needs it)",
          _sign.get("GS_WALLET_PASSWORD") == "spend-key-password")
    check("...and still no other GS_ variable",
          [k for k in _sign if k.startswith("GS_")] == ["GS_WALLET_PASSWORD"])

    # It is a scrub, not a wipe: children still need a working environment.
    check("the rest of the environment survives (PATH is still there)",
          "PATH" in _third and _third["PATH"] == os.environ["PATH"])
finally:
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ==========================================================================
# 2. the exit destination: environment first, argv warns
# ==========================================================================
print("\n=== the exit destination ===")


def resolve(argv_dests, env_dests=None):
    """Drive the REAL resolve_exit_destinations. Returns (args.exit_to, out)."""
    saved = os.environ.get("GS_EXIT_TO")
    saved_v = ghost.validate_xmr_address
    try:
        if env_dests is None:
            os.environ.pop("GS_EXIT_TO", None)
        else:
            os.environ["GS_EXIT_TO"] = env_dests
        # The checksum validator needs python-monero, which is not installable
        # in every container. The channel is what is under test here.
        ghost.validate_xmr_address = lambda *a, **k: None
        ns = types.SimpleNamespace(exit_to=argv_dests)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ghost.resolve_exit_destinations(ns)
        return ns.exit_to, buf.getvalue()
    finally:
        ghost.validate_xmr_address = saved_v
        if saved is None:
            os.environ.pop("GS_EXIT_TO", None)
        else:
            os.environ["GS_EXIT_TO"] = saved


_d, _o = resolve(None, A1)
check("GS_EXIT_TO supplies the destination with no flag at all", _d == [A1])
check("...silently, because the environment is not world-readable",
      "command line" not in _o)

_d, _o = resolve(None, f"{A1} {A2}")
check("GS_EXIT_TO carries several destinations, whitespace separated",
      _d == [A1, A2])
_d, _o = resolve(None, f"{A1},{A2}")
check("...and comma separated", _d == [A1, A2])

_d, _o = resolve([A1], None)
check("--exit-to on argv still works", _d == [A1])
check("...but WARNS that it is world-readable", "command line" in _o)
check("...and names the variable to use instead", "GS_EXIT_TO" in _o)

_d, _o = resolve([A2], A1)
check("the environment wins over argv, as everywhere else in this toolchain",
      _d == [A1])

_d, _o = resolve(None, None)
check("no destination anywhere is still fine (nothing is withdrawn)",
      not _d)


# ==========================================================================
# 3. the console must not put it on a command line
# ==========================================================================
print("\n=== the console's command preview ===")

_params = {"btc_entry": "bc1qOPERATOR", "btc_amount": "0.42",
           "exit_to": [A1, A2]}
_argv, _why = console.pipeline_argv(_params)
_env = console.secret_env(_params)

check("the exit destination is NOT on the argv the console builds",
      not any(A1 in str(x) or A2 in str(x) for x in _argv))
check("...and --exit-to is not composed at all",
      "--exit-to" not in _argv)
check("the exit destination IS in the environment instead",
      _env.get("GS_EXIT_TO") == f"{A1} {A2}")
check("the other sensitive values are still by environment too",
      _env.get("GS_BTC_ENTRY") == "bc1qOPERATOR"
      and not any("bc1qOPERATOR" in str(x) for x in _argv))

# The argv IS the preview the page renders, which is why this matters.
check("nothing sensitive is left anywhere in the rendered command",
      not any(v in " ".join(str(x) for x in _argv)
              for v in (A1, A2, "bc1qOPERATOR", "0.42")))

# ...and the doc that asserted this must now be true.
_doc = open(os.path.join(REPO, "OPSEC_SETUP.md"), encoding="utf-8").read()
check("OPSEC_SETUP lists GS_EXIT_TO among the values passed by environment",
      "GS_EXIT_TO" in _doc)



# ==========================================================================
# F8: THE ENVIRONMENT PATH BYPASSED THE ARGV PATH'S VALIDATION
# ==========================================================================
print("\n=== numeric values from the environment ===")
#
# Every numeric flag is declared type=decimal_arg, which exists because
# type=Decimal answers a typo with a raw traceback and because Decimal ACCEPTS
# "NaN" and "Infinity". Then the same tools grew GS_* variables, PREFERRED over
# argv because /proc/<pid>/cmdline is world-readable — and every one re-parsed
# with a bare Decimal(). The preferred path was the unvalidated one.
#
# Measured before the fix: `GS_EXPECT_XMR=Infinity receive_watch ...` produced
# an uncaught ValueError traceback out of accept_floor.
import subprocess as _sp2, json as _json2, tempfile as _tf2

_RWA = ("83Ss8Wx9CmH4EaWkan3bdGhAybs7r3xgHZnMeWMNgwwdW3BJc6nfjTbFL9V4Go9Lx"
        "ZjUvDCX9H416cHR68m8aLc6FUZFVRJ")
_bdir = _tf2.mkdtemp(prefix="f8_")
_bundle = os.path.join(_bdir, "b.json")
with open(_bundle, "w") as _fh:
    _json2.dump({"schema": "gs_receive_wallet_v1", "address": _RWA,
                 "account_index": 3, "subaddress_index": 1, "wallet_file": "w",
                 "nettype": "mainnet", "created": "2026-01-01T00:00:00Z"}, _fh)


def _run_env(tool, env_name, value, extra):
    e = dict(os.environ)
    e[env_name] = value
    e.pop("GS_EXIT_TO", None)
    p = _sp2.run([sys.executable, os.path.join(REPO, tool)] + extra,
                 capture_output=True, text=True, timeout=90, env=e, cwd=_bdir)
    return (p.stdout + p.stderr)


_CASES = [
    ("receive_watch", "GS_EXPECT_XMR",
     ["--receive-wallet", _bundle, "--tor-proxy", "socks5h://127.0.0.1:9050"]),
    ("thor_swap_preparer", "GS_SWAP_AMOUNTS",
     ["--dests", _RWA, "--tor-proxy", "socks5h://127.0.0.1:9050"]),
]
for _tool, _var, _extra in _CASES:
    for _bad, _why in (("Infinity", "finite"), ("NaN", "finite"),
                       ("notanumber", "number")):
        _out = _run_env(_tool, _var, _bad, _extra)
        check(f"F8: {_var}={_bad} is refused by name, not by traceback",
              _var in _out and "Traceback" not in _out and _why in _out)
    # ...and a VALID value must still get through. Asserting the ABSENCE of an
    # error is not enough: the first version of decimal_env took (text, label)
    # instead of (label, text), so every call parsed the variable NAME and
    # aborted on valid input — and a check that only grepped for "Traceback"
    # passed it.
    _ok = _run_env(_tool, _var, "2.5", _extra)
    check(f"F8: {_var}=2.5 is ACCEPTED (the tool proceeds past parsing)",
          "is not a number" not in _ok and "not a finite" not in _ok
          and "must be positive" not in _ok)

# GhostSpiral's two, same shape.
_GSE = ["--tor-proxy", "socks5h://127.0.0.1:9050"]
_gs_env = dict(os.environ)
for _var in ("GS_BTC_AMOUNT", "GS_EXPECT_TOTAL_XMR"):
    _e = dict(os.environ)
    _e["GS_BTC_ENTRY"] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    _e[_var] = "Infinity"
    _e.pop("GS_EXIT_TO", None)
    _p = _sp2.run([sys.executable, os.path.join(REPO, "GhostSpiral")] + _GSE,
                  capture_output=True, text=True, timeout=90, env=_e, cwd=_bdir)
    _o = _p.stdout + _p.stderr
    check(f"F8: {_var}=Infinity is refused by name, not by traceback",
          _var in _o and "Traceback" not in _o and "finite" in _o)

# The helper itself, directly — including the argument order that was wrong.
check("F8: decimal_env takes (label, value), not (value, label)",
      _gsc.decimal_env("GS_X", "2.5") == D("2.5"))
for _v in ("Infinity", "NaN", "abc"):
    _r = None
    try:
        _gsc.decimal_env("GS_X", _v)
    except SystemExit as _e:
        _r = str(_e)
    check(f"F8: decimal_env refuses {_v!r}", _r is not None and "GS_X" in _r)
check("F8: ...and its rules match decimal_arg's, which the argv path uses",
      not D("Infinity").is_finite() and not D("NaN").is_finite())



# ==========================================================================
# F9: THE TOOL CHMOD'ED THE DIRECTORY YOU RAN IT IN
# ==========================================================================
print("\n=== operator-chosen directories are not this tool's to modify ===")
#
# create_receive_wallet's --output-dir defaults to ".", and secure_mkdir
# deliberately NARROWS a pre-existing directory's mode (its docstring says so:
# "exist_ok=True silently keeps a pre-existing directory's mode ... It is
# narrowed too"). So every run chmod'ed the operator's current working
# directory to 0700. Measured: 755 -> 700.
#
# It only ever narrows, so nothing leaked. Silently changing the permissions of
# a directory you were merely asked to write a file into is still not the
# tool's business, and "it was only tightened" is not a defence.
import stat as _stat2, shutil as _sh2

_d9 = _tf2.mkdtemp(prefix="f9_")
_theirs = os.path.join(_d9, "operator_dir")
os.mkdir(_theirs)
os.chmod(_theirs, 0o755)
_gsc.secure_mkdir(_theirs, narrow_existing=False)
check("F9: a directory that ALREADY existed keeps its mode",
      _stat2.S_IMODE(os.stat(_theirs).st_mode) == 0o755)

# ...while one this toolchain CREATES is still made owner-only: the metadata
# leak secure_mkdir exists to close is real for staging dirs.
_ours = os.path.join(_d9, "made_by_us", "nested")
_gsc.secure_mkdir(_ours)
check("F9: a directory the tool CREATES is still 0700",
      _stat2.S_IMODE(os.stat(_ours).st_mode) == 0o700)
check("F9: ...including the parents it had to create",
      _stat2.S_IMODE(os.stat(os.path.dirname(_ours)).st_mode) == 0o700)

# Non-vacuity: the default still narrows, so the parameter is what changed the
# behaviour and not some unrelated edit.
_theirs2 = os.path.join(_d9, "operator_dir2")
os.mkdir(_theirs2)
os.chmod(_theirs2, 0o755)
_gsc.secure_mkdir(_theirs2)
check("control: secure_mkdir STILL narrows by default (the old behaviour is "
      "intact for callers that want it)",
      _stat2.S_IMODE(os.stat(_theirs2).st_mode) == 0o700)

# And the caller uses it. Checked over the AST, not by grepping for a string:
# a substring search would pass on `secure_mkdir(outdir)  # narrow_existing=False`.
import ast as _ast9
_crw = _ast9.parse(open(os.path.join(REPO, "create_receive_wallet")).read())
_calls = [n for n in _ast9.walk(_crw)
          if isinstance(n, _ast9.Call)
          and getattr(n.func, "id", None) == "secure_mkdir"]
check("F9: create_receive_wallet calls secure_mkdir exactly once",
      len(_calls) == 1)
check("F9: ...and passes narrow_existing=False as a real keyword argument",
      any(k.arg == "narrow_existing"
          and getattr(k.value, "value", None) is False
          for k in _calls[0].keywords))
_sh2.rmtree(_d9, ignore_errors=True)



# ==========================================================================
# F5: THE WIPE-COVERAGE WARNING EXISTED, AND TWO OF FOUR TOOLS USED IT
# ==========================================================================
print("\n=== artifacts written outside paranoia_mode's reach ===")
#
# gs_common.wipe_covers was written for exactly this and names the case in its
# own docstring: "Anything an operator redirects elsewhere -- `--output
# /mnt/usb/plans`, `--outfile /srv/exit.json` -- is never looked at, and
# nothing told them so, because both tools report success identically wherever
# they wrote."
#
# It was wired into GhostSpiral (--output) and exit_strategy_simulator
# (--outfile). thor_swap_preparer (--outfile) and create_receive_wallet
# (--output-dir, default ".") never called it — and thor's file is the worst
# one to leave uncovered: every pair carries the deposit address AND the memo,
# and the memo contains the destination XMR address in full. It is the single
# artifact tying the BTC side to the XMR side.
check("F5: wipe_covers says a repo-local path IS covered",
      _gsc.wipe_covers("thor_pairs_batch.json"))
check("F5: ...and a redirected one is NOT",
      not _gsc.wipe_covers("/mnt/usb/pairs.json"))

_F5D = "8" + "A" + "1" * 93
_F5DEP = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def _run_thor(outfile):
    """Drive the REAL thor main() to `outfile`, network stubbed."""
    m = load("thor_swap_preparer")
    for _stub in ("verify_tor", "newnym", "secure_delay",
                  "install_signal_handlers", "integrity_log"):
        setattr(m, _stub, lambda *a, **k: None)
    m.validate_proxy = lambda p: {"http": p, "https": p}
    m.shutdown_requested = lambda: False
    m._validate_xmr_addr = lambda a: None
    m.safe_get = lambda url, proxy=None: {"monero": {"btc": "0.005"}}
    m.safe_post = lambda url, payload, proxy=None: {"routes": [{
        "transaction": {"depositAddress": _F5DEP,
                        "memo": f"=:XMR.XMR:{_F5D}:0/1/0"},
        "expectedOutput": "1.0"}]}
    _argv = sys.argv
    sys.argv = ["thor", "--amounts", "0.005", "--dests", _F5D,
                "--outfile", str(outfile),
                "--tor-proxy", "socks5h://127.0.0.1:9050"]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            m.main()
    except SystemExit:
        pass
    finally:
        sys.argv = _argv
    return buf.getvalue()


import tempfile as _tf5
_away = os.path.join(_tf5.mkdtemp(prefix="f5_away_"), "pairs.json")
_out_away = _run_thor(_away)
check("F5: thor WARNS when its outfile is outside the wipe roots",
      "OUTSIDE the directories" in _out_away)
check("F5: ...and says what the file holds (the memo carries the XMR address)",
      "memo contains the destination XMR address" in _out_away)
check("F5: ...and the file really was written there",
      os.path.exists(_away))

# NON-VACUITY: writing somewhere the sweep DOES cover must NOT warn, or the
# check above would pass on a tool that warns unconditionally.
#
# THE NAME IS PART OF "COVERED" NOW. The sweep matches location AND filename,
# and this control used "f5_probe_pairs.json", which no pattern matches -- so
# under wipe_will_erase it warns, correctly: that file really would never be
# erased. Using a name the sweep actually sweeps is what this control meant
# all along; the old one passed only because the predicate was blind to names.
_cwd_out = os.path.join(os.getcwd(), "thor_pairs_batch.json")
try:
    _out_home = _run_thor(_cwd_out)
    check("F5 control: writing under the working directory does NOT warn",
          "OUTSIDE the directories" not in _out_home)
finally:
    if os.path.exists(_cwd_out):
        os.remove(_cwd_out)

# create_receive_wallet, same helper, same reason: the bundle names the receive
# address and its (account, subaddress) -- the pair report_holdings refuses to
# put on disk.
_crw_src = open(os.path.join(REPO, "create_receive_wallet")).read()
_crw_flat = re.sub(r"\s+", " ", _crw_src)
_crw_flat = re.sub(r'"\s*f?"', "", _crw_flat)
check("F5: create_receive_wallet asks whether its bundle will be ERASED, "
      "which needs the filename as well as the directory",
      "wipe_will_erase(fname)" in _crw_flat)
check("F5: ...and warns that the bundle will not be wiped",
      "will NOT be wiped with the rest of the run" in _crw_flat)
check("F5: ...naming what it discloses",
      "names the receive address and its account/subaddress" in _crw_flat)


# ===========================================================================
# A LIBRARY DOES NOT GET TO WRITE AN UNREDACTED RPC RESPONSE TO STDERR.
#
# Everything here redacts: scrub_address on operator lines, chain_safe on the
# integrity chain, amounts kept off argv. And then monero-python's
# raw_request() does, on any RPC error:
#
#     _log.error("JSON RPC error:\n{result}")     # the WHOLE response
#     _log.debug("Method: ...\nParams:\n{params}")  # the destinations
#
# A logger with no handler is not silent -- logging.lastResort is a
# StreamHandler on stderr at WARNING, measured -- so that reaches gs_console's
# retained job output, gs_wake_agent's job log and the operator's scrollback,
# by default, from a dependency, past every redactor in this repository.
import logging as _lg                                        # noqa: E402
import io as _io9, contextlib as _cl9                         # noqa: E402

check("logging.lastResort really is a stderr handler, so 'no handler' is not "
      "'no output' -- the premise of this section, measured rather than "
      "assumed",
      isinstance(_lg.lastResort, _lg.Handler)
      and _lg.lastResort.level <= _lg.ERROR)

for _name in ("monero", "monero.backends.jsonrpc.wallet",
              "monero.backends.jsonrpc.daemon"):
    _l = _lg.getLogger(_name)
    check(f"{_name} has a NullHandler and does not propagate to root",
          any(isinstance(h, _lg.NullHandler) for h in _l.handlers)
          and _l.propagate is False)

_err = _io9.StringIO()
with _cl9.redirect_stderr(_err):
    _lg.getLogger("monero.backends.jsonrpc.wallet").error(
        'JSON RPC error:\n{"dst": "44AAAA_A_REAL_LOOKING_ADDRESS"}')
check("...so an ERROR record carrying an address reaches no stream",
      "44AAAA" not in _err.getvalue())

check("the gag is OPT-OUTABLE and the source says so, because a permanent "
      "one hides the operator's own debugging from them",
      "GS_DEBUG_RPC_LOG" in open(os.path.join(REPO, "gs_common.py")).read())


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
