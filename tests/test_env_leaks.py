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
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    mod = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(mod)
    return mod


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


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
