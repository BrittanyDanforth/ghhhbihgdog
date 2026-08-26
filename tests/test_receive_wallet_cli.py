#!/usr/bin/env python3
"""create_receive_wallet's argument gates, which no test executed.

Coverage across all 14 suites put this tool at 40% -- the lowest in the repo --
with 7 abort lines never run. It mints the receive subaddress the ENTIRE
pipeline is built around, and its gates encode real OPSEC decisions:

  * --count > 1 with --account pins every receive to ONE account, so they share
    a change sink and the separation --count exists for is silently lost.
  * account 0's subaddress 0 is the wallet's PRIMARY address. The tool refuses
    to FALL BACK to it when fresh-account creation fails, because every
    leftover from mixing would come to rest on the operator's identity.
  * --tor-proxy is mandatory before any RPC contact.

These are argument-parsing and gate checks: no daemon, no wallet, no binaries.
They run the REAL main() and assert on its exit, rather than re-implementing
the conditions.
"""
import re
import importlib.machinery, importlib.util, io, os, sys, contextlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

_ld = importlib.machinery.SourceFileLoader(
    "create_receive_wallet", os.path.join(REPO, "create_receive_wallet"))
crw = importlib.util.module_from_spec(
    importlib.util.spec_from_loader(_ld.name, _ld))
_ld.exec_module(crw)

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


def run(argv):
    """Drive the real main(). Returns (exit_code_or_None, combined_output)."""
    old = sys.argv
    sys.argv = ["create_receive_wallet"] + argv
    buf = io.StringIO()
    code = None
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            crw.main()
    except SystemExit as e:
        code = e.code
    except Exception as e:                                   # noqa: BLE001
        return ("RAW-%s" % type(e).__name__, f"{e}")
    finally:
        sys.argv = old
    return code, buf.getvalue()


# --count must be sane, and the message must name the flag.
_c, _o = run(["--count", "0", "--tor-proxy", "socks5h://127.0.0.1:9050"])
check("--count 0 is refused, not silently treated as 1",
      _c not in (None, 0) and "--count must be at least 1" in f"{_c}{_o}")
_c, _o = run(["--count", "-3", "--tor-proxy", "socks5h://127.0.0.1:9050"])
check("a negative --count is refused", _c not in (None, 0))

# THE SEPARATION GATE. --count exists to give each receive its own account;
# --account pins them all to one, which silently defeats it.
_c, _o = run(["--count", "3", "--account", "5",
              "--tor-proxy", "socks5h://127.0.0.1:9050"])
check("--count > 1 together with --account is refused",
      _c not in (None, 0))
check("...and the message explains the separation that would be lost",
      "share a change sink" in f"{_c}{_o}")
_c, _o = run(["--count", "1", "--account", "5",
              "--tor-proxy", "socks5h://127.0.0.1:9050"])
check("--count 1 with --account is allowed (no separation to lose)",
      "share a change sink" not in f"{_c}{_o}")

# Tor is mandatory, and is checked BEFORE any RPC contact.
_c, _o = run(["--count", "1"])
check("a missing --tor-proxy aborts", _c not in (None, 0))
check("...naming the flag rather than failing later at the RPC",
      "--tor-proxy is REQUIRED" in f"{_c}{_o}")

# A bad numeric argument must not produce a raw traceback (the type=Decimal
# trap that hit every other tool in this repo).
_c, _o = run(["--count", "abc", "--tor-proxy", "socks5h://127.0.0.1:9050"])
check("a non-numeric --count is an argparse error, never a traceback",
      isinstance(_c, int) and _c != 0 and "Traceback" not in _o)

# The refusal to fall back to account 0 must be stated in the source that
# handles a failed fresh-account creation: account 0 subaddress 0 is the
# wallet's PRIMARY address. Asserted at source level because reaching that
# branch needs a live wallet-rpc that fails mid-call.
_src = open(os.path.join(REPO, "create_receive_wallet")).read()
check("a failed fresh-account creation refuses to fall back to account 0",
      "Refusing to fall back to account 0" in _src)
check("...and an explicit --account 0 is still warned about as the PRIMARY "
      "address", "You asked for account 0" in _src)

# ---- THE GUIDANCE MUST NOT WALK PAST A GATE THIS TOOLCHAIN ADDED --------
#
# print_next_steps prints the thor_swap_preparer command the operator is meant
# to run next, and it omitted --min-out-xmr -- the gate that refuses a quote
# too small to mix, at the one moment refusing is free. Following the printed
# command produced a quote with no minimum, so the payment settled and only
# then met the mixing floor, with the money on an address the swap memo names
# publicly. The function's own docstring states the rule it was breaking:
# "a fix that the guidance walks the operator around is not a fix."
check("next steps: the printed quote command carries the minimum gate",
      "--min-out-xmr" in _src)
check("next steps: ...and does not print a figure for it, because the figure "
      "moves with the network fee and only GhostSpiral can compute it",
      "--print-limits" in _src
      and not re.search(r"--min-out-xmr\s+0\.\d", _src))
# NON-VACUITY: it still prints the two flags that were always there, so this
# is an addition rather than a rewrite that dropped something.
check("next steps: NON-VACUITY -- the destination and proxy flags survive",
      "--dest-from-receive-wallet" in _src and "--tor-proxy" in _src)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
else:
    print("ALL GREEN")
sys.exit(1 if FAIL else 0)
