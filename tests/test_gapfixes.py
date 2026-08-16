#!/usr/bin/env python3
"""Executable tests for the paranoia_mode and exit_strategy_simulator gap fixes.

Both drive the REAL functions. Confirmed to FAIL against the pre-fix build.
"""
import sys, os, subprocess, tempfile, importlib.util, importlib.machinery
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


_scratch = tempfile.mkdtemp(prefix="gs_gap_")
os.chdir(_scratch)
para = load("paranoia_mode")


class FakeIp:
    """Records `ip` invocations; fails `set <iface> address` like a driver that
    refuses the change (the realistic failure, and the one that used to strand
    the interface administratively DOWN)."""

    def __init__(self, fail_on="address"):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        if self.fail_on and self.fail_on in argv:
            raise subprocess.CalledProcessError(
                2, argv, output=b"", stderr=b"RTNETLINK answers: Operation not supported")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def did(self, *words):
        return any(all(w in c for w in words) for c in self.calls)


# --------------------------------------------------------------------------
# 1. A failed MAC spoof must not leave the interface DOWN.
#    Pre-fix: down → set address (raises) → the `up` was skipped entirely, so
#    a spoof that failed for lack of root killed the operator's networking.
# --------------------------------------------------------------------------
def test_failed_mac_spoof_restores_interface():
    ip = FakeIp()
    logged = []
    old_run, old_log = para.subprocess.run, para.integrity_log
    para.subprocess.run = ip
    para.integrity_log = lambda tag, msg: logged.append(msg)
    try:
        para.spoof_mac("wlan0", dry=False)
    finally:
        para.subprocess.run, para.integrity_log = old_run, old_log

    check("failed MAC spoof brings the interface back UP", ip.did("up", "wlan0"))
    check("failed MAC spoof is recorded", any("mac_fail" in m for m in logged))


def test_successful_mac_spoof_restores_interface():
    ip = FakeIp(fail_on=None)
    old_run, old_log = para.subprocess.run, para.integrity_log
    para.subprocess.run = ip
    para.integrity_log = lambda tag, msg: None
    try:
        para.spoof_mac("wlan0", dry=False)
    finally:
        para.subprocess.run, para.integrity_log = old_run, old_log
    check("successful MAC spoof brings the interface back UP", ip.did("up", "wlan0"))


def test_mac_restore_failure_is_reported():
    """If even the `up` fails, the operator must be told -- silence here means
    an offline machine with no explanation."""
    class DownAndOut(FakeIp):
        def __call__(self, argv, **kw):
            self.calls.append(list(argv))
            if "down" in argv:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            raise subprocess.CalledProcessError(2, argv, output=b"", stderr=b"nope")

    ip = DownAndOut()
    logged = []
    old_run, old_log = para.subprocess.run, para.integrity_log
    para.subprocess.run = ip
    para.integrity_log = lambda tag, msg: logged.append(msg)
    try:
        para.spoof_mac("wlan0", dry=False)
    finally:
        para.subprocess.run, para.integrity_log = old_run, old_log
    check("an interface stuck DOWN is logged", any("still_down" in m for m in logged))


# --------------------------------------------------------------------------
# 2. The spoofed MAC must never reach the persistent integrity chain.
#    Pre-fix it logged `mac_spoof:wlan0->e2:03:bd:...`, persisting the exact
#    value the spoof exists to make unlinkable.
# --------------------------------------------------------------------------
def _mac_leaked(logged):
    import re
    pat = re.compile(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}")
    return [m for m in logged if pat.search(m)]


def test_spoofed_mac_never_written_to_integrity_log():
    for dry in (False, True):
        ip = FakeIp(fail_on=None)
        logged = []
        old_run, old_log = para.subprocess.run, para.integrity_log
        para.subprocess.run = ip
        para.integrity_log = lambda tag, msg: logged.append(msg)
        try:
            para.spoof_mac("wlan0", dry=dry)
        finally:
            para.subprocess.run, para.integrity_log = old_run, old_log
        check(f"MAC value not persisted to the chain (dry={dry})",
              not _mac_leaked(logged))
        check(f"a spoof is still recorded as having happened (dry={dry})",
              any("mac_" in m for m in logged))


def test_rand_mac_is_locally_administered_unicast():
    """A spoofed MAC must be locally-administered (bit 1 of octet 0) and
    unicast (bit 0 clear), or it is itself a fingerprint / breaks the link."""
    bad = []
    for _ in range(200):
        first = int(para.rand_mac().split(":")[0], 16)
        if not (first & 0b10) or (first & 0b01):
            bad.append(first)
    check("rand_mac is always locally-administered unicast", not bad)


# --------------------------------------------------------------------------
# 3. exit_strategy_simulator --redact must actually mask the magnitudes.
#    The header used to CLAIM terminal output was redacted while printing the
#    exact holding and its exact fiat value.
# --------------------------------------------------------------------------
def _run_exit_sim(args, prices):
    """Drive the real main() with the price oracle and Tor stubbed."""
    sim = load("exit_strategy_simulator")
    sim.verify_tor = lambda *a, **k: None
    sim.validate_proxy = lambda p: {"http": p, "https": p}
    sim.integrity_log = lambda *a, **k: None
    sim.install_signal_handlers = lambda *a, **k: None
    sim.fetch_prices = lambda proxy: prices
    out = os.path.join(_scratch, "plan.json")
    sys.argv = ["exit_strategy_simulator", *args,
                "--tor-proxy", "socks5h://127.0.0.1:9050", "--outfile", out]
    import io
    buf = io.StringIO()
    real, sys.stdout = sys.stdout, buf
    try:
        sim.main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    finally:
        sys.stdout = real
    return code, buf.getvalue(), out


PRICES = {"xmr_usd": Decimal("162.35"), "btc_usd": Decimal("64000"),
          "source": "stub"}


def test_redact_masks_amount_and_value():
    _, plain, _ = _run_exit_sim(["137.4491"], PRICES)
    check("without --redact the figures are shown (documented behaviour)",
          "137.4491" in plain)

    code, red, outfile = _run_exit_sim(["137.4491", "--redact"], PRICES)
    check("--redact is accepted", code == 0 and "Value" in red)
    check("--redact hides the gross amount", "137.4491" not in red)
    value_line = (red.split("Value", 1)[1].split("\n")[0] if "Value" in red else "")
    check("--redact hides the fiat value",
          bool(value_line) and "22" not in value_line.replace("USD", ""))
    check("--redact still shows the method", "bisq" in red)
    check("--redact still shows liquidity guidance", "Liquidity" in red)

    import json
    plan = {}
    if os.path.exists(outfile):
        with open(outfile) as f:
            plan = json.load(f)
    check("--redact does NOT weaken the saved plan",
          plan.get("amount_in_xmr") == "137.4491")
    check("the saved plan file is 0600",
          os.path.exists(outfile) and oct(os.stat(outfile).st_mode)[-3:] == "600")


def test_header_no_longer_claims_terminal_is_redacted():
    """The specific false claim that was in the docstring."""
    src = open(os.path.join(REPO, "exit_strategy_simulator")).read()
    head = src.split('"""')[1]
    # The claim was an OPSEC bullet. Quoting it in prose to document the fix is
    # fine; asserting it as a live guarantee is not -- so check the bullets.
    bullets = [l.strip() for l in head.splitlines() if l.strip().startswith("- ")]
    check("no OPSEC bullet claims terminal output is redacted",
          not any("leaked to terminal" in b or
                  ("redacted" in b.lower() and "--redact" not in b)
                  for b in bullets))
    check("header states output is not redacted by default",
          "NOT REDACTED BY DEFAULT" in head)
    check("header documents --redact instead", "--redact" in head)


def test_amounts_never_reach_the_integrity_chain():
    """The header claims amounts are NOT written to the chain -- verify it."""
    logged = []
    sim = load("exit_strategy_simulator")
    sim.verify_tor = lambda *a, **k: None
    sim.validate_proxy = lambda p: {"http": p, "https": p}
    sim.install_signal_handlers = lambda *a, **k: None
    sim.fetch_prices = lambda proxy: PRICES
    sim.integrity_log = lambda tag, msg: logged.append(msg)
    out = os.path.join(_scratch, "plan2.json")
    sys.argv = ["x", "137.4491", "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--outfile", out]
    import io
    real, sys.stdout = sys.stdout, io.StringIO()
    try:
        sim.main()
    except SystemExit:
        pass
    finally:
        sys.stdout = real
    check("no amount reaches the integrity chain",
          not any("137" in m or "22" in m for m in logged))
    check("the off-ramp method IS recorded", any("bisq" in m for m in logged))


def run_all():
    for fn in sorted([f for n, f in globals().items() if n.startswith("test_")],
                     key=lambda f: f.__name__):
        fn()
    print(f"\n  gapfixes: {PASS} passed, {FAIL} failed")
    if FAILURES:
        for f in FAILURES:
            print(f"    - {f}")
    return FAIL


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
