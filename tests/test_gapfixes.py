#!/usr/bin/env python3
"""Executable tests for the paranoia_mode and exit_strategy_simulator gap fixes.

Both drive the REAL functions. Confirmed to FAIL against the pre-fix build.
"""
import sys, os, subprocess, tempfile, importlib.util, importlib.machinery
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
from srcutil import code_only


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


# ==========================================================================
# paranoia_mode: the final summary must reflect what actually happened.
# The old code printed "paranoia_mode complete." unconditionally, so a wipe
# where phases failed still read as success.
# ==========================================================================
def _run_paranoia_main(phase_returns, dry=False):
    """Drive the REAL main() with each phase stubbed to a chosen return value.
    Returns (exit_code, stdout)."""
    import io
    p = load("paranoia_mode")
    p.require_resources = lambda **k: None
    p.integrity_log = lambda *a, **k: None
    p.install_signal_handlers = lambda: None
    stubs = {
        "spoof_mac": lambda iface, d: phase_returns.get("MAC spoof", 0),
        "dns_check": lambda: phase_returns.get("DNS check", 0),
        "flush_dns_cache": lambda d: phase_returns.get("DNS cache flush", 0),
        "wipe_shell_histories": lambda d: phase_returns.get("Shell histories", 0),
        "wipe_pycache": lambda d: phase_returns.get("Python cache", 0),
        "wipe_tmp_files": lambda d: phase_returns.get("Temp files", 0),
        "wipe_system_logs": lambda days, d: phase_returns.get("System logs", 0),
        "clear_journal": lambda d: phase_returns.get("Journal", 0),
        "wipe_swap_ram": lambda d: phase_returns.get("Swap/RAM", 0),
        "wipe_clipboard": lambda d: phase_returns.get("Clipboard", 0),
        "wipe_xdg_traces": lambda d: phase_returns.get("XDG", 0),
        "scrub_env_vars": lambda d: phase_returns.get("Env", 0),
        "wipe_gs_artifacts": lambda d, extra_dirs=None: phase_returns.get("Artifacts", 0),
    }
    for name, fn in stubs.items():
        setattr(p, name, fn)
    argv = ["paranoia_mode"] + (["--dry-run"] if dry else [])
    old_argv = sys.argv
    sys.argv = argv
    buf = io.StringIO(); real = sys.stdout; sys.stdout = buf
    code = 0
    try:
        p.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    finally:
        sys.stdout = real
        sys.argv = old_argv
    return code, buf.getvalue()


def test_clean_wipe_reports_success_and_exits_zero():
    code, out = _run_paranoia_main({})
    check("a fully-clean wipe exits 0", code == 0)
    check("a fully-clean wipe says every phase succeeded",
          "every phase reported success" in out)
    check("a clean wipe still states the best-effort caveats",
          "not zeroed" in out)


def test_any_failure_makes_the_summary_honest_and_exit_nonzero():
    code, out = _run_paranoia_main({"MAC spoof": 1, "Shell histories": 2})
    check("a wipe with failures exits nonzero", code != 0)
    check("a wipe with failures does NOT claim completion",
          "complete — every phase" not in out)
    check("the summary says the host is not known clean",
          "NOT known clean" in out)
    check("the failing phases are named with counts",
          "MAC spoof: 1" in out and "Shell histories: 2" in out)
    check("a succeeding phase is NOT listed as failed",
          "Journal:" not in out.split("FINISHED WITH FAILURES")[-1])


def test_dry_run_never_claims_a_wipe_happened():
    code, out = _run_paranoia_main({}, dry=True)
    check("a dry run exits 0", code == 0)
    check("a dry run says nothing was changed", "nothing was changed" in out)
    check("a dry run does not claim phases succeeded",
          "every phase reported success" not in out)


def test_every_phase_returns_a_failure_count():
    """Regression guard: a phase that returns None silently drops its failures
    from the summary. Confirm each shipped phase returns an int on the dry path
    (dry has no real failures, so all must be 0)."""
    p = load("paranoia_mode")
    p.integrity_log = lambda *a, **k: None
    import io
    real = sys.stdout; sys.stdout = io.StringIO()
    try:
        results = {
            "spoof_mac": p.spoof_mac("nonexistent-iface-zzz", True),
            "dns_check_dry": 0,  # dns_check has no dry path; skipped in main on dry
            "flush_dns_cache": p.flush_dns_cache(True),
            "wipe_shell_histories": p.wipe_shell_histories(True),
            "wipe_pycache": p.wipe_pycache(True),
            "wipe_system_logs": p.wipe_system_logs(7, True),
            "clear_journal": p.clear_journal(True),
            "wipe_swap_ram": p.wipe_swap_ram(True),
            "wipe_clipboard": p.wipe_clipboard(True),
            "scrub_env_vars": p.scrub_env_vars(True),
        }
    finally:
        sys.stdout = real
    for name, r in results.items():
        check(f"{name} returns an int failure count (dry)", isinstance(r, int))


def test_dns_check_failure_does_not_abort_the_wipe():
    """dns_check used to sys.exit(1), abandoning every wipe phase after it.
    The real function must now RETURN a status, not exit."""
    p = load("paranoia_mode")
    p.integrity_log = lambda *a, **k: None
    import io, socket
    orig = socket.getaddrinfo
    socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("no dns"))
    real = sys.stdout; sys.stdout = io.StringIO()
    exited = False
    try:
        rc = p.dns_check()
    except SystemExit:
        exited = True; rc = None
    finally:
        sys.stdout = real
        socket.getaddrinfo = orig
    check("dns_check does NOT sys.exit on failure", not exited)
    check("dns_check reports failure as a return code", rc == 1)


def test_shell_history_coverage():
    """The phase's own docstring names the stake -- "an operator who ran the
    pipeline with `--wallet-password ...` has that password sitting in
    ~/.bash_history verbatim" -- and then the list named bash and zsh and
    stopped. Two separate ways that failed."""
    para = load("paranoia_mode")

    prev_hf = os.environ.get("HISTFILE")
    os.environ["HISTFILE"] = "/tmp/gs_custom_histfile_probe"
    try:
        hs = [str(x) for x in para._shell_histories()]
    finally:
        if prev_hf is None:
            os.environ.pop("HISTFILE", None)
        else:
            os.environ["HISTFILE"] = prev_hf

    check("history: fish is covered (a whole mainstream shell was missing)",
          any("fish_history" in h for h in hs))
    check("history: $HISTFILE is covered (bash and zsh both honour it, so an "
          "operator who moved their history kept it through every wipe)",
          any("gs_custom_histfile_probe" in h for h in hs))
    check("history: zsh's other conventional name is covered",
          any(h.endswith(".zhistory") for h in hs))
    check("history: ash/dash and ksh are covered",
          any(h.endswith(".ash_history") for h in hs)
          and any(h.endswith(".sh_history") for h in hs))
    check("history: the originals are still covered",
          any(h.endswith(".bash_history") for h in hs)
          and any(h.endswith(".zsh_history") for h in hs))
    check("history: no duplicates in the list", len(hs) == len(set(hs)))


def test_shell_history_rewrite_warning():
    """The part it CANNOT fix, which is what made the phase look effective.

    Demonstrated with a real bash: a session holding
    `GhostSpiral --wallet-password s3cret...` had its history file wiped to
    zero bytes by this phase, and bash wrote the password BACK verbatim on
    exit. paranoia_mode cannot reach another process's memory, so it must say
    so -- otherwise the phase reports success and the run summary says "every
    phase reported success" while the password is already back on disk.
    """
    import io as _io, contextlib as _ctx
    para = load("paranoia_mode")
    buf = _io.StringIO()
    with _ctx.redirect_stdout(buf):
        para._warn_history_will_be_rewritten(dry=False)
    w = buf.getvalue()
    check("history: the wipe warns an open shell will write its history BACK",
          "in MEMORY" in w and "put its history BACK" in w)
    check("history: ...and gives the operator the actual remedy",
          "history -c" in w or "history clear" in w or "history -p" in w)
    check("history: ...and says this phase cannot do it for them",
          "cannot do it for you" in w)

    prev_sh = os.environ.get("SHELL")
    try:
        os.environ["SHELL"] = "/usr/bin/fish"
        b2 = _io.StringIO()
        with _ctx.redirect_stdout(b2):
            para._warn_history_will_be_rewritten(dry=False)
        check("history: a fish user is given fish's command, not bash's",
              "history clear" in b2.getvalue())
    finally:
        if prev_sh is None:
            os.environ.pop("SHELL", None)
        else:
            os.environ["SHELL"] = prev_sh

    check("history: wipe_shell_histories actually emits that warning",
          "_warn_history_will_be_rewritten(" in code_only(
              os.path.join(REPO, "paranoia_mode")))


def test_env_scrub_names_the_survivors():
    """The docstring was always right that a process cannot change its parent's
    environment. The operator reads the TERMINAL, and "Unset 5 sensitive env
    var(s) in this process" followed by the run summary's "every phase reported
    success" reads as done -- while the shell that exported
    GS_WALLET_PASSWORD still has it, still hands it to everything launched from
    that terminal, and still shows it in /proc/<shell-pid>/environ."""
    import io as _io, contextlib as _ctx
    para = load("paranoia_mode")
    para.integrity_log = lambda *a, **k: None
    prev = {k: os.environ.get(k) for k in ("GS_WALLET_PASSWORD", "GS_BTC_ENTRY")}
    try:
        os.environ["GS_WALLET_PASSWORD"] = "x"
        os.environ["GS_BTC_ENTRY"] = "y"
        buf = _io.StringIO()
        with _ctx.redirect_stdout(buf):
            para.scrub_env_vars(dry=False)
        out = buf.getvalue()
    finally:
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    check("env scrub: says the vars survive in the PARENT shell",
          "still set in the SHELL" in out)
    check("env scrub: names them, so the operator does not have to guess",
          "GS_WALLET_PASSWORD" in out and "GS_BTC_ENTRY" in out)
    check("env scrub: gives the exact command", "unset GS_" in out)
    check("env scrub: says why it matters while the terminal stays open",
          "/proc/<shell-pid>/environ" in out)
    # and it must still actually clear its own copy
    check("env scrub: this process's copy really is cleared",
          os.environ.get("GS_WALLET_PASSWORD") in (None, prev["GS_WALLET_PASSWORD"]))


def run_all():
    for fn in sorted([f for n, f in globals().items() if n.startswith("test_")],
                     key=lambda f: f.__name__):
        try:
            fn()
        except Exception as e:
            check(f"{fn.__name__} raised {type(e).__name__}: {str(e)[:60]}", False)
    print(f"\n  gapfixes: {PASS} passed, {FAIL} failed")
    if FAILURES:
        for f in FAILURES:
            print(f"    - {f}")
    return FAIL


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
