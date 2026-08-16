#!/usr/bin/env python3
"""Collect REAL project status into JSON for the control dashboard.

Everything here is MEASURED by executing the thing it reports on:
  * each test suite is actually run; assertion counts and durations are parsed
    from its real output, not declared;
  * the real-binary suites really spin up monerod/monero-wallet-rpc and relay
    on an isolated testnet (they SKIP cleanly when the binaries are absent);
  * commit history, diff stats and the monero version come from the tools.

Nothing is hand-written. If a suite fails, this records the failure rather
than hiding it -- a dashboard that can only show green is worthless.

Usage:
  python3 tests/collect_status.py [out.json] [--skip-real]
"""
import subprocess, os, sys, re, time, json

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
args = [a for a in sys.argv[1:] if not a.startswith("--")]
SKIP_REAL = "--skip-real" in sys.argv
OUT = args[0] if args else os.path.join(REPO, "tests", "status.json")

# The real-binary suites need the `monero` python package, installed in a venv
# because its varint dep breaks on modern setuptools (see tests/README.md).
VENV_PY = os.environ.get("GS_VENV_PY", "")


def sh(cmd, timeout=900, **kw):
    try:
        return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                              timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "TIMEOUT")


OFFLINE = [
    ("test_units", "pure logic: validation, fingerprint, money math, parsing"),
    ("test_realfns", "real fetch_prices, secure-delete, perms, core dumps"),
    ("test_cli_flags", "every script: --help, argparse, pre-network aborts"),
    ("test_integration", "real phase_create/phase_sign/broadcast + orchestration"),
    ("test_gitignore", "enforces .gitignore covers every wiped artifact"),
    ("test_ipleak", "proxy scheme, egress guards, localhost spoofing, fail-closed"),
]
REALBIN = [
    ("real_roundtrip_testnet", "full cold-signing round-trip vs real binaries"),
    ("real_flags_testnet", "fee-priority 1-4 + multi-dest fan-out + password"),
    ("real_dag_subaddr_testnet", "on-chain proof subaddr_indices isolates a hop"),
    ("real_phase_sign_testnet", "SHIPPED phase_sign relayed + confirmed on-chain"),
    ("real_phase_create_testnet", "SHIPPED phase_create -> phase_sign chain"),
    ("leak_audit_testnet", "runs all 3 stages, audits what hits disk"),
]

RESULT_RE = re.compile(r"RESULT:\s*(\d+)\s+passed,\s*(\d+)\s+failed")


def run_suite(name, kind, desc, interpreter):
    path = os.path.join("tests", f"{name}.py")
    t0 = time.time()
    r = sh([interpreter, path])
    dur = round(time.time() - t0, 1)
    out = (r.stdout or "") + (r.stderr or "")
    m = RESULT_RE.search(out)
    passed = int(m.group(1)) if m else 0
    failed = int(m.group(2)) if m else 0
    skipped = "SKIP:" in out and not m
    if r.returncode == 124:
        status = "timeout"
    elif skipped:
        status = "skipped"
    elif m:
        status = "pass" if failed == 0 else "fail"
    else:
        # No RESULT line: some real-binary suites print a SUCCESS banner instead.
        status = "pass" if ("SUCCESS" in out or "NO LEAKS" in out) and r.returncode == 0 \
                 else ("pass" if r.returncode == 0 else "fail")
    # Pull the headline banner if the suite prints one.
    banner = ""
    for line in out.splitlines():
        if line.startswith(">>>"):
            banner = line.strip(">< ").strip()
    fails = [l.strip() for l in out.splitlines() if l.strip().startswith("FAIL:")]
    return {
        "name": name, "kind": kind, "desc": desc, "status": status,
        "passed": passed, "failed": failed, "duration_s": dur,
        "banner": banner, "failures": fails[:10], "exit_code": r.returncode,
    }


data = {
    "generated_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
    "suites": [], "env": {}, "commits": [], "loc": {},
}

# ---- provenance -----------------------------------------------------------
data["env"]["commit"] = sh(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
data["env"]["branch"] = sh(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
mv = sh(["monerod", "--version"]).stdout.strip().splitlines()
data["env"]["monero"] = mv[0] if mv else "(not installed)"
data["env"]["python"] = sys.version.split()[0]
data["env"]["dirty"] = bool(sh(["git", "status", "--porcelain"]).stdout.strip())

# ---- source size ----------------------------------------------------------
SCRIPTS = ["gs_common.py", "GhostSpiral", "airgap_tx_signer", "broadcast_signed_xmr",
           "create_receive_wallet", "exit_strategy_simulator", "paranoia_mode",
           "thor_swap_preparer"]
for f in SCRIPTS:
    p = os.path.join(REPO, f)
    if os.path.exists(p):
        data["loc"][f] = sum(1 for _ in open(p, errors="ignore"))
data["loc"]["_tests"] = sum(
    sum(1 for _ in open(os.path.join(REPO, "tests", t), errors="ignore"))
    for t in os.listdir(os.path.join(REPO, "tests")) if t.endswith(".py"))

# ---- commit history for this branch ---------------------------------------
log = sh(["git", "log", "--pretty=format:%h\x1f%ad\x1f%s", "--date=short", "-40"]).stdout
for line in log.splitlines():
    parts = line.split("\x1f")
    if len(parts) == 3:
        data["commits"].append({"sha": parts[0], "date": parts[1], "subject": parts[2]})

# ---- run the suites -------------------------------------------------------
for name, desc in OFFLINE:
    print(f"[*] {name} ...", flush=True)
    s = run_suite(name, "offline", desc, sys.executable)
    print(f"    {s['status']}  {s['passed']} passed, {s['failed']} failed  ({s['duration_s']}s)")
    data["suites"].append(s)

if not SKIP_REAL:
    interp = VENV_PY or sys.executable
    for name, desc in REALBIN:
        print(f"[*] {name} (real binaries) ...", flush=True)
        s = run_suite(name, "realbin", desc, interp)
        print(f"    {s['status']}  {s['passed']} passed, {s['failed']} failed  ({s['duration_s']}s)")
        data["suites"].append(s)

# ---- totals ---------------------------------------------------------------
data["totals"] = {
    "assertions": sum(s["passed"] for s in data["suites"]),
    "failed": sum(s["failed"] for s in data["suites"]),
    "suites": len(data["suites"]),
    "suites_pass": sum(1 for s in data["suites"] if s["status"] == "pass"),
    "suites_fail": sum(1 for s in data["suites"] if s["status"] == "fail"),
    "suites_skipped": sum(1 for s in data["suites"] if s["status"] == "skipped"),
    "runtime_s": round(sum(s["duration_s"] for s in data["suites"]), 1),
    "src_lines": sum(v for k, v in data["loc"].items() if not k.startswith("_")),
    "test_lines": data["loc"].get("_tests", 0),
}

with open(OUT, "w") as f:
    json.dump(data, f, indent=2)
print(f"\n[+] wrote {OUT}")
print(f"    {data['totals']['assertions']} assertions, "
      f"{data['totals']['failed']} failed, "
      f"{data['totals']['suites_pass']}/{data['totals']['suites']} suites green, "
      f"{data['totals']['runtime_s']}s")
