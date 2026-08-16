#!/usr/bin/env python3
"""CLI/flag tests for every script: --help works, argparse rejects bad flags
(invalid choices, missing required args, mutual exclusion), valid flags are
accepted, and the early runtime validations fire BEFORE any network I/O."""
import subprocess, os, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = ["GhostSpiral", "airgap_tx_signer", "broadcast_signed_xmr",
           "create_receive_wallet", "exit_strategy_simulator",
           "paranoia_mode", "thor_swap_preparer"]
PROXY = "socks5h://127.0.0.1:9050"

PASS = 0; FAIL = 0; FAILS = []
def run(script, args, timeout=30, stdin=""):
    p = subprocess.run([sys.executable, script] + args, capture_output=True,
                       text=True, timeout=timeout, input=stdin, cwd=REPO)
    return p.returncode, (p.stdout + p.stderr)
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else: FAIL += 1; FAILS.append(name); print(f"  FAIL: {name}")

# ---- --help works everywhere (exit 0, prints usage) ----
for s in SCRIPTS:
    rc, out = run(s, ["--help"])
    check(f"help:{s} exit0", rc == 0)
    check(f"help:{s} usage", "usage" in out.lower())

# ---- argparse rejects bad flags (exit code 2) ----
def arg_reject(name, script, args):
    rc, out = run(script, args)
    check(name, rc == 2)

arg_reject("airgap:no-args",             "airgap_tx_signer", [])
arg_reject("airgap:bad-phase",           "airgap_tx_signer", ["x.json", "--phase", "bogus"])
arg_reject("airgap:fee-priority-5",      "airgap_tx_signer", ["x.json", "--phase", "create", "--fee-priority", "5"])
arg_reject("airgap:fee-priority-0",      "airgap_tx_signer", ["x.json", "--phase", "create", "--fee-priority", "0"])
arg_reject("ghost:no-mode",              "GhostSpiral", ["--tor-proxy", PROXY])
arg_reject("ghost:both-modes",           "GhostSpiral", ["--btc-entry", "bc1qxyz", "--receive-wallet", "f.json", "--tor-proxy", PROXY])
arg_reject("ghost:missing-tor-proxy",    "GhostSpiral", ["--btc-entry", "bc1qxyz"])
arg_reject("ghost:fee-priority-9",       "GhostSpiral", ["--btc-entry", "bc1qxyz", "--tor-proxy", PROXY, "--fee-priority", "9"])
arg_reject("exit:no-amount",             "exit_strategy_simulator", ["--method", "bisq"])
arg_reject("exit:bad-method",            "exit_strategy_simulator", ["10", "--method", "bogus"])
arg_reject("exit:bad-currency",          "exit_strategy_simulator", ["10", "--currency", "yen"])
arg_reject("thor:no-required",           "thor_swap_preparer", [])

# ---- valid flags ACCEPTED: they get PAST argparse to a runtime check (rc != 2) ----
def accepted_past_argparse(name, script, args, needle):
    rc, out = run(script, args)
    check(name + ":not-argparse-err", rc != 2)
    check(name + ":reached-runtime", needle.lower() in out.lower())

# every valid --fee-priority reaches the "file not found" runtime check
for fp in ("1", "2", "3", "4"):
    accepted_past_argparse(f"airgap:fp{fp}", "airgap_tx_signer",
                           ["definitely_missing_xyz.json", "--phase", "create", "--fee-priority", fp],
                           "not found")
# --phase sign valid too
accepted_past_argparse("airgap:phase-sign", "airgap_tx_signer",
                       ["definitely_missing_xyz.json", "--phase", "sign"], "not found")

# ---- early RUNTIME validations fire before any network ----
# GhostSpiral: invalid BTC entry rejected before proxy/Tor
rc, out = run("GhostSpiral", ["--btc-entry", "NOT_A_BTC_ADDR", "--tor-proxy", PROXY])
check("ghost:bad-btc rejected", rc != 0 and "invalid btc" in out.lower())
# GhostSpiral: --dag-mixing accepted (still fails on bad btc, proving flag exists)
rc, out = run("GhostSpiral", ["--btc-entry", "NOT_A_BTC_ADDR", "--tor-proxy", PROXY, "--dag-mixing"])
check("ghost:dag-mixing accepted", rc != 2 and "invalid btc" in out.lower())
# GhostSpiral: receive-wallet file missing rejected before network
rc, out = run("GhostSpiral", ["--receive-wallet", "missing_rw_xyz.json", "--tor-proxy", PROXY])
check("ghost:missing-receive-wallet", rc != 0 and "not found" in out.lower())
# GhostSpiral: --max-slippage 0 is refused before any network (same as thor)
rc, out = run("GhostSpiral", ["--btc-entry", "NOT_A_BTC_ADDR", "--tor-proxy", PROXY,
                              "--max-slippage", "0"])
check("ghost:max-slippage-0", rc != 0 and "max-slippage" in out.lower())
# broadcast: --tor-proxy is enforced as REQUIRED at runtime
rc, out = run("broadcast_signed_xmr", ["some_dir"])
check("broadcast:tor-proxy-required", rc != 0 and "tor" in out.lower() and "required" in out.lower())
# exit_strategy_simulator: non-positive amount rejected before network
rc, out = run("exit_strategy_simulator", ["0"])
check("exit:amount-positive", rc != 0 and "positive" in out.lower())

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS); sys.exit(1)
print("ALL GREEN")
