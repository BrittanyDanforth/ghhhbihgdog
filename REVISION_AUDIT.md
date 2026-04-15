# Revision Audit — Complete Issue Inventory
**Date:** 2026-04-15  
**Scope:** Every user-facing flow, every script, every file path, every OPSEC claim

This is a complete inventory of every issue found by tracing all 11 menu flows
end-to-end plus direct CLI usage, startup, setup, and cleanup paths.

Issues are categorized by severity and grouped by theme.

---

## CRITICAL — Breaks Flow, Loses Money, or Misleads About Safety

### C1. Wallet discovery is CWD-only — "No wallet found" when wallet exists
**Files:** `run` lines 345, 370, 447, 525, 599  
**Problem:** Every flow that needs a `wallet_*.json` does `Path(".").glob("wallet_*.json")` — 
only searches the current working directory. If the user created a wallet from a different
directory, or if CWD is not the toolkit root, the wallet is invisible.  
**Impact:** User told "No wallet found" and creates a duplicate, or has to manually type a path
they may not remember. In testnet flow, this forces wallet re-creation every time CWD differs.  
**Fix required:** Search the toolkit root directory (`ROOT`) in addition to CWD. Also search 
common locations like `~/` and `~/Downloads/`.

### C2. Receiver flow dumps manual shell commands instead of using the UI
**Files:** `core/create_receive_wallet` lines 161-172  
**Problem:** After creating a wallet, the script prints "RECEIVER FLOW: NEXT STEPS" with raw 
shell commands like `python3 thor_swap_preparer --amounts <BTC_AMOUNT> --dests $(jq -r ...)`.
The user has to manually copy-paste these commands. Menu option 7 (Swap Preparer) exists and 
does exactly this, but create_receive_wallet doesn't tell the user to use it.  
**Impact:** User thinks they need to run manual commands. The `jq` dependency may not be 
installed. The path `thor_swap_preparer` is wrong (should be `core/thor_swap_preparer`).
The `./gs mixer` path printed also assumes CWD is toolkit root.  
**Fix required:** Replace manual shell commands with guidance to use menu options 7 and 2.

### C3. All artifacts are CWD-relative — split artifacts if directory changes
**Files:** `core/mixer_core` (tx_staging, .mixer.lock, unsigned/), `core/gs_common.py` 
(integrity_chain.log), `core/broadcast_signed_xmr` (broadcast_progress.json)  
**Problem:** Every progress file, lock file, staging directory, and integrity log is created
relative to CWD. If the user runs the toolkit from `/root/Downloads/toolkit/` once and 
`/root/` another time, artifacts split across directories. Resume can't find progress files.
Cleanup can't find all logs. Lock files don't prevent concurrent runs from different dirs.  
**Impact:** Resume fails silently (no progress found → restarts from scratch → potential 
double-spend). Paranoia cleanup misses artifacts in other directories. Multiple integrity 
logs exist in different directories.  
**Fix required:** Use toolkit root directory for all artifacts, not CWD.

### C4. thor_swap_preparer output is not consumed by anything
**Files:** `core/thor_swap_preparer` (writes `thor_pairs_batch.json`), `core/mixer_core` 
(fetches quotes independently)  
**Problem:** There are TWO independent ways to get ThorChain quotes:
1. Menu option 7 runs `thor_swap_preparer` → writes `thor_pairs_batch.json`
2. Menu option 1 runs `mixer_core` → fetches quotes internally in Stage 2
These are completely disconnected. `mixer_core` never reads `thor_pairs_batch.json`.
If the user runs option 7 first (as the "next steps" tell them to), then runs option 1,
the quotes are fetched again from scratch. The first set expires.  
**Impact:** User does double work. Expired quotes from option 7 may confuse the user.
The "next steps" from create_receive_wallet point to a flow that doesn't connect.  
**Fix required:** For the receiver flow (option 2), the user should be guided through
create wallet → swap preparer → wait for XMR → receive mode, all from the menu.
Document that option 7 is standalone and does NOT feed into option 1.

### C5. Paranoia cleanup has limited search depth and fixed roots
**Files:** `opsec/paranoia_mode` lines 439-463  
**Problem:** Artifact search uses glob patterns limited to 3 levels deep under fixed root 
directories. `wallet_*.json` files in deeper paths, non-standard locations, or other drives
are missed. The user is told "Deleted N artifact(s)" but doesn't know what was missed.  
**Impact:** False sense of "all traces wiped" when wallet JSON, progress files, or integrity
logs still exist in unsearched locations.  
**Fix required:** Add the toolkit root to search roots. Expose `--search-dir` in the menu.
Print a warning that cleanup searches specific paths and may miss files elsewhere.

### C6. Fee estimate "Method not found" not handled specifically  
**Files:** `core/mixer_core` lines 105-146  
**Problem:** Some monero-wallet-rpc versions (especially older ones or ones started without
a daemon connection) return `{"error": {"code": -32601, "message": "Method not found"}}` 
for `get_fee_estimate`. The current code catches this as a generic Exception but the error
message says "Cannot get fee estimate from wallet-rpc / Ensure monerod is synced" — which 
is wrong for this case. The actual problem is the RPC method isn't available.  
**Impact:** User sees unhelpful error message. In cold/airgap mode, the fallback works but
the JSON-RPC error is dumped to terminal (ugly, confusing).  
**Fix required:** Catch the specific -32601 error code and show a targeted message.
In cold/airgap mode, suppress the raw JSON dump.

---

## HIGH — Major UX Failure, Should Be Automated, Confusing

### H1. Receiver flow requires manual multi-step process
**Problem:** To receive mixed XMR, the user must:
1. Run option 6 (Create Wallet) — gets manual shell commands
2. Run option 7 (Swap Preparer) — standalone, output not consumed
3. Give deposit info to sender, wait for BTC → XMR conversion
4. Run option 2 (Receive Mode) — must find wallet JSON from step 1
Each step is disconnected. The user navigates between 3 menu options with manual file 
path management.  
**Fix required:** Add a guided "Receive Funds" flow that chains: create wallet → show
deposit instructions (via swap preparer) → wait → run receive mode.

### H2. SETUP.md wallet creation doesn't handle "file already exists"
**Files:** `SETUP.md`  
**Problem:** The setup guide tells users to run `monero-wallet-cli --generate-new-wallet`.
If the wallet file already exists from a prior attempt, monero-wallet-cli errors with 
"Error: failed to generate new wallet: file already exists". No guidance on what to do.  
**Fix required:** Add "If you already created a wallet, skip this step" and 
"If you get 'file already exists', use your existing wallet".

### H3. install.sh system check says deps missing after pip install succeeds
**Problem:** The system check in `run` (`check_prereqs`) imports modules using the RUNNING 
Python. If that's system Python but packages are in the venv (or vice versa), deps show as 
missing even though `pip install` just succeeded.  
**Fix required:** Already partially fixed with venv auto-detection in `run`. Verify 
`check_prereqs` uses the same Python that will run the scripts.

### H4. Broadcast flow (option 4) path expectations not obvious
**Files:** `run` lines 401-422  
**Problem:** Option 4 defaults to `tx_staging/signed` which only exists if the user ran 
the full pipeline or air-gap signer. For air-gap workflows where blobs are on USB, the
user must know to type the USB path. No guidance is given.  
**Fix required:** If default path doesn't exist, explain where signed blobs come from.

### H5. Testnet/dry-run flow creates wallet but doesn't remember it for next run
**Problem:** `flow_testnet` auto-creates a wallet if none exists, but if the user quits and
re-enters testnet mode from a different CWD, it creates another wallet.  
**Fix required:** Part of C1 fix — search toolkit root for wallets.

### H6. thor_swap_preparer refuses overwrite without --force  
**Files:** `core/thor_swap_preparer` lines 277-284  
**Problem:** If `thor_pairs_batch.json` exists from a prior run, the script aborts with
"Output file exists! Re-running creates NEW deposit addresses". The menu flow doesn't pass
`--force`, so the user is stuck.  
**Fix required:** In menu flow, either auto-pass `--force` with confirmation prompt, or
use a timestamped filename.

---

## MEDIUM — Annoying But Workaround Exists

### M1. Startup Tor warning doesn't block menu — flows fail inside scripts
**Files:** `run` lines 706-718  
**Problem:** If Tor isn't running, the launcher prints a warning but still shows the menu.
Every operation then fails inside the child script with a less helpful error.  
**Fix required:** After Tor warning, offer to retry or limit menu to non-network options
(system check, paranoia cleanup).

### M2. Multiple integrity_chain.log files across directories
**Files:** `core/gs_common.py` line 40  
**Problem:** `INTEGRITY_LOG = Path("integrity_chain.log")` is CWD-relative. Running the 
toolkit from different directories creates separate log files, each with a partial chain.  
**Fix required:** Use toolkit root for the integrity log path.

### M3. Paranoia --search-dir not exposed in menu
**Files:** `run` lines 574-585, `opsec/paranoia_mode` lines 620-622  
**Problem:** `paranoia_mode` accepts `--search-dir` for additional artifact locations, but
the menu flow never offers this option.  
**Fix required:** Prompt for additional search directories in the paranoia flow.

### M4. Menu option 3 (Cold/Air-Gap) instructions reference wrong paths  
**Files:** `run` lines 391-398  
**Problem:** Instructions say `python3 core/airgap_tx_signer unsigned/unsigned_*.json` but
this only works from toolkit root. The path to the signer should use the toolkit root.  
**Fix required:** Show absolute or toolkit-relative paths.

### M5. create_receive_wallet prints subaddress index in terminal
**Files:** `core/create_receive_wallet` lines 146-148  
**Problem:** Prints "Subaddress index: N (account M)" which reveals wallet structure info.
While less sensitive than the full address, it's still operational detail.  
**Fix required:** Move to the JSON file only, print "Details saved to file" instead.

### M6. SETUP.md --password flag visible in shell history
**Files:** `SETUP.md`  
**Problem:** Example commands show `--password "YOUR_PASSWORD"` which gets saved in 
shell history. The doc warns about this but the example still uses the flag.  
**Fix required:** Use `--password-file` or env var in examples.

---

## LOW — Cosmetic or Minor

### L1. Testnet menu text says "simulates" but it's really cold-mode with mock balance
The implementation is `--cold` with a fake 10 XMR balance, not a separate testnet.

### L2. Menu option 't' naming inconsistency
Called "Testnet / Dry Run Mode" but has nothing to do with Monero testnet.

### L3. Version string in gs_common.py not updated with changes
`VERSION = "10.5"` — may need updating after this revision.

---

## Summary by Priority

| Priority | Count | Key Theme |
|----------|-------|-----------|
| CRITICAL | 6 | CWD coupling, disconnected flows, manual steps in money path |
| HIGH | 6 | Missing automation, confusing guidance, path assumptions |
| MEDIUM | 6 | Tor gating, scattered artifacts, missing menu features |
| LOW | 3 | Naming, versioning |

## Recommended Fix Order

1. **C1 + C3 + M2:** Fix CWD coupling (all artifact paths use toolkit ROOT)
2. **C2 + H1:** Rewrite create_receive_wallet next-steps + add guided receiver flow
3. **C6:** Handle fee "Method not found" gracefully  
4. **C4:** Document that option 7 is standalone; don't promise integration that doesn't exist
5. **C5:** Add toolkit root to paranoia search; expose --search-dir
6. **H2 + H3:** Fix SETUP.md and system check consistency
7. **H4 + H6:** Fix broadcast path guidance and swap overwrite
8. **M1:** Tor startup gating
9. Everything else
