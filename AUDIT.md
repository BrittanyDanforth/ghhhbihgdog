# GhostSpiral Toolchain — Full Codebase Audit & OPSEC Hardening

> Generated: 2026-04-12 | Updated: 2026-04-12 (v2 - deep hardening pass)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Scenario Analysis (12 scenarios)](#2-scenario-analysis)
3. [OPSEC Hardening Summary](#3-opsec-hardening-summary)
4. [Original Bug Inventory (Round 1)](#4-original-bug-inventory)
5. [Deep Hardening Changes (Round 2)](#5-deep-hardening-changes)
6. [End-to-End Wiring Verification](#6-end-to-end-wiring-verification)
7. [Remaining Items](#7-remaining-items)

---

## 1. Architecture Overview

```
                        GhostSpiral (core orchestrator)
                               |
          +--------------------+--------------------+
          |                    |                    |
    Stage 1              Stage 2              Stage 3-4
  JoinMarket          ThorChain swap       Wallet/DAG/Plan
  (optional)              |                     |
          |          thor_swap_preparer     create_receive_wallet
          |                |                    |
          +--------+-------+--------------------+
                   |
              Stage 5 (auto-mode)
                   |
        +----------+----------+
        |          |          |
  airgap_tx_signer | exit_strategy_simulator
        |          |
  broadcast_signed_xmr
        |
  paranoia_mode (post-op cleanup)
```

### Shared library: `gs_common.py`
All scripts import from `gs_common.py` which provides:
- Integrity hash-chain logging
- Tor verification + re-check + NEWNYM
- Atomic file writes with fsync
- Secure file permissions (0600)
- CSPRNG helpers (secrets module)
- Timing decorrelation (jitter)
- Proxy format validation
- Signal handlers for graceful shutdown
- Address scrubbing for terminal output
- Resource sentinel
- Retry-wrapped HTTP (GET/POST)
- RPC connection with host+port parsing

---

## 2. Scenario Analysis

### Scenario 1: GOOD - Normal full pipeline run
**Flow:** GhostSpiral --btc-entry bc1... --tor-proxy socks5h://... 
**What happens:**
- Stage 0: Tor verified, BTC address validated, RPC synced
- Stage 1: JM skipped (not enabled)
- Stage 2: Thor swap skipped (no BTC chunks from JM)
- Stage 3: Wallets created, DAG built with CSPRNG shuffle
- Stage 4: Balance fetched, fees deducted, unsigned plan written (0600 perms)
- Stage 5: Auto-sign -> broadcast -> exit sim
- NEWNYM between every stage, timing jitter throughout
**Result:** Complete pipeline with integrity log trail

### Scenario 2: BAD - Tor circuit drops mid-operation
**Flow:** Tor proxy dies during Stage 2 ThorChain requests
**What happens (before fix):** Requests would hang/fail silently, no re-check
**What happens (after fix):**
- `tor_recheck()` called before Stage 2, 3, and 5
- If Tor drops, immediate abort with integrity log entry
- `safe_post()` has 4x exponential retry for transient failures
- NEWNYM called on failure to get fresh circuit
**Result:** Clean abort, no clearnet leak, full audit trail

### Scenario 3: BAD - Crash during signing (power loss)
**Flow:** Power fails at TX 15 of 40 during airgap_tx_signer
**What happens (before fix):** Progress file might be corrupt (no fsync)
**What happens (after fix):**
- Progress atomically written after each TX (tmp -> fsync -> rename)
- On resume: `_verify_resume_integrity()` checks every blob hash
- If any blob was corrupted, abort with TAMPER_DETECTED
- Temp batch files securely wiped (overwrite + unlink)
**Result:** Resume from TX 16, all prior blobs verified

### Scenario 4: BAD - TX stuck in mempool (never mined)
**Flow:** Broadcast TX, node accepts, but TX never confirms
**What happens (before fix):** INFINITE LOOP waiting for mining
**What happens (after fix):**
- `MAX_MINE_WAIT_SECONDS = 7200` (2 hours, configurable via --mine-wait)
- After timeout: logs UNCONFIRMED, continues to next TX
- Progress saved so operator can manually handle stuck TX
**Result:** Bounded wait, no hang, clear status in progress file

### Scenario 5: BAD - Node rejects TX with "low_fee"
**Flow:** Monero node returns low_fee error
**What happens (before fix):** `bump_fee()` used os.system (no error handling, fd leak)
**What happens (after fix):**
- `_bump_fee()` uses subprocess.run with timeout + error capture
- File descriptor properly closed via os.fdopen
- Temp file securely overwritten + unlinked in finally block
- On failure: returns original hex, logs error, continues retry
**Result:** Fee bumped and retried, or graceful fallback

### Scenario 6: BAD - Operator hits Ctrl+C during broadcast
**Flow:** SIGINT received during TX 8 of 20
**What happens (before fix):** Crash, progress file possibly corrupt
**What happens (after fix):**
- `install_signal_handlers()` catches SIGINT/SIGTERM
- `shutdown_requested()` checked before each TX
- Current TX finishes, progress saved atomically
- Message tells operator how to resume
**Result:** Clean stop at TX 8 boundary, resume from 9

### Scenario 7: BAD - DAG builder crashes with too-small wallet count
**Flow:** --wallets 2 --deep 3 (k=9 but population=5)
**What happens (before fix):** `random.sample` raises ValueError
**What happens (after fix):**
- `min()` clamp: `k = min(rand(1,3)*deep, len(others))`
- `max(k, 1)` ensures at least 1 edge
- Minimum wallets enforced: `args.wallets = max(args.wallets, MIN_WALLETS)`
- CSPRNG (secrets module) for all randomness
**Result:** DAG always valid, no crash

### Scenario 8: BAD - ThorChain returns non-bech32 deposit address
**Flow:** ThorChain API returns a legacy BTC address or garbage
**What happens (before fix):** Used without validation, deposit could fail
**What happens (after fix):**
- `thor_swap_preparer`: validates deposit matches BTC_RE (bech32)
- `GhostSpiral stage2`: checks deposit is not None and starts with bc1/tb1
- Aborts with clear error + integrity log entry
**Result:** Bad deposit caught before any BTC sent

### Scenario 9: BAD - Signer receives wrong JSON format from GhostSpiral
**Flow:** GhostSpiral writes {"meta":{...}, "txs":[...]} but signer expects flat list
**What happens (before fix):** TypeError or schema validation crash
**What happens (after fix):**
- `_load_unsigned()` handles both formats:
  - Dict with "txs" key -> extracts txs list
  - Flat list -> uses directly
  - Anything else -> clear error
- Schema version logged from meta for audit
**Result:** Backward/forward compatible loading

### Scenario 10: GOOD - Cold wallet / air-gap workflow
**Flow:** GhostSpiral --cold -> USB transfer -> airgap_tx_signer -> USB -> broadcast
**What happens:**
- GhostSpiral: dumps unsigned plan, prints filename, exits cleanly
- Unsigned file: 0600 permissions, integrity logged
- airgap_tx_signer: validates schema, signs offline, writes 0600 blobs
- Manifest with SHA-256 hashes of every blob
- broadcast_signed_xmr: reads manifest, verifies blobs exist, broadcasts
- Each stage produces its own integrity log entries
**Result:** Fully air-gapped with chain of custody via hash manifest

### Scenario 11: BAD - Forensic analysis of host after operation
**Flow:** Adversary gains access to operator machine
**What happens (before fix):** Bash history, Python cache, tmp files, system logs all present
**What happens (after fix - paranoia_mode):**
- Phase 1: MAC spoofed (locally-administered unicast)
- Phase 2: DNS leak check
- Phase 3: DNS cache flushed
- Phase 4: Shell histories wiped (.bash_history, .zsh_history, .python_history, etc.)
- Phase 5: Python __pycache__ and .pyc files removed
- Phase 6: User-owned /tmp and /var/tmp files removed
- Phase 7: System logs older than N days truncated
- Phase 8: systemd journal cleared
- Phase 9: Swap disabled, /dev/shm overwritten with zeros
- All files written with 0600 perms throughout pipeline
**Result:** Massively reduced forensic footprint

### Scenario 12: BAD - Operator accidentally runs without Tor
**Flow:** Forgets --tor-proxy or proxy URL is malformed
**What happens (before fix):** Some scripts allowed clearnet, inconsistent validation
**What happens (after fix):**
- GhostSpiral: --tor-proxy is required (argparse enforced)
- `validate_proxy()`: regex check for socks5h://host:port format
- `verify_tor()`: actually checks check.torproject.org with 4x retry
- thor_swap_preparer: warns loudly if no proxy, logs WARNING:clearnet_mode
- broadcast_signed_xmr: Tor verified before first broadcast + periodic re-check
- Any Tor failure = immediate abort with integrity log
**Result:** Near-impossible to accidentally leak clearnet traffic

---

## 3. OPSEC Hardening Summary

### Tor / Network
| Feature | Before | After |
|---------|--------|-------|
| Proxy format validation | None | Regex check for socks5h://host:port |
| Tor verification | Single check, some scripts skipped | Verified at startup + re-checked mid-operation |
| NEWNYM rotation | Rarely called | Between every stage and every TX broadcast |
| Clearnet warning | Silent | Loud warning + integrity log if no proxy |
| Retry on network failure | Inconsistent | 4x exponential jitter across all scripts |
| HTTP status check | Never (.json() on any response) | raise_for_status() on every request |

### File Security
| Feature | Before | After |
|---------|--------|-------|
| Output file permissions | Default (0644) | 0600 on all sensitive outputs |
| Atomic writes | Inconsistent (some fsync, some not) | Consistent: tmp -> fsync -> rename everywhere |
| File handle leaks | Many unclosed open() calls | All wrapped in with statements |
| Temp file cleanup | Never cleaned | Securely overwritten + unlinked in finally blocks |

### Randomness
| Feature | Before | After |
|---------|--------|-------|
| RNG for security ops | random module (Mersenne Twister) | secrets module (CSPRNG) |
| Timing decorrelation | Fixed sleep() values | secure_delay() with CSPRNG jitter |
| DAG shuffle | random.shuffle | secrets.SystemRandom().shuffle |
| Hex generation | random.choice | secrets.token_hex |

### Integrity / Audit
| Feature | Before | After |
|---------|--------|-------|
| Log file name | Mixed (integrity.log vs integrity_chain.log) | Unified: integrity_chain.log everywhere |
| Hash chain | Copy-pasted with bugs | Single implementation in gs_common.py |
| Log file perms | Default | 0600 |
| Resume verification | None | Blob hashes verified on resume |
| Signal handling | None | SIGINT/SIGTERM -> graceful shutdown |

### Terminal Output
| Feature | Before | After |
|---------|--------|-------|
| Address display | Full addresses shown | Scrubbed: first8...last8 |
| Error messages | Inconsistent | Structured with [!] prefix |
| Progress feedback | Minimal | Per-TX progress with counts |

---

## 4. Original Bug Inventory (Round 1)

*(See git history for the original 40+ bugs found across all files. Key categories:)*

- **FATAL:** Junk text before shebang in all 8 files
- **FATAL:** subprocess calls to .py files that don't exist
- **FATAL:** Schema mismatch between GhostSpiral output and signer input
- **FATAL:** paranoia_mode was 1182 lines of concatenated scripts
- **HIGH:** connect_rpc ignored hostname
- **HIGH:** Infinite mine-wait loop
- **HIGH:** DAG builder could crash on small wallet counts
- **HIGH:** bump_fee fd leak + os.system
- **HIGH:** Shell history / Python cache never cleaned

---

## 5. Deep Hardening Changes (Round 2)

### New file: `gs_common.py` (shared OPSEC library)
- Eliminated all copy-paste of integrity logging, Tor checks, atomic writes
- 14 shared functions used across all 7 scripts
- Single source of truth for all security-critical operations

### Per-file changes:

**GhostSpiral:**
- Tor re-check before stages 2, 3, 5
- NEWNYM between every stage
- CSPRNG for DAG, delays, hex extras
- Signal handlers for graceful shutdown
- Subprocess timeouts on all child processes
- Fee oracle with fallback + logging
- Minimum wallets/depth enforced

**create_receive_wallet:**
- Output directory configurable (--output-dir)
- NEWNYM after wallet creation
- Address scrubbed in terminal output

**airgap_tx_signer:**
- Resume integrity verification (blob hash check)
- Wallet file existence check
- Batch files securely wiped (overwrite + unlink)
- Subprocess timeout per TX
- Per-TX progress counter

**broadcast_signed_xmr:**
- NEWNYM per TX for circuit isolation
- Periodic Tor re-check (every 5 min)
- CSPRNG for RPC selection
- Empty blob detection
- Secure temp wipe in bump_fee
- Mine-wait configurable via --mine-wait

**thor_swap_preparer:**
- BTC deposit address format validation
- Slippage deviation logged with percentage
- NEWNYM between quote requests
- GPG encryption failure handled gracefully
- Amount positivity validation

**exit_strategy_simulator:**
- Amount positivity validation
- Net-amount non-positive check
- KYC warning in terminal output
- Liquidity "consider splitting" advice

**paranoia_mode:**
- 9 cleanup phases (was 4)
- Added: shell histories, Python cache, tmp files, DNS cache, journal
- MAC: uses SystemRandom, verified unicast+locally-administered
- dd targets file inside /dev/shm (not the directory)
- All subprocess calls have capture_output + timeout

---

## 6. End-to-End Wiring Verification

| Step | Producer | Consumer | Schema | Status |
|------|----------|----------|--------|--------|
| Wallet creation | create_receive_wallet | GhostSpiral (manual) | gs_receive_wallet_v1 | OK |
| Thor quotes | thor_swap_preparer | GhostSpiral stage2 (manual) | thor_pairs_v1 | OK |
| Unsigned plan | GhostSpiral stage4 | airgap_tx_signer | unsigned_v1 (dict with meta+txs) | OK |
| Signed blobs | airgap_tx_signer | broadcast_signed_xmr | signed_manifest_v1 + .blob files | OK |
| Exit plan | exit_strategy_simulator | Operator (manual) | exitplan_v1 | OK |
| Integrity log | All scripts | All scripts (append) | SHA-256 hash-chain | OK (unified) |
| Subprocess calls | GhostSpiral stage5 | signer, broadcaster, exit sim | CLI args | OK (no .py suffix) |

---

## 7. Money-Flow & Silent OPSEC Bugs Found (Round 3 - Deep Trace)

These bugs were found by mentally tracing real crypto through the entire pipeline.

### BUG 1: MONEY LOST - Stage 2 (ThorChain swap) was NEVER actually called
**Scenario:** Operator runs full pipeline. BTC enters via JoinMarket, ThorChain is supposed to swap BTC->XMR, but stage2_thor_swap() is defined but the actual call was gated behind a condition that was always false in the non-JM case, and even in the JM case it said "Would need a real XMR dest address here" and did nothing.
**Impact:** BTC sits at ThorChain deposit address forever. XMR never arrives. Money gone.
**Fix:** Reordered stages: Stage 3 (wallet creation) now runs BEFORE Stage 2 (swap), so ENTRY address exists when stage2 needs it. stage2_thor_swap() is now actually called with the ENTRY address.

### BUG 2: MONEY LOST - Spending locked/unconfirmed balance
**Scenario:** XMR arrives from ThorChain but hasn't confirmed yet (10 blocks). GhostSpiral reads `balance` (includes unconfirmed) instead of `unlocked_balance`. Builds a plan for 10 XMR. Signs TXs. Broadcasts. Node rejects every TX because the funds are locked.
**Impact:** All TXs fail. Operator thinks something is broken. Retries, gets same failure. Meanwhile timing window leaks that "someone is trying to spend newly received XMR."
**Fix:** Now reads `unlocked_balance` specifically. Warns if there's a gap between total and unlocked.

### BUG 3: MONEY LOST - Rounding dust accumulates across rounds
**Scenario:** 9.9997 XMR usable, 40 rounds. split = 0.24999... quantized to 0.2499. 40 * 0.2499 = 9.996. But if quantize rounds UP to 0.2500, then 40 * 0.2500 = 10.0 > 9.9997. Signing fails because there isn't enough balance.
**Impact:** Entire batch of TXs fails at signing or broadcast.
**Fix:** After quantizing, verify total_planned <= usable. If it overflows, subtract 0.0001 from the per-round amount.

### BUG 4: MONEY SENT WRONG - DAG edge count operator precedence bug
**Scenario:** `_secrets.randbelow(3) + 1 * args.deep` evaluates as `randbelow(3) + (1 * deep)` instead of `(randbelow(3) + 1) * deep`. With deep=2, k is always 2-4 instead of 2-8. DAG is less mixed than intended.
**Impact:** Mixing graph is sparser than intended, reducing privacy.
**Fix:** Added parentheses: `(_secrets.randbelow(3) + 1) * args.deep`

### BUG 5: BROADCAST SENDS TO WRONG ENDPOINT
**Scenario:** `send_raw_transaction` is NOT a Monero JSON-RPC method (it's not under `/json_rpc`). It's a separate daemon endpoint at `/sendrawtransaction`. Similarly `get_transactions` is at `/gettransactions`. The code was sending to `/json_rpc` which would return "Method not found."
**Impact:** Every single broadcast attempt fails. Money signed but never sent. Operator sees "Node: Method not found" errors.
**Fix:** Changed to use correct daemon HTTP endpoints: `/sendrawtransaction` and `/gettransactions`.

### BUG 6: DOUBLE-SPEND DETECTION MISSING
**Scenario:** TX is broadcast but the node says "double_spend: true". The old code didn't check this flag and might retry, potentially getting a different TX accepted or confusing the state.
**Impact:** Potential double-spend attempt logged against operator, or funds sent twice.
**Fix:** Now checks `double_spend` flag in response. If true, logs it and stops retrying that TX.

### BUG 7: PROGRESS LOG DUPLICATE ENTRIES
**Scenario:** Successful TX appends to `prog["log"]` inside the success branch, then AGAIN after the while loop in the unconditional append.
**Impact:** On resume, progress file has duplicate entries per TX. If code iterates progress to count sent TXs, it overcounts. Manifest integrity check could also be confused.
**Fix:** Success branch saves its own progress (with txid). Failure branch saves separately. No unconditional append.

### BUG 8: OPSEC LEAK - Tor exit IP logged to integrity_chain.log
**Scenario:** `verify_tor()` logged `verified_exit_ip=185.220.100.xxx` into integrity_chain.log. This file persists on disk.
**Impact:** Forensic investigator reads integrity_chain.log, sees exact Tor exit IP used at each stage. Can correlate with ThorChain/node logs by timestamp+IP to deanonymize the operator.
**Fix:** Now logs only "verified_ok" with no IP.

### BUG 9: OPSEC LEAK - BTC entry address logged (even scrubbed)
**Scenario:** integrity_chain.log contains `btc_entry_ok:bc1qxyz...12345678`. Even scrubbed, 8+8 chars of a bech32 address is often enough to narrow to a single address on-chain.
**Impact:** Links the GhostSpiral run to a specific BTC address.
**Fix:** Now logs only "btc_entry_validated" with no address fragment.

### BUG 10: OPSEC LEAK - Full XMR balance logged
**Scenario:** integrity_chain.log contains `balance_total=47.239100000000:unlocked=47.239100000000`. Exact balance at exact timestamp.
**Impact:** Trivially correlates with on-chain data to identify the wallet.
**Fix:** Now logs only "balance_fetched" with no amounts.

### BUG 11: OPSEC LEAK - integrity_chain.log survives paranoia_mode
**Scenario:** Operator runs paranoia_mode to wipe everything. But integrity_chain.log was never in the wipe list. It contains timestamps, stage transitions, fee rates, and (previously) addresses.
**Impact:** Complete forensic timeline of the operation survives on disk.
**Fix:** paranoia_mode now has Phase 10: wipe GhostSpiral artifacts, including integrity_chain.log, all unsigned/signed plans, wallet JSONs, progress files, thor pairs, exit plans. Files are overwritten with null bytes before unlinking.

### BUG 12: --split flag accepted but never used
**Scenario:** Operator passes `--split 5` expecting BTC to be split into 5 chunks across ThorChain for better mixing. The flag is parsed but nothing in the pipeline reads it.
**Impact:** Operator thinks they're getting 5-chunk mixing, actually getting none. False sense of security.
**Status:** Logged but still needs full implementation (requires BTC splitting logic).

## 8. Money-Flow Deep Trace (Round 4)

Precise mathematical audit of fund flow through the pipeline.

### Finding 1: BALANCE MATH — Rounding guard is correct
**Trace with** `unlocked_balance=47.5, fee_xmr=0.00005, wallets=10, deep=2`:
- `rounds = 10 * 2 * 2 = 40`
- `per_round_fee = 0.00005 * 1.5 = 0.000075` (was `*2=0.00010`, fixed)
- `total_fees = 0.000075 * 40 = 0.003`
- `usable = 47.5 - 0.003 = 47.497`
- `split_amt = 47.497 / 40 = 1.187425`
- `quantized_split = 1.1874`
- `total_planned = 1.1874 * 40 = 47.496 <= 47.497` → guard does NOT fire
- **Guard proof:** `quantize(0.0001)` rounds up by at most 0.00005. Max overshoot = `rounds * 0.00005`. Correction subtracts `0.0001 * rounds > 0.00005 * rounds`. Guard always sufficient.

### Finding 2: SELF-SEND is impossible
- `dag[a]` built from `others = [b for b in subs if b != a]` — a is excluded (GhostSpiral:304)
- Plan picks `dst = dag[src][random]` — dst can never equal src
- **No fix needed.**

### Finding 3: ENTRY survives shuffle correctly
- `ENTRY = subs[0]` binds to the string object (GhostSpiral:260)
- `shuffle(subs)` rearranges list but ENTRY keeps original reference
- No subsequent code assumes `subs[0] == ENTRY`
- **No fix needed.**

### BUG 13 (FIXED): Stale progress files not cleaned in airgap/cold mode
**Scenario:** Run 1 produces 40-TX plan + signer_progress.json (last=39). Run 2 produces 15-TX plan in --airgap mode. `sys.exit(0)` skipped the cleanup that auto-mode does.
**Impact:** Signer detects plan mismatch and aborts, but operator must manually delete the stale file.
**Fix:** Added progress file cleanup before `sys.exit(0)` on the airgap/cold path (GhostSpiral:416-420).

### BUG 14 (FIXED): Unsigned file timestamp collision
**Scenario:** Two runs within the same second produce `unsigned_{ts}.json` with identical name. `os.replace()` silently overwrites the first.
**Impact:** First plan destroyed without warning. Also affected `create_receive_wallet` filenames.
**Fix:** Added `secure_hex(4)` random suffix: `unsigned_{ts}_{hex}.json` (GhostSpiral:409, create_receive_wallet:76).

### BUG 15 (FIXED): Fee estimation 2x over-budget
**Scenario:** `per_round_fee = fee_xmr * 2` but only 1 TX is generated per round. Budgets double the actual fees.
**Impact:** For 47.5 XMR the waste is 0.002 XMR (negligible). For small balances (e.g. 0.01 XMR), can lose 3%+ or cause false "insufficient balance" aborts.
**Fix:** Changed to `fee_xmr * Decimal("1.5")` — 1 TX/round + 50% safety margin (GhostSpiral:359).

## 9. Remaining Items

| Item | Status | Notes |
|------|--------|-------|
| `renamethis1` | NOT FIXED | 2400-line chat/code mess. Needs owner decision. |
| Real JoinMarket UTXO parsing | STUB | stage1 returns placeholder; needs JM output format spec |
| Real mempool monitoring | STUB | stage2 uses sleep-mock; needs ThorChain WS integration |
| monero-wallet-cli batch format | NEEDS TESTING | --batch-file usage may vary by wallet-cli version |
| Production RPC endpoints | PLACEHOLDER | Default endpoints are localhost/node.onion |
