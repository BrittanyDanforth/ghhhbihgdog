# GhostSpiral Toolchain — Full Codebase Audit & OPSEC Hardening

> ## ⚠ THIS DOCUMENT IS A SNAPSHOT, NOT THE AUDIT OF RECORD
>
> It describes the codebase **as of 2026-04-12** and has not been updated
> since. It is kept for the reasoning it records, not as a description of
> what the tools do now. Do not act on it without checking the code.
>
> **What is current instead:**
>
> * `OPSEC_SETUP.md` — checked flag by flag against the real parsers,
>   including subcommands, with zero mismatches.
> * `tests/` — the executable record. Every claim worth relying on is
>   asserted there, and the suites run in seconds.
> * The source comments — this repo puts the reasoning next to the code
>   precisely so it cannot drift the way this file has.


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

## 9. Deanonymization Audit (Round 5 — Chain Analyst Perspective)

Full trace of every network call, DNS resolution, and identity leak vector.

### FINDING D1 (FIXED): SOCKS5 vs SOCKS5H DNS leak
**File:** `gs_common.py` line 36 (old)
**Bug:** `SOCKS_RE = re.compile(r"^socks5h?://...")` accepted both `socks5://` and `socks5h://`.
With plain `socks5://`, the Python `requests` library resolves hostnames **locally** before sending
through the proxy. Every domain (check.torproject.org, api.thorswap.net, api.coingecko.com,
moneroblocks.info, xmrchain.net, bisq.markets, haveno.network) would appear in ISP DNS logs.
**Impact:** CRITICAL — full list of contacted services visible to ISP, trivially correlating the
operator to BTC→XMR mixing activity.
**Fix:** Regex now only accepts `socks5h://`. Explicit error message if operator passes `socks5://`.

### FINDING D2 (FIXED): safe_get/safe_post accept proxies=None silently
**File:** `gs_common.py` lines 189-199 (old)
**Bug:** `safe_get(url, proxies=None)` and `safe_post(url, payload, proxies=None)` default to None.
Any caller that forgets to pass the proxy dict sends traffic clearnet without any warning.
Same for `_single_post` in `broadcast_signed_xmr` line 33.
**Impact:** HIGH — a single forgotten `proxy` argument anywhere in the codebase leaks the
operator's real IP to the destination API.
**Fix:** All three functions now `sys.exit()` if proxies is None.

### FINDING D3 (FIXED): Four scripts had optional --tor-proxy
**Files:**
- `broadcast_signed_xmr` line 81: `--tor-proxy` was optional
- `thor_swap_preparer` line 79: `--tor-proxy` was optional, only warned
- `exit_strategy_simulator` line 69: `--tor-proxy` was optional
- `create_receive_wallet` line 39: `--tor-proxy` was optional
**Impact:** CRITICAL — each script could silently operate over clearnet. The operator might
think Tor is in use (because GhostSpiral forced it) but subprocess scripts didn't enforce it.
**Fix:** All four scripts now abort if `--tor-proxy` is not provided.

### FINDING D4 (FIXED): JoinMarket subprocess missing Tor proxy
**File:** `GhostSpiral` line 162 (old)
**Bug:** `subprocess.run(["python3", "tumble.py", wallet, addr, "all"])` — no SOCKS proxy
passed to JoinMarket. JM's tumble.py makes its own network connections to makers and
directory nodes. Without explicit proxy config, JM may use clearnet for directory lookups
and maker connections, leaking the operator's IP to every maker in the tumble.
**Impact:** CRITICAL — every JoinMarket maker sees the operator's real IP.
**Fix:** Now passes `--socks5-host` and `--socks5-port` extracted from `--tor-proxy`.

### FINDING D5 (FIXED): MoneroRPC connection has no proxy support
**File:** `gs_common.py` lines 205-239 (old)
**Bug:** `JSONRPCWallet(host=host, port=port)` from monero-python uses a bare
`requests.Session()` internally with no proxy configuration. If `--rpc-primary` points
to any non-localhost host (e.g., a remote node, a `.onion` address), the HTTP connection
goes clearnet. The operator's IP is leaked to the Monero node operator.
**Impact:** HIGH — if RPC is remote, every wallet RPC call (get_balance, new_subaddress,
get_height, transfer) leaks the operator's IP with correlation to specific wallet activity.
**Fix:** MoneroRPC now validates that the host is localhost. Non-localhost hosts require
external tunneling (socat/ssh through Tor) and trigger an abort with instructions.
If the backend exposes `_session`, proxies are patched in as a defense-in-depth measure.

### FINDING D6 (FIXED): Integrity log timestamps enable correlation
**File:** `gs_common.py` line 64 (old)
**Bug:** `ts = int(time.time())` — exact Unix second. Combined with blockchain timestamps
(Monero block timestamps, ThorChain swap timestamps), an analyst can correlate the
operation window to within seconds. The integrity log contains stage transitions that map
to observable on-chain events (swap initiated → XMR received → mixing started → outputs).
**Impact:** MEDIUM — narrows the anonymity set significantly when combined with chain data.
**Fix:** Timestamps coarsened to 600-second (10-minute) buckets: `ts = int(time.time()) // 600 * 600`.

### FINDING D7 (FIXED): Output files contain exact timestamps
**Files and lines (old):**
- `GhostSpiral` line 395: `"created": int(time.time())` in unsigned plan JSON
- `GhostSpiral` line 401: `unsigned_{int(time.time())}.json` in filename
- `thor_swap_preparer` line 160: `"ts": int(time.time())` per pair
- `create_receive_wallet` line 68: `datetime.now(timezone.utc).isoformat()` (ISO format!)
- `create_receive_wallet` line 76: `wallet_{int(time.time())}.json` in filename
- `exit_strategy_simulator` line 106: `"timestamp": int(time.time())`
**Impact:** MEDIUM — if files are transferred to air-gap machine (USB), recovered by forensics,
or shared with any third party, the exact creation time is embedded in both content and filename.
The ISO timestamp in `create_receive_wallet` was second-precise with timezone.
**Fix:** All embedded timestamps coarsened to 10-minute buckets. Filenames now use
`secure_hex(8)` random identifiers instead of timestamps.

### FINDING D8 (FIXED): paranoia_mode dns_check() does clearnet DNS for Tor domain
**File:** `paranoia_mode` line 50 (old)
**Bug:** `socket.getaddrinfo("check.torproject.org", 443)` — after MAC spoofing, this
immediately performs a clearnet DNS resolution for a Tor Project domain. This:
1. Links the new spoofed MAC to Tor activity in ISP DNS logs
2. Confirms to a network observer that the machine is Tor-aware
3. Creates a timing marker (MAC spoof → immediate Tor DNS → operation start)
**Impact:** HIGH — defeats the purpose of MAC spoofing by immediately fingerprinting
the connection as Tor-related.
**Fix:** Changed to resolve `www.google.com` — a benign, ubiquitous domain that reveals
nothing about operator intent.

### FINDING D9 (FIXED): paranoia_mode does not wipe clipboard, XDG traces, or env vars
**File:** `paranoia_mode` (entire file)
**Missing wipes:**
- **Clipboard:** After copying XMR/BTC addresses for manual operations, clipboard contents
  persist in X11/Wayland clipboard managers (xclip, xsel, wl-copy).
- **recently-used.xbel:** `~/.local/share/recently-used.xbel` records every file opened by
  GUI applications — including JSON plans, wallet files, and blob directories. Each entry
  has an exact timestamp and full file path.
- **Thumbnail cache:** `~/.cache/thumbnails/` stores rendered previews of files. If any
  JSON plan was previewed in a file manager, the thumbnail persists.
- **Trash:** `~/.local/share/Trash/` retains "deleted" files with original paths and timestamps.
- **File manager bookmarks:** `~/.config/gtk-3.0/bookmarks` may reference working directories.
- **Environment variables:** `GPT_KEYS`, `MASTER_ENTROPY`, `WG_CONF`, and other sensitive
  env vars persist in the process environment.
- **/proc/*/cmdline:** Command-line arguments (including addresses) are visible in
  `/proc/PID/cmdline` while processes run. Cannot be wiped from userspace, but
  operator should be aware.
**Impact:** MEDIUM-HIGH — forensic investigator recovers complete operation timeline from
`recently-used.xbel`, actual file contents from Trash, and visual previews from thumbnails.
**Fix:** Added Phase 11 (clipboard wipe), Phase 12 (XDG traces), Phase 13 (env vars).

### FINDING D10 (NOT FIXABLE IN USERSPACE): /proc/*/cmdline exposure
**All scripts** accept command-line arguments containing BTC addresses (`--btc-entry`),
XMR amounts, proxy URLs, wallet file paths, and RPC endpoints. While any GhostSpiral
process is running, these are visible to any process on the system via `/proc/PID/cmdline`.
A local adversary (another user, malware, or a compromised monitoring agent) can read
full command-line arguments of running processes.
**Mitigation:** Use environment variables or config files (read-then-wipe) instead of
command-line arguments for sensitive parameters. Not implemented in this pass.

### FINDING D11 (INFORMATIONAL): renamethis1 contains massive leak surface
**File:** `renamethis1` (2400+ lines)
This file appears to be a chat log concatenated with code from a different tool
(`targ_graber_v13`). It contains:
- `urllib.request.urlopen()` calls with no proxy (line 63)
- OpenAI API calls via `curl`/`torsocks` (line 98-99)
- References to `GPT_KEYS` environment variable
- WireGuard tunnel setup (`wg-quick up`)
- ANU QRNG API calls over clearnet
This file is not imported by any GhostSpiral script but its presence on disk is a
forensic gold mine linking the operator to specific tooling and API keys.
**Status:** Should be securely deleted or moved out of the workspace.

## 10. Idempotency & Crash-Resume Deep Trace (Round 5)

Six adversarial scenarios traced line-by-line through the exact code.
Each scenario documents the precise code path, whether it is handled or
broken, and the user-facing impact.

---

### SCENARIO 1: Operator runs GhostSpiral twice (full pipeline mode)

**Setup:** Run 1 creates plan, signs, broadcasts 20 of 40 TXs, then
broadcast fails at TX 20. Operator reruns GhostSpiral.

#### Run 1 trace
| Step | File:Line | What happens |
|------|-----------|--------------|
| Plan created | GhostSpiral:401 | `ufile = outdir / f"unsigned_{int(time.time())}.json"` → `unsigned/unsigned_1000.json` |
| Stage 5 cleanup | GhostSpiral:419-423 | Cleans `signer_progress.json`, `broadcast_progress.json` |
| Stage 5 cleanup | GhostSpiral:426-430 | `shutil.rmtree(signed_blobs)` removes old blob dir |
| Sign | GhostSpiral:434-438 | Runs signer on `str(ufile)` → 40 blobs in `signed_blobs/` |
| Broadcast | GhostSpiral:452-455 | Runs broadcaster on `signed_blobs/` → TX 0-19 succeed, TX 20 fails → process exits |

#### Run 2 trace
| Step | File:Line | What happens |
|------|-----------|--------------|
| Balance re-fetch | GhostSpiral:329 | `xmr_balance()` reads CURRENT unlocked balance (lower, because some TXs from run 1 spent funds) |
| New amounts | GhostSpiral:362 | `split_amt = usable / rounds` — different amounts from run 1 because balance changed |
| New plan | GhostSpiral:401 | `unsigned/unsigned_1001.json` (new DAG, new amounts, new delays) |
| Cleanup | GhostSpiral:419-423 | Cleans `signer_progress.json` and `broadcast_progress.json` ← **GOOD** |
| Cleanup | GhostSpiral:426-430 | `shutil.rmtree(signed_blobs)` removes ALL old blobs ← **GOOD** |
| Sign | GhostSpiral:434-438 | Signs new plan → fresh blobs |
| Broadcast | GhostSpiral:452-455 | Broadcasts new plan's blobs |

#### What about `unsigned/unsigned_1000.json`?

GhostSpiral Stage 5 cleans `signer_progress.json`, `broadcast_progress.json`,
and `signed_blobs/`, but it does **NOT** clean old unsigned plan files from
`./unsigned/`.

The stale file is not harmful to auto-mode (signer is passed the explicit
path to the new plan), but it is:
- **OPSEC risk**: contains full destination addresses in `txs[].dst`
- **Confusion risk**: operator may accidentally reference it later

#### What about run 1's partially-broadcast TXs and run 2's new plan?

Run 1 broadcast TXs 0-19 from plan 1000. These spent specific key images.
Run 2 creates a brand new plan with different amounts (because balance changed).
Run 2's signer creates fresh signatures for plan 1001's TXs.

**Can run 1's remaining unbroadcast TXs (20-39) cause issues?**
No — their blobs were deleted by `shutil.rmtree(signed_blobs)`.

**Can the already-mined TXs (0-19) from run 1 conflict with run 2?**
Yes, but only in the form of a lower balance — which is correctly handled
because run 2 re-fetches `xmr_balance()` at GhostSpiral:329.

#### Verdict: **PARTIALLY HANDLED**

| Aspect | Status | Detail |
|--------|--------|--------|
| Balance correctness | **OK** | Re-fetched at GhostSpiral:329 |
| Progress cleanup | **OK** | GhostSpiral:419-430 |
| Signed blob cleanup | **OK** | `shutil.rmtree` at GhostSpiral:426-430 |
| Old unsigned plans | **BUG (OPSEC)** | `unsigned/unsigned_1000.json` never cleaned |
| Delay loading | **OK** | Broadcaster loads newest plan at broadcast_signed_xmr:117 |
| Double-send risk | **NONE** | Key images prevent double-spend even if old TXs partially succeeded |

**BUG 16: Old unsigned plan files never cleaned in auto-mode.**
GhostSpiral Stage 5 (lines 419-430) cleans progress files and signed blobs
but not `unsigned/*.json`. Over multiple runs, destination addresses from
every plan accumulate on disk. `paranoia_mode` Phase 10 does clean these
(paranoia_mode:237-288), but between runs they persist.

---

### SCENARIO 2: Operator runs signer manually twice on same plan

**Setup:** Signer completes all 40 TXs. Operator accidentally reruns
without `--resume`. Some blobs (0-19) were already broadcast.

#### Sub-case A: `signer_progress.json` still exists (normal)

| Step | File:Line | What happens |
|------|-----------|--------------|
| Load progress | airgap_tx_signer:150-153 | `progress_file.exists()` → True → loads progress with `last=39` |
| Verify integrity | airgap_tx_signer:82-111 | Plan fingerprint matches (same plan); all 40 blob hashes verified |
| Sign loop | airgap_tx_signer:161-168 | `idx <= progress["last"]` → `idx <= 39` for all TXs → **ALL 40 SKIPPED** |
| Output | airgap_tx_signer:229-230 | "0 signed, 40 resumed" |

**Result:** Fully protected. No re-signing occurs.

#### Sub-case B: `signer_progress.json` was deleted

This happens when:
- GhostSpiral auto-mode cleaned it (GhostSpiral:419-421)
- Operator manually deleted it
- It never existed (first run failed before any progress)

| Step | File:Line | What happens |
|------|-----------|--------------|
| No progress | airgap_tx_signer:154-155 | Fresh progress: `{"last": -1, "manifest": [], "plan_fingerprint": plan_fp}` |
| Re-sign all | airgap_tx_signer:161-223 | All 40 TXs signed with **NEW random nonces** |
| Blob overwrite | airgap_tx_signer:173 | `blob_path = outdir / f"tx_{idx}.blob"` overwrites old blobs |
| New manifest | airgap_tx_signer:227-228 | `signed_manifest_v1.json` overwritten with new hashes |

**Are the new signatures identical?** NO. Monero uses random nonces per
CLSAG ring signature. Each signing produces a **different valid transaction**
for the same amount and destination.

**Can both old and new versions get mined?** NO. Both versions spend the
same inputs and produce the same key images. Monero nodes reject
transactions with duplicate key images against both the chain and the
mempool. Only one version can ever be accepted.

**Broadcaster behavior with re-signed blobs (if broadcast_progress was also cleaned):**

| Blob range | Status | Broadcaster action (broadcast_signed_xmr:267-340) |
|------------|--------|---------------------------------------------------|
| tx_0 – tx_19 | Old version already mined | Node returns `double_spend: true` → line 329-340: logged as `DOUBLE_SPEND`, skipped |
| tx_20 – tx_39 | Old version never sent | New version accepted normally |

**Broadcaster behavior with re-signed blobs (if broadcast_progress was NOT cleaned, `last=19`):**

| Blob range | Status | Broadcaster action |
|------------|--------|--------------------|
| tx_0 – tx_19 | `idx <= 19` | Skipped by progress check (line 202-203) |
| tx_20 – tx_39 | New signatures | Broadcast normally |

#### Verdict: **HANDLED (with acceptable edge cases)**

| Aspect | Status | Detail |
|--------|--------|--------|
| Progress file exists | **OK** | All TXs skipped, no re-signing |
| Progress deleted + broadcast done | **OK** | Double-spend rejected by node; broadcaster handles correctly at line 329-340 |
| Wrong amounts/destinations | **NONE** | Same plan → same amounts and destinations |
| Money loss | **NONE** | Key images prevent double-spend; one version eventually confirms |

---

### SCENARIO 3: Operator uses air-gap workflow

**Step 1: Online machine**
```
GhostSpiral --cold --btc-entry bc1... --tor-proxy socks5h://...
```

| Step | File:Line | What happens |
|------|-----------|--------------|
| Plan created | GhostSpiral:401 | `unsigned/unsigned_1000.json` written |
| Cold exit | GhostSpiral:406-410 | `args.cold` → prints path, `sys.exit(0)` |
| Stage 5 | — | **NEVER RUNS** (no cleanup, no signing, no broadcast) |

**Step 2: Air-gap machine (offline)**
```
airgap_tx_signer unsigned_1000.json --wallet-file offline.wallet --outdir /media/usb/signed_blobs
```

| Step | File:Line | What happens |
|------|-----------|--------------|
| Blob paths | airgap_tx_signer:173 | `blob_path = Path("/media/usb/signed_blobs") / f"tx_{idx}.blob"` |
| Manifest entry | airgap_tx_signer:215 | `"file": "/media/usb/signed_blobs/tx_0.blob"` (absolute path from air-gap machine) |
| Manifest file | airgap_tx_signer:227 | Written to `/media/usb/signed_blobs/signed_manifest_v1.json` |

**Step 3: Back on online machine**
```
broadcast_signed_xmr /media/usb/signed_blobs --tor-proxy socks5h://...
```

#### 3a. Blob loading — OK

| Step | File:Line | What happens |
|------|-----------|--------------|
| Input path | broadcast_signed_xmr:132 | `input_path = Path("/media/usb/signed_blobs")` |
| Glob blobs | broadcast_signed_xmr:142-152 | `input_path.is_dir()` → True → globs `*.blob` → finds all blobs ← **OK** |

#### 3b. Manifest verification — OK

| Step | File:Line | What happens |
|------|-----------|--------------|
| Manifest path | broadcast_signed_xmr:161 | `input_path / "signed_manifest_v1.json"` → `/media/usb/signed_blobs/signed_manifest_v1.json` ← exists |
| Hash lookup key | broadcast_signed_xmr:165 | `Path("/media/usb/signed_blobs/tx_0.blob").name` → `"tx_0.blob"` |
| Blob comparison | broadcast_signed_xmr:168 | `blob.name` → `"tx_0.blob"` → matches manifest key ← **OK** |

The `.name` extraction at line 165 correctly strips the absolute path from
the air-gap machine. Hash verification works across machines.

#### 3c. Delay loading — BROKEN

| Step | File:Line | What happens |
|------|-----------|--------------|
| Glob for plan | broadcast_signed_xmr:117 | `Path(".").glob("unsigned/unsigned_*.json")` |
| CWD is... | — | Whatever directory the operator is in on the online machine |
| Plan exists? | — | **PROBABLY NOT** — different machine, different directory, or plan is on a different path |
| Result | broadcast_signed_xmr:116 | `tx_delays = {}` (empty) |
| Per-TX delay | broadcast_signed_xmr:234 | `tx_delays.get(idx, 0)` → `0` for ALL TXs |
| Timing | broadcast_signed_xmr:235-245 | `if planned_delay > 0:` → False → **NO planned delays applied** |

**Impact:** All 40 TXs are broadcast with only NEWNYM rotation +
`secure_delay(5, 15)` jitter (line 247) between them. The planned delays
of 180-720 seconds (GhostSpiral:385) that decorrelate timing on the
blockchain are **completely lost**. All TXs cluster within ~10 minutes
instead of being spread over hours.

This is a **critical OPSEC failure** — timing decorrelation is the primary
privacy mechanism of the mixing pipeline. A blockchain observer sees 40
transfers from related subaddresses within minutes, trivially linkable.

**Root cause:** The broadcaster hardcodes `Path(".").glob("unsigned/unsigned_*.json")`
(line 117) instead of accepting the plan path as a CLI argument or reading
delays from the manifest/blobs.

#### 3d. Edge case: Manifest loaded as path argument

If operator passes the manifest directly:
```
broadcast_signed_xmr /media/usb/signed_blobs/signed_manifest_v1.json
```

| Step | File:Line | What happens |
|------|-----------|--------------|
| Detect JSON | broadcast_signed_xmr:133 | `args.path.endswith(".json")` → True |
| Load entries | broadcast_signed_xmr:134-141 | `blobs = [Path(e["file"]) ...]` → paths like `Path("/media/usb/signed_blobs/tx_0.blob")` |
| On online machine | — | These paths may not exist (air-gap paths) |
| Missing check | broadcast_signed_xmr:210-216 | `if not blob.exists()` → True → "skipping" → **ALL blobs skipped** |

**Impact:** Zero TXs broadcast, all skipped as "missing." Operator must
use the directory path, not the manifest JSON, for cross-machine workflows.

#### Verdict: **BROKEN — 2 issues**

| Aspect | Status | Detail |
|--------|--------|--------|
| Blob discovery | **OK** | Directory glob works across machines |
| Manifest hash verification | **OK** | `.name` extraction at broadcast_signed_xmr:165 handles cross-machine paths |
| Delay loading | **BROKEN (CRITICAL)** | broadcast_signed_xmr:117 hardcodes CWD-relative glob; delays lost in airgap workflow |
| Manifest-as-path | **BROKEN** | Absolute paths from air-gap machine don't resolve; all blobs skipped |

**BUG 17: Broadcaster does not accept unsigned plan path as CLI argument.**
The delay values are embedded in the unsigned plan JSON (`txs[i].delay` at
GhostSpiral:385) but the broadcaster finds them only via
`Path(".").glob("unsigned/unsigned_*.json")` (broadcast_signed_xmr:117).
In any cross-directory or cross-machine workflow, delays are silently zero.
Fix: add `--plan` argument to broadcaster CLI, or embed delays in the
manifest, or read them from the blob directory.

**BUG 18: Manifest-as-path mode uses absolute paths from signer machine.**
When the broadcaster is given a manifest JSON file as its `path` argument
(broadcast_signed_xmr:133-141), it constructs blob paths from
`e["file"]` which contains the signer machine's absolute paths. These
don't resolve on a different machine. Fix: resolve blob paths relative to
the manifest's parent directory, or always use `.name` to find blobs in the
same directory as the manifest.

---

### SCENARIO 4: Multiple unsigned plans in `./unsigned/` with stale blobs

**Setup:**
- Run 1: `unsigned/unsigned_1000.json` (40 TXs) → `signed_blobs/tx_0.blob` through `tx_39.blob`
- Run 2: `unsigned/unsigned_1001.json` (30 TXs) → signer creates blobs 0-29

#### In auto-mode (GhostSpiral Stage 5)

| Step | File:Line | What happens |
|------|-----------|--------------|
| Cleanup | GhostSpiral:426-430 | `shutil.rmtree(signed_blobs)` → **all old blobs deleted** |
| Sign | GhostSpiral:434-438 | Only 30 blobs created (plan 1001) |

**Result: Fully handled in auto-mode.** The `rmtree` removes everything.

#### In manual mode (operator runs signer + broadcaster separately)

**Signer behavior:**

| Step | File:Line | What happens |
|------|-----------|--------------|
| Create outdir | airgap_tx_signer:144-145 | `outdir.mkdir(parents=True, exist_ok=True)` — does NOT clean existing files |
| Sign 30 TXs | airgap_tx_signer:161-223 | Writes `tx_0.blob` through `tx_29.blob` (overwrites old 0-29) |
| Old blobs | — | `tx_30.blob` through `tx_39.blob` from run 1 **STILL EXIST** |
| Manifest | airgap_tx_signer:227-228 | Contains entries for indices 0-29 only |

After signing, `signed_blobs/` contains:
```
tx_0.blob  ... tx_29.blob   ← from plan 1001 (current)
tx_30.blob ... tx_39.blob   ← from plan 1000 (STALE)
signed_manifest_v1.json     ← covers only indices 0-29
```

**Broadcaster behavior:**

| Step | File:Line | What happens |
|------|-----------|--------------|
| Glob blobs | broadcast_signed_xmr:142-152 | Finds **40 blobs** (all `*.blob` files) |
| Sort | broadcast_signed_xmr:144-152 | Sorted numerically: tx_0 through tx_39 |
| Load delays | broadcast_signed_xmr:117-128 | Loads from plan 1001 → delays for indices 0-29 |
| Manifest verify | broadcast_signed_xmr:161-178 | Loads manifest with 30 entries |

**Manifest verification of stale blobs:**

| Blob | File:Line | What happens |
|------|-----------|--------------|
| tx_0 – tx_29 | broadcast_signed_xmr:168 | `blob.name in manifest_hashes` → True → hash verified ← **OK** |
| tx_30 – tx_39 | broadcast_signed_xmr:168 | `blob.name in manifest_hashes` → **False** → hash check **SKIPPED** |
| Tamper list | broadcast_signed_xmr:172-173 | Stale blobs are NOT added to `tampered` (only mismatches are) |

**The critical code path at broadcast_signed_xmr:167-171:**
```python
for blob in blobs:
    if blob.name in manifest_hashes and blob.exists():
        with open(blob, "rb") as bf:
            actual = hashlib.sha256(bf.read()).hexdigest()
        if actual != manifest_hashes[blob.name]:
            tampered.append(blob.name)
```

Blobs NOT in the manifest silently pass through with no verification.

**Broadcast of stale blobs:**

| Blob | broadcast_signed_xmr:196-360 | What happens |
|------|-------------------------------|--------------|
| tx_0 – tx_29 | Line 234: `tx_delays.get(idx, 0)` | Delays from plan 1001 ← correct |
| tx_30 – tx_39 | Line 234: `tx_delays.get(idx, 0)` → `0` | No delay entry → broadcast immediately |
| tx_30 – tx_39 | Line 258-262 | Blob hex submitted to node |

**What are blobs 30-39?** They are signed transactions from plan 1000 —
**different destinations, different amounts, different DAG.** They are
broadcast to addresses from the OLD mixing plan.

**Impact:**
- 10 extra TXs sent to **wrong destinations** (old plan's subaddresses)
- **Wrong amounts** (old plan may have had different `split_amt`)
- If old plan's addresses are operator-controlled: money not lost but mixing contaminated
- If old plan's addresses were decoys or no longer controlled: **MONEY LOST**
- No warning, no error — the stale blobs are broadcast silently

#### Verdict: **BROKEN — CRITICAL**

| Aspect | Status | Detail |
|--------|--------|--------|
| Auto-mode | **OK** | `shutil.rmtree` at GhostSpiral:426-430 wipes all old blobs |
| Manual-mode signer | **BUG** | airgap_tx_signer:144-145 does not clean outdir before signing |
| Manifest verification | **BUG** | broadcast_signed_xmr:168 silently skips blobs not in manifest |
| Blob count vs plan count | **BUG** | No check that blob count matches plan TX count |
| Wrong destinations | **YES** | Stale blobs from prior plan have different dst addresses |
| Wrong amounts | **YES** | Stale blobs from prior plan have different amounts |

**BUG 19: Signer does not clean output directory before signing.**
`airgap_tx_signer` creates the outdir with `mkdir(exist_ok=True)` at
line 144-145 but does not remove stale blobs from prior runs. If the
new plan has fewer TXs than the old plan, leftover blobs with higher
indices persist and will be broadcast by the broadcaster.
Fix: either `shutil.rmtree` + `mkdir` in the signer, or have the
broadcaster reject blobs not present in the manifest.

**BUG 20: Broadcaster does not reject unverified blobs.**
At broadcast_signed_xmr:167-171, blobs whose names are not in the
manifest are silently passed through without hash verification. The
broadcaster should either: (a) skip/reject blobs not in the manifest,
or (b) verify blob count matches manifest entry count and abort on
mismatch.

---

### SCENARIO 5: Stale `broadcast_progress.json` from prior run (manual mode)

**Setup:**
- Prior run: `broadcast_progress.json` exists with `last=25`
- New plan: 30 TXs signed, 30 blobs in `signed_blobs/`

#### In auto-mode (GhostSpiral Stage 5)

| Step | File:Line | What happens |
|------|-----------|--------------|
| Clean progress | GhostSpiral:419-423 | `Path("broadcast_progress.json").unlink()` ← **GOOD** |
| Broadcast starts fresh | broadcast_signed_xmr:188 | `prog = {"last": -1, "log": []}` |

**Result: Fully handled in auto-mode.**

#### In manual mode

| Step | File:Line | What happens |
|------|-----------|--------------|
| Default progress file | broadcast_signed_xmr:182 | `progF = Path("broadcast_progress.json")` (no `--resume` given) |
| File exists | broadcast_signed_xmr:183-185 | Loads old progress: `last_idx = 25` |
| Broadcast loop | broadcast_signed_xmr:196-203 | For `idx <= 25` → `continue` → **26 TXs SKIPPED** |
| Remaining | broadcast_signed_xmr:196-360 | Only blobs 26-29 broadcast (4 out of 30) |

**What the operator sees:**
```
  [+] TX 26 -> mempool | abcd1234...
  [+] TX 27 -> mempool | ef567890...
  [+] TX 28 -> mempool | 11223344...
  [+] TX 29 -> mempool | 55667788...

  [+] Broadcast complete: 4 sent, 0 failed.
  [+] Progress: broadcast_progress.json
```

The operator has no way to know that 26 TXs were silently skipped.
The output says "4 sent, 0 failed" which looks like a successful small
batch. There is no "X skipped due to resume" message.

**Does the broadcaster have plan fingerprint binding?**

Checking the progress structure:
- Signer progress (airgap_tx_signer:155): `{"last": -1, "manifest": [], "plan_fingerprint": plan_fp}` ← **HAS fingerprint**
- Broadcaster progress (broadcast_signed_xmr:188): `{"last": -1, "log": []}` ← **NO fingerprint**

The broadcaster has **zero protection** against loading a progress file
from a different plan/run.

#### Verdict: **BROKEN — CRITICAL**

| Aspect | Status | Detail |
|--------|--------|--------|
| Auto-mode | **OK** | GhostSpiral:419-423 cleans progress before broadcast |
| Manual-mode default | **BROKEN** | Stale progress causes silent TX skipping |
| Plan fingerprint | **MISSING** | broadcast_progress.json has no plan binding |
| Skip reporting | **MISSING** | No output tells operator how many TXs were skipped |
| Operator awareness | **NONE** | "4 sent, 0 failed" looks like success |

**BUG 21: Broadcaster progress file has no plan fingerprint.**
Unlike the signer (which binds progress to a plan via
`_compute_plan_fingerprint` at airgap_tx_signer:74-79), the broadcaster
progress file at broadcast_signed_xmr:188 contains only `last` and `log`
with no plan binding. A stale progress file from any prior run causes
TXs to be silently skipped.
Fix: add a plan fingerprint (or manifest hash) to broadcast progress and
verify it on load. Abort if the fingerprint doesn't match the current
blob set.

**BUG 22: Broadcaster does not report skipped-due-to-resume count.**
When TXs are skipped by the progress check at broadcast_signed_xmr:202-203,
no counter is incremented and no output is shown. The final summary at
line 363 only reports `success_count` and `fail_count`, giving the operator
a false impression that all TXs were handled.
Fix: add a `skipped_count` counter (like the signer has at
airgap_tx_signer:158) and report it in the summary.

---

### SCENARIO 6: Signed manifest path mismatch

#### 6a. Relative outdir (`--outdir signed_blobs`)

| Step | File:Line | Manifest entry |
|------|-----------|----------------|
| Signer writes | airgap_tx_signer:215 | `"file": "signed_blobs/tx_0.blob"` |
| Broadcaster reads | broadcast_signed_xmr:165 | `Path("signed_blobs/tx_0.blob").name` → `"tx_0.blob"` |
| Glob finds | broadcast_signed_xmr:142-152 | `blob.name` → `"tx_0.blob"` |
| Hash lookup | broadcast_signed_xmr:168 | `"tx_0.blob" in manifest_hashes` → True |

**Result: OK.**

#### 6b. Absolute outdir (`--outdir /tmp/signed/`)

| Step | File:Line | Manifest entry |
|------|-----------|----------------|
| Signer writes | airgap_tx_signer:215 | `"file": "/tmp/signed/tx_0.blob"` |
| Broadcaster reads | broadcast_signed_xmr:165 | `Path("/tmp/signed/tx_0.blob").name` → `"tx_0.blob"` |
| Broadcaster path arg | broadcast_signed_xmr:132 | `input_path = Path("/tmp/signed")` |
| Glob | broadcast_signed_xmr:143 | `/tmp/signed/*.blob` → finds blobs |
| Hash lookup | broadcast_signed_xmr:168 | `"tx_0.blob" in manifest_hashes` → True |

**Result: OK.**

#### 6c. Air-gap cross-machine paths

| Step | File:Line | Value |
|------|-----------|-------|
| Signer (air-gap) | airgap_tx_signer:215 | `"file": "/media/usb/signed_blobs/tx_0.blob"` |
| Broadcaster (online) | broadcast_signed_xmr:132 | `input_path = Path("/mnt/usb/signed")` (different mount point) |
| Manifest load | broadcast_signed_xmr:165 | `Path("/media/usb/signed_blobs/tx_0.blob").name` → `"tx_0.blob"` |
| Blob glob | broadcast_signed_xmr:143 | `/mnt/usb/signed/*.blob` → `blob.name` → `"tx_0.blob"` |
| Hash lookup | broadcast_signed_xmr:168 | Match ← **OK** |

**Result: OK** — the `.name` extraction handles cross-machine paths correctly.

#### 6d. Edge case: Manifest passed directly as path argument

```
broadcast_signed_xmr /media/usb/signed_blobs/signed_manifest_v1.json
```

| Step | File:Line | What happens |
|------|-----------|--------------|
| Detect JSON | broadcast_signed_xmr:133 | `args.path.endswith(".json")` → True |
| Load entries | broadcast_signed_xmr:134-141 | `blobs = [Path(e["file"]) ...]` |
| Blob paths | — | `Path("/media/usb/signed_blobs/tx_0.blob")` (from air-gap machine) |
| On online machine | broadcast_signed_xmr:210 | `if not blob.exists()` → **True** (paths don't resolve) |
| Result | broadcast_signed_xmr:211-216 | All blobs logged as "missing" and skipped |

**Impact:** Zero TXs broadcast. Operator must use directory path, not manifest.

| Step | File:Line | What happens (even on same machine with different CWD) |
|------|-----------|--------------------------------------------------------|
| Relative paths | — | If manifest has `"file": "signed_blobs/tx_0.blob"` and CWD changed, `blob.exists()` → False |

#### Verdict: **MOSTLY HANDLED**

| Aspect | Status | Detail |
|--------|--------|--------|
| Directory mode + relative outdir | **OK** | `.name` extraction works at broadcast_signed_xmr:165 |
| Directory mode + absolute outdir | **OK** | `.name` extraction works |
| Directory mode + cross-machine | **OK** | `.name` extraction works |
| JSON manifest mode (same machine) | **FRAGILE** | Depends on CWD matching signer's CWD |
| JSON manifest mode (cross-machine) | **BROKEN** | Absolute paths from signer don't resolve |

**BUG 18 (restated): Manifest-as-path mode uses absolute paths from signer.**
(Already documented in Scenario 3 above.)

---

### Summary of all bugs found in Round 5

| Bug | Severity | Scenario | Description | Auto-mode? | Manual-mode? |
|-----|----------|----------|-------------|------------|--------------|
| BUG 16 | Medium (OPSEC) | 1 | Old unsigned plans never cleaned in Stage 5 | Broken | Broken |
| BUG 17 | **Critical (OPSEC)** | 3 | Broadcaster hardcodes CWD glob for delays; delays lost in airgap | N/A | Broken |
| BUG 18 | Low | 3, 6 | Manifest-as-path mode fails cross-machine/cross-CWD | N/A | Broken |
| BUG 19 | **Critical (money)** | 4 | Signer does not clean output directory; stale blobs persist | OK (rmtree) | Broken |
| BUG 20 | **Critical (money)** | 4 | Broadcaster silently broadcasts blobs not in manifest | OK (rmtree) | Broken |
| BUG 21 | **Critical (money)** | 5 | Broadcaster progress has no plan fingerprint | OK (cleanup) | Broken |
| BUG 22 | High (UX) | 5 | Broadcaster does not report skipped-due-to-resume count | OK (cleanup) | Broken |

### Pattern: Auto-mode is safe, manual-mode is dangerous

Every critical bug is mitigated in auto-mode by GhostSpiral Stage 5's
cleanup logic (lines 419-430). The danger surface is entirely in manual
workflows:
- Air-gap/cold wallet signing (`--airgap` / `--cold`)
- Manual signer invocation
- Manual broadcaster invocation
- Any workflow where the operator runs components individually

This means the most security-sensitive workflow (air-gap, which exists
specifically for high-value operations) is the LEAST protected against
state corruption bugs.

## 11. Remaining Items

| Item | Status | Notes |
|------|--------|-------|
| `renamethis1` | NOT FIXED | 2400-line chat/code mess. Needs owner decision. Should be securely deleted. |
| Real JoinMarket UTXO parsing | STUB | stage1 returns placeholder; needs JM output format spec |
| Real mempool monitoring | STUB | stage2 uses sleep-mock; needs ThorChain WS integration |
| monero-wallet-cli batch format | NEEDS TESTING | --batch-file usage may vary by wallet-cli version |
| Production RPC endpoints | PLACEHOLDER | Default endpoints are localhost/node.onion |
| CLI args in /proc | KNOWN RISK | Sensitive args visible in /proc/PID/cmdline; consider env/config file approach |
| `random` module in paranoia_mode | LOW RISK | `rand_mac()` uses `random.SystemRandom()` (CSPRNG wrapper), OK |
| BUG 16 | UNFIXED | Clean old unsigned plans in Stage 5 |
| BUG 17 | UNFIXED | Add `--plan` arg to broadcaster for delay loading |
| BUG 18 | UNFIXED | Resolve manifest blob paths relative to manifest directory |
| BUG 19 | UNFIXED | Clean signer output directory before signing (or reject extra blobs) |
| BUG 20 | UNFIXED | Reject/skip blobs not present in manifest |
| BUG 21 | UNFIXED | Add plan fingerprint to broadcast progress |
| BUG 22 | UNFIXED | Report skipped-due-to-resume count in broadcaster |

---

## Section 11: Round 8 — Fundamental Rewrites Against Real-World APIs

### Monero Signing Workflow: COMPLETE REWRITE

**What was wrong:** The signer used `--batch-file` (not a real monero-wallet-cli flag) and tried to run `transfer` in offline mode with a batch file redirect. This is not how Monero offline signing works at all.

**Real workflow (from Monero docs):**
1. Online view-only wallet creates unsigned TX
2. Transfer unsigned TX to offline machine
3. Offline wallet signs with `sign_transfer`
4. Transfer signed TX back
5. Online wallet broadcasts with `submit_transfer`

**Fix:** Complete rewrite of `airgap_tx_signer`:
- Uses stdin to pipe transfer commands to wallet-cli
- Verifies wallet-cli binary exists and reports version
- Handles signed_monero_tx output file
- Supports wallet password
- Reports failed TXs separately (doesn't advance progress on failure)
- Output files use `.signed` extension instead of `.blob`

### ThorSwap API: COMPLETE REWRITE

**What was wrong:** Code used `POST /aggregator/swap` with fields `{from, to, amount, destination}`. The real SwapKit API is `POST /v3/quote` with fields `{sellAsset, buyAsset, sellAmount, destinationAddress}`. Response contains `{quoteId, routes: [{expectedOutput, transaction: {depositAddress, memo}}]}`.

**Fix:** Both `GhostSpiral` and `thor_swap_preparer` now use:
- Correct endpoint: `https://api.swapkit.dev/v3/quote`
- Correct request fields: `sellAsset`, `buyAsset`, `sellAmount`, `destinationAddress`
- Correct response parsing: routes array, expectedOutput, transaction.depositAddress

### Fee Bumping: REMOVED (Monero has no RBF)

**What was wrong:** `_bump_fee()` tried to call `sign_transfer` with a hex file to "bump" the fee. Monero does NOT support Replace-By-Fee. Once a TX is signed, its fee is fixed.

**Fix:** Removed fake `_bump_fee()`. When node rejects with "low_fee", broadcaster now clearly tells the operator to re-sign with higher `--fee-priority` on the signing machine.

### Broadcaster: Fixed crash bug (input_path used before defined)

The delay loading code referenced `input_path` on line 124 but `input_path` was defined on line 163. This would crash on EVERY run. Fixed by moving blob gathering before delay loading.

---

## Section 12: Real-World Scenario — $5,000 BTC Through GhostSpiral

**Starting position:** 0.08 BTC (~$5,000) from a KYC exchange. Goal: untraceable XMR.

### Steps:
1. **Setup:** Install deps, Tor, monero binaries, create offline+view-only wallet pair
2. **Create receive wallet:** `python3 create_receive_wallet --tor-proxy socks5h://127.0.0.1:9050`
3. **Get ThorChain quotes:** `python3 thor_swap_preparer --amounts 0.04 0.04 --dests <ENTRY> <ENTRY> --tor-proxy ...`
4. **MANUALLY send BTC** to deposit addresses with memos (2 swaps, different Tor circuits per quote)
5. **Wait for XMR** to arrive and unlock (~30 min)
6. **Run GhostSpiral** with `--cold` to create unsigned mixing plan (40 rounds)
7. **Sign on air-gapped machine** via USB transfer
8. **Broadcast** over Tor with 3-12 min random delays per TX (~4-8 hours total)
9. **Exit strategy** simulation for Bisq/Haveno off-ramp
10. **Paranoia cleanup** — wipe all artifacts, histories, caches

### Traceability (Sender Scenario):
| Layer | Risk | Why |
|-------|------|-----|
| BTC -> ThorChain | MEDIUM | BTC is transparent; ThorChain observers see swap |
| ThorChain -> XMR | LOW | Decentralized swap; XMR natively private |
| XMR mixing (40 hops) | VERY LOW | Ring signatures + 14 subaddresses + random delays |
| Network observer | LOW | All through Tor with socks5h DNS, NEWNYM per TX |
| Host forensics | LOW | 14-phase paranoia wipe |
| Operator error | MEDIUM | Manual BTC send is weakest link |

---

## Section 13: Receiver Scenario — Someone Sends YOU BTC

**Scenario:** You are the RECEIVER. Someone else sends BTC on your behalf. You just provide a deposit address. The BTC->ThorChain leg is NOT your OPSEC problem.

### Steps:
1. **Setup:** Tor, monero-wallet-rpc on localhost, offline wallet pair
2. **Create receive wallet:** `python3 create_receive_wallet --tor-proxy socks5h://127.0.0.1:9050`
3. **Get ThorChain deposit address:** `python3 thor_swap_preparer --amounts 0.08 --dests <YOUR_XMR_ENTRY> --tor-proxy ...`
4. **Give deposit address + memo to the sender** (over secure channel)
5. **Sender sends BTC** — this is their risk, not yours
6. **Wait for XMR to arrive** at your entry address (~20-40 min)
7. **Run GhostSpiral in RECEIVER mode:** `python3 GhostSpiral --receive-wallet wallet_xxx.json --tor-proxy ... --cold`
8. **Sign on air-gapped machine** -> **broadcast** -> **paranoia cleanup**

### Traceability (Receiver Scenario):
| Layer | Risk | Why |
|-------|------|-----|
| BTC -> ThorChain | NOT YOUR RISK | Sender's BTC, sender's problem |
| ThorChain -> XMR | LOW | Decentralized swap; you just receive |
| XMR receipt to entry addr | LOW | Monero natively private, one-time subaddress |
| XMR mixing (40 hops) | VERY LOW | Ring sigs + 14 subaddrs + 3-12 min random delays |
| Network observer | LOW | All through Tor, socks5h DNS, NEWNYM per TX |
| Host forensics | LOW | 14-phase paranoia wipe (including renamethis1) |
| Address linkage | LOW | Entry subaddress used once, then funds fanned out |
| Timing correlation | LOW | Fan-out + DAG mixing with 180-720s random delays |

### Key Difference: Receiver vs Sender
The receiver's attack surface is much smaller. The sender has the hard
part (BTC is transparent, exchange KYC trails lead to them). The receiver:
- Never touches BTC directly
- Receives XMR on a fresh one-time subaddress
- Immediately mixes into 14+ subaddresses via the DAG
- All network activity is through Tor
- The only link between sender and receiver is the ThorChain deposit
  address, which the receiver generates via Tor

---

## Section 14: Deep Wiring Fixes (Round 10)

### BUG 23 (FIXED): Stage 5 only called --phase create, never --phase sign

**File:** GhostSpiral Stage 5
**What was wrong:** Auto-mode called `airgap_tx_signer --phase create` which creates
unsigned TXs via wallet-rpc, but NEVER called `--phase sign` to actually sign them.
The broadcaster was then pointed at `tx_staging/signed/` which didn't exist.
**Impact:** CRITICAL — auto-mode pipeline produces unsigned TXs that can never be broadcast.
The entire auto-mode is broken. Every operator using auto-mode gets a crash at broadcast.
**Fix:** Stage 5 now has 4 phases:
- 5a: Create unsigned TXs (`--phase create`)
- 5b: Sign TXs (`--phase sign` with wallet file)
- 5c: Broadcast signed TXs
- 5d: Exit strategy simulation

Also added `--wallet-file` and `--wallet-password` CLI args to GhostSpiral,
and verification that unsigned/signed TX files actually exist before proceeding.

### BUG 24 (FIXED): --split flag was dead code (never produced BTC chunks)

**File:** GhostSpiral Stage 2
**What was wrong:** `--split 5` parsed the number but `btc_chunks` was always set to `[]`
because the code said "generating N deposits" but never created any. The `stage2_get_swap_quotes()`
function was only called when `btc_chunks` was non-empty, which only happened with JoinMarket UTXOs.
**Impact:** CRITICAL — operator thinks BTC is split into 5 ThorChain swaps for better mixing.
Actually gets zero deposits. False sense of security.
**Fix:** Added `--btc-amount` parameter. When provided with `--split N`, creates N equal chunks
and calls `stage2_get_swap_quotes()` which generates real deposit addresses + memos.
Also prints a copy-paste-ready SENDER INSTRUCTIONS block.

> **SUPERSEDED — do not read the paragraph above as current behaviour.** "N equal
> chunks" was itself a leak, and a later round removed it twice over. N identical
> deposits made minutes apart to the same vault are one cluster on the *Bitcoin*
> chain, and their OP_RETURNs then read out every Monero destination — so the
> chunks are now jittered (`split_btc_amount`) and sum exactly. Worse, all N
> chunks were routed to ONE entry address, which linked the swaps at the
> aggregator and made the entry veil an N-input transaction whose rings could be
> intersected to identify the carrier. `--split N` now mints one entry address
> per chunk. See `create_entry_set` and `build_entry_veils` in GhostSpiral, and
> the `--split` bullets in OPSEC_SETUP.md.

### BUG 20 (FIXED): Broadcaster silently broadcast unmanifested blobs

**File:** broadcast_signed_xmr
**What was wrong:** Blobs not in the manifest silently passed through hash verification
(the check was `if blob.name in manifest_hashes` — if not in manifest, no check at all).
Stale blobs from prior runs with wrong destinations would be broadcast to wrong addresses.
**Impact:** CRITICAL — money sent to wrong addresses silently.
**Fix:** After manifest verification, blobs are filtered to ONLY those present in the manifest.
Rejected blobs are logged and reported to operator.

### BUG 18 (FIXED): Manifest-as-path mode failed cross-machine

**File:** broadcast_signed_xmr
**What was wrong:** When loading from a manifest JSON, blob paths like
`/media/usb/signed/tx_0.signed` from the air-gap machine don't exist on the online machine.
**Impact:** All blobs reported as "missing" and skipped. Zero TXs broadcast.
**Fix:** When a blob path doesn't exist, try resolving by filename in the manifest's parent
directory. Covers cross-machine USB workflows.

### BUG 25 (FIXED): Fee oracle used fabricated API fields

**File:** GhostSpiral fetch_fee()
**What was wrong:** `moneroblocks.info/api/get_stats` doesn't return `fee_per_kb_median`.
`xmrchain.net/api/emission` doesn't return `fee_per_byte`. Both calls always failed,
silently falling back to a hardcoded value. The fee oracle was pure theater.
**Impact:** Medium — fallback value (0.00005 XMR) is roughly correct, but operator
thinks they have real-time fee data. If fees spike, TXs would be rejected.
**Fix:** Replaced with `get_fee_estimate` RPC call to monero-wallet-rpc, which is
the only reliable source. The RPC knows the actual mempool fee requirements.
Uses typical TX weight (2000 bytes) to estimate per-TX cost.

### BUG 26 (FIXED): exit_strategy_simulator crashed on CoinGecko failure

**File:** exit_strategy_simulator
**What was wrong:** `fetch_prices()` had no fallback. CoinGecko rate-limits Tor exit
nodes aggressively. One failed call = script crash = no exit plan.
**Impact:** High — exit strategy is the last step; a crash here wastes the entire
pipeline run and forces the operator to retry.
**Fix:** Added Bisq price oracle fallback (`price.bisq.wiz.biz/getAllMarketPrices`).
If both fail, exits with a clear error instead of an unhandled exception.
Price source is recorded in the output JSON.

### BUG 27 (FIXED): Liquidity probes used invented API endpoints

**File:** exit_strategy_simulator
**What was wrong:** `bisq.markets/api/markets` and `haveno.network/api/markets` are not
real APIs. Bisq is a P2P DEX with no centralized market data. Both calls always failed
silently and returned `Decimal(0)`.
**Impact:** Medium — "Liquidity depth validation" advertised in docstring was theater.
**Fix:** Replaced with heuristic guidance based on method and amount. P2P DEXs don't
have queryable order books — the honest answer is to guide the operator based on
typical volume ranges.

### BUG 16 (FIXED): Old unsigned plans never cleaned in auto-mode

**File:** GhostSpiral Stage 5
**What was wrong:** Stage 5 cleaned progress files and signed blobs, but NOT
`unsigned/*.json` files. Over multiple runs, destination addresses from every plan
accumulated on disk — a forensic goldmine.
**Fix:** Stage 5 now cleans old unsigned plans, old tx_staging dir, and old signed_blobs.

### Other fixes in this round:
- **Lock file cleanup:** Wrapped Stage 5 in try/finally so `.ghostspiral.lock` is
  always cleaned, even on error. Previously, a crash would leave the lock file,
  preventing all future runs until manually deleted.
- **paranoia dns_check in --dry-run:** DNS resolution now skipped in dry-run mode
  to avoid leaking a real DNS query when the operator expects no network activity.
- **renamethis1 in paranoia wipe:** Added to file patterns so paranoia_mode will
  securely delete this forensic hazard file.
- **Broadcaster --wallet-file removed:** Dead arg (Monero has no RBF). Cleaned up
  help text to reference .signed files instead of .blob.
- **Stale RBF comment removed:** Floating comment block between constants and main()
  was invalid Python (indented at module scope). Removed.

---

## Section 15: Complete Bug Status Table

| Bug | Description | Severity | Fixed? | Fix Location |
|-----|-------------|----------|--------|--------------|
| BUG 1 | Junk text before shebang | FATAL | YES | Round 1 |
| BUG 2 | Spending locked/unconfirmed balance | HIGH | YES | Round 3 |
| BUG 3 | Rounding dust loss | MEDIUM | YES | Round 3 |
| BUG 4 | DAG operator precedence | MEDIUM | YES | Round 3 |
| BUG 5 | Wrong broadcast endpoint | CRITICAL | YES | Round 3 |
| BUG 6 | Double-spend detection missing | HIGH | YES | Round 3 |
| BUG 7 | Progress log duplicate entries | MEDIUM | YES | Round 3 |
| BUG 8 | Tor exit IP logged | HIGH | YES | Round 3 |
| BUG 9 | BTC address logged | HIGH | YES | Round 3 |
| BUG 10 | XMR balance logged | HIGH | YES | Round 3 |
| BUG 11 | integrity_chain.log survives paranoia | HIGH | YES | Round 3 |
| BUG 12 | --split flag accepted but unused | CRITICAL | YES | Round 10 |
| BUG 13 | Stale progress in airgap/cold mode | MEDIUM | YES | Round 4 |
| BUG 14 | Unsigned file name collision | LOW | YES | Round 4 |
| BUG 15 | Fee estimation 2x over-budget | MEDIUM | YES | Round 4 |
| BUG 16 | Old unsigned plans not cleaned | MEDIUM | YES | Round 10 |
| BUG 17 | Broadcaster delays lost in airgap | CRITICAL | YES | Round 7 (manifest embeds delays) |
| BUG 18 | Manifest paths fail cross-machine | MEDIUM | YES | Round 10 |
| BUG 19 | Signer doesn't clean output dir | CRITICAL | YES | Round 7 |
| BUG 20 | Broadcaster broadcasts unmanifested blobs | CRITICAL | YES | Round 10 |
| BUG 21 | Broadcaster progress no fingerprint | CRITICAL | YES | Round 7 |
| BUG 22 | Broadcaster no skip count | HIGH | YES | Round 7 |
| BUG 23 | Stage 5 only creates, never signs | CRITICAL | YES | Round 10 |
| BUG 24 | --split flag dead code | CRITICAL | YES | Round 10 |
| BUG 25 | Fee oracle fake API fields | MEDIUM | YES | Round 10 |
| BUG 26 | exit_sim crashes on CoinGecko fail | HIGH | YES | Round 10 |
| BUG 27 | Liquidity URLs are invented | MEDIUM | YES | Round 10 |
| D1 | socks5:// DNS leak | CRITICAL | YES | Round 5 |
| D2 | safe_get/safe_post accept None proxy | HIGH | YES | Round 5 |
| D3 | Four scripts had optional --tor-proxy | CRITICAL | YES | Round 5 |
| D4 | JoinMarket missing Tor proxy | CRITICAL | YES | Round 5 |
| D5 | MoneroRPC no proxy support | HIGH | YES | Round 5 |
| D6 | Exact timestamps in integrity log | MEDIUM | YES | Round 5 |
| D7 | Exact timestamps in output files | MEDIUM | YES | Round 5 |
| D8 | dns_check resolves Tor domain | HIGH | YES | Round 5 |
| D9 | paranoia missing clipboard/XDG/env | MEDIUM | YES | Round 5 |
| BUG 28 | Stage 5 cleanup deletes current plan | CRITICAL | YES | Round 10c |
| BUG 29 | Signer hardcodes account_index=0 | CRITICAL | YES | Round 10b |
| BUG 30 | Broadcaster default RPC is fake | HIGH | YES | Round 10b |
| BUG 31 | Mock plans not guarded from signing | MEDIUM | YES | Round 10b |

### BUG 28 (FIXED): Stage 5 cleanup deleted the CURRENT unsigned plan

**File:** GhostSpiral Stage 5 cleanup
**What was wrong:** Before calling `_stage5_run`, the cleanup code deleted ALL
`unsigned_*.json` files in the output directory — including the one Stage 4 just
created. When the signer subprocess tried to open `ufile`, it was gone.
**Impact:** CRITICAL — auto-mode crashes at Stage 5a: "File not found" on the plan
that was just written 2 seconds earlier. The entire auto pipeline is broken.
**Fix:** Cleanup now skips the current plan file (`ufile.name`).

### BUG 29 (FIXED): airgap_tx_signer account_index was hardcoded to 0

**File:** airgap_tx_signer phase_create
**What was wrong:** `transfer_split` always passed `"account_index": 0` regardless
of the receive wallet's actual account. In receiver mode with a non-zero account,
the signer would try to spend from the wrong (empty) account.
**Impact:** CRITICAL — all TXs fail or spend from wrong funds.
**Fix:** GhostSpiral embeds `account_index` in the plan metadata; signer reads it.

### BUG 30 (FIXED): Broadcaster default RPC was fake placeholder

**File:** broadcast_signed_xmr
**What was wrong:** Default `--rpc` was `http://node.onion:18089` — a non-existent
hostname. Every run without `--rpc` would fail at the first broadcast attempt.
**Impact:** HIGH — operator has to figure out the correct RPC themselves.
**Fix:** Changed to `http://127.0.0.1:18081` (standard monerod daemon port).
Added clear help text distinguishing daemon RPC from wallet-rpc.

### BUG 31 (FIXED): Mock plans could be accidentally signed

**File:** GhostSpiral + airgap_tx_signer
**What was wrong:** When `--cold` or `--airgap` is used with zero balance, a mock
plan is created with fake 10 XMR. Nothing prevented the operator from running
the signer on this plan and attempting to broadcast, causing confusing failures.
**Impact:** MEDIUM — wasted time and confusing errors.
**Fix:** Mock plans now have `meta.mock = true`. Signer refuses to process them.

### Remaining Known Issues (not bugs, design limitations):
| Item | Status | Notes |
|------|--------|-------|
| JoinMarket UTXO parsing | STUB | Returns empty; needs JM output format spec |
| /proc/PID/cmdline exposure | KNOWN | Can't fix from userspace; consider env vars |
| renamethis1 | ON DISK | Not part of pipeline; paranoia now wipes it |
| CoinGecko rate limiting via Tor | KNOWN | Bisq fallback added; may still fail |

---

## Section 16: Boundary Audit — defects BETWEEN components

The previous rounds each hunted inside one file. This one only looked at the
seams: a value produced in one function and consumed in another, a claim made
in one place about behaviour implemented somewhere else, a fix applied to one
copy of a duplicated thing. Every finding below was reached by reading a path
end to end, not by a failing test — and each is now pinned by a behavioural
test that a recorded mutation turns red.

### B1 (FIXED): the fan-out amount map rode on list order

`size_distribution` built its per-destination amounts with `amounts.extend(got)`
— a flat concatenation of the per-slice results — and `main()` consumes them as
`dict(zip(fanout_dests, fanout_amounts))`. That is correct only while
`concat(slices) == fanout_dests` exactly, i.e. while `split_by_weight` returns
CONTIGUOUS slices IN ORDER.

Nothing stated that contract. `split_by_weight`'s own docstring justifies
contiguity on **readability** grounds — "contiguity keeps the mapping obvious
when a plan is read back by hand" — and names round-robin as the equivalent
alternative. The one edit its comment invites is the edit that breaks this.

Measured, 9 mix targets across chunks weighted 4/3/1:

| partition   | chunk budgets      | amounts each carrier is asked to pay |
|-------------|--------------------|--------------------------------------|
| contiguous  | 3.00 / 2.25 / 0.75 | 2.70 / 2.02 / 0.67  (fits)           |
| round-robin | 3.00 / 2.25 / 0.75 | 1.55 / 0.72 / **3.12** (does not)    |

The third carrier holds 0.75 XMR and is told to pay 3.12. The fan-out then dies
"not enough money" AFTER the veils have relayed and paid their fees — the exact
failure the per-carrier sizing exists to prevent.

**Fix:** amounts follow the ADDRESS, so any partition works, and a partition
that leaves a destination in no slice stops the run at plan time.

**The test was complicit:** the existing check read `sum(_amts[:3]) <= _su[0]`,
slicing the amounts positionally too — so it would have stayed green through
exactly the change that breaks the code.

### B2 (FIXED): "Re-run once it confirms" stranded the money

When a veil carrier does not confirm, `_stage5_run` returns early. It is the
ONLY early return in that function, so it is the one failure where no exit runs
and the balance simply stays put. The operator was told to "Re-run once it
confirms."

Nothing re-runs onto a carrier. Send mode calls `create_entry_set` and mints a
brand-new entry set; receiver mode needs a bundle, and `create_receive_wallet`
only ever calls `new_subaddress_indexed` — it mints a FRESH subaddress and
cannot describe an existing address.

The swap-shortfall gate already said this correctly ("a send-mode run mints a
NEW ENTRY every time, so re-running now leaves what did arrive stranded"). Two
messages about parked money; one corrected, one still pointing the wrong way.

**Also fixed on that path:** only the FAILING carrier's account was printed,
while `report_completion` deliberately skips `report_holdings` on an incomplete
run — so the operator finished holding money on accounts nothing had named.

### B3 (FIXED): the exit's recovery advice, read twice, merges two chunks

`_run_exit_withdrawals` prints "mint a fresh receive wallet ... send this
balance to it" INSIDE the per-held-output loop. With `--split`, a run can end
holding two late swap chunks — and the operator reads that paragraph twice. One
wallet, both balances: a single transaction spending two ENTRY outputs whose
swap settlements are both public, which is the intersection attack.

`report_holdings` does warn ("SPEND THEM ONE ACCOUNT AT A TIME"), but it runs
only on a COMPLETE run, and a run can reach the exit, hold two entry outputs and
still finish incomplete.

Same root cause as B2, in the sibling location. Both now refuse the merge
explicitly, and only when more than one output is held.

### B4 (FIXED): a wipe that cried wolf

`secure_delete_or_warn` printed "It is STILL ON DISK" for files that were never
created. `secure_delete_file` lstats first and returns False when that raises,
so a path that never existed reported exactly like a wipe that could not run.

`atomic_write_json`/`atomic_write_text` call it from `except BaseException`
precisely when `secure_write_bytes` may have failed to CREATE the temp file
(read-only or full filesystem, bad directory perms). Every one of those would
have printed a wipe failure for a nonexistent file and written
`secure_delete_failed` into the integrity chain. An operator who sees that
warning cry wolf is one who ignores the real one about a spend-key password
still sitting in `/dev/shm`.

### B5 (REMOVED): four module-level names nothing read

| name | file | what it was |
|------|------|-------------|
| `FANOUT_FEE_BUFFER_MULT` | GhostSpiral | leftover of the fee-sized buffer the block above it says was written and NOT shipped. Its comment described, in the present tense, a fan-out holding back three fee-widths; the code holds back 10% of the balance. It also called the change destination "the wallet's identity address", which the account rotation stopped being true. |
| `PICONERO` | GhostSpiral | second copy of gs_common's, used only there |
| `CG_PRICE` | thor_swap_preparer | copy of `gs_common.CG_PRICE_URL`; a URL edit here would have changed nothing |
| `_XMR_RE` | thor_swap_preparer | a **checksum-less** address regex sitting beside a validator that checks format AND checksum — an invitation to "validate" with the wrong one |
| `SHELL_HISTORIES` | paranoia_mode | computed at import, read by nothing, under a comment claiming the tests use it. They do not. `wipe_shell_histories` calls `_shell_histories()` live, which is correct: HISTFILE can change between import and the wipe. |

### Checked and found SOUND (recorded so the next audit does not redo them)

* **create → sign boundary.** `_validate_plan` is phase-aware and always runs
  with the real phase (`--phase` is `choices=["create","sign"]`); `src_index` is
  mandatory for create, and `phase_create` indexes it only after that check.
  `account_index` is validated and then actually reaches `sweep_all`/
  `transfer_split` — not validated-then-ignored.
* **The signing fingerprint** covers every field `phase_create` uses
  (`src_index`, `account_index`, `delay`, `sweep`, `dst`/`amt`, `destinations`).
  `peel_num` and `carrier` are planning-only and read by neither the signer nor
  the broadcaster.
* **`SPEND_SOURCES` ↔ `_dest_slices` alignment.** `build_entry_veils` appends
  one carrier per entry unconditionally, in order, and its docstring states the
  contract ("parallel to `entries`"). Unlike B1, the contract is explicit.
* **The dropped-chunk path.** `ENTRY_ADDRS` is assigned once before pruning and
  never narrowed, so `_exit_hold_list` genuinely gets the FULL entry set and a
  chunk that lands late is held back from the exit. Now driven end to end by
  `tests/test_split_partial.py` (4 / 0 / 1 XMR).
* **Failure propagation.** Both `_run_change_sweeps` call sites act on the
  return value and feed `incomplete`, which reaches `report_completion` and
  `sys.exit(1)` with no holdings report and no plan wipe.
* **`gs_console`.** `_guard` runs before every route on both `do_GET` and
  `do_POST` (only `/favicon.ico` bypasses, returning 204 with no data);
  `hmac.compare_digest` for the token; binds `127.0.0.1` only; Host check for
  DNS rebinding, Origin check for CSRF, `application/json` to defeat CORS-simple
  posts.
* **`resolve_destinations`** does enforce one destination per amount — the
  `zip(args.amounts, args.dests)` below it cannot truncate silently. (Checked
  after an initial four-suite mutation run wrongly suggested otherwise;
  `test_swap_receive` catches it. Recorded because the near-miss is the point:
  a mutation is only as good as the suite list it runs.)
* **No dead functions** anywhere in the toolchain (AST call-graph); the three
  apparent ones in `gs_console` are `BaseHTTPRequestHandler` overrides.

### B6 (FIXED): the DAG's safety net could merge two swap chunks

`assign_hop_destinations` exists because of a measured defect — independent
per-source picking put 4.2 of 7 outputs on a shared destination in 200/200
planning runs — and it guarantees "no destination used twice". It guarantees it
**within one call**.

`build_dag_plan` calls it repeatedly: once per chunk group, then once more for
sources belonging to no group. The results are merged with `_dsts.update()`,
which merges by SOURCE and never looked at the destinations. Two ways in:

* **The orphan pass** was given the FULL `mix_targets`, so it re-picked
  addresses the per-group passes had already assigned. Driven directly:
  **200 of 200 plans shared a destination, and every one merged sources from
  different chunk groups.**
* **Overlapping slices.** The per-group passes are safe only because the groups
  are disjoint — and `dest_slices` arrives as a parameter that this function
  never verifies partitions anything. Driven: **180 of 200.**

A shared destination holds value from two swap chunks, and the exit issues one
`sweep_all` per funded subaddress — so both leave in a single multi-input
transaction. That is the convergence the entire split exists to prevent,
produced by the branch written as a safety net, and it contradicted the policy
this same function prints fifteen lines below: *"a missed hop costs mixing
depth, sharing a destination would cost the no-merge guarantee."*

**Fix, in two parts that do different jobs:**

| defence | preserves |
|---------|-----------|
| orphan pass restricted to unclaimed destinations | mixing depth — the orphan can still hop instead of colliding and being dropped |
| cross-call duplicate check, keeping the first claim | the invariant — covers overlapping slices and any future third call site |

Both are needed, and a test that only looked for collisions would have called
the first one redundant. Measured before and after:

| case | before (collided plans, hops) | after |
|------|-------------------------------|-------|
| normal `--split 2` | 0 / 200, 6.0 hops | 0 / 200, 6.0 hops |
| normal, one slice  | 0 / 200, 8.0 | 0 / 200, 8.0 |
| no slices at all   | 0 / 200, 8.0 | 0 / 200, 8.0 |
| sources outside `mix_targets` | **200 / 200**, 8.0 | 0 / 200, 6.0 |
| overlapping slices | **180 / 200**, 6.0 | 0 / 200, 4.7 |

The three normal paths are behaviourally identical; only the two broken ones
change, and they trade hops for the guarantee — the trade the code already
said it wanted.

Unreachable today (`fanout_dests = mix_targets[:fanout_count]` and
`hop_sources = list(fanout_dests)`, so every source is in `mix_targets`), which
is exactly why it survived: it is the branch no run takes and no test drove.

### B7 (FIXED): a promise B1's rewrite had quietly broken — my own

`split_btc_amount`'s new construction works in integer satoshis, so a total
finer than a satoshi came back QUANTISED: 0.1234567891 BTC summed to
0.12345679, while the docstring two paragraphs up says "The total is EXACT".

The nudge loop it replaced kept the sum, by putting the sub-satoshi remainder
on a random chunk — the other half of the same problem, and the reason
`resolve_btc_amount` refuses these at parse time. Neither is correct; the
function now refuses too, so the promise holds for every input it accepts
rather than for every input the caller happened to filter.

Found by re-probing the change against inputs the parse gate normally hides,
not by a test — the same way B1 itself was found.

### B8 (FIXED): three loops checked for a duplicate wallet answer, two did not

`create_fresh_account` fails closed on a malformed answer, and its docstring is
careful about it. But it validates **one call** and has no memory across calls,
so nothing in it can notice a wallet handing back an index it already gave.
Every loop that mints in bulk has to check that for itself.

| loop | checks? |
|------|---------|
| `create_subs` | ✅ `DUPLICATE_SUBADDRESS`, aborts |
| `create_entry_set` | ✅ `DUPLICATE_ENTRY_SUBADDRESS`, aborts |
| `build_entry_veils` | ✅ `DUPLICATE_VEIL_CARRIER`, aborts, naming the merge |
| `build_peel_stage_plan` | ❌ nothing |
| `build_change_sweep_jobs` | ❌ nothing |

Both unguarded loops have the invariant a duplicate breaks written out in their
own prose, at length. Driven against a wallet that repeats one answer:

* **`build_change_sweep_jobs`** returned three jobs all paying **one** address.
  Each change location holds a different chunk's distribution remainder, so
  that address holds value from three swap chunks — and the exit issues one
  `sweep_all` per funded subaddress, spending them together.
* **`build_peel_stage_plan`** produced 4 peels spending only **2 distinct
  sources** (a duplicate carrier — the repeated-spender hub "ROTATING CARRIERS"
  exists to remove), or 4 peels with only **2 distinct change accounts** (a
  duplicate account — so two peels' change lands on one subaddress 0 and the
  collecting sweep becomes the 2-input transaction "ONE ACCOUNT PER HOP" spends
  three paragraphs explaining it must never be).

Both now refuse before any money moves, matching the three loops that already
did. Normal paths unchanged: 3 distinct destinations, 4 peels from 4 distinct
sources with 4 distinct change accounts.

This is the third instance of one shape, and worth naming as a class:
**a helper that guarantees a property per call, and callers that need it across
calls.** B1 was `split_by_weight` (contiguity assumed by `size_distribution`),
B6 was `assign_hop_destinations` (uniqueness assumed across repeated calls),
B8 is `create_fresh_account`. In each case some callers closed the gap and
others did not, and nothing marked which.

### B9 (FIXED): the end-to-end split test had been a coin flip since it was written

The final verification sweep turned `test_split_pipeline` red — one check,
`"Round 2 hops every funded output"`. Re-running it passed. Measured: **9
failures in 25 runs** on the tree from before this round's DAG work, **3 in 25**
after. Pre-existing, and unrelated to the changes that exposed it.

It was not a bug in the round. A hop must leave its source AND stay inside its
own chunk — that restriction is what stops two chunks meeting in one
transaction — so a chunk holding ONE mix subaddress has nowhere legal to send
it. With balances 4/3/1 the smallest chunk gets a slice of 1 when
`fanout_count` lands on 8 (slices `[4,3,1]`) and a slice of 2 when it lands on
10 (`[5,3,2]`), and `fanout_count` varies with the decoy count. The same test
drew both. The run reports the thin chunk ("nowhere to hop"); the test just
demanded more than the design provides.

Loosening it to `<=` would have hidden a genuinely dropped hop. It now counts
the outputs that CAN hop, requires the thin chunk to be reported, and keeps an
upper bound. **0 failures in 40 runs**, and 6/6 red against a mutation that
silently drops one hop.

Second instance of one shape this round — the BTC distinctness check was the
first. **A test that is really a coin flip reports SURVIVED and CAUGHT for the
same mutation on different runs**, and passes verification sweeps by luck. Both
are deterministic now.

### B10 (FIXED): the integrity chain still leaked the run's size by line count

`chain_safe` strips every number out of a chain payload, and its docstring
claims the result: *"which output or address it happened to, **and how many
there were**, does not [survive]."*

It does survive. `delay:idx=7` redacts to `delay:idx=#` — and a
twelve-transaction round writes **twelve identical lines**. Measured: 12 relays
produce 12 `broadcast|delay:idx=#` entries, so the batch size is read off the
file by counting.

The repo already found this and fixed it in one place. `_ROUND_EVENTS_LOGGED`'s
comment states the rule outright:

> Redacting the digits out of "Exit 7/11" gives "exit #/#", which is fine on its
> own and useless as a defence: an analyst counts the `broadcast_ok:exit` lines
> instead and has the number of outputs the run holds… **Cardinality survives
> redaction whenever a loop writes a line per turn.**

That fix covered round events. Six per-turn loops kept writing one line each:

| site | what counting it yields |
|------|-------------------------|
| `broadcast_signed_xmr` `delay:idx=` | transactions in the round |
| `broadcast_signed_xmr` `relayed:idx=:n=` | transactions relayed |
| `GhostSpiral` `quote_ready:{i}` | **`--split N`** |
| `GhostSpiral` `carrier_ready:idx=` | carriers, i.e. swap chunks |
| `GhostSpiral` `change_settled` | change locations |
| `thor_swap_preparer` `pair_{i}:ready` | swaps in the batch |

Those counts are the run's structure — the search keys the pipeline exists to
withhold — and `integrity_log`'s own docstring assumes a reader who has the
file ("An attacker with the log can only narrow the operation to a 10-min
window").

`gs_common.integrity_log_once(stage, kind)` chains an event at most once per
process, mirroring `_ROUND_EVENTS_LOGGED` but shared. Per-item detail still
reaches the terminal, which is the same trade the round-event fix and
paranoia_mode's MAC redaction already made. **Failure events are deliberately
not routed through it** — counting those yields the number of things that went
wrong, not the size of the run, and they are what an audit most needs.

Verified: 12 relays now write 2 lines (one `delay`, one `relayed`), distinct
kinds still get their own line, failure lines are still per-occurrence, and the
chain verifies link by link after the collapse.

The test that guarded this was another source-substring proxy — it asserted the
literal `f"delay:idx={real_idx}"`, so it went red when the call was routed
through the fix while the delay was still being chained, and it could not see
the twelve-lines defect at all. It drives the chain now.
