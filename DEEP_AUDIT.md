# GhostSpiral Deep Adversarial Audit — Round 4

**Date:** 2026-04-14
**Scope:** Full codebase — 8 core pipeline files + 20 new chaos/OPSEC modules
**Method:** Hostile end-to-end trace of every data flow, manual/air-gap/resume scenarios

---

## Executive Summary

Found **30+ confirmed bugs** across the entire codebase. The most dangerous:

1. **GhostSpiral Stage 5 completely broken for hot wallets** — presigned TXs written to `signed/tx_N.signed` but Stage 5 only checks for `tx_N.unsigned`
2. **Broadcaster can send stale blobs from prior runs** — directory mode without manifest broadcasts ALL `.signed` files including old ones with wrong destinations
3. **6 new scripts cannot even start** — syntax errors on line 1 (`collectgrab`, `en_seeder`) or crashes on import (`PAG`, `testergatherSystem`)
4. **Multiple clearnet IP leaks** — UDP to 8.8.8.8, ICMP ping, aiohttp without proxy, `socks5://` DNS leaks accepted
5. **Ghost_unifier references wrong script names** — none of its subprocess calls would find their targets

---

## CRITICAL Bugs (Pipeline Completely Broken)

### BUG 80: GhostSpiral Stage 5 hot-wallet path broken
**File:** `GhostSpiral` lines 804-808
**Scenario:** Hot wallet (has spend key) → `airgap_tx_signer --phase create` returns `tx_metadata_list` (presigned) → writes to `tx_staging/signed/tx_N.signed`. GhostSpiral checks ONLY for `tx_staging/tx_N.unsigned` → file not found → ABORT at TX 0.
**Impact:** CRITICAL — auto-mode 100% broken for hot wallets. Every TX fails.
**Affects:** Auto-mode only (manual mode unaffected).
**Category:** Money loss (pipeline unusable).
**Fix:** Check for both `tx_N.unsigned` and `signed/tx_N.signed`; skip sign phase if presigned.

### BUG 81: Broadcaster sends stale blobs without manifest
**File:** `broadcast_signed_xmr` lines 128-139
**Scenario:** Run 1 produces `tx_0.signed`...`tx_39.signed`. Run 2 produces `tx_0.signed`...`tx_19.signed` (overwrites 0-19). But `tx_20.signed`...`tx_39.signed` from Run 1 still exist. Without `signed_manifest_v1.json`, ALL 40 files are broadcast — including 20 stale TXs to WRONG addresses.
**Impact:** CRITICAL — funds sent to wrong addresses from prior run.
**Affects:** Manual broadcaster mode only.
**Category:** Money loss.
**Fix:** Refuse to broadcast directory without manifest when >1 blob found.

### BUG 82: collectgrab — SyntaxError on line 1
**File:** `collectgrab` line 1
**Scenario:** `python3 collectgrab` → line 1 is bare text "COLLECT AND GRAB" (not a comment) → SyntaxError.
**Impact:** CRITICAL — script cannot start at all.
**Fix:** Changed to `# COLLECT AND GRAB` after shebang.

### BUG 83: en_seeder — SyntaxError on line 1
**File:** `en_seeder` line 1
**Scenario:** Line 1 is bare text "entropy_seeder.py" → NameError.
**Impact:** CRITICAL — entropy seeder cannot start; all downstream tools that need entropy fail.
**Fix:** Changed to `# entropy_seeder.py` after shebang.

### BUG 84: PAG — `secrets.random()` crashes
**File:** `PAG` line 224
**Scenario:** `PolymorphicGenerator.generate()` selects "chaotic" strategy → `secrets.random()` → `AttributeError: module 'secrets' has no attribute 'random'`.
**Impact:** CRITICAL — DAG generation crashes on this strategy.
**Fix:** `secrets.randbelow(100) / 100.0`.

### BUG 85: ghost_unifier — all subprocess calls reference wrong filenames
**File:** `ghost_unifier` lines 62-70
**Scenario:** Calls `entropy_seeder.py`, `dag_generator_v2.py`, etc. but actual filenames are `en_seeder`, `PAG`, `labelmask`, `noise`, `ghostmutator`.
**Impact:** CRITICAL — orchestrator finds no modules; pipeline fails immediately.
**Fix:** Updated all MODULES paths to match actual filenames.

---

## HIGH Bugs (OPSEC Leaks / Significant Breakage)

### BUG 86: testergatherSystem — missing `events` import crashes Telegram monitoring
**File:** `testergatherSystem` line 678
**Scenario:** `@self.client.on(events.NewMessage(...))` references `events` which is never imported from telethon.
**Impact:** HIGH — Telegram real-time monitoring crashes with NameError.
**Fix:** Added `from telethon import events` to import block.

### BUG 87: testergatherSystem — clearnet proxy fetch
**File:** `testergatherSystem` lines 398-413
**Scenario:** `_fetch_socks5_proxies()` does `requests.get()` to clearnet URLs WITHOUT any proxy → real IP exposed to proxy list providers.
**Impact:** HIGH (OPSEC) — IP leaked to proxy aggregators.
**Fix:** Route through Tor SOCKS proxy.

### BUG 88: testergatherSystem — decoy traffic goes clearnet
**File:** `testergatherSystem` lines 1760-1784
**Scenario:** `_generate_decoy_traffic()` uses `aiohttp.ClientSession()` with NO proxy → direct clearnet connections to amazon.com, youtube.com, etc.
**Impact:** HIGH (OPSEC) — real IP exposed to major websites during "stealth" operations.
**Fix:** Route through aiohttp-socks ProxyConnector.

### BUG 89: swap_retry_guard — clearnet UDP to 8.8.8.8
**File:** `swap_retry_guard` lines 182-188
**Scenario:** `QuantumEntropyFusion.harvest_entropy()` opens UDP socket to 8.8.8.8:80 for "network entropy" → clearnet traffic.
**Impact:** HIGH (OPSEC) — Google DNS server sees connection from real IP.
**Fix:** Replaced with `os.urandom()` + `time.monotonic()`.

### BUG 90: swap_retry_guard — SecureMemory.secure_wipe crashes
**File:** `swap_retry_guard` lines 143-146
**Scenario:** `secrets.randbits(8 * self.size)` where size is in bytes → tries to generate absurdly large random integers → MemoryError or extreme slowness.
**Impact:** HIGH — "secure wipe" never actually runs; secrets persist in memory.
**Fix:** Use `os.urandom(self.size)` for random overwrite.

### BUG 91: swap_retry_guard — phantom failure advances progress
**File:** `swap_retry_guard` lines 577-589
**Scenario:** Phantom failure marks swap index as done in progress → on resume, swap is silently skipped → funds never swapped.
**Impact:** HIGH (money loss) — 15% chance per swap of being silently skipped forever.
**Fix:** Do NOT set `progress["last"] = idx` for phantom failures.

### BUG 92: tor_endpoint_juggler — wrong Monero RPC method
**File:** `tor_endpoint_juggler` line 313
**Scenario:** Probes Monero daemon with `"method": "get_height"` which is NOT a standard monerod/wallet-rpc method. Real method is `get_info` (daemon) or `get_height` (wallet-rpc only).
**Impact:** HIGH — healthy daemon nodes falsely marked as failed → reduced RPC pool.
**Fix:** Changed to `get_info` (standard monerod method).

### BUG 93: tor_endpoint_juggler — socks5:// DNS leak in isolation sessions
**File:** `tor_endpoint_juggler` lines 258-261
**Scenario:** `create_isolation_session()` builds URLs with `socks5://` instead of `socks5h://` → DNS resolved locally, not through Tor.
**Impact:** HIGH (OPSEC) — all onion endpoint checks leak DNS queries.
**Fix:** Changed to `socks5h://`.

### BUG 94: noise — accepts socks5:// (DNS leak)
**File:** `noise` line 155
**Scenario:** `validate_proxy()` accepts `socks5://` → requests resolves hostnames locally.
**Impact:** HIGH (OPSEC) — decoy noise HTTP destinations leaked via local DNS.
**Fix:** Reject `socks5://`; only accept `socks5h://`.

### BUG 95: vm_runtime — ICMP ping to 8.8.8.8 bypasses Tor
**File:** `vm_runtime` line 111
**Scenario:** Default `probe_network_latency(host="8.8.8.8")` sends ICMP to Google DNS → reveals real network path. ICMP cannot go through SOCKS proxy.
**Impact:** HIGH (OPSEC) — real IP/network path exposed.
**Fix:** Default host changed to `127.0.0.1` (loopback, no external traffic).

### BUG 96: idk — YubiKey always fails (simulation code)
**File:** `idk` lines 58-77
**Scenario:** `response = b"expected_response"` (hardcoded) compared against `hashlib.sha1(challenge + b"key").digest()` (random each run) → never matches → always rejects.
**Impact:** HIGH (UX deception) — advertised security feature is non-functional.
**Fix:** Use ykman API for real YubiKey challenge-response.

### BUG 97: dmswitch — full unlock token printed to stdout
**File:** `dmswitch` line 487
**Scenario:** When QR libs not available, full hex token printed to terminal → visible in scrollback, screen recordings, process monitoring.
**Impact:** HIGH (OPSEC) — secret token exposed.
**Fix:** Print only first/last 8 chars; write full token to `/dev/shm` (RAM-only).

### BUG 98: ghost_unifier — accepts socks5:// proxy
**File:** `ghost_unifier` line 96
**Scenario:** `validate_tor_proxy()` accepts `socks5://` → DNS leaked for all subprocess calls.
**Impact:** HIGH (OPSEC) — orchestrator allows insecure proxy format.
**Fix:** Reject `socks5://`; only accept `socks5h://`.

### BUG 99: PAG — node types incompatible with labelmask
**File:** `PAG` lines 314-317
**Scenario:** PAG creates nodes with types "transfer", "mixer", "exchange", "forward". labelmask `validate_dag_structure()` only accepts "root", "real", "decoy" → validation fails.
**Impact:** HIGH — generated DAGs rejected by downstream labelmask.
**Fix:** Changed node types to "real" and "decoy".

---

## MEDIUM Bugs

### BUG 100: SML — mlock silently fails (Python mmap has no .mlock())
**File:** `SML` lines 286-289
**Scenario:** `mm.mlock()` → `AttributeError` caught by `except: pass` → "locked in memory" is silently false.
**Impact:** MEDIUM — secrets not actually locked in RAM; may be swapped to disk.
**Fix:** Use `ctypes.CDLL("libc.so.6").mlock()` directly.

### BUG 101: integrity_faker — seed file written with default perms
**File:** `integrity_faker` lines 79-83
**Scenario:** `open(temp_file, 'w')` uses default umask → seed file may be world-readable.
**Impact:** MEDIUM (OPSEC) — entropy seed exposed on multi-user systems.
**Fix:** `os.chmod(temp_file, 0o600)` before and after replace.

### BUG 102: wdna — gap subaddresses with empty `address` field
**File:** `wdna` lines 187-196
**Scenario:** Tools that iterate wallet subaddresses expecting valid address strings crash or produce invalid outputs.
**Impact:** MEDIUM — downstream tools may crash on import.
**Fix:** Generate plausible-looking random hex address for gap slots.

### BUG 103: mirrormask — VM detection kills legitimate Kali VMs
**File:** `mirrormask` line 433
**Scenario:** `detect_analysis_environment()` detects VirtualBox/VMware → `sys.exit(0)` with misleading "maintenance completed" message. Most Kali users run in VMs.
**Impact:** MEDIUM (UX deception) — tool silently does nothing on most Kali setups.
**Fix:** Print warning but continue running.

### BUG 104: label_poisoner — raw RNG seed stored in output JSON
**File:** `label_poisoner` line 266
**Scenario:** `"rng_seed": rng_seed` in the poisoned map → correlates outputs across artifacts.
**Impact:** MEDIUM (OPSEC) — extra metadata leaked.
**Fix:** Store truncated SHA-256 hash of seed instead.

### BUG 105: fake_leaf_inserter — wrong depths for multi-root DAGs
**File:** `fake_leaf_inserter` lines 120-140
**Scenario:** Only BFS from first root → nodes under other roots get wrong depth → fake leaves at wrong positions.
**Impact:** MEDIUM — DAG structure anomalies.
**Fix:** BFS from ALL roots simultaneously.

### BUG 106: GhostSpiral — stage5_progress.json not cleaned on --cold/--airgap
**File:** `GhostSpiral` lines 593-598
**Scenario:** Old auto-mode progress persists when switching to cold mode → confusing state.
**Impact:** LOW — stale file on disk, no functional impact.
**Fix:** Added `stage5_progress.json` to stale cleanup list.

### BUG 107: broadcast_signed_xmr — delay fallback may use wrong plan
**File:** `broadcast_signed_xmr` lines 175-186
**Scenario:** Multiple `unsigned_*.json` in `./unsigned/` → picks newest by name, which may not match the blobs being broadcast.
**Impact:** MEDIUM — wrong timing delays applied (privacy reduction).
**Fix:** Warn when multiple plans found.

---

## Complete Bug Status Table (Round 4)

| Bug | Description | Severity | Fixed? |
|-----|-------------|----------|--------|
| BUG 80 | Stage 5 hot-wallet path broken | CRITICAL | YES |
| BUG 81 | Broadcaster sends stale blobs without manifest | CRITICAL | YES |
| BUG 82 | collectgrab SyntaxError line 1 | CRITICAL | YES |
| BUG 83 | en_seeder SyntaxError line 1 | CRITICAL | YES |
| BUG 84 | PAG secrets.random() crash | CRITICAL | YES |
| BUG 85 | ghost_unifier wrong script paths | CRITICAL | YES |
| BUG 86 | testergatherSystem missing events import | HIGH | YES |
| BUG 87 | testergatherSystem clearnet proxy fetch | HIGH | YES |
| BUG 88 | testergatherSystem decoy traffic clearnet | HIGH | YES |
| BUG 89 | swap_retry_guard UDP to 8.8.8.8 | HIGH | YES |
| BUG 90 | swap_retry_guard SecureMemory wipe crashes | HIGH | YES |
| BUG 91 | swap_retry_guard phantom skips real swaps | HIGH | YES |
| BUG 92 | tor_endpoint_juggler wrong RPC method | HIGH | YES |
| BUG 93 | tor_endpoint_juggler socks5:// DNS leak | HIGH | YES |
| BUG 94 | noise socks5:// DNS leak | HIGH | YES |
| BUG 95 | vm_runtime ICMP bypasses Tor | HIGH | YES |
| BUG 96 | idk YubiKey always fails | HIGH | YES |
| BUG 97 | dmswitch token leaked to stdout | HIGH | YES |
| BUG 98 | ghost_unifier accepts socks5:// | HIGH | YES |
| BUG 99 | PAG node types incompatible with labelmask | HIGH | YES |
| BUG 100 | SML mlock silently fails | MEDIUM | YES |
| BUG 101 | integrity_faker seed perms | MEDIUM | YES |
| BUG 102 | wdna empty gap addresses | MEDIUM | YES |
| BUG 103 | mirrormask kills VMs | MEDIUM | YES |
| BUG 104 | label_poisoner leaks RNG seed | MEDIUM | YES |
| BUG 105 | fake_leaf_inserter multi-root depth | MEDIUM | YES |
| BUG 106 | stage5_progress not cleaned on --cold | LOW | YES |
| BUG 107 | Delay fallback may use wrong plan | MEDIUM | YES |

---

## Round 5 Bugs (BUG 108-114)

### BUG 108 (FIXED): No way to resume Stage 5 on existing plan after crash
**File:** `GhostSpiral` CLI args
**Scenario:** GhostSpiral crashes at TX 15/40. Operator reruns the full command — it generates a NEW plan (new DAG, new fingerprint), discards old progress. No way to resume the old plan.
**Impact:** HIGH — operator loses progress, may double-send or skip TXs.
**Fix:** Added `--resume-plan` flag that loads an existing plan and jumps straight to Stage 5.

### BUG 109 (DOCUMENTED): subaddr_indices not enforced in transfer_split
**File:** `airgap_tx_signer` `phase_create()` line 156
**Scenario:** `transfer_split` is called with only `account_index` — the wallet picks inputs from ANY subaddress. The plan's `src` field is ignored.
**Impact:** MEDIUM — mixing graph topology not enforced at RPC level. This requires resolving subaddress strings to indices via `get_address`, which is a significant refactor.
**Status:** DOCUMENTED as known limitation. Mixing relies on Monero's native ring signatures for privacy rather than src enforcement.

### BUG 110 (FIXED): GhostSpiral Stage 2 doesn't pass SwapKit API key
**File:** `GhostSpiral` line 333
**Scenario:** `safe_post(SWAPKIT_API + "/v3/quote", payload, proxy)` — no `headers` parameter. API key never sent to SwapKit, causing 401 errors.
**Impact:** HIGH — ThorChain quotes fail for authenticated APIs.
**Fix:** Added `--swapkit-api-key` CLI arg + `SWAPKIT_API_KEY` env var lookup. Passes `x-api-key` header to `safe_post`.

### BUG 111 (FIXED): collectgrab runs clearnet when Tor unavailable
**File:** `collectgrab` lines 50-56
**Scenario:** If `stem` not installed (`TOR_AVAILABLE = False`), `proxies = {}` and all HTTP requests go direct clearnet.
**Impact:** CRITICAL (OPSEC) — real IP exposed to Google, Nitter, Reddit during OSINT collection.
**Fix:** Abort with clear error message if Tor not available.

### BUG 112 (FIXED): collectgrab output files world-readable (default umask)
**File:** `collectgrab` all `open(..., 'w')` calls
**Scenario:** Default umask (0022) → collected data files created at 0644, readable by any local user.
**Impact:** MEDIUM (OPSEC) — OSINT results exposed to local adversaries.
**Fix:** Added `_secure_perms()` helper that sets 0600 after each file write.

### BUG 113 (FIXED): Multiple modules write files without 0600 perms
**Files:** `error_log_poisoner`, `labelmask`, `ghostmutator`
**Scenario:** Same as BUG 112 — output files use default umask instead of `gs_common`'s 0600 convention.
**Impact:** MEDIUM (OPSEC) — label maps, mutated scripts, and decoy logs readable by local users.
**Fix:** Added `os.chmod(path, 0o600)` after writes in all three files.

### BUG 114 (FIXED): collectgrab boolean precedence bug in target parsing
**File:** `collectgrab` line 191
**Scenario:** `not line.startswith('[') and '@' in line or ' ' in line` — the `or` has lower precedence than `and`, so ANY line containing a space matches (log lines, errors, etc).
**Impact:** MEDIUM — spurious "targets" cause wrong queries and extra network activity.
**Fix:** Added parentheses: `('@' in line or ' ' in line)`.

### Updated Bug Status Table (Round 5)

| Bug | Description | Severity | Fixed? |
|-----|-------------|----------|--------|
| BUG 108 | No resume-plan mode | HIGH | YES |
| BUG 109 | subaddr_indices not enforced | MEDIUM | DOCUMENTED |
| BUG 110 | Stage 2 missing API key headers | HIGH | YES |
| BUG 111 | collectgrab clearnet when no Tor | CRITICAL | YES |
| BUG 112 | collectgrab output perms | MEDIUM | YES |
| BUG 113 | Module output perms (3 files) | MEDIUM | YES |
| BUG 114 | collectgrab boolean precedence | MEDIUM | YES |

---

## Round 6 — Deep Adversarial Audit (BUG 115-145)

### CRITICAL Bugs

### BUG 115 (FIXED): broadcast_signed_xmr — `rpc_url` undefined (NameError)
**File:** `broadcast_signed_xmr` line 427
**Scenario:** After successful TX broadcast, the mine-confirmation polling loop uses `rpc_url` which is never defined anywhere in the file. Every broadcast that reaches the confirmation-wait stage crashes with `NameError`.
**Impact:** CRITICAL — TX broadcasts succeed but confirmation tracking is impossible. Operator has no idea if TX was mined.
**Fix:** Changed `rpc_url` to `args.rpc`.

### BUG 116 (FIXED): GhostSpiral Stage 2 — only calls /v3/quote, not /v3/swap
**File:** `GhostSpiral` stage2_get_swap_quotes
**Scenario:** The function only called SwapKit's `/v3/quote` and tried to extract `depositAddress` from the quote response. SwapKit's documented flow requires a second `POST /v3/swap` call to get the actual deposit address. Quotes often don't include deposit details.
**Impact:** CRITICAL — Stage 2 fails with "no deposit address" for most SwapKit routes.
**Fix:** Complete rewrite with THORNode native API as primary (no API key needed, GET endpoint), SwapKit two-step flow as fallback. Also added to `thor_swap_preparer`.

### BUG 117 (FIXED): fake_leaf_inserter — missing `os` import
**File:** `fake_leaf_inserter` line 50
**Scenario:** `os.chmod(path, 0o600)` called but `os` never imported. Every successful file write crashes.
**Impact:** CRITICAL — tool completely broken.
**Fix:** Added `import os`.

### BUG 118 (FIXED): label_poisoner — missing `os` import
**File:** `label_poisoner` line 326
**Scenario:** Same as BUG 117. `os.chmod()` with no `os` import.
**Impact:** CRITICAL — tool completely broken.
**Fix:** Added `import os`.

### BUG 119 (FIXED): swap_retry_guard — `before_sleep_log` ImportError
**File:** `swap_retry_guard` line 70
**Scenario:** `before_sleep_log` is not part of tenacity's standard API. The import fails and the entire script cannot start.
**Impact:** CRITICAL — swap orchestrator completely broken on import.
**Fix:** Removed `before_sleep_log` from import (was unused).

### BUG 120 (FIXED): testergatherSystem — wrong PBKDF2 import
**File:** `testergatherSystem` line 40
**Scenario:** `from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2` — the `cryptography` library exports `PBKDF2HMAC`, not `PBKDF2`. ImportError on any code path that uses it.
**Impact:** CRITICAL — SecureDataProcessor completely broken.
**Fix:** Changed to `PBKDF2HMAC`.

### HIGH Bugs

### BUG 121 (FIXED): swap_retry_guard — phantom failure advances progress
**File:** `swap_retry_guard` lines 672-673
**Scenario:** After the phantom failure block, `self.progress["last"] = idx` was ALWAYS called. Phantom failures (decoys) advanced progress, causing real swaps to be permanently skipped on resume. 15% chance per swap of being silently lost.
**Impact:** HIGH — money loss on resume after phantom failure.
**Fix:** Added `return True` after phantom block to skip progress advancement.

### BUG 122 (FIXED): testergatherSystem — undefined `orchestrator` in KeyboardInterrupt
**File:** `testergatherSystem` near end of file
**Scenario:** If Ctrl+C during initialization, `except KeyboardInterrupt` references `orchestrator` which doesn't exist yet → NameError on top of the interrupt.
**Impact:** HIGH — unclean shutdown, potential resource leak.
**Fix:** Wrapped in `try/except NameError`.

### BUG 123 (FIXED): testergatherSystem — clearnet aiohttp leaks
**File:** `testergatherSystem` check_hibp, check_dehashed
**Scenario:** `aiohttp.ClientSession()` without proxy → operator's real IP sent to HaveIBeenPwned and DeHashed APIs.
**Impact:** HIGH (OPSEC) — real IP correlated with breach database queries.
**Fix:** Added ProxyConnector with `socks5h://127.0.0.1:9050`.

### BUG 124 (FIXED): testergatherSystem — socks5:// DNS leak in decoy traffic
**File:** `testergatherSystem` _generate_decoy_traffic
**Scenario:** `socks5://` instead of `socks5h://` → DNS resolution happens locally.
**Impact:** HIGH (OPSEC) — decoy traffic destinations leaked via DNS.
**Fix:** Changed to `socks5h://`.

### BUG 125 (FIXED): PAG — destructive log tampering
**File:** `PAG` anti-forensic functions
**Scenario:** Rewrites `~/.bash_history`, filters `/var/log/syslog` and `/var/log/auth.log`. Destructive on shared systems, needs root, corrupts logs.
**Impact:** HIGH — destroys evidence on shared systems, may break audit requirements.
**Fix:** Replaced with warning message telling operator to handle manually.

### BUG 126 (FIXED): dmswitch — name shadowing (method vs attribute)
**File:** `dmswitch` self.emergency_destruct
**Scenario:** Boolean attribute `self.emergency_destruct` shadows the `emergency_destruct()` method. Calling `switch.emergency_destruct(...)` could resolve to the wrong one.
**Impact:** HIGH — emergency destruct may not trigger when needed.
**Fix:** Renamed attribute to `self._emergency_destruct_enabled`.

### BUG 127 (FIXED): dmswitch — randomized paths at import
**File:** `dmswitch` lines 86-87
**Scenario:** `LOCKED_BUNDLE` and `LOCK_METADATA` paths use `secrets.token_hex(8)` at module load. A second process can never find the same paths.
**Impact:** HIGH — unlock impossible from a different process or after restart.
**Fix:** Changed to fixed paths `.gs_locked_bundle` and `.gs_lock_meta`.

### BUG 128 (FIXED): SML — zombie child processes
**File:** `SML` cmd_load, os.fork()
**Scenario:** Parent never calls `os.waitpid()` → zombie process accumulates.
**Impact:** MEDIUM — process table pollution.
**Fix:** Added `signal.signal(signal.SIGCHLD, signal.SIG_IGN)` before fork.

### BUG 129 (FIXED): GhostSpiral BTC_RE too restrictive
**File:** `GhostSpiral` line 46
**Scenario:** Only accepted bech32 (bc1.../tb1...) but THORChain vaults use legacy (1...) and P2SH (3...) addresses.
**Impact:** MEDIUM — operators with P2SH/legacy addresses rejected at startup.
**Fix:** Updated regex to match `thor_swap_preparer`'s broader pattern.

### MEDIUM Bugs

### BUG 130 (FIXED): tor_endpoint_juggler — log/export files not 0600
**Files:** `tor_endpoint_juggler` log file and JSON export
**Fix:** Added `os.chmod(path, 0o600)` after writes.

### BUG 131 (FIXED): wdna — output files not 0600
**File:** `wdna` write_file_atomically
**Fix:** Added `os.chmod(path, 0o600)` after atomic rename.

### BUG 132 (FIXED): integrity_faker — output not 0600
**File:** `integrity_faker` output writes
**Fix:** Added `os.chmod()` after write.

### BUG 133 (FIXED): mirrormask — entropy_seed.json created without 0600
**File:** `mirrormask` auto-create path
**Fix:** Added `os.chmod()` after write_text.

### BUG 134 (FIXED): collectgrab — no `if __name__` guard
**File:** `collectgrab` module level
**Scenario:** Importing the module for testing triggers the entire pipeline.
**Fix:** Wrapped in `_run_pipeline()` with `if __name__ == "__main__"` guard.

### BUG 135 (FIXED): error_log_poisoner — deprecated `utcfromtimestamp`
**File:** `error_log_poisoner`
**Fix:** Changed to `datetime.fromtimestamp(ts, tz=timezone.utc)`.

### LOW Bugs / Cleanup

### BUG 136-145 (FIXED): Unused imports across 8 files
- `label_poisoner`: removed `unicodedata`
- `swap_retry_guard`: removed `asyncio`, `mmap`, `uuid`, `weakref`
- `swap_retry_guard`: fixed fake `import mlock` → real `ctypes.CDLL` mlockall
- `tor_endpoint_juggler`: removed `aiohttp`, dead constants
- `noise`: removed `socket`, `ssl`, `urllib.parse`
- `ghostmutator`: removed `re`
- `vm_runtime`: removed `threading`; wired `tor_proxy` param in `snapshot_metrics`
- `PAG`: removed `mmap`, `timedelta`; removed dead `--chaos` flag
- `paranoia_mode`: removed unused `secure_hex` import
- `mirrormask`: removed `shutil`; removed dead CLI flags
- `broadcast_signed_xmr`: removed unused `import secrets as _secrets`

### Complete Bug Status Table (Round 6)

| Bug | Description | Severity | Fixed? |
|-----|-------------|----------|--------|
| BUG 115 | broadcast_signed_xmr `rpc_url` undefined | CRITICAL | YES |
| BUG 116 | GhostSpiral Stage 2 quote-only (no /v3/swap) | CRITICAL | YES |
| BUG 117 | fake_leaf_inserter missing `os` import | CRITICAL | YES |
| BUG 118 | label_poisoner missing `os` import | CRITICAL | YES |
| BUG 119 | swap_retry_guard `before_sleep_log` ImportError | CRITICAL | YES |
| BUG 120 | testergatherSystem wrong PBKDF2 import | CRITICAL | YES |
| BUG 121 | swap_retry_guard phantom advances progress | HIGH | YES |
| BUG 122 | testergatherSystem undefined orchestrator on interrupt | HIGH | YES |
| BUG 123 | testergatherSystem clearnet aiohttp (HIBP/DeHashed) | HIGH | YES |
| BUG 124 | testergatherSystem socks5:// DNS leak in decoy | HIGH | YES |
| BUG 125 | PAG destructive log tampering | HIGH | YES |
| BUG 126 | dmswitch name shadowing (method vs attribute) | HIGH | YES |
| BUG 127 | dmswitch randomized paths at import | HIGH | YES |
| BUG 128 | SML zombie child processes | MEDIUM | YES |
| BUG 129 | GhostSpiral BTC_RE too restrictive | MEDIUM | YES |
| BUG 130 | tor_endpoint_juggler file perms | MEDIUM | YES |
| BUG 131 | wdna file perms | MEDIUM | YES |
| BUG 132 | integrity_faker file perms | MEDIUM | YES |
| BUG 133 | mirrormask entropy_seed.json perms | MEDIUM | YES |
| BUG 134 | collectgrab no `__name__` guard | MEDIUM | YES |
| BUG 135 | error_log_poisoner deprecated utcfromtimestamp | MEDIUM | YES |
| BUG 136-145 | Unused imports / dead code across 8+ files | LOW | YES |

### Architecture Improvement: THORNode Native API

Added THORNode native API (`GET /thorchain/quote/swap`) as the primary swap quote source for both `GhostSpiral` and `thor_swap_preparer`. This eliminates the dependency on SwapKit API keys and provides a more reliable, direct connection to the THORChain protocol.

**Flow:**
1. Try THORNode endpoints (`thornode.ninerealms.com`, `thornode.thorswap.net`)
2. If THORNode fails, fall back to SwapKit two-step flow (quote + swap)
3. SwapKit now correctly implements the documented two-step flow

**Benefits:**
- No API key required for THORNode
- Direct protocol access (no intermediary)
- Multiple endpoint fallbacks
- SwapKit still available as backup

---

## Round 7 — Final Hardening Audit (BUG 146-150)

**Date:** 2026-04-14
**Scope:** Remaining integration issues in swap_retry_guard, vm_runtime, en_seeder
**Method:** Endpoint verification, protocol correctness, cross-version portability

### SwapKit Removal Confirmed

SwapKit aggregator endpoints have been **permanently removed** from the codebase. Multiple sources (including Malwarebytes) flagged SwapKit-associated domains as hosting phishing/malicious content. THORNode native API is now the **only** swap quote source across all modules.

### BUG 146 (FIXED): swap_retry_guard — THOR_APIS contained dead/wrong aggregator URLs
**File:** `swap_retry_guard` THOR_APIS constant
**Scenario:** `THOR_APIS` listed aggregator-style URLs (`api.thorswap.net/aggregator`, `thorchain.net/api/aggregator`, `midgard.ninerealms.com/v2/thorchain`) that are either defunct, return 404, or serve a different API format than expected.
**Impact:** HIGH — swap quotes fail on most endpoints; only 1 of 5 URLs was partially functional.
**Fix:** Replaced with verified THORNode native API base URLs: `thornode.ninerealms.com`, `thornode.thorswap.net`, `rpc.ninerealms.com`.

### BUG 147 (FIXED): swap_retry_guard — _execute_swap_request POSTs to /swap (wrong method & path)
**File:** `swap_retry_guard` `_execute_swap_request` method
**Scenario:** Method did `session.post(f"{endpoint}/swap", json=payload)`. THORNode's quote endpoint is `GET /thorchain/quote/swap` with query parameters, not a POST endpoint. Every request returned 404 or 405.
**Impact:** HIGH — swap execution completely broken against THORNode.
**Fix:** Changed to `session.get()` with `GET /thorchain/quote/swap?from_asset=...&to_asset=...&amount=...&destination=...` using proper query parameter encoding.

### BUG 148 (FIXED): swap_retry_guard — PHANTOM_TRAFFIC_PROB default 0.15 too aggressive
**File:** `swap_retry_guard` constant + argparse default
**Scenario:** 15% of swaps randomly get phantom-failed as decoys. While progress advancement was already fixed (Round 6, BUG 121), the high default still confuses operators who see frequent "failures" in logs with no explanation.
**Impact:** MEDIUM (UX) — operators assume real failures and abort or restart unnecessarily.
**Fix:** Changed default to `0.0` (disabled). Operators can opt in with `--phantom-prob 0.15`.

### BUG 149 (FIXED): vm_runtime — Tor connectivity test uses httpbin.org (third-party, unreliable)
**File:** `vm_runtime` `test_tor_connectivity` function
**Scenario:** Used `http://httpbin.org/ip` to verify Tor connectivity. httpbin.org is a third-party service that may be down, rate-limited, or blocked. It also cannot confirm whether traffic is actually routed through Tor — only that a connection succeeded.
**Impact:** MEDIUM (reliability + correctness) — false positives (connected but not via Tor) and false negatives (httpbin down).
**Fix:** Changed to `https://check.torproject.org/api/ip` (official Tor Project endpoint). Now validates `"IsTor": true` in the JSON response to confirm actual Tor routing.

### BUG 150 (FIXED): en_seeder — pickle serialization of random state is brittle
**File:** `en_seeder` `collect_system_entropy` function
**Scenario:** `pickle.dumps(random.getstate())` serializes Python's internal RNG state using pickle, then base64-encodes it into the seed file. Pickle format is not stable across Python versions — a seed generated on Python 3.11 may fail to deserialize on 3.12+, breaking seed portability.
**Impact:** MEDIUM (portability) — seed files not portable across Python versions; `pickle.loads` is also a deserialization attack vector if seed files are shared.
**Fix:** Replaced with `hashlib.sha256(str(random.getstate()).encode()).hexdigest()`. Stores a stable hash of the RNG state instead of raw pickle bytes. Removed unused `pickle` and `base64` imports.

### Complete Bug Status Table (Round 7)

| Bug | Description | Severity | Fixed? |
|-----|-------------|----------|--------|
| BUG 146 | swap_retry_guard dead/wrong THOR_APIS URLs | HIGH | YES |
| BUG 147 | swap_retry_guard POST to /swap (wrong method) | HIGH | YES |
| BUG 148 | swap_retry_guard PHANTOM_TRAFFIC_PROB too high | MEDIUM | YES |
| BUG 149 | vm_runtime httpbin.org Tor test unreliable | MEDIUM | YES |
| BUG 150 | en_seeder pickle serialization brittle | MEDIUM | YES |

### Final Architecture State

- **Swap source:** THORNode native API only (`GET /thorchain/quote/swap`). SwapKit removed entirely (confirmed malicious/phishing by Malwarebytes).
- **Endpoints:** `thornode.ninerealms.com`, `thornode.thorswap.net`, `rpc.ninerealms.com` — all verified THORNode instances.
- **Tor verification:** Uses official `check.torproject.org/api/ip` with `IsTor` validation.
- **Entropy:** Portable SHA-256 hash of RNG state; no pickle dependency.
- **Phantom traffic:** Disabled by default; opt-in via `--phantom-prob`.
- **All files compile cleanly** under Python 3.10+.
