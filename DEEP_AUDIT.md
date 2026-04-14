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
