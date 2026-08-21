# GhostSpiral Toolchain — BRUTAL Feature-vs-Reality Audit

> Generated: 2026-04-12 | Scope: Every file in /workspace
> Method: Line-by-line trace of every advertised feature against actual code behavior

---

## Table of Contents

1. [`--split` Flag (GhostSpiral)](#1---split-flag-ghostspiral)
2. [JoinMarket Integration (GhostSpiral Stage 1)](#2-joinmarket-integration-ghostspiral-stage-1)
3. [ThorChain "Swap" (GhostSpiral Stage 2)](#3-thorchain-swap-ghostspiral-stage-2)
4. [`monero-wallet-cli --batch-file` (airgap_tx_signer)](#4-monero-wallet-cli---batch-file-airgap_tx_signer)
5. [`_bump_fee` / `sign_transfer` (broadcast_signed_xmr)](#5-_bump_fee--sign_transfer-broadcast_signed_xmr)
6. [Fee Oracle (GhostSpiral)](#6-fee-oracle-ghostspiral)
7. [CoinGecko Rate Limiting](#7-coingecko-rate-limiting)
8. [DNS "Leak Check" (paranoia_mode)](#8-dns-leak-check-paranoia_mode)
9. [`resource_check` vs `require_resources`](#9-resource_check-vs-require_resources)
10. [`random` Module (Non-CSPRNG) Usage](#10-random-module-non-csprng-usage)
11. [Additional Findings](#11-additional-findings)

---

## 1. `--split` Flag (GhostSpiral)

### What the operator thinks is happening
The help text says:

```89:90:GhostSpiral
    cli.add_argument("--split", type=int, default=1,
                     help="Number of BTC chunks to split across ThorChain")
```

The operator passes `--split 5` expecting their BTC to be divided into 5 separate ThorChain swap operations, each with a different deposit address and circuit, for better mixing and timing decorrelation.

### What ACTUALLY happens

The `--split` value is parsed into `args.split` but **never used to create multiple chunks or multiple deposit addresses**. Here is the only code path that reads it:

```278:289:GhostSpiral
    if jm_utxos:
        btc_chunks = jm_utxos
    elif args.split >= 1:
        # Operator hasn't specified amounts per chunk, so we can't auto-split.
        # Instead, generate deposit addresses for --split chunks and let
        # the operator decide amounts. Use placeholder to get quotes.
        print(f"\n  [!] No JoinMarket UTXOs. Generating {args.split} ThorChain deposit(s).")
        print(f"  [!] You must manually send BTC to the deposit addresses below.")
        print(f"  [!] XMR will arrive at ENTRY address after ThorChain processes.")
        btc_chunks = []
    else:
        btc_chunks = []
```

Trace:
1. `args.split` defaults to `1`. The condition `args.split >= 1` is **always true** (even with `--split 1`, even with `--split 5`).
2. Both the `elif` and `else` branches set `btc_chunks = []`.
3. The subsequent code at line 291 checks `if btc_chunks:` — this is **always False** (empty list) unless JoinMarket ran.
4. Since `btc_chunks` is empty, `stage2_thor_swap()` is **never called**.
5. The print statements at lines 284-286 mention "Generating {args.split} ThorChain deposit(s)" but **zero deposits are actually generated**. It just prints the number and moves on.

### Can the operator tell without reading source?

**Partially.** They will see the messages:
```
[!] No JoinMarket UTXOs. Generating 5 ThorChain deposit(s).
[!] You must manually send BTC to the deposit addresses below.
```
But **no deposit addresses are ever printed below**. If they read carefully, they might notice the contradiction. But the phrasing "Generating 5 ThorChain deposit(s)" strongly implies the deposits are being created. An operator under stress could easily miss that no addresses follow.

### Danger

**CRITICAL.** The operator believes they have 5 independent ThorChain swap paths for mixing. They have zero. Their entire BTC amount goes through a single manual path with no chunking. The privacy benefit they think they're getting from splitting doesn't exist.

---

## 2. JoinMarket Integration (GhostSpiral Stage 1)

### What the operator thinks is happening

```87:88:GhostSpiral
    cli.add_argument("--joinmarket", action="store_true",
                     help="Enable JoinMarket tumble before ThorChain swap")
```

The operator enables `--joinmarket` expecting their BTC to be tumbled through JoinMarket CoinJoin transactions, producing multiple UTXOs that are then fed into ThorChain swaps.

### What ACTUALLY happens

```155:178:GhostSpiral
    def stage1_joinmarket(btc_addr: str) -> List[Decimal]:
        if not args.joinmarket:
            integrity_log("stage1", "JM_skipped")
            return []
        if not args.joinmarket_wallet:
            sys.exit("[!] --joinmarket-wallet required when --joinmarket is set")
        try:
            result = subprocess.run(
                ["python3", "tumble.py", args.joinmarket_wallet, btc_addr, "all"],
                check=True, capture_output=True, text=True, timeout=3600,
            )
            integrity_log("stage1", "JM_tumble_OK")
            # TODO: parse actual UTXO amounts from result.stdout
            # For now return empty - operator must check JM output manually
            return []
        except subprocess.TimeoutExpired:
```

**Step by step:**
1. `tumble.py` is invoked as a subprocess. This file does not exist in the repo — it relies on the operator having JoinMarket installed with `tumble.py` in the current working directory.
2. **Even if `tumble.py` runs successfully**, the function returns `[]` (empty list) at line 169.
3. The integrity log writes `"JM_tumble_OK"` at line 167 — this is logged **before** the empty return.
4. Back in `main()`, line 181: `integrity_log("stage1", f"done:jm_utxos={len(jm_utxos)}")` logs `jm_utxos=0`.

**The downstream consequence:**
- `jm_utxos` is `[]`, so at line 278 `if jm_utxos:` is False.
- Falls through to the `elif args.split >= 1` branch, which also produces `btc_chunks = []`.
- `stage2_thor_swap()` is never called.
- The pipeline proceeds to Stage 3/4 with **no XMR arriving** because no swap was initiated.

### Can the operator tell without reading source?

**No.** The integrity log says `JM_tumble_OK` followed by `done:jm_utxos=0`. The `_OK` suffix strongly implies success. The `utxos=0` is a number in a log file that most operators won't scrutinize. There is no warning printed to the terminal saying "JoinMarket completed but produced no usable UTXOs."

### Danger

**CRITICAL.** The operator thinks JoinMarket tumbled their BTC and produced tumbled UTXOs for ThorChain. In reality:
1. The tumble may or may not have actually run (depends on `tumble.py` existing).
2. Even if it ran perfectly, the result is discarded.
3. The log says "OK" so the operator moves on.
4. The BTC is now tumbled somewhere in JoinMarket's wallet but **never feeds into the GhostSpiral pipeline** — it's stranded.

---

## 3. ThorChain "Swap" (GhostSpiral Stage 2)

### What the operator thinks is happening

The docstring at the top of GhostSpiral says:

```11:12:GhostSpiral
  Stage 2: ThorChain BTC->XMR swap
```

And `stage2_thor_swap()` is described as:

```187:189:GhostSpiral
    def stage2_thor_swap(chunks: List[Decimal], xmr_dest: str) -> Decimal:
        """Execute BTC->XMR swaps via ThorChain for each BTC chunk.
        Returns total expected XMR received."""
```

The word "Execute" implies the swap happens automatically.

### What ACTUALLY happens

The function **only fetches a quote** from ThorChain and **prints deposit addresses for the operator to manually send BTC to**:

```204:236:GhostSpiral
            payload = {
                "from": "BTC.BTC",
                "to": "XMR.XMR",
                "amount": str(amt),
                "destination": xmr_dest,
            }
            quote = safe_post(f"{THOR_API}/swap", payload, proxy)

            deposit = quote.get("deposit")
            memo = quote.get("memo", "")
            expected = quote.get("expected_amount_out", "0")
            ...
            print(f"  [*] Chunk {i}/{len(chunks)-1}: send BTC to {scrub_address(deposit)}")
            print(f"      Memo: {memo}")
            print(f"      IMPORTANT: Manually send {amt} BTC to the above deposit address!")
            ...
            received_total += expected_dec
```

1. It calls the ThorChain aggregator API to get a quote (deposit address + memo + expected output).
2. It prints "Manually send {amt} BTC to the above deposit address!"
3. It **adds the expected XMR to `received_total` without waiting for or verifying any actual BTC send or XMR receipt**.
4. The function returns `received_total` which is a **theoretical projection**, not an observed balance.

**But it doesn't matter** because as shown in Finding #1 and #2 above, `stage2_thor_swap()` is **never called** unless JoinMarket produces non-empty UTXOs (which it never does per Finding #2). The only call site:

```291:292:GhostSpiral
    if btc_chunks:
        xmr_expected = stage2_thor_swap(btc_chunks, ENTRY)
```

`btc_chunks` is always `[]` in practice.

### Can the operator tell without reading source?

**Mixed.** If `stage2_thor_swap()` were actually called, the "IMPORTANT: Manually send" message is reasonably clear. But:
- The function is named "Execute BTC->XMR swaps" in its docstring — misleading.
- `received_total` is accumulated from quotes, not from actual balance checks. The print at line 294 says "Expected total: ~{xmr_expected} XMR after swaps" — but no swap has occurred, only a quote was fetched.
- In the current code, the function is never reached at all, and the operator sees "MANUAL MODE" messages instead.

### Danger

**CRITICAL (design) + HIGH (current).** Currently the swap is dead code. If it were fixed to actually be called, it would still require a completely manual BTC send that the pipeline doesn't wait for, verify, or confirm. The pipeline would proceed to Stage 3/4/5 assuming XMR has arrived when it hasn't.

---

## 4. `monero-wallet-cli --batch-file` (airgap_tx_signer)

### What the operator thinks is happening

The signer claims to use `monero-wallet-cli` in offline mode with a batch file to automate signing:

```184:194:airgap_tx_signer
                cmd = [
                    args.wallet_cli,
                    "--wallet-file", args.wallet_file,
                    "--offline",
                    "--trusted-daemon",
                    f"--priority={priority}",
                ]
                subprocess.run(
                    cmd + ["--batch-file", batch_path],
                    check=True, timeout=120,
                )
```

The batch file contains:

```180:182:airgap_tx_signer
                with os.fdopen(fd, "w") as batch:
                    batch.write(
                        f"transfer {tx['dst']} {amt}\n"
                    )
```

### What ACTUALLY happens — Multiple problems

**Problem 4a: `--batch-file` is NOT a real monero-wallet-cli flag.**

`monero-wallet-cli` does not have a `--batch-file` option. The actual mechanism for non-interactive command execution is piping commands via stdin, or using the `--command` flag for a single command. The correct approaches would be:
- `echo "transfer <addr> <amount>" | monero-wallet-cli --wallet-file ... --offline`
- `monero-wallet-cli --wallet-file ... --offline --command "transfer <addr> <amount>"`

Using `--batch-file` will cause `monero-wallet-cli` to fail with an "unknown option" error. The `check=True` will then raise `CalledProcessError`.

**Problem 4b: No blob output path specified.**

Even if the command syntax were correct, the code expects a blob file to appear at `outdir / f"tx_{idx}.blob"` (line 173), but no `--output-file` or similar flag is passed to `monero-wallet-cli` to tell it where to write the signed transaction. The `transfer` command in offline mode writes to `signed_monero_tx` in the current directory by default, not to `tx_{idx}.blob`.

**Problem 4c: `--offline` + `transfer` behavior.**

In offline mode, `monero-wallet-cli` creates an **unsigned** transaction file (typically `unsigned_monero_tx`), not a signed one. You need a separate `sign_transfer` step on the cold wallet. The code conflates signing and transfer creation.

**Problem 4d: No password provided.**

`monero-wallet-cli` requires a password to open the wallet. No `--password` or `--password-file` flag is passed. Without it, `monero-wallet-cli` will prompt for a password on stdin, which will hang (since `capture_output` is not set, but there's no stdin input either) or fail.

### Can the operator tell without reading source?

**Yes, eventually.** Every single signing attempt will fail with a `CalledProcessError` and the script will exit at line 197. But the error message won't explain *why* — the operator sees `[!] wallet-cli timed out on TX 0` or `[!] wallet-cli error: ...` with no guidance on the actual problem.

### Danger

**CRITICAL.** The entire signing pipeline is non-functional. Every run will fail at TX 0. The signer is fundamentally broken due to incorrect CLI flags, missing password, and wrong assumptions about output file paths.

---

## 5. `_bump_fee` / `sign_transfer` (broadcast_signed_xmr)

### What the operator thinks is happening

When a node rejects a TX with "low_fee", the broadcaster claims to bump the fee and retry:

```42:66:broadcast_signed_xmr
def _bump_fee(hex_tx: str, wallet_file: str) -> str:
    """Attempt to re-sign TX with bumped fee. Returns original on failure."""
    fd, tmp_path = tempfile.mkstemp(suffix=".hex", prefix="gs_bump_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(hex_tx)
        result = subprocess.run(
            ["monero-wallet-cli", "--wallet-file", wallet_file,
             "--offline", "--command", f"sign_transfer {tmp_path}"],
            capture_output=True, text=True, check=True, timeout=60,
        )
        bumped = Path(tmp_path).read_text().strip()
        if bumped and bumped != hex_tx:
            integrity_log("broadcast", "fee_bump_ok")
            return bumped
        return hex_tx
    except Exception as e:
        integrity_log("broadcast", f"fee_bump_fail:{str(e)[:40]}")
        return hex_tx
```

### What ACTUALLY happens — Multiple problems

**Problem 5a: `sign_transfer` does not accept a file path argument.**

The real `sign_transfer` command in `monero-wallet-cli` takes no arguments. It reads from the default file `unsigned_monero_tx` in the current directory, or you specify the filename *after* the command prompt, not as a CLI argument. The command `sign_transfer {tmp_path}` will either:
- Be interpreted as `sign_transfer` with an unrecognized argument, producing an error
- Or `monero-wallet-cli` will parse `{tmp_path}` as something else entirely

**Problem 5b: `sign_transfer` does not bump fees.**

`sign_transfer` signs an unsigned transaction. It does not modify the fee. Monero has no RBF (Replace-By-Fee) mechanism like Bitcoin. Once a transaction is constructed with a specific fee, you cannot "bump" it — you need to create an entirely new transaction with a higher priority.

**Problem 5c: Writing hex to a file and expecting `sign_transfer` to modify it in-place.**

The code writes the raw TX hex to a temp file, runs `sign_transfer` pointing at that file, then re-reads the same file expecting it to have changed. `sign_transfer` does not work this way — it reads `unsigned_monero_tx` and writes `signed_monero_tx` as separate files.

**Problem 5d: No password provided (same as Finding #4).**

**Problem 5e: The `--command` flag invocation.**

`--command` in `monero-wallet-cli` does exist, but it expects the command as a separate argument, not embedded in the string. It should be `--command`, `"sign_transfer"` as separate args, not `--command`, `"sign_transfer {tmp_path}"`.

### Can the operator tell without reading source?

**No.** The `except Exception` on line 59 catches all failures silently and returns the original hex. The integrity log says `fee_bump_fail:...` but the operator sees `[+] Fee bumped, retrying...` on line 344 **before** the bump is attempted (it's printed after the `_bump_fee` call returns, but the calling code at line 342-344 prints "Fee bumped" regardless of whether the bump actually worked):

```342:344:broadcast_signed_xmr
                    if "low_fee" in str(err_msg).lower() and args.wallet_file:
                        raw_hex = _bump_fee(raw_hex, args.wallet_file)
                        print("  [+] Fee bumped, retrying...")
```

The `raw_hex` variable is reassigned but `_bump_fee` always returns the **original hex** (because it always fails). The "[+] Fee bumped, retrying..." message prints **unconditionally** after `_bump_fee` returns. So the operator sees a success message for an operation that always fails.

### Danger

**HIGH.** Fee bumping silently never works. The operator sees "Fee bumped, retrying..." and thinks the problem is being handled. In reality, the same too-low-fee TX is being resubmitted unchanged, wasting all retry attempts. The TX will never confirm.

---

## 6. Fee Oracle (GhostSpiral)

### What the operator thinks is happening

```55:73:GhostSpiral
def fetch_fee(proxy: Dict[str, str]) -> Decimal:
    """Fetch current median XMR fee from oracle. Tries multiple sources."""
    for url in FEE_ORACLE_URLS:
        try:
            j = safe_get(url, proxy)
            # Different APIs return fee in different fields
            raw_fee = j.get("fee_per_kb_median") or j.get("fee_per_byte")
            if raw_fee:
                fee = Decimal(str(raw_fee)) / Decimal(1024)
                if fee > 0:
                    return fee
        except Exception:
            continue
    fallback = Decimal("0.00005")
    integrity_log("fee", "all_oracles_failed:using_fallback")
    return fallback
```

The operator thinks the pipeline fetches real-time XMR fee data from blockchain explorers.

### What ACTUALLY happens

**Problem 6a: `moneroblocks.info/api/get_stats` — fabricated field names.**

The `moneroblocks.info` API endpoint `/api/get_stats` returns fields like `"difficulty"`, `"hashrate"`, `"total_emission"`, `"last_reward"`, `"current_height"`, etc. It does **NOT** return `fee_per_kb_median`. This field name appears to be invented. The `.get("fee_per_kb_median")` will always return `None`.

**Problem 6b: `xmrchain.net/api/emission` — wrong endpoint for fees.**

The `xmrchain.net` `/api/emission` endpoint returns Monero emission data (total coins minted, coinbase, fee), not per-transaction fee rates. It does **NOT** return `fee_per_byte`. The `.get("fee_per_byte")` will always return `None`.

**Problem 6c: The math is wrong even if the fields existed.**

The code does `Decimal(str(raw_fee)) / Decimal(1024)` — dividing fee_per_kb by 1024 to get fee_per_byte. But Monero fees are typically expressed in atomic units (piconeros), and the actual fee calculation involves the transaction weight, not a simple per-byte division. This formula would produce nonsensical values.

**Problem 6d: Always hits fallback.**

Since both API endpoints return `None` for the expected fields, the function always falls through to the hardcoded fallback of `0.00005` XMR. The integrity log records `all_oracles_failed:using_fallback`.

### Can the operator tell without reading source?

**Probably not in normal operation.** The fallback value is used silently. The integrity log says `all_oracles_failed:using_fallback` but this looks like a transient network issue, not a fundamental code bug. The operator would need to check the log file and understand that this happens on every single run.

### Danger

**MEDIUM.** The hardcoded fallback of 0.00005 XMR happens to be roughly correct for current Monero fees (as of 2024-2025), so the pipeline won't break immediately. But:
- If fees change significantly, the estimate will be wrong, leading to transactions that are too low (rejected) or too high (wasted money).
- The operator thinks they have real-time fee data and they don't.
- The fee oracle is pure theater — two API calls that will never succeed.

---

## 7. CoinGecko Rate Limiting

### What the operator thinks is happening

Multiple scripts fetch live prices from CoinGecko's free API:

```37:37:thor_swap_preparer
CG_PRICE = "https://api.coingecko.com/api/v3/simple/price?ids=monero,bitcoin&vs_currencies=btc"
```

```27:27:exit_strategy_simulator
CG_URL = "https://api.coingecko.com/api/v3/simple/price?ids=monero,bitcoin&vs_currencies=usd,eur"
```

### What ACTUALLY happens

**CoinGecko's free API has a rate limit of 10-30 calls/minute** (varies, typically ~10-15 for unauthenticated). With `safe_get` using 4 retries with exponential backoff, a single failed call can generate up to 4 requests.

**A full pipeline run makes these CoinGecko calls:**
1. `thor_swap_preparer`: 1 call to `_btc_per_xmr()` (line 103) + up to 4 retries = 1-4 calls
2. `exit_strategy_simulator`: 1 call to `fetch_prices()` (line 82) + up to 4 retries = 1-4 calls
3. If `thor_swap_preparer` is called with multiple amounts and Tor causes slow responses, the retries stack up.

**The real problem: Tor exit nodes.** CoinGecko aggressively rate-limits Tor exit IPs because they're shared by thousands of users. The operator's requests are likely to hit rate limits even on the very first call, triggering all 4 retries, which further aggravates the limit.

**There's also a cascade effect:** `safe_get` in `gs_common.py` retries 4 times with exponential jitter (4s initial, 30s max). If the first CoinGecko call is rate-limited, each retry eats into the rate limit window. By the time `exit_strategy_simulator` runs, the limit is likely already hit.

### Can the operator tell without reading source?

**Yes, but poorly.** They'll see the script hang during retries, then either:
- Get a stale/cached response (CoinGecko sometimes returns cached data)
- Get an HTTP 429 error after all retries, causing an exception
- `thor_swap_preparer` will fall through to the hardcoded fallback rate of 0.003 BTC/XMR with a warning
- `exit_strategy_simulator` will crash since `fetch_prices()` has no fallback

### Danger

**MEDIUM.** The slippage check in `thor_swap_preparer` relies on the oracle price. If the oracle fails and falls back to `0.003` BTC/XMR, the slippage check may incorrectly approve or flag quotes. In `exit_strategy_simulator`, a CoinGecko failure is **fatal** — no fallback exists, the script crashes.

---

## 8. DNS "Leak Check" (paranoia_mode)

### What the operator thinks is happening

The docstring advertises:

```15:15:paranoia_mode
  - DNS leak check post-spoof
```

Phase 2 is labeled "DNS check":

```338:339:paranoia_mode
    print("  [*] Phase 2: DNS check")
    dns_check()
```

The operator expects this to detect whether DNS queries are leaking outside of Tor — a critical OPSEC check.

### What ACTUALLY happens

```47:57:paranoia_mode
def dns_check() -> None:
    """Verify DNS works (post-spoof connectivity check)."""
    try:
        res = socket.getaddrinfo("check.torproject.org", 443)
        if not res:
            raise RuntimeError("DNS returned empty")
        integrity_log("paranoia", "dns_check_ok")
    except socket.gaierror as e:
        integrity_log("paranoia", f"dns_fail:{e}")
        print(f"  [!] DNS resolution failed post-spoof: {e}")
        sys.exit(1)
```

**This is NOT a DNS leak check. It is a DNS connectivity check.** Here's what it actually does:

1. Calls `socket.getaddrinfo("check.torproject.org", 443)` — this performs a **regular system DNS lookup**.
2. If the lookup succeeds (returns any IP), it logs `dns_check_ok`.
3. If the lookup fails, it exits.

**What a real DNS leak check would do:**
- Resolve a unique hostname through Tor and verify the resolving IP is a Tor exit node
- Or use a DNS leak testing service (like dnsleaktest.com's API) to verify what DNS server resolved the query
- Or check that `/etc/resolv.conf` points to a Tor DNS resolver (127.0.0.1:5353 for tor-resolve)

**What this check actually proves:**
- That the system's DNS resolver is working (e.g., can reach 8.8.8.8 or the ISP's DNS)
- **This is the OPPOSITE of what you want** — if this succeeds without Tor, it means DNS is going through clearnet, which IS a leak

**The function's own docstring says it:** `"""Verify DNS works (post-spoof connectivity check)."""` — it verifies DNS *works*, not that DNS is *private*. But the module docstring and phase label call it a "DNS leak check."

### Can the operator tell without reading source?

**No.** They see:
```
[*] Phase 2: DNS check
```
And the integrity log says `dns_check_ok`. The operator has every reason to believe their DNS is not leaking. In reality, this check **passes when DNS IS leaking** (because the system DNS resolver works fine over clearnet).

### Danger

**CRITICAL OPSEC.** This is worse than no check at all — it gives false confidence. The operator thinks DNS leaks have been detected and found clean. In reality, their DNS queries are going straight to their ISP's resolver (or Google/Cloudflare), which logs the lookup for `check.torproject.org` — directly linking the operator to Tor usage.

---

## 9. `resource_check` vs `require_resources`

### What the operator thinks is happening

GhostSpiral imports both:

```34:34:GhostSpiral
    safe_get, safe_post, connect_rpc, require_resources, resource_check,
```

The docstring says:

```24:24:GhostSpiral
  - Resource sentinel prevents operation under system stress
```

### What ACTUALLY happens

- `require_resources` is called exactly once at line 120: `require_resources(min_disk_gb=2.0)`
- `resource_check` is **imported but never called** anywhere in GhostSpiral.

In `gs_common.py`, `resource_check` (line 245) is the non-fatal version that returns a boolean. `require_resources` (line 253) is the fatal version that calls `sys.exit`. Both exist and work correctly, but `resource_check` is dead code from the perspective of all scripts that import it.

Checking all files:
- `GhostSpiral`: imports `resource_check`, never calls it
- `create_receive_wallet`: imports `require_resources` only (correct)
- `paranoia_mode`: imports `require_resources` only (correct)
- Other scripts: don't import either

### Can the operator tell without reading source?

**No.** The import succeeds silently. There's no indication that the "resource sentinel" mentioned in the docstring is only doing a one-time check at startup rather than continuous monitoring.

### Danger

**LOW.** `require_resources` is called where needed. The unused `resource_check` import is just dead code — it doesn't cause incorrect behavior, but it suggests a planned feature (continuous monitoring?) that was never implemented.

---

## 10. `random` Module (Non-CSPRNG) Usage

### What the operator thinks is happening

The AUDIT.md and docstrings claim:

```19:19:GhostSpiral
  - CSPRNG for all security-critical randomness (delays, hex extras)
```

And AUDIT.md says:
> | RNG for security ops | random module (Mersenne Twister) | secrets module (CSPRNG) |

The operator believes all randomness uses `secrets` (CSPRNG).

### What ACTUALLY happens

**File: GhostSpiral, line 27:**

```27:27:GhostSpiral
import argparse, json, os, random, re, sys, time, subprocess
```

`random` is imported but **never used** in the rest of the file. All randomness operations use `_secrets` (imported at line 263). This is dead code — harmless but misleading and sloppy. If a future edit accidentally calls `random.something()`, it would silently use the non-CSPRNG.

**File: paranoia_mode, line 21:**

```21:21:paranoia_mode
import argparse, glob, hashlib, os, random, shutil, socket, subprocess, sys, time
```

And it's **actually used** at line 62:

```60:64:paranoia_mode
def rand_mac() -> str:
    """Generate locally-administered unicast MAC."""
    octets = [random.SystemRandom().randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE  # locally administered + unicast
    return ":".join(f"{o:02x}" for o in octets)
```

**This is actually safe.** `random.SystemRandom()` is a wrapper around `os.urandom()` — it IS a CSPRNG. It's not using `random.randint()` (Mersenne Twister); it's using `random.SystemRandom().randint()` which delegates to the OS CSPRNG. However, importing `random` for just `SystemRandom` is confusing and inconsistent with the rest of the codebase which uses `secrets`.

**File: renamethis1** (the 2400-line chat dump):

This file uses `random` extensively in non-CSPRNG contexts:
- Line 42: `import os, sys, json, time, random, secrets, ...`
- Line 111: `random.sample(cdns+onions, 2)` — selecting noise targets
- Line 123: `random.choice(GPT_KEYS)` — selecting API keys
- Line 683: `randf = lambda a,b: random.uniform(a*slow_factor, b*slow_factor)` — timing
- Line 717: `random.choice(ua_list)` — user agent selection
- Line 727: `random.randint(1200,1600)` — window size

These are all predictable Mersenne Twister randomness used for security-critical decisions (which onion to connect to, timing decorrelation, browser fingerprint). However, `renamethis1` appears to be a non-functional chat log dump, not an active script.

### Can the operator tell without reading source?

**No.** The documentation says CSPRNG everywhere. The `import random` in GhostSpiral is invisible to the operator.

### Danger

**LOW (currently) but HIGH (latent).** In the active codebase:
- GhostSpiral imports `random` but doesn't use it — no current vulnerability, but a loaded gun.
- paranoia_mode uses `random.SystemRandom()` which is actually safe, just confusingly written.
- `renamethis1` is riddled with insecure `random` usage but appears to be dead code.

---

## 11. Additional Findings

### Finding 11a: `create_receive_wallet` — Undefined Variable `acct`

**Line 70:**

```66:72:create_receive_wallet
    out = {
        "schema": "gs_receive_wallet_v1",
        "created": datetime.now(timezone.utc).isoformat(),
        "address": addr_str,
        "account_index": acct.index,
        "label": args.label,
    }
```

The variable `acct` is never defined. The function calls `wallet_rpc.new_subaddress()` which returns a string address, not an account object. This will raise `NameError: name 'acct' is not defined` on **every single run**.

**What the operator thinks:** The script creates a receive wallet and saves it to JSON.
**What actually happens:** Crashes with a NameError every time.
**Can they tell?** Yes, immediately — the script crashes.
**Danger:** HIGH — the companion wallet creation tool is completely broken.

---

### Finding 11b: `--suppress-kyc` Flag — Cosmetic Only

**exit_strategy_simulator, lines 70, 126, 139:**

```70:70:exit_strategy_simulator
    ap.add_argument("--suppress-kyc", action="store_true")
```

```125:127:exit_strategy_simulator
    kyc_label = "KYC" if cfg["kyc"] and not args.suppress_kyc else "No-KYC"
    print(f"  Method      : {args.method} ({kyc_label})")
```

```139:140:exit_strategy_simulator
    if cfg["kyc"] and not args.suppress_kyc:
        print(f"  [!] WARNING: {args.method} requires KYC verification")
```

The `--suppress-kyc` flag only affects **terminal display** (whether the KYC warning is shown and the label says "KYC" vs "No-KYC"). It does NOT change:
- The `kyc_required` field in the output JSON (line 108: always `cfg["kyc"]`)
- Any actual behavior regarding KYC avoidance

**What the operator thinks:** They might believe `--suppress-kyc` configures the exit strategy to avoid KYC exchanges.
**What actually happens:** It just hides the warning label from the terminal output.
**Can they tell?** Only by reading the JSON output and seeing `kyc_required: true`.
**Danger:** MEDIUM — operator may choose a KYC method thinking they've suppressed the KYC requirement, when they've only suppressed the *warning*.

---

### Finding 11c: Liquidity Probes Use Invented API Endpoints

**exit_strategy_simulator, lines 28-29:**

```28:29:exit_strategy_simulator
BISQ_URL = "https://bisq.markets/api/markets?pair=XMR_BTC"
HAVENO_URL = "https://haveno.network/api/markets/XMR_BTC"
```

- `bisq.markets` is not a real Bisq API endpoint. Bisq is a P2P DEX without a centralized market data API.
- `haveno.network/api/markets/XMR_BTC` is not a documented Haveno API endpoint.

The `liquidity_score()` function at line 49 will always fail with a network error and return `Decimal(0)`:

```48:56:exit_strategy_simulator
def liquidity_score(url: str, buy_key: str, sell_key: str, proxy) -> Decimal:
    try:
        book = safe_get(url, proxy)
        bids = Decimal(str(book[buy_key][0]["amount"])) if book.get(buy_key) else Decimal(0)
        asks = Decimal(str(book[sell_key][0]["amount"])) if book.get(sell_key) else Decimal(0)
        return bids + asks
    except Exception:
        return Decimal(0)
```

**What the operator thinks:** They're getting real-time order book depth analysis for their chosen exit method.
**What actually happens:** The function silently fails and returns 0 every time. The output shows "Liquidity: unavailable (API fail)".
**Can they tell?** Partially — they see "unavailable" but might attribute it to Tor connectivity issues rather than a fundamentally broken feature.
**Danger:** MEDIUM — the "liquidity depth validation" advertised in the docstring is pure theater. Operator makes exit decisions without the liquidity data they think they have.

---

### Finding 11d: ThorChain API Endpoint Is Wrong

**GhostSpiral line 42 and thor_swap_preparer line 36:**

```42:42:GhostSpiral
THOR_API = "https://api.thorswap.net/aggregator"
```

```36:36:thor_swap_preparer
THOR_API = "https://api.thorswap.net/aggregator"
```

ThorSwap's aggregator API at `api.thorswap.net` is **not** the same as ThorChain's native swap interface. ThorChain swaps are initiated by sending BTC with a specific memo to an inbound vault address. The actual ThorChain API (for getting quotes/inbound addresses) is at `https://thornode.ninerealms.com` or similar THORNode endpoints, using paths like `/thorchain/quote/swap`.

The ThorSwap aggregator is a third-party frontend service that:
1. Adds its own fee on top
2. May require API keys or have its own rate limits
3. Is a centralized service that logs requests
4. May not support XMR at all (ThorSwap frontend support for XMR has been inconsistent)

**What the operator thinks:** They're interacting directly with ThorChain's decentralized protocol.
**What actually happens:** They're hitting a centralized aggregator that can log their IP (even through Tor, correlating request patterns), add fees, and potentially refuse XMR swaps.
**Danger:** HIGH — OPSEC compromise (centralized logging) and potential swap failure.

---

### Finding 11e: Stage 5 Calls Scripts Without Verifying They Exist

**GhostSpiral lines 434-438, 452-455, 470-472:**

```434:438:GhostSpiral
        subprocess.run(
            ["python3", "airgap_tx_signer", str(ufile),
             "--wallet-file", "offline.wallet", "--outdir", "signed_blobs"],
            check=True, timeout=1800,
        )
```

- Hardcodes `"offline.wallet"` as the wallet file — this is never created by any script in the pipeline. The operator would need to manually place an `offline.wallet` file in the current directory.
- The scripts `airgap_tx_signer`, `broadcast_signed_xmr`, and `exit_strategy_simulator` are invoked by filename in the current directory. No `PATH` check, no existence check.

**Danger:** MEDIUM — Stage 5 will fail immediately if the scripts aren't in cwd or if `offline.wallet` doesn't exist, but the error messages will be confusing subprocess errors rather than helpful guidance.

---

### Finding 11f: `tor_recheck` Bypasses Dry-Run in `paranoia_mode`

`paranoia_mode` never calls `tor_recheck` or `verify_tor` — it doesn't import them. But more importantly, `dns_check()` at line 339 is called **even during `--dry-run`**. It performs a real DNS lookup regardless of the dry-run flag, potentially leaking that the operator is resolving `check.torproject.org`.

```336:339:paranoia_mode
    spoof_mac(args.iface, args.dry_run)

    print("  [*] Phase 2: DNS check")
    dns_check()
```

**Danger:** LOW-MEDIUM — In dry-run mode, the operator expects nothing to actually happen. But DNS resolution occurs unconditionally.

---

### Finding 11g: Integrity Log Survives Because It's Written By the Wipe Script

`paranoia_mode` Phase 10 wipes GhostSpiral artifacts including `integrity_chain.log`. But every phase of `paranoia_mode` itself writes to `integrity_chain.log` via `integrity_log()`. The final line:

```365:365:paranoia_mode
    integrity_log("paranoia", f"complete:dry={args.dry_run}")
```

This is written **after** Phase 10 (the artifact wipe at line 363). So the freshly-wiped integrity log is immediately re-created with the paranoia_mode completion entry. The resulting file contains a single line proving that `paranoia_mode` was run, including whether it was a dry run.

**What the operator thinks:** All traces are wiped.
**What actually happens:** A new `integrity_chain.log` is created after the wipe, containing forensic evidence.
**Can they tell?** Only by checking if the file exists after running.
**Danger:** MEDIUM — forensic evidence of the cleanup operation survives.

---

### Finding 11h: DAG Operator Precedence Bug (Partially Fixed)

AUDIT.md Bug #4 documents this:

```306:306:GhostSpiral
        k = min((_secrets.randbelow(3) + 1) * args.deep, max_k)
```

The parentheses fix is present in the current code. However, there's a subtler issue:

```303:313:GhostSpiral
    for a in subs:
        others = [b for b in subs if b != a]
        max_k = len(others)
        k = min((_secrets.randbelow(3) + 1) * args.deep, max_k)
        k = max(k, 1)
        chosen = []
        pool = list(others)
        for _ in range(k):
            idx = _secrets.randbelow(len(pool))
            chosen.append(pool.pop(idx))
        dag[a] = chosen
```

`_secrets.randbelow(3)` returns 0, 1, or 2. So `(_secrets.randbelow(3) + 1)` is 1, 2, or 3. With `args.deep=2`, `k` is 2, 4, or 6. This creates a non-uniform distribution of edge counts. This isn't a bug per se, but the mixing quality depends heavily on the DAG topology, and a 1/3 chance of only 2 edges vs 6 edges creates identifiable patterns.

---

### Finding 11i: Success Messages That Don't Prove Actions Happened

| Script | Message | What it proves |
|--------|---------|----------------|
| GhostSpiral:167 | `"JM_tumble_OK"` in integrity log | tumble.py returned exit code 0. Does NOT prove any BTC was tumbled. |
| GhostSpiral:293 | `"swap_deposits_generated"` in integrity log | API returned JSON. Does NOT prove any BTC was sent or XMR received. |
| GhostSpiral:439 | `"signer_ok"` in integrity log | subprocess exited 0. Does NOT verify any blobs were actually created or valid. |
| GhostSpiral:461 | `"broadcast_ok"` in integrity log | subprocess exited 0. Does NOT verify any TXs confirmed on-chain. |
| broadcast:56 | `"fee_bump_ok"` in integrity log | A file was read back. Does NOT verify the fee was actually increased. |
| broadcast:276 | `"TX {idx} -> mempool"` printed to terminal | Daemon returned status "OK". Does NOT mean the TX will confirm. |
| airgap:229 | `"done:signed={signed_count}"` | Loop completed. Does NOT verify blob contents are valid signed transactions. |

---

### Finding 11j: `renamethis1` — 2400-Line Security Hazard

This file is a concatenated chat log containing multiple versions of a surveillance/recon tool (`targ_graber_v13`, `collect_and_grab_v17`). It contains:
- Hardcoded patterns for scraping LinkedIn, Twitter, Reddit
- GPT API key handling
- Multiple `import random` usages for security-critical randomness
- Cleartext references to operational security concepts
- Syntax errors mixed with chat responses

It is not executable (contains chat text interleaved with code), but its mere presence on disk is a forensic goldmine linking the operator to the GhostSpiral toolchain and its capabilities.

`paranoia_mode` does NOT clean up `renamethis1` — it's not matched by any of the file patterns in `wipe_gs_artifacts()`.

---

## Summary Table

| # | Finding | Severity | Operator Deceived? | Currently Exploitable? |
|---|---------|----------|-------------------|----------------------|
| 1 | `--split` flag does nothing | CRITICAL | Yes | Yes — false mixing |
| 2 | JoinMarket returns empty, logs OK | CRITICAL | Yes | Yes — BTC stranded |
| 3 | ThorChain "swap" is quote-only + dead code | CRITICAL | Partially | Yes — no swap occurs |
| 4 | `--batch-file` is not a real CLI flag | CRITICAL | Yes (on crash) | Yes — signer broken |
| 5 | `sign_transfer` / fee bump is fabricated | HIGH | Yes | Yes — silent failure |
| 6 | Fee oracle fields don't exist | MEDIUM | Partially | Yes — always fallback |
| 7 | CoinGecko rate limit via Tor | MEDIUM | Yes | Likely — flaky prices |
| 8 | DNS "leak check" proves leaks WORK | CRITICAL | Yes | Yes — false confidence |
| 9 | `resource_check` imported, never called | LOW | No | No — cosmetic |
| 10 | `random` imported in GhostSpiral (unused) | LOW | No | Latent risk |
| 10 | `random.SystemRandom()` in paranoia_mode | NONE | No | Safe (CSPRNG) |
| 11a | `acct` undefined in create_receive_wallet | HIGH | Yes (crash) | Yes — always crashes |
| 11b | `--suppress-kyc` is display-only | MEDIUM | Yes | Yes — false safety |
| 11c | Bisq/Haveno API endpoints are invented | MEDIUM | Partially | Yes — always fails |
| 11d | ThorSwap aggregator ≠ ThorChain native | HIGH | Yes | Yes — OPSEC leak |
| 11e | Stage 5 hardcodes `offline.wallet` | MEDIUM | Yes (on crash) | Yes — always fails |
| 11f | `dns_check` runs even in dry-run | LOW-MEDIUM | Yes | Yes — DNS leak |
| 11g | Integrity log recreated after wipe | MEDIUM | Yes | Yes — forensic trace |
| 11h | DAG edge distribution non-uniform | LOW | No | Pattern analysis |
| 11i | Success messages don't verify outcomes | HIGH | Yes | Yes — false confidence |
| 11j | `renamethis1` not cleaned by paranoia | MEDIUM | Yes | Yes — forensic trace |
