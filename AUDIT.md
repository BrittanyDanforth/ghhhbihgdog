# GhostSpiral Toolchain — Full Codebase Audit

> Generated: 2026-04-12
> Scope: Every file in the repository root (8 scripts, 0 config files)

---

## Table of Contents

1. [Repository-Wide Issues](#1-repository-wide-issues)
2. [GhostSpiral (core)](#2-ghostspiral-core)
3. [create_receive_wallet](#3-create_receive_wallet)
4. [airgap_tx_signer](#4-airgap_tx_signer)
5. [broadcast_signed_xmr](#5-broadcast_signed_xmr)
6. [thor_swap_preparer](#6-thor_swap_preparer)
7. [exit_strategy_simulator](#7-exit_strategy_simulator)
8. [paranoia_mode](#8-paranoia_mode)
9. [renamethis1](#9-renamethis1)

---

## 1. Repository-Wide Issues

### 1.1 FATAL: Every file has junk title text before shebang (SyntaxError on run)

Every single script starts with a plaintext title line BEFORE the `#!/usr/bin/env python3` shebang. Python will crash on line 1 with `SyntaxError` when any file is executed.

| File                     | Line 1 content                   |
|--------------------------|----------------------------------|
| `GhostSpiral`            | `GHOST SPIRVAL V10.5`            |
| `create_receive_wallet`  | `create receive wallet`          |
| `airgap_tx_signer`       | `airgap tx signer`               |
| `broadcast_signed_xmr`   | `BROADCAST SIGNED XMR V10`       |
| `thor_swap_preparer`     | `thor swap preparer`             |
| `exit_strategy_simulator`| `exit_strategy_simulator.py`     |
| `paranoia_mode`          | `ALL TOGETHER` + `GHOST SPIRAL V10 ULTRA MIXER` |

**Fix:** Remove all lines before the shebang in every file.

### 1.2 No `.py` extensions on any script

All scripts are saved without `.py` extensions, but `GhostSpiral` Stage 5 calls them with `.py`:
- `subprocess.run(["python3","airgap_tx_signer.py", ...])`
- `subprocess.run(["python3","broadcast_signed_xmr.py", ...])`
- `subprocess.run(["python3","exit_strategy_simulator.py", ...])`

These will all raise `FileNotFoundError`. Either add `.py` extensions or fix the subprocess calls.

### 1.3 No `requirements.txt` / dependency manifest

Imports across the codebase require: `requests`, `tenacity`, `stem`, `monero`, `psutil`, `pyyaml`, `gnupg`. No `requirements.txt` exists.

### 1.4 No README

Zero documentation on how to install, configure, or run the toolchain.

### 1.5 `paranoia_mode` is a mega-bundle, not a standalone script

`paranoia_mode` (1182 lines) concatenates ALL other scripts into one file. It redefines every function, re-imports everything, and has multiple `argparse.ArgumentParser` / `parse_args()` calls. Python will crash because `parse_args()` at line ~134 consumes all CLI args, then later embedded scripts also call `parse_args()` and fail. This file should ONLY contain the paranoia sanitizer (lines 1057-1182), not copies of every other script.

### 1.6 Inconsistent integrity log filenames

- `GhostSpiral` writes to `integrity.log`
- Every other script writes to `integrity_chain.log`
- These are never reconciled — the hash chain is broken across tools.

### 1.7 `resource_ok()` defined but never called

In both `GhostSpiral` and `paranoia_mode`'s GhostSpiral section, `resource_ok()` is defined but never invoked anywhere.

---

## 2. GhostSpiral (core)

### 2.1 FATAL: Title typo before shebang (line 1)
```
GHOST SPIRVAL V10.5
```
"SPIRVAL" is a typo for "SPIRAL". More critically, this line makes the file un-runnable. Shebang is on line 4.

### 2.2 FATAL: subprocess calls reference `.py` files that don't exist (lines 237-241)
```python
subprocess.run(["python3","airgap_tx_signer.py",...])
subprocess.run(["python3","broadcast_signed_xmr.py",...])
subprocess.run(["python3","exit_strategy_simulator.py",...])
```
Files in repo have no `.py` extension.

### 2.3 FATAL: Schema mismatch with airgap_tx_signer
`GhostSpiral` writes: `{"meta": {...}, "txs": [...]}`
`airgap_tx_signer` reads: `plan = json.load(...)` then calls `_validate_plan(plan)` which iterates `plan` as a list.
The signer expects a flat list of TX dicts, but receives `{"meta": ..., "txs": [...]}`. It will fail schema validation because `plan` is a dict, not a list.

### 2.4 FATAL: `connect_rpc()` ignores hostname (line 131-133)
```python
def connect_rpc(url:str):
    port=int(url.rsplit(":",1)[-1])
    return XMRWallet(JSONRPCWallet(port=port))
```
Only extracts port. If `--rpc-primary` or `--rpc-alt` is a remote host (e.g., `http://10.0.0.5:18083`), the connection always goes to `127.0.0.1`. The `host` parameter is never passed to `JSONRPCWallet`.

### 2.5 BUG: `stage1_joinmarket()` always returns `[Decimal("0.0")]` (lines 155-167)
Even after a successful JoinMarket tumble, the function returns `[Decimal("0.0")]` — it never parses actual UTXO output.

### 2.6 BUG: `stage1_joinmarket()` and `stage2_thor_swap()` are defined but never called
These functions exist but are never invoked in the main flow. The pipeline jumps from CLI parsing straight to Stage 3 (wallet/DAG build).

### 2.7 BUG: `stage2_thor_swap()` uses sleep-mock instead of actual chain monitoring (line 185)
```python
time.sleep(random.randint(5,10))
```
No actual mempool/ThorChain monitoring.

### 2.8 BUG: `stage2_thor_swap()` crashes if `deposit` is `None` (line 181)
`deposit` could be `None`, then `deposit[:12]` and `f"Send ... → {deposit}"` would show `None`.

### 2.9 BUG: DAG `random.sample` can crash with `ValueError` (line 202)
```python
dag={a:random.sample([b for b in subs if b!=a], k=random.randint(1,3)*args.deep) for a in subs}
```
If `k` exceeds the population size (len(subs)-1), `random.sample` raises `ValueError`. With `--wallets 2 --deep 3`, k could be up to 9 but population is only 5 (2 wallets + 4 decoys - 1 = 5).

### 2.10 BUG: `FEE_XMR` computed but never used (line 127)
`FEE_XMR = fetch_fee(proxy)` — the result is assigned but never referenced in amount calculations.

### 2.11 BUG: `xmr_balance()` ignores the `addr` parameter (line 209-211)
```python
def xmr_balance(addr:str)->Decimal:
    res=rpc_primary.raw_request("get_balance",{"account_index":0,"address_indices":[]})
```
The `addr` argument is never used. It always fetches account 0 balance regardless.

### 2.12 WARN: Mock balance fallback (line 214-215)
```python
if bal<=0:
    bal=Decimal("10.0")  # mock balance for dry demonstration
```
Production code should not silently substitute fake balances.

### 2.13 WARN: File handles never closed in `_log()` (line 63)
```python
INTF.open("a").write(...)
```
File opened but never explicitly closed. Should use `with` statement.

### 2.14 WARN: `safe_get`/`safe_post` don't check HTTP status (lines 69-74)
`.json()` is called without checking `response.status_code`. A 404/500 HTML response will raise `JSONDecodeError` with no useful context.

### 2.15 WARN: `BLOCK_API` list defined but never used (lines 43-46)

### 2.16 WARN: `DUST_XMR` and `BASE_FEE_XMR` defined but never used (lines 39-40)

---

## 3. create_receive_wallet

### 3.1 FATAL: Title text before shebang (line 1)
```
create receive wallet
```
Makes file un-runnable.

### 3.2 BUG: `_dial_rpc()` ignores hostname (line 68-69)
```python
def _dial_rpc(url: str):
    return Wallet(JSONRPCWallet(port=int(url.split(":")[-1])))
```
Same as GhostSpiral — only port extracted, host always defaults to 127.0.0.1.

### 3.3 BUG: `subaddr.view_key()` likely wrong API (line 116)
Monero subaddresses from `monero-python` don't have a `view_key()` method. The wallet has `view_key()`, not individual subaddresses. This will raise `AttributeError`.

### 3.4 BUG: `subaddr.index` may not exist (line 118)
`new_subaddress()` returns an `Address` object in monero-python, which doesn't have an `.index` attribute by default.

### 3.5 BUG: `_atomic_dump` verify uses unclosed file handle (line 80)
```python
json.load(open(path))
```
Opens file for verification but never closes it.

### 3.6 WARN: `tempfile` imported but never used (line 32)

### 3.7 WARN: `Decimal` imported but never used (line 35)

---

## 4. airgap_tx_signer

### 4.1 FATAL: Title text before shebang (line 1)
```
airgap tx signer
```

### 4.2 FATAL: Expects flat list, receives wrapped dict from GhostSpiral
```python
plan = json.load(open(unsigned_path))
_validate_plan(plan)
```
GhostSpiral outputs `{"meta": {...}, "txs": [...]}`. This code tries to iterate `plan` as a list of TX dicts — will fail with `TypeError` or `KeyError`.

### 4.3 BUG: `subprocess.run()` mixes list args with `shell=True` (lines 98-101)
```python
subprocess.run([
    args.wallet_cli, "--wallet-file", args.wallet_file, "--offline",
    "--command", f"batch < {batch.name}"
], check=True, shell=True)
```
When `shell=True` with a list, the first element is the command and the rest are passed as args to the shell, not the command. This is platform-dependent and unreliable. Also, `batch < {batch.name}` uses shell redirection but the list form won't pass it correctly.

### 4.4 BUG: `_hash_line()` return value assigned to `_` (lines 75, 115, 121)
```python
_ = _hash_line(...)
```
`_hash_line` returns `None`. The `_ =` assignment is harmless but misleading — suggests it returns something useful.

### 4.5 BUG: Temp batch file never cleaned up (line 95-96)
`NamedTemporaryFile("w", delete=False)` creates a file that is never deleted after use.

### 4.6 BUG: `batch.name` used after `with` block closes the file (line 100)
The batch file content may not be flushed when wallet-cli reads it, since `write()` happens in the `with` block but the file isn't explicitly flushed before the subprocess reads it.

### 4.7 WARN: `Dict` imported but never used (line 29)

### 4.8 WARN: Docstring claims `check_tx_key` verification but only does SHA-256 hash (lines 106-108)

---

## 5. broadcast_signed_xmr

### 5.1 FATAL: Title text before shebang (lines 1-2)
```
BROADCAST SIGNED XMR V10

```
Two junk lines before shebang.

### 5.2 BUG: `bump_fee()` uses `os.system()` — fragile, no error capture (line 73)
```python
os.system(f"monero-wallet-cli --wallet-file {wallet_file} --command \"{cmd}\" --offline")
```
No error handling. If wallet_file path has spaces, command breaks. Return code ignored. The function reads the same temp file back expecting it to contain the bumped hex — but `monero-wallet-cli` doesn't write output back to the input file.

### 5.3 BUG: `bump_fee()` temp file leaked from `mkstemp` (line 70)
```python
tmp_in = Path(tempfile.mkstemp(suffix=".hex")[1])
```
`mkstemp` returns `(fd, path)`. The file descriptor `[0]` is never closed, leaking an OS fd.

### 5.4 BUG: Infinite mine-wait loop with no timeout (lines 141-149)
```python
while True:
    q = jpost(...)
    ...
    if not in_pool:
        break
    time.sleep(60)
```
If the TX never confirms (dropped from mempool, etc.), this loops forever. No timeout or max attempts.

### 5.5 BUG: `q["result"]["txs"][0]` — no safety checks (lines 143-144)
If `result` is missing, or `txs` is empty, this raises `KeyError`/`IndexError`.

### 5.6 BUG: Atomic progress write doesn't flush/fsync (line 167)
```python
tmp = progF.with_suffix(".tmp"); json.dump(prog, open(tmp, "w"), indent=2); os.replace(tmp, progF)
```
`open(tmp, "w")` file never flushed or fsynced before rename. Data could be lost on crash. Also, file handle never closed.

### 5.7 BUG: `args.path.endswith(".json")` — `args.path` could be None (line 109)
If no `path` argument provided (though argparse should catch this).

### 5.8 WARN: `newnym()` silently swallows all exceptions (lines 59-64)
```python
except Exception:
    pass
```
No logging at all when NEWNYM fails.

### 5.9 WARN: `jpost`/`jget` don't check HTTP status before `.json()`

---

## 6. thor_swap_preparer

### 6.1 FATAL: Title text before shebang (line 1)
```
thor swap preparer
```

### 6.2 BUG: `_ensure_tor()` not retry-wrapped (lines 63-69)
Unlike every other file's Tor check, this one doesn't use `@retry`. A single transient failure kills the whole process.

### 6.3 BUG: `_atomic_dump` verify uses unclosed file handle (line 100)
```python
json.load(open(path))
```

### 6.4 BUG: `_newnym()` called then `raise` in exception handler (lines 149-150)
```python
except Exception as e:
    _newnym(); raise
```
The `raise` re-raises into tenacity's retry loop, which is correct — but after 4 failures the final raise has no catch, terminating the script without cleanup or useful message.

### 6.5 BUG: Slippage check division direction may be wrong (line 157)
```python
oracle_xmr = (amt / btc_per_xmr) if btc_per_xmr else Decimal("0")
```
`amt` is in BTC. `btc_per_xmr` is how many BTC per 1 XMR. So `amt / btc_per_xmr` gives XMR equivalent — this is correct. But the fallback `Decimal("0.000015")` for `btc_per_xmr` is labeled "~1 XMR = 0.000015 BTC" which is wildly inaccurate (real rate ~0.003). This placeholder would cause massive slippage false alarms.

### 6.6 BUG: `from monero.address import address as _xmr_addr, Address` (line 37)
`_xmr_addr` is imported but never used.

### 6.7 WARN: `tempfile` imported but never used (line 30)

---

## 7. exit_strategy_simulator

### 7.1 FATAL: Title text + blank lines before shebang (lines 1-4)
```
exit_strategy_simulator.py



```

### 7.2 BUG: Dynamic key in output dict (line 164)
```python
f"amount_out_{args.currency}": str(fiat_val),
```
This creates keys like `amount_out_usd` or `amount_out_eur`. Downstream consumers must handle variable key names, which is fragile. Should be a fixed key with currency as a separate field.

### 7.3 WARN: `localmonero` method listed but LocalMonero shut down in 2024

### 7.4 WARN: No `--dry-run` or safety mode — always writes files

---

## 8. paranoia_mode

### 8.1 FATAL: This file is a concatenation of ALL scripts, not a standalone tool

Lines 1-211: Full copy of GhostSpiral v10.0 (with `parse_args()` call)
Lines 215-340: Full copy of create_receive_wallet (with `__main__` block)
Lines 349-531: Full copy of thor_swap_preparer (with `__main__` block)
Lines 547-671: Full copy of airgap_tx_signer (with `parse_args()` call)
Lines 679-847: Full copy of broadcast_signed_xmr (with `parse_args()` call)
Lines 858-1046: Full copy of exit_strategy_simulator (with `__main__` block)
Lines 1057-1182: Actual paranoia_mode sanitizer

Running `python3 paranoia_mode --dry-run` will:
1. Hit `GHOST SPIRAL V10 ULTRA MIXER` on line 4 → SyntaxError (because `ALL TOGETHER` on line 1 already crashes it)

Even if the title lines were removed, the GhostSpiral section at line 134 calls `args=cli.parse_args()` which steals CLI args and fails (since `--btc-entry` is required). The file is completely un-runnable as-is.

### 8.2 FATAL: GhostSpiral v10.0 section has NO Stage 1 or Stage 2 implementation (lines 168-172)
```python
# ───────────── Stage 1: BTC JoinMarket / direct receive ─────────────
# placeholder: implement full JM wrapper (omitted for brevity)

# ───────────── Stage 2: ThorChain swap wrapper ─────────────
# placeholder; use safe_post with retry + memo validation
```
These are just comments with zero code.

### 8.3 FATAL: Plan amounts are all "AUTO" (line 196)
```python
plan.append({..."amt":"AUTO",...})
```
The `airgap_tx_signer` will fail parsing this — `Decimal("AUTO")` raises `InvalidOperation`.

### 8.4 BUG: `_schema_tag = "audit_v1"` vs standalone uses `"unsigned_v1"` (line 73)
Schema version mismatch means downstream tools may reject the output.

### 8.5 BUG: `dns_check()` expects `example.com` to resolve to `127.0.0.1` (lines 1096-1100)
```python
res = socket.getaddrinfo(CHECK_HOST, 80)[0][4][0]
if res != "127.0.0.1":
    raise RuntimeError(f"DNS leak: {res} (expected 127.0.0.1)")
```
`example.com` resolves to `93.184.216.34` on any normal system. This check will ALWAYS fail and abort the script unless DNS is explicitly redirected through Tor, which is not documented.

### 8.6 BUG: `rand_mac()` can generate invalid MACs (line 1108)
```python
return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
```
First byte could have the multicast bit set (odd first byte) or be all zeros. Should force unicast + locally-administered bits.

### 8.7 BUG: `wipe_swap_ram()` writes 1GB of zeros to /dev/shm (line 1149)
```python
subprocess.run(["dd", "if=/dev/zero", "of=/dev/shm", "bs=1M", "count=1000"], check=True)
```
`/dev/shm` is a tmpfs mount point (directory), not a file. `dd` to a directory path fails. Should target a file within `/dev/shm/` or use different approach.

### 8.8 BUG: `import yaml` but yaml only used in paranoia_mode's GhostSpiral header, never in the actual sanitizer (line 49)

---

## 9. renamethis1

### 9.1 FATAL: Not a valid Python script
This is a ~2400-line file that mixes:
- Chat/conversation prose
- Multiple distinct Python scripts concatenated together
- Lines like `wipe_exit(0)  say emhancements` (junk tokens)
- Markdown table fragments embedded mid-script
- References to non-existent scripts: `targ_graber_v13.py`, `targ_graber_v14.py`

This file has no clear purpose in the current repo and cannot be executed.

---

## Summary of Severity

### FATAL (prevents execution):
- **8 files**: Junk title text before shebang
- **GhostSpiral**: subprocess calls to `.py` files that don't exist
- **GhostSpiral + airgap_tx_signer**: Schema mismatch (dict vs list)
- **paranoia_mode**: All 6 scripts concatenated; multiple parse_args; amounts="AUTO"
- **renamethis1**: Not valid Python at all

### HIGH (wrong behavior at runtime):
- **GhostSpiral**: connect_rpc ignores hostname; stages 1+2 never called; DAG can crash; FEE_XMR unused
- **create_receive_wallet**: RPC ignores host; subaddr API wrong
- **airgap_tx_signer**: shell=True with list args; temp files leaked; batch not flushed
- **broadcast_signed_xmr**: bump_fee broken; infinite mine-wait; progress write not atomic
- **thor_swap_preparer**: Tor check not retry-wrapped; wildly wrong price fallback
- **paranoia_mode**: dns_check always fails; dd to directory; invalid MAC bits

### MEDIUM (code quality / maintainability):
- No requirements.txt
- No README
- Unused imports in multiple files
- Unclosed file handles throughout
- HTTP response status never checked
- Inconsistent integrity log filenames

---

## Fix Plan (one file at a time)

1. **GhostSpiral** — Fix shebang, typo, subprocess paths, schema output, connect_rpc, wire stages, DAG safety, use FEE_XMR, close file handles
2. **create_receive_wallet** — Fix shebang, RPC host, subaddr API, remove unused imports
3. **airgap_tx_signer** — Fix shebang, unwrap schema dict, fix subprocess shell usage, clean up temp files
4. **broadcast_signed_xmr** — Fix shebang, fix bump_fee, add mine-wait timeout, fix atomic writes, fix fd leak
5. **thor_swap_preparer** — Fix shebang, add retry to tor check, fix price fallback, remove unused imports
6. **exit_strategy_simulator** — Fix shebang, fix dynamic key
7. **paranoia_mode** — Strip embedded scripts, keep ONLY the sanitizer section, fix dns_check, MAC gen, dd target
8. **renamethis1** — Needs owner decision (keep/delete/split)
9. **Add** `requirements.txt`
