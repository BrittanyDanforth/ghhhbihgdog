# Real-Monero verification (non-mock)

A **real Monero 0.18.3.1 stack** (`monerod`, `monero-wallet-rpc`,
`monero-wallet-cli`, installed via `apt`) was run and the pipeline's actual
logic was exercised against it — including a **full end-to-end cold-signing
round-trip**.

## ✅ END-TO-END COLD-SIGNING ROUND-TRIP — VERIFIED

`tests/real_roundtrip_testnet.py` runs the whole flow against real binaries and
passes (`>>> REAL COLD-SIGNING ROUND-TRIP: SUCCESS`):

1. Fund a full wallet by mining on an **isolated testnet** (see "how the wall was
   beaten" below).
2. Create a **view-only** wallet; `transfer_split(do_not_relay)` → a real
   `unsigned_txset` (hex).
3. **phase_sign's exact logic**: `bytes.fromhex(unsigned_txset)` →
   `unsigned_monero_tx`; `monero-wallet-cli sign_transfer` with the
   **password-first stdin** → `signed_monero_tx`. The real prompt
   `"…Is this okay?  (Y/Yes/N/No):"` was answered and the CLI reported
   `"Transaction successfully signed to file signed_monero_tx"`.
4. **broadcast's exact logic**: `signed_bytes.hex()` → `submit_transfer` →
   `tx_hash_list` returned (relayed).
5. Mine one block → the tx is on-chain (`in_pool: False`).

This directly verifies, no mocks, the things previously only reasoned about:

- The **hex↔binary tx-set round-trip** actually round-trips: the RPC's hex
  `unsigned_txset` decodes to a binary file wallet-cli parses, and its binary
  `signed_monero_tx` re-hexes to what `submit_transfer` accepts.
- The **multi-destination / view-only `transfer_split`** produces a usable
  `unsigned_txset`.
- **`submit_transfer` is the correct relay** (returns `tx_hash_list`; the tx
  confirms) — vindicating the switch away from the daemon's `sendrawtransaction`.
- The **`phase_sign` stdin fix on the SUCCESS path**: password-first, then the
  Y/N confirmation, yields a real signed tx.

## Bug found by actually running wallet-cli (now fixed AND round-trip-proven)

`sign_transfer` reads the wallet **password from stdin first** (even with
`--password` on the CLI), then the Y/N confirmation. The old `input="y\n"*4` fed
`"y"` as the password → **every real sign would have failed with "invalid
password"** (zero signed TXs). Proof: with an unsigned file present, `"y\n"` →
`"Error: invalid password"`; `"\n"` (empty pw) → got past it. Fixed to
`input=f"{wallet_password}\n" + "y\n"*3`, verified for empty and non-empty
passwords, and then confirmed on the full success path by the round-trip above.

Also confirmed real: `--password ""` opens without a hang; wallet-cli
`--command` **exits 0 even when signing fails** (so checking for the
`signed_monero_tx` output file, which `phase_sign` does, is the right success
signal, not the return code); the airgapped invocation (no `--offline`, no
daemon) reaches the sign stage in ~4s without hanging.

## Other real, non-mock corroborations (drove fixes)

- **Multi-dest `transfer_split` params accepted** — before funding, both
  multi- and single-dest returned `-17 "not enough money"` (a funds error, not
  a schema error). The fan-out shape is valid to real wallet-rpc.
- **`submit_transfer` error shape** — a corrupt blob returns
  `{"code": -40, "message": "Failed to parse signed tx data."}`. `broadcast`
  keys on `-40` (permanent `bad_data`), defaulting unknown errors to transient.
- **`get_fee_estimate` per-priority `fees[]`** — real:
  `[1200000, 4700000, 19000000, 240000000]` (priority-4 ≈ **200×**, not the
  classic 166×). Confirms `fetch_fee_from_daemon` is right to prefer `fees[]`
  and that `fees[priority-1]` indexes correctly.

## How the funding wall was beaten

The obvious route (regtest / `fakechain`, the only nettype with modern forks at
low height) is blocked: stock wallet binaries have no `fakechain` nettype flag,
so they reject the regtest chain with "Unexpected hard fork version v16 at
height 1" and never sync. A private **mainnet** chain is blocked differently —
mined blocks fail the hardcoded **checkpoint** at height 1. The way through: an
**isolated testnet** (`monerod --testnet --offline --fixed-difficulty 1`) has
**no** height-1 checkpoint (mines instantly) AND its wallet fork-table matches
(syncs cleanly), so a wallet can be funded and spent. That's what the round-trip
test uses.

## Residual gaps (still not covered)

- **Mainnet consensus specifics.** The isolated testnet sits at an early fork
  (small ring size), so mainnet-current rules (ring size 16, current tx weight
  /fee bounds) weren't exercised. The cold-signing *mechanism* the pipeline code
  implements is fork-independent, but a mainnet dry-run before real use is still
  wise.
- **GhostSpiral orchestration end-to-end.** The round-trip drives the RPC/CLI
  flow directly; it does not run GhostSpiral's Stage-4 planning, the
  confirmation waits, or the sender-arrival poll against a live wallet.
- **`submit_transfer` double-spend / low-fee error codes** were not provoked
  (only the parse `-40` and create-time `-17` were observed); that classification
  stays heuristic with a fail-safe transient default.

### Running it

```
apt-get install -y monero          # provides monerod / wallet-rpc / wallet-cli
python3 tests/real_roundtrip_testnet.py   # ~60s; SKIPs cleanly if binaries absent
```
