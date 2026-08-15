# Real-Monero verification (non-mock)

To move past mocked tests, a **real Monero 0.18.3.1 stack** (`monerod`,
`monero-wallet-rpc`, `monero-wallet-cli`, installed via `apt`) was run and the
pipeline's actual RPC calls were issued against it. This records what that
proved and — honestly — what it could not.

## Verified against real monero-wallet-rpc / monerod 0.18.3.1

- **Multi-destination `transfer_split` params are accepted.** The fan-out fix
  sends ONE `transfer_split` with N destinations and `subaddr_indices=[src]`.
  Issued against the real wallet-rpc, both the multi-destination and the
  single-destination (DAG-hop) shapes returned `code -17 "not enough money"` —
  a **funds** error, NOT a schema/parse error. So the destinations array +
  `subaddr_indices` + `account_index` + `priority` + `do_not_relay` +
  `get_tx_hex` structure is structurally valid to real Monero.

- **`submit_transfer` error shape.** A corrupt blob returns a JSON-RPC error
  object `{"code": -40, "message": "Failed to parse signed tx data."}`.
  `broadcast_signed_xmr` now keys on that code (`-40` → permanent `bad_data`,
  needs re-signing) in addition to message heuristics, and still defaults any
  unrecognized error to transient (fail-safe).

- **`get_fee_estimate` really returns a per-priority `fees[]` array.** Real
  output: `fee = 1200000`, `fees = [1200000, 4700000, 19000000, 240000000]`
  (ratios ≈ 1 / 3.9 / 15.8 / **200**). The classic fallback table used **166×**
  at priority 4 — ~17% low. This is direct evidence that `fetch_fee_from_daemon`
  is right to PREFER the daemon's `fees[]` over the multiplier table, and that
  `fees[priority-1]` indexing matches the real array (priority 4 → `fees[3]` →
  240000000).

## Bug found by actually running wallet-cli: sign_transfer stdin protocol

Running real `monero-wallet-cli 0.18.3.1 --command sign_transfer` (no funds
needed — a garbage `unsigned_monero_tx` still exercises the prompt path) proved
my earlier stdin fix was WRONG:

- `sign_transfer` reads the **wallet password from stdin FIRST** (a spend
  re-confirmation, even with `--password` on the CLI), then the "Is this okay?
  (Y/Yes/No)" confirmation.
- Evidence: with an unsigned file present, `input="y\n"` → **"Error: invalid
  password"** (the `y` was consumed as the password); `input="\n"` (empty
  password) → got past it to "Failed to sign transaction".
- So the old `input="y\n"*4` fed `"y"` as the password → **every real sign would
  have failed with "invalid password"**, producing zero signed TXs. Fixed to
  `input=f"{wallet_password}\n" + "y\n"*3`, and verified against real wallet-cli
  for empty AND non-empty passwords (passes the password stage; a wrong first
  line is still rejected).

Also confirmed real: `--password ""` opens the wallet without a hang, and
wallet-cli `--command` **exits 0 even when signing fails** — so `phase_sign` is
right to check for the `signed_monero_tx` output file rather than the return
code, and `--command` ignores stdin lines left over after the command finishes.

## NOT verified — the funded end-to-end round-trip

The full flow (multi-dest `transfer_split` producing a real `unsigned_txset` →
hex→binary → wallet-cli `sign_transfer` → `submit_transfer` → confirm) still
did **not** run, because the wallet could not be funded:

- Regtest is the only way to get modern-fork (RingCT/Bulletproofs) blocks at low
  height for instant mining. But stock `monero-wallet-rpc`/`-cli` cannot be put
  in the `fakechain` nettype (only mainnet/testnet/stagenet flags exist), so the
  wallet rejects the regtest chain with **"Unexpected hard fork version v16 at
  height 1"** and never syncs → balance stays 0 → no real `unsigned_txset` can
  be produced.
- Testnet/stagenet would sync (fork tables match) but need the real P2P network,
  which the environment's HTTPS-only proxy does not carry; an isolated testnet
  mined from genesis sits at pre-RingCT v1 and can't build modern txs.

So these remain unproven and need a proper testnet run with network access or a
`fakechain`-capable wallet build:

- That a real `unsigned_txset` (hex) decodes to a binary `unsigned_monero_tx`
  wallet-cli `sign_transfer` parses, and that its `signed_monero_tx` re-hexes to
  something `submit_transfer` accepts. (The round-trip is reasoned from Monero
  source; the param/format layers are now partly corroborated above, but the
  bytes were never round-tripped.)
- That a multi-dest `transfer_split` SUCCEEDS with funds (only "not enough
  money" — i.e. param acceptance — was observed).
- The confirmation waits and sender-arrival poll against a syncing wallet.
- The exact `submit_transfer` error strings/codes for double-spend and low-fee
  (only the parse-error `-40` and the create-time `-17` were observed).
