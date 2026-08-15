# Tests

Executable tests for the pure-Python logic of the GhostSpiral toolchain. They
load the real (extensionless) scripts as modules and exercise the actual
functions — no reimplementations — with the Monero/Tor dependencies mocked.

```
python3 tests/test_units.py         # validation, fingerprint, fee parsing, helpers
python3 tests/test_integration.py   # real phase_create + real broadcast.main()
python3 tests/test_realfns.py       # real fetch_prices + real wipe_gs_artifacts
python3 tests/test_cli_flags.py     # every script: --help, argparse validation,
                                     # required/mutually-exclusive/choice flags,
                                     # pre-network runtime checks
python3 tests/real_roundtrip_testnet.py  # FULL cold-signing round-trip vs real
                                          # monero binaries (SKIPs if not installed)
python3 tests/real_flags_testnet.py      # real fee-priority 1-4 + multi-dest
                                          # fan-out + password-protected signing
python3 tests/real_dag_subaddr_testnet.py # on-chain proof subaddr_indices
                                          # restricts a hop to ONE subaddress
python3 tests/real_phase_sign_testnet.py # calls the SHIPPED phase_sign() and
                                          # relays its output to a real daemon
```

### Which real tests run the shipped code, and which don't

This distinction matters and is easy to overstate, so it is spelled out:

- `real_phase_sign_testnet.py` **imports `airgap_tx_signer` and calls
  `phase_sign(args, plan)`**. The shipped manifest load, plan-fingerprint check,
  sha256 verify, hex→binary decode, password-first stdin protocol, signed-file
  collection and partial-sign abort are what actually execute; the resulting
  blob is then relayed by a real daemon and confirmed on-chain, and a
  hash-mismatched entry is proven to abort without signing.
- `real_roundtrip_testnet.py`, `real_flags_testnet.py` and
  `real_dag_subaddr_testnet.py` **reimplement the RPC/CLI sequence inline**
  rather than importing the scripts. They prove the Monero-side protocol the
  pipeline depends on (hex↔binary tx-sets, `sign_transfer` prompt order,
  `submit_transfer` relay, per-priority fees, `subaddr_indices` isolation) is
  what this code assumes. They do **not** prove the shipped functions are free
  of drift — a copy of the logic cannot catch a regression in the original.
  Treat them as protocol validation, not product validation.

`real_roundtrip_testnet.py` is the non-mock proof: it funds a wallet on an
isolated testnet and runs view-only `transfer_split` → `sign_transfer` →
`submit_transfer` → on-chain confirmation, exercising the pipeline's actual
hex↔binary and stdin logic against real `monerod`/`monero-wallet-rpc`/
`monero-wallet-cli`. See `REAL_MONERO_VERIFICATION.md`. It needs those binaries
(`apt-get install monero`) and SKIPs cleanly when they are absent.

`real_dag_subaddr_testnet.py` is the on-chain proof that per-hop mixing is real:
it funds several subaddresses, spends from exactly one with
`subaddr_indices=[N]`, and confirms on-chain that only that subaddress's balance
moved while the others stayed byte-identical — i.e. the DAG hop cannot silently
pull from co-located funds.

Only `requests` and `tenacity` are needed (both already required). The heavy
deps (`monero`, `stem`, `psutil`) are imported lazily inside functions these
tests don't call, so the modules import fine without them.

## What IS verified (by execution)

- **Plan schema** — `_validate_plan` accepts both the single-destination (DAG
  hop) and multi-destination (fan-out) TX shapes and rejects malformed plans;
  `_compute_plan_fingerprint` is deterministic, format-aware, and tamper-
  sensitive; `_load_unsigned` handles dict and bare-list bundles.
- **Fan-out contract** — `phase_create` (real, fake RPC) emits the fan-out as a
  SINGLE `transfer_split` with N destinations and correct atomic amounts,
  `subaddr_indices`, `account_index`, priority, and `do_not_relay`; DAG hops are
  single-destination. This is the fix for the round-1 single-output abort.
- **Broadcast resume/exit** — `broadcast.main()` (real, fake `_single_post`):
  full success exits 0; a permanent failure exits nonzero; **resuming when the
  only unrelayed blob is permanently failed still exits nonzero** (the
  false-success bug); a transient failure is NOT marked permanent and IS retried
  on `--resume`; key-image rejections are classified permanent.
- **Fee estimate** — `fetch_fee_from_daemon` prefers monerod's per-priority
  `fees[]`, falls back to base×multiplier, then to the constant.
- **Off-ramp rate** — `fetch_prices` Bisq fallback yields `xmr_usd = xmr_btc ×
  btc_usd` (≈300), not the old inverted ≈0.
- **Anti-forensics** — a real (non-dry) `wipe_gs_artifacts` does NOT recreate
  `integrity_chain.log`; dry mode still logs.
- **Misc** — `validate_proxy` (socks5h only), the integrity-log SHA-256 chain
  verifies, `_is_localhost`, `_blob_sort_key`, null-safe route parsing.

## What is NOT verified here (and cannot be without a live Monero stack)

These tests prove the **wiring, contracts, and control flow**. They do NOT and
cannot prove Monero-protocol acceptance, because the RPC is mocked:

- That monero-wallet-rpc actually accepts a multi-destination `transfer_split`
  from a single subaddress and returns a usable `unsigned_txset`.
- That the RPC's hex `unsigned_txset` decodes to a binary file wallet-cli's
  `sign_transfer` parses, and that its `signed_monero_tx` re-hexes to something
  `submit_transfer` accepts. (The hex↔binary round-trip is reasoned from Monero
  source, not observed.)
- That the confirmation waits and the sender-arrival poll behave against a real,
  syncing wallet — no real balance ever changed in these tests.
- The exact error strings monerod/wallet-rpc return: the permanent-vs-transient
  classification is heuristic and defaults to transient (fail-safe), but the
  real phrasings are unconfirmed.

Before trusting this toolchain with real funds, run it end-to-end on **testnet**
with a real monerod + monero-wallet-rpc + monero-wallet-cli.
