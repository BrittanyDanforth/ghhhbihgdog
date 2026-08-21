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
python3 tests/test_ipleak.py        # IP-LEAK defences: proxy scheme, empty-dict
                                     # egress guards, localhost spoofing, fail-closed
python3 tests/test_gitignore.py     # ENFORCES .gitignore covers every artifact
                                     # paranoia_mode wipes (OPSEC leak guard)
python3 tests/test_broadcast.py     # relay loop: planned delays, shutdown mid-delay,
                                    #   submit-time hash re-verify, resume/progress
                                    #   migration, manifest trust boundary
python3 tests/test_gapfixes.py      # paranoia_mode MAC-spoof restore + MAC-not-logged,
                                    #   exit_strategy_simulator --redact and its
                                    #   de-simulation (no invented liquidity/slippage)
python3 tests/test_receive_wallet_cli.py
                                    # create_receive_wallet's argument gates (40%
                                    #   covered, the repo's lowest). The gates were
                                    #   already correct -- this locks them in rather
                                    #   than fixing anything
python3 tests/test_opsec_guarantees.py
                                    # GUARANTEES THAT COULD PASS WITHOUT ESTABLISHING
                                    #   THEIR FACT: memo_binds_destination was a
                                    #   SUBSTRING test (a memo paying an attacker while
                                    #   merely mentioning you passed); newnym(required)
                                    #   did not rotate-or-stop; the artifact wipe
                                    #   RESURRECTED the chain it had destroyed; the
                                    #   broadcast's per-submit egress check was a timer;
                                    #   the signer staged the wallet password on disk
python3 tests/test_console_exit.py   # the CONSOLE's exit wiring, over REAL HTTP:
                                    #   token/origin/content-type gates, the arm
                                    #   phrase, server-side OPSEC preflight, and that
                                    #   collect() actually SENDS the field (a form can
                                    #   look complete and never post the parameter)
python3 tests/test_exit_withdraw.py  # THE EXIT: --exit-to actually spends the mixed
                                    #   funds off the wallet, ONE TRANSACTION PER
                                    #   OUTPUT (never a collecting sweep), to
                                    #   validated destinations. Stage 5d used to run
                                    #   a price valuation and move nothing
python3 tests/test_signer_schema.py # LAST GATE BEFORE MONEY MOVES: airgap_tx_signer's
                                    #   plan validator against malformed plans. Coverage
                                    #   put the signer at 57% with 45 abort lines never
                                    #   executed; driving them found that an INFINITE
                                    #   amount was accepted (Decimal("Infinity") <= 0
                                    #   is False, so it passed the positivity test)
python3 tests/test_swap_receive.py  # MONEY PATH: the swap memo must name your own
                                    #   XMR address, catastrophic slippage must
                                    #   abort, and the receive subaddress must be
                                    #   confirmed by the wallet itself
python3 tests/test_receive_watch.py # RECEIVE: the payment watcher — right
                                    #   subaddress, confirm/unlock gate, swap
                                    #   shortfall vs still-confirming, and that
                                    #   it asks NO block explorer anything
python3 tests/test_opsec_doc.py     # OPSEC_SETUP.md's promises about this code,
                                    #   asserted against the real source: loopback
                                    #   bind, fail-closed Tor, 0600 slips, the
                                    #   view-only path never spends, no Telegram
python3 tests/test_console.py       # gs_console: wallet-password scope, no
                                    #   invented fee numbers, preflight egress
                                    #   rule, HTTP gates over a real socket
python3 tests/test_peel_pipeline.py # THE PEEL CHAIN, THE DAG ROUND AND THE
                                    #   EXIT, driven through the REAL main()
                                    #   against a wallet that MOVES MONEY.
                                    #   test_split_pipeline drives the FAN-OUT
                                    #   and never reaches the exit; nothing
                                    #   ran a --peel run past the planner. It
                                    #   found that a chain stopping part-way
                                    #   leaves EVERYTHING on one carrier (each
                                    #   peel consumes its carrier exactly and
                                    #   pays the rest forward) and the exit
                                    #   swept that -- 9.62 of 12 XMR, unmixed,
                                    #   to --exit-to -- then printed "EXIT
                                    #   COMPLETE"

python3 tests/real_roundtrip_testnet.py  # FULL cold-signing round-trip vs real
                                          # monero binaries (SKIPs if not installed)
python3 tests/real_flags_testnet.py      # real fee-priority 1-4 + multi-dest
                                          # fan-out + password-protected signing
python3 tests/real_dag_subaddr_testnet.py # on-chain proof subaddr_indices
                                          # restricts a hop to ONE subaddress
python3 tests/real_phase_sign_testnet.py # calls the SHIPPED phase_sign() and
                                          # relays its output to a real daemon
python3 tests/leak_audit_testnet.py    # RUNS all 3 stages, audits everything
                                          # they leave on disk (perms + secrets)
python3 tests/real_phase_create_testnet.py # SHIPPED phase_create -> phase_sign
                                          # chain vs a REAL wallet-rpc
python3 tests/real_broadcast_testnet.py   # calls the SHIPPED broadcast main():
                                          #   a real daemon witnesses that a shutdown
                                          #   mid-delay and a swapped blob relay
                                          #   NOTHING, and that --resume then relays
                                          #   a tx that confirms on-chain
python3 tests/real_send_testnet.py       # SHIPPED jittered fan-out send: cold-signs a
                                          #   1->N fan-out with UNEQUAL amounts and
                                          #   confirms each subaddress got its exact
                                          #   planned amount on-chain
python3 tests/real_spend_account_testnet.py # SEND spends from the ROTATED account:
                                          #   proves the mix account owns ENTRY, that
                                          #   account 0 at that index is a DIFFERENT
                                          #   address, and by conservation of value
                                          #   that nothing reaches the wallet PRIMARY
python3 tests/real_hop_sweep_testnet.py  # DAG hops are SWEEPS: drives the SHIPPED
                                          #   phase_create/phase_sign on a view-only
                                          #   wallet and proves a cold-signed hop
                                          #   returns ZERO change to the account
python3 tests/real_fanout_change_testnet.py # WHERE the fan-out's change lands: proves
                                          #   monerod returns change to the SPENDING
                                          #   ACCOUNT's subaddr 0, so a rotated mix
                                          #   account keeps it off the wallet PRIMARY
python3 tests/real_peel_testnet.py       # SHIPPED peeling chain: N destinations via N
                                          #   SEPARATE confirmation-gated txs (not one
                                          #   fan-out), change carrying between peels
python3 tests/real_delay_pipeline_testnet.py # DOES A PLANNED DELAY REACH THE WIRE?
                                          #   plan -> SHIPPED phase_create ->
                                          #   phase_sign -> broadcast main(), two TXs
                                          #   with DIFFERENT delays, proving each one
                                          #   is served before its own submit. Negative
                                          #   control: strip them and the "minimal gap"
                                          #   warning must fire. real_broadcast_testnet
                                          #   patches the delay into the signed manifest
                                          #   by hand, so it covers only the last link
python3 tests/real_receive_watch_testnet.py # SHIPPED watch loop vs a real wallet-rpc:
                                          #   proves get_subaddress_balance is really
                                          #   PER-SUBADDRESS (account funded heavily,
                                          #   watched subaddress paid 3 XMR -> reports 3)
                                          #   and that locked funds are not "paid" yet
```

`real_delay_pipeline_testnet.py` and `real_phase_create_testnet.py` need the
`monero` package (the others do not).
Installing it can fail on modern setuptools, because its `varint` dependency
still uses `use_2to3`, removed in setuptools 58:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install "setuptools<58" wheel
.venv/bin/pip install monero
.venv/bin/python tests/real_phase_create_testnet.py
```

### Committing an artifact is an OPSEC failure, so it is machine-checked

`paranoia_mode.GS_ARTIFACT_FILE_PATTERNS` / `GS_ARTIFACT_DIR_PATTERNS` list what
this toolchain treats as sensitive enough to securely delete — deposit
addresses, memos, XMR destinations, txids, per-run traces. Anything on that
list must never reach a commit, so `test_gitignore.py` asks the real
`git check-ignore` whether a concrete filename built from each pattern is
actually blocked, and fails if not.

This replaced a comment asking the two lists to stay in sync. They had already
drifted once: `.gitignore` matched only DEFAULT filenames, so an operator's
`--outfile thor_pairs_myname.json` or a `signer_progress.json` would have been
committed by `git add -A`. The test is verified to actually fail (exit 1) when
a wipe pattern is added without a matching ignore rule — a green test that
cannot go red proves nothing. It also guards the other direction: no tracked
source file may be shadowed by the widened patterns.

### The leak audit runs the pipeline and watches what it leaves behind

`leak_audit_testnet.py` drives all three shipped stages against real monero
binaries — `phase_create` → `phase_sign` → `broadcast_signed_xmr.main()`, with
the transaction actually relayed — then audits the result from observation
rather than from reasoning:

- what appeared in `/tmp`, `/dev/shm`, `/var/tmp` and `$HOME`, and what survived;
- the permissions of every file **and directory** produced;
- whether any file's *content* contains a real secret (the wallet password,
  spend key, view key and mnemonic are pulled live from the wallet under test,
  so a hit is a genuine leak, not a placeholder match);
- the broadcast progress file, which carries txids and per-TX state.

It found the 0755-directory leak that surface-by-surface review had missed:
files were correctly 0600, but the directories holding them were world-listable,
so any local user could learn how many transactions were signed and when.

**The audit distrusts itself, deliberately.** A clean result is meaningless if
the instruments are blind, and this suite has repeatedly caught checks that
passed only because nothing ran. So:

- *Detector self-test* — each real secret is planted in a canary file and the
  scanner must flag every one before any clean result is trusted.
- *Watch self-test* — a canary is planted in each watched directory and must
  show up in the snapshot diff, proving the watches actually see.
- The `/dev/shm` check was separately verified non-vacuous by observing
  mid-run that the password file really is created there (0600, real content),
  so it passing means "erased", not "never existed".

### Which real tests run the shipped code, and which don't

This distinction matters and is easy to overstate, so it is spelled out:

- `real_phase_sign_testnet.py` **imports `airgap_tx_signer` and calls
  `phase_sign(args, plan)`**. The shipped manifest load, plan-fingerprint check,
  sha256 verify, hex→binary decode, password-first stdin protocol, signed-file
  collection and partial-sign abort are what actually execute; the resulting
  blob is then relayed by a real daemon and confirmed on-chain, and a
  hash-mismatched entry is proven to abort without signing.
- `real_phase_create_testnet.py` **calls the shipped `phase_create` against a
  real `monero-wallet-rpc`**, then hands the manifest *it* wrote to the shipped
  `phase_sign`, and relays the result on-chain. `test_integration.py` already
  drives `phase_create` and `broadcast.main()`, but against a FAKE RPC that
  returns whatever the test supplies — that proves the request SHAPE is built
  right, not that a real daemon accepts it. This closes that gap for both TX
  shapes (single-destination DAG hop and multi-destination fan-out) and proves
  the `phase_create` → `phase_sign` fingerprint/hash handoff works unmocked.
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
