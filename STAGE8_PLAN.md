# Stage 8 — the vault's *settings* are sealed to the pair too

Stage 7 sealed what the vault **writes**. This seals most of what it was
**told**, under the same two halves, for the same reason and with the same
boundary.

## 1. What a seized vault still yields after stage 7

`/etc/gs_wake_thinkpad.key` is `0400` and **unsealed by design**: nobody is at
the machine at boot to type a passphrase, so the file that authenticates the
wake note cannot ask for one. Today it holds, in the clear:

| field | what it is to an adversary |
|---|---|
| `btc_account_xpub` | **every deposit address this intake has ever issued or will issue.** Not a record of one job — a key that re-derives the whole address set and finds all of it on the public chain, retrospectively, for as long as the chain exists |
| `btc_electrum` | the operator's own Electrum onion: which server saw every one of those addresses queried |
| `thornode_url` | which node the forwards were quoted and cross-checked against |
| `fee_address`, `fee_sweep_to`, `usage_fee_addresses` | where the operator's cut goes — their own money, and a persistent handle on it |
| `wallet_file`, `fee_wallet_file`, `rpc_daemon` | what is on this disk and where |
| `allow_withdraw`, `allow_btc_forward`, `allow_btc_broadcast` | what this box was permitted to do |
| `account_ceiling`, `daily_wake_budget`, the fee band, `btc_returns_max` | the size and shape of the arrangement |

The xpub is the worst of these by a distance, and it is worse than anything
stage 7 sealed. A ledger names the deposits since the last wipe. **The xpub
names all of them, forever, including the ones whose records were wiped
years ago** — the wipe does not reach the public chain.

## 2. The same property makes the same fix work

Stage 7's §1 measured that nothing in the artifact directory is read before
M2 is opened. The same is true of nearly all of the table above. Measured,
not assumed — every `key[...]` and `key.get(...)` reached before the note is
authenticated:

    load_key   role, delivery_public, deposit_in_chat  (+ the schema)
    run_once   artifact_dir, secret, peer_public, doorbell_url,
               state_half, pair_fingerprint
    preflight  tor_proxy, rpc_primary

That is the whole of it. Everything else in the keyfile is read by
`_run_validated`, `_dispatch` or a child's argv — **after** the Pi has
authenticated a wake.

## 3. The shape

The vault's payload grows one member, `sealed`, holding a container of the
same kind stage 7 writes (`gs_wake_proto.state_seal`, keyed BLAKE2b, NaCl
SecretBox) under a **different schema string** so the two can never be
swapped for one another, and its own salt.

What stays in the clear, and why each one has to:

* `role`, `secret`, `peer_public` — this is the file that authenticates the
  note that carries the other half. It cannot be behind that half.
* `doorbell_url`, `artifact_dir`, `tor_proxy`, `rpc_primary` — read before
  M2. A LAN address, a directory path and two loopback endpoints; a public
  tree already says what they will look like.
* `state_half` — the vault's half itself, exactly as stage 7 documents.
* `pair_fingerprint` — shown on a dry run, so the operator can compare the
  two boxes without waking anything.
* `delivery_public`, `deposit_in_chat` — the delivery MODE. Validated at
  load, printed on a dry run, and a mode the Pi must never be able to change;
  keeping it readable is what keeps the refusal in `load_key` reachable.

Everything else goes inside.

## 4. The two boots that have no half

`--fee-sweep` (the operator at the machine) and the idle-boot sweep (a boot
nobody asked for: a hand power-on, or a stranger's magic packet) run with no
wake note, so they cannot open the seal — and they need `fee_rpc`,
`fee_wallet_file`, `fee_sweep_to`, `fee_address` and the depth.

* `--fee-sweep` takes `--unseal-state <hex>`, the half the operator already
  has beside the LUKS USB. They are standing there; that is the whole
  premise of the flag.

  **As first shipped, that command never swept.** `main()` tested
  `--unseal-state` before `--fee-sweep`, so `--fee-sweep --unseal-state
  <hex>` ran the recovery command instead: every sealed record written out
  in plaintext, and no sweep. Found by STAGE9_PLAN.md §6's re-read; with
  `--fee-sweep` beside it, `--unseal-state` is now the sweep's half.
* **`--fee-sweep-on-idle-boot` is refused at pairing** when the keyfile is
  sealed, naming the trade and the hand command. It is off by default. A
  feature that silently never runs is worse than one that says no while the
  operator is present to hear it.

## 5. Failing closed, and what is genuinely new

A seal that will not open refuses the job — and stage 7 already refuses it,
under the same key, for the same two causes (a re-pairing, or an altered
file). **So stage 8 adds no failure mode that stage 7 did not already
have.** That is the reason it is safe to do at all.

Nor does it add a way to lose money. The one thing a sealed keyfile hides
that an operator might have wanted by hand is the xpub — and the xpub
derives from the seed, which is on the LUKS USB by construction. Recovery is
the stage 7 command, unchanged:

    gs_doorbell state-key --key /etc/gs_wake_pi.key     # on the Pi
    gs_wake_agent --unseal-key --key /etc/gs_wake_...   # prints the settings

## 6. Compatibility

Additive, like stage 7. A keyfile with no `sealed` member is a pairing from
before this stage and runs exactly as it does today. A keyfile that HAS one
and is handed a note with no half is already refused by stage 7's
`state_half_missing`, so there is no new half-upgraded case.

## 7. What this still does not fix, stated

* `/etc/gs-wake-spend.env` — `GS_BTC_SEED`, the wallet passwords, the API
  key. Read by a CHILD process, from the unit's environment, not by the
  agent; sealing it means the agent must inject the variables into the
  child at dispatch instead. That is the next step and it is deliberately
  not this one: the failure mode is worse (a seed nobody can open is a
  client's money, not a client's bookkeeping), so the recovery path in §5
  should be a habit first.
* The Monero wallet file, which is the whole mix graph.
* A vault seized **while a job is running**: the settings are in RAM. One
  job's window, same as stage 7.
* Both boxes with the Pi's passphrase: everything, as before.

## 8. Read again: what `load_key` derived from fields it could not see

`load_key` builds `btc_issued_mark` — where the intake's issued-index mark
lives — from `btc_issued_mark_dir` and the xpub's chain id. From this stage
on **both are sealed**, so at load the mark fell back to its oldest place,
beside the keyfile under `/etc`, which the unit mounts read-only; and "the
clear half wins on a collision" then kept that fallback over the sealed
directory. Under the shipped unit every deposit would have been refused
`btc_issued_unrecorded` — the failure the marks' directory was added to
end — and no check saw it, because the stage-8 fixture's xpub is a
placeholder. `open_keyfile` now derives it again from the merged settings.

The dry run the pairing tells the operator to run saw only the clear half,
so every check that reads a sealed field (the intake, its mark, the fee
wallet) was skipped **without a word**, and `--dry-run --unseal-state <hex>`
ran the record dump instead. `--unseal-state` beside `--dry-run` or
`--fee-sweep` is now that command's half; without one the dry run says what
it could not check.

