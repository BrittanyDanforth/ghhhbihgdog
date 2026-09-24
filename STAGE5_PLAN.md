# Stage 5: what happens when it does not go to plan — failure handling and reconciliation

Status: **BUILT** — planned first, built step by step against sections 3–4,
then read back against the code (section 8: what the plan got wrong, and
the fixes). The status block at the end is the tally. This file is the
whole context for stage 5 of the BTC-intake rework (`BTC_INTAKE_DESIGN.md`;
the earlier stages are `STAGE2_PLAN.md`, `STAGE3_PLAN.md`, `STAGE4_PLAN.md`).

Stages 2–4 built the path that works: a client pays a plain address, the Pi
sees it, the vault signs and sends the forward, the swap lands, the mix
runs. Stage 5 is every place that path can stop with the client's money
sitting somewhere and nobody able to move it — and the promise "you get
back about X", which the forward-time swap does not keep by itself.

---

## 1. The end-to-end read (what is real, what is mocked, what is fake)

Before planning, the whole money path was read again as a stranger would,
without trusting the tests to have covered it: the wizard (`/deposit`),
`start_job`, the doorbell, `_run_validated`/`_dispatch` in BTC mode, the
deposit-time quote, the plain slip, the pager's reply and watcher, the
forward job, `btc_forwarder` top to bottom, `gs_btc_broadcast` top to
bottom, `gs_btc_watch.look`, the phase words, and back to the pager.

**Real.** The signing is embit on the system libsecp256k1 and refuses any
other backend; BIP143 is checked byte for byte against known vectors. The
quote goes to `api.swapkit.dev`, the price cross-check to CoinGecko, the
inbound cross-check to a THORNode the operator names, all over Tor on
separate circuits. The Electrum client, the SOCKS5 framing, the TLS pin,
the broadcast method and the history poll are the shipped code, driven in
the suites through a real transport against an in-process SOCKS5 + TLS
Electrum server (`tests/btcmock.py`) that computes the real txid of the hex
it is handed. Every refusal in the forwarder is reachable and tested.

**Mocked, and said so.** This sandbox has no Tor and no egress, so nothing
in it has ever touched a network. `tests/real_btc_forward_testnet.py`
drives the shipped forwarder over real Tor against real testnet on a box
that has both, with ONLY the quote stubbed, and its header says what that
leaves unproven: that THORChain accepts the memo. There is no testnet
THORChain and no testnet XMR quote; only mainnet, with money, proves the
swap starts. That statement stays true at the end of stage 5; the plan
below adds nothing that pretends otherwise.

**Nothing fake found**, in the sense of a stub shipped as production, a
guard that cannot fire, a switch with no writer, or a sentence promising
what the code does not do — with the exceptions below, which are not fakes
but gaps the working path hides, each found by asking "where does the
client's money sit now, and who can move it?":

1. **A forward that moved money and then died reads as "not yet" for
   ever.** The plan is written AFTER the broadcast. A power cut, the
   deadman, or a crash between the two leaves the outputs spent and no
   plan; the next run's `look` (listunspent only) sees nothing unspent and
   answers `nothing_settled` → `not_yet`. The swap went through and the
   phone hears "nothing on the address yet" indefinitely.
2. **A forward the mempool dropped is stranded behind the once-sent rule.**
   `seen` at height 0 is a mempool listing; a fee spike evicts it, it never
   confirms, the deposit's outputs are unspent again — and the handle is
   `forward_sent`, so every later run is a no-op answering `sent`. The
   signed bytes were kept only while unseen, so there is nothing to re-send
   and no path to re-sign. The client's money sits on the host's address.
3. **A refund lands where nobody looks.** THORChain refunds a swap it will
   not execute (the memo's limit not met, a halted chain, dust) to the
   SENDER: the transaction's input address, which is the host's deposit
   address. After `sent` the Pi has closed its watch entry and the vault
   answers `sent` for ever; the refunded bitcoin sits on the host's address
   with the client told the forward went out.
4. **`unsure` is answered for ever.** An ambiguous broadcast (bytes left,
   no acceptance, not listed in the wait) keeps the hex and reports
   `unsure`; nothing ever asks again whether it was listed, re-sends the
   kept bytes, or re-signs if the outputs are still there.
5. **The XMR side judges the arrival against the wrong quote.** The
   watching jobs read `expected_xmr` from the pairs file the DEPOSIT-time
   quote wrote, for the whole deposit; the real swap was quoted at forward
   time for the deposit minus the fee, at that day's rate. A rate move over
   the 10% tolerance reads as `short` ("UNDER what was quoted... Check
   before going further") about a swap that delivered exactly what it
   quoted. Reconciliation was named in the design and never built.
6. **A fee spike stalls the automatic path for good.** `fee_eats_deposit`
   and `fee_out_of_band` are refusals with no status word, so the pager
   marks the deposit stalled ("did not go through. Tap below to try
   again") and the watcher stops. Fees fall in hours; nothing tries again.
7. **The deposit floor and the fee cap contradict each other at the
   floor.** The vault's floor is `FORWARD_MIN_SAT` plus one input's fee at
   the ceiling rate; the forwarder refuses a fee over 20% of what settled.
   At the floor with fees at the ceiling the fee is ~80% of the deposit:
   the vault accepted a deposit the forwarder can never send at that rate.
8. **The THORNode cross-check is optional even when money moves.**
   `--thornode` may be omitted at pairing; then the forward pays whatever
   the aggregator names, and the one check against a compromised
   aggregator never runs. The design called that "the failure this
   catches"; a switch that can be off is not a catch.
9. **A wiped ledger closes the intake, and can pair a late payer with a
   new client.** `btc_index_exhausted` is permanent for the account (the
   forwarder derives account 0 only, so re-pairing changes nothing), and
   after a wipe an address issued to a client who pays LATE looks fresh to
   the network and can be reissued (STAGE4_PLAN.md section 8).

---

## 2. Self-doubt on the design, and the decisions this plan makes

**"Once sent, never again" was the wrong invariant.** It keyed on the
HANDLE; the thing that must never happen twice is a signature over the
same OUTPOINT. A refund, a client's second payment, an evicted forward —
each puts money on the address that has never been forwarded, and a rule
on the handle strands all of them. The plan chain records the outpoints
each forward spent, and a run may sign only outputs not on that list. The
handle's `forward_sent` stays as the fact "a forward went out", not as a
lock. (As first built the ledger kept a copy, `forward_inputs`; nothing
read it and every entry named a client's transaction, so the host-privacy
pass removed it; the mark block of `_dispatch` in gs_wake_agent says
so.)

**The repeat run is the reconciliation, not a no-op.** Stage 4 turned the
tap after `sent` into a run that answers from the plan. Stage 5 makes that
run LOOK: is our txid listed (mempool or block)? Are the inputs still
unspent? Is there new money on the address? Each answer is one word to the
phone and one action on the vault, listed in 3.1. No new job on the wire:
`forward_to_swap` on a sent handle is it, and the Pi already routes there.

**Words, not numbers, still.** Every new phase word is a closed sentence
with no coin, amount, depth, fee or server in it. The vault knows the
numbers; the phone hears "it is being sent on again" or "the network is
busy; tried again later, by itself".

**The floor is made honest rather than the cap made soft.** The cap (a
fee over 20% of the deposit is refused) protects the client; the floor was
what lied. It becomes the smallest deposit that is forwardable AT THE
CEILING under every rule: `max(FORWARD_MIN_SAT + fee_ceiling,
ceil(fee_ceiling / MAX_FEE_FRACTION))`. That is 0.002 BTC at the shipped
200 sat/vB ceiling and a fifth of it at 40; the ceiling is the operator's
choice and the number is quoted to them at pairing. A lower cap would have
burned the client's money to keep a small number on the wizard.

**Fee spikes are waited out, by the machine.** A fee refusal becomes a
status word (`delayed`); the pager keeps the deposit on its list and tries
the forward again after `--btc-fee-retry` (default one hour), through the
same gates as any wake. No operator, no tap.

**The THORNode cross-check becomes mandatory where money moves.**
`--allow-btc-broadcast` requires `--thornode` at pairing, and the forwarder
refuses `--broadcast` without one. A rehearsal may still run without it.

**The wiped ledger gets one rule: the ledger and the chain agree at
index 0, or the account is retired.** A vault whose ledger knows no index
while address 0 has history refuses every deposit (`ledger_wiped`) and
names the way out: re-pair with `--btc-account N+1`, a fresh chain under
the same seed. The forwarder derives the paired account and still proves
it against the xpub. One rule closes both the exhaustion and the late
payer; the gap search stays for the small case (a pruned record or two).
Records carrying `btc_index` are exempt from the ledger's pruning, so a
quiet month does not fake a wipe.

**Persistence on the Pi stays "none".** After a restart every ask goes to
the forward, which now answers truthfully at every stage (`not_yet`,
`arriving`, `delayed`, `sent`, `returned`, `unsure`); the automatic
sentences resume for a deposit as soon as its forward answers a word the
watcher can act on. Rule 6 keeps the card clean; the vault is the record.

---

## 3. Design

### 3.1 The reconciliation run: `forward_to_swap` on a handle that has a forward

`_dispatch` no longer answers a sent handle from the plan alone. It runs
`btc_forwarder --reconcile` (a third mode, exclusive with the other two)
with the plan's path; the forwarder reads the plan (txid, `tx_hex` when
kept, the inputs it spent, `send_sat`, `expected_xmr`) and asks the
network, on the address's own circuits: the address's HISTORY
(`Broadcaster.history`, read-only) and its unspent outputs (`look`). Then
one of these, in this order, each a status word and an action:

| what the network shows | word | the forwarder does |
|---|---|---|
| our txid listed at height > 0 | `sent` | nothing; writes `{state: confirmed}` beside the plan (depth stays on the vault) |
| our txid listed at height ≤ 0 | `sent` | nothing (still confirming) |
| not listed; inputs still unspent; hex kept | `unsure` → re-sent | `submit` the SAME bytes again; the outcome updates the plan (`resends`), `seen` polled |
| not listed; inputs still unspent; no hex | `returned` | the outputs are money never sent: a FRESH forward of them (new quote, new signature, new plan; the old plan kept as `btc_forward_<handle>.<n>.json`); the chain's outpoints grow |
| not listed; inputs spent by a tx that is not ours | FAILED, no word; kind `forward_foreign_spend` | nothing is signed. Only a leaked key does this; the phone hears "failed", which is true of the machine, and the operator reads the kind at the vault |
| new unspent outputs beyond the forwarded inputs (a refund, or a second payment) | `returned` | a fresh forward of the new outputs only, as above, once they settle to `min_conf` (a refund is a normal payment to the address) |
| the outputs are gone, our txid is in the history, and there is no plan (case 1 of section 1) | `sent` | the history shows our spend; the ledger learns `forward_sent`, the plan is reconstructed from the history (txid, inputs) with `reconstructed: true`. "Our txid" is one in `btc_forward_<h>.signed.json`, written before the bytes were sent -- not a memo naming the destination, which every forward publishes and a seed thief can copy |

The word `moved` is NOT reused: on the wire it means "paid out by a
withdrawal", and a forward that went out is `sent`. `_phase_of` reads the
new `{state}` words: `confirmed` → `sent`; `resent` → `unsure` or `sent`
by the new outcome; `returned` → `returned`. A run that could ask nobody
is a failure, as today.
The once-per-outpoint rule lives in the forwarder, read from the plan
chain, and only there: the ledger's copy this section first planned was
built, read by nothing, and removed (it named every client's transaction
on a disk that unlocks itself). The sweep proves a second signature over a
listed outpoint is refused.

### 3.2 Fee spikes: `delayed`, and the pager tries again

`fee_eats_deposit`, `fee_out_of_band` and `no_fee_estimate` write
`{state: delayed}` before refusing; `_phase_of` maps it to the new word
`delayed` ("the network is busy right now; it is tried again later, by
itself"). The pager, on `delayed` for a watched deposit, keeps the entry
as `seen` with `retry_after = now + --btc-fee-retry` (default 3600 s,
floor 600) and the watcher's tick starts the forward again once the time
has passed and `_btc_can_start()`; said once. The daily wake budget bounds
the retries by construction.

### 3.3 The floor, made honest

`btc_deposit_min_sat(key)` becomes `max(FORWARD_MIN_SAT + fee_ceiling,
-(-fee_ceiling // MAX_FEE_FRACTION))` with `fee_ceiling` the one-input
upper-bound fee at the keyfile's ceiling rate. `gs_wake_keys pair` prints
the resulting floor in BTC next to the ceiling it follows from, so the
operator sets `--deposit-min-sat` on the pager to the same number (or
lowers the ceiling). test_btc_forwarder proves a deposit at the floor is
forwardable at the ceiling under every guard the forwarder has. (Since
the MED pass after the deep read the pairing carries the floor to the
pager's card itself — `deposit_min_sat` in the pairing info, `PAIR_PROTO`
5 — and `--deposit-min-sat` only raises it; the hand-copied flag left a
gap between the wire's floor and the vault's that a deposit fell into.)

### 3.4 The XMR side judges the real swap

When a forward's plan first says the money moved (the mark in
`_dispatch`, and the reconciliation's `moved` for case 1), the agent
rewrites the handle's pairs file — the one `swap_status` and `watch` read
— from the plan: `btc_in` becomes `send_sat` in BTC, `expected_xmr` the
forward-time quote, and a new `forwarded_txid` field is added for the
operator's reading at the machine. The deposit-time quote is kept beside
it as `quoted_at_deposit` so nothing is lost. The watchers then compare
the arrival to what was actually swapped; "short" means short. A fresh
forward after `returned` rewrites again (the newest swap is the one still
in flight). The pairs file never travels; the rewrite is vault-side only.

### 3.5 Pairing and the forwarder's arguments

`--allow-btc-broadcast` requires `--thornode`; `btc_forwarder --broadcast`
and `--reconcile` refuse without `--thornode`. `--btc-account N` (default
0) is written to the keyfile as `btc_account`; the forwarder takes
`GS_BTC_ACCOUNT` from the environment beside the xpub and index and
derives `m/84'/coin'/N'`, still proving it against the xpub the Pi was
handed. `gs_wake_keys pair` refuses an xpub that is not the seed-less
account N (it cannot check the seed, but it prints the account it was
told and the floor of 3.3).

### 3.6 The wiped ledger

`_allocate_btc_index`: when the ledger knows no index at all and address 0
is not fresh, refuse `ledger_wiped` with the re-pair instruction; the gap
search runs only when the ledger knows at least one index. `_save_handles`
never prunes a record carrying `btc_index` (it prunes the rest as today).

### 3.7 The wire

`PHASES` gains `delayed` and `returned`, each with a numberless,
machine-nameless line in `PHASE_LINES`; the doorbell's closed table
accepts them; `WIRE_VERSION` 7 (a changelog entry; no shape change). No
new M3 field, no new job.

### 3.8 The pager

`_btc_forward_result`: `delayed` keeps the entry as `seen` with
`retry_after`; `returned` puts a closed entry back on the list as `seen`
(the forward will report again); `moved` closes it like `sent`. The
watcher starts a retry only after `retry_after` and through the same
gates. `--btc-fee-retry SECONDS` on the command line (default 3600, floor
600). New sentences: "the network is busy right now; it is tried again
later, by itself" and "some of it came back and is being sent on again —
nothing to do", both in the banned-word scan.

### 3.9 Rule 6

Every new sentence goes through `tests/test_depo_wizard.py`'s scan and its
currency ceiling. Nothing new reaches the hash chain but kinds
(`forward_resent`, `forward_returned`, `forward_foreign_spend`,
`forward_delayed`, `ledger_wiped`). The status files beside the plan carry
one word each; the plan chain carries the numbers, 0600, on the vault.

### 3.10 What only a box with Tor can prove

PLANNED here, and NOT what was built (read back in the stage 5 review):
`tests/real_btc_forward_testnet.py` was to drive a broadcast deliberately
sent to a server that will not relay it, then `--reconcile` re-sending,
and a second payment to the address answered `returned` and forwarded on
its own. What it drives is act E, `--reconcile` finding the forward
listed against a real history, and act F, the bump. The re-send, the
evicted re-sign and returned money are NOT driven on a real network; the
script's header says so and tells the operator how to act the last one
by hand (pay address 0 again, run the same argv with `--reconcile`).
Those rows are proven against the in-process server only.
THORChain's acceptance of the memo stays unprovable off mainnet.

---

## 4. Build order, each step validated before the next

1. **The floor and the cap agree** (3.3): `btc_deposit_min_sat`, the
   pairing printout, the forwarder proof. test_wake_agent, test_btc_forwarder.
2. **Pairing** (3.5): `--allow-btc-broadcast` needs `--thornode`;
   `--btc-account`; the forwarder's account derivation and `GS_BTC_ACCOUNT`.
   test_wake_agent (`_pairs_btc`), test_btc_tx, test_btc_forwarder.
3. **The wire** (3.7): two words, two lines, version 7. test_wake_protocol,
   test_wake_doorbell, test_plain_slip's phase checks.
4. **The forwarder's status words on refusal** (3.2's `delayed`) and the
   `moved` detection of section 1 case 1 (history on `not_seen`).
   test_btc_forwarder against the in-process server with history.
5. **`--reconcile`** (3.1): the table, the outpoint rule, the plan chain,
   the re-send of kept bytes, the fresh forward of new outputs. The largest
   step; test_btc_forwarder drives every row against the mock server
   (history and listunspent scenarios), including a foreign spend.
6. **The agent**: `_dispatch` runs the reconciliation instead of answering
   from the plan; the pairs rewrite (3.4);
   `ledger_wiped` and the pruning exemption (3.6); `_phase_of` for the new
   words. test_wake_agent, test_wake_endtoend (a returned deposit forwarded
   again on the real path; a delayed one).
7. **The pager** (3.8): `delayed` with the retry, `returned`, `moved`,
   `--btc-fee-retry`. test_telegram_pager, test_depo_wizard's scans.
8. **Docs**: OPSEC_SETUP (the floor and the ceiling, the retry, what
   `returned` means, `--btc-account`, the testnet acts), BTC_INTAKE_DESIGN
   (stage 5 BUILT, the outpoint invariant), SESSION_LOG.
9. **Anchors** (section 6), the sweep, the full suite, the self-doubt pass
   (a section 8 like stage 4's), commit.

---

## 5. Tests that break by design

- test_wake_agent / test_wake_endtoend: "a sent handle answers from the
  plan with no child" — now a child runs (the reconciliation) and the
  word comes from what the network shows.
- test_btc_forwarder: the floor arithmetic; "exactly one of --dry-run /
  --broadcast" becomes exactly one of three.
- test_wake_protocol / test_wake_doorbell: the closed phase table grows.
- test_telegram_pager: a refused forward no longer always stalls.

---

## 6. Mutation anchors to add

- the outpoint rule: a second signature over a forwarded outpoint;
- the reconciliation re-signs when the hex was kept (should re-send);
- `returned` forwards ALL outputs instead of the new ones;
- a foreign spend is answered `sent`;
- `moved` (case 1) answered `not_yet`;
- `delayed` written without the refusal, or the pager retrying before
  `retry_after`, or retrying without the gates;
- the floor formula drops the cap term;
- pairing accepts `--allow-btc-broadcast` without `--thornode`;
- the pairs rewrite skipped, or rewriting `expected_xmr` from the
  deposit-time quote;
- `ledger_wiped` not refused; a `btc_index` record pruned;
- a new sentence with a banned word.

---

## 7. Hazards this stage does not close

- THORChain's acceptance of the memo is proven only on mainnet with money.
- A leaked seed: the foreign-spend word tells the operator, and nothing
  else can.
- The operator's Electrum servers still see the addresses they are asked
  about; an own node over an onion is the answer, as before.
- The client's money sits on the host's address between arrival and
  forward and again after a refund: custody, stated in the design, is
  narrowed by this stage (the retry, the returned path) and not removed.
- Depth of the forward's confirmation is the vault's knowledge; the phone
  hears `sent` and then the XMR side's words.

---

## 8. Self-doubt after the build (what the plan got wrong, and the fixes)

Read back against the code once every step was green, asking again
"where does the client's money sit now, and who can move it?":

- **The pairs rewrite counted one swap.** 3.4 said "rewritten from the
  plan"; a returned deposit's second forward is a second swap to the same
  destination, so the newest plan alone told the XMR watcher to expect only
  the second output and to call the payment complete when that one landed
  with the first still in flight -- the client invited to withdraw early.
  FIXED: what was sent and what was quoted are summed over the plan and its
  rotated predecessors that moved money and were not superseded; the
  rotated chain is read from the artifact directory on the real mark path.
- **"Moved" was the wrong word for a forward found on chain.** The plan's
  table said `moved` for case 1; on the wire `moved` means "paid out by a
  withdrawal". A forward that went out is `sent`, and that is what the
  reconstructed plan reads as. A foreign spend is a FAILED run with the
  kind, not a word the phone could misread.
- **A rejected re-send was a dead end.** The first design refused
  `broadcast_rejected` when every server refused the kept bytes; those
  bytes are stale (a policy, a fee the network no longer takes) and the
  inputs still ours, so a fresh forward at today's fee follows, the stale
  plan rotated aside.
- **Two source tripwires from stage 3 were rewritten, not removed.** "the
  signed bytes are never read from a file" is now "from ONE file, the
  tool's own plan, schema checked, under --reconcile only, the bytes it
  kept because the network had not shown them"; "submit is called once" is
  "in exactly two places, the second for kept bytes". Both are pinned.
- **The steps 5-6 commit went in with four rotten anchors** because the
  anchor check's exit code did not gate the commit in one shell command;
  step 7 re-pointed them and the sweep ran after. One anchor of step 5
  ('--reconcile decides without the history') SURVIVED its first sweep:
  the mutation left the failure in place. Re-formed to remove it; caught.
- **Not closed, stated:** a forward listed by the server that accepted it
  but not by the one the reconciliation asks would be re-signed as
  "evicted" and race the original (both pay the same inbound with the
  same memo; whichever confirms swaps once; every input opts into RBF). A
  history over MAX_HISTORY (a dust attack) failed the reconciliation until
  the operator acted by hand; since the MED pass after the deep read it is
  read as its newest MAX_HISTORY entries (`history_truncated` on the
  chain), a forward within the window reconciles, and one that fell off
  it fails SAFELY (`history_inconsistent`, nothing signed) -- a flood can
  still delay a deposit, it can no longer jam one for good, and it can
  never make a run report success. A client's own payment replaced away under a
  forward makes the plan's inputs vanish: `history_inconsistent`, FAILED,
  the operator reads the log.

---

## 9. The stages 1–2 pass: the watcher, the builder, the signer, read again

Asked for after this stage landed, because the end-to-end read before it
had found nine gaps the tests missed. `gs_btc_watch.py` (derivation,
scripthash, the SOCKS5 and TLS transport, the framing caps, the Electrum
client, `summarize`/`classify`, the server rotation, the fee-estimate
conversion), `gs_btc_tx.py` (scripts, sizing, building, the account and
key derivation, BIP143 signing and the independent verifier, the backend
gate) and the forwarder's stage-2 guards were read top to bottom with the
question "what would a real server, a real network, a real operator do
here?", not "does a test cover it?".

**Real, and fixed:**

- **The fee floor turned cheap days into the days nothing moved.** An
  estimate under `--feerate-floor` was refused as out of band -- the same
  refusal as an estimate over the ceiling -- and since step 4 that refusal
  is `delayed`, retried every hour for as long as the network stays cheap.
  An operator who raised the floor above 1 (so a forward never sits for
  hours) had every forward on a cheap day wait. Paying MORE than an
  estimate never strands money; the floor now pays the floor, with a kind
  on the chain, and only the ceiling refuses.
- **A wrong-purpose xpub was caught only at forward time.** `derive_receive_address`
  accepts an "xpub"-prefixed key of the right network and depth; a BIP44
  or BIP49 account key carries the same prefix, derives P2WPKH addresses
  just as well, and the seed's m/84' account never matches it -- every
  deposit would settle on an address the forward refuses to sign for.
  The first version of this fix printed the account's first address at
  pairing for the operator to compare against their wallet, and called
  the rehearsal the proof. Re-read with the question "when does the
  forward take the seed?": after something has settled -- so the
  rehearsal proves a mismatch only once a client's money is already on
  the wrong address. That was a half fix. The guard is now on the VAULT,
  the one machine holding both halves: `_prove_btc_seed` derives the
  account from the seed in the agent's environment (account number and
  passphrase included) and proves it against the paired xpub at the first
  `/deposit`, before anything is minted or published; a mismatch, an
  absent seed or invalid words refuse the deposit with the kind on the
  chain and no child run. The pairing-time first address stays as the
  operator's own check; the forwarder's proof stays as the last line.

**Read and found sound** (recorded so the next reader need not re-derive
them): the BTC/kB → sat/vB conversion (×1e5, rounded up, never 0); the
SOCKS5 handshake fails closed on a proxy that will not take the isolation
credential, resolves at the proxy, reads the bound address properly; the
per-address credential is a salted hash of the tag with a constant
password (Tor isolates on the pair); TLS 1.2+ with SNI, unverified, pinned
by SHA-256 when a pin is given, the mismatch ending the look; the line and
session byte caps are checked before the next read; height 0 and -1 are
both "in the mempool", depth is never under 1 for a mined output even when
the tip lags; `summarize` counts each output on its own; the server order
is deterministic per scripthash so no one server sees every address; the
BIP143 script code is the P2PKH form, SIGHASH_ALL, the witness is
[sig, pubkey], the verifier re-derives from scratch; locktime is the tip
height (valid from the next block), every input opts into RBF, one
OP_RETURN, outputs never exceed inputs; the quote payload is byte for byte
the production quote tool's; the memo's destination is read positionally
and exactly, control characters refused, the hex-only binding refused.

**Considered and left:** the dry run prints the signed hex of a real spend
to the job log -- on a disk that already holds the seed, it adds nothing;
a deposit paid in two parts is forwarded as two swaps (waiting for
unconfirmed money would let a 1-satoshi griefing payment stall every
forward); the sizing pays for the policy's largest OP_RETURN rather than
the memo's real size, a few thousand satoshis at the ceiling, stated in
the forwarder.

---

## 10. The doorbell and wizard pass

The same read, over `gs_doorbell` (the keyfile, the one-job state machine,
the handler, the pairing, `run_wake`, the report) and the pager's command
parser, wizard, callbacks, `start_job`, the limits, the poke and its
outcome branches, the worker, the poll loop, the places and `main` -- with
three questions asked of every line: what does a second client see, what
does a hostile allowlisted client do to this, and what reaches the
transcript or the card.

**Real, and fixed:**

- **The payment details were deleted before the client had paid.**
  `--burn-after` (fifteen minutes by default) took the intake's "here is
  how to pay" message with every other, and nothing could show the address
  again: /check answered "not yet" about an address it would not name, a
  fresh /deposit minted a second address with the first still holding its
  place. That message is the one thing in the chat that has not served its
  purpose until the money is on the address. It now outlives the timed burn
  while the watch list has the deposit as `not_seen`, capped an hour inside
  Telegram's delete window so a deposit nobody pays still leaves nothing a
  bot can no longer delete; the moment money is seen the hold ends and the
  next tick takes it. The operator's burn signal ignores the hold. The
  message says so in the welcome's own words.
- **One allowlisted chat could hold the poll loop for everyone.** Every
  message from an allowlisted chat cost a reply over Tor on the one thread
  that reads every chat, and a burn-list entry, with nothing bounding
  either; a client sending a thousand lines held the loop for the better
  part of an hour with every other client's tap queued behind. A chat is
  now answered up to INBOUND_MAX times a minute and silently dropped past
  that (not recorded, not answered, counted once per streak on the chain);
  a tap counts as a message. Strangers were already silent.

**Read and found sound:** the doorbell answers 204 to every refusal so a
prober learns nothing by status code; a record of any length but
RECORD_LEN is refused before the AEAD; eight connections with an
eight-second deadline bound a LAN flood to eight threads; the per-window
nonce makes a captured M1 useless in any later window; the at-most-once
handover and the at-most-one result are under one lock; the plain and
sealed slips are shape-checked and never both; the phase word is a closed
set. On the pager: an unallowlisted chat or sender is never answered; the
sender is checked on a tap as on a message; a label is a MAC over (chat,
handle) so a guessed handle is refused and a wrong one backs off per chat;
a bare handle is accepted only while this process remembers minting it
for that chat; the wizard holds one int and one address list and burns
its own messages the moment it ends; a depth button is only a depth while
a question is asking for one; the confirm sum is one attempt; every wake
goes through `start_job` and its four gates; a chained withdrawal yields
when another chat is waiting; `/status` answers from memory with a per-chat
cooldown; a full card, a dead circuit or a stopped process are each told
to the chat whose job it is and to nobody else's.

**Considered and left:** the daily wake budget and the interval are shared
by every chat, so one client's taps can spend the day for the others --
documented, warned about at start (`--daily-cap` against
`--max-clients`), and the allowlist is the remedy: a client who does that
is a client the operator removes. A client can send dust to their own
address to spend one wake per dust payment on a refused forward, after
which the deposit is parked (`stalled`) and costs nothing more.

---

## Status

- [x] 1. floor and cap — test_btc_tx 101, test_btc_forwarder, test_wake_agent
- [x] 2. pairing, account — test_wake_agent (`_pairs_btc`), test_btc_tx,
      test_btc_forwarder
- [x] 3. wire — v7; test_wake_protocol 189, test_plain_slip 236,
      test_wake_doorbell 161, test_depo_wizard 434
- [x] 4. status words on refusal, the emptied address read —
      test_btc_forwarder, test_btc_broadcast 96
- [x] 5. `--reconcile` — test_btc_forwarder 219 (every row of 3.1)
- [x] 6. agent — test_wake_agent 692, test_wake_endtoend 70
- [x] 7. pager — test_telegram_pager 716
- [x] 8. docs — OPSEC_SETUP (the floor beside the ceiling, "When it does not
      go to plan", the pairing recipe, `--btc-fee-retry`), BTC_INTAKE_DESIGN
      (stage 5 BUILT, the outpoint invariant), SESSION_LOG, the testnet
      script's act E
- [x] 9. anchors (41 for stage 5, 595 total), the sweep (39 caught first
      pass, the two non-verdicts fixed and re-swept), the full suite, this
      section, commit
- [x] 10. the stages 1-2 pass (section 9): the fee floor pays the floor,
      the seed proven against the xpub on the vault before an address is
      issued, the first address at pairing -- 6 anchors (601 total, all
      caught; one test-side crash on a mutated copy turned into a red
      check and re-swept), test_btc_forwarder 221, test_wake_agent 700,
      test_wake_endtoend 71, the full suite
- [x] 11. the doorbell and wizard pass (section 10): the payment details
      outlive the timed burn until paid, a flooding chat is answered with
      silence -- 4 anchors (605 total, all caught; one test-side crash on
      a mutated copy turned red and re-swept), test_telegram_pager 728,
      test_depo_wizard 434, test_opsec_doc 92, the full suite
