# Stage 6: the forward after the send — a stuck forward is found and bumped, and the reconcile is driven

Status: BUILT. Written after an end-to-end read of what stage 5 built,
without trusting its tests; built step by step against this file, each
step validated before the next; section 8 is the self-doubt pass over the
build, whose findings are folded into sections 3.1, 3.3, 3.5 and 3.6 as
"as built".

Stage 5 made the run after a forward a RECONCILIATION: `btc_forwarder
--reconcile` reads the address's history and re-sends kept bytes, re-signs
an evicted forward, forwards money that came back, or fails on a spend that
is not ours. Stage 3's plan (3.4) had promised stage 5 "the BTC-side
tracking (dropped from the mempool, fee bump, reorg) as its own woken probe
over the plan file". Read back against the code, three of the four are
there and the fourth is not -- and the probe that would run any of them is
not driven by anything.

---

## 1. The end-to-end read (what stage 5 left half-wired)

Read: `btc_forwarder` (reconcile, resend, reconcile_emptied, main),
`gs_wake_agent` (the forward branch of `_dispatch`, `_phase_of`,
`_forward_outcome`, `_reconcile_pairs`, `build_argv`), `gs_telegram_pager`
(the intake watch list, `_btc_forward_result`, `btc_tick`, the routing in
`handle()`), `gs_wake_proto` (PHASES, PHASE_LINES), `gs_btc_broadcast`
(`spends_of`, `submit`, `seen`), `tests/real_btc_forward_testnet.py`, and
the stage 3 and 5 plans.

**(a) The reconcile is reachable only after a restart.** STAGE5_PLAN
section 2 says "`forward_to_swap` on a sent handle is it, and the Pi
already routes there". The Pi does not. `handle()` routes an ask about an
intake deposit to the forward only while the handle is NOT in
`_btc_sent_set`, and `_btc_forward_result` puts every handle whose forward
reported `sent` OR `unsure` into that set; `btc_tick` looks only at
`not_seen` and `seen` entries. So after the first send every tap goes to
the XMR side, which answers "nothing on the address yet" for as long as
nothing lands -- and nothing ever asks the forward again unless the pager
restarts (the set is memory) or the operator runs the tool by hand. The
pager's own comment says why it routes that way: "a deposit whose forward
reported sent has nothing more to hear from that job". That is false for
`unsure` (the bytes may never have propagated; stage 5's re-send exists
for exactly this and is never invoked), false for a forward the network
dropped (the evicted re-sign, never invoked), and false for the case
below.

**(b) A fresh forward that is refused after the rotation leaves no plan.**
`main()` rotates the current plan aside (`_rotate_plan`) as soon as
`reconcile()` returns a `forward` verdict (`returned`, `evicted`,
`rejected`), BEFORE the fresh forward runs. Every refusal after that point
-- a fee over the ceiling (`delayed`, which the Pi will retry in an hour),
a quote that fails, a memo that will not fit, a stale quote -- ends the
run with no current plan file. The next reconcile reads `--outfile`, finds
nothing, and refuses `no_plan`; the ledger's `forward_sent` keeps routing
every later run there. The phone hears "it is here, but sending it on did
not go through. Tap below to try again", and the tap gives the same
answer, for ever. A refund arriving on a busy fee day is enough to reach
it. Read at lines 1303-1343 of the forwarder; driven in the build
(section 5).

**(c) No fee bump.** A forward listed in the mempool is answered "our
transaction is listed in the mempool. Nothing to send." however long it
has sat there and however far above its rate the network has moved. Every
input opts into RBF (`gs_btc_tx.SEQUENCE_RBF`, chosen in stage 2 for this
reason) and nothing builds a replacement. Why it is money and not
tidiness: ThorChain's inbound vaults churn on a scale of days, and a
forward that confirms after its vault retired pays an address the chain
may no longer credit; and the memo's limit protects the price only of a
swap that happens. A forward sent at a rate the estimate got wrong, or
overtaken by a fee spike minutes later, is exactly this.

**(d) The phone cannot tell a mined forward from one still waiting.**
`sent` covers both. Once the Pi asks the forward again on a clock (the fix
for (a)), it needs a word to stop on, or every mined forward costs a wake
per window until the XMR side lands.

**What is real:** the listed / re-send / evicted / returned / foreign
paths, driven against the mock server in `test_btc_forwarder` and, for
listed, against a real server over Tor in the testnet drill's act E; the
plan chain and the pairs rewrite summing every forward that moved; the
once-per-outpoint rule on both boxes. Nothing in the send path is a stub
shipped as production. What is missing is the wiring above.

---

## 2. Self-doubt on the design, and the decisions this plan makes

**A bump is a fresh forward over the SAME outpoints at today's rate, not
a surgical fee edit.** There is no change output, so a higher fee comes
out of `send_sat`; a smaller amount needs its own quote (a new memo limit
for the new amount, and the CURRENT inbound address -- churn is half the
reason to bump at all). So the replacement runs the whole stage-2/3 path
that a `returned` forward runs today. What is new: where the inputs come
from (the plan's own list -- an Electrum server's `listunspent` hides an
output a mempool transaction spends, so the stuck transaction's inputs
are not in the look), the rate floor (BIP125: the replacement must pay
more absolute fee than the original by at least the incremental relay
fee; a target rate one above the original's, sized against the same
bound, guarantees it), and the accounting (a replaced plan must not be
counted beside its replacement).

**The Pi asks the forward again on a clock, and stops on a word.** The
routing that sends a `sent` handle to the XMR side stays -- it is right
inside the window -- and past `--btc-recheck` after the send, or at once
after `unsure`, the next ask goes to the forward instead; when nobody
taps, the watcher starts that run itself, once per window, through the
same gates as every wake. The forward answers `forwarded` when its
transaction is mined, and that word ends the rechecks. The ordinary cost
is one extra wake per deposit, hours after the send, buying the certainty
that a forward the network dropped, never propagated, or stopped
confirming is not invisible. When the XMR side reports the arrival first,
no recheck runs.

**Rotation happens when the fresh plan is written, never before.** The
current plan stays the current plan until there is a new one. A chain
already in state (b) is recovered: with no current plan and rotated
predecessors present, the newest predecessor is the plan the reconcile
reads (a kind on the chain says so).

**One new word, no new numbers.** `forwarded` (wire v8), one numberless
sentence. A bump reports `sent` -- the forward went out, again -- and the
phone is never told a fee, a rate, a txid or a count of attempts.

**Bounded.** A bump is attempted only when the transaction has sat for at
least `--bump-after` (keyfile `btc_bump_after_s`, paired with
`--btc-bump-after`, default two hours) AND today's estimate is above the
rate it pays; the replacement is still under the 20% cap and over the
minimum send, else it is `delayed` / `short` exactly as a first forward
is. Fees that keep rising can bump more than once, each a plan in the
chain naming what it replaces, each bounded by the cap.

**Rule 6.** The Pi keeps `sent_at` and the last word in memory with the
rest of the watch entry; the chain gets kinds (`forward_recheck` on the
Pi, `reconcile_bumped`, `plan_recovered` on the vault); the chat gets the
one sentence.

---

## 3. Design

### 3.1 The bump (the forwarder)

`reconcile()`, in the LISTED branch, when `hit["height"] <= 0` (the
mempool) and neither `settled_new` nor `unsettled_new` applies first:

    due = (now - plan["ts"]) >= args.bump_after
          and picture.get("fee_sat_vb") is not None
          and picture["fee_sat_vb"] > plan["feerate_target_sat_vb"]

If `due`: kind `reconcile_bumped`; return
`("forward", sorted(consumed - plan_inputs), "bumped", plan)`. The caller
(`main()`) then:

- adds the plan's inputs to `picture["utxos"]` (deduplicated by outpoint
  against what the look returned; `confirmations` = the greater of
  `--min-conf` and what the plan recorded -- they were settled when they
  were chosen and depth only grows) and to `settled_sat`;
- raises the run's fee floor to the larger of
  `plan["feerate_target_sat_vb"] + 1` and `ceil((old fee + bound) /
  bound)` — with the fee's jitter (the Kerckhoffs pass) the old fee is
  over the bound times the rate, so that is usually the paid rate plus
  TWO; a ceiling of the paid rate plus one refuses the bump
  (`fee_band` then pays at least that; an estimate over the ceiling is
  still `delayed`, and the original stands);
- runs the ordinary forward: quote for the new (smaller) amount, the
  current inbound, THORNode's word on it, sign, submit, seen;
- writes the plan with `reconcile_reason: "bumped"`, `replaces:
  <old txid>`, and rotates the old plan aside AT THAT MOMENT (3.2).

The old and new transactions spend the same outputs; whichever the network
mines swaps once. The next reconcile finds the current (new) plan listed
-> done; or finds the old one mined and the new one's inputs consumed by
it -> the existing "superseded" branch marks the new plan
`superseded_by` the old, and the old counts (its `replaces` is empty).

**As built, after the self-doubt pass (section 8), the bump is more
general than the sketch above:**

- **The whole chain is scanned** (`stuck_forward`), the current plan first
  and the rotated predecessors after it. A forward can fall BEHIND a later
  plan: money came back and was forwarded beside it (`returned`), and the
  fresh plan became the current one; read the current plan alone and the
  stuck one is never seen again. The verdict carries the plan to replace
  as a fourth element and the plans that conflict with it as a fifth.
- **Money that came back rides in the replacement.** When a forward is
  stuck AND new outputs settled, the bump verdict comes first and its
  exclusion list leaves the new outputs in: one transaction, one fee,
  instead of a second forward beside a stuck one.
- **The replacement outbids every earlier signature of ours over its
  outpoints** (`replacement_floor`): a chain can already hold more than
  one (a replacement the server asked does not list beside the original
  it does; an evicted re-sign beside an original that came back), each
  perhaps alive on some node. `bump_floor` is taken over the stuck plan
  and every conflicting plan, each sized over the replacement's own input
  count (a lower bound: more inputs pay more at the same rate), so any
  node takes it and whichever mines swaps once.
- **The window is measured from the newest attempt** over those
  outpoints, so a replacement sent minutes ago that the server has not
  seen yet is not replaced again at once.
- **The replaced outpoints are spent whole**: `with_plan_inputs` marks
  them `must`, and `select_inputs` spends a `must` output whether or not
  it is worth spending at today's rate (it is committed either way, and
  the floor was sized over the same count). Settlement is still required.
- **A superseded plan records where its superseder is**
  (`superseded_height`), so the agent can say `forwarded` for a forward
  whose own txid never mines (3.5).

`submit` of a replacement is the same call as any send; a node with the
original accepts a replacement that pays more (BIP125, and full-RBF is
the default since Core 28); a rejection is `broadcast_rejected` as today,
nothing rotated, the original stands.

### 3.2 The rotation, made safe

`_rotate_plan(args.outfile)` moves from the top of the fresh-forward path
to the line before `write_plan` for a forward with a `reconcile_reason`.
Nothing between the verdict and the write can now leave the chain without
a current plan. `main()` in reconcile mode: when `--outfile` does not
exist and `_plan_chain` has rotated predecessors, the newest is the plan
(`plan_recovered` on the chain, the reason in the log); only with no plan
anywhere is `no_plan` the answer.

### 3.3 The accounting

`_reconcile_pairs._counts`: a plan is counted unless `superseded_by` is
set OR another plan in the set names it in `replaces` and is itself
counted. Two passes: the counted set without the replacement rule, then
the replaced ones removed. So after a bump the replacement counts and the
original does not; if the original mines instead, the new plan is
superseded and the original counts. Never both, never neither.

**As built (section 8): one swap per outpoint, and the record.** An
evicted forward's re-sign and a rejected re-send's fresh forward name
nothing in `replaces`, yet the original's file still says sent and seen
once, and stage 5 summed it beside the plan that carries the money. A
third pass keeps at most one plan per outpoint: the record the
reconciliation named (`superseded_by` on the CURRENT plan, which counts
even under a stale superseded mark on its own rotated file -- rotated
plans are never rewritten), else the newest by `ts`. Plans over different
outpoints (a returned deposit's second swap) still sum.

### 3.4 The wire

`PHASES` gains `forwarded`: a forward's transaction is in a block; the
Pi's rechecks end; the arrival is the XMR side's question. Sentence: "the
forward has confirmed. Nothing more to check on this side — ask again
later for the arrival." WIRE_VERSION 8, changelog only, as 5 and 7 were:
an old Pi refuses a new vault's M3 carrying it, loud.

### 3.5 The agent

- `_phase_of` for a done forward: `moved and seen_height > 0` ->
  `forwarded`; else `sent` / `unsure` as today. As built: also
  `forwarded` when the plan is superseded by another forward of ours and
  `superseded_height > 0` (the record moved, whatever this plan's own
  outcome was); an own-txid `forwarded` still requires `accepted`.
- `build_argv`: `--bump-after` from `btc_bump_after_s`
  (`_btc_setting(key, "btc_bump_after_s", 7200, 600, 7 * 86400)`).
- `gs_wake_keys pair --btc-bump-after SECONDS` (default 7200, floor 600),
  written as `btc_bump_after_s`; validated at pairing like the others.
- The mark block is unchanged: `forward_sent` from `_forward_outcome`,
  `forward_inputs` the union (the same outpoints again), the pairs
  rewrite with 3.3.

### 3.6 The pager

The watch entry keeps the last forward word (`word`) beside `sent_at`.

- `_btc_forward_result`: `sent` -> state `sent`, word `sent`, `sent_at`
  now; `unsure` -> state `sent`, word `unsure`, `sent_at` now;
  `forwarded` -> state `forwarded` (terminal for this side; expires on the
  same clock as `sent`); `delayed` on a `sent` entry -> stays `sent`, a
  `retry_after` (the original stands; the bump is tried again after
  `--btc-fee-retry`); `returned` as today.
- `_btc_recheck_due(h)`: the entry is `sent`, no `retry_after` pending,
  and (word is `unsure`, or `now - sent_at >= btc_recheck_s`).
- `handle()`: an ask on a handle in the sent set goes to the forward when
  the recheck is due; otherwise to the XMR side as today.
- `btc_tick`: a `sent` entry whose recheck is due and has not been started
  this window (`rechecked_at`) starts `forward_to_swap` through
  `_btc_can_start()` and `start_job`, once per window; kind
  `forward_recheck`. The forward's answer refreshes `sent_at` (a new
  window) or ends the rechecks (`forwarded`).
- A `sent` or `forwarded` entry forgotten after `DEPOSIT_PLACE_TTL_S` is
  also dropped from the sent set: an ask about a forward this end no
  longer remembers is the forward's question again.
- `--btc-recheck SECONDS` (default 10800, floor 600); the startup line
  says it must be at least the vault's `--btc-bump-after` to find a bump
  due. `BTC_STATE_WORDS` gains `forwarded: "sent on, confirmed"`.
- As built (section 8): `rechecked_at` -- when this end last STARTED a
  recheck by itself -- is kept across `sent`/`unsure` answers, so the
  automatic path starts one per window whatever word came back; and a
  `sent`/`unsure`/`forwarded` answer about a handle with no entry (a
  restart) creates the entry (no address, the chat, the word, the clock),
  so the window and the automatic recheck apply after a restart too. An
  answer that needs an address to act on (`returned`, `arriving`,
  `not_yet`) forgets such an entry instead of leaving a looked-at state
  with nothing to look at.

### 3.7 Rule 6

The chat: one sentence for `forwarded`; a bump is `sent`. The card: the
kinds above, no number. The Pi's memory: two more fields on an entry it
already forgets after two days.

---

## 4. Build order, each step validated before the next

1. **The wire** (3.4): `forwarded` in PHASES and PHASE_LINES, WIRE_VERSION
   8 with its changelog entry; the pager's BTC_STATE_WORDS. test_wake_protocol,
   test_wake_doorbell (the word carried), test_depo_wizard's banned-word
   scan on the sentence.
2. **The rotation and the recovery** (3.2), with the trap driven first: a
   `returned` forward refused `delayed` after the verdict, then a second
   reconcile -- red before (no_plan), green after. test_btc_forwarder;
   anchors.
3. **The bump** (3.1): due / not due (too young, estimate not above the
   rate, no estimate); the inputs from the plan, deduplicated against the
   look; the floor raised by one; the replacement quoted for the smaller
   amount and sent; `replaces` and the rotated original; a replacement
   `delayed` by the ceiling leaves the original standing and the plan in
   place; a rejected replacement likewise. test_btc_forwarder; anchors.
4. **The agent and the pairing** (3.3, 3.5): `forwarded` from a mined
   plan, `--bump-after` composed from the keyfile, `--btc-bump-after`
   paired and validated, the pairs rewrite never counting a replaced
   plan beside its replacement (and counting the original when the
   replacement is superseded). test_wake_agent, test_wake_endtoend;
   anchors.
5. **The pager** (3.6): the routing on a due recheck, the automatic
   recheck once per window, `forwarded` ending it, `unsure` making it
   due at once, `delayed` on a sent entry holding the original, the sent
   set dropped with a forgotten entry, `--btc-recheck`. test_telegram_pager;
   anchors.
6. **Docs and the drill**: OPSEC_SETUP (the intake's "When it does not go
   to plan": the bump, the recheck, the two windows; the pairing recipe's
   new flag; the pager's flag), BTC_INTAKE_DESIGN (stage 6), SESSION_LOG
   (the stage table), the testnet drill's act F (a reconcile with
   `--bump-after 0` right after the send, while the transaction is still
   in the mempool: the replacement sent and seen, the original plan
   rotated with `replaces`). Then the self-doubt pass, the sweep of every
   new anchor, the full suite, commit.

## 5. Tests that break by design (the ones that must be red before the fix)

- (b): first send accepted and seen; reconcile with a returned settled
  output and a fee over the ceiling -> `delayed`; reconcile again ->
  today `no_plan` (EXIT_REFUSED); after: the same `delayed` again, the
  plan chain intact, or the forward once the fee is inside the band.
- (c): first send accepted, listed at height 0, `ts` two hours old,
  estimate above the paid rate -> today "listed, nothing to send"; after:
  a quote for the smaller amount, a submit of a NEW transaction spending
  the same outpoints at a higher rate, the plan chain of two with the new
  one naming the old in `replaces`.
- (a): a pager entry in `sent` with `sent_at` past the recheck -> today
  the tap goes to `swap_status`; after: `forward_to_swap`. An entry whose
  word is `unsure` -> the forward at once. `btc_tick` with such an entry
  and a free box -> a forward started, once, and not again inside the
  window.
- (d): a plan with `seen_height > 0` -> today `sent`; after `forwarded`;
  the pager on `forwarded` starts nothing more for that handle.
- the accounting: a plan chain [new (replaces old, moved), old (moved)]
  -> the pairs file carries the new plan's figures alone; [new
  (superseded_by old), old] -> the old's alone.

## 6. Mutation anchors to add

- the bump is never due (the `due` test forced False);
- the bump does not raise the floor (the replacement could pay the same
  rate: BIP125 refuses it);
- the plan's inputs are not added to the look (the replacement has
  nothing to spend);
- the rotation happens before the write again;
- a missing current plan is not recovered from the chain;
- a mined forward is still `sent`;
- a replaced plan is counted beside its replacement;
- the recheck is never due; the automatic recheck starts every tick; the
  forgotten entry keeps routing to the XMR side; `forwarded` does not end
  the rechecks.

## 7. Hazards this stage does not close

- A replacement and its original race like an evicted re-sign and its
  original: whichever confirms swaps once (the same money, the same
  destination); the other is invalid the moment it does. Stated in stage
  5; unchanged. With more than two signatures over one outpoint (a second
  replacement priced over both), the same: the pairs file follows the one
  the reconciliation found in the network (3.3).
- A server that will not take replacements answers `rejected`; the
  original stands and the next recheck tries again. The operator's own
  node is the answer, as everywhere.
- The recheck is a wake, and wakes are the scarce thing (twelve a day):
  one per deposit in the ordinary case, one per window while a forward is
  stuck. `--btc-recheck` is the operator's dial. After a `delayed`
  replacement the automatic path waits the LONGER of `--btc-fee-retry`
  and the window; a tap after `--btc-fee-retry` asks sooner.
- Rotated plans are never rewritten: a superseded mark on one can go
  stale (the record rule in 3.3 is the answer for the count; the
  reconciliation reads only the current plan for the verdict).
- A replacement bumps ONE stuck forward per run; a second stuck forward of
  the same deposit over other outpoints waits for the next recheck.
- THORChain's acceptance of the memo, and its treatment of a payment
  that confirms after its vault churned, are proven only on mainnet.

---

## 8. Self-doubt pass (the build read end to end, without its tests)

Read after step 5 was green: `_btc_forward_result`, `btc_tick`, the
routing, `reconcile()` and `main()`'s bump path, `stuck`/`superseded`
paths, `_phase_of`, `_forward_mined`, `_reconcile_pairs`. Six findings,
each fixed with a test that reads red on the old code and an anchor:

1. **A wake a tick.** An `unsure` answer to the automatic recheck popped
   `rechecked_at`, and `unsure` is due at once: a network that kept
   answering ambiguously would have cost a wake every tick until the
   day's budget refused. Now the start stamp survives the answer; the
   automatic path is once per window whatever the word (taps are the
   client's and stay at once).
2. **The gap of 1(a), reopened by a restart.** After a restart the
   forward's `sent` answer was learned into the sent set alone; with no
   entry, `_btc_recheck_due` was never true and every later tap went to
   the XMR side for ever -- the very thing this stage exists to end. The
   answer now recreates the entry (the state, the word, the clock, the
   chat, no address), so the windows apply. `/balance` names it by its
   state word.
3. **A looked-at state with no address.** A `returned`, `arriving` or
   `not_yet` answer on that recovered entry would have put it in `seen`
   or `not_seen` with an empty address: a look that fails silently every
   tick. Such an answer forgets the entry (the tap still asks the forward).
4. **A stuck forward behind a later plan** (forwarder). Only the current
   plan was ever considered for the bump; money that came back and was
   forwarded beside a stuck forward rotated the stuck one out of sight for
   ever. Fixed as 3.1 "as built": the whole chain, the returned money in
   the replacement, the window from the newest attempt, a floor over every
   conflicting signature, the outpoints spent whole (the dust rule would
   have dropped a small input at the higher rate, and the node would have
   refused a replacement priced over fewer inputs).
5. **A superseded plan whose superseder mined never said `forwarded`**:
   `_forward_mined` read the current plan's own height, and a superseded
   plan's own txid never mines -- the Pi would have asked once a window
   for two days about money that had long moved. The reconciliation now
   records `superseded_height`; the agent reads it.
6. **Two forwards counted for one payment** (a stage-5 bug this read
   found): an evicted original and its re-sign, or a rejected re-send and
   its fresh forward, both said "sent, seen once" and both summed into the
   pairs file, so the XMR watcher expected two arrivals of one. One swap
   per outpoint (3.3), the record first.

Also re-read and left alone, with the reason: `bump_due` refuses a plan
without a rate (a reconstructed one) rather than guess; an own-txid
`forwarded` still needs `accepted` (an ambiguous send that mined inside
the seen-wait says `unsure` once and is corrected by the next recheck, one
wake); `delayed` on a sent entry keeps `rechecked_at` (section 7).

---

## Status

- [x] 1. wire — v8, `forwarded`; test_wake_protocol 189, test_wake_doorbell
      165, test_depo_wizard 434, test_plain_slip 238; anchors 528, 532
- [x] 2. rotation and recovery — the trap driven red then green, the
      recovery by moving back, one plan-read site; test_btc_forwarder
      228; anchors 529, 530, 531, 598 (re-pointed)
- [x] 3. the bump — due / not due / mined / too young / at once, the
      inputs from the plan deduplicated, the floor a node takes, the
      replacement quoted for the smaller amount and sent with `replaces`,
      over the ceiling `delayed`, rejected leaves the original;
      test_btc_forwarder 248; anchors 532-538
- [x] 4. agent and pairing — `forwarded` from a mined plan, `--bump-after`
      from the keyfile (validated, never coerced), `--btc-bump-after`
      paired, the pairs rewrite counting a replacement alone; test_wake_agent
      716, test_wake_endtoend 71; anchors 525 (re-pointed), 539-542 (one
      test-side crash on a mutated copy turned red and re-swept)
- [x] 5. pager — the routing on a due recheck, the automatic recheck once
      per window, `forwarded` ending it, `unsure` due at once, `delayed`
      on a sent entry holding the original, the sent set dropped with a
      forgotten entry, `--btc-recheck`; test_telegram_pager 748; anchors
      543-548 and the re-pointed 580, 584, 622, 623 (one test-side crash
      on a mutated copy turned red and re-swept)
- [x] 6. docs (OPSEC_SETUP, BTC_INTAKE_DESIGN, SESSION_LOG), the drill's
      act F, the self-doubt pass (section 8: six findings fixed --
      test_telegram_pager 761, test_btc_forwarder 261, test_wake_agent
      721; anchors 549-552, 532-542 re-pointed and new, 546 re-pointed,
      548-551 new; every anchor swept and caught), the full suite, commit
