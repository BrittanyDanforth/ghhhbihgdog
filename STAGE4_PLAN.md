# Stage 4: the deposit the client actually makes — a plain address, no note

Status: **BUILT** — planned first, built step by step against sections 3–4,
then read back against the code (section 8: what the plan got wrong, and
the fixes). The status block at the end is the tally. This file is the
whole context for stage 4 of the BTC-intake rework (`BTC_INTAKE_DESIGN.md`;
stages 2 and 3 are `STAGE2_PLAN.md` and `STAGE3_PLAN.md`).

Stage 4 is the client-facing half of the rework. Until now every stage has
been vault-side plumbing: a deposit still hands the phone the SHARED inbound
address plus a note the phone cannot attach. After this stage, on a pair
that opts in, `/deposit` hands the phone an amount and a plain, unique
address the host owns; the Pi watches that address; the chat hears
"received" and "confirmed" without anybody asking; and the confirmation
starts the forward by itself. The note, the phone warning and the
"pay from a desktop" sentence disappear from that mode.

---

## 1. What the earlier stages handed over

- `receive_and_quote` mints an XMR receive subaddress (step 0) and quotes the
  swap (step 1, `thor_swap_preparer`, whose pairs file carries the SHARED
  ThorChain inbound as `deposit` and the memo naming the destination). The
  slip -- sealed for a delivery machine, or plain for the chat under the
  vault keyfile's `deposit_in_chat` -- is built from that file.
- `forward_to_swap` (stages 2-3) needs the handle's `bundle` (the XMR
  destination) and `btc_index` (the address the client paid) from the
  ledger; today NO real handle carries `btc_index`, so on a live box the job
  refuses `no_btc_deposit`. Stage 4 mints it.
- `gs_btc_watch` (stage 1) derives an address from an account xpub and looks
  at it over Tor on its own circuit -- and nothing on the Pi imports it yet:
  neither the doorbell nor the pager has a line of BTC wiring.
- `PLAIN_FIELDS` is an EXACT key set `{b, d, m, x, h}` and the doorbell
  refuses any other; `plain_lines` renders no memo line (the note goes as
  its own first message), and the pager's deposit reply sends the note
  first, then the address block, then "tap below or /check ... Then
  /withdraw sends it on".
- The Pi's sealed card carries role, secret, peer_public, pair_fingerprint,
  listen_host, listen_port, target_mac, wol_broadcast, wol_port and nothing
  else, deliberately (gs_doorbell's pairing block: values that mean
  something are removed from a card assumed seizable).
- STAGE2_PLAN's floor: `FORWARD_MIN_SAT` (10,000 sat) is what must REACH
  ThorChain after the fee, so a deposit at the wizard's minimum can never
  be forwarded; stage 4's minimum must be that plus a fee allowance at the
  ceiling rate for a one-input transaction, and must be quoted as such.
- The forwarder (stage 3) refuses `nothing_settled` when nothing is settled
  and writes a plan only on success; a refused forward reports no phase.

---

## 2. Self-doubt on the design's own choices, and where this plan departs

**The xpub does NOT go on the Pi.** `BTC_INTAKE_DESIGN.md` says "Pi keyfile:
the xpub only" and accepts that "a seized Pi learns the addresses it was
watching". That understates it: an xpub is the generator of EVERY address
the host has ever minted and ever will, so a seized card yields the host's
whole intake history on chain, past and future -- the shape of the
arrangement, in one string, on the box assumed seizable. The Pi does not
need it. What the Pi needs is the ADDRESS of each OPEN deposit, and in the
one mode this stage builds (below) that address is already on its way to the
phone in the plain slip. So the Pi watches the addresses it is handed, holds
them in memory, and never holds the generator. A seized Pi learns the
currently open deposits and nothing before or after them.

**This stage builds ONE mode: plaintext, unique address.** BTC intake without
`deposit_in_chat` would hand a phone-only client nothing to pay (the sealed
slip goes to a delivery machine, and the whole point of the rework is that
there is no desktop in the loop). So pairing `--btc-xpub` on the vault
REQUIRES `--deposit-in-chat`, refused at pairing otherwise, and
`seal_slip_for_delivery` returns "" for a BTC-mode record (the delivery
path is the shared-inbound flow this mode replaces). The rule-6 bargain of
the plaintext mode -- an address and an amount in a transcript assumed
readable -- is the operator's, made at the vault, exactly as before.

**Addresses are never reused, and the ledger is not what guarantees it.**
The vault allocates indices sequentially from its ledger, but the ledger is
one of the things `paranoia_mode` wipes; a wiped ledger would restart at
index 0 and hand a new client an address an earlier client paid. So before
an address is issued the vault asks the network, over Tor, whether it has
ANY history (`gs_btc_broadcast.unused`, read-only), and steps past one that
does -- up to a bounded gap -- and refuses outright when nobody could be
asked. An address is issued only when a second party has said it is fresh.

**The Pi persists nothing about open deposits.** Rule 6 forbids an address
on the SD card; a sealed-to-the-card registry was considered and rejected
for this stage (more crypto surface on the seizable box, for a convenience).
The cost is stated: a pager restart forgets the open deposits it was
watching, so the automatic "received / confirmed / sending on" stops for
them. The existing button still works -- it wakes the vault -- and stage 5
may revisit persistence. Meanwhile `/check` on a BTC deposit gets a TRUE
answer (below), not the XMR-side probe. (As built this sentence was false
for a forgotten deposit until section 8's first fix: the button woke the
vault on the XMR-side probe, which cannot move bitcoin.)

**The forward's refusals learn to say what they saw.** A `/check` on a BTC
deposit after a restart, or a tap before the money settled, wakes
`forward_to_swap`; today its `nothing_settled` refusal reaches the phone as
"refused" with no reason. The forwarder now writes a small status file on
those two refusals (`btc_forward_status_<handle>.json`: `not_seen` or
`seen`), and `_phase_of` maps them to the existing words `not_yet` and
`arriving` on the REFUSED status -- the `full` precedent: a refusal that
carries the one word a person can act on. No new phase word, no wire-shape
change.

**The forward may be started by the deposit's own chat.** Stage 2 deferred
"who may start a forward". Decided: the Pi starts it for the chat that owns
the deposit, automatically, once the deposit is confirmed -- and a tap on
"Has it arrived?" for a BTC deposit starts it too (it is the same wake, and
it forwards if settled or answers `not_yet` / `arriving` if not). The vault's
owner wall (the client's own token, or the host's) is unchanged, so no chat
can forward another's deposit. There is no `/forward` command.

---

## 3. Design

### 3.1 The vault: `receive_and_quote` in BTC mode

BTC mode is a property of the vault's keyfile: `btc_account_xpub` set (and,
enforced at pairing, `deposit_in_chat`). In that mode `_dispatch`, when it
records the new handle at step 0:

1. computes `next = max(btc_index over handles) + 1` (0 when none);
2. derives `address = derive_receive_address(xpub, next, network)` and asks
   `gs_btc_broadcast.unused(address, servers, proxy, network=...)` over Tor
   on the address's own circuit; a used address steps to the next index, at
   most `BTC_INDEX_GAP` (20) times, then refuses `btc_index_exhausted`; a
   look nobody answered refuses `btc_lookup_failed` (fail closed: never issue
   an address that was not seen fresh);
3. records `btc_index` on the handle beside `bundle`, `minted`, `admitted`,
   `slip`, `owner`.

`plain_slip_for_chat` for a record carrying `btc_index` builds
`{b: btc_in, d: <the host's derived address>, x: expected_xmr, h}` -- no `m`.
The pairs file's shared inbound and memo are NOT read: the quote's memo is
the forward's business at forward time. `seal_slip_for_delivery` returns ""
for such a record, logged as a kind. The deposit floor: before minting, the
amount must be at least `btc_deposit_min_sat(key)` =
`FORWARD_MIN_SAT + vsize_upper_bound(1, [INBOUND_SPK_MAX,
op_return_script_len(op_return_max_bytes)]) * feerate_ceiling`, else
`deposit_too_small` (before any Tor work, before any mint).

### 3.2 The wire

`PLAIN_FIELDS` keeps its bounds; `plain_slip_is_wellformed` accepts EITHER
the full set `{b, d, m, x, h}` OR the BTC-mode set `{b, d, x, h}`, nothing
else. An old Pi refuses a BTC-mode slip ("not a set of deposit
instructions"), loud, which is the half-upgrade behaviour. The doorbell
learns nothing new: the shape check is the protocol's. `WIRE_VERSION` 6 (a
changelog entry). No new M3 field: the Pi reads the address off `plain["d"]`
and knows the mode by the absence of `m`.

### 3.3 The Pi: the pager

Configuration on the pager's own command line, like its Tor proxy, never on
the card: `--btc-electrum HOST[:PORT][,PIN]` (repeatable), `--btc-min-conf`
(default 2), `--btc-network` (default main), `--btc-poll` seconds (default
600), `--deposit-min-sat` (default `DEPOSIT_MIN_SAT`; the operator sets it to
the vault's floor so the wizard refuses early with the number rather than
spending a wake on the vault's `deposit_too_small`). Without `--btc-electrum`
the pager watches nothing and BTC-mode deposits behave as today's (the
button wakes the vault).

The deposit reply in BTC mode (a plain slip without `m`): no note message,
no "phone CANNOT" line, no "/withdraw sends it on"; instead the amount, the
address, the label, and one sentence: it will say here when the payment
arrives and when it is confirmed, and then it moves on by itself.

The watcher: one thread, every `--btc-poll` seconds, over the in-memory
registry `{handle: {addr, chat_id, state, since}}` populated when a BTC-mode
slip is rendered. Each address is looked at with `gs_btc_watch.look` over
Tor on its own circuit. Transitions, each said once: `not_seen -> seen`
("received — waiting for it to confirm"), `-> confirmed` ("confirmed.
Sending it on now."), then `start_job(chat, "forward_to_swap", {handle})`
through the ONE path every wake takes (rate limit, one-job lock, owner
token). A forward that reports done with `sent`/`unsure` closes the entry;
one refused or failed leaves it in `forward_failed` and says so once; the
button still wakes. A look that fails is not a state change and is not
said. Nothing the watcher says carries a number or a currency word.

The button and `/check` on a registered BTC deposit run `forward_to_swap`
instead of `swap_status`; on an unregistered handle (after a restart) they
run `swap_status` as today -- the vault answers from the XMR side, which is
truthful about that side. `/balance`: for the chat's registered deposits,
one line each with the label and its state word -- no figure (the fix pass
after the deep read removed the totals: an on-chain amount in the
transcript is a number on the chain, rule 6). Gated implicitly: a
registered deposit exists only where the plaintext mode is on.

### 3.4 The doorbell

`report()` already prints the plain lines without a note when `m` is absent;
the "how to pay" wording gains nothing. `on_m3` accepts the BTC-mode set
through the protocol's predicate. Nothing else.

### 3.5 Pairing

`gs_wake_keys`: `--btc-xpub` requires `--deposit-in-chat` (refused at
pairing with the reason); the keyfile is unchanged otherwise (stage 2's BTC
fields already exist).

### 3.6 The forwarder's status file

On `nothing_settled` and on the new `nothing_settled` variant where money is
present but shallow, `btc_forwarder` writes `btc_forward_status_<handle>.json`
next to the plan path: `{"state": "not_seen" | "seen"}`; nothing else in it,
no amount. The agent's `_phase_of("forward_to_swap", status="refused")` reads
it: `not_seen -> not_yet`, `seen -> arriving`, else "". The refusal path in
`_run_validated` passes the phase through `_reported` (today it sends none).
The file is read once and removed, like the probe's status file.

### 3.7 Rule 6 on every new sentence

Every string the watcher, the deposit reply and `/balance` send goes through
`tests/test_depo_wizard.py`'s banned-word scan (no "bitcoin", "btc",
"swap", "memo", "mix", "wallet", "tor", "vault", ...) and its currency
ceiling. The by-hand doorbell path shows what the chat shows.

---

## 4. Build order, each step validated before the next

1. **Protocol:** `plain_slip_is_wellformed` two shapes, `WIRE_VERSION` 6,
   `BTC_INDEX_GAP`; `gs_btc_broadcast.unused`. Tests: test_wake_protocol /
   test_plain_slip (both shapes accepted, a third refused), test_btc_broadcast.
2. **Vault:** the floor, the allocation with the freshness check, the record,
   the two slip builders. `tests/test_wake_agent.py`: a BTC-mode deposit
   records index 0, the next records 1, a used address is stepped past, an
   unanswered look refuses, the gap refuses, the plain body has no `m` and
   carries the derived address, the sealed slip is "", the floor refuses
   before any mint or look, and a non-BTC keyfile is untouched.
3. **The forwarder's status file and `_phase_of` on refusal:** test_btc_forwarder
   (the file, its two states, nothing else in it), test_wake_agent (a refused
   forward carries `not_yet`/`arriving`), test_wake_doorbell (a refused
   result with those words renders them).
4. **Pairing:** the coupling; test_wake_agent's `_pairs_btc`.
5. **The pager:** flags, the BTC deposit reply, the watcher (driven with
   `look` stubbed at the module attribute and a fake clock), the button and
   `/check` routing, `/balance`, restart behaviour. test_telegram_pager,
   test_depo_wizard's scans.
6. **End to end:** test_wake_endtoend: a BTC-mode deposit through the real
   doorbell and agent (the look stubbed on the vault) -> the M3's plain has
   no `m` and carries the derived address -> the forward of that handle
   finds `btc_index` on the record.
7. **Docs:** OPSEC_SETUP ("If you have only a phone" gains the BTC-mode
   paragraph; pairing recipe), BTC_INTAKE_DESIGN's stage table and the xpub
   departure, SESSION_LOG.
8. **Anchors** (section 6), the full suite, the sweep, commit.

---

## 5. Tests that break by design

- test_plain_slip / test_wake_doorbell: "an exact key set" for the plain
  slip -- now two exact sets.
- test_telegram_pager: the deposit reply's "/withdraw sends it on" and the
  note-first sequence, for BTC-mode slips only (the shared-inbound rendering
  is unchanged and its checks stay).
- test_wake_agent: the `no_btc_deposit` refusal for a handle minted in BTC
  mode (it now carries an index).
- test_depo_wizard: every new literal enters the scan.

---

## 6. Mutation anchors to add

- the freshness check skipped (a used address issued);
- an unanswered look issues an address anyway;
- the gap unbounded;
- the plain body carries the shared inbound (`deposit`) instead of the
  derived address, or carries `m`;
- the sealed slip built for a BTC-mode record;
- the floor removed;
- `plain_slip_is_wellformed` accepts a third shape (e.g. `{b, d, h}`);
- the watcher says "confirmed" on `seen`, or starts the forward on `seen`;
- the watcher starts the forward twice;
- the watcher speaks through a path other than `start_job`;
- the forwarder's status file carries an amount;
- `_phase_of` maps `seen` to `not_yet`;
- pairing accepts `--btc-xpub` without `--deposit-in-chat`;
- a new sentence with a banned word.

---

## 7. Hazards this stage does not close

- The pager's memory is the registry: a restart stops the automatic path
  for open deposits (stated in 2).
- The Electrum servers the Pi asks see which addresses it watches, on
  separate circuits; an own node over an onion removes the third party, as
  for the vault.
- Custody: the client's money now sits on the host's address from arrival
  to forward, in the ordinary flow, not only in a rehearsal.
- Reconciling "you get back about X" against what the forward actually
  swapped, the confirmation depth of the forward, and re-sending a kept
  transaction: stage 5.

---

## 8. Self-doubt after the build (what the plan got wrong, and the fixes)

Read against the code once every step was green, with the question "where
does a client's money sit with nobody able to move it?":

- **A pager restart stranded every open deposit.** Section 2 said "the
  existing button still works — it wakes the vault", and it did: on
  `swap_status`, the XMR-side probe, which cannot move bitcoin and answers
  "nothing yet" for ever about an address the client has paid. The watch
  list is memory by design, so after a reboot nothing on the Pi knew which
  deposits were the intake's. FIXED: on a pager that declares the intake
  (`--btc-electrum`) EVERY deposit is the intake's, so the button and
  `/check` on a forgotten handle ask the forward, which sends a settled one
  on and otherwise answers `not_yet`/`arriving`. `--btc-electrum` is no
  longer optional on an intake pair and OPSEC_SETUP says so.
- **The automatic path died silently whenever the box was busy.** The
  watcher's `start_job` for a confirmed deposit went through the one wake
  path, which is right — and that path answers "no: busy" into the chat and
  returned nothing, so the entry, already marked `forwarding`, was never
  looked at again. A withdrawal chain holds the lock for hours; with two
  clients this was the common case, not the edge. FIXED: `start_job` now
  returns whether a wake started; the watcher reads the same three gates
  (lock, daily budget, restart hold) before it transitions, keeps a
  confirmed deposit as `seen` while it cannot wake (the chat hears once, in
  words with nothing in them, that it is sent on when this end is free),
  retries next tick, and a start that was refused after all puts the entry
  back to `seen` instead of trusting a forward that never ran.
- **An xpub without the forward switch.** Pairing accepted `--btc-xpub`
  with `--deposit-in-chat` and no `--allow-btc-forward`: an intake that hands
  out addresses no job can send on from, with every automatic start refused
  `not_allowed`. FIXED at pairing, where the operator is standing.
- **The freshness look is a new thing the vault says to a server**: it
  names an address moments before that address is paid, on its own circuit.
  A third-party Electrum server can correlate the two; the operator's own
  electrs cannot. Stated in OPSEC_SETUP; not closable by code.
- **Exhaustion is permanent for that account.** A ledger wiped with more
  than a gap of history behind it refuses `btc_index_exhausted` on every
  deposit, and re-pairing the same xpub does not help (same chain); the
  forwarder derives account 0 only, so a fresh account is not a re-pair
  either. The refusal now says so. Recovery (restoring the ledger; a
  per-pair account number) is stage 5. A subtler cousin lives in the same
  place: after a wipe, an address issued to a client who has not paid YET
  looks fresh to the network and could be reissued; a late payer and a new
  client would then share one line. Bounded by the in-flight ceiling, and
  stage 5's.
- **The first fix broke the tap AFTER a forward.** Routing every intake
  ask to the forward meant the client's "has it arrived?" after `sent` --
  the moment they most want the XMR side's answer -- hit the once-sent
  rule and came back "refused" with no reason. FIXED on both ends: the
  vault answers a sent handle's forward run with DONE and the plan's own
  word (`sent`/`unsure`) instead of refusing, running no child (once sent,
  never signed again still holds and its anchor still proves no child
  runs); the pager learns the sent handles from those answers and asks the
  XMR side from then on. Stage 5 turns that no-op run into the
  reconciliation (is the txid listed; re-send kept bytes).
- **A never-paid deposit was watched for ever.** Nothing removed a
  `not_seen` entry: every tire-kicker's address got a fresh Tor circuit and
  a look every ten minutes, indefinitely, and the list only grew. FIXED:
  an entry nothing has reached for `DEPOSIT_PLACE_TTL_S` (two days, the
  vault's own reserve window for an unpaid deposit, on the same wall clock
  the pager's places use) is dropped silently and logged by kind; a payment
  landing later is still sent on by the button, which asks the forward.
- Not a bug, but confirmed by reading rather than assumed: a forward that
  found nothing settled reports DONE with the word (`_run_validated` skips
  the failure path when the status file exists), so the pager's table for
  `(done, not_yet)` and `(done, arriving)` is the real contract.

---

## Status

- [x] 1. protocol + `unused` — test_wake_protocol, test_plain_slip 232,
      test_btc_broadcast 83
- [x] 2. vault: floor, allocation, record, slips — test_wake_agent
- [x] 3. forwarder status file, `_phase_of` on refusal — test_btc_forwarder
      168, test_wake_agent, test_wake_doorbell 161
- [x] 4. pairing — test_wake_agent (`_pairs_btc`), now with the forward
      coupling
- [x] 5. pager: flags, reply, watcher, routing, `/balance` —
      test_telegram_pager 704, test_depo_wizard 434
- [x] 6. end to end — test_wake_endtoend 70 (the intake cycle over real HTTP;
      the repeat run on a sent handle answering `sent` with no child)
- [x] 7. docs — OPSEC_SETUP ("The intake" under the phone section, the
      pairing recipe), BTC_INTAKE_DESIGN (stage 4 BUILT, the xpub departure),
      SESSION_LOG
- [x] 8. anchors 530–565 (36, the six from section 8 included), full suite,
      sweep, commit — see the commit message for the tally. Two anchors
      first came back NO-RESULT (the suite crashed on the mutated copy
      instead of failing a check: an unguarded index and an unguarded key);
      the checks were hardened so a missing message or entry is a FAIL, and
      both are caught.
