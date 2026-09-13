# Stage 3: broadcast over Tor — the forward leaves the machine

Status: **PLANNED** (this commit); the build follows in the commits after it,
and the status block at the end is updated as each step lands. This file is
the whole context for stage 3 of the BTC-intake rework (`BTC_INTAKE_DESIGN.md`;
stage 2 is `STAGE2_PLAN.md`), written before the build and kept as its record.

Stage 3 turns the signed, never-broadcast forward of stage 2 into a forward
that is handed to the Bitcoin network over Tor, verified as seen, recorded,
and reported to the phone in one closed word. It does NOT yet track the
transaction to confirmation depth, bump its fee, or recover from a reorg:
those are stage 5 (`BTC_INTAKE_DESIGN.md` lists "forward failure and retry,
reorg/confirmation edge cases" there, and the stage table's "confirmation-wait"
under stage 3 is resolved here as "seen in the network's mempool", not "buried
N blocks deep" — see section 3.4 for why).

---

## 1. What stage 2 handed over (facts this build stands on)

- `btc_forwarder` builds, signs, verifies and prints; `--dry-run` is REQUIRED
  and there is no other mode. The signed hex goes to stdout (the 0600 job log)
  and is written to the plan file only under `--write-signed-hex`. The plan
  carries `broadcast: false`.
- `gs_btc_watch.Electrum` "knows no method that could move money", and three
  tests pin that by reading the source: `tests/test_btc_watch.py` ("the module
  never speaks a method that could spend or broadcast"),
  `tests/test_btc_forwarder.py` ("the forwarder has no broadcast path" and "the
  stage-1 client it uses still knows no method that could spend").
- A done forward marks its ledger record `forwarded` (a 600 s bucket) and
  `forward_plan`; a second `forward_to_swap` on that handle is refused
  `already_forwarded`. The mark was meant to be cleared by "stage 3, which
  consumes the plan".
- The forward's M3 carries `phase ""` (nothing to say); the pager and the
  doorbell render a done forward as "signed on the machine. Nothing was sent
  yet (stage 2)."
- The quote has no expiry bound (`STAGE2_PLAN.md` section 9: "stage 3 should
  bound it explicitly rather than inherit the claim").
- The memo's output limit is now SET by the forwarder (99% of the worst-case
  arrival), so the on-chain slippage guard does not depend on the aggregator.
- The relay strategy for the >80-byte OP_RETURN was deferred to stage 3
  (`STAGE2_PLAN.md` section 2).
- Testnet was deferred to stage 3 "where a broadcast exists to test". This
  sandbox has no Tor, no egress and no bitcoind, so the live testnet run is a
  test FILE that skips here and runs on the operator's box (section 3.11).

---

## 2. Self-doubt on stage 2, carried into this stage

Findings from re-reading stage 2 with the question "what would break on the
first real run", beyond the memo-limit fix already landed:

- **The affiliate cap defaults to 0.** If the aggregator injects its own
  affiliate THORName and basis points into every memo (SwapKit's referral
  scheme does this for keyed accounts), the default refuses every real quote
  as `memo_affiliate_fee`. Unverifiable here (egress blocked). The knob exists
  (`--max-affiliate-bps` in the keyfile); the refusal names the figure; the
  testnet run (3.11) will show the real memo shape. Not changed.
- **THORNode field shapes** (`address`, `halted`, `chain_trading_paused`,
  `global_trading_paused`, `chain_lp_actions_paused`, `dust_threshold` as a
  string) match THORNode's published `inbound_addresses` schema. Not changed.
- **`fee_out_of_band` after signing** (real rate under the floor) is checked
  after the seed was used. Harmless in a dry run; in stage 3 it MUST stay
  before the broadcast, and it does (the ordering is pinned in the build).
- **The sign step has no clock.** Between the quote and the signature nothing
  bounds the elapsed time. Stage 3 adds the bound (3.5).
- **`already_forwarded` on a dry-run mark** would refuse the very broadcast the
  dry run rehearsed. Stage 3 changes the rule (3.6).

---

## 3. Design decisions

### 3.1 Where the broadcast lives: a separate module, a subclass, one method

New file `gs_btc_broadcast.py`. It imports `gs_btc_watch` and adds:

```
class Broadcaster(watch.Electrum):
    def broadcast(self, raw_hex) -> str      # blockchain.transaction.broadcast
    def history(self, scripthash) -> list    # blockchain.scripthash.get_history
```

`broadcast` is THE one method in this codebase that can move bitcoin. It lives
in a module the Pi never imports (a source-level test pins that
`gs_btc_watch.py` and `gs_btc_broadcast.py` are two files and that nothing on
the Pi's side names the second). The stage-1 guarantee — the watch client knows
no such method — stays literally true and its three tripwire tests stay green
unchanged: the string `transaction.broadcast` still does not appear in
`gs_btc_watch.py`, and in `btc_forwarder` it appears only as an import of the
function below, under the `--broadcast` branch.

`history` is read-only and could have gone in stage 1's client; it goes here
because only the broadcast needs it (to see its own transaction) and because
adding it to the watch module would widen the Pi's behavioural fingerprint
(section header of `gs_btc_watch.py`: every connection speaks the same calls).

Two module functions:

```
submit(raw_hex, expected_txid, address, servers, proxy_url, *, network,
       timeout, transport_factory=None) -> dict
    {outcome: "accepted" | "rejected" | "ambiguous" | "unreachable",
     server, cert_sha256, codes: [int|"unknown", ...], attempts: n}

seen(txid, address, servers, proxy_url, *, network, timeout, wait_s,
     interval_s, sleeper=None, transport_factory=None) -> dict
    {seen: bool, height: int|None, server, cert_sha256}
```

Semantics of `submit`, per server in the same rotation order `look()` uses
(start at the address's own scripthash, so no single server gets every
address) but on a DIFFERENT circuit tag (`btcsend:<address>`), so the look and
the spend do not share a circuit:

- the server returns a string equal to `expected_txid` → **accepted**, stop.
- the server returns a string that is NOT our txid → treated as a lying or
  broken server (a segwit txid cannot be malleated by a third party), logged
  as kind `txid_mismatch`, try the next server; if nothing better comes it
  counts as **ambiguous** (the bytes were sent).
- the server answers with an error → the numeric code only (stage 1's
  `_error_code` rule: ElectrumX echoes the node's rejection text, which for a
  rejected OP_RETURN carries the memo) → **rejected by this server**, try the
  next. Rejection is per-server POLICY as often as it is consensus: a node with
  the pre-Core-30 `datacarriersize` refuses the 105-byte memo that the next
  node relays. That is the relay strategy (3.3).
- the bytes were sent and no well-formed reply came (deadline, closed socket)
  → **ambiguous** for this server, try the next. Re-submitting the same signed
  transaction is idempotent — the same txid, and a node that already has it
  answers with the txid.
- the connection or the SOCKS/TLS handshake failed before the bytes were sent →
  **unreachable** for this server, try the next.

The whole result: accepted if any server accepted; else ambiguous if any send
completed; else rejected if every reachable server rejected; else unreachable.
`PinMismatch` is re-raised at once, as `look()` does: an interception is not a
server to route around.

`Broadcaster.broadcast` sets `self.sent = True` after `send_line` returns and
before it reads, so `submit` can tell "the bytes left" from "they never did".
That flag is the difference between a run that may have moved money and one
that certainly has not, and the exit code and the phase word both hang on it.

### 3.2 Sign and broadcast in ONE process; no file is ever the input

`btc_forwarder` gains `--broadcast`, mutually exclusive with `--dry-run`, and
exactly one of the two is REQUIRED (omitting both is still `not_dry_run`, so a
stage-2 caller keeps its refusal). Under `--broadcast` the tool does everything
stage 2 does — look, size, quote, validate, set the limit, cross-check, sign,
verify, the real-rate floor — and THEN hands the bytes it just signed to
`submit`, from memory. There is no `--rebroadcast <plan>` in stage 3: a signed
transaction on disk is a bearer instrument, and a tool that reads one back and
broadcasts it is a tool that broadcasts whatever is in that file. Stage 5's
retry consumer will own that path, with its own checks.

The signed hex is persisted in the plan ONLY when the run cannot say the
network has it: outcome `ambiguous`, or `accepted` but not `seen` within the
wait. Then the file carries `tx_hex` and `tx_hex_reason`, and the summary says
so out loud. A run that saw its transaction in the mempool writes no hex: the
network is the copy now.

### 3.3 The relay strategy for the >80-byte memo

Decided: **failover across the operator's configured servers, in rotation
order, treating a rejection as that server's policy and moving on.** Bitcoin
Core 30 raised the default `datacarriersize` far past 105 bytes, and a
transaction with a 105-byte OP_RETURN is consensus-valid on every node. The
operator's `--btc-electrum` list must therefore contain at least one server
whose node relays it; `OPSEC_SETUP.md` says which two ways satisfy that: their
OWN electrs/Fulcrum over an onion service on a Core ≥ 30 node (the stage-1
recommendation, for the fingerprint reason too), or a public server known to
run Core ≥ 30. `op_return_max_bytes` stays what it was — the operator's
declared policy, checked BEFORE signing — and a `rejected` outcome on every
server is reported with the codes so the operator learns their list is wrong
before any money moves (nothing moved: every server said no).

Rejected alternatives, on the record: submitting to a mining pool's HTTP
endpoint (a clearnet, keyed, logged path to a party that sees the memo and
the source; no), and THORName (rejected in stage 2 for linkability; unchanged).

### 3.4 What "seen" means, and why confirmation depth is stage 5

After `accepted` or `ambiguous`, `seen()` polls `blockchain.scripthash.get_history`
for the DEPOSIT address (our input's scripthash — the transaction spends it, so
it appears in that address's history) until the txid is listed, for at most
`--seen-wait` seconds (default 90) at `--seen-interval` (default 15), on the
`btcsend:` circuit. Height 0 or −1 is the mempool; > 0 is a block. `seen` is
the broadcast PROOF: a second server, asked read-only, reports the transaction.

Confirmation DEPTH is not waited for here. A forward job has a 900 s budget
and holds the vault powered on; a Bitcoin block is ten minutes on average and
an hour is ordinary. Waiting for depth inside the job would either blow the
budget or double the vault's powered-on signature for nothing the operator can
act on. The existing probes (`swap_status`, `watch`) answer the question that
matters — has the XMR landed — and stage 5 adds the BTC-side tracking (dropped
from the mempool, fee bump, reorg) as its own woken probe over the plan file.

### 3.5 The quote is bounded in time

`quoted_at = time.monotonic()` after the quote. Before `submit`,
`--quote-max-age` seconds (default 300) must not have elapsed, else
`quote_stale` (a refusal: nothing moved; the seed was used, the bytes stay in
memory and die with the process). Inbound vaults churn on a scale of days and
the limit protects the price, so 300 s is generous; it exists so the number is
a decision and not an accident of Tor's latency.

### 3.6 The ledger mark and the repeat rule

`handles[h]["forward_sent"]` is added beside `forwarded`: `True` when the run's
outcome was `accepted` or `ambiguous` (money may have moved), absent/`False`
for a dry run. `_dispatch`'s repeat rule becomes:

- `forward_sent` → `already_forwarded`, in every mode (irreversible).
- `forwarded` but not sent (a dry-run rehearsal) → a `--broadcast` run is
  ALLOWED and supersedes the plan; a second dry run is still `already_forwarded`
  (stage 2's reason stands: no silent re-quoting of the same destination for
  nothing).

The plan file is overwritten by the broadcast run (fresh quote, fresh
signature); `forward_plan` keeps pointing at the same path.

### 3.7 The wire: two new words

`PHASES` gains `"sent"` and `"unsure"`; `PHASE_LINES` gains one sentence each,
numberless and machine-nameless (rule 6, and `tests/test_depo_wizard.py`
scans every `PHASE_LINES` value):

- `sent` — "the forward went out. It confirms on its own — ask again later."
- `unsure` — "the forward may or may not have gone out. It will be checked
  before anything else is done with it."

`_phase_of("forward_to_swap", ...)` reads the plan file the job just wrote —
`broadcast_outcome` `accepted` → `sent` (whether or not `seen`: a server took
it, that is a fact), `ambiguous` → `unsure`, anything else (dry run, rejected)
→ `""`. Never the txid, never a number. The doorbell validates the word with
`phase_is_known` as it validates every other; an OLD Pi refuses an M3 carrying
a word it does not know, which is the documented half-upgrade behaviour: update
both boxes together. `WIRE_VERSION` 4 → 5 (a changelog, not a check).

Rendering: the pager's done-branch for `forward_to_swap` renders the phase line
when there is one and keeps "forward signed on the machine. Nothing was sent."
for a dry run (the "(stage 2)" suffix goes). The doorbell's `report()` does the
same on the by-hand path.

### 3.8 The switch: a second keyfile gate

Pairing flag `--allow-btc-broadcast`, keyfile field `allow_btc_broadcast`,
refused at pairing without `--allow-btc-forward`. `build_argv` composes
`--broadcast` iff `allow_btc_forward` AND `allow_btc_broadcast` are both true
(validated as booleans, never coerced: a keyfile value that is present and not
a boolean is `btc_config_malformed`), else `--dry-run`. Absent from every
keyfile written before it existed → dry run. So an upgraded pair gains nothing
silently, which is the property every spending switch here was built for.

### 3.9 What reaches where (rule 6)

- **Hash chain:** kinds only — `broadcast_accepted`, `broadcast_seen`,
  `broadcast_unseen`, `broadcast_ambiguous`, `refused:broadcast_rejected`,
  `broadcast_unreachable`, `txid_mismatch`, `refused:quote_stale`. Never a
  txid, a server, a height, a code.
- **Plan file (0600, in the wipe):** everything — `broadcast: true/false`,
  `broadcast_outcome`, `broadcast_server`, `broadcast_codes`, `seen`,
  `seen_height`, `txid`, and the hex only per 3.2.
- **Job log:** the summary lines, including the txid (as stage 2 already logs
  it) and the outcome in words.
- **The phone / the Pi:** one word. A `rejected` or `unreachable` run is a
  refusal/failure with no reason on the wire, as every other is.

### 3.10 Exit codes and what each means for money

| outcome | exit | money | phase |
|---|---|---|---|
| dry run | 0 | not moved | "" |
| accepted (seen or not) | 0 | moved | sent |
| ambiguous | 0 | MAY have moved; hex persisted | unsure |
| rejected by every reachable server | 2 (refused) | not moved | "" |
| unreachable (no send completed) | 1 (failed) | not moved | "" |
| quote_stale | 2 | not moved | "" |

`ambiguous` exits 0 deliberately: a non-zero exit is rendered as "the vault
FAILED", and stage 2's whole phase vocabulary exists because that sentence was
false about money in flight. The plan file and `unsure` say the truth.

### 3.11 Testnet, end to end, on the box that has Tor

`tests/real_btc_forward_testnet.py`: SKIPS (exit 0) unless
`GS_BTC_TESTNET_SEED`, `GS_BTC_TESTNET_ELECTRUM` (repeatable, comma-separated)
and a reachable Tor proxy (`GS_BTC_TESTNET_TOR`, default
`socks5h://127.0.0.1:9050`) are all present. With them it:

1. derives address 0 of the seed's testnet account and asks the operator (via
   the log) to fund it if `look()` finds nothing settled;
2. runs the REAL `btc_forwarder --broadcast --network testnet` with the quote
   STUBBED (there is no testnet THORChain and no testnet XMR quote): the
   "inbound" is address 1 of the same account, the memo is a real-shaped
   `=:XMR.XMR:<95-char dest>:<limit>/1/0`, the oracle is stubbed to the
   quote's own rate; everything else — the look, the fee estimate, the
   signing, the broadcast, the seen-poll — is live over Tor;
3. asserts `broadcast_outcome == "accepted"`, `seen`, and that address 1's
   `look()` shows the forwarded amount as unconfirmed money.

That proves the transport, the client, the signature, the OP_RETURN relay
policy of the configured servers and the seen-poll against the real network.
It cannot prove that THORChain accepts the memo — only mainnet can — and it
says so in its header. This sandbox cannot run it; its SKIP path is exercised
by the ordinary suite so a syntax error cannot hide in it.

### 3.12 What stays open

Reorg of the input after broadcast (the forward becomes invalid; the deposit
reappears), the transaction dropped from mempools at a low rate, an RBF bump,
a confirmation-depth probe, and reconciling the real swapped-out amount: stage
5. The custody window (deposit lands → forward confirms) is now real money in
flight rather than a signed file; `BTC_INTAKE_DESIGN.md` hazard 1 stands as
written.

---

## 4. Build order, each step validated before the next

1. **`gs_btc_broadcast.py`** — `Broadcaster`, `submit`, `seen`; driven in
   `tests/test_btc_broadcast.py` through the fake-transport seam AND the
   in-process SOCKS5 + TLS Electrum mock copied from `tests/test_btc_watch.py`
   (extended with `blockchain.transaction.broadcast` and
   `blockchain.scripthash.get_history`): accepted, rejected with a code, a
   server returning a foreign txid, a server that reads the request and hangs
   up (ambiguous), a server that refuses the CONNECT (unreachable), the four
   combined across a list, `PinMismatch` re-raised, the seen-poll finding the
   txid on the second poll and giving up at the wait, and the source rules
   (the Pi's module never names the broadcast method; no server text in any
   error).
2. **`btc_forwarder --broadcast`** — the flag pair, the quote clock, the
   ordering (real-rate floor BEFORE submit), the outcome table, hex
   persistence per 3.2, the summary, the chain kinds. `tests/test_btc_forwarder.py`
   drives every row of 3.10 with `submit`/`seen` stubbed at the module
   attribute, and one run through the REAL `gs_btc_broadcast` against the
   in-process mock.
3. **The wire and the ledger** — `PHASES`, `PHASE_LINES`, `WIRE_VERSION` 5,
   `_phase_of` for the forward, `forward_sent`, the repeat rule, the keyfile
   switch and its pairing validation, `build_argv`. `tests/test_wake_agent.py`
   (the forward block), `tests/test_plain_slip.py` (every phase word has a
   line), `tests/test_wake_keys`-side pairing checks.
4. **Rendering** — the pager and the doorbell; `tests/test_telegram_pager.py`,
   `tests/test_wake_doorbell.py`, the rule-6 scans.
5. **End to end** — `tests/test_wake_endtoend.py`: a broadcast forward through
   the real doorbell and the real agent over real HTTP with the child faked to
   write an `accepted` plan, the M3 carrying `sent`, and the repeat refused.
6. **The testnet file** (3.11), its SKIP path in the suite.
7. **Docs** — `OPSEC_SETUP.md` (the switch, the server list requirement, the
   recipe), the unit file comment, `BTC_INTAKE_DESIGN.md`'s stage table,
   `SESSION_LOG_AND_PLAN.md`.
8. **Mutation anchors** — section 6 — then the full suite and a targeted
   sweep, then commit.

---

## 5. Tests that break by design the moment this lands

- `tests/test_btc_forwarder.py`: "the forwarder has no broadcast path"
  (rewritten: the path exists, is reachable only under `--broadcast`, and
  `--dry-run` never calls `submit` — pinned by a stub that raises).
- `tests/test_btc_forwarder.py`: "the plan says: dry run, NOT broadcast";
  `_HEX_LINE` ("stage 2: NOT broadcast, not persisted") — the wording changes.
- `tests/test_wake_agent.py` forward block: "--dry-run in argv" — now
  conditional on the switch; "already_forwarded on repeat" — now the dry-run
  rehearsal case allows a broadcast run.
- `tests/test_wake_endtoend.py`: the forward cycle's repeat check.
- `tests/test_telegram_pager.py` `_forward_done` and `tests/test_wake_doorbell.py`
  (159): the "(stage 2)" sentence.
- `tests/test_plain_slip.py`: iterates `PHASES` and requires a `PHASE_LINES`
  entry for each — green once the two lines exist.
- `tests/test_depo_wizard.py` rule-6 scan of `PHASE_LINES` values — the two
  new sentences must pass it (no digits, no machine nouns).

---

## 6. Mutation anchors to add (each must be CAUGHT)

- `submit` treats a foreign txid as accepted.
- `submit` keeps going after `PinMismatch`.
- `submit` reports `unreachable` when bytes were sent (the `sent` flag ignored).
- `seen` returns True on an empty history.
- the forwarder broadcasts under `--dry-run` (the mode check inverted).
- the forwarder broadcasts a stale quote (`quote_stale` removed).
- the forwarder broadcasts before the real-rate floor check (order swapped).
- the hex is persisted on `accepted`+`seen` (3.2 inverted) / NOT persisted on
  `ambiguous`.
- `ambiguous` exits non-zero (3.10 inverted).
- `_phase_of` says `sent` for a dry-run plan.
- `_dispatch` lets a `forward_sent` handle be forwarded again.
- `build_argv` passes `--broadcast` without `allow_btc_broadcast`.
- pairing accepts `--allow-btc-broadcast` without `--allow-btc-forward`.
- a `PHASE_LINES` sentence with a digit or a machine noun.

---

## 7. Hazards this stage does not close

- **Custody is now live** (hazard 1): between the deposit's settlement and the
  forward's confirmation the host holds and moves the client's BTC.
- **The OP_RETURN relay** is only as good as the operator's server list; the
  `rejected` outcome is loud but costs a wake.
- **An `unsure` run leaves a bearer instrument on disk** (the persisted hex),
  inside the wipe, until stage 5 consumes it. Stated in the summary line.
- **The Electrum server that takes the broadcast sees the transaction, the
  memo and the source circuit together** — the same footprint the client used
  to have (hazard 8). An own node over an onion removes the third party.
- **No confirmation depth, no reorg handling, no fee bump** — stage 5.

---

## Status

- [ ] 1. `gs_btc_broadcast.py` + `tests/test_btc_broadcast.py`
- [ ] 2. `btc_forwarder --broadcast` + tests
- [ ] 3. wire, ledger, switch, pairing
- [ ] 4. rendering
- [ ] 5. end to end over real HTTP
- [ ] 6. testnet file (skips here)
- [ ] 7. docs
- [ ] 8. anchors, full suite, sweep, commit
