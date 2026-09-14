# Session log, every fix, and the plan — GhostSpiral phone bot

A complete handoff of this working session: what the system is, every change
made and why, how each is validated, the decisions taken, and the staged plan
for the BTC-intake rework. Written so a reader with no memory of this session
(a person, or a later session) can pick up exactly where this stopped.

This is a context document. The authoritative spec for the new work is
`BTC_INTAKE_DESIGN.md`; the authoritative operating rules are `OPSEC_SETUP.md`
and `AGENTS.md`; the code and its tests are the truth. Where this file
disagrees with any of those, they win.

Branch: `claude/phone-withdrawal-destinations-ey6ovb`. Every commit named
below is on it and pushed. No pull request has been opened (none was asked
for). Development happens only on that branch.

---

## 1. What the system is (the facts every fix rests on)

**GhostSpiral** is a BTC→XMR privacy pipeline driven from a phone.

- **Vault (laptop).** OFF by default. Boots on a wake, runs ONE job, powers
  off, disk resealed (it auto-unlocks on boot, which is why "off" is the
  security posture). Holds the Monero spend wallet and the receive wallet.
  Tools: `gs_wake_agent` (the job runner), `GhostSpiral` (the mixer),
  `create_receive_wallet`, `thor_swap_preparer` (ThorChain quote + memo),
  `receive_watch`, `monero-wallet-rpc`. Also a separate hot **fee wallet**
  with a threshold sweep (`--fee-sweep`), so a usage fee never lands on the
  mixing wallet.
- **Pi.** Always on, assumed seizable, holds NO wallet and NO keys. Runs
  `gs_telegram_pager` (the Telegram bot) with an in-process `gs_doorbell`
  (the wake/collect endpoint on a fixed LAN port). Persists exactly one file
  (rate state, stamps coarsened to 5-minute buckets) and an integrity
  hash-chain on the SD card.
- **Phone.** Telegram. Talks only to the Pi. Every message in that chat is
  assumed readable by someone who is not the operator.
- **Wire.** `gs_wake_proto.py`: sealed M1/M2/M3 records between Pi and vault;
  `validate_job` enforces an EXACT key set per job (adding a field is a wire
  change: bump `WIRE_VERSION`, update both boxes together, an old box refuses
  loud). Every job carries an `owner` token: 16 hex, derived one-way by the
  pager from the asking chat, keyed by the pairing secret; `HOST_OWNER` is
  all zeros. `WIRE_VERSION` is 3.
- **Jobs** (`JOBS`): `receive_and_quote` (mint a receive subaddress + quote a
  ThorChain swap to it; spends nothing), `watch` (long wait for a payment),
  `swap_status` (the 5-minute /check: look once, answer in one word, power
  off), `withdraw` (the only job that spends; runs GhostSpiral at a chosen
  depth). `receive_new` (pay a subaddress directly in XMR) existed and was
  removed as half-wired.
- **The deposit today.** The client pays BTC to ThorChain's SHARED inbound
  vault address with a swap memo (`=:XMR.XMR:<dest>:...`) in an OP_RETURN.
  That memo is the only thing that routes the payment; BTC sent without it
  arrives belonging to nobody. The received XMR lands on a fresh receive
  subaddress minted for that deposit, is mixed, and is later withdrawn to the
  client's own address(es).
- **Phases** a /check can report (`PHASE_LINES`): `not_yet`, `arriving`
  (received, not yet spendable), `landed` (CONFIRMED, spendable, the rest not
  run yet), `short`, `stuck`, `more_left`, `more_locked`, `moved`, `partial`,
  and `full` (the one refusal that carries a word: the vault is at capacity).
- **Depths** (`WITHDRAW_DEPTHS`): 3 hops ≈ 6 h, 10 hops ≈ 9 h, 20 hops ≈ 13 h a
  leg; the chat talks in hops, the wire in keys. A withdrawal with several
  arrivals runs leg after leg (a chain) up to `MAX_CHAIN_LEGS`.
- **Windows the Pi holds the line for** (`result_budget_s`): swap_status
  1800 s, receive_and_quote 5100 s, watch 8700 s, withdraw 59700 s (≈17 h) —
  which is why the working line says "Nothing else can run for up to N".

### The two rules everything is measured against
- **AGENTS.md rule 6.** Assume the chat is read by someone who is not the
  operator and the Pi's SD card is in someone else's hands. Nothing may reach
  either that names a machine, a tool, an address, an amount, a memo, or the
  shape of the arrangement. Enforced by tests: a banned-word list (vault,
  thorchain, monero, xmr, bitcoin, btc, memo, op_return, swap, wallet, tor,
  mix/hop words, …) scanned over every literal the bot can send, a currency
  scrub with a ceiling of zero, per-literal length caps, and welcome-text
  sweeps for architecture words.
- **Kerckhoffs.** Nothing rests on hiding how the system works; the repo is
  the design. Security rests on the keys. Rule 6 is separate from this: it is
  about what a *transcript* reveals, not about the design being secret.

---

## 2. Everything changed this session, by commit (newest first)

Validation vocabulary: every suite runs per file (`python3 tests/test_X.py`,
prints `RESULT: N passed, M failed`); `tests/mutation_sweep.py` holds
**anchors**, each of which flips one exact line of source and asserts a named
suite goes red — proof the test is load-bearing, not decorative.

### Stage 0 (first landed as `8c86548`, then REWORKED): vendor embit, constant-time native preferred, trimmed, proven
- The first cut pinned embit to its pure-Python curve and forbade the native
  path. That was the wrong call for a box that signs: pure-Python big-integer
  curve arithmetic is variable-time — a timing side channel on the key that
  moves the money. The rework reverses it on principle.
- `third_party/embit/` = embit 0.8.0 `src/embit/` with THREE deliberate
  changes, all recorded in `third_party/README.md`: the seven in-package
  native blobs (`util/prebuilt/`) deleted — native code comes only from the
  operating system; the unused surface deleted (`bip85`, `slip39`,
  `psbtview`, `finalizer`, `liquid/`, `descriptor/`, the non-BIP39
  wordlists) — 50 files → 23, 14 380 → 7 612 lines, with a guard proving no
  kept module imports or references a removed one; and `util/secp256k1.py`
  replaced by a selector that prefers the SYSTEM libsecp256k1 (Bitcoin
  Core's constant-time library, from the distro's signed `libsecp256k1-1`)
  through embit's own ctypes bindings, falls back to the pure-Python curve,
  and exposes `NATIVE` / `BACKEND` so the signing path can refuse to degrade.
  The sdist sha256 was checked against PyPI's independently published digest,
  not only the downloaded file. `py_ripemd160` stays: `hashes.py` falls back
  to it when the host's OpenSSL 3 has RIPEMD-160 disabled.
- Split of trust: the **vault** (it signs) must install `libsecp256k1-1`;
  the **Pi** (watch-only, no secret) is correct and safe on the fallback.
- `tests/test_btc_embit.py` proves it against values published outside this
  repo: BIP32 test vector 1 (master, `m/0h`, and the deep path
  `m/0h/1/2h/2/1000000000` xprv+xpub), the BIP84 reference mnemonic's first
  two receive and first change addresses, public derivation agreeing with
  private derivation on a non-hardened path (the Pi/vault split in
  miniature) and refusing hardened steps, fifty consecutive indexes giving
  fifty distinct bc1q addresses, a testnet tb1 derivation, BIP173 bech32
  decode/encode/round-trip and checksum rejection, HASH160('') against
  RIPEMD160(SHA256('')) with the `py_ripemd160` fallback forced, secp256k1
  sign→verify broken on a wrong hash and a wrong key, the pure-Python
  fallback computing the same public key as the native library, the
  selector preferring native and reporting truthfully whichever is live, and
  the 23-file manifest pinned with no binary anywhere in the tree.
- A vacuous always-true check found in review was removed before commit; the
  one failing vector turned out to be a hand-typed expected string and was
  resolved against the canonical BIP32 value (embit's output was right).

### Stage 1: watch-only derivation + Electrum-over-Tor detector (`gs_btc_watch.py`) — REBUILT from scratch (`9f19781` and the commit after it)
The first stage-1 module (`b2d3993`) was discarded on request and rewritten
end to end; an adversarial review of the first version (six lenses, three
refuters per finding) found real defects, all fixed in the rewrite:
- **Settlement is per OUTPUT, never an aggregate.** The old version took
  `get_balance` + the MAX confirmation over the whole `get_history`, so 1 sat
  of long-settled dust plus a one-block-old real deposit read "confirmed,
  100 confirmations" — a reorg/RBF-able output would have been handed to the
  vault. Now `blockchain.scripthash.listunspent` is depth-checked output by
  output: `settled_sat` = sum of outputs at least `min_conf` deep; state is
  `confirmed` iff `settled_sat > 0`; every output is returned with its own
  depth (`utxos`), so the forward can only ever spend the settled ones.
  The dust trap is a named test. A fresh dust output cannot hold a settled
  deposit hostage either (the reverse case is tested).
- **SOCKS5 fails closed.** The proxy must select exactly the auth method
  offered (a "no auth" downgrade used to be accepted and silently dropped
  the per-address circuit isolation); a proxy URL that already carries a
  credential is refused (`isolated_proxy` would hand it back verbatim and
  every address would share one circuit); only `socks5h://` is accepted;
  RFC 1929 lengths and both reply version bytes are checked; ports/hosts
  are range-checked before any connection; every failure path closes the
  socket.
- **One deadline per server exchange** (`DEFAULT_TIMEOUT` 30 s), re-armed
  before every read: a server trickling one byte at a time can no longer
  hold the watcher (per-read timeouts could not stop that; proven with a
  dripping mock). `MAX_LINE_BYTES` (2 MiB) bounds a line and
  `MAX_SESSION_BYTES` (8 MiB) bounds an exchange.
- **Nothing a server chose ever reaches a log.** A server error is reported
  by numeric code only (ElectrumX echoes the scripthash into error text);
  `look()`'s final error repeats the module's own reason or names a system
  error's CLASS only, never socket text that could name a peer; a pin
  mismatch does not print either fingerprint.
- **TLS 1.2+, with optional pinning.** Unverified TLS stops a passive
  listener only; a server entry may be `(host, port, pin)` with the SHA-256
  of the server's certificate and a mismatch is refused; every result
  carries `cert_sha256` so a caller can record it once and pin from then
  on. `.onion` servers need no pin (the onion address authenticates).
- **No single server sees every address**: each address starts at a server
  chosen by its own scripthash and fails over from there (rotation, not
  truncation — all servers are still tried). Client name is a stock
  wallet's release string; the residual behavioural fingerprint (three
  read-only calls and hang up) is documented and is only removed by an own
  node.
- **Derivation refuses everything that could yield a quiet wrong address**:
  an xprv, a hardened index, a bool/float index, an xpub for another
  network (mainnet xpub asked for testnet), a ypub (nested segwit), and any
  key not at account depth 3 (root xpub, child xpub). Accepts xpub/zpub for
  mainnet, tpub/vpub for test/signet/regtest. `look()` checks the address
  belongs to the named network and is native segwit, refuses
  `min_conf < 1` (an unconfirmed deposit is never settled money), and
  validates every server spec up front.
- Every server field is type-checked, never coerced; a deeply nested JSON
  line (`RecursionError`, not `ValueError`) is caught; JSON-RPC 2.0 framing;
  a null-id error (our request rejected) is loud instead of skipped as a
  notification; the notification-skip loop is bounded (64).
- **Third round** (a second adversarial review over the FINAL code, tests
  and anchors — 8 lenses, 3 refuters each, 6 confirmed of 23): a server's
  integer `code` was an unbounded pass-through (a JSON integer is
  arbitrary-precision, so a scripthash in base 10 fit in it) — now only a
  16-bit code is a code; `timeout` is validated (inf/nan/str used to escape
  from the socket layer as stray exceptions); a proxy URL that can never
  work is ONE refusal, not a failover per server; an IDNA-invalid proxy or
  server name is the module's error, not a `UnicodeError`; a spec refusal
  never repeats the spec (it names a machine); a **pin mismatch is
  `PinMismatch`** and ends the look at once — a detected interception is
  not a dead server to route around; the header no longer claims a
  plaintext/LAN path (an own node is reached by its onion service).
  Test vacuity found and closed: the pin/timeout tests all injected their
  own transport, so `look()`'s own wiring (`pin=pin`, `timeout=timeout`,
  TLS on by default) was unproven — now driven with NO factory through the
  mock proxy (right pin completes, wrong pin refused with the server asked
  nothing, a server that goes silent after TLS is cut off by the deadline);
  the trickle mock now drips a valid handshake for ten seconds so only the
  client's clock can produce the refusal; a raw socket error in a
  handshake check is a FAIL of that check, never a file death that disarms
  every check after it; the id-matching rule has a test (a stale id is
  skipped). Anchors added for the three settlement money guards (mempool
  height, `min_conf` floor, depth formula), the pin/timeout wiring, the
  code bound and the `PinMismatch` re-raise.
- `tests/test_btc_watch.py` (213 checks): BIP84 known-answer vectors (xpub
  and the published zpub, testnet tpub/vpub → `tb1q6rz28...`), every
  refusal and that no refusal echoes the key, the settlement function as a
  truth table including the dust trap, a real in-process SOCKS5 server for
  the framing and every refusal (downgrade, trickle past the deadline, bad
  versions, closed mid-frame), the transport's line framing and byte caps,
  the REAL transport + REAL client end to end through the mock proxy to an
  in-process Electrum server in plaintext and over TLS 1.2+ with a right
  pin, a wrong pin and no pin — with and without a factory — then `look()`
  against a fake transport through every state, failover, rotation, the
  notification bound, every malformed reply, and the error-text rules.
  18 mutation anchors, all caught.
- `gs_console`'s compile action now names `gs_btc_watch.py` (test_console
  had been flagging it missing since `b2d3993`); test_gitignore lists it
  as this repo's own source.

### The deep read: constants nobody could mock, and the pair that could never forward
- Read for values that look right and are not: the Electrum fee estimate's
  units (BTC/kB to sat/vB, ceiling -- right), the transaction sizing
  constants (right), the SwapKit route fields, the THORNode inbound fields
  and the memo grammar (match the published schemas), the CoinGecko URL,
  the wake protocol's crypto (libsodium Box with library nonces, argon2id,
  HMAC-SHA256 tokens under compare_digest, commit-then-reveal pairing:
  Kerckhoffs holds, security rests on keys alone), the broadcaster's
  Electrum methods.
- FOUND: the pairing's default `--op-return-max-bytes` is the 80-byte
  standard, the documented intake recipe never set it, and no swap memo
  fits 80. Worse, the memo grows with the deposit (the output limit the
  forward writes is in 1e8 base units), so a policy of 120 -- the tests'
  fixture -- forwards small deposits and refuses the first large one with
  `memo_overflow`, for ever, with the client's money on the host's
  address. Fixed at three ends: `gs_common.SWAP_MEMO_MAX_BYTES` (126, the
  forward's own arithmetic) with `SWAP_MEMO_POLICY_BYTES` (140) to pair
  with; the pairing refuses an intake pair under the bound naming the
  flag and the number; the vault refuses to mint a deposit
  (`op_return_too_small`, before an address exists) or compose a forward
  under it; and the forwarder drops affiliate fields that carry no fee, so
  an aggregator's decoration (a thirty-character THORName at 0 bps) cannot
  push a memo past the policy. OPSEC_SETUP's recipe now carries the flag.
- FOUND: a first forward refused or failed for any reason other than the
  fee (`delayed`) left the deposit `stalled` for a tap. Most such refusals
  are the network on a bad Tor day (a stale quote, an aggregator or
  THORNode that did not answer, a relay that said no), and on an
  unattended host a tap never comes: a confirmed deposit sat on the
  host's address for ever. Now `STALL_RETRIES` (5) automatic retries, the
  wait doubling from `--btc-fee-retry` (thirty-one hours in all, past the
  vault's own 24 h wake budget, which the Pi cannot tell from any other
  refusal), as background starts that leave the reserve; the chat hears
  once that it is tried again by itself, and once more when the retries
  are spent. A run that finished clears the count. A refusal about an
  UNPAID deposit changes nothing (found on the second read: it had
  entered the retry branch and ended the hold on the payment details).
  test_telegram_pager 796; six anchors.
- FOUND on the third read: a forward the vault reached EARLY -- the Pi
  saw the deposit at its confirmation count, the vault's own server (a
  different one, over Tor) still had it `arriving` or `not_yet` -- came
  back with the entry `seen` and no wait, so `_btc_apply` started it again
  the very next tick, and the next, each a wake off the day's budget,
  until the two servers agreed. Now such a return sets `early_tries` and a
  wait (`EARLY_WAIT_S`, twenty minutes, doubling to eight times) that the
  tick honours as a background start; a done run clears it; a tap sets no
  wait. test_telegram_pager 804; three anchors.
- FOUND on the third read, the worst of the pass: money that CAME BACK to
  the deposit address was sent on again with no bound. Right once -- a
  limit the price moved past while the forward confirmed, re-quoted -- and
  ruinous for a route that refuses: ThorChain refunds a swap it will not
  run, less its outbound fee, the refund is settled by the next recheck
  (three hours), the reconciliation forwarded it into the same swap, and
  the chat heard "sent" each time, a network fee and an outbound fee per
  round, until the deposit was gone. Nothing proves ThorChain routes XMR
  before mainnet does, so the FIRST mainnet deposit could have gone this
  way, automatically. Now `--returns-max` (paired as `--btc-returns-max`,
  default 2, on the keyfile like the bump window): past that many forwards
  of returned money in the deposit's plan chain (`reconcile_reason`,
  counted once per txid), the next return is written on the plan as
  `returned_kept` and the run is done -- nothing quoted, nothing signed --
  and the vault's word is a new phase, `kept` (WIRE_VERSION 9), read
  before `forwarded` so the Pi does not end its rechecks on "confirmed"
  about money sitting on the host's address. The Pi's entry becomes
  `kept`: not looked at, not rechecked, not retried, expiring with the
  sent ones; the tap asks the forward, which answers kept until the
  operator has moved the money by hand or re-paired with a higher bound;
  the chat hears the word's own sentence (no amount, no count, no coin, no
  reason), and `--alert-chat` hears once that a forward was stopped for
  another chat. Money returned past the bound does not ride in a bump's
  replacement either. Tests at all four ends; anchors; OPSEC_SETUP.
- Beside it: a refusal or a `delayed` on a kept entry leaves it kept (the
  retry branch put it back on the list as money to send on, a wake spent
  learning it is kept); and the operator's chat hears once when a refused
  forward's five automatic retries are spent (`stalled`) -- a refusal is
  not a failure, so nothing had told them the automatic path stopped on
  a confirmed deposit. test_btc_forwarder 274, test_wake_agent 740,
  test_telegram_pager 814; 679 anchors, 22 swept this pass.
- FOUND next to it: money that came back AFTER the forward mined was
  stranded. A `forwarded` entry was not looked at (the snapshot took
  not_seen and seen only), not rechecked (only `sent` is), and every tap
  on it went to the XMR side, "nothing yet" for ever -- while ThorChain
  refunds only once the inbound has confirmed, so a refund lands after
  `forwarded` whenever a tap or a recheck saw the block first; a second
  payment likewise. The `forwarded` branch even said "money that comes
  back to it can be watched again" and nothing did. Now a forwarded entry
  with an address is looked at while it is kept (a look is not a wake);
  money seen on it again is handled as the vault's `returned` word is --
  money seen, the forward the next ask, said and started as for a first
  payment when it settles, and kept by the vault past --returns-max. An
  entry learned after a restart has no address and is not looked at.
  test_telegram_pager 818; two anchors.
- ASKED (the user): can a refund be told from a re-deposit? It could not,
  and the difference mattered in one place: a refunded forward's swap
  never happened, yet `_reconcile_pairs` summed its quote into what the
  XMR watcher expects, so a deposit whose re-forward fully landed read
  "partial" for ever. Now `spends_of(with_funding=True)` also returns
  what PAID the address, each output with its transaction's memo and --
  for one whose memo claims `REFUND:` -- the address its first input was
  paid from (the previous transaction, fetched in the same session);
  `classify_returns` calls an output a refund when the memo names a
  forward of ours and it carries less than that forward sent, and
  VERIFIED when its source is the vault that forward paid or THORNode's
  current inbound (fetched only when something claims). Kerckhoffs
  throughout: the memo is a public convention anyone can write, the
  amount can be matched, only the source cannot be forged; a claim is
  recorded (`refunds` on the plan, kept on rotation) and changes nothing,
  a verified refund's forward drops out of the pairs sums, and when every
  forward was refunded nothing is rewritten (the deposit-time quote
  stands, never an expectation of nothing). The bound still counts every
  return (a refund whose memo shape changed must stay bounded); the kept
  mark says how many are verified refunds; the job log names each. The
  one new trust is THORNode's word on its own vault address, which the
  cross-check already sends the money on. test_btc_broadcast, forwarder,
  agent; six anchors.
- Checked and left alone: the forward's worst case over Tor (look,
  history, quote, oracle, THORNode, submit, seen, each bounded) fits its
  900 s budget; the quote-age bound (300 s) covers the cross-check's own
  circuit; Telegram's 48 h deletion window and the long-poll hold.
- Still only mainnet can prove: that THORChain routes XMR and takes this
  memo at all. Every stage's docs say so; nothing here changes that.

### After stage 6: the functionality pass (the weaknesses list, read end to end)
- Read: `Limits`, `start_job`, `_btc_can_start`, `_btc_apply`, the
  `delayed` branches, `btc_tick`'s recheck, `gs_btc_watch.look` (it fails
  over across servers per address, so "one server down means no deposits"
  holds only with one server configured), the vault's job log (truncated
  per boot, not a growth). Three fixes on the Pi, each with tests and
  anchors swept:
- **A reserve for taps.** `Limits.headroom()`; a start nobody asked for
  (a fee retry, a recheck) waits while `--btc-reserve` (default 2) or fewer
  of the day's courtesy pokes remain, so the automatic path cannot spend
  the last wake a client's question needs. A first forward of a confirmed
  deposit is not background. A held retry is silent (the chat heard the
  vault's `delayed` sentence); refused at startup at or above `--daily-cap`.
- **The fee retry backs off.** Each `delayed` in a row doubles the wait
  (`fee_retry_wait`: 1, 2, 4, then 8 times `--btc-fee-retry`, the count
  on the entry, cleared by any other answer). A day-long spike cost a wake
  an hour per deposit — two deposits was the whole budget on retries.
- **The operator hears a failed forward.** `--alert-chat` (allowlisted,
  refused otherwise): one numberless line, at most hourly, when a forward
  for some OTHER chat FAILED; nothing for the deposit's own chat, a
  refusal, or a done run. Kind `operator_alerted`.
- Counts: test_telegram_pager 785; 651 anchors, 12 swept (one survived on
  a test that looked only at other chats; tightened and re-swept).

### Stage 6: the forward after the send — a stuck forward is found and bumped, the reconcile is driven (`STAGE6_PLAN.md`)
- Planned first, after an end-to-end read of what stage 5 built, without
  trusting its tests (section 1 of the plan: four things left half-wired);
  built in six steps against the plan; section 8 is the self-doubt pass,
  which found six more and fixed them before the commit.
- The reconciliation is now DRIVEN: the Pi routes an ask about a sent
  deposit to the forward again past `--btc-recheck` (default three hours,
  floor 600) or at once after `unsure`, and when nobody taps the watcher
  starts that run itself, once per window per deposit, through the same
  gates as every wake (`forward_recheck` on the chain); `forwarded` (wire
  v8: the forward's transaction is in a block) ends the rechecks. An
  `unsure` answer no longer clears the once-per-window stamp (a network
  that keeps answering ambiguously cost a wake a tick), and a forward
  learned after a restart is put back on the list with its word and
  clock (before, the answer was learned into the sent set alone and the
  recheck was never due again — the original gap, reopened by a restart).
- The BUMP: a forward of ours listed in the mempool past `--bump-after`
  (keyfile `btc_bump_after_s`, `gs_wake_keys pair --btc-bump-after`,
  default two hours) at a rate under today's estimate is replaced — the
  same outpoints (spent whole: `must` inputs), added to the look from the
  plan (a server's listunspent hides what a mempool transaction spends),
  at today's rate over a floor that beats EVERY earlier signature of ours
  over those outpoints (`replacement_floor`, BIP125), quoted afresh for
  the amount and the current inbound, carrying money that came back and
  settled meanwhile, the new plan naming the old in `replaces`. The whole
  plan chain is scanned (`stuck_forward`), not the current plan alone: a
  forward can fall behind a later `returned` plan. The window is measured
  from the newest attempt over the outpoints. Over the ceiling:
  `bump_over_ceiling`, the word `delayed`, the original stands; rejected:
  the original stands.
- The rotation made safe: the old plan is rotated when the fresh plan is
  written, never before; a chain left without a current plan (stage 5's
  ordering: a refusal after the rotation) is recovered from its newest
  rotated predecessor (`plan_recovered`), moved back, not copied.
- The accounting: one swap per outpoint. The pairs rewrite drops a plan
  named in a counted plan's `replaces`, and — found in the self-doubt pass,
  a stage-5 bug — two plans that spend a common outpoint (an evicted
  original beside its re-sign, a rejected re-send beside its fresh forward)
  count once: the record the reconciliation named (`superseded_by` on the
  current plan, which counts even under a stale mark on its own rotated
  file), else the newest. A superseded plan records the superseder's
  height (`superseded_height`) and is `forwarded` once that one mines.
- Counts: test_btc_forwarder 261, test_wake_agent 721, test_telegram_pager
  761, test_wake_doorbell 165, test_wake_protocol 189; 641 anchors. The
  testnet drill gains act F (a replacement with `--bump-after 0` and the
  estimate forced one above the rate paid).

### Stage 5: what happens when it does not go to plan (`STAGE5_PLAN.md`)
- Planned first, after an end-to-end read of the whole money path done
  without trusting the tests (section 1 of the plan: what is real, what is
  mocked and said so, and nine gaps the working path hid); built in five
  commits; section 8 is the self-doubt pass.
- The invariant changed: not "once per handle" but one signature per
  OUTPOINT while a spend of it may be in the network. `btc_forwarder
  --reconcile` (a third mode, held to the sending mode's rules) is what
  the tap after a forward runs: `gs_btc_broadcast` gained
  `blockchain.transaction.get` (read-only, bounded, re-hashed) and
  `spends_of()` (the address's history, each transaction fetched in one
  session, the spends of its own outputs with their values); the run then
  confirms our transaction is listed (bringing the plan up to date,
  turning an ambiguous send into accepted, dropping kept bytes), re-sends
  kept bytes (a rejected re-send becomes a fresh forward at today's fee),
  re-signs an evicted forward, forwards money that came back leaving out
  what our listed forwards consumed (`returned` while it is not settled),
  adopts a listed spend with our memo the chain forgot, or FAILS on a
  spend that is not ours or a history it could not read. A fresh forward
  rotates the earlier plan aside: the plan chain is the record. An address
  that holds nothing unspent is read for its last spend on ANY run, so a
  forward that went out and died before its plan was written is
  reconstructed from the chain rather than answered "not yet" for ever.
- A refusal about today's fee is a word: `delayed` (cheaper blocks would
  carry it; the Pi retries after `--btc-fee-retry`) or `short` (even the
  floor rate could not; under what was quoted). The floor is honest: the
  larger of the forwarder's two guards at the ceiling
  (`gs_btc_tx.forward_floor_sat`), printed at pairing beside the ceiling.
- The XMR side judges the real swap: once a plan says the money moved and
  carries a quote, the pairs file the watching jobs read is rewritten to
  what was sent and what was quoted, the deposit-time figures kept beside
  it once.
- `--allow-btc-broadcast` requires `--thornode`, and the agent refuses a
  sending pair without one before any child; `--btc-account N` retires a
  chain (the forwarder derives that account and proves it against the
  xpub); an empty ledger behind a used address 0 is refused `ledger_wiped`
  with the next account named; intake records are never pruned.
- The pager: `delayed` keeps the deposit watched with a retry time,
  `returned` watches it again and unlearns the routing, a sent deposit is
  kept as `sent` (its address remembered for a refund) and forgotten after
  the reserve's window.
- Wire 7 (`delayed`, `returned`). Counts: test_btc_forwarder 219,
  test_btc_broadcast 96, test_btc_tx 101, test_wake_agent 691,
  test_telegram_pager 716, test_wake_endtoend 70, test_depo_wizard 434.
  The testnet script gains act E (`--reconcile` against the real history)
  and says which rows only a hand-driven second payment can prove.

### Stage 4: the deposit the client actually makes — a plain address, no note (`STAGE4_PLAN.md`)
- Planned first, built against the plan in six commits plus the self-doubt
  pass recorded in its section 8.
- The vault in BTC mode (`btc_account_xpub` on the keyfile; pairing couples
  it to `--deposit-in-chat`, because a phone-only client has nowhere else
  to read the address from, and to `--allow-btc-forward`, because an
  address nothing can send on from is stranded money by configuration):
  `receive_and_quote` refuses a deposit under the forwardable floor
  (`FORWARD_MIN_SAT` plus a one-input fee allowance at the ceiling rate)
  before any mint or look; allocates the next index one past the ledger's
  highest, asking the network over Tor whether each candidate has EVER been
  used (`gs_btc_broadcast.unused`, read-only, on the address's own
  circuit), stepping past a used one up to `BTC_INDEX_GAP` and refusing
  outright when nobody could be asked; records `btc_index` on the handle;
  builds a memo-less plain slip carrying the host's own derived address
  (`PLAIN_SHAPES`: two exact key sets, a third refused; `WIRE_VERSION` 6);
  seals nothing for a delivery machine in this mode. The xpub does NOT go on
  the Pi (the design's first draft put it there): it is the generator of the
  whole intake history, and a seized card would have yielded it in one
  string. The Pi is handed each open deposit's address in the slip and
  holds it in memory.
- The forwarder writes a one-word status file (`not_seen`/`seen`, nothing
  else in it) when it found nothing settled; the agent reports that run as
  DONE with `not_yet`/`arriving` rather than "the machine failed", and the
  record is not marked forwarded (no plan was written).
- The pager: `--btc-electrum` (repeatable), `--btc-min-conf`,
  `--btc-network`, `--btc-poll` (≥ 60 s), `--deposit-min-sat` on the command
  line, never on the card. The intake reply is one message (amount,
  address, label, "I will say here when it arrives and when it has
  confirmed. After that it moves on by itself"), registered on the watch
  list before it is sent. The watcher thread looks at every open address on
  its own circuit each poll, says "received" and "confirmed" once each,
  and starts `forward_to_swap` through `start_job` — only when the box can
  wake (the lock, the day's budget and the restart hold are read first; a
  confirmed deposit it cannot wake for stays `seen`, the chat hears why
  once, and the next tick retries; `start_job` now returns whether a wake
  started, and a refused start puts the entry back rather than leaving it
  "forwarding" for ever). A forward's `sent`/`unsure` closes the entry;
  `not_yet`/`arriving` reopen it; a refusal or failure marks it stalled and
  is said once with the button. The button and `/check` on an intake
  deposit ask the forward — on a watched handle, and after a restart on
  every handle of a pager that declares the intake, because the XMR-side
  probe cannot move bitcoin and would answer "nothing yet" for ever about
  money on the host's address. Once the forward has gone out the ask is the
  XMR side's again: the vault answers a sent handle's forward run with
  DONE and the plan's word (`sent`/`unsure`) instead of refusing — no
  child, nothing signed — and the pager learns the sent handles from those
  answers and routes to `swap_status` from then on. `/balance` lists the
  chat's own watched deposits by label and state with the figures the chat
  already saw; every new sentence is in the banned-word scan. A deposit
  nothing has reached for `DEPOSIT_PLACE_TTL_S` is dropped from the list
  (the reserve's own window), so a never-paid address is not looked at for
  ever.
- Counts: test_wake_agent 669, test_telegram_pager 704, test_depo_wizard
  434, test_plain_slip 232, test_btc_forwarder 168, test_btc_broadcast 83,
  test_wake_doorbell 161, test_wake_endtoend 70. 36 new anchors (530–565),
  all caught — the sweep tally is in the commit message.

### Stage 3: broadcast over Tor — the forward leaves the machine (`STAGE3_PLAN.md`)
- Planned first (`ed6a087`), built against the plan in three commits.
- `gs_btc_broadcast.py`: the ONE method that moves bitcoin, as a subclass
  of the stage-1 watch client in its own file. The Pi's module still names
  no such method and its three source tripwires are unchanged. `submit()`
  hands the signed bytes to the configured servers in turn, on the
  address's own broadcast circuit (`btcsend:`, never the look's), and
  answers one of four words: `accepted` (our txid came back), `rejected`
  (every answering server said no; numeric codes only, because ElectrumX
  echoes the node's reason and for a refused OP_RETURN that reason carries
  the memo), `ambiguous` (the bytes left and nothing accepted them: a
  hang-up, a foreign txid — the money MAY have moved), `unreachable` (no
  send completed). Across a list the word worse for money wins. A
  `PinMismatch` before any bytes left is raised; after, it is reported
  inside an `ambiguous` result so "may have moved" survives the signal.
  `seen()` polls the deposit address's history for the txid and tells "not
  listed" from "nobody could be asked". The watch client gained a
  structured `ServerError` and a shared `server_order()`; nothing else in
  stage 1 moved. test_btc_broadcast 72 (fake transport, and the real
  transport + subclass through an in-process SOCKS5 + TLS Electrum server,
  `tests/btcmock.py`).
- `btc_forwarder --broadcast`, xor `--dry-run`, one required (neither is
  still `not_dry_run`; both is a contradiction). A quote older than
  `--quote-max-age` (300 s) is refused before sending; the broadcast sits
  after every stage-2 guard including the real-rate floor; the outcome
  table drives the exit code — rejected: refused, nothing moved;
  unreachable: failed, nothing moved; accepted and ambiguous: exit 0,
  because "may have moved" must never render as "failed". The signed hex is
  kept in the plan only while the network has not shown it (`tx_hex_reason`
  unseen / ambiguous), or under `--write-signed-hex`; a seen broadcast
  keeps it nowhere. Plan schema v2. The relay strategy for the >80-byte
  memo is failover across the operator's servers (`STAGE3_PLAN.md` 3.3).
  test_btc_forwarder 162, including one forward through the REAL
  transport, subclass and forwarder against the in-process server, which
  computes the real txid of the hex it is handed.
- The wire: `PHASES` gains `sent` and `unsure` with numberless,
  machine-nameless sentences; `WIRE_VERSION` 5. `_phase_of` for a done
  forward reads the plan through `_forward_outcome` (never raises; the two
  plan fields must agree). The ledger marks `forward_sent`; a SENT handle is
  refused `already_forwarded` in every mode, a rehearsed one may be followed
  by a sending run and by nothing else. `allow_btc_broadcast` is the second
  keyfile switch (validated as a boolean, never coerced; absent means
  rehearsal), `--allow-btc-broadcast` at pairing is refused without
  `--allow-btc-forward`. The doorbell and the pager render the word's own
  sentence, or the rehearsal line without one.
  Counts: test_wake_agent 641, test_wake_endtoend 64 (rehearsal, second
  rehearsal refused, a sending run superseding it with `sent` on the wire,
  a second sending run refused), doorbell 161, pager 653, plain_slip 225,
  depo_wizard 432, multi_client 93, protocol 189, sealed_slip 125,
  stability 50, chain_redaction 207.
- `tests/real_btc_forward_testnet.py`: the real forwarder against real
  testnet over real Tor with only the quote stubbed; skips without the
  three environment variables, so this sandbox (no Tor, no egress) runs its
  skip path only. Its header says what it cannot prove: that THORChain
  takes the memo — only mainnet does.
- **Self-doubt pass over the stage, after the first sweep:** (1) `seen()`
  polled the same server that had just accepted the transaction first, so
  a server lying about acceptance could also vouch for propagation; it now
  takes `avoid=<accepting server>` and starts elsewhere when there is
  anywhere else. (2) The once-sent rule trusted the ledger alone; a crash
  between the child's exit and the ledger mark would have let the next
  wake sign a conflicting spend. `_dispatch` now reads the plan on disk
  too. One anchor had produced NO-RESULT (a test crashed on a None result
  instead of going red); the test was hardened so the crash is a catch.
  Final counts: test_btc_broadcast 75, test_btc_forwarder 163,
  test_wake_agent 642.
- 24 stage-3 anchors plus three stage-2 anchors re-pointed by the flag pair
  and the plan fields, all caught.
- Two hygiene tripwires the new files tripped, fixed: the console's
  `compile` action names every shipped script and now names
  `gs_btc_broadcast.py` (test_console 491); test_concurrency required
  `--no-zmq` of every `real_*_testnet.py`, which assumed every such suite
  launches monerod -- the rule is now scoped to suites that do, with a
  non-vacuity check that it still covers them (52).
- Not closed, on purpose: confirmation depth, a transaction dropped from
  mempools, the fee bump, a reorg of the input, and re-sending a kept
  transaction — stage 5. The custody window is now real money in flight.

### Stage 2: `forward_to_swap` — build and sign the forward, print it, spend nothing (`STAGE2_PLAN.md`)
Planned first (`030adbb`, the plan file), then built in the plan's order.
Three code-mapping passes preceded the plan and corrected four things the
design doc assumed existed: there is no ThorChain-native code (the repo talks
to SwapKit and the inbound vault arrives inside a quote route); the repo never
builds a memo and does not need to (the quote returns one bound to our
destination, validated by `memo_binds_destination`); `memo_will_overflow` was
cited in two docs and defined nowhere; and there was no BTC fee estimation,
dust constant, OP_RETURN builder or coin selection.
- **The blocking constraint, measured:** a Monero subaddress is 95 chars, so
  the shortest swap memo is 105 bytes against the 80-byte standard OP_RETURN.
  Every real forward is over. Not new (the client-paid flow only warns); now
  the host's problem, which is better. `btc_forwarder` refuses on the default
  policy with the byte count; `--op-return-max-bytes` is the operator's relay
  policy; THORName rejected on the record for linkability. Stage 3 chooses the
  relay strategy.
- `gs_common`: `memo_will_overflow`, `memo_bytes`, `DUST_SAT_P2WPKH` (294,
  not the P2PKH 546), `electrum_fee_to_sat_vb` (rounds UP, never 0, -1 → None);
  `btc_forward_*.json` in the wipe patterns.
- `gs_btc_tx.py` (pure, no network): OP_RETURN laid out literally (embit's
  `Script.push` is CompactSize and malformed above 75 bytes — where every
  real memo lives); `address_script` accepts only this network's native
  segwit (embit's converter tries every network and returns None on base58
  it cannot place); `build_unsigned` passes fresh lists (embit's mutable
  default `vin=[]` is shared), RBF on every input, refuses duplicates, a
  zero non-data output, outputs over inputs; `sign_input`/`sign_p2wpkh` use
  the BIP143 SCRIPT CODE (P2PKH form), clear the sighash cache, refuse
  without the constant-time backend, and verify every signature before
  returning; `measure` computes vsize (the library has none);
  `vsize_upper_bound` sizes the fee before the memo is known;
  `account_from_mnemonic` / `account_matches_xpub` (key + chain code, depth
  3, xpub or zpub encoding) / `key_for`. `tests/test_btc_tx.py` 70/70:
  BIP143's native-P2WPKH vector reproduced BYTE FOR BYTE — script code,
  digest, the RFC6979 signature, the witness, the entire final tx; the
  75/76 push boundary; vault derivation meets the Pi's on the BIP84 vector.
- `gs_btc_watch.py`: `Electrum.estimate_fee` and `look(..., fee_blocks=)`,
  a fourth read-only method in the same session and circuit (220/220).
- `btc_forwarder`: look → fee against the largest transaction the policy
  allows (resolves the fee/amount/memo circularity without a loop; the real
  rate is ≥ target, the slack goes to the miner) → `send = settled − fee`
  (refuse if the fee eats > 20% or send < 10,000 sat, ThorChain's BTC dust)
  → SwapKit quote for EXACTLY that amount, `fmt_btc` not `str(Decimal)` →
  inbound (this network's native segwit, checksum), memo (printable, bound
  to our destination, fits the policy), expected (worst case ≥ mix floor,
  within `--max-slippage` of the oracle) → optional THORNode cross-check on
  a second circuit (address must match, chain not halted, live dust) →
  build → seed from `GS_BTC_SEED` only (removed from the environment once
  read), proven to derive the watched xpub and the exact address → sign,
  verify, measure → 0600 plan file with `broadcast: false`, `--dry-run`
  required, `--plan-only` needs no seed. No broadcast code exists.
  `tests/test_btc_forwarder.py` 87/87 through the real `main()`: the signed
  tx verified independently against the test's own derived key; every
  refusal by kind; the seed in neither file nor output; chain kinds carry no
  digit.
- The job: `forward_to_swap {handle, owner}` in `JOBS`, `SPENDING_JOBS`
  (deadman extension) and `btc_forwarder` in `GATED_TOOLS`; `WIRE_VERSION`
  4 (a changelog, not a check — an old vault refuses the unknown name);
  `gs_wake_agent`: argv composed from the keyfile + the ledger's `bundle`
  and `btc_index`, per-job spending switch (`allow_btc_forward`, never
  `allow_withdraw`), owner wall, spent → `already_moved`, no index →
  `no_btc_deposit`, seed injected into that one step's environment
  (`btc_seed_unset` otherwise), the plan named for the deposit's handle;
  `gs_wake_keys` pairing flags (`--btc-xpub`, `--btc-electrum`,
  `--btc-network`, `--btc-min-conf`, `--op-return-max-bytes`, `--thornode`,
  `--allow-btc-forward`); `CHAT_NAME` "forward"; OPSEC_SETUP's five jobs.
  Four tripwire tests updated by design; the forward's dispatch driven end
  to end (test_wake_agent 590/590, test_wake_protocol 189/189).
- **Adversarial review of stage 2** (eight lenses, three refuters per
  finding, 27 raised, the real ones fixed end to end):
  *Money:* a mined-but-shallow output (1 conf under a 2-conf policy) was
  spent while not counted, so its whole value would have gone to the miner
  — inputs are now selected by per-output depth AND worth (the dust-storm
  defence: two hundred 546-sat outputs no longer strand a deposit), and the
  built fee must equal the sized fee (`fee_mismatch`). The memo's own terms
  are read: a zero or missing output limit (a swap at ANY price) and a limit
  under the worst-case arrival are refused, as is an affiliate skim over
  `max_affiliate_bps` (default 0). A hex-encoded memo — which the shared
  validator accepts — is refused rather than embedded as hex text. The fee
  fraction fixture was over 100% (the 20% guard was never deciding); fixed
  and the boundary pinned. The fee bound's 34-byte inbound allowance is now
  exercised with a P2WSH vault. `build_and_sign`'s three guards are driven
  directly. *OPSEC:* a done forward re-shipped the DEPOSIT's slip (address,
  amount, memo naming the XMR destination) to the phone — only the quoting
  job has a slip now; the xpub (the generator of every deposit address) and
  the index moved off the 0444 argv into the step's environment; the signed
  bytes are no longer persisted in the plan file by default (a bearer
  instrument with no consumer yet; stdout/job log instead, `--write-signed-hex`
  for stage 3's consumer); a done forward marks its record and a repeat is
  `already_forwarded`; the plan is retired with the handle. *Reachability:*
  the host (a hand-poked note) may forward a client's deposit; a client token
  is still walled. *Rendering:* the doorbell and the pager say "signed,
  nothing sent" for a done forward, never deposit vocabulary. *Config:* the
  keyfile's BTC settings are validated at pairing with the forwarder's own
  functions (`_validate_btc`) and never coerced by the agent
  (`btc_config_malformed`); the fee band and affiliate cap are keyfile
  fields; `GS_SWAPKIT_API_KEY` reaches the step; a 401 from the aggregator is
  `quote_refused`, not a bare exit. *Docs:* the unit file and OPSEC_SETUP
  carry `GS_BTC_SEED`, the passphrase, the aggregator key and the
  libsecp256k1-1 requirement; the vendored ctypes loader no longer searches
  inside the package for a blob. *E2E:* the forward runs through the real
  doorbell + real agent over real HTTP (a done forward of the handle the
  first cycle minted; `already_forwarded` on the repeat).
  Counts: test_btc_tx 73, test_btc_forwarder 116, test_wake_agent 621,
  test_wake_doorbell 159, test_telegram_pager 651, test_wake_endtoend 59.
- 33 mutation anchors over the money guards and the OPSEC rules, all caught;
  two pre-existing anchors re-pointed.
- **Self-doubt pass over the review's own fixes:** the "refuse a zero or
  missing output limit" rule was wrong against the real world. THORChain's
  own example memo is `:0/1/0` and aggregators quote the limit as 0 (or omit
  it) routinely; the rule would have refused most real quotes. Replaced by
  SETTING the limit: the forwarder lays the OP_RETURN out itself, so
  `enforce_memo_terms` writes its own floor (99% of the worst-case arrival,
  in 1e8 base units) into field 3 whenever the quote's limit is absent,
  zero or lower; a higher quoted limit is kept as written; one above the
  quote's own expected output (a certain refund, minus fees) or a
  non-numeric one is refused (`memo_bad_limit`). Only the limit is touched;
  `fit_memo` re-binds the destination and measures the FINAL bytes. The
  plan records `memo` (as laid out), `memo_quoted` and `memo_limit_set`.
  test_btc_forwarder 133; six new anchors (rewrite, ceiling, rounding
  margin, re-bind) plus the re-pointed overflow anchor, all caught.
- Deferred on purpose: no real handle carries `btc_index` until stage 4
  mints addresses (the job refuses `no_btc_deposit` on a live box); the
  pager has no command that starts a forward (stage 4 decides who may; the
  host can by hand today); broadcast, which consumes the plan and clears
  the mark, and the relay strategy (stage 3); stage 4's deposit minimum must
  be `FORWARD_MIN_SAT` plus a fee allowance, not the typo guard.

### `cd3c1f9` — Design: BTC intake by unique address, host-side forward into the swap
- `BTC_INTAKE_DESIGN.md`: the blueprint for the rework (section 4 below).
  Design only; nothing ships from it until each stage is validated.

### `c63ca93` — Plain words on the three working lines and the deposit reply
- Working lines lost their filler. Now:
  `depo: getting your payment details now. They come here. Nothing else can
  run for up to {how}.` / `check: checking now. I will tell you here. Nothing
  else can run for up to {how}.` / `withdraw: sending now. About {N}h. I will
  tell you here when it is done — you can close this. Nothing else can run
  for up to {how}.` "Nothing else can run" stays in every variant (the chain
  tests count it once per chain; it is what makes the next "busy" read as
  expected).
- Deposit reply opens `here is how to pay.` The receipt's `Expected out`
  reads `You get back`. The instruction lines: `The code above is the note
  for this payment — add it to the payment. Most phone apps CANNOT add a
  note, and without it the money never arrives.` and `Pay it once. Never send
  to this address again — a second payment, now or later, loses the money.`
  Trailer: `When it is paid, tap below or /check that number — it tells you
  when the money has arrived. Then /withdraw sends it on.` The two mutation
  anchors on the instruction sentences follow; the OPSEC doc's transcript
  example follows.

### `58a1392` — Say why the note matters; say "received" when money is in but not yet spendable
- `arriving` phase line: `received — waiting for it to confirm. Not spendable
  yet; ask again shortly.` (was "something arrived and is still confirming",
  which made a reader ask what "something" was).
- The phone warning now states its reason (the note is what makes the money
  arrive) instead of ordering. Verified first that `/deposit` already asks
  the amount + a confirm sum and `/withdraw` already asks the destination
  address(es), the depth, and a confirm that says it spends — the bot was
  never skipping those; the load-model page's simulation was, and it was
  republished walking the real wizard.

### `a9976f0` — Deposit reply: lead with the payment, say the two rules in two sentences
- The reply used to open `pay this. Confirmation number: A3F1-9C2B7E01`, so
  the first thing a reader with money in hand saw was a reference code where
  they expected the thing to pay, then the same code again four lines down.
  The receipt now leads with amount and address; the number is one line of
  the receipt.

### `767909b` — Deep-read pass: leaked locks, hot loops, chain floods, racing saves
An end-to-end read for half-wired / unstable code. Every fix is driven by a
staged failure in `tests/test_stability_pass.py` (50 checks) and pinned by
18 new anchors, all caught.
- **Pager.** `start_job` owns the ONE release of `busy` through an ownership
  flag (`_give_back`): a chained leg whose gate raised (integrity_log on a
  full SD card) used to keep the lock for the life of the process, and
  releasing from the worker's except could free a lock the poll thread had
  just taken. A failed start clears the persisted in-flight bit as well as the
  lock. Silent refusals (stranger chats, non-operator senders, unknown
  commands, id-less updates) count every one but reach the hash chain at most
  once per kind per 10 minutes (`_log_ignored`, `IGNORED_LOG_EVERY_S=600`) —
  a stranger could put thousands of lines on the card in an hour. A
  getUpdates batch that cannot advance the cursor (all chaff, or a dict with
  no id) waits one poll period instead of spinning. `burn_all` is capped at 32
  deletes per tick and re-arms as a continuation; "burn_signal" is chained
  once per signal, not once per pass (a dead circuit re-armed it every tick).
  `Limits` (the one persisted file) is written under one re-entrant lock from
  both threads, in-flight bit and window as one picture; `why_not` treats a
  backwards clock jump (Pi has no battery clock) as elapsed. The second
  label-backoff site is exponent-capped (`60.0 * 2**1030` raised
  OverflowError and turned a chat's every later /check into "update
  dropped"). `_places` and `handle_owner` are walked from snapshots under a
  lock.
- **Vault.** `main()` remembers a `Refused(power=False)` instead of
  re-deciding from a hand-typed pair of codes at power-off (the box a person
  is using stays on). The accounts a mix minted are asked for three times
  before giving up, and an unreadable answer is written to the chain and the
  terminal rather than silently leaving the owner's change unattributed. A
  failed withdrawal shreds its entry bundle (it named the account it spent
  from) like a finished one; the fee sweep retires its bundle on the failed
  leg and after the last. The status file is unlinked once reported; the
  withdrawal minimum comes from the wire's depth table, not a duplicated
  literal.
- **Shared.** `integrity_log` reads the chain's last hash from the file TAIL
  in 4 KiB steps instead of reading and splitting the whole chain on every
  call. `atomic_write_json` gives each write its own `mkstemp` name beside
  the file (two writers of one path could truncate each other's tmp and
  rename an empty file over the real one).
- Test-side: a corrupted test file with an unterminated string literal was
  repaired before commit; a fee-kind pin that matched a name only a comment
  still carried now asserts the three real kinds.

### `30f94fa` — Give a phone-only client something to pay: the note travels, first and checked
- With `--deposit-in-chat`, the memo (the note) travels in the plain slip
  (`PLAIN_FIELDS` includes `m`), is sent as its own message FIRST and ALONE so
  a tap-and-hold copies it cleanly, with one retry; if it does not get
  through, the chat hears "nothing to pay yet" and the address is NEVER sent
  (an address without its note is a trap, not a partial delivery). The vault
  re-checks `memo_binds_destination` before building the record. The
  doorbell's console prints the note first too. OPSEC_SETUP.md §8 documents
  the mode.

### `c2656ec` — Serve several people on one vault: owner tokens, places, "busy" and "full"
- **Fund isolation.** Owner token on every job; a vault ledger (`handles` +
  `owners` envelope) of which wallet ACCOUNTS each owner's deposits and mixes
  created; `_funded_entry(owned_accounts=)` and `_locked_value(owned_accounts=)`
  never leave that set; `_reusable_receive` never hands one owner's unquoted
  address to another; a /check on someone else's label is refused on both
  boxes.
- **Capacity.** `--max-clients N` = places (deposits in flight); the
  allowlist may be longer; `_places()` prunes after `DEPOSIT_PLACE_TTL_S`
  (2 days) without a sign of life; beyond the cap a newcomer hears the
  protocol's own `full` sentence from the Pi's memory with no wake spent.
  The vault enforces its own reserve: `accounts_now + 30 × (in_flight + 1) ≤
  account_ceiling` (`at_capacity`), where 30 = one receive account + the
  deepest mix's outputs + decoys + carrier + change sweep. The one-person
  rule fires only on a bot configured for one. A chain yields its turn when
  anyone was refused during it. Shared `--daily-cap` and `--min-interval`
  across chats, with a startup note when the cap is too small for the places.
- **Honest number.** Capacity is derived, not "10": the smallest of accounts,
  wakes-per-day, and wall clock. At the shipped defaults it is ONE; sized per
  OPSEC_SETUP.md §4f it is three or four before withdraw queues run to days.
  The artifact "Places on One Vault" visualises this from the shipped
  constants and simulates people walking the real wizard.

### `f580584` and earlier — the earlier phases (summarised)
- Deposits tracked through to `spent` (pair kept, files shredded); the pager
  holds every command through a restart while a wake may still be running
  (persisted in-flight bit + window); the fee sweep's dead-man backstop armed.
- Hot fee wallet with a threshold sweep; the fee never lands on the mixing
  wallet from any path.
- OPSEC leak closure: machine names, paths, amounts and architecture words
  scrubbed from every chat literal, the hash chain redacted, the Pi's disk
  reduced to one coarsened file; sealed-slip delivery for a second machine.
- Button / instability / stale-value / fake-wiring fixes across the pager and
  console; service-lifecycle pass; half-fix audits after each phase.

### Validation state at the end of the session
- 40 of 40 suites green on the last full run; `tests/test_btc_embit.py` adds
  a 41st, 30/30.
- 447 mutation anchors match the sources; every new anchor is caught.
- One lesson recorded: the end-to-end suite and the pager suite both bind the
  doorbell's fixed LAN port, so running the mutation sweep concurrently with
  a full suite run produces spurious failures. Serialise them.

---

## 3. What the chat says now (so nobody re-derives it)

The `/deposit` wizard: `How much? Reply with the amount — for example 0.05.`
→ `Deposit 0.05. Confirm and it starts.  a + b = ?` → working line → the note
alone → the "here is how to pay" receipt. A typed `/deposit 0.05` is refused
("just /depo — it asks").

The `/withdraw` wizard: `Where do you want it? Reply with the address.`
(one to seven, validated by the protocol's address gate) → `How deep?` (3, 10
or 20 hops — the speed-and-cover choice) → a confirm that says it SPENDS →
sum → working line → `withdraw: sent. It is on its way to your addresses.`
plus one of: another is starting / more remains / still unlocking / nothing
more was found.

Refusals a client can hear: `busy… try again in about T` (the Pi's own
ceiling on the running job, never whose), `yours is still running`, the `full`
sentence, `wait Ns`, `daily limit reached`. What one client can learn about
another: that the vault is busy for up to about T, and that the service is
full. Not who, how many, what kind of job, or a queue position.

---

## 4. The BTC-intake rework (in progress) — see `BTC_INTAKE_DESIGN.md`

**The ask, in the operator's words.** The client pays a plain, unique BTC
address the host owns — any phone can pay a plain address, no note — and the
host forwards it into ThorChain, attaching the swap memo itself. Unique
address ⇒ the host auto-detects the arrival ("received") and can carry a
per-person balance. "Forward" means **start the mix**: the swap lands XMR on a
fresh receive subaddress and the existing pipeline runs; the final send to the
client's own address stays `/withdraw`.

**Why the note cannot simply be dropped today.** ThorChain's BTC inbound is a
SHARED address for every user on earth, and the memo is the only thing that
routes a payment. That is ThorChain's design, not a code choice; no code here
can make it hand out a unique BTC address per person. The unique-address model
IS native to Monero (subaddresses), and the vault already mints one per
deposit — as the swap's destination. Moving the note to the host means the host
receives the BTC and forwards it: the build below.

**The insight that makes it fit the off-by-default vault.** Split it across
the two boxes the way everything else here is:
- **Pi — watch-only.** Holds a BTC **xpub only** (no spend key). Derives a
  fresh address per deposit (BIP32 public derivation, index bound to the
  handle) and watches the chain for a payment to that one address. A seized
  Pi can watch, never spend.
- **Vault — the seed and the signing.** Holds the BTC seed. Forwarding is a
  new woken **job** (`forward_to_swap`), exactly like a withdrawal: sign one
  BTC tx paying ThorChain's *current* inbound with the memo in an OP_RETURN,
  broadcast over Tor, power off. The seed signs only while awake.

**Decisions taken (by the operator, or delegated and taken):**
- Model: host-side BTC intermediary (not XMR-direct, not keep-as-is).
- Chain source: **Electrum protocol over Tor, one fresh circuit per address,
  watch-only** as the default; **own node / Electrum server** as the
  zero-third-party upgrade. Tor removes the IP/identity leak entirely; the
  residual is *content correlation* against a third-party server, kept weak
  by per-address circuits or removed by a private node. A block-explorer REST
  API over Tor works but is the weakest private option, not the default;
  over clearnet it is never acceptable.
- Library: **embit 0.8.0**, vendored and trimmed, the system's constant-time libsecp256k1 preferred with a pure-Python fallback for the watch-only side, pinned, provenance
  recorded (stage 0, done). Hand-rolling elliptic-curve signing for real money
  is forbidden.

**Hazards named, not glossed:**
1. Custody between receipt and forward (minutes to hours): a theft target
   and the legal posture of a money transmitter. Accepted deliberately.
2. Hot key at rest on the auto-unlocking vault: mitigated by the box being
   off/sealed at rest, signing only during a woken job, and sweeping the
   receive path empty per forward; a separate air-gapped signer is a later
   option.
3. The rate floats to forward time; "you get back ~X" is an estimate that
   settles at forward and must be reconciled.
4. The 80-byte standard OP_RETURN limit that a 95-char XMR address plus the
   swap prefix exceeds — the repo already flags it (`OP_RETURN_STD_BYTES`,
   `memo_will_overflow`); the forward must use ThorChain's supported
   long-memo path (or a THORName/short memo).
5. Confirmation wait before forwarding (double-spend), N configurable.
6. Dust and fees: refuse up front with a stated minimum, never strand.
7. ThorChain inbound churn: fetch the current inbound at forward time, over
   Tor, never cached.
8. The on-chain footprint moves: the client's gets cleaner (plain address, no
   public memo naming the XMR destination); the host gains a new one (host
   address → ThorChain, memo on the host's tx).

**Wire and schema changes to come:** BTC seed + derivation path +
confirmation threshold + dust/fee floors in the vault keyfile (sealed like the
XMR key); xpub + Electrum/Tor config in the Pi keyfile; new `JOBS` entry
`forward_to_swap {handle, owner}` with tool `btc_forwarder`; `WIRE_VERSION`
bump; `/deposit` returns a unique address with no note and no phone warning
in this mode; auto received → confirmed → forwarding; per-owner `/balance`
gated behind the same plaintext opt-in as the deposit surface (an amount is
rule-6 material).

### Stage status

| # | Stage | State |
|---|-------|-------|
| 0 | Vendor embit, trimmed to the used surface, constant-time system libsecp256k1 preferred (pure-Python fallback for watch-only), proven with BIP32/BIP84/BIP173 known-answer vectors | **DONE** — landed `8c86548`, reworked in the commit that follows |
| 1 | Watch-only derivation + Electrum-over-Tor detector: xpub → unique address per handle; per-address circuit isolation; per-OUTPUT settlement (`listunspent`, `settled_sat`, `utxos` with depth); fail-closed SOCKS5; one deadline; optional TLS pin; no keys, no money; tests | **DONE, REBUILT** — `gs_btc_watch.py`, `tests/test_btc_watch.py` 213/213, 18 anchors all caught (`9f19781`, `2cc59ea`, and the third-round commit) |
| 2 | `forward_to_swap` job: build + sign the BTC tx (every settled output of the deposit address, inbound from a forward-time SwapKit quote, the quote's memo in an OP_RETURN laid out with OP_PUSHDATA1, no change), `--dry-run` required and no broadcast path exists; seed from `GS_BTC_SEED` only; constant-time gate; `WIRE_VERSION` 4; `allow_btc_forward` switch | **DONE, dry-run only, reviewed** — `gs_btc_tx.py` (test_btc_tx 73/73, BIP143 byte for byte), `btc_forwarder` (test_btc_forwarder 133/133; the memo's output limit is SET by the tool, never trusted), job wiring (test_wake_agent 621/621, test_wake_protocol 189/189, test_wake_endtoend 59/59 over real HTTP), 39 anchors all caught; `STAGE2_PLAN.md` is the record. Testnet moves to stage 3 with the broadcast |
| 3 | Broadcast over Tor; "seen" in the network as the proof; testnet end-to-end on a box with Tor; reorg edges and confirmation depth moved to stage 5 | **BUILT** — `gs_btc_broadcast.py` (test_btc_broadcast 75/75), `btc_forwarder --broadcast` (test_btc_forwarder 163/163, one forward through the real transport + real subclass + real forwarder against an in-process SOCKS5+TLS Electrum), wire v5 with `sent`/`unsure`, `allow_btc_broadcast`, the ledger's `forward_sent` and the once-sent rule (test_wake_agent 642, test_wake_endtoend 64, doorbell 161, pager 653), `tests/real_btc_forward_testnet.py` (skips here), 24 new anchors all caught; `STAGE3_PLAN.md` is the record |
| 4 | Deposit UX: unique address, no note, auto received→confirmed→forwarding, per-owner `/balance` (gated); pager + doorbell + doc; banned-word and currency scans extended | **BUILT** — the vault mints a fresh, network-verified address per deposit and a memo-less plain slip (wire v6, two exact shapes); the Pi watches it in memory (the xpub never goes on the card), says received/confirmed once each and starts the forward through the one wake path when the box is free; the button and `/check` on an intake deposit ask the forward, after a restart too; `/balance`; pairing couples `--btc-xpub` to `--deposit-in-chat` and `--allow-btc-forward` (test_wake_agent 669, test_telegram_pager 704, test_depo_wizard 434, test_plain_slip 232, test_btc_forwarder 168, test_btc_broadcast 83, test_wake_endtoend 70), 36 anchors all caught; `STAGE4_PLAN.md` is the record, its section 8 the self-doubt findings |
| 5 | Failure handling + floating-rate reconciliation: fee spikes, dust/minimum refusal, forward failure + retry, reorg, reconcile the real swapped-out amount; full suite + anchors green | **BUILT** — `btc_forwarder --reconcile` (listed / re-send / re-sign evicted / forward returned money / foreign spend fails; the plan chain; one signature per outpoint), fee refusals as `delayed`/`short` with the Pi retrying, an emptied address read for our own forward, the pairs file rewritten to the real swap, the honest floor, `--thornode` required to send, `--btc-account`, `ledger_wiped`; test_btc_forwarder 219, test_btc_broadcast 96, test_btc_tx 101, test_wake_agent 691, test_telegram_pager 716, test_wake_endtoend 70; `STAGE5_PLAN.md` is the record |
| 6 | The forward after the send: the reconciliation driven by the Pi (a recheck window, an automatic recheck once per window, `forwarded` ending it), a stuck forward found on the whole plan chain and replaced (RBF) at today's rate over a floor that beats every earlier signature, the rotation made safe and a chain without a current plan recovered, one swap per outpoint in the pairs file | **BUILT** — `btc_forwarder` (`stuck_forward`, `replacement_floor`, `with_plan_inputs`, `_recover_plan`, `--bump-after`), `gs_wake_agent` (`forwarded`, `_forward_mined` over the superseder too, the pairs rewrite one-swap-per-outpoint, `--bump-after` from the keyfile), `gs_wake_keys pair --btc-bump-after`, `gs_telegram_pager` (`--btc-recheck`, `_recheck_due_entry`, the recheck in `btc_tick`, the entry learned back after a restart); wire v8; test_btc_forwarder 261, test_wake_agent 721, test_telegram_pager 761; 641 anchors; `STAGE6_PLAN.md` is the record, its section 8 the self-doubt findings |

Each stage is validated before the next. Mainnet is not touched until every
stage is green on testnet and reviewed.

---

## 5. How to run and check things

- One suite: `python3 tests/test_X.py`. All of them: loop over
  `tests/test_*.py` and read each `RESULT:` line (five suites print
  `<name>: N passed, M failed` instead of `RESULT:`; they are not failures).
- The BTC library proof: `python3 tests/test_btc_embit.py`.
- Mutation sweep: `cd tests && python3 mutation_sweep.py` (all) or with index
  arguments for a range; verify every anchor still matches its source with
  `anchors_ok(list(enumerate(MUTATIONS)))` — an empty list means all match.
- The vendored library imports from `third_party/` (tests insert it on
  `sys.path`); it has no external dependencies.
- The load-model artifact can be rendered headlessly with Playwright
  (`NODE_PATH=$(npm root -g)`, Chromium at `/opt/pw-browsers`) to check for
  JS errors and that the simulation walks the wizard.
- Do not run the mutation sweep and a full suite run at the same time (port
  collision, see section 2). The sweep copies the whole repository once per
  mutation (`shutil.copytree`), so do not edit any file in the repository
  while a sweep is running: a half-written file lands in the copy and the
  verdict is about nothing. A test on a mutated copy must read RED, never
  die: a crash is NO-RESULT, so tests read with `.get`/`getattr`/`str.find`
  rather than indexing what the mutation may have removed.

## 6. Standing rules for this branch (do not drift)

- Develop only on `claude/phone-withdrawal-destinations-ey6ovb`; never push
  elsewhere without being told.
- No pull request unless explicitly asked.
- No model identifier in commits, code, comments, or any pushed artifact.
- The operator's email is identity-only; never send it to any service.
- Confirm before destructive or outward-facing actions.
- Rule 6 on every chat surface; Kerckhoffs everywhere.
- No hand-rolled cryptography for money: vetted, vendored, pinned only.
- No half-wired features: a stage is not done until it is driven by tests and
  its anchors are caught.

## 7. Residual risks worth carrying forward

- Capacity is genuinely small; a vault sized per §4f serves three or four
  people in flight before waits run to days. More vaults are the only way
  past that.
- The BTC intermediary, once built, makes the host a custodian and gives it a
  BTC footprint it does not have today. Both are accepted on purpose; the
  design records the mitigations.
- The note-first, address-only-if-note-landed rule is the one property of the
  current deposit path that must survive any UX simplification; it was
  removed once, made the phone-only mode a trap, and was restored.
