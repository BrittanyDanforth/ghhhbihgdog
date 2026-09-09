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
- 16 mutation anchors over the money guards, plus two pre-existing anchors
  re-pointed (the gate line changed; the mix-floor argv line was matched
  twice).
- Deferred on purpose: no real handle carries `btc_index` until stage 4
  mints addresses (the job refuses `no_btc_deposit` on a live box);
  broadcast and the relay strategy (stage 3).

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
| 2 | `forward_to_swap` job: build + sign the BTC tx (every settled output of the deposit address, inbound from a forward-time SwapKit quote, the quote's memo in an OP_RETURN laid out with OP_PUSHDATA1, no change), `--dry-run` required and no broadcast path exists; seed from `GS_BTC_SEED` only; constant-time gate; `WIRE_VERSION` 4; `allow_btc_forward` switch | **DONE, dry-run only** — `gs_btc_tx.py` (test_btc_tx 70/70, BIP143 byte for byte), `btc_forwarder` (test_btc_forwarder 87/87), job wiring (test_wake_agent 590/590, test_wake_protocol 189/189), 16 anchors; `STAGE2_PLAN.md` is the record. Testnet moves to stage 3 with the broadcast |
| 3 | Broadcast over Tor; confirmation-wait; testnet end-to-end proving the swap starts; reorg edges | pending |
| 4 | Deposit UX: unique address, no note, auto received→confirmed→forwarding, per-owner `/balance` (gated); pager + doorbell + doc + artifact; banned-word and currency scans extended | pending |
| 5 | Failure handling + floating-rate reconciliation: fee spikes, dust/minimum refusal, forward failure + retry, reorg, reconcile the real swapped-out amount; full suite + anchors green | pending |

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
  collision, see section 2).

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
