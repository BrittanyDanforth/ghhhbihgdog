# Session log and plan — GhostSpiral phone bot

A single place to see what was changed in this working session, why, and what
is planned next (the BTC-intake build). It is a handoff / context document, not
a spec the code depends on. The authoritative spec for the new work is
`BTC_INTAKE_DESIGN.md`; the authoritative OPSEC rules live in `OPSEC_SETUP.md`
and `AGENTS.md`. Where they disagree with this file, they win.

Branch: `claude/phone-withdrawal-destinations-ey6ovb`.

---

## The system in one paragraph

Three machines. A **vault** laptop that holds the Monero keys, is OFF by
default, and boots only to run ONE job then powers off (disk auto-unlocks on
boot). A **Pi** that runs the Telegram pager, holds no wallet and no keys, and
is assumed seizable. A **phone** on Telegram. The Pi wakes the vault with an
authenticated magic packet (the "doorbell"); the vault does the job and reports
back over the LAN. Everything the chat says is assumed readable by someone who
is not the operator (AGENTS.md rule 6): no machine name, address, amount, memo,
or shape of the arrangement in the transcript. Security rests on the keys, not
on hiding the design (Kerckhoffs).

Today a deposit is a ThorChain BTC→XMR swap the client pays directly: BTC to
ThorChain's shared inbound vault with a swap memo in an OP_RETURN. The received
XMR is mixed and later withdrawn to the client's own address.

---

## What changed this session (newest first)

Commits are on the branch above. Every suite is run per-file
(`python3 tests/test_X.py`), plus a mutation sweep (`tests/mutation_sweep.py`)
whose anchors each flip one line of source and assert a named test goes red.

### Deposit and withdraw wording, made plain (commits `a9976f0`, `58a1392`, `c63ca93`)
- The deposit reply led with a confirmation number where the reader expected
  the thing to pay, and printed the number twice. It now leads with the
  payment: `here is how to pay`, then amount / address / `You get back` /
  `Confirmation`, then two short instruction lines, then what to do next.
- The three working lines lost their filler ("a few minutes", "looking"):
  `depo: getting your payment details now. They come here. Nothing else can
  run for up to {how}.`; `check: checking now. ...`; `withdraw: sending now.
  About {N}h. ... Nothing else can run for up to {how}.` The withdraw variant
  keeps "Nothing else can run", which the chain tests pin.
- The note instruction now says WHY, in plain words the transcript may leak
  without cost: `The code above is the note for this payment — add it to the
  payment. Most phone apps CANNOT add a note, and without it the money never
  arrives.` The note stays because ThorChain requires it; only the wording
  changed. The once-rule names the address: `Pay it once. Never send to this
  address again — a second payment, now or later, loses the money.`
- The `arriving` status line says `received — waiting for it to confirm. Not
  spendable yet; ask again shortly.` instead of "something arrived".

### Deep-read stability pass (commit `767909b`, tests in `tests/test_stability_pass.py`)
An end-to-end read for half-wired / unstable / hot-loop paths, each fix driven
by a staged failure and pinned by a mutation anchor:
- `start_job` owns the ONE release of `busy` through a flag, so a gate that
  raises (integrity_log on a full SD card) cannot leak the lock or free it
  twice.
- A failed start clears the persisted in-flight bit as well as the lock.
- Silent refusals (stranger chats, non-operator senders, unknown commands,
  id-less updates) count every one but reach the hash chain at most once per
  kind per 10 minutes — a stranger can no longer flood the SD card.
- A `getUpdates` batch that cannot advance the cursor pauses one poll period
  instead of hot-looping.
- `burn_all` is capped at 32 deletes per tick and re-arms as a continuation;
  `burn_signal` is logged once per signal, not once per pass.
- `Limits` (the one persisted file) is written under one re-entrant lock from
  both threads, bit + window as one picture; `why_not` treats a backwards
  clock jump as elapsed.
- The second label-backoff site is exponent-capped (no `OverflowError`).
- `_places` and `handle_owner` are walked from snapshots under a lock.
- Vault: `main()` remembers a `Refused(power=False)` instead of re-deciding at
  power-off; the accounts a mix minted are asked for 3× before giving up and
  said on the chain when unreadable; a failed withdrawal shreds its entry
  bundle; the fee sweep retires its bundle on failure and success.
- Shared: `integrity_log` reads the chain's last hash from the file TAIL in
  4 KiB steps, not a whole-file read; `atomic_write_json` gives each write its
  own `mkstemp` name so two writers cannot truncate each other's tmp.

### Multi-client capacity + fund isolation (commits `c2656ec`, `30f94fa`, earlier)
- Several people on one vault: an **owner token** on every job (derived from
  the asking chat, one-way, keyed by the pairing secret); a vault ledger of
  which wallet ACCOUNTS each owner's deposits and mixes created; spend
  selection that never leaves that set. `--max-clients N` = places (deposits
  in flight); the allowlist may be longer; everyone past it hears "full" from
  the Pi's memory with no wake spent. The one-person rule fires only on a bot
  built for one. A chain yields its turn when someone was refused during it.
- Capacity is DERIVED, not "10": the smallest of three bounds — accounts
  (`accounts_now + 30 × (in_flight + 1) ≤ ceiling`), wakes/day, and wall clock
  (legs run one at a time). At the shipped defaults it is ONE; sized per
  OPSEC_SETUP.md §4f it is a few. The load-model artifact ("Places on One
  Vault") visualises this and is read out of the shipped constants.

### Earlier phases (summarised)
OPSEC leak closure on the transcript and the Pi's disk; button / instability /
stale-value / fake-wiring fixes; fee never onto the mixing wallet; hot fee
wallet with a threshold sweep; service-lifecycle pass (fees always swept,
restart resilience, multi-deposit tracking); the phone-only deposit rework
(note first and alone, vault re-checks `memo_binds_destination`).

### Validation state
40 of 40 suites green on the last full run; 447 mutation anchors match and each
new one is caught. `tests/test_btc_embit.py` (stage 0 below) adds 30 more,
green.

---

## The BTC-intake build (in progress) — see BTC_INTAKE_DESIGN.md

Goal, in the operator's words: the client pays a **plain, unique BTC address
the host owns** (any phone can pay a plain address, no note), and the **host**
forwards it into ThorChain, attaching the swap memo itself. Unique address ⇒
the host auto-detects the arrival and can carry a per-person balance.
"Forward" = start the mix.

Why the note cannot just be dropped for a client-paid BTC deposit: ThorChain's
BTC inbound is a SHARED address for every user, and the memo is the only thing
that routes a payment. That is ThorChain's design, not a code choice. Moving
the note to the host means the host receives the BTC and forwards it — which is
the build below.

The insight that makes it fit the off-by-default vault: split it across the two
boxes. The **Pi** holds an **xpub only** (watch-only), derives a unique address
per deposit, and watches for the payment. The **vault** holds the seed and does
the forward as a **woken job** (`forward_to_swap`), signing only while awake.

Decisions taken:
- **Chain source:** Electrum protocol over Tor, one fresh circuit per address,
  watch-only (default); "point at your own node / Electrum server" as the
  zero-third-party upgrade. Tor removes the IP leak; the residual content
  correlation is kept weak by per-address circuits or removed by a private
  node. (A block-explorer API over Tor is usable but the weakest private
  option — not the default.)
- **Library:** `embit` 0.8.0, vendored into `third_party/embit` pure-Python
  only (native blobs stripped), pinned, MIT licence kept, provenance in
  `third_party/README.md`. Hand-rolling curve signing for real money is
  forbidden.

Hazards named (not glossed): custody between receipt and forward; the hot key
at rest (mitigated: box off/sealed at rest, signs only during a woken job,
receive path swept empty); the rate floats to forward time; the 80-byte
OP_RETURN limit a 95-char XMR address exceeds; confirmation-wait before
forwarding; dust/fee floors; ThorChain inbound churn (fetch current at forward
time); the host's new on-chain footprint (client's gets cleaner, host's gains
one).

### Stage status

| # | Stage | State |
|---|-------|-------|
| 0 | Vendor embit (pure-Python) + prove with BIP32/BIP84/BIP173 known-answer vectors | **DONE** — `third_party/embit`, `tests/test_btc_embit.py` 30/30 |
| 1 | Watch-only derivation + Electrum-over-Tor detector (xpub→address per handle; dry-run; no keys/money) | next |
| 2 | `forward_to_swap` job: build+sign the BTC tx with the OP_RETURN memo, `--dry-run` (print, no broadcast); WIRE_VERSION bump | pending |
| 3 | Broadcast over Tor; confirmation-wait; testnet end-to-end | pending |
| 4 | Deposit UX: unique address, no note, auto received→confirmed→forwarding, per-owner `/balance` (gated behind the plaintext opt-in) | pending |
| 5 | Failure handling + floating-rate reconciliation; full suite + anchors green; mainnet only after all green on testnet | pending |

Each stage is validated before the next. Mainnet is not touched until every
stage is green on testnet and reviewed.

### Stage 0 detail (done)
- `third_party/embit/` = embit 0.8.0 `src/embit/` verbatim minus
  `util/prebuilt/` (7 native libsecp256k1 blobs deleted) and with
  `util/secp256k1.py` pinned to the pure-Python `py_secp256k1` path. sdist
  sha256 and reproduction steps are in `third_party/README.md`.
- `tests/test_btc_embit.py` proves it against values published outside this
  repo: BIP32 test vector 1 (master + hardened + the deep path xprv/xpub),
  BIP84 reference mnemonic → `bc1qcr8te4...` receive/change addresses,
  watch-only public derivation agreeing with private derivation and refusing
  hardened steps, BIP173 bech32 decode/encode/round-trip and checksum
  rejection, HASH160('') against RIPEMD160(SHA256('')), and secp256k1
  sign→verify then broken on a wrong hash / wrong key. It also pins the
  vendoring: the pure-Python path must be live, the native path must never
  load, and no binary may exist in the tree.

---

## How to run things

- One suite: `python3 tests/test_X.py` (prints `RESULT: N passed, M failed`).
- The BTC library proof: `python3 tests/test_btc_embit.py`.
- Mutation sweep (all): `cd tests && python3 mutation_sweep.py`; a range:
  `python3 mutation_sweep.py 428 429 …`; verify anchors match source:
  `anchors_ok(list(enumerate(MUTATIONS)))`.
- The vendored library imports from `third_party/` (tests add it to
  `sys.path`); it has no external dependencies.

## Standing rules (do not drift)
- Develop only on `claude/phone-withdrawal-destinations-ey6ovb`.
- No model identifier in commits, code, or any pushed artifact.
- Never send the operator's email to any service; identity-only.
- Confirm before destructive or outward actions.
- Rule 6 on every chat surface; Kerckhoffs everywhere.
- No hand-rolled cryptography for money — vetted, vendored, pinned only.
