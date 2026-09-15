# BTC intake by unique address — design

Status: DESIGN, not built. No code in this document ships until the library
decision below is made and each stage is validated. This file is the blueprint
the implementation follows; it is not itself a feature.

## What it is for

Today a deposit is a ThorChain BTC→XMR swap the **client** pays directly: they
send BTC to ThorChain's shared inbound vault with a swap memo in an OP_RETURN.
That memo is mandatory (ThorChain routes on it) and most phone wallets cannot
attach one, so the phone-only client is handed a cryptic note and a warning.

This design moves the note off the client. The client pays a **plain, unique
BTC address the host owns** — anything can pay a plain address — and the
**host** forwards it into ThorChain, attaching the memo itself. The client
never sees a note. Because the address is unique per deposit, the host detects
the arrival automatically ("received"), and can carry a per-person balance.

"Forward" here means **start the mix**: host BTC → ThorChain swap → XMR lands
on a fresh receive subaddress → the existing mix pipeline runs. The final send
to the client's own address stays the later `/withdraw`.

This is the standard instant-exchange deposit-address pattern. It is a real
build with new money-custody and new on-chain surfaces, spelled out below.

## The two-box split (why it fits the off-by-default vault)

The vault is OFF by default: it boots on a wake, does one job, powers off, disk
resealed. An always-on "receive and auto-forward" daemon is the opposite of
that. So the work splits across the two boxes the way everything else here does:

- **Pi — watch-only.** Watches the chain for a payment to each OPEN deposit's
  address. A seized Pi can watch, never spend. The Pi is always on, so it is
  where watching belongs. **Stage 4 departed from the first draft of this
  line, which put the xpub on the Pi:** an xpub is the generator of every
  address the host has ever minted and ever will, so a seized card would have
  yielded the whole intake history, past and future, in one string. The
  vault derives the address (it holds the xpub beside the seed it already
  holds) and hands it to the Pi in the same plain slip the phone gets; the
  Pi keeps it in memory and never holds the generator. A seized Pi learns the
  currently open deposits and nothing before or after them. The cost: a
  pager restart forgets the open deposits (the button still asks the vault,
  on the forward, which sends a settled one on).
- **Vault — the seed and the signing.** Holds the BTC seed. Forwarding is a new
  **job** (`forward_to_swap`), run when woken, exactly like a withdrawal: sign
  one BTC tx paying ThorChain's current inbound with the memo in an OP_RETURN,
  broadcast over Tor, power off. The seed signs only during a woken job; at rest
  the box is off and sealed.

Flow: `/deposit` → Pi shows a unique address (no note) → client pays from a
phone → Pi detects the arrival, waits for confirmations, says "received" →
Pi wakes the vault for `forward_to_swap` → vault forwards to ThorChain with the
memo → XMR lands on the receive subaddress → mix pipeline → `/withdraw`.

## Chain source (decided: Electrum-over-Tor default, own-node upgrade)

To watch an address you need a chain source.

- **Default:** the **Electrum protocol over Tor**, one **fresh circuit per
  address**, watch-only. Tor removes the IP/identity leak entirely. The residual
  is *content correlation* — a third-party server can log which addresses were
  queried and cluster them — which per-address circuit isolation keeps weak.
  Stage 1 adds two more cuts at it: with several servers configured, each
  address starts at a server chosen by its own scripthash (no single server is
  handed the whole set), and the client announces a stock wallet's version
  string. What isolation cannot hide is *behaviour* — three read-only calls
  and hang up, the same on every circuit — so a server that fingerprints by
  behaviour can still cluster; that residual is stated in the module header
  and only an own node removes it.
- **TLS on that link:** Electrum servers are self-signed, so unverified TLS
  stops a passive listener and nothing more. A `.onion` server needs no more
  than that (there is no exit hop; the onion address authenticates the
  server). A clearnet server should be **pinned**: a server entry is
  `(host, port, pin)` with the SHA-256 of its certificate, a mismatch is
  refused, and every result carries the certificate seen so the pin can be
  recorded once and enforced from then on.
- **Settlement is per output, never an aggregate.** The watcher depth-checks
  each unspent output (`listunspent`); "confirmed" means *some output is at
  least N deep*, and the forward (stage 2) may spend only those outputs. An
  aggregate balance plus a history-wide confirmation count would let settled
  dust vouch for a fresh, reorg-able deposit (hazard 5); the module names that
  trap in a test.
- **Upgrade (recommended for the paranoid):** point at **your own node /
  Electrum server** (e.g. Fulcrum/electrs behind a pruned Bitcoin node) over the
  LAN. No third party sees anything; correlation leak gone.
- **Never:** a block-explorer REST API over clearnet — that adds the IP leak on
  top of the correlation leak. A block-explorer API *over Tor* is usable but is
  the weakest of the private options (easiest to log/cluster); not the default.

## Dependency (BLOCKING — needs the operator's okay)

This environment has **no Bitcoin crypto at all**: no secp256k1, no BIP32, no
bech32 encoder. The repo only *validates* addresses by regex. Bitcoin uses
secp256k1; everything here uses libsodium (ed25519/X25519) — the wrong curve.

Building this needs a vetted BTC library on the vault. **Hand-rolling
elliptic-curve transaction signing for real money is forbidden.**

Decided and done (stage 0): **`embit`** — small, auditable, built for
air-gapped/offline signing (SeedSigner, Specter-DIY). Covers BIP32 (watch-only
derivation on the Pi and signing on the vault), bech32/bech32m, and PSBT/tx
construction. **Vendored into the repo, trimmed to the used surface, and
pinned**, so exactly what runs is in the tree and auditable; its in-package
native blobs are deleted.

**Constant-time is not optional for the signer.** embit's pure-Python curve is
variable-time — a timing side channel on the key that moves the money. So the
vendored selector prefers the **system** libsecp256k1 (Bitcoin Core's
constant-time library, installed from the distro's signed `libsecp256k1-1`
package, the same trust root as the rest of the OS) and exposes which backend
is live (`NATIVE` / `BACKEND`). The vault installs it and the signing path
(stage 2) refuses to sign without it. The watch-only Pi holds no secret and is
correct on the pure-Python fallback, so it needs no native library.

That gate is passed: embit is vendored (stage 0, `8c86548` / `69d379a`) and
stage 1 derives real addresses from it. The stage-1 exit criterion "against a
mock and a testnet server" is met on the mock side (an in-process SOCKS5 proxy
and Electrum server, plaintext and TLS, drive the REAL transport and client);
the live-testnet look needs Tor on the box and is folded into stage 3's
testnet end-to-end, where Tor is present. Mainnet still waits on every stage.

## Wire and schema changes

- **Keyfile (vault):** a BTC seed (sealed like the XMR key); the derivation
  path; the current ThorChain inbound source of truth; confirmation threshold;
  dust/fee floors. **Pi keyfile:** the **xpub only**, plus the Electrum/Tor
  config. The Pi never receives the seed.
- **New job `forward_to_swap`** in `JOBS` (gs_wake_proto): schema
  `{handle, owner}`; tool a new `btc_forwarder`. `validate_job`'s exact-key-set
  rule means adding it is a WIRE change — bump `WIRE_VERSION`, update both boxes
  together (an old box refuses the unknown job loud, as the header promises).
- **Deposit UX:** `/deposit` returns a unique address and amount, **no memo, no
  note, no phone warning**. Auto "received — waiting for confirmations", then
  "confirmed — forwarding". A `/balance` per owner lists each deposit's
  label and state word only — no amount, per rule 6 (the on-chain figure
  is not the one the chat was quoted).

## The hazards, named (not glossed)

1. **Custody.** Between receipt and forward (minutes to hours) the host holds
   the client's BTC. A theft target if the vault is ever popped; the legal
   posture of a money transmitter. Accepted deliberately or not at all.
2. **Hot key at rest.** The seed lives on the auto-unlocking vault. Mitigations:
   the box is off/sealed at rest and only signs during a woken job; the receive
   path is swept empty per forward so little sits at any derived address; the
   seed can be a separate air-gapped device in a later stage.
3. **Floating rate.** The swap happens at *forward* time, not deposit time, so
   "you get back ~X" is an estimate that settles at forward. Accounting and the
   UX must say "about", and reconcile the real out-amount after the swap.
4. **OP_RETURN 80-byte limit.** A raw XMR address (95 chars) plus the swap
   prefix exceeds the standard 80-byte OP_RETURN — the repo already flags this
   (`OP_RETURN_STD_BYTES`, `memo_will_overflow`). The forward must use
   ThorChain's supported long-memo path (or a THORName/short memo). This is a
   real constraint the current client-paid flow already lives with; the
   host-forward inherits it.
5. **Confirmation wait.** Forwarding unconfirmed BTC risks a double-spend, so
   the vault forwards only after N confirmations — adding delay before the mix
   starts. N is a keyfile setting (1–2 for small, more for large).
6. **Dust and fees.** The forward pays a BTC network fee; a deposit too small to
   forward net of fee, or below ThorChain's swap minimum, must be refused up
   front with a stated minimum, not silently stranded.
7. **Inbound churn.** ThorChain rotates its inbound address; the forward must
   fetch the **current** inbound at forward time (over Tor) — never a cached one.
8. **On-chain footprint moves.** The client's footprint gets *cleaner* (plain
   address, no public memo naming the XMR destination). The host gains a *new*
   BTC footprint: host address → ThorChain, with the memo now on the host's tx.
   Net better for the client, a new surface for the host — state it, don't hide.

## Staged build (each stage validated before the next)

0. **bech32/bech32m** encoder/decoder, vendored from the BIP173/350 reference,
   tested against the official vectors. Pure Python, no money, no curve — but
   load-bearing for address construction.
1. **Watch-only derivation + detector.** xpub → unique address per handle;
   Electrum-over-Tor client with per-address circuit isolation; dry-run detector
   that reports "seen / confirmed" against a mock and a testnet server. No keys,
   no money.
2. **`forward_to_swap` job**, `--dry-run` first: build the BTC tx (inputs from
   the derived address, OP_RETURN memo, no change -- the whole deposit is
   forwarded), sign with the seed, but print rather than broadcast. DONE in
   dry-run form (`STAGE2_PLAN.md` is its record); the testnet run belongs to
   stage 3, where a broadcast exists to test. What stage 2 established: every
   real swap memo (105+ bytes) is over the standard 80-byte OP_RETURN, so the
   forwarder REFUSES on a default policy and stage 3 must choose the relay
   strategy before mainnet.
3. **Broadcast over Tor**, testnet end-to-end: a real testnet BTC → testnet
   ThorChain (or a stubbed inbound) → confirm the swap starts. BUILT
   (`STAGE3_PLAN.md` is its record): `gs_btc_broadcast` holds the one method
   that moves bitcoin, in a file the Pi never imports; `btc_forwarder
   --broadcast` signs and sends in one process, from memory; the outcome is
   one of four words and drives the exit code so "may have moved" never
   renders as "failed"; the phone hears `sent` or `unsure` (wire v5); a
   second keyfile switch (`allow_btc_broadcast`) gates it. The testnet run
   is `tests/real_btc_forward_testnet.py`, on a box with Tor; it proves the
   relay and the seen-poll, and says in its header that only mainnet proves
   THORChain takes the memo. Confirmation depth, reorg and the fee bump are
   stage 5.
4. **Deposit UX**: unique address, auto-received, per-owner balance; the note
   and phone warning gone from this mode. BUILT (`STAGE4_PLAN.md` is its
   record): the vault in BTC mode (`btc_account_xpub` + `deposit_in_chat`,
   coupled at pairing with `allow_btc_forward`) refuses a deposit under the
   forwardable floor before any mint, allocates the next index only after the
   network has said the address is fresh (a bounded gap past used ones, fail
   closed when nobody could be asked), and builds a memo-less plain slip
   carrying its own derived address (wire v6: two exact slip shapes); the
   pager registers the address in memory, watches it over Tor, says
   "received" and "confirmed" once each, starts the forward through the one
   wake path when the box is free (held silently while a job runs), and
   closes the entry on `sent`/`unsure`; `/balance` lists the chat's own
   deposits by label and state word, no figure; the button and `/check` on an intake
   deposit ask the forward, which sends a settled one on and otherwise
   answers `not_yet`/`arriving` from the forwarder's one-word status file.
5. **Failure handling**: fee spikes, dust/minimum refusal, forward failure and
   retry, reorg/confirmation edge cases, floating-rate reconciliation. BUILT
   (`STAGE5_PLAN.md` is its record, section 1 the end-to-end read that
   found the gaps, section 8 the self-doubt pass). The invariant changed:
   not "once per handle" but **one signature per outpoint while a spend of
   it may be in the network**. `btc_forwarder --reconcile` is what a tap
   after a forward runs: it reads the address's history (each transaction
   fetched, read-only) and confirms our transaction is listed, re-sends
   kept bytes, re-signs an evicted one, forwards money that came back (a
   refund, a second payment) leaving out what our listed forwards consumed,
   or fails on a spend that is not ours; a plan chain is the record. A fee
   the vault will not pay today is the word `delayed` and the Pi tries
   again by itself; money that can never be sent on is `short`. The XMR
   side judges the forward-time swap (the pairs file is rewritten from the
   plan). The floor is the larger of the forwarder's two guards at the
   ceiling; `--allow-btc-broadcast` requires `--thornode`; a wiped ledger
   behind a used chain is refused with the next account named
   (`--btc-account`). What only mainnet proves is unchanged: that THORChain
   takes the memo.
6. **The forward after the send**: a stuck forward found and replaced, the
   reconciliation driven, a word for a mined forward. BUILT
   (`STAGE6_PLAN.md` is its record, section 1 the end-to-end read that found
   what stage 5 left half-wired, section 8 the self-doubt pass). The gaps:
   the reconciliation was reachable only after a pager restart (every ask
   after `sent` went to the XMR side, so the re-send, the re-sign and the
   returned money were never invoked); a fresh forward refused after the
   plan rotation left the chain with no current plan (`no_plan` for ever);
   nothing bumped a forward the network stopped confirming; and the phone
   could not tell a mined forward from one still waiting. Now: the Pi asks
   the forward again past `--btc-recheck` (at once after `unsure`), by
   itself once per window when nobody taps, and stops on `forwarded` (wire
   v8); the forwarder REPLACES a forward of ours listed in the mempool past
   `--bump-after` (keyfile `btc_bump_after_s`, paired with
   `--btc-bump-after`) at a rate under today's estimate -- the same
   outpoints, spent whole, at today's rate, priced to beat every earlier
   signature of ours over them, quoted afresh, carrying money that came
   back meanwhile, found on the whole plan chain and not the current plan
   alone, the window measured from the newest attempt; rotation happens
   when the fresh plan is written and a chain left without a current plan
   is recovered; the pairs file counts one swap per outpoint, the record
   the reconciliation named; a superseded plan whose superseder mined is
   `forwarded`. A forward learned after a pager restart is put back on the
   Pi's list with its word and clock, so the windows apply after a restart
   too. The testnet drill gains act F (a replacement, `--bump-after 0`).
   What only mainnet proves is unchanged.

Mainnet only after every stage above is green on testnet and reviewed.
