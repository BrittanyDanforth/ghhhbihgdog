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

- **Pi — watch-only.** Holds a Bitcoin **xpub only** (no spend key). Derives a
  fresh address per deposit (BIP32 public derivation; index bound to the
  handle). Watches the chain for a payment to that one address. A seized Pi can
  watch, never spend. The Pi is always on, so it is where watching belongs.
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

Until a library is chosen, nothing can derive even one real address, so stage 1
cannot begin. This is the gate, not a preference.

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
  "confirmed — forwarding". A `/balance` per owner (an amount, so gated behind
  the same opt-in as the plaintext deposit surface, per rule 6).

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
   the derived address, OP_RETURN memo, change), sign with the seed, but print
   rather than broadcast. Tested against testnet.
3. **Broadcast over Tor**, testnet end-to-end: a real testnet BTC → testnet
   ThorChain (or a stubbed inbound) → confirm the swap starts.
4. **Deposit UX**: unique address, auto-received, per-owner balance; the note
   and phone warning gone from this mode.
5. **Failure handling**: fee spikes, dust/minimum refusal, forward failure and
   retry, reorg/confirmation edge cases, floating-rate reconciliation.

Mainnet only after every stage above is green on testnet and reviewed.
