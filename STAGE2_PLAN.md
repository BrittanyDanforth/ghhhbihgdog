# Stage 2: `forward_to_swap` — build and sign the forward, print it, spend nothing

Status: **BUILT, dry-run only** (the commit that carries this line). This file
is the whole context for stage 2 of the BTC-intake rework
(`BTC_INTAKE_DESIGN.md`), written before the build and kept as its record.
What shipped, against the build order in section 7:

- `gs_common`: `memo_will_overflow`, `memo_bytes`, `DUST_SAT_P2WPKH`,
  `electrum_fee_to_sat_vb`; `btc_forward_*.json` in the wipe patterns.
- `gs_btc_tx.py`: the OP_RETURN builder (OP_PUSHDATA1 above 75 bytes),
  `address_script` (this network's native segwit only), `vsize_upper_bound`,
  `measure`, `build_unsigned` (RBF, fresh lists, refusals), `sign_input` /
  `sign_p2wpkh` (BIP143 script code, constant-time gate, self-verify),
  `verify_signed`, `account_from_mnemonic`, `account_matches_xpub`, `key_for`.
  `tests/test_btc_tx.py`: 70 checks, BIP143's vector byte for byte.
- `gs_btc_watch.py`: `Electrum.estimate_fee` and `look(..., fee_blocks=)` --
  the fourth read-only method, same session, same circuit.
- `btc_forwarder`: the tool, `--dry-run` required, `--plan-only` optional,
  seed from `GS_BTC_SEED` only, the THORNode cross-check behind `--thornode`.
  `tests/test_btc_forwarder.py`: 87 checks through the real `main()`.
- The job: `forward_to_swap` in `JOBS`, `SPENDING_JOBS` and `GATED_TOOLS`,
  `WIRE_VERSION` 4; the agent's argv branch, per-job spending switch
  (`allow_btc_forward`), ledger resolution (`btc_index`, owner wall, spent),
  seed injection into the one step's environment; pairing flags in
  `gs_wake_keys`; `CHAT_NAME`; the four tripwire tests updated and the
  forward's dispatch driven end to end in `tests/test_wake_agent.py`.
- 16 mutation anchors over the money guards.

Deferred, on purpose: the deposit ledger does not yet carry `btc_index` for
any real handle (stage 4 mints the addresses), so on a live box the job
refuses `no_btc_deposit` until then; broadcast (stage 3); the relay
strategy for the >80-byte memo (stage 3, see section 2).

**A floor stage 4 must respect (found in review):** `FORWARD_MIN_SAT` is
what must REACH ThorChain after the fee, and it equals the deposit wizard's
`DEPOSIT_MIN_SAT` (10,000 sat) — so a deposit of exactly the wizard's
minimum can never be forwarded (`send = settled − fee < 10,000`). The
forwarder's refusal already names the number that must settle. Stage 4's
deposit minimum must be `FORWARD_MIN_SAT` plus a fee allowance at the
ceiling rate for a one-input transaction (about 202 vB × the ceiling), not
the typo guard, and must be quoted to the client as such.

**Input selection (added in review):** an output is spent only if it is
settled to `min_conf` on its own AND worth more than twice its own input
cost at the live rate. The first rule closes a real bug — a one-conf output
under a two-conf policy was spent while not counted, and its whole value
would have gone to the miner; the built transaction's fee is now required
to equal the sized fee exactly (`fee_mismatch` otherwise). The second rule
is the dust-storm defence: anyone can park two hundred 546-sat outputs on
the address, and sweeping them would make the fee eat the deposit. Dust
stays; the plan counts what was left.

Stages 0 and 1 are done and green; this was the first one that touches a
spend key.

Written after mapping three surfaces in full: the wake protocol and the vault's
job runner, the existing ThorChain/SwapKit preparer and the Tor helpers, and the
vendored embit signing API. Everything below is measured against the source, not
assumed. **Read section 1 first — four things the design doc says already exist
do not exist.**

---

## 1. Corrections to the design doc's premises

`BTC_INTAKE_DESIGN.md` and `SESSION_LOG_AND_PLAN.md` were written before stage 1
and both assume capabilities the repo has never had. Each of these is now stage-2
work, not stage-2 plumbing.

**1.1 There is no ThorChain-native code anywhere.** Nothing fetches
`/thorchain/inbound_addresses`. The repo talks only to **SwapKit**
(`SWAPKIT_API = "https://api.swapkit.dev"`, `gs_common.py:2389`), and the inbound
vault address arrives *inside a quote route*, not from THORNode. So `halted`,
`router`, `gas_rate`, `outbound_fee`, `dust_threshold`,
`recommended_min_amount_in` and `expiry` are THORNode field names that appear
nowhere in this codebase. Hazard 7 ("fetch the current inbound at forward time,
never a cached one") is satisfiable — but through the quote, not through an
inbound-addresses endpoint. See 3.2.

**1.2 The repo never *builds* a memo, and it does not need to.** It only
*receives* one from the aggregator and *validates* it. There is no `=:XMR.XMR:`
construction site in any shipping file — every hit is a test fixture or prose.
This is a feature, not a gap: the quote returns a memo already bound to our
destination, and `gs_common.memo_binds_destination` (`:3810`) checks that binding
with a real positional parse (`_memo_fields_bind`, `:3879`) that has already been
hardened against five hostile memo shapes. **Stage 2 must not hand-author a
memo.** It asks for a quote and validates what comes back.

**1.3 `memo_will_overflow` does not exist.** Both design docs cite it as present.
Only `memo_size_note` exists (`gs_common.py:2445`), and it returns a *warning
string* — it never refuses. Stage 2 writes the predicate the docs promised.

**1.4 There is no Bitcoin fee estimation, no dust constant, no OP_RETURN
builder, and no coin selection.** Confirmed by exhaustive grep: no
`mempool.space`, no `estimatesmartfee`, no sat/vB helper, no `546` outside a
stage-1 test fixture. `FALLBACK_FEE_BY_PRIORITY` is **Monero**, in XMR.
`embit/script.py` has `p2pkh/p2sh/p2wpkh/p2wsh/p2tr/multisig` and no data-output
helper. All four are stage-2 work.

---

## 2. THE BLOCKING CONSTRAINT: the memo does not fit a standard OP_RETURN

This is the finding that decides whether the whole intake design ships, so it
goes above the build plan rather than in a hazards list at the bottom.

A Monero subaddress is 95 characters. The shortest possible swap memo is
`=:XMR.XMR:` + 95 = **105 bytes**, and a real SwapKit memo carries a limit field
and usually an affiliate, so ~105–130 bytes. `OP_RETURN_STD_BYTES = 80`
(`gs_common.py:2440`). **The memo is over the standard relay limit by 25–50
bytes, always, on every swap this design makes.**

What that means, stated plainly:

- This is **not new**. The client-paid flow has exactly this problem today — the
  client's own wallet has to attach a >80-byte OP_RETURN — and the repo's entire
  handling of it is `print(memo_size_note(memo))`, a warning, at
  `thor_swap_preparer:604`.
- Moving the forward host-side does not make it worse. It makes it **the host's
  problem**, which is strictly better, because the host controls its own node and
  can set `-datacarriersize`. A phone wallet cannot.
- Bitcoin Core 30 relaxed the default datacarrier relay limit, which is why this
  is a policy question and not a consensus one. A tx with a 105-byte OP_RETURN is
  **valid**; whether it *relays* depends on the nodes it meets.

Stage 2's job is to make this measurable rather than theoretical:

- Write `memo_will_overflow(memo, limit=OP_RETURN_STD_BYTES) -> bool` in
  `gs_common` — the predicate the docs already promise — beside the existing
  `memo_size_note`.
- Add a keyfile setting `op_return_max_bytes`, defaulting to
  `OP_RETURN_STD_BYTES` (80). The forwarder **refuses to sign** when the quoted
  memo exceeds it, with a refusal that names the byte count and says the operator
  must either raise the limit and run a node that will relay it, or that this
  swap cannot be forwarded from this box.
- Because stage 2 is dry-run only, that refusal costs nothing and is the honest
  outcome. Stage 3 decides the relay strategy (own node with a raised
  datacarrier limit, or submitting directly to a mining pool's endpoint).

**Rejected: THORName.** ThorChain's alias feature would shorten the memo to
`=:XMR.XMR:<name>:...`, which fits. It is rejected on OPSEC grounds and the
reason must survive: a THORName is a *persistent public identifier*, registered
on-chain, and one name reused across clients links every one of their swaps to
each other and to the host, permanently, in public. That is the exact clustering
the whole pipeline exists to prevent. A name per client is an on-chain
registration per client, which is worse. **Do not revisit this without a reason
that answers the linkability, not just the byte count.**

---

## 3. What stage 2 builds

One new tool, `btc_forwarder`, run as one step of one new woken job,
`forward_to_swap`. It never broadcasts in stage 2.

### 3.1 The shape of the run

```
handle  ->  ledger record  ->  the client's deposit address + its XMR subaddress
        ->  look() the address over Tor            (stage 1, unchanged)
        ->  settled outputs only                    (settled_sat, per-output depth)
        ->  estimate the fee                        (Electrum, same circuit)
        ->  send_amount = settled - fee_upper_bound
        ->  quote SwapKit for send_amount           (inbound + memo + expected out)
        ->  validate: memo binds OUR destination, memo fits, amount clears floors
        ->  build the tx: inputs = settled outputs, out0 = inbound, out1 = OP_RETURN,
                          out2 = change (or absorbed into fee if dust)
        ->  refuse unless secp256k1 is the constant-time native library
        ->  sign each input (BIP143, P2WPKH)
        ->  PRINT the signed hex, the txid, the vsize, the real feerate
        ->  DO NOT BROADCAST
```

### 3.2 Where the inbound address and the memo come from

From a **SwapKit quote taken at forward time**, on its own Tor circuit. This is
the design's hazard-7 requirement ("never a cached one") and it is also the only
route this repo has. It gives three things in one call, all of which stage 2
needs and none of which it should invent:

- `targetAddress` — the current ThorChain BTC inbound vault. Churns; that is why
  the fetch is at forward time.
- `memo` — already built, already bound to our destination.
- `expectedBuyAmount` — the "you get back about X" figure, which under a
  host-forward model is settled at forward time (hazard 3).

Reuse verbatim: `safe_post(f"{SWAPKIT_API}/v3/quote", payload, proxies)`
(`gs_common.py:2465`), `parse_swap_route` (`:2408`), `memo_binds_destination`
(`:3810`), `bech32_checksum_ok` (`:4091`), `BTC_RE` (`thor_swap_preparer:58`),
`instruction_field_safe` (`:3772`).

Two known defects in the existing call site, **not to be copied**:

- `thor_swap_preparer:513` sends `str(amt)`, which can emit `3E-8` for a small
  Decimal. `GhostSpiral:4011` correctly uses `fmt_btc`. **Use `fmt_btc`.**
- `gs_console:627` builds the quote action without `--min-out-xmr`, so the
  console path is ungated. Do not replicate; the forwarder always gates.

### 3.3 The chicken-and-egg between fee, amount and memo — resolved

The fee depends on tx vsize; vsize depends on the memo length; the memo comes
from a quote; the quote is for an amount that depends on the fee. Resolved
without a loop:

**Estimate the fee against a vsize upper bound that assumes the largest OP_RETURN
the operator's limit allows.** Then `send_amount = settled_sat - fee_upper`.
Quote for that. Build with the real memo, which is never longer than the bound,
so the real vsize is ≤ the bound and the real feerate is ≥ the target. The
surplus is a few satoshis and goes to the miner. No re-quote, no loop, no
oscillation. Record the real vsize and real feerate in the printed output so the
operator sees both.

### 3.4 Fee estimation: extend the stage-1 Electrum client

No fee source exists. The options were a block explorer (prohibited —
`receive_watch:18` names mempool.space and blockstream in a prohibition), a
static keyfile rate (stale by definition), or the Electrum server already being
asked about this very address.

**Add `blockchain.estimatefee` to `gs_btc_watch`'s client.** Same server, same
per-address circuit, same transport, same deadline, same refusals. It is
read-only and cannot move money, so the module's guarantee is intact.

Consequences to handle, both already located:

- `tests/test_btc_watch.py` asserts the **exact** method list
  `["server.version", "blockchain.headers.subscribe",
  "blockchain.scripthash.listunspent"]`. That assertion becomes four methods, and
  its comment must keep saying *why* the list is closed (nothing that spends).
- Electrum returns **BTC per kilobyte**, and returns **-1** for "no estimate".
  Convert to sat/vB with integer arithmetic; treat any non-positive answer as a
  refusal, never as "free". Clamp between keyfile `feerate_floor_sat_vb` (default
  1) and `feerate_ceiling_sat_vb` (default 200) and refuse outside the clamp
  rather than silently clamping — a server that says 5000 sat/vB is either broken
  or hostile, and this is money.

### 3.5 Dust, floors and refusals (hazard 6)

- `DUST_SAT_P2WPKH = 294` is the real P2WPKH dust threshold at the default
  3000 sat/kvB relay rate; 546 is the P2PKH figure the ecosystem quotes out of
  habit. Use 294 for the change output's own dust test and say so in a comment,
  because using 546 "because everyone does" is how a valid change output gets
  needlessly burned to fees.
- **No change output, by decision.** The whole settled deposit is forwarded:
  `send = settled - fee`, where the fee is sized against the upper bound, so
  the only "change" that could exist is the sizing slack (a few dozen
  satoshis) and it goes to the miner. A change output would chain every
  forward to the next on-chain and give a forensic reader the host's
  forwarding history for free. The builder supports a change output (tested)
  for a future partial forward; the tool never emits one. `DUST_SAT_P2WPKH`
  is kept for that day.
- A deposit too small to forward net of fee is refused **up front with the number**
  ("this needs at least N sat to forward; M arrived"), never silently stranded.
- The mix floor gate is the existing worst-case-arrival test, reused exactly:
  `_worst_arrival = expected * (1 - ARRIVAL_TOLERANCE)` against
  `live_min_out_xmr(key)` (`thor_swap_preparer:690`, `gs_wake_agent:966`). Gating
  on the headline quote instead leaves a band where the quote passes and the
  arrival lands under the floor.

### 3.6 The seed: the `wallet_file` pattern, mirrored exactly

The design says "a BTC seed sealed like the XMR key". **There is no per-field
sealing, and the vault's keyfile is not sealed at all** — `gs_wake_keys:926`
writes it with `kdf="none"` deliberately. The XMR wallet password is not in the
keyfile either; it arrives as `GS_WALLET_PASSWORD` from a root-0400
`EnvironmentFile`, is required to be *present* (`gs_wake_agent:3249`), and is
handed to exactly one step.

So the BTC seed follows that pattern and nothing else:

- Keyfile gains `btc_account_xpub` (public, safe at rest), `btc_network`,
  `btc_min_conf`, `op_return_max_bytes`, `feerate_floor_sat_vb`,
  `feerate_ceiling_sat_vb`, `allow_btc_forward`.
- The **seed never touches the keyfile or an argv**. It arrives as `GS_BTC_SEED`
  (a BIP39 mnemonic) from a root-0400 `EnvironmentFile`, injected into the one
  step that signs, scrubbed from every other child by `run_child`'s `GS_` strip
  (`gs_wake_agent:1808`).
- **The vault verifies the seed matches the xpub the Pi watches** before it signs:
  derive the account key from the seed, compare its base58 to `btc_account_xpub`,
  refuse on mismatch. Without this, a wrong seed signs for addresses nobody paid
  and the failure is a silently empty spend, hours later.

### 3.7 Constant-time or nothing

`third_party/embit/util/secp256k1.py` exposes `NATIVE` and `BACKEND` precisely so
the signer can refuse. `btc_forwarder` **refuses to sign** unless
`NATIVE and BACKEND in ("libsecp256k1", "micropython")`. The pure-Python curve
does big-int arithmetic whose running time depends on the secret key; the
watch-only Pi is fine on it because it holds no secret, and the vault is not.
This box has `libsecp256k1.so.1` installed, so the positive path is testable for
real and the negative path by monkeypatching the flag.

---

## 4. The embit API: five landmines, measured

From reading the vendored source. Each of these is a real defect if missed.

**4.1 Mutable default arguments.** `Transaction.__init__(self, version=2, vin=[],
vout=[], locktime=0)` stores the lists **without copying**
(`transaction.py:53-58`), unlike `Witness.__init__` which does `items[:]`. A
`Transaction()` followed by `tx.vin.append(...)` poisons every future
`Transaction()` in the process. **Always pass explicit fresh lists.**

**4.2 `Script.push()` is wrong for a memo this size.** It uses CompactSize
(`script.py:40`), not Bitcoin push opcodes. The two coincide only for 1..75
bytes. For a 76–80 byte push it emits a single byte `0x4c`–`0x50`, which the
interpreter reads as `OP_PUSHDATA1`/`2`/`4`/`OP_RESERVED` — a malformed script.
Build the data output literally:

```
len(memo) <= 75 :  Script(b"\x6a" + bytes([len(memo)]) + memo)
len(memo) >  75 :  Script(b"\x6a\x4c" + bytes([len(memo)]) + memo)   # OP_PUSHDATA1
```

and note that every real memo here is >75, so the OP_PUSHDATA1 branch is the
normal path, not the edge case. Pair with `TransactionOutput(0, script)`.
`Script.script_type()` returns `None` for it and `Script.address()` raises, so it
must never be routed through address rendering.

**4.3 BIP143 wants the script *code*, not the scriptPubKey.**
`sighash_segwit(input_index, script_pubkey, value, sighash)` writes
`script_pubkey.serialize()` length-prefixed, so for P2WPKH it must be the p2pkh
form. embit's own PSBT signer converts with
`script.p2pkh_from_p2wpkh(sc)` (`psbt.py:855`); `script.p2pkh(pubkey)` is
equivalent. Passing the p2wpkh scriptPubKey produces a valid-looking signature
that no node will accept.

**4.4 The sighash cache is not invalidated by mutation.** `hash_prevouts` /
`hash_sequence` / `hash_outputs` memoize into `self._hash_*`
(`transaction.py:169-192`). Changing any amount or output after computing a
sighash and before signing signs a **stale commitment**. Call `tx.clear_cache()`
after any mutation. Signing several inputs of an unchanged tx is exactly what the
cache is for and is safe.

**4.5 There is no `vsize()`, `weight()` or `size()` in the library**, and no
finalizer module (it was removed during vendoring). Compute vsize:

```
witness_bytes = 2 + sum(len(inp.witness.serialize()) for inp in tx.vin)
base   = len(tx.serialize()) - witness_bytes
weight = base * 3 + len(tx.serialize())
vsize  = -(-weight // 4)
```

Attach witnesses by assignment via `script.witness_p2wpkh(sig, pubkey)`
(`script.py:211`), leaving `script_sig` empty. `PrivateKey.sign` grinds for low-R
(`ec.py:216`), so a signed P2WPKH witness is a deterministic 107 bytes.

**Also:** `TransactionInput.txid` is stored in **display order** and reversed on
the wire (`transaction.py:368`), so `unhexlify(tx_hash)` straight from what
`gs_btc_watch.summarize` returns is correct. Set `sequence=0xFFFFFFFD` to signal
RBF while keeping nLockTime enforced; set `tx.locktime` to the current tip so the
tx cannot be mined into an earlier block than the one we surveyed.

**And a silent-`None` trap:** `script.address_to_scriptpubkey` falls off the end
returning `None` when a base58 address decodes but matches no network's version
byte (`script.py:176-183`), and it validates no network at all — it loops every
network in `NETWORKS`, so a testnet inbound converts happily while building a
mainnet tx. Check the result for `None` and validate the network separately, the
way `gs_btc_watch._require_native_segwit` already does.

---

## 5. Wiring the job: every place keyed by job name

The vault's argv template and its handle resolver live in different functions,
and the repo has been burned three times by adding a job to one and not the
other (`gs_wake_agent:2887-2894` says so in as many words). This is the complete
list.

| File / line | What to add |
|---|---|
| `gs_wake_proto.py:2536` | the `JOBS` entry: schema `{handle, owner}`, tools `("btc_forwarder",)`, `budget_s` 900 |
| `gs_wake_proto.py:2695` | `SPENDING_JOBS` — add it (see 5.1) |
| `gs_wake_proto.py:2794` | `GATED_TOOLS` — add `btc_forwarder` (forced by 5.1) |
| `gs_wake_agent:1301` | a `build_argv` branch — **without one, `:1493` refuses `unknown_job`** |
| `gs_wake_agent:2319` | the spending gate — per-job allow flag (see 5.1) |
| `gs_wake_agent:2345` | `handle = params["handle"]` — a handle-taking job needs this or it reports a freshly drawn label |
| `gs_wake_agent:2998` | `_dispatch`'s handle/bundle resolution `elif` chain |
| `gs_wake_agent:3110` | per-step `env_extra` — this is where `GS_BTC_SEED` is injected |
| `gs_wake_agent:2410` | `_phase_of` — the phase word this job reports |
| `gs_telegram_pager:482` | `CHAT_NAME` entry (asserted total over `JOBS`) |
| `gs_telegram_pager:2186` | `UNWATCHABLE_JOBS` — decide whether a forward's label is watchable |
| `OPSEC_SETUP.md:2021` | the "four jobs and no others" prose becomes five |

### 5.1 It spends, so it is gated — but by its own switch

`forward_to_swap` moves the client's BTC. It belongs in `SPENDING_JOBS` so the
deadman extension applies. That forces `btc_forwarder` into `GATED_TOOLS`,
because `job_tools_are_permitted` (`gs_wake_proto.py:2797`) enforces three rules
at once, one of which is that a spending job may name *nothing but* gated tools.

But the existing gate reads `key.get("allow_withdraw")`, which is the **XMR
withdrawal** switch. Conflating them would mean enabling withdrawals silently
enables BTC forwarding. The gate becomes per-job: `allow_withdraw` for
`withdraw`, `allow_btc_forward` for `forward_to_swap`. Absent from every keyfile
that predates this job, so an upgraded pair gains nothing silently — the same
property `allow_withdraw` was built for.

### 5.2 `WIRE_VERSION`

Bump 3 → 4. **It is a changelog, not a check** — `gs_wake_proto.py:143` states
that it is on no message, in no keyfile, and consulted by no branch, and no test
asserts its value. The three things that actually break a half-upgraded pair are
the tag whitelist, the fixed 1064-byte record length, and the exact key sets. An
old vault refuses the unknown job loudly, which is the promised behaviour. Bump
it because the changelog is the point, and update both boxes together.

### 5.3 Tests that break by design the moment the job is added

Four hard asserts, all deliberate tripwires:

- `tests/test_wake_protocol.py:89` — `assert set(SAMPLE) == set(P.JOBS)`.
- `tests/test_wake_protocol.py:246` — `P.SPENDING_JOBS == ("withdraw",)`.
- `tests/test_wake_agent.py:1237` — `assert set(_sample) == set(P.JOBS)`.
- `tests/test_wake_agent.py:1249` — the exact tool-basename set, which must gain
  `btc_forwarder`.

Plus `tests/test_telegram_pager.py:1358` (every job has a `CHAT_NAME`) and
`tests/test_wake_agent.py:1239` (drives `build_argv` for every job, so a missing
branch kills the suite there).

Budget arithmetic to keep green, all three of which 900 satisfies:

- `result_budget_s(job) = len(tools) * budget_s + 1200 + 300`, and every job's
  must stay under the unit's `TimeoutStartSec=61200` (`test_wake_agent.py:911`).
  At 900 with one tool this is 2400.
- `withdraw` must remain the maximum (`test_wake_protocol.py:1026`). It is, at
  58200 against 900.
- `test_wake_doorbell.py:1006` takes the job with the *smallest* `budget_s` and
  asserts it is below `VAULT_JITTER_HI_S = 1200`. `swap_status` at 300 stays the
  smallest, so that assertion is untouched. Note the trap the same test carries:
  it then constructs a `Bell` for the shortest job with a hard-coded
  `params={"handle": "A3F1"}`, so if a future job ever *did* become the shortest,
  that dict would need an `owner` too.

---

## 6. What must never reach a log, a chat, or the chain

Rule 6 (`AGENTS.md`) plus what the chain-redaction suite already pins
(`tests/test_chain_redaction.py:32`: *no payload carries a number*, and no
payload count carries one either).

- **Never on the hash chain:** an address, an amount, a satoshi count, a feerate,
  a txid, a memo, an account or subaddress index, an owner token. The chain gets
  event *kinds*: `forward_quoted`, `forward_refused_memo_size`,
  `forward_refused_dust`, `forward_signed`, `forward_not_broadcast`.
- **Per-output loops use `integrity_log_once`** (`gs_common.py:1598`), because
  byte-identical redacted lines can be *counted* to recover the tx shape — the
  exact leak the preparer was already fixed for.
- **The signed hex, the txid and the memo go to the job log only**
  (`gs_wake_job.log`, 0600, in the artifact dir), never into the M3 reply. The
  reply carries `status`, a 4-hex `handle`, an optional slip and a phase word
  from the closed `PHASES` vocabulary — the vault's refusal *reason* never
  travels (`gs_wake_agent:1860`).
- **The seed never appears anywhere**: not argv, not the keyfile, not a log, not
  an error. Errors name types and codes, never values — the rule stage 1 already
  enforces for server text.

---

## 7. Build order, each step validated before the next

1. **`gs_common` additions.** `memo_will_overflow`, `DUST_SAT_P2WPKH`, the
   sat/vB conversion from Electrum's BTC/kvB. Pure functions, tested first.
2. **The OP_RETURN builder and the vsize calculator**, as pure functions with
   known-answer tests — including the 75/76-byte boundary where `Script.push`
   would have gone wrong, proven against a hand-computed script.
3. **`blockchain.estimatefee` in `gs_btc_watch`**, with the method-allowlist test
   updated and the -1 / clamp refusals tested against the fake transport.
4. **`btc_forwarder` itself**, `--dry-run` mandatory in this stage (the broadcast
   path is stage 3 and should not exist yet as reachable code). Signing proven
   against a known-answer BIP143 vector, and the assembled tx verified by
   re-deriving the sighash and calling `PublicKey.verify` on our own signature.
5. **The job wiring**, with the four tripwire tests updated and an end-to-end
   run through `tests/test_wake_endtoend.py`'s `cycle()` harness.
6. **Mutation anchors** for every guard that protects money: the constant-time
   refusal, the memo-size refusal, the xpub/seed match, the dust absorption, the
   settled-outputs-only rule, the fee clamp, the no-broadcast rule.
7. **Full suite + targeted sweep**, then commit.

Testnet comes with stage 3, where a broadcast exists to test. Stage 2's
deliverable is a signed transaction printed to a log and refused a broadcast.

---

## 8. Test harnesses to copy, by name

- **`tests/test_swap_receive.py`** is the canonical preparer harness — `load()`
  via `SourceFileLoader` for extensionless scripts, `mkdtemp` + `chdir` *before*
  loading (the module writes `integrity_chain.log` into cwd), and stubs set as
  **module attributes on the loaded module** because the tool does
  `from gs_common import safe_get, ...`. `class ThorRun` (`:114`) is the template.
- **`tests/test_send_gates.py:747`** — `_drive_split()`, the 20-attribute stub set
  with a `_post` that captures payloads and raises to halt early. Copy this to
  assert on what the forwarder *sends*.
- **`tests/test_btc_watch.py`** — the transport-factory seam, the in-process
  SOCKS5 + TLS Electrum mock, and the no-factory path that proves `look()`'s own
  wiring. The fee-estimate work extends this file's existing mocks.
- **`tests/test_wake_endtoend.py:209`** — `cycle(job, params, bay)` runs the real
  doorbell and the real agent against each other over real HTTP with a fake WOL
  socket. This is how the new job gets an end-to-end test.
- **`tests/test_wake_agent.py:140`** — `deps_for()`, whose injected `run_child`
  records `(argv, env_extra)` and returns `(0, False)`. This is how to assert the
  seed rides in the environment and never on argv.

Two harness traps: `safe_get`/`safe_post` call **`sys.exit`** on a falsy `proxies`
argument rather than raising, so a stub that forgets it kills the interpreter;
and `newnym(required=True)` also `sys.exit`s on failure rather than returning
False.

---

## 9. Hazards this stage does not close

Stated so the next stage does not inherit them silently.

- **Custody (hazard 1) is unchanged and real.** Between the client's payment
  landing and the forward, the host holds the client's BTC. Stage 2 does not
  move money, so it does not add exposure, but shipping stages 3+ does.
- **The floating rate (hazard 3)** is settled at forward time, so the deposit
  receipt's "you get back about X" becomes an estimate that needs reconciling
  against what actually arrives. That is stage 5.
- **The host's new on-chain footprint (hazard 8).** The client's footprint gets
  cleaner — a plain address, no public memo naming their XMR destination. The
  host gains one: host address → ThorChain, with the memo now on the *host's*
  transaction, publicly linking the host's forwarding address to a swap whose
  memo names the destination subaddress. Change outputs chain those forwards
  together over time. Stage 5 should consider a fresh forwarding path per
  deposit and never reusing change across clients.
- **A quote has no expiry field here.** The existing tool prints "Quotes expire"
  while fetching and enforcing nothing. Under a host-forward the gap between
  quote and broadcast is seconds rather than a human's minutes, which helps, but
  stage 3 should bound it explicitly rather than inherit the claim.
