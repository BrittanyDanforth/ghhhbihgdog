# Traceability Audit — Plain Language Risk Assessment

**What this is:** A honest breakdown of how traceable someone is if they use this toolkit, assuming the worst case — the source code is public, the person's computer gets seized, and investigators have blockchain data + network logs.

Every attack angle is rated by how likely it actually catches someone.

---

## THE BIG PICTURE

The toolkit does BTC → XMR conversion through ThorChain, then mixes the XMR across many wallets. There are 5 places where tracing can happen:

1. **The Bitcoin side** (public, fully traceable)
2. **The ThorChain bridge** (public, links BTC to XMR)
3. **The Monero side** (private by design, hard to trace)
4. **The computer itself** (files, logs, history)
5. **Network traffic** (who connected to what, when)

---

## ATTACK 1: Following the Bitcoin

### What the investigator does
They look at Bitcoin transactions on the public blockchain. They see BTC going to a ThorChain vault address.

### How catchable is this?

**If BTC came from a KYC exchange (Coinbase, Kraken, etc):**
- Catch rate: **~95%**
- The exchange has your name, ID, address. They see you sent BTC to a ThorChain vault. They tell investigators. Done.

**If BTC came from mining or P2P purchase:**
- Catch rate: **~10-20%**
- No direct name link. Investigators would need other evidence (IP logs, timing).

**If BTC went through a CoinJoin/JoinMarket tumble first:**
- Catch rate: **~5-15%**
- The tumble breaks the direct trail. Investigators can sometimes untangle CoinJoin with enough data but it's hard.

### What the toolkit does about this
- Warns you NOT to use KYC exchanges (big warning box)
- Supports JoinMarket tumble before ThorChain (--joinmarket flag)
- Warns about intermediate wallet usage

### What it CAN'T fix
- If you already sent from a KYC exchange, there's no un-doing that. The record is permanent.

---

## ATTACK 2: The ThorChain Bridge (The Weak Link)

### What the investigator does
ThorChain is a public blockchain. Every BTC→XMR swap is recorded permanently:
- How much BTC went in
- When it happened
- What the expected XMR output was
- The Monero destination address (but Monero addresses are one-time use, so this alone doesn't help much)

### How catchable is this?

**Amount matching:**
- If you swapped 0.5 BTC and then 0.5 BTC worth of XMR starts moving around Monero soon after — that's a strong signal.
- Catch rate from amount alone: **~30-50%** (depends on how unique the amount is)

**Timing matching:**
- If the swap completes and mixing starts within minutes — very obvious.
- Catch rate with immediate mixing: **~60-80%**
- Catch rate with hours/days delay: **~10-20%**

### What the toolkit does about this
- `--pre-mix-delay` flag: you can set hours or days of waiting before mixing starts
- `--mix-fraction`: don't mix 100% at once — mix 90% now, 10% next week
- Amount jitter: each individual Monero TX has a tiny random variation so they're not identical
- Split deposits: warns you to space them out over hours/days
- Quote expiry checking: won't let you use expired quotes

### What it CAN'T fix
- The ThorChain record is permanent. Anyone can see "0.5 BTC was swapped to XMR on this date."
- If the exact BTC amount is unique (like 0.4837291 BTC), it's a strong fingerprint.

---

## ATTACK 3: Monero Blockchain Analysis

### What the investigator does
They try to follow the XMR after it arrives. Monero uses:
- **Ring signatures**: each transaction includes decoy inputs so you can't tell which one is real
- **Stealth addresses**: each payment goes to a one-time address
- **RingCT**: amounts are hidden

### How catchable is this?

**Direct Monero tracing (without any other info):**
- Catch rate: **~1-5%**
- Monero's privacy is strong. Without the wallet keys, following the money is nearly impossible.

**If investigator has the wallet file:**
- Catch rate: **~90%+**
- With the wallet, they can see everything — all subaddresses, all balances, all transactions.
- The mixing subaddresses (14+ created by the toolkit) are permanently in the wallet.

**If investigator has timing data (from ThorChain + Monero mempool):**
- Catch rate: **~15-30%**
- Even with Monero's privacy, if you know WHEN the money arrived and WHEN mixing started, you can narrow the possibilities.
- The toolkit's exponential delay distribution helps but doesn't eliminate this.

**If investigator has the plan file:**
- Catch rate: **~99%**
- The plan file contains every source and destination address. Game over.
- The toolkit auto-deletes this after success, but if it's recovered (disk forensics, backup, etc), everything is exposed.

### What the toolkit does about this
- Auto-wipes plan file after successful mixing
- Auto-wipes integrity log after success
- Uses Monero's built-in privacy (ring signatures, stealth addresses, RingCT)
- Amount jitter between transactions
- Random delays between transactions
- Warns about wallet subaddress fingerprint (destroy wallet after use)
- Warns about output consolidation risk (don't sweep_all)

### What it CAN'T fix
- Monero ring signatures are probabilistic, not perfect. Advanced timing analysis can sometimes narrow the ring.
- Wallet subaddresses are permanent — they can't be deleted from the wallet file.
- If the wallet is seized before cleanup, the mixing graph is fully exposed.

---

## ATTACK 4: Computer Forensics (Seized Disk)

### What the investigator does
They take your computer and look for evidence. They search for files, logs, browser history, shell history, deleted files, swap partition contents.

### How catchable is this?

**If you ran paranoia_mode cleanup:**
- Catch rate: **~5-15%**
- Most files are overwritten and deleted. But:
  - SSD/NVMe: old data may persist in unmapped flash pages (~5% recovery chance)
  - Wallet subaddresses: still in the Monero wallet (if wallet isn't destroyed)
  - Wallet-rpc logs: if not launched with --log-level 0
  - Terminal scrollback: may persist in terminal emulator files

**If you did NOT run cleanup:**
- Catch rate: **~90%+**
- Plan files with full mixing graph
- Shell history with command lines and BTC addresses
- Integrity chain log (now hashed, but still shows activity timeline)
- Progress files, manifests, temp files
- Python __pycache__ with file paths

**If you have full disk encryption (LUKS):**
- Catch rate if they don't have your password: **~0%**
- Catch rate if they have your password: same as above (depends on cleanup)

### What the toolkit does about this
- Auto-wipes plan, staging dir, integrity log, __pycache__, /dev/shm after success
- paranoia_mode wipes 40+ artifact types across multiple directories
- All files written with 0600 permissions
- Shell history reminder after completion
- Wallet-rpc logging warning at startup
- Integrity log entries are hashed (opaque without source code)
- Warns about SSD limitations

### What it CAN'T fix
- Can't wipe wallet subaddresses (they're inside the Monero wallet)
- Can't wipe wallet-rpc logs (separate process, started before toolkit runs)
- Can't wipe terminal scrollback (depends on terminal emulator)
- Can't guarantee SSD secure delete (hardware limitation)
- Can't help if you forgot to run cleanup

---

## ATTACK 5: Network Traffic Analysis

### What the investigator does
They look at network connections. Even through Tor, they might see:
- Connection timing
- Data volume
- Connection patterns

### How catchable is this?

**If investigator controls your ISP only:**
- Catch rate: **~5-10%**
- They see Tor traffic but can't see what's inside it. They know you used Tor, not what for.

**If investigator controls Tor entry + exit nodes:**
- Catch rate: **~20-40%**
- This is the "global adversary" scenario. They can correlate timing of your connections with activity on THORNode/Monero nodes.
- The toolkit rotates circuits (newnym) between each TX to reduce this.

**If THORNode operator cooperates with investigators:**
- Catch rate: **~30-50%**
- THORNode sees Tor exit IP + request timing. Combined with blockchain timestamps, they can narrow down who made the swap.

### What the toolkit does about this
- ALL traffic goes through Tor (enforced, aborts if Tor isn't working)
- Circuit rotation between each TX
- Exponential delay distribution (looks like natural traffic)
- Browser-like headers on all requests
- Tor re-verification during long operations
- No DNS leaks (socks5h enforced)

### What it CAN'T fix
- Can't prevent a global adversary from correlating Tor entry/exit
- Can't prevent THORNode operators from logging exit IPs
- The BTC transaction itself (done OUTSIDE the toolkit by your Bitcoin wallet) may leak your IP if your wallet doesn't use Tor

---

## ATTACK 6: Social/Behavioral Analysis

### What the investigator does
They look for patterns in your behavior:
- Do you always mix at the same time of day?
- Do you always use the same amounts?
- Do you use the same machine every time?
- Did you talk about it online?

### How catchable is this?

**If you have consistent patterns:**
- Catch rate: **~30-60%**
- Same time every week + same amounts + same exchange = strong profile

**If you vary everything:**
- Catch rate: **~5-10%**
- Different amounts, different times, different networks

### What the toolkit does about this
- Random delays (exponential distribution, configurable range)
- Amount jitter on every TX
- Warns about pattern risks
- Pre-flight checklist in launcher

### What it CAN'T fix
- Your own behavior is your own responsibility
- The toolkit can randomize technical parameters but can't change your habits

---

## OVERALL RISK SCORES

### Scenario A: Best case (everything done right)
- BTC from non-KYC source via intermediate wallet
- Hours/days delay before mixing
- Mix only 80-90% at once
- Full disk encryption
- Paranoia cleanup after
- Destroy wallet after
- Vary timing and amounts between sessions
- **Combined catch rate: ~2-8%**

### Scenario B: Average case (some mistakes)
- BTC from KYC exchange but through intermediate wallet
- Some delay before mixing (30 min - 1 hour)
- Mix 100% at once
- No full disk encryption
- Ran cleanup
- **Combined catch rate: ~15-35%**

### Scenario C: Worst case (careless usage)
- BTC directly from KYC exchange to ThorChain
- Mixing starts immediately after swap
- Computer seized before cleanup
- No disk encryption
- Consistent patterns
- **Combined catch rate: ~80-95%**

---

## WHAT THE TOOLKIT ACTUALLY PROTECTS AGAINST (HONESTLY)

| Protection | Works? | Limitation |
|---|---|---|
| Hiding Monero transactions | YES | Ring signatures are probabilistic, not perfect |
| Breaking BTC→XMR link on chain | PARTIAL | ThorChain record is permanent and public |
| Hiding your IP | YES | Only if your BTC wallet also uses Tor |
| Cleaning up your computer | MOSTLY | SSD secure delete is imperfect; wallet subaddresses persist |
| Preventing timing correlation | PARTIAL | Delays help but can't eliminate |
| Preventing amount correlation | PARTIAL | Jitter helps but ThorChain record shows total |
| Preventing KYC attribution | NO | Toolkit warns but can't undo exchange records |

---

## THE THREE THINGS THAT MATTER MOST

1. **Where your BTC comes from** — this is 80% of the risk. KYC exchange = they know who you are.
2. **How long you wait before mixing** — immediate mixing after ThorChain swap = trivial to correlate.
3. **Whether your computer gets seized before cleanup** — if the plan file is found, everything is exposed.

The toolkit handles #2 and #3 well (with proper usage). #1 is entirely on the operator.
