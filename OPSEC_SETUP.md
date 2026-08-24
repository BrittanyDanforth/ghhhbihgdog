# Operator setup — reception vs custody

This is the hardware/network layout for running GhostSpiral **without**
leaving the spend key on a box that stays online, and **without** the
home ISP seeing Tor guards.

The Telegram **pager** — the phone-to-Pi trigger — **is** now in this repo:
`gs_telegram_pager`. It triggers and it does not carry: the only things it can
ask for are the three wake jobs, the only parameters it can send are a bounded
integer or a 4-hex handle, and the only thing it can say back is which job
finished and that handle (§8).
The **wake channel** between the Pi and
the ThinkPad *is* shipped: `gs_wake_keys`, `gs_doorbell` and
`gs_wake_agent`. So the vault can sit powered off for weeks and be woken
for one job at a time. Until you build a trigger you poke the Pi by hand
over SSH; until you set the wake channel up at all, you sit at the
ThinkPad and use `gs_console` the same way. The split below still
applies.

```
 phone (throwaway Telegram)
        |  "ready" / "landed" only — never the memo
        v
 Pi  ---- WireGuard ---->  Mullvad  ---->  Tor  ---->  Telegram / Thor
 ^         (pipe)           (ISP sees this, not Tor)
 |
 WOL + signed "do this job" on the LAN only
 |
 ThinkPad (off unless a receive is in flight)
   view-only wallet, own Tor over the same Mullvad pipe
   spend key is NOT here — LUKS USB, other room
```

Thor still links BTC deposit → XMR dest. That is the swap. This file
does not fix that. KYC BTC and a real-name Telegram account also are
not fixed by any of this.


## 1. What lives where

| thing | where | if seized |
|---|---|---|
| spend key / seed | LUKS USB, not in the laptop drawer | they can spend |
| view-only wallet | ThinkPad disk (auto-unlock so it can wake) | they can watch incoming |
| BTC address + Thor memo | ThinkPad file, `0600` — copy from the bay | they see that receive |
| bot token, chat id | Pi only | they can wake / spam `/depo` |
| Mullvad account number | paper / Pi `/etc`, not GitHub | they can use your pipe |
| mix / `run_pipeline` | ThinkPad, you present, USB plugged in | — |

Telegram never gets: wallet path, RPC URL, view key, spend key, seed — and by
default nothing else either, only which job finished and a 4-hex handle.

The XMR address and the memo (the memo **is** the address) are the exception,
and it is the operator's to make, on the vault, in a 0400 file. Three modes:

| vault keyfile | Telegram gets | you need |
|---|---|---|
| neither field | a handle | to reach the vault |
| `delivery_public` | a sealed blob | `gs_delivery.key` on some machine |
| `plain_slip: true` | the address and memo, in the clear | a phone |

Nothing on the Pi and nothing in a chat can change which mode is in force.
§8 has what each costs — including the part of the plaintext cost that is
about **money** rather than privacy, which you must read before setting it.


## 2. Buy list

**Doorbell (always on)**
- Raspberry Pi **3B+** (1 GB) or **Pi 4 2 GB**. 1 GB is the floor.
  A Zero (512 MB) will swap under Tor. Do not buy an 8 GB toy.
- Official PSU, **ethernet** cable, 16 GB SD + a second SD already flashed
- Case, leave it in a closet next to the switch. A few watts.

**Vault (off by default)**
- Cheap ThinkPad, 8 GB RAM is plenty (wallet-rpc + Tor, not a node)
- Ethernet. BIOS: WiFi off, Bluetooth off, **Power Loss: Stay Off**
- Enable Wake-on-LAN
- Full-disk LUKS. Unlock must work **without you** or the Pi cannot
  wake a job — see §5. That means TPM/keyfile auto-unlock of the
  **view-only** volume only.

**Spend**
- Separate USB, its own LUKS passphrase. Different hiding place.
  Never left in the ThinkPad after a mix.

**Pipe**
- Mullvad account (number, no email). Pay cash or coin, not your card.
- WireGuard config for **one** device: the Pi. ThinkPad exits through
  the Pi, it does not get its own Mullvad key.

**Phone**
- Throwaway Telegram, not your real account, not your daily SIM.
  If the pager is your name, the rest is decoration.


## 3. Pi — doorbell

Raspberry Pi OS **Lite** (64-bit). No desktop. Ethernet only.

```bash
# as root, once
rfkill block wifi
rfkill block bluetooth
systemctl disable wpa_supplicant 2>/dev/null || true

apt-get update
apt-get install -y wireguard tor wakeonlan python3

# hostname that is not your name -- and not this one either. Every
# reader of this public repository knows to look for a host called
# "fuse" on a home LAN. Pick something that belongs on your network:
# the name of your router's brand, "printer", "nas". A hostname is
# broadcast in DHCP requests and answered over mDNS; it is the one
# identifier you hand out to everything on the switch.
hostnamectl set-hostname <something boring and yours>
```

### The SD card is the leak, and it is a bigger one than the wake key

Take the card out, put it in any laptop, and `chmod 600` means
nothing — you are root on the machine doing the reading. So the
question is not whether anyone would think to look. It is what is
there:

| on the card | what it gives them |
|---|---|
| `/etc/wireguard/wg0.conf` | **your Mullvad private key.** Mullvad can map it to your account, and whoever paid for that account. This is your network identity, and it is the single worst thing on the box |
| `/var/lib/tor/` | the Tor client's state, including its **guard set** — a fingerprint that persists across restarts and links this Pi to circuits seen elsewhere |
| `/etc/gs_wake_pi.key` | **sealed** with your passphrase since the pairing rewrite. Yields Argon2id parameters and a salt. Before that it yielded the wake key, the ThinkPad's MAC and your LAN layout in one file |
| the systemd journal | the minute of every poke, and — until the `StandardOutput=null` in `systemd/gs-doorbell.service.example` — the name of every job |

The wake keyfile is sealed. **The other three are not**, and no amount
of work on the wake channel touches them. If you stop reading here,
stop having read that.

**The fix is to encrypt the Pi, and it costs you something real.**
Raspberry Pi OS does not do this out of the box; the standard way is
LUKS on the root filesystem with `dropbear-initramfs`, so the Pi comes
up into a tiny SSH server and you unlock it remotely:

```bash
apt-get install -y cryptsetup-initramfs dropbear-initramfs
# put your public key in /etc/dropbear/initramfs/authorized_keys,
# set ip= in /boot/cmdline.txt so initramfs brings the NIC up,
# then luksFormat the root and rebuild the initramfs.
```

The cost, stated plainly: **after a power cut the Pi does not come
back on its own.** No unlock, no doorbell, no wake, until you are
somewhere you can SSH to it. That is consistent with the rest of this
layout — the ThinkPad's BIOS is already set to stay off after power
loss — but it means a blackout while you are away costs you the
doorbell until you return.

What encrypting the Pi does **not** fix: if it is seized while
running, the volume is unlocked and the key is in RAM. Full-disk
encryption protects a card in a pocket, not a box on a shelf with
power going into it. If that is the threat you care about, the
doorbell should not exist and you should sit at the ThinkPad.

If you will not do this, then treat the Pi as **public**: use a
Mullvad account you can burn, and expect to replace it and re-key
everything if the Pi ever leaves your sight.

`/etc/sysctl.d/99-fuse.conf`:

```
net.ipv4.ip_forward=1
```

### Mullvad first, Tor inside

1. Mullvad site (over Tor from some *other* machine) → WireGuard config.
2. Install as `/etc/wireguard/wg0.conf`, `chmod 600`.
3. `systemctl enable --now wg-quick@wg0`
4. Check: `curl https://am.i.mullvad.net/connected` should say yes.
   The home ISP now sees one VPN to Mullvad, not Tor.

`/etc/tor/torrc` — Tor must use the tunnel, and fail if the tunnel is down:

```
# do not listen to the world
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 1

# only after wg0 is up (use a systemd After=wg-quick@wg0.service)
# Isolate the client: no default route except the VPN.
```

Force the Pi’s default route through `wg0` only. If Mullvad is down,
**nothing** else leaves the ethernet (no “just this once” clearnet).
`systemctl enable tor` with `After=wg-quick@wg0.service` and
`Requires=wg-quick@wg0.service`.

The bot (when it exists) talks to Telegram **only** via `socks5h://127.0.0.1:9050`.
If Tor is down, the bot does not start. Same fail-closed as `gs_console`.

### Wake-on-LAN is not a login

WOL is a magic packet on the LAN. Anyone on the switch can send one.

- Do **not** forward UDP 9 on the router.
- ThinkPad only runs a job after a **signed** note from the Pi
  (shared key on the Pi and the ThinkPad). Random WOL = boot, sit,
  shut down.
- Pi and ThinkPad on the same switch. No WAN path to WOL.

### What the Pi must never hold

Spend key, view key, `wallet_*.json`, `thor_pairs.json`, memo, seed.
If you find any of those on the SD, the split is already broken.

`gs_doorbell` imports nothing but the standard library and PyNaCl, and
`tests/test_opsec_doc.py` asserts that — it may not import `gs_common`,
`monero`, `stem`, `psutil` or `requests`, and may not reference
`wallet_`, `thor_pairs`, `view_key`, `spend_key`, `mnemonic` or `seed`.
That is a test, not a paragraph, because a promise about what a file
does not contain is worth exactly as much as the thing that checks it.

**And it must not hold a record of what it did.** The example unit sets
`StandardOutput=null` and `StandardError=null`. Without those, systemd
journals the tool's own output onto the SD card — which names the job
it dispatched, the handle that came back, and the minute of both. The
handler's HTTP logging was already silenced; the unit's stdout was not,
and that is the copy that survives.


## 4. ThinkPad — vault

Debian or whatever you already run. Disk encrypted.

**BIOS**
- WiFi / BT disabled
- WOL enabled
- After power loss: **Off** (a blackout must not auto-boot it)

**Network**
- Ethernet to the same switch as the Pi
- Default route = the Pi (Pi NATs onto Mullvad). The ThinkPad never
  speaks to the home ISP.
- Run **its own** Tor on the ThinkPad (`127.0.0.1:9050`). Do not use
  the Pi as a Tor proxy — a pwned Pi would sit on the path.
  `gs_wake_agent` takes its proxy from its **own keyfile**, never from
  the wake note, so a pwned Pi cannot supply one. That is checked by
  `tests/test_opsec_doc.py`, not merely promised here.
  Cost: when a job is running, Mullvad sees two Tor clients in one
  tunnel. The ISP still only sees Mullvad.
- The Pi is still your default route, and it now also knows **which job
  it dispatched and roughly when**. Running your own Tor means the Pi
  cannot read or redirect the circuit; it does not make the Pi blind to
  timing and volume.

**Wallet — accounts, not just subaddresses**

Monero returns a transaction's change to the **spending account's subaddress
0**. So whatever a mix does not allocate — the fan-out remainder, the dust
from every hop — comes to rest on the subaddress 0 of whichever account the
run used. If that is account 0, it is the wallet's own primary address, on
every run, and two runs sharing a change address are trivially the same
wallet.

So: `create_receive_wallet` issues a **fresh account per receive**, and a send
runs the mix in a **fresh account** too. The wallet's primary address is not a
participant in the pipeline. Verified on-chain by
`tests/real_fanout_change_testnet.py`.

Do not point the pipeline at account 0 with `--account 0` unless you have a
reason; it warns, and the warning is the whole story above.

**Nothing is left parked.** A distribution cannot allocate its input exactly
— the fee is not known when the amounts are chosen — so a remainder always
comes back as change. Rotating the account moved that off your primary
address, but the value still sat there: unmixed, and the one fan-out output
that never moved. It is now **swept into the mix** (`sweep_all`, zero change
of its own) after the distribution, in both fan-out and peel modes. That is a
correctness fix as much as an OPSEC one — roughly a tenth of the balance was
previously never mixed at all while the run reported success.

**The entry is the one output an analyst is handed for free, so the run does
not spend it in the open.** A ThorChain swap's memo is public: it names the
address the swap paid, so anyone watching knows which on-chain output funded
your run. Ring signatures still hide *which* later transaction spent it — an
analyst has sixteen candidates per ring and no way to pick — **unless the real
transaction looks different from the rest of the network.** Measured on a chain
running current consensus, the first transaction out of the entry used to be:

| first spend out of the entry | shape | extra |
|---|---|---|
| fan-out mode (the default) | 1-in / **7**-out | 259 |
| peel mode | 1-in / **3**-out | 131 |
| an ordinary sweep | 1-in / 2-out | 44 |

Two outputs is what most of the network makes. Seven is not — so an analyst
holding the swap output does not need to break a ring, he lists the
transactions that reference it and keeps the odd-shaped one.

The run now sweeps the entry **once** into a fresh carrier first — 1-in/2-out,
zero change — and distributes from that carrier. Every transaction after it
spends an output nobody outside your wallet can enumerate. It costs one
transaction, one fee and one confirmation wait, and it inherits `--hop-delay`,
which matters more here than anywhere else: this is the only hop where an
analyst knows both endpoints of the wait. `--no-entry-veil` turns it off and
says what that costs.

**The exit is where a mix is usually lost, so the outputs are built to make
losing it hard.** A run ends with N outputs that you eventually spend, and
until now they all sat in one account. Measured on a chain running current
consensus, six mix outputs in one account:

| what the operator does | on-chain |
|---|---|
| "empty this account" | **one transaction, 6 inputs** |
| "send 5 XMR" | **one transaction, 4 inputs** |

A transaction's inputs are public. Spending six outputs together is permanent
proof that all six have one owner — no ring analysis, the input count is right
there — and those six are exactly what the peel chain spent six transactions
and several hours separating.

`--exit-to <address>` performs the withdrawal for you, **one transaction per
output**, so the merge never happens by accident. Repeat the flag to spread the
withdrawal across several destinations. Without it nothing is withdrawn and the
funds simply stay on the wallet — the run tells you so rather than implying it
exited.

Every output the run creates now lives in **its own account**. That makes the
merge impossible rather than merely discouraged, because a Monero transaction
cannot spend across accounts — asking one account for more than it holds
answers "not enough money" while a sibling account holds the rest. The same
six outputs then leave as six 1-in transactions for about 0.005 XMR more in
fees. `tests/real_spend_account_testnet.py` asks the wallet to prove it rather
than reasoning about it.

What this does **not** solve: sending all six to one exchange deposit address
tells that exchange they are yours. That is a custodial link, not a chain
link, and no on-chain structure can remove it — which is why `--exit-to` is
repeatable, and why splitting across venues and over time is the operator's
call rather than something the software can do for them.

**The exit address must be somewhere else, and both tools now refuse
otherwise.** Two mistakes are unrecoverable and, until this was added, nothing
looked for either:

* `--exit-to` naming an address **this run created** — its ENTRY, or one of
  its mix subaddresses. ENTRY is what the ThorChain memo publishes in a
  Bitcoin `OP_RETURN`, so withdrawing to it sweeps every mixed output back
  onto the one address an analyst already has. A mix subaddress is the other
  half: every output would land on one address, undoing by hand the
  one-account-per-output separation above. GhostSpiral checks this in stage 3
  — after the addresses exist, and still before the swap is quoted, so the run
  dies before any Bitcoin is deposited.
* A **swap destination that is your exit address**. `thor_swap_preparer`
  refuses when the resolved XMR destination appears in `GS_EXIT_TO`. The swap
  memo is written into a public, permanent Bitcoin `OP_RETURN` naming the XMR
  address in full — put your final address there and it is simply printed on
  the Bitcoin chain, with no mixing to follow and nothing downstream able to
  retract it. This one only works if `GS_EXIT_TO` is set (below); with the
  variable unset the tool has nothing to compare against and says so rather
  than implying it checked.

The swap destination is a **throwaway** that GhostSpiral then mixes away from
— that is what `create_receive_wallet` mints and what
`--dest-from-receive-wallet` passes. It is not where you want the money to end
up.

`exit_strategy_simulator` is a **standalone valuation reference**, not the
exit. It fetches a live price and reports what a holding is worth; it moves no
XMR, contacts no venue and places no order, and the pipeline no longer runs it.
The exit is `--exit-to`.

**Create the offline spend wallet with a large subaddress lookahead.** A
Monero wallet only derives subaddresses for a bounded number of accounts — 50
by default — and that bound is fixed when the wallet is **created**:
`monero-wallet-cli` refuses `--subaddress-lookahead` alongside `--wallet-file`,
so an existing wallet cannot be told a bigger number.

Isolating every output costs roughly twenty accounts per run, so the online
view-only wallet passes 50 accounts during your **second** run. After that the
offline wallet cannot derive the keys for the exported outputs:
`import_outputs` fails with *"Failed to generate key image"* and
`sign_transfer` prints *"Loaded 1 transactions"* and writes nothing. Nothing is
lost, but the round will not sign.

So restore the offline wallet from its seed with room to grow:

```
monero-wallet-cli --restore-deterministic-wallet     --generate-new-wallet /path/to/offline-wallet     --subaddress-lookahead 400:50
```

If your offline wallet already exists, you do **not** have to recreate it:
`phase_create` records how many accounts the online wallet has and
`phase_sign` creates the missing ones on the offline wallet before importing
(about half a second each, once — accounts persist). The lookahead above just
makes that unnecessary. `tests/real_cold_lookahead_testnet.py` pins both
halves, including a negative control that fails without the fix.

**How far apart the hops land is yours to choose, and the default is not the
strong setting.** A peel hop cannot be built until the previous hop's output
has confirmed and unlocked — about 10 blocks — and `--hop-delay` is added on
top of that. The default is 180–720 seconds, so each carrier output is spent
at roughly 11–16 blocks of age and a six-hop chain finishes inside two hours.

That is close to the youngest an output can legally be spent. Monero's decoy
selection draws ring members from a distribution fitted to how people actually
spend, and its bulk sits far above that floor, so an output spent at the floor
tends to be the youngest member of its own ring — and "assume the newest ring
member is the real one" is a standard heuristic against exactly that shape.
The peel chain removes the co-created fan-out an analyst can cluster; it does
not remove this.

This has **not been measured here** and no number is claimed for it. Doing it
honestly needs a chain with a realistic output-age distribution, and the
throwaway chains these tests run on have none — every output on them is
minutes old, so any ring-age statistic they produced would be an artifact.

`--hop-delay 21600-86400` spreads a six-hop chain over days: it costs time and
buys ring-age plausibility. The default stays short so a run finishes in one
sitting, not because it is the better choice.

**...and the sweep is not allowed to undo the peel chain.** Monero returns a
transaction's change to the *spending account's* subaddress 0, and that is not
selectable. When every peel ran in one account, all N peels deposited their
change onto one subaddress 0 and a single sweep collected the lot — one
transaction with N inputs. A transaction's inputs are public, so spending N
outputs together is permanent proof that those N outputs share one owner, and
it takes no ring analysis to read: the input count is right there. Those N
outputs are the change of the N peels, so that one tidy transaction announced
that the whole chain was one entity — the exact fact it spent N transactions
and several hours concealing.

Each peel now runs in its **own account**, so each hop's change lands on a
different subaddress 0 and is swept **alone**, to its **own** destination.
Measured on a chain running current consensus: six peels swept together
produced one 6-input transaction; swept separately they produced six
1-in/2-out transactions — the commonest shape on the network — for about
0.005 XMR more in fees against a 0.0024 XMR estimate. That fee difference is
the entire cost of not announcing the link.
`tests/real_peel_testnet.py` asserts the property directly: **no transaction
in the run may spend more than one input.**

The same rule bites per hop, not just once. A DAG hop that sent a *fixed
amount* had to pick that amount before the fee was known, so it always left a
remainder — 40 hops at `wallets=10 deep=2`, each dropping dust on that one
address. Hops are now **sweeps** (`sweep_all`: move the whole subaddress
balance, minus fee), which produce **no change output at all**. Verified
end-to-end through the cold path by `tests/real_hop_sweep_testnet.py`: every
hop returned nothing to the account.

**Wallet**
- `monero-wallet-rpc` with a **view-only** wallet (create it from the
  spend wallet on an offline machine, then copy the view-only files).
- `create_receive_wallet` / `thor_swap_preparer` / `receive_watch` /
  `gs_console` all point at that RPC.
- Console binds `127.0.0.1` only. Do not punch it out.

**Nothing identifying goes on a command line**

`/proc/<pid>/cmdline` is mode **0444** — every account on the host can read a
running process's arguments — while `/proc/<pid>/environ` is **0400**. So the
console hands its children the sensitive values through the environment, not
argv: `GS_BTC_ENTRY` (your Bitcoin address), `GS_BTC_AMOUNT`,
`GS_SWAP_AMOUNTS`, `GS_EXIT_TO` (your withdrawal destination),
`GS_EXPECT_TOTAL_XMR` (how much XMR this run is waiting for),
`GS_USAGE_FEE_ADDRESS` and `GS_USAGE_FEE_PCT` (see below), and
`GS_WALLET_PASSWORD` as before. (`GS_EXIT_AMOUNT` was listed here too and never
was: `exit_strategy_simulator` reads it when you run that tool by hand, but the
console has never set it. A list of protections is worth nothing if entries can
sit on it unearned, which is the same defect as the sentence below once was.) The command preview the page shows you is
the real argv, which is why no secret appears in it.

`GS_USAGE_FEE_PCT` is on that list for a reason that is easy to talk yourself
out of. The console used to compose `--usage-fee-pct 0.011` onto argv under a
comment saying the percentage "is a setting, not an identifier, and it is
already visible in the amounts". Both halves are wrong. A local reader of
`/proc/<pid>/cmdline` sees argv and does **not** see the amounts — those are
inside RingCT and inside plan files under a `0700` directory — so argv was not
a second copy of something public, it was the only disclosure of the number
that turns an observed cash-out back into the deposit behind it. The switch
`--usage-fee` still rides on argv: it is a boolean whose name is in the
public source. `GS_USAGE_FEE_ADDRESS` is the stronger case of the same rule —
one address collecting a slice of every run is the single value that could
re-join what all of those runs separated.

`GS_EXIT_TO` was missing from that list for as long as the list existed, and
the sentence above was false because of it: the console composed
`--exit-to <address>` onto GhostSpiral's command line. That is your FINAL
destination — the one address this whole pipeline exists to keep unlinkable
from the public ThorChain memo — and it sat in `ps` output, and in the preview,
for the several hours a run takes. Running GhostSpiral by hand, `--exit-to`
still works and warns.

Running a tool by hand still accepts the flags — it warns and logs when you do.

**What the wallet file gives away**

`paranoia_mode` wipes the pipeline's artifacts and **never touches the wallet
file** — that file is your money. So the wallet survives every wipe, holding
the balances, the transaction history and every subaddress a run created:
the whole mix graph. Section 6's "door kick, they take the ThinkPad → partly"
is exactly this.

**Your receive address is public, so dust can be sent to it**

The swap memo names your XMR address in plain text and the sender puts that
memo in the Bitcoin transaction's OP_RETURN. So the swap provider — and anyone
reading the Bitcoin chain — knows exactly where to send. That costs them one
transaction fee.

`receive_watch` therefore ignores balances below an **arrival floor**: the
larger of 0.0005 XMR and 0.1% of the target. Below that, a balance is reported
but is not treated as the payment. It is not an arbitrary number — an output
smaller than the fee needed to spend it is not money you can act on, so
counting it as an arrival is wrong even with no attacker present.

Without that floor, one piconero was enough to make the tool assert *"the swap
paid short"* when nothing had arrived, and one piconero every 25 minutes held
the shortfall verdict off for the entire 24-hour watch. `--min-arrival` changes
the threshold; `--min-arrival 0` restores the old, steerable behaviour and says
so when you use it.

**The swap is seen. Plan around it, not against it.**

A BTC→XMR aggregator has to be **told** where to deliver the Monero. That
instruction rides in the memo attached to the sender's Bitcoin payment, so the
aggregator — and anyone it shares with, or anyone who later compels it — can
tie *that BTC payment* to *your first XMR address*. Tor hides who arranged the
swap. It does not hide the link, and nothing in this toolchain can retract it.

The mixing that follows hides what you do **next** with the Monero. That is
the whole and only claim. So:

- **One fresh receive address per swap.** `thor_swap_preparer` *refuses* a
  batch that routes two swaps to the same address — reusing one hands the
  aggregator a link between those BTC payments, which is exactly what
  splitting the amount was meant to avoid, and it silently defeats the NEWNYM
  rotation between quotes (a new circuit cannot disguise identical request
  bodies). Mint them with `create_receive_wallet --count N` and pass every
  bundle to `--dest-from-receive-wallet`.
- **`--split N` obeys the same rule now, and it used to be refused for
  breaking it.** GhostSpiral routed every chunk of a split to ONE entry
  address, which cost all three of the above *and* something worse on-chain:
  the entry veil swept all N chunks in a single transaction whose N input
  rings each contained a publicly-known swap output, so intersecting them
  identified the carrier the rest of the run spends from. A split run now
  mints **one entry address per chunk**, quotes each chunk to its own address,
  veils each into its own carrier, and gives each carrier its own fan-out over
  its own slice of the mix subaddresses. The invariant that makes it safe is
  stronger than "the veil has one input":

  > **No transaction ever spends value derived from two different swap
  > chunks.**

  Veiling the chunks separately into a *shared* carrier would not be enough —
  the convergence would simply move to the distribution, where the same
  intersection works. So there is no convergence transaction at all. `--split`
  is capped at 8 (every chunk costs a swap fee, a veil transaction and a
  wallet account, and the offline signing wallet derives subaddresses for a
  bounded number of accounts), and it is **not supported with `--peel`**: each
  chunk would need its own sequential, confirmation-gated chain. That is
  refused when the flags are parsed, not when the distribution is built —
  refusing later would mean refusing after the deposit instructions were
  printed, possibly after you had already sent Bitcoin.
- **The chunks are UNEQUAL, and that is not cosmetic.** They used to be an
  exact division, so a `--split 4` run told you to make four deposits of an
  identical amount, within minutes, to the same vault. That is one cluster on
  the *Bitcoin* chain, and the OP_RETURNs then read out all four Monero
  destinations — the careful Monero-side separation undone by the side of the
  transaction nobody was looking at. Each chunk is now jittered, and they sum
  to exactly what you asked for. `--btc-amount` finer than a satoshi is
  refused rather than rounded: rounding would swap a different amount than you
  asked for, and the deposit line would name a figure no wallet can send.
- **A hop never crosses chunks either.** The DAG round is a permutation, so a
  mix subaddress that hops its own output away ends holding exactly one output
  and whose it is does not matter. But an output too small to fund a hop, or
  one that could not be given a destination, does *not* hop and can still
  receive one — keeping its own output *and* the incoming one. With one chunk
  that is harmless. With several, the exit's per-subaddress sweep would then
  spend two chunks in one transaction. Hop destinations are drawn from the
  source's own chunk, so it cannot happen.
- **A chunk that does not arrive does not sink the run.** The arrival gate
  compares the *sum* against the target, so one swap overshooting can cover
  another that has not landed. Chunks that arrived empty — or too small to
  fund even one mix output — are dropped, named, and their entry addresses
  stay held back from the exit, so a late arrival is never swept to your
  destination in one hop. The rest of the run continues.
- **Spending one output of an address holding several is not available, and
  that is structural.** `sweep_single` names its target by key image, and the
  online wallet is **view-only** — it cannot compute key images at all.
  Obtaining them would need a third air-gap crossing, offline → online,
  ordered *before* the phase it feeds; `sweep_single` also takes no
  `account_index`, so the one-account-per-hop invariant would stop being
  enforceable; and the signing fingerprint has no key-image field, so two
  plans naming different outputs would hash identically. The signer refuses
  such a plan outright rather than letting it fall through to an ordinary
  transfer that ignores the key image.
- **Treat the receive address as burned** once the swap is arranged. Let the
  mix move the funds off it; do not reuse it for anything.
- **Keep the memo off anything public.** It names your XMR address in plain
  text. A paste site, an issue tracker, a group chat — anything indexed turns
  a link one company holds into a link everybody holds.
- **If you do not want any party to see the destination, an aggregator is the
  wrong tool.** This one cannot route without being told.

**What is *not* at risk: your wallet, from the chain.** Nobody reads your
balance off the blockchain. Monero hides the amount and the spender, and your
view key is not derivable from chain data. A view key leaks exactly one way —
somebody gets your **files**: the online view-only box, a laptop that
auto-unlocks, a backup, or a key you pasted somewhere. That is a
disk-encryption and physical-custody problem, and it is precisely the one
`paranoia_mode` deliberately cannot solve for you (see the wallet note above).

**Close your terminals BEFORE you wipe**

A shell keeps its history in **memory** and writes it out when it **exits**.
`paranoia_mode` wipes the history file, but it cannot reach into a running
shell — so any terminal still open will write its history straight back when
you close it. Demonstrated: a bash session holding
`GhostSpiral --wallet-password s3cret…` had the file wiped to zero bytes, and
bash restored the password verbatim on exit.

The wipe now says this out loud, but the remedy is yours: in every open window
run `history -c && history -w` (fish: `history clear`), or close every terminal
first and run the wipe from a fresh one.

It also now covers the history files it used to miss entirely — **fish**
(`~/.local/share/fish/fish_history`), a custom **`$HISTFILE`**, `.zhistory`,
`.sh_history` and `.ash_history`. Previously a fish user's wipe erased nothing
they had typed while reporting success.

**Where the wipe reaches (and where it did not)**

`paranoia_mode`'s Temp files phase sweeps `/tmp` and `/var/tmp` wholesale for
anything you own. It now also sweeps **`/dev/shm` and `$TMPDIR`** — but only
for this toolchain's own scratch names (`gs_sign_*`, `gs_impout_*`,
`.gs_pw_*`), never wholesale.

That gap mattered because `airgap_tx_signer` *prefers* `/dev/shm` for its two
worst artifacts: the plaintext wallet password, and the wallet output-set blob
(a map of your holdings). Both are erased in a `finally`, so a normal run left
nothing — but a SIGKILL, an OOM kill or a power cut runs no `finally`, and
`/dev/shm` is a tmpfs that survives all but the power cut. Choosing RAM-backed
scratch made those files *more* dangerous to leave behind, not less: what is
there is the copy that existed at the moment things went wrong.

`$TMPDIR` was the same story for `gs_sign_*`, which holds a signed, relayable
transaction: `mkdtemp()` honours `TMPDIR`, and the sweep only knew `/tmp`.

The targeting is deliberate and must stay that way. `/dev/shm` holds live
segments belonging to Chromium, PostgreSQL and PulseAudio under your own uid —
wiping it wholesale breaks running software — and `TMPDIR` can legitimately
point at `$HOME`.

Subaddresses are therefore created with **no label**. They used to be tagged
`Mix_0`, `Decoy_3`, `Carrier_2`, `ChangeSweep`, `GhostSpiral_entry` — local
only, invisible on-chain, and a complete annotated map to anyone who opens the
wallet. Every on-chain heuristic this tool defeats was bypassed by reading a
string. Protecting the wallet is disk encryption and where the keys live, not
the wipe.

**Spend USB**
- Only plugged in to mix / cold-sign (`airgap_tx_signer`).
- Auto-job user on the ThinkPad must **not** be allowed to mount
  removable disks. If you leave the USB in and `/depo` wakes the
  box, you put custody on a networked machine. That is the failure
  this whole layout exists to prevent.

**Unattended boot (the trade you cannot dodge)**

The Pi cannot type your LUKS passphrase.

- Human passphrase at boot → no remote `/depo`. Babysitting.
- TPM / keyfile auto-unlock of the view-only OS → a thief who takes
  the **whole laptop** and plugs it in gets view-only.
- Steal-the-SSD-only is blocked if the key is in the TPM.

If you will not accept “laptop theft = they can watch incoming,”
there is no doorbell. Stop here and use the console by hand.


## 5. Job cycle

Steps 1–2 are `gs_telegram_pager`. Step 3 onward is `gs_doorbell` and
`gs_wake_agent`. You can still do steps 1–2 by hand — the pager only pokes the
doorbell, so anything it does you can do from a terminal.

1. Phone: `/recv` then `/depo` to the throwaway account. **A SLOT, not
   an amount**: the ladder lives on the ThinkPad and the Pi's keyfile does not
   contain it, so the Pi cannot turn "0.05" into a slot and is never given the
   chance to send a number (§8).

   `/depo` on its own asks which slot and then confirms, because the one
   command that spends a wake and quotes real money should not be a single
   keystroke. `/depo 2` still works in one shot. The confirm is a small sum —
   it stops a pocket-dial or a message pasted into the wrong chat, and it is
   **not** a security control: anyone holding the phone can read it and answer
   it. The bounds that matter are the 24 h wake budget and the account
   ceiling, both in a keyfile that needs physical access to change.

   Three things the chat will not set, and where each really lives:

   | `/fee` | the BTC network fee is your sending wallet's; `--max-slippage` is a vault-side refusal threshold |
   | `/speed` | not settable by anyone today — `thor_swap_preparer` does not request streaming, so the memo's `limit/interval/qty` tail comes back already fixed |
   | `/exit` | `GS_EXIT_TO`, at the vault, at mix time — this channel can never name or select a destination |
2. Pi checks Tor, allowlisted chat id, rate limit.
3. `gs_doorbell wake` binds its LAN socket **first**, waits a random
   0–15 min, then sends the magic packet and holds one job for 10 min.
   It hands that job over **at most once**, sealed to a public key the
   booting ThinkPad mints for that boot alone.
4. ThinkPad boots. `gs_wake_agent` checks it can do the job **before**
   asking for one — deadman armed, no removable disk attached, disk and
   RAM fine, its own Tor up — so a boot that cannot work does not burn
   the poke. Then it waits a **random 5–20 min** and runs
   `create_receive_wallet` and `thor_swap_preparer` as one job.

   Which jitter breaks which link, stated honestly: the Pi's pre-WOL
   delay decorrelates *poke → power spike*; the ThinkPad's 5–20 min
   decorrelates *boot → ThorChain*. **Nothing** decorrelates *boot →
   a second Tor client appearing in the Mullvad tunnel*. The ThinkPad's
   jitter is the floor because a pwned Pi can zero its own.
5. Slip stays on the ThinkPad (`0600`). Telegram gets `depo ready · slip A3F1`.
6. You copy BTC address + memo from the bay (or the file). Not from chat.

   **Unless you cannot get to the bay**, which is the case this design
   assumes and then never handled. A vault that is far away and hard to
   reach is the point of having one, and "read it on the vault" is not an
   OPSEC property when you cannot — it is a quote you are told about and
   cannot pay, which expires. So set up a **delivery key** (§4a below) and
   the slip travels **sealed**: Telegram carries 568 characters of base64,
   the Pi holds no key for it, and you open it with `gs_unseal` on the
   machine you send the BTC from — the one that already runs Electrum or
   Sparrow for the OP_RETURN.

   Set up no delivery key and nothing changes: no slip is sealed, none
   travels, and step 6 is exactly what it was.
7. ThinkPad `receive_watch` until landed **or 2 h** (`--timeout-min 110`,
   inside a 7200 s budget — the doc and the code say the same number),
   then **power off**. Power-off is three independent root-owned paths:
   the agent's own `finally`, `OnFailure=` on its unit, and a deadman
   timer armed at boot that does not depend on the agent being alive.
   The only two things that stop it are an inhibit file and a live
   GhostSpiral run lock — both mean a person is at the machine. The
   inhibit file has a name and a place, and it is no use to you unless
   you know both, so: it is `.gs_wake_inhibit` **in the artifact
   directory the keyfile names**, not in your home directory.

   ```bash
   touch /var/lib/ghostspiral/.gs_wake_inhibit    # sitting down at the vault
   rm    /var/lib/ghostspiral/.gs_wake_inhibit    # done; it can wake again
   ```

   While it exists, a woken boot refuses the job, does **not** power off,
   and disarms the deadman so nothing takes the machine down under you.
   Leave it there and the vault is simply not wakeable — which is the
   correct trade for the hour you are using it, and the wrong one to
   forget about for a week.
8. Idle weeks: ThinkPad is off. Only the Pi hums.

Until the bot exists: skip 1–3. You are at the ThinkPad. Same files,
same “memo never leaves the machine except to the sender.”


## 6. Bad situations (and whether this beats them)

| happens | beaten? |
|---|---|
| ISP “this house runs Tor” | **Yes** — they see Mullvad |
| Hotspot / SIM / towers | **Yes** — no cellular |
| VPS host images a wallet | **Yes** — no wallet on Mullvad |
| Door kick, Pi only | **Depends entirely on whether you encrypted the Pi (§3).** The wake keyfile is sealed with your passphrase, so the card alone no longer yields the wake key, your ThinkPad's MAC or your LAN layout — it yields Argon2id parameters and a salt. But an unencrypted card still hands over `/etc/wireguard/wg0.conf`, which is your **Mullvad private key**, and `/var/lib/tor`, which is your **guard set**. Those are your network identity and no work on the wake channel touches them. Wake traffic recorded off the switch stays sealed either way: each job note is boxed to a key the vault minted for that boot and then powered off with. Recovery is a two-box re-key (two commands, §8), plus a new Mullvad account |
| Door kick, they take the ThinkPad | **Partly** — view-only if auto-unlock; spend USB elsewhere |
| Spend USB left in the laptop | **No** — you blew the split |
| Stolen Telegram / bot token | **Partly** — they can wake and spam quotes, not spend, and the spam is bounded on the ThinkPad rather than on the stolen thing: a 24 h wake budget (12 by default) and an account ceiling (45) that refuses minting jobs once the wallet holds more subaddress accounts than the offline signer derives. Both live in the keyfile, so changing them needs physical access. What they still get is your vault powering on when they say |
| Somebody on the switch during PAIRING | **Only if you compare the code.** The two boxes have never met, so nothing but you can tell the real peer from an impostor. Each commits to its key before seeing the other's, which is what stops an attacker grinding keys until the two codes agree — so the 8 characters you compare are worth 2^40 and a man in the middle has to guess once, in public, with you looking at it. If you do not actually compare them, this is unauthenticated key agreement and the software cannot tell |
| Roommate sends WOL | **Yes** for job execution — no authenticated note, no job, boot-sit-shutdown. **No** for the side effects: they still chose when your vault powers on and auto-unlocks, and a no-job boot dwells a random 1–3 min before powering off, so it does not die the instant it learns there is nothing to do. That removes the boot-and-die tell; it does **not** make a no-job boot look like a job boot, which waits 5–20 min of jitter before it starts anything |
| WOL from the internet | **Yes** if UDP 9 is not forwarded |
| Power cut | **Yes** if BIOS stays Off |
| Tor / Mullvad down | **Yes** — fail closed, no clearnet “backup” |
| SD card dies | **Yes** — spare image, then re-key both boxes. There is no counter to go backwards: freshness is a per-boot challenge, so a restored Pi is not locked out |
| Telegram + Mullvad + Thor lined up on the clock | **Not really** — jitter helps, does not erase |
| BTC from a named exchange | **No** |
| Real-name Telegram | **No** |


## 7. Checks before you call it live

- [ ] `rfkill` on the Pi shows wifi/bt **blocked**
- [ ] Pi has **no** default route when `wg0` is down
- [ ] `am.i.mullvad.net` is connected **before** Tor starts
- [ ] ThinkPad `curl` to anything with Tor down **fails**
- [ ] `gs_console` still only on `127.0.0.1`
- [ ] `find` on the Pi SD: no `wallet`, no `thor_pairs`, no `.keys`
- [ ] Spend USB not in the ThinkPad
- [ ] Router: no port forwards, especially UDP 9
- [ ] Throwaway Telegram, not the account with your face
- [ ] A test `/depo` (or a hand-run quote) writes the slip **only**
      on the ThinkPad; chat has no memo
- [ ] The pairing code shown on the ThinkPad and the code shown on the
      Pi were **compared, by you, character for character** — not
      glanced at. Nothing else authenticates that exchange
- [ ] `python3 -c 'import json;print(json.load(open("/etc/gs_wake_pi.key"))["kdf"])'`
      on the Pi says `argon2id`. If it says `none`, that SD card is
      carrying your ThinkPad's MAC in the clear
- [ ] Both keyfiles are `0400`, and **no keyfile was ever copied
      between the boxes** — there is no step in the ceremony that does
      that, so if you have one on a USB stick something went wrong
- [ ] You can still open the Pi's keyfile: poke the doorbell once and
      type the passphrase. There is no recovery if you cannot
- [ ] `gs-wake-deadman.timer` is **active** — the agent refuses to run a
      job on a box that cannot turn itself off
- [ ] `sleep.target suspend.target hibernate.target hybrid-sleep.target`
      are **masked**: suspend leaves the LUKS key in RAM in a closet
- [ ] Spend USB **out** before any wake; the agent refuses if it sees a
      removable block device
- [ ] The doorbell's port is **not** forwarded, and it binds the LAN
      address only — never `0.0.0.0`, never `wg0`
- [ ] **UNMEASURED, test it yourself:** that this NIC honours the magic
      packet at all, and that WOL still works after a `paranoia_mode`
      MAC spoof. Whether a randomised MAC is the address the NIC's WOL
      engine matches is chip-dependent, so this repo does not claim it


## 8. What this repo actually runs today

On the ThinkPad, after Tor is up:

```bash
python3 gs_console          # http://127.0.0.1:8765/?t=…  (token is per-run)
```

Receive path (no mix):

- Create receive address → `create_receive_wallet`
- BTC deposit + memo → `thor_swap_preparer` (`--dest-from-receive-wallet`)
- Wait → `receive_watch`

Mix is `run_pipeline` / GhostSpiral and needs the spend USB. Do not
point a pager at it.

The Pi doorbell + signed note **are shipped now**:

Pairing is **two commands and one comparison**, and no secret ever
moves between the boxes. Each one generates its own keypair in place;
only public keys cross the LAN.

```bash
# 1. on the ThinkPad. It generates its key, prints the exact command
#    to run on the Pi, and waits.
python3 gs_wake_keys pair --amount-ladder 0.01 0.02 0.05

# 2. on the Pi, using the address the ThinkPad just printed
python3 gs_doorbell pair 192.168.1.20
```

Both boxes then show the **same 8-character code**:

```
  ==============================================
     PAIRING CODE      M404-ADJD
  ==============================================
```

Compare them. Character for character, on both screens. **This
comparison is the entire security of the exchange** — two boxes that
have never met cannot otherwise tell each other apart from anything
else on the switch. If the codes differ, answer `no` on either box:
nothing is written on either, and something on your network answered
instead of the box you meant.

Then the Pi asks for a passphrase, twice, and seals its keyfile with
it. Everything else is automatic:

- the ThinkPad's **MAC is detected**, from the interface holding the
  route to the Pi. It used to be a flag, and a typo in it produced a
  setup that paired perfectly, said success on both boxes, and then
  woke nothing forever — a magic packet is not acknowledged, so
  nothing in this system could ever have told you.
- the doorbell's **port is drawn at random** and recorded in both
  keyfiles. A fixed default in a public repository is a fingerprint:
  anyone who reads this file knows the port to look for, and finding
  it open on a home LAN identifies the setup. Randomising it does not
  make the doorbell secure — the design is published — it makes one
  install look unlike the next.
- the Pi's **listen address** is taken from the socket, not typed. An
  address that is right for the box but wrong for the route is a
  doorbell that binds fine and is never reachable.

```bash
# on the Pi, one process per poke — the job goes in on STDIN, never
# argv, and the passphrase is asked for on the terminal, so neither is
# ever in /proc/<pid>/cmdline
echo '{"job":"receive_and_quote","amount_slot":2}' | \
    python3 gs_doorbell wake --key /etc/gs_wake_pi.key

# on the ThinkPad, as a systemd oneshot at boot (see systemd/ in this repo)
python3 gs_wake_agent --key /etc/gs_wake_thinkpad.key
```

Install the units from `systemd/` **as shipped**, and leave
`WorkingDirectory=` and `Environment=HOME=` alone. `paranoia_mode`
sweeps four fixed roots — cwd, `$HOME`, `$HOME/ghostspiral`,
`$HOME/GhostSpiral` — and systemd starts a unit with cwd `/` and
`HOME=/root`, so without those two lines the woken job's bundles and
slips sit somewhere the wipe never looks. The agent checks this itself
and refuses the boot (`outside_wipe_roots`) rather than writing them
there, which is the right answer and not a working vault.

For the same reason, wipe the wake artifacts from **that** directory:

```bash
cd /var/lib/ghostspiral && python3 /opt/ghostspiral/paranoia_mode
```

A `paranoia_mode` run started from your home directory will not see
them.

It will **not** touch `/etc/gs_wake_thinkpad.key`, because `/etc` is not
one of the four roots — measured, not assumed. That is the right answer
for a routine wipe: the vault stays pairable and the doorbell keeps
working. It is the wrong answer if you are wiping because you expect the
door to come in, and `paranoia_mode` cannot tell those two apart. In
that case destroy the pairing yourself, and re-key both boxes afterwards:

```bash
shred -u /etc/gs_wake_thinkpad.key
```

If you instead keep the keyfile inside a swept root, `paranoia_mode`
destroys it on every wipe and says so ("DESTROYED the WAKE PAIRING"),
and recovery is a two-box re-key with `gs_wake_keys` — not a token
rotation.

The trigger INTO the Pi is now shipped — `gs_telegram_pager` — under the
constraint this paragraph has always stated. Do not “just run a Telegram bot”
that prints the memo: that throws away the only reason to have a Pi. The pager
therefore has no word for an address, a memo, a slip or an amount. The most it
ever says is `depo ready · slip A3F1`, which is step 5 below.

Do not have a chat id yet? You cannot get one out of this bot by asking it —
an unallowlisted chat is ignored in silence, on purpose, because a reply
confirms the bot is alive to whoever found it. Run `gs_telegram_pager --whoami`
once: it needs no `--key` and no `--chat-id`, arms nothing, wakes nothing,
prints the chat id of the next message it sees and exits.

### The slip travels sealed, or it does not travel

“Read it on the vault” is the right rule and it has one assumption: that you
can get to the vault. If you cannot, the rule delivers nothing — you are told a
swap is quoted and handed no way to pay it, and quotes expire. And you cannot
work around it by having the Pi read the slip, because that is exactly the
Telegram bot this section forbids.

So the payload travels as **ciphertext neither carrier can open**:

| holds | gets out of a slip |
|---|---|
| the vault | it sealed it; it has the plaintext anyway |
| the Pi / SD card / bot token | 568 characters of base64 |
| Telegram | the same 568 characters |
| **`gs_delivery.key`** | the deposit address, the memo and the amount |

Sealed with `Box(vault_secret, delivery_public)` — **authenticated**, not just
encrypted. Whoever holds the bot token owns that chat and could otherwise hand
you a deposit address of their choosing; `gs_unseal` refuses any slip your
vault did not seal, and says so in those words.

```bash
# ON THE VAULT, once. Writes the delivery key and tells the vault to use it.
python3 gs_delivery_key new --vault-key /etc/gs_wake_thinkpad.key \
                            --out /media/usb/gs_delivery.key

# ON THE MACHINE YOU SEND BTC FROM. Check it opens BEFORE shredding the copy.
python3 gs_unseal --key gs_delivery.key --self-test

# ON THE VAULT again, once the above worked.
python3 gs_delivery_key shred --key /media/usb/gs_delivery.key

# THEN, WHENEVER A SLIP ARRIVES IN THE CHAT:
python3 gs_unseal --key gs_delivery.key      # paste the blob at the prompt
```

`gs_unseal` re-checks, on that second machine, that the memo names your own
destination — the one failure that silently pays a stranger — and refuses to
print anything at all if it does not.

**What this costs, and it is not nothing.** Before, the ciphertext did not
exist off the vault. Now it does and Telegram keeps a copy forever, so an
adversary who gets the delivery key **later** can read any blob they kept.
Bounding it: the delivery key lives only on the sending machine, and a slip
names one already-spent swap — it is not a wallet, not a seed, and cannot move
anything. Set no delivery key and none of this happens: no slip is sealed and
`/depo` answers exactly as it did before.

### If you have only a phone: `plain_slip`

The sealed slip still assumes a machine that can run `gs_unseal`. With only a
phone you have none, so there is a third mode — set `"plain_slip": true` in the
**vault's** keyfile and the deposit address, the amount and the memo arrive in
the chat as text. The memo comes in its own message so a tap-and-hold copies it
alone.

```
/depo 2                -> Send exactly:  0.05000000 BTC
                          To address:    bc1q…
                          Expected out:  ~1.23 XMR
                          Slip:          A3F1
                       -> =:XMR.XMR:44AF…:0/1/0      (its own message)
/check A3F1            -> A3F1: nothing on the address yet. Normal —
                          ask again in a while.
```

**Read this before you set it.** Not the privacy cost — the money one.

The ThorChain deposit address is a **shared pooled vault**; it identifies
nobody. The memo is the *entire* binding between your Bitcoin and your Monero.
So whoever holds your bot token does not need to touch the deposit line — they
leave it correct, put **their** address in the memo, and your BTC becomes their
XMR, irreversibly. The sealed slip refuses anything your vault did not seal.
This cannot, and no scheme rescues it: you cannot verify a 111-character memo
by eye, and a code sheet, an HMAC or echoing the memo back all fail against the
same attacker, because someone holding the token **is** the bot as far as your
phone can tell — they can suppress the real message and send theirs first.

The mitigation is the token, and only the token. Keep it in
`/etc/gs-pager.env`, `0400`, root-owned, never on a command line.

The privacy cost is the smaller half and is stated in full in
`gs_wake_proto.py` under "THE PLAINTEXT SLIP": the destination is a one-shot
Monero account minted inside the same job and the deposit vault is shared, so
the transcript publishes no long-lived identity. What it does cost is
**attribution** — a SIM-bound account tied to a swap — and **archive**, a
searchable server-side ledger of every run that `paranoia_mode` cannot reach.

**And a phone still cannot finish the payment.** The memo has to go in a
Bitcoin `OP_RETURN`, and no mainstream mobile wallet can attach one — Electrum
for Android rejects it in code. Use **Electrum or Sparrow on a desktop**. Any
desktop, anywhere; the point of this mode is that it no longer has to be *the
vault*. Two things that look like ways round it and are not:

* a `bitcoin:` URI cannot carry the memo — `message=` is display-only, so it
  produces a valid-looking payment that broadcasts with **no memo** and strands
  the funds;
* ThorChain's "memoless" swaps do not help — they move the routing into an
  exact-to-the-satoshi amount, still require the memo to be broadcast first
  from a funded RUNE account, and add a 6-hour single-use fuse.

Both boxes must be updated together for this — `PAD_BLOCK` went 256→1024 to fit
a slip, so an old doorbell rejects a new record **on length, before any
crypto**, with `wake record is 1064 bytes, not 296`. Your existing keyfiles
still open; the pairing survives.

“No port forward, and no WAN path to WOL” is met more simply than by an onion
service: the pager **long-polls outward** over Tor and listens on nothing at
all, so there is no inbound port to forward. If Tor is down it does not start
(§4). A stolen phone or bot token can wake the vault and spam quotes — §7
already scores that — and cannot spend, cannot name a destination, and cannot
read a memo. The bound that matters is the vault's 24 h wake budget and
account ceiling, which live in a keyfile and need physical access to change.

The one real cost, stated plainly: to run unattended it needs
`GS_WAKE_PASSPHRASE` in its environment, which puts the passphrase on the same
SD card as the sealed keyfile and effectively unseals it. A pager you start by
hand, typing the passphrase, does not. That is the trade; make it knowingly.

The wake channel can ask for three jobs and no others — `receive_new`,
`receive_and_quote`, `watch`. There is deliberately no job that takes an
XMR destination: a doorbell that can name one turns “they can wake and
spam quotes, not spend” into “you read a valid memo off your own vault,
send real BTC, and ThorChain delivers to the attacker.” Every parameter
is a bounded integer or a 4-hex handle; the amount is an INDEX into a
ladder that lives on the ThinkPad, so the Pi never sends a number and
never a flag, a path or a proxy. The ThinkPad composes every argument
itself.

`watch` takes only a handle that came from `receive_and_quote`. A handle
from `receive_new` is refused, for two reasons: `--count N` mints N
bundles and the handle cannot name one of them without picking
arbitrarily, and a receive bundle carries no quoted amount, so the only
way to watch it would be `--any` — which stops on **any** balance, so a
piconero of dust from anyone holding the address would page you that
your money had landed.

Pi-side artifacts are **not** covered by `paranoia_mode`: it sweeps the
host it runs on, and nothing in this repo runs on the Pi except
`gs_doorbell`. The doorbell persists nothing — its only file is the
keyfile.
