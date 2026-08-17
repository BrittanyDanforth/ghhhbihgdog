# Operator setup — reception vs custody

This is the hardware/network layout for running GhostSpiral **without**
leaving the spend key on a box that stays online, and **without** the
home ISP seeing Tor guards.

The Telegram doorbell is a **pager**. It is not in this repo yet. Until
it exists, you sit at the ThinkPad and use `gs_console` the same way.
The split below still applies.

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

Telegram never gets: XMR address, memo (the memo **is** the address),
wallet path, RPC URL, view key.


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

# hostname that is not your name
hostnamectl set-hostname fuse
```

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
  Cost: when a job is running, Mullvad sees two Tor clients in one
  tunnel. The ISP still only sees Mullvad.

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


## 5. Job cycle (when the bot exists)

1. Phone: `/recv` then `/depo 0.05` to the throwaway account.
2. Pi checks Tor, allowlisted chat id, rate limit.
3. Pi WOL + signed job file on the LAN.
4. ThinkPad boots, waits a **random 5–20 min** (breaks the obvious
   Telegram→power-spike→Thor clock), brings up Tor, runs the same
   actions as the console: `create_receive_wallet`, `thor_swap_preparer`.
5. Slip stays on the ThinkPad (`0600`). Telegram gets `depo ready · slip A3F1`.
6. You copy BTC address + memo from the bay (or the file). Not from chat.
7. ThinkPad `receive_watch` until landed **or** a few hours, then
   `landed` / timeout, then **shutdown**.
8. Idle weeks: ThinkPad is off. Only the Pi hums.

Until the bot exists: skip 1–3. You are at the ThinkPad. Same files,
same “memo never leaves the machine except to the sender.”


## 6. Bad situations (and whether this beats them)

| happens | beaten? |
|---|---|
| ISP “this house runs Tor” | **Yes** — they see Mullvad |
| Hotspot / SIM / towers | **Yes** — no cellular |
| VPS host images a wallet | **Yes** — no wallet on Mullvad |
| Door kick, Pi only | **Yes** — rotate the bot token |
| Door kick, they take the ThinkPad | **Partly** — view-only if auto-unlock; spend USB elsewhere |
| Spend USB left in the laptop | **No** — you blew the split |
| Stolen Telegram / bot token | **Partly** — they can wake and spam quotes, not spend |
| Roommate sends WOL | **Yes** if jobs need a signed Pi note |
| WOL from the internet | **Yes** if UDP 9 is not forwarded |
| Power cut | **Yes** if BIOS stays Off |
| Tor / Mullvad down | **Yes** — fail closed, no clearnet “backup” |
| SD card dies | **Yes** — spare image; Telegram goes quiet |
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

The Pi doorbell + signed job file are **operator procedure**, not a
shipped binary. Do not “just run a Telegram bot” that prints the memo
— that throws away the only reason to have a Pi.
