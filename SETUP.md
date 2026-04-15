# GhostSpiral — Setup Guide

Everything is copy-paste ready. You need a Debian/Kali VM with `sudo`.

---

## First time ever? Run these 3 commands:

```
sudo apt update && sudo apt install -y tor torsocks jq gnupg python3-pip python3-venv curl wget bzip2
bash install.sh
sudo systemctl start tor && sudo systemctl enable tor
```

Done. Now run `./gs` to open the menu.

---

## Already set up? Just run:

```
./gs
```

If something broke: `bash install.sh` (only fixes what's missing).

---

## Monero setup (first time only)

### Step 1: Install Monero tools

```
cd /tmp
wget https://downloads.getmonero.org/cli/linux64 -O monero.tar.bz2
tar xf monero.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monerod /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-cli /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-rpc /usr/local/bin/
rm -rf monero-x86_64-linux-gnu-* monero.tar.bz2
cd -
```

### Step 2: Create a wallet

```
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

It asks for a password — **remember it.**
It shows a 25-word seed phrase — **write it on paper and store it safely.**
That seed is the ONLY way to recover your funds.

### Step 3: Start the blockchain node

```
monerod --detach --data-dir ~/.bitmonero
```

First time downloads ~170 GB. After that, starts in seconds.

---

## Before each session

### Start wallet-rpc (the thing that talks to your wallet)

Replace `YOUR_PASSWORD` with the password you chose in Step 2:

```
monero-wallet-rpc \
  --rpc-bind-port 18083 \
  --wallet-file ~/my_wallet \
  --password "YOUR_PASSWORD" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login \
  --log-level 0 \
  --detach
```

**What each flag does:**
- `--rpc-bind-port 18083` — the port the toolkit connects to
- `--wallet-file ~/my_wallet` — path to your wallet from Step 2
- `--password` — the password you set when creating the wallet
- `--daemon-address` — your local blockchain node from Step 3
- `--disable-rpc-login` — no extra login needed (it only listens on localhost)
- `--log-level 0` — **OPSEC: prevents wallet-rpc from logging your operations to disk**
- `--detach` — runs in background so you can close the terminal

### Set your password as environment variable

This passes it to the toolkit without it showing in `ps aux`:

```
export GS_WALLET_PASSWORD="YOUR_PASSWORD"
```

### Launch the toolkit

```
./gs
```

Choose `0` (System Check) to verify everything is connected.

---

## When you're done

### Quick shutdown (copy-paste this whole block):

```
./gs
```

Choose `9` (Paranoia Cleanup). Then:

```
pkill monero-wallet-rpc
monerod exit
unset GS_WALLET_PASSWORD
history -c && history -w
```

**What each line does:**
- `./gs` → `9` — wipes all toolkit artifacts, temp files, logs
- `pkill monero-wallet-rpc` — stops the wallet server
- `monerod exit` — stops the blockchain node cleanly (don't kill -9 it)
- `unset GS_WALLET_PASSWORD` — removes password from shell memory
- `history -c && history -w` — clears command history

---

## Tor firewall (lock down the VM)

Blocks ALL internet except through Tor. Nothing leaks — not DNS, not IPv6, nothing.

| What | Command |
|------|---------|
| **Enable** | `sudo bash tor_firewall.sh` |
| **Fix browser** | `sudo bash tor_firewall.sh --setup-browser` |
| **Fix Malwarebytes alerts** | `sudo bash tor_firewall.sh --setup-bridges` |
| **Survive reboots** | `sudo bash tor_firewall.sh --persist` |
| **Disable** | `sudo bash tor_firewall.sh --undo` |
| **Check status** | `sudo bash tor_firewall.sh --status` |

Your browser will stop working after enabling — that's correct. Run `--setup-browser` to fix it.

---

## Quick reference

| What | Command |
|------|---------|
| First install | `bash install.sh` |
| Run toolkit | `./gs` |
| System check | `./gs` then `0` |
| Start monerod | `monerod --detach --data-dir ~/.bitmonero` |
| Start wallet-rpc | See "Before each session" above |
| Stop wallet-rpc | `pkill monero-wallet-rpc` |
| Stop monerod | `monerod exit` |
| Cleanup everything | `./gs` then `9` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `curl: (7) ... port 9050` | Tor not running. `sudo systemctl start tor` |
| Browser says "can't connect" | `sudo bash tor_firewall.sh --setup-browser` |
| Malwarebytes flags on host | `sudo bash tor_firewall.sh --setup-bridges` |
| `ModuleNotFoundError` | `bash install.sh` |
| `NEWNYM failed` | `sudo systemctl restart tor` |
| `No wallet file` | Start wallet-rpc (see above) |
| `Cannot reach wallet-rpc` | Start wallet-rpc (see above) |
| Firewall locked me out | `sudo bash tor_firewall.sh --undo` |
| monerod sync is slow | Normal first time (~170 GB). Check: `monerod status` |

---

## Proxy safety

```
ONLY use: socks5h://127.0.0.1:9050 (system Tor)
     or:  socks5h://127.0.0.1:9150 (Tor Browser)

The "h" in socks5h routes DNS through Tor.
Without it, your ISP sees every domain you visit.
```
