# GhostSpiral — Setup Guide

Everything is copy-paste. You need a Debian/Kali VM with `sudo`.

---

## Step 1: Install

```
sudo apt update && sudo apt install -y tor torsocks jq gnupg python3-pip python3-venv curl wget bzip2
bash install.sh
sudo systemctl start tor && sudo systemctl enable tor
```

---

## Step 2: Lock down the VM (do this FIRST, before anything else)

```
sudo bash tor_firewall.sh
```

This blocks ALL direct internet. Only Tor traffic gets out.

Then fix your browser and CLI tools:

```
sudo bash tor_firewall.sh --setup-browser
```

This automatically configures:
- **wget, curl, apt, pip** — work through Tor immediately
- **Firefox** — SOCKS5 proxy + DNS privacy + WebRTC disabled

**For your current terminal** (if wget still fails after the above):

```
. /etc/profile.d/tor-proxy.sh
```

New terminals get it automatically.

**Make firewall survive reboots:**

```
sudo bash tor_firewall.sh --persist
```

**If Malwarebytes on your host PC flags Tor traffic:**

```
sudo bash tor_firewall.sh --setup-bridges
```

---

## Step 3: Install Monero tools

After `--setup-browser`, wget works through Tor automatically. If it still fails, prefix with `torsocks`:

```
cd /tmp
wget https://downloads.getmonero.org/cli/linux64 -O monero.tar.bz2
# If wget fails: torsocks wget https://downloads.getmonero.org/cli/linux64 -O monero.tar.bz2
tar xf monero.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monerod /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-cli /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-rpc /usr/local/bin/
rm -rf monero-x86_64-linux-gnu-* monero.tar.bz2
cd -
```

---

## Step 4: Create a wallet (first time only)

```
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

- Pick a password — **remember it**
- Write down the 25-word seed — **on paper, store safely**
- That seed is the ONLY way to recover funds

**If you get "file already exists":** You already have a wallet. Skip this step and use
your existing wallet in the next step. If you want a fresh wallet, pick a different name:
```
monero-wallet-cli --generate-new-wallet ~/my_wallet2
```

---

## Step 5: Start services (before each session)

**Start blockchain node** (first time downloads ~170 GB):

```
monerod --detach --data-dir ~/.bitmonero
```

**Start wallet server** — replace `YOUR_PASSWORD` with your wallet password:

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

What the flags mean:
| Flag | Why |
|------|-----|
| `--rpc-bind-port 18083` | Port the toolkit connects to |
| `--wallet-file` | Your wallet from Step 4 |
| `--password` | Same password from Step 4 |
| `--daemon-address` | Your local node from above |
| `--disable-rpc-login` | Safe — only listens on localhost |
| `--log-level 0` | **OPSEC:** prevents logging your operations |
| `--detach` | Runs in background |

**Set password as env var** (hides it from `ps aux`):

```
export GS_WALLET_PASSWORD="YOUR_PASSWORD"
```

---

## Step 6: Run the toolkit

```
./gs
```

Choose `0` to verify everything is connected.

---

## When you're done

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

| Command | What it does |
|---------|-------------|
| `./gs` → `9` | Wipes all toolkit artifacts and logs |
| `pkill monero-wallet-rpc` | Stops the wallet server |
| `monerod exit` | Stops the blockchain node cleanly |
| `unset GS_WALLET_PASSWORD` | Removes password from shell memory |
| `history -c && history -w` | Clears command history |

---

## Quick reference

| What | Command |
|------|---------|
| Run toolkit | `./gs` |
| System check | `./gs` → `0` |
| Enable firewall | `sudo bash tor_firewall.sh` |
| Fix browser + CLI | `sudo bash tor_firewall.sh --setup-browser` |
| Fix Malwarebytes | `sudo bash tor_firewall.sh --setup-bridges` |
| Keep after reboot | `sudo bash tor_firewall.sh --persist` |
| Disable firewall | `sudo bash tor_firewall.sh --undo` |
| Check firewall | `sudo bash tor_firewall.sh --status` |
| Start node | `monerod --detach --data-dir ~/.bitmonero` |
| Stop node | `monerod exit` |
| Start wallet-rpc | See Step 5 |
| Stop wallet-rpc | `pkill monero-wallet-rpc` |
| Cleanup | `./gs` → `9` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `wget: unable to resolve` | `sudo bash tor_firewall.sh --setup-browser` then `. /etc/profile.d/tor-proxy.sh` |
| Browser can't connect | `sudo bash tor_firewall.sh --setup-browser` then restart Firefox |
| Malwarebytes flags on host | `sudo bash tor_firewall.sh --setup-bridges` |
| `ModuleNotFoundError` | `bash install.sh` |
| `Cannot reach wallet-rpc` | Start wallet-rpc (Step 5) |
| `Tor is NOT running` | `sudo systemctl start tor` |
| Firewall locked me out | `sudo bash tor_firewall.sh --undo` |
