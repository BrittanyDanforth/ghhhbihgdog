# Setup Guide

Everything is copy-paste. You need a Debian/Kali VM with `sudo`.

---

## Step 1: Install

```
bash install.sh
```

The installer handles everything: system packages, Python environment,
dependency verification, and Tor configuration. Run it again any time
if something breaks — it skips what's already working.

Start Tor if the installer couldn't:

```
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

This configures wget, curl, apt, pip, and Firefox to route through Tor.

**For your current terminal** (if wget still fails):

```
. /etc/profile.d/tor-proxy.sh
```

New terminals get this automatically.

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

The installer offers to download these automatically. If you need to
do it manually:

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

---

## Step 4: Create a wallet (first time only)

```
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

- Pick a strong password — **remember it**
- Write down the 25-word seed — **on paper, store safely**
- That seed is the ONLY way to recover funds if the wallet file is lost

If you already have a wallet, skip this step.

---

## Step 5: Start services (before each session)

**Start blockchain node** (first run downloads ~170 GB):

```
monerod --detach --data-dir ~/.bitmonero
```

**Start wallet server:**

Create a password file (avoids putting the password in shell history):

```
touch /dev/shm/.wallet_pw && chmod 600 /dev/shm/.wallet_pw
```

Write your wallet password into that file using a text editor (not echo).
Then start the wallet server:

```
monero-wallet-rpc \
  --rpc-bind-port 18083 \
  --wallet-file ~/my_wallet \
  --password-file /dev/shm/.wallet_pw \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login \
  --log-level 0 \
  --detach
```

| Flag | Purpose |
|------|---------|
| `--rpc-bind-port 18083` | Port the toolkit connects to |
| `--wallet-file` | Your wallet from Step 4 |
| `--password-file` | Reads password from file (not visible in process list) |
| `--daemon-address` | Your local blockchain node |
| `--disable-rpc-login` | Safe — only listens on localhost |
| `--log-level 0` | **OPSEC:** prevents logging your operations |
| `--detach` | Runs in background |

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

Choose `9` (Paranoia Cleanup) to wipe all toolkit artifacts. Then
stop the services and clean up:

```
monerod exit
unset GS_WALLET_PASSWORD
```

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
