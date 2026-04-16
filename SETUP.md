# Setup Guide

Two paths: **Automatic** (recommended) or **Manual** (if you need control).
Both follow the same OPSEC-safe order: Tor first, then downloads.

---

## Automatic Setup

```
bash install.sh
```

This does everything in the correct OPSEC order:
1. System packages (apt)
2. **Start Tor** (before any downloads)
3. **Route pip through Tor** (so package downloads don't leak)
4. Python virtual environment + packages
5. Verify all imports
6. Monero tools (optional download)
7. Create `./gs` launcher

Run it again any time — it skips what's already working.

**After install, lock down the VM:**

```
sudo bash tor_firewall.sh
sudo bash tor_firewall.sh --setup-browser
sudo bash tor_firewall.sh --persist
```

---

## Manual Setup (same order, step by step)

### Step 1: System packages

```
sudo apt update
sudo apt install -y tor torsocks python3-pip python3-venv python3-dev \
    curl wget build-essential jq gnupg
```

### Step 2: Start Tor FIRST (before any downloads)

```
sudo systemctl start tor
sudo systemctl enable tor
```

Verify Tor is working:

```
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

You should see `"IsTor":true`.

### Step 3: Lock down the VM

```
sudo bash tor_firewall.sh
sudo bash tor_firewall.sh --setup-browser
```

This blocks ALL direct internet — only Tor traffic gets out.
All subsequent downloads (pip, wget, curl) will go through Tor.

**For your current terminal** (if downloads fail after this):

```
. /etc/profile.d/tor-proxy.sh
```

### Step 4: Install Python packages (through Tor)

```
python3 -m venv .venv
. .venv/bin/activate
pip install requests PySocks tenacity stem monero psutil \
    cryptography pycryptodomex qrcode pyyaml beautifulsoup4 \
    aiohttp aiohttp-socks
```

If pip fails with connection errors, set the proxy manually:

```
export ALL_PROXY=socks5h://127.0.0.1:9050
pip install requests PySocks tenacity stem monero psutil
```

### Step 5: Install Monero tools

```
cd /tmp
torsocks wget https://downloads.getmonero.org/cli/linux64 -O monero.tar.bz2
tar xf monero.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monerod /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-cli /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-rpc /usr/local/bin/
rm -rf monero-x86_64-linux-gnu-* monero.tar.bz2
cd -
```

### Step 6: Create a wallet (first time only)

```
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

- Pick a strong password — **remember it**
- Write down the 25-word seed — **on paper, store safely**
- That seed is the ONLY way to recover funds

### Step 7: Start services (before each session)

**Start blockchain node** (first run downloads ~170 GB):

```
monerod --detach --data-dir ~/.bitmonero
```

**Start wallet server:**

Create a password file:

```
touch /dev/shm/.wallet_pw && chmod 600 /dev/shm/.wallet_pw
```

Write your wallet password into that file using a text editor (not echo).
Then start wallet-rpc:

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
| `--wallet-file` | Your wallet from Step 6 |
| `--password-file` | Reads password from RAM-backed file |
| `--daemon-address` | Your local blockchain node |
| `--disable-rpc-login` | Safe — only listens on localhost |
| `--log-level 0` | **OPSEC:** prevents logging your operations |
| `--detach` | Runs in background |

### Step 8: Run the toolkit

```
./gs
```

Choose `0` to verify everything is connected.

---

## When you're done

Choose `9` (Paranoia Cleanup) from the menu to wipe all artifacts.
Then stop services:

```
monerod exit
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
| pip fails with connection error | `export ALL_PROXY=socks5h://127.0.0.1:9050` then retry |
| `wget: unable to resolve` | `. /etc/profile.d/tor-proxy.sh` or use `torsocks wget` |
| Browser can't connect | `sudo bash tor_firewall.sh --setup-browser` then restart browser |
| Malwarebytes flags on host | `sudo bash tor_firewall.sh --setup-bridges` |
| `ModuleNotFoundError` | `bash install.sh` |
| `Cannot reach wallet-rpc` | Start wallet-rpc (Step 7) |
| `Tor is NOT running` | `sudo systemctl start tor` |
| Firewall locked me out | `sudo bash tor_firewall.sh --undo` |
