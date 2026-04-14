# GhostSpiral — Complete Setup Guide

If you know nothing, start here. Every command is copy-paste ready.

---

## Step 1: Install system packages

Open a terminal on your Kali Linux machine and run:

```bash
sudo apt update
sudo apt install -y tor torsocks jq gnupg python3-pip curl wget bzip2
```

---

## Step 2: Install Python libraries

```bash
python3 -m pip install requests PySocks tenacity stem monero psutil
python3 -m pip install python-gnupg pycryptodomex cryptography qrcode pyyaml
python3 -m pip install beautifulsoup4 aiohttp aiohttp-socks
```

Check they all installed:

```bash
python3 -c "import requests, socks, stem, monero, psutil, tenacity, cryptography; print('ALL OK')"
```

If it prints `ALL OK` you're good. If it says `ModuleNotFoundError`, install whichever one it says is missing.

---

## Step 3: Set up Tor (this IS your proxy)

GhostSpiral uses Tor as its proxy. Tor routes ALL your traffic through 3 encrypted
hops so nobody (not your ISP, not police, not data companies) can see what you're
doing. You do NOT need any other proxy service. Tor is free and runs locally.

### Start Tor:

```bash
sudo systemctl start tor
sudo systemctl enable tor
```

### Verify Tor is working:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

You should see `{"IsTor":true, ...}`. If you see an error, Tor isn't running.

### Enable circuit rotation (REQUIRED):

GhostSpiral rotates your Tor circuit (changes your anonymous identity)
between each operation. This needs the Tor control port:

```bash
sudo bash -c 'echo "" >> /etc/tor/torrc'
sudo bash -c 'echo "ControlPort 9051" >> /etc/tor/torrc'
sudo bash -c 'echo "CookieAuthentication 1" >> /etc/tor/torrc'
sudo systemctl restart tor
```

### Your proxy address is:

```
socks5h://127.0.0.1:9050
```

This is what you'll enter whenever GhostSpiral asks for a proxy.
The `h` in `socks5h` means DNS lookups also go through Tor (critical for privacy).

**Ports:** `9050` is the SOCKS port for the system `tor` package (`apt install tor`). **Tor Browser** uses **`9150`** for SOCKS instead — if only the browser is running, use `socks5h://127.0.0.1:9150`. **`9051`** (system tor) and **`9151`** (Tor Browser) are **control** ports for `NEWNYM` / circuit rotation, not SOCKS; do not pass them as `--tor-proxy` or in a SOCKS proxy chain. GhostSpiral tries control **9051** then **9151** when the Unix control socket is missing.

### DO NOT USE:
- Free proxy lists from the internet (they log everything)
- Cheap VPN SOCKS proxies (they see your traffic)
- Any proxy you don't control (they can steal your funds)
- `socks5://` without the `h` (leaks DNS to your ISP)

Tor is the only proxy you need. It runs locally, it's free, and nobody
in the middle can see your traffic.

---

## Step 4: Install Monero CLI tools

GhostSpiral needs three Monero programs: `monerod` (blockchain node),
`monero-wallet-rpc` (wallet server), and `monero-wallet-cli` (signing tool).

### Download and install:

```bash
cd /tmp
wget https://downloads.getmonero.org/cli/linux64 -O monero.tar.bz2
tar xf monero.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monerod /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-cli /usr/local/bin/
sudo cp monero-x86_64-linux-gnu-*/monero-wallet-rpc /usr/local/bin/
rm -rf monero-x86_64-linux-gnu-* monero.tar.bz2
cd -
```

### Verify:

```bash
monerod --version
monero-wallet-cli --version
monero-wallet-rpc --version
```

All three should print a version number.

---

## Step 5: Start Monero (do this before each session)

### 5a. Start the blockchain node:

```bash
monerod --detach --data-dir ~/.bitmonero
```

First time: this downloads the full Monero blockchain (~170 GB). Takes hours.
After that: starts in seconds.

To check sync progress:
```bash
monerod status
```

### 5b. Create a wallet (first time only):

```bash
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

It will ask you for a password. Remember this password. It will show you a
25-word seed phrase. Write it down on paper and store it safely. This is
the ONLY way to recover your funds if something goes wrong.

### 5c. Start the wallet RPC server:

```bash
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file ~/my_wallet \
  --password "YOUR_WALLET_PASSWORD" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login
```

Keep this terminal open (or run with `--detach`). This is the wallet server
that GhostSpiral talks to.

### 5d. Verify wallet RPC is running:

```bash
curl -s http://127.0.0.1:18083/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_height"}' \
  -H 'Content-Type: application/json'
```

Should return something with `"height":` and a number.

---

## Step 6: Set environment variables

```bash
export GS_WALLET_PASSWORD="YOUR_WALLET_PASSWORD"
```

- `GS_WALLET_PASSWORD`: same password you used in step 5c. Setting it here
  prevents it from showing up in `ps aux` output where anyone on the machine
  could see it.

---

## Step 7: Run GhostSpiral

```bash
cd /path/to/ghostspiral
python3 run
```

This opens the interactive menu. Choose what you want to do:

```
  1  Full Pipeline          BTC → mixed XMR
  2  Receive Mode           Mix XMR that already arrived
  3  Cold / Air-Gap         Offline signing
  4  Broadcast              Send signed TXs
  5  Resume                 Continue after crash
  6  Create Wallet          New receive address
  7  Swap Preparer          ThorChain deposit address
  8  Exit Planner           Plan XMR off-ramp
  9  Paranoia Cleanup       Wipe all traces
  0  System Check           Verify everything works
  t  Testnet / Dry Run      Test without real funds
```

### First time? Start with option `0` (System Check):

It verifies Python deps, Tor, Monero tools, and wallet RPC are all working.

### Want to test safely? Use option `t` (Testnet):

Creates a mock plan with fake balance so you can see how the pipeline works
without touching real money.

---

## Step 8: Stopping Services (When Done)

Stop services in reverse order (GhostSpiral artifacts → wallet → node → Tor).

### 8a. Clean up GhostSpiral artifacts FIRST:

```bash
# Option 9 (Paranoia Cleanup) in the menu does this automatically.
# Or manually:
python3 run paranoia --dry-run   # see what would be deleted
python3 run paranoia             # actually delete (needs sudo for full wipe)
```

This wipes seed files, plans, timing profiles, noise logs, integrity chains,
shell histories, and Python caches. Run this **before** stopping services so
the cleanup tools can still talk to Tor for circuit rotation.

### 8b. Stop wallet RPC:

```bash
# If running in foreground: Ctrl+C
# If running with --detach:
kill $(pgrep monero-wallet-rpc)
# Verify it stopped:
pgrep monero-wallet-rpc || echo "wallet-rpc stopped"
```

### 8c. Stop monerod:

```bash
monerod exit
# Or if detached:
kill $(pgrep monerod)
# Wait for clean shutdown (saves blockchain state):
sleep 10 && pgrep monerod || echo "monerod stopped"
```

Do NOT `kill -9` monerod — it may corrupt the blockchain database.

### 8d. Stop Tor (optional — you probably want to keep it running):

```bash
sudo systemctl stop tor
# Or if using Tor Browser: just close the browser
```

### 8e. Unset environment variables in your shell:

```bash
unset GS_WALLET_PASSWORD TOR_CONTROL_PASSWORD
history -c && history -w   # clear shell history of passwords
```

### Verify everything is stopped:

```bash
pgrep -a monero || echo "No Monero processes"
ss -tlnp | grep -E '18081|18083|9050' || echo "No GhostSpiral ports open"
```

---

## Common Workflows

### Receive XMR (someone sends you BTC):

1. Choose `6` (Create Wallet) — generates a fresh XMR receive address
2. Choose `7` (Swap Preparer) — generates a BTC deposit address via ThorChain
3. Give the BTC deposit address + memo to the sender
4. Wait for XMR to arrive in your wallet
5. Choose `2` (Receive Mode) — mixes the XMR through multiple hops
6. Choose `9` (Paranoia Cleanup) — wipes all traces

### Cold-signing (maximum security):

1. On ONLINE machine: choose `3` (Cold) — creates unsigned plan
2. Copy the `unsigned/` folder to a USB drive
3. On OFFLINE machine: run the signer tool on the USB files
4. Copy `tx_staging/signed/` back to USB
5. On ONLINE machine: choose `4` (Broadcast) — sends the signed TXs

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run Step 2 again |
| `curl: (7) Failed to connect to 127.0.0.1 port 9050` | Nothing is listening on SOCKS: `sudo systemctl start tor` and check `journalctl -u tor -n 50`. If you use **Tor Browser** only, try port **9150** instead of 9050 |
| `Tor leak detected` | `sudo systemctl start tor` |
| `NEWNYM failed` | Run the ControlPort commands from Step 3 |
| `socks5:// leaks DNS` | Use `socks5h://` (with the h) |
| `No wallet file` | Start wallet RPC (Step 5c) |
| `Method not found` | You're connecting to port 18081 instead of 18083 |
| `No swap routes` | All THORNode endpoints failed. Check Tor connectivity, try again later |
| `Invalid BTC address` | Must start with `bc1`, `1`, or `3` |
| System Check shows `[!]` for Monero | Run Step 4 |
| System Check shows `[!]` for wallet-rpc | Run Step 5c |

---

## IMPORTANT: Proxy Safety

```
NEVER use free/cheap/public SOCKS proxies with GhostSpiral.

A malicious proxy can:
  - See ALL your traffic (destinations, amounts, addresses)
  - Modify RPC responses (change destination addresses = steal funds)
  - Log your real IP and correlate with blockchain activity

ONLY use:
  ✓ Your own local Tor instance (system tor: socks5h://127.0.0.1:9050 — Tor Browser: :9150)
  ✓ A Tor instance you control on a trusted VPS
  ✗ NEVER public proxy lists
  ✗ NEVER "free VPN" SOCKS proxies
  ✗ NEVER shared proxies from unknown providers

The ONLY safe proxy is one YOU control end-to-end.
```

---

## Manual Install (if you prefer)

```bash
# 1. System packages
sudo apt update && sudo apt install -y tor torsocks jq gnupg python3-pip curl wget bzip2

# 2. Python deps (use python3 -m pip, NOT bare pip which may be python2)
python3 -m pip install -r requirements.txt

# 3. Enable Tor control port
echo -e "\nControlPort 9051\nCookieAuthentication 1" | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor

# 4. Download + install Monero CLI tools
cd /tmp
wget https://downloads.getmonero.org/cli/linux64 -O monero-cli.tar.bz2
tar xf monero-cli.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/
rm -rf monero-x86_64-linux-gnu-* monero-cli.tar.bz2
cd -

# 5. Verify everything
python3 -c "import requests, stem, monero, psutil; print('OK')"
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip || curl --socks5-hostname 127.0.0.1:9150 https://check.torproject.org/api/ip
monerod --version
monero-wallet-rpc --version
```

---

## File Layout

```
ghostspiral/
├── run                    ← interactive launcher
├── install.sh             ← auto-installer
├── requirements.txt       ← Python dependencies
├── core/                  ← main pipeline
├── modules/               ← mixing & chaos
├── opsec/                 ← cleanup & anti-forensics
└── intel/                 ← OSINT collection
```

Run `python3 run list` to see all available tools.
