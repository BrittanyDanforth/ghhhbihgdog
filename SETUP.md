# GhostSpiral v10.6 — Setup Guide for Kali Linux

## Prerequisites

### 1. System packages

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Tor
sudo apt install -y tor torsocks

# Install Monero CLI tools (wallet-cli, wallet-rpc, monerod)
# Download from https://www.getmonero.org/downloads/
# Or use the package manager:
sudo apt install -y monero

# Optional: GPG for encrypted output
sudo apt install -y gnupg

# Optional: jq for reading JSON wallet files
sudo apt install -y jq
```

### 2. Python dependencies

```bash
# Requires Python 3.10+
python3 --version

# Install pip if not present
sudo apt install -y python3-pip

# Install GhostSpiral dependencies
pip install -r requirements.txt

# Verify critical packages
python3 -c "import requests; import stem; import monero; print('OK')"
```

### 3. Tor configuration

```bash
# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor

# Verify Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# For NEWNYM circuit rotation, enable the control port:
# Edit /etc/tor/torrc and add:
#   ControlPort 9051
#   CookieAuthentication 1
# Then restart Tor:
sudo systemctl restart tor

# If using HashedControlPassword instead of CookieAuthentication,
# set the password in your environment:
export TOR_CONTROL_PASSWORD="your_tor_control_password"
```

### 4. Monero wallet-rpc setup

```bash
# Start monero-wallet-rpc with your wallet
# For a HOT wallet (auto-mode, has spend key):
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file /path/to/your/wallet \
  --password "your_wallet_password" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login

# For a VIEW-ONLY wallet (cold-signing workflow):
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file /path/to/view-only-wallet \
  --password "password" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login

# Verify wallet-rpc is running:
curl -s http://127.0.0.1:18083/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_height"}' \
  -H 'Content-Type: application/json'
```

### 5. Monerod (daemon) setup

```bash
# If running your own node:
monerod --detach --data-dir /path/to/blockchain

# Or connect to a remote node (less private):
# wallet-rpc --daemon-address node.moneroworld.com:18089
# WARNING: Remote nodes see your IP unless tunneled through Tor
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TOR_CONTROL_PASSWORD` | If Tor uses password auth | Tor control port password for NEWNYM |
| `GS_WALLET_PASSWORD` | For auto-mode signing | Monero wallet password (avoids /proc leak) |
| `SWAPKIT_API_KEY` | For ThorChain swaps | SwapKit API key (get from swapkit.dev) |

```bash
# Set in your shell (these are wiped by paranoia_mode Phase 12):
export TOR_CONTROL_PASSWORD="your_tor_password"
export GS_WALLET_PASSWORD="your_wallet_password"
export SWAPKIT_API_KEY="your_swapkit_key"
```

## Quick Start — Receiver Workflow

```bash
# 1. Create a receive address
python3 create_receive_wallet \
  --rpc http://127.0.0.1:18083 \
  --tor-proxy socks5h://127.0.0.1:9050

# 2. Generate ThorChain deposit address for the sender
python3 thor_swap_preparer \
  --amounts 0.05 \
  --dests $(jq -r .address wallet_*.json) \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --api-key "$SWAPKIT_API_KEY"

# 3. Give the deposit address + memo to the BTC sender
# 4. Wait for XMR to arrive (check wallet-rpc balance)

# 5. Run GhostSpiral in receive mode
python3 GhostSpiral \
  --receive-wallet wallet_*.json \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc-primary http://127.0.0.1:18083

# 6. Clean up
python3 paranoia_mode --iface wlan0
```

## Quick Start — Sender Workflow

```bash
# 1. Create receive wallet (same as above)
# 2. Run GhostSpiral in sender mode with --cold for air-gap signing:
python3 GhostSpiral \
  --btc-entry bc1q... \
  --btc-amount 0.05 \
  --split 2 \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc-primary http://127.0.0.1:18083 \
  --cold

# 3. Transfer the unsigned plan to the air-gap machine
# 4. Sign each TX on the cold wallet (see AUDIT.md for cold-signing protocol)
# 5. Broadcast signed TXs
# 6. Clean up with paranoia_mode
```

## File Permissions

All output files are created with `0600` (owner read/write only).
Verify with: `ls -la unsigned/ tx_staging/ *.json`

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| "socks5:// leaks DNS" | Using socks5:// instead of socks5h:// | Change to `socks5h://` |
| "Tor leak detected" | Tor proxy not running | `sudo systemctl start tor` |
| "NEWNYM failed 3 times" | Tor control port not enabled | Enable ControlPort 9051 in torrc |
| "No wallet file" | wallet-rpc has no wallet loaded | Start wallet-rpc with --wallet-file |
| "No unsigned_txset" | Wallet is hot, not view-only | OK in auto-mode (uses tx_metadata_list) |
| "Method not found" on submit_transfer | Using monerod port instead of wallet-rpc | Use --wallet-rpc http://127.0.0.1:18083 |
