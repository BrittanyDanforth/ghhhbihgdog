# GhostSpiral v10.7 — Complete Setup & Operations Guide

## Project Structure

```
ghostspiral/
├── run                          # Unified launcher (python3 run <tool> [args])
├── requirements.txt             # All Python dependencies
├── SETUP.md                     # This file
├── AUDIT.md                     # Full audit trail (BUG 1-79)
├── DEEP_AUDIT.md                # Deep audit (BUG 80-114)
│
├── core/                        # Core pipeline — handles real money
│   ├── gs_common.py             #   Shared OPSEC library (Tor, crypto, RPC)
│   ├── GhostSpiral              #   Main orchestrator (BTC→XMR mixing)
│   ├── airgap_tx_signer         #   Cold-signing (create unsigned / sign offline)
│   ├── broadcast_signed_xmr     #   Tor-only Monero TX broadcaster
│   ├── create_receive_wallet    #   Generate receive subaddress
│   ├── thor_swap_preparer       #   ThorChain BTC→XMR deposit generator
│   └── exit_strategy_simulator  #   XMR off-ramp planner
│
├── modules/                     # Mixing & chaos modules
│   ├── PAG                      #   Polymorphic DAG generator
│   ├── labelmask                #   Label map generator
│   ├── label_poisoner           #   Forensic label injection
│   ├── fake_leaf_inserter       #   Decoy leaf nodes
│   ├── noise                    #   Decoy network traffic
│   ├── ghostmutator             #   Source code mutation
│   ├── wdna                     #   Wallet DNA mutation
│   ├── en_seeder                #   Entropy seed generator
│   ├── ghost_unifier            #   Module pipeline orchestrator
│   ├── swap_retry_guard         #   Swap retry with circuit rotation
│   ├── tor_endpoint_juggler     #   Onion RPC validator + rotation
│   └── vm_runtime               #   VM timing metrics
│
├── opsec/                       # OPSEC & anti-forensics
│   ├── paranoia_mode            #   Post-op host sanitization
│   ├── error_log_poisoner       #   Decoy log injection
│   ├── mirrormask               #   Forensic log mutation
│   ├── dmswitch                 #   Deadman switch (QR-locked)
│   ├── SML                      #   Secure memory-locked seeds
│   ├── integrity_faker          #   Integrity chain decoys
│   └── idk                      #   Entropy verifier + YubiKey
│
└── intel/                       # Intelligence collection
    ├── collectgrab              #   OSINT collector (Tor-routed)
    └── testergatherSystem       #   Advanced intel framework
```

---

## Running Tools

### Option 1: Unified Launcher (recommended)

```bash
# List all tools:
python3 run list

# Run any tool by short name:
python3 run ghostspiral --receive-wallet wallet.json --tor-proxy socks5h://127.0.0.1:9050
python3 run signer unsigned.json --phase sign --wallet-file wallet
python3 run broadcast tx_staging/signed/ --tor-proxy socks5h://127.0.0.1:9050
python3 run paranoia --dry-run
python3 run swap --amounts 0.05 --dests <XMR_ADDR> --tor-proxy socks5h://127.0.0.1:9050
```

### Option 2: Direct invocation

```bash
python3 core/GhostSpiral --help
python3 core/airgap_tx_signer plan.json --phase create --help
python3 opsec/paranoia_mode --dry-run
python3 modules/ghost_unifier --tor socks5h://127.0.0.1:9050
```

---

## System Requirements

- **OS:** Kali Linux (or any Debian-based Linux)
- **Python:** 3.10+
- **Tor:** Running with ControlPort 9051 enabled
- **Monero:** `monerod`, `monero-wallet-rpc`, `monero-wallet-cli`

---

## 1. Install System Packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tor torsocks jq gnupg python3-pip

# Monero CLI tools — download from https://www.getmonero.org/downloads/
tar xf monero-linux-x64-*.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/

# Verify
monerod --version && monero-wallet-cli --version && monero-wallet-rpc --version
```

## 2. Install Python Dependencies

```bash
pip install -r requirements.txt
python3 -c "import requests, stem, monero, psutil; print('Core deps OK')"
```

## 3. Configure Tor

```bash
# Enable ControlPort for NEWNYM circuit rotation
sudo tee -a /etc/tor/torrc << 'EOF'
ControlPort 9051
CookieAuthentication 1
EOF
sudo systemctl restart tor

# Verify Tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# If using password auth instead of cookie:
export TOR_CONTROL_PASSWORD="your_password"
```

## 4. Configure Monero

```bash
# Start daemon (local node):
monerod --detach --data-dir ~/.bitmonero

# Start wallet-rpc (hot wallet for auto-mode):
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file /path/to/wallet \
  --password "password" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login

# Verify:
curl -s http://127.0.0.1:18083/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_height"}' \
  -H 'Content-Type: application/json'
```

---

## Environment Variables

| Variable | When Needed | Description |
|----------|-------------|-------------|
| `TOR_CONTROL_PASSWORD` | HashedControlPassword in torrc | Tor control port password |
| `GS_WALLET_PASSWORD` | Auto-mode signing | Wallet password (avoids /proc leak) |
| `SWAPKIT_API_KEY` | ThorChain swaps | SwapKit API key (swapkit.dev) |

---

## Workflows

### 1. Receive XMR (sender gives you BTC)

```bash
# Create receive address
python3 run wallet --rpc http://127.0.0.1:18083 --tor-proxy socks5h://127.0.0.1:9050

# Generate ThorChain deposit for sender
python3 run swap --amounts 0.05 \
  --dests $(jq -r .address wallet_*.json) \
  --tor-proxy socks5h://127.0.0.1:9050

# After XMR arrives, run mixing:
python3 run ghostspiral --receive-wallet wallet_*.json \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083

# Clean up
python3 run paranoia --iface wlan0
```

### 2. Send BTC, get mixed XMR (auto-mode)

```bash
python3 run ghostspiral --btc-entry bc1q... --btc-amount 0.1 --split 3 \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083
```

### 3. Cold-signing (air-gap workflow)

```bash
# ONLINE machine (view-only wallet):
python3 run ghostspiral --receive-wallet wallet.json \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083 --cold

# Copy unsigned/ to USB → OFFLINE machine:
python3 run signer unsigned/unsigned_*.json --phase sign \
  --wallet-file /path/to/full_wallet --outdir tx_staging

# Copy tx_staging/signed/ back → ONLINE machine:
python3 run broadcast tx_staging/signed/ \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc http://127.0.0.1:18081 --wallet-rpc http://127.0.0.1:18083
```

### 4. Resume after crash

```bash
python3 run ghostspiral --receive-wallet wallet.json \
  --resume-plan unsigned/unsigned_abc123.json \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083
```

### 5. Chaos modules pipeline

```bash
python3 run seed                                          # Generate entropy
python3 run unify --tor socks5h://127.0.0.1:9050          # Run full chaos pipeline
# Or individual modules:
python3 run dag && python3 run labels && python3 run noise --tor-proxy socks5h://127.0.0.1:9050
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `socks5:// leaks DNS` | Change to `socks5h://` |
| `Tor leak detected` | `sudo systemctl start tor` |
| `NEWNYM failed` | Add `ControlPort 9051` to `/etc/tor/torrc` |
| `No wallet file` | Start `monero-wallet-rpc` with `--wallet-file` |
| `unsigned file not created` | Check wallet balance |
| `Method not found` | Use `--wallet-rpc` for submit_transfer |
| `No swap routes` | Set `SWAPKIT_API_KEY` env var |
| `Plan fingerprint mismatch` | Delete `stage5_progress.json` |
| `ModuleNotFoundError` | `pip install -r requirements.txt` |

## Security Notes

- All traffic routes through Tor (`socks5h://`). Plain `socks5://` is rejected.
- Wallet passwords pass via `GS_WALLET_PASSWORD` env var, never CLI args.
- `paranoia_mode` wipes ALL artifacts — run it last.
- All output files are 0600 (owner-only permissions).
- Terminal output shows scrubbed addresses (first/last 6 chars only).
