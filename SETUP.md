# GhostSpiral v10.7 — Complete Setup & Operations Guide

## System Requirements

- **OS:** Kali Linux (or Debian-based Linux)
- **Python:** 3.10+
- **Tor:** Running with ControlPort enabled
- **Monero:** `monerod`, `monero-wallet-rpc`, `monero-wallet-cli` installed

---

## 1. Install System Packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tor torsocks jq gnupg python3-pip

# Monero CLI tools — download from https://www.getmonero.org/downloads/
# Extract and add to PATH:
tar xf monero-linux-x64-*.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/

# Verify installation
monerod --version
monero-wallet-cli --version
monero-wallet-rpc --version
```

## 2. Install Python Dependencies

```bash
pip install -r requirements.txt

# Verify critical packages
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

# Verify Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# If using HashedControlPassword instead of CookieAuthentication:
export TOR_CONTROL_PASSWORD="your_password"
```

## 4. Configure Monero

### Start monerod (local node):
```bash
monerod --detach --data-dir ~/.bitmonero
# Wait for sync (can take hours for first sync)
```

### Start monero-wallet-rpc:
```bash
# For HOT wallet (auto-mode — has spend key):
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file /path/to/wallet \
  --password "wallet_password" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login

# For VIEW-ONLY wallet (cold-signing workflow):
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file /path/to/view-only-wallet \
  --password "password" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login
```

### Verify wallet-rpc:
```bash
curl -s http://127.0.0.1:18083/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_height"}' \
  -H 'Content-Type: application/json'
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TOR_CONTROL_PASSWORD` | If torrc uses HashedControlPassword | Tor control port password for NEWNYM |
| `GS_WALLET_PASSWORD` | For auto-mode signing | Monero wallet password (avoids /proc leak) |
| `SWAPKIT_API_KEY` | For ThorChain swaps | SwapKit API key (get from swapkit.dev) |

```bash
export TOR_CONTROL_PASSWORD="your_tor_password"
export GS_WALLET_PASSWORD="your_wallet_password"
export SWAPKIT_API_KEY="your_swapkit_key"
```

---

## File Layout

All scripts live at the project root. They are organized by purpose:

### Core Pipeline (handles real money)
| File | Purpose |
|------|---------|
| `gs_common.py` | Shared OPSEC library (Tor, crypto, integrity, RPC) |
| `GhostSpiral` | Main orchestrator — BTC→XMR mixing pipeline |
| `airgap_tx_signer` | Two-phase cold-signing (create unsigned / sign offline) |
| `broadcast_signed_xmr` | Resilient Tor-only Monero TX broadcaster |
| `create_receive_wallet` | Generate receive subaddress for incoming XMR |
| `thor_swap_preparer` | ThorChain BTC→XMR swap quote + deposit generator |
| `exit_strategy_simulator` | XMR off-ramp planner with price oracles |

### OPSEC / Cleanup
| File | Purpose |
|------|---------|
| `paranoia_mode` | Post-op host sanitization (MAC spoof, file wipe, log purge) |
| `error_log_poisoner` | Inject decoy error entries into logs |
| `mirrormask` | Forensic log mutation and analysis resistance |
| `dmswitch` | Deadman switch with QR-locked unlock tokens |
| `SML` | Secure memory-locked seed management |
| `idk` | Entropy bundle verifier with optional YubiKey auth |

### Chaos / Mixing Modules
| File | Purpose |
|------|---------|
| `PAG` | Polymorphic DAG generator for mixing graphs |
| `labelmask` | Label map generator tied to DAG structure |
| `label_poisoner` | Inject fake labels to confuse forensic analysis |
| `fake_leaf_inserter` | Add decoy leaf nodes to DAGs |
| `noise` | Decoy network traffic generator |
| `ghostmutator` | Source code mutation engine (symbol renaming) |
| `wdna` | Wallet DNA mutation (subaddress/account shuffling) |

### Infrastructure
| File | Purpose |
|------|---------|
| `en_seeder` | Entropy seed generator from multiple sources |
| `ghost_unifier` | Pipeline orchestrator for chaos modules |
| `swap_retry_guard` | Swap retry with circuit rotation and progress tracking |
| `tor_endpoint_juggler` | Monero onion RPC endpoint validator + rotation |
| `vm_runtime` | VM timing metrics for deterministic delays |
| `collectgrab` | OSINT collection tool (Tor-routed) |
| `testergatherSystem` | Advanced intelligence gathering framework |

---

## Workflows

### Workflow 1: Receive XMR (you receive BTC→XMR swap)

```bash
# Step 1: Create receive address
python3 create_receive_wallet \
  --rpc http://127.0.0.1:18083 \
  --tor-proxy socks5h://127.0.0.1:9050

# Step 2: Generate ThorChain deposit address for the sender
python3 thor_swap_preparer \
  --amounts 0.05 \
  --dests $(jq -r .address wallet_*.json) \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --api-key "$SWAPKIT_API_KEY"

# Step 3: Give deposit address + memo to the BTC sender
# Step 4: Wait for XMR to arrive (monitor wallet-rpc balance)

# Step 5: Run GhostSpiral in receive mode
python3 GhostSpiral \
  --receive-wallet wallet_*.json \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc-primary http://127.0.0.1:18083

# Step 6: Clean up
python3 paranoia_mode --iface wlan0
```

### Workflow 2: Send BTC, receive mixed XMR

```bash
# Auto-mode (hot wallet):
python3 GhostSpiral \
  --btc-entry bc1q... \
  --btc-amount 0.1 \
  --split 3 \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc-primary http://127.0.0.1:18083 \
  --swapkit-api-key "$SWAPKIT_API_KEY"
```

### Workflow 3: Cold-signing (air-gap)

```bash
# On ONLINE machine (view-only wallet):
python3 GhostSpiral \
  --receive-wallet wallet_*.json \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc-primary http://127.0.0.1:18083 \
  --cold

# Copy unsigned/ directory to USB

# On OFFLINE machine (full wallet):
python3 airgap_tx_signer unsigned/unsigned_*.json \
  --phase sign \
  --wallet-file /path/to/full_wallet \
  --outdir tx_staging

# Copy tx_staging/signed/ back to USB → online machine

# On ONLINE machine:
python3 broadcast_signed_xmr tx_staging/signed/ \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc http://127.0.0.1:18081 \
  --wallet-rpc http://127.0.0.1:18083
```

### Workflow 4: Resume after crash

```bash
# If GhostSpiral Stage 5 crashed, resume on the SAME plan:
python3 GhostSpiral \
  --receive-wallet wallet_*.json \
  --resume-plan unsigned/unsigned_abc123.json \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc-primary http://127.0.0.1:18083
```

### Workflow 5: Run chaos modules

```bash
# Generate entropy seed first:
python3 en_seeder

# Run the chaos pipeline via ghost_unifier:
python3 ghost_unifier --tor socks5h://127.0.0.1:9050

# Or run individual modules:
python3 PAG                    # Generate mixing DAG
python3 labelmask              # Generate label map
python3 noise --tor-proxy socks5h://127.0.0.1:9050  # Decoy traffic
python3 ghostmutator           # Mutate source code
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `socks5:// leaks DNS` | Using `socks5://` | Change to `socks5h://` |
| `Tor leak detected` | Tor not running | `sudo systemctl start tor` |
| `NEWNYM failed 3 times` | ControlPort not enabled | Add `ControlPort 9051` to torrc |
| `No wallet file` | wallet-rpc has no wallet | Start wallet-rpc with `--wallet-file` |
| `unsigned file not created` | Wallet balance too low | Check `get_balance` via wallet-rpc |
| `Method not found` on submit_transfer | Sending to monerod instead of wallet-rpc | Use `--wallet-rpc http://127.0.0.1:18083` |
| `No swap routes` | SwapKit API key missing | Set `SWAPKIT_API_KEY` env var |
| `Plan fingerprint mismatch` | Stale progress from old run | Delete `stage5_progress.json` |
| Script won't start | Missing Python deps | `pip install -r requirements.txt` |

## File Permissions

All output files are created with `0600` (owner read/write only).
Verify with: `ls -la unsigned/ tx_staging/ *.json`

## Security Notes

- All network traffic goes through Tor (`socks5h://`). Plain `socks5://` is rejected.
- Wallet passwords are passed via `GS_WALLET_PASSWORD` env var, not CLI args.
- `paranoia_mode` wipes all artifacts including integrity logs — run LAST.
- On CoW filesystems (btrfs/ZFS), use `shred` or full-disk encryption for secure deletion.
- Terminal output only shows scrubbed addresses (first/last 6 chars).
