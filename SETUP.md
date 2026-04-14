# GhostSpiral — Setup

## Quick Install (one command)

```bash
git clone <repo> ghostspiral && cd ghostspiral && bash install.sh
```

That installs everything: system packages, Python deps, Tor config, and verifies it all works.

## Manual Install (if you prefer)

```bash
# 1. System packages
sudo apt update && sudo apt install -y tor torsocks jq gnupg python3-pip curl

# 2. Python deps (use python3 -m pip, NOT bare pip which may be python2)
python3 -m pip install -r requirements.txt

# 3. Enable Tor control port (needed for circuit rotation)
echo -e "\nControlPort 9051\nCookieAuthentication 1" | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor

# 4. Download Monero CLI tools
#    Go to https://www.getmonero.org/downloads/
#    Then:
tar xf monero-linux-x64-*.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/

# 5. Verify everything works
python3 -c "import requests, stem, monero, psutil; print('OK')"
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
monerod --version
```

## Start Monero (before running GhostSpiral)

```bash
# Start the daemon (syncs blockchain — first run takes hours)
monerod --detach

# Start wallet RPC (needed by all core tools)
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file /path/to/your/wallet \
  --password "yourpassword" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login
```

## Environment Variables (set before running)

```bash
export GS_WALLET_PASSWORD="your_wallet_password"   # avoids leaking via /proc
export SWAPKIT_API_KEY="your_key"                   # for ThorChain swaps
export TOR_CONTROL_PASSWORD="tor_pass"              # only if Tor uses password auth
```

---

## Project Layout

```
ghostspiral/
├── run                    ← launcher: python3 run <tool> [args]
├── install.sh             ← one-command installer
├── requirements.txt       ← pip dependencies
│
├── core/                  ← main pipeline (handles real money)
│   ├── gs_common.py           shared library (Tor, crypto, RPC)
│   ├── GhostSpiral            main mixer orchestrator
│   ├── airgap_tx_signer       cold-signing (online create / offline sign)
│   ├── broadcast_signed_xmr   broadcast signed TXs through Tor
│   ├── create_receive_wallet  generate XMR receive address
│   ├── thor_swap_preparer     ThorChain BTC→XMR deposit setup
│   └── exit_strategy_simulator  plan XMR off-ramp
│
├── modules/               ← mixing & chaos tools
│   ├── PAG, labelmask, label_poisoner, fake_leaf_inserter
│   ├── noise, ghostmutator, wdna, en_seeder
│   ├── ghost_unifier, swap_retry_guard
│   └── tor_endpoint_juggler, vm_runtime
│
├── opsec/                 ← cleanup & anti-forensics
│   ├── paranoia_mode          wipe everything after operation
│   ├── error_log_poisoner, mirrormask, dmswitch
│   └── SML, integrity_faker, idk
│
└── intel/                 ← collection tools
    ├── collectgrab            OSINT (runs through Tor)
    └── testergatherSystem     advanced intel framework
```

---

## How to Run Tools

```bash
# See all available tools
python3 run list

# Run any tool by its short name
python3 run ghostspiral --help
python3 run wallet --rpc http://127.0.0.1:18083 --tor-proxy socks5h://127.0.0.1:9050
python3 run paranoia --dry-run
python3 run signer plan.json --phase sign --wallet-file wallet

# Or call directly
python3 core/GhostSpiral --help
python3 opsec/paranoia_mode --dry-run
```

---

## Common Workflows

### Receive XMR (someone sends you BTC, you get mixed XMR)

```bash
# 1. Create a receive address
python3 run wallet --rpc http://127.0.0.1:18083 --tor-proxy socks5h://127.0.0.1:9050

# 2. Generate deposit address for the BTC sender
python3 run swap --amounts 0.05 \
  --dests $(jq -r .address wallet_*.json) \
  --tor-proxy socks5h://127.0.0.1:9050

# 3. Give the deposit address + memo to the sender
# 4. Wait for XMR to arrive

# 5. Mix it
python3 run ghostspiral --receive-wallet wallet_*.json \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083

# 6. Clean up
python3 run paranoia --iface wlan0
```

### Cold-signing (air-gap)

```bash
# Online machine:
python3 run ghostspiral --receive-wallet wallet.json \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083 --cold

# Copy unsigned/ folder to USB → offline machine

# Offline machine:
python3 run signer unsigned/unsigned_*.json --phase sign \
  --wallet-file /mnt/usb/wallet --outdir tx_staging

# Copy tx_staging/signed/ back to USB → online machine

# Online machine:
python3 run broadcast tx_staging/signed/ \
  --tor-proxy socks5h://127.0.0.1:9050 \
  --rpc http://127.0.0.1:18081 --wallet-rpc http://127.0.0.1:18083
```

### Resume after crash

```bash
python3 run ghostspiral --receive-wallet wallet.json \
  --resume-plan unsigned/unsigned_abc123.json \
  --tor-proxy socks5h://127.0.0.1:9050 --rpc-primary http://127.0.0.1:18083
```

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `ModuleNotFoundError` | `python3 -m pip install -r requirements.txt` or `bash install.sh` |
| `Tor leak detected` | `sudo systemctl start tor` |
| `NEWNYM failed` | `echo "ControlPort 9051" \| sudo tee -a /etc/tor/torrc && sudo systemctl restart tor` |
| `socks5:// leaks DNS` | Use `socks5h://` (with the h) |
| `No wallet file` | Start monero-wallet-rpc with `--wallet-file` |
| `Method not found` | You're hitting monerod (18081) not wallet-rpc (18083) |
| `No swap routes` | `export SWAPKIT_API_KEY="your_key"` |
| `Plan fingerprint mismatch` | `rm stage5_progress.json` and retry |
