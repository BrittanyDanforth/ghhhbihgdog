# GhostSpiral — Setup Guide

Know nothing? Start here. Every command is copy-paste ready.
All commands run in a terminal. You need a Debian/Kali box with `sudo`.

---

## 1. System packages

```
sudo apt update
sudo apt install -y tor torsocks jq gnupg python3-pip curl wget bzip2
```

---

## 2. Python libraries

```
python3 -m pip install requests PySocks tenacity stem monero psutil
python3 -m pip install python-gnupg pycryptodomex cryptography qrcode pyyaml
python3 -m pip install beautifulsoup4 aiohttp aiohttp-socks
```

Quick check — should print `ALL OK`:

```
python3 -c "import requests, socks, stem, monero, psutil, tenacity, cryptography; print('ALL OK')"
```

If it says `ModuleNotFoundError`, just install whichever one it names.

---

## 3. Tor

Tor is your proxy. It routes all traffic through 3 encrypted hops — nobody
(ISP, law enforcement, data brokers) can see what you're doing. You don't
need any other proxy. Tor is free and runs on your machine.

**Start it:**

```
sudo systemctl start tor
sudo systemctl enable tor
```

**Check it works:**

```
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

You should see `"IsTor":true`. If you get an error, Tor isn't running.

**Enable circuit rotation** (required — GhostSpiral changes your identity
between operations):

```
sudo bash -c 'echo "" >> /etc/tor/torrc'
sudo bash -c 'echo "ControlPort 9051" >> /etc/tor/torrc'
sudo bash -c 'echo "CookieAuthentication 1" >> /etc/tor/torrc'
sudo systemctl restart tor
```

**Your proxy address:** `socks5h://127.0.0.1:9050`

This is what you enter whenever GhostSpiral asks for a proxy.
The `h` means DNS goes through Tor too (critical).

> **Port cheat-sheet:**
>
> | Port | What it is | When to use |
> |------|-----------|-------------|
> | 9050 | SOCKS (system `tor`) | Default — use this |
> | 9150 | SOCKS (Tor Browser) | Only if you run Tor Browser instead of system tor |
> | 9051 | Control (system `tor`) | GhostSpiral uses this automatically for circuit rotation |
> | 9151 | Control (Tor Browser) | GhostSpiral falls back to this if 9051 isn't there |
>
> **Never** pass 9051 or 9151 as `--tor-proxy`. Those are control ports, not SOCKS.

**Never use:**
- Free proxy lists (they log everything)
- Cheap VPN SOCKS proxies (they see your traffic)
- Any proxy you don't control (they can steal funds)
- `socks5://` without the `h` (leaks DNS to your ISP)

---

## 4. Monero CLI tools

GhostSpiral needs `monerod` (blockchain node), `monero-wallet-rpc` (wallet
server), and `monero-wallet-cli` (signing tool).

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

Check all three print a version:

```
monerod --version
monero-wallet-cli --version
monero-wallet-rpc --version
```

---

## 5. Start Monero (before each session)

**5a. Blockchain node:**

```
monerod --detach --data-dir ~/.bitmonero
```

First run downloads the full chain (~170 GB, takes hours). After that it
starts in seconds. Check progress with `monerod status`.

**5b. Create a wallet** (first time only):

```
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

It asks for a password — remember it. It shows a 25-word seed phrase —
**write it on paper and store it safely**. That phrase is the only way to
recover funds.

**5c. Start wallet RPC:**

```
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file ~/my_wallet \
  --password "YOUR_WALLET_PASSWORD" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login
```

Keep that terminal open (or add `--detach`).

**5d. Verify it's running:**

```
curl -s http://127.0.0.1:18083/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_height"}' \
  -H 'Content-Type: application/json'
```

Should return something with `"height":` and a number.

---

## 6. Environment variables

```
export GS_WALLET_PASSWORD="YOUR_WALLET_PASSWORD"
```

Same password from step 5c. Setting it as an env var keeps it out of
`ps aux` where anyone on the machine could see it.

---

## 7. Run GhostSpiral

```
cd /path/to/ghostspiral
python3 run
```

Interactive menu:

```
1  Full Pipeline          BTC -> mixed XMR
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

**First time?** Start with `0` — it checks everything is wired up.

**Want a safe test?** Use `t` — runs the whole pipeline with fake funds.

---

## 8. Stopping (when you're done)

Go in reverse order: clean artifacts first, then stop services.

**8a. Wipe GhostSpiral artifacts** (do this while Tor is still running):

```
python3 run paranoia --dry-run   # preview what gets deleted
python3 run paranoia             # actually delete (sudo recommended)
```

**8b. Stop wallet RPC:**

```
kill $(pgrep monero-wallet-rpc)
```

(Or Ctrl+C if it's running in a terminal.)

**8c. Stop monerod:**

```
monerod exit
```

Don't `kill -9` it — that can corrupt the blockchain database.

**8d. Stop Tor** (optional — you probably want to keep it):

```
sudo systemctl stop tor
```

**8e. Clean up your shell:**

```
unset GS_WALLET_PASSWORD TOR_CONTROL_PASSWORD
history -c && history -w
```

**Verify nothing's left running:**

```
pgrep -a monero || echo "No Monero processes"
ss -tlnp | grep -E '18081|18083|9050' || echo "No GhostSpiral ports open"
```

---

## Common workflows

**Receive XMR (someone sends you BTC):**

1. `6` Create Wallet — get a fresh XMR address
2. `7` Swap Preparer — get a BTC deposit address via ThorChain
3. Give the BTC address + memo to the sender
4. Wait for XMR to arrive
5. `2` Receive Mode — mix the XMR
6. `9` Paranoia Cleanup — wipe traces

**Cold signing (maximum security):**

1. Online machine: `3` Cold — creates unsigned plan
2. Copy `unsigned/` to USB
3. Offline machine: run the signer on the USB files
4. Copy `tx_staging/signed/` back to USB
5. Online machine: `4` Broadcast — sends the signed TXs

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Re-run step 2 |
| `curl: (7) ... port 9050` | Tor isn't running. `sudo systemctl start tor`. Using Tor Browser? Try port 9150 |
| `Tor leak detected` | `sudo systemctl start tor` |
| `NEWNYM failed` | Re-run the ControlPort lines from step 3 |
| `socks5:// leaks DNS` | Use `socks5h://` (with the h) |
| `No wallet file` | Start wallet RPC (step 5c) |
| `Method not found` | You're hitting port 18081 instead of 18083 |
| `No swap routes` | THORNode endpoints are down. Check Tor, try again later |
| `Invalid BTC address` | Must start with `bc1`, `1`, or `3` |
| System Check shows `[!]` for Monero | Run step 4 |
| System Check shows `[!]` for wallet-rpc | Run step 5c |

---

## Proxy safety

```
NEVER use free/cheap/public SOCKS proxies with GhostSpiral.

A malicious proxy can:
  - See ALL your traffic (destinations, amounts, addresses)
  - Modify RPC responses (swap destination = steal funds)
  - Log your IP and correlate with blockchain activity

ONLY use:
  OK  Your local Tor (socks5h://127.0.0.1:9050 or :9150 for Tor Browser)
  OK  A Tor instance on a VPS you control
  NO  Public proxy lists
  NO  "Free VPN" SOCKS
  NO  Shared proxies from unknown providers
```

---

## Quick install (all-in-one)

If you prefer one block instead of step-by-step:

```
sudo apt update && sudo apt install -y tor torsocks jq gnupg python3-pip curl wget bzip2
python3 -m pip install -r requirements.txt
echo -e "\nControlPort 9051\nCookieAuthentication 1" | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip || curl --socks5-hostname 127.0.0.1:9150 https://check.torproject.org/api/ip
```

For Monero tools:

```
cd /tmp
wget https://downloads.getmonero.org/cli/linux64 -O monero-cli.tar.bz2
tar xf monero-cli.tar.bz2
sudo cp monero-x86_64-linux-gnu-*/monero* /usr/local/bin/
rm -rf monero-x86_64-linux-gnu-* monero-cli.tar.bz2
cd -
monerod --version && monero-wallet-rpc --version
```

---

## File layout

```
ghostspiral/
  run                    <- interactive launcher
  install.sh             <- auto-installer
  requirements.txt       <- Python dependencies
  core/                  <- main pipeline
  modules/               <- mixing & chaos
  opsec/                 <- cleanup & anti-forensics
  intel/                 <- OSINT collection
```

`python3 run list` shows all available tools.
