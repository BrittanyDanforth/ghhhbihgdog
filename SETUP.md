# GhostSpiral — Setup Guide

Every command is copy-paste ready. You need a Debian/Kali VM with `sudo`.

---

## First time? Run this:

```
sudo apt update && sudo apt install -y tor torsocks jq gnupg python3-pip python3-venv curl wget bzip2
bash install.sh
```

That installs everything: system packages, Python deps, Tor config, and creates `./gs`.

After it finishes:

```
sudo systemctl start tor
sudo systemctl enable tor
./gs
```

You're in the menu. Choose `0` (System Check) to verify everything works.

---

## Already set up? Just run:

```
./gs
```

That's it. If something broke, run the installer again — it only fixes what's missing:

```
bash install.sh
```

---

## Tor firewall (lock down the VM)

This blocks ALL internet from the VM except through Tor. Malware can't call home,
DNS can't leak, nothing gets out unless Tor carries it.

**Enable:**

```
sudo bash tor_firewall.sh
```

**Your browser will stop working.** That's correct — it needs to go through Tor too:

```
sudo bash tor_firewall.sh --setup-browser
```

**If Malwarebytes on your HOST PC flags Tor traffic:**

```
sudo bash tor_firewall.sh --setup-bridges
```

This makes Tor use unlisted IPs with disguised traffic. Malwarebytes won't recognize it.

**Make firewall survive reboots:**

```
sudo bash tor_firewall.sh --persist
```

**Disable everything (back to normal networking):**

```
sudo bash tor_firewall.sh --undo
```

**Check status + run leak tests:**

```
sudo bash tor_firewall.sh --status
```

---

## Monero CLI tools

The toolkit needs `monerod`, `monero-wallet-cli`, and `monero-wallet-rpc`.

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

## Before each session

**Start the blockchain node** (first time downloads ~170 GB):

```
monerod --detach --data-dir ~/.bitmonero
```

**Start wallet RPC:**

```
monero-wallet-rpc --rpc-bind-port 18083 \
  --wallet-file ~/my_wallet \
  --password "YOUR_WALLET_PASSWORD" \
  --daemon-address 127.0.0.1:18081 \
  --disable-rpc-login \
  --log-level 0
```

`--log-level 0` prevents wallet-rpc from logging your operations.

Set the password as env var (keeps it out of `ps aux`):

```
export GS_WALLET_PASSWORD="YOUR_WALLET_PASSWORD"
```

Then launch:

```
./gs
```

---

## Create a wallet (first time only)

```
monero-wallet-cli --generate-new-wallet ~/my_wallet
```

Write down the 25-word seed phrase on paper. That's the only way to recover funds.

---

## When you're done

```
./gs                           # choose 9 (Paranoia Cleanup)
kill $(pgrep monero-wallet-rpc)
monerod exit
unset GS_WALLET_PASSWORD
history -c && history -w
```

---

## Quick reference

| What | Command |
|------|---------|
| First install | `bash install.sh` |
| Run toolkit | `./gs` |
| System check | `./gs` then `0` |
| Enable firewall | `sudo bash tor_firewall.sh` |
| Fix browser | `sudo bash tor_firewall.sh --setup-browser` |
| Fix Malwarebytes | `sudo bash tor_firewall.sh --setup-bridges` |
| Firewall survives reboot | `sudo bash tor_firewall.sh --persist` |
| Disable firewall | `sudo bash tor_firewall.sh --undo` |
| Firewall status + tests | `sudo bash tor_firewall.sh --status` |
| Cleanup | `./gs` then `9` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `curl: (7) ... port 9050` | Tor not running. `sudo systemctl start tor` |
| Browser says "can't connect" | Run `sudo bash tor_firewall.sh --setup-browser` |
| Malwarebytes flags on host | Run `sudo bash tor_firewall.sh --setup-bridges` |
| `ModuleNotFoundError` | Run `bash install.sh` or use `./gs` (auto-uses venv) |
| `NEWNYM failed` | Run the ControlPort setup: see install.sh step 3 |
| `No wallet file` | Start wallet RPC (see "Before each session") |
| Firewall locked me out | `sudo bash tor_firewall.sh --undo` |

---

## Proxy safety

```
ONLY use: socks5h://127.0.0.1:9050 (system Tor)
     or:  socks5h://127.0.0.1:9150 (Tor Browser)

NEVER use: free proxy lists, cheap VPN SOCKS, any proxy you don't control.
The "h" in socks5h is critical — it routes DNS through Tor.
Without it, your ISP sees every domain you visit.
```
