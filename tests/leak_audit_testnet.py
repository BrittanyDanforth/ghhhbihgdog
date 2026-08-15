#!/usr/bin/env python3
"""RUN the real pipeline and audit everything it leaves on disk.

Rather than reasoning about one surface at a time, this drives the shipped
phase_create -> phase_sign chain against real monero binaries and then answers,
from observation:

  1. Which files appeared anywhere the run could write (CWD, /tmp, /dev/shm,
     $HOME, the staging dir)?
  2. What are their PERMISSIONS -- is anything group/other-readable?
  3. Do any of them CONTAIN real secrets (wallet password, spend key, view key,
     mnemonic, addresses, txid)? Content is scanned, not guessed at.
  4. What SURVIVES the run, and is any of it sensitive?

Every secret is a real value pulled from the live wallet, so a hit is a genuine
leak rather than a string match on a placeholder.

Requires monerod / monero-wallet-rpc / monero-wallet-cli. SKIPS if absent.
"""
import subprocess, time, os, signal, shutil, tempfile, json, sys, stat
import importlib.machinery, importlib.util
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH")
        sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


airgap = load("airgap_tx_signer")
bcast = load("broadcast_signed_xmr")

BASE = tempfile.mkdtemp(prefix="leak_")
DR = "http://127.0.0.1:28131"; D = DR + "/json_rpc"
WPORT = 28133
WR = f"http://127.0.0.1:{WPORT}/json_rpc"
WALLET_PW = "LeakAudit-Spend-Pass-9271"

PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok   {name}")
    else:
        FAIL += 1; FAILURES.append(name); print(f"  LEAK {name}")


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=40).json()


def draw(path, body=None):
    return requests.post(DR + path, json=body or {}, timeout=40).json()


def wj(m, p=None, t=120):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def L(cmd, log):
    p = subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT)
    procs.append(p); return p


def step(s):
    print(f"\n=== {s} ===")


# Watch every directory the run could plausibly write to. $HOME and the CWD
# were originally omitted, which meant an artifact dropped there would not have
# been noticed at all -- the audit can only report on paths it looks at.
WATCH_DIRS = ["/tmp", "/dev/shm", "/var/tmp", os.path.expanduser("~")]


def snapshot(dirs):
    """Set of files currently present in the watched dirs (one level deep is
    not enough -- the signer nests, so walk)."""
    seen = set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, names in os.walk(d):
            for n in names:
                seen.add(os.path.join(root, n))
    return seen


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


result = "INCOMPLETE"
cwd0 = os.getcwd()
try:
    L(["monerod", "--testnet", "--offline", "--data-dir", os.path.join(BASE, "node"),
       "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28131", "--p2p-bind-port", "28130",
       "--no-igd", "--hide-my-port", "--fixed-difficulty", "1", "--non-interactive",
       "--log-file", os.path.join(BASE, "d.log"), "--log-level", "0"], os.path.join(BASE, "d.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None:
                break
        except Exception:
            pass
    L(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28131", "--trusted-daemon",
       "--wallet-dir", os.path.join(BASE, "w"), "--rpc-bind-port", str(WPORT), "--rpc-bind-ip", "127.0.0.1",
       "--disable-rpc-login", "--log-file", os.path.join(BASE, "w.log"), "--log-level", "0"],
      os.path.join(BASE, "w.out"))
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"):
                break
        except Exception:
            pass

    step("setup: fund a PASSWORD-PROTECTED wallet, harvest the real secrets")
    wj("create_wallet", {"filename": "full", "password": WALLET_PW, "language": "English"})
    faddr = wj("get_address", {"account_index": 0})["result"]["address"]
    sub = wj("create_address", {"account_index": 0, "label": "mix"})["result"]["address"]
    draw("/start_mining", {"miner_address": faddr, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < 80:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")
    view_key = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    spend_key = wj("query_key", {"key_type": "spend_key"})["result"]["key"]
    mnemonic = wj("query_key", {"key_type": "mnemonic"}).get("result", {}).get("key", "")
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    wj("close_wallet")

    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": faddr,
                              "viewkey": view_key, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})

    SECRETS = {
        "WALLET PASSWORD": WALLET_PW,
        "SPEND KEY": spend_key,
        "VIEW KEY": view_key,
        "MNEMONIC": (mnemonic.split()[0] + " " + mnemonic.split()[1]) if len(mnemonic.split()) > 1 else "",
    }
    # Addresses are sensitive too, but they legitimately appear in the plan and
    # tx files; tracked separately so the report distinguishes them.
    ADDRESSES = {"primary address": faddr, "mix subaddress": sub}

    airgap.verify_tor = lambda *a, **k: None
    airgap.validate_proxy = lambda u: {"http": u, "https": u}

    staging = os.path.join(BASE, "staging")
    os.chdir(BASE)

    step("RUN: shipped phase_create -> phase_sign, watching /tmp + /dev/shm")
    before = snapshot(WATCH_DIRS)
    plan = [{"src": faddr, "src_index": 0, "dst": sub, "amt": "0.3", "delay": 0}]
    airgap.phase_create(
        Args(tor_proxy="socks5h://127.0.0.1:9050", rpc=f"http://127.0.0.1:{WPORT}",
             outdir=staging, fee_priority=1), plan, {"account_index": 0})

    shim = os.path.join(BASE, "wcli")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\nexec monero-wallet-cli --testnet --offline "$@"\n')
    os.chmod(shim, 0o755)
    airgap.phase_sign(
        Args(outdir=staging, wallet_cli=shim,
             wallet_file=os.path.join(BASE, "w", "full"), wallet_password=WALLET_PW), plan)

    # Stage 3: the SHIPPED broadcast, relaying for real through the local
    # wallet-rpc. Previously unaudited -- it writes a progress file holding
    # txids and per-TX state, which is exactly the sort of artifact this audit
    # exists to catch. Tor/NEWNYM are stubbed (the RPC is a real local one).
    step("RUN: shipped broadcast_signed_xmr.main() against the real wallet-rpc")
    bcast.verify_tor = lambda *a, **k: None
    bcast.newnym = lambda *a, **k: True
    bcast.secure_delay = lambda *a, **k: None
    bcast.tor_recheck = lambda *a, **k: None
    bcast.validate_proxy = lambda u: {"http": u, "https": u}
    prog_file = os.path.join(BASE, "broadcast_progress.json")
    argv0 = sys.argv[:]
    sys.argv = ["broadcast_signed_xmr", os.path.join(staging, "signed"),
                "--tor-proxy", "socks5h://127.0.0.1:9050",
                "--rpc", f"http://127.0.0.1:{WPORT}",
                "--resume", prog_file, "--rebroadcast", "2"]
    broadcast_ok = False
    try:
        bcast.main()
        broadcast_ok = True
    except SystemExit as e:
        broadcast_ok = (e.code in (0, None))
        print(f"    broadcast exited: {e.code}")
    finally:
        sys.argv = argv0
    check("broadcast relayed the signed tx (exit 0)", broadcast_ok)

    after = snapshot(WATCH_DIRS)

    step("AUDIT 0: prove the WATCHES themselves work")
    # A watch that cannot see is worse than no watch: every "nothing left
    # behind" result below would be vacuously true. Plant a canary in each
    # watched directory and require the snapshot diff to surface it.
    watch_canaries = []
    for d in WATCH_DIRS:
        if os.path.isdir(d) and os.access(d, os.W_OK):
            cp = os.path.join(d, ".leak_audit_canary")
            try:
                with open(cp, "w") as f:
                    f.write("canary")
                watch_canaries.append(cp)
            except OSError:
                pass
    _probe = snapshot(WATCH_DIRS)
    unseen = [c for c in watch_canaries if c not in _probe]
    check(f"all {len(watch_canaries)} watched dirs are actually scanned "
          f"(blind to: {unseen})", not unseen)
    for c in watch_canaries:
        try:
            os.unlink(c)
        except OSError:
            pass

    step("AUDIT 1: files the run LEFT BEHIND in /tmp, /dev/shm, /var/tmp, $HOME")
    leftovers = sorted(after - before)
    for f in leftovers:
        print(f"    left: {f}")
    if not leftovers:
        print("    (none)")
    # The password file lives in /dev/shm; it must not survive.
    shm_left = [f for f in leftovers if f.startswith("/dev/shm")]
    check("no residue left in /dev/shm (password file erased)", not shm_left)
    sign_left = [f for f in leftovers if "gs_sign_" in f]
    check("no signer scratch dir left in /tmp", not sign_left)

    step("AUDIT 2: scan EVERY leftover + staging file for REAL secrets")
    audit_files = list(leftovers)
    for root, _, names in os.walk(staging):
        for n in names:
            audit_files.append(os.path.join(root, n))
    audit_files = sorted(set(audit_files))

    def scan_for_secrets(paths):
        hits = []
        for fp in paths:
            try:
                blob = open(fp, "rb").read()
            except OSError:
                continue
            txt = blob.decode("utf-8", errors="ignore")
            for label, val in SECRETS.items():
                if val and (val in txt or val.encode() in blob):
                    hits.append((fp, label))
        return hits

    # DETECTOR SELF-TEST. "No secrets found" is worthless if the scanner cannot
    # find one. Plant each real secret in a canary file and require the scanner
    # to flag every one before trusting a clean result below.
    canary_dir = os.path.join(BASE, "canary")
    os.makedirs(canary_dir, exist_ok=True)
    canaries = []
    for i, (label, val) in enumerate(SECRETS.items()):
        if not val:
            continue
        cp = os.path.join(canary_dir, f"canary_{i}.txt")
        with open(cp, "w") as f:
            f.write(f"harmless preamble\n{val}\ntrailing\n")
        canaries.append((cp, label))
    canary_hits = scan_for_secrets([c[0] for c in canaries])
    check(f"DETECTOR SELF-TEST: scanner finds all {len(canaries)} planted "
          f"secrets (found {len(canary_hits)})",
          len(canary_hits) == len(canaries))
    shutil.rmtree(canary_dir, ignore_errors=True)

    print(f"    scanning {len(audit_files)} real file(s)")
    secret_hits = scan_for_secrets(audit_files)
    for fp, label in secret_hits:
        print(f"    !!! {label} found in {fp}")
    check("no wallet password / spend key / view key / mnemonic in ANY file",
          not secret_hits)

    # The integrity chain is written to CWD by every script and survives the
    # run by design (it is the audit trail). Confirm it never records secrets.
    step("AUDIT 2b: the integrity chain log itself")
    chain = os.path.join(BASE, "integrity_chain.log")
    if os.path.exists(chain):
        ctext = open(chain, errors="ignore").read()
        print(f"    {len(ctext.splitlines())} chained entries")
        chain_secret = [lbl for lbl, v in SECRETS.items() if v and v in ctext]
        check(f"integrity chain records no secrets (found {chain_secret})",
              not chain_secret)
        chain_addr = [lbl for lbl, v in ADDRESSES.items() if v and v in ctext]
        check(f"integrity chain records no FULL addresses (found {chain_addr})",
              not chain_addr)
    else:
        print("    (no integrity_chain.log written during this run)")

    step("AUDIT 3: permissions on every FILE the pipeline produced")
    bad_perms = []
    for root, _, names in os.walk(staging):
        for n in names:
            fp = os.path.join(root, n)
            m = os.stat(fp).st_mode
            if m & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                bad_perms.append((fp, oct(m & 0o777)))
    for fp, m in bad_perms:
        print(f"    !!! {fp} is {m}")
    check("no pipeline output is group/other accessible", not bad_perms)

    # Directories were originally missed here: files were correctly 0600 while
    # the dirs holding them were 0755, so any local user could list them and
    # learn the TX count and timing -- metadata this toolchain exists to hide.
    step("AUDIT 3b: permissions on every DIRECTORY the pipeline produced")
    bad_dirs = []
    for root, dirs, _ in os.walk(staging):
        for d0 in [root] + [os.path.join(root, x) for x in dirs]:
            m = os.stat(d0).st_mode & 0o777
            if m & 0o077:
                bad_dirs.append((d0, oct(m)))
    for d0, m in sorted(set(bad_dirs)):
        print(f"    !!! {d0} is {m} (listable by others)")
    check("no pipeline directory is group/other accessible", not bad_dirs)
    print(f"    staging dir mode: {oct(os.stat(staging).st_mode & 0o777)}")

    step("AUDIT 3c: the broadcast progress file (txids + per-TX state)")
    if os.path.exists(prog_file):
        pm = os.stat(prog_file).st_mode & 0o777
        check(f"broadcast progress file is 0600 (got {oct(pm)})", pm == 0o600)
        ptext = open(prog_file, errors="ignore").read()
        p_secret = [lbl for lbl, v in SECRETS.items() if v and v in ptext]
        check(f"progress file holds no secrets (found {p_secret})", not p_secret)
        pj = json.loads(ptext)
        print(f"    relayed={pj.get('relayed')} failed_perm={pj.get('failed_perm')}")
        check("progress file recorded the relay as successful",
              pj.get("relayed") == [0])
    else:
        print("    (no progress file written)")

    step("AUDIT 4: the signed transaction itself")
    blob_path = os.path.join(staging, "signed", "tx_0.signed")
    check("signed tx exists", os.path.exists(blob_path))
    if os.path.exists(blob_path):
        m = os.stat(blob_path).st_mode & 0o777
        check(f"signed tx is 0600 (got {oct(m)})", m == 0o600)
        check("signed tx contains no wallet password",
              WALLET_PW.encode() not in open(blob_path, "rb").read())

    step("AUDIT 5: addresses appearing on disk (expected, but reported)")
    addr_hits = {}
    for fp in audit_files:
        try:
            txt = open(fp, "rb").read().decode("utf-8", errors="ignore")
        except OSError:
            continue
        for label, val in ADDRESSES.items():
            if val and val in txt:
                addr_hits.setdefault(os.path.basename(fp), []).append(label)
    for fn, labels in sorted(addr_hits.items()):
        print(f"    {fn}: {', '.join(labels)}")
    print("    (addresses in staging files are inherent to a tx plan; they are")
    print("     covered by the 0600 perms above and by paranoia's wipe list)")

    result = "NO LEAKS" if FAIL == 0 else "LEAKS FOUND"
finally:
    os.chdir(cwd0)
    for p in procs:
        try:
            p.send_signal(signal.SIGTERM); p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
print(">>> PIPELINE LEAK AUDIT:", result)
sys.exit(0 if FAIL == 0 else 1)
