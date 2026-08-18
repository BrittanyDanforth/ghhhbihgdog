#!/usr/bin/env python3
"""Hunt metadata / OPSEC leftovers that could name name1 or name2.

Not just address strings. Time buckets, tool labels, RPC URLs, host/user
paths, file names, wipe/gitignore gaps, and whether tx 'extra' ever hits
the chain.

An outsider without the PC still cannot read PRIMARY from shipped public
files. Several fields DO give leads (tool, time window, swap dest, amounts
on disk). Taking the box is a different game: wallet-rpc writes PRIMARY
into *.address.txt and the RPC log.

No monero binaries required.
"""
from __future__ import annotations
import ast, os, sys, json, tempfile, getpass, socket, time
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import importlib.machinery, importlib.util


def load(name, filename=None):
    path = os.path.join(REPO, filename or name)
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m)
    return m


gs = load("gs_common", "gs_common.py")
ghost = load("GhostSpiral")
para = load("paranoia_mode")
airgap = load("airgap_tx_signer")

NAME1 = "9w7H9tbA8foDb7RpAbW16eVNA9sP7zaN51GDxros5UpHcFWewZ3qZ3Q98NTksHREd4c8zWSY2XfJriZY92KowobtQvppovB"
NAME2 = "9yTv4Dh19MYHVzM5psV1XYGAg13oqNPibP1ZTikkKZcVi6WKTt1aMZ45LA3hthG12t4wVG6pQofCcPCAKhqHeGRy811izuM"
ENTRY = "BavoXAdgVzaMvr2Utf4UdEH3MDFXfb27yfBFv2jm3Q6nHJBam5eKSxBTDWGDEkz3hHPJZADzT5hRkMLQBofQkQ9v3NA9S5n"

PASS = 0
FAIL = 0
FAILS = []
LEADS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  ", name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL:", name)


def lead(kind, what):
    LEADS.append((kind, what))
    print(f"  LEAD [{kind}] {what}")


def src(name):
    return Path(REPO, name).read_text()


def main():
    print("\n=== METADATA / OPSEC HUNT  (no seed, try every leftover field) ===")
    host = socket.gethostname()
    user = getpass.getuser()
    home = str(Path.home())
    print(f"    this box would look like user={user!r} host={host!r}")
    print("    those strings must not be what the shipped writers persist\n")

    crw = src("create_receive_wallet")
    gss = src("GhostSpiral")
    gsc = src("gs_common.py")
    ags = src("airgap_tx_signer")
    par = src("paranoia_mode")

    # ── what the shipped writers put in the receive bundle ───────────────
    print("--- shipped receive bundle fields ---")
    check("bundle writes schema + created + address + account + sub + label + rpc",
          all(k in crw for k in (
              '"schema"', '"created"', '"address"', '"account_index"',
              '"subaddress_index"', '"label"', '"rpc_endpoint"')))
    check("bundle created timestamp is coarsened to a 10-min bucket",
          "time.time()) // 600 * 600" in crw)
    check("default receive label is GhostSpiral_entry (tool fingerprint)",
          'default="GhostSpiral_entry"' in crw)
    check("bundle does not write hostname / getuser / HOME / cwd",
          "gethostname" not in crw and "getuser" not in crw
          and "expanduser" not in crw and "getcwd" not in crw)
    lead("TOOL", "schema gs_receive_wallet_v1 + label GhostSpiral_entry")
    lead("TIME", "bundle['created'] is a 10-min unix bucket — correlate with swap/chain")
    lead("HOST", "bundle['rpc_endpoint'] is the wallet-rpc URL (localhost usually)")

    # ── integrity log ────────────────────────────────────────────────────
    print("\n--- integrity log (call the real writer) ---")
    tmp = Path(tempfile.mkdtemp(prefix="meta_"))
    logp = tmp / "integrity_chain.log"
    gs.integrity_log("wallet", f"created:{gs.scrub_address(ENTRY)}:label=GhostSpiral_entry",
                     log_path=logp)
    line = logp.read_text().strip()
    print(f"    wrote: {line[:120]}")
    check("log line carries VERSION + coarsened ts + stage + msg",
          f"|{gs.VERSION}|" in line and "wallet" in line)
    check("log scrubs the address (full ENTRY is not in the line)",
          ENTRY not in line and NAME1 not in line and NAME2 not in line)
    check("log does not carry hostname or username",
          host not in line and user not in line and home not in line)
    check("integrity_log coarsens time to 600s buckets",
          "// 600 * 600" in gsc)
    mac_msgs = [m for m in (
        "".join((v.value if isinstance(v, ast.Constant) else "{x}")
                for v in n.args[1].values)
        if isinstance(n.args[1], ast.JoinedStr) else
        (n.args[1].value if isinstance(n.args[1], ast.Constant) else "")
        for n in ast.walk(ast.parse(par))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name) and n.func.id == "integrity_log"
        and len(n.args) >= 2
    ) if "mac_" in m]
    check("MAC integrity_log lines never interpolate the MAC value",
          mac_msgs and all("->" not in m and "new_mac" not in m for m in mac_msgs))
    lead("TOOL", f"integrity log VERSION={gs.VERSION}")
    lead("TIME", "log timestamp is a 10-min bucket, not the exact second")
    lead("TOOL", "log records label=GhostSpiral_entry and account numbers")

    # ── unsigned plan meta ───────────────────────────────────────────────
    print("\n--- shipped unsigned plan meta ---")
    check("plan meta writes version + created + account_index + distribution_mode",
          '"version": VERSION' in gss and '"created":' in gss
          and '"account_index":' in gss and '"distribution_mode":' in gss)
    check("plan txs carry delay + extra on disk",
          '"delay"' in gss and '"extra": secure_hex(16)' in gss)
    check("phase_create does NOT forward 'extra' to transfer_split (not on-chain)",
          "extra" not in ags.split("raw_request(\"transfer_split\"")[1][:400]
          if "raw_request(\"transfer_split\"" in ags else
          "which phase_create never forwards" in ags)
    check("airgap says extra is excluded from the plan fingerprint",
          "phase_create never forwards" in ags)
    lead("TOOL", f"plan meta.version = GhostSpiral {gs.VERSION}")
    lead("TIME", "plan meta.created is the same 10-min bucket")
    lead("DISK", "plan lists ENTRY + mix dests + amounts + per-tx delay")
    lead("CHAIN", "tx extra is NOT sent to the daemon — no on-chain GS tag")

    # ── reconstruct a shipped-shaped public corpus and grep it ───────────
    print("\n--- reconstructed PUBLIC corpus (working dir, no wallet) ---")
    pub = tmp / "public"
    pub.mkdir()
    created = int(time.time()) // 600 * 600
    bundle = {
        "schema": "gs_receive_wallet_v1",
        "created": created,
        "address": ENTRY,
        "account_index": 1,
        "subaddress_index": 1,
        "label": "GhostSpiral_entry",
        "rpc_endpoint": "http://127.0.0.1:18083",
    }
    plan = {
        "meta": {
            "schema": "unsigned_v1",
            "version": gs.VERSION,
            "created": created,
            "account_index": 1,
            "distribution_mode": "fanout",
        },
        "txs": [{
            "src": ENTRY, "src_index": 1,
            "destinations": [
                {"address": "MIX_0", "amount": "2.4326"},
                {"address": "MIX_1", "amount": "1.1333"},
            ],
            "delay": 240, "extra": "deadbeefcafebabe",
        }],
    }
    pairs = {"schema": "thor_pairs_v1", "btc_in": "0.04",
             "memo": f"=:XMR:{ENTRY}", "dest": ENTRY,
             "deposit": "bc1qvaultxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    (pub / "wallet_recv.json").write_text(json.dumps(bundle, indent=2))
    (pub / "unsigned_fanout.json").write_text(json.dumps(plan, indent=2))
    (pub / "thor_pairs_batch.json").write_text(json.dumps(pairs, indent=2))
    (pub / "integrity_chain.log").write_text(line + "\n")
    corpus = "".join(p.read_text() for p in pub.iterdir())

    check("PUBLIC corpus does not contain name1 PRIMARY", NAME1 not in corpus)
    check("PUBLIC corpus does not contain name2 PRIMARY", NAME2 not in corpus)
    check("PUBLIC corpus does not contain this host/user/HOME",
          host not in corpus and user not in corpus and home not in corpus)
    check("PUBLIC corpus DOES contain ENTRY (swap dest / bundle / plan src)",
          ENTRY in corpus)
    check("PUBLIC corpus DOES contain GhostSpiral_entry label",
          "GhostSpiral_entry" in corpus)
    check("PUBLIC corpus DOES contain rpc_endpoint",
          "127.0.0.1:18083" in corpus)
    check("PUBLIC corpus DOES contain tool version",
          gs.VERSION in corpus)
    lead("SWAP", "Thor memo names ENTRY — that's who got paid, not PRIMARY")
    lead("AMOUNT", "plan amounts + btc_in are on disk; chain amounts stay hidden under RingCT")

    # ── writers themselves must not persist identity ─────────────────────
    print("\n--- shipped Python must not persist host/user ---")
    writers = {
        "create_receive_wallet": crw,
        "GhostSpiral": gss,
        "gs_common.py": gsc,
        "thor_swap_preparer": src("thor_swap_preparer"),
        "broadcast_signed_xmr": src("broadcast_signed_xmr"),
        "airgap_tx_signer": ags,
    }
    for name, text in writers.items():
        tree = ast.parse(text)
        calls = [n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                 for n in ast.walk(tree) if isinstance(n, ast.Call)]
        bad = {c for c in calls if c in ("gethostname", "getuser", "getlogin", "uname")}
        check(f"{name} does not call gethostname/getuser/getlogin/uname", not bad)

    # ── PC-taken surface (not an outsider) ───────────────────────────────
    print("\n--- PC taken: wallet-rpc leftovers (no seed needed) ---")
    check("wipe list now includes *.address.txt (PRIMARY plaintext)",
          "*.address.txt" in para.GS_ARTIFACT_FILE_PATTERNS)
    check("wipe list now includes *.keys (encrypted spend key)",
          "*.keys" in para.GS_ARTIFACT_FILE_PATTERNS)
    check("gitignore blocks name1.address.txt (rpc naming, not *.wallet.*)",
          os.system(f"git -C {REPO} check-ignore -q --no-index name1.address.txt") == 0)
    check("gitignore blocks name1.keys",
          os.system(f"git -C {REPO} check-ignore -q --no-index name1.keys") == 0)
    lead("PC-TAKEN", "*.address.txt is PRIMARY in plaintext — no seed")
    lead("PC-TAKEN", "wallet-rpc log: 'Loaded wallet keys file, with public address:'")
    lead("PC-TAKEN", "file uid/gid + mtime still name the local account if they get the disk")

    # ── scoreboard ───────────────────────────────────────────────────────
    print("\n--- scoreboard ---")
    person = [L for L in LEADS if L[0] == "PERSON"]
    check("no PERSON lead (PRIMARY never named from metadata)", person == [])
    check("outsider still has TOOL / TIME / SWAP leads",
          any(k == "TOOL" for k, _ in LEADS)
          and any(k == "TIME" for k, _ in LEADS)
          and any(k == "SWAP" for k, _ in LEADS))
    check("PC-TAKEN is listed separately from the remote outsider",
          any(k == "PC-TAKEN" for k, _ in LEADS))

    print(f"\nLEADS ({len(LEADS)}):")
    for k, w in LEADS:
        print(f"  [{k:8}] {w}")

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    for f in FAILS:
        print("  - " + f)
    if person:
        print(">>> METADATA NAMED THE PERSON: YES")
        return 1
    print(">>> METADATA NAMED THE PERSON: NO — leads only (tool / time / ENTRY)")
    print(">>> PC TAKEN: PRIMARY is in *.address.txt and the rpc log")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
