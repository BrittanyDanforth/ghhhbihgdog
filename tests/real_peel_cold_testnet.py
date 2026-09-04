#!/usr/bin/env python3
"""Prove COLD-SIGNED peeling actually works for peels 2..N — the real risk.

real_peel_testnet proved the peel MECHANISM but used a HOT full wallet for
every transaction. The pipeline ships the COLD-SIGNING model: an online
VIEW-ONLY wallet builds each unsigned tx, an offline full wallet signs it. The
open question that model raises, and that nothing tested: after peel 0 spends
ENTRY, can the VIEW-ONLY wallet build and cold-sign peel 1 that spends the
CHANGE output on subaddress 0 — an output whose key image the view-only wallet
does not itself hold?

This runs a real cold-signed peeling chain end to end on an isolated testnet:
each peel is view-only transfer_split(do_not_relay) -> monero-wallet-cli
sign_transfer -> submit_transfer, exactly as the pipeline does, and asserts
every peel — including the ones spending the change — confirms on-chain with
its own amount. If cold peeling were broken, peel 1 would fail here.

SKIPs (exit 0) if the monero binaries aren't installed.
"""
import subprocess, time, os, shutil, tempfile, sys, hashlib
import importlib.machinery, importlib.util
from decimal import Decimal
import random
import requests

for b in ("monerod", "monero-wallet-rpc", "monero-wallet-cli"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

import os as _os, sys as _sys                              # noqa: E402
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
from monerolab import MoneroLab                              # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""), os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


ghost = load("GhostSpiral")
airgap = load("airgap_tx_signer")   # the SHIPPED create+sign phases

BASE = tempfile.mkdtemp(prefix="peelcold_")
lab = MoneroLab(BASE, 30151, 30153)
DR = "http://127.0.0.1:30151"; D = DR + "/json_rpc"; WR = "http://127.0.0.1:30153/json_rpc"


dj = lab.dj

draw = lab.draw

wj = lab.wj

procs = []


def Lp(cmd, log):
    procs.append(subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT))


mine = lab.mine

def subbal(idx, acct=0):
    wj("refresh")
    r = wj("get_balance", {"account_index": acct, "address_indices": [idx]})["result"]
    e = [x for x in r.get("per_subaddress", []) if x.get("address_index") == idx]
    return (e[0].get("balance", 0), e[0].get("unlocked_balance", 0)) if e else (0, 0)


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


ATOMIC = Decimal(10) ** 12
result = "INCOMPLETE"
try:
    lab.start()
    # 1. FULL wallet funds ENTRY (a non-zero subaddress: the receive-mode case).
    wj("create_wallet", {"filename": "full", "password": "", "language": "English"})
    primary = wj("get_address", {"account_index": 0})["result"]["address"]
    mine(primary, 90); wj("refresh")
    entry = wj("create_address", {"account_index": 0})["result"]
    E = entry["address_index"]
    wj("transfer_split", {"destinations": [{"amount": int(6 * ATOMIC), "address": entry["address"]}],
                          "account_index": 0, "subaddr_indices": [0], "priority": 1})
    h = dj("get_info")["result"]["height"]; mine(primary, h + 12); wj("refresh")
    vk = wj("query_key", {"key_type": "view_key"})["result"]["key"]
    print(f"ENTRY subaddr {E} funded {subbal(E)[0] / 1e12} XMR")

    # SHIPPED plan: unequal amounts + peel sources.
    N = 3
    mix = [wj("create_address", {"account_index": 0})["result"] for _ in range(N)]
    midx = [m["address_index"] for m in mix]
    amounts = ghost.compute_fanout_amounts(Decimal("4"), N, Decimal("0.01"), False, random.Random(7))
    # ROTATING CARRIERS, through the COLD path: each peel spends a fresh
    # carrier the previous peel paid, so subaddress 0 is never spent. This
    # test's value is proving the rotation survives the air-gapped round trip
    # -- the offline signer must sign a spend of a carrier output it only
    # learns about via the outputs export.
    planned = [int((a * ATOMIC).to_integral_value()) for a in amounts]
    print("peel amounts:", [str(a) for a in amounts])

    # 2. Go VIEW-ONLY (this is what the pipeline's online machine runs).
    kimages = wj("export_key_images", {"all": True}).get("result", {}).get("signed_key_images")
    wj("close_wallet")
    wj("generate_from_keys", {"restore_height": 0, "filename": "view", "address": primary,
                              "viewkey": vk, "password": ""})
    wj("refresh")
    if kimages:
        wj("import_key_images", {"signed_key_images": kimages})

    # ONE ACCOUNT PER HOP, created HERE -- on the VIEW-ONLY wallet, after the
    # switch, because that is the only wallet the pipeline has online and it is
    # where the shipped planner calls create_account. The offline spend wallet
    # is a different file that never sees those calls, so it has to recognise
    # an output in an account it did not create. It manages that through
    # phase_create's export_outputs -> phase_sign's import_outputs; without the
    # import it falls back to wallet2's subaddress lookahead (50 accounts), so
    # a run whose accounts have climbed past that would sign its early peels
    # and fail its later ones. Creating these on the FULL wallet first, as this
    # suite used to, hides the whole question.
    #
    # Monero returns change to the SPENDING account's subaddress 0, so hops
    # sharing an account pile their change onto one subaddress and the sweep
    # that collects it is a single N-input transaction -- public proof that all
    # N peels are one owner.
    hop_accounts = [wj("create_account", {"label": ""})["result"]["account_index"]
                    for _ in range(N - 1)]
    carriers = [wj("create_address", {"account_index": a})["result"]
                for a in hop_accounts]
    carrier_pairs = [(c["address"], c["address_index"]) for c in carriers]
    peel_accounts = [0] + hop_accounts
    check("cold: every hop was given its own account",
          len(set(peel_accounts)) == N)
    check("cold: the hop accounts exist only on the view-only wallet",
          all(a > 0 for a in hop_accounts))
    _hop = (Decimal("0.05") * ghost.PEEL_CARRIER_RESERVE_MULT
            / Decimal("1.5") * ghost.FEE_SAFETY_MARGIN)
    remainders = [sum(amounts[i + 1:]) + _hop * (N - i - 1) for i in range(N - 1)]
    plan = ghost.build_peel_plan(E, [m["address"] for m in mix], amounts,
                                 carriers=carrier_pairs, remainders=remainders)
    check("cold: no peel spends subaddr 0 (MAIN)",
          all(p["src_index"] != 0 for p in plan))
    check("cold: every peel spends a distinct address",
          len({(peel_accounts[i], p["src_index"])
               for i, p in enumerate(plan)}) == len(plan))

    # An EMPTY account, created on the view-only wallet AFTER the hop accounts
    # so its index cannot collide with one of them. Every plan entry names its
    # own account, so meta's value must never be used; pointing meta at an
    # account with no funds turns "the signer ignored the per-TX account" from
    # a silent pass into a hard failure. Verified by mutation: making the
    # signer use meta fails the first peel with "not enough money".
    DECOY_ACCT = wj("create_account", {"label": ""})["result"]["account_index"]
    check("cold: the decoy meta account is not one of the hop accounts",
          DECOY_ACCT not in peel_accounts)

    # A shim so the SHIPPED phase_sign's wallet-cli calls hit the testnet.
    shim = os.path.join(BASE, "wcli-testnet")
    open(shim, "w").write('#!/bin/sh\nexec monero-wallet-cli --offline "$@"\n')
    os.chmod(shim, 0o755)

    class RpcShim:
        """Minimal connect_rpc stand-in: real HTTP to the testnet wallet-rpc, so
        the SHIPPED phase_create (including its export_outputs) really runs."""
        def raw_request(self, method, params):
            r = wj(method, params)
            if "error" in r:
                raise RuntimeError(str(r["error"])[:160])
            return r.get("result", {})

    airgap.verify_tor = lambda *a, **k: None          # no Tor on an isolated testnet
    airgap.connect_rpc = lambda *a, **k: RpcShim()
    os.chdir(BASE)                                    # integrity log into scratch

    class A:
        def __init__(self, **kw): self.__dict__.update(kw)

    txids = []
    for i, p in enumerate(plan):
        if i > 0:
            # Wait on the ROTATING carrier this peel spends, not subaddr 0 --
            # and for the FULL outgoing amount (destination + the forward to
            # the next carrier), not just the destination.
            src = p["src_index"]
            if p.get("destinations"):
                need = sum(int((Decimal(d["amount"]) * ATOMIC).to_integral_value())
                           for d in p["destinations"]) + int(ATOMIC // 20)
            else:
                need = planned[i] + int(ATOMIC // 20)
            _sa = peel_accounts[i]
            for _ in range(80):
                if subbal(src, _sa)[1] >= need:
                    break
                h = dj("get_info")["result"]["height"]; mine(primary, h + 2)
            check(f"peel {i}: view-only sees rotating carrier {_sa}/{src} unlocked",
                  subbal(src, _sa)[1] >= need)

        # Carry the carrier output through to the signer. Without it the cold
        # path would forward nothing and the next peel would have no carrier
        # to spend -- the rotation would silently degrade back to the hub.
        one = [{"src": "ENTRY" if i == 0 else "CARRIER", "src_index": p["src_index"],
                "account_index": peel_accounts[i],
                "dst": p["dst"], "amt": p["amt"], "delay": 0}]
        if p.get("destinations"):
            one[0]["destinations"] = p["destinations"]
        stage = os.path.join(BASE, f"stage{i}")

        # SHIPPED phase_create (online, view-only) -> unsigned + outputs_export
        airgap.phase_create(
            A(tor_proxy="socks5h://127.0.0.1:9050", rpc=WR.replace("/json_rpc", ""),
              outdir=stage, fee_priority=1), one, {"account_index": DECOY_ACCT})
        check(f"peel {i + 1}/{N}: SHIPPED phase_create built the unsigned tx",
              os.path.exists(os.path.join(stage, "tx_0.unsigned")))
        if i == 0:
            check("phase_create exported the wallet outputs (the multi-round fix)",
                  os.path.exists(os.path.join(stage, airgap.OUTPUTS_EXPORT_NAME)))

        # SHIPPED phase_sign (offline) -> imports outputs, then signs
        airgap.phase_sign(
            A(outdir=stage, wallet_file=os.path.join(BASE, "w", "full"),
              wallet_password="", wallet_cli=shim), one)
        sb = os.path.join(stage, "signed", "tx_0.signed")
        check(f"peel {i + 1}/{N}: SHIPPED phase_sign COLD-SIGNED it"
              + (" (spends the CHANGE - the case that used to fail)" if i else ""),
              os.path.exists(sb))
        assert os.path.exists(sb), f"cold peeling still broken at peel {i}"

        sr = wj("submit_transfer", {"tx_data_hex": open(sb, "rb").read().hex()})
        ths = sr.get("result", {}).get("tx_hash_list", [])
        if not ths:
            print(f"  peel {i} submit:", str(sr.get("result") or sr.get("error") or sr)[:200])
        check(f"peel {i + 1}/{N}: relayed to the daemon", bool(ths))
        assert ths
        txids.append(ths[0])
        h = dj("get_info")["result"]["height"]; mine(primary, h + 12); wj("refresh")

    # 3. Payoff: every cold-signed peel — including the change-spending ones —
    #    landed, each a distinct tx, each mix subaddress with its own amount.
    check("all peels are DISTINCT transactions", len(set(txids)) == N)
    got = {i: subbal(i)[0] for i in midx}
    for k in range(N):
        print(f"    mix {midx[k]}: planned {planned[k] / 1e12:.4f}  got {got[midx[k]] / 1e12:.4f}  "
              f"{'OK' if got[midx[k]] == planned[k] else 'MISMATCH'}")
    check("every mix subaddress received its cold-signed peel amount on-chain",
          all(got[midx[k]] == planned[k] for k in range(N)))
    check("COLD peeling works for peels that spend the change (peels 2..N)",
          all(got[midx[k]] > 0 for k in range(1, N)))
    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    lab.stop()
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    for f in FAILS: print("  -", f)
print(f">>> COLD-SIGNED PEELING AGAINST REAL BINARIES: {result}")
sys.exit(0 if FAIL == 0 and result == "SUCCESS" else 1)
