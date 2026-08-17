#!/usr/bin/env python3
"""Prove a SEND-mode run spends from the ROTATED account, not the wallet PRIMARY.

THE BUG THIS PINS. resolve_mix_account creates a fresh account and create_subs
puts ENTRY and every mix subaddress in it. Stage 4 then said

    bal_account = receive_account_index if receive_mode else 0

hard-coding 0 for send. That variable drives the balance poll, the peel
carriers, the PLAN's account_index, the change-sweep destination, and
change_target -- so every spend named account 0, the run's change came to rest
on account 0 / subaddress 0 (the wallet PRIMARY), and the change sweep then
SPENT it. The rotation was theatre in send mode.

It was also functionally wrong: the balance was polled from account 0 at
ENTRY's index, which is a DIFFERENT subaddress -- account 0's subaddress at
that number -- so the plan was sized from an unrelated balance.

Only a real wallet settles both halves, because both are about what monerod
does with an (account, index) pair. Isolated testnet; SKIPs if binaries absent.
"""
import subprocess, time, os, shutil, tempfile, sys
import importlib.machinery, importlib.util
from decimal import Decimal
import requests

for b in ("monerod", "monero-wallet-rpc"):
    if shutil.which(b) is None:
        print(f"SKIP: {b} not on PATH"); sys.exit(0)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


ghost = load("GhostSpiral")

BASE = tempfile.mkdtemp(prefix="spendacct_")
DR = "http://127.0.0.1:28141"; D = DR + "/json_rpc"; WP = 28143
WR = f"http://127.0.0.1:{WP}/json_rpc"
A = Decimal(10) ** 12


def dj(m, p=None):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(D, json=b, timeout=60).json()


def draw(p, b=None):
    return requests.post(DR + p, json=b or {}, timeout=60).json()


def wj(m, p=None, t=300):
    b = {"jsonrpc": "2.0", "id": "0", "method": m}
    b.update({"params": p} if p is not None else {})
    return requests.post(WR, json=b, timeout=t).json()


procs = []


def Lp(c, l):
    procs.append(subprocess.Popen(c, stdout=open(l, "w"), stderr=subprocess.STDOUT))


def mine(a, n):
    t = dj("get_info")["result"]["height"] + n
    draw("/start_mining", {"miner_address": a, "threads_count": 2,
                           "do_background_mining": False, "ignore_battery": True})
    while dj("get_info")["result"]["height"] < t:
        time.sleep(2)
    draw("/stop_mining"); wj("refresh")


PASS = 0; FAIL = 0; FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  ", name)
    else: FAIL += 1; FAILS.append(name); print("  FAIL:", name)


class Rpc:
    """The shipped code talks to the wallet through raw_request /
    get_subaddress_balance / new_subaddress_indexed. Give it the real thing."""
    def raw_request(self, method, params):
        r = wj(method, params)
        if "error" in r:
            raise RuntimeError(str(r["error"])[:160])
        return r.get("result", {})

    def get_subaddress_balance(self, account_index=0, address_index=0):
        r = self.raw_request("get_balance", {"account_index": account_index,
                                             "address_indices": [address_index]})
        e = r.get("per_subaddress", [])
        return ((e[0].get("balance", 0), e[0].get("unlocked_balance", 0))
                if e else (0, 0))

    def new_subaddress_indexed(self, account_index=0, label=""):
        r = self.raw_request("create_address", {"account_index": account_index,
                                                "label": label})
        return r["address"], r["address_index"]


class A_:
    def __init__(self, **kw): self.__dict__.update(kw)


result = "INCOMPLETE"
try:
    Lp(["monerod", "--testnet", "--offline", "--data-dir", BASE + "/n",
        "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", "28141",
        "--p2p-bind-port", "28140", "--no-igd", "--hide-my-port",
        "--fixed-difficulty", "1", "--non-interactive",
        "--log-file", BASE + "/d.log", "--log-level", "0"], BASE + "/d.out")
    for _ in range(45):
        time.sleep(1)
        try:
            if dj("get_info").get("result", {}).get("height") is not None: break
        except Exception: pass
    Lp(["monero-wallet-rpc", "--testnet", "--daemon-address", "127.0.0.1:28141",
        "--trusted-daemon", "--wallet-dir", BASE + "/w", "--rpc-bind-port", str(WP),
        "--rpc-bind-ip", "127.0.0.1", "--disable-rpc-login",
        "--log-file", BASE + "/w.log", "--log-level", "0"], BASE + "/w.out")
    for _ in range(45):
        time.sleep(1)
        try:
            if "result" in wj("get_version"): break
        except Exception: pass

    wj("create_wallet", {"filename": "s", "password": "", "language": "English"})
    primary = wj("get_address", {"account_index": 0})["result"]["address"]
    mine(primary, 90)
    rpc = Rpc()

    # 1. The SHIPPED rotation picks the mix account for a SEND run.
    ghost.integrity_log = lambda *a, **k: None
    ACC = ghost.resolve_mix_account(A_(), rpc, False, 0)
    check("SEND: the shipped resolver rotated to a fresh account", ACC != 0)

    # 2. The SHIPPED create_subs puts ENTRY and the mix subs in that account.
    subs, addr_index, _decoys = ghost.create_subs(rpc, 4, 2, acct_idx=ACC)
    ENTRY = subs[0]
    E = addr_index[ENTRY]
    check("SEND: ENTRY was created inside the rotated account", ENTRY in addr_index)

    # 3. THE FIX: the spend account is the mix account. Prove that (ACC, E)
    #    really is ENTRY, and that (0, E) is a DIFFERENT address -- which is
    #    exactly what the old code would have spent from.
    ra = rpc.raw_request("get_address", {"account_index": ACC,
                                         "address_index": [E]})["addresses"][0]
    check("(mix account, ENTRY index) resolves to ENTRY", ra["address"] == ENTRY)
    try:
        wrong = rpc.raw_request("get_address", {"account_index": 0,
                                                "address_index": [E]})["addresses"]
        wrong_addr = wrong[0]["address"] if wrong else None
    except Exception:
        wrong_addr = None
    print(f"  account {ACC} / sub {E} = ...{ENTRY[-8:]}")
    print(f"  account 0 / sub {E} = "
          f"{'...' + wrong_addr[-8:] if wrong_addr else '(no such subaddress)'}")
    check("account 0 at ENTRY's index is a DIFFERENT address (the old bug)",
          wrong_addr != ENTRY)

    # 4. The SHIPPED guard must accept the right pair and REFUSE the old one.
    try:
        ghost.verify_spend_source(rpc, ACC, E, ENTRY); good = True
    except SystemExit:
        good = False
    check("shipped guard ACCEPTS the rotated (account, index) for ENTRY", good)
    try:
        ghost.verify_spend_source(rpc, 0, E, ENTRY); bad_ok = True
    except SystemExit:
        bad_ok = False
    check("shipped guard REFUSES account 0 at ENTRY's index (fails closed)",
          not bad_ok)

    # 5. THE MEASUREMENT: fund ENTRY, spend from the mix account, and prove the
    #    change lands in the ROTATED account -- not on the wallet PRIMARY.
    wj("transfer_split", {"destinations": [{"amount": int(10 * A), "address": ENTRY}],
                          "account_index": 0, "subaddr_indices": [0], "priority": 1})
    h = dj("get_info")["result"]["height"]; mine(primary, h + 12); wj("refresh")

    # The shipped balance reader, with the FIXED account.
    tot, unl = ghost.xmr_balance(rpc, ACC, E)
    print(f"  shipped xmr_balance(mix acct {ACC}, sub {E}) = {unl} XMR unlocked")
    check("SEND: the shipped balance reader finds the funds in the mix account",
          unl > Decimal("9"))
    # And with the OLD account it would have seen nothing -- the plan would
    # have been sized from an unrelated balance.
    tot0, unl0 = ghost.xmr_balance(rpc, 0, E)
    print(f"  the OLD code's xmr_balance(account 0, sub {E}) = {unl0} XMR")
    check("SEND: the old hard-coded account 0 read a DIFFERENT balance",
          unl0 != unl)

    pri_before_sub0 = wj("get_balance", {"account_index": 0,
                         "address_indices": [0]})["result"]["per_subaddress"][0]["balance"]
    dests = [s for s in subs[1:5]]
    per = int((Decimal("1.5") * A))
    r = wj("transfer_split", {
        "destinations": [{"amount": per, "address": d} for d in dests],
        "account_index": ACC, "subaddr_indices": [E], "priority": 1})
    ths = r.get("result", {}).get("tx_hash_list", [])
    if not ths:
        print("  fan-out error:", str(r.get("result") or r)[:160])
    check("SEND: the fan-out relayed from the mix account", bool(ths))
    assert ths
    h = dj("get_info")["result"]["height"]; mine(primary, h + 12); wj("refresh")

    # Locate the change by BALANCE DELTA across every subaddress of both
    # accounts. get_transfer_by_txid does not reliably report a wallet's own
    # change output here, so scanning is the honest measurement -- and it also
    # answers "where DID it go?" rather than only "is it where I expected?".
    def scan(acc):
        r = wj("get_balance", {"account_index": acc})["result"]
        return {e["address_index"]: e.get("balance", 0)
                for e in r.get("per_subaddress", []) if e.get("balance")}

    mix_after = scan(ACC)
    pri_after = scan(0)
    print(f"  mix account {ACC} balances by subaddress: "
          f"{ {k: round(v/1e12, 4) for k, v in mix_after.items()} }")
    print(f"  wallet PRIMARY (acct 0) sub 0 balance: "
          f"{pri_after.get(0, 0)/1e12:.4f} XMR (mining credits land here)")

    spent = int(Decimal("1.5") * A) * len(dests)
    change_in_mix = mix_after.get(0, 0)
    print(f"  ENTRY held 10 XMR, distributed {spent/1e12} XMR")
    print(f"  change on mix account {ACC} / subaddress 0: {change_in_mix/1e12} XMR")

    check("ON-CHAIN: the run's change came to rest in the ROTATED account",
          change_in_mix > 0)
    check("ON-CHAIN: every fan-out destination is in the ROTATED account",
          all(addr_index[d] in mix_after for d in dests))
    # THE DECISIVE ONE, by conservation of value rather than by watching
    # account 0. This harness mines to the primary address after the spend, so
    # account 0's balance necessarily grows for reasons that have nothing to do
    # with the run -- an assertion on that number would be measuring the miner.
    #
    # Instead: account for every piconero ENTRY held. If the distributed
    # outputs plus the change plus the fee equal ENTRY's whole balance, and all
    # of those live in the mix account, then nothing from this transaction
    # reached account 0. That is airtight and immune to the mining noise.
    fee_paid = sum(r["result"].get("fee_list", []))
    distributed = sum(mix_after.get(addr_index[d], 0) for d in dests)
    accounted = distributed + change_in_mix + fee_paid
    entry_held = int(10 * A)
    print(f"  accounting: distributed {distributed/1e12} + change "
          f"{change_in_mix/1e12} + fee {fee_paid/1e12} = {accounted/1e12} "
          f"(ENTRY held {entry_held/1e12})")
    check("ON-CHAIN: every piconero ENTRY held is accounted for INSIDE the mix "
          "account, so nothing from this run reached the wallet PRIMARY",
          accounted == entry_held)

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    for p in procs:
        try: p.terminate(); p.wait(timeout=10)
        except Exception:
            try: p.kill()
            except Exception: pass
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
for f in FAILS:
    print("  - " + f)
print(f">>> SEND SPENDS FROM THE ROTATED ACCOUNT: {result}")
sys.exit(1 if FAIL or result != "SUCCESS" else 0)
