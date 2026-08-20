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

import os as _os, sys as _sys                              # noqa: E402
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
from monerolab import MoneroLab                              # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name.replace(".py", ""),
                                              os.path.join(REPO, name))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name, ld))
    ld.exec_module(m); return m


ghost = load("GhostSpiral")

BASE = tempfile.mkdtemp(prefix="spendacct_")
lab = MoneroLab(BASE, 30231, 30233)
DR = "http://127.0.0.1:30231"; D = DR + "/json_rpc"; WP = 30233
WR = f"http://127.0.0.1:{WP}/json_rpc"
A = Decimal(10) ** 12


dj = lab.dj

draw = lab.draw

wj = lab.wj

procs = []


def Lp(c, l):
    procs.append(subprocess.Popen(c, stdout=open(l, "w"), stderr=subprocess.STDOUT))


mine = lab.gen

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
    lab.start()
    wj("create_wallet", {"filename": "s", "password": "", "language": "English"})
    primary = wj("get_address", {"account_index": 0})["result"]["address"]
    mine(primary, 90)
    rpc = Rpc()

    # 1. A SEND run is no longer pinned to an account here: create_subs gives
    #    every output its own, so there is nothing correct for the resolver to
    #    invent and it says so.
    ghost.integrity_log = lambda *a, **k: None
    check("SEND: the resolver invents no account for a send run",
          ghost.resolve_mix_account(A_(), rpc, False, 0) is None)

    # 2. The SHIPPED create_subs puts EVERY output in its OWN account.
    subs, addr_index, _decoys = ghost.create_subs(rpc, 4, 2)
    ENTRY = subs[0]
    ACC, E = addr_index[ENTRY]
    check("SEND: ENTRY was created in an account of its own", ACC != 0)
    check("SEND: every output got a DIFFERENT account -- a transaction cannot "
          "spend across accounts, so the mix cannot be merged back together",
          len({addr_index[a][0] for a in subs}) == len(subs))
    check("SEND: no output was placed in account 0 (its subaddr 0 is PRIMARY)",
          all(addr_index[a][0] != 0 for a in subs))
    # The shipped resolver must read ENTRY's account back, not be told it.
    # Plural: --split N mints one entry per chunk, so the live path returns a
    # list of pairs. A send with one ENTRY is a one-element list.
    check("SEND: the shipped resolver agrees on ENTRY's (account, index)",
          ghost.resolve_entry_accounts(rpc, addr_index, [ENTRY], None) == [(ACC, E)])

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
    check("ON-CHAIN: every fan-out destination landed in its OWN account",
          all(scan(addr_index[d][0]).get(addr_index[d][1], 0) > 0 for d in dests))
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
    distributed = sum(scan(addr_index[d][0]).get(addr_index[d][1], 0)
                      for d in dests)
    accounted = distributed + change_in_mix + fee_paid
    entry_held = int(10 * A)
    print(f"  accounting: distributed {distributed/1e12} + change "
          f"{change_in_mix/1e12} + fee {fee_paid/1e12} = {accounted/1e12} "
          f"(ENTRY held {entry_held/1e12})")
    check("ON-CHAIN: every piconero ENTRY held is accounted for in the run's "
          "own accounts, so nothing from this run reached the wallet PRIMARY",
          accounted == entry_held)

    # THE EXIT. What the operator is left holding must not be spendable by one
    # transaction: a transaction's input count is public, and spending N of
    # these together proves all N share an owner -- which is exactly what the
    # distribution spent its effort separating. Verified by asking the wallet,
    # not by reasoning: each destination account holds well under the total, so
    # any single-transaction exit is impossible.
    _held = [scan(addr_index[d][0]).get(addr_index[d][1], 0) for d in dests]
    _biggest = max(_held)
    _total = sum(_held)
    print(f"  exit: {len(dests)} outputs, biggest single account holds "
          f"{_biggest/1e12} XMR of {_total/1e12} XMR total")
    check("EXIT: no single account holds the whole distribution, so no single "
          "transaction can spend it", _biggest < _total)
    _r = wj("transfer_split", {
        "destinations": [{"amount": _total, "address": primary}],
        "account_index": addr_index[dests[0]][0], "priority": 1,
        "do_not_relay": True})
    check("EXIT: asking one output's account for the whole amount is refused "
          "by the wallet, not merely discouraged",
          "not enough money" in str((_r.get("error") or {}).get("message", "")))

    result = "SUCCESS" if FAIL == 0 else "FAILED"
finally:
    lab.stop()
    shutil.rmtree(BASE, ignore_errors=True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
for f in FAILS:
    print("  - " + f)
print(f">>> SEND SPENDS FROM THE ROTATED ACCOUNT: {result}")
sys.exit(1 if FAIL or result != "SUCCESS" else 0)
