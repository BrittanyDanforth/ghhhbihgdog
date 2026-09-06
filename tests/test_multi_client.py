#!/usr/bin/env python3
"""SEVERAL PEOPLE ON ONE VAULT, AND WHAT KEEPS THEIR MONEY APART.

The pager used to refuse a second allowlisted person because a withdrawal took
the largest unlocked output on the whole wallet, whoever put it there. What
replaced that is an OWNER TOKEN on every job (the pager derives it from the
asking chat, one-way, keyed by the pairing secret), a ledger on the vault of
which wallet ACCOUNTS each owner's deposits and mixes created, and a spend
selection that never leaves that set. Around it: a capacity the vault derives
from its account ceiling, a Pi-side soft cap that answers "full" without a
wake, a busy answer that names nobody, and a chain that yields its turn.

Everything here is DRIVEN: the ledger through the real loaders, the spend
selection through a fake wallet-rpc, the dispatch through the real _dispatch,
the pager through a Pager built the way the other suites build one.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import types
from decimal import Decimal
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0
FAILS = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  ", name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL:", name)


import gs_wake_proto as P                                    # noqa: E402
import gs_common as GC                                       # noqa: E402
from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_multi_client.py")


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    sp = importlib.util.spec_from_loader(ld.name, ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    return m


os.environ.setdefault("GS_WALLET_PASSWORD", "hunter2")
A = load("gs_wake_agent")
DB = load("gs_doorbell")
pg = load("gs_telegram_pager")
import nacl.public as NP                                     # noqa: E402

XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaB"
       "YBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
OX, OY = "a" * 16, "b" * 16
_K = {"tor_proxy": "socks5h://127.0.0.1:9050",
      "rpc_primary": "http://127.0.0.1:18083",
      "wallet_file": "/var/lib/gs/spend.wallet"}
_saved_il = A.integrity_log
A.integrity_log = lambda *a, **k: None


def _bundle(d, name, acct, sub):
    p = d / name
    p.write_text(json.dumps({"schema": "gs_receive_wallet_v1", "address": XMR,
                             "account_index": acct, "subaddress_index": sub,
                             "rpc_endpoint": "http://127.0.0.1:18083"}))
    return p


# ===========================================================================
print("== the ledger: handles and owners in one file ==")
_ld = Path(tempfile.mkdtemp(prefix="mcledger_"))
(_ld / A.HANDLES_FILE).write_text(json.dumps(
    {"A3F1": {"bundle": "/x/wallet_1.json", "slip": None, "minted": 1}}))
_old = A._load_ledger(_ld)
check("a ledger written before owners existed loads as handles with no owners",
      _old["handles"]["A3F1"]["bundle"] == "/x/wallet_1.json"
      and _old["owners"] == {}
      and A._load_handles(_ld) == _old["handles"])
A._add_owner_accounts(_old, OX, {3, 0, True, 5, 5, "7"})
check("owners: account 0, bools, strings and duplicates never make it in",
      _old["owners"][OX]["accounts"] == [3, 5]
      and A._owner_accounts(_old, OX) == {3, 5}
      and A._owner_accounts(_old, OY) == set()
      and A._owner_accounts(_old, None) == set())
A._save_handles(_ld, _old["handles"], _old["owners"])
_rt = A._load_ledger(_ld)
check("the envelope round-trips, 0600",
      _rt["owners"] == {OX: {"accounts": [3, 5]}}
      and "A3F1" in _rt["handles"]
      and oct(os.stat(_ld / A.HANDLES_FILE).st_mode & 0o777) == "0o600")
A._save_handles(_ld, {"B7C2": {"bundle": "/x/wallet_2.json"}})
check("saving handles alone keeps the owners half the file already held",
      A._load_ledger(_ld)["owners"] == {OX: {"accounts": [3, 5]}}
      and list(A._load_ledger(_ld)["handles"]) == ["B7C2"])
(_ld / A.HANDLES_FILE).write_text(json.dumps(
    {"handles": {"A3F1": {"bundle": "b"}, 7: {"bundle": "c"}, "Z": "no"},
     "owners": {OX: {"accounts": [1, "x", 2.5, 0]}, "bad": 3}}))
_dirty = A._load_ledger(_ld)
check("a damaged envelope loses only its damaged entries",
      list(_dirty["handles"]) == ["A3F1"]
      and _dirty["owners"] == {OX: {"accounts": [1]}})

# ===========================================================================
print("\n== spend selection never leaves the owner's accounts ==")


class _Wallet:
    """A wallet-rpc: account 1 is X's (1000 XMR), 2 is Y's (300), 3 nobody's."""
    per = {1: 1000, 2: 300, 3: 50}

    def raw_request(self, m, p=None):
        p = p or {}
        if m == "get_accounts":
            return {"subaddress_accounts": [{"account_index": i}
                                            for i in (0, 1, 2, 3)]}
        if m == "get_balance":
            if p.get("all_accounts"):
                return {"balance": 1400 * 10 ** 12, "unlocked_balance": 1350 * 10 ** 12}
            i = p.get("account_index")
            amt = self.per.get(i, 0) * 10 ** 12
            return {"balance": amt + (5 * 10 ** 12 if i == 2 else 0),
                    "unlocked_balance": amt,
                    "per_subaddress": [{"account_index": i, "address_index": 1,
                                        "address": XMR, "unlocked_balance": amt}]
                    if amt else []}
        return {}


_saved_connect = GC.connect_rpc
GC.connect_rpc = lambda *a, **k: _Wallet()
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _all = A._funded_entry(_K)
        _x = A._funded_entry(_K, owned_accounts={1})
        _y = A._funded_entry(_K, owned_accounts={2})
        _none = A._funded_entry(_K, owned_accounts=set())
        _both = A._funded_entry(_K, owned_accounts={2, 3})
        _lock_y = A._locked_value(_K, owned_accounts={2})
        _lock_x = A._locked_value(_K, owned_accounts={1})
        _lock_all = A._locked_value(_K)
        _lock_none = A._locked_value(_K, owned_accounts=set())
finally:
    GC.connect_rpc = _saved_connect
check("no owner: the largest unlocked output on the whole wallet, as before",
      _all and _all[0] == 1 and _all[3] == 1000 * 10 ** 12)
check("Y's withdrawal sees Y's 300, never X's 1000 beside it",
      _y and _y[0] == 2 and _y[3] == 300 * 10 ** 12)
check("...X's sees X's", _x and _x[0] == 1)
check("...an owner with no accounts is answered None, never widened to the "
      "wallet", _none is None)
check("...and within an owner's set it is still the largest single output",
      _both and _both[0] == 2)
check("injected entries are filtered the same way, so a harness cannot hand a "
      "withdrawal an account outside the owner's set",
      A._funded_entry(_K, injected=lambda: (1, 1, XMR, 5), owned_accounts={2})
      is None
      and A._funded_entry(_K, injected=lambda: (2, 1, XMR, 5),
                          owned_accounts={2}) == (2, 1, XMR, 5))
check("locked value is summed over the owner's accounts alone",
      _lock_y == Decimal(5) and _lock_x == Decimal(0)
      and _lock_all == Decimal(50) and _lock_none == Decimal(0))

# ===========================================================================
print("\n== dispatch: a withdrawal spends the asker's own, marks it, shreds it ==")
_seen = []


def _runner(argv, env_extra, budget_s):
    _seen.append(list(argv))
    return 0, False


_dd = Path(tempfile.mkdtemp(prefix="mcdisp_"))
_bx = _bundle(_dd, "wallet_x.json", 1, 1)
_by = _bundle(_dd, "wallet_y.json", 2, 1)
_sx = _dd / "thor_pairs_A3F1.json"
_sx.write_text("{}")
_sy = _dd / "thor_pairs_B7C2.json"
_sy.write_text("{}")
A._save_handles(_dd, {"A3F1": {"bundle": str(_bx), "slip": str(_sx),
                               "minted": 1, "owner": OX},
                      "B7C2": {"bundle": str(_by), "slip": str(_sy),
                               "minted": 1, "owner": OY}},
                {OX: {"accounts": [1]}, OY: {"accounts": [2]}})
_accts = [{0, 1, 2}]


def _acct_indices():
    return set(_accts[0])


with contextlib.redirect_stdout(io.StringIO()):
    try:
        A._dispatch("withdraw", {"exit_to": XMR, "depth": 1, "owner": OY},
                    _K, _dd, "C4D5", _runner, "job-1",
                    funded=lambda: (1, 1, XMR, 1000 * 10 ** 12),
                    accounts=_acct_indices)
        _r1 = "ran"
    except A.Refused as e:
        _r1 = e.code
check("Y asking with only X's output unlocked is refused -- nothing of Y's",
      _r1 == "nothing_to_withdraw" and _seen == [])
with contextlib.redirect_stdout(io.StringIO()):
    try:
        A._dispatch("withdraw", {"exit_to": XMR, "depth": 1, "owner": "c" * 16},
                    _K, _dd, "C4D5", _runner, "job-2",
                    funded=lambda: (2, 1, XMR, 300 * 10 ** 12),
                    accounts=_acct_indices)
        _r2 = "ran"
    except A.Refused as e:
        _r2 = e.code
check("an owner the ledger has never seen is refused, never handed the wallet",
      _r2 == "nothing_to_withdraw" and _seen == [])


def _acct_after():
    return {0, 1, 2, 7, 8, 9}


_accts_calls = []


def _acct_seq():
    _accts_calls.append(1)
    return {0, 1, 2} if len(_accts_calls) == 1 else {0, 1, 2, 7, 8, 9}


with contextlib.redirect_stdout(io.StringIO()):
    _r3 = A._dispatch("withdraw", {"exit_to": XMR, "depth": 1, "owner": OY},
                      _K, _dd, "C4D5", _runner, "job-3",
                      funded=lambda: (2, 1, XMR, 300 * 10 ** 12),
                      accounts=_acct_seq)
_led3 = A._load_ledger(_dd)
check("Y asking with Y's output unlocked runs one mix", _r3[:2] == ("done", "done")
      and len(_seen) == 1)
check("...the accounts the mix minted are recorded as Y's, and X's set is "
      "untouched",
      _led3["owners"][OY]["accounts"] == [2, 7, 8, 9]
      and _led3["owners"][OX]["accounts"] == [1])
check("...Y's deposit is marked spent with its pair kept, X's is not",
      _led3["handles"]["B7C2"].get("spent") is True
      and _led3["handles"]["B7C2"].get("pair") == [2, 1]
      and "spent" not in _led3["handles"]["A3F1"])
check("...Y's slip and bundle are shredded, X's stay, and the withdrawal's own "
      "entry bundle is gone",
      not _sy.exists() and not _by.exists()
      and _sx.exists() and _bx.exists()
      and not (_dd / "wallet_withdraw_C4D5.json").exists())
check("...and the retired record still answers for its pair without the file",
      A._bundle_pair(_led3["handles"]["B7C2"]) == (2, 1))
_seen.clear()
with contextlib.redirect_stdout(io.StringIO()):
    try:
        A._dispatch("swap_status", {"handle": "A3F1", "owner": OY}, _K, _dd,
                    "D5E6", _runner, "job-4")
        _r4 = "ran"
    except A.Refused as e:
        _r4 = e.code
check("a /check on another owner's label is refused at the vault, no child run",
      _r4 == "handle_not_yours" and _seen == [])
with contextlib.redirect_stdout(io.StringIO()):
    _r5 = A._dispatch("swap_status", {"handle": "B7C2", "owner": OY}, _K, _dd,
                      "D5E6", _runner, "job-5")
check("...one's own label (paid out) is answered 'moved' from the ledger",
      _r5[:2] == ("done", "done") and A._phase_of("swap_status", _dd) == "moved")
(_dd / A.STATUS_FILE).unlink()
with contextlib.redirect_stdout(io.StringIO()):
    _r6 = A._dispatch("swap_status", {"handle": "A3F1", "owner": OX}, _K, _dd,
                      "E6F7", _runner, "job-6")
check("...and one's own live label runs its probe",
      _r6[:2] == ("done", "done") and len(_seen) == 1)
# A DEPOSIT IS RECORDED AS ITS OWNER'S, ACCOUNT AND ALL.
_seen.clear()


def _mint_runner(argv, env_extra, budget_s):
    _seen.append(list(argv))
    if "create_receive_wallet" in " ".join(argv):
        _bundle(_dd, "wallet_new.json", 11, 1)
    return 0, False


with contextlib.redirect_stdout(io.StringIO()):
    _r7 = A._dispatch("receive_and_quote", {"amount_sat": 5000000, "owner": OX},
                      _K, _dd, "F7A8", _mint_runner, "job-7",
                      reuse_balance=lambda k, a, s: 1)
_led7 = A._load_ledger(_dd)
check("a deposit records its owner on the handle and its account under the "
      "owner",
      _r7[:2] == ("done", "done")
      and _led7["handles"]["F7A8"].get("owner") == OX
      and 11 in _led7["owners"][OX]["accounts"])
# THE OWNER-SCOPED PHASE.
_cap = {}


def _fe(key, injected=None, rpc_url=None, owned_accounts=None):
    _cap["owned"] = owned_accounts
    return None


def _lv(key, injected=None, rpc_url=None, owned_accounts=None):
    _cap["lowned"] = owned_accounts
    return Decimal(0)


_sfe, _slv = A._funded_entry, A._locked_value
try:
    A._funded_entry, A._locked_value = _fe, _lv
    _ph = A._phase_of("withdraw", _dd, key=_K, status="done", owner=OY)
finally:
    A._funded_entry, A._locked_value = _sfe, _slv
check("the 'more left' question after a withdrawal is asked over the owner's "
      "accounts and no other",
      _ph == "" and _cap["owned"] == {2, 7, 8, 9} and _cap["lowned"] == {2, 7, 8, 9})

# ===========================================================================
print("\n== capacity: the vault reserves what every admitted deposit may mint ==")
check("one deposit reserves its account plus the deepest mix the phone can ask "
      "for: wallets + 7 decoys + a carrier + a change sweep",
      A.deposit_reserve_accounts() == 1 + A.withdraw_wallets(3) + 7 + 2
      and A.worst_mix_accounts(1) == A.withdraw_wallets(1) + 9)
_gs = load("GhostSpiral")
check("...and the extra nine are GhostSpiral's own DECOY_MAX plus two, not a "
      "typed guess", A.MIX_EXTRA_ACCOUNTS == _gs.DECOY_MAX + 2)

TP = NP.PrivateKey.generate()
PI = NP.PrivateKey.generate()


def _env(ceiling=45, pending=0):
    d = Path(tempfile.mkdtemp(prefix="mccap_"))
    key = {"schema": "gs_wake_v1", "version": 1, "role": "thinkpad",
           "secret": TP.encode().hex(),
           "peer_public": PI.public_key.encode().hex(),
           "doorbell_url": "http://10.0.0.9:8770",
           "tor_proxy": "socks5h://127.0.0.1:9050",
           "rpc_primary": "http://127.0.0.1:18083",
           "artifact_dir": str(d), "account_ceiling": ceiling}
    kf = d / "tp.key"
    kf.write_text(json.dumps(P.lock_keyfile(key, b"", role="thinkpad")))
    os.chmod(kf, 0o400)
    handles = {}
    for i in range(pending):
        # HEX HANDLES: the ledger drops a key that is not one (a record no
        # job could ever name), so the pending records here must be real.
        b = _bundle(d, f"wallet_p{i}.json", 20 + i, 1)
        s = d / f"thor_pairs_E{i}00.json"
        s.write_text("{}")
        handles[f"E{i}00"] = {"bundle": str(b), "slip": str(s), "minted": 1,
                              "owner": OX}
    if handles:
        A._save_handles(d, handles, {OX: {"accounts": [20 + i for i in range(pending)]}})
    bell = DB.Pending({"secret": PI.encode().hex(),
                       "peer_public": TP.public_key.encode().hex()},
                      "receive_and_quote", {"amount_sat": 5000000, "owner": OY},
                      clock=lambda: 0.0)
    return d, kf, bell


def _run(kf, bell, d, n_accounts, **extra):
    def post(url, path, rec, timeout=30):
        if path == "/window":
            return 200, bell.window
        if path == "/wake":
            try:
                return 200, bell.on_m1(rec)
            except Exception:                                # noqa: BLE001
                return 204, b""
        try:
            bell.on_m3(rec)
            return 200, b""
        except Exception:                                    # noqa: BLE001
            return 204, b""

    def child(argv, env_extra, budget):
        if "create_receive_wallet" in " ".join(argv):
            (d / "wallet_recv_1.json").write_text("{}")
        return 0, False
    deps = dict(post_record=post, sleep=lambda s: None, clock=lambda: 0.0,
                rng=types.SimpleNamespace(randint=lambda a, b: a),
                run_child=child, verify_tor=lambda: None,
                account_count=lambda: n_accounts,
                unit_is_active=lambda u: True, removable_devices=lambda: [],
                resource_check=lambda *a: True, tor_bootstrapped=lambda u: True,
                wipe_covers=lambda p: True, extend_deadman=lambda s: True)
    deps.update(extra)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            return A.run_once(types.SimpleNamespace(key=str(kf), dry_run=False),
                              deps), None
        except A.Refused as e:
            return None, e


_d1, _kf1, _b1 = _env(45, 0)
_o1, _e1 = _run(_kf1, _b1, _d1, 3)
check("a fresh wallet (3 accounts, nothing pending) admits a deposit at the "
      "stock ceiling", _o1 is not None and _o1[1] == "done")
_d2, _kf2, _b2 = _env(45, 1)
_o2, _e2 = _run(_kf2, _b2, _d2, 4)
check("...a second deposit while one is admitted and unpaid is refused "
      "at_capacity: 4 + 30 x 2 > 45",
      _o2 is None and _e2 is not None and _e2.code == "at_capacity")
_d3, _kf3, _b3 = _env(120, 1)
_o3, _e3 = _run(_kf3, _b3, _d3, 4)
check("...and admitted when the ceiling is sized for it (120)",
      _o3 is not None and _o3[1] == "done")
_d4, _kf4, _b4 = _env(45, 0)
_o4, _e4 = _run(_kf4, _b4, _d4, 16)
check("...a wallet already holding 16 accounts cannot carry one more cycle: "
      "16 + 30 > 45, refused before anything is minted",
      _o4 is None and _e4.code == "at_capacity")
_st = json.loads((_d1 / A.STATE_FILE).read_text())
check("the vault's job ledger keeps an id and a ten-minute bucket, not the "
      "job word",
      all(set(j) == {"id", "at"} and j["at"] % 600 == 0 for j in _st["jobs"])
      and all(w % 600 == 0 for w in _st["wakes"]))
_led1 = A._load_ledger(_d1)
check("an admitted deposit is stamped with a ten-minute bucket, no second",
      all(isinstance(r.get("admitted"), int) and r["admitted"] % 600 == 0
          for r in _led1["handles"].values()) and _led1["handles"])

# ===========================================================================
print("\n== the vault: an unpaid deposit stops holding a place ==")
_TTL = P.DEPOSIT_PLACE_TTL_S
_gb = _bundle(_d1, "wallet_ghost.json", 21, 1)
_gs_ = _d1 / "thor_pairs_G000.json"
_gs_.write_text("{}")
_ghost = {"bundle": str(_gb), "slip": str(_gs_), "minted": 1, "owner": OX,
          "admitted": 600}
_now = 600 + _TTL + 600
_zero = lambda k, a, s: 0                                    # noqa: E731
_some = lambda k, a, s: 5                                    # noqa: E731
_unk = lambda k, a, s: None                                  # noqa: E731
check("quoted, unpaid and older than the TTL: not pending any more",
      A._deposit_pending(_ghost, {}, _now, ask=_zero) is False)
check("...the same record with money on its address keeps its place at any "
      "age",
      A._deposit_pending(_ghost, {}, _now, ask=_some) is True)
check("...and a wallet that cannot be asked keeps it too (fails toward "
      "reserving)",
      A._deposit_pending(_ghost, {}, _now, ask=_unk) is True)
check("...younger than the TTL it is pending without asking the wallet",
      A._deposit_pending(_ghost, {}, 600 + _TTL - 600,
                         ask=lambda *a: (_ for _ in ()).throw(AssertionError))
      is True)
check("a record from before the stamp existed counts as old, so a stale "
      "unpaid one can let go",
      A._deposit_pending({k: v for k, v in _ghost.items() if k != "admitted"},
                         {}, _now, ask=_zero) is False)
check("paid out, or never quoted, was never pending",
      A._deposit_pending({**_ghost, "spent": True}, {}, _now, ask=_some) is False
      and A._deposit_pending({**_ghost, "slip": ""}, {}, _now, ask=_some)
      is False)
_bad = dict(_ghost, bundle=str(_d1 / "no_such_bundle.json"))
_bad.pop("pair", None)
check("...and one whose pair cannot be named keeps its place",
      A._deposit_pending(_bad, {}, _now, ask=_zero) is True)
# THROUGH THE GATE, END TO END: one stale unpaid deposit on record, stock
# ceiling, the wallet says its address holds nothing -> the next deposit is
# admitted; the wallet says it holds something -> refused as before.
_d5, _kf5, _b5 = _env(45, 1)
_o5, _e5 = _run(_kf5, _b5, _d5, 4, subaddress_total=_zero)
check("at_capacity lets a ghost go: a stale unpaid deposit no longer refuses "
      "the next one",
      _o5 is not None and _o5[1] == "done")
_d6, _kf6, _b6 = _env(45, 1)
_o6, _e6 = _run(_kf6, _b6, _d6, 4, subaddress_total=_some)
check("...while a paid one of the same age still does",
      _o6 is None and _e6 is not None and _e6.code == "at_capacity")
check("...and that refusal is the one that carries a word: 'full', so the "
      "phone hears the same sentence the Pi says from memory",
      _b6.result is not None and _b6.result.get("status") == "refused"
      and _b6.result.get("phase") == "full")
_d7, _kf7, _b7 = _env(45, 0)
_o7, _e7 = _run(_kf7, _b7, _d7, None)
check("...a refusal for any other reason carries none",
      _o7 is None and _e7 is not None and _e7.code == "account_count_unreadable"
      and _b7.result is not None and _b7.result.get("status") == "refused"
      and _b7.result.get("phase") == ""
      and P.PHASE_LINES["full"] == pg.FULL_ANSWER
      and not any(ch.isdigit() for ch in P.PHASE_LINES["full"]))

# ===========================================================================
print("\n== the pager: owner tokens ==")
_PIK = NP.PrivateKey.generate()
_KEY = {"role": "pi", "secret": _PIK.encode().hex()}
_t1 = pg.owner_token(_KEY, 111)
check("a token is sixteen lowercase hex the protocol accepts",
      P.OWNER_RE.match(_t1) and P._owner_field(_t1) == _t1)
check("...stable for a chat, distinct per chat and per pairing secret",
      pg.owner_token(_KEY, 111) == _t1
      and pg.owner_token(_KEY, 222) != _t1
      and pg.owner_token({"secret": "22" * 32}, 111) != _t1)
check("...domain-separated from the confirmation key, so one secret does two "
      "jobs under two keys",
      pg._owner_key(_KEY) != pg._confirm_key(_KEY)
      and pg._owner_key(_KEY) != bytes.fromhex(_KEY["secret"]))
try:
    pg.owner_token({"secret": "zz"}, 111)
    check("...and a keyfile with no usable secret raises rather than degrading",
          False)
except Exception:                                            # noqa: BLE001
    check("...and a keyfile with no usable secret raises rather than degrading",
          True)


def _pager(allow, max_clients=1):
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key = {"http": "x"}, "T", dict(_KEY)
    p.args = types.SimpleNamespace(no_jitter=True)
    p.allow, p.ignored, p.convos = set(allow), 0, {}
    p.allow_users, p.handle_owner, p.handle_job = set(), {}, {}
    p._chain, p._chain_leg, p._status_at, p._running = None, 0, {}, None
    p.spenders = len(p.allow)
    p.max_clients = max_clients
    p.inflight_owners, p._contended, p._label_fails = set(), False, {}
    p.burn, p.burn_after, p.burn_now = [], 0, False
    p.busy = threading.Lock()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.limits = types.SimpleNamespace(why_not=lambda: "", record=lambda: None,
                                     recent=lambda: [], daily_cap=12, offset=0,
                                     in_flight=False, in_flight_until=0.0,
                                     save=lambda: None)
    seen = []
    p.send = lambda c, t, buttons=None: (seen.append((c, t)), True)[1]
    return p, seen


def _msg(chat, text):
    return {"update_id": 1, "message": {"chat": {"id": chat}, "message_id": 1,
                                        "from": {"id": chat}, "text": text}}


# THE TOKEN RIDES EVERY WAKE, DERIVED FROM THE ASKING CHAT.
_wp, _ws = _pager([111, 222], max_clients=2)
_wire = []


class _Leg:
    def __init__(self, job, params):
        _wire.append((job, dict(params)))
        self.result = {"status": "done", "handle": "A3F1", "slip": "",
                       "plain": {}, "phase": ""}
        self.events = []

    def outcome(self):
        return "done"


_saved_db = pg._DOORBELL[0]
_saved_retry, pg.SLIP_RETRY_S = pg.SLIP_RETRY_S, 0
try:
    pg._DOORBELL[0] = types.SimpleNamespace(
        run_wake=lambda args, key, job, params, **k: _Leg(job, params),
        FETCH_WINDOW_S=600, PRE_WOL_MAX_S=900)
    _wp.start_job(222, "swap_status", {"handle": "A3F1"})
    for _ in range(300):
        if not _wp.busy.locked():
            break
        time.sleep(0.02)
finally:
    pg._DOORBELL[0] = _saved_db
    pg.SLIP_RETRY_S = _saved_retry
check("start_job stamps the note with the asking chat's own token and nothing "
      "a chat typed",
      _wire and _wire[0][1].get("owner") == pg.owner_token(_KEY, 222)
      and _wire[0][1].get("handle") == "A3F1")

# ===========================================================================
print("\n== the pager: busy, full, and whose ==")
_bp, _bs = _pager([111, 222], max_clients=2)
_bp._running = 111
_bp.limits.in_flight_until = time.time() + 7200
_mine = _bp._busy_answer(111)
_other = _bp._busy_answer(222)
check("the chat whose job runs hears 'yours'; another chat hears a bounded "
      "'busy for about', with a figure and nothing else",
      _mine == pg.BUSY_ANSWER_MINE
      and _other.startswith("no: busy right now") and "about 2h" in _other
      and "yours" not in _other and "report" not in _other)
_bp.limits.in_flight_until = 0.0
check("...and with no hold on record the figure is the public worst case, not "
      "a guess about anyone",
      pg._hold_words(P.result_budget_s("withdraw")) in _bp._busy_answer(222))
_bp.busy.acquire()
_bs.clear()
_bp.start_job(222, "swap_status", {"handle": "A3F1"})
check("a second chat refused while a job runs marks the run contended",
      _bp._contended is True and _bs and _bs[-1][1].startswith("no: busy"))
_bp._contended = False
_bs.clear()
_bp.start_job(111, "swap_status", {"handle": "A3F1"})
check("...the running chat's own tap does not",
      _bp._contended is False and _bs[-1][1] == pg.BUSY_ANSWER_MINE)
_bp.busy.release()
# FULL.
_fp, _fs = _pager([111, 222, 333], max_clients=2)
_fp.inflight_owners = {pg.owner_token(_KEY, 111), pg.owner_token(_KEY, 222)}
check("full: a newcomer's deposit is refused when the places are taken, a "
      "holder's is not, and nobody's check or withdrawal ever is",
      _fp._full_for(333, "receive_and_quote") is True
      and _fp._full_for(111, "receive_and_quote") is False
      and _fp._full_for(333, "swap_status") is False
      and _fp._full_for(333, "withdraw") is False)
_fp.begin_convo(333, kind="depo")
check("...begin_convo says so before asking an amount, in words with no "
      "figure and no count",
      _fs and _fs[-1][1] == pg.FULL_ANSWER
      and not any(ch.isdigit() for ch in pg.FULL_ANSWER)
      and 333 not in _fp.convos)
_fs.clear()
_fp.start_job(333, "receive_and_quote", {"amount_sat": 5000000})
check("...start_job refuses it too, from memory, without taking the lock",
      _fs[-1][1] == pg.FULL_ANSWER and not _fp.busy.locked())
_fs.clear()
_fp.handle(_msg(333, "/status"))
check("...and /status answers 'wait' to that chat, never 'ready' then refuse",
      _fs[-1][1] == "wait")
_fs.clear()
_fp._status_at = {}
_fp.handle(_msg(111, "/status"))
check("...while a chat holding a place hears 'ready'", _fs[-1][1] == "ready")
_one, _os = _pager([111], max_clients=1)
_one.inflight_owners = {"x" * 16, "y" * 16}
check("with one client the soft cap does not apply at all",
      _one._full_for(111, "receive_and_quote") is False)
# THE PLACE IS TAKEN ON A DEPOSIT DONE AND GIVEN BACK ON A WITHDRAWAL DONE.
_pp, _ps = _pager([111], max_clients=2)


def _drive(p, job, res):
    saved = pg._DOORBELL[0]
    sr, pg.SLIP_RETRY_S = pg.SLIP_RETRY_S, 0
    try:
        pg._DOORBELL[0] = types.SimpleNamespace(
            run_wake=lambda *a, **k: types.SimpleNamespace(
                result=res, events=[], outcome=lambda: res["status"]),
            FETCH_WINDOW_S=600, PRE_WOL_MAX_S=900)
        p.start_job(111, job, {"amount_sat": 5000000} if job == "receive_and_quote"
                    else {"exit_to": [XMR], "depth": 1})
        for _ in range(300):
            if not p.busy.locked() and p._chain is None:
                break
            time.sleep(0.02)
    finally:
        pg._DOORBELL[0] = saved
        pg.SLIP_RETRY_S = sr


_drive(_pp, "receive_and_quote", {"status": "done", "handle": "A3F1", "slip": "",
                                  "plain": {}, "phase": ""})
check("a deposit that reported done takes a place for its owner",
      set(_pp.inflight_owners) == {pg.owner_token(_KEY, 111)})
_drive(_pp, "withdraw", {"status": "done", "handle": "", "slip": "", "plain": {},
                         "phase": "more_locked"})
check("...a withdrawal that leaves more (locked) keeps it",
      set(_pp.inflight_owners) == {pg.owner_token(_KEY, 111)})
_drive(_pp, "withdraw", {"status": "done", "handle": "", "slip": "", "plain": {},
                         "phase": ""})
check("...and one that finds nothing more gives it back",
      set(_pp.inflight_owners) == set())
# A PLACE NOBODY PAYS FOR IS NOT HELD FOREVER. The place is a token -> last
# sign of life; with none for DEPOSIT_PLACE_TTL_S it is dropped, and a
# watching job that reports money on the address is a sign of life.
_gp, _gs = _pager([111, 222, 333], max_clients=2)
_gp.inflight_owners = {pg.owner_token(_KEY, 111): time.time(),
                       pg.owner_token(_KEY, 222): time.time()
                       - P.DEPOSIT_PLACE_TTL_S - 1}
check("a place with no sign of life for the TTL is a ghost and stops "
      "counting, so a newcomer's deposit is admitted",
      _gp._full_for(333, "receive_and_quote") is False
      and set(_gp.inflight_owners) == {pg.owner_token(_KEY, 111)})
_gp.inflight_owners[pg.owner_token(_KEY, 222)] = (time.time()
                                                  - P.DEPOSIT_PLACE_TTL_S + 60)
_drive(_gp, "swap_status", {"status": "done", "handle": "A3F1", "slip": "",
                            "plain": {}, "phase": "landed"})
check("...and a probe from chat 111 reporting money on the address renews "
      "111's place, not 222's",
      _gp.inflight_owners[pg.owner_token(_KEY, 111)] > time.time() - 5
      and _gp.inflight_owners[pg.owner_token(_KEY, 222)]
      < time.time() - P.DEPOSIT_PLACE_TTL_S + 120)
_drive(_gp, "swap_status", {"status": "done", "handle": "A3F1", "slip": "",
                            "plain": {}, "phase": "moved"})
check("...and 'moved' (paid and sent on) gives 111's place back",
      pg.owner_token(_KEY, 111) not in _gp.inflight_owners)
check("the TTL is one number on both boxes, two days",
      P.DEPOSIT_PLACE_TTL_S == 2 * 86400)
# THE VAULT'S OWN "FULL" REACHES THE CHAT AS THE SAME SENTENCE. After a
# restart this box has forgotten the places; the vault's reserve refuses the
# deposit with the one refusal that carries a word, and the chat hears the
# "full" sentence rather than "refused, it does not say why".
_rp, _rs = _pager([111], max_clients=2)
_drive(_rp, "receive_and_quote", {"status": "refused", "handle": "", "slip": "",
                                  "plain": {}, "phase": "full"})
check("a deposit the vault refused as 'full' is answered with the full "
      "sentence, no figure",
      _rs and _rs[-1][1] == pg.FULL_ANSWER
      and not any(ch.isdigit() for ch in _rs[-1][1]))
_rs.clear()
_drive(_rp, "receive_and_quote", {"status": "refused", "handle": "", "slip": "",
                                  "plain": {}, "phase": ""})
check("...and a refusal with no word gets the generic line, as before",
      _rs and "refused before it started" in _rs[-1][1]
      and "does not say why" in _rs[-1][1])
_rs.clear()
_drive(_rp, "withdraw", {"status": "refused", "handle": "", "slip": "",
                         "plain": {}, "phase": "full"})
check("...and the word on any job but a deposit is not honoured",
      _rs and "refused before it started" in _rs[-1][1]
      and pg.FULL_ANSWER not in [t for _, t in _rs])

# ===========================================================================
print("\n== the pager: a chain yields when somebody waited ==")


def _chain(max_clients, tap_from):
    # A ONE-PERSON BOT ALLOWLISTS ONE PERSON (several is refused outright);
    # above one, the allowlist may be longer than the places.
    p, s = _pager([111, 222] if max_clients > 1 else [111],
                  max_clients=max_clients)
    legs = [0]

    class _L:
        def __init__(self):
            legs[0] += 1
            if tap_from is not None:
                p.start_job(tap_from, "swap_status", {"handle": "A3F1"})
            self.result = {"status": "done", "handle": "", "slip": "",
                           "plain": {}, "phase": "more_left"}
            self.events = []

        def outcome(self):
            return "done"

    saved = pg._DOORBELL[0]
    sr, pg.SLIP_RETRY_S = pg.SLIP_RETRY_S, 0
    try:
        pg._DOORBELL[0] = types.SimpleNamespace(
            run_wake=lambda *a, **k: _L(), FETCH_WINDOW_S=600, PRE_WOL_MAX_S=900)
        p.start_job(111, "withdraw", {"exit_to": [XMR], "depth": 1})
        for _ in range(600):
            if not p.busy.locked() and p._chain is None:
                break
            time.sleep(0.02)
    finally:
        pg._DOORBELL[0] = saved
        pg.SLIP_RETRY_S = sr
    return legs[0], [t for c, t in s if c == 111]


_n_alone, _m_alone = _chain(2, None)
check("nobody waiting: the chain runs to its cap as before",
      _n_alone == pg.Pager.MAX_CHAIN_LEGS)
_n_wait, _m_wait = _chain(2, 222)
check("another chat refused during the leg: the chain yields after ONE leg "
      "and says more remains, so the waiter gets a turn",
      _n_wait == 1 and any("More remains" in t for t in _m_wait)
      and not any("Another is starting" in t for t in _m_wait))
_n_single, _ = _chain(1, 111)
check("a single-client bot keeps the whole chain whatever is tapped",
      _n_single == pg.Pager.MAX_CHAIN_LEGS)

# ===========================================================================
print("\n== the pager: wrong labels cost something, and say the same thing ==")
_lp, _ls = _pager([111])
_lp.handle_owner["A3F1"] = 111
_first = None
for _i in range(pg.LABEL_FAILS_FREE + 2):
    _ls.clear()
    _lp.handle(_msg(111, "/check A3F1-00000000"))
    if _first is None:
        _first = _ls[-1][1]
_fails, _until = _lp._label_fails[111]
check("after the free wrong labels the chat is slowed, with the SAME answer "
      "every time",
      _fails == pg.LABEL_FAILS_FREE + 2 and _until > time.time()
      and _ls[-1][1] == _first and _first.startswith("no: I have no record"))
_lp._label_fails[111] = (3, 0.0)
_ls.clear()
_lp.start_job = lambda cid, job, params, leg=0, held=False: _ls.append((cid, "JOB"))
_lp.handle(_msg(111, f"/check {pg.confirmation_number(_KEY, 111, 'A3F1')}"))
check("...a right label resets the count and goes through",
      111 not in _lp._label_fails and _ls[-1][1] == "JOB")
check("the label's tag is four bytes now, and the pattern reads eight hex",
      pg.CONFIRM_TAG_BYTES == 4
      and len(pg.confirmation_number(_KEY, 111, "A3F1")) == 4 + 1 + 8
      and pg.CONFIRM_RE.match("A3F1-9C2B7E01")
      and not pg.CONFIRM_RE.match("A3F1-9C2B7E"))

# ===========================================================================
print("\n== the Pi's chain names no job, and the chat forwards no exception ==")
_src = open(os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read()
check("a stop mid-wake with no known chat tells the one person on a one-"
      "person bot, and NOBODY on a bot serving several",
      "else sorted(self.allow) if self._max_clients() <= 1 else []" in _src)
check("no chain kind on the Pi carries the job word",
      'integrity_log("pager", f"poke:' not in _src
      and 'integrity_log("pager", f"collected:' not in _src
      and 'integrity_log("pager", f"outcome:{job}' not in _src
      and 'integrity_log("pager", f"wake_failed:' not in _src
      and '"withdraw_result_undelivered"' not in _src
      and '"withdraw_unresolved"' not in _src
      and '"chain_capped"' not in _src)
check("no chat-bound message carries an exception's text",
      "_redact(e)[:160]}\")" not in _src
      and 'could not start — {_redact' not in _src
      and 'failed to start — {_redact' not in _src)
check("the command menu is published per allowlisted chat, and the default "
      "scope is emptied",
      'deleteMyCommands' in _src and '"type": "chat"' in _src)
_sp, _ss = _pager([111, 222])
_sp._running = 111
_sp.busy.acquire()
_ss.clear()
_sp.handle(_msg(222, "/cancel"))
_sp.handle(_msg(111, "/cancel"))
_sp.busy.release()
check("/cancel while a job runs: the other chat hears 'nothing to cancel', "
      "the owner hears 'yours is running'",
      _ss[0][1] == "nothing to cancel." and "yours IS running" in _ss[1][1])
_hp, _hs = _pager([1])
_hp.handle({"update_id": 1, "message": {"chat": {"id": True}, "message_id": 1,
                                        "text": "/status"}})
check("a JSON-bool chat id is not chat 1", _hs == [] and _hp.ignored == 1)

# ===========================================================================
print("\n== the doorbell: a whole-connection deadline, and the hand-poked owner ==")


class _RawSock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, t):
        self.timeouts.append(t)


class _Raw:
    def readline(self, *a):
        return b"POST /window HTTP/1.1\r\n"

    def read(self, n=-1):
        return b"x" * max(0, n)


_t = [1000.0]
_saved_mono = DB.time.monotonic
DB.time.monotonic = lambda: _t[0]
try:
    _sock = _RawSock()
    _rd = DB._DeadlineReader(_Raw(), _sock, 1008.0)
    _l1 = _rd.readline()
    _t[0] = 1005.0
    _l2 = _rd.read(4)
    _t[0] = 1009.0
    try:
        _rd.readline()
        _late = None
    except socket.timeout as e:
        _late = e
finally:
    DB.time.monotonic = _saved_mono
check("every read arms the socket with what is left of ONE deadline, and a "
      "read past it raises the timeout the handler already closes on",
      _l1.startswith(b"POST") and _l2 == b"xxxx"
      and _sock.timeouts == [8.0, 3.0] and isinstance(_late, socket.timeout))
# DRIVEN AGAINST THE REAL HANDLER: a dribbler is dropped at the deadline.
_pend = DB.Pending({"secret": PI.encode().hex(),
                    "peer_public": TP.public_key.encode().hex()},
                   "swap_status", {"handle": "A3F1", "owner": OX})
_H = DB.make_handler(_pend)
_H.CONNECTION_DEADLINE_S = 1
_srv_sock = socket.socket()
_srv_sock.bind(("127.0.0.1", 0))
_port = _srv_sock.getsockname()[1]
_srv_sock.close()
_srv = ThreadingHTTPServer(("127.0.0.1", _port), _H)
threading.Thread(target=_srv.serve_forever, daemon=True).start()
_c = socket.create_connection(("127.0.0.1", _port), timeout=5)
_c.sendall(b"POST /wi")
_t0 = time.monotonic()
_c.settimeout(5)
try:
    _got = _c.recv(64)
except socket.timeout:
    _got = b"timeout"
_elapsed = time.monotonic() - _t0
_c.close()
_srv.shutdown()
_srv.server_close()
check("a connection that dribbles is closed by the deadline, not held for the "
      "per-read timeout",
      _got == b"" and _elapsed < 4)
_jb = DB.read_job_from_stdin(io.StringIO('{"job":"swap_status","handle":"A3F1"}'))
check("a hand-poked job with no owner is the host's",
      _jb[1].get("owner") == P.HOST_OWNER)
_jb2 = DB.read_job_from_stdin(io.StringIO(
    '{"job":"swap_status","handle":"A3F1","owner":"0123456789abcdef"}'))
check("...one that names an owner keeps it", _jb2[1]["owner"] == "0123456789abcdef")
try:
    DB.read_job_from_stdin(io.StringIO(
        '{"job":"swap_status","handle":"A3F1","owner":"NOPE"}'))
    check("...and a malformed owner is refused before anything is woken", False)
except DB.Doorbell:
    check("...and a malformed owner is refused before anything is woken", True)

A.integrity_log = _saved_il
_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL GREEN")
