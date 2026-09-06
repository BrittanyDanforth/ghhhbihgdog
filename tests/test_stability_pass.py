#!/usr/bin/env python3
"""THE DEEP-READ PASS: half-wired, unstable and hot-loop paths, DRIVEN.

Every check here exercises a fix from the end-to-end read that followed the
multi-client work -- a lock that could leak, a loop that could spin, a chain
that could flood, a save that could race, a bit that could stay on. Each is
run through the real code with the failure staged (a gate that raises, a card
that is full, a circuit that is dead, a clock that jumped), not asserted from
the source alone; the few source pins are on shapes a behaviour cannot see.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import types
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
                                 "test_stability_pass.py")


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    sp = importlib.util.spec_from_loader(ld.name, ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    return m


os.environ.setdefault("GS_WALLET_PASSWORD", "hunter2")
A = load("gs_wake_agent")
pg = load("gs_telegram_pager")
import nacl.public as NP                                     # noqa: E402

_SRC_PG = Path(os.path.join(REPO, "gs_telegram_pager")).read_text()
_SRC_A = Path(os.path.join(REPO, "gs_wake_agent")).read_text()
_SRC_GC = Path(os.path.join(REPO, "gs_common.py")).read_text()
_SRC_DB = Path(os.path.join(REPO, "gs_doorbell")).read_text()

XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaB"
       "YBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
OX, OY = "a" * 16, "b" * 16
_K = {"tor_proxy": "socks5h://127.0.0.1:9050",
      "rpc_primary": "http://127.0.0.1:18083",
      "wallet_file": "/var/lib/gs/spend.wallet"}
_PIK = NP.PrivateKey.generate()
_KEY = {"role": "pi", "secret": _PIK.encode().hex()}


class _Clock:
    """`time` with sleep made free. Everything else is the real module."""

    def __init__(self, log):
        self.log = log

    def sleep(self, s):
        self.log.append(s)

    def __getattr__(self, n):
        return getattr(time, n)


# ===========================================================================
print("== the chain's last hash is read from the tail, and the chain holds ==")
_cd = Path(tempfile.mkdtemp(prefix="chain_"))
_log = _cd / "integrity.log"
check("no chain yet: the all-zero root", GC._last_chain_prev(_log) == "0" * 64)
_log.write_text("")
check("an empty chain file: the root", GC._last_chain_prev(_log) == "0" * 64)
_hashes = [GC.integrity_log("t", f"entry {i}", log_path=_log)
           for i in range(200)]
check("a chain past two 4 KiB steps still yields the LAST line's hash",
      _log.stat().st_size > 8192 and GC._last_chain_prev(_log) == _hashes[-1])
_full = [ln for ln in _log.read_text().splitlines() if ln.strip()][-1]
check("...the same hash a whole-file read gives",
      _full.split(" | ")[0] == _hashes[-1])
with open(_log, "ab") as _f:
    _f.write(b"\n\n")
check("trailing blank lines are skipped", GC._last_chain_prev(_log) == _hashes[-1])
_hashes.append(GC.integrity_log("t", "after the blanks", log_path=_log))


def _verify(path):
    prev = "0" * 64
    for ln in path.read_text().splitlines():
        if not ln.strip():
            continue
        h, line = ln.split(" | ", 1)
        if h != __import__("hashlib").sha256((prev + line).encode()).hexdigest():
            return False
        prev = h
    return True


check("every link recomputes: the entry written from a tail read chains off "
      "the true last line", _verify(_log))

# ===========================================================================
print("\n== one state file, several writers ==")
_aw = _cd / "state.json"
_errs = []


def _writer(i):
    try:
        for _ in range(20):
            GC.atomic_write_json({"n": i, "pad": "y" * 2000}, _aw)
    except Exception as e:                                   # noqa: BLE001
        _errs.append(e)


_ths = [threading.Thread(target=_writer, args=(i,)) for i in range(6)]
for _t in _ths:
    _t.start()
for _t in _ths:
    _t.join()
_final = json.loads(_aw.read_text())
check("six writers on one file: none raises, and what is left is one whole "
      "write", not _errs and _final["n"] in range(6)
      and len(_final["pad"]) == 2000)
check("...and no tmp is left beside it", not list(_cd.glob("state.json.*")))
check("the tmp is a name of its own per write, beside the file",
      'mkstemp(prefix=path.name + ".", suffix=".tmp"' in _SRC_GC
      and "dir=str(path.parent)" in _SRC_GC)


# ===========================================================================
def _pager(allow, max_clients=1):
    p = pg.Pager.__new__(pg.Pager)
    p.proxies, p.token, p.key = {"http": "x"}, "T", dict(_KEY)
    p.args = types.SimpleNamespace(no_jitter=True)
    p.allow, p.ignored, p.convos = set(allow), 0, {}
    p.allow_users, p.handle_owner, p.handle_job = set(), {}, {}
    p._chain, p._chain_leg, p._status_at, p._running = None, 0, {}, None
    p.spenders = len(p.allow)
    p.max_clients = max_clients
    p.inflight_owners, p._contended, p._label_fails = {}, False, {}
    p.burn, p.burn_after, p.burn_now = [], 0, False
    p._burn_resumed = False
    p.busy = threading.Lock()
    p.clock, p.rng = (lambda: 0.0), __import__("random").SystemRandom()
    p.limits = types.SimpleNamespace(why_not=lambda: "", record=lambda: None,
                                     recent=lambda: [], daily_cap=12, offset=0,
                                     in_flight=False, in_flight_until=0.0,
                                     save=lambda: None)
    seen = []
    p.send = lambda c, t, buttons=None: (seen.append((c, t)), True)[1]
    return p, seen


def _msg(chat, text, uid=1):
    m = {"message": {"chat": {"id": chat}, "message_id": 1,
                     "from": {"id": chat}, "text": text}}
    if uid is not None:
        m["update_id"] = uid
    return m


_il = []
_saved_il = pg.integrity_log
pg.integrity_log = lambda st, k: _il.append(k)

print("\n== silent refusals count every one and write the chain once ==")
_p, _seen = _pager([111])
for _ in range(5):
    _p._log_ignored("chat_not_allowlisted")
_p._log_ignored("sender_not_allowlisted")
check("five ignored updates of one kind: five counted, ONE chain line; a "
      "second kind gets its own",
      _p.ignored == 6
      and _il == ["chat_not_allowlisted", "sender_not_allowlisted"])
_p._ignored_logged["chat_not_allowlisted"] -= pg.Pager.IGNORED_LOG_EVERY_S + 1
_p._log_ignored("chat_not_allowlisted")
check("...and again once the window has passed",
      _il.count("chat_not_allowlisted") == 2)
_p._ignored_logged["chat_not_allowlisted"] = time.time() + 10 ** 6
_p._log_ignored("chat_not_allowlisted")
check("...and a clock that jumped back does not silence the kind for ever",
      _il.count("chat_not_allowlisted") == 3)
_p.ignored, _il[:] = 0, []
_p._ignored_logged.clear()
for _ in range(20):
    _p.handle(_msg(999, "/status"))
check("twenty messages from a stranger: twenty counted, one line, nothing "
      "sent", _p.ignored == 20 and _il == ["chat_not_allowlisted"]
      and not _seen)
_p.__dict__.pop("_ignored_logged", None)
_p._log_ignored("unknown_command")
check("a Pager built without __init__ counts and logs like one that was",
      _p.ignored == 21 and _il[-1] == "unknown_command")

# ===========================================================================
print("\n== the lock is given back exactly once, whatever start_job does ==")


def _raise(e):
    raise e


_p, _seen = _pager([111])
_p.busy.acquire()
_p._hold_why = lambda: _raise(OSError("card"))
try:
    _p.start_job(111, "withdraw", {"exit_to": XMR, "depth": 1}, leg=1,
                 held=True)
    _r = False
except OSError:
    _r = True
check("a chained leg whose gate RAISES gives the lock back and re-raises",
      _r and not _p.busy.locked())
_p, _seen = _pager([111])
_p.limits.why_not = lambda: "daily limit reached"
_p.busy.acquire()
_p.start_job(111, "withdraw", {"exit_to": XMR, "depth": 1}, leg=1, held=True)
check("a chained leg the rate limit refuses gives it back and says why",
      not _p.busy.locked() and _seen[-1][1] == "no: daily limit reached")
_p, _seen = _pager([111, 222])
_drops = []
_p._drop_busy = lambda: _drops.append(1)
pg.integrity_log = lambda st, k: _raise(OSError("card"))
_p.busy.acquire()
try:
    _p.start_job(111, "withdraw", {"exit_to": XMR, "depth": 1}, leg=1,
                 held=True)
except OSError:
    pass
pg.integrity_log = lambda st, k: _il.append(k)
check("...given back ONCE when the chain write raises after the refusal had "
      "already given it back -- never a second release that could free "
      "another thread's lock", _drops == [1])

_p, _seen = _pager([111])
_p.limits.record = lambda: _raise(OSError("No space left on device: "
                                          "/var/lib/gs/pager_state.json.tmp"))
_p.limits.in_flight = True
_il[:] = []
with contextlib.redirect_stdout(io.StringIO()):
    _p.start_job(111, "swap_status", {"handle": "A3F1"})
check("a start that fails: lock free, nothing running, the persisted bit "
      "OFF, 'could not start' with no path in it",
      not _p.busy.locked() and _p._running is None
      and _p.limits.in_flight is False
      and "could not start" in _seen[-1][1]
      and "device" not in _seen[-1][1] and ".json" not in _seen[-1][1]
      and "worker_start_failed" in _il)
_wire = []


class _Leg:
    def __init__(self, job, params):
        _wire.append((job, dict(params)))
        self.result = {"status": "done", "handle": "A3F1", "slip": "",
                       "plain": {}, "phase": ""}
        self.events = []

    def outcome(self):
        return "done"


_p.limits.record = lambda: None
_saved_db = pg._DOORBELL[0]
_saved_retry, pg.SLIP_RETRY_S = pg.SLIP_RETRY_S, 0
try:
    pg._DOORBELL[0] = types.SimpleNamespace(
        run_wake=lambda args, key, job, params, **k: _Leg(job, params),
        FETCH_WINDOW_S=600, PRE_WOL_MAX_S=900)
    with contextlib.redirect_stdout(io.StringIO()):
        _p.start_job(111, "swap_status", {"handle": "A3F1"})
    for _ in range(300):
        if not _p.busy.locked() and _wire:
            break
        time.sleep(0.02)
finally:
    pg._DOORBELL[0] = _saved_db
    pg.SLIP_RETRY_S = _saved_retry
check("...and the next start after it takes the lock and reaches the wire: "
      "nothing was leaked, nothing was released twice",
      len(_wire) == 1 and not _p.busy.locked())

# ===========================================================================
print("\n== a poll that cannot advance pauses instead of spinning ==")
_sl = []
_saved_time, _saved_get = pg.time, pg.safe_get
_p, _seen = _pager([111])
_p.poll_failures = 0
try:
    pg.time = _Clock(_sl)
    pg.safe_get = lambda url, proxies=None, **k: {"ok": True,
                                                 "result": ["junk", None, 3]}
    _u1 = _p.updates()
    pg.safe_get = lambda url, proxies=None, **k: {"ok": True,
                                                 "result": [{"update_id": 5}]}
    _u2 = _p.updates()
    pg.safe_get = lambda url, proxies=None, **k: {"ok": True, "result": []}
    _u3 = _p.updates()
finally:
    pg.time, pg.safe_get = _saved_time, _saved_get
check("a batch that is all chaff comes back empty AND waits one poll period; "
      "a real batch and an empty long-poll wait nothing",
      _u1 == [] and _sl == [5] and _u2 == [{"update_id": 5}] and _u3 == []
      and _sl == [5])


def _one_tick(p, batch, il):
    """Run the poll loop for exactly one tick over `batch`."""
    p.publish_commands = lambda: True
    p._check_group_rights = lambda: None
    p.announce_restart = lambda: None
    p.retry_wizard_deletes = lambda: None
    p.burn_expired = lambda s: 0
    n = [0]

    def _sr():
        n[0] += 1
        return n[0] > 1
    p.updates = lambda: list(batch)
    sl = []
    saved_time, saved_sr = pg.time, pg.shutdown_requested
    try:
        pg.time = _Clock(sl)
        pg.shutdown_requested = _sr
        with contextlib.redirect_stdout(io.StringIO()):
            p.run()
    finally:
        pg.time, pg.shutdown_requested = saved_time, saved_sr
    return sl


_p, _seen = _pager([111])
_il[:] = []
_sl = _one_tick(_p, [_msg(111, "/status", uid=None)], _il)
check("an update with no id: skipped, counted, one chain line, and the loop "
      "PAUSES -- Telegram hands the same batch straight back",
      _p.ignored == 1 and _il.count("update_without_id") == 1
      and 5 in _sl and not _seen)
_p, _seen = _pager([111])
_p.limits.offset = 0
_sl = _one_tick(_p, [_msg(111, "/status", uid=7)], _il)
check("...a batch that moved the cursor waits nothing",
      _p.limits.offset == 8 and 5 not in _sl and _seen)

# ===========================================================================
print("\n== burning a session's messages: capped, resumed, logged once ==")
_p, _seen = _pager([111])
_p.burn = [(111, i, 0.0) for i in range(40)]
_dm = []
_p.delete_message = lambda c, m: (_dm.append(m), True)[1]
_g, _t = _p.burn_all()
check("a burn of forty: thirty-two this tick, eight kept, re-armed as a "
      "continuation", (_g, _t) == (32, 32) and len(_p.burn) == 8
      and _p.burn_now and _p._burn_resumed)
_p.burn = [(111, i, 0.0) for i in range(3)]
_p.burn_now = _p._burn_resumed = False
_p.delete_message = lambda c, m: None
_g, _t = _p.burn_all()
check("a dead circuit: one try, everything kept, re-armed as a continuation",
      (_g, _t) == (0, 1) and len(_p.burn) == 3 and _p.burn_now
      and _p._burn_resumed)
_p, _seen = _pager([111])
_p.burn_all = lambda chat_id=None: (0, 0)
_p.burn_now, _p._burn_resumed = True, True
_il[:] = []
_one_tick(_p, [], _il)
check("a continued pass puts nothing on the chain",
      "burn_signal" not in _il and _p._burn_resumed is False)
_p.burn_now, _p._burn_resumed = True, False
_one_tick(_p, [], _il)
check("...a fresh signal does, once", _il.count("burn_signal") == 1)

# ===========================================================================
print("\n== the rate state: one lock, two threads, a clock that jumped ==")
_ld = Path(tempfile.mkdtemp(prefix="lim_"))
L = pg.Limits(_ld / "state.json", 300, 12)
check("the limits lock is one re-entrant lock, made once",
      L._lk() is L._lk() and type(L._lk()) is type(threading.RLock()))
L2 = pg.Limits.__new__(pg.Limits)
check("...and a Limits built without __init__ gets one on first use",
      L2._lk() is L2._lk())
L.last_poke = time.time() + 3600
check("a clock that jumped backwards does not answer 'wait' for an hour",
      L.why_not() == "")
L.last_poke = time.time() - 10
check("...while a real recent poke still does", L.why_not().startswith("wait "))
_errs = []


def _rec():
    try:
        for _ in range(30):
            L.record()
    except Exception as e:                                   # noqa: BLE001
        _errs.append(e)


def _sv():
    try:
        for _ in range(30):
            L.in_flight = not L.in_flight
            L.save()
    except Exception as e:                                   # noqa: BLE001
        _errs.append(e)


_ths = [threading.Thread(target=_rec), threading.Thread(target=_sv)]
for _t in _ths:
    _t.start()
for _t in _ths:
    _t.join()
check("record and save from two threads never raise and the file is whole",
      not _errs and isinstance(json.loads((_ld / "state.json").read_text()),
                               dict)
      and len(L.recent()) == 30)
check("save, recent and record all take it",
      _SRC_PG.count("        with self._lk():") == 3)
_p, _ = _pager([111])
_p.limits = L
_p._set_in_flight(True, until=time.time() + 100)
_d = json.loads((_ld / "state.json").read_text())
check("_set_in_flight goes to the card under the same lock, bit and window "
      "together", _d["in_flight"] is True and _d["in_flight_until"] > 0
      and '_lk = getattr(self.limits, "_lk", None)' in _SRC_PG)

# ===========================================================================
print("\n== a thousand wrong labels do not crash the next /check ==")
_p, _seen = _pager([111])
_p._label_fails = {111: (2000, 0.0)}
_saved_hfc = pg.handle_from_confirmation
pg.handle_from_confirmation = lambda key, cid, text: None
try:
    _p.handle(_msg(111, "/check A3F1-9C2B7E01"))
    _ok = True
except OverflowError:
    _ok = False
finally:
    pg.handle_from_confirmation = _saved_hfc
check("a chat with two thousand misses: refused, not an OverflowError, and "
      "the wait is bounded",
      _ok and _seen and "no record" in _seen[-1][1]
      and _p._label_fails[111][0] == 2001
      and _p._label_fails[111][1] - time.time() <= pg.LABEL_BACKOFF_MAX_S + 1)
check("...on both sites", _SRC_PG.count("2 ** min(20,") == 2)

# ===========================================================================
print("\n== places under one lock, on both threads ==")
_p, _ = _pager([111, 222], max_clients=5)
_errs = []


def _churn(cid):
    try:
        for _ in range(400):
            _p._hold_place(cid)
            _p._drop_place(cid)
    except Exception as e:                                   # noqa: BLE001
        _errs.append(e)


def _reader():
    try:
        for _ in range(400):
            _p._places()
            _p._full_for(333, "receive_and_quote")
    except Exception as e:                                   # noqa: BLE001
        _errs.append(e)


_ths = [threading.Thread(target=_churn, args=(111,)),
        threading.Thread(target=_churn, args=(222,)),
        threading.Thread(target=_reader)]
for _t in _ths:
    _t.start()
for _t in _ths:
    _t.join()
check("holds, drops and reads from three threads: no 'dict changed size' "
      "out of the one command whose job is to answer", not _errs)
check("...and the mine-lookup walks a snapshot of handle_owner",
      "for _k, _v in list(self.handle_owner.items())" in _SRC_PG)

pg.integrity_log = _saved_il

# ===========================================================================
print("\n== the vault: a refusal that keeps the machine on is not re-decided ==")
_calls = []
_sv_ = (A.run_once, A.somebody_is_here, A.power_off, A.disarm_deadman,
        A.install_signal_handlers, A.integrity_log)


def _main_with(exc):
    _calls[:] = []
    A.run_once = lambda args, deps=None: _raise(exc)
    A.somebody_is_here = lambda: (_calls.append("looked"), "")[1]
    A.power_off = lambda dry_run=False: _calls.append("off")
    A.disarm_deadman = lambda: _calls.append("disarm")
    A.install_signal_handlers = lambda: None
    A.integrity_log = lambda *a, **k: None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return A.main(["--key", "/nonexistent.key"])
    finally:
        (A.run_once, A.somebody_is_here, A.power_off, A.disarm_deadman,
         A.install_signal_handlers, A.integrity_log) = _sv_


_rc = _main_with(A.Refused("somebody_here", "a person is at the keyboard",
                           power=False))
check("Refused(power=False): exit 0, deadman disarmed, and the power-off "
      "guard is NOT re-run -- the machine stays on",
      _rc == 0 and "disarm" in _calls and "off" not in _calls
      and "looked" not in _calls)
_rc = _main_with(A.Refused("at_capacity", "full", power=True))
check("Refused(power=True): exit 1, the guard is looked at, and it powers off",
      _rc == 1 and _calls == ["looked", "off"])

# ===========================================================================
print("\n== the accounts a mix minted: asked again, said when unreadable ==")
_dd = Path(tempfile.mkdtemp(prefix="stab_disp_"))


def _bundle(d, name, acct, sub):
    p = d / name
    p.write_text(json.dumps({"schema": "gs_receive_wallet_v1", "address": XMR,
                             "account_index": acct, "subaddress_index": sub,
                             "rpc_endpoint": "http://127.0.0.1:18083"}))
    return p


def _fresh_ledger(d):
    by = _bundle(d, "wallet_y.json", 2, 1)
    sy = d / "thor_pairs_B7C2.json"
    sy.write_text("{}")
    A._save_handles(d, {"B7C2": {"bundle": str(by), "slip": str(sy),
                                 "minted": 1, "owner": OY}},
                    {OY: {"accounts": [2]}})


_seen_argv = []
_ail = []
_saved_ail, A.integrity_log = A.integrity_log, lambda st, k: _ail.append(k)
_saved_atime = A.time
_asl = []


def _runner(argv, env_extra, budget_s):
    _seen_argv.append(list(argv))
    return 0, False


def _dispatch_withdraw(d, seq, runner=_runner):
    calls = []

    def _acct():
        calls.append(1)
        return seq[min(len(calls), len(seq)) - 1]
    with contextlib.redirect_stdout(io.StringIO()):
        r = A._dispatch("withdraw", {"exit_to": XMR, "depth": 1, "owner": OY},
                        _K, d, "C4D5", runner, "job-s",
                        funded=lambda: (2, 1, XMR, 300 * 10 ** 12),
                        accounts=_acct)
    return r, len(calls)


try:
    A.time = _Clock(_asl)
    _fresh_ledger(_dd)
    _r, _n = _dispatch_withdraw(_dd, [{0, 1, 2}, None, None, {0, 1, 2, 7}])
    _led = A._load_ledger(_dd)
    check("the wallet busy twice after the mix: asked a third time, and the "
          "account it minted is recorded as the owner's",
          _r[:2] == ("done", "done") and _n == 4
          and _led["owners"][OY]["accounts"] == [2, 7]
          and _asl.count(2) == 2 and "owner_accounts_unreadable" not in _ail)
    _dd2 = Path(tempfile.mkdtemp(prefix="stab_disp2_"))
    _fresh_ledger(_dd2)
    _ail[:] = []
    _out = io.StringIO()
    with contextlib.redirect_stdout(_out):
        _r, _n = _dispatch_withdraw(_dd2, [{0, 1, 2}, None, None, None, None])
    _led2 = A._load_ledger(_dd2)
    check("...still unreadable after three: nothing guessed into the ledger, "
          "and it is on the chain",
          _r[:2] == ("done", "done") and _n == 4
          and _led2["owners"][OY]["accounts"] == [2]
          and "owner_accounts_unreadable" in _ail)
finally:
    A.time = _saved_atime

print("\n== a failed withdrawal shreds its entry bundle ==")
_dd3 = Path(tempfile.mkdtemp(prefix="stab_disp3_"))
_fresh_ledger(_dd3)
_ail[:] = []
_r, _n = _dispatch_withdraw(_dd3, [{0, 1, 2}, {0, 1, 2}],
                            runner=lambda a, e, b: (1, False))
check("a withdrawal whose child fails: reported failed, the deposit NOT "
      "marked spent, and the bundle naming the account it spent from is gone",
      _r == ("job_failed", "failed", "C4D5")
      and not (_dd3 / "wallet_withdraw_C4D5.json").exists()
      and "spent" not in A._load_ledger(_dd3)["handles"]["B7C2"]
      and "job_failed:withdraw" in _ail)
A.integrity_log = _saved_ail

print("\n== the fee sweep's entry bundle goes with the sweep ==")
_fd = Path(tempfile.mkdtemp(prefix="stab_fee_"))
(_fd / A.FEE_SWEEP_BUNDLE).write_text("{}")
with contextlib.redirect_stdout(io.StringIO()):
    A._retire_fee_bundle(_fd)
check("present: shredded", not (_fd / A.FEE_SWEEP_BUNDLE).exists())
try:
    A._retire_fee_bundle(_fd)
    _ok = True
except Exception:                                            # noqa: BLE001
    _ok = False
check("absent: nothing to do, nothing raised", _ok)
_ail[:] = []
(_fd / A.FEE_SWEEP_BUNDLE).write_text("{}")
_saved_sd = A.secure_delete_or_warn
A.integrity_log = lambda st, k: _ail.append(k)
A.secure_delete_or_warn = lambda p, w: _raise(OSError("busy"))
try:
    A._retire_fee_bundle(_fd)
    _ok = True
except Exception:                                            # noqa: BLE001
    _ok = False
finally:
    A.secure_delete_or_warn, A.integrity_log = _saved_sd, _saved_ail
check("a shred that fails is on the chain and does not take the sweep down",
      _ok and _ail == ["retire_failed:fee_bundle"])
_rfs = _SRC_A.split("def run_fee_sweep(")[1].split("\ndef ")[0]
check("...and run_fee_sweep retires it on the failed leg AND after the last",
      _rfs.count("_retire_fee_bundle(artifact_dir)") == 2
      and "_CHILD_STARTED[0] = True" in _rfs)

print("\n== the rest of the pass: shapes a behaviour cannot see ==")
check("the withdrawal minimum is the wire's shallowest depth, not a literal",
      A._MIN_OUT_WALLETS == P.WITHDRAW_DEPTHS[min(P.WITHDRAW_DEPTHS)][0])
check("the status file is taken off the disk once it has been reported",
      _SRC_A.count("(artifact_dir / STATUS_FILE).unlink()") >= 2)
check("the doorbell's console says the 'full' line for a full vault",
      "if _rph == \"full\":" in _SRC_DB
      and "proto.PHASE_LINES.get('full'" in _SRC_DB)
check("the chain's prev comes from the tail reader, never a whole-file read",
      "prev = _last_chain_prev(log_path)" in _SRC_GC
      and "read_text().splitlines()" not in
      _SRC_GC.split("def integrity_log(")[1].split("\ndef ")[0])

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
