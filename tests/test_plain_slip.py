#!/usr/bin/env python3
"""THE PHONE-ONLY PATH: the deposit instructions in the clear, and a status
word that does not lie.

WHY THIS EXISTS, because it looks like the thing OPSEC_SETUP.md §8 forbids.

§8 says: do not "just run a Telegram bot" that prints the memo. That rule is
right and it assumes a walk to the vault. Two designs have now failed on that
assumption -- "read it on the vault", then a sealed slip that needs a THIRD
machine holding a delivery key. An operator with only a phone has neither, so
what they got was a quoted swap and no way to pay it.

So there is a third mode, and everything here is about bounding it:

  * IT IS OFF UNLESS THE VAULT'S OWN KEYFILE SAYS OTHERWISE. Not a pager flag,
    not a chat command, not an M2 parameter -- a field in a 0400 file on the
    machine 500 km away. A stolen bot token and a compromised Pi both still
    get a handle and nothing else.
  * EXACTLY FIVE FIELDS travel, by allowlist, and dest_xmr and ts are NOT
    among them: a phone can run neither the memo-binding re-check nor the
    staleness check that those two exist for, so they would be extra copies of
    sensitive values bought for nothing.
  * ONE PAYLOAD PER RESULT. Sealed and plaintext are two answers to one
    question; carrying both would double the exposure for a single delivery.
  * THE STATUS WORD IS A CLOSED SET. The operator needs "has my money
    arrived?" answered on their phone; the vault must not gain a free-text
    channel into a chat while answering it.

WHAT IS NOT DEFENDED, stated here so no later reader assumes it is: a
plaintext slip is NOT AUTHENTICATED. The ThorChain deposit address is a shared
pooled vault, so the memo is the entire binding between the operator's Bitcoin
and their Monero -- and whoever holds the bot token can leave the deposit line
correct and substitute their own address into the memo. The sealed slip
refused that; this cannot. A human cannot verify a 111-character memo by eye,
and every scheme that looks like it helps (a code sheet, an HMAC, echoing the
memo back) fails against the same attacker, because someone holding the token
IS the bot as far as the phone can tell. The mitigation is the token.
"""
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = FAIL = 0
FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   " + name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL: " + name)


def load(name):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(REPO, name))
    spec = importlib.util.spec_from_loader(ld.name, ld)
    mod = importlib.util.module_from_spec(spec)
    ld.exec_module(mod)
    return mod


P = load("gs_wake_proto.py")
from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILURES),
                                 "test_plain_slip")

DB = load("gs_doorbell")
sys.modules["gs_doorbell"] = DB
AG = load("gs_wake_agent")
pg = load("gs_telegram_pager")
pg._DOORBELL[0] = DB
import nacl.public as NP                                     # noqa: E402

XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSs"
       "aBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
MEMO = f"=:XMR.XMR:{XMR}:0/1/0"
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
AMOUNT = "0.05000000"
PAIR = {"schema": "x", "btc_in": AMOUNT, "deposit": BTC, "memo": MEMO,
        "dest_xmr": XMR, "expected_xmr": "1.23456789", "ts": 1755900000}

VAULT = NP.PrivateKey.generate()
PI = NP.PrivateKey.generate()


def bay(handles=None, slip_pairs=PAIR):
    d = Path(tempfile.mkdtemp(prefix="plainbay_"))
    sp = d / "thor_pairs_A3F1.json"
    sp.write_text(json.dumps([slip_pairs] if isinstance(slip_pairs, dict)
                             else slip_pairs))
    (d / AG.HANDLES_FILE).write_text(json.dumps(
        handles if handles is not None
        else {"A3F1": {"bundle": "w.json", "minted": 1, "slip": str(sp)}}))
    return d


def vkey(**over):
    k = {"secret": bytes(VAULT).hex(),
         "peer_public": bytes(PI.public_key).hex(), "plain_slip": True}
    k.update(over)
    return k


BAY = bay()

# ===========================================================================
# 1. OFF BY DEFAULT, AND THE SWITCH IS ON THE VAULT.
# ===========================================================================
print("\n-- off unless the vault's keyfile says otherwise --")
check("with plain_slip unset, nothing is built",
      AG.plain_slip_for_chat(vkey(plain_slip=None), BAY, "done", "A3F1") == {})
check("with plain_slip false, nothing is built",
      AG.plain_slip_for_chat(vkey(plain_slip=False), BAY, "done", "A3F1") == {})
PLAIN = AG.plain_slip_for_chat(vkey(), BAY, "done", "A3F1")
check("with plain_slip true, the deposit instructions are built", bool(PLAIN))

# THE SWITCH IS NOT REACHABLE FROM THE PI. A job carries a bounded integer or a
# 4-hex handle and nothing else, so there is no representable way for the Pi to
# ask for plaintext -- checked structurally rather than by enumerating attempts.
_all_params = set()
for _spec in P.JOBS.values():
    _all_params |= set(_spec["schema"])
check("no job schema has a field that could request plaintext",
      not any("plain" in f or "clear" in f for f in _all_params))
_pgsrc = open(os.path.join(REPO, "gs_telegram_pager"), encoding="utf-8").read()
check("the pager never writes plain_slip: the switch is not on this box",
      '"plain_slip"' not in _pgsrc and "'plain_slip'" not in _pgsrc)

# ===========================================================================
# 2. EXACTLY THE ALLOWED FIELDS, AND dest_xmr AND ts ARE NOT AMONG THEM.
# ===========================================================================
print("\n-- exactly five fields, by allowlist --")
check("the built slip carries exactly the declared field set",
      set(PLAIN) == set(P.PLAIN_FIELDS))
check("the destination address does NOT travel separately -- a phone cannot "
      "re-check memo binding, so it would be a second copy for nothing",
      XMR not in {v for k, v in PLAIN.items() if k != "m"})
check("...and neither does the quote timestamp",
      not any(str(PAIR["ts"]) == v for v in PLAIN.values()))
check("the amount, the deposit address and the memo all DO travel -- they are "
      "the payment",
      PLAIN["b"] == AMOUNT and PLAIN["d"] == BTC and PLAIN["m"] == MEMO)
check("and the handle, so the operator can /check it later", PLAIN["h"] == "A3F1")

# A FIELD ADDED TO THE PAIR RECORD MUST NOT RIDE ALONG. The pair is written by
# another tool; the next field somebody adds there is the one that would reach
# a chat unexamined.
_extra = AG.plain_slip_for_chat(
    vkey(), bay(slip_pairs=dict(PAIR, secret_note="do not send this")),
    "done", "A3F1")
check("a NEW field in the pair record does not reach the slip",
      "do not send this" not in json.dumps(_extra))

# ===========================================================================
# 3. THE SHAPE CHECK, WHICH IS ALSO A CONTROL-CHARACTER GATE.
#
# These values are pasted into a message a human copies into a wallet. A
# newline in the memo forges a line of it -- the same attack thor_swap_preparer
# gates its own SENDER INSTRUCTIONS block against.
# ===========================================================================
print("\n-- the shape check the doorbell runs before relaying --")
check("a real slip is well-formed", P.plain_slip_is_wellformed(PLAIN))
for _bad, _why in (
        (dict(PLAIN, z="x"), "an extra field"),
        ({k: v for k, v in PLAIN.items() if k != "m"}, "a missing field"),
        (dict(PLAIN, m=""), "an empty field"),
        (dict(PLAIN, m="x" * 500), "an overlong field"),
        (dict(PLAIN, b=5), "a non-string"),
        (dict(PLAIN, m=MEMO + "\nTo address:    bc1qattacker"), "a newline"),
        (dict(PLAIN, d=BTC + "\x1b[2K"), "an escape sequence"),
        (dict(PLAIN, h="A3F1\x7f"), "a DEL"),
        ("not a dict", "a non-object"),
        (None, "None")):
    check(f"...{_why} is refused", not P.plain_slip_is_wellformed(_bad))

# THE VAULT CHECKS IT TOO, where the operator is present to be told.
_ctl = AG.plain_slip_for_chat(
    vkey(), bay(slip_pairs=dict(PAIR, memo=MEMO + "\nTo: bc1qattacker")),
    "done", "A3F1")
check("the VAULT refuses to send a slip the Pi would reject, rather than "
      "powering off believing it delivered", _ctl == {})

# ===========================================================================
# 4. ONE PAYLOAD PER RESULT, ENFORCED IN TWO INDEPENDENT PLACES.
# ===========================================================================
print("\n-- sealed and plaintext are mutually exclusive --")
_refused = ""
try:
    AG.load_key  # noqa: B018  (named so the check below is not vacuous)
    from types import SimpleNamespace  # noqa: F401
except Exception:                                            # noqa: BLE001
    pass


def _loadkey_with(**over):
    """Write a REAL vault keyfile and load it through the shipped loader."""
    d = Path(tempfile.mkdtemp(prefix="vkey_"))
    payload = {"role": "thinkpad", "secret": bytes(VAULT).hex(),
               "peer_public": bytes(PI.public_key).hex()}
    payload.update(over)
    p = d / "tp.key"
    p.write_text(json.dumps(P.lock_keyfile(payload, b"", role="thinkpad")))
    os.chmod(p, 0o400)
    try:
        AG.load_key(p)
        return ""
    except AG.Refused as e:
        return e.code


check("a keyfile setting BOTH plain_slip and delivery_public is refused at "
      "load, before the machine has done anything",
      _loadkey_with(plain_slip=True,
                    delivery_public="aa" * 32) == "delivery_mode_ambiguous")
check("...either one ALONE is fine", _loadkey_with(plain_slip=True) == ""
      and _loadkey_with(delivery_public="aa" * 32) == "")
check("a non-boolean plain_slip is refused rather than being truthy",
      _loadkey_with(plain_slip="yes") == "plain_slip_malformed")


def pending(job="receive_and_quote", params=None):
    return DB.Pending({"secret": bytes(PI).hex(),
                       "peer_public": bytes(VAULT.public_key).hex()},
                      job, params or {"amount_slot": 2})


def m3(pend, **over):
    body = {"job_id": pend.job_id, "challenge": "a" * 64, "status": "done",
            "handle": "A3F1", "slip": "", "plain": {}, "phase": ""}
    body.update(over)
    return P.seal(VAULT, PI.public_key, P.TAG_M3, body)


def accepted(pend, **over):
    try:
        pend.on_m3(m3(pend, **over))
        return True
    except DB.Doorbell:
        return False


# A REAL SEALED BLOB, not 568 filler characters. The first version of this
# check passed for the wrong reason and the mutation sweep caught it: "Z" * 568
# is the right LENGTH but decodes to 426 bytes rather than 424, so
# slip_is_wellformed rejected it and the record died at the slip check without
# ever reaching the both-check. Deleting the both-check left the suite green.
_REAL_BLOB = P.seal_slip(VAULT, NP.PrivateKey.generate().public_key,
                         {"b": AMOUNT, "d": BTC, "m": MEMO, "a": XMR,
                          "x": "1.2", "t": 1755900000, "h": "A3F1"})
check("the fixture blob is a genuinely well-formed slip, so the check below "
      "cannot pass by accident", P.slip_is_wellformed(_REAL_BLOB))
check("the DOORBELL refuses a result carrying both, independently of the vault",
      not accepted(pending(), plain=PLAIN, slip=_REAL_BLOB))
check("...and each one ALONE is accepted, so the refusal is about carrying "
      "two payloads and not about either of them",
      accepted(pending(), slip=_REAL_BLOB) and accepted(pending(), plain=PLAIN))

# AN UNKNOWN STATUS WORD IS REFUSED. The word is rendered into a sentence the
# operator acts on, and the closed set is what stops the vault gaining a
# free-text channel into a chat.
for _bad_phase in ("FAILED", "everything is fine, send more", "landed!",
                   "not_yet "):
    check(f"a phase of {_bad_phase!r} is refused by the doorbell",
          not accepted(pending(), phase=_bad_phase))
check("...and every word the protocol DOES have is accepted",
      all(accepted(pending(), phase=_w) for _w in P.PHASES))
check("plaintext alone is accepted", accepted(pending(), plain=PLAIN))
check("a mangled plaintext slip is refused on the vault's own channel",
      not accepted(pending(), plain=dict(PLAIN, m=MEMO + "\nbc1qevil")))
check("plaintext on a job that did not finish is refused",
      not accepted(pending(), status="failed", handle="", plain=PLAIN))

# ===========================================================================
# 5. THE STATUS WORD: A CLOSED SET, AND "NOT YET" IS NOT A FAILURE.
#
# This is the defect the operator actually hit. receive_watch distinguishes
# five outcomes, exits 0/1/130, and gs_wake_agent collapsed that to `rc != 0`
# -> "failed" -> "the vault ran it and it FAILED. Reason is on the vault."
# Money that was simply still in flight was reported as a broken vault, on a
# machine they cannot reach.
# ===========================================================================
print("\n-- a status word, from a closed set --")
for _w in P.PHASES:
    check(f"{_w!r} is a word this protocol has", P.phase_is_known(_w))
for _w in ("FAILED", "not_yet ", "landed!", "arrived", 7, None, ""):
    if _w == "":
        continue
    check(f"{_w!r} is not", not P.phase_is_known(_w))
check("every non-empty phase renders to a sentence, so none can reach a chat "
      "as a bare protocol token",
      all(w in P.PHASE_LINES for w in P.PHASES if w))

_sd = Path(tempfile.mkdtemp(prefix="status_"))
for _state, _total, _want in (("timeout", "0", "not_yet"),
                              ("timeout", "0.4", "arriving"),
                              ("funded", "1.23", "landed"),
                              ("stalled", "0.4", "short"),
                              ("not_syncing", "0", "stuck"),
                              ("interrupted", "0", "")):
    (_sd / AG.STATUS_FILE).write_text(json.dumps(
        {"state": _state, "total": _total, "unlocked": _total, "ticks": 2}))
    check(f"receive_watch {_state!r} with total={_total} -> {_want!r}",
          AG._phase_of("swap_status", _sd) == _want)

# THE SPLIT THAT MATTERS. receive_watch has no "arriving" state -- it is built
# to wait for hours, so inside a three-minute probe a payment that is on-chain
# and confirming looks identical to an empty address. `total` is the only thing
# that separates them, and telling someone "nothing yet" when their money is
# two confirmations away is the same class of wrong answer as "it FAILED".
check("...so 'nothing yet' and 'still confirming' are DIFFERENT answers",
      P.PHASE_LINES["not_yet"] != P.PHASE_LINES["arriving"])
check("no phase line calls an ordinary wait a failure",
      not any("FAIL" in v.upper() for v in P.PHASE_LINES.values()))

(_sd / AG.STATUS_FILE).write_text("{ not json")
check("an unreadable status file gives no word rather than a made-up one",
      AG._phase_of("swap_status", _sd) == "")
(_sd / AG.STATUS_FILE).write_text(json.dumps({"state": "invented"}))
check("a state word this version has never heard of gives no word",
      AG._phase_of("swap_status", _sd) == "")
check("a job that is not a status probe never carries a phase",
      AG._phase_of("receive_and_quote", _sd) == "")

# ===========================================================================
# 5b. AND THE SAME THING THROUGH _dispatch, WHICH IS WHERE IT WENT WRONG.
#
# _phase_of only translates a word. What put "the vault ran it and it FAILED"
# on the operator's phone is one line further out: receive_watch exits NON-ZERO
# for timeout, and `if rc != 0` turned that into a failed job before any word
# was ever read. Driving _phase_of alone leaves that line untested -- the
# mutation sweep proved it by deleting the branch and watching this suite stay
# green.
# ===========================================================================
print("\n-- a probe that finds nothing has NOT failed --")


def _probe(rc, hard=False, write_result=True):
    """Run _dispatch for swap_status against a child that exits `rc`."""
    d = bay()
    key = {"tor_proxy": "socks5h://127.0.0.1:9050",
           "rpc_primary": "http://127.0.0.1:18083"}

    def child(argv, env_extra, budget):
        if write_result:
            (d / AG.STATUS_FILE).write_text(json.dumps(
                {"state": "timeout", "total": "0", "unlocked": "0",
                 "ticks": 4}))
        return rc, hard

    buf = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(buf):
        return AG._dispatch("swap_status", {"handle": "A3F1"}, key, d,
                            "ZZZZ", child, "job" * 8)


_code, _status, _ = _probe(rc=1)
check("receive_watch exiting 1 because nothing arrived is NOT a failed job",
      _status == "done" and _code == "done")
_code0, _status0, _ = _probe(rc=0)
check("...and a probe that exits 0 is a done job too", _status0 == "done")
_codeh, _statush, _ = _probe(rc=1, hard=True)
check("a probe SIGKILLED past its budget IS a failure — its cleanup did not "
      "run, so this is not the ordinary case", _statush == "failed")
_coden, _statusn, _ = _probe(rc=1, write_result=False)
check("a probe that exits non-zero having written NO answer is a failure — "
      "there is nothing to report and pretending otherwise is the same lie "
      "in the other direction", _statusn == "failed")
# NON-VACUITY: the same non-zero exit on a real `watch` must still fail, or
# this branch would have quietly excused every job.
_dw = bay()
_cw, _sw, _ = AG._dispatch(
    "watch", {"handle": "A3F1"},
    {"tor_proxy": "socks5h://127.0.0.1:9050",
     "rpc_primary": "http://127.0.0.1:18083"}, _dw, "ZZZZ",
    lambda a, e, b: (1, False), "job" * 8)
check("...and a real /watch exiting non-zero DOES still fail: the excuse is "
      "scoped to the probe", _sw == "failed")

# LAST WEEK'S ANSWER MUST NOT BE REPORTED AS THIS WEEK'S.
#
# Found by driving the tool rather than by reading it. Nothing removed the
# status file between probes, and _phase_of reads whatever is on disk -- so a
# probe whose child died before writing (an RPC that will not answer, a
# SIGKILL past the budget, a wallet that never opens) reported the PREVIOUS
# probe's outcome. The worst available failure: an old "funded" becomes
# "landed and spendable, the swap is done" about money that never arrived, and
# the operator's next move is to stop watching for it.
#
# It also fed the branch above, which treats "the file exists" as proof the
# probe answered -- a stale file satisfies that for free.
_stale = bay()
(_stale / AG.STATUS_FILE).write_text(json.dumps(
    {"state": "funded", "total": "9.9", "unlocked": "9.9", "ticks": 99}))
check("a stale status file is a REAL hazard: read directly it does say landed",
      AG._phase_of("swap_status", _stale) == "landed")
_bc = io.StringIO()
import contextlib as _cl
with _cl.redirect_stdout(_bc):
    _sc, _ss, _ = AG._dispatch(
        "swap_status", {"handle": "A3F1"},
        {"tor_proxy": "socks5h://127.0.0.1:9050",
         "rpc_primary": "http://127.0.0.1:18083"}, _stale, "ZZZZ",
        lambda a, e, b: (1, False), "job" * 8)
check("...but a probe whose child writes nothing is a FAILURE, not an "
      "inherited success", _ss == "failed")
check("...and the phase reported is empty, so the chat says the probe told us "
      "nothing rather than announcing a swap that never happened",
      AG._phase_of("swap_status", _stale) == "")
check("...because the previous answer is deleted BEFORE the probe runs",
      not (_stale / AG.STATUS_FILE).exists())

# ===========================================================================
# 6. THE PROBE IS SHORT, AND THAT IS THE POINT.
# ===========================================================================
print("\n-- swap_status looks once; watch waits for hours --")
check("swap_status's result window is a small fraction of watch's",
      P.result_budget_s("swap_status") * 4 < P.result_budget_s("watch"))
check("...and its budget is minutes, not hours",
      P.JOBS["swap_status"]["budget_s"] <= 600)
_argv = AG.build_argv("swap_status", {"handle": "A3F1"},
                      {"tor_proxy": "socks5h://127.0.0.1:9050",
                       "rpc_primary": "http://127.0.0.1:18083"},
                      Path("/tmp/bay"), bundle="/tmp/bay/w.json",
                      slip="/tmp/bay/s.json", handle="A3F1")[0]
check("it asks receive_watch for a SHORT wait",
      "--timeout-min" in _argv
      and int(_argv[_argv.index("--timeout-min") + 1]) <= 5)
check("...and for a machine-readable answer, because the exit code cannot "
      "carry one", "--result-json" in _argv)
check("no XMR address, memo or amount is anywhere in that argv",
      not any(XMR in a or MEMO in a or AMOUNT in a for a in _argv))

# ===========================================================================
# 7. WHAT THE CHAT ACTUALLY RECEIVES.
# ===========================================================================
print("\n-- the messages an operator reads on a phone --")
_sent = []
pg.integrity_log = lambda *a, **k: None
pg.SLIP_RETRY_S = 0
_p = pg.Pager.__new__(pg.Pager)
_p.proxies, _p.token, _p.key, _p.args = {}, "x", {}, None
_ok = [True]
_p.send = lambda cid, t: (_sent.append(t), _ok[0])[1]


def _drive(result, job="receive_and_quote", params=None):
    _sent.clear()
    fin = type("F", (), {"result": result,
                         "outcome": staticmethod(lambda: "done")})()
    pg._DOORBELL[0] = type("D", (), {
        "run_wake": staticmethod(lambda a, k, j, p: fin)})()
    _p.poke(111, job, params or {"amount_slot": 2})
    return list(_sent)


_msgs = _drive({"status": "done", "handle": "A3F1", "slip": "",
                "plain": PLAIN, "phase": ""})
_chat = "\n".join(_msgs)
check("the real deposit address reaches the chat", BTC in _chat)
check("...the exact amount to send", AMOUNT in _chat)
check("...and the memo", MEMO in _chat)
check("THE MEMO IS ALONE IN ITS OWN MESSAGE -- tap-and-hold copies a WHOLE "
      "Telegram message, and this string must reach a wallet character for "
      "character or the swap is unroutable and the money is stranded",
      MEMO in _msgs)
check("...and the message before it says the memo needs an OP_RETURN",
      "OP_RETURN" in _chat)
check("the handle is there, so /check works later", "A3F1" in _chat)

# THE DEFAULT PATH IS UNCHANGED, and this is the check that keeps §8 true for
# every operator who never turns plaintext on.
_msgs_off = _drive({"status": "done", "handle": "A3F1", "slip": "",
                    "plain": {}, "phase": ""})
_chat_off = "\n".join(_msgs_off)
for _label, _secret in (("the deposit address", BTC), ("the memo", MEMO),
                        ("the amount", AMOUNT), ("the destination", XMR)):
    check(f"with plaintext OFF, {_label} does not reach the chat",
          _secret not in _chat_off)
# WHAT IT SAYS INSTEAD IS THE HANDLE, AND ONLY THE HANDLE.
#
# This used to assert the reply said "Read the address and memo on the vault".
# True and useless: the operator knows where their own machine is, and the
# sentence names it, in the surface this whole design assumes gets read. The
# handle is the pointer -- §8's own example of what this channel should carry
# is "depo ready · slip A3F1" and nothing more.
check("...and what it says instead is the handle, which is the pointer",
      "A3F1" in _chat_off)
check("...and it does not name the machine to go and read it on",
      "vault" not in _chat_off.lower())
# NON-VACUITY: the reply is a real reply, not an empty string that trivially
# contains no secrets and no machine name.
check("NON-VACUITY -- the plaintext-off reply is a real message",
      _chat_off.strip() and "ready" in _chat_off)

# THE STATUS REPLY.
for _w in ("not_yet", "arriving", "landed", "short", "stuck"):
    _m = _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": {},
                 "phase": _w}, job="swap_status", params={"handle": "A3F1"})
    check(f"a {_w!r} probe answers in one sentence, naming the slip",
          len(_m) == 1 and "A3F1" in _m[0]
          and P.PHASE_LINES[_w] in _m[0])
check("a 'not yet' answer never uses the word FAILED -- that sentence, for "
      "money still in flight, is the defect this whole feature exists for",
      "FAIL" not in _drive(
          {"status": "done", "handle": "A3F1", "slip": "", "plain": {},
           "phase": "not_yet"}, job="swap_status",
          params={"handle": "A3F1"})[0].upper())

# A DROPPED MEMO MUST NOT LOOK LIKE A DELIVERED ONE.
_ok[0] = False
_m = _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": PLAIN,
             "phase": ""})
_tail = "\n".join(t for t in _m if t != MEMO)
check("when the memo does not send, the operator is told NOT to pay without "
      "it", "did not get through" in _tail and "NOT send" in _tail)
check("...and it was retried before saying so", _m.count(MEMO) == 2)
_ok[0] = True

# ===========================================================================
# 8. THE PI STILL HOLDS NO KEY, AND STILL CANNOT ASK FOR ANY OF THIS.
# ===========================================================================
print("\n-- what the Pi is still not allowed to do --")
_dbsrc = open(os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read()
check("the doorbell holds no delivery key", "delivery_secret" not in _dbsrc)
check("the doorbell never parses a memo, only checks its shape",
      "XMR.XMR" not in _dbsrc)
_p2 = pending()
_p2.on_m3(m3(_p2, plain=PLAIN))
check("a relayed plaintext slip is recorded as an event the operator can see",
      "plain_carried" in _p2.events)
check("...and the doorbell kept it verbatim rather than reformatting money",
      _p2.result["plain"] == PLAIN)

_finished()
print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILURES:
    print("FAILED:", FAILURES)
    sys.exit(1)
print("ALL GREEN")
