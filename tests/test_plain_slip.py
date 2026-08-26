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
import ast as _ast_ps
import os
import re
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
         "peer_public": bytes(PI.public_key).hex(), "deposit_in_chat": True}
    k.update(over)
    return k


BAY = bay()

# ===========================================================================
# 1. OFF BY DEFAULT, AND THE SWITCH IS ON THE VAULT.
# ===========================================================================
print("\n-- off unless the vault's keyfile says otherwise --")
check("with plain_slip unset, nothing is built",
      AG.plain_slip_for_chat(vkey(deposit_in_chat=None), BAY, "done", "A3F1") == {})
check("with plain_slip false, nothing is built",
      AG.plain_slip_for_chat(vkey(deposit_in_chat=False), BAY, "done", "A3F1") == {})
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


def _writes_field(source, field):
    """Does this file ever SET `field`? Assignment, dict key or CLI flag.

    CODE, NOT PROSE, and this check learned that the hard way twice over.
    It banned the STRING anywhere in the file, so it caught the comments
    explaining why the Pi may not set it -- and then caught a legitimate READ,
    when the welcome started describing the delivery mode the vault actually
    chose instead of asserting one. Reading the vault's decision is the
    opposite of overriding it; what must not exist is a way to SET it here.
    """
    tree = _ast_ps.parse(source)
    for n in _ast_ps.walk(tree):
        if isinstance(n, _ast_ps.Dict):
            for k in n.keys:
                if isinstance(k, _ast_ps.Constant) and k.value == field:
                    return True
        if isinstance(n, (_ast_ps.Assign, _ast_ps.AnnAssign)):
            for t in ([n.target] if isinstance(n, _ast_ps.AnnAssign)
                      else n.targets):
                if (isinstance(t, _ast_ps.Subscript)
                        and isinstance(t.slice, _ast_ps.Constant)
                        and t.slice.value == field):
                    return True
        if isinstance(n, _ast_ps.Call) and getattr(
                n.func, "attr", "") == "add_argument":
            for a in n.args:
                if isinstance(a, _ast_ps.Constant) and isinstance(a.value, str) \
                        and a.value.strip("-").replace("-", "_") == field:
                    return True
    return False


check("the pager never writes plain_slip: the switch is not on this box",
      not _writes_field(_pgsrc, "deposit_in_chat"))
check("...nor does the doorbell, which is the other thing on that card",
      not _writes_field(
          open(os.path.join(REPO, "gs_doorbell"), encoding="utf-8").read(),
          "deposit_in_chat"))
# NON-VACUITY: the detector really does find a writer, so "no writer" is not
# "no detector". gs_wake_keys is the one tool that has one.
check("NON-VACUITY -- the same check DOES find the vault-side writer",
      _writes_field(
          open(os.path.join(REPO, "gs_wake_keys"), encoding="utf-8").read(),
          "deposit_in_chat"))
# ...AND THE PAGER MAY STILL READ IT. The welcome's deposit line describes
# where the address turns up, which is a statement about this exact field: a
# fixed sentence there was wrong for every install that set it.
check("...and the pager DOES read it, so the welcome describes the mode the "
      "vault actually chose rather than asserting one",
      '.get("deposit_in_chat")' in _pgsrc)

# ===========================================================================
# 2. EXACTLY THE ALLOWED FIELDS, AND dest_xmr AND ts ARE NOT AMONG THEM.
# ===========================================================================
print("\n-- exactly five fields, by allowlist --")
check("the built slip carries exactly the declared field set",
      set(PLAIN) == set(P.PLAIN_FIELDS))
check("the destination address does not travel at all -- and now neither "
      "does the memo that named it",
      XMR not in set(PLAIN.values()) and "m" not in PLAIN)
check("...and neither does the quote timestamp",
      not any(str(PAIR["ts"]) == v for v in PLAIN.values()))
# ---- AND THE MEMO IS THE ONE FIELD THAT NO LONGER TRAVELS --------------
#
# It is the only field in the quoted pair that names ANYBODY. The deposit
# address is a shared pooled vault paid by everyone swapping the same pair;
# the amount is already in the transcript because the confirm echoes it; the
# handle is four hex characters the vault drew. The memo NAMES THE DESTINATION
# MONERO ADDRESS IN FULL, so sending it put a permanent link between this chat
# and one Monero address into a surface this design assumes somebody else
# reads.
#
# It also closes the one way this channel could LOSE the deposit. The memo is
# the whole binding between the Bitcoin and the Monero, so whoever held the
# bot token could leave the address correct, substitute their own memo and
# take the payment -- irreversibly, with nothing the phone could check.
# OPSEC_SETUP.md argued no scheme rescues that. Not sending one does: there is
# nothing in the chat left to replace.
check("the amount and the deposit address DO travel -- they are the payment",
      PLAIN["b"] == AMOUNT and PLAIN["d"] == BTC)
check("...and the memo does NOT, on the wire or anywhere after it",
      "m" not in PLAIN and MEMO not in json.dumps(PLAIN)
      and "m" not in P.PLAIN_FIELDS)
check("...and a record that still carries one is REFUSED by the doorbell's "
      "own shape check, so a vault from before this cannot push one through",
      not P.plain_slip_is_wellformed(dict(PLAIN, m=MEMO)))
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
        ({k: v for k, v in PLAIN.items() if k != "d"}, "a missing field"),
        (dict(PLAIN, d=""), "an empty field"),
        (dict(PLAIN, d="x" * 500), "an overlong field"),
        (dict(PLAIN, b=5), "a non-string"),
        (dict(PLAIN, d=BTC + "\nTo address:    bc1qattacker"), "a newline"),
        (dict(PLAIN, d=BTC + "\x1b[2K"), "an escape sequence"),
        (dict(PLAIN, h="A3F1\x7f"), "a DEL"),
        ("not a dict", "a non-object"),
        (None, "None")):
    check(f"...{_why} is refused", not P.plain_slip_is_wellformed(_bad))

# THE VAULT CHECKS IT TOO, where the operator is present to be told.
_ctl = AG.plain_slip_for_chat(
    vkey(), bay(slip_pairs=dict(PAIR, deposit=BTC + "\nTo: bc1qattacker")),
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
      _loadkey_with(deposit_in_chat=True,
                    delivery_public="aa" * 32) == "delivery_mode_ambiguous")
check("...either one ALONE is fine", _loadkey_with(deposit_in_chat=True) == ""
      and _loadkey_with(delivery_public="aa" * 32) == "")
check("a non-boolean plain_slip is refused rather than being truthy",
      _loadkey_with(deposit_in_chat="yes") == "deposit_in_chat_malformed")
# ---- AN OLD KEYFILE FAILS LOUDLY RATHER THAN LOSING THE MODE ------------
#
# The field was called plain_slip. Reading the new name with .get() would turn
# an old keyfile's `true` into a silent `false`: the vault stops sending the
# deposit details, the chat goes back to "read them on the machine", and
# nothing anywhere says why. On this setting the operator finds out by having
# nothing to pay.
_old_refused = _loadkey_with(plain_slip=True)
check("a keyfile still carrying plain_slip is REFUSED, not silently read as "
      "the mode being off",
      _old_refused == "keyfile_field_renamed")
check("...and the same is true when it carried false, because the point is "
      "that the operator is told, not which way it was set",
      _loadkey_with(plain_slip=False) == "keyfile_field_renamed")
check("NON-VACUITY -- the new name is accepted",
      _loadkey_with(deposit_in_chat=True) == "")


def pending(job="receive_and_quote", params=None):
    return DB.Pending({"secret": bytes(PI).hex(),
                       "peer_public": bytes(VAULT.public_key).hex()},
                      job, params or {"amount_sat": 5000000})


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

# "LANDED" IS ABOUT THE SWAP, AND IT HAS TO SAY WHICH STEP IT MEANS.
#
# This line was shortened from "landed and spendable. The swap is done." to
# "...Done." while stripping prose out of the chat surface -- and the edit
# changed which NOUN the sentence was about. The swap has landed; the MIX has
# not run and cannot be run from the phone (gs_wake_agent refuses every job
# while a removable device is attached, because the mix needs the spend USB).
# So "Done" tells the operator the job finished while their money is sitting
# un-mixed on the receive wallet, on the one surface they check most.
#
# A mutation sweep found nothing testing it: the shortened line SURVIVED.
_landed = P.PHASE_LINES["landed"]
check("the 'landed' line names WHICH step finished, not just that one did",
      "swap" in _landed.lower())
check("...and does not read as the whole job being over",
      not _landed.rstrip().lower().endswith("done.")
      or "swap" in _landed.lower())
# NON-VACUITY: the line is a real sentence that still says the money arrived,
# so this is not passing on an empty or unrelated string.
# THE WORD IS "CONFIRMED", NOT "landed". A status line that opens with the
# jargon of the step it describes tells the reader nothing they can act on;
# what they want to know is whether the money is theirs to spend yet. The
# check is on the two FACTS, not on either spelling -- a check pinned to the
# word would have to be rewritten every time the sentence is, which is how a
# non-vacuity check stops being about anything.
check("NON-VACUITY -- it still tells the operator the money is there",
      "the money is here" in _landed.lower()
      and "spendable" in _landed.lower())
# AND NO PHASE LINE NAMES THE OPERATOR'S HARDWARE. These are sent verbatim to
# the chat by gs_telegram_pager, so they are chat text living in a file that
# does not look like chat text -- which is how two of them kept saying "check
# it on the vault" after every reply in the pager itself had been stripped.
for _k, _v in P.PHASE_LINES.items():
    check(f"phase line {_k!r} names no machine",
          not any(w in _v.lower()
                  for w in ("vault", "thinkpad", "keyfile", "pi ")))

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
#: A REAL PAIRING SECRET. Every label the chat sees is a MAC over (chat,
#: handle) keyed from one, and a Pager without one is refused at startup.
_KEY = {"secret": "11" * 32}
_p.proxies, _p.token, _p.key, _p.args = {}, "x", dict(_KEY), None
_p.handle_owner = {}
_p.handle_job = {}
_p._chain = None
_p._chain_leg = 0
_p._status_at = {}
_p.spenders = 1
_ok = [True]
_p.send = lambda cid, t, buttons=None: (_sent.append(t), _ok[0])[1]


def _drive(result, job="receive_and_quote", params=None):
    _sent.clear()
    fin = type("F", (), {"result": result,
                         "outcome": staticmethod(lambda: "done")})()
    pg._DOORBELL[0] = type("D", (), {
        "run_wake": staticmethod(
            lambda a, k, j, p, on_event=None: fin)})()
    _p.poke(111, job, params or {"amount_sat": 5000000})
    return list(_sent)


_msgs = _drive({"status": "done", "handle": "A3F1", "slip": "",
                "plain": PLAIN, "phase": ""})
_chat = "\n".join(_msgs)
check("the real deposit address reaches the chat", BTC in _chat)
check("...the exact amount to send", AMOUNT in _chat)
check("...and NOT the memo, which is the only field that named anybody",
      MEMO not in _chat and "XMR.XMR" not in _chat and "=:" not in _chat)
check("...so the deposit is ONE message now, not two",
      len([t for t in _msgs if t.strip()]) == 1)
check("...and it says the one thing that would lose the money, which is "
      "paying it from a phone wallet",
      "phone wallet" in _chat and "machine" in _chat)
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
#
# "ready" WAS THE NEEDLE AND IS GONE ON PURPOSE. "depo ready · slip A3F1" said
# ready for WHAT, to an operator who then had nothing to pay to -- the address
# and the memo are on the machine and nothing here carries them. On the
# topology this is deployed on, one laptop and one Pi, that is the only case:
# a delivery key wants a THIRD machine, the one you send the BTC from, and
# sealing to a key held on the machine that sealed it buys nothing. It does
# not need to travel either -- the memo goes in an OP_RETURN, which no phone
# wallet can compose, so the operator has to be at that desktop wallet to pay
# at all. The reply says where it is and what paying needs.
check("NON-VACUITY -- the plaintext-off reply is a real message",
      _chat_off.strip() and "quoted" in _chat_off)
check("...and it says where the address actually is",
      "ON THE MACHINE" in _chat_off)
check("...and that paying needs a desktop wallet, which is the part that "
      "stops an operator trying from the phone",
      "desktop wallet" in _chat_off and "OP_RETURN" in _chat_off)

# ===========================================================================
#  A PHASE OUTRANKS THE OUTCOME
# ===========================================================================
#
# receive_watch exits non-zero when its window runs out, so a /watch whose
# money was still confirming after 110 minutes reported "watch: failed." --
# money in flight, called a failure of the machine, after the vault had already
# powered off. Every reasonable reaction to that message is wrong.
#
# The phase was being computed and carried and then dropped, at three separate
# gates: _dispatch excused a non-zero rc only for swap_status, report_back sent
# `phase if done else ""`, and the pager's phase branch was nested inside
# `if out == "done"`. Fixing any one alone changes nothing, which is why this
# drives the OUTCOME and the PHASE together rather than either on its own.
print("\n-- a watch that saw something is not a failed watch --")


def _drive_out(result, outcome, job="watch", chat_id=111):
    """Like _drive, but the OUTCOME is what the caller says.

    _drive stubs outcome() to "done" unconditionally, which is right for the
    slip cases it was written for and makes it structurally unable to see this
    defect: the bug only exists when the outcome is NOT done.

    `chat_id` because a NEGATIVE one is a group, and a group is a broadcast
    surface -- which is a different question from what the outcome was.
    """
    _sent.clear()
    fin = type("F", (), {"result": result,
                         "outcome": staticmethod(lambda: outcome)})()
    pg._DOORBELL[0] = type("D", (), {
        "run_wake": staticmethod(
            lambda a, k, j, p, on_event=None: fin)})()
    _p.poke(chat_id, job, {"handle": "A3F1"})
    return list(_sent)


def _res(status, phase, plain=None):
    return {"status": status, "handle": "A3F1", "slip": "",
            "plain": plain or {}, "phase": phase}


for _ph in ("not_yet", "arriving", "short", "stuck"):
    _m = _drive_out(_res("failed", _ph), "failed")
    check(f"watch/{_ph}: a non-done outcome carrying a phase reports the "
          f"phase, not a failure",
          len(_m) == 1 and P.PHASE_LINES[_ph] in _m[0]
          and "failed" not in _m[0].lower())
    check(f"watch/{_ph}: ...and still names the handle, so /check works later",
          "A3F1" in _m[0])
# ...AND THE RULE IS ABOUT THE JOBS THAT WATCH, NOT ABOUT EVERY JOB.
#
# "The phase is the honest answer and the outcome is the return code" holds
# for a probe, where "your money has not arrived yet" is the answer and the
# non-zero exit is the noise. It INVERTS on a withdrawal. Every phase word
# presupposes a run that finished, so a failed withdrawal carrying one
# answered
#
#     B7C2: that one is done and there is more here. Run /withdraw again
#           for the next.
#
# about a run that moved nothing: a false success on the one job that spends,
# followed by an instruction to spend again after a failure ("too deep for
# the balance") that would fail identically. The failure branch already says
# that in the operator's own words.
#
# gs_wake_agent._phase_of will not produce this today -- its withdraw branch
# returns "" unless the status is "done". That is the first defence; this is
# the second, and the doorbell is why one is not enough: it validates the
# phase WORD against the closed table and does not tie it to the status, so a
# version skew or a compromised vault lands exactly here.
_wf = _drive_out(_res("failed", "more_left"), "failed", job="withdraw")
check("withdraw: a FAILED run carrying a phase is not reported as a finished "
      "one", len(_wf) == 1 and "failed" in _wf[0].lower())
check("withdraw: ...and does not tell the operator to spend again over a "
      "spend that did not happen",
      "that one is done" not in _wf[0].lower()
      and "more here" not in _wf[0].lower())
check("withdraw: ...and arms no next leg off a run that moved nothing",
      _p._chain is None)
# NON-VACUITY: the watching jobs still get the original behaviour, so this
# scoped the rule rather than deleting it.
_wn = _drive_out(_res("failed", "not_yet"), "failed", job="swap_status")
check("withdraw: NON-VACUITY -- a swap_status timeout is still answered with "
      "its phase and not called a failure",
      P.PHASE_LINES["not_yet"] in _wn[0] and "failed" not in _wn[0].lower())

# NON-VACUITY 1: a genuine failure with NOTHING seen still says failed. A fix
# that reported every outcome as a phase would pass every check above.
_mf = _drive_out(_res("failed", ""), "failed")
check("watch: NON-VACUITY -- a failure that saw nothing still says failed",
      _mf == ["watch: failed."])
_mr = _drive_out(_res("refused", ""), "refused")
check("watch: NON-VACUITY -- and a refusal still says refused",
      len(_mr) == 1 and _mr[0].startswith("watch: refused"))
# A REFUSAL IS THE ONE ENDING WHERE "NOTHING RAN" IS CERTAIN. Refused is
# raised in preflight and in the dispatcher's own checks, always BEFORE the
# first child process starts -- a failure inside a child reports "failed" --
# so the message can say so without guessing.
check("watch: ...and says it never started, which is the fact a refusal "
      "carries and a failure does not",
      "before it started" in _mr[0])

# ---- A FAILED WITHDRAWAL SAYS THE ONE THING THE OPERATOR CAN ACT ON -----
#
# "withdraw: failed." was the entire message, delivered after a boot and 5-20
# minutes of mandatory jitter, and it left no next move. The commonest cause
# is the one the depth menu exists for: the mix minimum rises with the hop
# count, so a balance that cannot fund 20 hops can often fund 3, and
# GhostSpiral refuses at stage 4 with nothing spent -- on the vault's console,
# which is the machine nobody is standing at.
_mw = _drive_out(_res("failed", ""), "failed", job="withdraw")
check("withdraw: a failure points at the depth, which is the one thing the "
      "operator can change",
      len(_mw) == 1 and "too deep" in _mw[0])
# AND IT MUST NOT IMPLY THE MONEY IS SAFE. "failed" means the run STARTED and
# did not finish, and a run can stop while planning (nothing spent) or
# part-way through (something spent). This box has never been told a balance
# and cannot tell those apart, so it says both are live rather than picking
# the comfortable one -- the reassuring reading is the expensive one to get
# wrong.
check("withdraw: ...and does NOT imply nothing was spent, because a run that "
      "started can stop after it has moved money",
      "may already have moved" in _mw[0]
      and "nothing was spent" not in _mw[0].lower())
check("withdraw: ...and says to check the balance before running it again",
      "CHECK THE BALANCE" in _mw[0])
check("withdraw: ...and still says it failed, rather than burying that",
      "failed" in _mw[0])
# A HINT, NOT A DIAGNOSIS. This box has never been told a balance and must not
# claim to know why the run died -- so the sentence is hedged and carries no
# figure. A confident cause would be an invented one.
check("withdraw: ...and does not claim to know that WAS the cause",
      "may be" in _mw[0])
check("withdraw: ...and states no balance, because this box has none",
      not re.search(r"\d+\.\d", _mw[0]))
# NON-VACUITY: the advice is specific to the job that HAS a depth. Offering it
# on a deposit would be a confident answer to a question nobody asked.
for _j in ("watch", "receive_and_quote", "swap_status"):
    _mo = _drive_out(_res("failed", ""), "failed", job=_j)
    check(f"{_j}: NON-VACUITY -- no depth advice on a job that has no depth",
          "shallower" not in _mo[0])
# AND A REFUSAL IS NOT A FAILURE. A withdrawal the vault refused outright
# (allow_withdraw off, deadman too short) has nothing to do with the balance.
_mwr = _drive_out(_res("refused", ""), "refused", job="withdraw")
check("withdraw: NON-VACUITY -- a refusal gets no depth advice either",
      len(_mwr) == 1 and "shallower" not in _mwr[0]
      and "too deep" not in _mwr[0])
# ...AND IT IS THE ONE WITHDRAWAL ENDING THAT CAN SAY THE MONEY IS UNTOUCHED.
check("withdraw: a refusal says nothing was spent, which is certain here and "
      "is not certain on a failure",
      "nothing was spent" in _mwr[0])

# ---- THE TWO SILENT ENDINGS, WHICH MEANT OPPOSITE THINGS AND READ ALIKE -
#
# A withdrawal that produces no result record ends one of two ways, and the
# difference is whether running it again spends the same money twice:
#
#   expired_uncollected   THIS job was never handed over, so this attempt ran
#                         nothing and spent nothing.
#   collected_no_result   the job WAS handed over and nothing came back for up
#                         to 16.5 h. It may have finished and lost the reply,
#                         or stopped part-way. Both are live.
#
# They used to read "not collected. Nothing was handed over." and "no result.
# Check before trying again." -- the second of which invites the retry that is
# the whole danger.
#
# AND THE FIRST ONE OVERREACHED, which is what these three checks pinned. It
# said "NOTHING WAS SPENT — your funds are exactly where they were", and the
# second half is a claim about the WALLET that this box has no basis for: it
# has never been told a balance, and it keeps no record that a wake is in
# flight (`busy` is process memory, and the shipped unit has
# Restart=on-failure). Pager dies mid-withdrawal, comes back, vault still
# mixing, next magic packet lands on a machine already up and nothing collects
# it -- and the operator reads that their funds have not moved, followed by an
# invitation to try again, on the one job that spends.
#
# So the checks now pin the scope rather than the reassurance. The `refused`
# ending is where "nothing ran" is CERTAIN, and it says so; certainty there
# comes from the vault having said it, and here nobody said anything.
_mu = _drive_out(_res("expired_uncollected", ""), "expired_uncollected",
                 job="withdraw")
check("withdraw: never picked up says THIS attempt spent nothing",
      "THIS attempt" in _mu[0] and "spent nothing" in _mu[0])
check("withdraw: ...and makes no claim about where the funds are",
      "exactly where they were" not in _mu[0]
      and "NOTHING WAS SPENT" not in _mu[0])
check("withdraw: ...and says it keeps no record of an earlier attempt, "
      "instead of inviting a retry it cannot vouch for",
      "no record" in _mu[0].lower()
      and "check the balance" in _mu[0].lower())

_mn = _drive_out(_res("collected_no_result", ""), "collected_no_result",
                 job="withdraw")
check("withdraw: picked-up-then-silent does NOT claim the money is safe",
      "NOTHING WAS SPENT" not in _mn[0]
      and "exactly where they were" not in _mn[0])
check("withdraw: ...and says outright that it does not know",
      "do not know" in _mn[0].lower())
check("withdraw: ...and names both readings rather than picking one",
      "lost the reply" in _mn[0] and "part-way" in _mn[0])
# THE ONE THAT MATTERS: it must not invite a retry, because a second run could
# spend what the first one already sent.
check("withdraw: ...and tells the operator NOT to run it again until they "
      "have checked, naming the cost of not checking",
      "Do not run" in _mn[0] and "spend what the first one already sent"
      in _mn[0])
# NON-VACUITY, both ways: the two endings are different messages, and the
# non-spending jobs get neither lecture.
check("withdraw: NON-VACUITY -- the two silent endings are different text",
      _mu[0] != _mn[0])
for _j in ("watch", "receive_and_quote", "swap_status"):
    _o1 = _drive_out(_res("expired_uncollected", ""), "expired_uncollected",
                     job=_j)
    _o2 = _drive_out(_res("collected_no_result", ""), "collected_no_result",
                     job=_j)
    check(f"{_j}: no spend-safety language on a job that does not spend",
          "NOTHING WAS SPENT" not in _o1[0]
          and "already sent" not in _o2[0])

# ---- A GROUP IS A BROADCAST SURFACE, AND A PAYLOAD IS NOT FOR ONE ------
#
# main() allows a negative --chat-id when --user-id is given, and its refusal
# text OFFERS --user-id as the fix. --user-id is inbound only: it gates who
# may DRIVE the bot. Every send() posts to chat_id, so with plain_slip set in
# the vault's keyfile the whole deposit slip went to the room. Driven with
# --chat-id -1001999999999 --user-id 555: the amount, the deposit address and
# a memo naming the destination XMR address in full, to everyone in it.
_GROUP = -1001999999999
# THE FIXTURE CARRIED A MEMO FIELD THE WIRE NO LONGER HAS, so the memo
# assertion below tested nothing: plain_lines does not render "m" whatever is
# in the dict, and plain_slip_is_wellformed REFUSES a record carrying one, so
# such a record cannot reach this code path at all. A check that cannot fail
# would have gone on passing if the memo came back.
#
# The fixture is now the real shape, and the memo guarantee is asserted where
# it is actually enforced -- at the gate -- just below.
_PL_OK = {"b": "0.05000000", "d": "bc1qdeposit0000000000000000000000",
          "x": "1.2345", "h": "A3F1"}
_PL_MEMO = dict(_PL_OK, m="=:XMR.XMR:" + "8" + "d" * 94 + ":0/1/0")
check("plain: the wire REFUSES a deposit record carrying a memo, which is "
      "what stops one reaching the chat at all",
      P.plain_slip_is_wellformed(_PL_OK)
      and not P.plain_slip_is_wellformed(_PL_MEMO))
check("plain: ...and the renderer would not print one even if a record "
      "smuggled it past, so the two halves do not rest on each other",
      not any("=:XMR.XMR:" in _l or "8" + "d" * 94 in _l
              for _l in P.plain_lines(_PL_MEMO, label="A3F1-1234AB")))
_gp = _drive_out(_res("done", "", plain=dict(_PL_OK)), "done",
                 job="receive_and_quote", chat_id=_GROUP)
_gtext = "\n".join(_gp)
check("group: the deposit address is NOT posted into a room",
      "bc1qdeposit" not in _gtext)
check("group: ...nor the amount", "0.05000000" not in _gtext)
check("group: ...and the operator is told why, rather than left waiting",
      "this is a group" in _gtext and "everyone in it" in _gtext)
check("group: ...and told where the details are and how to get them properly",
      "at the machine" in _gtext and "one-to-one" in _gtext)
check("group: ...and still gets the handle, so /check works",
      "A3F1" in _gtext)
# NON-VACUITY: the SAME slip in a one-to-one chat is still delivered in full.
# The keyfile decision is real and this must not quietly cancel it.
_pp = _drive_out(_res("done", "", plain={
    "b": "0.05000000", "d": "bc1qdeposit0000000000000000000000",
    "x": "1.2345", "h": "A3F1"}), "done", job="receive_and_quote")
_ptext = "\n".join(_pp)
check("group: NON-VACUITY -- a one-to-one chat still gets the deposit",
      "bc1qdeposit" in _ptext and "0.05000000" in _ptext)
check("group: ...in one message, since the memo that needed its own is gone",
      len([t for t in _pp if t.strip()]) == 1)

# ---- A FINISHED SPEND IS NOT A READY DEPOSIT ---------------------------
#
# With no slip and no plain, a COMPLETED withdrawal fell through to the
# generic line and reported "withdraw ready · slip A3F1" -- after up to
# sixteen hours, about money that has already left the wallet. Both halves
# were wrong, and every suite was green through it.
#
#   * "ready" is deposit vocabulary for something that has not happened, used
#     on the one job where the irreversible thing HAS. This repo caught the
#     same error once already, in PHASE_LINES, where "Done." "changed which
#     noun it was about".
#   * The handle is a PHANTOM. gs_wake_agent._dispatch writes handles[] only
#     for receive_and_quote and receive_new, so no withdrawal label is ever
#     registered and /check or /wait on the one printed here answers
#     unknown_handle. It named a slip that does not exist and invited an
#     action that fails.
_mws = _drive_out(_res("done", ""), "done", job="withdraw")
check("withdraw: a finished spend says SENT, not 'ready'",
      len(_mws) == 1 and "sent" in _mws[0].lower()
      and "ready" not in _mws[0].lower())
check("withdraw: ...and advertises no slip handle, because none was registered",
      "slip" not in _mws[0].lower() and "A3F1" not in _mws[0])
# THE SECOND SENTENCE IS THE ONE THAT SAVES MONEY. _funded_entry deliberately
# takes the LARGEST SINGLE unlocked output rather than summing -- summing
# would spend inputs from several subaddresses in one transaction, which is
# permanent public proof they share an owner. So a withdrawal moves ONE pile,
# and nothing said so: an operator with money in three places had two thirds
# of it left behind with no indication.
# "one address", NOT "one". The first version of this check tested for the
# bare word and the mutation sweep found it: replacing "This moves ONE address
# at a time" with "It moves everything at once" left the check green, because
# "more than one place" further down the same message still contains "one".
# A substring test on a word that common is a check that cannot fail.
#
# AND "ONE ADDRESS" WAS ITSELF THE AMBIGUITY. /withdraw takes up to
# MAX_WAKE_EXIT_DESTS destinations by reply and the confirm calls them "the
# addresses you just sent" -- so "this moves ONE address at a time" reads as
# one of THOSE, telling an operator who gave five that four were skipped. The
# next thing they do is run it again, which is a second real spend. The "one"
# is at the source end, and the message has to say which end each is.
# SAID FROM NOWHERE. "sent -- all of it, to the addresses you gave" was
# written as a reply to a question. This lands up to sixteen hours after the
# confirm, on a phone, possibly after a reboot, and "the addresses you gave"
# then reads as the bot assuming a context the reader has to scroll for.
check("withdraw: ...and says what happened without leaning on a conversation "
      "the reader may not have in front of them",
      "sent" in _mws[0].lower()
      and "you gave" not in _mws[0].lower())
# AND IT SAYS WHICH LEG, WITHOUT PROMISING A TOTAL IT CANNOT KNOW. This read
# "withdraw 1/6: sent", where 6 is MAX_CHAIN_LEGS -- the cap that stops a
# runaway chain, not a count of what is coming. A run ends when the wallet has
# no funded entry left, so the operator who got three legs was reading the
# third as the run stopping halfway.
check("withdraw: ...and numbers the leg without inventing a total",
      re.search(r"withdraw 1 sent", _mws[0])
      and f"/{pg.Pager.MAX_CHAIN_LEGS}" not in _mws[0])
# THE SCOPE IS NAMED, AND THE CHAIN DECIDES WHICH SENTENCE FOLLOWS.
#
# A run empties ONE arrival -- _funded_entry takes the largest single unlocked
# output and never sums, because summing is permanent public proof the inputs
# share an owner. That is not negotiable. What was wrong is that the operator
# was then left to notice and drive the rest by hand with no idea how many
# were left, so being paid a third of what they put in read as the tool
# shortchanging them. The vault answers that now (phase "more_left") and the
# pager keeps going.
check("withdraw: with nothing left, it says so plainly",
      "wallet empty" in _mws[0].lower())
_mwm = _drive_out(_res("done", "more_left"), "done", job="withdraw")
check("withdraw: with more left, it says another is starting rather than "
      "leaving the operator to notice",
      "next one starting" in _mwm[0].lower())
check("withdraw: ...and gives the reason they go separately, which is why it "
      "is not a limitation to be fixed later",
      "all yours" in _mwm[0].lower())
check("withdraw: NON-VACUITY -- the two endings really are different text",
      _mws[0] != _mwm[0])
check("withdraw: ...and states no balance and no count, because this box has "
      "neither", not re.search(r"\d+\.\d", _mws[0]))
# NON-VACUITY: a DEPOSIT still takes the ordinary path, so the withdrawal
# branch is a branch and not a rewrite of every completion message.
_md2 = _drive_out(_res("done", ""), "done", job="receive_and_quote")
check("receive_and_quote: NON-VACUITY -- a deposit still takes its own path "
      "and carries its label",
      len(_md2) == 1 and "A3F1" in _md2[0] and "quoted" in _md2[0])

# ...AND receive_new IS GONE ENTIRELY. It minted a Monero subaddress to be
# paid into directly -- an entry point for somebody who already held XMR --
# and nothing in this repository swaps XMR to BTC, so it could take money in
# and had no way to say where. Both slip builders returned empty on it by
# construction, so the command whose whole purpose was to hand over an address
# delivered none on every configuration; both watching jobs refused its handle,
# so /check and /wait on one spent a wake to be told no. The job, the command,
# the button and the welcome line all went with it.
check("receive_new: the job is not on the wire any more",
      "receive_new" not in P.JOBS)
# ...AND THE OLD SPELLING IS ANSWERED WITH SILENCE. It used to explain itself
# -- "nothing here swaps Monero to Bitcoin, so it could take money in and
# never say where" -- which is a description of the toolchain's SHAPE in the
# one surface every other reply is scrubbed of, and a POST from the Pi for a
# command that does not exist.
check("receive_new: ...and the pager says nothing at all to the old spelling",
      all(pg.parse_command(_c)[2] == pg.IGNORE
          for _c in ("/address", "/addr", "/receive", "/recv")))
check("receive_new: ...and what it does not say is the toolchain's shape",
      not any("swaps" in str(pg.parse_command(_c)[2]).lower()
              for _c in ("/address", "/addr", "/receive", "/recv")))

# ONE RETRY ON THE COMPLETION NOTICE, and this is the only notification that a
# spend finished -- at the end of a job that ran up to sixteen hours and moved
# real money. send() does not retry on its own; it returns whether it landed.
# A single Tor circuit failing at the wrong second would leave "working" as the
# last thing the operator ever heard, which is exactly what the poll-failure
# fix in updates() exists to prevent. Saving the result from a closed socket
# and then losing it to a dropped POST would be absurd.
_saved_sleep2 = pg.time.sleep
_tries = []


def _drive_withdraw_send(ok_on):
    """Complete a withdrawal whose send succeeds on attempt `ok_on`."""
    _tries.clear()
    _saved_send = _p.send
    try:
        _p.send = lambda cid, t, buttons=None: (_tries.append(t),
                                                len(_tries) >= ok_on)[1]
        _drive_out(_res("done", ""), "done", job="withdraw")
    finally:
        _p.send = _saved_send
    return len(_tries)


try:
    pg.time.sleep = lambda _s: None
    _n_ok = _drive_withdraw_send(1)
    _n_retry = _drive_withdraw_send(2)
    _n_dead = _drive_withdraw_send(99)
finally:
    pg.time.sleep = _saved_sleep2

check("withdraw: a completion notice that lands is sent once", _n_ok == 1)
check("withdraw: ...one that drops is retried, so a single bad circuit does "
      "not swallow the only word that a spend finished", _n_retry == 2)
# BOUNDED. This still holds `busy`; a retry storm against a dead circuit would
# hold it for the rate limit's whole window.
check("withdraw: ...and it is ONE retry, not a loop, because this holds the "
      "one-job lock while it runs", _n_dead == 2)
# NON-VACUITY 2: a DONE outcome still takes the ordinary path.
_md = _drive_out(_res("done", "landed"), "done")
check("watch: NON-VACUITY -- a done outcome still reports its phase the way "
      "it always did", len(_md) == 1 and P.PHASE_LINES["landed"] in _md[0])
# NON-VACUITY 3: the same drive on a job with no phase is untouched.
_mq = _drive_out(_res("done", ""), "done", job="receive_and_quote")
check("watch: NON-VACUITY -- a quote with no phase still reports its handle",
      any("A3F1" in t for t in _mq))

# AND THE AGENT MUST NOT THROW THE PHASE AWAY BEFORE IT GETS HERE. Three gates,
# each of which alone makes the fix inert.
_AG_SRC = open(os.path.join(REPO, "gs_wake_agent"), encoding="utf-8").read()
check("watch/agent: a non-zero rc is excused for BOTH watching jobs",
      'if rc != 0 and job in ("swap_status", "watch") and not hard:' in _AG_SRC)
check("watch/agent: the stale status file is cleared for both, or a watch "
      "reports the answer a probe left behind hours earlier",
      'if job in ("swap_status", "watch"):' in _AG_SRC)
check("watch/agent: and the phase travels with a non-done status",
      '"phase": phase}' in _AG_SRC and '"phase": phase if done' not in _AG_SRC)
# NON-VACUITY: the OTHER fields are still gated on done -- a job that did not
# finish must not hand over a slip.
check("watch/agent: NON-VACUITY -- slip and plain are still done-only, so "
      "this loosened one field and not the envelope",
      '"slip": slip if done else ""' in _AG_SRC
      and '"plain": plain if done else {}' in _AG_SRC)


# THE STATUS REPLY.
for _w in ("not_yet", "arriving", "landed", "short", "stuck"):
    _m = _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": {},
                 "phase": _w}, job="swap_status", params={"handle": "A3F1"})
    check(f"a {_w!r} probe answers in one sentence, naming the slip",
          len(_m) == 1 and "A3F1" in _m[0]
          and P.PHASE_LINES[_w] in _m[0])
# ...AND IT CARRIES THE NEXT STEP, which is the one reply in this bot that
# used to carry none.
#
# A status answer is what waiting LOOKS LIKE -- it is the message an operator
# sees more often than any other -- and it ended with a full stop and an empty
# keyboard. "landed and spendable" left somebody who had just been told their
# money was there with no way to be paid short of knowing the word /withdraw;
# "nothing on the address yet" left them retyping a four-character hex label
# off the screen above to ask again. _handle_buttons exists for exactly that
# defect and did not cover this surface.
_btns = []
_saved_send_pb = _p.send
_p.send = lambda cid, t, buttons=None: (_sent.append(t),
                                        _btns.append(buttons), _ok[0])[2]
try:
    # THE ASK-AGAIN BUTTONS CARRY THE CONFIRMATION NUMBER, not the handle:
    # Telegram keyboards never expire, and a button holding a bare handle
    # stops working the moment this process restarts and forgets who owned it.
    _WCN = pg.confirmation_number(_p.key, 111, "A3F1")
    # ONE BUTTON WHERE THERE WERE TWO. "Wait for it" sat beside "Has it
    # arrived?" and asked the reader to choose between them with nothing on
    # the labels to choose ON: waiting is what happens either way, and the
    # only real difference -- three minutes of looking against a hundred and
    # ten, the long one holding every other command -- was on neither. /wait
    # is still a typed command for an operator who knows they want it.
    for _w, _want in ((("not_yet", f"c:{_WCN}"), ("arriving", f"c:{_WCN}"),
                       ("landed", "m:send"), ("short", "m:help"),
                       ("stuck", "m:help"))):
        _btns.clear()
        _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": {},
                "phase": _w}, job="swap_status", params={"handle": "A3F1"})
        _flat = [d for _row in (_btns[-1] or []) for _l, d in _row]
        check(f"a {_w!r} answer offers the step that follows it ({_want})",
              _want in _flat)
    # THE TWO WAITING ANSWERS OFFER THE LABEL, NOT A BARE COMMAND: asking
    # again has to carry the handle or the wake is spent on unknown_handle.
    _btns.clear()
    _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": {},
            "phase": "not_yet"}, job="swap_status", params={"handle": "A3F1"})
    check("...and the ask-again buttons carry the label, so nothing has to be "
          "retyped",
          all("A3F1" in d for _row in (_btns[-1] or []) for _l, d in _row))
    # ONE BUTTON, AND IT IS THE MENU'S OWN. Falling through to the full menu
    # is not a small regression here: the menu LEADS with "Bitcoin in", so the
    # reply that says the money arrived would point first at putting more in.
    # And the button is read off the menu rather than spelt again, because two
    # spellings of one button is how one of them stops matching what it does --
    # this bot already shipped a "What this does" that opened a settings table.
    check("...and it is exactly one button, not the whole menu, whose first "
          "entry would be the way to put MORE money in",
          _p._phase_buttons("landed", "A3F1", "swap_status")
          == [[pg._menu_button("m:send")]])
    check("...and that button is the menu's own row, label and all, so the "
          "two cannot drift apart",
          pg._menu_button("m:send") in
          [_b for _row in pg.MENU_BUTTONS for _b in _row]
          and "pays you" in pg._menu_button("m:send")[0])
    # NON-VACUITY: 'landed' does NOT offer ask-again -- the money is there and
    # a third probe is a wasted wake.
    _btns.clear()
    _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": {},
            "phase": "landed"}, job="swap_status", params={"handle": "A3F1"})
    check("...and a landed answer does not offer to check again, which would "
          "spend a wake to be told the same thing",
          not any(d.startswith(("c:", "w:"))
                  for _row in (_btns[-1] or []) for _l, d in _row))
    # EVERY BUTTON IS A REAL ONE. A status reply is built from a word the
    # vault chose, so a phase this version has never heard of must still
    # produce a keyboard that works rather than a dead tap.
    for _w in ("not_yet", "arriving", "landed", "short", "stuck", "more_left",
               "a-phase-from-a-newer-vault", ""):
        _bs = _p._phase_buttons(_w, "A3F1", "swap_status")
        check(f"phase {_w!r}: every button it offers maps to a real command",
              bool(_bs) and all(pg.parse_callback(d)[1] == ""
                                for _row in _bs for _l, d in _row))
finally:
    _p.send = _saved_send_pb
    _sent.clear()

check("a 'not yet' answer never uses the word FAILED -- that sentence, for "
      "money still in flight, is the defect this whole feature exists for",
      "FAIL" not in _drive(
          {"status": "done", "handle": "A3F1", "slip": "", "plain": {},
           "phase": "not_yet"}, job="swap_status",
          params={"handle": "A3F1"})[0].upper())

# THE SECOND MESSAGE IS GONE, AND SO IS EVERYTHING THAT GUARDED IT.
#
# The memo used to be sent on its own, with a retry and a "do NOT send without
# it -- unroutable" fallback, because it had to reach a wallet character for
# character. None of that is needed once the memo does not travel, and leaving
# it in place would be a retry loop around a message that no longer exists.
_ok[0] = False
_m = _drive({"status": "done", "handle": "A3F1", "slip": "", "plain": PLAIN,
             "phase": ""})
check("a deposit that does not send is ONE undelivered message, not a memo "
      "retry storm", len(_m) == 1)
_ok[0] = True
_PG_SRC_M = open(os.path.join(REPO, "gs_telegram_pager"),
                 encoding="utf-8").read()
check("...and the memo retry path is gone from the source with it",
      "memo_undelivered" not in _PG_SRC_M
      and "Do NOT send without it" not in _PG_SRC_M)

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
