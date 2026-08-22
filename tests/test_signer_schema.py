#!/usr/bin/env python3
"""airgap_tx_signer's plan validator, exercised against malformed plans.

WHY THIS FILE EXISTS. Coverage across all 14 suites put airgap_tx_signer at
57% with 45 abort lines never executed by any test -- and this is the component
that turns a plan file into a SIGNED, RELAYABLE transaction. Its validator is
the last gate before real money moves, and almost none of it was being run.

Driving it found a real defect: Decimal("Infinity") <= 0 is False, so an
INFINITE amount passed the positivity test and was ACCEPTED. NaN was rejected
only by accident -- comparing NaN raises InvalidOperation, which landed in the
broad except. The sibling tools had already ruled on exactly this
(exit_strategy_simulator rejects both by name; gs_common.decimal_arg now does
it at every CLI boundary), so the signer was the last place it could get
through, and the only one where the value becomes a transaction.

These are pure-function checks: no daemon, no wallet, no binaries.
"""
import importlib.machinery, importlib.util, io, os, sys, contextlib
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
ld=importlib.machinery.SourceFileLoader("airgap_tx_signer", os.path.join(REPO,"airgap_tx_signer"))
a=importlib.util.module_from_spec(importlib.util.spec_from_loader(ld.name,ld)); ld.exec_module(a)
P=F=0
def ck(n,c):
    global P,F
    if c: P+=1; print("  ok  ",n)
    else: F+=1; print("  FAIL:",n)

def rejects(plan, phase="create"):
    """True if _validate_plan refuses this plan (SystemExit), with no traceback."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            a._validate_plan(plan, phase)
        return (False, "ACCEPTED")
    except SystemExit as e:
        return (True, str(e.code)[:70])
    except Exception as e:
        return (False, f"RAW {type(e).__name__}: {e}")

GOOD = {"src":"84AAA","src_index":1,"dst":"84BBB","amt":"1.0"}
ck("a well-formed tx is accepted", rejects([GOOD])[0] is False)
ck("an empty plan is refused", rejects([])[0])

# src / src_index
for bad,label in [({**GOOD,"src":None},"src None"), ({**GOOD,"src":123},"src int"),
                  ({**GOOD,"src_index":-1},"src_index negative"),
                  ({**GOOD,"src_index":True},"src_index bool (True==1 in Python!)"),
                  ({**GOOD,"src_index":"1"},"src_index string"),
                  ({k:v for k,v in GOOD.items() if k!="src_index"},"src_index missing")]:
    r,msg=rejects([bad]); ck(f"refuses {label} ({msg[:44]})", r)

# account_index override: never silently defaulted to 0 (= PRIMARY address)
for bad,label in [({**GOOD,"account_index":-1},"account_index negative"),
                  ({**GOOD,"account_index":True},"account_index bool"),
                  ({**GOOD,"account_index":"3"},"account_index string"),
                  ({**GOOD,"account_index":1.5},"account_index float")]:
    r,msg=rejects([bad]); ck(f"refuses {label} rather than falling back to account 0", r)
ck("accepts a valid account_index override",
   rejects([{**GOOD,"account_index":7}])[0] is False)

# sweep shape
SW={"src":"84AAA","src_index":1,"dst":"84BBB","sweep":True}
ck("accepts a sweep with no amt (sweeps carry none by design)", rejects([SW])[0] is False)
for bad,label in [({**SW,"amt":"1.0"},"sweep carrying amt (would be silently ignored)"),
                  ({**SW,"destinations":[{"address":"84C","amount":"1"}]},"sweep + destinations"),
                  ({k:v for k,v in SW.items() if k!="dst"},"sweep with no dst")]:
    r,msg=rejects([bad]); ck(f"refuses {label}", r)

# destinations shape
ck("accepts valid destinations",
   rejects([{"src":"84AAA","src_index":1,"destinations":[{"address":"84B","amount":"1.0"}]}])[0] is False)
for bad,label in [([],"destinations empty list"), ("x","destinations not a list"),
                  ([{"address":123,"amount":"1"}],"dest address wrong type"),
                  ([{"address":"84B","amount":"0"}],"dest amount zero"),
                  ([{"address":"84B","amount":"-1"}],"dest amount negative"),
                  ([{"address":"84B","amount":"abc"}],"dest amount unparsable"),
                  ([{"address":"84B"}],"dest amount missing"),
                  ([{"address":"84B","amount":"NaN"}],"dest amount NaN"),
                  ([{"address":"84B","amount":"Infinity"}],"dest amount Infinity")]:
    r,msg=rejects([{"src":"84AAA","src_index":1,"destinations":bad}])
    ck(f"refuses {label} ({msg[:40]})", r)

# plain dst/amt shape
for bad,label in [({**GOOD,"amt":"0"},"amt zero"), ({**GOOD,"amt":"-1"},"amt negative"),
                  ({**GOOD,"amt":"abc"},"amt unparsable"), ({**GOOD,"amt":1.0},"amt float not str"),
                  ({**GOOD,"amt":"NaN"},"amt NaN"), ({**GOOD,"amt":"Infinity"},"amt Infinity"),
                  ({k:v for k,v in GOOD.items() if k!="dst"},"dst missing")]:
    r,msg=rejects([bad]); ck(f"refuses {label} ({msg[:40]})", r)

# sign phase is deliberately laxer about src_index but not about the rest
ck("sign phase tolerates a missing src_index (source fixed at create time)",
   rejects([{k:v for k,v in GOOD.items() if k!="src_index"}], "sign")[0] is False)
ck("sign phase STILL refuses an invalid src_index",
   rejects([{**GOOD,"src_index":-5}], "sign")[0])

# ==========================================================================
# PER-OUTPUT SPENDING IS REFUSED, AND REFUSED ON PURPOSE.
#
# sweep_single -- spend exactly ONE of several outputs on a subaddress, named
# by its key image -- is the primitive that would let a multi-output entry
# address be veiled as N one-input transactions. It cannot work here: phase 1
# runs against a VIEW-ONLY wallet, which cannot compute key images at all.
#
# It was already rejected, but only by ACCIDENT: such an entry fell through to
# the transfer branch and died on "field 'amt' missing". Follow that message,
# add `amt`, and the entry builds as an ordinary transfer_split which picks its
# own inputs and ignores the key image -- authoritative-looking and inert,
# which is the exact failure this validator refuses for sweep+amt.
#
# So the refusal is explicit now, and this is what stops it rotting back into
# an accident.
# ==========================================================================
_NO_AMT = {k: v for k, v in GOOD.items() if k != "amt"}
for bad, label in [({**GOOD, "sweep_single": True}, "a sweep_single flag"),
                   ({**GOOD, "key_image": "aa" * 32}, "a key_image field"),
                   ({**GOOD, "key_image": "aa" * 32},
                    "a key_image WITH an amt (following the old message)"),
                   ({**_NO_AMT, "key_image": "aa" * 32},
                    "a key_image and no amt"),
                   ({**GOOD, "key_image": ""}, "an EMPTY key_image")]:
    r, msg = rejects([bad])
    ck(f"refuses {label} ({msg[:44]})", r)

# The message must say WHY, or an implementer follows it into the wrong fix.
def _full_refusal(plan):
    """The WHOLE abort message. `rejects` slices to 70 chars for its labels,
    which is fine for identifying an error and useless for asserting on what
    it explains."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            a._validate_plan(plan, "create")
        return ""
    except SystemExit as e:
        return str(e.code)


_m = _full_refusal([{**GOOD, "key_image": "aa" * 32}])
ck("...and the refusal names the view-only wallet, not a missing field",
   "VIEW-ONLY" in _m or "view-only" in _m)
ck("...and warns that adding 'amt' would build an inert transfer",
   "ignores the key image" in _m)

# NON-VACUITY: the two real shapes still validate.
ck("control: an ordinary SWEEP still validates",
   rejects([{"src": "84AAA", "src_index": 1, "dst": "84BBB",
             "sweep": True}])[0] is False)
ck("control: an ordinary dst/amt transfer still validates",
   rejects([GOOD])[0] is False)


# ==========================================================================
# consume_to -- "the rest, minus the real fee, goes here".
#
# A peel names ONE fixed destination and forwards everything else to the next
# carrier. That forwarded amount cannot be in the plan: it is
# (balance - fixed - fee) and the real fee is not knowable until the
# transaction is built. Naming a fixed second amount instead is what left
# monerod's change output on every peel -- measured on a completed chain, six
# transactions at in=1/out=3/extra=131 among thirty at in=1/out=2/extra=44,
# and the six change outputs reached the exit as a near-equal cluster.
# ==========================================================================
print("\n=== consume_to: the peel's zero-change second output ===")

CONSUME = {"src": "84AAA", "src_index": 1, "account_index": 5,
           "dst": "84BBB", "amt": "1.5",
           "destinations": [{"address": "84BBB", "amount": "1.5"}],
           "consume_to": "84CCC"}
ck("a well-formed consume_to entry validates",
   rejects([CONSUME])[0] is False)
ck("consume_to must be a non-empty address",
   rejects([{**CONSUME, "consume_to": ""}])[0] is True
   and rejects([{**CONSUME, "consume_to": 7}])[0] is True)
# EXACTLY ONE fixed destination beside it, or "the rest" is ambiguous.
ck("consume_to with TWO fixed destinations is refused",
   rejects([{**CONSUME, "destinations": [
       {"address": "84BBB", "amount": "1.5"},
       {"address": "84DDD", "amount": "0.5"}]}])[0] is True)
ck("consume_to with NO destinations is refused",
   rejects([{k: v for k, v in CONSUME.items() if k != "destinations"}])[0] is True)
# Paying the same address twice would not move the peel forward.
ck("consume_to equal to the fixed destination is refused",
   rejects([{**CONSUME, "consume_to": "84BBB"}])[0] is True)
# A sweep already sends everything.
ck("consume_to on a SWEEP is refused -- one of the two is a mistake",
   rejects([{"src": "84AAA", "src_index": 1, "dst": "84BBB",
             "sweep": True, "consume_to": "84CCC"}])[0] is True)

# THE FINGERPRINT MUST COVER IT. consume_to receives nearly the whole balance
# on every peel but the last; its AMOUNT cannot be covered (it does not exist
# until build time), so the address is the whole of its identity and swapping
# it silently redirects the chain.
_fp1 = a._compute_plan_fingerprint([CONSUME])
_fp2 = a._compute_plan_fingerprint([{**CONSUME, "consume_to": "84ZZZ"}])
ck("swapping consume_to CHANGES the plan fingerprint", _fp1 != _fp2)
ck("...and removing it does too",
   _fp1 != a._compute_plan_fingerprint(
       [{k: v for k, v in CONSUME.items() if k != "consume_to"}]))
ck("...while the fingerprint is still deterministic",
   _fp1 == a._compute_plan_fingerprint([CONSUME]))

# THE BUILDER. Two passes: probe for the fee, then consume the source exactly.
print("\n=== _build_exact_consume: two passes, no change ===")


class _RPC:
    def __init__(self, unlocked, fee=2632800000, fee2=None):
        self.unlocked, self.fee, self.fee2 = unlocked, fee, fee2
        self.builds = []

    def raw_request(self, method, params=None):
        if method == "get_balance":
            return {"per_subaddress": [
                {"address_index": params["address_indices"][0],
                 "balance": self.unlocked, "unlocked_balance": self.unlocked}]}
        if method == "transfer":
            self.builds.append(params)
            f = self.fee if len(self.builds) == 1 else (self.fee2 or self.fee)
            return {"fee": f, "amount": 1, "tx_hash": "aa" * 32,
                    "unsigned_txset": "beef"}
        raise AssertionError(f"unexpected RPC {method}")


_r = _RPC(5_000_000_000_000)
_dests = [{"amount": 1_500_000_000_000, "address": "84BBB"}]
_res = a._build_exact_consume(_r, CONSUME, _dests, 5, 1, 1)
ck("it builds twice: one probe, one real", len(_r.builds) == 2)
ck("...and both are `transfer`, never transfer_split, so one peel can never "
   "become two transactions", True)   # _RPC asserts on any other method
_final = _r.builds[-1]
_sum = sum(int(d["amount"]) for d in _final["destinations"])
ck("the final build consumes the source EXACTLY (destinations + fee = balance)",
   _sum + _r.fee == _r.unlocked)
ck("...so there is no change output left to cluster or to sweep",
   _r.unlocked - _sum - _r.fee == 0)
ck("the fixed destination is paid its planned amount, untouched",
   int(_final["destinations"][0]["amount"]) == 1_500_000_000_000)
ck("the remainder goes to consume_to",
   _final["destinations"][1]["address"] == "84CCC")
ck("it spends ONLY the named subaddress",
   _final["subaddr_indices"] == [1] and _final["account_index"] == 5)
ck("it never relays -- both passes are do_not_relay",
   all(b["do_not_relay"] for b in _r.builds))
ck("the probe leaves slack, so it is the second build that is exact",
   sum(int(d["amount"]) for d in _r.builds[0]["destinations"]) < _sum)
ck("transfer's scalar fee is normalised to the list shape phase_create reads",
   _res.get("fee_list") == [_r.fee] and _res.get("amount_list") == [1])

# FAILS CLOSED, at CREATE time, before anything is signed or relayed.
def _raises(rpc, tx=CONSUME, dests=None):
    try:
        a._build_exact_consume(rpc, tx, dests or _dests, 5, 1, 1)
        return ""
    except Exception as e:                                   # noqa: BLE001
        return str(e)


ck("a carrier that cannot cover its fixed destination is refused",
   "does not cover" in _raises(_RPC(1_000_000_000_000)))
ck("a carrier with too little to probe with is refused",
   "probe" in _raises(_RPC(1_500_000_000_001)))
ck("a probe that reports no fee is refused rather than guessed",
   "no fee" in _raises(_RPC(5_000_000_000_000, fee=0)))
ck("more than one fixed destination is refused here too",
   "exactly one" in _raises(_RPC(5_000_000_000_000),
                            dests=[dict(_dests[0]), dict(_dests[0])]))
# A fee that MOVES between the passes must not silently produce change: the
# second build uses the probe's fee, so the shortfall shows up as a smaller
# forward, and the carrier account stays on the exit's list to catch it.
_rm = _RPC(5_000_000_000_000, fee=2632800000, fee2=2632800000)
a._build_exact_consume(_rm, CONSUME, _dests, 5, 1, 1)
ck("control: a stable fee is the ordinary case and consumes exactly",
   sum(int(d["amount"]) for d in _rm.builds[-1]["destinations"]) + 2632800000
   == _rm.unlocked)

# ===========================================================================
# --phase create ERASES --outdir, UNRECOVERABLY, WITH NO CONFIRMATION.
#
# secure_delete_tree overwrites every file before unlinking it -- that is the
# point of using it rather than rmtree, because a previous attempt's
# signed/tx_*.signed is a RELAYABLE transaction. But it ran on whatever
# --outdir named, so a typo, a stale path, or `--outdir ~/Documents` destroyed
# every file in that directory beyond recovery. It is reachable in ordinary
# use: it sits AFTER the Tor and RPC checks succeed, which on the online
# machine that runs --phase create is the normal case, and there is no
# confirmation prompt anywhere in this tool.
#
# The re-run into our own staging directory has to stay frictionless, so the
# test is "does this hold anything we did not put there".
# ===========================================================================
import tempfile as _tf, pathlib as _pl


def _mkdir_with(names):
    d = _tf.mkdtemp(prefix="stgtest_")
    for n in names:
        q = _pl.Path(d) / n
        if n.endswith("/"):
            q.mkdir()
        else:
            q.write_text("x")
    return d


ck("a staging dir this tool created is still wipeable, so re-running "
   "--phase create is not made painful",
   a._staging_strays(_mkdir_with(
       ["tx_0.unsigned", "tx_1.unsigned", "tx_11.unsigned",
        "unsigned_manifest.json", "outputs_export.hex",
        "accounts_count.txt", "signed/"])) == [])
ck("...and so is an empty directory, which is what a fresh --outdir is",
   a._staging_strays(_mkdir_with([])) == [])
for _junk in ("tax_return.pdf", "wallet.keys", "photos/", ".ssh/"):
    ck(f"a directory holding {_junk} is refused, not erased",
       a._staging_strays(_mkdir_with([_junk])) == [_junk.rstrip("/")])
ck("ONE stray among our own files is still a refusal — the dangerous case is "
   "a directory that looks half like ours",
   a._staging_strays(_mkdir_with(["notes.txt", "tx_0.unsigned"])) == ["notes.txt"])
for _near in ("tx_.unsigned", "tx_1.unsigned.bak", "tx_01.unsignedX",
              "Signed/", "unsigned_manifest.json.tmp"):
    ck(f"near-miss {_near} does not pass as one of ours",
       a._staging_strays(_mkdir_with([_near])) == [_near.rstrip("/")])
ck("an unreadable directory counts as a stray, because guessing wrong here "
   "erases somebody's files",
   a._staging_strays("/proc/1/root/nope") != [])
_src = open(os.path.join(REPO, "airgap_tx_signer")).read()
# THE CALL SITE, not the substring. `_staging_strays(outdir)` also occurs in
# `def _staging_strays(outdir) -> list:`, so checking for the bare substring
# matched the DEFINITION and passed with the call deleted -- the mutation sweep
# reported SURVIVED on exactly that, which is what it is for.
def _pos(hay, needle):
    """Index or -1. str.index RAISES, and a test that dies scores NO-RESULT in
    the mutation sweep -- which proves nothing about the check. Fail with our
    own words instead."""
    return hay.find(needle)


_CALL = "_ours = _staging_strays(outdir)"
ck("the guard is actually wired in front of the wipe, not merely defined",
   _pos(_src, _CALL) >= 0
   and _pos(_src, _CALL) < _pos(_src, "secure_delete_tree(outdir)"))
ck("...and its refusal is reachable, i.e. the result is actually branched on",
   _pos(_src, "if _ours:") >= 0
   and _pos(_src, _CALL) < _pos(_src, "if _ours:"))
ck("...and the refusal says the erase is unrecoverable",
   "cannot be recovered" in _src)

print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
