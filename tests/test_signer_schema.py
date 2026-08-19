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
print(f"\n{P} passed, {F} failed"); sys.exit(1 if F else 0)
