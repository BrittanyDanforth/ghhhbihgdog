#!/usr/bin/env python3
"""Executable tests for the swap/receive money path.

thor_swap_preparer and create_receive_wallet decide WHERE money lands: the swap
memo is the only thing routing the XMR to you, and the receive subaddress is
what gets pasted into that memo. Both are driven here through their real code
paths with only the network stubbed. Confirmed to FAIL against the pre-fix build.
"""
import sys, os, json, tempfile, types, importlib.util, importlib.machinery
from decimal import Decimal

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def load(name):
    path = os.path.join(REPO, name)
    loader = importlib.machinery.SourceFileLoader(name.replace(".py", ""), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


PASS = 0; FAIL = 0; FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1; FAILURES.append(name); print(f"  FAIL: {name}")


_scratch = tempfile.mkdtemp(prefix="gs_swap_")
os.chdir(_scratch)
thor = load("thor_swap_preparer")
crw = load("create_receive_wallet")

# A real-format mainnet Monero subaddress (starts with 8, 95 chars).
DEST = "8" + "A" + "1" * 93
OTHER = "8" + "B" + "2" * 93
THIRD = "8" + "0" + "3" * 93
# A real mainnet bech32 P2WPKH address (valid BIP173 checksum).
DEPOSIT = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


# ==========================================================================
# thor_swap_preparer: the memo is the only binding between the swap and you
# ==========================================================================
def test_memo_binding_logic():
    good = f"=:XMR.XMR:{DEST}:0/1/0:t:0"
    check("plain memo naming the destination binds",
          thor._memo_binds_destination(good, DEST))
    check("long-form SWAP memo binds",
          thor._memo_binds_destination(f"SWAP:XMR.XMR:{DEST}:0", DEST))
    check("hex-encoded OP_RETURN memo binds",
          thor._memo_binds_destination(good.encode().hex(), DEST))
    check("0x-prefixed hex memo binds",
          thor._memo_binds_destination("0x" + good.encode().hex(), DEST))

    check("memo naming a DIFFERENT address does not bind",
          not thor._memo_binds_destination(f"=:XMR.XMR:{OTHER}:0/1/0", DEST))
    check("empty memo does not bind", not thor._memo_binds_destination("", DEST))
    check("memo missing the address does not bind",
          not thor._memo_binds_destination("=:XMR.XMR::0/1/0", DEST))
    check("non-hex garbage does not bind",
          not thor._memo_binds_destination("zzzz", DEST))
    check("hex that decodes to another address does not bind",
          not thor._memo_binds_destination(
              f"=:XMR.XMR:{OTHER}:0".encode().hex(), DEST))

    # EVERY NEGATIVE CASE ABOVE VARIES THE DESTINATION, so the destination
    # check alone satisfies all of them and the other two fields are untested.
    # Proven by mutation: deleting the ASSET check entirely left this file, and
    # every other suite, green. The project's own audit recorded noticing this
    # ("my 'wrong asset' case used the attacker's address -- the destination
    # check rejected it either way") and the case was never added.
    #
    # These hold the destination CORRECT and vary one other field, which is the
    # only shape that can test that field. A memo with our address but the
    # wrong asset is not harmless: THORChain reads the fields positionally, so
    # it describes a swap that does not deliver XMR to us.
    for _asset in ("BTC.BTC", "ETH.ETH", "BTC", "XMRX", "DOGE.DOGE", ""):
        check(f"memo with OUR address but asset {_asset!r} does not bind",
              not thor._memo_binds_destination(
                  f"=:{_asset}:{DEST}:0/1/0", DEST))
    check("...while the same memo on the XMR chain does bind (so the checks "
          "above are about the ASSET, not the shape)",
          thor._memo_binds_destination(f"=:XMR.XMR:{DEST}:0/1/0", DEST))
    check("a bare XMR asset still binds (THORChain accepts both spellings)",
          thor._memo_binds_destination(f"=:XMR:{DEST}:0/1/0", DEST))

    for _op in ("ADD", "WITHDRAW", "BOND", "LOAN+", "", "x"):
        check(f"memo with OUR address but op {_op!r} does not bind",
              not thor._memo_binds_destination(
                  f"{_op}:XMR.XMR:{DEST}:0/1/0", DEST))

    # The hex path must re-parse the FIELDS, not substring-match the decoded
    # text -- decoding and then searching would reopen the original hole by a
    # different door.
    check("hex decoding to our address with the wrong ASSET does not bind",
          not thor._memo_binds_destination(
              f"=:BTC.BTC:{DEST}:0/1/0".encode().hex(), DEST))
    check("hex decoding to our address with a non-swap OP does not bind",
          not thor._memo_binds_destination(
              f"ADD:XMR.XMR:{DEST}:0/1/0".encode().hex(), DEST))
    check("...and a memo that merely CONTAINS our address does not bind",
          not thor._memo_binds_destination(
              f"=:XMR.XMR:{OTHER}:0/1/0:{DEST}:10", DEST))


class ThorRun:
    """Drive thor_swap_preparer.main() with the network stubbed."""

    def __init__(self, memo, expected="1.0", deposit=DEPOSIT, rate="0.005"):
        self.mod = load("thor_swap_preparer")
        m = self.mod
        for stub in ("verify_tor", "newnym", "secure_delay",
                     "install_signal_handlers", "integrity_log"):
            setattr(m, stub, lambda *a, **k: None)
        m.validate_proxy = lambda p: {"http": p, "https": p}
        m.shutdown_requested = lambda: False
        m._validate_xmr_addr = lambda a: None      # skip the monero dependency
        m.safe_get = lambda url, proxy=None: {"monero": {"btc": rate}}
        m.safe_post = lambda url, payload, proxy=None: {
            "routes": [{"transaction": {"depositAddress": deposit, "memo": memo},
                        "expectedOutput": expected}]}

    def run(self, dest=DEST, amount="0.005", extra=()):
        out = os.path.join(_scratch, "pairs.json")
        if os.path.exists(out):
            os.remove(out)
        sys.argv = ["thor_swap_preparer", "--amounts", amount, "--dests", dest,
                    "--tor-proxy", "socks5h://127.0.0.1:9050",
                    "--outfile", out, *extra]
        import io
        real, sys.stdout = sys.stdout, io.StringIO()
        try:
            self.mod.main()
            code, msg = 0, ""
        except SystemExit as e:
            code, msg = (e.code if isinstance(e.code, int) else 1), str(e.code or "")
        except Exception as e:
            code, msg = 70, f"CRASH: {type(e).__name__}: {e}"
        finally:
            text = sys.stdout.getvalue(); sys.stdout = real
        return code, msg, text, out


def test_memo_naming_another_address_is_refused():
    r = ThorRun(memo=f"=:XMR.XMR:{OTHER}:0/1/0")
    code, msg, text, out = r.run()
    check("a memo routing to someone else is refused", code != 0)
    check("refusal explains the memo is the routing", "memo" in msg.lower())
    check("no sender instructions are printed", "Send exactly" not in text)
    check("no pairs file is written", not os.path.exists(out))


def test_missing_memo_is_refused():
    r = ThorRun(memo="")
    code, msg, text, out = r.run()
    check("a quote with no memo is refused", code != 0)
    check("no sender instructions are printed for a memo-less quote",
          "Send exactly" not in text)
    check("sender is never told a memo is optional", "none required" not in text)


def test_good_memo_produces_instructions():
    r = ThorRun(memo=f"=:XMR.XMR:{DEST}:0/1/0:t:0")
    code, msg, text, out = r.run()
    check("a correctly-bound quote succeeds", code == 0)
    check("sender instructions are printed", "Send exactly" in text)
    check("the memo is shown to the sender", DEST in text)
    pairs = json.load(open(out))
    check("the pair is saved", len(pairs) == 1 and pairs[0]["dest_xmr"] == DEST)
    check("the saved bundle is 0600", oct(os.stat(out).st_mode)[-3:] == "600")


def test_unbound_memo_override_works_but_warns():
    r = ThorRun(memo=f"=:XMR.XMR:{OTHER}:0/1/0")
    code, msg, text, out = r.run(extra=("--allow-unbound-memo",))
    check("--allow-unbound-memo proceeds", code == 0)
    check("--allow-unbound-memo warns loudly", "VERIFY IT BY HAND" in text)


# ==========================================================================
# thor_swap_preparer: slippage must have a hard stop, not only a warning
# ==========================================================================
def test_catastrophic_slippage_aborts():
    # oracle says 0.005 BTC / 0.005 BTC-per-XMR = 1.0 XMR; quote offers 0.2.
    r = ThorRun(memo=f"=:XMR.XMR:{DEST}:0", expected="0.2", rate="0.005")
    code, msg, text, out = r.run()
    check("an 80%-off quote is refused", code != 0)
    check("the refusal cites --max-slippage", "max-slippage" in msg)
    check("no sender instructions for a bad-rate quote", "Send exactly" not in text)


def test_small_deviation_only_warns():
    r = ThorRun(memo=f"=:XMR.XMR:{DEST}:0", expected="0.93", rate="0.005")
    code, msg, text, out = r.run()
    check("a 7% deviation still completes", code == 0)
    check("a 7% deviation warns", "deviates" in text)


def test_max_slippage_is_tunable():
    r = ThorRun(memo=f"=:XMR.XMR:{DEST}:0", expected="0.2", rate="0.005")
    code, _, _, _ = r.run(extra=("--max-slippage", "0.9"))
    check("--max-slippage raises the limit", code == 0)
    r2 = ThorRun(memo=f"=:XMR.XMR:{DEST}:0", expected="0.2", rate="0.005")
    code2, _, _, _ = r2.run(extra=("--max-slippage", "0"))
    check("--max-slippage 0 is rejected as nonsense", code2 != 0)


def test_oracle_failure_disables_the_check_rather_than_faking_it():
    r = ThorRun(memo=f"=:XMR.XMR:{DEST}:0", expected="0.2")

    def boom(url, proxy=None):
        raise RuntimeError("oracle down")
    r.mod.safe_get = boom
    code, msg, text, out = r.run()
    check("an unreachable oracle does not invent a baseline", code == 0)
    check("an unreachable oracle says the check is disabled",
          "DISABLED" in text)


# ==========================================================================
# create_receive_wallet: the address must be confirmed by the wallet itself
# ==========================================================================
class FakeWallet:
    def __init__(self, readback=None, validate=None, raise_on=None):
        self.readback = readback
        self.validate = validate
        self.raise_on = raise_on or set()

    def raw_request(self, method, params):
        if method in self.raise_on:
            raise RuntimeError("method not found")
        if method == "get_address":
            return self.readback
        if method == "validate_address":
            return self.validate
        raise AssertionError(method)


def _verify(wallet, addr=DEST, idx=7):
    old = crw.integrity_log
    crw.integrity_log = lambda *a, **k: None
    import io
    real, sys.stdout = sys.stdout, io.StringIO()
    try:
        crw.verify_receive_address(wallet, addr, idx)
        return 0, "", sys.stdout.getvalue()
    except SystemExit as e:
        return 1, str(e.code or ""), sys.stdout.getvalue()
    finally:
        sys.stdout = real
        crw.integrity_log = old


OK_VALIDATE = {"valid": True, "integrated": False, "subaddress": True,
               "nettype": "mainnet"}


def test_receive_address_readback_mismatch_is_refused():
    w = FakeWallet(readback={"addresses": [{"address": OTHER, "address_index": 7}]},
                   validate=OK_VALIDATE)
    code, msg, _ = _verify(w)
    check("a substituted address is refused", code != 0)
    check("the mismatch is named", "MISMATCH" in msg)


def test_receive_address_matching_readback_passes():
    w = FakeWallet(readback={"addresses": [{"address": DEST, "address_index": 7}]},
                   validate=OK_VALIDATE)
    code, msg, text = _verify(w)
    check("a wallet-confirmed address passes", code == 0)
    check("the verification is reported", "verified" in text)


def test_receive_address_missing_index_is_refused():
    w = FakeWallet(readback={"addresses": []}, validate=OK_VALIDATE)
    code, msg, _ = _verify(w)
    check("an index the wallet does not know is refused", code != 0)


def test_receive_address_wrong_index_is_refused():
    """The wallet answering about a DIFFERENT index must not be accepted."""
    w = FakeWallet(readback={"addresses": [{"address": DEST, "address_index": 3}]},
                   validate=OK_VALIDATE)
    code, msg, _ = _verify(w)
    check("a read-back for the wrong index is refused", code != 0)


def test_receive_address_primary_or_integrated_is_refused():
    w = FakeWallet(readback={"addresses": [{"address": DEST, "address_index": 7}]},
                   validate={"valid": True, "integrated": False,
                             "subaddress": False, "nettype": "mainnet"})
    code, msg, _ = _verify(w)
    check("a non-subaddress is refused", code != 0 and "subaddress" in msg)

    w2 = FakeWallet(readback={"addresses": [{"address": DEST, "address_index": 7}]},
                    validate={"valid": True, "integrated": True,
                              "subaddress": True, "nettype": "mainnet"})
    code2, msg2, _ = _verify(w2)
    check("an integrated address is refused", code2 != 0 and "INTEGRATED" in msg2)

    w3 = FakeWallet(readback={"addresses": [{"address": DEST, "address_index": 7}]},
                    validate={"valid": False})
    code3, _, _ = _verify(w3)
    check("an address the wallet calls invalid is refused", code3 != 0)


def test_readback_failure_is_fail_closed():
    w = FakeWallet(raise_on={"get_address"})
    code, msg, _ = _verify(w)
    check("an unreadable read-back is fail-CLOSED", code != 0)


def test_missing_validate_address_degrades_honestly():
    """Old wallet-rpc builds lack validate_address. Ownership was still proven,
    so this must continue -- but must not claim a full check ran."""
    w = FakeWallet(readback={"addresses": [{"address": DEST, "address_index": 7}]},
                   raise_on={"validate_address"})
    code, msg, text = _verify(w)
    check("a missing validate_address does not block", code == 0)
    check("the reduced assurance is stated", "read-back only" in text)


def test_dest_from_receive_bundle():
    """The swap destination decides where the money lands, irreversibly. Taking
    it from the bundle the wallet already verified beats retyping 95 characters
    -- but only if the bundle itself is checked, or an unrelated JSON with an
    'address' key could become someone's payment destination."""
    import json as _json
    d = tempfile.mkdtemp(prefix="gs_bundle_")

    def w(name, obj):
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            _json.dump(obj, fh)
        return p

    good = w("good.json", {"schema": "gs_receive_wallet_v1", "address": DEST,
                           "account_index": 0, "subaddress_index": 3})
    check("the destination is read out of a valid receive bundle",
          thor._dest_from_bundle(good) == DEST)

    def refuses(path):
        try:
            thor._dest_from_bundle(path)
            return False
        except SystemExit:
            return True

    # An unrelated JSON that happens to carry an address must NOT be usable as
    # a payment destination just because the key name matches.
    check("a JSON with an address but no schema is refused",
          refuses(w("nos.json", {"address": DEST})))
    check("a JSON with the WRONG schema is refused",
          refuses(w("bad.json", {"schema": "thor_pairs_v1", "address": DEST})))
    check("a bundle with no address is refused",
          refuses(w("noa.json", {"schema": "gs_receive_wallet_v1"})))
    check("a non-object bundle is refused", refuses(w("lst.json", [DEST])))
    check("a missing file is refused", refuses(os.path.join(d, "nope.json")))

    # The address must be scrubbed in the persistent chain, not written whole.
    src = open(os.path.join(REPO, "thor_swap_preparer")).read()
    check("the bundle destination is scrubbed in the integrity log",
          "dest_from_bundle:{scrub_address(addr)}" in src)
    # Ambiguity about where money goes must be refused, never silently resolved.
    check("--dests and --dest-from-receive-wallet together are refused",
          "not both" in src)


def test_one_fresh_destination_per_swap():
    """A batch must never route two swaps to the SAME XMR address.

    The old resolver was
        args.dests = [_dest_from_bundle(bundle)] * len(args.amounts)
    so splitting a swap into three amounts sent three quotes naming one
    address. That hands the aggregator a link between three BTC payments --
    the very link splitting the amount was meant to avoid -- and it silently
    defeats the NEWNYM rotation between quotes, because a fresh Tor circuit
    cannot disguise three request bodies carrying the same unique
    95-character identifier.
    """
    from decimal import Decimal as D
    A, B, C = DEST, OTHER, THIRD

    def resolve(amounts, dests=None, bundles=None):
        try:
            return thor.resolve_destinations([D(x) for x in amounts],
                                             dests or [], bundles or [])
        except SystemExit as e:
            return "REFUSED:" + str(e.code or "")

    # the normal single swap still works, unchanged
    check("one amount, one dest resolves", resolve(["0.01"], dests=[A]) == [A])
    check("three amounts, three DISTINCT dests resolve",
          resolve(["0.01", "0.02", "0.03"], dests=[A, B, C]) == [A, B, C])

    # the defect
    r = resolve(["0.01", "0.02"], dests=[A, A])
    check("two swaps to the SAME address are REFUSED", str(r).startswith("REFUSED"))
    check("...the refusal names both swap positions",
          "0 and 1" in str(r))
    check("...and explains the aggregator keeps the link",
          "no amount of mixing afterwards retracts" in str(r))
    check("...and points at the circuit rotation it defeats",
          "rotation" in str(r))
    check("...and says how to fix it",
          "--count 2" in str(r))

    # a duplicate anywhere in a longer batch, not just adjacent
    check("a duplicate at the END of a batch is caught",
          str(resolve(["1", "2", "3"], dests=[A, B, A])).startswith("REFUSED"))

    # length mismatches
    check("more amounts than dests is refused",
          str(resolve(["1", "2"], dests=[A])).startswith("REFUSED"))
    check("both input forms at once is refused",
          str(resolve(["1"], dests=[A], bundles=["x.json"])).startswith("REFUSED"))


def test_one_bundle_cannot_serve_many_swaps():
    """--dest-from-receive-wallet takes ONE BUNDLE PER AMOUNT.

    This is the path the tool's own guidance recommends, so it is the path
    that actually produced the reuse: one bundle multiplied across N amounts.
    """
    import json as _json
    d = tempfile.mkdtemp(prefix="gs_bundle_n_")

    def bundle(name, addr):
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            _json.dump({"schema": "gs_receive_wallet_v1", "address": addr,
                        "account_index": 1, "subaddress_index": 1}, fh)
        return p

    from decimal import Decimal as D
    b1, b2 = bundle("a.json", DEST), bundle("b.json", OTHER)

    def resolve(amounts, bundles):
        try:
            return thor.resolve_destinations([D(x) for x in amounts], [], bundles)
        except SystemExit as e:
            return "REFUSED:" + str(e.code or "")

    check("one bundle for one amount still works (the normal case)",
          resolve(["0.01"], [b1]) == [DEST])
    check("two bundles for two amounts works",
          resolve(["0.01", "0.02"], [b1, b2]) == [DEST, OTHER])

    r = resolve(["0.01", "0.02", "0.03"], [b1])
    check("ONE bundle for THREE amounts is REFUSED — no silent reuse",
          str(r).startswith("REFUSED"))
    check("...and tells the operator to mint three",
          "--count 3" in str(r))

    # two bundles that happen to hold the SAME address must also be refused:
    # the invariant is on the resolved addresses, not on the file names
    b3 = bundle("c.json", DEST)
    check("two DIFFERENT bundle files holding the same address are refused",
          str(resolve(["0.01", "0.02"], [b1, b3])).startswith("REFUSED"))


def test_next_steps_do_not_teach_an_argv_leak():
    """create_receive_wallet's own guidance used to print

        python3 thor_swap_preparer --amounts <BTC_AMOUNT> --dests <address>

    putting the swap amount AND the 95-char XMR destination on a command line
    that /proc/<pid>/cmdline (mode 444) exposes to every local account. Both
    tools already had the non-leaking path -- GS_SWAP_AMOUNTS and
    --dest-from-receive-wallet -- and the text recommended neither.
    """
    src = open(os.path.join(REPO, "create_receive_wallet")).read()

    # Scan what is PRINTED, not the whole file. print_next_steps' docstring
    # quotes the old leaking command verbatim to explain why it was removed,
    # and a plain grep cannot tell a documented counter-example from live
    # guidance -- it flagged the explanation as the defect.
    import ast as _ast
    _fn = next(n for n in _ast.walk(_ast.parse(src))
               if isinstance(n, _ast.FunctionDef) and n.name == "print_next_steps")
    printed = []
    for _n in _ast.walk(_fn):
        if (isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name)
                and _n.func.id == "print"):
            for _a in _n.args:
                for _c in _ast.walk(_a):
                    if isinstance(_c, _ast.Constant) and isinstance(_c.value, str):
                        printed.append(_c.value)
    printed_text = "\n".join(printed)
    check("the printed guidance is non-trivial (the scan actually found it)",
          len(printed) > 20)
    check("next steps no longer put --dests on the printed command line",
          "--dests" not in printed_text)
    check("next steps no longer put --amounts on the printed command line",
          "--amounts" not in printed_text)
    check("next steps use the env var for the amount",
          "GS_SWAP_AMOUNTS=" in printed_text)
    check("next steps use the bundle path for the destination",
          "--dest-from-receive-wallet" in printed_text)

    # and the disclosure the operator needs BEFORE handing the address over
    for phrase, why in [
        ("does not hide the link", "Tor hides who asked, not the linkage"),
        ("do not reuse", "the address is burned by the swap"),
        ("public", "the memo must not be posted anywhere indexed"),
        ("view key", "how a view key actually leaks"),
    ]:
        check(f"next steps state: {why}", phrase.lower() in src.lower())

    # thor says it too, at the moment the memo is on screen
    tsrc = open(os.path.join(REPO, "thor_swap_preparer")).read()
    check("thor's sender instructions state the disclosure",
          "WHAT THE SWAP DISCLOSES" in tsrc)
    check("thor tells the operator not to reuse the destination",
          "Do not reuse the destination" in tsrc)


def test_count_mints_independent_receives():
    """--count N must give N addresses in N DIFFERENT accounts.

    Same account would share a change sink, which is the whole reason a
    receive gets its own account: change lands on the SPENDING account's
    subaddress 0, so two receives in one account pool their leftovers on one
    address.
    """
    made = []

    class FakeRPC:
        accounts = [0]
        def __init__(self):
            self.next_acct = 0
        def raw_request(self, m, p=None):
            if m == "create_account":
                self.next_acct += 1
                return {"account_index": self.next_acct}
            if m == "get_address":
                idx = p["address_index"][0]
                return {"addresses": [{"address_index": idx,
                                       "address": made[-1][0]}]}
            if m == "validate_address":
                return {"valid": True, "integrated": False,
                        "subaddress": True, "nettype": "mainnet"}
            return {}
        def new_subaddress_indexed(self, account_index, label=""):
            addr = f"8{account_index}" + "A" * 93
            made.append((addr, account_index))
            return addr, 1

    outdir = tempfile.mkdtemp(prefix="gs_count_")
    crw.newnym = lambda *a, **k: None
    crw.integrity_log = lambda *a, **k: None
    args = types.SimpleNamespace(account=None, label="", rpc="http://127.0.0.1:18083",
                                 output_dir=outdir, count=3)
    rpc = FakeRPC()
    import io
    real, sys.stdout = sys.stdout, io.StringIO()
    try:
        bundles = [crw.mint_one_receive(rpc, args) for _ in range(3)]
    finally:
        sys.stdout = real

    accts = [a for _, a in made]
    check("--count 3 created three receives", len(bundles) == 3)
    check("...each in its OWN account (no shared change sink)",
          len(set(accts)) == 3, )
    check("...none of them in account 0 (the wallet PRIMARY)",
          0 not in accts)
    addrs = [b[0] for b in bundles]
    check("...with three DISTINCT addresses", len(set(addrs)) == 3)
    files = [b[1] for b in bundles]
    check("...and three distinct bundle files", len(set(map(str, files))) == 3)
    for f in files:
        check(f"bundle {os.path.basename(str(f))} is owner-only 0600",
              (os.stat(f).st_mode & 0o777) == 0o600)

    # the resolver must accept exactly what --count produced
    from decimal import Decimal as D
    got = thor.resolve_destinations([D("1"), D("2"), D("3")], [],
                                    [str(f) for f in files])
    check("thor accepts the three bundles --count wrote", got == addrs)


def test_swap_dest_must_not_be_the_exit_address():
    """THE SWAP MEMO MUST NOT NAME THE ADDRESS THE MIX EXITS TO.

    resolve_destinations enforced ONE FRESH ADDRESS PER SWAP and validated the
    form, and a well-formed fresh address that happens to be the operator's
    FINAL destination passed both. The memo goes into a Bitcoin OP_RETURN --
    public, permanent, and carrying the 95-character XMR address in full -- so
    that combination prints the answer the entire pipeline exists to withhold.
    Nothing downstream retracts it: the entry veil, the per-output accounts,
    the peel chain and the exit's own refusal to sweep ENTRY all become
    decoration.

    GS_EXIT_TO is where GhostSpiral keeps the exit destination (deliberately,
    to keep it off argv), so it is what this can compare against.

    Every check here manipulates the REAL environment around the REAL
    resolver, and the controls below are the point: the guard must fire on a
    collision and must NOT fire otherwise, or it would refuse every ordinary
    run.
    """
    from decimal import Decimal as D
    import json as _json

    _saved = os.environ.get("GS_EXIT_TO")

    def resolve(amounts, dests=None, bundles=None, exit_to=None):
        if exit_to is None:
            os.environ.pop("GS_EXIT_TO", None)
        else:
            os.environ["GS_EXIT_TO"] = exit_to
        try:
            return thor.resolve_destinations([D(x) for x in amounts],
                                             dests or [], bundles or [])
        except SystemExit as e:
            return "REFUSED:" + str(e.code or "")
        finally:
            if _saved is None:
                os.environ.pop("GS_EXIT_TO", None)
            else:
                os.environ["GS_EXIT_TO"] = _saved

    try:
        # -- the defect ---------------------------------------------------
        r = resolve(["0.01"], dests=[DEST], exit_to=DEST)
        check("a swap delivering to the GS_EXIT_TO address is REFUSED",
              str(r).startswith("REFUSED"))
        check("...and says WHY it is unrecoverable: the memo is a public "
              "Bitcoin OP_RETURN",
              "OP_RETURN" in str(r))
        check("...and names GS_EXIT_TO, so the operator knows which value to "
              "look at", "GS_EXIT_TO" in str(r))
        check("...and says what a swap destination is supposed to be",
              "throwaway" in str(r).lower())
        check("...and tells them how to mint one",
              "create_receive_wallet" in str(r))
        check("...without echoing the address it is complaining about",
              DEST not in str(r))

        # -- CONTROLS: it must not fire on an ordinary run -----------------
        # Without these, a resolver that refused everything would look
        # identical to a working guard.
        check("control: GS_EXIT_TO UNSET resolves normally",
              resolve(["0.01"], dests=[DEST], exit_to=None) == [DEST])
        check("control: GS_EXIT_TO EMPTY resolves normally",
              resolve(["0.01"], dests=[DEST], exit_to="") == [DEST])
        check("control: a GS_EXIT_TO that is a DIFFERENT address resolves "
              "normally",
              resolve(["0.01"], dests=[DEST], exit_to=OTHER) == [DEST])
        check("control: a whole batch of non-colliding dests resolves",
              resolve(["1", "2"], dests=[DEST, OTHER], exit_to=THIRD)
              == [DEST, OTHER])

        # -- every position, and every separator GhostSpiral accepts -------
        # GS_EXIT_TO holds SEVERAL addresses (GhostSpiral splits on whitespace
        # or commas). Reading only the first would leave the others unchecked.
        check("a collision at the END of a batch is caught",
              str(resolve(["1", "2"], dests=[OTHER, DEST],
                          exit_to=DEST)).startswith("REFUSED"))
        check("...and the refusal names THAT swap's position",
              "Swap 1" in str(resolve(["1", "2"], dests=[OTHER, DEST],
                                      exit_to=DEST)))
        check("a SPACE-separated GS_EXIT_TO is read in full, not just its "
              "first address",
              str(resolve(["1"], dests=[DEST],
                          exit_to=f"{OTHER} {DEST}")).startswith("REFUSED"))
        check("a COMMA-separated GS_EXIT_TO is read in full too",
              str(resolve(["1"], dests=[DEST],
                          exit_to=f"{OTHER},{DEST}")).startswith("REFUSED"))

        # -- however the destination was supplied --------------------------
        # The check is on the RESOLVED list, so a bundle is no way around it.
        d = tempfile.mkdtemp(prefix="gs_exitcoll_")

        def bundle(name, addr):
            p = os.path.join(d, name)
            with open(p, "w") as fh:
                _json.dump({"schema": "gs_receive_wallet_v1", "address": addr,
                            "account_index": 1, "subaddress_index": 1}, fh)
            return p

        _b = bundle("x.json", DEST)
        check("a RECEIVE BUNDLE holding the exit address is refused too — the "
              "rule is on the resolved list, not on how it was typed",
              str(resolve(["0.01"], bundles=[_b],
                          exit_to=DEST)).startswith("REFUSED"))
        check("control: the same bundle resolves when it is NOT the exit "
              "address", resolve(["0.01"], bundles=[_b], exit_to=OTHER)
              == [DEST])

        # -- which refusal wins ---------------------------------------------
        # A batch can break both rules at once. The exit collision is the
        # worse outcome (a duplicate links two swaps; this publishes the
        # answer), so it is the one the operator must be told about.
        _both = str(resolve(["1", "2"], dests=[DEST, DEST], exit_to=DEST))
        check("a batch that is BOTH duplicated and the exit address is "
              "refused", _both.startswith("REFUSED"))
        check("...naming the exit collision, which is the worse of the two",
              "OP_RETURN" in _both)
    finally:
        if _saved is None:
            os.environ.pop("GS_EXIT_TO", None)
        else:
            os.environ["GS_EXIT_TO"] = _saved


def run_all():
    for fn in sorted([f for n, f in globals().items() if n.startswith("test_")],
                     key=lambda f: f.__name__):
        try:
            fn()
        except Exception as e:
            # A test that blows up is a FAILURE, not a reason to abandon the
            # remaining tests -- otherwise one crash hides everything after it.
            check(f"{fn.__name__} raised {type(e).__name__}: {str(e)[:60]}", False)
    print(f"\n  swap/receive: {PASS} passed, {FAIL} failed")
    if FAILURES:
        for f in FAILURES:
            print(f"    - {f}")
    return FAIL


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
