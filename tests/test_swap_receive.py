#!/usr/bin/env python3
"""Executable tests for the swap/receive money path.

thor_swap_preparer and create_receive_wallet decide WHERE money lands: the swap
memo is the only thing routing the XMR to you, and the receive subaddress is
what gets pasted into that memo. Both are driven here through their real code
paths with only the network stubbed. Confirmed to FAIL against the pre-fix build.
"""
import sys, os, json, tempfile, importlib.util, importlib.machinery
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
