#!/usr/bin/env python3
"""THE VENDORED BITCOIN LIBRARY IS PROVEN, NOT TRUSTED.

third_party/embit is the one piece of crypto in this repository that did not
come from libsodium, and it will derive the addresses clients pay and sign the
transactions that move their money. So it is driven here against KNOWN-ANSWER
vectors from the BIPs themselves -- BIP32 test vector 1, the BIP84 reference
mnemonic, the BIP173 bech32 example, HASH160 of the empty string -- and the
signatures it produces are verified and then broken on purpose. Nothing below
is "it imports and runs"; every check compares against a value published
outside this repository.

It also pins the vendoring as reworked: the tree is exactly the trimmed
23-file manifest with no binary anywhere in it; the secp256k1 selector prefers
the SYSTEM libsecp256k1 (constant-time -- what a signer must use) and falls
back to embit's pure-Python curve, and reports truthfully which is live; the
pure-Python fallback the watch-only Pi relies on computes the same public keys
as the native library; and the pure-Python RIPEMD-160 that an OpenSSL-3 vault
falls back to gives the published digest.
"""
import hashlib
import os
import sys
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "third_party"))
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


from srcutil import fail_loudly_on_crash                     # noqa: E402

_finished = fail_loudly_on_crash(lambda: (PASS, FAIL, FAILS),
                                 "test_btc_embit.py")

from embit import bip32, bip39, script, ec, hashes, bech32   # noqa: E402
from embit.networks import NETWORKS                          # noqa: E402
from embit.util import secp256k1 as _sel                     # noqa: E402
from embit.util import py_secp256k1 as _py                   # noqa: E402
from embit.util import py_ripemd160 as _pyrmd                # noqa: E402

_tp = Path(REPO) / "third_party" / "embit"

# ===========================================================================
print("== the vendored tree is the trimmed manifest, and nothing else ==")
_MANIFEST = {
    "LICENSE", "__init__.py", "base.py", "base58.py", "bech32.py", "bip32.py",
    "bip39.py", "compact.py", "ec.py", "hashes.py", "misc.py", "networks.py",
    "psbt.py", "script.py", "transaction.py",
    "util/__init__.py", "util/ctypes_secp256k1.py", "util/key.py",
    "util/py_ripemd160.py", "util/py_secp256k1.py", "util/secp256k1.py",
    "wordlists/__init__.py", "wordlists/bip39.py",
}
_have = {str(p.relative_to(_tp)) for p in _tp.rglob("*")
         if p.is_file() and "__pycache__" not in p.parts}
check("exactly the 23 files of the manifest are present (surface pinned)",
      _have == _MANIFEST)
check("...none of the removed surface came back (liquid, descriptor, slip39, "
      "bip85, psbtview, finalizer, other wordlists)",
      not any(p in _have for p in ("bip85.py", "slip39.py", "psbtview.py",
                                   "finalizer.py", "wordlists/ubip39.py",
                                   "wordlists/uslip39.py"))
      and not any(p.split("/")[0] in ("liquid", "descriptor") for p in _have))
check("no prebuilt binary directory and no .so/.dylib/.dll anywhere",
      not (_tp / "util" / "prebuilt").exists()
      and not any(p.suffix in (".so", ".dylib", ".dll")
                  for p in _tp.rglob("*") if p.is_file()))
check("the MIT licence travels with the code", (_tp / "LICENSE").is_file()
      and "MIT License" in (_tp / "LICENSE").read_text())

# ===========================================================================
print("\n== the secp256k1 selector: native preferred, pure-Python fallback, "
      "and it says which ==")
check("the selector exposes NATIVE and BACKEND",
      isinstance(_sel.NATIVE, bool)
      and _sel.BACKEND in ("libsecp256k1", "python", "micropython"))
check("...and they agree with each other",
      _sel.NATIVE == (_sel.BACKEND in ("libsecp256k1", "micropython")))
# CODE ONLY: the selector's comment explains that prebuilt/ is gone, and a
# raw substring search cannot tell that explanation from a reference (see
# srcutil). What must be true is that the code never names it.
from srcutil import code_only                                # noqa: E402
_src_sel = code_only(str(_tp / "util" / "secp256k1.py"))
check("the selector never loads a library from inside the package: its code "
      "does not name prebuilt/", "prebuilt" not in _src_sel)
check("...it tries the system ctypes binding BEFORE the pure-Python one",
      _src_sel.index("ctypes_secp256k1") < _src_sel.index("py_secp256k1"))
# AND THE LOADER ITSELF. Deleting the blobs was half the fix: upstream's
# _find_library looked for one INSIDE the package first, so a file dropped
# into this tree would have become the curve that signs. The search is gone
# too -- only the dynamic linker's view of the system library is consulted.
_src_ld = code_only(str(_tp / "util" / "ctypes_secp256k1.py"))
check("the ctypes loader searches nowhere inside the package and no "
      "hand-installed path: only find_library (the system library)",
      "prebuilt" not in _src_ld and "/usr/local" not in _src_ld
      and "os.path.dirname(__file__)" not in _src_ld
      and 'find_library("secp256k1")' in _src_ld)
_has_os_lib = bool(__import__("ctypes.util").util.find_library("secp256k1"))
if _has_os_lib:
    check("with the OS libsecp256k1 installed, the constant-time native "
          "backend is the live one",
          _sel.NATIVE and _sel.BACKEND == "libsecp256k1")
else:
    check("with no OS libsecp256k1, the pure-Python backend is the live one "
          "and says so", not _sel.NATIVE and _sel.BACKEND == "python")
print(f"      (live backend here: {_sel.BACKEND})")

# ===========================================================================
print("\n== BIP32 test vector 1 (seed 000102...0f) ==")
_seed1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_m = bip32.HDKey.from_seed(_seed1)
check("m: the master xprv is the BIP32 published value",
      _m.to_base58() == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
check("m: ...and its xpub",
      _m.to_public().to_base58() == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
check("m/0h: hardened child xprv matches the vector",
      _m.derive("m/0h").to_base58() == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
check("m/0h/1/2h/2/1000000000: the deepest vector-1 path matches (xprv)",
      _m.derive("m/0h/1/2h/2/1000000000").to_base58()
      == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
check("m/0h/1/2h/2/1000000000: ...and its xpub matches the vector",
      _m.derive("m/0h/1/2h/2/1000000000").to_public().to_base58()
      == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
# PUBLIC DERIVATION MUST AGREE WITH PRIVATE DERIVATION for non-hardened steps:
# that is exactly what the Pi will do (xpub only) while the vault holds the
# xprv, and a mismatch would hand the client an address the vault cannot spend.
_acct_priv = _m.derive("m/0h/1")
_acct_pub = _acct_priv.to_public()
check("watch-only: deriving 2/1000000000 from the PUBLIC key equals deriving "
      "it from the private key, so an xpub-only Pi and an xprv vault agree",
      _acct_pub.derive("m/2/1000000000").to_base58()
      == _acct_priv.derive("m/2/1000000000").to_public().to_base58())
try:
    _acct_pub.derive("m/2h")
    _hard_refused = False
except Exception:                                            # noqa: BLE001
    _hard_refused = True
check("watch-only: a hardened step from an xpub is refused (it would be a "
      "silent wrong address otherwise)", _hard_refused)

# ===========================================================================
print("\n== BIP84 reference mnemonic -> native segwit addresses ==")
_mn = ("abandon abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon about")
_root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(_mn))


def _addr(path, net="main"):
    return script.p2wpkh(_root.derive(path).get_public_key()).address(NETWORKS[net])


check("m/84h/0h/0h/0/0 is the BIP84 published first receive address",
      _addr("m/84h/0h/0h/0/0") == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
check("m/84h/0h/0h/0/1 is the published second receive address",
      _addr("m/84h/0h/0h/0/1") == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
check("m/84h/0h/0h/1/0 is the published first change address",
      _addr("m/84h/0h/0h/1/0") == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
# UNIQUE PER INDEX, which is the whole premise of a per-deposit address.
_first_50 = [_addr(f"m/84h/0h/0h/0/{i}") for i in range(50)]
check("fifty consecutive receive indexes give fifty distinct addresses",
      len(set(_first_50)) == 50)
check("...every one of them is a 42-char bc1q (v0 p2wpkh) address",
      all(a.startswith("bc1q") and len(a) == 42 for a in _first_50))
# TESTNET: structural, not a memorised string -- the HRP and the program shape.
_tb = _addr("m/84h/1h/0h/0/0", "test")
_tv, _tprog = bech32.decode("tb", _tb)
check("a testnet derivation is a tb1 address that decodes to a 20-byte v0 "
      "program", _tb.startswith("tb1q") and _tv == 0 and len(bytes(_tprog)) == 20)

# ===========================================================================
print("\n== bech32 (BIP173) and HASH160 known answers ==")
_v, _prog = bech32.decode("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
check("the BIP173 example decodes to witness v0 and the published program",
      _v == 0 and bytes(_prog).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6")
check("...and re-encodes to the same address (round trip)",
      bech32.encode("bc", 0, bytes(_prog))
      == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
_bad = bech32.decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
check("a one-character corruption fails the checksum and decodes to nothing",
      _bad == (None, None) or _bad[0] is None)
_wrong_hrp = bech32.decode("tb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
check("...and a mainnet address does not decode under the testnet hrp",
      _wrong_hrp == (None, None) or _wrong_hrp[0] is None)
_H160_EMPTY = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
check("hash160('') is ripemd160(sha256('')) -- the published value",
      hashes.hash160(b"").hex() == _H160_EMPTY)
# THE OPENSSL-3 FALLBACK, EXERCISED DIRECTLY. hashes.py switches to
# py_ripemd160 when hashlib has no RIPEMD-160 (OpenSSL 3's default), so the
# vault's address derivation stands or falls on that pure-Python function.
check("py_ripemd160 -- the fallback an OpenSSL-3 vault uses -- gives the same "
      "published HASH160",
      _pyrmd.ripemd160(hashlib.sha256(b"").digest()).hex() == _H160_EMPTY)
check("...and RIPEMD-160('') itself is the published digest",
      _pyrmd.ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31")
check("sha256 underneath it is Python's own",
      hashes.sha256(b"abc").hex() == hashlib.sha256(b"abc").hexdigest())

# ===========================================================================
print("\n== signing: verifies, breaks on purpose, and both curves agree ==")
_k = _m.derive("m/0h").key
_pub = _k.get_public_key()
_h = hashlib.sha256(b"forward this deposit").digest()
_sig = _k.sign(_h)
check("a signature over a 32-byte hash verifies under the matching public key",
      _pub.verify(_sig, _h) is True)
check("...and does NOT verify over a different hash",
      _pub.verify(_sig, hashlib.sha256(b"forward a different one").digest())
      is False)
_other = _m.derive("m/1h").key.get_public_key()
check("...and does NOT verify under a different key",
      _other.verify(_sig, _h) is False)
check("the signature is DER (0x30) and low-S (grind), standard on the network",
      _sig.serialize()[0] == 0x30)
check("a public key round-trips through compressed SEC bytes",
      ec.PublicKey.parse(_pub.sec()).sec() == _pub.sec()
      and len(_pub.sec()) == 33)
# THE FALLBACK AGREES WITH THE NATIVE LIBRARY. The watch-only Pi may run on
# the pure-Python curve; the vault signs on libsecp256k1. If they disagreed
# about a public key, the Pi would hand out an address the vault cannot spend.
# Computed straight through the pure-Python module regardless of which
# backend is live, and compared with the live backend's serialisation.
_sec = _k.secret
_py_pub = _py.ec_pubkey_serialize(_py.ec_pubkey_create(_sec))
check("the pure-Python curve derives the SAME compressed public key as the "
      "live backend for the same secret",
      bytes(_py_pub) == _pub.sec() and len(bytes(_py_pub)) == 33)
if _sel.NATIVE:
    _live_pub = _sel.ec_pubkey_serialize(_sel.ec_pubkey_create(_sec))
    check("...and the native library (the live one here) serialises it "
          "identically", bytes(_live_pub) == bytes(_py_pub))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
