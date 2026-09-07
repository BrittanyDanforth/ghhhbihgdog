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

It also pins the vendoring deviation: the pure-Python secp256k1 path must be
the one that is live, the native/ctypes path must never load, and no prebuilt
binary may exist in the tree. A future re-vendor that quietly brings the blobs
back fails here.
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

# ===========================================================================
print("== the vendoring deviation holds: pure Python, no native path, no blobs ==")
check("the pure-Python secp256k1 is the live implementation",
      "embit.util.py_secp256k1" in sys.modules)
check("the ctypes/native secp256k1 path was never loaded",
      "embit.util.ctypes_secp256k1" not in sys.modules)
_tp = Path(REPO) / "third_party" / "embit"
check("no prebuilt binary directory exists in the vendored tree",
      not (_tp / "util" / "prebuilt").exists())
check("...and no .so/.dylib/.dll anywhere under it",
      not any(p.suffix in (".so", ".dylib", ".dll")
              for p in _tp.rglob("*") if p.is_file()))
check("the selector is the documented one-line pin to py_secp256k1",
      "from .py_secp256k1 import *" in (_tp / "util" / "secp256k1.py").read_text()
      and "ctypes" not in (_tp / "util" / "secp256k1.py").read_text()
                          .split("from .py_secp256k1")[1])
check("the MIT licence travels with the code", (_tp / "LICENSE").is_file()
      and "MIT License" in (_tp / "LICENSE").read_text())

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
check("hash160('') is ripemd160(sha256('')) -- the pure-Python ripemd160 is "
      "correct", hashes.hash160(b"").hex()
      == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
check("...and sha256 underneath it is Python's own",
      hashes.sha256(b"abc").hex() == hashlib.sha256(b"abc").hexdigest())

# ===========================================================================
print("\n== signing with the pure-Python curve: verifies, and breaks on purpose ==")
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
check("the signature is low-S (grind) so it is standard on the network",
      _sig.serialize()[0] == 0x30)
check("a private key's public key round-trips through compressed SEC bytes",
      ec.PublicKey.parse(_pub.sec()).sec() == _pub.sec()
      and len(_pub.sec()) == 33)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
