# Vendored third-party code

## embit 0.8.0  (Bitcoin: BIP32/BIP39, bech32, secp256k1, PSBT, tx signing)

- Upstream: https://pypi.org/project/embit/0.8.0/ (MIT, © 2020 Stepan Snigirev).
- Source sdist `embit-0.8.0.tar.gz`, sha256
  `8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770`.
  That digest was checked against the one PyPI publishes for the release
  (`https://pypi.org/pypi/embit/0.8.0/json`, `urls[].digests.sha256`), not
  only against the file that was downloaded — a tampered download would hash
  consistently with itself. They match.

### What is in the tree, and what was done to it

Vendored from the sdist's `src/embit/`, then THREE deliberate changes:

1. **`util/prebuilt/` deleted** — seven native libsecp256k1 `.so/.dylib/.dll`
   blobs (~1.4 MB). Unaudited binaries shipped inside a package do not belong
   on the vault. Native code is taken only from the operating system (below).
2. **Unused surface deleted** to shrink what has to be audited: `bip85.py`,
   `slip39.py`, `psbtview.py`, `finalizer.py`, `liquid/`, `descriptor/`, and
   `wordlists/{base,slip39,ubip39,uslip39}.py`. A guard confirmed no kept
   module imports or references a removed one (the one grep hit was the
   dictionary word "liquid" inside the BIP39 English wordlist). 50 files →
   23; 14 380 → 7 612 Python lines. Kept, exactly:
   `LICENSE __init__ base base58 bech32 bip32 bip39 compact ec hashes misc
   networks psbt script transaction util/{__init__,ctypes_secp256k1,key,
   py_ripemd160,py_secp256k1,secp256k1} wordlists/{__init__,bip39}`.
   `tests/test_btc_embit.py` pins that manifest; anything else appearing, or
   any of the removed files returning, fails it.
3. **`util/secp256k1.py` replaced** with a selector that (a) prefers the
   **system** libsecp256k1 through embit's own ctypes bindings, (b) falls
   back to embit's pure-Python `py_secp256k1`, and (c) **exposes which one is
   live** as `NATIVE` (bool) and `BACKEND` (`"libsecp256k1"` / `"python"` /
   `"micropython"`). Nothing in the package can load a library from inside
   the package any more: (1) removed the only in-package binaries, and
   `util/ctypes_secp256k1.py`'s `_find_library` no longer looks there (nor at
   a hand-installed `/usr/local/lib` path) -- only `ctypes.util.find_library`,
   the dynamic linker's view of the system library. Deleting the blobs was
   half the fix; a file dropped back into the tree would otherwise have been
   loaded first. `tests/test_btc_embit.py` pins the loader's code to that.

### Why native is preferred, and where pure-Python is acceptable

The pure-Python curve does big-integer arithmetic whose running time depends
on the secret; that is a timing side channel on a key that moves real money.
Bitcoin Core's libsecp256k1 is constant-time and is what every serious signer
uses. So:

- **The vault (it signs)** MUST have the distro's signed package installed —
  `libsecp256k1-1` on Debian/Ubuntu — which embit's loader finds through
  `ctypes.util.find_library("secp256k1")`. The operator verifies it with the
  package manager, the same trust root as the rest of the OS. The signing
  path (stage 2) gates on `NATIVE` and refuses to sign without it rather than
  silently degrading.
- **The Pi (watch-only)** derives addresses from an xpub and holds no secret;
  the pure-Python fallback is correct and safe there and needs no native lib.
- **Tests** run on whichever is present and assert the fallback computes the
  same public keys as the native library.

`py_ripemd160.py` stays because `hashes.py` falls back to it when the host's
OpenSSL has RIPEMD-160 disabled (OpenSSL 3 default) — HASH160 must work on the
vault regardless. The test forces that fallback and checks the digest.

### Reproduce

`pip download embit==0.8.0 --no-deps --no-binary :all:`; confirm the sha256
above against PyPI's JSON; unpack `src/embit/`; delete the paths in (1) and
(2); replace `util/secp256k1.py` as in (3). The result should be file-for-file
identical to this directory.

### Why embit

Small, dependency-free, built for air-gapped/offline signing (SeedSigner,
Specter-DIY use it), with a pure-Python path for boxes that must not carry
native code and a ctypes path for the one box that must sign constant-time.
See `BTC_INTAKE_DESIGN.md`.
