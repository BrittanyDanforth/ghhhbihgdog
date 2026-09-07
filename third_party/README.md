# Vendored third-party code

## embit 0.8.0  (Bitcoin: BIP32/BIP39, bech32, secp256k1, PSBT, tx signing)

- Upstream: https://pypi.org/project/embit/0.8.0/ (MIT, © 2020 Stepan Snigirev).
- Source sdist sha256: `8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770`  (embit-0.8.0.tar.gz).
- Vendored from that sdist's `src/embit/` verbatim, with TWO changes:
  1. `util/prebuilt/` (7 native libsecp256k1 .so/.dylib/.dll blobs, ~1.4 MB)
     **deleted** — no unaudited binaries on the vault.
  2. `util/secp256k1.py` replaced with a one-line selector pinned to the
     pure-Python `py_secp256k1` implementation embit already ships and tests
     (the ctypes/native path is never taken). Diff is that one file.
- To reproduce: `pip download embit==0.8.0 --no-deps --no-binary :all:`,
  verify the sha256 above, unpack `src/embit/`, delete `util/prebuilt/`, and
  apply the `util/secp256k1.py` change above.
- Only a subset is exercised here: bip32, bip39, bech32, ec, script,
  transaction, psbt, networks, hashes, base, compact, misc. The package is
  kept whole (minus the blobs) so it diffs cleanly against the pinned release.
- Why embit: small, dependency-free, pure-Python-capable, built for
  air-gapped/offline signing (SeedSigner, Specter-DIY). See BTC_INTAKE_DESIGN.md.
- An import walk of every module under `embit/` reports exactly three
  failures, all expected and inert: `util.ctypes_secp256k1` (cannot find a
  native libsecp256k1 -- correct, we removed them and the selector never
  imports it) and `wordlists.ubip39` / `wordlists.uslip39` (MicroPython-only
  shims importing `uembit`; never run on CPython). Everything used imports.
- Proven in-repo by `tests/test_btc_embit.py` against published BIP32 /
  BIP84 / BIP173 known-answer vectors, and that test pins the pure-Python
  path: it fails if the native path ever loads or a binary reappears.
