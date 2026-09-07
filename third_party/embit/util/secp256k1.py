# VENDORED DEVIATION FROM UPSTREAM embit 0.8.0. See ../../README.md.
#
# Upstream tries ctypes bindings to a prebuilt/system libsecp256k1 first and
# falls back to the pure-Python implementation. On an air-gapped, seizable
# vault we do not ship or depend on unaudited native binaries and do not want
# behaviour that varies with whatever libsecp256k1 a host happens to have.
# So the prebuilt/ blobs were deleted and this selector is pinned to the
# pure-Python implementation embit already ships and tests -- the same code
# hardware wallets run. It is slower; we sign a handful of transactions, not
# thousands, so that cost is irrelevant, and determinism + auditability win.
from .py_secp256k1 import *                                    # noqa: F401,F403
