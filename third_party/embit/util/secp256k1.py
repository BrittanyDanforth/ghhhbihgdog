# VENDORED DEVIATION FROM UPSTREAM embit 0.8.0. See ../../README.md.
#
# WHICH secp256k1 IS LIVE, AND WHY THAT MATTERS FOR MONEY.
#
# Upstream tries ctypes bindings first -- a prebuilt blob shipped inside the
# package, then a system libsecp256k1 -- and falls back to its pure-Python
# implementation. The prebuilt blobs are DELETED from this tree: unaudited
# native binaries do not belong on the vault. What remains is the right order
# for a box that signs:
#
#   1. the SYSTEM libsecp256k1 -- Bitcoin Core's library, constant-time,
#      installed from the distro's signed package (libsecp256k1-1 on Debian /
#      Ubuntu) that the operator can verify with the package manager. A
#      signer must use this: the pure-Python fallback does big-int arithmetic
#      whose running time depends on the secret key.
#   2. the pure-Python implementation embit ships and tests -- correct, and
#      fine wherever there is NO secret (the watch-only Pi derives addresses
#      from an xpub) or for tests. Not for signing real money.
#
# The choice is EXPOSED as NATIVE / BACKEND so the signing path can refuse to
# sign without the constant-time library rather than silently degrading.
# Nothing here ever loads a library from inside this package.
NATIVE = False
BACKEND = "python"
try:
    # MicroPython ships its own module; irrelevant on CPython (ImportError).
    from micropython import const                          # noqa: F401
    from secp256k1 import *                                # noqa: F401,F403
    NATIVE = True
    BACKEND = "micropython"
except ImportError:
    try:
        # ctypes over the SYSTEM library only (the in-package search paths
        # find nothing because prebuilt/ is gone). Raises RuntimeError when
        # no libsecp256k1 is installed.
        from .ctypes_secp256k1 import *                    # noqa: F401,F403
        NATIVE = True
        BACKEND = "libsecp256k1"
    except (ImportError, OSError, RuntimeError):
        from .py_secp256k1 import *                        # noqa: F401,F403
