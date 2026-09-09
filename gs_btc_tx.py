#!/usr/bin/env python3
"""Build, measure and sign the one Bitcoin transaction this system makes.

STAGE 2 of the BTC-intake rework (STAGE2_PLAN.md). Pure library, no network,
no file, no policy: the forwarder tool decides WHAT to send; this decides
HOW the bytes are laid out and proves the signature before handing it back.
Everything here is a function of its arguments and is driven against
published known-answer vectors (BIP143's native-P2WPKH example) in
tests/test_btc_tx.py.

The transaction it builds is deliberately one shape:

    inputs   every settled output of ONE deposit address (P2WPKH), RBF on
    output 0 ThorChain's inbound vault, the amount being forwarded
    output 1 OP_RETURN carrying the swap memo
    output 2 (optional, normally absent) change to a fresh address

and the rules that keep money from going wrong are stated where they bite:

  * embit's Script.push() encodes lengths as CompactSize, which is NOT the
    push-opcode encoding above 75 bytes -- and every real memo here is over
    75 bytes. The OP_RETURN is laid out literally, with OP_PUSHDATA1, and the
    75/76 boundary is a known-answer test.
  * BIP143 wants the P2PKH-form SCRIPT CODE for a P2WPKH input, not the
    scriptPubKey; the wrong one yields a signature no node accepts.
  * embit caches the sighash midstate and does not invalidate it when the
    transaction is mutated; signing here happens on a transaction that is
    complete, and the cache is cleared before the first digest anyway.
  * Transaction.__init__ keeps the caller's lists WITHOUT copying and its
    defaults are shared module-level lists; fresh lists are passed always.
  * The library has no vsize; it is computed here from the two
    serialisations, and the fee-rate the forwarder prints is from that.
  * SIGNING REFUSES unless the constant-time system libsecp256k1 is the live
    backend (require_native). The pure-Python curve's running time depends
    on the secret; the watch-only Pi may use it, a signer may not.
  * Every signature is verified against its own public key before the
    transaction is returned. A signer that trusts its own output is the one
    that broadcasts garbage.

Nothing here logs, prints, or touches the hash chain.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "third_party"))
from embit import bech32, bip32, bip39, script                # noqa: E402
from embit.ec import PrivateKey, PublicKey                     # noqa: E402
from embit.networks import NETWORKS                            # noqa: E402
from embit.script import Script, Witness                       # noqa: E402
from embit.transaction import (SIGHASH, Transaction,           # noqa: E402
                               TransactionInput, TransactionOutput)
from embit.util import secp256k1 as _curve                     # noqa: E402

#: BIP125: opt in to replace-by-fee while keeping nLockTime enforced.
SEQUENCE_RBF = 0xFFFFFFFD
#: An OP_RETURN's data push, as this module lays it out, may carry at most
#: this many bytes: one OP_PUSHDATA1 length byte. Longer would need
#: OP_PUSHDATA2 and no memo here is anywhere near it.
MAX_OP_RETURN_DATA = 255
#: Upper bound on one P2WPKH witness: count(1) + len(1) + DER sig with the
#: sighash byte at its longest (73) + len(1) + compressed pubkey(33).
WITNESS_P2WPKH_MAX = 1 + 1 + 73 + 1 + 33
#: A P2WPKH input on the wire, without its witness: outpoint(36) +
#: empty scriptSig length(1) + sequence(4).
INPUT_BASE = 36 + 1 + 4
#: The account level of BIP84: m/84'/coin'/0'.
BIP84_PURPOSE = 84
#: nLockTime at or above this is a UNIX timestamp, not a height.
LOCKTIME_THRESHOLD = 500_000_000
#: 21 million bitcoin in satoshis; no honest value is above it.
MAX_MONEY = 21_000_000 * 100_000_000
_HARDENED = 0x80000000

_NETWORKS = {"main": "main", "mainnet": "main",
             "test": "test", "testnet": "test",
             "regtest": "regtest", "signet": "signet"}


class BtcTxError(Exception):
    """A transaction could not be built or signed. Carries no key."""


def network_of(name):
    key = _NETWORKS.get(str(name).lower())
    if key is None:
        raise BtcTxError(f"unknown network {name!r}")
    return NETWORKS[key]


# --- scripts ----------------------------------------------------------------

def op_return_script(data):
    """An OP_RETURN output script carrying `data` (bytes), with the push
    encoded the way the script interpreter reads it.

    1..75 bytes: a direct push (the length byte IS the opcode). 76..255: an
    OP_PUSHDATA1 (0x4c) then the length. embit's Script.push() would emit a
    bare 0x4c..0xff length byte for 76+ -- the interpreter reads 0x4c as the
    OP_PUSHDATA1 opcode and the memo as its length, a malformed script.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise BtcTxError("OP_RETURN data must be bytes")
    n = len(data)
    if n < 1:
        raise BtcTxError("OP_RETURN data is empty")
    if n > MAX_OP_RETURN_DATA:
        raise BtcTxError("OP_RETURN data over 255 bytes needs OP_PUSHDATA2, "
                         "which this module does not lay out")
    if n <= 75:
        return Script(b"\x6a" + bytes([n]) + bytes(data))
    return Script(b"\x6a\x4c" + bytes([n]) + bytes(data))


def address_script(address, network="main"):
    """The scriptPubKey of a native-segwit address OF THIS NETWORK.

    Only bech32/bech32m (witness v0 P2WPKH/P2WSH, v1 P2TR) is accepted, and
    only with this network's prefix: embit's address_to_scriptpubkey tries
    every network's version bytes and returns None on a base58 string it
    cannot place, so a testnet vault address could otherwise become a
    mainnet output, or a None a crash three calls later.
    """
    net = network_of(network)
    addr = str(address)
    if addr != addr.lower() and addr != addr.upper():
        raise BtcTxError("address mixes case")
    witver, prog = bech32.decode(net["bech32"], addr.lower())
    if witver is None or prog is None:
        raise BtcTxError("address is not a native-segwit address of "
                         f"the {net['name']} network")
    prog = bytes(prog)
    if witver == 0 and len(prog) not in (20, 32):
        raise BtcTxError("witness v0 program must be 20 or 32 bytes")
    if witver == 1 and len(prog) != 32:
        raise BtcTxError("witness v1 program must be 32 bytes")
    if witver > 1:
        raise BtcTxError("witness version above 1 is not a known output")
    opcode = 0x00 if witver == 0 else (0x50 + witver)
    return Script(bytes([opcode, len(prog)]) + prog)


def p2wpkh_script(pubkey):
    return script.p2wpkh(pubkey)


# --- size and fee arithmetic --------------------------------------------------

def _compact_len(n):
    return 1 if n < 0xFD else (3 if n <= 0xFFFF else 5)


def vsize_upper_bound(n_inputs, output_script_lens):
    """The virtual size a transaction with `n_inputs` P2WPKH inputs and
    outputs of the given script lengths can never exceed once signed.

    Used to size the fee BEFORE the memo is known (the quote needs the
    amount, the amount needs the fee, the fee needs the memo): the caller
    passes the largest OP_RETURN its policy allows, and the real size is
    always at or under this, so the real fee-rate is at or over the target.
    """
    if not isinstance(n_inputs, int) or n_inputs < 1:
        raise BtcTxError("at least one input")
    if not output_script_lens:
        raise BtcTxError("at least one output")
    base = 4 + _compact_len(n_inputs) + n_inputs * INPUT_BASE
    base += _compact_len(len(output_script_lens))
    for ln in output_script_lens:
        base += 8 + _compact_len(ln) + ln
    base += 4
    witness = 2 + n_inputs * WITNESS_P2WPKH_MAX
    weight = base * 4 + witness
    return -(-weight // 4)


def op_return_script_len(data_len):
    """Length of the OP_RETURN script for a data push of `data_len` bytes."""
    if data_len < 1 or data_len > MAX_OP_RETURN_DATA:
        raise BtcTxError("OP_RETURN data length out of range")
    return 2 + data_len if data_len <= 75 else 3 + data_len


def measure(tx):
    """(vsize, weight, base_size, total_size) of a serialised transaction.

    embit has no vsize. weight = base*3 + total, where base is the
    serialisation without marker, flag and witnesses.
    """
    total = len(tx.serialize())
    if tx.is_segwit:
        witness = 2 + sum(len(i.witness.serialize()) for i in tx.vin)
    else:
        witness = 0
    base = total - witness
    weight = base * 3 + total
    return -(-weight // 4), weight, base, total


def fee_for(vsize, sat_per_vb):
    """The fee, in whole satoshis, for `vsize` at `sat_per_vb`, rounded up."""
    if not isinstance(vsize, int) or vsize < 1:
        raise BtcTxError("vsize must be a positive int")
    if not isinstance(sat_per_vb, int) or isinstance(sat_per_vb, bool) \
            or sat_per_vb < 1:
        raise BtcTxError("fee rate must be a positive int of sat/vB")
    return vsize * sat_per_vb


# --- building ---------------------------------------------------------------

def _check_input(u):
    if not isinstance(u, dict):
        raise BtcTxError("input must be a dict")
    txid, vout, value = u.get("tx_hash"), u.get("vout"), u.get("value")
    if not (isinstance(txid, str) and len(txid) == 64
            and all(c in "0123456789abcdef" for c in txid.lower())):
        raise BtcTxError("input tx_hash must be 64 hex chars")
    for name, v in (("vout", vout), ("value", value)):
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise BtcTxError(f"input {name} must be a non-negative int")
    if value == 0:
        raise BtcTxError("input value is zero")
    # Wire widths, so a hostile listunspent cannot make serialisation blow
    # up far from the cause: vout is 4 bytes, value is 8 bytes and below
    # the money supply.
    if vout > 0xFFFFFFFF:
        raise BtcTxError("input vout out of range")
    if value > MAX_MONEY:
        raise BtcTxError("input value exceeds the money supply")
    return txid.lower(), vout, value


def build_unsigned(inputs, outputs, locktime=0):
    """An unsigned transaction: `inputs` are {tx_hash, vout, value} dicts
    (the shape gs_btc_watch.summarize returns), `outputs` are (value_sat,
    Script) pairs in order. Every input opts into RBF. Refuses a duplicate
    outpoint, a zero output that is not an OP_RETURN, and outputs that sum
    to more than the inputs (a negative fee is a transaction that spends
    money that is not there).
    """
    if not inputs:
        raise BtcTxError("no inputs")
    if not outputs:
        raise BtcTxError("no outputs")
    # A BLOCK HEIGHT, never a timestamp: Bitcoin reads nLockTime at or
    # above 500,000,000 as UNIX time, so a "height" in that range would
    # silently become a date decades away.
    if isinstance(locktime, bool) or not isinstance(locktime, int) \
            or not 0 <= locktime < LOCKTIME_THRESHOLD:
        raise BtcTxError("locktime must be a block height")
    seen = set()
    vin, total_in = [], 0
    for u in inputs:
        txid, vout, value = _check_input(u)
        if (txid, vout) in seen:
            raise BtcTxError("duplicate input")
        seen.add((txid, vout))
        vin.append(TransactionInput(bytes.fromhex(txid), vout,
                                    sequence=SEQUENCE_RBF))
        total_in += value
    if total_in > MAX_MONEY:
        raise BtcTxError("inputs exceed the money supply")
    vout_list, total_out, data_outputs = [], 0, 0
    for value, spk in outputs:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BtcTxError("output value must be a non-negative int")
        if not isinstance(spk, Script):
            raise BtcTxError("output script must be a Script")
        is_data = spk.data[:1] == b"\x6a"
        if value == 0 and not is_data:
            raise BtcTxError("a zero-value output that is not OP_RETURN")
        if value != 0 and is_data:
            raise BtcTxError("an OP_RETURN output must carry zero")
        data_outputs += is_data
        vout_list.append(TransactionOutput(value, spk))
        total_out += value
    if data_outputs > 1:
        # Relay policy: one data output per transaction. A second would be
        # a valid, unrelayable transaction -- the worst kind.
        raise BtcTxError("more than one OP_RETURN output")
    if total_out > total_in:
        raise BtcTxError("outputs exceed inputs")
    return Transaction(version=2, vin=vin, vout=vout_list, locktime=locktime)


def fee_of(tx, input_values):
    """inputs minus outputs, for a transaction and the values its inputs
    spend, in order."""
    if len(input_values) != len(tx.vin):
        raise BtcTxError("one value per input")
    return sum(input_values) - sum(o.value for o in tx.vout)


# --- keys -------------------------------------------------------------------

def require_native():
    """Refuse to sign on anything but the constant-time native library."""
    if not (_curve.NATIVE and _curve.BACKEND in ("libsecp256k1",
                                                  "micropython")):
        raise BtcTxError("refusing to sign: the constant-time system "
                         "libsecp256k1 is not the live backend "
                         f"(backend is {_curve.BACKEND!r}); the pure-Python "
                         "curve's running time depends on the secret key")


def account_from_mnemonic(mnemonic, network="main", passphrase=""):
    """The BIP84 account key m/84'/coin'/0' from a BIP39 mnemonic, as a
    PRIVATE HDKey. Refuses an invalid mnemonic (bad checksum, unknown word)
    rather than deriving something from garbage."""
    net = network_of(network)
    words = " ".join(str(mnemonic).split())
    if not bip39.mnemonic_is_valid(words):
        raise BtcTxError("the seed is not a valid BIP39 mnemonic")
    seed = bip39.mnemonic_to_seed(words, str(passphrase or ""))
    root = bip32.HDKey.from_seed(seed, version=net["xprv"])
    return root.derive([BIP84_PURPOSE + _HARDENED,
                        int(net["bip32"]) + _HARDENED,
                        0 + _HARDENED])


def account_matches_xpub(account, xpub_text):
    """True iff the private account key's public half IS the given account
    xpub -- compared on the public key and chain code, so an xpub and a zpub
    encoding of the same key both match. Depth is checked too: a root or a
    child key is not the account."""
    try:
        hd = bip32.HDKey.from_base58(str(xpub_text))
    except Exception:                                        # noqa: BLE001
        return False
    if hd.key.is_private or hd.depth != 3:
        return False
    pub = account.get_public_key()
    return (hd.key.sec() == pub.sec()
            and bytes(hd.chain_code) == bytes(account.chain_code))


def key_for(account, change, index):
    """The private key at <change>/<index> under the account key."""
    for name, v in (("change", change), ("index", index)):
        if isinstance(v, bool) or not isinstance(v, int) or v < 0 \
                or v >= _HARDENED:
            raise BtcTxError(f"{name} must be a non-negative, non-hardened "
                             "int")
    if change not in (0, 1):
        raise BtcTxError("change must be 0 or 1")
    return account.derive([change, index]).key


# --- signing ----------------------------------------------------------------

def sign_p2wpkh(tx, input_values, keys):
    """Sign every input as P2WPKH with the matching key, SIGHASH_ALL, and
    verify each signature before returning. `input_values` and `keys` are
    per input, in order. Mutates and returns `tx`.

    Refuses without the constant-time backend; refuses a key whose
    scriptPubKey is not the one the input... cannot be checked here (the
    previous output's script is not in the input), so the caller proves the
    key belongs to the address BEFORE calling -- see the forwarder, which
    derives the address from the key and compares it to the one watched.
    """
    require_native()
    if len(input_values) != len(tx.vin) or len(keys) != len(tx.vin):
        raise BtcTxError("one value and one key per input")
    tx.clear_cache()
    for i, (value, key) in enumerate(zip(input_values, keys)):
        sign_input(tx, i, value, key)
    return tx


def sign_input(tx, index, value, key):
    """Sign ONE input of `tx` as P2WPKH spending `value` with `key`, verify
    the signature, attach the witness. The digest commits to the whole
    transaction, so `tx` must be complete. Refuses without the constant-time
    backend."""
    require_native()
    if not isinstance(key, PrivateKey):
        raise BtcTxError("a PrivateKey per input")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise BtcTxError("input value must be a positive int")
    if not isinstance(index, int) or not 0 <= index < len(tx.vin):
        raise BtcTxError("input index out of range")
    pub = key.get_public_key()
    code = script.p2pkh(pub)                   # BIP143 script code, not spk
    digest = tx.sighash_segwit(index, code, value, SIGHASH.ALL)
    sig = key.sign(digest)
    if not pub.verify(sig, digest):
        raise BtcTxError("signature failed to verify against its own key")
    tx.vin[index].witness = script.witness_p2wpkh(sig, pub, SIGHASH.ALL)
    return tx


def verify_signed(tx, input_values, pubkeys):
    """Re-derive every digest and verify every witness signature against
    the given public keys -- an independent check a caller can run on a
    transaction it did not sign itself."""
    if len(input_values) != len(tx.vin) or len(pubkeys) != len(tx.vin):
        raise BtcTxError("one value and one pubkey per input")
    from embit.ec import Signature
    # INDEPENDENT OF THE SIGNER'S CACHE: embit memoises the sighash
    # midstate and never invalidates it, so a verifier that reused it
    # would pass a transaction mutated after signing. Re-derive from
    # scratch.
    tx.clear_cache()
    ok = True
    for i, (value, pub) in enumerate(zip(input_values, pubkeys)):
        items = tx.vin[i].witness.items
        if len(items) != 2 or items[1] != pub.sec():
            return False
        sig_bytes = items[0]
        if not sig_bytes or sig_bytes[-1] != SIGHASH.ALL:
            return False
        try:
            sig = Signature.parse(sig_bytes[:-1])
        except Exception:                                    # noqa: BLE001
            return False
        code = script.p2pkh(pub)
        digest = tx.sighash_segwit(i, code, value, SIGHASH.ALL)
        ok = ok and pub.verify(sig, digest)
    return ok


def txid_hex(tx):
    return tx.txid().hex()


def pubkey_from_sec(sec_hex):
    return PublicKey.parse(bytes.fromhex(sec_hex))
