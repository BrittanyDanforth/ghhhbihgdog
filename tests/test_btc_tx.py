#!/usr/bin/env python3
"""THE TRANSACTION LIBRARY, PROVEN AGAINST PUBLISHED VECTORS.

gs_btc_tx lays out and signs the one Bitcoin transaction this system makes.
Nothing below is "it runs": every byte-level claim is compared against a
value published outside this repository or computed a second, independent
way.

  * BIP143's native-P2WPKH example: the script code, the sighash, the
    deterministic signature, the witness, and the ENTIRE final signed
    transaction, byte for byte.
  * The OP_RETURN push at the 75/76 boundary, where embit's own Script.push
    would have produced a malformed script -- and every real memo here is
    over 75 bytes.
  * vsize from the two serialisations against an upper bound, on a real
    signed transaction.
  * The vault's private derivation and the Pi's public derivation meet on the
    BIP84 vector: the same address from the seed and from the xpub.
  * Refusals: no constant-time backend, a wrong-network address, a base58
    address, a duplicate input, a zero output that is not data, a memo over
    255 bytes, an invalid mnemonic, a key not at account depth.
  * The stage-2 helpers in gs_common: memo_will_overflow (the predicate two
    docs cited before it existed), memo_bytes, DUST_SAT_P2WPKH, and the
    Electrum BTC/kB -> sat/vB conversion that rounds UP and never says 0.
"""
import os
import sys

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
                                 "test_btc_tx.py")

import gs_btc_tx as T                                        # noqa: E402
import gs_btc_watch as W                                     # noqa: E402
import gs_common as C                                        # noqa: E402
from embit import bip32, bip39                               # noqa: E402
from embit import script as _es                              # noqa: E402
from embit.ec import PrivateKey                              # noqa: E402
from embit.networks import NETWORKS                          # noqa: E402
from embit.script import Script                              # noqa: E402
from embit.transaction import SIGHASH, Transaction           # noqa: E402
from embit.util import secp256k1 as _curve                   # noqa: E402


def _refused(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except T.BtcTxError:
        return True


def _raises(fn, exc, *a, **k):
    try:
        fn(*a, **k)
        return False
    except exc:
        return True
    except Exception:                                        # noqa: BLE001
        return False


print(f"      (live secp256k1 backend here: {_curve.BACKEND})")
check("the constant-time native library is live here, so the signing path "
      "below is the real one", _curve.NATIVE
      and _curve.BACKEND == "libsecp256k1")

# ===========================================================================
print("== BIP143 native P2WPKH: the published vector, byte for byte ==")
# The unsigned transaction from BIP143's "Native P2WPKH" example: two inputs,
# the SECOND is P2WPKH spending 6 BTC with the key below.
_UNSIGNED = (
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad"
    "969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9"
    "b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df3"
    "78db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e"
    "4dbe6a21b2d50ce2f0167faa815988ac11000000")
_KEY1 = PrivateKey(bytes.fromhex(
    "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"))
_PUB1_HEX = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
_SIGHASH1 = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
_SIG1 = ("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01"
         "cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de6"
         "7eebee")
# input 0 is a legacy P2PK; its published scriptSig is pasted in so the
# WHOLE final transaction can be compared to the published bytes.
_SCRIPTSIG0 = ("4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a5"
               "5d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede9"
               "44ccf4ecbab4cc618ef3ed01")
_FINAL = (
    "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4"
    "e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3beb"
    "f337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede9"
    "44ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b"
    "309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a914"
    "8280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143b"
    "de42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7"
    "d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c45183315"
    "61406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368d"
    "a1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000")

_tx = Transaction.parse(bytes.fromhex(_UNSIGNED))
check("the key's public half is the vector's", _KEY1.sec().hex() == _PUB1_HEX)
_pub1 = _KEY1.get_public_key()
check("the BIP143 script code for P2WPKH is the P2PKH form of the key hash "
      "(1976a914<hash160>88ac), not the scriptPubKey",
      _es.p2pkh(_pub1).serialize().hex()
      == "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
check("the sighash for input 1 is the published digest",
      _tx.sighash_segwit(1, _es.p2pkh(_pub1), 600000000, SIGHASH.ALL).hex()
      == _SIGHASH1)
check("...and the scriptPubKey in its place gives a DIFFERENT digest -- the "
      "mistake the library is written to make impossible",
      _tx.sighash_segwit(1, _es.p2wpkh(_pub1), 600000000, SIGHASH.ALL).hex()
      != _SIGHASH1)
T.sign_input(_tx, 1, 600000000, _KEY1)
check("sign_input produces the published deterministic (RFC6979) signature",
      _tx.vin[1].witness.items[0][:-1].hex() == _SIG1)
check("...with SIGHASH_ALL appended and the pubkey as the second witness item",
      _tx.vin[1].witness.items[0][-1] == 1
      and _tx.vin[1].witness.items[1].hex() == _PUB1_HEX)
_tx.vin[0].script_sig = Script(bytes.fromhex(_SCRIPTSIG0))
check("THE WHOLE SIGNED TRANSACTION equals the published bytes -- marker, "
      "flag, both inputs, both outputs, the witness, the locktime",
      _tx.serialize().hex() == _FINAL)
_vs, _wt, _base, _total = T.measure(_tx)
_stripped = Transaction.parse(bytes.fromhex(_UNSIGNED))
_stripped.vin[0].script_sig = Script(bytes.fromhex(_SCRIPTSIG0))
check("txid is computed WITHOUT the witness (the witness-stripped form shares "
      "it, the published final bytes parse to it) but WITH a legacy "
      "scriptSig, and is 64 hex",
      T.txid_hex(_tx) == T.txid_hex(_stripped)
      == T.txid_hex(Transaction.parse(bytes.fromhex(_FINAL)))
      and T.txid_hex(_tx)
      != T.txid_hex(Transaction.parse(bytes.fromhex(_UNSIGNED)))
      and len(T.txid_hex(_tx)) == 64)
check("measure(): base size equals the witness-stripped serialisation, "
      "weight = base*3 + total, vsize = ceil(weight/4)",
      _base == len(_stripped.serialize()) and _total == len(_tx.serialize())
      and _wt == _base * 3 + _total and _vs == -(-_wt // 4))
check("sign_input refuses a bad index, a non-key, a zero value",
      _refused(T.sign_input, _tx, 5, 1, _KEY1)
      and _refused(T.sign_input, _tx, 1, 1, "not a key")
      and _refused(T.sign_input, _tx, 1, 0, _KEY1))

# ===========================================================================
print("\n== the OP_RETURN push: the 75/76 boundary, laid out literally ==")
check("1 byte: 6a 01 xx", T.op_return_script(b"\x42").data.hex() == "6a0142")
check("75 bytes: a direct push, the length byte is the opcode (6a 4b ...)",
      T.op_return_script(b"a" * 75).data.hex() == "6a4b" + "61" * 75)
check("76 bytes: OP_PUSHDATA1 (6a 4c 4c ...) -- where Script.push would have "
      "emitted a bare 0x4c and produced a malformed script",
      T.op_return_script(b"a" * 76).data.hex() == "6a4c4c" + "61" * 76)
check("...and Script.push really would have: its 76-byte encoding is the "
      "malformed one (proof the special case is load-bearing)",
      (lambda s: (s.push(b"a" * 76), s.data.hex())[1])(Script(b"\x6a"))
      == "6a4c" + "61" * 76)
_MEMO = "=:XMR.XMR:" + "8" + "A" * 94                       # 105 bytes
check("a real-shape swap memo (105 bytes) is an OP_PUSHDATA1 push of 105",
      T.op_return_script(_MEMO.encode()).data.hex() == "6a4c69"
      + _MEMO.encode().hex())
check("255 bytes is the most this lays out; 256 is refused (would need "
      "OP_PUSHDATA2), as is empty, as is a str",
      T.op_return_script(b"z" * 255).data.hex() == "6a4cff" + "7a" * 255
      and _refused(T.op_return_script, b"z" * 256)
      and _refused(T.op_return_script, b"")
      and _refused(T.op_return_script, "text"))
check("op_return_script_len agrees with the laid-out script at both sides "
      "of the boundary and on the real memo",
      all(T.op_return_script_len(n) == len(T.op_return_script(b"a" * n).data)
          for n in (1, 74, 75, 76, 77, 105, 255)))

# ===========================================================================
print("\n== address -> scriptPubKey: this network's native segwit only ==")
_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"       # BIP173 example
_P2WSH = ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
check("P2WPKH -> 0014<20 bytes>, and embit's own converter agrees",
      T.address_script(_P2WPKH).data.hex().startswith("0014")
      and len(T.address_script(_P2WPKH).data) == 22
      and T.address_script(_P2WPKH).data
      == _es.address_to_scriptpubkey(_P2WPKH).data)
check("P2WSH -> 0020<32 bytes>", T.address_script(_P2WSH).data.hex()
      .startswith("0020") and len(T.address_script(_P2WSH).data) == 34)
check("P2TR -> 5120<32 bytes> (witness v1 is OP_1)",
      T.address_script(_P2TR).data.hex().startswith("5120")
      and len(T.address_script(_P2TR).data) == 34
      and T.address_script(_P2TR).data
      == _es.address_to_scriptpubkey(_P2TR).data)
check("a testnet address asked for mainnet is refused (embit's converter "
      "would have accepted it: it tries every network)",
      _refused(T.address_script,
               "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", "main")
      and T.address_script("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
                           "testnet").data.hex().startswith("0014"))
check("a base58 address is refused (the converter returns None on one it "
      "cannot place; here it is a loud refusal)",
      _refused(T.address_script, "1BitcoinEaterAddressDontSendf59kuE")
      and _refused(T.address_script, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"))
check("mixed case, a bad checksum, junk and an unknown network are refused",
      _refused(T.address_script, _P2WPKH[:10] + _P2WPKH[10:].upper())
      and _refused(T.address_script, _P2WPKH[:-1] + "x")
      and _refused(T.address_script, "nope")
      and _refused(T.address_script, _P2WPKH, "mars"))

# ===========================================================================
print("\n== size and fee arithmetic ==")
check("fee_for rounds nothing away: vsize * rate exactly; refuses a zero "
      "or float rate", T.fee_for(141, 7) == 987 and _refused(T.fee_for, 141, 0)
      and _refused(T.fee_for, 141, 1.5) and _refused(T.fee_for, 0, 5))
check("vsize_upper_bound: one P2WPKH input, a P2WPKH output and an "
      "OP_RETURN of 80 bytes -> 4+1+41+1+(31)+(92)+4 = 174 base, "
      "witness 2+109 -> ceil((174*4+111)/4) = 202",
      T.vsize_upper_bound(1, [22, T.op_return_script_len(80)]) == 202)
check("...and it refuses no inputs or no outputs",
      _refused(T.vsize_upper_bound, 0, [22])
      and _refused(T.vsize_upper_bound, 1, []))

# ===========================================================================
print("\n== the vault's derivation meets the Pi's on the BIP84 vector ==")
_MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
             "abandon abandon abandon about")
_acct = T.account_from_mnemonic(_MNEMONIC)
_XPUB = (bip32.HDKey.from_seed(bip39.mnemonic_to_seed(_MNEMONIC))
         .derive("m/84h/0h/0h").to_public().to_base58())
_ZPUB = ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqt"
         "fSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
check("the account key from the mnemonic matches the account xpub the Pi "
      "would hold, in xpub AND zpub encoding (compared on key + chain code)",
      T.account_matches_xpub(_acct, _XPUB)
      and T.account_matches_xpub(_acct, _ZPUB))
check("...and does NOT match the root xpub, a child, another seed's account, "
      "an xprv, or junk",
      not T.account_matches_xpub(
          _acct, bip32.HDKey.from_seed(bip39.mnemonic_to_seed(_MNEMONIC))
          .to_public().to_base58())
      and not T.account_matches_xpub(
          _acct, _acct.derive([0]).to_public().to_base58())
      and not T.account_matches_xpub(
          _acct, T.account_from_mnemonic("zoo " * 11 + "wrong")
          .to_public().to_base58())
      and not T.account_matches_xpub(_acct, _acct.to_base58())
      and not T.account_matches_xpub(_acct, "junk"))
_k00 = T.key_for(_acct, 0, 0)
check("key_for(0, 0) signs for EXACTLY the address the Pi derives at index 0 "
      "(bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu): the two boxes agree",
      _es.p2wpkh(_k00.get_public_key()).address(NETWORKS["main"])
      == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
      == W.derive_receive_address(_XPUB, 0))
check("...and at change=1 index 0 the published first change address",
      _es.p2wpkh(T.key_for(_acct, 1, 0).get_public_key())
      .address(NETWORKS["main"])
      == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
_tacct = T.account_from_mnemonic(_MNEMONIC, network="testnet")
check("testnet: coin type 1, and the address matches the Pi's tpub path",
      _es.p2wpkh(T.key_for(_tacct, 0, 0).get_public_key())
      .address(NETWORKS["test"]) == "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl")
check("an invalid mnemonic (bad checksum) is refused, not derived from",
      _refused(T.account_from_mnemonic, "abandon " * 11 + "abandon")
      and _refused(T.account_from_mnemonic, "not words at all"))
check("a passphrase changes the account (BIP39 optional passphrase honoured)",
      not T.account_matches_xpub(
          T.account_from_mnemonic(_MNEMONIC, passphrase="TREZOR"), _XPUB))
check("key_for refuses a hardened, negative, bool index and change=2",
      _refused(T.key_for, _acct, 0, T._HARDENED)
      and _refused(T.key_for, _acct, 0, -1)
      and _refused(T.key_for, _acct, 0, True)
      and _refused(T.key_for, _acct, 2, 0))

# ===========================================================================
print("\n== building and signing the one shape this system makes ==")
_H1 = "ab" * 32
_H2 = "cd" * 32
_inputs = [{"tx_hash": _H1, "vout": 0, "value": 300000},
           {"tx_hash": _H2, "vout": 3, "value": 250000}]
_inbound = T.address_script(_P2WPKH)
_memo_spk = T.op_return_script(_MEMO.encode())
_send = 300000 + 250000 - 1500
_utx = T.build_unsigned(_inputs, [(_send, _inbound), (0, _memo_spk)],
                        locktime=850000)
check("build_unsigned: version 2, RBF on every input, the locktime given, "
      "outputs in order, txids stored in display order",
      _utx.version == 2 and all(i.sequence == 0xFFFFFFFD for i in _utx.vin)
      and _utx.locktime == 850000 and _utx.vout[0].value == _send
      and _utx.vout[1].value == 0 and _utx.vout[1].script_pubkey.data[:1]
      == b"\x6a" and _utx.vin[0].txid.hex() == _H1
      and _utx.vin[1].vout == 3)
check("...it is not segwit until signed (no witness = legacy serialisation)",
      not _utx.is_segwit)
check("fee_of is inputs minus outputs",
      T.fee_of(_utx, [300000, 250000]) == 1500)
for _label, _bad_in, _bad_out in [
        ("a duplicate input", [_inputs[0], _inputs[0]],
         [(1000, _inbound), (0, _memo_spk)]),
        ("outputs exceeding inputs", _inputs, [(600000, _inbound)]),
        ("a zero output that is not OP_RETURN", _inputs, [(0, _inbound)]),
        ("an OP_RETURN carrying value", _inputs, [(5, _memo_spk)]),
        ("no inputs", [], [(1, _inbound)]),
        ("no outputs", _inputs, []),
        ("a negative output", _inputs, [(-1, _inbound)]),
        ("a string txid that is not hex", [{"tx_hash": "zz" * 32, "vout": 0,
                                           "value": 5}], [(1, _inbound)]),
        ("a zero-value input", [{"tx_hash": _H1, "vout": 0, "value": 0}],
         [(0, _memo_spk)]),
        ("a bool vout", [{"tx_hash": _H1, "vout": True, "value": 5}],
         [(1, _inbound)]),
]:
    check(f"build_unsigned refuses {_label}",
          _refused(T.build_unsigned, _bad_in, _bad_out))
check("build_unsigned refuses a locktime out of range",
      _refused(T.build_unsigned, _inputs, [(1, _inbound)], locktime=-1)
      and _refused(T.build_unsigned, _inputs, [(1, _inbound)],
                   locktime=2 ** 32))
check("build_unsigned passes FRESH lists to embit (the mutable-default "
      "landmine): two builds do not share inputs",
      len(T.build_unsigned([_inputs[0]], [(1, _inbound)]).vin) == 1
      and len(T.build_unsigned(_inputs, [(1, _inbound)]).vin) == 2
      and len(Transaction().vin) == 0)

_k1 = T.key_for(_acct, 0, 7)
_k2 = T.key_for(_acct, 0, 7)                                  # same address
_stx = T.sign_p2wpkh(_utx, [300000, 250000], [_k1, _k2])
check("sign_p2wpkh signs every input, the result is segwit, and every "
      "signature verifies independently against its public key",
      _stx.is_segwit and all(len(i.witness.items) == 2 for i in _stx.vin)
      and T.verify_signed(_stx, [300000, 250000],
                          [_k1.get_public_key(), _k2.get_public_key()]))
_vs, _wt, _base, _total = T.measure(_stx)
_upper = T.vsize_upper_bound(2, [22, T.op_return_script_len(len(_MEMO))])
check("the signed vsize is at or under the upper bound, and within the "
      f"signature-length slack (real {_vs}, bound {_upper})",
      0 <= _upper - _vs <= 4)
check("...so a fee sized from the bound at 7 sat/vB yields a real rate of "
      "at least 7", T.fee_for(_upper, 7) // _vs >= 7)
check("a witness is 107 or 108 bytes (low-R grinding keeps the DER at 70 "
      "or 71)", all(len(i.witness.serialize()) in (107, 108)
                    for i in _stx.vin))
check("tampering with an output after signing breaks every signature (the "
      "digest commits to the whole transaction)",
      (lambda: (setattr(_stx.vout[0], "value", _send - 1), _stx.clear_cache(),
                not T.verify_signed(_stx, [300000, 250000],
                                    [_k1.get_public_key(),
                                     _k2.get_public_key()]))[2])())
_stx.vout[0].value = _send
_stx.clear_cache()
check("...and restoring it restores verification (the cache was cleared, "
      "so this is a real re-derivation)",
      T.verify_signed(_stx, [300000, 250000],
                      [_k1.get_public_key(), _k2.get_public_key()]))
check("verify_signed with the WRONG public key fails",
      not T.verify_signed(_stx, [300000, 250000],
                          [_k1.get_public_key(),
                           T.key_for(_acct, 0, 8).get_public_key()]))
check("verify_signed with the wrong input value fails (the value is in the "
      "digest)", not T.verify_signed(_stx, [300000, 250001],
                                     [_k1.get_public_key(),
                                      _k2.get_public_key()]))
check("sign_p2wpkh refuses a key/value count mismatch",
      _refused(T.sign_p2wpkh, _utx, [1], [_k1, _k2])
      and _refused(T.sign_p2wpkh, _utx, [1, 2], [_k1]))

# the constant-time gate, driven by taking the native library away
_saved = (_curve.NATIVE, _curve.BACKEND)
_curve.NATIVE, _curve.BACKEND = False, "python"
check("WITHOUT the constant-time native library, signing is REFUSED -- the "
      "pure-Python curve's running time depends on the secret",
      _refused(T.sign_p2wpkh, _utx, [300000, 250000], [_k1, _k2])
      and _refused(T.sign_input, _utx, 0, 300000, _k1)
      and _refused(T.require_native))
_curve.NATIVE, _curve.BACKEND = _saved
check("...and with it back, signing proceeds",
      T.sign_p2wpkh(T.build_unsigned(_inputs, [(_send, _inbound),
                                               (0, _memo_spk)]),
                    [300000, 250000], [_k1, _k2]).is_segwit)

# ===========================================================================
print("\n== the stage-2 helpers in gs_common ==")
check("memo_bytes counts UTF-8 bytes, not characters",
      C.memo_bytes(_MEMO) == 105 and C.memo_bytes("é") == 2
      and C.memo_bytes("") == 0 and C.memo_bytes(None) == 0)
check("memo_will_overflow: 80 bytes fits, 81 does not, at the standard limit",
      not C.memo_will_overflow("a" * 80) and C.memo_will_overflow("a" * 81))
check("...a real swap memo (105 bytes) overflows the standard limit and "
      "fits a raised one", C.memo_will_overflow(_MEMO)
      and not C.memo_will_overflow(_MEMO, 120))
check("...and it agrees with memo_size_note on both sides of the limit",
      all(C.memo_will_overflow(m) == bool(C.memo_size_note(m))
          for m in ("a" * 79, "a" * 80, "a" * 81, _MEMO, "")))
check("...a limit that is not a positive int is refused",
      all(_raises(C.memo_will_overflow, ValueError, "a", lim)
          for lim in (0, -1, True, 1.5, "80")))
check("DUST_SAT_P2WPKH is the P2WPKH figure, 294, not the P2PKH 546",
      C.DUST_SAT_P2WPKH == 294)
check("electrum_fee_to_sat_vb: 0.00001 BTC/kB -> 1 sat/vB, 0.0001 -> 10, "
      "0.000012 -> 2 (rounded UP)",
      C.electrum_fee_to_sat_vb(0.00001) == 1
      and C.electrum_fee_to_sat_vb(0.0001) == 10
      and C.electrum_fee_to_sat_vb(0.000012) == 2
      and C.electrum_fee_to_sat_vb("0.00002") == 2)
check("...a tiny positive estimate rounds up to 1, never 0",
      C.electrum_fee_to_sat_vb(1e-9) == 1)
check("...-1 (Electrum's 'no estimate'), 0, a negative, NaN, inf, a bool, "
      "text, None and a list are all None -- never a free transaction",
      all(C.electrum_fee_to_sat_vb(v) is None
          for v in (-1, 0, -0.5, float("nan"), float("inf"), True, "abc",
                    None, [1])))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
if FAILS:
    print("FAILED:", FAILS)
_finished()
sys.exit(1 if FAIL else 0)
