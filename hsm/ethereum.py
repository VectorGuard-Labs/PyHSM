# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM Ethereum / EVM Blockchain Signing Utilities.

This module implements the Ethereum-specific signing layer on top of
PyHSM's existing secp256k1 ECDSA signing capability.

Key operations
--------------
keccak256(data)
    Ethereum's hashing primitive (Keccak-256, not SHA3-256).
    Used for: EIP-191 personal_sign prefix hashing, EIP-1559 transaction
    hashing, and Ethereum address derivation from public keys.

eth_address_from_public_key(pem)
    Derive the 0x-prefixed, EIP-55 checksummed Ethereum address from
    a secp256k1 public key PEM. Algorithm:
      1. Decode DER/SubjectPublicKeyInfo → uncompressed point (04 || x || y)
      2. keccak256(x || y)  — 64 bytes, no 04 prefix
      3. Take the last 20 bytes → raw address
      4. Apply EIP-55 checksum capitalisation

eip191_personal_sign_hash(message)
    Hash a human-readable message for use with MetaMask's eth_sign /
    personal_sign.  EIP-191 prefix:
        "\\x19Ethereum Signed Message:\\n" + str(len(message)) + message
    Returns the 32-byte Keccak-256 digest of the prefixed message.

eip1559_transaction_hash(tx)
    Hash an EIP-1559 (type-2) transaction for signing.  Encoding:
        keccak256(0x02 || RLP(chain_id, nonce, max_priority_fee,
                               max_fee, gas_limit, to, value,
                               data, access_list))
    Returns the 32-byte digest.

der_to_eth_sig(der_sig, prehash, public_key_pem)
    Convert a DER-encoded ECDSA signature to Ethereum's 65-byte
    (r || s || v) format, computing the recovery identifier v (27 or 28).
    The recovery identifier is determined by trying both possible public
    key candidates recovered from (r, s, hash) and comparing with the
    known public key.

verify_eth_sig(message_hash, eth_sig_hex, expected_address)
    Verify an Ethereum 65-byte signature and confirm it was produced by
    the private key corresponding to expected_address.

Signing workflow
----------------
The caller's responsibility is:

    1. Derive/look up the Ethereum address once (eth_address_from_public_key).
    2. Compute the appropriate message hash:
         - For personal_sign: eip191_personal_sign_hash(message)
         - For transactions:  eip1559_transaction_hash(tx_dict)
         - For raw digests:   pass the 32-byte hash directly
    3. Call hsm.sign(key_id, message_hash) → DER hex.
    4. Call der_to_eth_sig(der_hex, message_hash, pub_pem) → 65-byte hex.

The 32-byte pre-hash is fed directly to sign() because PyHSM's secp256k1
code path applies an internal SHA-256 via ECDSA(SHA256()).  For Ethereum
we need to control hashing precisely (Keccak-256, not SHA-256), so we pass
the already-hashed 32-byte digest.  When ECDSA receives a 32-byte input
and the hash algorithm is SHA-256, the library hashes those 32 bytes again
— producing SHA-256(keccak256(data)).  To avoid this double-hash, we use
the Prehashed primitive from the cryptography library when calling the low-
level private key directly. However, since PyHSM's sign() abstracts away
the private key, we implement a separate sign_digest() method that accepts
a 32-byte pre-hashed digest and signs it directly without any further
hashing.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


# ---------------------------------------------------------------------------
# Keccak-256
# ---------------------------------------------------------------------------

def keccak256(data: bytes) -> bytes:
    """
    Compute the Keccak-256 hash of data.

    Note: This is Keccak-256 as used by Ethereum, which is NOT the same as
    the NIST-standardised SHA3-256.  Python's hashlib.sha3_256 produces the
    NIST variant; Ethereum predates standardisation and uses the original
    Keccak submission.

    Implementation uses pycryptodome (``Crypto.Hash.keccak``), which
    correctly implements the pre-standardisation Keccak.
    """
    from Crypto.Hash import keccak as _keccak
    k = _keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

def eth_address_from_public_key(public_key_pem: str) -> str:
    """
    Derive the EIP-55 checksummed Ethereum address from a secp256k1 public key.

    Algorithm (Yellow Paper §298, EIP-55):
      1. Load the PEM and extract the uncompressed point bytes (65 bytes: 04 || X || Y).
      2. Drop the 0x04 prefix; concatenate X || Y (64 bytes).
      3. keccak256(X || Y) → 32 bytes.
      4. Take the rightmost 20 bytes → raw 20-byte address.
      5. Apply EIP-55 mixed-case checksum encoding.

    Parameters
    ----------
    public_key_pem : str
        SubjectPublicKeyInfo PEM string as returned by PyHSM's get_public_key().
        Must be a secp256k1 key.

    Returns
    -------
    str
        "0x"-prefixed, EIP-55 checksummed 40-hex-character Ethereum address.

    Raises
    ------
    ValueError
        If the public key is not a secp256k1 key.
    """
    pub_key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise ValueError("eth_address_from_public_key: key must be an EC (secp256k1) public key")
    if not isinstance(pub_key.curve, ec.SECP256K1):
        raise ValueError(
            f"eth_address_from_public_key: key curve must be secp256k1, "
            f"got {pub_key.curve.name}"
        )

    # Export as uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
    uncompressed = pub_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    assert uncompressed[0] == 0x04, "Expected uncompressed point prefix 0x04"
    xy_bytes = uncompressed[1:]  # 64 bytes: X || Y

    # keccak256(X || Y), take last 20 bytes
    digest = keccak256(xy_bytes)
    raw_address = digest[-20:]  # rightmost 20 bytes

    return _eip55_checksum(raw_address.hex())


def _eip55_checksum(hex_address: str) -> str:
    """
    Apply EIP-55 mixed-case checksum to a 40-hex-character address (no 0x prefix).

    For each character in the hex address:
      - If it is a letter (a-f), capitalise it if the corresponding nibble
        of keccak256(lowercase_address) is >= 8.
      - Digits are unchanged.
    """
    hex_lower = hex_address.lower()
    checksum_hash = keccak256(hex_lower.encode("ascii")).hex()

    result = []
    for i, c in enumerate(hex_lower):
        if c.isdigit():
            result.append(c)
        else:
            # Capitalise if the corresponding nibble of the checksum hash is >= 8
            result.append(c.upper() if int(checksum_hash[i], 16) >= 8 else c)

    return "0x" + "".join(result)


# ---------------------------------------------------------------------------
# EIP-191: personal_sign message hashing
# ---------------------------------------------------------------------------

def eip191_personal_sign_hash(message: str | bytes) -> bytes:
    """
    Compute the EIP-191 personal_sign hash of a message.

    This is the hash that MetaMask and most wallets compute when asked to
    sign a human-readable message via eth_sign / personal_sign.

    EIP-191 prefix: "\\x19Ethereum Signed Message:\\n{len}"
    Full prefixed message: prefix || message_bytes
    Return value: keccak256(prefix || message_bytes)  — 32 bytes.

    Parameters
    ----------
    message : str or bytes
        The human-readable message to sign.  Strings are encoded as UTF-8.

    Returns
    -------
    bytes
        32-byte Keccak-256 digest ready to be signed as a raw digest.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode("utf-8")
    return keccak256(prefix + message)


# ---------------------------------------------------------------------------
# EIP-1559 transaction hashing (RLP encoding)
# ---------------------------------------------------------------------------

def _rlp_encode_item(item) -> bytes:
    """Minimal RLP encoding of a single item (bytes or list)."""
    if isinstance(item, (bytes, bytearray)):
        data = bytes(item)
        if len(data) == 1 and data[0] < 0x80:
            return data
        length = len(data)
        if length <= 55:
            return bytes([0x80 + length]) + data
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0xb7 + len(len_bytes)]) + len_bytes + data
    elif isinstance(item, list):
        encoded_items = b"".join(_rlp_encode_item(i) for i in item)
        length = len(encoded_items)
        if length <= 55:
            return bytes([0xc0 + length]) + encoded_items
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0xf7 + len(len_bytes)]) + len_bytes + encoded_items
    elif isinstance(item, int):
        if item == 0:
            return b"\x80"
        b = item.to_bytes((item.bit_length() + 7) // 8, "big")
        return _rlp_encode_item(b)
    else:
        raise TypeError(f"_rlp_encode_item: unsupported type {type(item)}")


def eip1559_transaction_hash(tx: dict) -> bytes:
    """
    Compute the EIP-1559 (type-2) transaction signing hash.

    The signing hash is:
        keccak256(0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas,
                                max_fee_per_gas, gas_limit, to, value,
                                data, access_list]))

    All integer fields are encoded as big-endian bytes with no leading zeros
    (RLP convention).  The "to" address is encoded as 20 bytes.

    Parameters
    ----------
    tx : dict
        Transaction fields:
          chain_id             : int   (e.g. 1 for Ethereum mainnet)
          nonce                : int
          max_priority_fee_per_gas : int  (wei)
          max_fee_per_gas      : int  (wei)
          gas_limit            : int
          to                   : str  ("0x"-prefixed 20-byte address) or bytes
          value                : int  (wei)
          data                 : bytes or hex str (calldata, may be empty)
          access_list          : list (usually [] for simple transfers)

    Returns
    -------
    bytes
        32-byte Keccak-256 digest ready to be signed as a raw digest.
    """
    chain_id    = tx["chain_id"]
    nonce       = tx["nonce"]
    max_prio    = tx["max_priority_fee_per_gas"]
    max_fee     = tx["max_fee_per_gas"]
    gas_limit   = tx["gas_limit"]
    to_raw      = tx["to"]
    value       = tx["value"]
    data_raw    = tx.get("data", b"")
    access_list = tx.get("access_list", [])

    # Normalise "to"
    if isinstance(to_raw, str):
        # Strip exactly the "0x" or "0X" prefix if present, not individual chars
        if to_raw.startswith(("0x", "0X")):
            to_raw = to_raw[2:]
        to_bytes = bytes.fromhex(to_raw)
    else:
        to_bytes = bytes(to_raw)
    if len(to_bytes) != 20:
        raise ValueError(f"eip1559_transaction_hash: 'to' must be 20 bytes, got {len(to_bytes)}")

    # Normalise calldata
    if isinstance(data_raw, str):
        if data_raw.startswith(("0x", "0X")):
            data_raw = data_raw[2:]
        data_bytes = bytes.fromhex(data_raw) if data_raw else b""
    else:
        data_bytes = bytes(data_raw)

    rlp_payload = _rlp_encode_item([
        chain_id,
        nonce,
        max_prio,
        max_fee,
        gas_limit,
        to_bytes,
        value,
        data_bytes,
        access_list,
    ])

    # EIP-2718 transaction type prefix: 0x02 for EIP-1559
    return keccak256(b"\x02" + rlp_payload)


# ---------------------------------------------------------------------------
# DER → Ethereum 65-byte signature conversion
# ---------------------------------------------------------------------------

def der_to_eth_sig(
    der_sig_hex: str,
    message_hash: bytes,
    public_key_pem: str,
) -> str:
    """
    Convert a DER-encoded ECDSA signature to Ethereum's 65-byte format.

    Ethereum signatures are 65 bytes:
        r (32 bytes, big-endian) || s (32 bytes, big-endian) || v (1 byte)

    where v is 27 if the recovered public key candidate 0 matches, or 28
    if candidate 1 matches (the "recovery identifier").

    The recovery identifier v is determined by trying both possible public
    key candidates that can be recovered from (r, s, message_hash) on the
    secp256k1 curve, and checking which one matches the known public key.

    Parameters
    ----------
    der_sig_hex : str
        Hex-encoded DER ECDSA signature as returned by PyHSM's sign().
    message_hash : bytes
        The exact 32-byte digest that was signed (e.g. from
        eip191_personal_sign_hash() or eip1559_transaction_hash()).
    public_key_pem : str
        The signer's secp256k1 public key PEM (from get_public_key()).

    Returns
    -------
    str
        Hex-encoded 65-byte Ethereum signature (r || s || v), no "0x" prefix.

    Raises
    ------
    ValueError
        If neither recovery candidate matches the public key.
    """
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    der_sig = bytes.fromhex(der_sig_hex)
    r, s = decode_dss_signature(der_sig)

    # Load the known public key to compare against recovery candidates
    known_pub = serialization.load_pem_public_key(public_key_pem.encode())
    known_pub_bytes = known_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    # Try both recovery IDs (0 and 1) and check which gives back the right key
    for recovery_id in (0, 1):
        candidate = _recover_public_key(message_hash, r, s, recovery_id)
        if candidate is not None:
            candidate_bytes = candidate.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            if candidate_bytes == known_pub_bytes:
                v = 27 + recovery_id
                r_bytes = r.to_bytes(32, "big")
                s_bytes = s.to_bytes(32, "big")
                return (r_bytes + s_bytes + bytes([v])).hex()

    raise ValueError(
        "der_to_eth_sig: neither recovery candidate matched the public key. "
        "Ensure the message_hash passed here is the exact same 32-byte digest "
        "that was passed to sign()."
    )


def _recover_public_key(
    msg_hash: bytes,
    r: int,
    s: int,
    recovery_id: int,
) -> Optional[ec.EllipticCurvePublicKey]:
    """
    Attempt to recover a secp256k1 public key from (r, s, msg_hash, recovery_id).

    Uses the standard ECDSA public key recovery algorithm (SEC 1 v2.0, §4.1.6):
      1. Compute curve point R from r and recovery_id.
      2. Compute public key Q = r^{-1} * (s * R - hash * G).

    Returns None if the point R is not on the curve or other arithmetic fails.
    """
    # secp256k1 curve parameters
    p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a  = 0
    b  = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    h  = 1  # cofactor

    def modinv(a, m):
        return pow(a, m - 2, m)

    def point_add(P, Q):
        if P is None: return Q
        if Q is None: return P
        if P[0] == Q[0]:
            if P[1] != Q[1]: return None
            m = (3 * P[0] * P[0] + a) * modinv(2 * P[1], p) % p
        else:
            m = (Q[1] - P[1]) * modinv(Q[0] - P[0], p) % p
        x = (m * m - P[0] - Q[0]) % p
        y = (m * (P[0] - x) - P[1]) % p
        return (x, y)

    def point_mul(k, P):
        R = None
        while k:
            if k & 1:
                R = point_add(R, P)
            P = point_add(P, P)
            k >>= 1
        return R

    # Compute candidate R point from r and recovery_id
    x = r + (recovery_id // 2) * n
    if x >= p:
        return None
    # Compute y from x using the curve equation y^2 = x^3 + 7 (mod p)
    y_sq = (pow(x, 3, p) + b) % p
    y = pow(y_sq, (p + 1) // 4, p)  # p ≡ 3 (mod 4) so this gives a square root
    if pow(y, 2, p) != y_sq:
        return None
    # Choose the correct y parity
    if (y % 2) != (recovery_id % 2):
        y = p - y

    R_point = (x, y)

    # Q = r^{-1} * (s * R - e * G)  where e = int(msg_hash)
    e = int.from_bytes(msg_hash, "big")
    r_inv = modinv(r, n)
    G = (Gx, Gy)

    # sR
    sR = point_mul(s, R_point)
    # eG (negated: -e * G = n-e mod n * G)
    neg_eG = point_mul((n - e) % n, G)
    # Q = r_inv * (sR + neg_eG)
    Q = point_mul(r_inv, point_add(sR, neg_eG))

    if Q is None:
        return None

    # Build EllipticCurvePublicKey from the recovered point
    try:
        pub_numbers = ec.EllipticCurvePublicNumbers(x=Q[0], y=Q[1], curve=ec.SECP256K1())
        return pub_numbers.public_key()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Signature verification via address
# ---------------------------------------------------------------------------

def verify_eth_sig(
    message_hash: bytes,
    eth_sig_hex: str,
    expected_address: str,
) -> bool:
    """
    Verify an Ethereum 65-byte signature and confirm it matches the expected address.

    Parameters
    ----------
    message_hash : bytes
        The 32-byte digest that was signed (e.g. from eip191_personal_sign_hash()).
    eth_sig_hex : str
        Hex-encoded 65-byte Ethereum signature (r || s || v).
        "0x" prefix is accepted but not required.
    expected_address : str
        The "0x"-prefixed Ethereum address that should have signed the message.
        Compared case-insensitively against the recovered address.

    Returns
    -------
    bool
        True if the recovered address matches expected_address, False otherwise.
    """
    sig_bytes = bytes.fromhex(eth_sig_hex[2:] if eth_sig_hex.startswith(("0x", "0X")) else eth_sig_hex)
    if len(sig_bytes) != 65:
        return False

    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]

    # Normalise v: Ethereum uses 27/28; some tools use 0/1
    if v >= 27:
        recovery_id = v - 27
    else:
        recovery_id = v

    if recovery_id not in (0, 1):
        return False

    recovered_pub = _recover_public_key(message_hash, r, s, recovery_id)
    if recovered_pub is None:
        return False

    recovered_pem = recovered_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    recovered_address = eth_address_from_public_key(recovered_pem)
    return recovered_address.lower() == expected_address.lower()
