# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM Adversarial Test Suite.

This module contains dedicated adversarial tests — every test represents
a specific attack scenario, not a happy-path workflow. Each test is named
after the attack it covers, and the docstring documents the threat model.

Test categories:
  AT-KS  — Keystore tamper / authentication attacks
  AT-PW  — Password policy enforcement
  AT-KI  — Key ID injection
  AT-CP  — Ciphertext tampering
  AT-PL  — Policy / access control enforcement
  AT-RL  — Rate limiter abuse
  AT-AU  — Audit log tampering
  AT-SS  — Shamir secret sharing attacks
  AT-JW  — JWK import attacks
  AT-SE  — Session integrity attacks
  AT-PF  — Password file permission attacks
  AT-AS  — Asymmetric key constraint attacks
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hsm import PyHSM, TamperError
from hsm.audit import AuditLog
from hsm.rate_limiter import RateLimiter
from hsm.shamir import reconstruct_secret, split_secret, zeroize
from hsm.jwk import import_jwk

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_STRONG_PW = "AdversarialTest-789!"


@pytest.fixture()
def store_path(tmp_path: Path) -> str:
    return str(tmp_path / "keystore.enc")


@pytest.fixture()
def hsm(store_path: str) -> PyHSM:
    h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
    yield h
    try:
        h.close_session()
    except Exception:
        pass


# ===========================================================================
# AT-KS: Keystore tamper / authentication attacks
# ===========================================================================

class TestKeystoreTamperAttacks:
    """
    AT-KS: Attacks that attempt to read or modify the encrypted keystore
    file directly, bypassing PyHSM's authenticated encryption envelope.

    Defense: Encrypt-then-MAC (HMAC-SHA256 over AES-256-GCM ciphertext),
    using Argon2id-derived subkeys. Any modification to the ciphertext,
    the HMAC field, or the salt breaks either the HMAC check or the GCM
    authentication tag.
    """

    def test_bit_flip_in_ciphertext_raises_tamper_error(self, store_path):
        """AT-KS-01: Single bit-flip anywhere in the ciphertext must be detected.

        Attack: attacker flips one bit near the end of the keystore binary.
        Expected: TamperError raised, no key material released.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        data = Path(store_path).read_bytes()
        ba = bytearray(data)
        ba[-10] ^= 0xFF
        Path(store_path).write_bytes(bytes(ba))

        with pytest.raises(TamperError, match="authentication failed"):
            PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)

    def test_bit_flip_in_hmac_field_raises_tamper_error(self, store_path):
        """AT-KS-02: Attacker overwrites the stored HMAC field with zeros.

        Attack: zero out the 32-byte HMAC region (bytes 16–47).
        The HMAC comparison will fail since the computed HMAC won't match zeros.
        Expected: TamperError raised.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        data = Path(store_path).read_bytes()
        ba = bytearray(data)
        # Salt is bytes 0–15, HMAC is bytes 16–47
        for i in range(16, 48):
            ba[i] = 0x00
        Path(store_path).write_bytes(bytes(ba))

        with pytest.raises(TamperError, match="authentication failed"):
            PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)

    def test_truncated_keystore_raises_tamper_error(self, store_path):
        """AT-KS-03: Attacker truncates the keystore file.

        Attack: truncate file to fewer than the minimum valid size (76 bytes).
        Expected: TamperError raised, no partial state accessed.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        data = Path(store_path).read_bytes()
        Path(store_path).write_bytes(data[:20])

        with pytest.raises(TamperError):
            PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)

    def test_wrong_master_password_releases_no_key_material(self, store_path):
        """AT-KS-04: Wrong master password must not release key material.

        Attack: enumerate likely passwords and attempt to open the keystore.
        Expected: TamperError (or equivalent exception) raised; no keys returned.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("secret-key")
        h.close_session()

        with pytest.raises(Exception):
            h2 = PyHSM(store_path, master_password="wrong-password-xyz!", session_timeout_s=0)
            h2.list_keys()

    def test_empty_file_raises_tamper_error(self, store_path):
        """AT-KS-05: Completely empty keystore file must be rejected.

        Attack: attacker replaces keystore with a zero-byte file.
        Expected: TamperError (too short guard triggers).
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        Path(store_path).write_bytes(b"")

        with pytest.raises(TamperError):
            PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)

    def test_random_garbage_file_raises_tamper_error(self, store_path):
        """AT-KS-06: Random garbage blob must not be accepted as a keystore.

        Attack: attacker creates a file of the right length but random content,
        attempting to get the HMAC check to pass by luck (probability ≈ 2^-256).
        Expected: TamperError raised.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        # Write a properly-sized random blob to the keystore path
        Path(store_path).write_bytes(os.urandom(256))

        with pytest.raises(TamperError):
            PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)

    def test_byte_swap_in_salt_raises_tamper_error(self, store_path):
        """AT-KS-07: Swapping the salt bytes breaks key derivation and HMAC.

        Attack: replace the 16-byte salt (bytes 0–15) with random bytes.
        This changes the derived keys so the HMAC will not match.
        Expected: TamperError raised.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        data = Path(store_path).read_bytes()
        ba = bytearray(data)
        # Replace the 16-byte salt with random bytes
        new_salt = os.urandom(16)
        ba[0:16] = new_salt
        Path(store_path).write_bytes(bytes(ba))

        with pytest.raises(TamperError):
            PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)


# ===========================================================================
# AT-PW: Password policy enforcement
# ===========================================================================

class TestPasswordPolicyAttacks:
    """
    AT-PW: Attempts to bypass or circumvent master password requirements.

    Defense: _validate_master_password() enforces minimum length (12),
    minimum distinct characters (3), no single-char repetition, and a
    known-weak password deny-list.
    """

    def test_no_password_raises(self, store_path):
        """AT-PW-01: No password provided — hard error, no default.

        Attack: caller omits master_password hoping for a default/bypass.
        Expected: ValueError identifying the missing parameter.
        """
        with pytest.raises(ValueError, match="master_password or password_file is required"):
            PyHSM(store_path)

    def test_empty_string_password_raises(self, store_path):
        """AT-PW-02: Empty string password must be rejected.

        Attack: caller passes empty string to bypass length check logic.
        Expected: ValueError.
        """
        with pytest.raises(ValueError):
            PyHSM(store_path, master_password="")

    def test_password_below_minimum_length_raises(self, store_path):
        """AT-PW-03: Password shorter than 12 characters must be rejected.

        Attack: use a short but complex password to reduce brute-force cost.
        Expected: ValueError mentioning "too short".
        """
        with pytest.raises(ValueError, match="too short"):
            PyHSM(store_path, master_password="short")

    def test_single_repeated_character_password_raises(self, store_path):
        """AT-PW-04: All-same-character passwords have near-zero entropy.

        Attack: "aaaaaaaaaaaa" passes length check but has 1 distinct char.
        Expected: ValueError mentioning repeated character.
        """
        with pytest.raises(ValueError, match="single repeated character"):
            PyHSM(store_path, master_password="aaaaaaaaaaaa")

    def test_two_distinct_character_password_raises(self, store_path):
        """AT-PW-05: Passwords with fewer than 3 distinct characters are rejected.

        Attack: "ababababababab" passes length but has only 2 distinct chars.
        Expected: ValueError.
        """
        with pytest.raises(ValueError):
            PyHSM(store_path, master_password="ababababababab")

    def test_known_weak_password_raises(self, store_path):
        """AT-PW-06: Known-weak passwords that pass length/entropy checks are rejected.

        Attack: use a common password from the deny-list ("password123456") which
        passes 12-char length and 3-distinct-char checks but is trivially guessable.
        Expected: ValueError mentioning known-weak.
        """
        with pytest.raises(ValueError, match="known-weak"):
            PyHSM(store_path, master_password="password123456")

    def test_another_known_weak_password_raises(self, store_path):
        """AT-PW-07: A second known-weak pattern from the deny-list is also rejected.

        Attack: "123456789012" passes length but is on the deny-list.
        Expected: ValueError.
        """
        with pytest.raises(ValueError, match="known-weak"):
            PyHSM(store_path, master_password="123456789012")


# ===========================================================================
# AT-KI: Key ID injection
# ===========================================================================

class TestKeyIDInjectionAttacks:
    """
    AT-KI: Attempts to inject malicious or malformed key identifiers.

    Defense: _validate_key_id() enforces regex ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$.
    This prevents path traversal, shell injection, and excessively long IDs.
    """

    def test_path_traversal_key_id_raises(self, hsm):
        """AT-KI-01: Path traversal sequences in key IDs must be rejected.

        Attack: use "../" in key ID to attempt filesystem traversal.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("../traversal")

    def test_null_byte_key_id_raises(self, hsm):
        """AT-KI-02: Null bytes and non-printable characters in key IDs rejected.

        Attack: embed a null byte to terminate strings in C-based backends.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("key\x00null")

    def test_slash_in_key_id_raises(self, hsm):
        """AT-KI-03: Forward slash in key ID must be rejected (path separator).

        Attack: "key/subdir" could be interpreted as a filesystem path.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("key/subdir")

    def test_space_in_key_id_raises(self, hsm):
        """AT-KI-04: Spaces in key IDs must be rejected.

        Attack: "my key" could cause confusion in CLI argument parsing.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("my key")

    def test_empty_key_id_raises(self, hsm):
        """AT-KI-05: Empty key ID must be rejected.

        Attack: empty string key ID could cause lookup collisions.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("")

    def test_leading_dash_key_id_raises(self, hsm):
        """AT-KI-06: Key ID starting with a dash resembles a CLI flag.

        Attack: "-key" could be misinterpreted as a flag in CLI contexts.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("-key")

    def test_oversized_key_id_raises(self, hsm):
        """AT-KI-07: Key IDs exceeding 128 characters must be rejected.

        Attack: oversized key IDs may cause buffer overflows or storage bloat.
        Expected: ValueError("Invalid key ID").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
            hsm.generate_key("a" * 129)

    def test_duplicate_key_id_raises(self, hsm):
        """AT-KI-08: Generating a key with a duplicate ID must be rejected.

        Attack: overwrite an existing key by re-generating with the same ID.
        Expected: ValueError("already exists").
        """
        hsm.generate_key("existing-key")
        with pytest.raises(ValueError, match="already exists"):
            hsm.generate_key("existing-key")


# ===========================================================================
# AT-CP: Ciphertext tampering
# ===========================================================================

class TestCiphertextTamperAttacks:
    """
    AT-CP: Attacks on stored or transmitted ciphertexts.

    Defense: AES-256-GCM provides authenticated encryption. Any modification
    to the ciphertext, nonce, or AAD invalidates the GCM authentication tag.
    The AAD includes the key ID and version, preventing cross-key decryption.
    """

    def test_single_bit_flip_in_ciphertext_raises(self, hsm):
        """AT-CP-01: Single bit-flip in ciphertext must be detected by GCM tag.

        Attack: attacker intercepts the ciphertext hex and flips one byte.
        Expected: Exception raised (InvalidTag from cryptography library).
        """
        hsm.generate_key("enc")
        ct = hsm.encrypt("enc", "sensitive plaintext")
        ba = bytearray(bytes.fromhex(ct))
        ba[-1] ^= 0xFF
        with pytest.raises(Exception):
            hsm.decrypt("enc", ba.hex())

    def test_ciphertext_truncation_raises(self, hsm):
        """AT-CP-02: Truncated ciphertext must be rejected.

        Attack: attacker strips bytes from the end of the ciphertext.
        Expected: ValueError("too short").
        """
        hsm.generate_key("enc")
        with pytest.raises(ValueError, match="too short"):
            hsm.decrypt("enc", bytes(10).hex())

    def test_cross_key_decryption_fails(self, hsm):
        """AT-CP-03: Ciphertext encrypted under key-A must not decrypt under key-B.

        Attack: attacker routes ciphertext from key-A to a decrypt call using
        key-B (key confusion / cross-key oracle attack).
        Defense: AAD binds ciphertext to key_id; GCM tag fails on wrong key.
        Expected: Exception raised.
        """
        hsm.generate_key("key-a")
        hsm.generate_key("key-b")
        ct_a = hsm.encrypt("key-a", "secret for key-a")
        with pytest.raises(Exception):
            hsm.decrypt("key-b", ct_a)

    def test_replay_old_version_ciphertext_fails(self, hsm):
        """AT-CP-04: Version-bound AAD prevents replaying old-version ciphertext
        when the version prefix is altered to point to the new version.

        Attack: attacker captures v1 ciphertext, modifies the version prefix bytes
        to claim v2, and submits for decryption under the rotated key.
        Defense: GCM tag is over the ciphertext + AAD; changing the version prefix
        means the raw ciphertext no longer matches its tag.
        Expected: Exception raised.
        """
        hsm.generate_key("rot")
        ct_v1 = hsm.encrypt("rot", "original plaintext")
        hsm.rotate_key("rot")

        # Attempt to flip the version prefix (first 4 bytes after the format byte)
        raw = bytearray(bytes.fromhex(ct_v1))
        # Format byte is raw[0]; version is raw[1:5] big-endian uint32
        # Change version from 1 to 2 to make it look like a v2 ciphertext
        import struct
        raw[1:5] = struct.pack(">I", 2)

        with pytest.raises(Exception):
            hsm.decrypt("rot", raw.hex())

    def test_oversized_plaintext_raises(self, hsm):
        """AT-CP-05: Plaintext exceeding 64 MB must be rejected.

        Attack: attacker submits huge plaintext to trigger OOM denial-of-service.
        Defense: _MAX_PLAINTEXT_SIZE check before allocating GCM context.
        Expected: ValueError("too large").
        """
        hsm.generate_key("enc")
        oversized = b"X" * (64 * 1024 * 1024 + 1)
        with pytest.raises(ValueError, match="too large"):
            hsm.encrypt("enc", oversized)

    def test_oversized_ciphertext_raises(self, hsm):
        """AT-CP-06: Ciphertext exceeding the maximum input size must be rejected.

        Attack: attacker submits a multi-GB hex string to exhaust memory during decode.
        Defense: hex-length check before bytes.fromhex() call.
        Expected: ValueError("too large").
        """
        hsm.generate_key("enc")
        ct = hsm.encrypt("enc", "x")
        # Build a hex string that's too long (much larger than the ciphertext could be)
        oversized_hex = ct + "00" * (64 * 1024 * 1024 + 1)
        with pytest.raises(ValueError, match="too large"):
            hsm.decrypt("enc", oversized_hex)

    def test_random_garbage_ciphertext_raises(self, hsm):
        """AT-CP-07: Random bytes submitted as ciphertext must be rejected.

        Attack: attacker submits random bytes hoping for GCM tag collision (≈ 2^-128).
        Expected: Exception raised on every legitimate call.
        """
        hsm.generate_key("enc")
        garbage_hex = os.urandom(64).hex()
        with pytest.raises(Exception):
            hsm.decrypt("enc", garbage_hex)


# ===========================================================================
# AT-PL: Policy / access control enforcement
# ===========================================================================

class TestPolicyEnforcementAttacks:
    """
    AT-PL: Attacks that attempt to use keys for operations their policy forbids,
    or by callers that are not authorized.

    Defense: _enforce_policy() checks ACL, operation permission, max_operations,
    expiry, and rate limit — in that order with no side effects until all checks pass.
    """

    def test_encrypt_denied_by_policy(self, hsm):
        """AT-PL-01: Key with allow_encrypt=False must not encrypt.

        Attack: caller attempts encryption on a decrypt-only key.
        Expected: ValueError("policy denies encrypt").
        """
        hsm.generate_key("dec-only", policy={"allow_encrypt": False, "allow_decrypt": True})
        with pytest.raises(ValueError, match="policy denies encrypt"):
            hsm.encrypt("dec-only", "data")

    def test_decrypt_denied_by_policy(self, hsm):
        """AT-PL-02: Key with allow_decrypt=False must not decrypt.

        Attack: caller attempts decryption on an encrypt-only key.
        Expected: ValueError("policy denies decrypt").
        """
        hsm.generate_key("enc-only", policy={"allow_encrypt": True, "allow_decrypt": False})
        ct = hsm.encrypt("enc-only", "data")
        with pytest.raises(ValueError, match="policy denies decrypt"):
            hsm.decrypt("enc-only", ct)

    def test_sign_denied_by_policy(self, hsm):
        """AT-PL-03: Key with allow_sign=False must not sign.

        Attack: caller attempts signing on a key with signing disabled.
        Expected: ValueError("policy denies sign").
        """
        hsm.generate_key(
            "nosign", "ec-p256",
            policy={"allow_encrypt": False, "allow_decrypt": False, "allow_sign": False}
        )
        with pytest.raises(ValueError, match="policy denies sign"):
            hsm.sign("nosign", "data")

    def test_max_operations_cap_enforced(self, hsm):
        """AT-PL-04: Key must not be usable beyond its max_operations limit.

        Attack: attempt to exhaust a limited-use key by exceeding its operation cap.
        Expected: ValueError("exceeded max operations") after the cap is hit.
        """
        hsm.generate_key("limited", policy={
            "allow_encrypt": True, "allow_decrypt": True, "max_operations": 3
        })
        hsm.encrypt("limited", "op1")
        hsm.encrypt("limited", "op2")
        hsm.encrypt("limited", "op3")
        with pytest.raises(ValueError, match="exceeded max operations"):
            hsm.encrypt("limited", "op4")

    def test_expired_key_releases_no_material(self, hsm):
        """AT-PL-05: Expired key must refuse all operations.

        Attack: attempt to use a key after its expiry date.
        Expected: ValueError("has expired").
        """
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        hsm.generate_key("expired", policy={
            "allow_encrypt": True, "allow_decrypt": True, "expires_at": past
        })
        with pytest.raises(ValueError, match="has expired"):
            hsm.encrypt("expired", "data")

    def test_unauthorized_caller_denied(self, hsm):
        """AT-PL-06: Caller not in allowed_callers must be denied.

        Attack: a service not on the ACL attempts to use the key.
        Expected: ValueError("not authorized").
        """
        hsm.generate_key("acl-key", policy={
            "allow_encrypt": True, "allow_decrypt": True,
            "allowed_callers": ["service-a"]
        })
        with pytest.raises(ValueError, match="not authorized"):
            hsm.encrypt("acl-key", "data", caller_id="service-x")

    def test_none_caller_denied_on_acl_protected_key(self, hsm):
        """AT-PL-07: caller_id=None must be denied when allowed_callers is set.

        Attack: omit caller_id hoping the ACL check is skipped for None.
        Expected: ValueError("not authorized") — None is not in the list.
        """
        hsm.generate_key("acl-key", policy={
            "allow_encrypt": True, "allow_decrypt": True,
            "allowed_callers": ["service-a"]
        })
        with pytest.raises(ValueError, match="not authorized"):
            hsm.encrypt("acl-key", "data", caller_id=None)

    def test_acl_enforcement_on_sign_operation(self, hsm):
        """AT-PL-08: ACL must be enforced for signing operations too.

        Attack: unauthorized caller attempts to sign using an ACL-protected key.
        Expected: ValueError("not authorized").
        """
        hsm.generate_key("sign-acl", "ec-p256", policy={
            "allow_sign": True,
            "allowed_callers": ["signing-service"]
        })
        with pytest.raises(ValueError, match="not authorized"):
            hsm.sign("sign-acl", "payload", caller_id="attacker")

    def test_export_denied_without_allow_export_policy(self, hsm):
        """AT-PL-09: JWK export must be denied unless allow_export=True.

        Attack: attempt to export raw key material from a key with default policy.
        Defense: allow_export defaults to False; export requires explicit opt-in.
        Expected: ValueError("policy denies export").
        """
        hsm.generate_key("no-export", "ec-p256")
        with pytest.raises(ValueError, match="policy denies export"):
            hsm.export_jwk("no-export")

    def test_rotate_asymmetric_key_raises(self, hsm):
        """AT-PL-10: Key rotation must be rejected for asymmetric keys.

        Attack: attempt to rotate an EC key (rotation only valid for AES).
        Expected: ValueError("only supported for AES keys").
        """
        hsm.generate_key("ec-key", "ec-p256")
        with pytest.raises(ValueError, match="[Aa][Ee][Ss]"):
            hsm.rotate_key("ec-key")

    def test_encrypt_with_asymmetric_key_raises(self, hsm):
        """AT-PL-11: AES-GCM encrypt must reject an asymmetric key.

        Attack: attempt to use an RSA key as an AES encryption key.
        Expected: ValueError("AES key").
        """
        hsm.generate_key("rsa-key", "rsa-2048")
        with pytest.raises(ValueError, match="AES key"):
            hsm.encrypt("rsa-key", "data")

    def test_sign_with_aes_key_raises(self, hsm):
        """AT-PL-12: Signing must reject a symmetric AES key.

        Attack: attempt to sign with an AES key which has no private key material.
        Expected: ValueError mentioning RSA, EC, or Ed25519.
        """
        hsm.generate_key("aes-key")
        with pytest.raises(ValueError, match="RSA, EC, or Ed25519"):
            hsm.sign("aes-key", "data")

    def test_access_denied_is_recorded_in_audit_log(self, hsm):
        """AT-PL-13: Every ACL denial must be recorded in the audit log.

        This ensures that all access-control violations leave a forensic trail
        even when no exception handler captures it.
        Expected: 'accessDenied' entry present with success=False.
        """
        hsm.generate_key("audit-acl", policy={
            "allow_encrypt": True,
            "allowed_callers": ["trusted"]
        })
        try:
            hsm.encrypt("audit-acl", "data", caller_id="attacker")
        except ValueError:
            pass

        audit = hsm.get_audit_log()
        entries = audit.export_jsonl(operation="accessDenied")
        denied = [e for e in entries if e.get("success") is False]
        assert len(denied) >= 1


# ===========================================================================
# AT-RL: Rate limiter abuse
# ===========================================================================

class TestRateLimiterAbuse:
    """
    AT-RL: Attacks that attempt to abuse the rate limiter or bypass it.

    Defense: Sliding-window RateLimiter with thread-safe locking. The rate
    limiter is checked last in _enforce_policy() so unauthorized callers
    cannot burn tokens for legitimate callers.
    """

    def test_rate_limit_enforced_after_max_ops(self, store_path):
        """AT-RL-01: Operations beyond the rate limit must be blocked.

        Attack: flood a key with requests to exhaust or bypass the rate limit.
        Expected: ValueError("rate-limited") after limit is reached.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0,
                  rate_limit_max_ops=3, rate_limit_window_s=60)
        h.generate_key("rl-key")
        h.encrypt("rl-key", "1")
        h.encrypt("rl-key", "2")
        h.encrypt("rl-key", "3")
        with pytest.raises(ValueError, match="rate-limited"):
            h.encrypt("rl-key", "4")
        h.close_session()

    def test_unauthorized_caller_does_not_consume_rate_limit_token(self, store_path):
        """AT-RL-02: Rejected (unauthorized) callers must not burn rate-limit tokens.

        Attack: DoS vector — flood access-denied calls to exhaust the rate-limit
        window, then the real caller finds the key rate-limited.
        Defense: _enforce_policy() checks ACL before the rate limiter.
        Expected: after 3 denied calls, the authorized caller still gets 3 allows.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0,
                  rate_limit_max_ops=3, rate_limit_window_s=60)
        h.generate_key("acl-rl", policy={
            "allow_encrypt": True,
            "allowed_callers": ["legit"]
        })

        # Unauthorized calls — should all be denied, no tokens consumed
        for _ in range(5):
            try:
                h.encrypt("acl-rl", "x", caller_id="attacker")
            except ValueError:
                pass

        # Authorized caller should still have full 3 tokens available
        h.encrypt("acl-rl", "1", caller_id="legit")
        h.encrypt("acl-rl", "2", caller_id="legit")
        h.encrypt("acl-rl", "3", caller_id="legit")

        # 4th attempt is legitimately rate-limited
        with pytest.raises(ValueError, match="rate-limited"):
            h.encrypt("acl-rl", "4", caller_id="legit")

        h.close_session()

    def test_rate_limiter_is_per_key_independent(self):
        """AT-RL-03: Rate limits must be independent per key.

        Attack: exhaust one key's rate limit, then verify another key is unaffected.
        Expected: key-1 blocked, key-2 still allowed.
        """
        rl = RateLimiter(max_ops_per_window=2, window_seconds=60)
        assert rl.allow("key-1") is True
        assert rl.allow("key-1") is True
        assert rl.allow("key-1") is False  # key-1 exhausted

        # key-2 should still have full allowance
        assert rl.allow("key-2") is True
        assert rl.allow("key-2") is True
        assert rl.allow("key-2") is False  # now key-2 exhausted

    def test_rate_limiter_concurrent_race_condition_prevention(self):
        """AT-RL-04: Concurrent callers must not exceed the rate limit.

        Attack: exploit a check-then-act race: two threads both check
        len(window) < max before either appends, allowing 2× the limit.
        Defense: global lock wraps the entire read-modify-write.
        Expected: total admitted ops ≤ max_ops (never more).
        """
        import threading
        MAX_OPS = 10
        NUM_THREADS = 50
        rl = RateLimiter(max_ops_per_window=MAX_OPS, window_seconds=60)
        admitted = []
        barrier = threading.Barrier(NUM_THREADS)

        def try_allow():
            barrier.wait()  # All threads race simultaneously
            result = rl.allow("k")
            if result:
                admitted.append(1)

        threads = [threading.Thread(target=try_allow) for _ in range(NUM_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Must never exceed the configured limit
        assert len(admitted) <= MAX_OPS


# ===========================================================================
# AT-AU: Audit log tampering
# ===========================================================================

class TestAuditLogTamperAttacks:
    """
    AT-AU: Attacks on the audit log, including retroactive modification
    and attempts to forge or suppress audit entries.

    Defense: HMAC-SHA256 chain links every entry to its predecessor,
    using a key derived from the master password. Any modification breaks
    the chain and is detected by verify().
    """

    def test_modified_success_field_detected(self, tmp_path):
        """AT-AU-01: Changing a 'success' field in a log entry must be detected.

        Attack: attacker edits the log file to change a 'success: false'
        entry to 'success: true' to hide a failed access attempt.
        Expected: verify() returns the sequence number of the tampered entry.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32))
        log.record("generateKey", key_id="k1", success=True)
        log.record("accessDenied", key_id="k1", success=False)
        log.record("encrypt", key_id="k1", success=True)

        lines = Path(path).read_text().strip().split("\n")
        entry = json.loads(lines[1])
        entry["success"] = True  # tamper: hide the access denied
        lines[1] = json.dumps(entry)
        Path(path).write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result >= 0  # chain broken

    def test_deleted_log_entry_detected(self, tmp_path):
        """AT-AU-02: Deleting an entry from the log must be detected.

        Attack: attacker removes an incriminating audit entry from the file.
        Expected: verify() returns corrupted sequence number.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32))
        log.record("generateKey", key_id="k1", success=True)
        log.record("accessDenied", key_id="k1", success=False)
        log.record("encrypt", key_id="k1", success=True)

        lines = Path(path).read_text().strip().split("\n")
        # Remove the accessDenied entry (line index 1)
        del lines[1]
        Path(path).write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result >= 0

    def test_inserted_log_entry_detected(self, tmp_path):
        """AT-AU-03: Inserting a forged entry into the log must be detected.

        Attack: attacker inserts a fake 'generateKey' entry to create
        plausible deniability or confuse forensic analysis.
        Expected: verify() returns corrupted sequence number.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32))
        log.record("encrypt", key_id="k1", success=True)
        log.record("encrypt", key_id="k1", success=True)

        lines = Path(path).read_text().strip().split("\n")
        # Inject a fake entry between lines 0 and 1 (wrong HMAC chain)
        fake = {"timestamp": "2026-01-01T00:00:00+00:00", "sequence": 999,
                "operation": "generateKey", "success": True, "hmac": "a" * 64}
        lines.insert(1, json.dumps(fake))
        Path(path).write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result >= 0

    def test_audit_log_requires_hmac_key(self, tmp_path):
        """AT-AU-04: AuditLog must refuse to initialize without an HMAC key.

        Attack: caller creates AuditLog without a key, hoping chain is disabled.
        Expected: ValueError("hmac_key is required").
        """
        path = str(tmp_path / "audit.jsonl")
        import os as _os
        env_backup = _os.environ.pop("PYHSM_AUDIT_HMAC_KEY", None)
        try:
            with pytest.raises(ValueError, match="hmac_key is required"):
                AuditLog(path)
        finally:
            if env_backup is not None:
                _os.environ["PYHSM_AUDIT_HMAC_KEY"] = env_backup

    def test_http_webhook_url_rejected_ssrf_prevention(self, tmp_path):
        """AT-AU-05: Non-HTTPS webhook URL must be rejected to prevent SSRF.

        Attack: set a plain http:// webhook URL to route audit events to an
        internal service (Server-Side Request Forgery).
        Expected: ValueError("must use https://").
        """
        path = str(tmp_path / "audit.jsonl")
        with pytest.raises(ValueError, match="https://"):
            AuditLog(path, webhook_url="http://internal.corp/collect",
                     hmac_key=os.urandom(32))

    def test_file_scheme_webhook_url_rejected(self, tmp_path):
        """AT-AU-06: file:// webhook URL must be rejected to prevent local reads.

        Attack: set webhook_url="file:///etc/passwd" to read local files.
        Expected: ValueError.
        """
        path = str(tmp_path / "audit.jsonl")
        with pytest.raises(ValueError, match="https://"):
            AuditLog(path, webhook_url="file:///etc/passwd",
                     hmac_key=os.urandom(32))

    def test_clean_log_verify_returns_negative_one(self, tmp_path):
        """AT-AU-07: Unmodified log must return -1 (all-clear) from verify().

        Baseline test: confirms verify() reports clean for a legitimate log,
        so that any detected tampering has a meaningful contrast.
        Expected: verify() == -1.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32))
        for i in range(5):
            log.record("encrypt", key_id=f"k{i}", success=True)
        assert log.verify() == -1


# ===========================================================================
# AT-SS: Shamir secret sharing attacks
# ===========================================================================

class TestShamirSecretSharingAttacks:
    """
    AT-SS: Attacks against the Shamir Secret Sharing implementation.

    Defense: Per-share HMAC-SHA256 pre-verification (before any interpolation),
    post-reconstruction HMAC check, and constant-time GF(256) arithmetic
    using the Russian-peasant algorithm (no lookup tables).
    """

    def test_insufficient_shares_rejected(self):
        """AT-SS-01: Fewer than threshold shares must not yield the secret.

        Attack: attacker has k-1 of the k required shares and attempts
        to reconstruct the secret.
        Expected: ValueError("checksum verification") — wrong reconstruction
        detected before result is returned.
        """
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, 3, 5)
        with pytest.raises(ValueError, match="checksum verification"):
            reconstruct_secret(shares[:2])

    def test_forged_share_hmac_rejected_before_interpolation(self):
        """AT-SS-02: Share with invalid HMAC must be rejected before interpolation.

        Attack: attacker tampers with share data but keeps the old HMAC,
        attempting to trick reconstruction into producing an attacker-chosen value.
        Defense: per-share HMAC pre-verification runs before Lagrange interpolation.
        Expected: ValueError("HMAC verification").
        """
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, 2, 3)

        # Tamper with share[0]'s data bytes
        tampered = shares[0].copy()
        original_data = bytes.fromhex(tampered["data"])
        tampered_data = bytearray(original_data)
        tampered_data[0] ^= 0xFF
        tampered["data"] = tampered_data.hex()
        # Leave share_hmac unchanged — HMAC no longer matches

        with pytest.raises(ValueError, match="HMAC verification"):
            reconstruct_secret([tampered, shares[1]])

    def test_share_index_transplant_rejected(self):
        """AT-SS-03: Transplanting one share's HMAC onto a different share must fail.

        Attack: attacker has shares 1 and 2. They copy share-1's HMAC onto
        share-3's entry, hoping the HMAC check doesn't bind to the index.
        Defense: HMAC covers (index_byte || share_data); index-binding prevents
        tag transplantation.
        Expected: ValueError("HMAC verification").
        """
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, 2, 3)

        # Transplant share[0]'s HMAC onto share[2]'s index+data
        transplanted = shares[2].copy()
        transplanted["share_hmac"] = shares[0]["share_hmac"]
        # share_hmac from index=1 won't match data at index=3

        with pytest.raises(ValueError, match="HMAC verification"):
            reconstruct_secret([shares[0], transplanted])

    def test_corrupted_share_data_hex_rejected(self):
        """AT-SS-04: Share whose data hex decodes to wrong bytes must be rejected.

        Attack: attacker flips a bit in the hex-encoded share data.
        The share_hmac no longer matches the corrupted data.
        Expected: ValueError("HMAC verification").
        """
        secret = secrets.token_bytes(16)
        shares = split_secret(secret, 2, 3)

        corrupted = shares[0].copy()
        data_bytes = bytearray(bytes.fromhex(corrupted["data"]))
        data_bytes[-1] ^= 0x01
        corrupted["data"] = data_bytes.hex()

        with pytest.raises(ValueError, match="HMAC verification"):
            reconstruct_secret([corrupted, shares[1]])

    def test_invalid_hmac_salt_hex_rejected(self):
        """AT-SS-05: Malformed hmac_salt field must be rejected gracefully.

        Attack: attacker submits a share with a non-hex hmac_salt string.
        Expected: ValueError("hmac_salt is not valid hex").
        """
        secret = secrets.token_bytes(16)
        shares = split_secret(secret, 2, 3)

        bad_salt = shares[0].copy()
        bad_salt["hmac_salt"] = "GGGGGGGG-not-hex"

        with pytest.raises(ValueError, match="hmac_salt is not valid hex"):
            reconstruct_secret([bad_salt, shares[1]])

    def test_wrong_split_shares_rejected(self):
        """AT-SS-06: Shares from different splits must not reconstruct either secret.

        Attack: attacker mixes shares from split-A and split-B. Each share's
        per-share HMAC passes (different hmac_salts), but the reconstruction
        HMAC check detects the wrong result.
        Expected: ValueError("checksum verification").
        """
        secret_a = secrets.token_bytes(32)
        secret_b = secrets.token_bytes(32)
        shares_a = split_secret(secret_a, 2, 3)
        shares_b = split_secret(secret_b, 2, 3)

        # Mix: take share[0] from split-A, share[1] from split-B
        # They have different hmac_salts, so the per-share HMAC check on
        # share[1] will use salt from share[0] and fail.
        with pytest.raises(ValueError):
            reconstruct_secret([shares_a[0], shares_b[1]])

    def test_empty_secret_raises(self):
        """AT-SS-07: Empty secret must be rejected.

        Attack: split an empty secret to observe behavior (zero-length polynomial).
        Expected: ValueError.
        """
        with pytest.raises(ValueError):
            split_secret(b"", 2, 3)

    def test_threshold_below_two_raises(self):
        """AT-SS-08: Threshold k < 2 is not meaningful for secret sharing.

        Attack: k=1 would mean any single share reveals the secret — no security.
        Expected: ValueError("Invalid k/n").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid"):
            split_secret(b"secret", 1, 3)

    def test_threshold_exceeds_total_raises(self):
        """AT-SS-09: k > n makes reconstruction impossible.

        Attack: misconfigured split where you need more shares than exist.
        Expected: ValueError("Invalid k/n").
        """
        with pytest.raises(ValueError, match="[Ii]nvalid"):
            split_secret(b"secret", 4, 3)

    def test_single_share_provided_raises(self):
        """AT-SS-10: Only one share is not enough for any threshold ≥ 2.

        Attack: attacker has only one share, attempts reconstruction.
        Expected: ValueError("at least 2 shares").
        """
        secret = secrets.token_bytes(16)
        shares = split_secret(secret, 2, 3)
        with pytest.raises(ValueError, match="at least 2 shares"):
            reconstruct_secret([shares[0]])


# ===========================================================================
# AT-JW: JWK import attacks
# ===========================================================================

class TestJWKImportAttacks:
    """
    AT-JW: Attacks that attempt to import weak or malformed JWK key material.

    Defense: import_jwk() enforces minimum RSA key size (2048 bits),
    rejects unknown curves and key types, and validates byte lengths
    for symmetric and Ed25519 keys.
    """

    def test_rsa_1024_import_rejected(self):
        """AT-JW-01: RSA-1024 key import must be rejected (key size too small).

        Attack: import a 1024-bit RSA key, which is considered broken
        and can be factored within days using modern hardware.
        Expected: ValueError mentioning key size.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from hsm.jwk import export_rsa_jwk

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        jwk = export_rsa_jwk(pem)
        with pytest.raises(ValueError, match="not allowed"):
            import_jwk(jwk)

    def test_rsa_3072_import_rejected(self):
        """AT-JW-02: RSA-3072 import must be rejected (only 2048 and 4096 allowed).

        Attack: import an RSA-3072 key which is not in the allowed set
        {2048, 4096}, preventing unexpected key sizes.
        Expected: ValueError mentioning key size.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from hsm.jwk import export_rsa_jwk

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        jwk = export_rsa_jwk(pem)
        with pytest.raises(ValueError, match="not allowed"):
            import_jwk(jwk)

    def test_unknown_kty_rejected(self):
        """AT-JW-03: Completely unknown key type must be rejected.

        Attack: submit a JWK with an unknown 'kty' field hoping it's accepted.
        Expected: ValueError("Unsupported JWK key type").
        """
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            import_jwk({"kty": "QUANTUM", "k": "AAEC"})

    def test_unsupported_ec_curve_rejected(self):
        """AT-JW-04: EC JWK with an unsupported curve must be rejected.

        Attack: import a P-192 or brainpool key to bypass curve restrictions.
        Expected: ValueError("Unsupported curve").
        """
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            import_jwk({
                "kty": "EC",
                "crv": "P-192",
                "x": "AAAA",
                "y": "AAAA",
                "d": "AAAA",
            })

    def test_symmetric_key_wrong_size_rejected(self):
        """AT-JW-05: Symmetric JWK with a non-standard key length must be rejected.

        Attack: import a 24-byte (192-bit) AES key which is not in {16, 32} bytes.
        Expected: ValueError("Unsupported symmetric key size").
        """
        import base64
        key_24_bytes = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()
        with pytest.raises(ValueError, match="[Uu]nsupported symmetric key size"):
            import_jwk({"kty": "oct", "k": key_24_bytes})

    def test_unsupported_okp_curve_rejected(self):
        """AT-JW-06: OKP JWK with a non-Ed25519 curve must be rejected.

        Attack: import an X25519 (ECDH) key as if it were Ed25519 (signing).
        Expected: ValueError("Unsupported OKP curve").
        """
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            import_jwk({
                "kty": "OKP",
                "crv": "X25519",
                "x": "AAAA",
                "d": "AAAA",
            })


# ===========================================================================
# AT-SE: Session integrity attacks
# ===========================================================================

class TestSessionIntegrityAttacks:
    """
    AT-SE: Attacks on PyHSM session state.

    Defense: _assert_session() guards every operation. Any operation on a
    closed session raises RuntimeError immediately.
    """

    def test_closed_session_blocks_all_operations(self, store_path):
        """AT-SE-01: All operations must raise after session is closed.

        Attack: attempt to continue using an HSM instance after close_session().
        Expected: RuntimeError("session is closed") on any operation.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        with pytest.raises(RuntimeError, match="session is closed"):
            h.list_keys()

    def test_closed_session_blocks_encrypt(self, store_path):
        """AT-SE-02: Encrypt must raise on a closed session.

        Attack: attempt to encrypt after close_session() (key material zeroized).
        Expected: RuntimeError.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("k1")
        h.close_session()

        with pytest.raises(RuntimeError, match="session is closed"):
            h.encrypt("k1", "data")

    def test_double_close_is_safe(self, store_path):
        """AT-SE-03: Calling close_session() twice must not raise or corrupt state.

        Attack: double-free scenario — calling close_session() after it has
        already run could cause a use-after-free or state corruption.
        Expected: second call is silently ignored.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.close_session()
        h.close_session()  # must not raise

    def test_operate_on_nonexistent_key_raises(self, hsm):
        """AT-SE-04: Operations on a nonexistent key ID must raise KeyError.

        Attack: probe for key names that don't exist to enumerate the keystore.
        Expected: KeyError (does not reveal whether other keys exist).
        """
        with pytest.raises(KeyError):
            hsm.encrypt("ghost-key", "data")

    def test_destroy_nonexistent_key_raises(self, hsm):
        """AT-SE-05: Destroying a nonexistent key must raise KeyError.

        Attack: attempt to destroy a key that was never created.
        Expected: KeyError.
        """
        with pytest.raises(KeyError):
            hsm.destroy_key("ghost-key")

    def test_rotate_nonexistent_key_raises(self, hsm):
        """AT-SE-06: Rotating a nonexistent key must raise KeyError.

        Attack: attempt to rotate a key that doesn't exist.
        Expected: KeyError.
        """
        with pytest.raises(KeyError):
            hsm.rotate_key("ghost-key")


# ===========================================================================
# AT-PF: Password file permission attacks
# ===========================================================================

class TestPasswordFilePermissionAttacks:
    """
    AT-PF: Attacks on the password file mechanism.

    Defense: load_password_from_file() enforces O_NOFOLLOW (no symlinks),
    owner-UID match, no group-read, no world-read, and non-empty content.
    """

    def test_world_readable_password_file_rejected(self, tmp_path):
        """AT-PF-01: World-readable password file must be rejected.

        Attack: HSM process is tricked into reading a password file that
        any user can read (effectively public password).
        Expected: PermissionError.
        """
        from hsm.password_file import load_password_from_file

        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("AdversarialTest-789!")
        pw_file.chmod(0o644)  # world-readable

        # On macOS, 0o644 sets group-read AND world-read; whichever fires first
        # is implementation-dependent. We assert any PermissionError is raised.
        with pytest.raises(PermissionError):
            load_password_from_file(str(pw_file))

    def test_group_readable_password_file_rejected(self, tmp_path):
        """AT-PF-02: Group-readable password file must be rejected.

        Attack: password file is readable by a group that includes
        other users on the system (common misconfiguration).
        Expected: PermissionError.
        """
        from hsm.password_file import load_password_from_file

        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("AdversarialTest-789!")
        pw_file.chmod(0o640)  # group-readable

        with pytest.raises(PermissionError, match="group-readable"):
            load_password_from_file(str(pw_file))

    def test_symlink_password_file_rejected(self, tmp_path):
        """AT-PF-03: Symlink password file must be rejected (TOCTOU prevention).

        Attack: attacker creates a symlink that points to a different file.
        Between the permission check and the read, the symlink target could
        be swapped for an attacker-controlled file.
        Defense: O_NOFOLLOW causes ELOOP for final-component symlinks.
        Expected: PermissionError.
        """
        from hsm.password_file import load_password_from_file

        real = tmp_path / "real.txt"
        real.write_text("AdversarialTest-789!")
        real.chmod(0o600)
        link = tmp_path / "link.txt"
        link.symlink_to(real)

        with pytest.raises(PermissionError, match="[Ss]ymbolic link"):
            load_password_from_file(str(link))

    def test_empty_password_file_rejected(self, tmp_path):
        """AT-PF-04: Empty password file must be rejected.

        Attack: empty password file would produce an empty password string,
        which is trivially guessable.
        Expected: ValueError.
        """
        from hsm.password_file import load_password_from_file

        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("")
        pw_file.chmod(0o600)

        with pytest.raises((ValueError, PermissionError)):
            load_password_from_file(str(pw_file))

    def test_correct_permission_password_file_loads(self, tmp_path):
        """AT-PF-05: Correctly configured password file (0o600) must load.

        Baseline: a file with correct permissions and a strong password
        should load successfully, confirming valid configs still work.
        """
        from hsm.password_file import load_password_from_file

        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("AdversarialTest-789!")
        pw_file.chmod(0o600)

        password = load_password_from_file(str(pw_file))
        assert password == "AdversarialTest-789!"


# ===========================================================================
# AT-AS: Asymmetric key constraint attacks
# ===========================================================================

class TestAsymmetricKeyConstraintAttacks:
    """
    AT-AS: Attacks that attempt to misuse asymmetric keys — using signing keys
    for encryption, using encrypt-only keys for signing, or mixing up key types
    in ways the policy model does not permit.

    Defense: PyHSM enforces key-type constraints in every operation:
    encrypt/decrypt require AES keys, sign/verify require RSA/EC/Ed25519 keys,
    and get_public_key is only valid for asymmetric keys.
    """

    def test_encrypt_with_rsa_key_raises(self, hsm):
        """AT-AS-01: AES-GCM encryption must be rejected for an RSA key.

        Attack: caller attempts to use an RSA private key as an AES encryption
        key (e.g., by generating rsa-2048 and then calling encrypt()).
        Expected: ValueError mentioning "AES key".
        """
        hsm.generate_key("rsa-key", "rsa-2048")
        with pytest.raises(ValueError, match="AES key"):
            hsm.encrypt("rsa-key", "secret data")

    def test_encrypt_with_ec_key_raises(self, hsm):
        """AT-AS-02: AES-GCM encryption must be rejected for an EC key.

        Attack: caller attempts to use an EC key as an encryption key.
        Expected: ValueError mentioning "AES key".
        """
        hsm.generate_key("ec-key", "ec-p256")
        with pytest.raises(ValueError, match="AES key"):
            hsm.encrypt("ec-key", "secret data")

    def test_encrypt_with_ed25519_key_raises(self, hsm):
        """AT-AS-03: AES-GCM encryption must be rejected for an Ed25519 key.

        Attack: caller attempts to use an Ed25519 signing key for encryption.
        Expected: ValueError mentioning "AES key".
        """
        hsm.generate_key("ed-key", "ed25519")
        with pytest.raises(ValueError, match="AES key"):
            hsm.encrypt("ed-key", "secret data")

    def test_sign_with_aes256_key_raises(self, hsm):
        """AT-AS-04: Signing must be rejected for an AES-256 key.

        Attack: caller attempts to sign data with an AES key (no private key material
        for asymmetric signing exists).
        Expected: ValueError mentioning "RSA, EC, or Ed25519".
        """
        hsm.generate_key("aes-key", "aes-256")
        with pytest.raises(ValueError, match="RSA, EC, or Ed25519"):
            hsm.sign("aes-key", "data to sign")

    def test_sign_with_aes128_key_raises(self, hsm):
        """AT-AS-05: Signing must be rejected for an AES-128 key.

        Attack: caller uses a 128-bit AES key for a signing call.
        Expected: ValueError mentioning "RSA, EC, or Ed25519".
        """
        hsm.generate_key("aes128-key", "aes-128")
        with pytest.raises(ValueError, match="RSA, EC, or Ed25519"):
            hsm.sign("aes128-key", "data")

    def test_decrypt_with_rsa_key_raises(self, hsm):
        """AT-AS-06: AES-GCM decryption must be rejected for an RSA key.

        Attack: caller submits an RSA key ID to the decrypt operation.
        Expected: ValueError mentioning "AES key".
        """
        hsm.generate_key("rsa-key", "rsa-2048")
        with pytest.raises(ValueError, match="AES key"):
            hsm.decrypt("rsa-key", "deadbeef" * 8)

    def test_decrypt_with_ec_key_raises(self, hsm):
        """AT-AS-07: AES-GCM decryption must be rejected for an EC key.

        Attack: caller submits an EC key ID to the decrypt operation.
        Expected: ValueError mentioning "AES key".
        """
        hsm.generate_key("ec-key", "ec-p256")
        with pytest.raises(ValueError, match="AES key"):
            hsm.decrypt("ec-key", "deadbeef" * 8)

    def test_get_public_key_from_aes_raises(self, hsm):
        """AT-AS-08: Exporting a public key from a symmetric AES key must raise.

        Attack: caller attempts to extract a "public key" from an AES key,
        which has no asymmetric component.
        Expected: ValueError.
        """
        hsm.generate_key("sym-key", "aes-256")
        with pytest.raises(ValueError):
            hsm.get_public_key("sym-key")

    def test_verify_with_aes_key_raises(self, hsm):
        """AT-AS-09: Signature verification must be rejected for a symmetric key.

        Attack: caller passes an AES key ID to verify(), hoping it falls through
        to a code path that processes the symmetric key as if it had a public component.
        Expected: ValueError.
        """
        hsm.generate_key("aes-key", "aes-256")
        with pytest.raises(ValueError):
            hsm.verify("aes-key", "data", "00" * 64)

    def test_rotate_rsa_key_raises(self, hsm):
        """AT-AS-10: Key rotation must be rejected for RSA keys.

        Rotation generates a new AES key material in-place; it is not defined
        for asymmetric keys (new RSA key generation would change the public key,
        invalidating all previously issued certificates or JWKs).
        Expected: ValueError mentioning AES.
        """
        hsm.generate_key("rsa-rot", "rsa-2048")
        with pytest.raises(ValueError, match="[Aa][Ee][Ss]"):
            hsm.rotate_key("rsa-rot")

    def test_rotate_ec_key_raises(self, hsm):
        """AT-AS-11: Key rotation must be rejected for EC keys.

        Expected: ValueError mentioning AES.
        """
        hsm.generate_key("ec-rot", "ec-p256")
        with pytest.raises(ValueError, match="[Aa][Ee][Ss]"):
            hsm.rotate_key("ec-rot")

    def test_cross_key_type_ciphertext_rejected(self, hsm):
        """AT-AS-12: Ciphertext encrypted under one AES key must not decrypt under another.

        Attack: attacker routes ciphertext from key-A to a decrypt call using
        key-B (key confusion / cross-key oracle attack).
        Defense: AAD binds ciphertext to key_id; GCM tag fails on wrong key.
        Expected: Exception raised (GCM authentication tag mismatch).
        """
        hsm.generate_key("key-a", "aes-256")
        hsm.generate_key("key-b", "aes-256")
        ct = hsm.encrypt("key-a", "secret payload")
        with pytest.raises(Exception):
            hsm.decrypt("key-b", ct)


# ===========================================================================
# AT-KS-EX: Key separation verification
# ===========================================================================

class TestKeySeparationVerification:
    """
    AT-KS-EX: Verifies that the three HKDF-derived subkeys (encryption key,
    MAC key, KEK) are cryptographically independent. A compromise of one
    must not reveal the others.

    These tests operate at the KeyStore level, verifying that:
    1. enc_key, mac_key, and KEK are all distinct values.
    2. The keys change when the salt changes (they are salt-dependent).
    3. The same master password with a different salt produces completely
       different keys (no correlation).
    """

    def test_enc_key_and_mac_key_are_distinct(self, store_path):
        """AT-KS-EX-01: Encryption key and MAC key derived from the same password must differ.

        Defense: independent HKDF-Expand calls with different 'info' strings
        ("pyhsm-enc-v1" vs "pyhsm-mac-v1"). If both used the same derivation,
        a MAC forgery attack could reuse enc_key as the MAC key.
        Expected: enc_key ≠ mac_key.
        """
        from hsm.storage import KeyStore
        import os

        store = KeyStore(store_path, master_password=_STRONG_PW)
        salt = os.urandom(16)
        enc_key, mac_key = store._derive_subkeys(salt)

        assert bytes(enc_key) != bytes(mac_key), (
            "enc_key and mac_key must be distinct — HKDF info strings differ"
        )
        from hsm.secure_memory import zeroize_bytearray
        zeroize_bytearray(enc_key)
        zeroize_bytearray(mac_key)
        store.zeroize_memory()

    def test_kek_is_distinct_from_enc_and_mac_keys(self, store_path):
        """AT-KS-EX-02: KEK must differ from both enc_key and mac_key.

        Defense: KEK uses a separate salt stored inside the encrypted keystore
        and a distinct info string ("pyhsm-kek-v1"). If KEK equalled enc_key,
        an attacker who recovered the enc_key (e.g. via GCM nonce reuse) would
        also have the key to unwrap all stored key material.
        Expected: kek ≠ enc_key and kek ≠ mac_key.
        """
        from hsm.storage import KeyStore
        import os

        store = KeyStore(store_path, master_password=_STRONG_PW)
        salt = os.urandom(16)
        enc_key, mac_key = store._derive_subkeys(salt)
        kek = store._derive_kek()

        assert bytes(kek) != bytes(enc_key), "KEK must not equal enc_key"
        assert bytes(kek) != bytes(mac_key), "KEK must not equal mac_key"
        from hsm.secure_memory import zeroize_bytearray
        zeroize_bytearray(enc_key)
        zeroize_bytearray(mac_key)
        zeroize_bytearray(kek)
        store.zeroize_memory()

    def test_different_salts_produce_different_subkeys(self, store_path):
        """AT-KS-EX-03: Two different salts must produce different subkey pairs.

        This confirms the salt actually participates in key derivation (not ignored).
        If salt were ignored, an attacker who observed one ciphertext could derive
        the keys for any other ciphertext with the same password.
        Expected: enc_key_1 ≠ enc_key_2 and mac_key_1 ≠ mac_key_2.
        """
        from hsm.storage import KeyStore
        import os

        store = KeyStore(store_path, master_password=_STRONG_PW)
        salt_1 = os.urandom(16)
        salt_2 = os.urandom(16)
        # Extremely unlikely to collide (128-bit random salt)
        while salt_2 == salt_1:
            salt_2 = os.urandom(16)

        enc_1, mac_1 = store._derive_subkeys(salt_1)
        enc_2, mac_2 = store._derive_subkeys(salt_2)

        assert bytes(enc_1) != bytes(enc_2), "Different salts must yield different enc_keys"
        assert bytes(mac_1) != bytes(mac_2), "Different salts must yield different mac_keys"
        from hsm.secure_memory import zeroize_bytearray
        for k in (enc_1, mac_1, enc_2, mac_2):
            zeroize_bytearray(k)
        store.zeroize_memory()

    def test_different_passwords_produce_different_subkeys(self, store_path):
        """AT-KS-EX-04: Two different master passwords must produce different subkeys.

        This confirms Argon2id password input actually affects derived keys.
        If the password input were ignored, any password would open any keystore.
        Expected: keys derived from password-A ≠ keys derived from password-B.
        """
        import tempfile
        from hsm.storage import KeyStore
        import os

        store_b_path = store_path + ".b"
        store_a = KeyStore(store_path, master_password=_STRONG_PW)
        store_b = KeyStore(store_b_path, master_password="DifferentPassword!99")

        salt = os.urandom(16)
        enc_a, mac_a = store_a._derive_subkeys(salt)
        enc_b, mac_b = store_b._derive_subkeys(salt)

        assert bytes(enc_a) != bytes(enc_b), "Different passwords must yield different enc_keys"
        assert bytes(mac_a) != bytes(mac_b), "Different passwords must yield different mac_keys"
        from hsm.secure_memory import zeroize_bytearray
        for k in (enc_a, mac_a, enc_b, mac_b):
            zeroize_bytearray(k)
        store_a.zeroize_memory()
        store_b.zeroize_memory()

    def test_secure_bytes_zeroization_clears_buffer(self, store_path):
        """AT-KS-EX-05: SecureBytes.zeroize() must overwrite the buffer with zeros.

        Defense: key material is held in SecureBytes (wrapping bytearray) during
        use and zeroized immediately after each operation.
        Expected: buf is all-zero after zeroize(); accessing buf raises RuntimeError.
        """
        from hsm.secure_memory import SecureBytes

        raw = bytes(range(32))
        sb = SecureBytes(raw)
        assert bytes(sb.buf) == raw  # data is present before zeroize
        sb.zeroize()
        # Buffer should be all zeros
        assert all(b == 0 for b in sb._buf)
        # Accessing .buf after zeroize should raise
        with pytest.raises(RuntimeError, match="zeroized"):
            _ = sb.buf

    def test_zeroize_bytearray_overwrites_in_place(self, store_path):
        """AT-KS-EX-06: zeroize_bytearray() must overwrite the exact same object.

        Defense: per-operation key material is zeroized before returning to the
        heap. This test verifies the zeroing is in-place (not a copy).
        Expected: same bytearray object is all-zero after call.
        """
        from hsm.secure_memory import zeroize_bytearray

        buf = bytearray(b"\xff" * 32)
        original_id = id(buf)
        zeroize_bytearray(buf)

        assert id(buf) == original_id, "zeroize_bytearray must operate in-place"
        assert bytes(buf) == b"\x00" * 32, "buffer must be all zeros after zeroize"

    def test_key_material_zeroized_after_session_close(self, store_path):
        """AT-KS-EX-07: All key material in the keystore must be zeroed on session close.

        Defense: _close_session_locked() calls store.zeroize_memory() which calls
        zeroize_dict_keys() on every key entry.
        Expected: after close_session(), the key_data bytearrays in the internal
        store are all-zero.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h.generate_key("zeroize-test")

        # Grab a reference to the key_data bytearray BEFORE close
        entry = h._store._keys.get("zeroize-test")
        assert entry is not None
        kd = entry["versions"][0]["key_data"]
        assert isinstance(kd, bytearray), "key_data must be bytearray before close"

        h.close_session()

        # After close, the same bytearray object must be all-zero
        assert all(b == 0 for b in kd), (
            "key_data bytearray must be zeroed after close_session()"
        )
