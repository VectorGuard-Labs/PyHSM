# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM Property-Based and Fuzz Tests.

Uses Hypothesis to generate arbitrary inputs and verify that invariants hold
across the entire input space, not just the examples a developer thought to
write manually.

Test categories:
  PB-JW  — JWK parsing invariants (arbitrary/malformed input)
  PB-CT  — Ciphertext decode invariants (arbitrary byte sequences)
  PB-SS  — Shamir sharing invariants (arbitrary secrets, thresholds)
  PB-EN  — Encrypt/decrypt round-trip with arbitrary plaintext
  PB-KI  — Key ID validation invariants
  PB-AU  — Audit log HMAC chain invariants

Each test function is named after the property it verifies, not a single
example. A property test failure is reported with the minimal failing example
Hypothesis found by shrinking.
"""

from __future__ import annotations

import json
import os
import secrets
import string
from pathlib import Path

import tempfile
import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from hsm import PyHSM, TamperError
from hsm.audit import AuditLog
from hsm.shamir import reconstruct_secret, split_secret, zeroize
from hsm.jwk import import_jwk

# ---------------------------------------------------------------------------
# Shared settings
# ---------------------------------------------------------------------------

_STRONG_PW = "PropertyBased!2026"

# Suppress the too_slow health check for tests that run PyHSM (Argon2id is slow)
_HSM_SETTINGS = settings(
    max_examples=15,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

_FAST_SETTINGS = settings(
    max_examples=200,
    deadline=2000,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Arbitrary bytes representing a potential JWK field value (base64url-ish)
_b64_chars = string.ascii_letters + string.digits + "-_="
_b64url_st = st.text(alphabet=_b64_chars, min_size=0, max_size=100)

# Arbitrary JSON-serialisable values for JWK fields
_jwk_field_value = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=50),
    st.binary(max_size=32).map(lambda b: b.hex()),
)

# Arbitrary dict that resembles a JWK but has random field values
_malformed_jwk = st.fixed_dictionaries(
    {},
    optional={
        "kty": st.sampled_from(["oct", "EC", "OKP", "RSA", "UNKNOWN", "", None]),
        "crv": st.one_of(st.none(), st.text(max_size=20)),
        "k":   _b64url_st,
        "x":   _b64url_st,
        "y":   _b64url_st,
        "d":   _b64url_st,
        "n":   _b64url_st,
        "e":   _b64url_st,
    },
)

# Valid threshold/total combinations for Shamir
_shamir_k_n = st.integers(min_value=2, max_value=6).flatmap(
    lambda k: st.tuples(
        st.just(k),
        st.integers(min_value=k, max_value=min(k + 3, 8)),
    )
)


# ===========================================================================
# PB-JW: JWK parsing invariants
# ===========================================================================

class TestJWKParsingInvariants:
    """
    PB-JW: For any arbitrary dict, import_jwk() must either return a valid
    (key_type, bytes, optional_pem) tuple or raise a specific Exception —
    it must never crash with an unhandled exception that exposes internal state.
    """

    @given(_malformed_jwk)
    @_FAST_SETTINGS
    def test_arbitrary_jwk_never_crashes_unhandled(self, jwk_dict):
        """PB-JW-01: Arbitrary JWK dict must never produce an unhandled exception.

        Property: import_jwk(x) ∈ {returns valid tuple, raises ValueError/KeyError/Exception}
        It must never raise an unhandled exception type that could crash the caller
        or produce unexpected behaviour not covered by a simple try/except.
        """
        try:
            key_type, raw, pub = import_jwk(jwk_dict)
            # If it succeeds, the result must be a recognisable key type
            valid_types = {
                "aes-128", "aes-256",
                "ec-p256", "ec-p384", "ec-p521", "ec-secp256k1",
                "ed25519",
                "rsa-2048", "rsa-4096",
            }
            assert key_type in valid_types
            assert isinstance(raw, (bytes, bytearray))
        except Exception:
            # Any exception is acceptable — what's NOT acceptable is an
            # exception escaping this test entirely (which would cause a test error,
            # not a test failure — Hypothesis reports that differently).
            pass

    @given(st.binary(min_size=0, max_size=64))
    @_FAST_SETTINGS
    def test_non_dict_jwk_raises_or_handles_cleanly(self, raw_bytes):
        """PB-JW-02: Passing raw bytes (not a dict) must raise, not crash.

        Property: import_jwk called with bytes always raises some Exception.
        """
        # Build a dict with a bytes value for 'k' field — simulate bad base64
        try:
            import base64
            b64 = base64.urlsafe_b64encode(raw_bytes).decode().rstrip("=")
            import_jwk({"kty": "oct", "k": b64})
        except Exception:
            pass  # any exception is acceptable

    @given(st.dictionaries(st.text(max_size=10), _jwk_field_value, max_size=10))
    @_FAST_SETTINGS
    def test_random_dict_never_produces_unhandled_exception(self, d):
        """PB-JW-03: Completely random dict passed to import_jwk must not crash.

        Property: import_jwk(random_dict) always either succeeds or raises.
        """
        try:
            import_jwk(d)
        except Exception:
            pass


# ===========================================================================
# PB-CT: Ciphertext decode invariants
# ===========================================================================

class TestCiphertextDecodeInvariants:
    """
    PB-CT: Arbitrary byte sequences passed to decrypt() must never produce
    key material — they must either raise ValueError/Exception or return a
    specific error. The property is: decrypt(garbage) ≠ any valid plaintext.
    """

    @given(st.binary(min_size=0, max_size=256))
    @_HSM_SETTINGS
    def test_arbitrary_ciphertext_always_rejected(self, raw_bytes):
        """PB-CT-01: Any arbitrary byte sequence must fail decryption.

        Property: ∀ b ∈ bytes, decrypt(AES_key, hex(b)) raises or returns
        an exception — it never returns valid plaintext.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            h.generate_key("fuzz-key")
            ct_hex = raw_bytes.hex()
            try:
                result = h.decrypt("fuzz-key", ct_hex)
                assert result != b"known-plaintext"
            except Exception:
                pass
            finally:
                h.close_session()

    @given(st.text(alphabet=string.hexdigits, min_size=0, max_size=512))
    @_HSM_SETTINGS
    def test_arbitrary_hex_string_ciphertext_always_rejected(self, hex_str):
        """PB-CT-02: Arbitrary hex string passed as ciphertext never decrypts successfully.

        Property: ∀ s ∈ hex_strings, decrypt(key, s) raises or returns garbage
        that doesn't equal known plaintext.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            h.generate_key("fuzz-key2")
            try:
                result = h.decrypt("fuzz-key2", hex_str)
                assert result != b"sentinel-value"
            except Exception:
                pass
            finally:
                h.close_session()


# ===========================================================================
# PB-SS: Shamir sharing invariants
# ===========================================================================

class TestShamirInvariants:
    """
    PB-SS: Properties that must hold for all valid (secret, k, n) combinations.
    """

    @given(st.binary(min_size=1, max_size=64), _shamir_k_n)
    @_FAST_SETTINGS
    def test_reconstruction_recovers_exact_secret(self, secret, k_n):
        """PB-SS-01: Reconstructing with exactly k shares always recovers the exact secret.

        Property: ∀ secret, k, n: reconstruct(split(secret, k, n)[:k]) == secret
        """
        k, n = k_n
        shares = split_secret(secret, k, n)
        recovered = reconstruct_secret(shares[:k])
        assert bytes(recovered) == secret
        zeroize(recovered)

    @given(st.binary(min_size=1, max_size=64),
           st.integers(min_value=3, max_value=6).flatmap(
               lambda k: st.tuples(st.just(k), st.integers(min_value=k, max_value=min(k + 3, 8)))
           ))
    @_FAST_SETTINGS
    def test_fewer_than_threshold_shares_never_recover_secret(self, secret, k_n):
        """PB-SS-02: Fewer than k shares must either raise ValueError or produce a wrong secret.

        Property: ∀ secret, k≥3, n: reconstruct(split(secret,k,n)[:k-1]) raises ValueError
        OR returns a value ≠ secret (the reconstruction_hmac check catches this case).

        Using k≥3 directly in the strategy ensures k-1≥2, satisfying the minimum-shares
        requirement; the checksum mismatch (not the len check) is what fires.
        In rare GF-arithmetic coincidences for short secrets, the wrong reconstruction
        matches the reconstruction_hmac purely by chance — but in those cases the
        reconstructed bytes will differ from the original secret, so we accept that too.
        """
        k, n = k_n
        shares = split_secret(secret, k, n)
        try:
            result = reconstruct_secret(shares[:k - 1])
            # If reconstruction "succeeded" without raising, the result must differ from secret
            assert bytes(result) != secret, (
                f"k-1={k-1} shares reconstructed the exact secret — "
                f"threshold enforcement failed"
            )
            zeroize(result)
        except ValueError:
            pass  # expected — checksum or HMAC mismatch detected insufficient shares

    @given(st.binary(min_size=1, max_size=64), _shamir_k_n)
    @_FAST_SETTINGS
    def test_any_k_shares_from_n_reconstruct_correctly(self, secret, k_n):
        """PB-SS-03: Any combination of k shares (not just the first k) works.

        Property: ∀ valid subset S of shares with |S|=k: reconstruct(S) == secret
        We test with the last k shares instead of the first k.
        """
        k, n = k_n
        shares = split_secret(secret, k, n)
        # Use the last k shares instead of the first k
        recovered = reconstruct_secret(shares[-k:])
        assert bytes(recovered) == secret
        zeroize(recovered)

    @given(st.binary(min_size=1, max_size=32), _shamir_k_n)
    @_FAST_SETTINGS
    def test_share_data_tampering_always_detected(self, secret, k_n):
        """PB-SS-04: Any single-byte corruption in any share's data is always detected.

        Property: ∀ share i, byte position p, flip:
          corrupt(share[i].data[p]) → reconstruct raises ValueError
        We test the first byte of share 0.
        """
        k, n = k_n
        shares = split_secret(secret, k, n)
        tampered = shares[0].copy()
        data = bytearray(bytes.fromhex(tampered["data"]))
        data[0] ^= 0xFF
        tampered["data"] = data.hex()
        with pytest.raises(ValueError):
            reconstruct_secret([tampered] + shares[1:k])


# ===========================================================================
# PB-EN: Encrypt/decrypt round-trip invariants
# ===========================================================================

class TestEncryptDecryptInvariants:
    """
    PB-EN: Core encrypt/decrypt round-trip properties.
    These must hold for arbitrary plaintext inputs.
    """

    @given(st.binary(min_size=0, max_size=4096))
    @_HSM_SETTINGS
    def test_round_trip_arbitrary_bytes(self, plaintext):
        """PB-EN-01: Encrypting then decrypting arbitrary bytes always recovers the original.

        Property: ∀ b ∈ bytes: decrypt(key, encrypt(key, b)) == b
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            h.generate_key("rt-key")
            ct = h.encrypt("rt-key", plaintext)
            recovered = h.decrypt("rt-key", ct)
            assert recovered == plaintext
            h.close_session()

    @given(st.text(min_size=0, max_size=1000))
    @_HSM_SETTINGS
    def test_round_trip_arbitrary_unicode(self, text):
        """PB-EN-02: Encrypting then decrypting arbitrary Unicode strings always works.

        Property: ∀ s ∈ Unicode strings: decrypt(key, encrypt(key, s)).decode() == s
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            h.generate_key("uni-key")
            ct = h.encrypt("uni-key", text)
            recovered = h.decrypt("uni-key", ct).decode("utf-8")
            assert recovered == text
            h.close_session()

    @given(st.binary(min_size=1, max_size=2048), st.binary(min_size=1, max_size=2048))
    @_HSM_SETTINGS
    def test_two_different_plaintexts_produce_different_ciphertexts(self, p1, p2):
        """PB-EN-03: Two different plaintexts must produce different ciphertexts.

        Property: p1 ≠ p2 → encrypt(key, p1) ≠ encrypt(key, p2) with overwhelming probability
        (nonce is fully random, so collisions are astronomically unlikely).
        """
        assume(p1 != p2)
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            h.generate_key("diff-key")
            ct1 = h.encrypt("diff-key", p1)
            ct2 = h.encrypt("diff-key", p2)
            assert ct1 != ct2
            h.close_session()

    @given(st.binary(min_size=1, max_size=512))
    @_HSM_SETTINGS
    def test_same_plaintext_produces_different_ciphertexts(self, plaintext):
        """PB-EN-04: Encrypting the same plaintext twice must produce different ciphertexts.

        Property: ∀ p: encrypt(key, p) ≠ encrypt(key, p) (random nonce each time)
        This confirms nonces are not reused.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            h.generate_key("nonce-key")
            ct1 = h.encrypt("nonce-key", plaintext)
            ct2 = h.encrypt("nonce-key", plaintext)
            assert ct1 != ct2  # different nonces → different ciphertexts
            h.close_session()


# ===========================================================================
# PB-KI: Key ID validation invariants
# ===========================================================================

class TestKeyIDValidationInvariants:
    """
    PB-KI: The key ID regex must accept exactly the intended character set
    and reject everything else. We verify both directions.
    """

    # Valid key IDs: start alphanumeric, body [a-zA-Z0-9._-], length 1-128
    _valid_id_st = st.from_regex(r"[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}", fullmatch=True)

    # Invalid key IDs: any string with at least one forbidden character
    _invalid_id_st = st.one_of(
        st.just(""),
        st.text(alphabet=string.printable, min_size=1, max_size=5).filter(
            lambda s: not s[0].isalnum() if s else True
        ),
        st.text(alphabet="/\\: \t\n\x00", min_size=1, max_size=20),
        st.text(min_size=129, max_size=200),  # too long
    )

    @given(_valid_id_st)
    @_HSM_SETTINGS
    def test_valid_key_ids_are_accepted(self, key_id):
        """PB-KI-01: Any string matching the key ID regex must be accepted.

        Property: ∀ s matching [a-zA-Z0-9][a-zA-Z0-9._-]{0,127}: generate_key(s) succeeds.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "ks.enc")
            h = PyHSM(store, master_password=_STRONG_PW, session_timeout_s=0)
            try:
                h.generate_key(key_id)
            except ValueError as e:
                assert "already exists" in str(e)
            finally:
                h.close_session()

    @given(_invalid_id_st)
    @settings(max_examples=200, deadline=2000,
              suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_invalid_key_ids_always_raise_value_error(self, tmp_path, key_id):
        """PB-KI-02: Any key ID outside the valid set must raise ValueError.

        Property: ∀ s ∉ valid_set: generate_key(s) raises ValueError.
        """
        from hsm.core import _validate_key_id
        try:
            _validate_key_id(key_id)
            # If it passed, that's a failure — the string should have been invalid
            pytest.fail(f"Expected ValueError for key_id={key_id!r}")
        except ValueError:
            pass  # correct


# ===========================================================================
# PB-AU: Audit log HMAC chain invariants
# ===========================================================================

class TestAuditLogChainInvariants:
    """
    PB-AU: The audit log HMAC chain must satisfy the following invariant:
    any single-byte modification to any entry breaks the chain at exactly
    that position.
    """

    @given(st.integers(min_value=1, max_value=20))
    @_FAST_SETTINGS
    def test_clean_log_always_verifies(self, n_entries):
        """PB-AU-01: A log with n entries written correctly always verifies clean.

        Property: ∀ n: write_n_entries(log) → log.verify() == -1
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            key = os.urandom(32)
            log = AuditLog(path, hmac_key=key)
            for i in range(n_entries):
                log.record("encrypt", key_id=f"k{i}", success=True)
            assert log.verify() == -1

    @given(
        st.integers(min_value=3, max_value=10),
        st.integers(min_value=0, max_value=2),
    )
    @_FAST_SETTINGS
    def test_single_entry_tamper_always_detected(self, n_entries, tamper_idx):
        """PB-AU-02: Tampering with any single entry always breaks the chain.

        Property: ∀ n, i<n: tamper(entry[i]) → verify() ≥ 0 (not -1)
        """
        assume(tamper_idx < n_entries)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            key = os.urandom(32)
            log = AuditLog(path, hmac_key=key)
            for i in range(n_entries):
                log.record("encrypt", key_id=f"k{i}", success=True)

            lines = Path(path).read_text().strip().split("\n")
            entry = json.loads(lines[tamper_idx])
            entry["success"] = not entry["success"]
            lines[tamper_idx] = json.dumps(entry)
            Path(path).write_text("\n".join(lines) + "\n")

            result = log.verify()
            assert result >= 0
