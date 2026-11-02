# PyHSM Adversarial Testing Report

**Project:** PyHSM  
**Version tested:** current (`main` branch)  
**Date:** November 2, 2026  
**Tested by:** VectorGuard Labs internal review  
**Test file:** `tests/test_adversarial.py`  
**Result: 80 / 80 adversarial tests passed**

---

## Purpose

This document records the adversarial testing performed against PyHSM. Each test
represents a specific attack scenario — not a happy-path workflow. The goal is to
demonstrate that PyHSM detects or rejects hostile inputs at every security
boundary, and that this is proven by automated, reproducible tests, not manual
inspection.

Adversarial tests are distinct from functional tests. A functional test checks
that something works. An adversarial test checks that something *fails safely*
when attacked.

To reproduce all results:

```bash
python -m pytest tests/test_adversarial.py -v --no-cov
```

---

## Test Categories

| Category | Code | Tests | Result |
|----------|------|-------|--------|
| Keystore tamper / authentication attacks | AT-KS | 7 | ✅ All passed |
| Password policy enforcement | AT-PW | 7 | ✅ All passed |
| Key ID injection | AT-KI | 8 | ✅ All passed |
| Ciphertext tampering | AT-CP | 7 | ✅ All passed |
| Policy / access control enforcement | AT-PL | 13 | ✅ All passed |
| Rate limiter abuse | AT-RL | 4 | ✅ All passed |
| Audit log tampering | AT-AU | 7 | ✅ All passed |
| Shamir secret sharing attacks | AT-SS | 10 | ✅ All passed |
| JWK import attacks | AT-JW | 6 | ✅ All passed |
| Session integrity attacks | AT-SE | 6 | ✅ All passed |
| Password file permission attacks | AT-PF | 5 | ✅ All passed |
| **Total** | | **80** | **✅ 80 / 80** |

---

## AT-KS: Keystore Tamper / Authentication Attacks

**Threat:** An attacker with filesystem access modifies the encrypted keystore
file directly, attempting to recover key material or corrupt the HSM state.

**Defense:** Encrypt-then-MAC envelope — AES-256-GCM ciphertext protected by a
separate HMAC-SHA256 computed over the ciphertext. Both keys are derived from the
master password via Argon2id (64 MB memory-hard KDF). Any modification to any
byte of the file breaks either the HMAC check or the GCM authentication tag.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-KS-01 | Single bit-flip anywhere in ciphertext | `TamperError` raised | ✅ |
| AT-KS-02 | HMAC field overwritten with zeros | `TamperError` raised | ✅ |
| AT-KS-03 | File truncated below minimum valid length (76 bytes) | `TamperError` raised | ✅ |
| AT-KS-04 | Wrong master password presented | `TamperError` or `Exception`, no key material released | ✅ |
| AT-KS-05 | Keystore replaced with a zero-byte file | `TamperError` raised | ✅ |
| AT-KS-06 | Keystore replaced with random garbage of valid length | `TamperError` raised | ✅ |
| AT-KS-07 | Salt bytes (bytes 0–15) replaced with random bytes | `TamperError` raised | ✅ |

**Key point:** AT-KS-03 and AT-KS-06 together confirm that both structural
integrity (minimum length) and cryptographic integrity (HMAC) are checked — an
attacker cannot craft a synthetic keystore that passes either check without the
master password.

---

## AT-PW: Password Policy Enforcement

**Threat:** An attacker configures PyHSM with a weak or trivially guessable
master password, making the keystore vulnerable to offline brute-force attack
despite the Argon2id KDF.

**Defense:** `_validate_master_password()` enforces minimum 12-character length
(NIST SP 800-63B), at least 3 distinct characters, no single-character repetition,
and a deny-list of 30+ known-weak patterns that pass length and entropy checks
but are trivially guessable (e.g. "password123456", "123456789012").

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-PW-01 | No password provided (hoping for a default) | `ValueError: master_password … is required` | ✅ |
| AT-PW-02 | Empty string password | `ValueError` | ✅ |
| AT-PW-03 | Password shorter than 12 characters | `ValueError: too short` | ✅ |
| AT-PW-04 | All-same-character password ("aaaaaaaaaaaa") | `ValueError: single repeated character` | ✅ |
| AT-PW-05 | Two-distinct-character password ("ababababababab") | `ValueError` | ✅ |
| AT-PW-06 | Known-weak pattern: "password123456" | `ValueError: known-weak` | ✅ |
| AT-PW-07 | Known-weak pattern: "123456789012" | `ValueError: known-weak` | ✅ |

**Key point:** AT-PW-06 and AT-PW-07 are significant — these passwords pass naive
length and character-diversity checks but are among the most commonly used
passwords in breach databases. The deny-list explicitly rejects them.

---

## AT-KI: Key ID Injection

**Threat:** An attacker injects a malicious string as a key ID to cause path
traversal, shell argument injection, or key-lookup collision.

**Defense:** `_validate_key_id()` enforces the regex
`^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}$`. This allows only alphanumeric characters,
dots, dashes, and underscores; requires an alphanumeric start character; and caps
length at 128 characters.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-KI-01 | Path traversal: `../traversal` | `ValueError: Invalid key ID` | ✅ |
| AT-KI-02 | Null byte: `key\x00null` | `ValueError: Invalid key ID` | ✅ |
| AT-KI-03 | Path separator: `key/subdir` | `ValueError: Invalid key ID` | ✅ |
| AT-KI-04 | Space: `my key` | `ValueError: Invalid key ID` | ✅ |
| AT-KI-05 | Empty string: `""` | `ValueError: Invalid key ID` | ✅ |
| AT-KI-06 | Looks like CLI flag: `-key` | `ValueError: Invalid key ID` | ✅ |
| AT-KI-07 | Oversized: 129-character string | `ValueError: Invalid key ID` | ✅ |
| AT-KI-08 | Duplicate ID (overwrite attempt) | `ValueError: already exists` | ✅ |

---

## AT-CP: Ciphertext Tampering

**Threat:** An attacker intercepts or modifies encrypted data, either to recover
plaintext or to have a different key decrypt it (cross-key oracle attack).

**Defense:** AES-256-GCM provides authenticated encryption — any modification to
ciphertext, nonce, or AAD invalidates the authentication tag. The AAD (Additional
Authenticated Data) includes the key ID and version number, binding each
ciphertext to a specific key and version so it cannot be decrypted under a
different key.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-CP-01 | Single bit-flip in ciphertext | `Exception` (GCM `InvalidTag`) | ✅ |
| AT-CP-02 | Ciphertext truncated to 10 bytes | `ValueError: too short` | ✅ |
| AT-CP-03 | Cross-key: decrypt key-A ciphertext under key-B | `Exception` (AAD mismatch → `InvalidTag`) | ✅ |
| AT-CP-04 | Version replay: modify version prefix to claim v2 | `Exception` (GCM tag over original bytes) | ✅ |
| AT-CP-05 | Oversized plaintext (64 MB + 1 byte) | `ValueError: too large` | ✅ |
| AT-CP-06 | Oversized ciphertext hex string | `ValueError: too large` | ✅ |
| AT-CP-07 | Random garbage submitted as ciphertext | `Exception` | ✅ |

**Key point:** AT-CP-03 is the cross-key oracle test. It confirms that a
ciphertext encrypted under `key-a` cannot be fed to `decrypt("key-b", …)` to
obtain the plaintext — the AAD binding prevents this. AT-CP-04 confirms the
version prefix is part of the authenticated data, so version forgery is also
detected.

---

## AT-PL: Policy / Access Control Enforcement

**Threat:** An attacker attempts to use keys for operations their policy forbids,
or to perform operations as an unauthorized caller.

**Defense:** `_enforce_policy()` runs five checks in order — caller ACL,
operation permission, max operations, key expiry, rate limit. The first four have
no side effects. The rate limiter runs last so that rejected callers cannot burn
tokens for authorized ones.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-PL-01 | Encrypt on key with `allow_encrypt: false` | `ValueError: policy denies encrypt` | ✅ |
| AT-PL-02 | Decrypt on key with `allow_decrypt: false` | `ValueError: policy denies decrypt` | ✅ |
| AT-PL-03 | Sign on key with `allow_sign: false` | `ValueError: policy denies sign` | ✅ |
| AT-PL-04 | Exceed `max_operations` limit | `ValueError: exceeded max operations` | ✅ |
| AT-PL-05 | Use key past its `expires_at` date | `ValueError: has expired` | ✅ |
| AT-PL-06 | Unauthorized `caller_id` on ACL-protected key | `ValueError: not authorized` | ✅ |
| AT-PL-07 | `caller_id=None` on ACL-protected key | `ValueError: not authorized` | ✅ |
| AT-PL-08 | Unauthorized caller attempts to sign | `ValueError: not authorized` | ✅ |
| AT-PL-09 | JWK export without `allow_export: true` | `ValueError: policy denies export` | ✅ |
| AT-PL-10 | Rotate an EC/RSA key (rotation is AES-only) | `ValueError` (AES-only message) | ✅ |
| AT-PL-11 | Encrypt with an RSA key | `ValueError: AES key` | ✅ |
| AT-PL-12 | Sign with an AES key | `ValueError: RSA, EC, or Ed25519` | ✅ |
| AT-PL-13 | Denied access is recorded in audit log | `accessDenied` entry with `success=false` present | ✅ |

**Key point:** AT-PL-13 confirms that access-control violations are not silently
swallowed — every denial creates a forensic record in the audit log, even when
the caller's exception handler catches the `ValueError`. AT-PL-07 confirms that
`caller_id=None` is not treated as a wildcard on ACL-protected keys.

---

## AT-RL: Rate Limiter Abuse

**Threat:** An attacker floods a key with decrypt requests to perform bulk key
material recovery (e.g., plaintext-known-ciphertext attack), or exploits a race
condition to exceed the rate limit.

**Defense:** Sliding-window `RateLimiter` with a thread-safe global lock wrapping
the entire read-modify-write sequence. Rate limits are per-key and independent.
The rate limit check runs after the ACL check so unauthorized callers cannot
consume tokens for authorized ones.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-RL-01 | Flood key with requests beyond `rate_limit_max_ops` | `ValueError: rate-limited` after limit | ✅ |
| AT-RL-02 | DoS via unauthorized calls to exhaust rate limit window | Denied calls do not consume tokens; authorized caller unaffected | ✅ |
| AT-RL-03 | Exhaust one key's limit and probe another | Other key remains unaffected (per-key isolation) | ✅ |
| AT-RL-04 | 50 threads race to call `allow()` simultaneously | Total admitted ≤ `max_ops` (no check-then-act race) | ✅ |

**Key point:** AT-RL-04 is a regression test for a concurrency vulnerability
(check-then-act race) that was fixed in v2.3.1. Previously, two threads could
both pass the `len(window) >= max_ops` check before either appended, allowing up
to 2× the configured limit. The fix wraps the entire operation in a lock.

---

## AT-AU: Audit Log Tampering

**Threat:** An attacker with log file access modifies, deletes, or inserts audit
entries to hide evidence of unauthorized access or erase the forensic trail.

**Defense:** Each audit entry carries an HMAC-SHA256 tag computed over the entry's
content chained to the previous entry's HMAC. Any modification, deletion, or
insertion breaks the chain and is detected by `verify()`. The HMAC key is derived
from the master password via Argon2id, so it is not in the log file itself.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-AU-01 | Modify `success` field in an audit entry | `verify()` returns the tampered sequence number (not -1) | ✅ |
| AT-AU-02 | Delete an audit entry from the log file | Chain break detected; `verify()` returns non-(-1) | ✅ |
| AT-AU-03 | Insert a forged entry into the log file | Forged entry breaks chain; `verify()` returns non-(-1) | ✅ |
| AT-AU-04 | Create `AuditLog` without providing an HMAC key | `ValueError: hmac_key is required` | ✅ |
| AT-AU-05 | Set HTTP webhook URL (SSRF attempt) | `ValueError: must use https://` | ✅ |
| AT-AU-06 | Set `file://` webhook URL (local read attempt) | `ValueError: must use https://` | ✅ |
| AT-AU-07 | Unmodified log chain verification baseline | `verify()` returns -1 (all-clear) | ✅ |

**Key point:** AT-AU-05 and AT-AU-06 address SSRF (Server-Side Request Forgery).
If a compromised environment variable points the webhook to an internal service,
the webhook rejects it outright. AT-AU-07 is the clean-state baseline — a
necessary control to confirm that `verify()` doesn't always return non-(-1).

---

## AT-SS: Shamir Secret Sharing Attacks

**Threat:** An attacker has fewer shares than the threshold, or submits forged or
modified shares, attempting to recover the secret or cause a wrong value to be
silently accepted.

**Defense:** Per-share HMAC-SHA256 pre-verification (before any interpolation),
post-reconstruction HMAC verification, and constant-time GF(256) arithmetic using
the Russian-peasant algorithm. The HMAC covers `(index_byte || share_data)`,
binding each tag to its specific share index to prevent transplantation.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-SS-01 | Present k-1 of k required shares | `ValueError: checksum verification` — wrong result detected | ✅ |
| AT-SS-02 | Tamper share data but keep original HMAC | `ValueError: HMAC verification` — rejected before interpolation | ✅ |
| AT-SS-03 | Transplant share-1's HMAC tag onto share-3's data | `ValueError: HMAC verification` — index binding prevents transplant | ✅ |
| AT-SS-04 | Flip a bit in share data hex | `ValueError: HMAC verification` | ✅ |
| AT-SS-05 | Provide non-hex `hmac_salt` string | `ValueError: hmac_salt is not valid hex` | ✅ |
| AT-SS-06 | Mix shares from two different splits | `ValueError: checksum verification` | ✅ |
| AT-SS-07 | Split an empty secret | `ValueError` | ✅ |
| AT-SS-08 | Threshold k=1 (any share reveals secret) | `ValueError: Invalid k/n` | ✅ |
| AT-SS-09 | Threshold k > n (reconstruction impossible) | `ValueError: Invalid k/n` | ✅ |
| AT-SS-10 | Provide only one share for reconstruction | `ValueError: at least 2 shares` | ✅ |

**Key point:** AT-SS-02 is critical — the per-share HMAC pre-verification runs
*before* Lagrange interpolation begins. This means a forged share is rejected
before any secret-dependent computation occurs, preventing a chosen-share oracle
attack where an attacker submits crafted shares and observes partial results.

AT-SS-03 confirms the index-binding property — a valid HMAC from share index 1
cannot be transplanted onto share index 3 because the HMAC covers the index byte
alongside the share data.

---

## AT-JW: JWK Import Attacks

**Threat:** An attacker imports a deliberately weak or non-standard key through
the JWK import API, bypassing key generation strength requirements.

**Defense:** `import_jwk()` enforces minimum RSA key size (only 2048 and 4096
bits allowed), rejects unsupported curves and key types, and validates byte
lengths for symmetric and Ed25519 keys.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-JW-01 | Import RSA-1024 JWK (factored in days) | `ValueError: not allowed` | ✅ |
| AT-JW-02 | Import RSA-3072 JWK (not in allowed set) | `ValueError: not allowed` | ✅ |
| AT-JW-03 | Import JWK with unknown `kty` field | `ValueError: Unsupported JWK key type` | ✅ |
| AT-JW-04 | Import EC JWK with P-192 curve (deprecated) | `ValueError: Unsupported curve` | ✅ |
| AT-JW-05 | Import symmetric JWK with 24-byte key (192-bit) | `ValueError: Unsupported symmetric key size` | ✅ |
| AT-JW-06 | Import OKP JWK with X25519 curve (ECDH, not signing) | `ValueError: Unsupported OKP curve` | ✅ |

**Key point:** AT-JW-01 confirms that the JWK import path cannot be used to
bypass the minimum key size that is enforced at generation time. An attacker
cannot import a 1024-bit RSA key even though `generate_key("rsa-1024")` is also
rejected. AT-JW-02 confirms that even valid NIST key sizes (3072-bit) are
rejected if they are not in the explicitly approved set, reducing attack surface
from unexpected key types.

---

## AT-SE: Session Integrity Attacks

**Threat:** An attacker reuses a closed HSM session, or attempts operations on
resources that do not exist.

**Defense:** `_assert_session()` guards every operation. After `close_session()`,
key material is zeroized and `_session_active` is set to `False`. Any subsequent
call raises `RuntimeError` immediately without touching any key material.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-SE-01 | Call `list_keys()` after `close_session()` | `RuntimeError: session is closed` | ✅ |
| AT-SE-02 | Call `encrypt()` after `close_session()` | `RuntimeError: session is closed` | ✅ |
| AT-SE-03 | Call `close_session()` twice | Second call silently ignored (no double-free) | ✅ |
| AT-SE-04 | Encrypt with a nonexistent key ID | `KeyError` | ✅ |
| AT-SE-05 | Destroy a nonexistent key | `KeyError` | ✅ |
| AT-SE-06 | Rotate a nonexistent key | `KeyError` | ✅ |

---

## AT-PF: Password File Permission Attacks

**Threat:** An attacker exploits a misconfigured or symlinked password file to
read the master password or inject an attacker-controlled password.

**Defense:** `load_password_from_file()` uses `O_NOFOLLOW` to refuse symlinks
(preventing TOCTOU race conditions), verifies file ownership matches the calling
process's UID, rejects group-readable and world-readable files, and rejects empty
files.

| Test ID | Attack Scenario | Expected Behavior | Result |
|---------|----------------|-------------------|--------|
| AT-PF-01 | Password file mode 0o644 (world-readable) | `PermissionError` | ✅ |
| AT-PF-02 | Password file mode 0o640 (group-readable) | `PermissionError: group-readable` | ✅ |
| AT-PF-03 | Password file is a symlink (TOCTOU attack) | `PermissionError: symbolic link` | ✅ |
| AT-PF-04 | Password file is empty | `ValueError` | ✅ |
| AT-PF-05 | Password file mode 0o600 with correct content | Loads successfully (valid baseline) | ✅ |

**Key point:** AT-PF-03 is the TOCTOU (time-of-check/time-of-use) prevention
test. `O_NOFOLLOW` causes the open syscall to fail with `ELOOP` if the final
path component is a symlink, before any stat-based checks even run. This prevents
an attacker from swapping the target between a permissions check and a read.

---

## What This Testing Does and Does Not Prove

### What it proves

- PyHSM rejects every tested attack input without releasing key material.
- All 80 attack scenarios fail in the expected, documented way.
- The rejections are enforced automatically and repeatedly — any future code
  change that breaks a rejection will immediately fail a test in CI.
- Specific security properties are tested: encrypt-then-MAC integrity, AAD
  cross-key binding, Argon2id-gated authentication, HMAC chain tamper detection,
  pre-interpolation share verification, per-index HMAC binding, and rate-limit
  race condition prevention.

### What it does not prove

- **Side-channel resistance at the hardware level.** Timing attacks against the
  CPU execution units, cache-timing attacks, or power analysis are not covered
  by software tests. A hardware-level side-channel audit requires dedicated
  measurement equipment and methodology.
- **Absence of unknown vulnerabilities.** Passing these tests means the known
  attack surfaces are defended. It does not guarantee the absence of novel
  attacks that were not anticipated during test design.
- **IPC process isolation security.** The `ipc_client.py` / `ipc_server.py`
  process-isolation layer has no adversarial test coverage and was not assessed
  in this round.
- **Network-facing attack surface.** PyHSM is a library, not a network service.
  If it is exposed via an API layer, that layer requires its own security assessment.
- **Independent validation.** These tests were designed and run by the same team
  that wrote the code. Independent third-party adversarial testing and code review
  are the next recommended step before production deployment in high-assurance
  environments.

---

## Recommended Next Steps

1. **Independent security audit** of `hsm/storage.py`, `hsm/core.py`, and
   `hsm/shamir.py` by a third-party cryptographic review firm.
2. **IPC layer adversarial tests** — add equivalent coverage for
   `ipc_client.py` / `ipc_server.py`, including privilege-escalation scenarios
   and malformed IPC message injection.
3. **Cross-rotation audit chain verification test** — add a test that verifies
   `verify_across_rotations()` detects a deleted or replaced rotated log file.
4. **Session timeout test** — add a test that verifies the background timeout
   thread actually calls `close_session()` and zeroizes key material.
5. **Fuzz testing** — integrate a fuzzer (e.g., Hypothesis or Atheris) against
   `import_jwk()`, `reconstruct_secret()`, and `decrypt()` to discover inputs
   beyond the manually crafted adversarial cases.
