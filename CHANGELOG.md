# PyHSM Changelog

All security-relevant changes are cross-referenced in [SECURITY.md](SECURITY.md).
Versions follow [Semantic Versioning](https://semver.org/).
Repository: https://github.com/VectorGuard-Labs/PyHSM

---

## [2.3.7] — 2026-11-02

### Changed
- Repository moved to **https://github.com/VectorGuard-Labs/PyHSM**.
  All documentation, `pyproject.toml` URLs, systemd unit references, and
  security advisory links updated to reflect the new organisation.
- All `*.md` files updated to document changes from v2.3.2 through v2.3.6:
  Ethereum integration, cross-process audit integration tests, AT-AS and
  AT-KS-EX adversarial test categories, CHANGELOG creation, and audit chain
  bug fix.

---

## [2.3.6] — 2026-11-02

### Added
- `hsm/ethereum.py` — Ethereum / EVM blockchain signing module:
  - `keccak256()` — Ethereum Keccak-256 hash (pre-standardisation, not SHA3-256)
  - `eth_address_from_public_key()` — secp256k1 PEM → EIP-55 checksummed address
  - `eip191_personal_sign_hash()` — EIP-191 personal_sign prefix hashing (MetaMask-compatible)
  - `eip1559_transaction_hash()` — EIP-1559 type-2 transaction RLP encoding + Keccak-256 hash
  - `der_to_eth_sig()` — DER ECDSA → 65-byte Ethereum `r ‖ s ‖ v` with recovery identifier
  - `verify_eth_sig()` — verify 65-byte Ethereum sig against expected address
  - `_eip55_checksum()` — EIP-55 mixed-case address checksum
  - `_recover_public_key()` — SEC 1 v2.0 §4.1.6 secp256k1 key recovery
  - Minimal pure-Python RLP encoder for EIP-1559 (no external blockchain deps)
- `PyHSM.sign_digest(key_id, digest)` — sign a pre-computed 32-byte Keccak-256
  digest directly without re-hashing (uses `cryptography.Prehashed`)
- `PyHSM.eth_address(key_id)` — derive EIP-55 Ethereum address for a secp256k1 key
- CLI subcommands `eth-sign` and `eth-address`
- `tests/test_ethereum.py` — 44 tests across 7 categories (ETH-KV through ETH-ERR)
- `pycryptodome>=3.20.0` added to declared dependencies (Keccak-256)

### Fixed
- `cli.py` indentation errors from prior str_replace operations
- `lstrip("0x")` → explicit `[2:]` slice for address/data hex normalisation
  (`lstrip` strips individual characters, not the prefix string)

---

## [2.3.5] — 2026-11-02

### Added
- `tests/test_audit_integration.py` — 6 cross-process audit log integration
  tests proving that audit verification works across separate OS process
  executions, not just within a single in-memory `AuditLog` object:
  - AI-01: clean log verifies in a fresh process (HMAC key re-derived from disk)
  - AI-02: tampered entry detected after process A exits (exit 1, "CORRUPTED")
  - AI-03: chain accumulated across many separate process invocations verifies
  - AI-04: tampered entry reports exact sequence number in error output
  - AI-05: key rotation, encrypt, sign all produce cross-process verifiable chains
  - AI-06: audit log survives session close and reopen; entries readable in new process

---

## [2.3.4] — 2026-11-02

### Fixed
- `audit.py` `verify_across_rotations()`: HMAC chain anchor reset bug.
  The verifier now initialises `current_prev` to `prev_seal_hmac` when
  entering each subsequent file, matching how `_rotate()` writes the
  `rotationOpen` entry. Previously reset to `"0"*64`, making cross-rotation
  verification always fail after the first rotation. Three previously-xfailed
  lifecycle tests now pass.
- `tests/test_lifecycle_recovery.py`: Removed `xfail` markers from LC-AL-01,
  LC-AL-03, and LC-AL-04.
- `tests/test_property_based.py`: Fixed intermittent failure in
  `test_fewer_than_threshold_shares_never_recover_secret` by narrowing the
  Hypothesis strategy to `k≥3`.

### Added
- `tests/test_adversarial.py`: `TestAsymmetricKeyConstraintAttacks` (AT-AS,
  12 tests) covering all key-type misuse scenarios.
- `tests/test_adversarial.py`: `TestKeySeparationVerification` (AT-KS-EX,
  7 tests) proving enc_key ≠ mac_key ≠ kek, salt/password participation,
  `SecureBytes` zeroization, in-place zeroing, and key material zeroed on close.
- `CHANGELOG.md` — this file.

---

## [2.3.3] — 2026-11-02

### Fixed
- `ipc_server.py` deadlock — `_dispatch()` acquired per-key and global locks
  then called PyHSM methods that acquire the same locks (non-reentrant
  deadlock). Every IPC operation silently hung. Removed redundant outer locks.
- `ipc_server.py` signal crash — `signal.signal()` only works on the main
  thread. Added `threading.current_thread() is threading.main_thread()` guard.
- `ipc_server.py` — Added `conn_timeout_s` parameter (default 30 s).

### Added
- `tests/test_ipc_adversarial.py` — 20 IPC adversarial tests (IPC-AU through IPC-LF).
- `tests/test_property_based.py` — 18 Hypothesis property-based tests (PB-JW through PB-AU).
- `tests/test_lifecycle_recovery.py` — 21 lifecycle/recovery tests (LC-ST through LC-CC);
  3 were marked `xfail` for audit chain bug (fixed in 2.3.4).
- `hypothesis>=6.100.0` added to dev dependencies.

### Discovered
- `audit.py` `verify_across_rotations()` HMAC chain anchor bug (fixed in 2.3.4).

---

## [2.3.2] — 2026-11-02

### Fixed
- `hsm/storage.py`: Misleading error message on wrong master password.
  `"TAMPER DETECTED: HMAC verification failed"` → `"Keystore authentication
  failed. The master password may be incorrect, or the keystore may have been
  modified. No key material was released."`
- `tests/test_pyhsm.py`: Updated match string in `test_tamper_detection_flipped_byte`.

### Added
- `tests/test_adversarial.py` — 80 adversarial tests across 11 categories (AT-KS through AT-PF).
- `ADVERSARIAL_TESTING.md` — adversarial test report.

---

## [2.3.1] — 2026-10-29

### Fixed (security)
- `RateLimiter` thread-safety (High) — `threading.Lock` on all methods.
- Audit log `verify()` timing oracle (Medium) — `hmac.compare_digest()`.
- Shamir legacy checksum timing oracle (Medium) — `hmac.compare_digest()`.
- JWK RSA import size (Medium) — allowlist `{2048, 4096}`.
- Ed25519 KAT wrong-key rejection (Low).
- RSA-PSS KAT fixed embedded key + cross-key + tamper checks (Low).

---

## [2.3.0] — 2026-10-15

### Added
- Offline RS256 JWT commercial license token verification.
- `license` CLI subcommand; `get_license_info()` API method.
- Per-tier key limits enforced at `generate_key()`.

---

## [2.2.0] — 2026-09-20

### Fixed (security)
- IPC unauthenticated by default (High) — `--ipc-secret` mandatory.
- IPC global lock DoS (Medium) — per-key locking, 30 s connection timeout.
- Shamir 4-byte checksum (Medium) — per-share HMAC-SHA256.
- KATs missing 6 primitives (Medium) — 10 KATs total.
- Audit chain not spanning rotations (Low) — `rotationSeal`/`rotationOpen`.

---

## [2.1.0] — 2026-08-10

### Added
- IPC process-isolation server/client, secp256k1, Ed25519, EC P-384/P-521,
  JWK import/export, backup/restore, key search, auto-rotation, OTLP metrics.

---

## [2.0.0] — 2026-07-01

Major release. Argon2id required, AES-KWP per-key wrapping, HKDF key
separation, atomic writes, per-key policies, rate limiting, HMAC audit log,
session timeout, SecureBytes zeroization.

---

## [1.x] — Prior to 2026-07-01

End-of-life. No security patches. Upgrade to v2.0.0 or later.


### Added
- `tests/test_ipc_adversarial.py` — 20 IPC adversarial tests across 5 categories:
  authentication attacks (IPC-AU), protocol attacks (IPC-PR), operation attacks (IPC-OP),
  concurrency attacks (IPC-CN), lifecycle attacks (IPC-LF).
- `tests/test_property_based.py` — 18 Hypothesis property-based tests across 6 categories:
  JWK parsing invariants (PB-JW), ciphertext decode invariants (PB-CT), Shamir invariants
  (PB-SS), encrypt/decrypt round-trip invariants (PB-EN), key ID validation invariants
  (PB-KI), audit HMAC chain invariants (PB-AU).
- `tests/test_lifecycle_recovery.py` — 21 lifecycle and recovery tests: session timeout
  (LC-ST), key rotation (LC-KR), backup (LC-BK), audit log rotation (LC-AL), crash-safe
  persistence (LC-IW), concurrent operations (LC-CC).
- `hypothesis>=6.100.0` added to `[project.optional-dependencies] dev`.

### Fixed
- `ipc_server.py`: Deadlock — `_dispatch()` was acquiring per-key and global locks then
  calling PyHSM methods that acquire the same locks (non-reentrant deadlock). Every IPC
  operation involving a key silently hung forever. Removed the redundant outer locks;
  PyHSM core manages its own locking internally.
- `ipc_server.py`: `signal.signal()` called unconditionally in `run()`, crashing when
  invoked from a background thread (only the main thread can install signal handlers).
  Added `threading.current_thread() is threading.main_thread()` guard.
- `ipc_server.py`: Added `conn_timeout_s` parameter to make the per-connection read
  timeout configurable (default 30 s, tests use 2 s).

### Discovered (documented as xfail, now fixed in 2.3.4)
- `audit.py` `verify_across_rotations()` was resetting the HMAC chain anchor to `"0"*64`
  at the start of each rotated file, but entries were written with the running chain anchor
  (the previous file's seal HMAC). This caused cross-rotation verification to always fail
  on any file after the first rotation. Three lifecycle tests were marked `xfail(strict=True)`
  to document the defect pending fix.

---

## [2.3.4] — 2026-11-02

### Fixed
- `audit.py` `verify_across_rotations()`: Fixed HMAC chain anchor reset bug. The verifier
  now initialises `current_prev` to `prev_seal_hmac` (from the preceding file's
  `rotationSeal` entry) when entering each subsequent file, matching how `_rotate()` writes
  the `rotationOpen` entry. Previously reset to `"0"*64`, making cross-rotation verification
  always fail after the first rotation. All 3 previously-xfailed lifecycle tests now pass.
- `tests/test_lifecycle_recovery.py`: Removed `xfail` markers from LC-AL-01, LC-AL-03,
  and LC-AL-04 (all now pass).
- `tests/test_property_based.py`: Fixed intermittent failure in
  `test_fewer_than_threshold_shares_never_recover_secret` by narrowing the Hypothesis
  strategy to `k≥3` directly, eliminating reliance on `assume(k>2)` filter that interacted
  unpredictably with Hypothesis's shrinking database across full suite runs.

### Added
- `tests/test_adversarial.py`: `TestAsymmetricKeyConstraintAttacks` (AT-AS) — 12 tests
  covering all key-type misuse scenarios: encrypt/decrypt with asymmetric keys (RSA, EC,
  Ed25519), sign/verify with symmetric keys (AES-256, AES-128), get_public_key from AES,
  rotate asymmetric keys, and cross-key ciphertext confusion.
- `tests/test_adversarial.py`: `TestKeySeparationVerification` (AT-KS-EX) — 7 tests proving
  cryptographic key separation: enc_key ≠ mac_key, KEK distinct from enc/mac keys, salt
  dependence, password dependence, SecureBytes zeroization, in-place bytearray zeroing, and
  key material zeroed after session close.
- `CHANGELOG.md` — this file.

---

## [2.3.2] — 2026-11-02

### Fixed
- `hsm/storage.py`: Misleading error message when wrong master password is supplied.
  Previous message: `"TAMPER DETECTED: HMAC verification failed. Keystore may have been
  modified outside of PyHSM."` — incorrectly implied actual tampering when a wrong password
  is the more common cause. New message: `"Keystore authentication failed. The master
  password may be incorrect, or the keystore may have been modified. No key material was
  released."` — accurately covers both cases.
- `tests/test_pyhsm.py`: Updated `test_tamper_detection_flipped_byte` match string from
  `"TAMPER"` to `"authentication failed"` to reflect the new message.

### Added
- `tests/test_adversarial.py` — 80 dedicated adversarial tests across 11 attack categories:
  keystore tamper (AT-KS), password policy (AT-PW), key ID injection (AT-KI), ciphertext
  tampering (AT-CP), policy enforcement (AT-PL), rate limiter abuse (AT-RL), audit log
  tampering (AT-AU), Shamir attacks (AT-SS), JWK import attacks (AT-JW), session integrity
  (AT-SE), password file permissions (AT-PF).
- `ADVERSARIAL_TESTING.md` — adversarial test report documenting all 80 scenarios,
  defenses, results, and recommended next steps.

---

## [2.3.1] — 2026-10-29

### Fixed (security)
- `hsm/rate_limiter.py` — **High**: `RateLimiter.allow()` had a check-then-act race under
  concurrent access (two threads could both pass `len(window) >= max_ops` before either
  appended, admitting up to 2× the limit). Fixed by wrapping the entire read-modify-write
  in `threading.Lock`. All three public methods (`allow`, `usage`, `reset`) are now atomic.
- `hsm/audit.py` — **Medium**: `verify()` and `verify_across_rotations()` used plain `!=`
  for HMAC string comparison. Replaced with `hmac.compare_digest()` throughout to prevent
  timing-oracle attacks where an attacker measures response latency to recover the HMAC key.
- `hsm/shamir.py` — **Medium**: Legacy backward-compatible 4-byte checksum path used plain
  `!=`. Replaced with `hmac.compare_digest()`.
- `hsm/jwk.py` — **Medium**: `import_jwk()` accepted RSA keys below 2048 bits (including
  RSA-1024, which can be factored in days). Added allowlist `{2048, 4096}`; keys outside
  this set raise `ValueError` citing NIST SP 800-131A Rev. 2.
- `hsm/self_test.py` — **Low**: Ed25519 KAT used a self-generated test vector, not an
  independently published RFC value. Updated to RFC 8032 §6.1 Test Vector 1. Added
  cross-key rejection and tamper-detection checks.
- `hsm/self_test.py` — **Low**: RSA-PSS KAT was a round-trip only (no fixed key or
  cross-key confusion test). Replaced with a fixed embedded 2048-bit private key; added
  wrong-key and tampered-ciphertext checks.

### Added
- `tests/test_pyhsm.py`: `TestRateLimiterThreadSafety` — concurrent `allow()` race
  condition regression test (50 threads, limit 10, admitted must be ≤ 10).
- `tests/test_pyhsm.py`: `TestJWKWeakKeyRejection` — RSA-1024 import rejection test.
- `tests/test_pyhsm.py`: `TestAuditVerifyConstantTime` — timing-oracle regression test.
- `tests/test_pyhsm.py`: `TestKATVectors` — pinned Ed25519 and RSA-PSS KAT regression tests.

---

## [2.3.0] — 2026-10-15

### Added
- Commercial license system: RS256-signed JWT tokens verified locally (no network call)
  against an embedded RSA-2048 public key. `LicenseError` raised on invalid/expired token.
- `license` CLI subcommand.
- `get_license_info()` API method returning `LicenseInfo` dataclass.
- `--license-file` CLI flag and `PYHSM_LICENSE_TOKEN` environment variable.
- Per-tier key limit enforced in `generate_key()` (Startup tier: 5 keys).
- `license_verified` / `agpl_mode` audit events recorded at session open.
- Runtime license notice logged at every `PyHSM()` instantiation (AGPL constructive notice).
- CLI license banner printed to stderr before every subcommand.

### Security
- RS256/RSA-2048 signature verification: license tokens cannot be forged without the
  issuer's private key. Algorithm confusion, expiry, and issuer claims are all validated
  before any claim is trusted.

---

## [2.2.0] — 2026-09-20

### Fixed (security)
- `hsm/ipc_server.py` — **High**: IPC server was unauthenticated by default. Any local
  process that could reach the Unix socket had full HSM access. `--ipc-secret` is now
  mandatory; server raises `ValueError` and refuses to start without it.
- `hsm/ipc_server.py` — **Medium**: Global lock serialized all IPC operations including
  slow RSA-4096 key generation (~5 s), allowing one slow request to stall all other clients.
  Replaced with per-key locking; read-only operations (health, list_keys, has_key,
  get_public_key, get_metrics) hold no lock. Added 30-second per-connection read timeout
  to prevent slow-client connection exhaustion.
- `hsm/shamir.py` — **Medium**: Shares carried a 4-byte truncated SHA-256 checksum (32-bit
  forgery resistance). Replaced with per-share `HMAC-SHA256(salt, index_byte || share_data)`
  providing 256-bit existential forgery resistance with index binding. Added
  `reconstruction_hmac` covering the full reconstructed secret.
- `hsm/self_test.py` — **Medium**: Startup KAT battery covered only 4 primitives
  (AES-256-GCM, PBKDF2-SHA256, HMAC-SHA256, CSPRNG). Extended to 10 primitives: added
  Argon2id, HKDF-SHA256, AES-256-KWP, ECDSA P-256, RSA-2048-PSS, Ed25519.
- `hsm/audit.py` — **Low**: HMAC chain did not span log rotation boundaries, allowing an
  attacker to delete rotated log files without detection. Added `rotationSeal` and
  `rotationOpen` cross-file stitching entries and `verify_across_rotations()`.
- `SECURITY.md` — **Informational**: Supported versions table listed v1.x as supported.
  Updated to show v1.x as EOL and v2.x as the supported branch.

---

## [2.1.0] — 2026-08-10

### Added
- IPC process-isolation mode: `hsm/ipc_server.py` (Unix domain socket server) and
  `hsm/ipc_client.py` (drop-in companion client). Runs PyHSM core in a separate OS
  process; raw key material never enters the application process address space.
- `vectorguard-pyhsm-server` entry point.
- secp256k1 (Ethereum/Bitcoin) and Ed25519 (Solana/SSH) key types.
- EC P-384 and P-521 curves.
- JWK import/export (`import_key_jwk()`, `export_jwk()`).
- Backup creation and verification (`create_backup()`, `verify_backup()`).
- Key search (`search_keys()`).
- Automatic key rotation via `rotate_every_days` policy field.
- OTLP-compatible metrics output.

---

## [2.0.0] — 2026-07-01

### Breaking changes
- Master password is now required at every `PyHSM()` instantiation. There is no default.
- Keystore format upgraded: Argon2id replaces PBKDF2 as the primary KDF. PBKDF2 keystores
  are automatically migrated on first open.
- Per-key AES-KWP (RFC 5649) wrapping added (double encryption of key material).
- HKDF key separation: encryption key, MAC key, KEK, and audit HMAC key are now derived
  via independent HKDF-Expand calls with separate `info` strings.
- Keystore write path is now atomic (temp file + `os.replace()`).

### Added
- Argon2id (64 MB, OWASP recommended) replaces PBKDF2 as the primary KDF.
- HMAC-SHA256 tamper seal over AES-256-GCM ciphertext (Encrypt-then-MAC).
- Per-key policies: `allow_encrypt`, `allow_decrypt`, `allow_sign`, `max_operations`,
  `expires_at`, `allowed_callers`, `allow_export`, `rotate_every_days`.
- Per-key sliding-window rate limiter (`RateLimiter`).
- HMAC-chained append-only audit log with `verify()`.
- Session timeout with automatic key material zeroization.
- RSA-PSS, ECDSA P-256, Ed25519 signing.
- Password file loader with `O_NOFOLLOW`, owner-UID, and permission enforcement.
- `SecureBytes` class and `zeroize_bytearray()` for deterministic key material erasure.
- Prometheus-compatible metrics (`get_prometheus_metrics()`).
- Shamir M-of-N secret sharing (`split_secret()`, `reconstruct_secret()`).
- Known-Answer Tests at startup (4 primitives).

---

## [1.x] — Prior to 2026-07-01

v1.x is end-of-life and receives no security patches. The v1.x codebase had no formal
security review, no adversarial tests, and used PBKDF2 without memory-hard KDF.
Upgrade to v2.0.0 or later.
