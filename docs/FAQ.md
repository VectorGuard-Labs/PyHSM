# PyHSM — Frequently Asked Questions

Architecture, security, and design questions about PyHSM.

---

## Why did you build a software HSM instead of using Vault?

Vault solves a different problem at a different scale. It's a secrets management platform — it manages database credentials, API tokens, PKI certificates, and dynamic secrets across an organization. It requires Consul for HA, needs dedicated operators, and the Enterprise license for features like HSM auto-unseal costs six figures.

PyHSM is a focused key management library. You `pip install` it, import it in your code, and you have key generation, signing, encryption, and audit logging in five lines. There's no cluster to manage, no Consul dependency, no operator UI to secure, no HCL policy language to learn.

**Use Vault if:** You need org-wide secrets management with 50 services and dynamic credential rotation.

**Use PyHSM if:** You need to encrypt data or sign transactions from your application with proper key lifecycle management — without the operational overhead.

Additional distinction: Vault's Transit engine doesn't support secp256k1. If you're signing Ethereum or Bitcoin transactions, Vault can't do it natively. PyHSM can — and as of v2.3.6 includes a complete Ethereum signing stack: Keccak-256, EIP-191 personal_sign, EIP-1559 transaction hashing, recovery identifier computation, and EIP-55 address derivation.

---

## How do you prevent key extraction?

Short answer: PyHSM doesn't claim the key is *impossible* to extract. It makes extraction as difficult as possible within software constraints, and makes all access auditable.

The layers of defense:

1. **Double-encrypted at rest.** The keystore file is AES-256-GCM encrypted (master password → Argon2id → HKDF → encryption key). Each individual key inside is additionally wrapped with AES-KWP (RFC 5649). Stealing the file gives an attacker nothing without the master password.

2. **Never in memory as immutable objects.** Key material is stored as mutable `bytearray` (Python) or `Buffer` (Node.js) and deterministically zeroized byte-by-byte after each operation. It doesn't sit in a string pool waiting for garbage collection.

3. **The API never returns raw key bytes.** You call `hsm.sign()` and get a signature back. The private key is unwrapped internally, used, and zeroized — your application code never holds it.

4. **Process isolation mode** puts the keys in a separate OS process. Even a full RCE in your application can't read the HSM process's address space without a kernel exploit.

5. **Export is explicit and audited.** `export_jwk()` exists for interoperability, but it's a deliberate call that gets logged in the audit trail. You can design key policies that allow signing but never export.

**What PyHSM cannot prevent:** A root-level attacker with memory debugging tools attached to the running HSM process during the microseconds of signing. That's what hardware HSMs solve with a physical trust boundary. The [THREAT_MODEL.md](../THREAT_MODEL.md) documents this explicitly.

---

## How is key rotation implemented?

Key rotation generates a new key version and archives the old one. Old ciphertexts remain decryptable because the version number is embedded in the ciphertext format.

```
Before rotation:
  "my-key" → version 1 (active)

After hsm.rotate_key("my-key"):
  "my-key" → version 2 (active — used for new encryptions)
             version 1 (archived — can still decrypt old ciphertexts)
```

Mechanically:

1. New random key material is generated (`os.urandom(32)`)
2. It's wrapped with AES-KWP before storage
3. The previous version is marked `archived: true`
4. New `encrypt()` calls use version 2
5. `decrypt()` reads the version prefix from the ciphertext header and selects the matching key version automatically

This means you can rotate keys without re-encrypting your entire database. Old data decrypts with the old version, new data uses the new version. Both versions remain protected at rest with the same double-encryption.

Rotation is currently supported for AES keys. Asymmetric keys (EC, RSA, Ed25519) don't rotate in-place — you generate a new key ID and transition callers.

### Automatic rotation

Set `rotate_every_days` in a key's policy to enable lazy auto-rotation:

```python
hsm.generate_key("app-key", policy={
    "allow_encrypt": True,
    "allow_decrypt": True,
    "rotate_every_days": 90,
})
```

When you call `encrypt()` and the current version is older than the threshold, PyHSM transparently rotates before encrypting. This is lazy — keys that are never used don't rotate, and no background scheduler is needed. The rotation is recorded in the audit log with reason `"auto-rotation (policy: 90 days)"`.

---

## How are audit logs protected from tampering?

Each audit entry contains an HMAC that chains to the previous entry — similar to a blockchain of log records.

```
Entry 0: HMAC(key, timestamp + operation + data)
Entry 1: HMAC(key, timestamp + operation + data + HMAC_of_entry_0)
Entry 2: HMAC(key, timestamp + operation + data + HMAC_of_entry_1)
...
```

**To tamper with entry N**, an attacker would need to recompute the HMAC for entries N, N+1, N+2, ... all the way to the end. And to compute any HMAC, they need the audit HMAC key — which is derived from the master password via HKDF (Python layer) or stored independently (TypeScript layer).

**Verification** walks the chain and checks every HMAC against its predecessor. If any entry was modified, inserted, or deleted, the chain breaks and verification reports the exact sequence number where corruption occurred.

**The log is append-only** — entries are never modified or deleted during normal operation. Every operation (including denied ones) is recorded with timestamp, operation type, key ID, caller ID, and success/failure status.

---

## What cryptographic guarantees do you provide?

| Property | Mechanism | Standard |
|---|---|---|
| Confidentiality at rest | AES-256-GCM (Python) / AES-256-GCM-SIV (TypeScript) | NIST SP 800-38D / RFC 8452 |
| Key wrapping | AES-KWP | RFC 5649 |
| Key derivation | Argon2id (64MB/3 passes) → HKDF-Expand | RFC 9106 / RFC 5869 |
| Key separation | HKDF with distinct info strings | Enc, MAC, and KEK are cryptographically independent |
| Authentication | Encrypt-then-MAC (HMAC-SHA256) | Bellare & Namprempre proven-secure composition |
| Nonce safety | Hybrid nonce (random+counter+random) / GCM-SIV | Birthday bound eliminated / nonce-misuse resistant |
| Ciphertext binding | AAD = key_id + version | Prevents cross-key confusion attacks |
| Signing (ECDSA) | SHA-256 (P-256, secp256k1), SHA-384 (P-384), SHA-512 (P-521) | FIPS 186-5 |
| Signing (EdDSA) | Ed25519 | RFC 8032 |
| Constant-time comparison | `hmac.compare_digest` / length-padded `timingSafeEqual` | Timing side-channel resistant |
| Audit integrity | HMAC-chained append-only log | Tamper-evident |

**What is explicitly NOT guaranteed:**

- Protection against an attacker with kernel-level access to a running process
- Side-channel attacks on the CPU (cache timing, speculative execution)
- Physical access to the hardware
- Resistance to compromised underlying crypto libraries (supply chain)

---

## What threat model did you design against?

PyHSM defends against five classes of threat actors:

| Threat Actor | Capability | PyHSM Defense |
|---|---|---|
| **T1: Network attacker** | Can reach services on the host | Process isolation; app never holds keys |
| **T2: App-level code execution** | RCE in the application process | Rate limiting, ACLs, operation caps, process isolation |
| **T3: Filesystem read access** | Stolen disk/backup | Double-encryption (AES-GCM + AES-KWP), Argon2id |
| **T4: Malicious insider** | Partial system access, no master password | Shamir M-of-N, tamper detection, audit log |
| **T5: Root/kernel access** | Full machine control | **LIMITED** — deterministic zeroization reduces window only |

**In-scope:** Filesystem theft, application compromise, unauthorized key usage, silent key abuse, insider threats with partial access, keystore tampering, audit log manipulation.

**Out-of-scope (acknowledged):** Root attacker with debugger during signing, CPU side-channels, physical hardware access, compromised OS kernel.

The full threat model with detailed mitigations for each actor is in [THREAT_MODEL.md](../THREAT_MODEL.md).

---

## Why should I use this instead of AWS KMS?

It depends on your constraints. Neither is universally better.

| Factor | AWS KMS | PyHSM |
|---|---|---|
| Cost | $1/key/month + $0.03/10K API calls | $0 (MIT licensed) |
| secp256k1 support | No | Yes |
| Ed25519 support | No | Yes |
| Data sovereignty | Keys in AWS infrastructure | Keys on your infrastructure |
| Vendor lock-in | Yes (ciphertext only decryptable via AWS) | No (JWK export, standard formats) |
| Network dependency | Yes (API call per operation) | No (local library call) |
| Latency | 5–50 ms per API call (network round-trip) | <1 ms crypto + ~103 ms persistence |
| Audit | CloudTrail (managed by AWS) | Self-managed HMAC-chained log you own |
| FIPS certification | Yes (Level 2) | No |
| Hardware isolation | Yes (HSM-backed) | No (software process boundaries) |
| Compliance checkbox | Yes | Depends on your auditor |

**Use AWS KMS if:** You're in a regulated environment requiring FIPS certification, you're already all-in on AWS, you don't need secp256k1/Ed25519, and you're fine with per-operation costs and network latency.

**Use PyHSM if:** You need secp256k1/Ed25519 signing (blockchain), you want to avoid per-operation costs at scale, you require data sovereignty, you want zero vendor lock-in, or your latency budget can't tolerate network round-trips for every operation.

**They're not mutually exclusive:** Some teams use AWS KMS for general infrastructure encryption and PyHSM specifically for blockchain transaction signing where AWS has no native support.


---

## Why does PyHSM refuse to start without argon2-cffi?

Argon2id is a memory-hard key derivation function that makes brute-force attacks on the master password prohibitively expensive (64 MB per attempt). PBKDF2, while still acceptable per NIST guidelines, is orders of magnitude cheaper to attack on GPUs.

Previous versions of PyHSM silently fell back to PBKDF2 when `argon2-cffi` wasn't installed. This created a dangerous situation: a production deployment could unknowingly run with weaker key derivation simply because a dependency was missing from the Docker image or requirements file.

Now, PyHSM raises a `RuntimeError` at initialization if Argon2id is unavailable. This fail-hard behavior ensures you can't accidentally deploy with degraded security.

**For testing or migration scenarios** where you genuinely need PBKDF2 (e.g., CI environments without native extensions, or migrating old keystores), set:

```bash
export PYHSM_ALLOW_PBKDF2_FALLBACK=1
```

This is an explicit opt-in that should never appear in production configurations.

---

## How do I see what PyHSM is doing in production?

PyHSM emits JSON-structured logs via Python's standard `logging` module. Every log line is a single JSON object with consistent fields:

```json
{"timestamp": "2026-01-15T10:30:00+00:00", "level": "INFO", "logger": "hsm.core", "message": "key generated", "event": "generate_key", "key_id": "my-key", "key_type": "aes-256"}
```

**To enable operational logging:**

```bash
export PYHSM_LOG_LEVEL=INFO
```

Or configure programmatically:

```python
import logging
logging.getLogger("hsm").setLevel(logging.INFO)
```

**What gets logged:**

| Level | Events |
|---|---|
| `INFO` | Session open/close, key generated/rotated/destroyed, KDF migrations, self-test results |
| `WARNING` | Access denied (caller ACL), rate limiting triggered |
| `ERROR` | Webhook delivery failures |
| `CRITICAL` | Self-test failures, tamper detection |

Crypto operations (encrypt, decrypt, sign) are logged at `DEBUG` level to avoid noise in production while remaining available for troubleshooting.

**Key design decisions:**

- Default level is `WARNING` — PyHSM is silent unless something is wrong
- Webhook failures are now logged (previously silently swallowed)
- No sensitive material (keys, passwords, plaintexts) is ever included in log output
- Output is one JSON object per line — compatible with any log aggregator (Datadog, Splunk, ELK, CloudWatch)

---

## How is thread safety verified?

PyHSM includes 8 dedicated concurrency stress tests that exercise the sharded-lock architecture under realistic load:

1. **Same-key contention** — 16 threads × 20 encrypt operations on a single key
2. **Interleaved encrypt/decrypt** — concurrent readers and writers on the same key
3. **Multi-key parallelism** — 16 threads each operating on their own key (no contention)
4. **Concurrent key generation** — 16 threads creating keys simultaneously (global lock stress)
5. **Mixed workload** — generate + encrypt + rotate + destroy running in parallel
6. **Cross-contamination proof** — verifies ciphertexts from key A never decrypt under key B
7. **Operation count consistency** — 4 threads × 50 ops, then verifies no lost counter updates
8. **Concurrent signing** — 8 threads signing with the same EC key, all signatures verified

These tests run as part of the standard `pytest` suite and are enforced in CI. They use real cryptographic operations (no mocking) to expose race conditions in key material handling, operation counting, and keystore persistence.


---

## How do I search for keys by metadata or type?

Use `search_keys()` to filter the keystore without iterating `list_keys()` manually:

```python
# By key type
aes_keys = hsm.search_keys(key_type="aes-256")

# By metadata tags (all specified pairs must match — AND logic)
prod_keys = hsm.search_keys(metadata={"env": "prod", "team": "payments"})

# By status: "active", "archived", or "expired"
expired = hsm.search_keys(status="expired")

# By policy fields
auto_rotating = hsm.search_keys(policy_filter={"rotate_every_days": 90})

# Combine filters
results = hsm.search_keys(key_type="aes-256", metadata={"env": "prod"}, status="active")
```

This is useful at scale when you have dozens or hundreds of keys and need to find specific subsets for rotation, audit, or decommissioning.

---

## What observability options does PyHSM support?

Three formats for different stacks:

1. **Dict** — `hsm.get_metrics()` returns a Python dict with all counters and gauges. Good for custom dashboards or ad-hoc inspection.

2. **Prometheus** — `hsm.get_prometheus_metrics()` returns text in Prometheus exposition format. Serve it via HTTP or write to a file for `node_exporter`'s textfile collector.

3. **OpenTelemetry (OTLP)** — `hsm.get_otlp_metrics()` returns a dict conforming to the OTLP `ExportMetricsServiceRequest` JSON schema. POST it to any OTLP-compatible collector:

```python
import json, urllib.request

payload = json.dumps(hsm.get_otlp_metrics()).encode()
req = urllib.request.Request(
    "http://localhost:4318/v1/metrics",
    data=payload,
    headers={"Content-Type": "application/json"},
)
urllib.request.urlopen(req)
```

This works with Grafana Agent, OpenTelemetry Collector, Datadog Agent, Honeycomb, and any other OTLP-compatible backend. No additional dependencies are needed — it's just JSON serialization.

---

## How does audit log rotation work?

The audit log supports automatic rotation to prevent unbounded growth:

```python
from hsm.audit import AuditLog

log = AuditLog(
    "audit.jsonl",
    hmac_key=my_key,
    max_bytes=50 * 1024 * 1024,  # rotate at 50 MB (default)
    max_entries=0,                # or rotate after N entries (0 = disabled)
    max_rotated_files=10,         # keep up to 10 rotated files
)
```

When the threshold is exceeded, the current log is renamed to `.1`, previous `.1` becomes `.2`, etc. Files beyond `max_rotated_files` are deleted. The HMAC chain continues across rotations — verification of the current file still works because the chain state is maintained in memory.

Default behavior: rotate at 50 MB, keep 10 rotated files. For most deployments this means you'll retain several months of audit history without manual intervention.

---

## How do backups work?

**Python:**

```python
# Create an encrypted backup (byte-for-byte copy of the keystore envelope)
backup_path = hsm.create_backup("/secure/backups")

# Verify a backup is intact without loading it into the live store
hsm.verify_backup(backup_path)  # returns True or raises TamperError/ValueError
```

**TypeScript:**

```typescript
const path = hsm.createBackup();
hsm.verifyBackup(path);
```

Backups are atomic (temp file + rename), timestamped, and written with mode `0o600`. The backup file is the raw encrypted keystore — no decryption or re-encryption occurs. Verification confirms HMAC integrity and successful decryption without loading keys into memory.

Store backups on a separate volume or off-host. The backup is useless without the master password, so it's safe to store in less-trusted locations than the live keystore.

---

## How do I sign Ethereum transactions with PyHSM?

As of v2.3.6, PyHSM includes a complete Ethereum signing module (`hsm/ethereum.py`) that handles the entire signing stack — no third-party blockchain library required.

**1. Generate or import a secp256k1 key:**

```python
hsm = PyHSM("/secure/keystore.enc", master_password="strong-pw")
hsm.generate_key("eth-wallet", "ec-secp256k1")
address = hsm.eth_address("eth-wallet")  # EIP-55 checksummed
```

**2. Sign a personal_sign message (MetaMask-compatible):**

```python
from hsm.ethereum import eip191_personal_sign_hash, der_to_eth_sig

msg_hash = eip191_personal_sign_hash("Approve transfer")
der_hex  = hsm.sign_digest("eth-wallet", msg_hash)
eth_sig  = der_to_eth_sig(der_hex, msg_hash, hsm.get_public_key("eth-wallet"))
# eth_sig = 65 bytes: r (32) || s (32) || v (27 or 28)
```

**3. Sign an EIP-1559 transaction:**

```python
from hsm.ethereum import eip1559_transaction_hash, der_to_eth_sig

tx_hash = eip1559_transaction_hash({
    "chain_id": 1, "nonce": 0,
    "max_priority_fee_per_gas": 1_500_000_000,
    "max_fee_per_gas": 30_000_000_000,
    "gas_limit": 21_000,
    "to": "0xRecipientAddress...",
    "value": 1_000_000_000_000_000_000,
    "data": b"", "access_list": [],
})
der_hex = hsm.sign_digest("eth-wallet", tx_hash)
eth_sig = der_to_eth_sig(der_hex, tx_hash, hsm.get_public_key("eth-wallet"))
```

**4. Verify a signature:**

```python
from hsm.ethereum import verify_eth_sig
assert verify_eth_sig(msg_hash, eth_sig, address)
```

**Via CLI:**

```bash
# Derive address
vectorguard-pyhsm --store keystore.enc eth-address eth-wallet

# Sign personal message
vectorguard-pyhsm --store keystore.enc eth-sign eth-wallet \
    --personal "Approve transfer"

# Sign EIP-1559 transaction
vectorguard-pyhsm --store keystore.enc eth-sign eth-wallet --tx-file tx.json
```

**Why `sign_digest()` instead of `sign()`?**

PyHSM's `sign()` applies an internal SHA-256 hash (via `ECDSA(SHA256())`). Ethereum uses Keccak-256, not SHA-256. If you passed a Keccak-256 digest to `sign()`, it would SHA-256 the already-hashed digest — a double-hash producing an incorrect Ethereum signature. `sign_digest()` uses `ECDSA(Prehashed())` to sign the exact bytes you provide without any additional hashing.

---

## What is the difference between sign() and sign_digest()?

`sign(key_id, message)` — the standard signing method. For secp256k1 keys, it applies `ECDSA(SHA256())`, hashing the message with SHA-256 before signing. This is correct for generic ECDSA applications.

`sign_digest(key_id, digest)` — Ethereum-specific. Signs a 32-byte pre-computed digest directly without any further hashing. Only supported for `ec-secp256k1` keys. Use this when you have already hashed the message with Keccak-256 (or any other hash) and want PyHSM to sign the raw digest.

For `verify()`, PyHSM uses the stored public key and `ECDSA(SHA256())`. To verify an Ethereum signature produced by `sign_digest()`, use `verify_eth_sig()` from `hsm.ethereum`, which uses the secp256k1 recovery algorithm rather than the standard ECDSA verification path.

---

## How many tests does PyHSM have?

As of v2.3.7: **391 Python tests** across 8 test files:

| File | Tests | Category |
|------|-------|----------|
| `tests/test_pyhsm.py` | 180 | Core unit tests |
| `tests/test_adversarial.py` | 99 | Adversarial tests (AT-KS through AT-KS-EX) |
| `tests/test_ipc_adversarial.py` | 20 | IPC boundary adversarial tests |
| `tests/test_lifecycle_recovery.py` | 21 | Lifecycle / recovery tests |
| `tests/test_property_based.py` | 18 | Hypothesis property-based tests |
| `tests/test_ethereum.py` | 44 | Ethereum/EVM signing tests |
| `tests/test_audit_integration.py` | 6 | Cross-process audit integration tests |
| `tests/test_cli.py` + `test_concurrency.py` | 38 | CLI and concurrency tests |

Run the full suite: `python -m pytest tests/ --no-cov`
