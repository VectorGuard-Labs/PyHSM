# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
Audit log cross-process integration tests.

These tests prove that audit log verification works correctly across
separate OS process executions — not just within a single in-memory
AuditLog object.

WHY THESE TESTS EXIST
---------------------
A unit test that creates an AuditLog object, writes entries, and then
calls .verify() on the *same object in the same process* does not prove
cross-process integrity. Specifically, it does not prove:

  1. The HMAC key is correctly re-derived from the master password and
     keystore salt in a fresh process (not carried in memory from the
     prior process).
  2. The on-disk JSONL file written by process A is correctly read and
     verified by process B.
  3. A tampered entry that was modified after process A exited is
     detected by process B, not silently ignored.

Each test here runs at least two separate subprocess invocations:
  - Process A: creates a keystore, performs operations (generating audit entries)
  - Process B: opens the same keystore on disk and runs `audit --verify`

The audit HMAC key is derived from the master password via Argon2id →
HKDF using a per-instance salt stored inside the encrypted keystore.
Process B must independently re-derive that exact same key to verify the
chain — proving that the derivation is deterministic and that no
in-memory state leaks between processes.

HOW TO RUN
----------
    python -m pytest tests/test_audit_integration.py -v --no-cov

TESTS
-----
  AI-01  Clean log verifies across process boundary              → PASS
  AI-02  Tampered entry detected across process boundary         → CORRUPTED
  AI-03  Multiple operations produce a verifiable chain          → PASS
  AI-04  Tampered entry: exact sequence number reported          → CORRUPTED at N
  AI-05  Key rotation, encrypt, sign produce verifiable entries  → PASS
  AI-06  Log survives session close and reopen                   → PASS
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CLI = [sys.executable, "-m", "cli"]
_PASSWORD = "AuditIntegration!2026"


def _run(args: list[str], store: str, *, expect_fail: bool = False) -> subprocess.CompletedProcess:
    """
    Invoke the CLI as a fresh subprocess.

    Each call is an independent OS process: the Python interpreter starts
    fresh, re-reads the keystore from disk, and re-derives the audit HMAC
    key from the master password + on-disk keystore salt.  No state is
    shared with any prior call.
    """
    env = os.environ.copy()
    env["PYHSM_MASTER_PASSWORD"] = _PASSWORD
    env["PYHSM_ALLOW_ENV_PASSWORD"] = "1"

    cmd = CLI + ["--store", store] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    if not expect_fail and result.returncode != 0:
        raise AssertionError(
            f"CLI unexpectedly failed (exit {result.returncode}):\n"
            f"  cmd : {' '.join(cmd)}\n"
            f"  out : {result.stdout!r}\n"
            f"  err : {result.stderr!r}"
        )
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAuditCrossProcessIntegration:
    """
    Cross-process audit log verification tests.

    Every test uses at least two subprocess invocations to prove that
    audit integrity survives a full process boundary.
    """

    def test_ai_01_clean_log_verifies_across_process_boundary(self, tmp_path: Path) -> None:
        """AI-01: A clean audit log written by process A must verify in process B.

        Scenario:
          Process A — generate a key (writes sessionOpen, selfTestPass,
                       generateKey, sessionClose to the audit log).
          Process B — run `audit --verify` on the same keystore path.

        This is the fundamental cross-process integrity test. If it fails,
        the HMAC key derivation is not deterministic across processes (which
        would be a critical bug).

        Expected: exit 0, stdout contains "OK".
        """
        store = str(tmp_path / "keystore.enc")
        audit = store + ".audit.jsonl"

        # --- Process A: create keystore and generate a key ---
        _run(["generate", "integration-key", "--type", "aes-256"], store)

        # Confirm the audit log exists on disk before process B opens it
        assert Path(audit).exists(), "Audit log must be written to disk by process A"

        # --- Process B: open the same keystore, verify the audit log ---
        result = _run(["audit", "--verify"], store)

        assert result.returncode == 0
        assert "OK" in result.stdout, (
            f"Expected 'OK' in stdout. Got: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_ai_02_tampered_entry_detected_across_process_boundary(self, tmp_path: Path) -> None:
        """AI-02: An entry tampered after process A exits must be detected by process B.

        Scenario:
          Process A — generate a key.
          (between processes) — directly modify the second line of the
                                audit JSONL file to change success=true → false.
          Process B — run `audit --verify`.

        This is the core tamper-detection test. If it passes only because both
        processes share memory, this test will catch it: the file is modified
        between the two subprocess calls.

        Expected: exit 1, stderr contains "CORRUPTED".
        """
        store = str(tmp_path / "keystore.enc")
        audit = store + ".audit.jsonl"

        # --- Process A ---
        _run(["generate", "tamper-key", "--type", "aes-256"], store)
        assert Path(audit).exists()

        # --- Tamper: modify the second audit entry on disk ---
        lines = Path(audit).read_text().splitlines()
        assert len(lines) >= 2, f"Expected at least 2 audit entries, got {len(lines)}"

        entry = json.loads(lines[1])
        # Flip the success field — a common forensic cover-up attempt
        entry["success"] = not entry.get("success", True)
        lines[1] = json.dumps(entry)
        Path(audit).write_text("\n".join(lines) + "\n")

        # --- Process B: verify should detect the tampered entry ---
        result = _run(["audit", "--verify"], store, expect_fail=True)

        assert result.returncode != 0, (
            "Expected non-zero exit code for tampered log"
        )
        assert "CORRUPTED" in result.stderr, (
            f"Expected 'CORRUPTED' in stderr. Got: {result.stderr!r}"
        )

    def test_ai_03_multiple_operations_produce_verifiable_chain(self, tmp_path: Path) -> None:
        """AI-03: A chain of many operations written by process A verifies in process B.

        Scenario:
          Multiple separate process A invocations each perform one operation,
          each appending their own audit entries. Process B then verifies
          the entire accumulated chain.

        This proves that the chain is correctly extended across multiple
        process lifetimes — not just within a single session.

        Expected: exit 0, stdout contains "OK".
        """
        store = str(tmp_path / "keystore.enc")

        # Each call is a separate process that appends to the same audit log
        _run(["generate", "key-alpha", "--type", "aes-256"], store)
        _run(["generate", "key-beta", "--type", "ec-p256"], store)
        _run(["generate", "key-gamma", "--type", "ed25519"], store)
        _run(["encrypt", "key-alpha", "--data", "hello world"], store)

        # Process B: verify the accumulated chain from all prior processes
        result = _run(["audit", "--verify"], store)

        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_ai_04_tampered_entry_reports_exact_sequence_number(self, tmp_path: Path) -> None:
        """AI-04: The CORRUPTED error must report the correct sequence number.

        This proves the verifier walks the chain entry-by-entry and stops
        at the first broken link — not just reporting a generic failure.

        Scenario:
          Process A — generate two keys (produces several audit entries).
          (between) — tamper with the entry at a known sequence position.
          Process B — verify; parse the reported sequence number.

        Expected: stderr contains "CORRUPTED at sequence N" where N matches
        the sequence field of the tampered entry.
        """
        store = str(tmp_path / "keystore.enc")
        audit = store + ".audit.jsonl"

        # --- Process A ---
        _run(["generate", "seq-key-1", "--type", "aes-256"], store)
        _run(["generate", "seq-key-2", "--type", "aes-256"], store)

        lines = Path(audit).read_text().splitlines()
        assert len(lines) >= 4, f"Expected at least 4 audit entries, got {len(lines)}"

        # Tamper specifically with line index 3 (the 4th entry)
        tamper_line_idx = 3
        entry = json.loads(lines[tamper_line_idx])
        target_seq = entry.get("sequence", tamper_line_idx)
        entry["operation"] = "forgedOperation"  # change the operation name
        lines[tamper_line_idx] = json.dumps(entry)
        Path(audit).write_text("\n".join(lines) + "\n")

        # --- Process B ---
        result = _run(["audit", "--verify"], store, expect_fail=True)

        assert result.returncode != 0
        assert "CORRUPTED" in result.stderr
        # The reported sequence number must match what we tampered
        assert str(target_seq) in result.stderr, (
            f"Expected sequence number {target_seq} in stderr. "
            f"Got: {result.stderr!r}"
        )

    def test_ai_05_key_rotation_encrypt_sign_produce_verifiable_chain(
        self, tmp_path: Path
    ) -> None:
        """AI-05: Key rotation, encryption, and signing all produce verifiable audit entries.

        Scenario:
          Process A — generate an AES key, encrypt data, rotate the key.
          Process B — generate an EC key, sign data.
          Process C — verify the full chain.

        This exercises the three main audit-generating operation types
        (crypto operations, not just key management) across process boundaries.

        Expected: exit 0, stdout contains "OK".
        """
        store = str(tmp_path / "keystore.enc")

        # Process A: AES key lifecycle
        _run(["generate", "rot-key", "--type", "aes-256"], store)
        _run(["encrypt", "rot-key", "--data", "sensitive payload"], store)
        _run(["rotate", "rot-key"], store)

        # Process B: EC signing
        _run(["generate", "sign-key", "--type", "ec-p256"], store)
        _run(["sign", "sign-key", "--data", "document to sign"], store)

        # Process C: verify the entire accumulated chain
        result = _run(["audit", "--verify"], store)

        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_ai_06_audit_log_survives_session_close_and_reopen(self, tmp_path: Path) -> None:
        """AI-06: The audit log written in one session must be readable in a new session.

        This is a prerequisite for all the above tests: it verifies that the
        audit log file is flushed to disk on session close and that the keystore
        salt used to derive the audit HMAC key is correctly persisted, so a new
        process can derive the same key and read the chain.

        Scenario:
          Process A — generate a key (writes to audit log), then close session.
          Process B — open the keystore, export the audit log entries,
                      verify they contain the operations from process A.

        Expected: audit entries from process A are present in process B's output.
        """
        store = str(tmp_path / "keystore.enc")
        audit = store + ".audit.jsonl"

        # --- Process A ---
        _run(["generate", "persist-key", "--type", "aes-256"], store)
        assert Path(audit).exists()

        # --- Process B: export raw entries and check content ---
        result = _run(["audit", "--raw"], store)

        assert result.returncode == 0

        # Parse all audit entries
        entries = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        assert len(entries) >= 2, (
            f"Expected at least 2 audit entries (sessionOpen + generateKey). "
            f"Got {len(entries)}: {result.stdout!r}"
        )

        operations = {e.get("operation") for e in entries}
        assert "generateKey" in operations, (
            f"Expected 'generateKey' in audit entries. Got operations: {operations}"
        )
        assert "sessionOpen" in operations, (
            f"Expected 'sessionOpen' in audit entries. Got operations: {operations}"
        )

        # Verify the chain is intact too
        verify_result = _run(["audit", "--verify"], store)
        assert verify_result.returncode == 0
        assert "OK" in verify_result.stdout
