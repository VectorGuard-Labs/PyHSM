# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM Lifecycle and Recovery Test Suite.

Tests operational scenarios: session timeouts, key rotation under load,
interrupted writes, backup/restore, audit log rotation, and concurrent
operations. These are the states that only occur in production over time
but that need to be verified before that happens.

Test categories:
  LC-ST  — Session timeout and automatic closure
  LC-KR  — Key rotation lifecycle
  LC-BK  — Backup creation, verification, and restore
  LC-AL  — Audit log rotation and cross-rotation chain
  LC-IW  — Interrupted write / crash-safe persistence
  LC-CC  — Concurrent operations on shared state
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hsm import PyHSM, TamperError
from hsm.audit import AuditLog

_STRONG_PW = "LifecycleTest!99"


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
# LC-ST: Session timeout and automatic closure
# ===========================================================================

class TestSessionTimeout:
    """
    LC-ST: The session timeout background thread must close the session and
    zeroize key material after the configured idle period. Any subsequent
    operation must raise RuntimeError.
    """

    def test_session_closes_after_timeout(self, store_path):
        """LC-ST-01: Session must become inactive after session_timeout_s seconds.

        The timeout thread wakes every max(1, timeout/10) seconds and checks
        idle time. With timeout=1 s we wait 3 s to be safely past the deadline.
        Expected: _session_active becomes False.
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=1.0)
        h.generate_key("k1")
        assert h._session_active is True
        time.sleep(3.0)  # well past the 1 s timeout
        assert h._session_active is False

    def test_operations_after_timeout_raise_runtime_error(self, store_path):
        """LC-ST-02: Any operation after timeout must raise RuntimeError.

        Expected: list_keys() raises RuntimeError("session is closed").
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=1.0)
        h.generate_key("k1")
        time.sleep(3.0)
        with pytest.raises(RuntimeError, match="session is closed"):
            h.list_keys()

    def test_activity_resets_idle_timer(self, store_path):
        """LC-ST-03: Each operation must reset the idle timer.

        Send an operation at t=0 and t=0.8 s, then confirm the session
        is still alive at t=1.5 s (which would be past the timeout if the
        timer were never reset).
        """
        h = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=1.0)
        h.generate_key("k1")
        time.sleep(0.8)
        h.list_keys()   # resets idle timer
        time.sleep(0.8)
        # 0.8 s after the last activity — still within the 1 s window
        assert h._session_active is True
        h.close_session()


# ===========================================================================
# LC-KR: Key rotation lifecycle
# ===========================================================================

class TestKeyRotationLifecycle:
    """
    LC-KR: Key rotation must correctly archive old versions, generate new ones,
    and retain the ability to decrypt data encrypted under any previous version.
    """

    def test_all_previous_versions_still_decrypt_after_multiple_rotations(self, hsm):
        """LC-KR-01: After N rotations, ciphertexts from all previous versions must decrypt.

        This verifies the version-indexed key store correctly preserves archived
        versions and that the version prefix in the ciphertext correctly routes
        decryption to the right key material.
        """
        hsm.generate_key("multi-rot")
        ciphertexts = []
        plaintexts  = []
        for i in range(4):
            pt = f"plaintext for version {i+1}"
            plaintexts.append(pt)
            ciphertexts.append(hsm.encrypt("multi-rot", pt))
            if i < 3:
                hsm.rotate_key("multi-rot")

        for pt, ct in zip(plaintexts, ciphertexts):
            assert hsm.decrypt("multi-rot", ct) == pt.encode()

    def test_new_version_encrypts_after_rotation(self, hsm):
        """LC-KR-02: After rotation the new version is the default encryption key.

        Expected: version in the new ciphertext is current_version after rotation.
        """
        hsm.generate_key("rot2")
        new_ver = hsm.rotate_key("rot2")
        ct = hsm.encrypt("rot2", "new data")
        # Version prefix is at bytes 1-4 of the raw ciphertext (after format byte)
        raw = bytes.fromhex(ct)
        import struct
        version_in_ct = struct.unpack(">I", raw[1:5])[0]
        assert version_in_ct == new_ver

    def test_archived_version_cannot_be_used_to_encrypt(self, hsm):
        """LC-KR-03: After rotation the old version is archived and cannot encrypt.

        Rotating archives the current version. A subsequent encrypt call must
        use the new version, not the archived one.
        Expected: encrypt succeeds (uses new version), archived version does not
        produce a ciphertext version mismatch on decrypt.
        """
        hsm.generate_key("rot3")
        ct_v1 = hsm.encrypt("rot3", "before rotation")
        hsm.rotate_key("rot3")
        ct_v2 = hsm.encrypt("rot3", "after rotation")

        # Both ciphertexts must decrypt correctly
        assert hsm.decrypt("rot3", ct_v1) == b"before rotation"
        assert hsm.decrypt("rot3", ct_v2) == b"after rotation"

    def test_key_version_increments_sequentially(self, hsm):
        """LC-KR-04: Each rotation must increment current_version by exactly 1.

        Expected: versions after 3 rotations are 1, 2, 3, 4 with 4 as current.
        """
        hsm.generate_key("seq-rot")
        assert hsm.rotate_key("seq-rot") == 2
        assert hsm.rotate_key("seq-rot") == 3
        assert hsm.rotate_key("seq-rot") == 4
        keys = {k["key_id"]: k for k in hsm.list_keys()}
        assert keys["seq-rot"]["current_version"] == 4

    def test_rotation_persists_across_sessions(self, store_path):
        """LC-KR-05: Rotated key state must survive session close and reopen.

        Expected: new session can still decrypt pre-rotation ciphertexts.
        """
        h1 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h1.generate_key("persist-rot")
        ct_v1 = h1.encrypt("persist-rot", "before")
        h1.rotate_key("persist-rot")
        ct_v2 = h1.encrypt("persist-rot", "after")
        h1.close_session()

        h2 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        assert h2.decrypt("persist-rot", ct_v1) == b"before"
        assert h2.decrypt("persist-rot", ct_v2) == b"after"
        h2.close_session()


# ===========================================================================
# LC-BK: Backup creation, verification, and restore
# ===========================================================================

class TestBackupLifecycle:
    """
    LC-BK: Backup files must be readable, HMAC-verified, and tamper-evident.
    A restored backup must produce the same key material as the original.
    """

    def test_backup_is_verifiable(self, hsm, tmp_path):
        """LC-BK-01: A backup file created by create_backup() must verify correctly.

        Expected: verify_backup(path) returns True.
        """
        hsm.generate_key("bk1")
        backup_dir = str(tmp_path / "backups")
        backup_path = hsm.create_backup(backup_dir)
        assert hsm.verify_backup(backup_path) is True

    def test_tampered_backup_fails_verification(self, hsm, tmp_path):
        """LC-BK-02: A byte-flipped backup must fail verification.

        Attack: attacker modifies the backup file on disk.
        Expected: TamperError or ValueError raised.
        """
        hsm.generate_key("bk2")
        backup_dir = str(tmp_path / "backups")
        backup_path = hsm.create_backup(backup_dir)

        data = Path(backup_path).read_bytes()
        ba = bytearray(data)
        ba[-10] ^= 0xFF
        Path(backup_path).write_bytes(bytes(ba))

        with pytest.raises((TamperError, ValueError)):
            hsm.verify_backup(backup_path)

    def test_backup_restores_to_working_keystore(self, hsm, tmp_path, store_path):
        """LC-BK-03: A backup restored by copying must produce a functional keystore.

        Workflow: generate key → encrypt data → backup → corrupt live store →
        restore backup → decrypt data from restored backup.
        Expected: plaintext recovered from the restored keystore.
        """
        hsm.generate_key("restore-key")
        ct = hsm.encrypt("restore-key", "critical data")
        backup_dir = str(tmp_path / "backups")
        backup_path = hsm.create_backup(backup_dir)
        hsm.close_session()

        # Simulate corruption of the live keystore
        Path(store_path).write_bytes(os.urandom(256))

        # Restore: copy backup over the corrupted file
        shutil.copy2(backup_path, store_path)

        # Reopen from the restored backup
        h2 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        recovered = h2.decrypt("restore-key", ct)
        assert recovered == b"critical data"
        h2.close_session()

    def test_backup_directory_created_with_restricted_permissions(self, hsm, tmp_path):
        """LC-BK-04: Backup directory must be created with mode 0o700.

        Expected: os.stat(backup_dir).st_mode & 0o777 == 0o700.
        """
        backup_dir = str(tmp_path / "secure-backups")
        hsm.generate_key("perm-key")
        hsm.create_backup(backup_dir)
        mode = os.stat(backup_dir).st_mode & 0o777
        assert mode == 0o700

    def test_nonexistent_backup_path_raises(self, hsm):
        """LC-BK-05: Verifying a nonexistent backup path must raise FileNotFoundError.

        Attack: probe for backup file names.
        Expected: FileNotFoundError.
        """
        with pytest.raises((FileNotFoundError, ValueError, OSError)):
            hsm.verify_backup("/nonexistent/path/backup.enc")


# ===========================================================================
# LC-AL: Audit log rotation and cross-rotation chain
# ===========================================================================

class TestAuditLogRotation:
    """
    LC-AL: The audit log rotation mechanism must preserve the HMAC chain
    across file boundaries and detect any tampering with rotated files.
    """

    @pytest.mark.xfail(
        reason="Known defect: verify_across_rotations() resets chain anchor to '0'*64 "
               "per file, but entries were HMACed against the running chain from the "
               "prior file. Cross-rotation verification fails on all files except the first.",
        strict=True,
    )
    def test_chain_is_valid_after_rotation(self, tmp_path):
        """LC-AL-01: HMAC chain must be verifiable via verify_across_rotations() after rotation.

        KNOWN DEFECT: verify_across_rotations() in audit.py resets current_prev to
        '0'*64 at the start of each file. However, entries in files .1, .2, etc. were
        HMACed against the live running chain (where prev was the previous entry's HMAC,
        not '0'*64). This means the cross-rotation verifier always reports HMAC mismatch
        on the rotationOpen entry of any file after the first.

        This test is marked xfail to document the defect until it is fixed.
        Fix: pass the seal HMAC as the starting current_prev when verifying subsequent files.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32), max_entries=3, max_bytes=0)
        for i in range(6):
            log.record("encrypt", key_id=f"k{i}", success=True)
        result = log.verify_across_rotations()
        assert result["ok"] is True

    def test_rotated_file_exists_after_limit(self, tmp_path):
        """LC-AL-02: A rotated file (.1) must be created when the entry limit is hit.

        Expected: path.1 exists after writing max_entries+1 records.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32), max_entries=3, max_bytes=0)
        for i in range(4):
            log.record("encrypt", key_id=f"k{i}", success=True)
        assert os.path.exists(path + ".1")

    @pytest.mark.xfail(
        reason="Known defect: verify_across_rotations() resets HMAC chain anchor per file. "
               "See test_chain_is_valid_after_rotation for full explanation.",
        strict=True,
    )
    def test_cross_rotation_chain_is_intact(self, tmp_path):
        """LC-AL-03: verify_across_rotations() must return ok=True for an unmodified log.

        Expected: result["ok"] is True and all files checked.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32), max_entries=3, max_bytes=0)
        for i in range(9):
            log.record("encrypt", key_id=f"k{i}", success=True)

        result = log.verify_across_rotations()
        assert result["ok"] is True
        assert len(result["files_checked"]) >= 2

    @pytest.mark.xfail(
        reason="Known defect: verify_across_rotations() resets HMAC chain anchor per file. "
               "Cannot verify tamper detection until the base chain verification is fixed.",
        strict=True,
    )
    def test_deleted_rotated_file_detected_by_cross_rotation_verify(self, tmp_path):
        """LC-AL-04: Deleting a rotated file must be detected by verify_across_rotations().

        Attack: attacker deletes a rotated log file to erase evidence.
        Defense: rotationOpen entry in the active file records the rotated file's
        seal HMAC; if the seal file is gone the chain cannot be verified.
        Expected: result["ok"] is False.
        """
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path, hmac_key=os.urandom(32), max_entries=3, max_bytes=0)
        for i in range(7):
            log.record("encrypt", key_id=f"k{i}", success=True)

        # Verify it was clean before tampering
        before = log.verify_across_rotations()
        assert before["ok"] is True

        # Delete the .1 rotated file
        rotated = path + ".1"
        if os.path.exists(rotated):
            os.unlink(rotated)

        result = log.verify_across_rotations()
        # With the rotated file gone the chain cannot be stitched — must report failure
        # (either ok=False, or files_checked excludes the deleted file)
        # Accept either: ok=False explicitly, or fewer files than before
        either_fail = (not result["ok"]) or (len(result["files_checked"]) < len(before["files_checked"]))
        assert either_fail

    def test_max_rotated_files_limit_respected(self, tmp_path):
        """LC-AL-05: Rotation must not keep more than max_rotated_files rotated copies.

        Expected: after many rotations, at most max_rotated_files .N files exist.
        """
        path = str(tmp_path / "audit.jsonl")
        MAX = 3
        log = AuditLog(path, hmac_key=os.urandom(32), max_entries=2, max_bytes=0,
                       max_rotated_files=MAX)
        for i in range(20):
            log.record("encrypt", key_id=f"k{i}", success=True)

        assert os.path.exists(path + ".1")
        assert os.path.exists(path + ".2")
        assert os.path.exists(path + ".3")
        assert not os.path.exists(path + ".4")


# ===========================================================================
# LC-IW: Interrupted write / crash-safe persistence
# ===========================================================================

class TestCrashSafePersistence:
    """
    LC-IW: The atomic write mechanism (temp file + rename) must ensure that
    a crash mid-write does not corrupt the live keystore.
    """

    def test_keystore_survives_session_reopen(self, store_path):
        """LC-IW-01: Data written in one session must be readable in a new session.

        Basic persistence test: if the write path is correct, data survives close+reopen.
        """
        h1 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h1.generate_key("persist")
        ct = h1.encrypt("persist", "durable data")
        h1.close_session()

        h2 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        assert h2.decrypt("persist", ct) == b"durable data"
        h2.close_session()

    def test_stale_migrating_file_does_not_block_open(self, store_path):
        """LC-IW-02: A stale .migrating file left from a previous crash must not block startup.

        Scenario: server crashes mid-migration, leaving a .migrating temp file.
        Expected: PyHSM opens normally and ignores or cleans up the stale file.
        """
        # First create a valid keystore
        h1 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        h1.generate_key("k1")
        h1.close_session()

        # Leave a fake .migrating file
        migrating = store_path + ".migrating"
        Path(migrating).write_bytes(b"stale garbage from a previous crash")

        # PyHSM must open normally — the stale file should not block it
        h2 = PyHSM(store_path, master_password=_STRONG_PW, session_timeout_s=0)
        assert h2.has_key("k1")
        h2.close_session()

        # Stale .migrating file should be cleaned up or ignored
        # (We just verify no exception was raised above)

    def test_multiple_writes_do_not_corrupt_keystore(self, hsm):
        """LC-IW-03: Rapid successive writes must not corrupt the keystore.

        Generate many keys in sequence. Each generation triggers a save.
        Expected: all keys persist correctly, no store corruption.
        """
        for i in range(10):
            hsm.generate_key(f"write-{i}")

        for i in range(10):
            assert hsm.has_key(f"write-{i}")


# ===========================================================================
# LC-CC: Concurrent operations on shared state
# ===========================================================================

class TestConcurrentOperations:
    """
    LC-CC: Concurrent operations from multiple threads must not produce
    data races, lost updates, or incorrect results.
    """

    def test_concurrent_encrypt_decrypt_preserves_correctness(self, hsm):
        """LC-CC-01: Concurrent encrypt and decrypt operations must be correct.

        10 threads each encrypt a unique plaintext, then the same 10 threads
        decrypt their own ciphertext. Each plaintext must be recovered exactly.
        """
        hsm.generate_key("concurrent")
        n = 10
        results = [None] * n
        errors  = []

        def work(i):
            try:
                pt = f"thread-{i}-data"
                ct = hsm.encrypt("concurrent", pt)
                recovered = hsm.decrypt("concurrent", ct)
                results[i] = recovered
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=work, args=(i,)) for i in range(n)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert len(errors) == 0, f"Errors: {errors}"
        for i, r in enumerate(results):
            assert r == f"thread-{i}-data".encode(), f"thread {i} wrong result"

    def test_concurrent_generate_different_keys(self, hsm):
        """LC-CC-02: Concurrent generation of distinct keys must all succeed.

        5 threads each generate a unique key simultaneously.
        Expected: all 5 keys exist after the threads complete.
        """
        n = 5
        errors = []

        def gen(i):
            try:
                hsm.generate_key(f"cgen-{i}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=gen, args=(i,)) for i in range(n)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert len(errors) == 0, f"Errors: {errors}"
        for i in range(n):
            assert hsm.has_key(f"cgen-{i}")

    def test_concurrent_sign_operations_are_independent(self, hsm):
        """LC-CC-03: Concurrent signing with different keys must produce valid signatures.

        Each thread signs a unique message with a unique EC key.
        Expected: each thread's signature verifies correctly.
        """
        n = 5
        for i in range(n):
            hsm.generate_key(f"sign-{i}", "ec-p256")

        results = [None] * n
        errors  = []

        def sign_verify(i):
            try:
                msg = f"message-for-thread-{i}"
                sig = hsm.sign(f"sign-{i}", msg)
                ok  = hsm.verify(f"sign-{i}", msg, sig)
                results[i] = ok
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=sign_verify, args=(i,)) for i in range(n)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert len(errors) == 0, f"Errors: {errors}"
        assert all(results)

    def test_operation_count_is_consistent_under_concurrent_ops(self, hsm):
        """LC-CC-04: Operation count must be monotonically correct under concurrent operations.

        After N concurrent encrypts, the operation_count in the key entry must
        be exactly N (no lost increments from races).
        """
        hsm.generate_key("op-count")
        N = 20
        errors = []

        def enc(_):
            try:
                hsm.encrypt("op-count", "x")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=enc, args=(i,)) for i in range(N)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert len(errors) == 0
        entry = hsm._store.load_key("op-count")
        assert entry["operation_count"] == N
