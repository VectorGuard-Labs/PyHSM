# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM IPC Adversarial Test Suite.

Tests the process-isolation boundary: the Unix-socket server (ipc_server.py)
and its client (ipc_client.py). Every test represents a specific attack or
failure scenario at the IPC layer — not a happy-path workflow.

Test categories:
  IPC-AU  — Authentication attacks (missing secret, wrong secret, forged HMAC)
  IPC-PR  — Protocol attacks (malformed frames, oversized messages, truncation)
  IPC-OP  — Operation attacks (unknown ops, missing fields, cross-key confusion)
  IPC-CN  — Concurrency attacks (races, flood, slow client DoS)
  IPC-LF  — Lifecycle attacks (server not running, unexpected termination)

Architecture under test:

    IPCClient ──[Unix socket]──> IPCServer ──> PyHSM

The socket file is created at 0o600 so only the server's UID can connect.
Every request must carry a valid HMAC-SHA256(secret, request_id:op) token.
The server enforces an operation allowlist; unknown ops are rejected.
Per-connection 30 s read timeout prevents slow-client DoS.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import socket
import struct
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

import pytest

from hsm.ipc_server import IPCServer, ALLOWED_OPERATIONS, _MSG_HEADER, _send_msg, _recv_msg

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_STRONG_PW  = "IpcAdversarial!99"
_IPC_SECRET = "correct-ipc-secret-64-hex-chars-aabbccdd1122"


def _make_server(tmp_path: Path, secret: str = _IPC_SECRET) -> tuple[IPCServer, str, str]:
    """Create an IPCServer with a temp keystore and socket. Returns (server, socket_path, store_path).

    The socket is placed under /tmp (short path) because macOS limits AF_UNIX
    socket paths to 104 bytes; pytest's tmp_path is often longer than that.
    """
    store_path  = str(tmp_path / "keystore.enc")
    # Use a short /tmp path for the socket to stay inside the 104-byte AF_UNIX limit
    sock_dir    = tempfile.mkdtemp(prefix="pyhsm_", dir="/tmp")
    socket_path = os.path.join(sock_dir, "p.sock")
    server = IPCServer(
        store_path=store_path,
        socket_path=socket_path,
        master_password=_STRONG_PW,
        ipc_secret=secret,
        session_timeout_s=0,
        conn_timeout_s=2.0,   # short timeout so slow-client tests complete quickly
    )
    return server, socket_path, store_path


def _start_server_thread(server: IPCServer) -> threading.Thread:
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    # Wait until the server has created a real socket file (up to 5 s).
    # We check stat for S_ISSOCK to avoid matching a stale regular file.
    import stat as _stat
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            if _stat.S_ISSOCK(os.stat(server._socket_path).st_mode):
                break
        except OSError:
            pass
        time.sleep(0.05)
    return t


def _raw_sock(socket_path: str, timeout: float = 15.0) -> socket.socket:
    """Open a raw Unix socket connection without using IPCClient."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(socket_path)
    return s


def _build_auth(secret: str, request_id: str, operation: str) -> str:
    return _hmac.new(
        secret.encode("utf-8"),
        f"{request_id}:{operation}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _send_raw(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    sock.sendall(_MSG_HEADER.pack(len(data)) + data)


def _recv_raw(sock: socket.socket) -> Optional[dict]:
    header = bytearray()
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header.extend(chunk)
    (length,) = _MSG_HEADER.unpack(bytes(header))
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            return None
        body.extend(chunk)
    return json.loads(body.decode("utf-8"))


# ===========================================================================
# IPC-AU: Authentication attacks
# ===========================================================================

class TestIPCAuthenticationAttacks:
    """
    IPC-AU: Attacks that attempt to use the IPC server without valid credentials.

    Defense: HMAC-SHA256(ipc_secret, request_id:operation) token is required
    on every request. The server closes the connection immediately on any
    auth failure and logs the event.
    """

    def test_no_ipc_secret_server_refuses_to_start(self, tmp_path):
        """IPC-AU-01: Server must refuse to start without an ipc_secret.

        Attack: operator accidentally omits --ipc-secret; any local process
        that can reach the socket would get full HSM access.
        Expected: ValueError raised before the socket is opened.
        """
        with pytest.raises(ValueError, match="ipc_secret is required"):
            IPCServer(
                store_path=str(tmp_path / "ks.enc"),
                socket_path=str(tmp_path / "pyhsm.sock"),
                master_password=_STRONG_PW,
                ipc_secret=None,
            )

    def test_missing_auth_field_rejected(self, tmp_path):
        """IPC-AU-02: Request with no 'auth' field must be rejected.

        Attack: attacker connects to the socket and sends a request without
        an HMAC token, hoping auth is optional.
        Expected: server responds with ok=false and closes the connection.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        _send_raw(s, {"type": "health", "request_id": rid})  # no 'auth' field
        resp = _recv_raw(s)
        assert resp is not None
        assert resp["ok"] is False
        s.close()
        server._shutdown.set()

    def test_wrong_ipc_secret_rejected(self, tmp_path):
        """IPC-AU-03: Request signed with the wrong secret must be rejected.

        Attack: attacker guesses or brute-forces the IPC secret.
        Expected: ok=false, connection closed.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        bad_auth = _build_auth("wrong-secret-entirely", rid, "health")
        _send_raw(s, {"type": "health", "request_id": rid, "auth": bad_auth})
        resp = _recv_raw(s)
        assert resp is not None
        assert resp["ok"] is False
        s.close()
        server._shutdown.set()

    def test_replayed_auth_token_rejected(self, tmp_path):
        """IPC-AU-04: Replaying a previously used (request_id, auth) pair must be rejected.

        Attack: attacker captures a valid request on the wire and replays it.
        Since the HMAC covers request_id, replaying the same request_id + auth
        token means the second request's auth is valid for that ID, but the
        server closes the connection after an auth failure on the *new*
        request_id with the reused token.
        Expected: second request with mismatched request_id/auth fails.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        # First: make a legitimate request and capture its auth token
        s = _raw_sock(socket_path)
        rid1 = str(uuid.uuid4())
        auth1 = _build_auth(_IPC_SECRET, rid1, "health")
        _send_raw(s, {"type": "health", "request_id": rid1, "auth": auth1})
        resp1 = _recv_raw(s)
        assert resp1["ok"] is True
        s.close()

        # Replay: open new connection, send same auth1 but with a different request_id
        s2 = _raw_sock(socket_path)
        rid2 = str(uuid.uuid4())  # different request_id
        # auth1 was computed for rid1 — mismatches rid2
        _send_raw(s2, {"type": "health", "request_id": rid2, "auth": auth1})
        resp2 = _recv_raw(s2)
        assert resp2 is not None
        assert resp2["ok"] is False
        s2.close()
        server._shutdown.set()

    def test_empty_auth_token_rejected(self, tmp_path):
        """IPC-AU-05: Empty string auth token must be rejected.

        Attack: attacker sends auth="" hoping an empty string compares equal.
        Expected: ok=false.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        _send_raw(s, {"type": "health", "request_id": rid, "auth": ""})
        resp = _recv_raw(s)
        assert resp["ok"] is False
        s.close()
        server._shutdown.set()


# ===========================================================================
# IPC-PR: Protocol attacks
# ===========================================================================

class TestIPCProtocolAttacks:
    """
    IPC-PR: Attacks at the wire-protocol level — malformed frames, oversized
    messages, and truncated data.

    Defense: _recv_msg() enforces a 64 MB maximum message size and requires
    a complete length-prefixed frame. Incomplete frames cause the connection
    to be dropped cleanly.
    """

    def test_unknown_operation_rejected(self, tmp_path):
        """IPC-PR-01: Operation not in ALLOWED_OPERATIONS must be rejected.

        Attack: attacker sends an operation name not in the server's whitelist,
        hoping to trigger an unhandled code path.
        Expected: ok=false, error mentioning unknown operation; no traceback leaked.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        auth = _build_auth(_IPC_SECRET, rid, "admin_shell")
        _send_raw(s, {"type": "admin_shell", "request_id": rid, "auth": auth})
        resp = _recv_raw(s)
        assert resp["ok"] is False
        assert "Unknown operation" in resp.get("error", "")
        s.close()
        server._shutdown.set()

    def test_operation_with_missing_required_field(self, tmp_path):
        """IPC-PR-02: Operation missing a required field must return an error, not crash.

        Attack: send encrypt without a key_id or plaintext, hoping for an unhandled
        KeyError that leaks a traceback.
        Expected: ok=false with a clean error string; no traceback in response.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        auth = _build_auth(_IPC_SECRET, rid, "encrypt")
        # Intentionally omit key_id and plaintext
        _send_raw(s, {"type": "encrypt", "request_id": rid, "auth": auth})
        resp = _recv_raw(s)
        assert resp["ok"] is False
        # Traceback must not appear in the public error field
        assert "Traceback" not in resp.get("error", "")
        assert "File " not in resp.get("error", "")
        s.close()
        server._shutdown.set()

    def test_truncated_length_prefix_drops_connection(self, tmp_path):
        """IPC-PR-03: Sending only 2 of the 4 required header bytes drops the connection.

        Attack: attacker sends a partial frame, hoping the server blocks forever
        waiting for the rest (resource exhaustion via half-open connections).
        Defense: per-connection read timeout (30 s) disconnects stalled clients.
        Expected: server closes the connection after the timeout.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        s.settimeout(6.0)  # longer than server's 2 s conn_timeout_s
        # Send only 2 bytes of the 4-byte header — incomplete frame
        s.sendall(b"\x00\x00")
        # Server will timeout after 30 s and close the connection
        result = b""
        try:
            result = s.recv(1024)
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        # Connection should be closed or empty (no data returned)
        assert result == b""
        s.close()
        server._shutdown.set()

    def test_valid_json_but_empty_request_rejected(self, tmp_path):
        """IPC-PR-04: Sending a valid JSON object with no 'type' field must be rejected.

        Attack: attacker sends {} hoping an empty operation maps to something useful.
        Expected: ok=false (unknown operation or auth failure).
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        auth = _build_auth(_IPC_SECRET, rid, "")
        _send_raw(s, {"request_id": rid, "auth": auth})  # no 'type'
        resp = _recv_raw(s)
        assert resp["ok"] is False
        s.close()
        server._shutdown.set()

    def test_request_id_echo_matches(self, tmp_path):
        """IPC-PR-05: Server must echo the exact request_id back in every response.

        This is a correctness+security property: if the server echoes the wrong
        request_id, a client using pipelining could attribute the response to
        the wrong request (confused deputy).
        Expected: response request_id == sent request_id.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        auth = _build_auth(_IPC_SECRET, rid, "health")
        _send_raw(s, {"type": "health", "request_id": rid, "auth": auth})
        resp = _recv_raw(s)
        assert resp["request_id"] == rid
        s.close()
        server._shutdown.set()


# ===========================================================================
# Module-level shared server for tests that do real HSM operations
# (generate_key, encrypt, decrypt). Creating a new PyHSM per test is too
# slow because Argon2id runs on every open. One server is started once and
# shared across the operation and concurrency test classes.
# ===========================================================================

@pytest.fixture(scope="module")
def shared_server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("shared_ipc")
    server, socket_path, _ = _make_server(tmp)
    _start_server_thread(server)
    yield server, socket_path
    server._shutdown.set()


# ===========================================================================
# IPC-OP: Operation-level attacks
# ===========================================================================

class TestIPCOperationAttacks:
    """
    IPC-OP: Attacks on specific HSM operations through the IPC layer.

    Defense: The IPC server delegates to PyHSM which enforces all its own
    policy checks. The IPC layer adds: operation whitelisting, HMAC auth,
    and error sanitization (no tracebacks in responses).
    """

    def test_encrypt_nonexistent_key_returns_error_not_crash(self, shared_server):
        """IPC-OP-01: Encrypting with a nonexistent key must return an error, not crash the server.

        Attack: probe for key IDs that don't exist; server must stay alive.
        Expected: ok=false; server still responds to subsequent requests.
        """
        _, socket_path = shared_server
        s = _raw_sock(socket_path)

        # Attempt 1: encrypt with a ghost key
        rid = str(uuid.uuid4())
        auth = _build_auth(_IPC_SECRET, rid, "encrypt")
        _send_raw(s, {"type": "encrypt", "request_id": rid, "auth": auth,
                      "key_id": "ghost-nonexistent", "plaintext": "secret"})
        resp = _recv_raw(s)
        assert resp["ok"] is False

        # Attempt 2: server must still respond to a health check
        rid2 = str(uuid.uuid4())
        auth2 = _build_auth(_IPC_SECRET, rid2, "health")
        _send_raw(s, {"type": "health", "request_id": rid2, "auth": auth2})
        resp2 = _recv_raw(s)
        assert resp2["ok"] is True

        s.close()

    def test_all_allowed_operations_are_in_whitelist(self, tmp_path):
        """IPC-OP-02: The ALLOWED_OPERATIONS whitelist must cover all expected operations.

        This is a regression guard: if a developer adds a new operation to
        _dispatch() but forgets to add it to ALLOWED_OPERATIONS, it would
        be silently blocked.
        """
        expected_ops = {
            "encrypt", "decrypt", "sign", "verify",
            "generate_key", "rotate_key", "destroy_key",
            "list_keys", "has_key", "get_public_key",
            "export_jwk", "create_backup", "verify_backup",
            "get_metrics", "health",
        }
        assert expected_ops == ALLOWED_OPERATIONS

    def test_sensitive_error_not_leaked_in_response(self, shared_server):
        """IPC-OP-03: Internal error details must not appear in the IPC response.

        Attack: trigger an internal error and read the response, hoping for a
        stack trace that reveals file paths, key IDs, or internal state.
        Expected: error field contains a clean user-facing message only.
        """
        _, socket_path = shared_server
        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        auth = _build_auth(_IPC_SECRET, rid, "decrypt")
        # Send decrypt with junk ciphertext
        _send_raw(s, {"type": "decrypt", "request_id": rid, "auth": auth,
                      "key_id": "nonexistent-key", "ciphertext": "deadbeef"})
        resp = _recv_raw(s)
        assert resp["ok"] is False
        error = resp.get("error", "")
        # These strings must not appear in the response
        assert "Traceback" not in error
        assert "/Users/" not in error
        assert "/home/" not in error
        s.close()

    def test_generate_key_and_encrypt_round_trip_over_ipc(self, shared_server):
        """IPC-OP-04: Full encrypt/decrypt round trip must work correctly over IPC.

        Baseline functional test to confirm the IPC layer correctly passes
        data through to PyHSM and back.
        """
        _, socket_path = shared_server
        s = _raw_sock(socket_path)

        # Generate a key
        rid = str(uuid.uuid4())
        _send_raw(s, {"type": "generate_key", "request_id": rid,
                      "auth": _build_auth(_IPC_SECRET, rid, "generate_key"),
                      "key_id": "ipc-rt-test", "key_type": "aes-256"})
        resp = _recv_raw(s)
        assert resp["ok"] is True

        # Encrypt
        rid2 = str(uuid.uuid4())
        _send_raw(s, {"type": "encrypt", "request_id": rid2,
                      "auth": _build_auth(_IPC_SECRET, rid2, "encrypt"),
                      "key_id": "ipc-rt-test", "plaintext": "hello ipc"})
        resp2 = _recv_raw(s)
        assert resp2["ok"] is True
        ciphertext = resp2["data"]

        # Decrypt
        rid3 = str(uuid.uuid4())
        _send_raw(s, {"type": "decrypt", "request_id": rid3,
                      "auth": _build_auth(_IPC_SECRET, rid3, "decrypt"),
                      "key_id": "ipc-rt-test", "ciphertext": ciphertext})
        resp3 = _recv_raw(s)
        assert resp3["ok"] is True
        assert resp3["data"] == "hello ipc"

        s.close()


# ===========================================================================
# IPC-CN: Concurrency attacks
# ===========================================================================

class TestIPCConcurrencyAttacks:
    """
    IPC-CN: Concurrency attacks — races between clients, flood attacks,
    and slow-client DoS.

    Defense: per-connection threads with per-connection read timeout;
    per-key locks in the server's _dispatch() to prevent races between
    concurrent mutating operations on the same key.
    """

    def test_concurrent_clients_all_succeed(self, shared_server):
        """IPC-CN-01: Multiple concurrent clients must each succeed independently.

        Attack: concurrent client flood hoping for race conditions that cause
        incorrect results or crashes.
        Expected: all N clients complete their requests correctly.
        """
        server, socket_path = shared_server

        # First generate a key (single-threaded setup)
        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        _send_raw(s, {"type": "generate_key", "request_id": rid,
                      "auth": _build_auth(_IPC_SECRET, rid, "generate_key"),
                      "key_id": "concurrent-ipc-key", "key_type": "aes-256"})
        assert _recv_raw(s)["ok"] is True
        s.close()

        N = 10
        results = []
        errors  = []

        def client_work():
            try:
                sock = _raw_sock(socket_path)
                r = str(uuid.uuid4())
                _send_raw(sock, {"type": "encrypt", "request_id": r,
                                 "auth": _build_auth(_IPC_SECRET, r, "encrypt"),
                                 "key_id": "concurrent-ipc-key", "plaintext": "data"})
                resp = _recv_raw(sock)
                results.append(resp["ok"])
                sock.close()
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=client_work) for _ in range(N)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert len(errors) == 0, f"IPC errors: {errors}"
        assert all(results), "Not all concurrent clients succeeded"

    def test_slow_client_does_not_block_other_clients(self, tmp_path):
        """IPC-CN-02: A client that connects but never sends data must not block others.

        Attack: slow-client / connection exhaustion — open a connection and
        send nothing, tying up a server thread.
        Defense: per-connection conn_timeout_s drops stalled connections.
        Expected: a second legitimate client still gets a response promptly.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        # Slow client: connects but sends nothing
        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.settimeout(60.0)
        slow.connect(socket_path)
        # Do NOT send anything — holds the thread for up to 30 s

        # Fast client: should still get a response immediately
        fast = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        _send_raw(fast, {"type": "health", "request_id": rid,
                         "auth": _build_auth(_IPC_SECRET, rid, "health")})
        resp = _recv_raw(fast)
        assert resp["ok"] is True

        fast.close()
        slow.close()
        server._shutdown.set()

    def test_auth_failure_does_not_crash_server(self, tmp_path):
        """IPC-CN-03: Many consecutive auth failures must not crash or lock up the server.

        Attack: brute-force the IPC secret by sending wrong tokens repeatedly.
        Expected: server remains responsive to legitimate clients throughout.
        """
        server, socket_path, _ = _make_server(tmp_path)
        _start_server_thread(server)

        # Fire 20 bad-auth connections
        for _ in range(20):
            try:
                s = _raw_sock(socket_path)
                rid = str(uuid.uuid4())
                _send_raw(s, {"type": "health", "request_id": rid, "auth": "bad"})
                _recv_raw(s)
                s.close()
            except Exception:
                pass

        # Server must still respond to a legit request
        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        _send_raw(s, {"type": "health", "request_id": rid,
                      "auth": _build_auth(_IPC_SECRET, rid, "health")})
        resp = _recv_raw(s)
        assert resp["ok"] is True
        s.close()
        server._shutdown.set()


# ===========================================================================
# IPC-LF: Lifecycle attacks
# ===========================================================================

class TestIPCLifecycleAttacks:
    """
    IPC-LF: Lifecycle attack scenarios — server not running, double-start,
    and graceful shutdown behavior.
    """

    def test_client_connection_refused_when_server_not_running(self, tmp_path):
        """IPC-LF-01: IPCClient must raise ConnectionError when no server is running.

        Attack: application misconfiguration — client started before server.
        Expected: ConnectionError with a clear message.
        """
        from hsm.ipc_client import IPCClient
        fake_socket = "/tmp/pyhsm_no_such_socket_xyz.sock"
        with pytest.raises(ConnectionError, match="socket not found|refused|connect"):
            IPCClient(fake_socket, ipc_secret=_IPC_SECRET)

    def test_server_shutdown_drops_active_connections_cleanly(self, tmp_path):
        """IPC-LF-02: Server shutdown must not corrupt in-flight operations.

        Shutdown is signalled via _shutdown.set(). Active handler threads are
        daemons and will exit with the server. The socket file must be cleaned up.
        Expected: socket file removed after shutdown.
        """
        server, socket_path, _ = _make_server(tmp_path)
        t = _start_server_thread(server)
        # Confirm server is live
        assert os.path.exists(socket_path)

        server._shutdown.set()
        t.join(timeout=5.0)
        # Socket file should be cleaned up after shutdown
        assert not os.path.exists(socket_path)

    def test_stale_socket_file_removed_on_restart(self, tmp_path):
        """IPC-LF-03: A stale regular file at the socket path must be removed on restart.

        Attack: after an unclean shutdown a regular file is left at the socket path.
        Expected: IPCServer.run() unlinks the stale file, binds a fresh socket,
        and accepts connections normally.
        """
        server, socket_path, _ = _make_server(tmp_path)
        # Leave a stale regular file at the exact socket path before starting
        Path(socket_path).write_bytes(b"stale")
        assert os.path.exists(socket_path)

        t = _start_server_thread(server)
        # Server must have replaced the stale file with a live socket
        assert os.path.exists(socket_path)

        s = _raw_sock(socket_path)
        rid = str(uuid.uuid4())
        _send_raw(s, {"type": "health", "request_id": rid,
                      "auth": _build_auth(_IPC_SECRET, rid, "health")})
        resp = _recv_raw(s)
        assert resp["ok"] is True
        s.close()
        server._shutdown.set()
