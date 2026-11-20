# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM IPC Server — Unix domain socket process isolation.

Runs the PyHSM core in a dedicated subprocess that communicates with the
application over a Unix domain socket. This implements the process isolation
boundary described in the threat model: even if application code is
compromised (supply-chain attack, RCE via a web framework), the attacker
cannot directly read key material or call cryptographic operations because
the HSM lives in a separate address space with a distinct OS process identity.

Architecture
------------

    ┌──────────────────────────────────────────────────────────┐
    │  Application Process                                       │
    │                                                           │
    │  IPCClient.encrypt("key", "hello") ──────────────────┐   │
    └──────────────────────────────────────────────────────│───┘
                                                           │ Unix socket
    ┌──────────────────────────────────────────────────────│───┐
    │  PyHSM Server Process (this module)                   │   │
    │                                                       ↓   │
    │  IPCServer → PyHSM(keystore, password_file=...)           │
    │  Raw key material NEVER leaves this process               │
    └──────────────────────────────────────────────────────────┘

Wire protocol
-------------
Each message is a length-prefixed JSON frame:
    [4 bytes big-endian uint32 = payload length][UTF-8 JSON payload]

Request fields:
    type     : str   — operation name (see ALLOWED_OPERATIONS)
    request_id : str — caller-provided correlation ID for tracing
    ...      : operation-specific fields

Response fields:
    ok         : bool
    request_id : str  — echoed from request
    data       : any  — on success
    error      : str  — on failure (never includes raw key material)

Security properties
-------------------
- The socket file is created with mode 0o600 so only the HSM server's
  UID can connect. The server verifies this on startup.
- HMAC authentication is REQUIRED. The server refuses to start without
  --ipc-secret (or PYHSM_IPC_SECRET). Every request must carry a valid
  version-2 token: HMAC-SHA256 over the request id, operation, timestamp and a
  hash of the whole request body, so parameters cannot be altered. A request id
  is accepted once, and the timestamp must be within --max-clock-skew seconds
  (see hsm/ipc_auth.py). Version-1 tokens are refused unless
  --allow-legacy-auth is given.
- The kernel-reported identity of the connecting process (uid, pid) is checked
  against --allow-uid (default: the server's own uid) and written to the audit
  log next to the caller name the client gives.
- Errors sent back are fixed messages with a code (rate_limited, not_found,
  policy_denied, decrypt_failed, invalid_request, internal, auth_failed);
  exception details stay in the server log.
- Per-key locking: read-only operations (health, list_keys, has_key,
  get_public_key, get_metrics) hold no lock; key-mutating operations
  acquire a per-key lock via the PyHSM core's own _key_lock(). This
  replaces the previous single global lock and eliminates the DoS
  where a slow RSA-4096 keygen stalled all other clients.
- Per-connection read timeout (default 30 s) ensures a stalled or
  malicious client cannot hold a thread indefinitely.
- The server enforces a whitelist of allowed operations. Unknown
  operation names are rejected with an error, not a traceback.
- Each request is handled in a new thread so slow operations (RSA keygen)
  don't block the accept loop.
- The server shuts down cleanly on SIGTERM/SIGINT: closes the session,
  zeroizes memory, removes the socket file.

Usage
-----
Start the server (blocks until SIGTERM)::

    python -m hsm.ipc_server \\
        --store /secure/keystore.enc \\
        --password-file /run/secrets/pyhsm-password \\
        --ipc-secret $(openssl rand -hex 32) \\
        --socket /run/pyhsm/pyhsm.sock

Or via the convenience entry point added to pyproject.toml::

    vectorguard-pyhsm-server --store keystore.enc \\
        --password-file /run/secrets/pyhsm-password \\
        --ipc-secret $(openssl rand -hex 32)
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import signal
import socket
import struct
import sys
import threading
import traceback
from typing import Optional

from .core import PyHSM
from .logging import get_logger

_logger = get_logger(__name__)

# Operations the server will execute. Any operation not in this set is
# rejected before touching the HSM instance.
ALLOWED_OPERATIONS = frozenset({
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "generate_key",
    "rotate_key",
    "destroy_key",
    "list_keys",
    "has_key",
    "get_public_key",
    "export_jwk",
    "create_backup",
    "verify_backup",
    "get_metrics",
    "health",
})

from .ipc_auth import (
    DEFAULT_MAX_SKEW_S,
    SAFE_ERRORS,
    Verifier,
    attributed_caller,
    classify_error,
    peer_identity,
)

_MSG_HEADER = struct.Struct(">I")   # 4-byte big-endian uint32
_MAX_MSG_BYTES = 64 * 1024 * 1024  # 64 MB — matches PyHSM plaintext limit
_SOCKET_MODE = 0o600

# Per-connection read timeout in seconds. A client that stops sending data
# after this many seconds is disconnected, freeing the handler thread.
# Prevents a stalled or malicious client from holding a thread indefinitely.
_CONN_TIMEOUT_S = 30.0

# Operations that require NO lock at all — they are read-only and the
# underlying PyHSM calls are thread-safe for concurrent reads.
_READ_ONLY_OPERATIONS = frozenset({
    "health",
    "list_keys",
    "has_key",
    "get_public_key",
    "get_metrics",
})


def _send_msg(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    header = _MSG_HEADER.pack(len(data))
    sock.sendall(header + data)


def _recv_msg(sock: socket.socket) -> Optional[dict]:
    header = _recv_exact(sock, _MSG_HEADER.size)
    if not header:
        return None
    (length,) = _MSG_HEADER.unpack(header)
    if length > _MAX_MSG_BYTES:
        raise ValueError(f"IPC message too large: {length} bytes")
    raw = _recv_exact(sock, length)
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class IPCServer:
    """
    PyHSM IPC server — wraps a PyHSM instance and exposes it over a
    Unix domain socket using length-prefixed JSON framing.

    Locking strategy
    ----------------
    The previous implementation used a single global lock around all HSM
    operations. This meant a slow RSA-4096 keygen or a deliberately slow
    client could stall every other client — a DoS vector.

    The new strategy mirrors what PyHSM core already does internally:

    - Read-only operations (health, list_keys, has_key, get_public_key,
      get_metrics) acquire NO lock. PyHSM's internal sharded key locks
      make these safe to run concurrently.

    - Key-mutating operations (encrypt, decrypt, sign, verify, rotate_key,
      destroy_key, export_jwk) acquire only the per-key lock for the
      specific key_id involved, via PyHSM's existing _key_lock() mechanism.
      Two operations on *different* keys can now run in parallel.

    - Session-level operations (generate_key, create_backup, verify_backup)
      acquire the PyHSM global lock, consistent with how core.py handles them.

    Authentication
    --------------
    HMAC authentication is REQUIRED. The server refuses to start without
    an ipc_secret. Every request must carry a valid HMAC-SHA256 token.
    """

    def __init__(
        self,
        store_path: str,
        socket_path: str,
        *,
        master_password: Optional[str] = None,
        password_file: Optional[str] = None,
        ipc_secret: Optional[str] = None,
        session_timeout_s: float = 0.0,
        rate_limit_max_ops: int = 100,
        rate_limit_window_s: float = 60.0,
        conn_timeout_s: float = _CONN_TIMEOUT_S,
        max_clock_skew_s: int = DEFAULT_MAX_SKEW_S,
        allow_legacy_auth: bool = False,
        allowed_uids: Optional[set[int]] = None,
    ) -> None:
        # --- Require ipc_secret — no unauthenticated operation ---
        if not ipc_secret:
            raise ValueError(
                "IPCServer: ipc_secret is required. "
                "Pass --ipc-secret <secret> or set PYHSM_IPC_SECRET. "
                "Without a shared secret, any local process that reaches the "
                "socket gets full HSM access with no authentication.\n"
                "Generate a strong secret with: openssl rand -hex 32"
            )

        self._socket_path = socket_path
        self._ipc_secret: bytes = ipc_secret.encode("utf-8")
        # Version-2 authentication: the HMAC covers the whole request and its time, and a
        # request id is accepted once. See hsm/ipc_auth.py.
        self._verifier = Verifier(self._ipc_secret, max_skew_s=max_clock_skew_s, allow_legacy=allow_legacy_auth)
        # Which operating-system users may connect, checked against what the kernel reports for
        # the peer. Default: only the user this server runs as.
        self._allowed_uids = set(allowed_uids) if allowed_uids else {os.getuid()}
        self._shutdown = threading.Event()
        self._conn_timeout_s = conn_timeout_s

        _logger.info("IPC server starting", extra={
            "event": "ipc_server_start",
            "socket_path": socket_path,
            "store_path": store_path,
            "auth": "hmac-v2-required" + ("+legacy-v1" if allow_legacy_auth else ""),
            "allowed_uids": sorted(self._allowed_uids),
        })

        self._hsm = PyHSM(
            storage_path=store_path,
            master_password=master_password,
            password_file=password_file,
            session_timeout_s=session_timeout_s,
            rate_limit_max_ops=rate_limit_max_ops,
            rate_limit_window_s=rate_limit_window_s,
        )
        _logger.info("PyHSM session opened", extra={"event": "ipc_hsm_ready"})

    def _authenticate(self, request: dict) -> bool:
        """Verify request authentication (version 2, see hsm/ipc_auth.py). Always required."""
        ok, reason = self._verifier.verify(request)
        if not ok:
            # The reason is for the operator's log only; the client is told nothing more than
            # "authentication failed", so it cannot probe which check failed.
            _logger.warning("IPC authentication rejected", extra={
                "event": "ipc_auth_rejected", "reason": reason,
            })
        return ok

    def _handle_request(self, request: dict, peer=None) -> dict:
        """Dispatch a validated, authenticated request to the PyHSM instance."""
        op = request.get("type", "")
        # The audit trail records the name the client gave AND the uid/pid the kernel reported.
        caller_id = attributed_caller(request.get("caller_id"), peer) if peer is not None else (
            str(request.get("caller_id", "ipc-client"))[:64]
        )

        if op not in ALLOWED_OPERATIONS:
            return {"ok": False, "code": "invalid_request", "error": "Unknown operation"}

        try:
            result = self._dispatch(op, request, caller_id)
            return {"ok": True, "data": result}
        except Exception as exc:
            # Only a fixed message goes back to the client: exception text can carry key ids,
            # file paths, version numbers or library internals. The detail stays in this log.
            code = classify_error(exc)
            _logger.error("IPC request failed", extra={
                "event": "ipc_error",
                "operation": op,
                "code": code,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            return {"ok": False, "code": code, "error": SAFE_ERRORS[code]}

    def _dispatch(self, op: str, req: dict, caller_id: str):
        hsm = self._hsm

        # --- Read-only operations: no lock needed ---
        if op == "health":
            return {"status": "ok", "session_active": hsm._session_active}
        elif op == "list_keys":
            return hsm.list_keys()
        elif op == "has_key":
            return hsm.has_key(req["key_id"])
        elif op == "get_public_key":
            return hsm.get_public_key(req["key_id"])
        elif op == "get_metrics":
            return hsm.get_metrics()

        # --- Per-key mutating operations: PyHSM methods manage their own per-key locks ---
        elif op in ("encrypt", "decrypt", "sign", "verify",
                    "rotate_key", "destroy_key", "export_jwk"):
            key_id = req["key_id"]
            if op == "encrypt":
                return hsm.encrypt(key_id, req["plaintext"], caller_id=caller_id)
            elif op == "decrypt":
                result = hsm.decrypt(key_id, req["ciphertext"], caller_id=caller_id)
                return result.decode("utf-8", errors="surrogateescape")
            elif op == "sign":
                return hsm.sign(key_id, req["message"], caller_id=caller_id)
            elif op == "verify":
                return hsm.verify(key_id, req["message"], req["signature"], caller_id=caller_id)
            elif op == "rotate_key":
                return hsm.rotate_key(key_id, caller_id=caller_id)
            elif op == "destroy_key":
                hsm.destroy_key(key_id, caller_id=caller_id)
                return None
            elif op == "export_jwk":
                return hsm.export_jwk(key_id, caller_id=caller_id)

        # --- Session-level operations: PyHSM methods manage their own global lock ---
        elif op in ("generate_key", "create_backup", "verify_backup"):
            if op == "generate_key":
                return hsm.generate_key(
                    req["key_id"],
                    req.get("key_type", "aes-256"),
                    policy=req.get("policy"),
                    caller_id=caller_id,
                )
            elif op == "create_backup":
                return hsm.create_backup(req["backup_dir"], caller_id=caller_id)
            elif op == "verify_backup":
                return hsm.verify_backup(req["backup_path"], caller_id=caller_id)

        raise ValueError(f"Unhandled operation: {op!r}")

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        """Handle one client connection in a dedicated thread."""
        # Apply per-connection read timeout so a stalled or malicious client
        # cannot hold this thread indefinitely. If the client sends no data
        # within _CONN_TIMEOUT_S seconds the socket.timeout exception is
        # caught below and the connection is dropped cleanly.
        conn.settimeout(self._conn_timeout_s)
        try:
            # Who is connecting, according to the kernel. Refuse anyone not allowed before
            # reading a single request. (The socket's mode 600 already stops other users; this
            # also stops root, and any user the socket was shared with by mistake.)
            peer = peer_identity(conn)
            if peer.uid is None or peer.uid not in self._allowed_uids:
                _logger.warning("IPC connection refused: peer not allowed", extra={
                    "event": "ipc_peer_refused", "peer": peer.label(),
                })
                return
            while True:
                request = _recv_msg(conn)
                if request is None:
                    break  # client disconnected

                request_id = request.get("request_id", "")

                if not self._authenticate(request):
                    _logger.warning("IPC authentication failed", extra={
                        "event": "ipc_auth_failed", "request_id": request_id,
                    })
                    _send_msg(conn, {
                        "ok": False,
                        "request_id": request_id,
                        "code": "auth_failed",
                        "error": "Authentication failed",
                    })
                    break  # close connection on auth failure

                response = self._handle_request(request, peer)
                response["request_id"] = request_id
                _send_msg(conn, response)

        except socket.timeout:
            _logger.warning("IPC connection timed out", extra={
                "event": "ipc_conn_timeout",
                "timeout_s": _CONN_TIMEOUT_S,
            })
        except Exception:
            _logger.debug("IPC connection error", extra={
                "event": "ipc_conn_error",
                "traceback": traceback.format_exc(),
            })
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def run(self) -> None:
        """Start the server and block until shutdown."""
        # Remove stale socket file
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

        # Ensure parent directory exists and is private
        sock_dir = os.path.dirname(self._socket_path)
        if sock_dir:
            os.makedirs(sock_dir, mode=0o700, exist_ok=True)

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server_sock.bind(self._socket_path)
            os.chmod(self._socket_path, _SOCKET_MODE)
            server_sock.listen(32)
            server_sock.settimeout(1.0)  # allow periodic shutdown checks

            _logger.info("IPC server listening", extra={
                "event": "ipc_listening",
                "socket_path": self._socket_path,
            })

            # Install signal handlers for clean shutdown.
            # signal.signal() only works on the main thread; when run() is
            # called from a background thread (e.g. in tests), skip installation.
            if threading.current_thread() is threading.main_thread():
                def _shutdown_handler(signum, frame):
                    _logger.info("IPC server shutting down", extra={
                        "event": "ipc_shutdown", "signal": signum,
                    })
                    self._shutdown.set()

                signal.signal(signal.SIGTERM, _shutdown_handler)
                signal.signal(signal.SIGINT, _shutdown_handler)

            while not self._shutdown.is_set():
                try:
                    conn, addr = server_sock.accept()
                    t = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue  # check shutdown flag

        finally:
            server_sock.close()
            try:
                os.unlink(self._socket_path)
            except OSError:
                pass
            try:
                self._hsm.close_session()
            except Exception:
                pass
            _logger.info("IPC server stopped", extra={"event": "ipc_stopped"})


def main() -> None:
    """Entry point for vectorguard-pyhsm-server."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="vectorguard-pyhsm-server",
        description="PyHSM IPC server — run the HSM in an isolated process",
    )
    parser.add_argument("--store", required=True, help="Path to keystore file")
    parser.add_argument(
        "--socket",
        default=os.environ.get("PYHSM_SOCKET", "/run/pyhsm/pyhsm.sock"),
        help="Unix socket path (default: /run/pyhsm/pyhsm.sock or PYHSM_SOCKET env var)",
    )
    parser.add_argument(
        "--password-file",
        metavar="PATH",
        default=os.environ.get("PYHSM_PASSWORD_FILE"),
        help="Path to password file (chmod 600). Preferred over --password.",
    )
    parser.add_argument(
        "--ipc-secret",
        metavar="SECRET",
        default=os.environ.get("PYHSM_IPC_SECRET"),
        help=(
            "Shared HMAC secret for request authentication (or PYHSM_IPC_SECRET env var). "
            "REQUIRED — the server refuses to start without this. "
            "Generate with: openssl rand -hex 32"
        ),
    )
    parser.add_argument(
        "--rate-limit", type=int, default=100,
        help="Max operations per key per minute (default: 100)",
    )
    parser.add_argument(
        "--max-clock-skew", type=int, default=DEFAULT_MAX_SKEW_S,
        help=f"Seconds a request's timestamp may differ from this server's clock (default: {DEFAULT_MAX_SKEW_S})",
    )
    parser.add_argument(
        "--allow-uid", type=int, action="append", default=None, metavar="UID",
        help="Operating-system user id allowed to connect (repeatable). Default: only the user this server runs as.",
    )
    parser.add_argument(
        "--allow-legacy-auth", action="store_true",
        help="Also accept version-1 request authentication (request id and operation only; no protection "
             "against altered parameters). For migrating old clients only. Default: refused.",
    )
    args = parser.parse_args()

    if not args.password_file:
        print(
            "ERROR: --password-file is required for the IPC server.\n"
            "Create the file with: install -m 600 /dev/null /run/secrets/pyhsm-password\n"
            "Then write the password: printf '%%s' 'YourPassword' > /run/secrets/pyhsm-password",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.ipc_secret:
        print(
            "ERROR: --ipc-secret is required for the IPC server.\n"
            "Without a shared secret, any local process that can reach the socket\n"
            "gets full HSM access with no authentication.\n"
            "\n"
            "Generate a strong secret and pass it via --ipc-secret or PYHSM_IPC_SECRET:\n"
            "  export PYHSM_IPC_SECRET=$(openssl rand -hex 32)\n"
            "\n"
            "The same secret must be provided to the IPC client (IPCClient or --ipc-secret\n"
            "on the client side).",
            file=sys.stderr,
        )
        sys.exit(1)

    server = IPCServer(
        store_path=args.store,
        socket_path=args.socket,
        password_file=args.password_file,
        ipc_secret=args.ipc_secret,
        rate_limit_max_ops=args.rate_limit,
        max_clock_skew_s=args.max_clock_skew,
        allow_legacy_auth=args.allow_legacy_auth,
        allowed_uids=set(args.allow_uid) if args.allow_uid else None,
    )
    server.run()


if __name__ == "__main__":
    main()
