# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
IPC request authentication (version 2), replay protection, peer identity, and safe errors.

Version 1 authenticated only ``request_id`` and the operation name::

    auth = HMAC-SHA256(secret, f"{request_id}:{operation}")

so a captured request could be sent again unchanged, or sent again with different parameters
(another key, another ciphertext) under the same token. Version 2 binds the whole request and
its time, and the server remembers which request ids it has already accepted::

    message = "pyhsm-ipc-v2\\n" + request_id + "\\n" + operation + "\\n" + str(ts) + "\\n" + body_sha256
    auth    = hex(HMAC-SHA256(secret, message))

``body_sha256`` is the SHA-256 (hex) of the canonical JSON of the request **without** the
fields ``auth`` and ``auth_v``: keys sorted, no whitespace, UTF-8 (``ensure_ascii=False``).
Requests carry only strings, integers, booleans, null, lists and objects, so every language's
JSON encoder produces the same bytes. (A client that also writes floats must format them as
Python does.)

A request is accepted only if the HMAC matches, ``ts`` is within ``max_skew_s`` of the server's
clock, and its ``request_id`` has not been accepted before within the replay window.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict
from typing import Any, Optional

AUTH_VERSION = 2
DEFAULT_MAX_SKEW_S = 60
_DOMAIN = "pyhsm-ipc-v2"
_UNSIGNED_FIELDS = ("auth", "auth_v")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
_CALLER_RE = re.compile(r"[^A-Za-z0-9._-]")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def canonical_body(request: dict) -> bytes:
    """The bytes that are hashed: the request minus its signature fields, canonical JSON."""
    unsigned = {k: v for k, v in request.items() if k not in _UNSIGNED_FIELDS}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def auth_message(request: dict) -> bytes:
    body_hash = hashlib.sha256(canonical_body(request)).hexdigest()
    return "\n".join(
        [_DOMAIN, str(request.get("request_id", "")), str(request.get("type", "")), str(request.get("ts", "")), body_hash]
    ).encode("utf-8")


def sign_request(secret: bytes, request: dict) -> dict:
    """Return a copy of ``request`` with ``ts``, ``auth_v`` and ``auth`` filled in."""
    signed = dict(request)
    signed.setdefault("ts", int(time.time()))
    signed["auth_v"] = AUTH_VERSION
    signed.pop("auth", None)
    signed["auth"] = _hmac.new(secret, auth_message(signed), hashlib.sha256).hexdigest()
    return signed


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class ReplayCache:
    """Request ids accepted recently. Bounded: when full, new requests are refused (fail closed)
    rather than forgetting ids that could still be replayed."""

    def __init__(self, window_s: float, max_entries: int = 200_000) -> None:
        self._window_s = window_s
        self._max = max_entries
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def add(self, request_id: str, now: float) -> bool:
        """Record ``request_id``. False if it was already seen, or the cache is full."""
        with self._lock:
            cutoff = now - self._window_s
            while self._seen:
                oldest_id, at = next(iter(self._seen.items()))
                if at > cutoff:
                    break
                self._seen.popitem(last=False)
            if request_id in self._seen:
                return False
            if len(self._seen) >= self._max:
                return False
            self._seen[request_id] = now
            return True

    def __len__(self) -> int:
        return len(self._seen)


class Verifier:
    """Checks version-2 request authentication. ``reason`` of the last failure is kept for the
    server's own log; it is never sent to the client."""

    def __init__(self, secret: bytes, max_skew_s: int = DEFAULT_MAX_SKEW_S, allow_legacy: bool = False,
                 clock=time.time) -> None:
        self._secret = secret
        self._max_skew_s = max_skew_s
        self._allow_legacy = allow_legacy
        self._clock = clock
        # An id older than the skew window is refused on time alone, so remembering ids for
        # twice the window covers every request that could still pass the time check.
        self._replay = ReplayCache(window_s=2 * max_skew_s)

    def verify(self, request: dict) -> tuple[bool, str]:
        provided = request.get("auth")
        if not isinstance(provided, str) or not provided:
            return False, "missing auth"
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not _REQUEST_ID_RE.match(request_id):
            return False, "malformed request_id"

        if request.get("auth_v") != AUTH_VERSION:
            if not self._allow_legacy:
                return False, "legacy (v1) authentication is disabled"
            expected = _hmac.new(
                self._secret, f"{request_id}:{request.get('type', '')}".encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not _hmac.compare_digest(provided, expected):
                return False, "bad v1 signature"
            # v1 has no timestamp; replay protection still applies by request id.
            if not self._replay.add(request_id, self._clock()):
                return False, "replayed request_id (or replay cache full)"
            return True, "ok (legacy v1)"

        ts = request.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            return False, "missing or malformed ts"
        try:
            expected = _hmac.new(self._secret, auth_message(request), hashlib.sha256).hexdigest()
        except (TypeError, ValueError):
            return False, "request cannot be canonicalised"
        if not _hmac.compare_digest(provided, expected):
            return False, "bad signature"
        now = self._clock()
        if abs(now - ts) > self._max_skew_s:
            return False, "timestamp outside the allowed clock skew"
        # Last, so a forged request cannot fill the replay cache.
        if not self._replay.add(request_id, now):
            return False, "replayed request_id (or replay cache full)"
        return True, "ok"


# ---------------------------------------------------------------------------
# Who is on the other end of the socket
# ---------------------------------------------------------------------------

class PeerIdentity:
    __slots__ = ("uid", "gid", "pid")

    def __init__(self, uid: Optional[int], gid: Optional[int], pid: Optional[int]) -> None:
        self.uid, self.gid, self.pid = uid, gid, pid

    def label(self) -> str:
        return f"uid={self.uid if self.uid is not None else '?'},pid={self.pid if self.pid is not None else '?'}"


def peer_identity(conn: socket.socket) -> PeerIdentity:
    """The connecting process's uid, gid and pid, from the kernel (not from anything the client
    says). Linux: SO_PEERCRED. macOS/BSD: LOCAL_PEERCRED and LOCAL_PEERPID. Unknown parts are None."""
    if hasattr(socket, "SO_PEERCRED"):  # Linux
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return PeerIdentity(uid, gid, pid)
    if sys.platform == "darwin" or "bsd" in sys.platform:
        SOL_LOCAL, LOCAL_PEERCRED, LOCAL_PEERPID = 0, 0x001, 0x002
        uid = gid = pid = None
        try:
            # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; (2 bytes padding)
            #                 gid_t cr_groups[16]; }  -> 76 bytes; the primary group is cr_groups[0].
            fmt = "IIh2x16I"
            raw = conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, struct.calcsize(fmt))
            fields = struct.unpack(fmt, raw[: struct.calcsize(fmt)])
            uid, ngroups = fields[1], fields[2]
            gid = fields[3] if ngroups > 0 else None
        except (OSError, struct.error):
            pass
        try:
            pid = struct.unpack("i", conn.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]
        except OSError:
            pass
        return PeerIdentity(uid, gid, pid)
    return PeerIdentity(None, None, None)


def attributed_caller(claimed: Any, peer: PeerIdentity) -> str:
    """What goes into the audit log as the caller: the name the client gave, cleaned and capped,
    followed by the identity the kernel reported. The second part is the one to trust."""
    name = _CALLER_RE.sub("", str(claimed or "ipc-client"))[:64] or "ipc-client"
    return f"{name}({peer.label()})"


# ---------------------------------------------------------------------------
# Errors that are safe to send back
# ---------------------------------------------------------------------------

#: (code, message) pairs. Messages are fixed text: no key ids, paths, versions or library output.
SAFE_ERRORS = {
    "rate_limited": "rate-limited: too many operations on this key, retry shortly",
    "policy_denied": "the key's policy does not allow this operation",
    "not_found": "no such key or key version",
    "decrypt_failed": "decryption failed",
    "invalid_request": "invalid request",
    "internal": "internal error",
}


def classify_error(exc: BaseException) -> str:
    """Map an exception raised while handling a request to one of ``SAFE_ERRORS``."""
    text = str(exc)
    name = type(exc).__name__
    if "is rate-limited" in text:
        return "rate_limited"
    if "policy denies" in text or "exceeded max operations" in text or "has expired" in text or "is archived" in text:
        return "policy_denied"
    if isinstance(exc, KeyError):
        # A missing request field is the caller's mistake; a missing stored key is "not found".
        return "not_found" if "not found" in text else "invalid_request"
    if "not found" in text:
        return "not_found"
    if name == "InvalidTag" or "Decryption failed" in text or "ciphertext too short" in text:
        return "decrypt_failed"
    if isinstance(exc, (ValueError, TypeError)):
        return "invalid_request"
    return "internal"
